//! Authenticated, runtime-neutral Handshake P2P DNS transports.
//!
//! This crate constructs and validates draft HIP-76 DNS Relay and HIP-77
//! ODoH exchanges. A platform adapter owns sockets and the Brontide record
//! layer, but must return the static key authenticated by that exact session.
//! Relay DNS remains untrusted. ODoH is opened locally, and both paths parse
//! and correlate the DNS response before it can enter the gateway.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "DNS, ODoH, P2P, HIP, and Brontide are protocol names"
)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use hns_dns_relay_protocol::{
    DnsRelay, DnsRelayProtocolError, DnsRelayStatus, GetDnsRelay,
    MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE,
};
use hns_dns_wire::{Message, ParseLimits, Query};
use hns_gateway::{AttemptOutcome, GatewayIdentities, TransportFailure};
use hns_odoh_protocol::{
    ClientQuery, DirectTargetLocator, MAX_ODOH_PACKET_SIZE, MAX_OUTER_PADDING_SIZE, OdnsPacket,
    OdohConfig, OdohErrorBody, OdohOpcode, OdohProtocolError, OdohResponseBody, OdohStatus,
    QueryContext, TargetConfigRecord, seal_query,
};
use hns_p2p_experimental::{
    DNS_RELAY_REQUEST_PACKET, DNS_RELAY_RESPONSE_PACKET, ExperimentalPeerState, NegotiatedRegistry,
    ODOH_PACKET, PacketType, PeerProtocolError,
};
use hns_transport::CancellationToken;
use k256::PublicKey;
use thiserror::Error;

/// Maximum DNS response admitted to the browser validation path.
pub const MAX_DNS_RESPONSE_BYTES: usize = u16::MAX as usize;
/// Default ODoH outer-message padding bucket.
pub const DEFAULT_ODOH_PADDING_BUCKET: usize = 512;

/// A compressed secp256k1 key authenticated by an established Brontide session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerIdentity([u8; 33]);

impl PeerIdentity {
    /// Validate and bind a compressed Brontide static key.
    pub fn new(key: [u8; 33]) -> Result<Self, P2pTransportError> {
        PublicKey::from_sec1_bytes(&key).map_err(|_| P2pTransportError::InvalidPeerIdentity)?;
        Ok(Self(key))
    }

    /// Compressed static key.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 33] {
        self.0
    }

    fn gateway_label(self) -> String {
        format!("brontide:{}", hex::encode(self.0))
    }
}

/// One admitted, established experimental peer.
///
/// The caller may create this value only after the adapter's Brontide
/// handshake authenticated `identity`. The constructor installs the exact
/// negotiated Denuo registry before any private packet can be used.
#[derive(Debug)]
pub struct AuthenticatedPeer {
    identity: PeerIdentity,
    admission: ExperimentalPeerState,
    maximum_send_size: usize,
}

impl AuthenticatedPeer {
    /// Bind an authenticated key to established registry-negotiated state.
    pub fn bind(
        identity: PeerIdentity,
        mut admission: ExperimentalPeerState,
        negotiated: NegotiatedRegistry,
    ) -> Result<Self, P2pTransportError> {
        admission.validate_advertisements()?;
        let protocol_ids: BTreeSet<_> = negotiated
            .protocols
            .iter()
            .map(|(protocol_id, _)| *protocol_id)
            .collect();
        if negotiated.registry_version == 0
            || negotiated.maximum_send_size == 0
            || negotiated.maximum_live_requests == 0
            || negotiated
                .protocols
                .iter()
                .any(|(_, version)| *version == 0)
            || protocol_ids.len() != negotiated.protocols.len()
        {
            return Err(P2pTransportError::InvalidNegotiatedRegistry);
        }
        admission.mark_established();
        let maximum_send_size = usize::try_from(negotiated.maximum_send_size)
            .map_err(|_| P2pTransportError::InvalidNegotiatedRegistry)?;
        admission.install_negotiation(negotiated)?;
        Ok(Self {
            identity,
            admission,
            maximum_send_size,
        })
    }

    /// Brontide-authenticated remote identity.
    #[must_use]
    pub const fn identity(&self) -> PeerIdentity {
        self.identity
    }

    fn admit(&mut self, packet: PacketType) -> Result<(), P2pTransportError> {
        self.admission.admit_packet(packet)?;
        Ok(())
    }

    fn admit_outbound(
        &mut self,
        packet: PacketType,
        payload_length: usize,
    ) -> Result<(), P2pTransportError> {
        self.admit(packet)?;
        if payload_length > self.maximum_send_size {
            return Err(P2pTransportError::NegotiatedRequestLimit);
        }
        Ok(())
    }
}

/// Request passed to a platform Brontide adapter.
#[derive(Clone, Copy, Debug)]
pub struct ExperimentalRequest<'request> {
    /// Exact authenticated destination.
    pub peer: PeerIdentity,
    /// Negotiated semantic packet assignment.
    pub packet: PacketType,
    /// Strictly encoded packet payload.
    pub payload: &'request [u8],
    /// Absolute caller clock deadline.
    pub deadline: u64,
    /// Maximum payload the adapter may allocate for the response.
    pub maximum_response_payload: usize,
}

/// Response attested by a platform Brontide adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalResponse {
    /// Static key authenticated by the response-bearing Brontide session.
    pub authenticated_peer: PeerIdentity,
    /// Semantic response packet assignment.
    pub packet: PacketType,
    /// Decrypted Brontide packet payload.
    pub payload: Vec<u8>,
    /// Caller-clock time after the full response was received.
    pub completed_at: u64,
}

/// Failure classification supplied by a platform adapter.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdapterFailure {
    /// Destination could not be reached.
    #[error("experimental P2P destination is unreachable")]
    Unreachable,
    /// The finite request deadline expired.
    #[error("experimental P2P request timed out")]
    Timeout,
    /// The runtime does not implement the selected path.
    #[error("experimental P2P transport is unsupported")]
    Unsupported,
    /// Brontide or endpoint authentication failed.
    #[error("experimental P2P peer authentication failed")]
    AuthenticationFailed,
    /// Platform lifecycle cancelled the request.
    #[error("experimental P2P request was cancelled")]
    Cancelled,
}

/// Socket/runtime boundary for one established Brontide request.
pub trait ExperimentalExchange {
    /// Send exactly one bounded semantic packet and await one response.
    fn exchange(
        &mut self,
        request: ExperimentalRequest<'_>,
    ) -> Result<ExperimentalResponse, AdapterFailure>;
}

/// Bounded requester configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequesterLimits {
    /// Maximum locally admitted DNS response bytes.
    pub maximum_dns_response_bytes: usize,
    /// ODoH outer-message padding bucket, or zero to disable outer padding.
    pub odoh_padding_bucket: usize,
}

impl Default for RequesterLimits {
    fn default() -> Self {
        Self {
            maximum_dns_response_bytes: MAX_DNS_RESPONSE_BYTES,
            odoh_padding_bucket: DEFAULT_ODOH_PADDING_BUCKET,
        }
    }
}

impl RequesterLimits {
    fn validate(self) -> Result<Self, P2pTransportError> {
        if self.maximum_dns_response_bytes < 12
            || self.maximum_dns_response_bytes > MAX_DNS_RESPONSE_BYTES
            || (self.odoh_padding_bucket != 0
                && (!(128..=MAX_OUTER_PADDING_SIZE).contains(&self.odoh_padding_bucket)
                    || !self.odoh_padding_bucket.is_power_of_two()))
        {
            return Err(P2pTransportError::InvalidLimits);
        }
        Ok(self)
    }
}

/// A signed, current ODoH target record reduced to immutable requester fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedOdohTarget {
    locator: DirectTargetLocator,
    configuration: OdohConfig,
    record_id: [u8; 32],
    expires_at: u64,
}

impl VerifiedOdohTarget {
    /// Verify a target-signed record and select one supported configuration.
    #[allow(
        clippy::too_many_arguments,
        reason = "every argument is a distinct signed-record check"
    )]
    pub fn decode(
        record: &[u8],
        expected_locator: &DirectTargetLocator,
        expected_network_magic: u32,
        now: u64,
        allow_private: bool,
        configuration_index: usize,
    ) -> Result<Self, P2pTransportError> {
        let record = TargetConfigRecord::decode_and_verify(
            record,
            expected_locator,
            expected_network_magic,
            now,
            allow_private,
        )?;
        let configuration = record
            .configurations
            .get(configuration_index)
            .cloned()
            .ok_or(P2pTransportError::MissingOdohConfiguration)?;
        Ok(Self {
            locator: record.locator,
            configuration,
            record_id: record.record_id,
            expires_at: record.expires_at,
        })
    }

    /// Authenticated target locator.
    #[must_use]
    pub const fn locator(&self) -> &DirectTargetLocator {
        &self.locator
    }

    /// Target record identifier carried in the proxy request.
    #[must_use]
    pub const fn record_id(&self) -> [u8; 32] {
        self.record_id
    }

    /// Target configuration expiration time.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    fn target_identity(&self) -> Result<PeerIdentity, P2pTransportError> {
        PeerIdentity::new(self.locator.target_peer_key)
    }

    fn ensure_current(&self, now: u64) -> Result<(), P2pTransportError> {
        if now >= self.expires_at {
            Err(P2pTransportError::ExpiredOdohTarget)
        } else {
            Ok(())
        }
    }
}

/// DNS bytes admitted after protocol parsing and exact query correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedDnsResponse {
    wire: Vec<u8>,
    message: Message,
    identities: GatewayIdentities,
}

impl AdmittedDnsResponse {
    /// Exact admitted DNS wire bytes.
    #[must_use]
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// Parsed, correlated DNS response.
    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.message
    }

    /// Authenticated transport identities for gateway provenance.
    #[must_use]
    pub const fn identities(&self) -> &GatewayIdentities {
        &self.identities
    }

    /// Consume into the gateway's successful adapter result.
    #[must_use]
    pub fn into_gateway_outcome(self) -> AttemptOutcome {
        AttemptOutcome::Response {
            bytes: self.wire,
            identities: self.identities,
        }
    }
}

/// Stateful HIP-76 requester with its own nonzero request-ID space.
#[derive(Debug)]
pub struct DnsRelayRequester {
    request_ids: RequestIds,
    limits: RequesterLimits,
}

impl DnsRelayRequester {
    /// Create with an explicit unpredictable first request ID.
    pub fn new(
        first_request_id: NonZeroU64,
        limits: RequesterLimits,
    ) -> Result<Self, P2pTransportError> {
        Ok(Self {
            request_ids: RequestIds::new(first_request_id),
            limits: limits.validate()?,
        })
    }

    /// Execute one authenticated HIP-76 exchange.
    pub fn exchange<A: ExperimentalExchange>(
        &mut self,
        adapter: &mut A,
        relay: &mut AuthenticatedPeer,
        query: &Query,
        cancellation: &CancellationToken,
        now: u64,
        deadline: u64,
    ) -> Result<AdmittedDnsResponse, P2pTransportError> {
        check_lifecycle(cancellation, now, deadline)?;
        let request_id = self.request_ids.take()?;
        let query_wire = query.encode(hns_dns_relay_protocol::MAX_DNS_RELAY_QUERY_SIZE)?;
        let request = GetDnsRelay::new(request_id, query_wire)?.encode()?;
        relay.admit_outbound(DNS_RELAY_REQUEST_PACKET, request.len())?;
        let response = adapter.exchange(ExperimentalRequest {
            peer: relay.identity(),
            packet: DNS_RELAY_REQUEST_PACKET,
            payload: &request,
            deadline,
            maximum_response_payload: MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE,
        })?;
        check_response_boundary(
            cancellation,
            relay.identity(),
            &response,
            deadline,
            MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE,
        )?;
        if response.packet != DNS_RELAY_RESPONSE_PACKET {
            return Err(P2pTransportError::UnexpectedPacket {
                expected: DNS_RELAY_RESPONSE_PACKET,
                actual: response.packet,
            });
        }
        relay.admit(DNS_RELAY_RESPONSE_PACKET)?;
        let response = DnsRelay::decode(&response.payload)?;
        if response.request_id != request_id {
            return Err(P2pTransportError::RequestIdMismatch);
        }
        if response.status != DnsRelayStatus::Ok {
            return Err(P2pTransportError::DnsRelayStatus(response.status));
        }
        admit_dns(
            query,
            response.response,
            self.limits.maximum_dns_response_bytes,
            GatewayIdentities {
                peer: Some(relay.identity().gateway_label()),
                ..GatewayIdentities::default()
            },
        )
    }
}

/// Stateful HIP-77 requester with its own nonzero request-ID space.
#[derive(Debug)]
pub struct OdohRequester {
    request_ids: RequestIds,
    limits: RequesterLimits,
}

impl OdohRequester {
    /// Create with an explicit unpredictable first request ID.
    pub fn new(
        first_request_id: NonZeroU64,
        limits: RequesterLimits,
    ) -> Result<Self, P2pTransportError> {
        Ok(Self {
            request_ids: RequestIds::new(first_request_id),
            limits: limits.validate()?,
        })
    }

    /// Execute one proxy-authenticated, target-authenticated HIP-77 exchange.
    #[allow(
        clippy::too_many_arguments,
        reason = "proxy, signed target, query, lifecycle, and clock are independent trust inputs"
    )]
    pub fn exchange<A: ExperimentalExchange>(
        &mut self,
        adapter: &mut A,
        proxy: &mut AuthenticatedPeer,
        target: &VerifiedOdohTarget,
        query: &Query,
        cancellation: &CancellationToken,
        now: u64,
        deadline: u64,
    ) -> Result<AdmittedDnsResponse, P2pTransportError> {
        check_lifecycle(cancellation, now, deadline)?;
        target.ensure_current(now)?;
        let target_identity = target.target_identity()?;
        if proxy.identity() == target_identity {
            return Err(P2pTransportError::ProxyTargetCollision);
        }
        let request_id = self.request_ids.take()?;
        let query_wire = query.encode(hns_odoh_protocol::MAX_ODOH_QUERY_SIZE)?;
        let (message, context) = seal_query(&target.configuration, &query_wire)?;
        let client_query = ClientQuery {
            locator: target.locator.clone(),
            config_id: target.record_id,
            message,
            padding: Vec::new(),
        };
        let body = encode_padded_client_query(client_query, self.limits.odoh_padding_bucket)?;
        let packet = OdnsPacket::new(OdohOpcode::ClientQuery, request_id, body)?.encode()?;
        proxy.admit_outbound(ODOH_PACKET, packet.len())?;
        let response = adapter.exchange(ExperimentalRequest {
            peer: proxy.identity(),
            packet: ODOH_PACKET,
            payload: &packet,
            deadline,
            maximum_response_payload: MAX_ODOH_PACKET_SIZE,
        })?;
        check_response_boundary(
            cancellation,
            proxy.identity(),
            &response,
            deadline,
            MAX_ODOH_PACKET_SIZE,
        )?;
        target.ensure_current(response.completed_at)?;
        if response.packet != ODOH_PACKET {
            return Err(P2pTransportError::UnexpectedPacket {
                expected: ODOH_PACKET,
                actual: response.packet,
            });
        }
        proxy.admit(ODOH_PACKET)?;
        let response = OdnsPacket::decode(&response.payload)?;
        if response.request_id != request_id {
            return Err(P2pTransportError::RequestIdMismatch);
        }
        let response_wire = open_odoh_response(&response, context)?;
        admit_dns(
            query,
            response_wire,
            self.limits.maximum_dns_response_bytes,
            GatewayIdentities {
                proxy: Some(proxy.identity().gateway_label()),
                target: Some(target_identity.gateway_label()),
                ..GatewayIdentities::default()
            },
        )
    }
}

#[derive(Debug)]
struct RequestIds {
    next: Option<NonZeroU64>,
}

impl RequestIds {
    const fn new(first: NonZeroU64) -> Self {
        Self { next: Some(first) }
    }

    fn take(&mut self) -> Result<u64, P2pTransportError> {
        let current = self
            .next
            .take()
            .ok_or(P2pTransportError::RequestIdExhausted)?;
        self.next = current.get().checked_add(1).and_then(NonZeroU64::new);
        Ok(current.get())
    }
}

fn encode_padded_client_query(
    mut query: ClientQuery,
    bucket: usize,
) -> Result<Vec<u8>, P2pTransportError> {
    let unpadded = query.encode()?;
    if bucket == 0 {
        return Ok(unpadded);
    }
    let packet_length = 12_usize
        .checked_add(unpadded.len())
        .ok_or(P2pTransportError::ResponseLimit)?;
    let padding = (bucket - packet_length % bucket) % bucket;
    if padding > MAX_OUTER_PADDING_SIZE {
        return Err(P2pTransportError::InvalidLimits);
    }
    query.padding = vec![0; padding];
    Ok(query.encode()?)
}

fn open_odoh_response(
    response: &OdnsPacket,
    context: QueryContext,
) -> Result<Vec<u8>, P2pTransportError> {
    match response.opcode {
        OdohOpcode::ClientResponse => {
            let response = OdohResponseBody::decode(&response.body)?;
            Ok(context.open_response(&response.message)?)
        }
        OdohOpcode::Error => {
            let error = OdohErrorBody::decode(&response.body)?;
            Err(P2pTransportError::OdohStatus(error.status))
        }
        actual => Err(P2pTransportError::UnexpectedOdohOpcode(actual)),
    }
}

fn check_lifecycle(
    cancellation: &CancellationToken,
    now: u64,
    deadline: u64,
) -> Result<(), P2pTransportError> {
    if cancellation.is_cancelled() {
        Err(P2pTransportError::Cancelled)
    } else if now > deadline {
        Err(P2pTransportError::DeadlineExpired)
    } else {
        Ok(())
    }
}

fn check_response_boundary(
    cancellation: &CancellationToken,
    expected_peer: PeerIdentity,
    response: &ExperimentalResponse,
    deadline: u64,
    maximum: usize,
) -> Result<(), P2pTransportError> {
    if cancellation.is_cancelled() {
        return Err(P2pTransportError::Cancelled);
    }
    if response.completed_at > deadline {
        return Err(P2pTransportError::DeadlineExpired);
    }
    if response.authenticated_peer != expected_peer {
        return Err(P2pTransportError::PeerIdentityMismatch);
    }
    if response.payload.is_empty() || response.payload.len() > maximum {
        return Err(P2pTransportError::ResponseLimit);
    }
    Ok(())
}

fn admit_dns(
    query: &Query,
    wire: Vec<u8>,
    maximum: usize,
    identities: GatewayIdentities,
) -> Result<AdmittedDnsResponse, P2pTransportError> {
    if wire.is_empty() || wire.len() > maximum {
        return Err(P2pTransportError::ResponseLimit);
    }
    let mut limits = ParseLimits::requester();
    limits.max_message_len = maximum;
    let message = Message::parse_with_limits(&wire, limits)?;
    query.correlate(&message)?;
    Ok(AdmittedDnsResponse {
        wire,
        message,
        identities,
    })
}

/// Authenticated peer, protocol, DNS, deadline, or resource-bound failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum P2pTransportError {
    /// A configured bound is zero, excessive, or not a valid bucket.
    #[error("invalid experimental P2P requester limits")]
    InvalidLimits,
    /// The compressed Brontide identity is not a secp256k1 public key.
    #[error("invalid Brontide peer identity")]
    InvalidPeerIdentity,
    /// Experimental peer admission or registry negotiation failed.
    #[error("experimental peer admission failed: {0}")]
    PeerAdmission(#[from] PeerProtocolError),
    /// Negotiated registry fields are internally invalid.
    #[error("experimental peer supplied an invalid negotiated registry")]
    InvalidNegotiatedRegistry,
    /// HIP-76 payload encoding or decoding failed.
    #[error("HIP-76 DNS Relay protocol failed: {0}")]
    DnsRelayProtocol(#[from] DnsRelayProtocolError),
    /// HIP-77 or RFC 9230 processing failed.
    #[error("HIP-77 ODoH protocol failed: {0}")]
    OdohProtocol(#[from] OdohProtocolError),
    /// DNS construction, parsing, or exact correlation failed.
    #[error("P2P DNS response failed local correlation: {0}")]
    DnsWire(#[from] hns_dns_wire::Error),
    /// Platform adapter failure.
    #[error(transparent)]
    Adapter(#[from] AdapterFailure),
    /// The signed target record has no configuration at the selected index.
    #[error("signed ODoH target record has no selected configuration")]
    MissingOdohConfiguration,
    /// The signed target configuration is no longer current.
    #[error("signed ODoH target configuration expired")]
    ExpiredOdohTarget,
    /// Proxy and target are the same authenticated identity.
    #[error("ODoH proxy and target identities must differ")]
    ProxyTargetCollision,
    /// Adapter returned another authenticated Brontide peer.
    #[error("response arrived from a different authenticated peer")]
    PeerIdentityMismatch,
    /// Semantic response packet differs from the request protocol.
    #[error("unexpected experimental packet {actual}; expected {expected}")]
    UnexpectedPacket {
        /// Required packet assignment.
        expected: PacketType,
        /// Actual packet assignment.
        actual: PacketType,
    },
    /// ODoH response carried an invalid state-machine opcode.
    #[error("unexpected ODoH response opcode {0:?}")]
    UnexpectedOdohOpcode(OdohOpcode),
    /// Response request ID does not equal the local outstanding ID.
    #[error("experimental P2P response request ID mismatch")]
    RequestIdMismatch,
    /// This requester's independent ID space was exhausted.
    #[error("experimental P2P request ID space exhausted")]
    RequestIdExhausted,
    /// Encoded request exceeds the peer's negotiated receive bound.
    #[error("experimental request exceeds the negotiated peer bound")]
    NegotiatedRequestLimit,
    /// HIP-76 peer returned a defined error.
    #[error("HIP-76 relay returned {0:?}")]
    DnsRelayStatus(DnsRelayStatus),
    /// HIP-77 proxy/target returned a defined error.
    #[error("HIP-77 ODoH path returned {0:?}")]
    OdohStatus(OdohStatus),
    /// Response is empty or exceeds an allocation bound.
    #[error("experimental P2P response exceeds its bound")]
    ResponseLimit,
    /// Platform lifecycle cancelled the request.
    #[error("experimental P2P request cancelled")]
    Cancelled,
    /// Caller or adapter crossed the exact request deadline.
    #[error("experimental P2P request deadline expired")]
    DeadlineExpired,
}

impl P2pTransportError {
    /// Fail-closed gateway classification for this transport error.
    #[must_use]
    pub const fn gateway_failure(&self) -> TransportFailure {
        match self {
            Self::Adapter(AdapterFailure::Unreachable)
            | Self::DnsRelayStatus(DnsRelayStatus::Busy | DnsRelayStatus::ResolverUnavailable)
            | Self::OdohStatus(
                OdohStatus::Busy | OdohStatus::TargetUnreachable | OdohStatus::RateLimited,
            ) => TransportFailure::Unreachable,
            Self::Adapter(AdapterFailure::Timeout)
            | Self::DeadlineExpired
            | Self::DnsRelayStatus(DnsRelayStatus::Timeout)
            | Self::OdohStatus(OdohStatus::TargetTimeout) => TransportFailure::Timeout,
            Self::Adapter(AdapterFailure::Unsupported)
            | Self::NegotiatedRequestLimit
            | Self::DnsRelayStatus(DnsRelayStatus::Unsupported)
            | Self::OdohStatus(OdohStatus::Unsupported) => TransportFailure::Unsupported,
            Self::Adapter(AdapterFailure::AuthenticationFailed)
            | Self::InvalidPeerIdentity
            | Self::PeerAdmission(_)
            | Self::InvalidNegotiatedRegistry
            | Self::OdohProtocol(OdohProtocolError::InvalidSignature)
            | Self::ExpiredOdohTarget
            | Self::ProxyTargetCollision
            | Self::PeerIdentityMismatch => TransportFailure::AuthenticationFailed,
            Self::Adapter(AdapterFailure::Cancelled)
            | Self::Cancelled
            | Self::OdohStatus(OdohStatus::Cancelled) => TransportFailure::Cancelled,
            _ => TransportFailure::Malformed,
        }
    }

    /// Consume into the gateway's failed adapter result.
    #[must_use]
    pub fn into_gateway_outcome(self) -> AttemptOutcome {
        AttemptOutcome::Failure(self.gateway_failure())
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests fail immediately on deterministic in-memory protocol fixtures"
)]
mod tests {
    use std::net::SocketAddr;

    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    use hns_dns_wire::{Flags, Header, Name, Question, RecordType};
    use hns_odoh_protocol::config::encode_config_list;
    use hns_odoh_protocol::{ClientQuery, open_query};
    use hns_p2p_experimental::{
        DENUO_EXTENSION_SERVICE, DNS_RELAY_SERVICE, ExperimentalWireProfile, Network, ODOH_SERVICE,
        ServiceMask,
    };
    use hns_primitives::RegistryFingerprint;
    use hpke::kem::X25519HkdfSha256;
    use hpke::{Kem as _, Serializable as _};
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};

    use super::*;

    const NETWORK_MAGIC: u32 = 0xae38_95cf;
    const NOW: u64 = 1_700_000_001;
    const DEADLINE: u64 = NOW + 5;

    fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).unwrap();
        for part in parts {
            hasher.update(part);
        }
        let mut output = [0_u8; 32];
        hasher.finalize_variable(&mut output).unwrap();
        output
    }

    fn secp_identity(secret: u8) -> (SigningKey, PeerIdentity) {
        let signing = SigningKey::from_bytes((&[secret; 32]).into()).unwrap();
        let encoded = signing.verifying_key().to_encoded_point(true);
        (
            signing,
            PeerIdentity::new(encoded.as_bytes().try_into().unwrap()).unwrap(),
        )
    }

    fn authenticated_peer_with_max(
        identity: PeerIdentity,
        maximum_send_size: u32,
    ) -> AuthenticatedPeer {
        let fingerprint = RegistryFingerprint::new([0x42; 32]);
        let genesis = [0x24; 32];
        let services = ServiceMask::default()
            .with(DENUO_EXTENSION_SERVICE)
            .with(DNS_RELAY_SERVICE)
            .with(ODOH_SERVICE);
        let state = ExperimentalPeerState::new(
            ExperimentalWireProfile::DenuoV1,
            Network::Regtest,
            genesis,
            fingerprint,
            services,
        );
        let negotiated = NegotiatedRegistry {
            fingerprint,
            registry_version: 1,
            protocols: Vec::new(),
            maximum_send_size,
            maximum_live_requests: 8,
            network: Network::Regtest,
            genesis_hash: genesis,
            feature_flags: 0,
        };
        AuthenticatedPeer::bind(identity, state, negotiated).unwrap()
    }

    fn authenticated_peer(identity: PeerIdentity) -> AuthenticatedPeer {
        authenticated_peer_with_max(identity, u32::try_from(MAX_ODOH_PACKET_SIZE).unwrap())
    }

    fn query() -> Query {
        Query::new(
            0x1234,
            Name::from_ascii("_443._tcp.alpha.").unwrap(),
            RecordType::Tlsa,
        )
        .unwrap()
    }

    fn response(query: &Query) -> Vec<u8> {
        Message {
            header: Header {
                id: query.id,
                flags: Flags::from_bits(0x8400),
                question_count: 1,
                answer_count: 0,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![Question {
                name: query.question.name.clone(),
                record_type: query.question.record_type,
                class: query.question.class,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode(MAX_DNS_RESPONSE_BYTES)
        .unwrap()
    }

    struct RelayAdapter {
        relay: PeerIdentity,
        response_peer: PeerIdentity,
        wrong_id: bool,
        wrong_dns_id: bool,
    }

    impl ExperimentalExchange for RelayAdapter {
        fn exchange(
            &mut self,
            request: ExperimentalRequest<'_>,
        ) -> Result<ExperimentalResponse, AdapterFailure> {
            assert_eq!(request.peer, self.relay);
            assert_eq!(request.packet, DNS_RELAY_REQUEST_PACKET);
            let request = GetDnsRelay::decode(request.payload).unwrap();
            let query = Query::parse(&request.query, ParseLimits::requester()).unwrap();
            let mut response_wire = response(&query);
            if self.wrong_dns_id {
                response_wire[1] ^= 1;
            }
            let response = DnsRelay::new(
                request.request_id + u64::from(self.wrong_id),
                DnsRelayStatus::Ok,
                response_wire,
            )
            .unwrap()
            .encode()
            .unwrap();
            Ok(ExperimentalResponse {
                authenticated_peer: self.response_peer,
                packet: DNS_RELAY_RESPONSE_PACKET,
                payload: response,
                completed_at: NOW + 1,
            })
        }
    }

    #[test]
    fn relay_requires_authenticated_packet_and_dns_correlation() {
        let (_, relay_identity) = secp_identity(2);
        let mut relay = authenticated_peer(relay_identity);
        let mut adapter = RelayAdapter {
            relay: relay_identity,
            response_peer: relay_identity,
            wrong_id: false,
            wrong_dns_id: false,
        };
        let mut requester =
            DnsRelayRequester::new(NonZeroU64::new(7).unwrap(), RequesterLimits::default())
                .unwrap();
        let admitted = requester
            .exchange(
                &mut adapter,
                &mut relay,
                &query(),
                &CancellationToken::default(),
                NOW,
                DEADLINE,
            )
            .unwrap();
        assert_eq!(admitted.message().header.id, 0x1234);
        assert_eq!(
            admitted.identities().peer.as_deref(),
            Some(relay_identity.gateway_label().as_str())
        );

        adapter.wrong_id = true;
        assert!(matches!(
            requester.exchange(
                &mut adapter,
                &mut relay,
                &query(),
                &CancellationToken::default(),
                NOW,
                DEADLINE,
            ),
            Err(P2pTransportError::RequestIdMismatch)
        ));

        adapter.wrong_id = false;
        adapter.response_peer = secp_identity(4).1;
        assert!(matches!(
            requester.exchange(
                &mut adapter,
                &mut relay,
                &query(),
                &CancellationToken::default(),
                NOW,
                DEADLINE,
            ),
            Err(P2pTransportError::PeerIdentityMismatch)
        ));

        adapter.response_peer = relay_identity;
        adapter.wrong_dns_id = true;
        assert!(matches!(
            requester.exchange(
                &mut adapter,
                &mut relay,
                &query(),
                &CancellationToken::default(),
                NOW,
                DEADLINE,
            ),
            Err(P2pTransportError::DnsWire(hns_dns_wire::Error::IdMismatch))
        ));
    }

    fn signed_target_record(
        signing: &SigningKey,
        locator: &DirectTargetLocator,
        configuration: &OdohConfig,
    ) -> Vec<u8> {
        let configurations = encode_config_list(std::slice::from_ref(configuration)).unwrap();
        let mut raw = Vec::new();
        raw.push(1);
        raw.extend_from_slice(&NETWORK_MAGIC.to_le_bytes());
        raw.extend_from_slice(&locator.encode());
        raw.extend_from_slice(&7_u64.to_le_bytes());
        raw.extend_from_slice(&(NOW - 1).to_le_bytes());
        raw.extend_from_slice(&(NOW + 3_600).to_le_bytes());
        raw.extend_from_slice(&u16::try_from(configurations.len()).unwrap().to_le_bytes());
        raw.extend_from_slice(&configurations);
        let digest = blake2b_256(&[b"HNS-P2P-ODOH-CONFIG-V1\0", &raw]);
        let signature: Signature = signing.sign_prehash(&digest).unwrap();
        let signature = signature.to_der();
        raw.push(u8::try_from(signature.as_bytes().len()).unwrap());
        raw.extend_from_slice(signature.as_bytes());
        raw
    }

    struct OdohAdapter {
        proxy: PeerIdentity,
        target: VerifiedOdohTarget,
        private_key: [u8; 32],
        plaintext_name: Vec<u8>,
        mutate_response: bool,
        completed_at: u64,
    }

    impl ExperimentalExchange for OdohAdapter {
        fn exchange(
            &mut self,
            request: ExperimentalRequest<'_>,
        ) -> Result<ExperimentalResponse, AdapterFailure> {
            assert_eq!(request.peer, self.proxy);
            assert_eq!(request.packet, ODOH_PACKET);
            assert!(
                !request
                    .payload
                    .windows(self.plaintext_name.len())
                    .any(|window| window == self.plaintext_name)
            );
            assert_eq!(request.payload.len() % DEFAULT_ODOH_PADDING_BUCKET, 0);

            let outer = OdnsPacket::decode(request.payload).unwrap();
            assert_eq!(outer.opcode, OdohOpcode::ClientQuery);
            let client = ClientQuery::decode(&outer.body, true).unwrap();
            assert_eq!(client.locator, *self.target.locator());
            assert_eq!(client.config_id, self.target.record_id());
            let opened = open_query(
                &self.private_key,
                &self.target.configuration,
                &client.message,
            )
            .unwrap();
            let opened_query = Query::parse(opened.dns(), ParseLimits::requester()).unwrap();
            let message = opened
                .seal_response(&response(&opened_query), [9; 16], 128)
                .unwrap();
            let body = OdohResponseBody {
                message,
                padding: Vec::new(),
            }
            .encode()
            .unwrap();
            let mut payload = OdnsPacket::new(OdohOpcode::ClientResponse, outer.request_id, body)
                .unwrap()
                .encode()
                .unwrap();
            if self.mutate_response {
                *payload.last_mut().unwrap() ^= 1;
            }
            Ok(ExperimentalResponse {
                authenticated_peer: self.proxy,
                packet: ODOH_PACKET,
                payload,
                completed_at: self.completed_at,
            })
        }
    }

    fn odoh_fixture_for(
        proxy_secret: u8,
        target_secret: u8,
    ) -> (
        AuthenticatedPeer,
        VerifiedOdohTarget,
        [u8; 32],
        PeerIdentity,
    ) {
        let (_, proxy_identity) = secp_identity(proxy_secret);
        let (target_signing, target_identity) = secp_identity(target_secret);
        let locator = DirectTargetLocator::new(
            target_identity.as_bytes(),
            "127.0.0.1:14039".parse::<SocketAddr>().unwrap(),
            true,
        )
        .unwrap();
        let (private, public) = X25519HkdfSha256::gen_keypair();
        let configuration = OdohConfig {
            public_key: public.to_bytes().as_slice().try_into().unwrap(),
        };
        let private_key = private.to_bytes().as_slice().try_into().unwrap();
        let record = signed_target_record(&target_signing, &locator, &configuration);
        let target =
            VerifiedOdohTarget::decode(&record, &locator, NETWORK_MAGIC, NOW, true, 0).unwrap();
        (
            authenticated_peer(proxy_identity),
            target,
            private_key,
            proxy_identity,
        )
    }

    fn odoh_fixture() -> (
        AuthenticatedPeer,
        VerifiedOdohTarget,
        [u8; 32],
        PeerIdentity,
    ) {
        odoh_fixture_for(2, 3)
    }

    #[test]
    fn odoh_hides_qname_and_opens_only_after_distinct_authenticated_hops() {
        let (mut proxy, target, private_key, proxy_identity) = odoh_fixture();
        let mut adapter = OdohAdapter {
            proxy: proxy_identity,
            target: target.clone(),
            private_key,
            plaintext_name: b"_443\x04_tcp\x05alpha".to_vec(),
            mutate_response: false,
            completed_at: NOW + 1,
        };
        let mut requester =
            OdohRequester::new(NonZeroU64::new(9).unwrap(), RequesterLimits::default()).unwrap();
        let admitted = requester
            .exchange(
                &mut adapter,
                &mut proxy,
                &target,
                &query(),
                &CancellationToken::default(),
                NOW,
                DEADLINE,
            )
            .unwrap();
        assert_eq!(admitted.message().header.id, 0x1234);
        assert_ne!(admitted.identities().proxy, admitted.identities().target);

        adapter.mutate_response = true;
        let mutation_error = requester
            .exchange(
                &mut adapter,
                &mut proxy,
                &target,
                &query(),
                &CancellationToken::default(),
                NOW,
                DEADLINE,
            )
            .unwrap_err();
        assert_eq!(
            mutation_error.gateway_failure(),
            TransportFailure::Malformed
        );
    }

    #[test]
    fn wrong_peer_deadline_collision_and_statuses_fail_closed() {
        let (mut proxy, target, private_key, proxy_identity) = odoh_fixture();
        let mut requester =
            OdohRequester::new(NonZeroU64::new(1).unwrap(), RequesterLimits::default()).unwrap();
        let mut adapter = OdohAdapter {
            proxy: proxy_identity,
            target: target.clone(),
            private_key,
            plaintext_name: b"_443\x04_tcp\x05alpha".to_vec(),
            mutate_response: false,
            completed_at: NOW + 1,
        };
        assert!(matches!(
            requester.exchange(
                &mut adapter,
                &mut proxy,
                &target,
                &query(),
                &CancellationToken::default(),
                DEADLINE + 1,
                DEADLINE,
            ),
            Err(P2pTransportError::DeadlineExpired)
        ));

        let failure = P2pTransportError::OdohStatus(OdohStatus::TargetTimeout);
        assert_eq!(failure.gateway_failure(), TransportFailure::Timeout);
        let failure = P2pTransportError::DnsRelayStatus(DnsRelayStatus::InvalidQuery);
        assert_eq!(failure.gateway_failure(), TransportFailure::Malformed);
    }

    #[test]
    fn odoh_rejects_same_hop_and_expired_target_before_exchange() {
        let (mut proxy, target, private_key, proxy_identity) = odoh_fixture_for(2, 2);
        let mut adapter = OdohAdapter {
            proxy: proxy_identity,
            target: target.clone(),
            private_key,
            plaintext_name: b"_443\x04_tcp\x05alpha".to_vec(),
            mutate_response: false,
            completed_at: NOW + 1,
        };
        let mut requester =
            OdohRequester::new(NonZeroU64::new(1).unwrap(), RequesterLimits::default()).unwrap();
        assert!(matches!(
            requester.exchange(
                &mut adapter,
                &mut proxy,
                &target,
                &query(),
                &CancellationToken::default(),
                NOW,
                DEADLINE,
            ),
            Err(P2pTransportError::ProxyTargetCollision)
        ));

        let (mut proxy, target, private_key, proxy_identity) = odoh_fixture();
        let mut adapter = OdohAdapter {
            proxy: proxy_identity,
            target: target.clone(),
            private_key,
            plaintext_name: b"_443\x04_tcp\x05alpha".to_vec(),
            mutate_response: false,
            completed_at: NOW + 1,
        };
        assert!(matches!(
            requester.exchange(
                &mut adapter,
                &mut proxy,
                &target,
                &query(),
                &CancellationToken::default(),
                target.expires_at(),
                target.expires_at() + 1,
            ),
            Err(P2pTransportError::ExpiredOdohTarget)
        ));

        adapter.completed_at = target.expires_at();
        assert!(matches!(
            requester.exchange(
                &mut adapter,
                &mut proxy,
                &target,
                &query(),
                &CancellationToken::default(),
                NOW,
                target.expires_at(),
            ),
            Err(P2pTransportError::ExpiredOdohTarget)
        ));
    }

    #[test]
    fn request_id_space_fails_closed_after_u64_max() {
        let mut request_ids = RequestIds::new(NonZeroU64::new(u64::MAX).unwrap());
        assert_eq!(request_ids.take().unwrap(), u64::MAX);
        assert!(matches!(
            request_ids.take(),
            Err(P2pTransportError::RequestIdExhausted)
        ));
    }

    #[test]
    fn negotiated_peer_request_bound_is_enforced_before_adapter_io() {
        let (_, relay_identity) = secp_identity(2);
        let mut relay = authenticated_peer_with_max(relay_identity, 1);
        let mut adapter = RelayAdapter {
            relay: relay_identity,
            response_peer: relay_identity,
            wrong_id: false,
            wrong_dns_id: false,
        };
        let mut requester =
            DnsRelayRequester::new(NonZeroU64::new(1).unwrap(), RequesterLimits::default())
                .unwrap();
        let error = requester
            .exchange(
                &mut adapter,
                &mut relay,
                &query(),
                &CancellationToken::default(),
                NOW,
                DEADLINE,
            )
            .unwrap_err();
        assert!(matches!(&error, P2pTransportError::NegotiatedRequestLimit));
        assert_eq!(error.gateway_failure(), TransportFailure::Unsupported);
    }
}
