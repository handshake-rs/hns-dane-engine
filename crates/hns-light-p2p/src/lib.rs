//! Bounded standard Handshake P2P session for light clients.
//!
//! The state machine is runtime independent: socket adapters exchange
//! `hns-p2p-wire` frames and provide an explicit clock. Only standard HSD
//! version/verack, ping/pong, headers, and name-proof traffic is authoritative
//! here. Experimental HIP sessions remain separate.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "HNS, P2P, HSD, and HIP are protocol names"
)]

use hns_header_consensus::Header;
use hns_p2p_wire::{
    Frame, GetProofPacket, LocatorPacket, NetworkMagic, Packet, PacketType, ProofPacket,
    RejectPacket, SERVICE_NETWORK, VersionPacket, WireError,
};
use hns_primitives::{BlockHash, NameHash, TreeRoot};
use thiserror::Error;

/// Default complete version/verack deadline.
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;
/// Default header/proof/ping response deadline.
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 15;
/// Default maximum peer wall-clock skew.
pub const DEFAULT_MAX_CLOCK_SKEW_SECONDS: u64 = 2 * 60 * 60;

/// Standard-peer session bounds and admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerConfig {
    /// Selected Handshake wire network.
    pub network: NetworkMagic,
    /// Required standard service bits.
    pub required_services: u64,
    /// Complete handshake deadline.
    pub handshake_timeout_seconds: u64,
    /// Per-request deadline.
    pub request_timeout_seconds: u64,
    /// Maximum version timestamp skew.
    pub max_clock_skew_seconds: u64,
}

impl PeerConfig {
    /// Secure defaults for one network.
    #[must_use]
    pub const fn for_network(network: NetworkMagic) -> Self {
        Self {
            network,
            required_services: SERVICE_NETWORK,
            handshake_timeout_seconds: DEFAULT_HANDSHAKE_TIMEOUT_SECONDS,
            request_timeout_seconds: DEFAULT_REQUEST_TIMEOUT_SECONDS,
            max_clock_skew_seconds: DEFAULT_MAX_CLOCK_SKEW_SECONDS,
        }
    }

    fn validate(self) -> Result<Self, PeerError> {
        if self.required_services & SERVICE_NETWORK == 0
            || self.handshake_timeout_seconds == 0
            || self.handshake_timeout_seconds > 60
            || self.request_timeout_seconds == 0
            || self.request_timeout_seconds > 300
            || self.max_clock_skew_seconds > 24 * 60 * 60
        {
            return Err(PeerError::InvalidConfig);
        }
        Ok(self)
    }
}

/// Peer session phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerState {
    /// Local version sent; remote version required.
    AwaitingVersion,
    /// Remote version accepted and local verack sent.
    AwaitingVerack,
    /// Standard requests may be issued.
    Ready,
    /// Session is permanently closed.
    Closed,
}

/// Admitted remote version metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerMetadata {
    /// Negotiated HSD protocol version.
    pub version: u32,
    /// Advertised standard services.
    pub services: u64,
    /// Remote Unix timestamp.
    pub time: u64,
    /// Remote user agent.
    pub agent: String,
    /// Advertised best height.
    pub height: u32,
}

/// Response-bearing request category.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestKind {
    /// Standard `getheaders`.
    Headers = 0,
    /// Standard `getproof`.
    Proof = 1,
    /// Standard ping.
    Ping = 2,
}

/// Requests that exceeded their explicit deadline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExpiredRequests {
    /// Header request expired.
    pub headers: bool,
    /// Name-proof request expired.
    pub proof: bool,
    /// Ping expired.
    pub ping: bool,
}

impl ExpiredRequests {
    /// Whether at least one request expired.
    #[must_use]
    pub const fn any(self) -> bool {
        self.headers || self.proof || self.ping
    }
}

/// Event emitted by one admitted inbound frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerEvent {
    /// Send this standard frame to the peer.
    Send(Frame),
    /// Version/verack completed.
    Ready(PeerMetadata),
    /// Correlated bounded header batch.
    Headers(Vec<Header>),
    /// Correlated exact-root/key Urkel proof.
    Proof(ProofPacket),
    /// Matching pong arrived.
    Pong([u8; 8]),
    /// Peer rejected a request.
    Rejected(RejectPacket),
    /// Ordinary packet was safely outside the light-client flow.
    Ignored(PacketType),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pending {
    deadline: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingProof {
    root: TreeRoot,
    key: NameHash,
    deadline: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingPing {
    nonce: [u8; 8],
    deadline: u64,
}

/// One bounded standard HSD peer session.
#[derive(Clone, Debug)]
pub struct PeerSession {
    config: PeerConfig,
    state: PeerState,
    local_nonce: [u8; 8],
    handshake_deadline: u64,
    metadata: Option<PeerMetadata>,
    pending_headers: Option<Pending>,
    pending_proof: Option<PendingProof>,
    pending_ping: Option<PendingPing>,
}

impl PeerSession {
    /// Start a session and return the local version frame.
    pub fn start(
        config: PeerConfig,
        local_version: &VersionPacket,
        now: u64,
    ) -> Result<(Self, Frame), PeerError> {
        let config = config.validate()?;
        if local_version.nonce == [0; 8]
            || local_version.version < hns_p2p_wire::MIN_PROTOCOL_VERSION
            || local_version.time.abs_diff(now) > config.max_clock_skew_seconds
        {
            return Err(PeerError::InvalidLocalVersion);
        }
        let handshake_deadline = now
            .checked_add(config.handshake_timeout_seconds)
            .ok_or(PeerError::TimeOverflow)?;
        let frame = Frame::from_packet(&Packet::Version(local_version.clone()))?;
        Ok((
            Self {
                config,
                state: PeerState::AwaitingVersion,
                local_nonce: local_version.nonce,
                handshake_deadline,
                metadata: None,
                pending_headers: None,
                pending_proof: None,
                pending_ping: None,
            },
            frame,
        ))
    }

    /// Selected wire network for the adapter's frame decoder.
    #[must_use]
    pub const fn network(&self) -> NetworkMagic {
        self.config.network
    }

    /// Current session phase.
    #[must_use]
    pub const fn state(&self) -> PeerState {
        self.state
    }

    /// Admitted remote metadata after version.
    #[must_use]
    pub const fn metadata(&self) -> Option<&PeerMetadata> {
        self.metadata.as_ref()
    }

    /// Close permanently and revoke all outstanding requests.
    pub fn close(&mut self) {
        self.state = PeerState::Closed;
        self.pending_headers = None;
        self.pending_proof = None;
        self.pending_ping = None;
    }

    /// Admit one strict frame from the selected-network decoder.
    pub fn handle_frame(&mut self, frame: &Frame, now: u64) -> Result<PeerEvent, PeerError> {
        if self.state == PeerState::Closed {
            return Err(PeerError::Closed);
        }
        if self.state != PeerState::Ready && now > self.handshake_deadline {
            self.close();
            return Err(PeerError::HandshakeTimeout);
        }
        let packet = frame.decode_packet()?;
        match self.state {
            PeerState::AwaitingVersion => self.handle_version(packet, now),
            PeerState::AwaitingVerack => {
                if packet != Packet::Verack {
                    return Err(PeerError::ExpectedVerack);
                }
                self.state = PeerState::Ready;
                Ok(PeerEvent::Ready(
                    self.metadata.clone().ok_or(PeerError::InternalInvariant)?,
                ))
            }
            PeerState::Ready => self.handle_ready(packet, now),
            PeerState::Closed => Err(PeerError::Closed),
        }
    }

    /// Build one bounded `getheaders`; only one may be outstanding.
    pub fn request_headers(
        &mut self,
        locator: Vec<BlockHash>,
        stop: BlockHash,
        now: u64,
    ) -> Result<Frame, PeerError> {
        self.require_ready()?;
        if locator.is_empty() {
            return Err(PeerError::EmptyLocator);
        }
        if self.pending_headers.is_some() {
            return Err(PeerError::DuplicateRequest(RequestKind::Headers));
        }
        let deadline = self.request_deadline(now)?;
        let frame = Frame::from_packet(&Packet::GetHeaders(LocatorPacket { locator, stop }))?;
        self.pending_headers = Some(Pending { deadline });
        Ok(frame)
    }

    /// Build one exact-root/key standard name-proof request.
    pub fn request_proof(
        &mut self,
        root: TreeRoot,
        key: NameHash,
        now: u64,
    ) -> Result<Frame, PeerError> {
        self.require_ready()?;
        if self.pending_proof.is_some() {
            return Err(PeerError::DuplicateRequest(RequestKind::Proof));
        }
        let deadline = self.request_deadline(now)?;
        let frame = Frame::from_packet(&Packet::GetProof(GetProofPacket { root, key }))?;
        self.pending_proof = Some(PendingProof {
            root,
            key,
            deadline,
        });
        Ok(frame)
    }

    /// Build one ping; only one may be outstanding.
    pub fn ping(&mut self, nonce: [u8; 8], now: u64) -> Result<Frame, PeerError> {
        self.require_ready()?;
        if nonce == [0; 8] {
            return Err(PeerError::ZeroPingNonce);
        }
        if self.pending_ping.is_some() {
            return Err(PeerError::DuplicateRequest(RequestKind::Ping));
        }
        let deadline = self.request_deadline(now)?;
        let frame = Frame::from_packet(&Packet::Ping(nonce))?;
        self.pending_ping = Some(PendingPing { nonce, deadline });
        Ok(frame)
    }

    /// Expire all overdue work and return name-free timeout flags.
    pub fn expire(&mut self, now: u64) -> Result<ExpiredRequests, PeerError> {
        if self.state != PeerState::Ready {
            if self.state != PeerState::Closed && now > self.handshake_deadline {
                self.close();
                return Err(PeerError::HandshakeTimeout);
            }
            return Ok(ExpiredRequests::default());
        }
        let expired = ExpiredRequests {
            headers: self
                .pending_headers
                .is_some_and(|pending| now > pending.deadline),
            proof: self
                .pending_proof
                .is_some_and(|pending| now > pending.deadline),
            ping: self
                .pending_ping
                .is_some_and(|pending| now > pending.deadline),
        };
        if expired.headers {
            self.pending_headers = None;
        }
        if expired.proof {
            self.pending_proof = None;
        }
        if expired.ping {
            self.pending_ping = None;
        }
        Ok(expired)
    }

    fn handle_version(&mut self, packet: Packet, now: u64) -> Result<PeerEvent, PeerError> {
        let Packet::Version(version) = packet else {
            return Err(PeerError::ExpectedVersion);
        };
        if version.version < hns_p2p_wire::MIN_PROTOCOL_VERSION {
            return Err(PeerError::ObsoleteVersion);
        }
        if version.services & self.config.required_services != self.config.required_services {
            return Err(PeerError::MissingService);
        }
        if version.nonce == self.local_nonce {
            return Err(PeerError::SelfConnection);
        }
        if version.time.abs_diff(now) > self.config.max_clock_skew_seconds {
            return Err(PeerError::ClockSkew);
        }
        self.metadata = Some(PeerMetadata {
            version: version.version.min(hns_p2p_wire::PROTOCOL_VERSION),
            services: version.services,
            time: version.time,
            agent: version.agent,
            height: version.height,
        });
        self.state = PeerState::AwaitingVerack;
        Ok(PeerEvent::Send(Frame::from_packet(&Packet::Verack)?))
    }

    fn handle_ready(&mut self, packet: Packet, now: u64) -> Result<PeerEvent, PeerError> {
        match packet {
            Packet::Version(_) | Packet::Verack => Err(PeerError::DuplicateHandshake),
            Packet::Ping(nonce) => Ok(PeerEvent::Send(Frame::from_packet(&Packet::Pong(nonce))?)),
            Packet::Pong(nonce) => {
                let pending = self.pending_ping.ok_or(PeerError::UnsolicitedPong)?;
                if now > pending.deadline {
                    self.pending_ping = None;
                    return Err(PeerError::RequestTimeout(RequestKind::Ping));
                }
                if pending.nonce != nonce {
                    return Err(PeerError::WrongPong);
                }
                self.pending_ping = None;
                Ok(PeerEvent::Pong(nonce))
            }
            Packet::Headers(headers) => {
                let pending = self
                    .pending_headers
                    .take()
                    .ok_or(PeerError::UnsolicitedHeaders)?;
                if now > pending.deadline {
                    return Err(PeerError::RequestTimeout(RequestKind::Headers));
                }
                Ok(PeerEvent::Headers(headers))
            }
            Packet::Proof(proof) => {
                let pending = self
                    .pending_proof
                    .take()
                    .ok_or(PeerError::UnsolicitedProof)?;
                if now > pending.deadline {
                    return Err(PeerError::RequestTimeout(RequestKind::Proof));
                }
                if proof.root != pending.root || proof.key != pending.key {
                    return Err(PeerError::WrongProof);
                }
                Ok(PeerEvent::Proof(proof))
            }
            Packet::Reject(reject) => Ok(PeerEvent::Rejected(reject)),
            packet => Ok(PeerEvent::Ignored(packet.packet_type())),
        }
    }

    fn require_ready(&self) -> Result<(), PeerError> {
        match self.state {
            PeerState::Ready => Ok(()),
            PeerState::Closed => Err(PeerError::Closed),
            PeerState::AwaitingVersion | PeerState::AwaitingVerack => Err(PeerError::NotReady),
        }
    }

    fn request_deadline(&self, now: u64) -> Result<u64, PeerError> {
        now.checked_add(self.config.request_timeout_seconds)
            .ok_or(PeerError::TimeOverflow)
    }
}

/// Standard peer handshake, correlation, or deadline failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PeerError {
    /// Canonical shared wire codec failed.
    #[error("standard Handshake wire failure: {0}")]
    Wire(#[from] WireError),
    /// Session configuration is zero, excessive, or omits NETWORK service.
    #[error("invalid light-peer configuration")]
    InvalidConfig,
    /// Local version has a zero nonce, obsolete version, or implausible timestamp.
    #[error("invalid local version packet")]
    InvalidLocalVersion,
    /// Clock/deadline arithmetic overflowed.
    #[error("peer deadline overflow")]
    TimeOverflow,
    /// Version/verack did not complete by its deadline.
    #[error("peer handshake timed out")]
    HandshakeTimeout,
    /// Version was required before this packet.
    #[error("expected remote version packet")]
    ExpectedVersion,
    /// Verack was required after remote version.
    #[error("expected remote verack packet")]
    ExpectedVerack,
    /// Remote protocol version is obsolete.
    #[error("remote Handshake protocol version is obsolete")]
    ObsoleteVersion,
    /// Remote omitted a required standard service.
    #[error("remote peer omitted a required service")]
    MissingService,
    /// Remote nonce identifies a self-connection.
    #[error("remote version nonce matches local nonce")]
    SelfConnection,
    /// Remote version timestamp exceeds configured skew.
    #[error("remote version timestamp exceeds clock-skew policy")]
    ClockSkew,
    /// Handshake packet repeated after readiness.
    #[error("duplicate version or verack")]
    DuplicateHandshake,
    /// Request was attempted before version/verack.
    #[error("peer session is not ready")]
    NotReady,
    /// Session has been closed.
    #[error("peer session is closed")]
    Closed,
    /// Block locator cannot be empty.
    #[error("header locator is empty")]
    EmptyLocator,
    /// A response-bearing request of this kind is already outstanding.
    #[error("duplicate outstanding {0:?} request")]
    DuplicateRequest(RequestKind),
    /// A response arrived after its exact request deadline.
    #[error("{0:?} response arrived after its request deadline")]
    RequestTimeout(RequestKind),
    /// Peer sent headers without an outstanding request.
    #[error("unsolicited headers packet")]
    UnsolicitedHeaders,
    /// Peer sent proof without an outstanding request.
    #[error("unsolicited proof packet")]
    UnsolicitedProof,
    /// Proof root or name key differs from the exact request.
    #[error("proof response does not match requested root and key")]
    WrongProof,
    /// Peer sent pong without an outstanding ping.
    #[error("unsolicited pong")]
    UnsolicitedPong,
    /// Pong nonce differs from the outstanding ping.
    #[error("pong nonce mismatch")]
    WrongPong,
    /// Zero ping nonce is not admitted.
    #[error("ping nonce must be nonzero")]
    ZeroPingNonce,
    /// Internal handshake metadata invariant failed.
    #[error("peer session internal invariant failed")]
    InternalInvariant,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid local peer fixtures"
)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use hns_p2p_wire::{NetAddress, Packet};

    use super::*;

    fn version(nonce: [u8; 8], now: u64) -> VersionPacket {
        VersionPacket {
            version: hns_p2p_wire::PROTOCOL_VERSION,
            services: SERVICE_NETWORK,
            time: now,
            remote: NetAddress::from_socket_addr(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12_038),
                now,
                SERVICE_NETWORK,
            ),
            nonce,
            agent: "/hns-light-p2p:test/".to_owned(),
            height: 100,
            no_relay: true,
        }
    }

    fn ready(now: u64) -> PeerSession {
        let (mut session, local) = PeerSession::start(
            PeerConfig::for_network(NetworkMagic::Regtest),
            &version([1; 8], now),
            now,
        )
        .unwrap();
        assert!(matches!(local.decode_packet().unwrap(), Packet::Version(_)));
        let remote = Frame::from_packet(&Packet::Version(version([2; 8], now))).unwrap();
        assert!(matches!(
            session.handle_frame(&remote, now).unwrap(),
            PeerEvent::Send(_)
        ));
        let verack = Frame::from_packet(&Packet::Verack).unwrap();
        assert!(matches!(
            session.handle_frame(&verack, now).unwrap(),
            PeerEvent::Ready(_)
        ));
        session
    }

    #[test]
    fn completes_standard_handshake_and_rejects_invalid_versions() {
        let now = 1_700_000_000;
        let session = ready(now);
        assert_eq!(session.state(), PeerState::Ready);
        assert_eq!(session.metadata().unwrap().height, 100);

        let mut local_light_client = version([9; 8], now);
        local_light_client.services = 0;
        assert!(
            PeerSession::start(
                PeerConfig::for_network(NetworkMagic::Mainnet),
                &local_light_client,
                now
            )
            .is_ok()
        );

        let (mut self_peer, _) = PeerSession::start(
            PeerConfig::for_network(NetworkMagic::Mainnet),
            &version([3; 8], now),
            now,
        )
        .unwrap();
        let frame = Frame::from_packet(&Packet::Version(version([3; 8], now))).unwrap();
        assert!(matches!(
            self_peer.handle_frame(&frame, now),
            Err(PeerError::SelfConnection)
        ));

        let (mut missing_service, _) = PeerSession::start(
            PeerConfig::for_network(NetworkMagic::Mainnet),
            &version([4; 8], now),
            now,
        )
        .unwrap();
        let mut remote = version([5; 8], now);
        remote.services = 0;
        let frame = Frame::from_packet(&Packet::Version(remote)).unwrap();
        assert!(matches!(
            missing_service.handle_frame(&frame, now),
            Err(PeerError::MissingService)
        ));
    }

    #[test]
    fn correlates_one_header_request_and_expires_duplicates() {
        let now = 1_700_000_000;
        let mut session = ready(now);
        let request = session
            .request_headers(vec![BlockHash::new([1; 32])], BlockHash::default(), now)
            .unwrap();
        assert!(matches!(
            request.decode_packet().unwrap(),
            Packet::GetHeaders(_)
        ));
        assert!(matches!(
            session.request_headers(vec![BlockHash::new([1; 32])], BlockHash::default(), now,),
            Err(PeerError::DuplicateRequest(RequestKind::Headers))
        ));
        let headers = Frame::from_packet(&Packet::Headers(Vec::new())).unwrap();
        assert_eq!(
            session.handle_frame(&headers, now).unwrap(),
            PeerEvent::Headers(Vec::new())
        );
        assert!(matches!(
            session.handle_frame(&headers, now),
            Err(PeerError::UnsolicitedHeaders)
        ));

        session
            .request_headers(vec![BlockHash::new([2; 32])], BlockHash::default(), now)
            .unwrap();
        let expired = session
            .expire(now + DEFAULT_REQUEST_TIMEOUT_SECONDS + 1)
            .unwrap();
        assert!(expired.headers);
        assert!(matches!(
            session.handle_frame(&headers, now + DEFAULT_REQUEST_TIMEOUT_SECONDS + 1),
            Err(PeerError::UnsolicitedHeaders)
        ));

        session
            .request_headers(vec![BlockHash::new([3; 32])], BlockHash::default(), now)
            .unwrap();
        assert!(matches!(
            session.handle_frame(&headers, now + DEFAULT_REQUEST_TIMEOUT_SECONDS + 1),
            Err(PeerError::RequestTimeout(RequestKind::Headers))
        ));
        assert!(matches!(
            session.handle_frame(&headers, now + DEFAULT_REQUEST_TIMEOUT_SECONDS + 1),
            Err(PeerError::UnsolicitedHeaders)
        ));
    }

    #[test]
    fn proof_root_key_and_ping_nonce_are_exactly_correlated() {
        let now = 1_700_000_000;
        let mut session = ready(now);
        let root = TreeRoot::new([7; 32]);
        let key = NameHash::new([8; 32]);
        session.request_proof(root, key, now).unwrap();

        let mut payload = Vec::new();
        payload.extend_from_slice(root.as_bytes());
        payload.extend_from_slice(NameHash::new([9; 32]).as_bytes());
        payload.extend_from_slice(&[0, 0, 0, 0]);
        let wrong = Frame::new(PacketType::Proof, payload).unwrap();
        assert!(matches!(
            session.handle_frame(&wrong, now),
            Err(PeerError::WrongProof)
        ));

        session.request_proof(root, key, now).unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(root.as_bytes());
        payload.extend_from_slice(key.as_bytes());
        payload.extend_from_slice(&[0, 0, 0, 0]);
        let proof = Frame::new(PacketType::Proof, payload).unwrap();
        assert!(matches!(
            session.handle_frame(&proof, now).unwrap(),
            PeerEvent::Proof(_)
        ));

        let request_frame = session.ping([4; 8], now).unwrap();
        assert!(matches!(
            request_frame.decode_packet().unwrap(),
            Packet::Ping(_)
        ));
        let wrong_pong = Frame::from_packet(&Packet::Pong([5; 8])).unwrap();
        assert!(matches!(
            session.handle_frame(&wrong_pong, now),
            Err(PeerError::WrongPong)
        ));
        let response_frame = Frame::from_packet(&Packet::Pong([4; 8])).unwrap();
        assert_eq!(
            session.handle_frame(&response_frame, now).unwrap(),
            PeerEvent::Pong([4; 8])
        );
    }

    #[test]
    fn answers_ping_and_times_out_incomplete_handshake() {
        let now = 1_700_000_000;
        let mut session = ready(now);
        let inbound = Frame::from_packet(&Packet::Ping([6; 8])).unwrap();
        let outbound = match session.handle_frame(&inbound, now).unwrap() {
            PeerEvent::Send(frame) => Some(frame),
            _ => None,
        }
        .unwrap();
        assert_eq!(outbound.decode_packet().unwrap(), Packet::Pong([6; 8]));

        let (mut incomplete, _) = PeerSession::start(
            PeerConfig::for_network(NetworkMagic::Regtest),
            &version([1; 8], now),
            now,
        )
        .unwrap();
        assert!(matches!(
            incomplete.expire(now + DEFAULT_HANDSHAKE_TIMEOUT_SECONDS + 1),
            Err(PeerError::HandshakeTimeout)
        ));
        assert_eq!(incomplete.state(), PeerState::Closed);
    }
}
