//! Proof-authorized direct authoritative DNS over UDP and TCP.
//!
//! Endpoints can only be derived from a [`VerifiedHnsResource`]. Mainnet and
//! testnet require globally routable committed glue on port 53. A nonstandard
//! loopback port is available only through an explicit regtest-fixture policy.
//! Queries are strict class-IN, DNSSEC-enabled, non-recursive messages.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "HNS and DNS protocol names are intentional"
)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use hns_covenants::hash_name;
use hns_dns_wire::{Message, ParseLimits, Query};
use hns_header_consensus::Network;
use hns_light_chain::{HnsAnchor, HnsResourceRecord, ResourceName, VerifiedHnsResource};
use hns_primitives::NameHash;
use thiserror::Error;

/// Standard authoritative DNS port.
pub const DNS_PORT: u16 = 53;
/// Maximum committed authoritative endpoints admitted from one resource.
pub const MAX_AUTHORITY_ENDPOINTS: usize = 64;

/// Port admission for committed authoritative endpoints.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AuthorityPortPolicy {
    /// Port 53 on all networks.
    #[default]
    StandardDns,
    /// Explicit nonstandard loopback port for controlled regtest fixtures.
    RegtestFixture(u16),
}

/// Direct DNS transport bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportLimits {
    /// Socket connect/read/write timeout.
    pub timeout: Duration,
    /// Maximum encoded query bytes.
    pub max_query_bytes: usize,
    /// Maximum accepted UDP/TCP response bytes.
    pub max_response_bytes: usize,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_query_bytes: 1_232,
            max_response_bytes: usize::from(u16::MAX),
        }
    }
}

impl TransportLimits {
    fn validate(self) -> Result<Self, TransportError> {
        if self.timeout.is_zero()
            || self.timeout > Duration::from_secs(60)
            || self.max_query_bytes == 0
            || self.max_query_bytes > usize::from(u16::MAX)
            || self.max_response_bytes < 12
            || self.max_response_bytes > usize::from(u16::MAX)
        {
            return Err(TransportError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Cooperative cancellation shared with the platform lifecycle.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Mark all clones cancelled.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn check(&self) -> Result<(), TransportError> {
        if self.is_cancelled() {
            Err(TransportError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// One immutable endpoint derived from current on-chain HNS authority data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthoritativeEndpoint {
    address: SocketAddr,
    anchor: HnsAnchor,
    name_hash: NameHash,
}

impl AuthoritativeEndpoint {
    /// Committed socket address.
    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.address
    }

    /// Exact current Handshake anchor that authorized the endpoint.
    #[must_use]
    pub const fn anchor(self) -> HnsAnchor {
        self.anchor
    }

    /// Exact HNS TLD hash whose resource committed this endpoint.
    #[must_use]
    pub const fn name_hash(self) -> NameHash {
        self.name_hash
    }
}

/// Deduplicated endpoints from one verified current HNS resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritativeSet {
    endpoints: Vec<AuthoritativeEndpoint>,
    anchor: HnsAnchor,
}

impl AuthoritativeSet {
    /// Derive direct endpoints from committed in-bailiwick glue and synth records.
    pub fn from_verified_resource(
        resource: &VerifiedHnsResource,
        port_policy: AuthorityPortPolicy,
    ) -> Result<Self, TransportError> {
        let port = match port_policy {
            AuthorityPortPolicy::StandardDns => DNS_PORT,
            AuthorityPortPolicy::RegtestFixture(port) => {
                if resource.anchor().network() != Network::Regtest || port == 0 || port == DNS_PORT
                {
                    return Err(TransportError::InvalidRegtestFixture);
                }
                port
            }
        };
        let mut addresses = Vec::new();
        for record in resource.resource().records() {
            let address = match record {
                HnsResourceRecord::Glue4 { name, address }
                    if in_bailiwick(name, resource.name()) =>
                {
                    Some(IpAddr::V4(*address))
                }
                HnsResourceRecord::Glue6 { name, address }
                    if in_bailiwick(name, resource.name()) =>
                {
                    Some(IpAddr::V6(*address))
                }
                HnsResourceRecord::Synth4(address) => Some(IpAddr::V4(*address)),
                HnsResourceRecord::Synth6(address) => Some(IpAddr::V6(*address)),
                _ => None,
            };
            let Some(address) = address else {
                continue;
            };
            let permitted = match port_policy {
                AuthorityPortPolicy::RegtestFixture(_) => address.is_loopback(),
                AuthorityPortPolicy::StandardDns
                    if matches!(
                        resource.anchor().network(),
                        Network::Mainnet | Network::Testnet
                    ) =>
                {
                    is_globally_routable(address)
                }
                AuthorityPortPolicy::StandardDns => {
                    !address.is_unspecified() && !address.is_multicast()
                }
            };
            if permitted && !addresses.contains(&address) {
                if addresses.len() >= MAX_AUTHORITY_ENDPOINTS {
                    return Err(TransportError::EndpointLimit);
                }
                addresses.push(address);
            }
        }
        if addresses.is_empty() {
            return Err(TransportError::NoPermittedEndpoint);
        }
        let anchor = resource.anchor();
        Ok(Self {
            endpoints: addresses
                .into_iter()
                .map(|address| AuthoritativeEndpoint {
                    address: SocketAddr::new(address, port),
                    anchor,
                    name_hash: resource.name_hash(),
                })
                .collect(),
            anchor,
        })
    }

    /// Exact resource anchor shared by every endpoint.
    #[must_use]
    pub const fn anchor(&self) -> HnsAnchor {
        self.anchor
    }

    /// Committed, policy-permitted endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[AuthoritativeEndpoint] {
        &self.endpoints
    }
}

/// Synchronous direct-authoritative DNS transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectDnsTransport {
    limits: TransportLimits,
}

impl DirectDnsTransport {
    /// Create a transport after validating all finite bounds.
    pub fn new(limits: TransportLimits) -> Result<Self, TransportError> {
        Ok(Self {
            limits: limits.validate()?,
        })
    }

    /// Send one strict non-recursive query over connected UDP.
    pub fn exchange_udp(
        &self,
        endpoint: AuthoritativeEndpoint,
        query: &Query,
        cancellation: &CancellationToken,
        now: u64,
    ) -> Result<Message, TransportError> {
        authorize(endpoint, query, now)?;
        cancellation.check()?;
        let query_bytes = query.encode(self.limits.max_query_bytes)?;
        let bind_address = match endpoint.address.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind_address)?;
        socket.set_read_timeout(Some(self.limits.timeout))?;
        socket.set_write_timeout(Some(self.limits.timeout))?;
        socket.connect(endpoint.address)?;
        cancellation.check()?;
        if socket.send(&query_bytes)? != query_bytes.len() {
            return Err(TransportError::ShortWrite);
        }
        let mut response = vec![0_u8; self.limits.max_response_bytes.saturating_add(1)];
        let received = socket.recv(&mut response)?;
        cancellation.check()?;
        if received == 0 || received > self.limits.max_response_bytes {
            return Err(TransportError::ResponseLimit);
        }
        response.truncate(received);
        parse_correlated(query, &response, self.limits.max_response_bytes)
    }

    /// Send one strict non-recursive query over length-delimited TCP.
    pub fn exchange_tcp(
        &self,
        endpoint: AuthoritativeEndpoint,
        query: &Query,
        cancellation: &CancellationToken,
        now: u64,
    ) -> Result<Message, TransportError> {
        authorize(endpoint, query, now)?;
        cancellation.check()?;
        let query_bytes = query.encode(self.limits.max_query_bytes)?;
        let query_length =
            u16::try_from(query_bytes.len()).map_err(|_| TransportError::QueryLimit)?;
        let mut stream = TcpStream::connect_timeout(&endpoint.address, self.limits.timeout)?;
        stream.set_read_timeout(Some(self.limits.timeout))?;
        stream.set_write_timeout(Some(self.limits.timeout))?;
        cancellation.check()?;
        stream.write_all(&query_length.to_be_bytes())?;
        stream.write_all(&query_bytes)?;
        stream.flush()?;
        let mut length = [0_u8; 2];
        stream.read_exact(&mut length)?;
        let response_length = usize::from(u16::from_be_bytes(length));
        if response_length == 0 || response_length > self.limits.max_response_bytes {
            return Err(TransportError::ResponseLimit);
        }
        let mut response = vec![0_u8; response_length];
        stream.read_exact(&mut response)?;
        cancellation.check()?;
        parse_correlated(query, &response, self.limits.max_response_bytes)
    }

    /// Configured finite bounds.
    #[must_use]
    pub const fn limits(self) -> TransportLimits {
        self.limits
    }
}

fn parse_correlated(
    query: &Query,
    response: &[u8],
    maximum: usize,
) -> Result<Message, TransportError> {
    let mut limits = ParseLimits::requester();
    limits.max_message_len = maximum;
    let message = Message::parse_with_limits(response, limits)?;
    query.correlate(&message)?;
    Ok(message)
}

fn authorize(
    endpoint: AuthoritativeEndpoint,
    query: &Query,
    now: u64,
) -> Result<(), TransportError> {
    if now < endpoint.anchor.validated_at().get() || now > endpoint.anchor.valid_until().get() {
        return Err(TransportError::StaleAnchor);
    }
    let tld = query
        .question
        .name
        .labels()
        .last()
        .ok_or(TransportError::QueryOutsideAuthority)?;
    if hash_name(tld)? != endpoint.name_hash {
        return Err(TransportError::QueryOutsideAuthority);
    }
    Ok(())
}

fn in_bailiwick(name: &ResourceName, tld: &[u8]) -> bool {
    name.labels().last().is_some_and(|label| label == tld)
}

fn is_globally_routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_global_v4(address),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_global_v4(mapped);
            }
            let segments = address.segments();
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || segments[0] & 0xfe00 == 0xfc00
                || segments[0] & 0xffc0 == 0xfe80
                || segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn is_global_v4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_private()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_documentation()
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        && !(octets[0] == 198 && matches!(octets[1], 18 | 19))
        && octets[0] < 240
}

/// Endpoint admission, DNS, I/O, timeout, or cancellation failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransportError {
    /// DNS wire construction, parsing, or correlation failed.
    #[error("DNS wire failure: {0}")]
    Wire(#[from] hns_dns_wire::Error),
    /// Socket or stream I/O failed.
    #[error("direct DNS I/O failure: {0}")]
    Io(#[from] std::io::Error),
    /// Timeout or message bounds are zero, excessive, or inconsistent.
    #[error("invalid direct DNS transport limits")]
    InvalidLimits,
    /// Regtest fixture port/network/address policy is invalid.
    #[error("invalid nonstandard regtest DNS fixture")]
    InvalidRegtestFixture,
    /// More committed endpoints exist than the browser bound permits.
    #[error("authoritative endpoint bound exceeded")]
    EndpointLimit,
    /// No committed endpoint survives bailiwick/address/port policy.
    #[error("verified HNS resource has no permitted direct endpoint")]
    NoPermittedEndpoint,
    /// Encoded query exceeds the configured/u16 bound.
    #[error("DNS query exceeds its bound")]
    QueryLimit,
    /// UDP/TCP response is empty or exceeds its bound.
    #[error("DNS response exceeds its bound")]
    ResponseLimit,
    /// Datagram write did not transmit the complete query.
    #[error("short DNS datagram write")]
    ShortWrite,
    /// Platform lifecycle requested cancellation.
    #[error("direct DNS request cancelled")]
    Cancelled,
    /// Endpoint's chain-currency attestation is not current at request time.
    #[error("authoritative endpoint Handshake anchor is stale")]
    StaleAnchor,
    /// Query is outside the exact HNS TLD that committed the endpoint.
    #[error("DNS query is outside the endpoint's verified HNS authority")]
    QueryOutsideAuthority,
    /// Handshake TLD label is invalid.
    #[error("invalid Handshake TLD in DNS query: {0}")]
    Covenant(#[from] hns_covenants::CovenantError),
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid local network fixtures"
)]
mod tests {
    use std::net::{TcpListener, UdpSocket};
    use std::thread;

    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    use hns_dns_wire::{Flags, Header as DnsHeader, Name, Question, RecordType};
    use hns_header_consensus::Header;
    use hns_light_chain::{ChainLimits, CurrencyPolicy, LightChain};
    use hns_primitives::{BlockTime, Chainwork, Height, TreeRoot};

    use super::*;

    fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).unwrap();
        for part in parts {
            hasher.update(part);
        }
        let mut output = [0_u8; 32];
        hasher.finalize_variable(&mut output).unwrap();
        output
    }

    fn verified_resource(port: u16) -> (VerifiedHnsResource, AuthoritativeSet) {
        let mut resource = vec![0, 2, 2, b'n', b's', 5];
        resource.extend_from_slice(b"alpha");
        resource.push(0);
        resource.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
        let mut state = Vec::new();
        state.push(5);
        state.extend_from_slice(b"alpha");
        state.extend_from_slice(&u16::try_from(resource.len()).unwrap().to_le_bytes());
        state.extend_from_slice(&resource);
        state.extend_from_slice(&1_u32.to_le_bytes());
        state.extend_from_slice(&1_u32.to_le_bytes());
        state.extend_from_slice(&0_u16.to_le_bytes());
        let key = hns_covenants::hash_name(b"alpha").unwrap();
        let value_hash = blake2b_256(&[&state]);
        let tree_root = TreeRoot::new(blake2b_256(&[&[0], key.as_bytes(), &value_hash]));
        let mut proof = Vec::new();
        proof.extend_from_slice(&0xc000_u16.to_le_bytes());
        proof.extend_from_slice(&0_u16.to_le_bytes());
        proof.extend_from_slice(&u16::try_from(state.len()).unwrap().to_le_bytes());
        proof.extend_from_slice(&state);

        let genesis_time = Network::Regtest.parameters().genesis_time;
        let now = BlockTime::new(genesis_time.get() + 100);
        let mut chain =
            LightChain::from_genesis(Network::Regtest, now, ChainLimits::default()).unwrap();
        let mut header = Header {
            time: BlockTime::new(genesis_time.get() + 1),
            previous_block: chain.tip().hash(),
            tree_root,
            bits: Network::Regtest.parameters().pow.bits,
            ..Header::default()
        };
        while !header.verify_pow() {
            header.nonce = header.nonce.checked_add(1).unwrap();
        }
        chain.append(&header, now).unwrap();
        let current = chain
            .require_current(CurrencyPolicy {
                now,
                maximum_tip_age_seconds: 3_600,
                minimum_height: Height::new(1),
                minimum_chainwork: Chainwork::ZERO,
            })
            .unwrap();
        let verified = current.verify_name_resource(b"alpha", &proof).unwrap();
        let set = AuthoritativeSet::from_verified_resource(
            &verified,
            AuthorityPortPolicy::RegtestFixture(port),
        )
        .unwrap();
        (verified, set)
    }

    fn query() -> Query {
        Query::new(
            0x1234,
            Name::from_ascii("_443._tcp.alpha.").unwrap(),
            RecordType::Tlsa,
        )
        .unwrap()
    }

    fn endpoint(set: &AuthoritativeSet) -> AuthoritativeEndpoint {
        set.endpoints().first().copied().unwrap()
    }

    fn response(query: &Query) -> Vec<u8> {
        Message {
            header: DnsHeader {
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
        .encode(usize::from(u16::MAX))
        .unwrap()
    }

    #[test]
    fn derives_only_in_bailiwick_loopback_regtest_fixture() {
        let (resource, set) = verified_resource(5_353);
        assert_eq!(set.endpoints().len(), 1);
        assert_eq!(
            endpoint(&set).address(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_353)
        );
        assert_eq!(set.anchor(), resource.anchor());
        assert!(matches!(
            AuthoritativeSet::from_verified_resource(
                &resource,
                AuthorityPortPolicy::RegtestFixture(DNS_PORT),
            ),
            Err(TransportError::InvalidRegtestFixture)
        ));
        assert!(!is_globally_routable(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_globally_routable(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn exchanges_correlated_udp_and_honors_cancellation() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = server.local_addr().unwrap().port();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 1_232];
            let (length, peer) = server.recv_from(&mut buffer).unwrap();
            let query =
                Query::parse(buffer.get(..length).unwrap(), ParseLimits::requester()).unwrap();
            server.send_to(&response(&query), peer).unwrap();
        });
        let (_, set) = verified_resource(port);
        let transport = DirectDnsTransport::new(TransportLimits {
            timeout: Duration::from_secs(2),
            ..TransportLimits::default()
        })
        .unwrap();
        let cancellation = CancellationToken::default();
        let query = query();
        let message = transport
            .exchange_udp(
                endpoint(&set),
                &query,
                &cancellation,
                endpoint(&set).anchor().validated_at().get(),
            )
            .unwrap();
        assert_eq!(message.header.id, query.id);
        server_thread.join().unwrap();

        cancellation.cancel();
        assert!(matches!(
            transport.exchange_udp(
                endpoint(&set),
                &query,
                &cancellation,
                endpoint(&set).anchor().validated_at().get(),
            ),
            Err(TransportError::Cancelled)
        ));
    }

    #[test]
    fn exchanges_exact_length_delimited_tcp() {
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = server.local_addr().unwrap().port();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            let mut length = [0_u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut bytes = vec![0_u8; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut bytes).unwrap();
            let query = Query::parse(&bytes, ParseLimits::requester()).unwrap();
            let response = response(&query);
            stream
                .write_all(&u16::try_from(response.len()).unwrap().to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });
        let (_, set) = verified_resource(port);
        let transport = DirectDnsTransport::new(TransportLimits {
            timeout: Duration::from_secs(2),
            ..TransportLimits::default()
        })
        .unwrap();
        let query = query();
        let message = transport
            .exchange_tcp(
                endpoint(&set),
                &query,
                &CancellationToken::default(),
                endpoint(&set).anchor().validated_at().get(),
            )
            .unwrap();
        assert_eq!(message.header.id, query.id);
        server_thread.join().unwrap();
    }

    #[test]
    fn limits_fail_before_network_io() {
        assert!(matches!(
            DirectDnsTransport::new(TransportLimits {
                timeout: Duration::ZERO,
                ..TransportLimits::default()
            }),
            Err(TransportError::InvalidLimits)
        ));
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let (_, set) = verified_resource(5_353);
        assert!(matches!(
            DirectDnsTransport::new(TransportLimits::default())
                .unwrap()
                .exchange_tcp(
                    endpoint(&set),
                    &query(),
                    &cancellation,
                    endpoint(&set).anchor().validated_at().get(),
                ),
            Err(TransportError::Cancelled)
        ));

        let transport = DirectDnsTransport::new(TransportLimits::default()).unwrap();
        let outside = Query::new(
            1,
            Name::from_ascii("_443._tcp.beta.").unwrap(),
            RecordType::Tlsa,
        )
        .unwrap();
        assert!(matches!(
            transport.exchange_tcp(
                endpoint(&set),
                &outside,
                &CancellationToken::default(),
                endpoint(&set).anchor().validated_at().get(),
            ),
            Err(TransportError::QueryOutsideAuthority)
        ));
        assert!(matches!(
            transport.exchange_tcp(
                endpoint(&set),
                &query(),
                &CancellationToken::default(),
                endpoint(&set).anchor().valid_until().get() + 1,
            ),
            Err(TransportError::StaleAnchor)
        ));
    }
}
