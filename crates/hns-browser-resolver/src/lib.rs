#![allow(
    missing_docs,
    reason = "temporary compatibility adapter preserves the existing browser resolver API"
)]

use hns_cache::ExpiringLru;
use hns_core::dns::{
    DnsEncodeConfig, DnsFlags, DnsHeader, DnsMessage, DnsName, DnsQuestion, RecordType,
    ResourceRecord, SVCB_PARAM_ALPN, SVCB_PARAM_DOHPATH, SVCB_PARAM_IPV4HINT, SVCB_PARAM_IPV6HINT,
    SVCB_PARAM_MANDATORY, SVCB_PARAM_PORT, SvcbRecord,
};
use hns_core::network::NetworkKind;
use hns_core::network_policy::{
    is_browser_blocked_port, is_browser_special_use_host, is_publicly_routable,
};
use hns_core::resource::{ResourceError, decode_handshake_resource_records};
use hns_core::{Hash, Height, NameHash, NameHashError};
use hns_dane::{TlsaMatching, TlsaRecord, TlsaSelector, TlsaUsage};
use hns_dnssec::{
    DnssecChainLink, DnssecChainValidationInput, DnssecStatus, DnssecTime,
    Nsec3NameErrorValidationInput, Nsec3NoDataValidationInput, NsecNameErrorValidationInput,
    NsecNoDataValidationInput, RrsigRecord, SignedRrsetValidationInput, validate_dnssec_chain,
    validate_nsec_name_error, validate_nsec_no_data, validate_nsec3_name_error,
    validate_nsec3_no_data, validate_rrset_signature, validate_signed_rrset,
};
use hns_namespace_resolution::{
    ClassificationError as NamespaceClassificationError, NamespaceDecision, OriginQuery,
    ValidationError as NamespaceValidationError,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const DNS_CLASS_IN: u16 = 1;
const DNS_OPT_RECORD_TYPE: u16 = 41;
const DNSSEC_DO_FLAG: u32 = 0x8000;
const DNS_RCODE_NOERROR: u8 = 0;
const DNS_RCODE_NXDOMAIN: u8 = 3;
const DEFAULT_DNS_UDP_PAYLOAD: usize = 1232;
const DEFAULT_DNS_TCP_MAX_MESSAGE_LEN: usize = 65_535;
const DEFAULT_DOH_PORT: u16 = 443;
const DEFAULT_DOH_PATH: &str = "/dns-query";
const DOH_URI_TEMPLATE_DNS_VARIABLE: &str = "{?dns}";
const HNSDNS_VERSION: &str = "1";
const HNSDNS_MAX_TEXT_BYTES: usize = 255;
const HNSDNS_MAX_TLSA_PINS: usize = 2;
const MAX_CNAME_CHAIN_LEN: usize = 8;
static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(0x4d00);
// Generated from https://data.iana.org/TLD/tlds-alpha-by-domain.txt, version 2026062302.
const ICANN_TLDS: &str = include_str!("icann_tlds.txt");

/// Returns the generated IANA root-zone snapshot used by browser namespace
/// classification. The trailing newline, when present, is not significant.
pub fn browser_icann_tld_snapshot() -> &'static str {
    ICANN_TLDS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameClass {
    Hns,
    Icann,
    Search,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResolutionRequest {
    pub qname: String,
    pub qtype: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionAnswer {
    pub name: DnsName,
    pub records: Vec<ResourceRecord>,
    pub secure: bool,
}

/// Atomic dual-root decision and any selected root's retained raw DNS
/// material. A completed `Neither` decision has no selected answer but still
/// crosses this boundary so consumers retain its exact request-local evidence
/// and fingerprint. Consumers use the complete selected plan for connection
/// state; the answer exists only for diagnostics and compatibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedNamespaceResolution {
    pub decision: NamespaceDecision,
    pub selected_answer: Option<ResolutionAnswer>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenNameRecords {
    pub root_name: String,
    pub name_hash: NameHash,
    pub records: Vec<ResourceRecord>,
    pub secure: bool,
    pub exists: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedResourceValue {
    pub root_name: String,
    pub name_hash: NameHash,
    pub value: Option<Vec<u8>>,
    pub secure: bool,
    pub anchor: Option<ResourceValueAnchor>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceValueAnchor {
    pub tree_root: Hash,
    pub height: Height,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ResolverError {
    #[error("HNS proof is unavailable")]
    ProofUnavailable,
    #[error("HNS name is invalid: {0}")]
    InvalidName(#[from] NameHashError),
    #[error("HNS proof payload does not match requested name")]
    ProofNameMismatch,
    #[error("HNS name does not exist")]
    NameNotFound,
    #[error("local HNS chain is not current enough to determine current name state")]
    LocalChainNotCurrent,
    #[error("DNSSEC validation failed")]
    DnssecFailed,
    #[error("DNSSEC validation of an HNS P2P relay response failed")]
    RelayDnssecFailed,
    #[error("transparent port 53 interception was confirmed")]
    Port53InterceptionDetected,
    #[error("HNS resource payload is invalid: {0}")]
    InvalidResource(#[from] ResourceError),
    #[error("resolver backend is not implemented")]
    UnsupportedBackend,
    #[error("HNS delegation has no usable nameserver address")]
    NoNameserverAddress,
    #[error("delegated DNS endpoint is not publicly routable")]
    NonPublicDnsEndpoint,
    #[error("authoritative DoH port {0} is blocked by browser network policy")]
    UnsafeAuthoritativeDohPort(u16),
    #[error("DNS transport failed: {0}")]
    DnsTransport(String),
    #[error("DNS response returned rcode {0}")]
    DnsResponseCode(u8),
    #[error("DNS response is invalid")]
    InvalidDnsResponse,
    #[error("HNS authoritative DoH discovery record is invalid")]
    InvalidAuthoritativeDoh,
    #[error("resolver cache lock is poisoned")]
    CachePoisoned,
    #[error("resolver storage error: {0}")]
    Storage(String),
    #[error("dual-root namespace input is invalid: {0}")]
    NamespaceValidation(#[from] NamespaceValidationError),
    #[error("dual-root namespace classification failed: {0}")]
    NamespaceClassification(#[from] NamespaceClassificationError),
    #[error("neither namespace has a usable origin plan")]
    NamespaceUnavailable,
}

pub trait Resolver {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError>;

    /// Builds one complete dual-root browser decision when the resolver owns
    /// that adapter. Legacy record-oriented resolvers return `None`.
    fn prepare_namespace_resolution(
        &self,
        _query: &OriginQuery,
    ) -> Result<Option<PreparedNamespaceResolution>, ResolverError> {
        Ok(None)
    }
}

pub trait DelegatedResolver {
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError>;
}

impl<R: Resolver> DelegatedResolver for R {
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        _delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError> {
        self.resolve(request)
    }
}

pub trait HnsProofProvider {
    fn prove_name(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<ProvenNameRecords, ResolverError>;
}

pub trait HnsResourceValueProvider {
    fn prove_resource_value(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<VerifiedResourceValue, ResolverError>;
}

pub struct FailClosedResolver;

pub struct CompositeResolver<H, I> {
    hns: H,
    icann: I,
}

pub struct ProofBackedResolver<P> {
    proof_provider: P,
}

pub struct DelegatingResolver<P, D> {
    proof_provider: P,
    delegated_resolver: D,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsDelegation {
    pub root_name: String,
    pub owner: DnsName,
    pub records: Vec<ResourceRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritativeDohEndpoint {
    pub ns: DnsName,
    pub host: String,
    pub connect_addr: IpAddr,
    pub port: u16,
    pub path_and_query: String,
    pub tls_authentication: AuthoritativeDohTlsAuthentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthoritativeDohTlsAuthentication {
    WebPki,
    HnsProofTlsa(Vec<TlsaRecord>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsEndpointPolicy {
    pub allow_non_public_addresses: bool,
    pub allow_unsafe_doh_ports: bool,
}

impl DnsEndpointPolicy {
    pub const fn strict() -> Self {
        Self {
            allow_non_public_addresses: false,
            allow_unsafe_doh_ports: false,
        }
    }

    pub const fn permissive() -> Self {
        Self {
            allow_non_public_addresses: true,
            allow_unsafe_doh_ports: true,
        }
    }

    pub const fn for_network(network: NetworkKind) -> Self {
        match network {
            NetworkKind::Mainnet | NetworkKind::Testnet => Self::strict(),
            NetworkKind::Regtest => Self::permissive(),
        }
    }
}

impl Default for DnsEndpointPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpTcpDnsTransport {
    pub timeout: Duration,
    pub max_udp_response_len: usize,
    pub max_tcp_message_len: usize,
    pub endpoint_policy: DnsEndpointPolicy,
}

pub struct SystemDnssecVerifier;

pub struct AuthoritativeDnssecResolver<T = UdpTcpDnsTransport, V = SystemDnssecVerifier> {
    transport: T,
    verifier: V,
    authoritative_doh_enabled: bool,
    prefer_authoritative_doh: bool,
    authoritative_doh_endpoint_cache: Mutex<HashMap<String, Vec<AuthoritativeDohEndpoint>>>,
}

pub trait DnsTransport {
    fn endpoint_policy(&self) -> DnsEndpointPolicy {
        DnsEndpointPolicy::strict()
    }

    fn exchange_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError>;

    fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError>;

    fn exchange_doh(
        &self,
        _endpoint: &AuthoritativeDohEndpoint,
        _query: &[u8],
    ) -> Result<Vec<u8>, ResolverError> {
        Err(ResolverError::UnsupportedBackend)
    }

    fn probe_dns_interception(&self) -> DnsInterceptionStatus {
        DnsInterceptionStatus::NotTested
    }

    fn dns_interception_status(&self) -> DnsInterceptionStatus {
        DnsInterceptionStatus::NotTested
    }

    /// A recursive relay ignores the proof-derived authoritative socket. Its
    /// transport owns retry diversity, so authoritative UDP-to-TCP and
    /// per-nameserver retries must not duplicate the same recursive question.
    fn is_recursive_relay(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsInterceptionStatus {
    NotTested,
    NotDetected,
    Detected,
    Inconclusive,
}

pub struct DelegatedDnssecValidation<'a> {
    pub dnskey_owner: &'a DnsName,
    pub ds_rrset: &'a [ResourceRecord],
    pub dnskey_rrset: &'a [ResourceRecord],
    pub dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub target_rrset: &'a [ResourceRecord],
    pub target_rrsig_rrset: &'a [ResourceRecord],
}

pub struct DelegatedDnssecNoDataValidation<'a> {
    pub dnskey_owner: &'a DnsName,
    pub ds_rrset: &'a [ResourceRecord],
    pub dnskey_rrset: &'a [ResourceRecord],
    pub dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub query_type: RecordType,
    pub nsec_rrset: &'a [ResourceRecord],
    pub nsec_rrsig_rrset: &'a [ResourceRecord],
    pub nsec3_rrset: &'a [ResourceRecord],
    pub nsec3_rrsig_rrset: &'a [ResourceRecord],
}

pub struct DelegatedDnssecNameErrorValidation<'a> {
    pub dnskey_owner: &'a DnsName,
    pub ds_rrset: &'a [ResourceRecord],
    pub dnskey_rrset: &'a [ResourceRecord],
    pub dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub closest_encloser: &'a DnsName,
    pub nsec_rrset: &'a [ResourceRecord],
    pub nsec_rrsig_rrset: &'a [ResourceRecord],
    pub nsec3_rrset: &'a [ResourceRecord],
    pub nsec3_rrsig_rrset: &'a [ResourceRecord],
}

pub struct DelegatedChildDnssecValidation<'a> {
    pub parent_dnskey_owner: &'a DnsName,
    pub parent_ds_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_owner: &'a DnsName,
    pub child_ds_rrset: &'a [ResourceRecord],
    pub child_ds_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub target_rrset: &'a [ResourceRecord],
    pub target_rrsig_rrset: &'a [ResourceRecord],
}

pub struct DelegatedChildDnssecNoDataValidation<'a> {
    pub parent_dnskey_owner: &'a DnsName,
    pub parent_ds_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_owner: &'a DnsName,
    pub child_ds_rrset: &'a [ResourceRecord],
    pub child_ds_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub query_type: RecordType,
    pub nsec_rrset: &'a [ResourceRecord],
    pub nsec_rrsig_rrset: &'a [ResourceRecord],
    pub nsec3_rrset: &'a [ResourceRecord],
    pub nsec3_rrsig_rrset: &'a [ResourceRecord],
}

pub struct DelegatedChildDnssecNameErrorValidation<'a> {
    pub parent_dnskey_owner: &'a DnsName,
    pub parent_ds_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrset: &'a [ResourceRecord],
    pub parent_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_owner: &'a DnsName,
    pub child_ds_rrset: &'a [ResourceRecord],
    pub child_ds_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub closest_encloser: &'a DnsName,
    pub nsec_rrset: &'a [ResourceRecord],
    pub nsec_rrsig_rrset: &'a [ResourceRecord],
    pub nsec3_rrset: &'a [ResourceRecord],
    pub nsec3_rrsig_rrset: &'a [ResourceRecord],
}

pub trait DelegatedDnssecVerifier {
    fn validate_positive_rrset(
        &self,
        input: DelegatedDnssecValidation<'_>,
    ) -> Result<bool, ResolverError>;

    fn validate_no_data(
        &self,
        input: DelegatedDnssecNoDataValidation<'_>,
    ) -> Result<bool, ResolverError>;

    fn validate_name_error(
        &self,
        _input: DelegatedDnssecNameErrorValidation<'_>,
    ) -> Result<bool, ResolverError> {
        Ok(false)
    }

    fn validate_child_positive_rrset(
        &self,
        input: DelegatedChildDnssecValidation<'_>,
    ) -> Result<bool, ResolverError>;

    fn validate_child_no_data(
        &self,
        input: DelegatedChildDnssecNoDataValidation<'_>,
    ) -> Result<bool, ResolverError>;

    fn validate_child_name_error(
        &self,
        _input: DelegatedChildDnssecNameErrorValidation<'_>,
    ) -> Result<bool, ResolverError> {
        Ok(false)
    }
}

pub struct ResourceValueProofProvider<P> {
    value_provider: P,
}

#[derive(Default)]
pub struct MemoryResourceValueProvider {
    values: Mutex<HashMap<(String, NameHash), VerifiedResourceValue>>,
}

pub struct SqliteResourceValueProvider {
    connection: Mutex<Connection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceValueCacheStats {
    pub entries: usize,
    pub value_bytes: usize,
}

pub struct CachedResolver<R> {
    inner: R,
    cache: Mutex<ExpiringLru<ResolutionRequest, CachedResolution>>,
    ttl: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CachedResolution {
    Answer(ResolutionAnswer),
    NameNotFound,
}

impl VerifiedResourceValue {
    pub fn inclusion(root_name: String, name_hash: NameHash, value: Vec<u8>) -> Self {
        Self {
            root_name,
            name_hash,
            value: Some(value),
            secure: true,
            anchor: None,
        }
    }

    pub fn non_inclusion(root_name: String, name_hash: NameHash) -> Self {
        Self {
            root_name,
            name_hash,
            value: None,
            secure: true,
            anchor: None,
        }
    }

    pub fn with_anchor(mut self, tree_root: Hash, height: Height) -> Self {
        self.anchor = Some(ResourceValueAnchor { tree_root, height });
        self
    }
}

impl ProvenNameRecords {
    pub fn from_resource_value(
        root_name: String,
        name_hash: NameHash,
        value: &[u8],
    ) -> Result<Self, ResolverError> {
        let owner =
            DnsName::from_ascii(&root_name).map_err(|_| ResolverError::UnsupportedBackend)?;
        let records = decode_handshake_resource_records(&owner, value)?;
        Ok(Self {
            root_name,
            name_hash,
            records,
            secure: true,
            exists: true,
        })
    }

    pub fn from_verified_resource_value(
        verified: VerifiedResourceValue,
    ) -> Result<Self, ResolverError> {
        let exists = verified.value.is_some();
        let records = match verified.value {
            Some(value) => {
                let owner = DnsName::from_ascii(&verified.root_name)
                    .map_err(|_| ResolverError::UnsupportedBackend)?;
                decode_handshake_resource_records(&owner, &value)?
            }
            None => Vec::new(),
        };

        Ok(Self {
            root_name: verified.root_name,
            name_hash: verified.name_hash,
            records,
            secure: verified.secure,
            exists,
        })
    }
}

impl Resolver for FailClosedResolver {
    fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        Err(ResolverError::UnsupportedBackend)
    }
}

impl<H, I> CompositeResolver<H, I> {
    pub fn new(hns: H, icann: I) -> Self {
        Self { hns, icann }
    }

    pub fn into_parts(self) -> (H, I) {
        (self.hns, self.icann)
    }
}

impl<H, I> Resolver for CompositeResolver<H, I>
where
    H: Resolver,
    I: Resolver,
{
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        match classify_name(&request.qname) {
            NameClass::Hns => self.hns.resolve(request),
            NameClass::Icann => self.icann.resolve(request),
            NameClass::Search => Err(ResolverError::UnsupportedBackend),
        }
    }
}

impl Default for UdpTcpDnsTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            max_udp_response_len: DEFAULT_DNS_UDP_PAYLOAD,
            max_tcp_message_len: DEFAULT_DNS_TCP_MAX_MESSAGE_LEN,
            endpoint_policy: DnsEndpointPolicy::strict(),
        }
    }
}

impl DnsTransport for UdpTcpDnsTransport {
    fn endpoint_policy(&self) -> DnsEndpointPolicy {
        self.endpoint_policy
    }

    fn exchange_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        validate_dns_server(self.endpoint_policy, server)?;
        let bind_addr = match server {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind_addr)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        socket
            .send_to(query, server)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;

        let mut response = vec![0u8; self.max_udp_response_len];
        let (len, source) = socket
            .recv_from(&mut response)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        if source != server {
            return Err(ResolverError::InvalidDnsResponse);
        }
        response.truncate(len);
        Ok(response)
    }

    fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
        validate_dns_server(self.endpoint_policy, server)?;
        if query.len() > u16::MAX as usize {
            return Err(ResolverError::InvalidDnsResponse);
        }

        let mut stream = TcpStream::connect_timeout(&server, self.timeout)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;

        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .and_then(|_| stream.write_all(query))
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;

        let mut length = [0u8; 2];
        stream
            .read_exact(&mut length)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        let length = u16::from_be_bytes(length) as usize;
        if length > self.max_tcp_message_len {
            return Err(ResolverError::InvalidDnsResponse);
        }

        let mut response = vec![0u8; length];
        stream
            .read_exact(&mut response)
            .map_err(|error| ResolverError::DnsTransport(error.to_string()))?;
        Ok(response)
    }
}

impl DelegatedDnssecVerifier for SystemDnssecVerifier {
    fn validate_positive_rrset(
        &self,
        input: DelegatedDnssecValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.dnskey_owner,
            ds_rrset: input.ds_rrset,
            dnskey_rrset: input.dnskey_rrset,
            dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
            rrset: input.target_rrset,
            rrsig_rrset: input.target_rrsig_rrset,
            now: DnssecTime(now),
        })
        .map_err(|_| ResolverError::DnssecFailed)?;

        Ok(status == DnssecStatus::Secure)
    }

    fn validate_no_data(
        &self,
        input: DelegatedDnssecNoDataValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let now = DnssecTime(now);
        let dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.dnskey_owner,
            ds_rrset: input.ds_rrset,
            dnskey_rrset: input.dnskey_rrset,
            dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
            rrset: input.dnskey_rrset,
            rrsig_rrset: input.dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        if !input.nsec_rrset.is_empty() {
            let status = validate_nsec_no_data(NsecNoDataValidationInput {
                signer_name: input.dnskey_owner,
                dnskey_rrset: input.dnskey_rrset,
                query_name: input.query_name,
                query_type: input.query_type,
                nsec_rrset: input.nsec_rrset,
                nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        if !input.nsec3_rrset.is_empty() {
            let status = validate_nsec3_no_data(Nsec3NoDataValidationInput {
                signer_name: input.dnskey_owner,
                dnskey_rrset: input.dnskey_rrset,
                query_name: input.query_name,
                query_type: input.query_type,
                nsec3_rrset: input.nsec3_rrset,
                nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn validate_name_error(
        &self,
        input: DelegatedDnssecNameErrorValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let now = DnssecTime(now);
        let dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.dnskey_owner,
            ds_rrset: input.ds_rrset,
            dnskey_rrset: input.dnskey_rrset,
            dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
            rrset: input.dnskey_rrset,
            rrsig_rrset: input.dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        if !input.nsec_rrset.is_empty() {
            let status = validate_nsec_name_error(NsecNameErrorValidationInput {
                signer_name: input.dnskey_owner,
                dnskey_rrset: input.dnskey_rrset,
                query_name: input.query_name,
                closest_encloser: input.closest_encloser,
                covering_nsec_rrset: input.nsec_rrset,
                covering_nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                wildcard_nsec_rrset: input.nsec_rrset,
                wildcard_nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        if !input.nsec3_rrset.is_empty() {
            let status = validate_nsec3_name_error(Nsec3NameErrorValidationInput {
                signer_name: input.dnskey_owner,
                dnskey_rrset: input.dnskey_rrset,
                query_name: input.query_name,
                closest_encloser: input.closest_encloser,
                closest_encloser_nsec3_rrset: input.nsec3_rrset,
                closest_encloser_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                next_closer_nsec3_rrset: input.nsec3_rrset,
                next_closer_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                wildcard_nsec3_rrset: input.nsec3_rrset,
                wildcard_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn validate_child_positive_rrset(
        &self,
        input: DelegatedChildDnssecValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let link = DnssecChainLink {
            child_dnskey_owner: input.child_dnskey_owner,
            ds_rrset: input.child_ds_rrset,
            ds_rrsig_rrset: input.child_ds_rrsig_rrset,
            child_dnskey_rrset: input.child_dnskey_rrset,
            child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
        };
        let status = validate_dnssec_chain(DnssecChainValidationInput {
            initial_dnskey_owner: input.parent_dnskey_owner,
            initial_ds_rrset: input.parent_ds_rrset,
            initial_dnskey_rrset: input.parent_dnskey_rrset,
            initial_dnskey_rrsig_rrset: input.parent_dnskey_rrsig_rrset,
            delegation_links: &[link],
            target_rrset: input.target_rrset,
            target_rrsig_rrset: input.target_rrsig_rrset,
            now: DnssecTime(now),
        })
        .map_err(|_| ResolverError::DnssecFailed)?;

        Ok(status == DnssecStatus::Secure)
    }

    fn validate_child_no_data(
        &self,
        input: DelegatedChildDnssecNoDataValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let now = DnssecTime(now);
        let parent_dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.parent_dnskey_owner,
            ds_rrset: input.parent_ds_rrset,
            dnskey_rrset: input.parent_dnskey_rrset,
            dnskey_rrsig_rrset: input.parent_dnskey_rrsig_rrset,
            rrset: input.parent_dnskey_rrset,
            rrsig_rrset: input.parent_dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if parent_dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        let child_ds_status = validate_rrset_signature(
            input.parent_dnskey_owner,
            input.parent_dnskey_rrset,
            input.child_ds_rrset,
            input.child_ds_rrsig_rrset,
            now,
        )
        .map_err(|_| ResolverError::DnssecFailed)?;
        if child_ds_status != DnssecStatus::Secure {
            return Ok(false);
        }

        let child_dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.child_dnskey_owner,
            ds_rrset: input.child_ds_rrset,
            dnskey_rrset: input.child_dnskey_rrset,
            dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
            rrset: input.child_dnskey_rrset,
            rrsig_rrset: input.child_dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if child_dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        if !input.nsec_rrset.is_empty() {
            let status = validate_nsec_no_data(NsecNoDataValidationInput {
                signer_name: input.child_dnskey_owner,
                dnskey_rrset: input.child_dnskey_rrset,
                query_name: input.query_name,
                query_type: input.query_type,
                nsec_rrset: input.nsec_rrset,
                nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        if !input.nsec3_rrset.is_empty() {
            let status = validate_nsec3_no_data(Nsec3NoDataValidationInput {
                signer_name: input.child_dnskey_owner,
                dnskey_rrset: input.child_dnskey_rrset,
                query_name: input.query_name,
                query_type: input.query_type,
                nsec3_rrset: input.nsec3_rrset,
                nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn validate_child_name_error(
        &self,
        input: DelegatedChildDnssecNameErrorValidation<'_>,
    ) -> Result<bool, ResolverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResolverError::DnssecFailed)?
            .as_secs();
        let now = DnssecTime(now);
        let parent_dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.parent_dnskey_owner,
            ds_rrset: input.parent_ds_rrset,
            dnskey_rrset: input.parent_dnskey_rrset,
            dnskey_rrsig_rrset: input.parent_dnskey_rrsig_rrset,
            rrset: input.parent_dnskey_rrset,
            rrsig_rrset: input.parent_dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if parent_dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        let child_ds_status = validate_rrset_signature(
            input.parent_dnskey_owner,
            input.parent_dnskey_rrset,
            input.child_ds_rrset,
            input.child_ds_rrsig_rrset,
            now,
        )
        .map_err(|_| ResolverError::DnssecFailed)?;
        if child_ds_status != DnssecStatus::Secure {
            return Ok(false);
        }

        let child_dnskey_status = validate_signed_rrset(SignedRrsetValidationInput {
            dnskey_owner: input.child_dnskey_owner,
            ds_rrset: input.child_ds_rrset,
            dnskey_rrset: input.child_dnskey_rrset,
            dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
            rrset: input.child_dnskey_rrset,
            rrsig_rrset: input.child_dnskey_rrsig_rrset,
            now,
        })
        .map_err(|_| ResolverError::DnssecFailed)?;
        if child_dnskey_status != DnssecStatus::Secure {
            return Ok(false);
        }

        if !input.nsec_rrset.is_empty() {
            let status = validate_nsec_name_error(NsecNameErrorValidationInput {
                signer_name: input.child_dnskey_owner,
                dnskey_rrset: input.child_dnskey_rrset,
                query_name: input.query_name,
                closest_encloser: input.closest_encloser,
                covering_nsec_rrset: input.nsec_rrset,
                covering_nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                wildcard_nsec_rrset: input.nsec_rrset,
                wildcard_nsec_rrsig_rrset: input.nsec_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        if !input.nsec3_rrset.is_empty() {
            let status = validate_nsec3_name_error(Nsec3NameErrorValidationInput {
                signer_name: input.child_dnskey_owner,
                dnskey_rrset: input.child_dnskey_rrset,
                query_name: input.query_name,
                closest_encloser: input.closest_encloser,
                closest_encloser_nsec3_rrset: input.nsec3_rrset,
                closest_encloser_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                next_closer_nsec3_rrset: input.nsec3_rrset,
                next_closer_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                wildcard_nsec3_rrset: input.nsec3_rrset,
                wildcard_nsec3_rrsig_rrset: input.nsec3_rrsig_rrset,
                now,
            })
            .map_err(|_| ResolverError::DnssecFailed)?;
            if status == DnssecStatus::Secure {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl<T, V> AuthoritativeDnssecResolver<T, V> {
    pub fn new(transport: T, verifier: V) -> Self {
        Self {
            transport,
            verifier,
            authoritative_doh_enabled: true,
            prefer_authoritative_doh: false,
            authoritative_doh_endpoint_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_authoritative_doh_preferred(mut self) -> Self {
        self.prefer_authoritative_doh = true;
        self
    }

    /// Disables authoritative DoH discovery for transports that deliberately
    /// implement only a later resolver stage, such as the experimental P2P
    /// recursive relay. The proof-backed primary resolver remains responsible
    /// for trying authoritative DoH before such a stage is constructed.
    pub fn without_authoritative_doh(mut self) -> Self {
        self.authoritative_doh_enabled = false;
        self.prefer_authoritative_doh = false;
        self
    }

    pub fn into_parts(self) -> (T, V) {
        (self.transport, self.verifier)
    }

    fn authoritative_doh_endpoints(
        &self,
        delegation: &HnsDelegation,
    ) -> Result<Vec<AuthoritativeDohEndpoint>, ResolverError>
    where
        T: DnsTransport,
        V: DelegatedDnssecVerifier,
    {
        let cache_key = authoritative_doh_cache_key(delegation);
        if let Some(cached) = self
            .authoritative_doh_endpoint_cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&cache_key).cloned())
        {
            return Ok(cached);
        }

        let endpoints = authoritative_doh_endpoints(&self.transport, &self.verifier, delegation)?;
        if let Ok(mut cache) = self.authoritative_doh_endpoint_cache.lock() {
            cache.insert(cache_key, endpoints.clone());
        }
        Ok(endpoints)
    }
}

impl Default for AuthoritativeDnssecResolver {
    fn default() -> Self {
        Self::new(UdpTcpDnsTransport::default(), SystemDnssecVerifier)
    }
}

impl<T, V> DelegatedResolver for AuthoritativeDnssecResolver<T, V>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    fn resolve_delegated(
        &self,
        request: &ResolutionRequest,
        delegation: &HnsDelegation,
    ) -> Result<ResolutionAnswer, ResolverError> {
        if request.qtype == u16::MAX {
            return Err(ResolverError::UnsupportedBackend);
        }

        let request_name =
            DnsName::from_ascii(&request.qname).map_err(|_| ResolverError::UnsupportedBackend)?;
        let qtype = RecordType::from_code(request.qtype);
        let servers = nameserver_addresses(delegation);
        if servers.is_empty() {
            return Err(ResolverError::NoNameserverAddress);
        }

        let ds_rrset = records_for(&delegation.records, &delegation.owner, RecordType::Ds);
        let mut last_error = None;
        if self.authoritative_doh_enabled && self.prefer_authoritative_doh {
            match self.authoritative_doh_endpoints(delegation) {
                Ok(endpoints) => {
                    for endpoint in endpoints {
                        match resolve_delegated_from_doh_endpoint(
                            &self.transport,
                            &self.verifier,
                            &endpoint,
                            delegation,
                            &request_name,
                            qtype,
                            &ds_rrset,
                        ) {
                            Ok(answer) => return Ok(answer),
                            Err(error) => retain_strongest_resolution_error(&mut last_error, error),
                        }
                    }
                }
                Err(error) => retain_strongest_resolution_error(&mut last_error, error),
            }
        }

        if self.transport.is_recursive_relay() {
            let server = servers
                .iter()
                .copied()
                .find(|server| {
                    validate_dns_server(self.transport.endpoint_policy(), *server).is_ok()
                })
                .ok_or(ResolverError::NoNameserverAddress)?;
            return resolve_delegated_from_server_target(
                &self.transport,
                &self.verifier,
                server,
                DnsQueryTarget::Server(server),
                delegation,
                &request_name,
                qtype,
                &ds_rrset,
            );
        } else if self.transport.dns_interception_status() == DnsInterceptionStatus::Detected {
            last_error = Some(ResolverError::Port53InterceptionDetected);
        } else {
            for server in servers {
                match resolve_delegated_from_server(
                    &self.transport,
                    &self.verifier,
                    server,
                    delegation,
                    &request_name,
                    qtype,
                    &ds_rrset,
                ) {
                    Ok(answer) => return Ok(answer),
                    Err(ResolverError::Port53InterceptionDetected) => {
                        retain_strongest_resolution_error(
                            &mut last_error,
                            ResolverError::Port53InterceptionDetected,
                        );
                        break;
                    }
                    Err(error) => retain_strongest_resolution_error(&mut last_error, error),
                }
            }
        }

        if self.authoritative_doh_enabled && !self.prefer_authoritative_doh {
            match self.authoritative_doh_endpoints(delegation) {
                Ok(endpoints) => {
                    for endpoint in endpoints {
                        match resolve_delegated_from_doh_endpoint(
                            &self.transport,
                            &self.verifier,
                            &endpoint,
                            delegation,
                            &request_name,
                            qtype,
                            &ds_rrset,
                        ) {
                            Ok(answer) => return Ok(answer),
                            Err(error) => retain_strongest_resolution_error(&mut last_error, error),
                        }
                    }
                }
                Err(error) => retain_strongest_resolution_error(&mut last_error, error),
            }
        }

        self.transport.probe_dns_interception();
        Err(last_error.unwrap_or(ResolverError::NoNameserverAddress))
    }
}

fn retain_strongest_resolution_error(
    current: &mut Option<ResolverError>,
    candidate: ResolverError,
) {
    let candidate_priority = resolution_error_priority(&candidate);
    if current
        .as_ref()
        .is_none_or(|error| candidate_priority >= resolution_error_priority(error))
    {
        *current = Some(candidate);
    }
}

fn strongest_resolution_error(first: ResolverError, second: ResolverError) -> ResolverError {
    let mut strongest = Some(first);
    retain_strongest_resolution_error(&mut strongest, second);
    strongest.expect("a seeded strongest resolution error must remain present")
}

fn resolution_error_priority(error: &ResolverError) -> u8 {
    match error {
        // Only these typed availability failures may reach a separately
        // consented recursive fallback. Keep every authenticated-data,
        // response-validity, proof, and policy failure stronger so a later
        // transport failure cannot erase it.
        ResolverError::DnsTransport(_) => 0,
        ResolverError::Port53InterceptionDetected => 1,
        _ => 2,
    }
}

impl<P> ProofBackedResolver<P> {
    pub fn new(proof_provider: P) -> Self {
        Self { proof_provider }
    }

    pub fn into_inner(self) -> P {
        self.proof_provider
    }
}

impl<P: HnsProofProvider> Resolver for ProofBackedResolver<P> {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        let request_name =
            DnsName::from_ascii(&request.qname).map_err(|_| ResolverError::UnsupportedBackend)?;
        let root_name = hns_root_label(&request.qname)?;
        let name_hash = NameHash::from_name(&root_name)?;
        let proven = self.proof_provider.prove_name(&root_name, name_hash)?;
        if proven.root_name != root_name || proven.name_hash != name_hash || !proven.secure {
            return Err(ResolverError::ProofNameMismatch);
        }
        if !proven.exists {
            return Err(ResolverError::NameNotFound);
        }

        let records = filter_records(proven.records, &request_name, request.qtype);

        Ok(ResolutionAnswer {
            name: request_name,
            records,
            secure: true,
        })
    }
}

impl<P, D> DelegatingResolver<P, D> {
    pub fn new(proof_provider: P, delegated_resolver: D) -> Self {
        Self {
            proof_provider,
            delegated_resolver,
        }
    }

    pub fn into_parts(self) -> (P, D) {
        (self.proof_provider, self.delegated_resolver)
    }
}

impl<P, D> Resolver for DelegatingResolver<P, D>
where
    P: HnsProofProvider,
    D: DelegatedResolver,
{
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        let request_name =
            DnsName::from_ascii(&request.qname).map_err(|_| ResolverError::UnsupportedBackend)?;
        let root_name = hns_root_label(&request.qname)?;
        let root_owner =
            DnsName::from_ascii(&root_name).map_err(|_| ResolverError::UnsupportedBackend)?;
        let name_hash = NameHash::from_name(&root_name)?;
        let proven = self.proof_provider.prove_name(&root_name, name_hash)?;
        if proven.root_name != root_name || proven.name_hash != name_hash || !proven.secure {
            return Err(ResolverError::ProofNameMismatch);
        }
        if !proven.exists {
            return Err(ResolverError::NameNotFound);
        }
        let mut delegation_records = proven.records.clone();

        let direct_records =
            filter_records(delegation_records.clone(), &request_name, request.qtype);
        if (request_name == root_owner && !direct_records.is_empty())
            || root_records_answer_request(&request_name, &root_owner, request.qtype)
            || !has_owner_record(&delegation_records, &root_owner, RecordType::Ns)
        {
            return Ok(ResolutionAnswer {
                name: request_name.clone(),
                records: direct_records,
                secure: true,
            });
        }

        hydrate_hns_nameserver_addresses(
            &self.proof_provider,
            &root_owner,
            &mut delegation_records,
        )?;
        let delegation = HnsDelegation {
            root_name: root_name.clone(),
            owner: root_owner.clone(),
            records: delegation_records.clone(),
        };

        let has_secure_delegation =
            has_owner_record(&delegation_records, &root_owner, RecordType::Ds);
        let mut delegated = match self
            .delegated_resolver
            .resolve_delegated(request, &delegation)
        {
            Ok(answer) => answer,
            Err(ResolverError::NameNotFound) if !has_secure_delegation => {
                return Err(ResolverError::DnssecFailed);
            }
            Err(error) => return Err(error),
        };
        if !has_secure_delegation {
            delegated.secure = false;
            return Ok(delegated);
        }
        if !delegated.secure {
            return Err(ResolverError::DnssecFailed);
        }

        Ok(delegated)
    }
}

fn hydrate_hns_nameserver_addresses<P: HnsProofProvider>(
    proof_provider: &P,
    delegation_owner: &DnsName,
    records: &mut Vec<ResourceRecord>,
) -> Result<(), ResolverError> {
    let ns_names = records
        .iter()
        .filter(|record| record.name == *delegation_owner && record.record_type == RecordType::Ns)
        .filter_map(record_name_rdata)
        .fold(Vec::<DnsName>::new(), |mut names, name| {
            if !names.contains(&name) {
                names.push(name);
            }
            names
        });

    for ns_name in ns_names {
        if has_owner_record(records, &ns_name, RecordType::A)
            || has_owner_record(records, &ns_name, RecordType::Aaaa)
        {
            continue;
        }

        let Some(ns_root) = ns_name.labels().last().cloned() else {
            continue;
        };
        let name_hash = match NameHash::from_name(&ns_root) {
            Ok(name_hash) => name_hash,
            Err(_) => continue,
        };
        let proven = match proof_provider.prove_name(&ns_root, name_hash) {
            Ok(proven) => proven,
            Err(ResolverError::ProofUnavailable) => continue,
            Err(error) => return Err(error),
        };
        if proven.root_name != ns_root || proven.name_hash != name_hash || !proven.secure {
            return Err(ResolverError::ProofNameMismatch);
        }
        if !proven.exists {
            continue;
        }

        records.extend(proven.records.into_iter().filter(|record| {
            record.name == ns_name && matches!(record.record_type, RecordType::A | RecordType::Aaaa)
        }));
    }

    Ok(())
}

impl<P> ResourceValueProofProvider<P> {
    pub fn new(value_provider: P) -> Self {
        Self { value_provider }
    }

    pub fn into_inner(self) -> P {
        self.value_provider
    }
}

impl<P: HnsResourceValueProvider> HnsProofProvider for ResourceValueProofProvider<P> {
    fn prove_name(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<ProvenNameRecords, ResolverError> {
        let verified = self
            .value_provider
            .prove_resource_value(root_name, name_hash)?;
        if verified.root_name != root_name || verified.name_hash != name_hash || !verified.secure {
            return Err(ResolverError::ProofNameMismatch);
        }
        ProvenNameRecords::from_verified_resource_value(verified)
    }
}

impl MemoryResourceValueProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, mut verified: VerifiedResourceValue) -> Result<(), ResolverError> {
        let root_name = normalize_verified_root(&verified.root_name)?;
        verified = normalize_verified_resource_value(verified)?;
        self.values
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .insert((root_name, verified.name_hash), verified);
        Ok(())
    }

    pub fn len(&self) -> Result<usize, ResolverError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .len())
    }

    pub fn is_empty(&self) -> Result<bool, ResolverError> {
        Ok(self.len()? == 0)
    }
}

impl SqliteResourceValueProvider {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ResolverError> {
        let connection =
            Connection::open(path).map_err(|error| ResolverError::Storage(error.to_string()))?;
        Self::from_connection(connection)
    }

    pub fn in_memory() -> Result<Self, ResolverError> {
        let connection = Connection::open_in_memory()
            .map_err(|error| ResolverError::Storage(error.to_string()))?;
        Self::from_connection(connection)
    }

    pub fn from_connection(connection: Connection) -> Result<Self, ResolverError> {
        let provider = Self {
            connection: Mutex::new(connection),
        };
        provider.initialize()?;
        Ok(provider)
    }

    pub fn insert(&self, verified: VerifiedResourceValue) -> Result<(), ResolverError> {
        let verified = normalize_verified_resource_value(verified)?;
        let value = verified.value.as_deref();
        let secure = if verified.secure { 1_i64 } else { 0_i64 };
        let proof_tree_root = verified
            .anchor
            .map(|anchor| anchor.tree_root.as_bytes().as_slice().to_vec());
        let proof_height = verified.anchor.map(|anchor| i64::from(anchor.height.0));
        self.connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .execute(
                "
                INSERT INTO verified_resource_values(
                    root_name,
                    name_hash,
                    value,
                    secure,
                    proof_tree_root,
                    proof_height,
                    updated_at_unix
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, unixepoch())
                ON CONFLICT(root_name, name_hash) DO UPDATE SET
                    value = excluded.value,
                    secure = excluded.secure,
                    proof_tree_root = excluded.proof_tree_root,
                    proof_height = excluded.proof_height,
                    updated_at_unix = excluded.updated_at_unix
                ",
                params![
                    verified.root_name.as_str(),
                    verified.name_hash.as_hash().as_bytes().as_slice(),
                    value,
                    secure,
                    proof_tree_root,
                    proof_height,
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn len(&self) -> Result<usize, ResolverError> {
        let count = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .query_row("SELECT COUNT(*) FROM verified_resource_values", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(sqlite_error)?;
        usize::try_from(count).map_err(|error| ResolverError::Storage(error.to_string()))
    }

    pub fn is_empty(&self) -> Result<bool, ResolverError> {
        Ok(self.len()? == 0)
    }

    pub fn stats(&self) -> Result<ResourceValueCacheStats, ResolverError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        let (entries, value_bytes) = connection
            .query_row(
                "
                SELECT COUNT(*), COALESCE(SUM(COALESCE(length(value), 0)), 0)
                FROM verified_resource_values
                ",
                [],
                |row| {
                    let entries: i64 = row.get(0)?;
                    let value_bytes: i64 = row.get(1)?;
                    Ok((entries, value_bytes))
                },
            )
            .map_err(sqlite_error)?;

        Ok(ResourceValueCacheStats {
            entries: usize::try_from(entries)
                .map_err(|error| ResolverError::Storage(error.to_string()))?,
            value_bytes: usize::try_from(value_bytes)
                .map_err(|error| ResolverError::Storage(error.to_string()))?,
        })
    }

    pub fn total_value_bytes(&self) -> Result<usize, ResolverError> {
        self.stats().map(|stats| stats.value_bytes)
    }

    pub fn enforce_value_byte_limit(&self, max_bytes: usize) -> Result<usize, ResolverError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        let mut total = total_value_bytes_in(&transaction)?;
        let mut removed = 0usize;

        while total > max_bytes {
            let Some(entry) = oldest_resource_value_entry(&transaction)? else {
                break;
            };

            transaction
                .execute(
                    "
                    DELETE FROM verified_resource_values
                    WHERE root_name = ?1 AND name_hash = ?2
                    ",
                    params![entry.root_name, entry.name_hash.as_slice()],
                )
                .map_err(sqlite_error)?;
            total = total.saturating_sub(entry.value_bytes);
            removed = removed.saturating_add(1);
        }

        transaction.commit().map_err(sqlite_error)?;
        Ok(removed)
    }

    pub fn anchored_heights(&self) -> Result<Vec<Height>, ResolverError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        let mut statement = connection
            .prepare(
                "
                SELECT DISTINCT proof_height
                FROM verified_resource_values
                WHERE proof_tree_root IS NOT NULL AND proof_height IS NOT NULL
                ORDER BY proof_height DESC
                ",
            )
            .map_err(sqlite_error)?;
        let heights = statement
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(sqlite_error)?
            .map(|height| {
                let height = height.map_err(sqlite_error)?;
                let height = u32::try_from(height)
                    .map_err(|error| ResolverError::Storage(error.to_string()))?;
                Ok(Height(height))
            })
            .collect::<Result<Vec<_>, ResolverError>>()?;
        Ok(heights)
    }

    pub fn prune_invalid_anchors(
        &self,
        valid_anchors: &[ResourceValueAnchor],
        prune_unanchored: bool,
    ) -> Result<usize, ResolverError> {
        let valid_anchors = valid_anchors.iter().copied().collect::<BTreeSet<_>>();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        let entries = resource_value_anchor_entries(&transaction)?;
        let mut removed = 0usize;

        for entry in entries {
            let remove = match entry.anchor {
                Some(anchor) => !valid_anchors.contains(&anchor),
                None => prune_unanchored,
            };
            if !remove {
                continue;
            }

            transaction
                .execute(
                    "
                    DELETE FROM verified_resource_values
                    WHERE root_name = ?1 AND name_hash = ?2
                    ",
                    params![entry.root_name, entry.name_hash.as_slice()],
                )
                .map_err(sqlite_error)?;
            removed = removed.saturating_add(1);
        }

        transaction.commit().map_err(sqlite_error)?;
        Ok(removed)
    }

    pub fn clear(&self) -> Result<(), ResolverError> {
        self.connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .execute("DELETE FROM verified_resource_values", [])
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn flush(self) -> Result<(), ResolverError> {
        let connection = self
            .connection
            .into_inner()
            .map_err(|_| ResolverError::CachePoisoned)?;
        connection
            .close()
            .map_err(|(_, error)| ResolverError::Storage(error.to_string()))
    }

    fn initialize(&self) -> Result<(), ResolverError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?;
        connection
            .execute_batch(
                "
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS verified_resource_values (
                    root_name TEXT NOT NULL,
                    name_hash BLOB NOT NULL,
                    value BLOB,
                    secure INTEGER NOT NULL,
                    proof_tree_root BLOB,
                    proof_height INTEGER,
                    updated_at_unix INTEGER NOT NULL,
                    PRIMARY KEY(root_name, name_hash)
                );
                ",
            )
            .map_err(sqlite_error)?;
        ensure_sqlite_column(&connection, "proof_tree_root", "BLOB")?;
        ensure_sqlite_column(&connection, "proof_height", "INTEGER")?;
        connection
            .execute_batch(
                "
                CREATE INDEX IF NOT EXISTS verified_resource_values_by_anchor
                    ON verified_resource_values(proof_height, proof_tree_root);
                ",
            )
            .map_err(sqlite_error)?;
        Ok(())
    }
}

impl HnsResourceValueProvider for MemoryResourceValueProvider {
    fn prove_resource_value(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<VerifiedResourceValue, ResolverError> {
        let root_name = normalize_verified_root(root_name)?;
        if name_hash != NameHash::from_name(&root_name)? {
            return Err(ResolverError::ProofNameMismatch);
        }

        self.values
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .get(&(root_name, name_hash))
            .cloned()
            .ok_or(ResolverError::ProofUnavailable)
    }
}

impl HnsResourceValueProvider for SqliteResourceValueProvider {
    fn prove_resource_value(
        &self,
        root_name: &str,
        name_hash: NameHash,
    ) -> Result<VerifiedResourceValue, ResolverError> {
        let root_name = normalize_verified_root(root_name)?;
        if name_hash != NameHash::from_name(&root_name)? {
            return Err(ResolverError::ProofNameMismatch);
        }

        self.connection
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .query_row(
                "
                SELECT name_hash, value, secure, proof_tree_root, proof_height
                FROM verified_resource_values
                WHERE root_name = ?1 AND name_hash = ?2
                ",
                params![root_name, name_hash.as_hash().as_bytes().as_slice()],
                |row| {
                    let hash_bytes: Vec<u8> = row.get(0)?;
                    let value: Option<Vec<u8>> = row.get(1)?;
                    let secure: i64 = row.get(2)?;
                    let proof_tree_root: Option<Vec<u8>> = row.get(3)?;
                    let proof_height: Option<i64> = row.get(4)?;
                    let stored_hash = Hash::from_slice(&hash_bytes).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Blob,
                            Box::new(error),
                        )
                    })?;
                    let anchor = sqlite_anchor(proof_tree_root, proof_height)?;
                    Ok(VerifiedResourceValue {
                        root_name: root_name.clone(),
                        name_hash: NameHash::new(stored_hash),
                        value,
                        secure: secure != 0,
                        anchor,
                    })
                },
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or(ResolverError::ProofUnavailable)
    }
}

impl<R> CachedResolver<R> {
    pub fn new(inner: R, max_entries: usize, ttl: Duration) -> Self {
        Self {
            inner,
            cache: Mutex::new(ExpiringLru::new(
                NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::MIN),
            )),
            ttl,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Resolver> Resolver for CachedResolver<R> {
    fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
        if let Some(cached) = self
            .cache
            .lock()
            .map_err(|_| ResolverError::CachePoisoned)?
            .get(request)
        {
            return cached.into_result();
        }

        match self.inner.resolve(request) {
            Ok(answer) => {
                let mut cache = self
                    .cache
                    .lock()
                    .map_err(|_| ResolverError::CachePoisoned)?;
                if cache
                    .insert(
                        request.clone(),
                        CachedResolution::Answer(answer.clone()),
                        self.ttl,
                    )
                    .is_err()
                {
                    cache.clear();
                }
                Ok(answer)
            }
            Err(ResolverError::NameNotFound) => {
                let mut cache = self
                    .cache
                    .lock()
                    .map_err(|_| ResolverError::CachePoisoned)?;
                if cache
                    .insert(request.clone(), CachedResolution::NameNotFound, self.ttl)
                    .is_err()
                {
                    cache.clear();
                }
                Err(ResolverError::NameNotFound)
            }
            Err(error) => Err(error),
        }
    }
}

impl CachedResolution {
    fn into_result(self) -> Result<ResolutionAnswer, ResolverError> {
        match self {
            Self::Answer(answer) => Ok(answer),
            Self::NameNotFound => Err(ResolverError::NameNotFound),
        }
    }
}

fn normalize_verified_root(root_name: &str) -> Result<String, ResolverError> {
    hns_root_label(root_name)
}

fn normalize_verified_resource_value(
    mut verified: VerifiedResourceValue,
) -> Result<VerifiedResourceValue, ResolverError> {
    let root_name = normalize_verified_root(&verified.root_name)?;
    if verified.name_hash != NameHash::from_name(&root_name)? {
        return Err(ResolverError::ProofNameMismatch);
    }

    verified.root_name = root_name;
    Ok(verified)
}

struct ResourceValueEntry {
    root_name: String,
    name_hash: Vec<u8>,
    value_bytes: usize,
}

struct ResourceValueAnchorEntry {
    root_name: String,
    name_hash: Vec<u8>,
    anchor: Option<ResourceValueAnchor>,
}

fn total_value_bytes_in(connection: &Connection) -> Result<usize, ResolverError> {
    let value_bytes = connection
        .query_row(
            "
            SELECT COALESCE(SUM(COALESCE(length(value), 0)), 0)
            FROM verified_resource_values
            ",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    usize::try_from(value_bytes).map_err(|error| ResolverError::Storage(error.to_string()))
}

fn oldest_resource_value_entry(
    connection: &Connection,
) -> Result<Option<ResourceValueEntry>, ResolverError> {
    connection
        .query_row(
            "
            SELECT root_name, name_hash, COALESCE(length(value), 0)
            FROM verified_resource_values
            ORDER BY updated_at_unix ASC, root_name ASC, name_hash ASC
            LIMIT 1
            ",
            [],
            |row| {
                let root_name: String = row.get(0)?;
                let name_hash: Vec<u8> = row.get(1)?;
                let value_bytes: i64 = row.get(2)?;
                Ok((root_name, name_hash, value_bytes))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .map(|(root_name, name_hash, value_bytes)| {
            Ok(ResourceValueEntry {
                root_name,
                name_hash,
                value_bytes: usize::try_from(value_bytes)
                    .map_err(|error| ResolverError::Storage(error.to_string()))?,
            })
        })
        .transpose()
}

fn resource_value_anchor_entries(
    connection: &Connection,
) -> Result<Vec<ResourceValueAnchorEntry>, ResolverError> {
    let mut statement = connection
        .prepare(
            "
            SELECT root_name, name_hash, proof_tree_root, proof_height
            FROM verified_resource_values
            ",
        )
        .map_err(sqlite_error)?;
    statement
        .query_map([], |row| {
            let root_name: String = row.get(0)?;
            let name_hash: Vec<u8> = row.get(1)?;
            let proof_tree_root: Option<Vec<u8>> = row.get(2)?;
            let proof_height: Option<i64> = row.get(3)?;
            let anchor = sqlite_anchor(proof_tree_root, proof_height)?;
            Ok(ResourceValueAnchorEntry {
                root_name,
                name_hash,
                anchor,
            })
        })
        .map_err(sqlite_error)?
        .map(|entry| entry.map_err(sqlite_error))
        .collect()
}

fn sqlite_anchor(
    proof_tree_root: Option<Vec<u8>>,
    proof_height: Option<i64>,
) -> rusqlite::Result<Option<ResourceValueAnchor>> {
    match (proof_tree_root, proof_height) {
        (Some(root), Some(height)) => {
            let tree_root = Hash::from_slice(&root).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;
            let height = u32::try_from(height).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?;
            Ok(Some(ResourceValueAnchor {
                tree_root,
                height: Height(height),
            }))
        }
        _ => Ok(None),
    }
}

fn ensure_sqlite_column(
    connection: &Connection,
    column: &str,
    column_type: &str,
) -> Result<(), ResolverError> {
    let mut statement = connection
        .prepare("PRAGMA table_info(verified_resource_values)")
        .map_err(sqlite_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    if columns.iter().any(|existing| existing == column) {
        return Ok(());
    }

    connection
        .execute_batch(&format!(
            "ALTER TABLE verified_resource_values ADD COLUMN {column} {column_type};"
        ))
        .map_err(sqlite_error)
}

fn sqlite_error(error: rusqlite::Error) -> ResolverError {
    ResolverError::Storage(error.to_string())
}

fn filter_records(
    records: Vec<ResourceRecord>,
    request_name: &DnsName,
    qtype: u16,
) -> Vec<ResourceRecord> {
    if qtype == u16::MAX {
        return records;
    }

    let qtype = RecordType::from_code(qtype);
    records
        .into_iter()
        .filter(|record| record.name == *request_name && record.record_type == qtype)
        .collect()
}

fn root_records_answer_request(request_name: &DnsName, root_owner: &DnsName, qtype: u16) -> bool {
    if request_name != root_owner {
        return false;
    }

    if qtype == u16::MAX {
        return true;
    }

    matches!(
        RecordType::from_code(qtype),
        RecordType::Ds | RecordType::Ns | RecordType::Txt
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthoritativeDohTemplate {
    ns: DnsName,
    host: String,
    port: u16,
    path_and_query: String,
    tls_authentication: AuthoritativeDohTlsAuthentication,
}

fn key_value_part(part: &str) -> Option<(&str, &str)> {
    let (key, value) = part.trim().split_once('=')?;
    let key = key.trim();
    let value = value.trim();
    (!key.is_empty() && !value.is_empty()).then_some((key, value))
}

fn txt_rdata_strings(rdata: &[u8]) -> Result<Vec<String>, ResolverError> {
    let mut cursor = 0usize;
    let mut strings = Vec::new();
    while cursor < rdata.len() {
        let length = *rdata
            .get(cursor)
            .ok_or(ResolverError::InvalidAuthoritativeDoh)? as usize;
        cursor += 1;
        let end = cursor
            .checked_add(length)
            .ok_or(ResolverError::InvalidAuthoritativeDoh)?;
        let bytes = rdata
            .get(cursor..end)
            .ok_or(ResolverError::InvalidAuthoritativeDoh)?;
        strings.push(
            std::str::from_utf8(bytes)
                .map_err(|_| ResolverError::InvalidAuthoritativeDoh)?
                .to_owned(),
        );
        cursor = end;
    }
    Ok(strings)
}

fn hnsdns_is_declared(text: &str) -> bool {
    text.split(';').any(|part| {
        key_value_part(part).is_some_and(|(key, value)| {
            key.eq_ignore_ascii_case("hnsdns") && value == HNSDNS_VERSION
        })
    })
}

fn authoritative_doh_templates_from_hns(
    delegation: &HnsDelegation,
) -> Result<Vec<AuthoritativeDohTemplate>, ResolverError> {
    let mut templates = Vec::new();
    for record in delegation
        .records
        .iter()
        .filter(|record| record.name == delegation.owner && record.record_type == RecordType::Txt)
    {
        for text in txt_rdata_strings(&record.rdata)? {
            let Some(template) = parse_hnsdns_declaration(&text, &delegation.owner)? else {
                continue;
            };
            if !templates.contains(&template) {
                templates.push(template);
            }
        }
    }
    Ok(templates)
}

fn parse_hnsdns_declaration(
    text: &str,
    root_owner: &DnsName,
) -> Result<Option<AuthoritativeDohTemplate>, ResolverError> {
    if !hnsdns_is_declared(text) {
        return Ok(None);
    }
    if text.len() > HNSDNS_MAX_TEXT_BYTES {
        return Err(ResolverError::InvalidAuthoritativeDoh);
    }

    let mut saw_version = false;
    let mut ns = None;
    let mut transport = None;
    let mut doh_uri = None;
    let mut explicit_port = None;
    let mut explicit_path = None;
    let mut proof_tlsa_records = Vec::new();
    for part in text.split(';') {
        let (key, value) = key_value_part(part).ok_or(ResolverError::InvalidAuthoritativeDoh)?;
        match key.to_ascii_lowercase().as_str() {
            "hnsdns" if value == HNSDNS_VERSION => saw_version = true,
            "hnsdns" => return Err(ResolverError::InvalidAuthoritativeDoh),
            "ns" => {
                if ns.is_some() {
                    return Err(ResolverError::InvalidAuthoritativeDoh);
                }
                ns = Some(hnsdns_ns_name(root_owner, value)?);
            }
            "transport" => {
                if transport.replace(value.to_ascii_lowercase()).is_some() {
                    return Err(ResolverError::InvalidAuthoritativeDoh);
                }
            }
            "doh" => {
                if doh_uri.replace(parse_doh_uri_template(value)?).is_some() {
                    return Err(ResolverError::InvalidAuthoritativeDoh);
                }
            }
            "port" => {
                let port = value
                    .parse::<u16>()
                    .map_err(|_| ResolverError::InvalidAuthoritativeDoh)?;
                if explicit_port.replace(port).is_some() {
                    return Err(ResolverError::InvalidAuthoritativeDoh);
                }
            }
            "path" => {
                let path = normalize_doh_path(value)?;
                if explicit_path.replace(path).is_some() {
                    return Err(ResolverError::InvalidAuthoritativeDoh);
                }
            }
            "tlsa" => {
                let record = parse_hnsdns_tlsa(value)?;
                if !proof_tlsa_records.contains(&record) {
                    if proof_tlsa_records.len() >= HNSDNS_MAX_TLSA_PINS {
                        return Err(ResolverError::InvalidAuthoritativeDoh);
                    }
                    proof_tlsa_records.push(record);
                }
            }
            _ => {}
        }
    }

    if !saw_version || transport.as_deref().is_some_and(|value| value != "doh") {
        return Err(ResolverError::InvalidAuthoritativeDoh);
    }
    let ns = ns.ok_or(ResolverError::InvalidAuthoritativeDoh)?;
    let (host, port, path_and_query) = doh_uri.unwrap_or_else(|| {
        (
            ns.to_string().trim_end_matches('.').to_ascii_lowercase(),
            DEFAULT_DOH_PORT,
            DEFAULT_DOH_PATH.to_owned(),
        )
    });
    Ok(Some(AuthoritativeDohTemplate {
        ns,
        host,
        port: explicit_port.unwrap_or(port),
        path_and_query: explicit_path.unwrap_or(path_and_query),
        tls_authentication: if proof_tlsa_records.is_empty() {
            AuthoritativeDohTlsAuthentication::WebPki
        } else {
            AuthoritativeDohTlsAuthentication::HnsProofTlsa(proof_tlsa_records)
        },
    }))
}

fn parse_hnsdns_tlsa(value: &str) -> Result<TlsaRecord, ResolverError> {
    let fields = value.split(',').map(str::trim).collect::<Vec<_>>();
    let [usage, selector, matching, association] = fields.as_slice() else {
        return Err(ResolverError::InvalidAuthoritativeDoh);
    };
    if *usage != "3" || *selector != "1" || *matching != "1" {
        return Err(ResolverError::InvalidAuthoritativeDoh);
    }
    let digest = Hash::from_hex(association).map_err(|_| ResolverError::InvalidAuthoritativeDoh)?;
    Ok(TlsaRecord {
        usage: TlsaUsage::DaneEe,
        selector: TlsaSelector::SubjectPublicKeyInfo,
        matching: TlsaMatching::Sha256,
        association_data: digest.into_bytes().to_vec(),
    })
}

fn hnsdns_ns_name(root_owner: &DnsName, value: &str) -> Result<DnsName, ResolverError> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value == "@" || value.contains('*') {
        return Err(ResolverError::InvalidAuthoritativeDoh);
    }
    let name = DnsName::from_ascii(&value).map_err(|_| ResolverError::InvalidAuthoritativeDoh)?;
    if name.labels().len() == 1 {
        DnsName::from_ascii(&format!("{name}.{root_owner}"))
            .map_err(|_| ResolverError::InvalidAuthoritativeDoh)
    } else {
        Ok(name)
    }
}

fn parse_doh_uri_template(value: &str) -> Result<(String, u16, String), ResolverError> {
    let value = value.trim();
    let remainder = value
        .get(..8)
        .filter(|scheme| scheme.eq_ignore_ascii_case("https://"))
        .and_then(|_| value.get(8..))
        .ok_or(ResolverError::InvalidAuthoritativeDoh)?;
    if remainder.contains('#')
        || remainder
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(ResolverError::InvalidAuthoritativeDoh);
    }
    let (authority, raw_path) = remainder
        .split_once('/')
        .unwrap_or((remainder, DEFAULT_DOH_PATH.trim_start_matches('/')));
    if authority.is_empty() || authority.contains('@') {
        return Err(ResolverError::InvalidAuthoritativeDoh);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (
            host,
            port.parse::<u16>()
                .map_err(|_| ResolverError::InvalidAuthoritativeDoh)?,
        ),
        Some(_) => return Err(ResolverError::InvalidAuthoritativeDoh),
        None => (authority, DEFAULT_DOH_PORT),
    };
    let host = normalize_doh_host(host)?;
    let path_and_query = normalize_doh_path(&format!("/{raw_path}"))?;
    Ok((host, port, path_and_query))
}

fn normalize_doh_host(host: &str) -> Result<String, ResolverError> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'?' | b'#' | b'@' | b' '))
        || DnsName::from_ascii(&host).is_err()
    {
        return Err(ResolverError::InvalidAuthoritativeDoh);
    }
    Ok(host)
}

fn normalize_doh_path(path: &str) -> Result<String, ResolverError> {
    let mut path = path.trim();
    if let Some(stripped) = path.strip_suffix(DOH_URI_TEMPLATE_DNS_VARIABLE) {
        path = stripped;
    }
    if !path.starts_with('/') {
        return Err(ResolverError::InvalidAuthoritativeDoh);
    }
    if path.is_empty()
        || path.contains('#')
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(ResolverError::InvalidAuthoritativeDoh);
    }
    Ok(path.to_owned())
}

fn authoritative_doh_endpoints<T, V>(
    transport: &T,
    verifier: &V,
    delegation: &HnsDelegation,
) -> Result<Vec<AuthoritativeDohEndpoint>, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    let mut endpoints = Vec::new();

    let address_map = nameserver_ip_addresses(delegation);
    for template in authoritative_doh_templates_from_hns(delegation)? {
        for (ns, address) in &address_map {
            if *ns != template.ns {
                continue;
            }
            let endpoint = AuthoritativeDohEndpoint {
                ns: template.ns.clone(),
                host: template.host.clone(),
                connect_addr: *address,
                port: template.port,
                path_and_query: template.path_and_query.clone(),
                tls_authentication: template.tls_authentication.clone(),
            };
            if !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }
    }
    if !endpoints.is_empty() {
        return Ok(endpoints);
    }
    let ds_rrset = records_for(&delegation.records, &delegation.owner, RecordType::Ds);
    if ds_rrset.is_empty() {
        return Ok(endpoints);
    }
    for (ns, address) in address_map {
        let server = SocketAddr::new(address, 53);
        let service_name = dns_service_binding_name(&ns)?;
        let response = match resolve_delegated_from_server(
            transport,
            verifier,
            server,
            delegation,
            &service_name,
            RecordType::Svcb,
            &ds_rrset,
        ) {
            Ok(response) => response,
            Err(_) => continue,
        };

        if !response.secure {
            continue;
        }
        for record in records_for(&response.records, &service_name, RecordType::Svcb) {
            let Some(template) = authoritative_doh_template_from_svcb(&ns, &record)? else {
                continue;
            };
            let endpoint = AuthoritativeDohEndpoint {
                ns: template.ns,
                host: template.host,
                connect_addr: address,
                port: template.port,
                path_and_query: template.path_and_query,
                tls_authentication: template.tls_authentication,
            };
            if !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }
    }

    Ok(endpoints)
}

fn authoritative_doh_cache_key(delegation: &HnsDelegation) -> String {
    let records = delegation
        .records
        .iter()
        .map(|record| {
            format!(
                "{}:{}:{}:{}:{:02x?}",
                record.name,
                record.record_type.code(),
                record.class,
                record.ttl,
                record.rdata,
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    let servers = nameserver_ip_addresses(delegation)
        .into_iter()
        .map(|(ns, address)| format!("{ns}@{address}"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    format!("{}|{}|{}", delegation.owner, servers, records)
}

fn dns_service_binding_name(ns: &DnsName) -> Result<DnsName, ResolverError> {
    DnsName::from_ascii(&format!("_dns.{ns}")).map_err(|_| ResolverError::InvalidAuthoritativeDoh)
}

fn authoritative_doh_template_from_svcb(
    ns: &DnsName,
    record: &ResourceRecord,
) -> Result<Option<AuthoritativeDohTemplate>, ResolverError> {
    let svcb =
        SvcbRecord::from_record(record).map_err(|_| ResolverError::InvalidAuthoritativeDoh)?;
    if svcb.is_alias_mode() || !svcb_mandatory_keys_supported(&svcb) {
        return Ok(None);
    }

    let target = if svcb.target_name == DnsName::root() {
        ns.clone()
    } else {
        svcb.target_name.clone()
    };
    let alpn_ids = svcb
        .alpn_ids()
        .map_err(|_| ResolverError::InvalidAuthoritativeDoh)?;
    if !alpn_ids.iter().any(|id| id.as_slice() == b"h2") {
        return Ok(None);
    }

    let Some(dohpath) = svcb.param(SVCB_PARAM_DOHPATH) else {
        return Ok(None);
    };
    let path_and_query = doh_path_from_svcb_param(dohpath)?;
    let port = svcb
        .port()
        .map_err(|_| ResolverError::InvalidAuthoritativeDoh)?
        .unwrap_or(DEFAULT_DOH_PORT);

    Ok(Some(AuthoritativeDohTemplate {
        ns: ns.clone(),
        host: target
            .to_string()
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        port,
        path_and_query,
        tls_authentication: AuthoritativeDohTlsAuthentication::WebPki,
    }))
}

fn svcb_mandatory_keys_supported(svcb: &SvcbRecord) -> bool {
    let Some(value) = svcb.param(SVCB_PARAM_MANDATORY) else {
        return true;
    };
    value.chunks_exact(2).all(|chunk| {
        let key = u16::from_be_bytes([chunk[0], chunk[1]]);
        matches!(
            key,
            SVCB_PARAM_ALPN
                | SVCB_PARAM_PORT
                | SVCB_PARAM_IPV4HINT
                | SVCB_PARAM_IPV6HINT
                | SVCB_PARAM_DOHPATH
        )
    })
}

fn doh_path_from_svcb_param(value: &[u8]) -> Result<String, ResolverError> {
    let template =
        std::str::from_utf8(value).map_err(|_| ResolverError::InvalidAuthoritativeDoh)?;
    if !template.contains("dns") {
        return Err(ResolverError::InvalidAuthoritativeDoh);
    }
    normalize_doh_path(template)
}

fn has_owner_record(records: &[ResourceRecord], owner: &DnsName, record_type: RecordType) -> bool {
    records
        .iter()
        .any(|record| record.name == *owner && record.record_type == record_type)
}

fn resolve_delegated_from_server<T, V>(
    transport: &T,
    verifier: &V,
    server: SocketAddr,
    delegation: &HnsDelegation,
    request_name: &DnsName,
    qtype: RecordType,
    ds_rrset: &[ResourceRecord],
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    match resolve_delegated_from_server_target(
        transport,
        verifier,
        server,
        DnsQueryTarget::Server(server),
        delegation,
        request_name,
        qtype,
        ds_rrset,
    ) {
        Err(ResolverError::DnssecFailed)
            if transport.probe_dns_interception() == DnsInterceptionStatus::Detected =>
        {
            Err(ResolverError::Port53InterceptionDetected)
        }
        Err(ResolverError::DnssecFailed) => {
            match resolve_delegated_from_server_target(
                transport,
                verifier,
                server,
                DnsQueryTarget::ServerTcp(server),
                delegation,
                request_name,
                qtype,
                ds_rrset,
            ) {
                Ok(answer) => Ok(answer),
                Err(error) => Err(strongest_resolution_error(
                    ResolverError::DnssecFailed,
                    error,
                )),
            }
        }
        result => result,
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_delegated_from_server_target<T, V>(
    transport: &T,
    verifier: &V,
    server: SocketAddr,
    target: DnsQueryTarget<'_>,
    delegation: &HnsDelegation,
    request_name: &DnsName,
    qtype: RecordType,
    ds_rrset: &[ResourceRecord],
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    let target_response = dns_query_target(transport, target, request_name, qtype)?;
    let target_rrset = records_for(&target_response.answers, request_name, qtype);

    if ds_rrset.is_empty() {
        return Ok(ResolutionAnswer {
            name: request_name.clone(),
            records: target_rrset,
            secure: false,
        });
    }

    let dnskey_response =
        dns_query_target(transport, target, &delegation.owner, RecordType::Dnskey)?;
    let dnskey_rrset = records_for(
        &dnskey_response.answers,
        &delegation.owner,
        RecordType::Dnskey,
    );
    let dnskey_rrsig_rrset = records_for(
        &dnskey_response.answers,
        &delegation.owner,
        RecordType::Rrsig,
    );
    if target_response.header.flags.rcode() == DNS_RCODE_NXDOMAIN {
        return resolve_secure_name_error(
            verifier,
            NameErrorResolutionInput {
                delegation,
                request_name,
                ds_rrset,
                dnskey_rrset: &dnskey_rrset,
                dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                response: &target_response,
                prefix_records: &[],
            },
        );
    }
    if let Some(referral) = child_referral(&target_response, &delegation.owner, request_name) {
        return resolve_secure_child_referral(
            transport,
            verifier,
            ChildReferralResolutionInput {
                parent_delegation: delegation,
                referral,
                request_name,
                qtype,
                parent_ds_rrset: ds_rrset,
                parent_dnskey_rrset: &dnskey_rrset,
                parent_dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
            },
        );
    }
    let target_rrsig_rrset = records_for(&target_response.answers, request_name, RecordType::Rrsig);
    if let Some(child_owner) = inline_child_answer_signer(
        delegation,
        request_name,
        &target_rrset,
        &target_rrsig_rrset,
        qtype,
    ) {
        return resolve_secure_inline_child_answer(
            transport,
            verifier,
            InlineChildAnswerResolutionInput {
                parent_delegation: delegation,
                child_owner,
                server,
                request_name,
                parent_ds_rrset: ds_rrset,
                parent_dnskey_rrset: &dnskey_rrset,
                parent_dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                target_rrset: &target_rrset,
                target_rrsig_rrset: &target_rrsig_rrset,
            },
        );
    }
    if target_rrset.is_empty()
        && records_for(&target_response.answers, request_name, RecordType::Cname).is_empty()
    {
        let proof_records = combined_response_records(&target_response);
        if let Some(child_owner) =
            inline_child_denial_signer(delegation, request_name, &proof_records)
        {
            return resolve_secure_inline_child_no_data(
                transport,
                verifier,
                InlineChildNoDataResolutionInput {
                    parent_delegation: delegation,
                    child_owner,
                    server,
                    request_name,
                    qtype,
                    parent_ds_rrset: ds_rrset,
                    parent_dnskey_rrset: &dnskey_rrset,
                    parent_dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                    response: &target_response,
                    prefix_records: &[],
                },
            );
        }
        return resolve_secure_no_data(
            verifier,
            NoDataResolutionInput {
                delegation,
                request_name,
                qtype,
                ds_rrset,
                dnskey_rrset: &dnskey_rrset,
                dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                response: &target_response,
                prefix_records: &[],
            },
        );
    }

    if dnskey_rrset.is_empty() || dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }

    resolve_secure_answer_records(SecureAnswerResolutionInput {
        transport,
        verifier,
        target,
        delegation,
        request_name,
        qtype,
        ds_rrset,
        dnskey_rrset: &dnskey_rrset,
        dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
        initial_response: target_response,
    })
}

fn resolve_delegated_from_doh_endpoint<T, V>(
    transport: &T,
    verifier: &V,
    endpoint: &AuthoritativeDohEndpoint,
    delegation: &HnsDelegation,
    request_name: &DnsName,
    qtype: RecordType,
    ds_rrset: &[ResourceRecord],
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    let target_response = dns_query_doh(transport, endpoint, request_name, qtype)?;
    let target_rrset = records_for(&target_response.answers, request_name, qtype);

    if ds_rrset.is_empty() {
        return Ok(ResolutionAnswer {
            name: request_name.clone(),
            records: target_rrset,
            secure: false,
        });
    }

    let dnskey_response =
        dns_query_doh(transport, endpoint, &delegation.owner, RecordType::Dnskey)?;
    let dnskey_rrset = records_for(
        &dnskey_response.answers,
        &delegation.owner,
        RecordType::Dnskey,
    );
    let dnskey_rrsig_rrset = records_for(
        &dnskey_response.answers,
        &delegation.owner,
        RecordType::Rrsig,
    );
    if target_response.header.flags.rcode() == DNS_RCODE_NXDOMAIN {
        return resolve_secure_name_error(
            verifier,
            NameErrorResolutionInput {
                delegation,
                request_name,
                ds_rrset,
                dnskey_rrset: &dnskey_rrset,
                dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                response: &target_response,
                prefix_records: &[],
            },
        );
    }
    if let Some(referral) = child_referral(&target_response, &delegation.owner, request_name) {
        return resolve_secure_child_referral(
            transport,
            verifier,
            ChildReferralResolutionInput {
                parent_delegation: delegation,
                referral,
                request_name,
                qtype,
                parent_ds_rrset: ds_rrset,
                parent_dnskey_rrset: &dnskey_rrset,
                parent_dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
            },
        );
    }
    let target_rrsig_rrset = records_for(&target_response.answers, request_name, RecordType::Rrsig);
    if let Some(child_owner) = inline_child_answer_signer(
        delegation,
        request_name,
        &target_rrset,
        &target_rrsig_rrset,
        qtype,
    ) {
        return resolve_secure_inline_child_answer(
            transport,
            verifier,
            InlineChildAnswerResolutionInput {
                parent_delegation: delegation,
                child_owner,
                server: SocketAddr::new(endpoint.connect_addr, endpoint.port),
                request_name,
                parent_ds_rrset: ds_rrset,
                parent_dnskey_rrset: &dnskey_rrset,
                parent_dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                target_rrset: &target_rrset,
                target_rrsig_rrset: &target_rrsig_rrset,
            },
        );
    }
    if target_rrset.is_empty()
        && records_for(&target_response.answers, request_name, RecordType::Cname).is_empty()
    {
        let proof_records = combined_response_records(&target_response);
        if let Some(child_owner) =
            inline_child_denial_signer(delegation, request_name, &proof_records)
        {
            return resolve_secure_inline_child_no_data(
                transport,
                verifier,
                InlineChildNoDataResolutionInput {
                    parent_delegation: delegation,
                    child_owner,
                    server: SocketAddr::new(endpoint.connect_addr, endpoint.port),
                    request_name,
                    qtype,
                    parent_ds_rrset: ds_rrset,
                    parent_dnskey_rrset: &dnskey_rrset,
                    parent_dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                    response: &target_response,
                    prefix_records: &[],
                },
            );
        }
        return resolve_secure_no_data(
            verifier,
            NoDataResolutionInput {
                delegation,
                request_name,
                qtype,
                ds_rrset,
                dnskey_rrset: &dnskey_rrset,
                dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                response: &target_response,
                prefix_records: &[],
            },
        );
    }

    if dnskey_rrset.is_empty() || dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }

    resolve_secure_answer_records(SecureAnswerResolutionInput {
        transport,
        verifier,
        target: DnsQueryTarget::Doh(endpoint),
        delegation,
        request_name,
        qtype,
        ds_rrset,
        dnskey_rrset: &dnskey_rrset,
        dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
        initial_response: target_response,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ChildReferral {
    owner: DnsName,
    ds_rrset: Vec<ResourceRecord>,
    ds_rrsig_rrset: Vec<ResourceRecord>,
    servers: Vec<SocketAddr>,
}

struct ChildReferralResolutionInput<'a> {
    parent_delegation: &'a HnsDelegation,
    referral: ChildReferral,
    request_name: &'a DnsName,
    qtype: RecordType,
    parent_ds_rrset: &'a [ResourceRecord],
    parent_dnskey_rrset: &'a [ResourceRecord],
    parent_dnskey_rrsig_rrset: &'a [ResourceRecord],
}

struct InlineChildAnswerResolutionInput<'a> {
    parent_delegation: &'a HnsDelegation,
    child_owner: DnsName,
    server: SocketAddr,
    request_name: &'a DnsName,
    parent_ds_rrset: &'a [ResourceRecord],
    parent_dnskey_rrset: &'a [ResourceRecord],
    parent_dnskey_rrsig_rrset: &'a [ResourceRecord],
    target_rrset: &'a [ResourceRecord],
    target_rrsig_rrset: &'a [ResourceRecord],
}

struct InlineChildNoDataResolutionInput<'a> {
    parent_delegation: &'a HnsDelegation,
    child_owner: DnsName,
    server: SocketAddr,
    request_name: &'a DnsName,
    qtype: RecordType,
    parent_ds_rrset: &'a [ResourceRecord],
    parent_dnskey_rrset: &'a [ResourceRecord],
    parent_dnskey_rrsig_rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
    prefix_records: &'a [ResourceRecord],
}

struct InlineChildDnssecMaterial {
    child_ds_rrset: Vec<ResourceRecord>,
    child_ds_rrsig_rrset: Vec<ResourceRecord>,
    child_dnskey_rrset: Vec<ResourceRecord>,
    child_dnskey_rrsig_rrset: Vec<ResourceRecord>,
}

fn resolve_secure_child_referral<T, V>(
    transport: &T,
    verifier: &V,
    input: ChildReferralResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    if input.parent_dnskey_rrset.is_empty()
        || input.parent_dnskey_rrsig_rrset.is_empty()
        || input.referral.ds_rrset.is_empty()
        || input.referral.ds_rrsig_rrset.is_empty()
    {
        return Err(ResolverError::DnssecFailed);
    }
    if input.referral.servers.is_empty() {
        return Err(ResolverError::NoNameserverAddress);
    }

    if transport.is_recursive_relay() {
        let server = input
            .referral
            .servers
            .iter()
            .copied()
            .find(|server| validate_dns_server(transport.endpoint_policy(), *server).is_ok())
            .ok_or(ResolverError::NoNameserverAddress)?;
        return resolve_secure_child_from_server(transport, verifier, server, &input);
    }

    let mut last_error = None;
    for &server in &input.referral.servers {
        match resolve_secure_child_from_server(transport, verifier, server, &input) {
            Ok(answer) => return Ok(answer),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or(ResolverError::NoNameserverAddress))
}

fn resolve_secure_inline_child_answer<T, V>(
    transport: &T,
    verifier: &V,
    input: InlineChildAnswerResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    if input.parent_dnskey_rrset.is_empty()
        || input.parent_dnskey_rrsig_rrset.is_empty()
        || input.target_rrset.is_empty()
        || input.target_rrsig_rrset.is_empty()
    {
        return Err(ResolverError::DnssecFailed);
    }

    let child_material =
        fetch_inline_child_dnssec_material(transport, input.server, &input.child_owner)?;

    let secure = verifier.validate_child_positive_rrset(DelegatedChildDnssecValidation {
        parent_dnskey_owner: &input.parent_delegation.owner,
        parent_ds_rrset: input.parent_ds_rrset,
        parent_dnskey_rrset: input.parent_dnskey_rrset,
        parent_dnskey_rrsig_rrset: input.parent_dnskey_rrsig_rrset,
        child_dnskey_owner: &input.child_owner,
        child_ds_rrset: &child_material.child_ds_rrset,
        child_ds_rrsig_rrset: &child_material.child_ds_rrsig_rrset,
        child_dnskey_rrset: &child_material.child_dnskey_rrset,
        child_dnskey_rrsig_rrset: &child_material.child_dnskey_rrsig_rrset,
        target_rrset: input.target_rrset,
        target_rrsig_rrset: input.target_rrsig_rrset,
    })?;
    if !secure {
        return Err(ResolverError::DnssecFailed);
    }

    Ok(ResolutionAnswer {
        name: input.request_name.clone(),
        records: input.target_rrset.to_vec(),
        secure: true,
    })
}

fn resolve_secure_inline_child_no_data<T, V>(
    transport: &T,
    verifier: &V,
    input: InlineChildNoDataResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    if input.parent_dnskey_rrset.is_empty() || input.parent_dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }

    let child_material =
        fetch_inline_child_dnssec_material(transport, input.server, &input.child_owner)?;
    let proof_records = combined_response_records(input.response);
    let nsec_rrset = records_for(&proof_records, input.request_name, RecordType::Nsec);
    let nsec_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let nsec3_rrset = records_of_type(&proof_records, RecordType::Nsec3);
    let nsec3_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let secure = verifier.validate_child_no_data(DelegatedChildDnssecNoDataValidation {
        parent_dnskey_owner: &input.parent_delegation.owner,
        parent_ds_rrset: input.parent_ds_rrset,
        parent_dnskey_rrset: input.parent_dnskey_rrset,
        parent_dnskey_rrsig_rrset: input.parent_dnskey_rrsig_rrset,
        child_dnskey_owner: &input.child_owner,
        child_ds_rrset: &child_material.child_ds_rrset,
        child_ds_rrsig_rrset: &child_material.child_ds_rrsig_rrset,
        child_dnskey_rrset: &child_material.child_dnskey_rrset,
        child_dnskey_rrsig_rrset: &child_material.child_dnskey_rrsig_rrset,
        query_name: input.request_name,
        query_type: input.qtype,
        nsec_rrset: &nsec_rrset,
        nsec_rrsig_rrset: &nsec_rrsig_rrset,
        nsec3_rrset: &nsec3_rrset,
        nsec3_rrsig_rrset: &nsec3_rrsig_rrset,
    })?;
    if !secure {
        return Err(ResolverError::DnssecFailed);
    }

    Ok(ResolutionAnswer {
        name: input.request_name.clone(),
        records: input.prefix_records.to_vec(),
        secure: true,
    })
}

fn fetch_inline_child_dnssec_material<T>(
    transport: &T,
    server: SocketAddr,
    child_owner: &DnsName,
) -> Result<InlineChildDnssecMaterial, ResolverError>
where
    T: DnsTransport,
{
    let child_ds_response = dns_query(transport, server, child_owner, RecordType::Ds)?;
    let child_ds_rrset = records_for(&child_ds_response.answers, child_owner, RecordType::Ds);
    let child_ds_rrsig_rrset =
        records_for(&child_ds_response.answers, child_owner, RecordType::Rrsig);
    let child_dnskey_response = dns_query(transport, server, child_owner, RecordType::Dnskey)?;
    let child_dnskey_rrset = records_for(
        &child_dnskey_response.answers,
        child_owner,
        RecordType::Dnskey,
    );
    let child_dnskey_rrsig_rrset = records_for(
        &child_dnskey_response.answers,
        child_owner,
        RecordType::Rrsig,
    );

    if child_ds_rrset.is_empty()
        || child_ds_rrsig_rrset.is_empty()
        || child_dnskey_rrset.is_empty()
        || child_dnskey_rrsig_rrset.is_empty()
    {
        return Err(ResolverError::DnssecFailed);
    }

    Ok(InlineChildDnssecMaterial {
        child_ds_rrset,
        child_ds_rrsig_rrset,
        child_dnskey_rrset,
        child_dnskey_rrsig_rrset,
    })
}

fn resolve_secure_child_from_server<T, V>(
    transport: &T,
    verifier: &V,
    server: SocketAddr,
    input: &ChildReferralResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    let child_dnskey_response =
        dns_query(transport, server, &input.referral.owner, RecordType::Dnskey)?;
    let child_dnskey_rrset = records_for(
        &child_dnskey_response.answers,
        &input.referral.owner,
        RecordType::Dnskey,
    );
    let child_dnskey_rrsig_rrset = records_for(
        &child_dnskey_response.answers,
        &input.referral.owner,
        RecordType::Rrsig,
    );
    if child_dnskey_rrset.is_empty() || child_dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }

    let target_response = dns_query(transport, server, input.request_name, input.qtype)?;
    resolve_secure_child_answer_records(ChildSecureAnswerResolutionInput {
        transport,
        verifier,
        server,
        referral: input,
        child_dnskey_rrset: &child_dnskey_rrset,
        child_dnskey_rrsig_rrset: &child_dnskey_rrsig_rrset,
        initial_response: target_response,
    })
}

struct ChildSecureAnswerResolutionInput<'a, T, V> {
    transport: &'a T,
    verifier: &'a V,
    server: SocketAddr,
    referral: &'a ChildReferralResolutionInput<'a>,
    child_dnskey_rrset: &'a [ResourceRecord],
    child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    initial_response: DnsMessage,
}

fn resolve_secure_child_answer_records<T, V>(
    input: ChildSecureAnswerResolutionInput<'_, T, V>,
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    let mut response = input.initial_response;
    let mut owner = input.referral.request_name.clone();
    let mut cname_records = Vec::new();

    for _ in 0..=MAX_CNAME_CHAIN_LEN {
        let target_rrset = records_for(&response.answers, &owner, input.referral.qtype);
        let cname_rrset = if input.referral.qtype == RecordType::Cname {
            Vec::new()
        } else {
            records_for(&response.answers, &owner, RecordType::Cname)
        };
        if !target_rrset.is_empty() && !cname_rrset.is_empty() {
            return Err(ResolverError::DnssecFailed);
        }

        if !target_rrset.is_empty() {
            validate_secure_child_rrset(
                input.verifier,
                ChildSecureRrsetValidationInput {
                    referral: input.referral,
                    child_dnskey_rrset: input.child_dnskey_rrset,
                    child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
                    owner: &owner,
                    rrset: &target_rrset,
                    response: &response,
                },
            )?;
            cname_records.extend(target_rrset);
            return Ok(ResolutionAnswer {
                name: input.referral.request_name.clone(),
                records: cname_records,
                secure: true,
            });
        }

        if !cname_rrset.is_empty() {
            validate_secure_child_rrset(
                input.verifier,
                ChildSecureRrsetValidationInput {
                    referral: input.referral,
                    child_dnskey_rrset: input.child_dnskey_rrset,
                    child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
                    owner: &owner,
                    rrset: &cname_rrset,
                    response: &response,
                },
            )?;
            let next_owner = cname_target(&cname_rrset)?;
            if !dns_name_is_subdomain_or_equal(&next_owner, &input.referral.referral.owner) {
                return Err(ResolverError::DnssecFailed);
            }
            cname_records.extend(cname_rrset);
            owner = next_owner;
            continue;
        }

        if owner != *input.referral.request_name && response.questions[0].name != owner {
            response = dns_query(input.transport, input.server, &owner, input.referral.qtype)?;
            continue;
        }

        if response.header.flags.rcode() == DNS_RCODE_NXDOMAIN {
            return resolve_secure_child_name_error(
                input.verifier,
                ChildNameErrorResolutionInput {
                    referral: input.referral,
                    request_name: &owner,
                    child_dnskey_rrset: input.child_dnskey_rrset,
                    child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
                    response: &response,
                    prefix_records: &cname_records,
                },
            );
        }

        return resolve_secure_child_no_data(
            input.verifier,
            ChildNoDataResolutionInput {
                referral: input.referral,
                request_name: &owner,
                qtype: input.referral.qtype,
                child_dnskey_rrset: input.child_dnskey_rrset,
                child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
                response: &response,
                prefix_records: &cname_records,
            },
        );
    }

    Err(ResolverError::DnssecFailed)
}

struct ChildSecureRrsetValidationInput<'a> {
    referral: &'a ChildReferralResolutionInput<'a>,
    child_dnskey_rrset: &'a [ResourceRecord],
    child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    owner: &'a DnsName,
    rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
}

fn validate_secure_child_rrset<V>(
    verifier: &V,
    input: ChildSecureRrsetValidationInput<'_>,
) -> Result<(), ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    let rrsig_rrset = records_for(&input.response.answers, input.owner, RecordType::Rrsig);
    if rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }
    let secure = verifier.validate_child_positive_rrset(DelegatedChildDnssecValidation {
        parent_dnskey_owner: &input.referral.parent_delegation.owner,
        parent_ds_rrset: input.referral.parent_ds_rrset,
        parent_dnskey_rrset: input.referral.parent_dnskey_rrset,
        parent_dnskey_rrsig_rrset: input.referral.parent_dnskey_rrsig_rrset,
        child_dnskey_owner: &input.referral.referral.owner,
        child_ds_rrset: &input.referral.referral.ds_rrset,
        child_ds_rrsig_rrset: &input.referral.referral.ds_rrsig_rrset,
        child_dnskey_rrset: input.child_dnskey_rrset,
        child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
        target_rrset: input.rrset,
        target_rrsig_rrset: &rrsig_rrset,
    })?;
    if secure {
        Ok(())
    } else {
        Err(ResolverError::DnssecFailed)
    }
}

struct ChildNoDataResolutionInput<'a> {
    referral: &'a ChildReferralResolutionInput<'a>,
    request_name: &'a DnsName,
    qtype: RecordType,
    child_dnskey_rrset: &'a [ResourceRecord],
    child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
    prefix_records: &'a [ResourceRecord],
}

struct ChildNameErrorResolutionInput<'a> {
    referral: &'a ChildReferralResolutionInput<'a>,
    request_name: &'a DnsName,
    child_dnskey_rrset: &'a [ResourceRecord],
    child_dnskey_rrsig_rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
    prefix_records: &'a [ResourceRecord],
}

fn resolve_secure_child_no_data<V>(
    verifier: &V,
    input: ChildNoDataResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    let proof_records = combined_response_records(input.response);
    let nsec_rrset = records_for(&proof_records, input.request_name, RecordType::Nsec);
    let nsec_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let nsec3_rrset = records_of_type(&proof_records, RecordType::Nsec3);
    let nsec3_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let secure = verifier.validate_child_no_data(DelegatedChildDnssecNoDataValidation {
        parent_dnskey_owner: &input.referral.parent_delegation.owner,
        parent_ds_rrset: input.referral.parent_ds_rrset,
        parent_dnskey_rrset: input.referral.parent_dnskey_rrset,
        parent_dnskey_rrsig_rrset: input.referral.parent_dnskey_rrsig_rrset,
        child_dnskey_owner: &input.referral.referral.owner,
        child_ds_rrset: &input.referral.referral.ds_rrset,
        child_ds_rrsig_rrset: &input.referral.referral.ds_rrsig_rrset,
        child_dnskey_rrset: input.child_dnskey_rrset,
        child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
        query_name: input.request_name,
        query_type: input.qtype,
        nsec_rrset: &nsec_rrset,
        nsec_rrsig_rrset: &nsec_rrsig_rrset,
        nsec3_rrset: &nsec3_rrset,
        nsec3_rrsig_rrset: &nsec3_rrsig_rrset,
    })?;
    if !secure {
        return Err(ResolverError::DnssecFailed);
    }

    Ok(ResolutionAnswer {
        name: input.request_name.clone(),
        records: input.prefix_records.to_vec(),
        secure: true,
    })
}

fn resolve_secure_child_name_error<V>(
    verifier: &V,
    input: ChildNameErrorResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    if input.child_dnskey_rrset.is_empty() || input.child_dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }
    let proof_records = combined_response_records(input.response);
    let nsec_rrset = records_of_type(&proof_records, RecordType::Nsec);
    let nsec_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let nsec3_rrset = records_of_type(&proof_records, RecordType::Nsec3);
    let nsec3_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    for closest_encloser in
        closest_encloser_candidates(input.request_name, &input.referral.referral.owner)?
    {
        let secure =
            verifier.validate_child_name_error(DelegatedChildDnssecNameErrorValidation {
                parent_dnskey_owner: &input.referral.parent_delegation.owner,
                parent_ds_rrset: input.referral.parent_ds_rrset,
                parent_dnskey_rrset: input.referral.parent_dnskey_rrset,
                parent_dnskey_rrsig_rrset: input.referral.parent_dnskey_rrsig_rrset,
                child_dnskey_owner: &input.referral.referral.owner,
                child_ds_rrset: &input.referral.referral.ds_rrset,
                child_ds_rrsig_rrset: &input.referral.referral.ds_rrsig_rrset,
                child_dnskey_rrset: input.child_dnskey_rrset,
                child_dnskey_rrsig_rrset: input.child_dnskey_rrsig_rrset,
                query_name: input.request_name,
                closest_encloser: &closest_encloser,
                nsec_rrset: &nsec_rrset,
                nsec_rrsig_rrset: &nsec_rrsig_rrset,
                nsec3_rrset: &nsec3_rrset,
                nsec3_rrsig_rrset: &nsec3_rrsig_rrset,
            })?;
        if secure {
            return Ok(ResolutionAnswer {
                name: input.request_name.clone(),
                records: input.prefix_records.to_vec(),
                secure: true,
            });
        }
    }

    Err(ResolverError::DnssecFailed)
}

struct SecureAnswerResolutionInput<'a, T, V> {
    transport: &'a T,
    verifier: &'a V,
    target: DnsQueryTarget<'a>,
    delegation: &'a HnsDelegation,
    request_name: &'a DnsName,
    qtype: RecordType,
    ds_rrset: &'a [ResourceRecord],
    dnskey_rrset: &'a [ResourceRecord],
    dnskey_rrsig_rrset: &'a [ResourceRecord],
    initial_response: DnsMessage,
}

fn resolve_secure_answer_records<T, V>(
    input: SecureAnswerResolutionInput<'_, T, V>,
) -> Result<ResolutionAnswer, ResolverError>
where
    T: DnsTransport,
    V: DelegatedDnssecVerifier,
{
    let mut response = input.initial_response;
    let mut owner = input.request_name.clone();
    let mut cname_records = Vec::new();

    for _ in 0..=MAX_CNAME_CHAIN_LEN {
        let target_rrset = records_for(&response.answers, &owner, input.qtype);
        let cname_rrset = if input.qtype == RecordType::Cname {
            Vec::new()
        } else {
            records_for(&response.answers, &owner, RecordType::Cname)
        };
        if !target_rrset.is_empty() && !cname_rrset.is_empty() {
            return Err(ResolverError::DnssecFailed);
        }

        if !target_rrset.is_empty() {
            validate_secure_rrset(
                input.verifier,
                SecureRrsetValidationInput {
                    delegation: input.delegation,
                    ds_rrset: input.ds_rrset,
                    dnskey_rrset: input.dnskey_rrset,
                    dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
                    owner: &owner,
                    rrset: &target_rrset,
                    response: &response,
                },
            )?;
            cname_records.extend(target_rrset);
            return Ok(ResolutionAnswer {
                name: input.request_name.clone(),
                records: cname_records,
                secure: true,
            });
        }

        if !cname_rrset.is_empty() {
            validate_secure_rrset(
                input.verifier,
                SecureRrsetValidationInput {
                    delegation: input.delegation,
                    ds_rrset: input.ds_rrset,
                    dnskey_rrset: input.dnskey_rrset,
                    dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
                    owner: &owner,
                    rrset: &cname_rrset,
                    response: &response,
                },
            )?;
            let next_owner = cname_target(&cname_rrset)?;
            if !dns_name_is_subdomain_or_equal(&next_owner, &input.delegation.owner) {
                return Err(ResolverError::DnssecFailed);
            }
            cname_records.extend(cname_rrset);
            owner = next_owner;
            continue;
        }

        if owner != *input.request_name && response.questions[0].name != owner {
            response = dns_query_target(input.transport, input.target, &owner, input.qtype)?;
            continue;
        }

        if response.header.flags.rcode() == DNS_RCODE_NXDOMAIN {
            return resolve_secure_name_error(
                input.verifier,
                NameErrorResolutionInput {
                    delegation: input.delegation,
                    request_name: &owner,
                    ds_rrset: input.ds_rrset,
                    dnskey_rrset: input.dnskey_rrset,
                    dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
                    response: &response,
                    prefix_records: &cname_records,
                },
            );
        }

        return resolve_secure_no_data(
            input.verifier,
            NoDataResolutionInput {
                delegation: input.delegation,
                request_name: &owner,
                qtype: input.qtype,
                ds_rrset: input.ds_rrset,
                dnskey_rrset: input.dnskey_rrset,
                dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
                response: &response,
                prefix_records: &cname_records,
            },
        );
    }

    Err(ResolverError::DnssecFailed)
}

struct SecureRrsetValidationInput<'a> {
    delegation: &'a HnsDelegation,
    ds_rrset: &'a [ResourceRecord],
    dnskey_rrset: &'a [ResourceRecord],
    dnskey_rrsig_rrset: &'a [ResourceRecord],
    owner: &'a DnsName,
    rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
}

fn validate_secure_rrset<V>(
    verifier: &V,
    input: SecureRrsetValidationInput<'_>,
) -> Result<(), ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    let rrsig_rrset = records_for(&input.response.answers, input.owner, RecordType::Rrsig);
    if rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }
    let secure = verifier.validate_positive_rrset(DelegatedDnssecValidation {
        dnskey_owner: &input.delegation.owner,
        ds_rrset: input.ds_rrset,
        dnskey_rrset: input.dnskey_rrset,
        dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
        target_rrset: input.rrset,
        target_rrsig_rrset: &rrsig_rrset,
    })?;
    if secure {
        Ok(())
    } else {
        Err(ResolverError::DnssecFailed)
    }
}

struct NoDataResolutionInput<'a> {
    delegation: &'a HnsDelegation,
    request_name: &'a DnsName,
    qtype: RecordType,
    ds_rrset: &'a [ResourceRecord],
    dnskey_rrset: &'a [ResourceRecord],
    dnskey_rrsig_rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
    prefix_records: &'a [ResourceRecord],
}

struct NameErrorResolutionInput<'a> {
    delegation: &'a HnsDelegation,
    request_name: &'a DnsName,
    ds_rrset: &'a [ResourceRecord],
    dnskey_rrset: &'a [ResourceRecord],
    dnskey_rrsig_rrset: &'a [ResourceRecord],
    response: &'a DnsMessage,
    prefix_records: &'a [ResourceRecord],
}

fn resolve_secure_no_data<V>(
    verifier: &V,
    input: NoDataResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    if input.dnskey_rrset.is_empty() || input.dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }
    let proof_records = combined_response_records(input.response);
    let nsec_rrset = records_for(&proof_records, input.request_name, RecordType::Nsec);
    let nsec_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let nsec3_rrset = records_of_type(&proof_records, RecordType::Nsec3);
    let nsec3_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let secure = verifier.validate_no_data(DelegatedDnssecNoDataValidation {
        dnskey_owner: &input.delegation.owner,
        ds_rrset: input.ds_rrset,
        dnskey_rrset: input.dnskey_rrset,
        dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
        query_name: input.request_name,
        query_type: input.qtype,
        nsec_rrset: &nsec_rrset,
        nsec_rrsig_rrset: &nsec_rrsig_rrset,
        nsec3_rrset: &nsec3_rrset,
        nsec3_rrsig_rrset: &nsec3_rrsig_rrset,
    })?;
    if !secure {
        return Err(ResolverError::DnssecFailed);
    }

    Ok(ResolutionAnswer {
        name: input.request_name.clone(),
        records: input.prefix_records.to_vec(),
        secure: true,
    })
}

fn resolve_secure_name_error<V>(
    verifier: &V,
    input: NameErrorResolutionInput<'_>,
) -> Result<ResolutionAnswer, ResolverError>
where
    V: DelegatedDnssecVerifier,
{
    if input.dnskey_rrset.is_empty() || input.dnskey_rrsig_rrset.is_empty() {
        return Err(ResolverError::DnssecFailed);
    }
    let proof_records = combined_response_records(input.response);
    let nsec_rrset = records_of_type(&proof_records, RecordType::Nsec);
    let nsec_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    let nsec3_rrset = records_of_type(&proof_records, RecordType::Nsec3);
    let nsec3_rrsig_rrset = records_of_type(&proof_records, RecordType::Rrsig);
    for closest_encloser in
        closest_encloser_candidates(input.request_name, &input.delegation.owner)?
    {
        let secure = verifier.validate_name_error(DelegatedDnssecNameErrorValidation {
            dnskey_owner: &input.delegation.owner,
            ds_rrset: input.ds_rrset,
            dnskey_rrset: input.dnskey_rrset,
            dnskey_rrsig_rrset: input.dnskey_rrsig_rrset,
            query_name: input.request_name,
            closest_encloser: &closest_encloser,
            nsec_rrset: &nsec_rrset,
            nsec_rrsig_rrset: &nsec_rrsig_rrset,
            nsec3_rrset: &nsec3_rrset,
            nsec3_rrsig_rrset: &nsec3_rrsig_rrset,
        })?;
        if secure {
            return Ok(ResolutionAnswer {
                name: input.request_name.clone(),
                records: input.prefix_records.to_vec(),
                secure: true,
            });
        }
    }

    Err(ResolverError::DnssecFailed)
}

fn closest_encloser_candidates(
    query_name: &DnsName,
    zone_owner: &DnsName,
) -> Result<Vec<DnsName>, ResolverError> {
    let query_labels = query_name.labels();
    let zone_labels = zone_owner.labels();
    if query_labels.len() <= zone_labels.len() || !query_labels.ends_with(zone_labels) {
        return Ok(Vec::new());
    }

    let mut candidates = Vec::new();
    for start in 1..=(query_labels.len() - zone_labels.len()) {
        let candidate = DnsName::from_ascii(&query_labels[start..].join("."))
            .map_err(|_| ResolverError::InvalidDnsResponse)?;
        candidates.push(candidate);
    }
    Ok(candidates)
}

#[derive(Clone, Copy)]
enum DnsQueryTarget<'a> {
    Server(SocketAddr),
    ServerTcp(SocketAddr),
    Doh(&'a AuthoritativeDohEndpoint),
}

fn validate_dns_server(policy: DnsEndpointPolicy, server: SocketAddr) -> Result<(), ResolverError> {
    if policy.allow_non_public_addresses || is_publicly_routable(server.ip()) {
        Ok(())
    } else {
        Err(ResolverError::NonPublicDnsEndpoint)
    }
}

fn validate_doh_endpoint(
    policy: DnsEndpointPolicy,
    endpoint: &AuthoritativeDohEndpoint,
) -> Result<(), ResolverError> {
    validate_dns_server(
        policy,
        SocketAddr::new(endpoint.connect_addr, endpoint.port),
    )?;
    if policy.allow_unsafe_doh_ports || !is_browser_blocked_port(endpoint.port) {
        Ok(())
    } else {
        Err(ResolverError::UnsafeAuthoritativeDohPort(endpoint.port))
    }
}

fn dns_query<T: DnsTransport>(
    transport: &T,
    server: SocketAddr,
    qname: &DnsName,
    qtype: RecordType,
) -> Result<DnsMessage, ResolverError> {
    dns_query_target(transport, DnsQueryTarget::Server(server), qname, qtype)
}

fn dns_query_doh<T: DnsTransport>(
    transport: &T,
    endpoint: &AuthoritativeDohEndpoint,
    qname: &DnsName,
    qtype: RecordType,
) -> Result<DnsMessage, ResolverError> {
    dns_query_target(transport, DnsQueryTarget::Doh(endpoint), qname, qtype)
}

fn dns_query_target<T: DnsTransport>(
    transport: &T,
    target: DnsQueryTarget<'_>,
    qname: &DnsName,
    qtype: RecordType,
) -> Result<DnsMessage, ResolverError> {
    let endpoint_policy = transport.endpoint_policy();
    match target {
        DnsQueryTarget::Server(server) | DnsQueryTarget::ServerTcp(server) => {
            validate_dns_server(endpoint_policy, server)?
        }
        DnsQueryTarget::Doh(endpoint) => validate_doh_endpoint(endpoint_policy, endpoint)?,
    }
    let id = next_dns_query_id();
    let query = build_dns_query(id, qname, qtype)?;
    if transport.is_recursive_relay()
        && matches!(
            target,
            DnsQueryTarget::Server(_) | DnsQueryTarget::ServerTcp(_)
        )
    {
        let server = match target {
            DnsQueryTarget::Server(server) | DnsQueryTarget::ServerTcp(server) => server,
            DnsQueryTarget::Doh(_) => return Err(ResolverError::UnsupportedBackend),
        };
        let response = transport.exchange_udp(server, &query)?;
        let response = parse_dns_response(id, qname, qtype, &response)?;
        if response.header.flags.truncated() {
            return Err(ResolverError::InvalidDnsResponse);
        }
        return Ok(response);
    }
    let server = match target {
        DnsQueryTarget::Server(server) => server,
        DnsQueryTarget::ServerTcp(server) => {
            return dns_query_tcp(transport, server, id, qname, qtype, &query);
        }
        DnsQueryTarget::Doh(_) => {
            return dns_query_https(transport, target, qname, qtype, &query);
        }
    };
    let udp_response = match transport.exchange_udp(server, &query) {
        Ok(response) => response,
        Err(error) if dns_query_should_retry_tcp(&error) => {
            return dns_query_tcp(transport, server, id, qname, qtype, &query)
                .map_err(|tcp_error| strongest_resolution_error(error, tcp_error));
        }
        Err(error) => return Err(error),
    };
    let response = match parse_dns_response(id, qname, qtype, &udp_response) {
        Ok(response) => response,
        Err(error) if dns_query_should_retry_tcp(&error) => {
            return dns_query_tcp(transport, server, id, qname, qtype, &query)
                .map_err(|tcp_error| strongest_resolution_error(error, tcp_error));
        }
        Err(error) => return Err(error),
    };
    if response.header.flags.truncated() {
        return dns_query_tcp(transport, server, id, qname, qtype, &query);
    }

    Ok(response)
}

fn dns_query_https<T: DnsTransport>(
    transport: &T,
    target: DnsQueryTarget<'_>,
    qname: &DnsName,
    qtype: RecordType,
    query: &[u8],
) -> Result<DnsMessage, ResolverError> {
    let DnsQueryTarget::Doh(endpoint) = target else {
        return Err(ResolverError::UnsupportedBackend);
    };
    let mut query = query.to_vec();
    if query.len() < 2 {
        return Err(ResolverError::InvalidDnsResponse);
    }
    query[0] = 0;
    query[1] = 0;
    let response = transport.exchange_doh(endpoint, &query)?;
    parse_dns_response(0, qname, qtype, &response)
}

fn dns_query_should_retry_tcp(error: &ResolverError) -> bool {
    matches!(
        error,
        ResolverError::DnsTransport(_) | ResolverError::InvalidDnsResponse
    )
}

fn dns_query_tcp<T: DnsTransport>(
    transport: &T,
    server: SocketAddr,
    id: u16,
    qname: &DnsName,
    qtype: RecordType,
    query: &[u8],
) -> Result<DnsMessage, ResolverError> {
    let tcp_response = transport.exchange_tcp(server, query)?;
    let response = parse_dns_response(id, qname, qtype, &tcp_response)?;
    if response.header.flags.truncated() {
        return Err(ResolverError::InvalidDnsResponse);
    }

    Ok(response)
}

fn next_dns_query_id() -> u16 {
    DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
}

fn build_dns_query(id: u16, qname: &DnsName, qtype: RecordType) -> Result<Vec<u8>, ResolverError> {
    let message = DnsMessage {
        header: DnsHeader {
            id,
            flags: DnsFlags::new(0),
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 1,
        },
        questions: vec![DnsQuestion {
            name: qname.clone(),
            record_type: qtype,
            class: DNS_CLASS_IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: vec![ResourceRecord {
            name: DnsName::root(),
            record_type: RecordType::Unknown(DNS_OPT_RECORD_TYPE),
            class: DEFAULT_DNS_UDP_PAYLOAD as u16,
            ttl: DNSSEC_DO_FLAG,
            rdata: Vec::new(),
        }],
    };

    message
        .encode(&DnsEncodeConfig {
            max_message_len: DEFAULT_DNS_UDP_PAYLOAD,
        })
        .map_err(|_| ResolverError::InvalidDnsResponse)
}

fn parse_dns_response(
    id: u16,
    qname: &DnsName,
    qtype: RecordType,
    response: &[u8],
) -> Result<DnsMessage, ResolverError> {
    let message = DnsMessage::parse(response).map_err(|_| ResolverError::InvalidDnsResponse)?;
    let rcode = message.header.flags.rcode();
    if message.header.id != id
        || !message.header.flags.is_response()
        || message.header.flags.opcode() != 0
        || message.questions.len() != 1
        || message.questions[0].name != *qname
        || message.questions[0].record_type != qtype
        || message.questions[0].class != DNS_CLASS_IN
    {
        return Err(ResolverError::InvalidDnsResponse);
    }
    if !matches!(rcode, DNS_RCODE_NOERROR | DNS_RCODE_NXDOMAIN) {
        return Err(ResolverError::DnsResponseCode(rcode));
    }

    Ok(message)
}

fn nameserver_addresses(delegation: &HnsDelegation) -> Vec<SocketAddr> {
    nameserver_ip_addresses(delegation)
        .into_iter()
        .map(|(_, address)| SocketAddr::new(address, 53))
        .fold(Vec::new(), |mut addresses, socket| {
            if !addresses.contains(&socket) {
                addresses.push(socket);
            }
            addresses
        })
}

fn nameserver_ip_addresses(delegation: &HnsDelegation) -> Vec<(DnsName, IpAddr)> {
    let ns_names = delegation
        .records
        .iter()
        .filter(|record| record.name == delegation.owner && record.record_type == RecordType::Ns)
        .filter_map(record_name_rdata)
        .fold(Vec::<DnsName>::new(), |mut names, name| {
            if !names.contains(&name) {
                names.push(name);
            }
            names
        });

    let mut addresses = Vec::new();
    for ns_name in ns_names {
        for record in delegation
            .records
            .iter()
            .filter(|record| record.name == ns_name)
        {
            let address = match record.record_type {
                RecordType::A if record.rdata.len() == 4 => Some(IpAddr::V4(Ipv4Addr::new(
                    record.rdata[0],
                    record.rdata[1],
                    record.rdata[2],
                    record.rdata[3],
                ))),
                RecordType::Aaaa if record.rdata.len() == 16 => {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&record.rdata);
                    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
                }
                _ => None,
            };
            let Some(address) = address else {
                continue;
            };
            let entry = (ns_name.clone(), address);
            if !addresses.contains(&entry) {
                addresses.push(entry);
            }
        }
    }

    addresses
}

fn child_referral(
    response: &DnsMessage,
    parent_owner: &DnsName,
    request_name: &DnsName,
) -> Option<ChildReferral> {
    let owner = response
        .authorities
        .iter()
        .filter(|record| record.record_type == RecordType::Ns)
        .map(|record| record.name.clone())
        .filter(|owner| {
            owner != parent_owner
                && dns_name_is_subdomain_or_equal(owner, parent_owner)
                && dns_name_is_subdomain_or_equal(request_name, owner)
        })
        .max_by_key(|owner| owner.labels().len())?;
    let ns_rrset = records_for(&response.authorities, &owner, RecordType::Ns);
    let ds_rrset = records_for(&response.authorities, &owner, RecordType::Ds);
    let ds_rrsig_rrset = records_for(&response.authorities, &owner, RecordType::Rrsig);
    if ns_rrset.is_empty() || ds_rrset.is_empty() || ds_rrsig_rrset.is_empty() {
        return None;
    }

    Some(ChildReferral {
        owner,
        servers: referral_nameserver_addresses(&ns_rrset, &response.additionals),
        ds_rrset,
        ds_rrsig_rrset,
    })
}

fn inline_child_answer_signer(
    delegation: &HnsDelegation,
    request_name: &DnsName,
    rrset: &[ResourceRecord],
    rrsig_rrset: &[ResourceRecord],
    record_type: RecordType,
) -> Option<DnsName> {
    let first = rrset.first()?;
    for record in rrsig_rrset.iter().filter(|record| {
        record.name == first.name
            && record.class == first.class
            && record.record_type == RecordType::Rrsig
    }) {
        let rrsig = RrsigRecord::from_record(record).ok()?;
        if rrsig.type_covered == record_type
            && rrsig.signer_name != delegation.owner
            && dns_name_is_subdomain_or_equal(&rrsig.signer_name, &delegation.owner)
            && dns_name_is_subdomain_or_equal(request_name, &rrsig.signer_name)
        {
            return Some(rrsig.signer_name);
        }
    }

    None
}

fn inline_child_denial_signer(
    delegation: &HnsDelegation,
    request_name: &DnsName,
    proof_records: &[ResourceRecord],
) -> Option<DnsName> {
    proof_records
        .iter()
        .filter(|record| record.record_type == RecordType::Rrsig)
        .filter_map(|record| {
            let rrsig = RrsigRecord::from_record(record).ok()?;
            if matches!(rrsig.type_covered, RecordType::Nsec | RecordType::Nsec3)
                && rrsig.signer_name != delegation.owner
                && dns_name_is_subdomain_or_equal(&rrsig.signer_name, &delegation.owner)
                && dns_name_is_subdomain_or_equal(request_name, &rrsig.signer_name)
            {
                Some(rrsig.signer_name)
            } else {
                None
            }
        })
        .max_by_key(|owner| owner.labels().len())
}

fn referral_nameserver_addresses(
    ns_rrset: &[ResourceRecord],
    additionals: &[ResourceRecord],
) -> Vec<SocketAddr> {
    let ns_names = ns_rrset.iter().filter_map(record_name_rdata).fold(
        Vec::<DnsName>::new(),
        |mut names, name| {
            if !names.contains(&name) {
                names.push(name);
            }
            names
        },
    );
    let mut addresses = Vec::new();
    for ns_name in ns_names {
        for record in additionals.iter().filter(|record| record.name == ns_name) {
            let address = match record.record_type {
                RecordType::A if record.rdata.len() == 4 => Some(IpAddr::V4(Ipv4Addr::new(
                    record.rdata[0],
                    record.rdata[1],
                    record.rdata[2],
                    record.rdata[3],
                ))),
                RecordType::Aaaa if record.rdata.len() == 16 => {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&record.rdata);
                    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
                }
                _ => None,
            };
            let Some(address) = address else {
                continue;
            };
            let socket = SocketAddr::new(address, 53);
            if !addresses.contains(&socket) {
                addresses.push(socket);
            }
        }
    }

    addresses
}

fn record_name_rdata(record: &ResourceRecord) -> Option<DnsName> {
    let (name, end) = DnsName::parse_wire(&record.rdata, 0).ok()?;
    (end == record.rdata.len()).then_some(name)
}

fn cname_target(cname_rrset: &[ResourceRecord]) -> Result<DnsName, ResolverError> {
    if cname_rrset.len() != 1 || cname_rrset[0].record_type != RecordType::Cname {
        return Err(ResolverError::DnssecFailed);
    }
    record_name_rdata(&cname_rrset[0]).ok_or(ResolverError::DnssecFailed)
}

fn dns_name_is_subdomain_or_equal(name: &DnsName, parent: &DnsName) -> bool {
    name.labels().ends_with(parent.labels())
}

fn records_for(
    records: &[ResourceRecord],
    owner: &DnsName,
    record_type: RecordType,
) -> Vec<ResourceRecord> {
    records
        .iter()
        .filter(|record| record.name == *owner && record.record_type == record_type)
        .cloned()
        .collect()
}

fn records_of_type(records: &[ResourceRecord], record_type: RecordType) -> Vec<ResourceRecord> {
    records
        .iter()
        .filter(|record| record.record_type == record_type)
        .cloned()
        .collect()
}

fn combined_response_records(response: &DnsMessage) -> Vec<ResourceRecord> {
    response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .cloned()
        .collect()
}

pub fn hns_root_label(input: &str) -> Result<String, ResolverError> {
    let trimmed = input
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim_end_matches('.');
    let name = DnsName::from_ascii(trimmed).map_err(|_| ResolverError::UnsupportedBackend)?;
    let labels = name.labels();
    let root = labels.last().ok_or(ResolverError::UnsupportedBackend)?;

    NameHash::from_name(root)?;
    Ok(root.to_owned())
}

pub fn classify_name(input: &str) -> NameClass {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return NameClass::Search;
    }

    let host = trimmed
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();

    let host = host.trim_end_matches('.');

    if host.is_empty() {
        NameClass::Search
    } else if host.parse::<IpAddr>().is_ok() || uses_icann_namespace(host) {
        NameClass::Icann
    } else if hns_root_label(host).is_ok() {
        NameClass::Hns
    } else {
        NameClass::Icann
    }
}

fn uses_icann_namespace(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    let Some(suffix) = host.rsplit('.').next() else {
        return false;
    };
    is_browser_special_use_host(host)
        || host.contains('.')
            && ICANN_TLDS
                .lines()
                .any(|candidate| suffix.eq_ignore_ascii_case(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    type DnsRequestLog = Arc<Mutex<Vec<(SocketAddr, String, u16, bool)>>>;
    type DnsValidationLog = Arc<Mutex<Vec<(usize, usize, usize, usize, usize)>>>;
    type DnsResponseMap = HashMap<(String, u16), DnsResponseFixture>;
    type ServerDnsResponseMap = HashMap<(SocketAddr, String, u16), DnsResponseFixture>;

    struct CountingResolver {
        count: AtomicUsize,
    }

    struct CountingNameNotFoundResolver {
        count: AtomicUsize,
    }

    struct StaticProofProvider {
        proven: ProvenNameRecords,
    }

    struct MapProofProvider {
        proven: HashMap<String, ProvenNameRecords>,
    }

    struct StaticValueProvider {
        verified: VerifiedResourceValue,
    }

    struct ScriptedResolver {
        responses: Vec<(ResolutionRequest, ResolutionAnswer)>,
        requests: Arc<Mutex<Vec<ResolutionRequest>>>,
    }

    struct CapturingDelegatedResolver {
        delegations: Arc<Mutex<Vec<HnsDelegation>>>,
    }

    struct ScriptedDnsTransport {
        responses: DnsResponseMap,
        server_responses: ServerDnsResponseMap,
        requests: DnsRequestLog,
        udp_behavior: ScriptedUdpBehavior,
    }

    struct PolicyDnsTransport {
        policy: DnsEndpointPolicy,
        calls: AtomicUsize,
    }

    struct FailingPinnedDohTransport {
        doh_calls: AtomicUsize,
        udp_calls: AtomicUsize,
        tcp_calls: AtomicUsize,
    }

    struct InterceptedDnsTransport {
        interception_detected: AtomicBool,
        probe_calls: AtomicUsize,
        doh_calls: AtomicUsize,
        udp_calls: AtomicUsize,
        tcp_calls: AtomicUsize,
    }

    struct TcpRepairDnsTransport {
        requests: DnsRequestLog,
    }

    struct RecursiveRelayErrorTransport {
        udp_calls: AtomicUsize,
        tcp_calls: AtomicUsize,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum ScriptedUdpBehavior {
        #[default]
        Normal,
        Truncated,
        TransportError,
        InvalidResponse,
    }

    struct StaticDnssecVerifier {
        positive_valid: bool,
        no_data_valid: bool,
        name_error_valid: bool,
        child_positive_valid: bool,
        child_no_data_valid: bool,
        child_name_error_valid: bool,
        validations: DnsValidationLog,
        no_data_validations: DnsValidationLog,
        name_error_validations: DnsValidationLog,
        child_validations: DnsValidationLog,
        child_no_data_validations: DnsValidationLog,
        child_name_error_validations: DnsValidationLog,
    }

    fn accepting_dnssec_verifier() -> StaticDnssecVerifier {
        StaticDnssecVerifier {
            positive_valid: true,
            no_data_valid: false,
            name_error_valid: false,
            child_positive_valid: false,
            child_no_data_valid: false,
            child_name_error_valid: false,
            validations: Arc::new(Mutex::new(Vec::new())),
            no_data_validations: Arc::new(Mutex::new(Vec::new())),
            name_error_validations: Arc::new(Mutex::new(Vec::new())),
            child_validations: Arc::new(Mutex::new(Vec::new())),
            child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
            child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct DnsResponseFixture {
        rcode: u8,
        answers: Vec<ResourceRecord>,
        authorities: Vec<ResourceRecord>,
        additionals: Vec<ResourceRecord>,
    }

    impl Resolver for CountingResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(ResolutionAnswer {
                name: DnsName::root(),
                records: Vec::new(),
                secure: true,
            })
        }
    }

    impl Resolver for CountingNameNotFoundResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::NameNotFound)
        }
    }

    impl HnsProofProvider for StaticProofProvider {
        fn prove_name(
            &self,
            _root_name: &str,
            _name_hash: NameHash,
        ) -> Result<ProvenNameRecords, ResolverError> {
            Ok(self.proven.clone())
        }
    }

    impl HnsProofProvider for MapProofProvider {
        fn prove_name(
            &self,
            root_name: &str,
            name_hash: NameHash,
        ) -> Result<ProvenNameRecords, ResolverError> {
            let proven = self
                .proven
                .get(root_name)
                .cloned()
                .ok_or(ResolverError::ProofUnavailable)?;
            if proven.root_name != root_name || proven.name_hash != name_hash || !proven.secure {
                return Err(ResolverError::ProofNameMismatch);
            }
            Ok(proven)
        }
    }

    impl HnsResourceValueProvider for StaticValueProvider {
        fn prove_resource_value(
            &self,
            _root_name: &str,
            _name_hash: NameHash,
        ) -> Result<VerifiedResourceValue, ResolverError> {
            Ok(self.verified.clone())
        }
    }

    impl ScriptedResolver {
        fn new(
            responses: Vec<(ResolutionRequest, ResolutionAnswer)>,
            requests: Arc<Mutex<Vec<ResolutionRequest>>>,
        ) -> Self {
            Self {
                responses,
                requests,
            }
        }
    }

    impl Resolver for ScriptedResolver {
        fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.requests
                .lock()
                .map_err(|_| ResolverError::CachePoisoned)?
                .push(request.clone());
            self.responses
                .iter()
                .find(|(candidate, _)| candidate == request)
                .map(|(_, answer)| answer.clone())
                .ok_or(ResolverError::ProofUnavailable)
        }
    }

    impl DelegatedResolver for CapturingDelegatedResolver {
        fn resolve_delegated(
            &self,
            request: &ResolutionRequest,
            delegation: &HnsDelegation,
        ) -> Result<ResolutionAnswer, ResolverError> {
            self.delegations
                .lock()
                .map_err(|_| ResolverError::CachePoisoned)?
                .push(delegation.clone());
            Ok(ResolutionAnswer {
                name: DnsName::from_ascii(&request.qname).unwrap(),
                records: vec![record(
                    DnsName::from_ascii(&request.qname).unwrap(),
                    RecordType::A,
                    vec![127, 0, 0, 1],
                )],
                secure: true,
            })
        }
    }

    impl DnsTransport for ScriptedDnsTransport {
        fn endpoint_policy(&self) -> DnsEndpointPolicy {
            DnsEndpointPolicy::permissive()
        }

        fn exchange_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
            let query = DnsMessage::parse(query).unwrap();
            let question = query.questions[0].clone();
            assert_eq!(query.additionals.len(), 1);
            assert_eq!(
                query.additionals[0].record_type,
                RecordType::Unknown(DNS_OPT_RECORD_TYPE)
            );
            assert_eq!(query.additionals[0].ttl, DNSSEC_DO_FLAG);
            self.requests.lock().unwrap().push((
                server,
                question.name.to_string(),
                question.record_type.code(),
                false,
            ));
            match self.udp_behavior {
                ScriptedUdpBehavior::Normal => {}
                ScriptedUdpBehavior::Truncated => {
                    return Ok(dns_response(&query, DnsResponseFixture::default(), true));
                }
                ScriptedUdpBehavior::TransportError => {
                    return Err(ResolverError::DnsTransport("udp failed".to_owned()));
                }
                ScriptedUdpBehavior::InvalidResponse => return Ok(vec![0, 1, 2, 3]),
            }
            let fixture = self
                .server_responses
                .get(&(
                    server,
                    question.name.to_string(),
                    question.record_type.code(),
                ))
                .or_else(|| {
                    self.responses
                        .get(&(question.name.to_string(), question.record_type.code()))
                })
                .cloned()
                .unwrap_or_default();
            Ok(dns_response(&query, fixture, false))
        }

        fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
            let query = DnsMessage::parse(query).unwrap();
            let question = query.questions[0].clone();
            self.requests.lock().unwrap().push((
                server,
                question.name.to_string(),
                question.record_type.code(),
                true,
            ));
            let fixture = self
                .server_responses
                .get(&(
                    server,
                    question.name.to_string(),
                    question.record_type.code(),
                ))
                .or_else(|| {
                    self.responses
                        .get(&(question.name.to_string(), question.record_type.code()))
                })
                .cloned()
                .unwrap_or_default();
            Ok(dns_response(&query, fixture, false))
        }

        fn exchange_doh(
            &self,
            endpoint: &AuthoritativeDohEndpoint,
            query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            let query = DnsMessage::parse(query).unwrap();
            let question = query.questions[0].clone();
            let server = SocketAddr::new(endpoint.connect_addr, endpoint.port);
            self.requests.lock().unwrap().push((
                server,
                question.name.to_string(),
                question.record_type.code(),
                true,
            ));
            let fixture = self
                .server_responses
                .get(&(
                    server,
                    question.name.to_string(),
                    question.record_type.code(),
                ))
                .or_else(|| {
                    self.responses
                        .get(&(question.name.to_string(), question.record_type.code()))
                })
                .cloned()
                .unwrap_or_default();
            Ok(dns_response(&query, fixture, false))
        }
    }

    impl DnsTransport for PolicyDnsTransport {
        fn endpoint_policy(&self) -> DnsEndpointPolicy {
            self.policy
        }

        fn exchange_udp(
            &self,
            _server: SocketAddr,
            _query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::UnsupportedBackend)
        }

        fn exchange_tcp(
            &self,
            _server: SocketAddr,
            _query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::UnsupportedBackend)
        }

        fn exchange_doh(
            &self,
            _endpoint: &AuthoritativeDohEndpoint,
            _query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::UnsupportedBackend)
        }
    }

    impl DnsTransport for FailingPinnedDohTransport {
        fn endpoint_policy(&self) -> DnsEndpointPolicy {
            DnsEndpointPolicy::permissive()
        }

        fn exchange_udp(
            &self,
            _server: SocketAddr,
            query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            self.udp_calls.fetch_add(1, Ordering::SeqCst);
            let query = DnsMessage::parse(query).unwrap();
            let question = query.questions[0].clone();
            Ok(dns_response(
                &query,
                tcp_repair_fixture(&question, true),
                false,
            ))
        }

        fn exchange_tcp(
            &self,
            _server: SocketAddr,
            _query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            self.tcp_calls.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::DnsTransport("unexpected TCP".to_owned()))
        }

        fn exchange_doh(
            &self,
            _endpoint: &AuthoritativeDohEndpoint,
            _query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            self.doh_calls.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::DnsTransport(
                "HNS proof TLSA validation failed".to_owned(),
            ))
        }
    }

    impl DnsTransport for InterceptedDnsTransport {
        fn endpoint_policy(&self) -> DnsEndpointPolicy {
            DnsEndpointPolicy::permissive()
        }

        fn exchange_udp(
            &self,
            _server: SocketAddr,
            query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            self.udp_calls.fetch_add(1, Ordering::SeqCst);
            let query = DnsMessage::parse(query).unwrap();
            let question = query.questions[0].clone();
            Ok(dns_response(
                &query,
                tcp_repair_fixture(&question, false),
                false,
            ))
        }

        fn exchange_tcp(
            &self,
            _server: SocketAddr,
            _query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            self.tcp_calls.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::DnsTransport(
                "intercepted TCP must not be attempted".to_owned(),
            ))
        }

        fn exchange_doh(
            &self,
            _endpoint: &AuthoritativeDohEndpoint,
            query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            self.doh_calls.fetch_add(1, Ordering::SeqCst);
            let query = DnsMessage::parse(query).unwrap();
            let question = query.questions[0].clone();
            Ok(dns_response(
                &query,
                tcp_repair_fixture(&question, true),
                false,
            ))
        }

        fn probe_dns_interception(&self) -> DnsInterceptionStatus {
            self.probe_calls.fetch_add(1, Ordering::SeqCst);
            self.interception_detected.store(true, Ordering::SeqCst);
            DnsInterceptionStatus::Detected
        }

        fn dns_interception_status(&self) -> DnsInterceptionStatus {
            if self.interception_detected.load(Ordering::SeqCst) {
                DnsInterceptionStatus::Detected
            } else {
                DnsInterceptionStatus::NotTested
            }
        }
    }

    impl DnsTransport for TcpRepairDnsTransport {
        fn endpoint_policy(&self) -> DnsEndpointPolicy {
            DnsEndpointPolicy::permissive()
        }

        fn exchange_udp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
            let query = DnsMessage::parse(query).unwrap();
            let question = query.questions[0].clone();
            self.requests.lock().unwrap().push((
                server,
                question.name.to_string(),
                question.record_type.code(),
                false,
            ));
            Ok(dns_response(
                &query,
                tcp_repair_fixture(&question, false),
                false,
            ))
        }

        fn exchange_tcp(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, ResolverError> {
            let query = DnsMessage::parse(query).unwrap();
            let question = query.questions[0].clone();
            self.requests.lock().unwrap().push((
                server,
                question.name.to_string(),
                question.record_type.code(),
                true,
            ));
            Ok(dns_response(
                &query,
                tcp_repair_fixture(&question, true),
                false,
            ))
        }
    }

    impl DnsTransport for RecursiveRelayErrorTransport {
        fn endpoint_policy(&self) -> DnsEndpointPolicy {
            DnsEndpointPolicy::permissive()
        }

        fn exchange_udp(
            &self,
            _server: SocketAddr,
            _query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            self.udp_calls.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::DnsTransport("relay unavailable".to_owned()))
        }

        fn exchange_tcp(
            &self,
            _server: SocketAddr,
            _query: &[u8],
        ) -> Result<Vec<u8>, ResolverError> {
            self.tcp_calls.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::DnsTransport(
                "recursive relay must not receive TCP retry".to_owned(),
            ))
        }

        fn is_recursive_relay(&self) -> bool {
            true
        }
    }

    #[test]
    fn composite_resolver_routes_hns_and_icann_requests() {
        let resolver = CompositeResolver::new(
            CountingResolver {
                count: AtomicUsize::new(0),
            },
            CountingResolver {
                count: AtomicUsize::new(0),
            },
        );

        resolver
            .resolve(&ResolutionRequest {
                qname: "name".to_owned(),
                qtype: RecordType::A.code(),
            })
            .unwrap();
        resolver
            .resolve(&ResolutionRequest {
                qname: "example.com".to_owned(),
                qtype: RecordType::A.code(),
            })
            .unwrap();
        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: "bad name".to_owned(),
                    qtype: RecordType::A.code(),
                })
                .unwrap_err(),
            ResolverError::UnsupportedBackend,
        );

        let (hns, icann) = resolver.into_parts();
        assert_eq!(hns.count.load(Ordering::SeqCst), 1);
        assert_eq!(icann.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn recursive_relay_owns_retries_and_ignores_additional_nameserver_addresses() {
        let transport = RecursiveRelayErrorTransport {
            udp_calls: AtomicUsize::new(0),
            tcp_calls: AtomicUsize::new(0),
        };
        let resolver = AuthoritativeDnssecResolver::new(transport, accepting_dnssec_verifier())
            .without_authoritative_doh();
        let delegation = HnsDelegation {
            root_name: "welcome".to_owned(),
            owner: DnsName::from_ascii("welcome").unwrap(),
            records: vec![
                ns_record("welcome", "ns1.welcome"),
                ns_record("welcome", "ns2.welcome"),
                glue4_record("ns1.welcome", [203, 0, 113, 53]),
                glue4_record("ns2.welcome", [203, 0, 113, 54]),
            ],
        };

        assert!(matches!(
            resolver.resolve_delegated(
                &ResolutionRequest {
                    qname: "www.welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation,
            ),
            Err(ResolverError::DnsTransport(_))
        ));
        let (transport, _) = resolver.into_parts();
        assert_eq!(transport.udp_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transport.tcp_calls.load(Ordering::SeqCst), 0);
    }

    impl DelegatedDnssecVerifier for StaticDnssecVerifier {
        fn validate_positive_rrset(
            &self,
            input: DelegatedDnssecValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.validations.lock().unwrap().push((
                input.ds_rrset.len(),
                input.dnskey_rrset.len(),
                input.dnskey_rrsig_rrset.len(),
                input.target_rrset.len(),
                input.target_rrsig_rrset.len(),
            ));
            Ok(self.positive_valid)
        }

        fn validate_no_data(
            &self,
            input: DelegatedDnssecNoDataValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.no_data_validations.lock().unwrap().push((
                input.ds_rrset.len(),
                input.dnskey_rrset.len(),
                input.dnskey_rrsig_rrset.len(),
                input.nsec_rrset.len() + input.nsec3_rrset.len(),
                input.nsec_rrsig_rrset.len() + input.nsec3_rrsig_rrset.len(),
            ));
            Ok(self.no_data_valid)
        }

        fn validate_name_error(
            &self,
            input: DelegatedDnssecNameErrorValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.name_error_validations.lock().unwrap().push((
                input.ds_rrset.len(),
                input.dnskey_rrset.len(),
                input.dnskey_rrsig_rrset.len(),
                input.nsec_rrset.len() + input.nsec3_rrset.len(),
                input.nsec_rrsig_rrset.len() + input.nsec3_rrsig_rrset.len(),
            ));
            Ok(self.name_error_valid)
        }

        fn validate_child_positive_rrset(
            &self,
            input: DelegatedChildDnssecValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.child_validations.lock().unwrap().push((
                input.child_ds_rrset.len(),
                input.child_dnskey_rrset.len(),
                input.child_dnskey_rrsig_rrset.len(),
                input.target_rrset.len(),
                input.target_rrsig_rrset.len(),
            ));
            Ok(self.child_positive_valid)
        }

        fn validate_child_no_data(
            &self,
            input: DelegatedChildDnssecNoDataValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.child_no_data_validations.lock().unwrap().push((
                input.child_ds_rrset.len(),
                input.child_dnskey_rrset.len(),
                input.child_dnskey_rrsig_rrset.len(),
                input.nsec_rrset.len() + input.nsec3_rrset.len(),
                input.nsec_rrsig_rrset.len() + input.nsec3_rrsig_rrset.len(),
            ));
            Ok(self.child_no_data_valid)
        }

        fn validate_child_name_error(
            &self,
            input: DelegatedChildDnssecNameErrorValidation<'_>,
        ) -> Result<bool, ResolverError> {
            self.child_name_error_validations.lock().unwrap().push((
                input.child_ds_rrset.len(),
                input.child_dnskey_rrset.len(),
                input.child_dnskey_rrsig_rrset.len(),
                input.nsec_rrset.len() + input.nsec3_rrset.len(),
                input.nsec_rrsig_rrset.len() + input.nsec3_rrsig_rrset.len(),
            ));
            Ok(self.child_name_error_valid)
        }
    }

    #[test]
    fn single_label_is_hns() {
        assert_eq!(classify_name("welcome"), NameClass::Hns);
    }

    #[test]
    fn trailing_dot_single_label_is_hns() {
        assert_eq!(classify_name("welcome."), NameClass::Hns);
    }

    #[test]
    fn service_prefixed_name_extracts_hns_root() {
        assert_eq!(hns_root_label("_443._tcp.welcome").unwrap(), "welcome");
        assert_eq!(hns_root_label("_443._tcp.welcome.2d").unwrap(), "2d");
    }

    #[test]
    fn strongest_resolution_error_preserves_terminal_evidence_failures() {
        let mut current = Some(ResolverError::DnssecFailed);
        retain_strongest_resolution_error(
            &mut current,
            ResolverError::DnsTransport("later timeout".to_owned()),
        );
        assert_eq!(current, Some(ResolverError::DnssecFailed));

        let mut current = Some(ResolverError::InvalidDnsResponse);
        retain_strongest_resolution_error(&mut current, ResolverError::Port53InterceptionDetected);
        assert_eq!(current, Some(ResolverError::InvalidDnsResponse));

        let mut current = Some(ResolverError::ProofUnavailable);
        retain_strongest_resolution_error(
            &mut current,
            ResolverError::DnsTransport("later refusal".to_owned()),
        );
        assert_eq!(current, Some(ResolverError::ProofUnavailable));
    }

    #[test]
    fn strongest_resolution_error_prefers_confirmed_interception_over_transport_failure() {
        let mut current = Some(ResolverError::DnsTransport("timeout".to_owned()));
        retain_strongest_resolution_error(&mut current, ResolverError::Port53InterceptionDetected);
        assert_eq!(current, Some(ResolverError::Port53InterceptionDetected));

        retain_strongest_resolution_error(
            &mut current,
            ResolverError::DnsTransport("later refusal".to_owned()),
        );
        assert_eq!(current, Some(ResolverError::Port53InterceptionDetected));
    }

    #[test]
    fn dotted_name_is_icann() {
        assert_eq!(classify_name("example.com"), NameClass::Icann);
    }

    #[test]
    fn uncommon_and_internationalized_iana_tlds_are_icann() {
        assert_eq!(classify_name("collection.museum"), NameClass::Icann);
        assert_eq!(
            classify_name("example.xn--vermgensberater-ctb"),
            NameClass::Icann
        );
        assert_eq!(classify_name("museum"), NameClass::Hns);
    }

    #[test]
    fn special_use_suffixes_and_ip_literals_never_route_to_hns() {
        for host in [
            "alt",
            "name.alt",
            "example",
            "www.example",
            "internal",
            "corp.internal",
            "name.invalid",
            "printer.local",
            "home.arpa",
            "localhost",
            "www.localhost",
            "service.onion",
            "name.test",
            "127.0.0.1",
            "::1",
        ] {
            assert_eq!(classify_name(host), NameClass::Icann, "{host}");
        }
    }

    #[test]
    fn delegated_dns_policy_rejects_non_public_endpoints_before_transport() {
        let name = DnsName::from_ascii("host.name").unwrap();
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "::1",
            "fc00::1",
            "fe80::1",
            "64:ff9b::a00:1",
        ] {
            let transport = PolicyDnsTransport {
                policy: DnsEndpointPolicy::strict(),
                calls: AtomicUsize::new(0),
            };
            let server = SocketAddr::new(address.parse().unwrap(), 53);

            assert_eq!(
                dns_query(&transport, server, &name, RecordType::A).unwrap_err(),
                ResolverError::NonPublicDnsEndpoint,
                "{address}"
            );
            assert_eq!(transport.calls.load(Ordering::SeqCst), 0, "{address}");
        }
    }

    #[test]
    fn authoritative_doh_policy_rejects_unsafe_port_before_transport() {
        let transport = PolicyDnsTransport {
            policy: DnsEndpointPolicy::strict(),
            calls: AtomicUsize::new(0),
        };
        let endpoint = AuthoritativeDohEndpoint {
            ns: DnsName::from_ascii("ns.name").unwrap(),
            host: "ns.name".to_owned(),
            connect_addr: "1.1.1.1".parse().unwrap(),
            port: 22,
            path_and_query: "/dns-query".to_owned(),
            tls_authentication: AuthoritativeDohTlsAuthentication::WebPki,
        };

        assert_eq!(
            dns_query_doh(
                &transport,
                &endpoint,
                &DnsName::from_ascii("host.name").unwrap(),
                RecordType::A,
            )
            .unwrap_err(),
            ResolverError::UnsafeAuthoritativeDohPort(22),
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn regtest_endpoint_policy_explicitly_allows_private_endpoints() {
        let transport = PolicyDnsTransport {
            policy: DnsEndpointPolicy::for_network(NetworkKind::Regtest),
            calls: AtomicUsize::new(0),
        };
        let error = dns_query(
            &transport,
            "127.0.0.1:53".parse().unwrap(),
            &DnsName::from_ascii("host.name").unwrap(),
            RecordType::A,
        )
        .unwrap_err();

        assert_eq!(error, ResolverError::UnsupportedBackend);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            DnsEndpointPolicy::for_network(NetworkKind::Mainnet),
            DnsEndpointPolicy::strict()
        );
        assert_eq!(
            DnsEndpointPolicy::for_network(NetworkKind::Testnet),
            DnsEndpointPolicy::strict()
        );
    }

    #[test]
    fn udp_transport_rejects_response_from_wrong_source_port() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_address = server.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut query = [0u8; 16];
            let (_, client) = server.recv_from(&mut query).unwrap();
            let wrong_source = UdpSocket::bind("127.0.0.1:0").unwrap();
            wrong_source.send_to(b"spoofed", client).unwrap();
        });
        let transport = UdpTcpDnsTransport {
            timeout: Duration::from_secs(1),
            endpoint_policy: DnsEndpointPolicy::permissive(),
            ..UdpTcpDnsTransport::default()
        };

        assert_eq!(
            transport
                .exchange_udp(server_address, b"query")
                .unwrap_err(),
            ResolverError::InvalidDnsResponse
        );
        responder.join().unwrap();
    }

    #[test]
    fn dotted_hns_name_extracts_final_root_label() {
        assert_eq!(hns_root_label("welcome.2d").unwrap(), "2d");
        assert_eq!(classify_name("welcome.2d"), NameClass::Hns);
    }

    #[test]
    fn whitespace_is_search() {
        assert_eq!(classify_name("two words"), NameClass::Search);
    }

    #[test]
    fn cached_resolver_reuses_fresh_answer() {
        let resolver = CachedResolver::new(
            CountingResolver {
                count: AtomicUsize::new(0),
            },
            32,
            Duration::from_secs(60),
        );
        let request = ResolutionRequest {
            qname: "name".to_owned(),
            qtype: 1,
        };

        resolver.resolve(&request).unwrap();
        resolver.resolve(&request).unwrap();

        assert_eq!(resolver.inner.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cached_resolver_reuses_name_not_found() {
        let resolver = CachedResolver::new(
            CountingNameNotFoundResolver {
                count: AtomicUsize::new(0),
            },
            32,
            Duration::from_secs(60),
        );
        let request = ResolutionRequest {
            qname: "missing".to_owned(),
            qtype: 1,
        };

        assert_eq!(
            resolver.resolve(&request).unwrap_err(),
            ResolverError::NameNotFound
        );
        assert_eq!(
            resolver.resolve(&request).unwrap_err(),
            ResolverError::NameNotFound
        );

        assert_eq!(resolver.inner.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn proof_backed_resolver_filters_verified_records() {
        let root_name = "welcome".to_owned();
        let request_name = DnsName::from_ascii("welcome").unwrap();
        let resolver = ProofBackedResolver::new(StaticProofProvider {
            proven: ProvenNameRecords {
                root_name: root_name.clone(),
                name_hash: NameHash::from_name(&root_name).unwrap(),
                records: vec![
                    record(request_name.clone(), RecordType::A, vec![127, 0, 0, 1]),
                    record(request_name.clone(), RecordType::Aaaa, vec![0; 16]),
                    record(
                        DnsName::from_ascii("other").unwrap(),
                        RecordType::A,
                        vec![1, 1, 1, 1],
                    ),
                ],
                secure: true,
                exists: true,
            },
        });

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: "welcome".to_owned(),
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert_eq!(answer.name, request_name);
        assert!(answer.secure);
        assert_eq!(
            answer.records,
            vec![record(answer.name, RecordType::A, vec![127, 0, 0, 1])]
        );
    }

    #[test]
    fn proof_backed_resolver_rejects_mismatched_proof_name() {
        let resolver = ProofBackedResolver::new(StaticProofProvider {
            proven: ProvenNameRecords {
                root_name: "other".to_owned(),
                name_hash: NameHash::from_name("other").unwrap(),
                records: Vec::new(),
                secure: true,
                exists: true,
            },
        });

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                })
                .unwrap_err(),
            ResolverError::ProofNameMismatch,
        );
    }

    #[test]
    fn proof_backed_resolver_reports_verified_non_inclusion() {
        let root_name = "missing".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let resolver = ProofBackedResolver::new(StaticProofProvider {
            proven: ProvenNameRecords {
                root_name: root_name.clone(),
                name_hash,
                records: Vec::new(),
                secure: true,
                exists: false,
            },
        });

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: root_name,
                    qtype: RecordType::A.code(),
                })
                .unwrap_err(),
            ResolverError::NameNotFound,
        );
    }

    #[test]
    fn proven_records_decode_hsd_resource_value() {
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let mut value = vec![0, 1];
        encode_name(&mut value, "ns1.welcome");

        let proven =
            ProvenNameRecords::from_resource_value(root_name.clone(), name_hash, &value).unwrap();

        assert_eq!(proven.root_name, root_name);
        assert_eq!(proven.name_hash, name_hash);
        assert!(proven.secure);
        assert!(proven.exists);
        assert_eq!(proven.records.len(), 1);
        assert_eq!(
            proven.records[0].name,
            DnsName::from_ascii("welcome").unwrap()
        );
        assert_eq!(proven.records[0].record_type, RecordType::Ns);
        assert_eq!(
            proven.records[0].ttl,
            hns_core::resource::DEFAULT_HANDSHAKE_RESOURCE_TTL
        );
        assert_eq!(proven.records[0].rdata, name_bytes("ns1.welcome"));
    }

    #[test]
    fn proven_records_reject_invalid_resource_value() {
        assert_eq!(
            ProvenNameRecords::from_resource_value(
                "welcome".to_owned(),
                NameHash::from_name("welcome").unwrap(),
                &[1],
            )
            .unwrap_err(),
            ResolverError::InvalidResource(ResourceError::UnsupportedVersion),
        );
    }

    #[test]
    fn resource_value_provider_decodes_verified_inclusion_for_resolver() {
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let mut value = vec![0, 1];
        encode_name(&mut value, "ns1.welcome");
        let resolver =
            ProofBackedResolver::new(ResourceValueProofProvider::new(StaticValueProvider {
                verified: VerifiedResourceValue::inclusion(root_name.clone(), name_hash, value),
            }));

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::Ns.code(),
            })
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].record_type, RecordType::Ns);
        assert_eq!(answer.records[0].rdata, name_bytes("ns1.welcome"));
    }

    #[test]
    fn delegating_resolver_answers_root_ns_from_hns_proof() {
        let root_name = "welcome".to_owned();
        let request_name = DnsName::from_ascii("welcome").unwrap();
        let resolver = DelegatingResolver::new(
            StaticProofProvider {
                proven: ProvenNameRecords {
                    root_name: root_name.clone(),
                    name_hash: NameHash::from_name(&root_name).unwrap(),
                    records: vec![ns_record("welcome", "ns1.welcome")],
                    secure: true,
                    exists: true,
                },
            },
            FailClosedResolver,
        );

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::Ns.code(),
            })
            .unwrap();

        assert_eq!(answer.name, request_name);
        assert!(answer.secure);
        assert_eq!(answer.records, vec![ns_record("welcome", "ns1.welcome")]);
    }

    #[test]
    fn delegating_resolver_delegates_apex_address_with_ds() {
        let root_name = "welcome".to_owned();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = DelegatingResolver::new(
            StaticProofProvider {
                proven: ProvenNameRecords {
                    root_name: root_name.clone(),
                    name_hash: NameHash::from_name(&root_name).unwrap(),
                    records: vec![ns_record("welcome", "ns1.welcome"), ds_record("welcome")],
                    secure: true,
                    exists: true,
                },
            },
            ScriptedResolver::new(
                vec![resolver_response(
                    "welcome",
                    RecordType::A.code(),
                    true,
                    vec![record(
                        DnsName::from_ascii("welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    )],
                )],
                Arc::clone(&requests),
            ),
        );

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].record_type, RecordType::A);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![ResolutionRequest {
                qname: "welcome".to_owned(),
                qtype: RecordType::A.code(),
            }],
        );
    }

    #[test]
    fn delegating_resolver_does_not_synthesize_from_hns_dane_capsule_experiment() {
        let root_name = "welcome".to_owned();
        let resolver = DelegatingResolver::new(
            StaticProofProvider {
                proven: ProvenNameRecords {
                    root_name: root_name.clone(),
                    name_hash: NameHash::from_name(&root_name).unwrap(),
                    records: vec![txt_record(
                        "welcome",
                        "hnsb=1;host=@;a=203.0.113.10;alpn=h2,h3;tlsa=3,1,1,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    )],
                    secure: true,
                    exists: true,
                },
            },
            FailClosedResolver,
        );

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert!(answer.secure);
        assert!(answer.records.is_empty());
    }

    #[test]
    fn authoritative_doh_endpoint_bootstraps_from_hns_proven_txt_without_port_53() {
        let delegation = HnsDelegation {
            root_name: "welcome".to_owned(),
            owner: DnsName::from_ascii("welcome").unwrap(),
            records: vec![
                ns_record("welcome", "ns1.welcome"),
                glue4_record("ns1.welcome", [203, 0, 113, 53]),
                txt_record(
                    "welcome",
                    "hnsdns=1;ns=ns1;transport=doh;doh=https://doh.example:8443/dns-query{?dns}",
                ),
            ],
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let transport = ScriptedDnsTransport {
            responses: HashMap::new(),
            server_responses: HashMap::new(),
            requests: Arc::clone(&requests),
            udp_behavior: ScriptedUdpBehavior::Normal,
        };

        assert_eq!(
            authoritative_doh_endpoints(&transport, &accepting_dnssec_verifier(), &delegation)
                .unwrap(),
            vec![AuthoritativeDohEndpoint {
                ns: DnsName::from_ascii("ns1.welcome").unwrap(),
                host: "doh.example".to_owned(),
                connect_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)),
                port: 8443,
                path_and_query: "/dns-query".to_owned(),
                tls_authentication: AuthoritativeDohTlsAuthentication::WebPki,
            }]
        );
        assert!(requests.lock().unwrap().is_empty());
    }

    #[test]
    fn authoritative_doh_endpoint_uses_hns_proof_tlsa_pins() {
        let first = "11".repeat(32);
        let second = "AA".repeat(32);
        let declaration = format!(
            "hnsdns=1;ns=ns1.denuoweb.;transport=doh;doh=https://denuoweb:8443/dns-query;tlsa=3,1,1,{first};tlsa=3,1,1,{second}"
        );
        assert!(declaration.len() <= HNSDNS_MAX_TEXT_BYTES);
        let delegation = HnsDelegation {
            root_name: "denuoweb".to_owned(),
            owner: DnsName::from_ascii("denuoweb").unwrap(),
            records: vec![
                ns_record("denuoweb", "ns1.denuoweb"),
                glue4_record("ns1.denuoweb", [35, 212, 156, 128]),
                txt_record("denuoweb", &declaration),
            ],
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let transport = ScriptedDnsTransport {
            responses: HashMap::new(),
            server_responses: HashMap::new(),
            requests: Arc::clone(&requests),
            udp_behavior: ScriptedUdpBehavior::Normal,
        };

        let endpoints =
            authoritative_doh_endpoints(&transport, &accepting_dnssec_verifier(), &delegation)
                .unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].host, "denuoweb");
        assert_eq!(endpoints[0].port, 8443);
        assert_eq!(
            endpoints[0].tls_authentication,
            AuthoritativeDohTlsAuthentication::HnsProofTlsa(vec![
                TlsaRecord {
                    usage: TlsaUsage::DaneEe,
                    selector: TlsaSelector::SubjectPublicKeyInfo,
                    matching: TlsaMatching::Sha256,
                    association_data: vec![0x11; 32],
                },
                TlsaRecord {
                    usage: TlsaUsage::DaneEe,
                    selector: TlsaSelector::SubjectPublicKeyInfo,
                    matching: TlsaMatching::Sha256,
                    association_data: vec![0xaa; 32],
                },
            ])
        );
        assert!(requests.lock().unwrap().is_empty());
    }

    #[test]
    fn pinned_authoritative_doh_failure_falls_back_to_port_53() {
        let pin = "36".repeat(32);
        let delegation = HnsDelegation {
            root_name: "denuoweb".to_owned(),
            owner: DnsName::from_ascii("denuoweb").unwrap(),
            records: vec![
                ns_record("denuoweb", "ns1.denuoweb"),
                glue4_record("ns1.denuoweb", [35, 212, 156, 128]),
                ds_record("denuoweb"),
                txt_record(
                    "denuoweb",
                    &format!(
                        "hnsdns=1;ns=ns1.denuoweb.;transport=doh;doh=https://denuoweb:8443/dns-query;tlsa=3,1,1,{pin}"
                    ),
                ),
            ],
        };
        let resolver = AuthoritativeDnssecResolver::new(
            FailingPinnedDohTransport {
                doh_calls: AtomicUsize::new(0),
                udp_calls: AtomicUsize::new(0),
                tcp_calls: AtomicUsize::new(0),
            },
            accepting_dnssec_verifier(),
        )
        .with_authoritative_doh_preferred();

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "denuoweb".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation,
            )
            .unwrap();
        assert!(answer.secure);
        assert_eq!(
            answer.records,
            vec![record(
                DnsName::from_ascii("denuoweb").unwrap(),
                RecordType::A,
                vec![1, 1, 1, 1],
            )]
        );

        let (transport, _) = resolver.into_parts();
        assert_eq!(transport.doh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transport.udp_calls.load(Ordering::SeqCst), 2);
        assert_eq!(transport.tcp_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn direct_authority_precedes_available_pinned_doh_by_default() {
        let pin = "36".repeat(32);
        let delegation = HnsDelegation {
            root_name: "denuoweb".to_owned(),
            owner: DnsName::from_ascii("denuoweb").unwrap(),
            records: vec![
                ns_record("denuoweb", "ns1.denuoweb"),
                glue4_record("ns1.denuoweb", [35, 212, 156, 128]),
                ds_record("denuoweb"),
                txt_record(
                    "denuoweb",
                    &format!(
                        "hnsdns=1;ns=ns1.denuoweb.;transport=doh;doh=https://denuoweb:8443/dns-query;tlsa=3,1,1,{pin}"
                    ),
                ),
            ],
        };
        let resolver = AuthoritativeDnssecResolver::new(
            FailingPinnedDohTransport {
                doh_calls: AtomicUsize::new(0),
                udp_calls: AtomicUsize::new(0),
                tcp_calls: AtomicUsize::new(0),
            },
            accepting_dnssec_verifier(),
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "denuoweb".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation,
            )
            .unwrap();
        assert!(answer.secure);

        let (transport, _) = resolver.into_parts();
        assert_eq!(transport.udp_calls.load(Ordering::SeqCst), 2);
        assert_eq!(transport.tcp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(transport.doh_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn later_authoritative_doh_transport_failure_cannot_mask_direct_dnssec_failure() {
        let pin = "36".repeat(32);
        let delegation = HnsDelegation {
            root_name: "denuoweb".to_owned(),
            owner: DnsName::from_ascii("denuoweb").unwrap(),
            records: vec![
                ns_record("denuoweb", "ns1.denuoweb"),
                glue4_record("ns1.denuoweb", [35, 212, 156, 128]),
                ds_record("denuoweb"),
                txt_record(
                    "denuoweb",
                    &format!(
                        "hnsdns=1;ns=ns1.denuoweb.;transport=doh;doh=https://denuoweb:8443/dns-query;tlsa=3,1,1,{pin}"
                    ),
                ),
            ],
        };
        let mut verifier = accepting_dnssec_verifier();
        verifier.positive_valid = false;
        let resolver = AuthoritativeDnssecResolver::new(
            FailingPinnedDohTransport {
                doh_calls: AtomicUsize::new(0),
                udp_calls: AtomicUsize::new(0),
                tcp_calls: AtomicUsize::new(0),
            },
            verifier,
        );

        assert_eq!(
            resolver
                .resolve_delegated(
                    &ResolutionRequest {
                        qname: "denuoweb".to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    &delegation,
                )
                .unwrap_err(),
            ResolverError::DnssecFailed,
        );

        let (transport, _) = resolver.into_parts();
        assert_eq!(transport.udp_calls.load(Ordering::SeqCst), 2);
        assert_eq!(transport.tcp_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transport.doh_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn confirmed_port53_interception_pivots_to_pinned_doh_and_stays_off_direct() {
        let pin = "36".repeat(32);
        let delegation = HnsDelegation {
            root_name: "denuoweb".to_owned(),
            owner: DnsName::from_ascii("denuoweb").unwrap(),
            records: vec![
                ns_record("denuoweb", "ns1.denuoweb"),
                glue4_record("ns1.denuoweb", [35, 212, 156, 128]),
                ds_record("denuoweb"),
                txt_record(
                    "denuoweb",
                    &format!(
                        "hnsdns=1;ns=ns1.denuoweb.;transport=doh;doh=https://denuoweb:8443/dns-query;tlsa=3,1,1,{pin}"
                    ),
                ),
            ],
        };
        let resolver = AuthoritativeDnssecResolver::new(
            InterceptedDnsTransport {
                interception_detected: AtomicBool::new(false),
                probe_calls: AtomicUsize::new(0),
                doh_calls: AtomicUsize::new(0),
                udp_calls: AtomicUsize::new(0),
                tcp_calls: AtomicUsize::new(0),
            },
            accepting_dnssec_verifier(),
        );
        let request = ResolutionRequest {
            qname: "denuoweb".to_owned(),
            qtype: RecordType::A.code(),
        };

        for _ in 0..2 {
            let answer = resolver.resolve_delegated(&request, &delegation).unwrap();
            assert!(answer.secure);
            assert_eq!(
                answer.records,
                vec![record(
                    DnsName::from_ascii("denuoweb").unwrap(),
                    RecordType::A,
                    vec![1, 1, 1, 1],
                )]
            );
        }

        let (transport, _) = resolver.into_parts();
        assert_eq!(transport.udp_calls.load(Ordering::SeqCst), 2);
        assert_eq!(transport.tcp_calls.load(Ordering::SeqCst), 0);
        assert_eq!(transport.probe_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transport.doh_calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn malformed_pinned_authoritative_doh_falls_back_to_port_53() {
        let delegation = HnsDelegation {
            root_name: "denuoweb".to_owned(),
            owner: DnsName::from_ascii("denuoweb").unwrap(),
            records: vec![
                ns_record("denuoweb", "ns1.denuoweb"),
                glue4_record("ns1.denuoweb", [35, 212, 156, 128]),
                ds_record("denuoweb"),
                txt_record(
                    "denuoweb",
                    "hnsdns=1;ns=ns1.denuoweb.;doh=https://denuoweb:8443/dns-query;tlsa=3,1,1,invalid",
                ),
            ],
        };
        let resolver = AuthoritativeDnssecResolver::new(
            FailingPinnedDohTransport {
                doh_calls: AtomicUsize::new(0),
                udp_calls: AtomicUsize::new(0),
                tcp_calls: AtomicUsize::new(0),
            },
            accepting_dnssec_verifier(),
        )
        .with_authoritative_doh_preferred();

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "denuoweb".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation,
            )
            .unwrap();
        assert!(answer.secure);
        assert_eq!(
            answer.records,
            vec![record(
                DnsName::from_ascii("denuoweb").unwrap(),
                RecordType::A,
                vec![1, 1, 1, 1],
            )]
        );

        let (transport, _) = resolver.into_parts();
        assert_eq!(transport.doh_calls.load(Ordering::SeqCst), 0);
        assert_eq!(transport.udp_calls.load(Ordering::SeqCst), 2);
        assert_eq!(transport.tcp_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn authoritative_doh_endpoint_rejects_invalid_or_excess_proof_tlsa_pins() {
        let valid = "11".repeat(32);
        let invalid_declarations = [
            "hnsdns=1;ns=ns1;doh=https://welcome/dns-query;tlsa=3,1,1,abcd".to_owned(),
            format!("hnsdns=1;ns=ns1;doh=https://welcome/dns-query;tlsa=2,1,1,{valid}"),
            format!("hnsdns=1;ns=ns1;doh=https://welcome/dns-query;tlsa=3,0,1,{valid}"),
            format!("hnsdns=1;ns=ns1;doh=https://welcome/dns-query;tlsa=3,1,2,{valid}"),
            format!(
                "hnsdns=1;ns=ns1;tlsa=3,1,1,{valid};tlsa=3,1,1,{};tlsa=3,1,1,{}",
                "22".repeat(32),
                "33".repeat(32),
            ),
        ];

        for declaration in invalid_declarations {
            assert!(declaration.len() <= HNSDNS_MAX_TEXT_BYTES, "{declaration}");
            assert_eq!(
                parse_hnsdns_declaration(&declaration, &DnsName::from_ascii("welcome").unwrap(),)
                    .unwrap_err(),
                ResolverError::InvalidAuthoritativeDoh,
                "{declaration}",
            );
        }
    }

    #[test]
    fn authoritative_doh_cache_key_changes_when_proof_pin_changes() {
        let delegation = |pin: &str| HnsDelegation {
            root_name: "welcome".to_owned(),
            owner: DnsName::from_ascii("welcome").unwrap(),
            records: vec![
                ns_record("welcome", "ns1.welcome"),
                glue4_record("ns1.welcome", [203, 0, 113, 53]),
                txt_record(
                    "welcome",
                    &format!("hnsdns=1;ns=ns1;doh=https://welcome/dns-query;tlsa=3,1,1,{pin}"),
                ),
            ],
        };

        assert_ne!(
            authoritative_doh_cache_key(&delegation(&"11".repeat(32))),
            authoritative_doh_cache_key(&delegation(&"22".repeat(32))),
        );
    }

    #[test]
    fn authoritative_doh_endpoint_is_discovered_from_rfc9461_svcb() {
        let delegation = HnsDelegation {
            root_name: "welcome".to_owned(),
            owner: DnsName::from_ascii("welcome").unwrap(),
            records: vec![
                ns_record("welcome", "ns1.welcome"),
                glue4_record("ns1.welcome", [203, 0, 113, 53]),
                ds_record("welcome"),
            ],
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let transport = ScriptedDnsTransport {
            responses: dns_responses(vec![
                (
                    "_dns.ns1.welcome",
                    RecordType::Svcb,
                    vec![
                        svcb_doh_record("_dns.ns1.welcome", "doh.example", "/dns-query{?dns}"),
                        rrsig_record("_dns.ns1.welcome"),
                    ],
                ),
                (
                    "welcome",
                    RecordType::Dnskey,
                    vec![
                        record(
                            DnsName::from_ascii("welcome").unwrap(),
                            RecordType::Dnskey,
                            vec![1, 2, 3, 4],
                        ),
                        rrsig_record("welcome"),
                    ],
                ),
            ]),
            server_responses: HashMap::new(),
            requests: Arc::clone(&requests),
            udp_behavior: ScriptedUdpBehavior::Normal,
        };

        assert_eq!(
            authoritative_doh_endpoints(&transport, &accepting_dnssec_verifier(), &delegation)
                .unwrap(),
            vec![AuthoritativeDohEndpoint {
                ns: DnsName::from_ascii("ns1.welcome").unwrap(),
                host: "doh.example".to_owned(),
                connect_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)),
                port: 443,
                path_and_query: "/dns-query".to_owned(),
                tls_authentication: AuthoritativeDohTlsAuthentication::WebPki,
            }]
        );
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 53),
                    "_dns.ns1.welcome".to_owned(),
                    RecordType::Svcb.code(),
                    false,
                ),
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 53),
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
            ]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_prefers_discovered_authoritative_doh_when_enabled() {
        let delegation = HnsDelegation {
            root_name: "welcome".to_owned(),
            owner: DnsName::from_ascii("welcome").unwrap(),
            records: vec![
                ns_record("welcome", "ns1.welcome"),
                glue4_record("ns1.welcome", [203, 0, 113, 53]),
                ds_record("welcome"),
            ],
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "_dns.ns1.welcome",
                        RecordType::Svcb,
                        vec![
                            svcb_doh_record("_dns.ns1.welcome", "doh.example", "/dns-query{?dns}"),
                            rrsig_record("_dns.ns1.welcome"),
                        ],
                    ),
                    (
                        "welcome",
                        RecordType::A,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::A,
                                vec![203, 0, 113, 20],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests: Arc::clone(&requests),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: true,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        )
        .with_authoritative_doh_preferred();

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation,
            )
            .unwrap();
        let second_answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation,
            )
            .unwrap();

        assert!(answer.secure);
        assert!(second_answer.secure);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 53),
                    "_dns.ns1.welcome".to_owned(),
                    RecordType::Svcb.code(),
                    false,
                ),
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 53),
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 443),
                    "welcome".to_owned(),
                    RecordType::A.code(),
                    true,
                ),
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 443),
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    true,
                ),
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 443),
                    "welcome".to_owned(),
                    RecordType::A.code(),
                    true,
                ),
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 443),
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    true,
                ),
            ]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_retries_tcp_when_udp_dnssec_fails() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 53);
        let resolver = AuthoritativeDnssecResolver::new(
            TcpRepairDnsTransport {
                requests: Arc::clone(&requests),
            },
            StaticDnssecVerifier {
                positive_valid: true,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    glue4_record("ns1.welcome", [203, 0, 113, 53]),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert_eq!(
            answer.records,
            vec![record(
                DnsName::from_ascii("welcome").unwrap(),
                RecordType::A,
                vec![1, 1, 1, 1],
            )]
        );
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (server, "welcome".to_owned(), RecordType::A.code(), false),
                (
                    server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false
                ),
                (server, "welcome".to_owned(), RecordType::A.code(), true),
                (
                    server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    true
                ),
            ]
        );
    }

    #[test]
    fn delegating_resolver_fails_closed_when_ds_child_is_insecure() {
        let root_name = "welcome".to_owned();
        let resolver = DelegatingResolver::new(
            StaticProofProvider {
                proven: ProvenNameRecords {
                    root_name: root_name.clone(),
                    name_hash: NameHash::from_name(&root_name).unwrap(),
                    records: vec![ns_record("welcome", "ns1.welcome"), ds_record("welcome")],
                    secure: true,
                    exists: true,
                },
            },
            ScriptedResolver::new(
                vec![resolver_response(
                    "welcome",
                    RecordType::A.code(),
                    false,
                    Vec::new(),
                )],
                Arc::new(Mutex::new(Vec::new())),
            ),
        );

        assert_eq!(
            resolver
                .resolve(&ResolutionRequest {
                    qname: root_name,
                    qtype: RecordType::A.code(),
                })
                .unwrap_err(),
            ResolverError::DnssecFailed,
        );
    }

    #[test]
    fn delegating_resolver_marks_unsigned_delegation_insecure() {
        let root_name = "welcome".to_owned();
        let resolver = DelegatingResolver::new(
            StaticProofProvider {
                proven: ProvenNameRecords {
                    root_name: root_name.clone(),
                    name_hash: NameHash::from_name(&root_name).unwrap(),
                    records: vec![ns_record("welcome", "ns1.welcome")],
                    secure: true,
                    exists: true,
                },
            },
            ScriptedResolver::new(
                vec![resolver_response(
                    "welcome",
                    RecordType::A.code(),
                    true,
                    vec![record(
                        DnsName::from_ascii("welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    )],
                )],
                Arc::new(Mutex::new(Vec::new())),
            ),
        );

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert!(!answer.secure);
        assert_eq!(answer.records.len(), 1);
    }

    #[test]
    fn delegated_name_error_requires_a_ds_secured_child() {
        let resolver_for = |secure_child: bool| {
            let mut records = vec![ns_record("welcome", "ns1.welcome")];
            if secure_child {
                records.push(ds_record("welcome"));
            }
            DelegatingResolver::new(
                StaticProofProvider {
                    proven: ProvenNameRecords {
                        root_name: "welcome".to_owned(),
                        name_hash: NameHash::from_name("welcome").unwrap(),
                        records,
                        secure: true,
                        exists: true,
                    },
                },
                CountingNameNotFoundResolver {
                    count: AtomicUsize::new(0),
                },
            )
        };
        let request = ResolutionRequest {
            qname: "welcome".to_owned(),
            qtype: RecordType::A.code(),
        };

        assert_eq!(
            resolver_for(true).resolve(&request).unwrap_err(),
            ResolverError::NameNotFound,
        );
        assert_eq!(
            resolver_for(false).resolve(&request).unwrap_err(),
            ResolverError::DnssecFailed,
        );
    }

    #[test]
    fn delegating_resolver_passes_hns_delegation_context() {
        let root_name = "welcome".to_owned();
        let delegations = Arc::new(Mutex::new(Vec::new()));
        let resolver = DelegatingResolver::new(
            StaticProofProvider {
                proven: ProvenNameRecords {
                    root_name: root_name.clone(),
                    name_hash: NameHash::from_name(&root_name).unwrap(),
                    records: vec![
                        ns_record("welcome", "ns1.welcome"),
                        record(
                            DnsName::from_ascii("ns1.welcome").unwrap(),
                            RecordType::A,
                            vec![127, 0, 0, 1],
                        ),
                        ds_record("welcome"),
                    ],
                    secure: true,
                    exists: true,
                },
            },
            CapturingDelegatedResolver {
                delegations: Arc::clone(&delegations),
            },
        );

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert!(answer.secure);
        let captured = delegations.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].root_name, "welcome");
        assert_eq!(captured[0].owner, DnsName::from_ascii("welcome").unwrap());
        assert_eq!(captured[0].records.len(), 3);
    }

    #[test]
    fn delegating_resolver_hydrates_out_of_zone_hns_nameserver_address() {
        let root_name = "welcome".to_owned();
        let ns_root_name = "hshub".to_owned();
        let ns_name = DnsName::from_ascii("ns1.hshub").unwrap();
        let delegations = Arc::new(Mutex::new(Vec::new()));
        let mut proven = HashMap::new();
        proven.insert(
            root_name.clone(),
            ProvenNameRecords {
                root_name: root_name.clone(),
                name_hash: NameHash::from_name(&root_name).unwrap(),
                records: vec![ns_record("welcome", "ns1.hshub"), ds_record("welcome")],
                secure: true,
                exists: true,
            },
        );
        proven.insert(
            ns_root_name.clone(),
            ProvenNameRecords {
                root_name: ns_root_name.clone(),
                name_hash: NameHash::from_name(&ns_root_name).unwrap(),
                records: vec![
                    ns_record("hshub", "ns1.hshub"),
                    record(ns_name.clone(), RecordType::A, vec![127, 0, 0, 9]),
                ],
                secure: true,
                exists: true,
            },
        );
        let resolver = DelegatingResolver::new(
            MapProofProvider { proven },
            CapturingDelegatedResolver {
                delegations: Arc::clone(&delegations),
            },
        );

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::A.code(),
            })
            .unwrap();

        assert!(answer.secure);
        let captured = delegations.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(
            captured[0]
                .records
                .contains(&record(ns_name, RecordType::A, vec![127, 0, 0, 9],))
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_validates_positive_rrset() {
        let server = SocketAddr::from(([127, 0, 0, 1], 53));
        let validations = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "welcome",
                        RecordType::A,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::A,
                                vec![127, 0, 0, 1],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests: Arc::clone(&requests),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: true,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::clone(&validations),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].rdata, vec![127, 0, 0, 1]);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (server, "welcome".to_owned(), RecordType::A.code(), false),
                (
                    server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false
                ),
            ],
        );
        assert_eq!(*validations.lock().unwrap(), vec![(1, 1, 1, 1, 1)]);
    }

    #[test]
    fn authoritative_dnssec_resolver_validates_inline_child_signed_answer() {
        let server = SocketAddr::from(([127, 0, 0, 1], 53));
        let child_validations = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "blog.welcome",
                        RecordType::A,
                        vec![
                            record(
                                DnsName::from_ascii("blog.welcome").unwrap(),
                                RecordType::A,
                                vec![127, 0, 0, 1],
                            ),
                            rrsig_record_for_signer("blog.welcome", RecordType::A, "blog.welcome"),
                        ],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record_for_signer("welcome", RecordType::Dnskey, "welcome"),
                        ],
                    ),
                    (
                        "blog.welcome",
                        RecordType::Ds,
                        vec![
                            ds_record("blog.welcome"),
                            rrsig_record_for_signer("blog.welcome", RecordType::Ds, "welcome"),
                        ],
                    ),
                    (
                        "blog.welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("blog.welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![5, 6, 7, 8],
                            ),
                            rrsig_record_for_signer(
                                "blog.welcome",
                                RecordType::Dnskey,
                                "blog.welcome",
                            ),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests: Arc::clone(&requests),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: true,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::clone(&child_validations),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "blog.welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records.len(), 1);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (
                    server,
                    "blog.welcome".to_owned(),
                    RecordType::A.code(),
                    false
                ),
                (
                    server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false
                ),
                (
                    server,
                    "blog.welcome".to_owned(),
                    RecordType::Ds.code(),
                    false
                ),
                (
                    server,
                    "blog.welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false
                ),
            ],
        );
        assert_eq!(
            *child_validations.lock().unwrap(),
            vec![(1usize, 1usize, 1usize, 1usize, 1usize)]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_validates_inline_child_nsec_no_data() {
        let server = SocketAddr::from(([127, 0, 0, 1], 53));
        let child_no_data_validations = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut responses = dns_responses(vec![
            (
                "welcome",
                RecordType::Dnskey,
                vec![
                    record(
                        DnsName::from_ascii("welcome").unwrap(),
                        RecordType::Dnskey,
                        vec![1, 2, 3, 4],
                    ),
                    rrsig_record_for_signer("welcome", RecordType::Dnskey, "welcome"),
                ],
            ),
            (
                "blog.welcome",
                RecordType::Ds,
                vec![
                    ds_record("blog.welcome"),
                    rrsig_record_for_signer("blog.welcome", RecordType::Ds, "welcome"),
                ],
            ),
            (
                "blog.welcome",
                RecordType::Dnskey,
                vec![
                    record(
                        DnsName::from_ascii("blog.welcome").unwrap(),
                        RecordType::Dnskey,
                        vec![5, 6, 7, 8],
                    ),
                    rrsig_record_for_signer("blog.welcome", RecordType::Dnskey, "blog.welcome"),
                ],
            ),
        ]);
        responses.insert(
            ("blog.welcome".to_owned(), RecordType::Https.code()),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: Vec::new(),
                authorities: vec![
                    nsec_record("blog.welcome"),
                    rrsig_record_for_signer("blog.welcome", RecordType::Nsec, "blog.welcome"),
                ],
                additionals: Vec::new(),
            },
        );
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses,
                server_responses: HashMap::new(),
                requests: Arc::clone(&requests),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: true,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::clone(&child_no_data_validations),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "blog.welcome".to_owned(),
                    qtype: RecordType::Https.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert!(answer.records.is_empty());
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (
                    server,
                    "blog.welcome".to_owned(),
                    RecordType::Https.code(),
                    false
                ),
                (
                    server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false
                ),
                (
                    server,
                    "blog.welcome".to_owned(),
                    RecordType::Ds.code(),
                    false
                ),
                (
                    server,
                    "blog.welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false
                ),
            ],
        );
        assert_eq!(
            *child_no_data_validations.lock().unwrap(),
            vec![(1usize, 1usize, 1usize, 1usize, 2usize)]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_accepts_secure_nsec_no_data() {
        let validations = Arc::new(Mutex::new(Vec::new()));
        let no_data_validations = Arc::new(Mutex::new(Vec::new()));
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "welcome",
                        RecordType::Aaaa,
                        vec![nsec_record("welcome"), rrsig_record("welcome")],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests: Arc::new(Mutex::new(Vec::new())),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: true,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::clone(&validations),
                no_data_validations: Arc::clone(&no_data_validations),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::Aaaa.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert!(answer.records.is_empty());
        assert!(validations.lock().unwrap().is_empty());
        assert_eq!(*no_data_validations.lock().unwrap(), vec![(1, 1, 1, 1, 2)]);
    }

    #[test]
    fn authoritative_dnssec_resolver_accepts_secure_nsec_name_error() {
        let validations = Arc::new(Mutex::new(Vec::new()));
        let no_data_validations = Arc::new(Mutex::new(Vec::new()));
        let name_error_validations = Arc::new(Mutex::new(Vec::new()));
        let mut responses = dns_responses(vec![(
            "welcome",
            RecordType::Dnskey,
            vec![
                record(
                    DnsName::from_ascii("welcome").unwrap(),
                    RecordType::Dnskey,
                    vec![1, 2, 3, 4],
                ),
                rrsig_record("welcome"),
            ],
        )]);
        responses.insert(
            ("missing.welcome".to_owned(), RecordType::A.code()),
            DnsResponseFixture {
                rcode: DNS_RCODE_NXDOMAIN,
                answers: Vec::new(),
                authorities: vec![
                    nsec_record("alpha.welcome"),
                    nsec_record("z.welcome"),
                    rrsig_record("welcome"),
                ],
                additionals: Vec::new(),
            },
        );
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses,
                server_responses: HashMap::new(),
                requests: Arc::new(Mutex::new(Vec::new())),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: true,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::clone(&validations),
                no_data_validations: Arc::clone(&no_data_validations),
                name_error_validations: Arc::clone(&name_error_validations),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "missing.welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert!(answer.records.is_empty());
        assert!(validations.lock().unwrap().is_empty());
        assert!(no_data_validations.lock().unwrap().is_empty());
        assert_eq!(
            *name_error_validations.lock().unwrap(),
            vec![(1, 1, 1, 2, 2)]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_follows_secure_cname_chain() {
        let validations = Arc::new(Mutex::new(Vec::new()));
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "welcome",
                        RecordType::A,
                        vec![
                            cname_record("welcome", "edge.welcome"),
                            rrsig_record("welcome"),
                            record(
                                DnsName::from_ascii("edge.welcome").unwrap(),
                                RecordType::A,
                                vec![127, 0, 0, 1],
                            ),
                            rrsig_record("edge.welcome"),
                        ],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests: Arc::new(Mutex::new(Vec::new())),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: true,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::clone(&validations),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.name, DnsName::from_ascii("welcome").unwrap());
        assert_eq!(answer.records.len(), 2);
        assert_eq!(answer.records[0].record_type, RecordType::Cname);
        assert_eq!(
            answer.records[1].name,
            DnsName::from_ascii("edge.welcome").unwrap()
        );
        assert_eq!(answer.records[1].record_type, RecordType::A);
        assert_eq!(
            *validations.lock().unwrap(),
            vec![(1, 1, 1, 1, 1), (1, 1, 1, 1, 1)]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_follows_secure_child_referral() {
        let parent_server = SocketAddr::from(([127, 0, 0, 1], 53));
        let child_server = SocketAddr::from(([127, 0, 0, 2], 53));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let child_validations = Arc::new(Mutex::new(Vec::new()));
        let mut responses = dns_responses(vec![(
            "welcome",
            RecordType::Dnskey,
            vec![
                record(
                    DnsName::from_ascii("welcome").unwrap(),
                    RecordType::Dnskey,
                    vec![1, 2, 3, 4],
                ),
                rrsig_record("welcome"),
            ],
        )]);
        responses.insert(
            ("www.sub.welcome".to_owned(), RecordType::A.code()),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: Vec::new(),
                authorities: vec![
                    ns_record("sub.welcome", "ns1.sub.welcome"),
                    ds_record("sub.welcome"),
                    rrsig_record("sub.welcome"),
                ],
                additionals: vec![record(
                    DnsName::from_ascii("ns1.sub.welcome").unwrap(),
                    RecordType::A,
                    vec![127, 0, 0, 2],
                )],
            },
        );
        let mut server_responses = HashMap::new();
        server_responses.insert(
            (
                child_server,
                "sub.welcome".to_owned(),
                RecordType::Dnskey.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: vec![
                    record(
                        DnsName::from_ascii("sub.welcome").unwrap(),
                        RecordType::Dnskey,
                        vec![1, 2, 3, 4],
                    ),
                    rrsig_record("sub.welcome"),
                ],
                authorities: Vec::new(),
                additionals: Vec::new(),
            },
        );
        server_responses.insert(
            (
                child_server,
                "www.sub.welcome".to_owned(),
                RecordType::A.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: vec![
                    record(
                        DnsName::from_ascii("www.sub.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 3],
                    ),
                    rrsig_record("www.sub.welcome"),
                ],
                authorities: Vec::new(),
                additionals: Vec::new(),
            },
        );
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses,
                server_responses,
                requests: Arc::clone(&requests),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: true,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::clone(&child_validations),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "www.sub.welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].rdata, vec![127, 0, 0, 3]);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (
                    parent_server,
                    "www.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
                (
                    parent_server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "sub.welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "www.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
            ],
        );
        assert_eq!(*child_validations.lock().unwrap(), vec![(1, 1, 1, 1, 1)]);
    }

    #[test]
    fn authoritative_dnssec_resolver_follows_secure_child_cname_chain() {
        let parent_server = SocketAddr::from(([127, 0, 0, 1], 53));
        let child_server = SocketAddr::from(([127, 0, 0, 2], 53));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let child_validations = Arc::new(Mutex::new(Vec::new()));
        let mut responses = dns_responses(vec![(
            "welcome",
            RecordType::Dnskey,
            vec![
                record(
                    DnsName::from_ascii("welcome").unwrap(),
                    RecordType::Dnskey,
                    vec![1, 2, 3, 4],
                ),
                rrsig_record("welcome"),
            ],
        )]);
        responses.insert(
            ("www.sub.welcome".to_owned(), RecordType::A.code()),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: Vec::new(),
                authorities: vec![
                    ns_record("sub.welcome", "ns1.sub.welcome"),
                    ds_record("sub.welcome"),
                    rrsig_record("sub.welcome"),
                ],
                additionals: vec![record(
                    DnsName::from_ascii("ns1.sub.welcome").unwrap(),
                    RecordType::A,
                    vec![127, 0, 0, 2],
                )],
            },
        );
        let mut server_responses = HashMap::new();
        server_responses.insert(
            (
                child_server,
                "sub.welcome".to_owned(),
                RecordType::Dnskey.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: vec![
                    record(
                        DnsName::from_ascii("sub.welcome").unwrap(),
                        RecordType::Dnskey,
                        vec![1, 2, 3, 4],
                    ),
                    rrsig_record("sub.welcome"),
                ],
                authorities: Vec::new(),
                additionals: Vec::new(),
            },
        );
        server_responses.insert(
            (
                child_server,
                "www.sub.welcome".to_owned(),
                RecordType::A.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: vec![
                    cname_record("www.sub.welcome", "edge.sub.welcome"),
                    rrsig_record("www.sub.welcome"),
                    record(
                        DnsName::from_ascii("edge.sub.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 4],
                    ),
                    rrsig_record("edge.sub.welcome"),
                ],
                authorities: Vec::new(),
                additionals: Vec::new(),
            },
        );
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses,
                server_responses,
                requests: Arc::clone(&requests),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: true,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::clone(&child_validations),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "www.sub.welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert_eq!(answer.records.len(), 2);
        assert_eq!(answer.records[0].record_type, RecordType::Cname);
        assert_eq!(answer.records[1].rdata, vec![127, 0, 0, 4]);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (
                    parent_server,
                    "www.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
                (
                    parent_server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "sub.welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "www.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
            ],
        );
        assert_eq!(
            *child_validations.lock().unwrap(),
            vec![(1, 1, 1, 1, 1), (1, 1, 1, 1, 1)]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_accepts_secure_child_nsec_no_data() {
        let parent_server = SocketAddr::from(([127, 0, 0, 1], 53));
        let child_server = SocketAddr::from(([127, 0, 0, 2], 53));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let child_no_data_validations = Arc::new(Mutex::new(Vec::new()));
        let mut responses = dns_responses(vec![(
            "welcome",
            RecordType::Dnskey,
            vec![
                record(
                    DnsName::from_ascii("welcome").unwrap(),
                    RecordType::Dnskey,
                    vec![1, 2, 3, 4],
                ),
                rrsig_record("welcome"),
            ],
        )]);
        responses.insert(
            ("missing.sub.welcome".to_owned(), RecordType::A.code()),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: Vec::new(),
                authorities: vec![
                    ns_record("sub.welcome", "ns1.sub.welcome"),
                    ds_record("sub.welcome"),
                    rrsig_record("sub.welcome"),
                ],
                additionals: vec![record(
                    DnsName::from_ascii("ns1.sub.welcome").unwrap(),
                    RecordType::A,
                    vec![127, 0, 0, 2],
                )],
            },
        );
        let mut server_responses = HashMap::new();
        server_responses.insert(
            (
                child_server,
                "sub.welcome".to_owned(),
                RecordType::Dnskey.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: vec![
                    record(
                        DnsName::from_ascii("sub.welcome").unwrap(),
                        RecordType::Dnskey,
                        vec![1, 2, 3, 4],
                    ),
                    rrsig_record("sub.welcome"),
                ],
                authorities: Vec::new(),
                additionals: Vec::new(),
            },
        );
        server_responses.insert(
            (
                child_server,
                "missing.sub.welcome".to_owned(),
                RecordType::A.code(),
            ),
            DnsResponseFixture {
                rcode: DNS_RCODE_NOERROR,
                answers: Vec::new(),
                authorities: vec![
                    nsec_record("missing.sub.welcome"),
                    rrsig_record("missing.sub.welcome"),
                ],
                additionals: Vec::new(),
            },
        );
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses,
                server_responses,
                requests: Arc::clone(&requests),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: true,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::clone(&child_no_data_validations),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let answer = resolver
            .resolve_delegated(
                &ResolutionRequest {
                    qname: "missing.sub.welcome".to_owned(),
                    qtype: RecordType::A.code(),
                },
                &delegation_with_records(vec![
                    ns_record("welcome", "ns1.welcome"),
                    record(
                        DnsName::from_ascii("ns1.welcome").unwrap(),
                        RecordType::A,
                        vec![127, 0, 0, 1],
                    ),
                    ds_record("welcome"),
                ]),
            )
            .unwrap();

        assert!(answer.secure);
        assert!(answer.records.is_empty());
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                (
                    parent_server,
                    "missing.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
                (
                    parent_server,
                    "welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "sub.welcome".to_owned(),
                    RecordType::Dnskey.code(),
                    false,
                ),
                (
                    child_server,
                    "missing.sub.welcome".to_owned(),
                    RecordType::A.code(),
                    false,
                ),
            ],
        );
        assert_eq!(
            *child_no_data_validations.lock().unwrap(),
            vec![(1, 1, 1, 1, 2)]
        );
    }

    #[test]
    fn authoritative_dnssec_resolver_fails_closed_when_verifier_rejects() {
        let resolver = AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "welcome",
                        RecordType::A,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::A,
                                vec![127, 0, 0, 1],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests: Arc::new(Mutex::new(Vec::new())),
                udp_behavior: ScriptedUdpBehavior::Normal,
            },
            StaticDnssecVerifier {
                positive_valid: false,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        );

        assert_eq!(
            resolver
                .resolve_delegated(
                    &ResolutionRequest {
                        qname: "welcome".to_owned(),
                        qtype: RecordType::A.code(),
                    },
                    &delegation_with_records(vec![
                        ns_record("welcome", "ns1.welcome"),
                        record(
                            DnsName::from_ascii("ns1.welcome").unwrap(),
                            RecordType::A,
                            vec![127, 0, 0, 1],
                        ),
                        ds_record("welcome"),
                    ]),
                )
                .unwrap_err(),
            ResolverError::DnssecFailed,
        );
    }

    fn authoritative_dnssec_retry_resolver(
        udp_behavior: ScriptedUdpBehavior,
        requests: DnsRequestLog,
    ) -> AuthoritativeDnssecResolver<ScriptedDnsTransport, StaticDnssecVerifier> {
        AuthoritativeDnssecResolver::new(
            ScriptedDnsTransport {
                responses: dns_responses(vec![
                    (
                        "welcome",
                        RecordType::A,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::A,
                                vec![127, 0, 0, 1],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                    (
                        "welcome",
                        RecordType::Dnskey,
                        vec![
                            record(
                                DnsName::from_ascii("welcome").unwrap(),
                                RecordType::Dnskey,
                                vec![1, 2, 3, 4],
                            ),
                            rrsig_record("welcome"),
                        ],
                    ),
                ]),
                server_responses: HashMap::new(),
                requests,
                udp_behavior,
            },
            StaticDnssecVerifier {
                positive_valid: true,
                no_data_valid: false,
                name_error_valid: false,
                child_positive_valid: false,
                child_no_data_valid: false,
                child_name_error_valid: false,
                validations: Arc::new(Mutex::new(Vec::new())),
                no_data_validations: Arc::new(Mutex::new(Vec::new())),
                name_error_validations: Arc::new(Mutex::new(Vec::new())),
                child_validations: Arc::new(Mutex::new(Vec::new())),
                child_no_data_validations: Arc::new(Mutex::new(Vec::new())),
                child_name_error_validations: Arc::new(Mutex::new(Vec::new())),
            },
        )
    }

    fn resolve_welcome_a(
        resolver: &AuthoritativeDnssecResolver<ScriptedDnsTransport, StaticDnssecVerifier>,
    ) -> Result<ResolutionAnswer, ResolverError> {
        resolver.resolve_delegated(
            &ResolutionRequest {
                qname: "welcome".to_owned(),
                qtype: RecordType::A.code(),
            },
            &delegation_with_records(vec![
                ns_record("welcome", "ns1.welcome"),
                record(
                    DnsName::from_ascii("ns1.welcome").unwrap(),
                    RecordType::A,
                    vec![127, 0, 0, 1],
                ),
                ds_record("welcome"),
            ]),
        )
    }

    fn assert_welcome_a_retried_over_tcp(requests: &DnsRequestLog) {
        let requests = requests.lock().unwrap();
        assert!(requests.iter().any(|(_, qname, qtype, tcp)| {
            qname == "welcome" && *qtype == RecordType::A.code() && !*tcp
        }));
        assert!(requests.iter().any(|(_, qname, qtype, tcp)| {
            qname == "welcome" && *qtype == RecordType::A.code() && *tcp
        }));
    }

    #[test]
    fn authoritative_dnssec_resolver_retries_truncated_udp_over_tcp() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = authoritative_dnssec_retry_resolver(
            ScriptedUdpBehavior::Truncated,
            Arc::clone(&requests),
        );
        let answer = resolve_welcome_a(&resolver).unwrap();

        assert!(answer.secure);
        assert_welcome_a_retried_over_tcp(&requests);
    }

    #[test]
    fn authoritative_dnssec_resolver_retries_udp_transport_error_over_tcp() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = authoritative_dnssec_retry_resolver(
            ScriptedUdpBehavior::TransportError,
            Arc::clone(&requests),
        );
        let answer = resolve_welcome_a(&resolver).unwrap();

        assert!(answer.secure);
        assert_welcome_a_retried_over_tcp(&requests);
    }

    #[test]
    fn authoritative_dnssec_resolver_retries_invalid_udp_response_over_tcp() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let resolver = authoritative_dnssec_retry_resolver(
            ScriptedUdpBehavior::InvalidResponse,
            Arc::clone(&requests),
        );
        let answer = resolve_welcome_a(&resolver).unwrap();

        assert!(answer.secure);
        assert_welcome_a_retried_over_tcp(&requests);
    }

    #[test]
    fn dns_response_parser_returns_response_code_for_servfail() {
        let qname = DnsName::from_ascii("welcome").unwrap();
        let id = 0x1234;
        let query =
            DnsMessage::parse(&build_dns_query(id, &qname, RecordType::A).unwrap()).unwrap();
        let response = dns_response(
            &query,
            DnsResponseFixture {
                rcode: 2,
                answers: Vec::new(),
                authorities: Vec::new(),
                additionals: Vec::new(),
            },
            false,
        );

        assert_eq!(
            parse_dns_response(id, &qname, RecordType::A, &response).unwrap_err(),
            ResolverError::DnsResponseCode(2),
        );
    }

    #[test]
    fn resolver_all_record_query_keeps_synth_address_records() {
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let value = vec![0, 4, 127, 0, 0, 1];
        let resolver =
            ProofBackedResolver::new(ResourceValueProofProvider::new(StaticValueProvider {
                verified: VerifiedResourceValue::inclusion(root_name.clone(), name_hash, value),
            }));

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: u16::MAX,
            })
            .unwrap();

        assert_eq!(answer.records.len(), 2);
        assert!(
            answer
                .records
                .iter()
                .any(|record| record.record_type == RecordType::A && record.rdata == [127, 0, 0, 1])
        );
    }

    #[test]
    fn resource_value_provider_allows_verified_non_inclusion() {
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let provider = ResourceValueProofProvider::new(StaticValueProvider {
            verified: VerifiedResourceValue::non_inclusion(root_name.clone(), name_hash),
        });

        let proven = provider.prove_name(&root_name, name_hash).unwrap();

        assert!(proven.secure);
        assert!(!proven.exists);
        assert!(proven.records.is_empty());
    }

    #[test]
    fn resource_value_provider_rejects_mismatched_verified_value() {
        let provider = ResourceValueProofProvider::new(StaticValueProvider {
            verified: VerifiedResourceValue::non_inclusion(
                "other".to_owned(),
                NameHash::from_name("other").unwrap(),
            ),
        });

        assert_eq!(
            provider
                .prove_name("welcome", NameHash::from_name("welcome").unwrap())
                .unwrap_err(),
            ResolverError::ProofNameMismatch,
        );
    }

    #[test]
    fn memory_resource_value_provider_serves_inserted_value() {
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let mut value = vec![0, 1];
        encode_name(&mut value, "ns1.welcome");
        let values = MemoryResourceValueProvider::new();
        values
            .insert(VerifiedResourceValue::inclusion(
                root_name.clone(),
                name_hash,
                value,
            ))
            .unwrap();
        let resolver = ProofBackedResolver::new(ResourceValueProofProvider::new(values));

        let answer = resolver
            .resolve(&ResolutionRequest {
                qname: root_name,
                qtype: RecordType::Ns.code(),
            })
            .unwrap();

        assert_eq!(answer.records.len(), 1);
        assert_eq!(answer.records[0].rdata, name_bytes("ns1.welcome"));
    }

    #[test]
    fn memory_resource_value_provider_rejects_missing_value() {
        let values = MemoryResourceValueProvider::new();

        assert_eq!(
            values
                .prove_resource_value("welcome", NameHash::from_name("welcome").unwrap())
                .unwrap_err(),
            ResolverError::ProofUnavailable,
        );
        assert!(values.is_empty().unwrap());
    }

    #[test]
    fn memory_resource_value_provider_rejects_mismatched_hash() {
        let values = MemoryResourceValueProvider::new();

        assert_eq!(
            values
                .insert(VerifiedResourceValue::non_inclusion(
                    "welcome".to_owned(),
                    NameHash::from_name("other").unwrap(),
                ))
                .unwrap_err(),
            ResolverError::ProofNameMismatch,
        );
    }

    #[test]
    fn sqlite_resource_value_provider_persists_inserted_value() {
        let path = temp_db_path("resource-value");
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let mut value = vec![0, 1];
        encode_name(&mut value, "ns1.welcome");

        {
            let values = SqliteResourceValueProvider::open(&path).unwrap();
            values
                .insert(VerifiedResourceValue::inclusion(
                    root_name.clone(),
                    name_hash,
                    value.clone(),
                ))
                .unwrap();
            assert_eq!(values.len().unwrap(), 1);
            values.flush().unwrap();
        }

        {
            let values = SqliteResourceValueProvider::open(&path).unwrap();
            let verified = values.prove_resource_value(&root_name, name_hash).unwrap();
            assert_eq!(verified.value, Some(value.clone()));

            let resolver = ProofBackedResolver::new(ResourceValueProofProvider::new(values));
            let answer = resolver
                .resolve(&ResolutionRequest {
                    qname: root_name,
                    qtype: RecordType::Ns.code(),
                })
                .unwrap();

            assert_eq!(answer.records.len(), 1);
            assert_eq!(answer.records[0].rdata, name_bytes("ns1.welcome"));
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn sqlite_resource_value_provider_persists_non_inclusion() {
        let path = temp_db_path("resource-non-inclusion");
        let root_name = "welcome".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();

        {
            let values = SqliteResourceValueProvider::open(&path).unwrap();
            values
                .insert(VerifiedResourceValue::non_inclusion(
                    root_name.clone(),
                    name_hash,
                ))
                .unwrap();
            values.flush().unwrap();
        }

        {
            let values = SqliteResourceValueProvider::open(&path).unwrap();
            let verified = values.prove_resource_value(&root_name, name_hash).unwrap();
            assert_eq!(verified.value, None);
            assert!(verified.secure);
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn sqlite_resource_value_provider_reports_bytes_and_evicts_oldest_values() {
        let values = SqliteResourceValueProvider::in_memory().unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();

        values
            .insert(VerifiedResourceValue::inclusion(
                "alpha".to_owned(),
                alpha_hash,
                vec![1, 2, 3, 4, 5, 6],
            ))
            .unwrap();
        values
            .insert(VerifiedResourceValue::inclusion(
                "beta".to_owned(),
                beta_hash,
                vec![7, 8],
            ))
            .unwrap();

        assert_eq!(
            values.stats().unwrap(),
            ResourceValueCacheStats {
                entries: 2,
                value_bytes: 8,
            },
        );
        assert_eq!(values.enforce_value_byte_limit(2).unwrap(), 1);

        assert_eq!(
            values.stats().unwrap(),
            ResourceValueCacheStats {
                entries: 1,
                value_bytes: 2,
            },
        );
        assert_eq!(
            values
                .prove_resource_value("alpha", alpha_hash)
                .unwrap_err(),
            ResolverError::ProofUnavailable,
        );
        assert_eq!(
            values
                .prove_resource_value("beta", beta_hash)
                .unwrap()
                .value,
            Some(vec![7, 8]),
        );

        values.clear().unwrap();
        assert_eq!(
            values.stats().unwrap(),
            ResourceValueCacheStats {
                entries: 0,
                value_bytes: 0,
            },
        );
    }

    #[test]
    fn sqlite_resource_value_provider_persists_and_prunes_anchors() {
        let values = SqliteResourceValueProvider::in_memory().unwrap();
        let alpha_hash = NameHash::from_name("alpha").unwrap();
        let beta_hash = NameHash::from_name("beta").unwrap();
        let gamma_hash = NameHash::from_name("gamma").unwrap();
        let valid_anchor = ResourceValueAnchor {
            tree_root: Hash::new([1; 32]),
            height: Height(3),
        };
        let invalid_anchor = ResourceValueAnchor {
            tree_root: Hash::new([2; 32]),
            height: Height(3),
        };

        values
            .insert(
                VerifiedResourceValue::inclusion("alpha".to_owned(), alpha_hash, vec![1])
                    .with_anchor(valid_anchor.tree_root, valid_anchor.height),
            )
            .unwrap();
        values
            .insert(
                VerifiedResourceValue::inclusion("beta".to_owned(), beta_hash, vec![2])
                    .with_anchor(invalid_anchor.tree_root, invalid_anchor.height),
            )
            .unwrap();
        values
            .insert(VerifiedResourceValue::inclusion(
                "gamma".to_owned(),
                gamma_hash,
                vec![3],
            ))
            .unwrap();

        assert_eq!(values.anchored_heights().unwrap(), vec![Height(3)]);
        assert_eq!(
            values.prune_invalid_anchors(&[valid_anchor], true).unwrap(),
            2
        );
        assert_eq!(
            values
                .prove_resource_value("alpha", alpha_hash)
                .unwrap()
                .anchor,
            Some(valid_anchor),
        );
        assert_eq!(
            values.prove_resource_value("beta", beta_hash).unwrap_err(),
            ResolverError::ProofUnavailable,
        );
        assert_eq!(
            values
                .prove_resource_value("gamma", gamma_hash)
                .unwrap_err(),
            ResolverError::ProofUnavailable,
        );
    }

    #[test]
    fn sqlite_resource_value_provider_migrates_previous_anchor_columns() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE verified_resource_values (
                    root_name TEXT NOT NULL,
                    name_hash BLOB NOT NULL,
                    value BLOB,
                    secure INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    PRIMARY KEY(root_name, name_hash)
                );
                ",
            )
            .unwrap();
        let values = SqliteResourceValueProvider::from_connection(connection).unwrap();
        let root_name = "alpha".to_owned();
        let name_hash = NameHash::from_name(&root_name).unwrap();
        let anchor = ResourceValueAnchor {
            tree_root: Hash::new([3; 32]),
            height: Height(11),
        };

        values
            .insert(
                VerifiedResourceValue::inclusion(root_name.clone(), name_hash, vec![1, 2])
                    .with_anchor(anchor.tree_root, anchor.height),
            )
            .unwrap();

        let stored = values.prove_resource_value(&root_name, name_hash).unwrap();
        assert_eq!(stored.anchor, Some(anchor));
    }

    fn record(name: DnsName, record_type: RecordType, rdata: Vec<u8>) -> ResourceRecord {
        ResourceRecord {
            name,
            record_type,
            class: 1,
            ttl: 300,
            rdata,
        }
    }

    fn ns_record(owner: &str, target: &str) -> ResourceRecord {
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::Ns,
            name_bytes(target),
        )
    }

    fn ds_record(owner: &str) -> ResourceRecord {
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::Ds,
            vec![0, 1, 8, 2, 0xaa],
        )
    }

    fn glue4_record(owner: &str, address: [u8; 4]) -> ResourceRecord {
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::A,
            address.to_vec(),
        )
    }

    fn txt_record(owner: &str, text: &str) -> ResourceRecord {
        assert!(text.len() <= u8::MAX as usize);
        let mut rdata = Vec::new();
        rdata.push(text.len() as u8);
        rdata.extend(text.as_bytes());
        record(DnsName::from_ascii(owner).unwrap(), RecordType::Txt, rdata)
    }

    fn svcb_doh_record(owner: &str, target: &str, dohpath: &str) -> ResourceRecord {
        let mut rdata = Vec::new();
        rdata.extend(1u16.to_be_bytes());
        encode_name(&mut rdata, target);
        rdata.extend(SVCB_PARAM_ALPN.to_be_bytes());
        rdata.extend(3u16.to_be_bytes());
        rdata.extend([2, b'h', b'2']);
        rdata.extend(SVCB_PARAM_DOHPATH.to_be_bytes());
        rdata.extend((dohpath.len() as u16).to_be_bytes());
        rdata.extend(dohpath.as_bytes());
        record(DnsName::from_ascii(owner).unwrap(), RecordType::Svcb, rdata)
    }

    fn rrsig_record(owner: &str) -> ResourceRecord {
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::Rrsig,
            vec![0, 1, 8, 1],
        )
    }

    fn rrsig_record_for_signer(
        owner: &str,
        type_covered: RecordType,
        signer: &str,
    ) -> ResourceRecord {
        let mut rdata = Vec::new();
        rdata.extend(type_covered.code().to_be_bytes());
        rdata.push(8);
        rdata.push(DnsName::from_ascii(owner).unwrap().labels().len() as u8);
        rdata.extend(300u32.to_be_bytes());
        rdata.extend(2_000_000_000u32.to_be_bytes());
        rdata.extend(1u32.to_be_bytes());
        rdata.extend(0x1234u16.to_be_bytes());
        DnsName::from_ascii(signer)
            .unwrap()
            .encode_wire(&mut rdata)
            .unwrap();
        rdata.push(0xaa);
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::Rrsig,
            rdata,
        )
    }

    fn cname_record(owner: &str, target: &str) -> ResourceRecord {
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::Cname,
            name_bytes(target),
        )
    }

    fn nsec_record(owner: &str) -> ResourceRecord {
        record(
            DnsName::from_ascii(owner).unwrap(),
            RecordType::Nsec,
            name_bytes(owner),
        )
    }

    fn delegation_with_records(records: Vec<ResourceRecord>) -> HnsDelegation {
        HnsDelegation {
            root_name: "welcome".to_owned(),
            owner: DnsName::from_ascii("welcome").unwrap(),
            records,
        }
    }

    fn dns_responses(responses: Vec<(&str, RecordType, Vec<ResourceRecord>)>) -> DnsResponseMap {
        responses
            .into_iter()
            .map(|(name, record_type, records)| {
                (
                    (name.to_owned(), record_type.code()),
                    DnsResponseFixture {
                        rcode: DNS_RCODE_NOERROR,
                        answers: records,
                        authorities: Vec::new(),
                        additionals: Vec::new(),
                    },
                )
            })
            .collect()
    }

    fn tcp_repair_fixture(question: &DnsQuestion, valid_dnskey: bool) -> DnsResponseFixture {
        let records = match question.record_type {
            RecordType::A => vec![
                record(question.name.clone(), RecordType::A, vec![1, 1, 1, 1]),
                rrsig_record(&question.name.to_string()),
            ],
            RecordType::Dnskey if valid_dnskey => vec![
                record(question.name.clone(), RecordType::Dnskey, vec![1, 2, 3, 4]),
                rrsig_record(&question.name.to_string()),
            ],
            _ => Vec::new(),
        };
        DnsResponseFixture {
            rcode: DNS_RCODE_NOERROR,
            answers: records,
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    fn dns_response(query: &DnsMessage, fixture: DnsResponseFixture, truncated: bool) -> Vec<u8> {
        let flags = (if truncated { 0x8600 } else { 0x8400 }) | fixture.rcode as u16;
        DnsMessage {
            header: DnsHeader {
                id: query.header.id,
                flags: DnsFlags::new(flags),
                question_count: 1,
                answer_count: fixture.answers.len() as u16,
                authority_count: fixture.authorities.len() as u16,
                additional_count: fixture.additionals.len() as u16,
            },
            questions: query.questions.clone(),
            answers: fixture.answers,
            authorities: fixture.authorities,
            additionals: fixture.additionals,
        }
        .encode(&DnsEncodeConfig {
            max_message_len: DEFAULT_DNS_TCP_MAX_MESSAGE_LEN,
        })
        .unwrap()
    }

    fn resolver_response(
        qname: &str,
        qtype: u16,
        secure: bool,
        records: Vec<ResourceRecord>,
    ) -> (ResolutionRequest, ResolutionAnswer) {
        (
            ResolutionRequest {
                qname: qname.to_owned(),
                qtype,
            },
            ResolutionAnswer {
                name: DnsName::from_ascii(qname).unwrap(),
                records,
                secure,
            },
        )
    }

    fn encode_name(out: &mut Vec<u8>, name: &str) {
        DnsName::from_ascii(name).unwrap().encode_wire(out).unwrap();
    }

    fn name_bytes(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        encode_name(&mut out, name);
        out
    }

    fn temp_db_path(label: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hns-resolver-{label}-{}-{now}.sqlite",
            std::process::id()
        ))
    }

    fn cleanup_db_path(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
