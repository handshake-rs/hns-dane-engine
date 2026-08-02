//! Authenticated exact-origin loopback proxy admission.
//!
//! This crate owns the platform-neutral boundary in front of a native browser
//! proxy. It admits only strict loopback `CONNECT` requests carrying one
//! per-instance Basic capability, then requires an atomically published,
//! current-generation [`hns_dane_engine::ProviderAuthorityContext`] before an
//! exact-origin tunnel grant can be issued. Socket accept loops, DNS wire I/O,
//! origin dialing, local CA storage, and TLS I/O remain native-host adapter
//! responsibilities.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "HNS, HTTP, TLS, and SNI are protocol names"
)]

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

use hns_dane_engine::{
    AuthenticatedContextStatus, AuthorityState, Engine, EngineError, EngineSnapshot, HnsNetwork,
    LogicalOrigin, Namespace, OriginScheme, ProviderAuthorityContext, TlsTrustPolicy,
};
use subtle::ConstantTimeEq;
use thiserror::Error;

static NEXT_PROXY_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

const PROXY_USERNAME: &str = "hns-browser";
const CAPABILITY_BYTES: usize = 32;
const REALM_NONCE_BYTES: usize = 16;
/// HTTP proxy authorization header.
pub const PROXY_AUTHORIZATION_HEADER: &str = "proxy-authorization";
/// HTTP proxy authentication challenge header.
pub const PROXY_AUTHENTICATE_HEADER: &str = "Proxy-Authenticate";
/// Default maximum CONNECT head bytes.
pub const DEFAULT_MAXIMUM_HEAD_BYTES: usize = 16_384;
/// Default maximum header fields.
pub const DEFAULT_MAXIMUM_HEADERS: usize = 64;
/// Default maximum simultaneous pending CONNECT admissions.
pub const DEFAULT_MAXIMUM_PENDING: usize = 64;
/// Default lifetime of one pending CONNECT admission, in seconds.
pub const DEFAULT_MAXIMUM_PENDING_LIFETIME_SECONDS: u64 = 15;
/// Hard maximum lifetime of one pending CONNECT admission, in seconds.
pub const MAXIMUM_PENDING_LIFETIME_SECONDS: u64 = 60;
/// Default maximum simultaneously published provider authorities.
pub const DEFAULT_MAXIMUM_PUBLICATIONS: usize = 64;
/// Default maximum lifetime of one in-memory publication, in seconds.
pub const DEFAULT_MAXIMUM_PUBLICATION_LIFETIME_SECONDS: u64 = 300;
/// Default maximum lifetime of one issued tunnel grant, in seconds.
pub const DEFAULT_MAXIMUM_GRANT_LIFETIME_SECONDS: u64 = 30;
/// Hard maximum lifetime of one issued tunnel grant, in seconds.
pub const MAXIMUM_GRANT_LIFETIME_SECONDS: u64 = 60;

/// Per-instance loopback proxy capability.
pub struct ProxyAuthorization {
    realm: String,
    expected_token: Vec<u8>,
}

impl ProxyAuthorization {
    /// Derive fixed-size Basic credentials from platform-generated random
    /// nonce and capability bytes.
    #[must_use]
    pub fn from_capability(
        realm_nonce: [u8; REALM_NONCE_BYTES],
        mut capability: [u8; CAPABILITY_BYTES],
    ) -> Self {
        let mut credentials = Vec::with_capacity(PROXY_USERNAME.len() + 1 + CAPABILITY_BYTES * 2);
        credentials.extend_from_slice(PROXY_USERNAME.as_bytes());
        credentials.push(b':');
        append_hex(&mut credentials, &capability);
        let expected_token = encode_base64(&credentials).into_bytes();
        credentials.fill(0);
        capability.fill(0);
        Self {
            realm: format!("hns-loopback-{}", encode_hex(&realm_nonce)),
            expected_token,
        }
    }

    /// Authentication realm; safe to expose in a 407 challenge.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Complete Basic authorization header value for the browser callback.
    #[must_use]
    pub fn authorization_header_value(&self) -> String {
        let token = std::str::from_utf8(&self.expected_token).unwrap_or_default();
        format!("Basic {token}")
    }

    /// Complete challenge header value.
    #[must_use]
    pub fn challenge_header_value(&self) -> String {
        format!("Basic realm=\"{}\"", self.realm)
    }

    /// Verify exactly one Basic header using a fixed-width constant-time
    /// capability comparison.
    #[must_use]
    pub fn verify_header_values<'a>(&self, values: impl IntoIterator<Item = &'a str>) -> bool {
        let mut values = values.into_iter();
        let Some(value) = values.next() else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        let Some(token) = basic_token(value) else {
            return false;
        };
        if token.len() != self.expected_token.len() {
            return false;
        }
        token.as_bytes().ct_eq(&self.expected_token).unwrap_u8() == 1
    }

    /// Match a browser authentication challenge only to the exact configured
    /// numeric loopback endpoint and realm.
    #[must_use]
    pub fn matches_challenge(
        &self,
        endpoint: LoopbackEndpoint,
        host: &str,
        port: u16,
        realm: &str,
    ) -> bool {
        let candidate = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        candidate == endpoint.address().ip().to_string()
            && port == endpoint.address().port()
            && realm == self.realm
    }
}

impl Drop for ProxyAuthorization {
    fn drop(&mut self) {
        self.expected_token.fill(0);
    }
}

impl fmt::Debug for ProxyAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyAuthorization")
            .field("realm", &"[redacted]")
            .field("expected_token", &"[redacted]")
            .finish()
    }
}

/// Numeric loopback endpoint; hostnames and wildcard binds are impossible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoopbackEndpoint(SocketAddr);

impl LoopbackEndpoint {
    /// Validate a nonzero numeric loopback bind.
    pub fn new(address: SocketAddr) -> Result<Self, ProxyError> {
        if !address.ip().is_loopback() {
            return Err(ProxyError::NonLoopbackEndpoint);
        }
        if address.port() == 0 {
            return Err(ProxyError::ZeroProxyPort);
        }
        Ok(Self(address))
    }

    /// Exact bind address.
    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.0
    }
}

/// Native-process and listener lifecycle identity for replay isolation.
///
/// The native host must generate a fresh unpredictable process session on
/// every process start and advance both generations for their corresponding
/// lifecycle replacement. This value is configuration identity, not provider
/// authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProxyInstanceIdentity {
    process_session: [u8; 16],
    process_generation: u64,
    listener_generation: u64,
}

impl ProxyInstanceIdentity {
    /// Validate nonzero process and listener lifecycle stamps.
    pub fn new(
        process_session: [u8; 16],
        process_generation: u64,
        listener_generation: u64,
    ) -> Result<Self, ProxyError> {
        if process_session == [0; 16] {
            return Err(ProxyError::ZeroProcessSession);
        }
        if process_generation == 0 {
            return Err(ProxyError::ZeroProcessGeneration);
        }
        if listener_generation == 0 {
            return Err(ProxyError::ZeroListenerGeneration);
        }
        Ok(Self {
            process_session,
            process_generation,
            listener_generation,
        })
    }

    /// Fresh native-process session stamp.
    #[must_use]
    pub const fn process_session(self) -> [u8; 16] {
        self.process_session
    }

    /// Native-process lifecycle generation.
    #[must_use]
    pub const fn process_generation(self) -> u64 {
        self.process_generation
    }

    /// Exact listener lifecycle generation.
    #[must_use]
    pub const fn listener_generation(self) -> u64 {
        self.listener_generation
    }
}

impl fmt::Debug for ProxyInstanceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyInstanceIdentity")
            .field("process_session", &"[redacted]")
            .field("process_generation", &self.process_generation)
            .field("listener_generation", &self.listener_generation)
            .finish()
    }
}

/// Strict lowercase ASCII DNS host.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedHost(String);

impl NormalizedHost {
    /// Normalize browser-emitted ASCII/punycode DNS text.
    pub fn parse(input: &str) -> Result<Self, ProxyError> {
        if input.is_empty()
            || input.trim() != input
            || input.chars().any(|character| {
                character.is_control()
                    || character.is_whitespace()
                    || matches!(
                        character,
                        '/' | ':' | '?' | '#' | '@' | '[' | ']' | '\\' | '<' | '>' | '"'
                    )
            })
        {
            return Err(ProxyError::InvalidHost);
        }
        let without_dot = input.strip_suffix('.').unwrap_or(input);
        if without_dot.is_empty() || without_dot.ends_with('.') {
            return Err(ProxyError::InvalidHost);
        }
        let normalized = without_dot.to_ascii_lowercase();
        if normalized.len() > 253
            || !normalized.is_ascii()
            || normalized.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            || normalized.parse::<IpAddr>().is_ok()
            || looks_like_legacy_ipv4(&normalized)
        {
            return Err(ProxyError::InvalidHost);
        }
        Ok(Self(normalized))
    }

    /// Canonical ASCII host.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NormalizedHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NormalizedHost([redacted])")
    }
}

/// Immutable HNS TLD scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostScope {
    root: NormalizedHost,
}

impl HostScope {
    /// Construct from a proof-verified single-label HNS TLD.
    pub fn from_verified_hns_tld(root: &str) -> Result<Self, ProxyError> {
        let root = NormalizedHost::parse(root)?;
        if root.as_str().contains('.') {
            return Err(ProxyError::ScopeMustBeHnsTld);
        }
        Ok(Self { root })
    }

    /// Verify equality or a label-boundary subdomain.
    pub fn authorize(&self, candidate: &str) -> Result<NormalizedHost, ProxyError> {
        let candidate = NormalizedHost::parse(candidate)?;
        if candidate == self.root {
            return Ok(candidate);
        }
        let prefix = candidate
            .as_str()
            .strip_suffix(self.root.as_str())
            .ok_or(ProxyError::HostOutsideScope)?;
        if !prefix.ends_with('.') {
            return Err(ProxyError::HostOutsideScope);
        }
        Ok(candidate)
    }

    /// Redacted canonical scope root for equality checks.
    #[must_use]
    pub const fn root(&self) -> &NormalizedHost {
        &self.root
    }
}

/// Deterministic proxy resource bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyLimits {
    /// Maximum complete CONNECT head.
    pub maximum_head_bytes: usize,
    /// Maximum HTTP fields.
    pub maximum_headers: usize,
    /// Maximum pending two-phase admissions.
    pub maximum_pending: usize,
    /// Maximum lifetime of one pending admission, in seconds.
    pub maximum_pending_lifetime_seconds: u64,
    /// Maximum simultaneously published provider authorities.
    pub maximum_publications: usize,
    /// Maximum lifetime of one publication, in seconds.
    pub maximum_publication_lifetime_seconds: u64,
    /// Maximum lifetime of one tunnel grant, in seconds.
    pub maximum_grant_lifetime_seconds: u64,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            maximum_head_bytes: DEFAULT_MAXIMUM_HEAD_BYTES,
            maximum_headers: DEFAULT_MAXIMUM_HEADERS,
            maximum_pending: DEFAULT_MAXIMUM_PENDING,
            maximum_pending_lifetime_seconds: DEFAULT_MAXIMUM_PENDING_LIFETIME_SECONDS,
            maximum_publications: DEFAULT_MAXIMUM_PUBLICATIONS,
            maximum_publication_lifetime_seconds:
                DEFAULT_MAXIMUM_PUBLICATION_LIFETIME_SECONDS,
            maximum_grant_lifetime_seconds: DEFAULT_MAXIMUM_GRANT_LIFETIME_SECONDS,
        }
    }
}

impl ProxyLimits {
    fn validate(self) -> Result<Self, ProxyError> {
        if self.maximum_head_bytes < 256
            || self.maximum_head_bytes > 65_536
            || self.maximum_headers == 0
            || self.maximum_headers > 256
            || self.maximum_pending == 0
            || self.maximum_pending > 1_024
            || self.maximum_pending_lifetime_seconds == 0
            || self.maximum_pending_lifetime_seconds > MAXIMUM_PENDING_LIFETIME_SECONDS
            || self.maximum_publications == 0
            || self.maximum_publications > 1_024
            || self.maximum_publication_lifetime_seconds == 0
            || self.maximum_publication_lifetime_seconds > 3_600
            || self.maximum_grant_lifetime_seconds == 0
            || self.maximum_grant_lifetime_seconds
                > self.maximum_publication_lifetime_seconds
            || self.maximum_grant_lifetime_seconds > MAXIMUM_GRANT_LIFETIME_SECONDS
        {
            return Err(ProxyError::InvalidLimits);
        }
        Ok(self)
    }
}

/// One proxy instance configuration.
pub struct ProxyConfig {
    endpoint: LoopbackEndpoint,
    instance_identity: ProxyInstanceIdentity,
    runtime_session: [u8; 16],
    runtime_generation: u64,
    scope: HostScope,
    authorization: ProxyAuthorization,
    limits: ProxyLimits,
}

impl ProxyConfig {
    /// Bind a fresh process/listener identity and proxy capability to one
    /// runtime generation, HNS TLD, and bounded lifetime configuration.
    pub fn new(
        endpoint: LoopbackEndpoint,
        instance_identity: ProxyInstanceIdentity,
        runtime_session: [u8; 16],
        runtime_generation: u64,
        scope: HostScope,
        authorization: ProxyAuthorization,
        limits: ProxyLimits,
    ) -> Result<Self, ProxyError> {
        if runtime_session == [0; 16] {
            return Err(ProxyError::ZeroRuntimeSession);
        }
        if runtime_generation == 0 {
            return Err(ProxyError::ZeroRuntimeGeneration);
        }
        Ok(Self {
            endpoint,
            instance_identity,
            runtime_session,
            runtime_generation,
            scope,
            authorization,
            limits: limits.validate()?,
        })
    }

    /// Exact numeric loopback endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> LoopbackEndpoint {
        self.endpoint
    }

    /// Browser callback authorization header.
    #[must_use]
    pub fn authorization_header_value(&self) -> String {
        self.authorization.authorization_header_value()
    }

    /// Browser challenge realm.
    #[must_use]
    pub fn realm(&self) -> &str {
        self.authorization.realm()
    }
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyConfig")
            .field("endpoint", &self.endpoint)
            .field("instance_identity", &self.instance_identity)
            .field("runtime_session", &"[redacted]")
            .field("runtime_generation", &self.runtime_generation)
            .field("scope", &"[redacted]")
            .field("authorization", &"[redacted]")
            .field("limits", &self.limits)
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PendingRecord {
    host: NormalizedHost,
    port: u16,
    admitted_at: u64,
    expires_at: u64,
}

/// Opaque authenticated CONNECT awaiting exact provider-authority admission.
#[derive(Eq, PartialEq)]
pub struct PendingConnect {
    instance_id: u64,
    sequence: u64,
    host: NormalizedHost,
    port: u16,
    admitted_at: u64,
    expires_at: u64,
}

impl PendingConnect {
    /// Exact normalized target host.
    #[must_use]
    pub fn host(&self) -> &str {
        self.host.as_str()
    }

    /// Exact target port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Trusted admission time.
    #[must_use]
    pub const fn admitted_at(&self) -> u64 {
        self.admitted_at
    }

    /// Exclusive pending-admission expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl fmt::Debug for PendingConnect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingConnect")
            .field("instance_id", &self.instance_id)
            .field("sequence", &self.sequence)
            .field("host", &"[redacted]")
            .field("port", &self.port)
            .field("admitted_at", &self.admitted_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

struct PublicationRecord {
    publication_id: u64,
    publication_generation: u64,
    selected_namespace: Namespace,
    authenticated_context: AuthenticatedContextStatus,
    hns_network: HnsNetwork,
    service_port: u16,
    tls_policy: TlsTrustPolicy,
    runtime_session: [u8; 16],
    runtime_generation: u64,
    policy_generation: u64,
    event_sequence: u64,
    decision_fingerprint: [u8; 32],
    authority_valid_from: u64,
    authority_valid_until: u64,
    published_at: u64,
    publication_valid_until: u64,
    endpoint: LoopbackEndpoint,
    process_session: [u8; 16],
    process_generation: u64,
    listener_generation: u64,
    authority: ProviderAuthorityContext,
}

/// Opaque handle to one atomically published provider authority.
///
/// This type is deliberately neither cloneable nor serializable. It can only
/// be returned by [`ProxySession::publish_authority`] or
/// [`ProxySession::replace_authority`], both of which consume an engine-issued
/// [`ProviderAuthorityContext`].
#[derive(Eq, PartialEq)]
pub struct PublishedAdmission {
    instance_id: u64,
    logical_origin: LogicalOrigin,
    publication_id: u64,
    publication_generation: u64,
    registry_generation: u64,
    endpoint: LoopbackEndpoint,
    process_session: [u8; 16],
    process_generation: u64,
    listener_generation: u64,
}

impl PublishedAdmission {
    /// Exact normalized logical-origin host.
    #[must_use]
    pub fn host(&self) -> &str {
        self.logical_origin.host()
    }

    /// Exact logical-origin port.
    #[must_use]
    pub const fn origin_port(&self) -> u16 {
        self.logical_origin.port()
    }

    /// Registry generation committed by this publication operation.
    #[must_use]
    pub const fn registry_generation(&self) -> u64 {
        self.registry_generation
    }

    /// Generation of this exact origin publication.
    #[must_use]
    pub const fn publication_generation(&self) -> u64 {
        self.publication_generation
    }
}

impl fmt::Debug for PublishedAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedAdmission")
            .field("instance_id", &self.instance_id)
            .field("logical_origin", &"[redacted]")
            .field("publication_id", &self.publication_id)
            .field("publication_generation", &self.publication_generation)
            .field("registry_generation", &self.registry_generation)
            .field("endpoint", &self.endpoint)
            .field("process_session", &"[redacted]")
            .field("process_generation", &self.process_generation)
            .field("listener_generation", &self.listener_generation)
            .finish()
    }
}

/// Short-lived, single-CONNECT exact-origin permission.
///
/// This grant is deliberately opaque, non-cloneable, and non-serializable. A
/// native host must move it into one tunnel attempt and re-check lifecycle
/// cancellation before I/O. It is not a DNS, TLS, certificate, or wallet
/// permission verdict.
#[derive(Eq, PartialEq)]
pub struct TunnelGrant {
    instance_id: u64,
    logical_origin: LogicalOrigin,
    selected_namespace: Namespace,
    authenticated_context: AuthenticatedContextStatus,
    hns_network: HnsNetwork,
    service_port: u16,
    tls_policy: TlsTrustPolicy,
    runtime_session: [u8; 16],
    runtime_generation: u64,
    policy_generation: u64,
    event_sequence: u64,
    decision_fingerprint: [u8; 32],
    authority_valid_from: u64,
    authority_valid_until: u64,
    endpoint: LoopbackEndpoint,
    process_session: [u8; 16],
    process_generation: u64,
    listener_generation: u64,
    registry_generation: u64,
    publication_id: u64,
    publication_generation: u64,
    connect_sequence: u64,
    issued_at: u64,
    expires_at: u64,
}

impl TunnelGrant {
    /// Exact normalized leaf/tunnel host.
    #[must_use]
    pub fn host(&self) -> &str {
        self.logical_origin.host()
    }

    /// Exact logical-origin port requested by CONNECT.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.logical_origin.port()
    }

    /// Exact logical-origin URL scheme.
    #[must_use]
    pub const fn scheme(&self) -> OriginScheme {
        self.logical_origin.scheme()
    }

    /// Exact selected namespace.
    #[must_use]
    pub const fn selected_namespace(&self) -> Namespace {
        self.selected_namespace
    }

    /// Exact trusted authentication path.
    #[must_use]
    pub const fn authenticated_context(&self) -> AuthenticatedContextStatus {
        self.authenticated_context
    }

    /// Exact Handshake network retained by the namespace decision.
    #[must_use]
    pub const fn hns_network(&self) -> HnsNetwork {
        self.hns_network
    }

    /// Exact selected TCP service port for native origin dialing.
    #[must_use]
    pub const fn service_port(&self) -> u16 {
        self.service_port
    }

    /// Exact selected TLS trust policy.
    #[must_use]
    pub const fn tls_policy(&self) -> TlsTrustPolicy {
        self.tls_policy
    }

    /// Current runtime generation.
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    /// Runtime session that admitted the grant.
    #[must_use]
    pub const fn runtime_session(&self) -> [u8; 16] {
        self.runtime_session
    }

    /// Exact engine event that authorized the grant.
    #[must_use]
    pub const fn authorization_event(&self) -> u64 {
        self.event_sequence
    }

    /// Exact policy generation that authorized publication.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Complete query, plan, root outcome, evidence, and policy identity.
    #[must_use]
    pub const fn decision_fingerprint(&self) -> [u8; 32] {
        self.decision_fingerprint
    }

    /// Original provider-authority validity beginning.
    #[must_use]
    pub const fn authority_valid_from(&self) -> u64 {
        self.authority_valid_from
    }

    /// Original exclusive provider-authority expiry.
    #[must_use]
    pub const fn authority_valid_until(&self) -> u64 {
        self.authority_valid_until
    }

    /// Exact numeric loopback listener endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> LoopbackEndpoint {
        self.endpoint
    }

    /// Fresh native-process session stamp.
    #[must_use]
    pub const fn process_session(&self) -> [u8; 16] {
        self.process_session
    }

    /// Native-process lifecycle generation.
    #[must_use]
    pub const fn process_generation(&self) -> u64 {
        self.process_generation
    }

    /// Listener lifecycle generation.
    #[must_use]
    pub const fn listener_generation(&self) -> u64 {
        self.listener_generation
    }

    /// Registry generation revalidated for this grant.
    #[must_use]
    pub const fn registry_generation(&self) -> u64 {
        self.registry_generation
    }

    /// Exact origin-publication generation revalidated for this grant.
    #[must_use]
    pub const fn publication_generation(&self) -> u64 {
        self.publication_generation
    }

    /// Grant issue time and inclusive start of its short validity window.
    #[must_use]
    pub const fn valid_from(&self) -> u64 {
        self.issued_at
    }

    /// Exclusive short grant expiry.
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.expires_at
    }
}

impl fmt::Debug for TunnelGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelGrant")
            .field("instance_id", &self.instance_id)
            .field("logical_origin", &"[redacted]")
            .field("selected_namespace", &self.selected_namespace)
            .field("authenticated_context", &self.authenticated_context)
            .field("hns_network", &self.hns_network)
            .field("service_port", &self.service_port)
            .field("tls_policy", &self.tls_policy)
            .field("runtime_session", &"[redacted]")
            .field("runtime_generation", &self.runtime_generation)
            .field("policy_generation", &self.policy_generation)
            .field("event_sequence", &self.event_sequence)
            .field("decision_fingerprint", &"[redacted]")
            .field("authority_valid_from", &self.authority_valid_from)
            .field("authority_valid_until", &self.authority_valid_until)
            .field("endpoint", &self.endpoint)
            .field("process_session", &"[redacted]")
            .field("process_generation", &self.process_generation)
            .field("listener_generation", &self.listener_generation)
            .field("registry_generation", &self.registry_generation)
            .field("publication_id", &self.publication_id)
            .field("publication_generation", &self.publication_generation)
            .field("connect_sequence", &self.connect_sequence)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Platform-neutral authenticated proxy admission state.
pub struct ProxySession {
    instance_id: u64,
    config: ProxyConfig,
    last_observed_time: Option<u64>,
    sequence: u64,
    pending: HashMap<u64, PendingRecord>,
    registry_generation: u64,
    publication_sequence: u64,
    publications: HashMap<LogicalOrigin, PublicationRecord>,
}

impl fmt::Debug for ProxySession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxySession")
            .field("instance_id", &self.instance_id)
            .field("config", &self.config)
            .field("last_observed_time", &self.last_observed_time)
            .field("request_sequence", &self.sequence)
            .field("pending_count", &self.pending.len())
            .field("registry_generation", &self.registry_generation)
            .field("publication_sequence", &self.publication_sequence)
            .field("publication_count", &self.publications.len())
            .finish()
    }
}

impl ProxySession {
    /// Open one non-cloneable proxy session.
    pub fn new(config: ProxyConfig) -> Result<Self, ProxyError> {
        let instance_id = NEXT_PROXY_INSTANCE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ProxyError::InstanceSequenceExhausted)?;
        Ok(Self {
            instance_id,
            config,
            last_observed_time: None,
            sequence: 0,
            pending: HashMap::new(),
            registry_generation: 1,
            publication_sequence: 0,
            publications: HashMap::new(),
        })
    }

    /// Exact numeric loopback endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> LoopbackEndpoint {
        self.config.endpoint
    }

    /// Browser callback authorization value.
    #[must_use]
    pub fn authorization_header_value(&self) -> String {
        self.config.authorization_header_value()
    }

    /// Current in-memory publication-registry generation.
    #[must_use]
    pub const fn registry_generation(&self) -> u64 {
        self.registry_generation
    }

    /// Number of publication records currently resident in memory.
    #[must_use]
    pub fn publication_count(&self) -> usize {
        self.publications.len()
    }

    /// Bounded 407 response for missing/invalid proxy authentication.
    #[must_use]
    pub fn authentication_challenge(&self) -> Vec<u8> {
        format!(
            "HTTP/1.1 407 Proxy Authentication Required\r\n{}: {}\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            PROXY_AUTHENTICATE_HEADER,
            self.config.authorization.challenge_header_value()
        )
        .into_bytes()
    }

    /// Admit one strict authenticated loopback CONNECT before origin TLS.
    ///
    /// `now` must come from the native host's trusted nondecreasing clock.
    /// Rollback is rejected. Expired pending records are removed before the
    /// capacity check, and every returned handle carries its exact exclusive
    /// deadline.
    pub fn admit_connect(
        &mut self,
        engine: &Engine,
        client: SocketAddr,
        request_head: &[u8],
        now: u64,
    ) -> Result<PendingConnect, ProxyError> {
        let snapshot = engine.snapshot()?;
        self.ensure_runtime_ready(snapshot, false)?;
        self.observe_time(now)?;
        if !client.ip().is_loopback() {
            return Err(ProxyError::NonLoopbackClient);
        }
        self.pending.retain(|_, record| now < record.expires_at);
        if self.pending.len() >= self.config.limits.maximum_pending {
            return Err(ProxyError::PendingLimit);
        }
        let parsed = parse_connect_head(request_head, self.config.limits)?;
        let host = self.config.scope.authorize(parsed.host.as_str())?;
        if !self
            .config
            .authorization
            .verify_header_values(parsed.authorization.iter().filter_map(SecretHeader::as_str))
        {
            return Err(ProxyError::AuthenticationFailed);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ProxyError::RequestSequenceExhausted)?;
        let expires_at = now
            .checked_add(self.config.limits.maximum_pending_lifetime_seconds)
            .ok_or(ProxyError::TimeOverflow)?;
        let record = PendingRecord {
            host: host.clone(),
            port: parsed.port,
            admitted_at: now,
            expires_at,
        };
        self.pending.insert(sequence, record);
        self.sequence = sequence;
        Ok(PendingConnect {
            instance_id: self.instance_id,
            sequence,
            host,
            port: parsed.port,
            admitted_at: now,
            expires_at,
        })
    }

    /// Atomically publish one engine-issued provider authority.
    ///
    /// The context is consumed even when publication fails. Expired or
    /// engine-invalid records are reclaimed before uniqueness and capacity
    /// checks without advancing the generation because they can no longer
    /// authorize a tunnel. Current records are unchanged unless every
    /// authority, lifecycle, bound, time, uniqueness, capacity, and
    /// expected-generation check succeeds.
    pub fn publish_authority(
        &mut self,
        engine: &Engine,
        expected_registry_generation: u64,
        authority: ProviderAuthorityContext,
        now: u64,
    ) -> Result<PublishedAdmission, ProxyError> {
        self.ensure_registry_generation(expected_registry_generation)?;
        self.observe_time(now)?;
        let next_registry_generation = self.next_registry_generation()?;
        let publication_id = self
            .publication_sequence
            .checked_add(1)
            .ok_or(ProxyError::PublicationSequenceExhausted)?;
        let (logical_origin, record) = self.bind_authority(
            engine,
            authority,
            publication_id,
            next_registry_generation,
            now,
        )?;
        let mut reclaimable = Vec::new();
        let mut current_publications = 0_usize;
        let mut duplicate = false;
        for (origin, existing) in &self.publications {
            if self.publication_is_current(engine, existing, now)? {
                current_publications += 1;
                duplicate |= origin == &logical_origin;
            } else {
                reclaimable.push(origin.clone());
            }
        }
        for origin in reclaimable {
            self.publications.remove(&origin);
        }
        if duplicate {
            return Err(ProxyError::PublicationAlreadyExists);
        }
        if current_publications >= self.config.limits.maximum_publications {
            return Err(ProxyError::PublicationLimit);
        }
        let admission = self.admission_for(
            logical_origin.clone(),
            publication_id,
            next_registry_generation,
        );
        self.publications.insert(logical_origin, record);
        self.publication_sequence = publication_id;
        self.registry_generation = next_registry_generation;
        Ok(admission)
    }

    /// Atomically replace one exact-origin publication with fresh authority.
    ///
    /// The old handle and replacement context are consumed. Replacement cannot
    /// change the logical origin, publication identity, process, or listener.
    pub fn replace_authority(
        &mut self,
        engine: &Engine,
        expected_registry_generation: u64,
        admission: PublishedAdmission,
        authority: ProviderAuthorityContext,
        now: u64,
    ) -> Result<PublishedAdmission, ProxyError> {
        self.ensure_registry_generation(expected_registry_generation)?;
        self.observe_time(now)?;
        let publication_id = self.validate_admission(&admission)?.publication_id;
        let next_registry_generation = self.next_registry_generation()?;
        let (logical_origin, record) = self.bind_authority(
            engine,
            authority,
            publication_id,
            next_registry_generation,
            now,
        )?;
        if logical_origin != admission.logical_origin {
            return Err(ProxyError::PublicationMismatch);
        }
        let replacement = self.admission_for(
            logical_origin.clone(),
            publication_id,
            next_registry_generation,
        );
        self.publications.insert(logical_origin, record);
        self.registry_generation = next_registry_generation;
        Ok(replacement)
    }

    /// Atomically revoke one exact-origin publication.
    ///
    /// The handle is consumed and the generation advances only after the exact
    /// publication and expected registry generation match.
    pub fn revoke_authority(
        &mut self,
        expected_registry_generation: u64,
        admission: PublishedAdmission,
    ) -> Result<u64, ProxyError> {
        self.ensure_registry_generation(expected_registry_generation)?;
        self.validate_admission(&admission)?;
        let next_registry_generation = self.next_registry_generation()?;
        self.publications
            .remove(&admission.logical_origin)
            .ok_or(ProxyError::PublicationMismatch)?;
        self.registry_generation = next_registry_generation;
        Ok(next_registry_generation)
    }

    /// Convert one pending CONNECT into a short-lived exact-origin grant.
    ///
    /// The pending token is consumed before any publication or engine check can
    /// succeed or fail. The published admission remains usable for another
    /// separately authenticated CONNECT only while every generation remains
    /// current.
    pub fn authorize_connect(
        &mut self,
        engine: &Engine,
        pending: PendingConnect,
        admission: &PublishedAdmission,
        expected_registry_generation: u64,
        now: u64,
    ) -> Result<TunnelGrant, ProxyError> {
        let PendingConnect {
            instance_id,
            sequence,
            host,
            port,
            admitted_at,
            expires_at,
        } = pending;
        if instance_id != self.instance_id {
            return Err(ProxyError::PendingMismatch);
        }
        let record = self
            .pending
            .get(&sequence)
            .ok_or(ProxyError::PendingMismatch)?;
        if record.host != host
            || record.port != port
            || record.admitted_at != admitted_at
            || record.expires_at != expires_at
        {
            return Err(ProxyError::PendingMismatch);
        }
        let record = self
            .pending
            .remove(&sequence)
            .ok_or(ProxyError::PendingMismatch)?;
        self.observe_time(now)?;
        if now < record.admitted_at || now >= record.expires_at {
            return Err(ProxyError::PendingExpired);
        }
        self.ensure_registry_generation(expected_registry_generation)?;
        let snapshot = engine.snapshot()?;
        self.ensure_runtime_ready(snapshot, true)?;
        let publication = self.validate_admission(admission)?;
        if admission.logical_origin.scheme() != OriginScheme::Https
            || admission.logical_origin.host() != record.host.as_str()
            || admission.logical_origin.port() != record.port
            || !self.publication_is_current(engine, publication, now)?
        {
            return Err(ProxyError::ProviderAuthorityMismatch);
        }
        let grant_deadline = now
            .checked_add(self.config.limits.maximum_grant_lifetime_seconds)
            .ok_or(ProxyError::TimeOverflow)?;
        let grant_expires_at = publication.publication_valid_until.min(grant_deadline);
        if grant_expires_at <= now {
            return Err(ProxyError::ProviderAuthorityExpired);
        }
        Ok(TunnelGrant {
            instance_id: self.instance_id,
            logical_origin: admission.logical_origin.clone(),
            selected_namespace: publication.selected_namespace,
            authenticated_context: publication.authenticated_context,
            hns_network: publication.hns_network,
            service_port: publication.service_port,
            tls_policy: publication.tls_policy,
            runtime_session: publication.runtime_session,
            runtime_generation: publication.runtime_generation,
            policy_generation: publication.policy_generation,
            event_sequence: publication.event_sequence,
            decision_fingerprint: publication.decision_fingerprint,
            authority_valid_from: publication.authority_valid_from,
            authority_valid_until: publication.authority_valid_until,
            endpoint: publication.endpoint,
            process_session: publication.process_session,
            process_generation: publication.process_generation,
            listener_generation: publication.listener_generation,
            registry_generation: self.registry_generation,
            publication_id: publication.publication_id,
            publication_generation: publication.publication_generation,
            connect_sequence: sequence,
            issued_at: now,
            expires_at: grant_expires_at,
        })
    }

    /// Revalidate a grant immediately before native listener or origin I/O.
    ///
    /// This check is intentionally generation-wide: any publish, replace, or
    /// revoke invalidates an outstanding grant until the CONNECT is admitted
    /// again. It also rejects another process/listener instance, a replaced or
    /// revoked exact-origin publication, security-invalidating engine
    /// transition, and expiry. Ordinary later engine admissions do not revoke
    /// the retained opaque authority.
    pub fn revalidate_tunnel_grant(
        &mut self,
        engine: &Engine,
        grant: &TunnelGrant,
        expected_registry_generation: u64,
        now: u64,
    ) -> Result<(), ProxyError> {
        self.ensure_registry_generation(expected_registry_generation)?;
        self.observe_time(now)?;
        if grant.registry_generation != expected_registry_generation
            || grant.instance_id != self.instance_id
            || grant.endpoint != self.config.endpoint
        {
            return Err(ProxyError::PublicationMismatch);
        }
        let identity = self.config.instance_identity;
        if grant.process_session != identity.process_session()
            || grant.process_generation != identity.process_generation()
            || grant.listener_generation != identity.listener_generation()
        {
            return Err(ProxyError::PublicationMismatch);
        }
        if now < grant.issued_at || now >= grant.expires_at {
            return Err(ProxyError::ProviderAuthorityExpired);
        }
        let snapshot = engine.snapshot()?;
        self.ensure_runtime_ready(snapshot, true)?;
        let publication = self
            .publications
            .get(&grant.logical_origin)
            .ok_or(ProxyError::PublicationMismatch)?;
        if publication.publication_id != grant.publication_id
            || publication.publication_generation != grant.publication_generation
            || publication.selected_namespace != grant.selected_namespace
            || publication.authenticated_context != grant.authenticated_context
            || publication.hns_network != grant.hns_network
            || publication.service_port != grant.service_port
            || publication.tls_policy != grant.tls_policy
            || publication.runtime_session != grant.runtime_session
            || publication.runtime_generation != grant.runtime_generation
            || publication.policy_generation != grant.policy_generation
            || publication.event_sequence != grant.event_sequence
            || publication.decision_fingerprint != grant.decision_fingerprint
            || publication.authority_valid_from != grant.authority_valid_from
            || publication.authority_valid_until != grant.authority_valid_until
            || publication.endpoint != grant.endpoint
            || publication.process_session != grant.process_session
            || publication.process_generation != grant.process_generation
            || publication.listener_generation != grant.listener_generation
            || grant.expires_at > publication.publication_valid_until
            || !self.publication_is_current(engine, publication, now)?
        {
            return Err(ProxyError::ProviderAuthorityMismatch);
        }
        Ok(())
    }

    /// Cancel one exact pending request.
    pub fn cancel(&mut self, pending: &PendingConnect) -> Result<(), ProxyError> {
        if pending.instance_id != self.instance_id {
            return Err(ProxyError::PendingMismatch);
        }
        self.pending
            .remove(&pending.sequence)
            .map(|_| ())
            .ok_or(ProxyError::PendingMismatch)
    }

    fn bind_authority(
        &self,
        engine: &Engine,
        authority: ProviderAuthorityContext,
        publication_id: u64,
        publication_generation: u64,
        now: u64,
    ) -> Result<(LogicalOrigin, PublicationRecord), ProxyError> {
        let snapshot = engine.snapshot()?;
        self.ensure_runtime_ready(snapshot, true)?;
        let logical_origin = authority.logical_origin().clone();
        let host = self.config.scope.authorize(logical_origin.host())?;
        if logical_origin.scheme() != OriginScheme::Https
            || host.as_str() != logical_origin.host()
            || logical_origin.port() == 0
            || authority.service_port() == 0
            || authority.authenticated_context() == AuthenticatedContextStatus::Unauthenticated
            || authority.tls_policy() == TlsTrustPolicy::Cleartext
            || authority.runtime_session() != snapshot.runtime_session
            || authority.runtime_generation() != snapshot.runtime_generation
            || authority.policy_generation() != snapshot.policy.generation()
            || authority.hns_network() != snapshot.hns_network()
        {
            return Err(ProxyError::ProviderAuthorityMismatch);
        }
        if now < authority.valid_from() {
            return Err(ProxyError::ProviderAuthorityNotYetValid);
        }
        if now >= authority.valid_until() {
            return Err(ProxyError::ProviderAuthorityExpired);
        }
        if !engine.provider_authority_is_current(&authority, now)? {
            return Err(ProxyError::ProviderAuthorityMismatch);
        }
        let publication_deadline = now
            .checked_add(
                self.config
                    .limits
                    .maximum_publication_lifetime_seconds,
            )
            .ok_or(ProxyError::TimeOverflow)?;
        let publication_valid_until = authority.valid_until().min(publication_deadline);
        if publication_valid_until <= now {
            return Err(ProxyError::ProviderAuthorityExpired);
        }
        let identity = self.config.instance_identity;
        Ok((
            logical_origin,
            PublicationRecord {
                publication_id,
                publication_generation,
                selected_namespace: authority.selected_namespace(),
                authenticated_context: authority.authenticated_context(),
                hns_network: authority.hns_network(),
                service_port: authority.service_port(),
                tls_policy: authority.tls_policy(),
                runtime_session: authority.runtime_session(),
                runtime_generation: authority.runtime_generation(),
                policy_generation: authority.policy_generation(),
                event_sequence: authority.event_sequence(),
                decision_fingerprint: authority.decision_fingerprint(),
                authority_valid_from: authority.valid_from(),
                authority_valid_until: authority.valid_until(),
                published_at: now,
                publication_valid_until,
                endpoint: self.config.endpoint,
                process_session: identity.process_session(),
                process_generation: identity.process_generation(),
                listener_generation: identity.listener_generation(),
                authority,
            },
        ))
    }

    fn admission_for(
        &self,
        logical_origin: LogicalOrigin,
        publication_id: u64,
        publication_generation: u64,
    ) -> PublishedAdmission {
        let identity = self.config.instance_identity;
        PublishedAdmission {
            instance_id: self.instance_id,
            logical_origin,
            publication_id,
            publication_generation,
            registry_generation: publication_generation,
            endpoint: self.config.endpoint,
            process_session: identity.process_session(),
            process_generation: identity.process_generation(),
            listener_generation: identity.listener_generation(),
        }
    }

    fn validate_admission(
        &self,
        admission: &PublishedAdmission,
    ) -> Result<&PublicationRecord, ProxyError> {
        let identity = self.config.instance_identity;
        if admission.instance_id != self.instance_id
            || admission.endpoint != self.config.endpoint
            || admission.process_session != identity.process_session()
            || admission.process_generation != identity.process_generation()
            || admission.listener_generation != identity.listener_generation()
        {
            return Err(ProxyError::PublicationMismatch);
        }
        let record = self
            .publications
            .get(&admission.logical_origin)
            .ok_or(ProxyError::PublicationMismatch)?;
        if record.publication_id != admission.publication_id
            || record.publication_generation != admission.publication_generation
            || record.endpoint != admission.endpoint
            || record.process_session != admission.process_session
            || record.process_generation != admission.process_generation
            || record.listener_generation != admission.listener_generation
        {
            return Err(ProxyError::PublicationMismatch);
        }
        Ok(record)
    }

    fn publication_is_current(
        &self,
        engine: &Engine,
        publication: &PublicationRecord,
        now: u64,
    ) -> Result<bool, ProxyError> {
        let authority = &publication.authority;
        Ok(publication.selected_namespace == authority.selected_namespace()
            && publication.authenticated_context == authority.authenticated_context()
            && publication.hns_network == authority.hns_network()
            && publication.service_port == authority.service_port()
            && publication.tls_policy == authority.tls_policy()
            && publication.runtime_session == authority.runtime_session()
            && publication.runtime_generation == authority.runtime_generation()
            && publication.policy_generation == authority.policy_generation()
            && publication.event_sequence == authority.event_sequence()
            && publication.decision_fingerprint == authority.decision_fingerprint()
            && publication.authority_valid_from == authority.valid_from()
            && publication.authority_valid_until == authority.valid_until()
            && now >= publication.authority_valid_from
            && now < publication.authority_valid_until
            && now >= publication.published_at
            && now < publication.publication_valid_until
            && engine.provider_authority_is_current(authority, now)?)
    }

    fn ensure_registry_generation(&self, expected: u64) -> Result<(), ProxyError> {
        if expected != self.registry_generation {
            return Err(ProxyError::StaleRegistryGeneration);
        }
        Ok(())
    }

    fn observe_time(&mut self, now: u64) -> Result<(), ProxyError> {
        if self
            .last_observed_time
            .is_some_and(|last_observed| now < last_observed)
        {
            return Err(ProxyError::ClockRollback);
        }
        self.last_observed_time = Some(now);
        Ok(())
    }

    fn next_registry_generation(&self) -> Result<u64, ProxyError> {
        self.registry_generation
            .checked_add(1)
            .ok_or(ProxyError::RegistryGenerationExhausted)
    }

    fn ensure_runtime_ready(
        &self,
        snapshot: EngineSnapshot,
        bridge_required: bool,
    ) -> Result<(), ProxyError> {
        if snapshot.runtime_session != self.config.runtime_session
            || snapshot.runtime_generation != self.config.runtime_generation
        {
            return Err(ProxyError::StaleRuntime);
        }
        let ready = if bridge_required {
            matches!(
                snapshot.authority_state,
                AuthorityState::BrowserBridgeReady | AuthorityState::Active
            )
        } else {
            matches!(
                snapshot.authority_state,
                AuthorityState::ResolutionTransportReady
                    | AuthorityState::DnssecVerified
                    | AuthorityState::DaneOriginVerified
                    | AuthorityState::BrowserBridgeReady
                    | AuthorityState::Active
            )
        };
        if !ready {
            return Err(ProxyError::AuthorityNotReady);
        }
        Ok(())
    }
}

impl Drop for ProxySession {
    fn drop(&mut self) {
        self.pending.clear();
        self.publications.clear();
    }
}

struct SecretHeader(Vec<u8>);

impl SecretHeader {
    fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }
}

impl Drop for SecretHeader {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct ParsedConnect {
    host: NormalizedHost,
    port: u16,
    authorization: Vec<SecretHeader>,
}

fn parse_connect_head(input: &[u8], limits: ProxyLimits) -> Result<ParsedConnect, ProxyError> {
    if input.len() > limits.maximum_head_bytes
        || !input.ends_with(b"\r\n\r\n")
        || input.windows(2).filter(|pair| *pair == b"\r\n").count() < 2
    {
        return Err(ProxyError::MalformedRequest);
    }
    let text = std::str::from_utf8(input).map_err(|_| ProxyError::MalformedRequest)?;
    if input.first() == Some(&b'\n')
        || input
            .windows(2)
            .any(|window| window.get(1) == Some(&b'\n') && window.first() != Some(&b'\r'))
    {
        return Err(ProxyError::MalformedRequest);
    }
    let mut lines = text
        .strip_suffix("\r\n\r\n")
        .ok_or(ProxyError::MalformedRequest)?
        .split("\r\n");
    let request_line = lines.next().ok_or(ProxyError::MalformedRequest)?;
    if request_line.contains('\t') {
        return Err(ProxyError::MalformedRequest);
    }
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(ProxyError::MalformedRequest)?;
    let target = parts.next().ok_or(ProxyError::MalformedRequest)?;
    let version = parts.next().ok_or(ProxyError::MalformedRequest)?;
    if method != "CONNECT" || version != "HTTP/1.1" || parts.next().is_some() || target.is_empty() {
        return Err(ProxyError::MalformedRequest);
    }
    let (host, port) = parse_authority(target)?;
    let mut host_values = Vec::new();
    let mut authorization = Vec::new();
    let mut header_count = 0_usize;
    for line in lines {
        header_count = header_count
            .checked_add(1)
            .ok_or(ProxyError::MalformedRequest)?;
        if header_count > limits.maximum_headers || line.is_empty() || line.starts_with([' ', '\t'])
        {
            return Err(ProxyError::MalformedRequest);
        }
        let (name, raw_value) = line.split_once(':').ok_or(ProxyError::MalformedRequest)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err(ProxyError::MalformedRequest);
        }
        let value = raw_value.trim_matches([' ', '\t']);
        if value.is_empty()
            || value
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\t'))
        {
            return Err(ProxyError::MalformedRequest);
        }
        if name.eq_ignore_ascii_case("host") {
            host_values.push(value.to_owned());
        } else if name.eq_ignore_ascii_case(PROXY_AUTHORIZATION_HEADER) {
            authorization.push(SecretHeader(value.as_bytes().to_vec()));
        } else if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("upgrade")
            || name.eq_ignore_ascii_case("expect")
            || ((name.eq_ignore_ascii_case("connection")
                || name.eq_ignore_ascii_case("proxy-connection"))
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade")))
        {
            return Err(ProxyError::RequestBodyOrUpgrade);
        }
    }
    if host_values.len() != 1 || authorization.len() != 1 {
        return Err(ProxyError::MalformedRequest);
    }
    let (host_header, host_port) =
        parse_authority(host_values.first().ok_or(ProxyError::MalformedRequest)?)?;
    if host_header != host || host_port != port {
        return Err(ProxyError::AuthorityMismatch);
    }
    Ok(ParsedConnect {
        host,
        port,
        authorization,
    })
}

fn parse_authority(input: &str) -> Result<(NormalizedHost, u16), ProxyError> {
    let (host, port_text) = input
        .rsplit_once(':')
        .ok_or(ProxyError::MalformedAuthority)?;
    if host.contains(':')
        || port_text.is_empty()
        || (port_text.len() > 1 && port_text.starts_with('0'))
        || !port_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ProxyError::MalformedAuthority);
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|_| ProxyError::MalformedAuthority)?;
    if port == 0 {
        return Err(ProxyError::MalformedAuthority);
    }
    Ok((NormalizedHost::parse(host)?, port))
}

fn basic_token(value: &str) -> Option<&str> {
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, ' ' | '\t'))
    {
        return None;
    }
    let value = value.trim_matches([' ', '\t']);
    let separator = value.find([' ', '\t'])?;
    let (scheme, remainder) = value.split_at(separator);
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let token = remainder.trim_start_matches([' ', '\t']);
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return None;
    }
    Some(token)
}

fn encode_hex(input: &[u8]) -> String {
    let mut output = Vec::with_capacity(input.len() * 2);
    append_hex(&mut output, input);
    String::from_utf8(output).unwrap_or_default()
}

fn append_hex(output: &mut Vec<u8>, input: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in input {
        output.push(HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0'));
        output.push(HEX.get(usize::from(byte & 0x0f)).copied().unwrap_or(b'0'));
    }
}

fn encode_base64(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = u32::from(chunk.first().copied().unwrap_or(0));
        let second = chunk.get(1).copied().map_or(0, u32::from);
        let third = chunk.get(2).copied().map_or(0, u32::from);
        let value = (first << 16) | (second << 8) | third;
        output.push(base64_character((value >> 18) & 0x3f));
        output.push(base64_character((value >> 12) & 0x3f));
        output.push(if chunk.len() > 1 {
            base64_character((value >> 6) & 0x3f)
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            base64_character(value & 0x3f)
        } else {
            '='
        });
    }
    output
}

fn base64_character(index: u32) -> char {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let index = usize::try_from(index).unwrap_or(0);
    char::from(ALPHABET.get(index).copied().unwrap_or(b'A'))
}

fn looks_like_legacy_ipv4(host: &str) -> bool {
    let mut count = 0_usize;
    let numeric = host.split('.').all(|label| {
        count += 1;
        if let Some(hex) = label
            .strip_prefix("0x")
            .or_else(|| label.strip_prefix("0X"))
        {
            return !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit());
        }
        if label.len() > 1 && label.starts_with('0') {
            return label.bytes().all(|byte| matches!(byte, b'0'..=b'7'));
        }
        !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit())
    });
    numeric && (1..=4).contains(&count)
}

/// Proxy configuration, request, runtime, or provider-publication failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// Engine state could not be read or advanced.
    #[error("browser engine failure: {0}")]
    Engine(#[from] EngineError),
    /// Listener endpoint is not numeric loopback.
    #[error("proxy endpoint must be numeric loopback")]
    NonLoopbackEndpoint,
    /// Port zero cannot be advertised in PAC/native messaging.
    #[error("proxy endpoint port must be nonzero")]
    ZeroProxyPort,
    /// Client did not connect from a loopback address.
    #[error("proxy client must be loopback")]
    NonLoopbackClient,
    /// Browser runtime session must be nonzero.
    #[error("proxy runtime session must be nonzero")]
    ZeroRuntimeSession,
    /// Runtime generation must begin above zero.
    #[error("proxy runtime generation must be nonzero")]
    ZeroRuntimeGeneration,
    /// Native process session must be nonzero and fresh per start.
    #[error("proxy process session must be nonzero")]
    ZeroProcessSession,
    /// Native process generation must begin above zero.
    #[error("proxy process generation must be nonzero")]
    ZeroProcessGeneration,
    /// Listener generation must begin above zero.
    #[error("proxy listener generation must be nonzero")]
    ZeroListenerGeneration,
    /// Proxy resource bounds are invalid.
    #[error("invalid proxy limits")]
    InvalidLimits,
    /// Caller-supplied trusted time moved backwards within this session.
    #[error("proxy trusted clock moved backwards")]
    ClockRollback,
    /// A bounded absolute deadline cannot be represented.
    #[error("proxy absolute deadline overflow")]
    TimeOverflow,
    /// Host is not strict ASCII/punycode DNS text.
    #[error("invalid proxy host")]
    InvalidHost,
    /// Scope root must be one proof-verified HNS TLD label.
    #[error("proxy scope root must be one HNS TLD")]
    ScopeMustBeHnsTld,
    /// CONNECT target is outside the immutable HNS scope.
    #[error("proxy target is outside HNS scope")]
    HostOutsideScope,
    /// Runtime session/generation was revoked or differs from this proxy.
    #[error("proxy runtime is stale")]
    StaleRuntime,
    /// Engine authority state is not ready for this phase.
    #[error("proxy authority is not ready")]
    AuthorityNotReady,
    /// Request head is malformed, incomplete, oversized, or ambiguous.
    #[error("malformed CONNECT request")]
    MalformedRequest,
    /// CONNECT authority is not canonical host:port.
    #[error("malformed CONNECT authority")]
    MalformedAuthority,
    /// Host header does not exactly match the request target.
    #[error("CONNECT Host header and target differ")]
    AuthorityMismatch,
    /// CONNECT request attempted a body or protocol upgrade.
    #[error("CONNECT request body or upgrade is prohibited")]
    RequestBodyOrUpgrade,
    /// Proxy capability is missing, duplicated, or incorrect.
    #[error("proxy authentication failed")]
    AuthenticationFailed,
    /// Pending request bound is full.
    #[error("proxy pending request limit reached")]
    PendingLimit,
    /// Pending CONNECT reached its exclusive expiry.
    #[error("proxy pending CONNECT expired")]
    PendingExpired,
    /// Process-local proxy instance counter cannot advance.
    #[error("proxy instance sequence exhausted")]
    InstanceSequenceExhausted,
    /// Request sequence cannot advance.
    #[error("proxy request sequence exhausted")]
    RequestSequenceExhausted,
    /// Publication sequence cannot advance.
    #[error("proxy publication sequence exhausted")]
    PublicationSequenceExhausted,
    /// Registry generation cannot advance.
    #[error("proxy publication registry generation exhausted")]
    RegistryGenerationExhausted,
    /// Caller did not present the exact current registry generation.
    #[error("proxy publication registry generation is stale")]
    StaleRegistryGeneration,
    /// Publication registry reached its configured capacity.
    #[error("proxy publication registry capacity reached")]
    PublicationLimit,
    /// Exact logical origin already has a publication.
    #[error("proxy origin publication already exists")]
    PublicationAlreadyExists,
    /// Admission belongs to another, replaced, revoked, or restarted registry.
    #[error("proxy origin publication mismatch")]
    PublicationMismatch,
    /// Pending token belongs to another proxy, was changed, or was consumed.
    #[error("proxy pending CONNECT mismatch")]
    PendingMismatch,
    /// Engine-issued provider authority is not valid for the exact current binding.
    #[error("provider authority does not match the current proxy binding")]
    ProviderAuthorityMismatch,
    /// Provider authority predates its validity window.
    #[error("provider authority is not yet valid")]
    ProviderAuthorityNotYetValid,
    /// Provider authority or its short publication lifetime expired.
    #[error("provider authority publication expired")]
    ProviderAuthorityExpired,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid deterministic proxy fixtures"
)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use hns_dane_engine::{
        EngineConfig, IcannOriginAuthentication, IcannOriginAuthenticationRequest,
        NamespaceDecision, RuntimeSessionId,
    };
    use hns_namespace_resolution::{
        AbsenceKind, ApplicationProtocol, CanonicalHost, EvidenceProvenance, Freshness,
        IcannChainState, OriginPlanInput, OriginQuery, ProtocolCapabilities, RootLookup,
        SelectionPolicy, ServiceBinding, ServiceBindingInput, ServiceTransport, ValidatedAbsence,
        ValidatedOriginPlan, decide_namespace,
    };
    use hns_resolution_policy::{Network, PolicySnapshot};

    use super::*;

    const AUTHORITY_NOW: u64 = 1_700_000_000;

    fn ready_engine(session: [u8; 16]) -> Engine {
        let engine = Engine::new(EngineConfig {
            runtime_session: RuntimeSessionId::new(session).unwrap(),
            network: Network::Regtest,
            policy: PolicySnapshot::default(),
        });
        for state in [
            AuthorityState::LocalStateOpened,
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
        ] {
            engine.advance_authority_state(state).unwrap();
        }
        engine
    }

    fn authorization() -> ProxyAuthorization {
        ProxyAuthorization::from_capability([7; 16], [9; 32])
    }

    fn proxy_for_engine(
        engine: &Engine,
        process_session: [u8; 16],
        maximum_pending: usize,
        maximum_publications: usize,
    ) -> ProxySession {
        proxy_for_engine_with_limits(
            engine,
            process_session,
            ProxyLimits {
                maximum_pending,
                maximum_publications,
                ..ProxyLimits::default()
            },
        )
    }

    fn proxy_for_engine_with_limits(
        engine: &Engine,
        process_session: [u8; 16],
        limits: ProxyLimits,
    ) -> ProxySession {
        let snapshot = engine.snapshot().unwrap();
        let config = ProxyConfig::new(
            LoopbackEndpoint::new("127.0.0.1:39000".parse().unwrap()).unwrap(),
            ProxyInstanceIdentity::new(process_session, 1, 1).unwrap(),
            snapshot.runtime_session,
            snapshot.runtime_generation,
            HostScope::from_verified_hns_tld("alpha").unwrap(),
            authorization(),
            limits,
        )
        .unwrap();
        ProxySession::new(config).unwrap()
    }

    fn session(session_id: [u8; 16], maximum_pending: usize) -> (Engine, ProxySession) {
        let engine = ready_engine(session_id);
        let proxy = proxy_for_engine(&engine, [90; 16], maximum_pending, 4);
        (engine, proxy)
    }

    fn active_engine(session_id: [u8; 16]) -> Engine {
        let engine = ready_engine(session_id);
        for state in [
            AuthorityState::DnssecVerified,
            AuthorityState::BrowserBridgeReady,
            AuthorityState::Active,
        ] {
            engine.advance_authority_state(state).unwrap();
        }
        engine
    }

    fn recover_active_engine(engine: &Engine) {
        for state in [
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
            AuthorityState::BrowserBridgeReady,
            AuthorityState::Active,
        ] {
            engine.advance_authority_state(state).unwrap();
        }
    }

    fn provider_decision(host: &str) -> NamespaceDecision {
        let query = OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            OriginScheme::Https,
            None,
            ProtocolCapabilities::all(),
        );
        let target = query.host().clone();
        let port = query.origin_port();
        let freshness = Freshness::new(AUTHORITY_NOW - 10, AUTHORITY_NOW + 100).unwrap();
        let service = ServiceBinding::new(ServiceBindingInput {
            priority: None,
            service_target: target.clone(),
            mandatory_keys: Vec::new(),
            advertised_alpn: Vec::new(),
            selected_protocol: ApplicationProtocol::Http11,
            effective_port: port,
            transport: ServiceTransport::Tcp,
            connection_hints: Vec::new(),
            ech_config: None,
            parameters: Vec::new(),
        })
        .unwrap();
        let icann = ValidatedOriginPlan::new(OriginPlanInput {
            namespace: Namespace::Icann,
            query: query.clone(),
            alias_path: Vec::new(),
            terminal_target: target.clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: target,
            endpoints: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                port.get(),
            )],
            service,
            tls_policy: TlsTrustPolicy::WebPkiAuthenticatedAbsence,
            tlsa_records: Vec::new(),
            provenance: EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
            freshness,
        })
        .unwrap();
        let hns_absence = ValidatedAbsence::new(
            Namespace::Hns,
            query.clone(),
            AbsenceKind::HnsCurrentUrkelNonInclusion,
            EvidenceProvenance::Hns {
                network: HnsNetwork::Regtest,
                tree_root: [21; 32],
                height: 42,
            },
            freshness,
        )
        .unwrap();
        decide_namespace(
            &query,
            RootLookup::Absent(hns_absence),
            RootLookup::Present(icann),
            SelectionPolicy::default(),
            AUTHORITY_NOW,
        )
        .unwrap()
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "the test adapter implements the optional trusted-authenticator result"
    )]
    fn trusted_icann_webpki(
        request: &IcannOriginAuthenticationRequest,
    ) -> Option<IcannOriginAuthentication> {
        Some(request.attest_webpki_verified())
    }

    fn provider_authority(
        engine: &Engine,
        decision: &NamespaceDecision,
    ) -> ProviderAuthorityContext {
        let context = engine
            .bind_icann_origin_context(decision, &trusted_icann_webpki, AUTHORITY_NOW)
            .unwrap();
        engine
            .authorize_provider_injection(decision, &context, AUTHORITY_NOW)
            .unwrap()
            .into_context()
            .unwrap()
    }

    fn connect_request_for(host: &str, authorization: &str) -> Vec<u8> {
        format!(
            "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nProxy-Authorization: {authorization}\r\nProxy-Connection: keep-alive\r\n\r\n"
        )
        .into_bytes()
    }

    fn connect_request(authorization: &str) -> Vec<u8> {
        connect_request_for("www.alpha", authorization)
    }

    #[test]
    fn capability_auth_is_exact_constant_time_and_redacted() {
        let authorization = authorization();
        let valid = authorization.authorization_header_value();
        assert!(authorization.verify_header_values([valid.as_str()]));
        assert!(authorization.verify_header_values([valid.replacen("Basic", "bAsIc", 1).as_str()]));
        assert!(!authorization.verify_header_values(std::iter::empty()));
        assert!(!authorization.verify_header_values([valid.as_str(), valid.as_str()]));
        assert!(!authorization.verify_header_values(["Basic wrong"]));
        assert!(!authorization.verify_header_values(["Bearer wrong"]));
        let debug = format!("{authorization:?}");
        assert!(!debug.contains(authorization.realm()));
        assert!(!debug.contains(valid.split_once(' ').unwrap().1));
    }

    #[test]
    fn endpoint_challenge_and_clients_are_exact_loopback() {
        assert!(matches!(
            LoopbackEndpoint::new("0.0.0.0:39000".parse().unwrap()),
            Err(ProxyError::NonLoopbackEndpoint)
        ));
        assert!(matches!(
            LoopbackEndpoint::new("127.0.0.1:0".parse().unwrap()),
            Err(ProxyError::ZeroProxyPort)
        ));
        let (engine, mut proxy) = session([1; 16], 2);
        let endpoint = proxy.endpoint();
        assert!(proxy.config.authorization.matches_challenge(
            endpoint,
            "127.0.0.1",
            39000,
            proxy.config.realm()
        ));
        let request = connect_request(&proxy.authorization_header_value());
        assert!(matches!(
            proxy.admit_connect(
                &engine,
                "192.0.2.1:50000".parse().unwrap(),
                &request,
                1,
            ),
            Err(ProxyError::NonLoopbackClient)
        ));
    }

    #[test]
    fn host_scope_is_label_bound_and_rejects_ip_forms() {
        let scope = HostScope::from_verified_hns_tld("ALPHA.").unwrap();
        assert_eq!(scope.authorize("WWW.Alpha.").unwrap().as_str(), "www.alpha");
        assert!(matches!(
            scope.authorize("notalpha"),
            Err(ProxyError::HostOutsideScope)
        ));
        for invalid in ["127.0.0.1", "2130706433", "0x7f000001", "[::1]", "bad name"] {
            assert!(matches!(
                NormalizedHost::parse(invalid),
                Err(ProxyError::InvalidHost)
            ));
        }
        assert!(matches!(
            HostScope::from_verified_hns_tld("www.alpha"),
            Err(ProxyError::ScopeMustBeHnsTld)
        ));
    }

    #[test]
    fn admits_only_strict_authenticated_connect() {
        let (engine, mut proxy) = session([2; 16], 4);
        let authorization = proxy.authorization_header_value();
        let valid = connect_request(&authorization);
        let pending = proxy
            .admit_connect(&engine, "127.0.0.1:50000".parse().unwrap(), &valid, 1)
            .unwrap();
        assert_eq!(pending.host(), "www.alpha");
        assert_eq!(pending.port(), 443);

        for invalid in [
            b"GET https://www.alpha/ HTTP/1.1\r\nHost: www.alpha\r\n\r\n".to_vec(),
            connect_request("Basic wrong"),
            format!(
                "CONNECT www.alpha:443 HTTP/1.1\r\nHost: other.alpha:443\r\nProxy-Authorization: {authorization}\r\n\r\n"
            )
            .into_bytes(),
            format!(
                "CONNECT www.alpha:443 HTTP/1.1\r\nHost: www.alpha:443\r\nProxy-Authorization: {authorization}\r\nProxy-Authorization: {authorization}\r\n\r\n"
            )
            .into_bytes(),
            format!(
                "CONNECT www.alpha:443 HTTP/1.1\r\nHost: www.alpha:443\r\nProxy-Authorization: {authorization}\r\nContent-Length: 1\r\n\r\nx"
            )
            .into_bytes(),
            format!(
                "CONNECT www.alpha:443 HTTP/1.1\r\nHost: www.alpha:443\r\nProxy-Authorization: {authorization}\r\nExpect: 100-continue\r\n\r\n"
            )
            .into_bytes(),
            format!(
                "CONNECT www.alpha:443 HTTP/1.1\r\nHost: www.alpha:443\r\nProxy-Authorization: {authorization}\r\nConnection: keep-alive, Upgrade\r\n\r\n"
            )
            .into_bytes(),
        ] {
            assert!(proxy
                .admit_connect(
                    &engine,
                    "127.0.0.1:50000".parse().unwrap(),
                    &invalid,
                    1,
                )
                .is_err());
        }
    }

    #[test]
    fn pending_tokens_are_bounded_cancelled_and_instance_scoped() {
        let (engine, mut first) = session([3; 16], 1);
        let (_, mut second) = session([3; 16], 1);
        let request = connect_request(&first.authorization_header_value());
        let pending = first
            .admit_connect(&engine, "127.0.0.1:50000".parse().unwrap(), &request, 10)
            .unwrap();
        assert_eq!(pending.admitted_at(), 10);
        assert_eq!(
            pending.expires_at(),
            10 + DEFAULT_MAXIMUM_PENDING_LIFETIME_SECONDS
        );
        assert!(matches!(
            first.admit_connect(
                &engine,
                "127.0.0.1:50001".parse().unwrap(),
                &request,
                10,
            ),
            Err(ProxyError::PendingLimit)
        ));
        assert!(matches!(
            second.cancel(&pending),
            Err(ProxyError::PendingMismatch)
        ));
        let replacement = first
            .admit_connect(
                &engine,
                "127.0.0.1:50002".parse().unwrap(),
                &request,
                pending.expires_at(),
            )
            .unwrap();
        assert!(matches!(
            first.cancel(&pending),
            Err(ProxyError::PendingMismatch)
        ));
        assert!(matches!(
            first.admit_connect(
                &engine,
                "127.0.0.1:50003".parse().unwrap(),
                &request,
                replacement.admitted_at() - 1,
            ),
            Err(ProxyError::ClockRollback)
        ));
        first.cancel(&replacement).unwrap();
    }

    #[test]
    fn stale_runtime_and_authentication_challenge_fail_closed() {
        let (engine, mut proxy) = session([4; 16], 2);
        let challenge = String::from_utf8(proxy.authentication_challenge()).unwrap();
        assert!(challenge.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"));
        assert!(challenge.contains(PROXY_AUTHENTICATE_HEADER));
        assert!(challenge.contains("Cache-Control: no-store"));

        let before = engine.snapshot().unwrap().policy;
        let mut next = before.config();
        next.authenticated_authoritative_doh = false;
        engine.update_policy(before.generation(), next).unwrap();
        let request = connect_request(&proxy.authorization_header_value());
        assert!(matches!(
            proxy.admit_connect(
                &engine,
                "127.0.0.1:50000".parse().unwrap(),
                &request,
                1,
            ),
            Err(ProxyError::StaleRuntime)
        ));
    }

    #[test]
    fn provider_publication_is_atomic_bounded_and_restart_scoped() {
        let engine = active_engine([7; 16]);
        let decision = provider_decision("www.alpha");
        let mut proxy = proxy_for_engine(&engine, [90; 16], 4, 1);
        let initial_generation = proxy.registry_generation();

        let stale_authority = provider_authority(&engine, &decision);
        assert!(matches!(
            proxy.publish_authority(
                &engine,
                initial_generation + 1,
                stale_authority,
                AUTHORITY_NOW,
            ),
            Err(ProxyError::StaleRegistryGeneration)
        ));
        assert_eq!(proxy.registry_generation(), initial_generation);
        assert_eq!(proxy.publication_count(), 0);

        let authority = provider_authority(&engine, &decision);
        let decision_fingerprint = authority.decision_fingerprint();
        let authority_valid_from = authority.valid_from();
        let authority_valid_until = authority.valid_until();
        let admission = proxy
            .publish_authority(&engine, initial_generation, authority, AUTHORITY_NOW)
            .unwrap();
        assert_eq!(admission.host(), "www.alpha");
        assert_eq!(admission.origin_port(), 443);
        assert_eq!(admission.registry_generation(), initial_generation + 1);
        assert_eq!(proxy.publication_count(), 1);
        assert!(!format!("{admission:?}").contains("www.alpha"));

        let other = provider_decision("other.alpha");
        let capacity_authority = provider_authority(&engine, &other);
        let capacity_generation = proxy.registry_generation();
        assert!(matches!(
            proxy.publish_authority(
                &engine,
                capacity_generation,
                capacity_authority,
                AUTHORITY_NOW,
            ),
            Err(ProxyError::PublicationLimit)
        ));
        assert_eq!(proxy.registry_generation(), capacity_generation);
        assert_eq!(proxy.publication_count(), 1);

        let mut restarted = proxy_for_engine(&engine, [91; 16], 4, 1);
        let restarted_request =
            connect_request_for("www.alpha", &restarted.authorization_header_value());
        let restarted_pending = restarted
            .admit_connect(
                &engine,
                "127.0.0.1:50000".parse().unwrap(),
                &restarted_request,
                AUTHORITY_NOW,
            )
            .unwrap();
        let restarted_generation = restarted.registry_generation();
        assert!(matches!(
            restarted.authorize_connect(
                &engine,
                restarted_pending,
                &admission,
                restarted_generation,
                AUTHORITY_NOW,
            ),
            Err(ProxyError::PublicationMismatch)
        ));

        let request = connect_request_for("www.alpha", &proxy.authorization_header_value());
        let pending = proxy
            .admit_connect(
                &engine,
                "127.0.0.1:50001".parse().unwrap(),
                &request,
                AUTHORITY_NOW,
            )
            .unwrap();
        let grant_generation = proxy.registry_generation();
        let grant = proxy
            .authorize_connect(
                &engine,
                pending,
                &admission,
                grant_generation,
                AUTHORITY_NOW,
            )
            .unwrap();
        assert_eq!(grant.host(), "www.alpha");
        assert_eq!(grant.scheme(), OriginScheme::Https);
        assert_eq!(grant.port(), 443);
        assert_eq!(grant.selected_namespace(), Namespace::Icann);
        assert_eq!(
            grant.authenticated_context(),
            AuthenticatedContextStatus::IcannWebPkiAuthenticatedAbsence
        );
        assert_eq!(grant.hns_network(), HnsNetwork::Regtest);
        assert_eq!(grant.service_port(), 443);
        assert_eq!(
            grant.tls_policy(),
            TlsTrustPolicy::WebPkiAuthenticatedAbsence
        );
        assert_eq!(grant.runtime_session(), [7; 16]);
        assert_eq!(grant.policy_generation(), 1);
        assert_eq!(grant.decision_fingerprint(), decision_fingerprint);
        assert_eq!(grant.authority_valid_from(), authority_valid_from);
        assert_eq!(grant.authority_valid_until(), authority_valid_until);
        assert_eq!(grant.endpoint(), proxy.endpoint());
        assert_eq!(grant.process_session(), [90; 16]);
        assert_eq!(grant.process_generation(), 1);
        assert_eq!(grant.listener_generation(), 1);
        assert_eq!(grant.registry_generation(), proxy.registry_generation());
        assert_eq!(grant.valid_from(), AUTHORITY_NOW);
        assert_eq!(
            grant.valid_until(),
            AUTHORITY_NOW + DEFAULT_MAXIMUM_GRANT_LIFETIME_SECONDS
        );
        let revalidation_generation = proxy.registry_generation();
        proxy
            .revalidate_tunnel_grant(
                &engine,
                &grant,
                revalidation_generation,
                AUTHORITY_NOW,
            )
            .unwrap();

        let replacement_authority = provider_authority(&engine, &decision);
        let previous_publication_generation = admission.publication_generation();
        let replacement_generation = proxy.registry_generation();
        let replacement = proxy
            .replace_authority(
                &engine,
                replacement_generation,
                admission,
                replacement_authority,
                AUTHORITY_NOW,
            )
            .unwrap();
        assert!(replacement.publication_generation() > previous_publication_generation);
        assert!(grant.registry_generation() < proxy.registry_generation());
        let stale_grant_generation = proxy.registry_generation();
        assert!(matches!(
            proxy.revalidate_tunnel_grant(
                &engine,
                &grant,
                stale_grant_generation,
                AUTHORITY_NOW,
            ),
            Err(ProxyError::PublicationMismatch)
        ));
        let revocation_generation = proxy.registry_generation();
        let revoked_generation = proxy
            .revoke_authority(revocation_generation, replacement)
            .unwrap();
        assert_eq!(revoked_generation, proxy.registry_generation());
        assert_eq!(proxy.publication_count(), 0);

        let mut reclaiming = proxy_for_engine_with_limits(
            &engine,
            [92; 16],
            ProxyLimits {
                maximum_publications: 1,
                maximum_publication_lifetime_seconds: 1,
                maximum_grant_lifetime_seconds: 1,
                ..ProxyLimits::default()
            },
        );
        let expiring_authority = provider_authority(&engine, &decision);
        let expiring_generation = reclaiming.registry_generation();
        let expired = reclaiming
            .publish_authority(
                &engine,
                expiring_generation,
                expiring_authority,
                AUTHORITY_NOW,
            )
            .unwrap();
        let reclaim_generation = reclaiming.registry_generation();
        let replacement_authority = provider_authority(&engine, &other);
        let reclaimed = reclaiming
            .publish_authority(
                &engine,
                reclaim_generation,
                replacement_authority,
                AUTHORITY_NOW + 1,
            )
            .unwrap();
        assert_eq!(reclaiming.registry_generation(), reclaim_generation + 1);
        assert_eq!(reclaiming.publication_count(), 1);
        assert_eq!(reclaimed.host(), "other.alpha");
        assert!(matches!(
            reclaiming.validate_admission(&expired),
            Err(ProxyError::PublicationMismatch)
        ));
    }

    #[test]
    fn publication_survives_unrelated_authority_admissions() {
        let engine = active_engine([17; 16]);
        let decision = provider_decision("www.alpha");
        let mut proxy = proxy_for_engine(&engine, [93; 16], 2, 2);
        let generation = proxy.registry_generation();
        let admission = proxy
            .publish_authority(
                &engine,
                generation,
                provider_authority(&engine, &decision),
                AUTHORITY_NOW,
            )
            .unwrap();

        let unrelated = provider_decision("other.alpha");
        let _unrelated_authority = provider_authority(&engine, &unrelated);

        let request = connect_request_for("www.alpha", &proxy.authorization_header_value());
        let pending = proxy
            .admit_connect(
                &engine,
                "127.0.0.1:50010".parse().unwrap(),
                &request,
                AUTHORITY_NOW,
            )
            .unwrap();
        let generation = proxy.registry_generation();
        let grant = proxy
            .authorize_connect(
                &engine,
                pending,
                &admission,
                generation,
                AUTHORITY_NOW,
            )
            .unwrap();
        proxy
            .revalidate_tunnel_grant(&engine, &grant, generation, AUTHORITY_NOW)
            .unwrap();
    }

    #[test]
    fn invalidated_publication_is_reclaimed_before_capacity() {
        let engine = active_engine([18; 16]);
        let first = provider_decision("www.alpha");
        let second = provider_decision("other.alpha");
        let mut proxy = proxy_for_engine(&engine, [94; 16], 2, 1);
        let generation = proxy.registry_generation();
        let stale = proxy
            .publish_authority(
                &engine,
                generation,
                provider_authority(&engine, &first),
                AUTHORITY_NOW,
            )
            .unwrap();

        engine
            .advance_authority_state(AuthorityState::Degraded)
            .unwrap();
        recover_active_engine(&engine);

        let generation = proxy.registry_generation();
        let replacement = proxy
            .publish_authority(
                &engine,
                generation,
                provider_authority(&engine, &second),
                AUTHORITY_NOW,
            )
            .unwrap();
        assert_eq!(replacement.host(), "other.alpha");
        assert_eq!(proxy.publication_count(), 1);
        assert!(matches!(
            proxy.validate_admission(&stale),
            Err(ProxyError::PublicationMismatch)
        ));
    }
}
