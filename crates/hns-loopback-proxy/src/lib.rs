//! Authenticated exact-origin loopback proxy admission.
//!
//! This crate owns the platform-neutral boundary in front of a native browser
//! proxy. It admits only strict loopback `CONNECT` requests carrying one
//! per-instance Basic capability, then requires a non-forgeable
//! current-generation browser-bridge authorization from `hns-dane-engine`
//! before an exact-host tunnel grant can be issued. Socket accept loops, local
//! CA storage, and TLS I/O remain native-host adapter responsibilities.

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
    AuthorityState, BrowserBridgeAuthorization, Engine, EngineError, EngineSnapshot,
};
use subtle::ConstantTimeEq;
use thiserror::Error;

static NEXT_PROXY_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

const PROXY_USERNAME: &str = "hns-browser";
const CAPABILITY_BYTES: usize = 32;
const REALM_NONCE_BYTES: usize = 16;
const DEFAULT_ORIGIN_PORT: u16 = 443;
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
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            maximum_head_bytes: DEFAULT_MAXIMUM_HEAD_BYTES,
            maximum_headers: DEFAULT_MAXIMUM_HEADERS,
            maximum_pending: DEFAULT_MAXIMUM_PENDING,
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
        {
            return Err(ProxyError::InvalidLimits);
        }
        Ok(self)
    }
}

/// One proxy instance configuration.
pub struct ProxyConfig {
    endpoint: LoopbackEndpoint,
    runtime_session: [u8; 16],
    runtime_generation: u64,
    scope: HostScope,
    authorization: ProxyAuthorization,
    limits: ProxyLimits,
    origin_port: u16,
}

impl ProxyConfig {
    /// Bind a fresh proxy capability to one runtime generation and HNS TLD.
    pub fn new(
        endpoint: LoopbackEndpoint,
        runtime_session: [u8; 16],
        runtime_generation: u64,
        scope: HostScope,
        authorization: ProxyAuthorization,
        limits: ProxyLimits,
    ) -> Result<Self, ProxyError> {
        if runtime_generation == 0 {
            return Err(ProxyError::ZeroRuntimeGeneration);
        }
        Ok(Self {
            endpoint,
            runtime_session,
            runtime_generation,
            scope,
            authorization,
            limits: limits.validate()?,
            origin_port: DEFAULT_ORIGIN_PORT,
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
            .field("runtime_session", &self.runtime_session)
            .field("runtime_generation", &self.runtime_generation)
            .field("scope", &"[redacted]")
            .field("authorization", &"[redacted]")
            .field("limits", &self.limits)
            .field("origin_port", &self.origin_port)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingRecord {
    host: NormalizedHost,
    port: u16,
}

/// Opaque authenticated CONNECT awaiting exact-origin DANE authorization.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingConnect {
    instance_id: u64,
    sequence: u64,
    host: NormalizedHost,
    port: u16,
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
}

impl fmt::Debug for PendingConnect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingConnect")
            .field("instance_id", &self.instance_id)
            .field("sequence", &self.sequence)
            .field("host", &"[redacted]")
            .field("port", &self.port)
            .finish()
    }
}

/// Exact-host backend permission issued after engine DANE authorization.
#[derive(Eq, PartialEq)]
pub struct TunnelGrant {
    host: NormalizedHost,
    port: u16,
    runtime_session: [u8; 16],
    runtime_generation: u64,
    authorization_event: u64,
    valid_from: u64,
    valid_until: u64,
}

impl TunnelGrant {
    /// Exact normalized leaf/tunnel host.
    #[must_use]
    pub fn host(&self) -> &str {
        self.host.as_str()
    }

    /// Exact origin port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
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
        self.authorization_event
    }

    /// Inclusive beginning of the chain-anchor validity window.
    #[must_use]
    pub const fn valid_from(&self) -> u64 {
        self.valid_from
    }

    /// Inclusive chain-anchor validity deadline.
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

impl fmt::Debug for TunnelGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelGrant")
            .field("host", &"[redacted]")
            .field("port", &self.port)
            .field("runtime_session", &self.runtime_session)
            .field("runtime_generation", &self.runtime_generation)
            .field("authorization_event", &self.authorization_event)
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .finish()
    }
}

/// Platform-neutral authenticated proxy admission state.
#[derive(Debug)]
pub struct ProxySession {
    instance_id: u64,
    config: ProxyConfig,
    sequence: u64,
    pending: HashMap<u64, PendingRecord>,
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
            sequence: 0,
            pending: HashMap::new(),
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
    pub fn admit_connect(
        &mut self,
        engine: &Engine,
        client: SocketAddr,
        request_head: &[u8],
    ) -> Result<PendingConnect, ProxyError> {
        let snapshot = engine.snapshot()?;
        self.ensure_runtime_ready(snapshot, false)?;
        if !client.ip().is_loopback() {
            return Err(ProxyError::NonLoopbackClient);
        }
        if self.pending.len() >= self.config.limits.maximum_pending {
            return Err(ProxyError::PendingLimit);
        }
        let parsed = parse_connect_head(request_head, self.config.limits)?;
        if parsed.port != self.config.origin_port {
            return Err(ProxyError::OriginPortRejected);
        }
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
        let record = PendingRecord {
            host: host.clone(),
            port: parsed.port,
        };
        self.pending.insert(sequence, record);
        self.sequence = sequence;
        Ok(PendingConnect {
            instance_id: self.instance_id,
            sequence,
            host,
            port: parsed.port,
        })
    }

    /// Convert one pending CONNECT into an exact-host tunnel grant.
    pub fn authorize_connect(
        &mut self,
        engine: &Engine,
        pending: PendingConnect,
        authorization: &BrowserBridgeAuthorization,
        now: u64,
    ) -> Result<TunnelGrant, ProxyError> {
        let PendingConnect {
            instance_id,
            sequence,
            host,
            port,
        } = pending;
        if instance_id != self.instance_id {
            return Err(ProxyError::PendingMismatch);
        }
        let record = self
            .pending
            .get(&sequence)
            .ok_or(ProxyError::PendingMismatch)?;
        if record.host != host || record.port != port {
            return Err(ProxyError::PendingMismatch);
        }
        let record = self
            .pending
            .remove(&sequence)
            .ok_or(ProxyError::PendingMismatch)?;
        let snapshot = engine.snapshot()?;
        self.ensure_runtime_ready(snapshot, true)?;
        if authorization.runtime_session() != snapshot.runtime_session
            || authorization.runtime_generation() != snapshot.runtime_generation
            || authorization.policy_generation() != snapshot.policy.generation()
            || authorization.event_sequence() != snapshot.event_sequence
            || now < authorization.valid_from()
            || now > authorization.valid_until()
            || authorization.origin() != record.host.as_str()
        {
            return Err(ProxyError::BridgeAuthorizationMismatch);
        }
        Ok(TunnelGrant {
            host: record.host,
            port: record.port,
            runtime_session: snapshot.runtime_session,
            runtime_generation: snapshot.runtime_generation,
            authorization_event: authorization.event_sequence(),
            valid_from: authorization.valid_from(),
            valid_until: authorization.valid_until(),
        })
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

/// Proxy configuration, request, runtime, or bridge failure.
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
    /// Runtime generation must begin above zero.
    #[error("proxy runtime generation must be nonzero")]
    ZeroRuntimeGeneration,
    /// Proxy resource bounds are invalid.
    #[error("invalid proxy limits")]
    InvalidLimits,
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
    /// Only the configured secure origin port is admitted.
    #[error("CONNECT origin port is not permitted")]
    OriginPortRejected,
    /// Proxy capability is missing, duplicated, or incorrect.
    #[error("proxy authentication failed")]
    AuthenticationFailed,
    /// Pending request bound is full.
    #[error("proxy pending request limit reached")]
    PendingLimit,
    /// Process-local proxy instance counter cannot advance.
    #[error("proxy instance sequence exhausted")]
    InstanceSequenceExhausted,
    /// Request sequence cannot advance.
    #[error("proxy request sequence exhausted")]
    RequestSequenceExhausted,
    /// Pending token belongs to another proxy, was changed, or was consumed.
    #[error("proxy pending CONNECT mismatch")]
    PendingMismatch,
    /// Engine bridge capability does not authorize this exact current origin.
    #[error("browser bridge authorization mismatch")]
    BridgeAuthorizationMismatch,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid deterministic proxy fixtures"
)]
mod tests {
    use hns_browser_testkit::{
        STRICT_HNS_ORIGIN, STRICT_RUNTIME_SESSION, StrictRegtestDaneFixture,
    };
    use hns_dane::DaneLimits;
    use hns_dane_engine::{CompletionContext, EngineConfig, RuntimeSessionId, ValidatedDaneInput};
    use hns_dns_wire::ParseLimits;
    use hns_resolution_policy::{Network, PolicySnapshot, ResolutionTransport};

    use super::*;

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

    fn session(session_id: [u8; 16], maximum_pending: usize) -> (Engine, ProxySession) {
        let engine = ready_engine(session_id);
        let snapshot = engine.snapshot().unwrap();
        let config = ProxyConfig::new(
            LoopbackEndpoint::new("127.0.0.1:39000".parse().unwrap()).unwrap(),
            snapshot.runtime_session,
            snapshot.runtime_generation,
            HostScope::from_verified_hns_tld("alpha").unwrap(),
            authorization(),
            ProxyLimits {
                maximum_pending,
                ..ProxyLimits::default()
            },
        )
        .unwrap();
        (engine, ProxySession::new(config).unwrap())
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
            proxy.admit_connect(&engine, "192.0.2.1:50000".parse().unwrap(), &request),
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
            .admit_connect(&engine, "127.0.0.1:50000".parse().unwrap(), &valid)
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
                    &invalid
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
            .admit_connect(&engine, "127.0.0.1:50000".parse().unwrap(), &request)
            .unwrap();
        assert!(matches!(
            first.admit_connect(&engine, "127.0.0.1:50001".parse().unwrap(), &request),
            Err(ProxyError::PendingLimit)
        ));
        assert!(matches!(
            second.cancel(&pending),
            Err(ProxyError::PendingMismatch)
        ));
        first.cancel(&pending).unwrap();
        assert!(matches!(
            first.cancel(&pending),
            Err(ProxyError::PendingMismatch)
        ));
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
            proxy.admit_connect(&engine, "127.0.0.1:50000".parse().unwrap(), &request),
            Err(ProxyError::StaleRuntime)
        ));
    }

    #[test]
    fn strict_regtest_path_mints_only_an_exact_current_tunnel_grant() {
        let fixture = StrictRegtestDaneFixture::new().unwrap();
        let validation_time = fixture.validation_time();
        let (engine, mut proxy) = session(STRICT_RUNTIME_SESSION, 4);
        let authorization = proxy.authorization_header_value();
        let exact_request = connect_request_for(STRICT_HNS_ORIGIN, &authorization);
        let pending = proxy
            .admit_connect(&engine, "127.0.0.1:50000".parse().unwrap(), &exact_request)
            .unwrap();

        let attempt = engine
            .admit_resolution(
                ResolutionTransport::DirectAuthoritativeTcp,
                fixture.query().clone(),
            )
            .unwrap();
        let parsed = engine
            .parse_response(&attempt, fixture.response(), ParseLimits::requester())
            .unwrap();
        let validated = fixture.validate_response(parsed.message()).unwrap();
        engine
            .advance_authority_state(AuthorityState::DnssecVerified)
            .unwrap();
        let certificate_chain = [fixture.certificate()];
        let completion = engine
            .complete_resolution_with_validated_tlsa(
                &attempt,
                &parsed,
                ValidatedDaneInput {
                    validated: &validated,
                    certificate_chain_der: &certificate_chain,
                    origin_sni: STRICT_HNS_ORIGIN,
                    validation_unix_time: i64::from(validation_time),
                    limits: DaneLimits::default(),
                },
                CompletionContext::default(),
            )
            .unwrap();
        let bridge = engine
            .authorize_browser_bridge(&completion, u64::from(validation_time))
            .unwrap();
        let grant = proxy
            .authorize_connect(&engine, pending, &bridge, u64::from(validation_time))
            .unwrap();
        assert_eq!(grant.host(), STRICT_HNS_ORIGIN);
        assert_eq!(grant.port(), 443);
        assert_eq!(
            grant.runtime_generation(),
            engine.snapshot().unwrap().runtime_generation
        );
        assert_eq!(grant.runtime_session(), STRICT_RUNTIME_SESSION);
        assert_eq!(grant.authorization_event(), bridge.event_sequence());
        assert_eq!(grant.valid_from(), bridge.valid_from());
        assert_eq!(grant.valid_until(), bridge.valid_until());

        let wrong_origin = proxy
            .admit_connect(
                &engine,
                "127.0.0.1:50001".parse().unwrap(),
                &connect_request(&authorization),
            )
            .unwrap();
        assert!(matches!(
            proxy.authorize_connect(&engine, wrong_origin, &bridge, u64::from(validation_time)),
            Err(ProxyError::BridgeAuthorizationMismatch)
        ));

        let too_early = proxy
            .admit_connect(&engine, "127.0.0.1:50002".parse().unwrap(), &exact_request)
            .unwrap();
        assert!(matches!(
            proxy.authorize_connect(
                &engine,
                too_early,
                &bridge,
                bridge.valid_from().checked_sub(1).unwrap()
            ),
            Err(ProxyError::BridgeAuthorizationMismatch)
        ));

        let expired = proxy
            .admit_connect(&engine, "127.0.0.1:50003".parse().unwrap(), &exact_request)
            .unwrap();
        assert!(matches!(
            proxy.authorize_connect(
                &engine,
                expired,
                &bridge,
                bridge.valid_until().checked_add(1).unwrap()
            ),
            Err(ProxyError::BridgeAuthorizationMismatch)
        ));

        let stale_event = proxy
            .admit_connect(&engine, "127.0.0.1:50004".parse().unwrap(), &exact_request)
            .unwrap();
        let _new_attempt = engine
            .admit_resolution(
                ResolutionTransport::DirectAuthoritativeTcp,
                fixture.query().clone(),
            )
            .unwrap();
        assert!(matches!(
            proxy.authorize_connect(&engine, stale_event, &bridge, u64::from(validation_time)),
            Err(ProxyError::BridgeAuthorizationMismatch)
        ));
    }
}
