//! Shared full-host namespace decision contract for dual-root browsers.
//!
//! Network adapters independently build one complete, validated origin plan
//! for HNS and ICANN. This crate compares those plans, preserves authenticated
//! absence separately from failures, applies explicit divergence precedence,
//! and produces a query- and policy-bound decision fingerprint for connection
//! and cache isolation. Plans retain distinct origin-alias, ServiceMode target,
//! endpoint-CNAME, address, and TLS trust state and never mix roots.
//!
//! The IANA root-zone list is intentionally absent. A suffix snapshot may
//! order network work outside this crate, but it can never create a namespace
//! decision.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    reason = "DNSSEC, HNS, ICANN, TLSA, SVCB, ALPN, ECH, and WebPKI are protocol names"
)]

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::str::FromStr;

/// Comparison schema included in cache and decision identities.
pub const COMPARISON_SCHEMA_VERSION: u16 = 1;
/// Maximum canonical DNS presentation-name length without a root dot.
pub const MAX_HOST_BYTES: usize = 253;
/// Maximum aliases retained in each origin or endpoint path in one root plan.
pub const MAX_ALIAS_STEPS: usize = 8;
/// Maximum number of usable endpoints retained in one root plan.
pub const MAX_ENDPOINTS: usize = 32;
/// Maximum number of ALPN identifiers retained in one service binding.
pub const MAX_ALPN_IDS: usize = 16;
/// Maximum bytes in one ALPN identifier.
pub const MAX_ALPN_ID_BYTES: usize = 255;
/// Maximum number of SVCB parameters retained in one service binding.
pub const MAX_SERVICE_PARAMETERS: usize = 32;
/// Maximum bytes retained in one SVCB parameter value or ECH configuration.
pub const MAX_PARAMETER_BYTES: usize = 65_535;
/// Maximum number of canonical TLSA records retained in one root plan.
pub const MAX_TLSA_RECORDS: usize = 32;

/// DNS namespace whose independently validated plan may be selected.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Namespace {
    /// Handshake root.
    Hns = 1,
    /// ICANN root.
    Icann = 2,
}

impl Namespace {
    fn tag(self) -> u8 {
        self as u8
    }
}

/// Canonical Handshake network identity used for proof and cache isolation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum HnsNetwork {
    /// Handshake mainnet.
    Mainnet = 0,
    /// Handshake testnet.
    Testnet = 1,
    /// Handshake regtest.
    Regtest = 2,
    /// Handshake simnet.
    Simnet = 3,
}

impl HnsNetwork {
    fn tag(self) -> u8 {
        self as u8
    }
}

/// Canonical lower-case ASCII DNS hostname without a root dot.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalHost(String);

impl CanonicalHost {
    /// Parses a host after the platform URL parser has applied IDNA.
    ///
    /// IP literals, whitespace, empty labels, underscore labels, and names
    /// outside DNS presentation bounds are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidHost`] for a non-DNS hostname.
    pub fn parse(input: &str) -> Result<Self, ValidationError> {
        if input.trim() != input || input.is_empty() || !input.is_ascii() {
            return Err(ValidationError::InvalidHost);
        }
        let without_root = input.strip_suffix('.').unwrap_or(input);
        if without_root.is_empty()
            || without_root.ends_with('.')
            || without_root.len() > MAX_HOST_BYTES
            || IpAddr::from_str(without_root).is_ok()
        {
            return Err(ValidationError::InvalidHost);
        }
        let normalized = without_root.to_ascii_lowercase();
        for label in normalized.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(ValidationError::InvalidHost);
            }
        }
        Ok(Self(normalized))
    }

    /// Returns the canonical host.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Browser origin scheme whose effective endpoint is classified.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum OriginScheme {
    /// Cleartext HTTP.
    Http = 1,
    /// TLS HTTP.
    Https = 2,
    /// Cleartext WebSocket.
    Ws = 3,
    /// TLS WebSocket.
    Wss = 4,
}

impl OriginScheme {
    /// Default port for this scheme.
    #[must_use]
    pub const fn default_port(self) -> NonZeroU16 {
        match self {
            Self::Http | Self::Ws => nonzero_port(80),
            Self::Https | Self::Wss => nonzero_port(443),
        }
    }

    /// Whether the origin uses TLS.
    #[must_use]
    pub const fn uses_tls(self) -> bool {
        matches!(self, Self::Https | Self::Wss)
    }

    fn tag(self) -> u8 {
        self as u8
    }
}

const fn nonzero_port(value: u16) -> NonZeroU16 {
    match NonZeroU16::new(value) {
        Some(value) => value,
        None => unreachable!(),
    }
}

/// Application protocol selected for an origin connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ApplicationProtocol {
    /// HTTP/1.1, including ordinary WebSocket Upgrade.
    Http11 = 1,
    /// HTTP/2.
    Http2 = 2,
    /// HTTP/3 over QUIC.
    Http3 = 3,
}

impl ApplicationProtocol {
    fn tag(self) -> u8 {
        self as u8
    }
}

/// Protocols supported by the requesting browser transport.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtocolCapabilities {
    http11: bool,
    http2: bool,
    http3: bool,
}

impl ProtocolCapabilities {
    /// Creates one non-empty protocol capability set.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidQuery`] when all protocols are off.
    pub const fn new(http11: bool, http2: bool, http3: bool) -> Result<Self, ValidationError> {
        if http11 || http2 || http3 {
            Ok(Self {
                http11,
                http2,
                http3,
            })
        } else {
            Err(ValidationError::InvalidQuery)
        }
    }

    /// Capabilities used by a browser supporting HTTP/1.1, HTTP/2, and HTTP/3.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            http11: true,
            http2: true,
            http3: true,
        }
    }

    /// Whether the selected protocol is supported.
    #[must_use]
    pub const fn supports(self, protocol: ApplicationProtocol) -> bool {
        match protocol {
            ApplicationProtocol::Http11 => self.http11,
            ApplicationProtocol::Http2 => self.http2,
            ApplicationProtocol::Http3 => self.http3,
        }
    }

    fn flags(self) -> u8 {
        u8::from(self.http11) | (u8::from(self.http2) << 1) | (u8::from(self.http3) << 2)
    }
}

/// Canonical origin input common to both root lookups.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OriginQuery {
    host: CanonicalHost,
    scheme: OriginScheme,
    explicit_port: Option<NonZeroU16>,
    supported_protocols: ProtocolCapabilities,
}

impl OriginQuery {
    /// Creates a canonical origin query.
    #[must_use]
    pub const fn new(
        host: CanonicalHost,
        scheme: OriginScheme,
        explicit_port: Option<NonZeroU16>,
        supported_protocols: ProtocolCapabilities,
    ) -> Self {
        Self {
            host,
            scheme,
            explicit_port,
            supported_protocols,
        }
    }

    /// Canonical DNS host.
    #[must_use]
    pub const fn host(&self) -> &CanonicalHost {
        &self.host
    }

    /// Browser origin scheme.
    #[must_use]
    pub const fn scheme(&self) -> OriginScheme {
        self.scheme
    }

    /// Explicit URL port, if present.
    #[must_use]
    pub const fn explicit_port(&self) -> Option<NonZeroU16> {
        self.explicit_port
    }

    /// URL port before HTTPS/SVCB service selection.
    #[must_use]
    pub const fn origin_port(&self) -> NonZeroU16 {
        match self.explicit_port {
            Some(port) => port,
            None => self.scheme.default_port(),
        }
    }

    /// Supported origin protocols.
    #[must_use]
    pub const fn supported_protocols(&self) -> ProtocolCapabilities {
        self.supported_protocols
    }
}

/// Alias mechanism represented by one retained origin-plan step.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AliasKind {
    /// DNS CNAME.
    Cname = 1,
    /// HTTPS/SVCB AliasMode.
    Https = 2,
}

impl AliasKind {
    fn tag(self) -> u8 {
        self as u8
    }
}

/// One canonical alias edge inside a single root lookup.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AliasStep {
    kind: AliasKind,
    owner: CanonicalHost,
    target: CanonicalHost,
}

impl AliasStep {
    /// Creates a non-self-referential alias step.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidPlan`] for a self-alias.
    pub fn new(
        kind: AliasKind,
        owner: CanonicalHost,
        target: CanonicalHost,
    ) -> Result<Self, ValidationError> {
        if owner == target {
            return Err(ValidationError::InvalidPlan);
        }
        Ok(Self {
            kind,
            owner,
            target,
        })
    }

    /// Alias mechanism.
    #[must_use]
    pub const fn kind(&self) -> AliasKind {
        self.kind
    }

    /// Canonical alias owner.
    #[must_use]
    pub const fn owner(&self) -> &CanonicalHost {
        &self.owner
    }

    /// Canonical alias target.
    #[must_use]
    pub const fn target(&self) -> &CanonicalHost {
        &self.target
    }
}

/// Effective service transport for TLSA and origin connection state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ServiceTransport {
    /// TCP.
    Tcp = 1,
    /// UDP, including QUIC.
    Udp = 2,
}

impl ServiceTransport {
    fn tag(self) -> u8 {
        self as u8
    }
}

/// Canonical SVCB parameter retained for equivalence comparison.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServiceParameter {
    key: u16,
    value: Vec<u8>,
}

impl ServiceParameter {
    /// Creates one bounded SVCB parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::BoundExceeded`] for an oversized value.
    pub fn new(key: u16, value: Vec<u8>) -> Result<Self, ValidationError> {
        if value.len() > MAX_PARAMETER_BYTES {
            return Err(ValidationError::BoundExceeded);
        }
        Ok(Self { key, value })
    }

    /// Numeric SVCB key.
    #[must_use]
    pub const fn key(&self) -> u16 {
        self.key
    }

    /// Canonical wire value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Unvalidated service-binding input normalized by [`ServiceBinding::new`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceBindingInput {
    /// Selected HTTPS/SVCB priority, or `None` when no binding applies.
    pub priority: Option<u16>,
    /// Effective ServiceMode target after expanding a root (`.`) TargetName to
    /// the alias-terminal owner.
    pub service_target: CanonicalHost,
    /// Canonical sorted mandatory parameter keys.
    pub mandatory_keys: Vec<u16>,
    /// Raw advertised ALPN identifiers. Implicit scheme defaults are not
    /// inserted into this list.
    pub advertised_alpn: Vec<Vec<u8>>,
    /// Protocol selected from the browser capability set.
    pub selected_protocol: ApplicationProtocol,
    /// Effective origin service port after HTTPS/SVCB selection.
    pub effective_port: NonZeroU16,
    /// Effective service transport.
    pub transport: ServiceTransport,
    /// Connection-used IPv4/IPv6 hints.
    pub connection_hints: Vec<IpAddr>,
    /// Supported ECH configuration used by the connection, if any.
    pub ech_config: Option<Vec<u8>>,
    /// Canonical supported SVCB parameters, including connection-affecting
    /// parameters not represented by a dedicated field.
    pub parameters: Vec<ServiceParameter>,
}

/// Normalized connection-affecting HTTPS/SVCB policy.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ServiceBinding {
    priority: Option<u16>,
    service_target: CanonicalHost,
    mandatory_keys: Vec<u16>,
    advertised_alpn: Vec<Vec<u8>>,
    selected_protocol: ApplicationProtocol,
    effective_port: NonZeroU16,
    transport: ServiceTransport,
    connection_hints: Vec<IpAddr>,
    ech_config: Option<Vec<u8>>,
    parameters: Vec<ServiceParameter>,
}

impl ServiceBinding {
    /// Normalizes and validates one service binding.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::BoundExceeded`] or
    /// [`ValidationError::InvalidPlan`] for malformed or duplicate data.
    pub fn new(mut input: ServiceBindingInput) -> Result<Self, ValidationError> {
        if input.advertised_alpn.len() > MAX_ALPN_IDS
            || input.mandatory_keys.len() > MAX_SERVICE_PARAMETERS
            || input.connection_hints.len() > MAX_ENDPOINTS
            || input.parameters.len() > MAX_SERVICE_PARAMETERS
            || input
                .advertised_alpn
                .iter()
                .any(|id| id.is_empty() || id.len() > MAX_ALPN_ID_BYTES)
            || input
                .ech_config
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_PARAMETER_BYTES)
        {
            return Err(ValidationError::BoundExceeded);
        }
        if !matches!(
            (input.selected_protocol, input.transport),
            (
                ApplicationProtocol::Http11 | ApplicationProtocol::Http2,
                ServiceTransport::Tcp
            ) | (ApplicationProtocol::Http3, ServiceTransport::Udp)
        ) {
            return Err(ValidationError::InvalidPlan);
        }
        if input.priority == Some(0)
            || (input.priority.is_none()
                && (!input.mandatory_keys.is_empty()
                    || !input.advertised_alpn.is_empty()
                    || !input.connection_hints.is_empty()
                    || input.ech_config.is_some()
                    || !input.parameters.is_empty()))
        {
            return Err(ValidationError::InvalidPlan);
        }
        input.mandatory_keys.sort_unstable();
        if input.mandatory_keys.windows(2).any(equal_values)
            || has_duplicate_alpn(&input.advertised_alpn)
        {
            return Err(ValidationError::InvalidPlan);
        }
        input.connection_hints.sort_unstable();
        input.connection_hints.dedup();
        input.parameters.sort_unstable();
        if input.parameters.windows(2).any(|pair| {
            pair.first().map(ServiceParameter::key) == pair.get(1).map(ServiceParameter::key)
        }) || input
            .parameters
            .first()
            .is_some_and(|parameter| parameter.key() == 0)
        {
            return Err(ValidationError::InvalidPlan);
        }
        if input
            .mandatory_keys
            .iter()
            .any(|key| !matches!(key, 1..=6) || !has_service_parameter(&input.parameters, *key))
            || !selected_alpn_is_valid(
                input.selected_protocol,
                &input.advertised_alpn,
                &input.parameters,
            )
            || !known_service_parameters_match(&input)?
        {
            return Err(ValidationError::InvalidPlan);
        }
        Ok(Self {
            priority: input.priority,
            service_target: input.service_target,
            mandatory_keys: input.mandatory_keys,
            advertised_alpn: input.advertised_alpn,
            selected_protocol: input.selected_protocol,
            effective_port: input.effective_port,
            transport: input.transport,
            connection_hints: input.connection_hints,
            ech_config: input.ech_config,
            parameters: input.parameters,
        })
    }

    /// Selected service priority.
    #[must_use]
    pub const fn priority(&self) -> Option<u16> {
        self.priority
    }

    /// Effective endpoint TargetName selected by HTTPS/SVCB ServiceMode.
    #[must_use]
    pub const fn service_target(&self) -> &CanonicalHost {
        &self.service_target
    }

    /// Mandatory SVCB keys.
    #[must_use]
    pub fn mandatory_keys(&self) -> &[u16] {
        &self.mandatory_keys
    }

    /// Raw advertised ALPN identifiers. Implicit scheme defaults are not
    /// inserted into this list.
    #[must_use]
    pub fn advertised_alpn(&self) -> &[Vec<u8>] {
        &self.advertised_alpn
    }

    /// Selected application protocol.
    #[must_use]
    pub const fn selected_protocol(&self) -> ApplicationProtocol {
        self.selected_protocol
    }

    /// Effective service port.
    #[must_use]
    pub const fn effective_port(&self) -> NonZeroU16 {
        self.effective_port
    }

    /// Effective service transport.
    #[must_use]
    pub const fn transport(&self) -> ServiceTransport {
        self.transport
    }

    /// Connection-used address hints.
    #[must_use]
    pub fn connection_hints(&self) -> &[IpAddr] {
        &self.connection_hints
    }

    /// Connection-used ECH configuration.
    #[must_use]
    pub fn ech_config(&self) -> Option<&[u8]> {
        self.ech_config.as_deref()
    }

    /// Canonical supported SVCB parameters.
    #[must_use]
    pub fn parameters(&self) -> &[ServiceParameter] {
        &self.parameters
    }
}

fn equal_values<T: PartialEq>(pair: &[T]) -> bool {
    pair.first() == pair.get(1)
}

fn has_duplicate_alpn(values: &[Vec<u8>]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values.iter().skip(index + 1).any(|other| other == value))
}

fn has_service_parameter(parameters: &[ServiceParameter], key: u16) -> bool {
    parameters.iter().any(|parameter| parameter.key() == key)
}

fn service_parameter(parameters: &[ServiceParameter], key: u16) -> Option<&[u8]> {
    parameters
        .iter()
        .find(|parameter| parameter.key() == key)
        .map(ServiceParameter::value)
}

fn selected_alpn_is_valid(
    selected: ApplicationProtocol,
    advertised: &[Vec<u8>],
    parameters: &[ServiceParameter],
) -> bool {
    let no_default_alpn = service_parameter(parameters, 2).is_some();
    if selected == ApplicationProtocol::Http11 && !no_default_alpn {
        return true;
    }
    advertised.iter().any(|identifier| match selected {
        ApplicationProtocol::Http11 => identifier.as_slice() == b"http/1.1",
        ApplicationProtocol::Http2 => identifier.as_slice() == b"h2",
        ApplicationProtocol::Http3 => {
            identifier.as_slice() == b"h3" || identifier.starts_with(b"h3-")
        }
    })
}

fn known_service_parameters_match(input: &ServiceBindingInput) -> Result<bool, ValidationError> {
    if let Some(value) = service_parameter(&input.parameters, 1) {
        if !alpn_wire_matches(value, &input.advertised_alpn)? {
            return Ok(false);
        }
    } else if !input.advertised_alpn.is_empty() {
        return Ok(false);
    }
    if service_parameter(&input.parameters, 2).is_some_and(|value| !value.is_empty()) {
        return Ok(false);
    }
    if service_parameter(&input.parameters, 3)
        .is_some_and(|value| value != input.effective_port.get().to_be_bytes())
    {
        return Ok(false);
    }
    if service_parameter(&input.parameters, 5) != input.ech_config.as_deref() {
        return Ok(false);
    }
    if service_parameter(&input.parameters, 4)
        .is_some_and(|wire| wire.is_empty() || wire.len() % 4 != 0)
        || service_parameter(&input.parameters, 6)
            .is_some_and(|wire| wire.is_empty() || wire.len() % 16 != 0)
    {
        return Ok(false);
    }
    Ok(input
        .connection_hints
        .iter()
        .all(|hint| service_parameters_contain_hint(&input.parameters, *hint)))
}

fn alpn_wire_matches(wire: &[u8], advertised: &[Vec<u8>]) -> Result<bool, ValidationError> {
    if wire.is_empty() {
        return Err(ValidationError::InvalidPlan);
    }
    let mut offset = 0usize;
    let mut parsed = Vec::new();
    while offset < wire.len() {
        let length = usize::from(*wire.get(offset).ok_or(ValidationError::InvalidPlan)?);
        offset = offset.checked_add(1).ok_or(ValidationError::InvalidPlan)?;
        if length == 0 {
            return Err(ValidationError::InvalidPlan);
        }
        let end = offset
            .checked_add(length)
            .ok_or(ValidationError::InvalidPlan)?;
        let identifier = wire.get(offset..end).ok_or(ValidationError::InvalidPlan)?;
        parsed.push(identifier);
        offset = end;
    }
    Ok(parsed.len() == advertised.len()
        && parsed
            .iter()
            .zip(advertised)
            .all(|(left, right)| *left == right.as_slice()))
}

fn service_parameters_contain_hint(parameters: &[ServiceParameter], hint: IpAddr) -> bool {
    match hint {
        IpAddr::V4(address) => service_parameter(parameters, 4)
            .is_some_and(|wire| wire.chunks_exact(4).any(|chunk| chunk == address.octets())),
        IpAddr::V6(address) => service_parameter(parameters, 6)
            .is_some_and(|wire| wire.chunks_exact(16).any(|chunk| chunk == address.octets())),
    }
}

/// Browser trust action included in convergence comparison.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TlsTrustPolicy {
    /// Origin scheme is cleartext.
    Cleartext = 1,
    /// Secure TLSA data must be enforced.
    Dane = 2,
    /// ICANN TLSA is securely absent, so WebPKI is permitted.
    WebPkiAuthenticatedAbsence = 3,
    /// ICANN delegation is proven insecure, so WebPKI is permitted.
    WebPkiInsecureDelegation = 4,
}

impl TlsTrustPolicy {
    fn tag(self) -> u8 {
        self as u8
    }
}

/// Canonical TLSA RDATA retained for trust comparison.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalTlsa(Vec<u8>);

impl CanonicalTlsa {
    /// Creates one bounded TLSA RDATA value.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidPlan`] unless the record uses the
    /// locally supported DANE-TA/DANE-EE usages, certificate/SPKI selectors,
    /// exact/SHA-256/SHA-512 matching types, and a valid nonempty association
    /// length. Oversized values return [`ValidationError::BoundExceeded`].
    pub fn new(rdata: Vec<u8>) -> Result<Self, ValidationError> {
        if rdata.len() > MAX_PARAMETER_BYTES {
            return Err(ValidationError::BoundExceeded);
        }
        let Some((&usage, remainder)) = rdata.split_first() else {
            return Err(ValidationError::InvalidPlan);
        };
        let Some((&selector, remainder)) = remainder.split_first() else {
            return Err(ValidationError::InvalidPlan);
        };
        let Some((&matching, association)) = remainder.split_first() else {
            return Err(ValidationError::InvalidPlan);
        };
        if !matches!(usage, 2 | 3)
            || !matches!(selector, 0 | 1)
            || !matches!((matching, association.len()), (0, 1..) | (1, 32) | (2, 64))
        {
            return Err(ValidationError::InvalidPlan);
        }
        Ok(Self(rdata))
    }

    /// Canonical TLSA wire RDATA.
    #[must_use]
    pub fn rdata(&self) -> &[u8] {
        &self.0
    }
}

/// DNSSEC state associated with authenticated ICANN DoH provenance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum IcannChainState {
    /// DNSSEC-secure data or denial.
    Secure = 1,
    /// Authenticated validating resolver proved an insecure delegation.
    ProvenInsecure = 2,
}

/// Evidence lineage retained for diagnostics and freshness, but ignored by
/// semantic convergence.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum EvidenceProvenance {
    /// HNS Urkel/header anchor.
    Hns {
        /// Canonical HNS network.
        network: HnsNetwork,
        /// Exact Urkel tree root carried by this resolution's verified proof.
        tree_root: [u8; 32],
        /// Exact canonical block height carried by that proof.
        height: u32,
    },
    /// TLS-authenticated validating ICANN DoH resolver.
    IcannDoh {
        /// Validated DNSSEC chain state.
        chain_state: IcannChainState,
    },
}

impl EvidenceProvenance {
    fn validate_for(&self, namespace: Namespace) -> Result<(), ValidationError> {
        match (namespace, self) {
            (Namespace::Hns, Self::Hns { .. }) | (Namespace::Icann, Self::IcannDoh { .. }) => {
                Ok(())
            }
            _ => Err(ValidationError::InvalidEvidence),
        }
    }

    fn hns_network(&self) -> Option<HnsNetwork> {
        match self {
            Self::Hns { network, .. } => Some(*network),
            Self::IcannDoh { .. } => None,
        }
    }
}

/// Absolute observation and expiry bounds for validated evidence.
///
/// Adapters must retain these timestamps with cached proof/denial evidence.
/// Reading a persisted TTL at a later time must never restart its lifetime.
/// Expiry is the earliest applicable TTL/negative-TTL, DNSSEC signature
/// expiry, HNS anchor-currentness deadline, and adapter lifecycle bound.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Freshness {
    observed_at_unix: u64,
    expires_at_unix: u64,
}

impl Freshness {
    /// Creates a non-empty freshness interval.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidEvidence`] when expiry does not
    /// follow observation time.
    pub const fn new(observed_at_unix: u64, expires_at_unix: u64) -> Result<Self, ValidationError> {
        if expires_at_unix <= observed_at_unix {
            return Err(ValidationError::InvalidEvidence);
        }
        Ok(Self {
            observed_at_unix,
            expires_at_unix,
        })
    }

    /// Evidence observation time.
    #[must_use]
    pub const fn observed_at_unix(self) -> u64 {
        self.observed_at_unix
    }

    /// Exclusive evidence expiry time.
    #[must_use]
    pub const fn expires_at_unix(self) -> u64 {
        self.expires_at_unix
    }

    /// Whether evidence is current at `now_unix`.
    #[must_use]
    pub const fn is_fresh_at(self, now_unix: u64) -> bool {
        now_unix >= self.observed_at_unix && now_unix < self.expires_at_unix
    }
}

/// Unvalidated complete origin plan normalized by
/// [`ValidatedOriginPlan::new`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginPlanInput {
    /// Root that independently produced every field.
    pub namespace: Namespace,
    /// Complete browser origin query this plan answers.
    pub query: OriginQuery,
    /// Bounded internally coherent alias chain.
    pub alias_path: Vec<AliasStep>,
    /// Terminal HTTPS/SVCB owner after origin CNAME and AliasMode processing.
    pub terminal_target: CanonicalHost,
    /// CNAME chain followed from the normalized HTTPS/SVCB ServiceMode
    /// TargetName to the final address owner.
    pub endpoint_alias_path: Vec<AliasStep>,
    /// Final canonical owner whose A/AAAA data produced `endpoints`.
    pub endpoint_target: CanonicalHost,
    /// Usable selected-root endpoints.
    pub endpoints: Vec<SocketAddr>,
    /// Selected service binding.
    pub service: ServiceBinding,
    /// Browser TLS action.
    pub tls_policy: TlsTrustPolicy,
    /// Canonical effective-service TLSA data.
    pub tlsa_records: Vec<CanonicalTlsa>,
    /// Authenticated evidence lineage.
    pub provenance: EvidenceProvenance,
    /// Earliest absolute evidence freshness bound.
    pub freshness: Freshness,
}

/// One complete, internally coherent origin plan from exactly one root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedOriginPlan {
    namespace: Namespace,
    query: OriginQuery,
    alias_path: Vec<AliasStep>,
    terminal_target: CanonicalHost,
    endpoint_alias_path: Vec<AliasStep>,
    endpoint_target: CanonicalHost,
    endpoints: Vec<SocketAddr>,
    service: ServiceBinding,
    tls_policy: TlsTrustPolicy,
    tlsa_records: Vec<CanonicalTlsa>,
    provenance: EvidenceProvenance,
    freshness: Freshness,
}

impl ValidatedOriginPlan {
    /// Validates and canonicalizes one single-root origin plan.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] for cross-root provenance, alias
    /// discontinuity/cycles, endpoint/service mismatch, unsupported trust
    /// combinations, duplicates outside bounds, or missing DANE TLSA data.
    pub fn new(mut input: OriginPlanInput) -> Result<Self, ValidationError> {
        input.provenance.validate_for(input.namespace)?;
        if input.alias_path.len() > MAX_ALIAS_STEPS
            || input.endpoint_alias_path.len() > MAX_ALIAS_STEPS
            || input.endpoints.is_empty()
            || input.endpoints.len() > MAX_ENDPOINTS
            || input.tlsa_records.len() > MAX_TLSA_RECORDS
        {
            return Err(ValidationError::BoundExceeded);
        }
        validate_plan_aliases(&input)?;
        input.endpoints.sort_unstable();
        input.endpoints.dedup();
        validate_plan_endpoints_and_service(&input)?;
        input.tlsa_records.sort_unstable();
        input.tlsa_records.dedup();
        validate_plan_tls(&input)?;
        Ok(Self {
            namespace: input.namespace,
            query: input.query,
            alias_path: input.alias_path,
            terminal_target: input.terminal_target,
            endpoint_alias_path: input.endpoint_alias_path,
            endpoint_target: input.endpoint_target,
            endpoints: input.endpoints,
            service: input.service,
            tls_policy: input.tls_policy,
            tlsa_records: input.tlsa_records,
            provenance: input.provenance,
            freshness: input.freshness,
        })
    }

    /// Root that produced this complete plan.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Complete browser origin query.
    #[must_use]
    pub const fn query(&self) -> &OriginQuery {
        &self.query
    }

    /// Browser origin host.
    #[must_use]
    pub const fn origin_host(&self) -> &CanonicalHost {
        self.query.host()
    }

    /// Retained alias path.
    #[must_use]
    pub fn alias_path(&self) -> &[AliasStep] {
        &self.alias_path
    }

    /// Terminal canonical service target.
    #[must_use]
    pub const fn terminal_target(&self) -> &CanonicalHost {
        &self.terminal_target
    }

    /// CNAME path from the service TargetName to the final address owner.
    #[must_use]
    pub fn endpoint_alias_path(&self) -> &[AliasStep] {
        &self.endpoint_alias_path
    }

    /// Final canonical A/AAAA owner.
    #[must_use]
    pub const fn endpoint_target(&self) -> &CanonicalHost {
        &self.endpoint_target
    }

    /// Sorted, deduplicated usable endpoint set.
    #[must_use]
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }

    /// Selected HTTPS/SVCB service state.
    #[must_use]
    pub const fn service(&self) -> &ServiceBinding {
        &self.service
    }

    /// Browser trust action.
    #[must_use]
    pub const fn tls_policy(&self) -> TlsTrustPolicy {
        self.tls_policy
    }

    /// Canonical sorted TLSA RDATA.
    #[must_use]
    pub fn tlsa_records(&self) -> &[CanonicalTlsa] {
        &self.tlsa_records
    }

    /// Authenticated evidence lineage.
    #[must_use]
    pub const fn provenance(&self) -> &EvidenceProvenance {
        &self.provenance
    }

    /// Earliest evidence freshness bound.
    #[must_use]
    pub const fn freshness(&self) -> Freshness {
        self.freshness
    }

    /// Connection/trust differences from another complete plan.
    ///
    /// Provenance, TTL-derived expiry, proof encoding, record order, resolver
    /// identity, and namespace identity do not create divergence.
    #[must_use]
    pub fn differences(&self, other: &Self) -> DivergenceMask {
        let mut mask = DivergenceMask::NONE;
        mask.set_if(Self::ORIGIN_QUERY_BIT, self.query != other.query);
        mask.set_if(Self::ALIAS_PATH_BIT, self.alias_path != other.alias_path);
        mask.set_if(
            Self::TERMINAL_TARGET_BIT,
            self.terminal_target != other.terminal_target,
        );
        mask.set_if(Self::ENDPOINTS_BIT, self.endpoints != other.endpoints);
        mask.set_if(
            Self::SERVICE_PRIORITY_BIT,
            self.service.priority != other.service.priority,
        );
        mask.set_if(
            Self::SERVICE_TARGET_BIT,
            self.service.service_target != other.service.service_target,
        );
        mask.set_if(
            Self::ENDPOINT_ALIAS_PATH_BIT,
            self.endpoint_alias_path != other.endpoint_alias_path,
        );
        mask.set_if(
            Self::ENDPOINT_TARGET_BIT,
            self.endpoint_target != other.endpoint_target,
        );
        mask.set_if(
            Self::MANDATORY_PARAMETERS_BIT,
            self.service.mandatory_keys != other.service.mandatory_keys,
        );
        mask.set_if(
            Self::ALPN_BIT,
            self.service.advertised_alpn != other.service.advertised_alpn,
        );
        mask.set_if(
            Self::APPLICATION_PROTOCOL_BIT,
            self.service.selected_protocol != other.service.selected_protocol,
        );
        mask.set_if(
            Self::EFFECTIVE_PORT_BIT,
            self.service.effective_port != other.service.effective_port,
        );
        mask.set_if(
            Self::TRANSPORT_BIT,
            self.service.transport != other.service.transport,
        );
        mask.set_if(
            Self::CONNECTION_HINTS_BIT,
            self.service.connection_hints != other.service.connection_hints,
        );
        mask.set_if(
            Self::ECH_BIT,
            self.service.ech_config != other.service.ech_config,
        );
        mask.set_if(
            Self::SERVICE_PARAMETERS_BIT,
            self.service.parameters != other.service.parameters,
        );
        mask.set_if(Self::TLS_POLICY_BIT, self.tls_policy != other.tls_policy);
        mask.set_if(Self::TLSA_BIT, self.tlsa_records != other.tlsa_records);
        mask
    }

    /// Whether every connection- and trust-affecting field converges.
    #[must_use]
    pub fn equivalent_to(&self, other: &Self) -> bool {
        self.differences(other).is_empty()
    }

    const ORIGIN_QUERY_BIT: u32 = 1 << 0;
    const ALIAS_PATH_BIT: u32 = 1 << 1;
    const TERMINAL_TARGET_BIT: u32 = 1 << 2;
    const ENDPOINTS_BIT: u32 = 1 << 3;
    const SERVICE_PRIORITY_BIT: u32 = 1 << 4;
    const SERVICE_TARGET_BIT: u32 = 1 << 5;
    const ENDPOINT_ALIAS_PATH_BIT: u32 = 1 << 6;
    const ENDPOINT_TARGET_BIT: u32 = 1 << 7;
    const MANDATORY_PARAMETERS_BIT: u32 = 1 << 8;
    const ALPN_BIT: u32 = 1 << 9;
    const APPLICATION_PROTOCOL_BIT: u32 = 1 << 10;
    const EFFECTIVE_PORT_BIT: u32 = 1 << 11;
    const TRANSPORT_BIT: u32 = 1 << 12;
    const CONNECTION_HINTS_BIT: u32 = 1 << 13;
    const ECH_BIT: u32 = 1 << 14;
    const SERVICE_PARAMETERS_BIT: u32 = 1 << 15;
    const TLS_POLICY_BIT: u32 = 1 << 16;
    const TLSA_BIT: u32 = 1 << 17;
}

fn validate_plan_aliases(input: &OriginPlanInput) -> Result<(), ValidationError> {
    validate_alias_path(
        input.query.host(),
        &input.alias_path,
        &input.terminal_target,
    )?;
    if input
        .endpoint_alias_path
        .iter()
        .any(|alias| alias.kind() != AliasKind::Cname)
    {
        return Err(ValidationError::InvalidPlan);
    }
    validate_alias_path(
        input.service.service_target(),
        &input.endpoint_alias_path,
        &input.endpoint_target,
    )?;

    let mut seen = vec![input.query.host()];
    for alias in &input.alias_path {
        seen.push(alias.target());
    }
    if input.service.service_target() != &input.terminal_target
        && seen.contains(&input.service.service_target())
    {
        return Err(ValidationError::InvalidPlan);
    }
    if !seen.contains(&input.service.service_target()) {
        seen.push(input.service.service_target());
    }
    for alias in &input.endpoint_alias_path {
        if seen.contains(&alias.target()) {
            return Err(ValidationError::InvalidPlan);
        }
        seen.push(alias.target());
    }
    Ok(())
}

fn validate_plan_endpoints_and_service(input: &OriginPlanInput) -> Result<(), ValidationError> {
    let endpoint_mismatch = input.endpoints.len() > MAX_ENDPOINTS
        || input
            .endpoints
            .iter()
            .any(|endpoint| endpoint.port() != input.service.effective_port().get())
        || input.service.connection_hints().iter().any(|hint| {
            !input
                .endpoints
                .iter()
                .any(|endpoint| endpoint.ip() == *hint)
        });
    let query_mismatch = !input
        .query
        .supported_protocols()
        .supports(input.service.selected_protocol())
        || (!input.query.scheme().uses_tls()
            && (input.service.priority().is_some()
                || input.service.selected_protocol() != ApplicationProtocol::Http11
                || input.service.transport() != ServiceTransport::Tcp))
        || (input.query.scheme().uses_tls() && input.tls_policy == TlsTrustPolicy::Cleartext)
        || (!input.query.scheme().uses_tls() && input.tls_policy != TlsTrustPolicy::Cleartext)
        || (input.service.priority().is_none()
            && (input.service.service_target() != &input.terminal_target
                || input.service.effective_port() != input.query.origin_port()))
        || (input.service.priority().is_some()
            && !has_service_parameter(input.service.parameters(), 3)
            && input.service.effective_port() != input.query.origin_port());
    if endpoint_mismatch || query_mismatch {
        Err(ValidationError::InvalidPlan)
    } else {
        Ok(())
    }
}

fn validate_plan_tls(input: &OriginPlanInput) -> Result<(), ValidationError> {
    let invalid_records = match input.tls_policy {
        TlsTrustPolicy::Dane => input.tlsa_records.is_empty(),
        TlsTrustPolicy::Cleartext
        | TlsTrustPolicy::WebPkiAuthenticatedAbsence
        | TlsTrustPolicy::WebPkiInsecureDelegation => !input.tlsa_records.is_empty(),
    };
    if invalid_records
        || (input.namespace == Namespace::Hns
            && matches!(
                input.tls_policy,
                TlsTrustPolicy::WebPkiAuthenticatedAbsence
                    | TlsTrustPolicy::WebPkiInsecureDelegation
            ))
    {
        return Err(ValidationError::InvalidPlan);
    }
    match (&input.provenance, input.tls_policy) {
        (
            EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
            TlsTrustPolicy::Dane | TlsTrustPolicy::WebPkiAuthenticatedAbsence,
        )
        | (
            EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::ProvenInsecure,
            },
            TlsTrustPolicy::WebPkiInsecureDelegation,
        )
        | (EvidenceProvenance::Hns { .. }, TlsTrustPolicy::Dane)
        | (_, TlsTrustPolicy::Cleartext) => Ok(()),
        _ => Err(ValidationError::InvalidEvidence),
    }
}

fn validate_alias_path(
    origin_host: &CanonicalHost,
    aliases: &[AliasStep],
    terminal_target: &CanonicalHost,
) -> Result<(), ValidationError> {
    let mut expected_owner = origin_host;
    let mut seen = vec![origin_host];
    for alias in aliases {
        if alias.owner() != expected_owner || seen.contains(&alias.target()) {
            return Err(ValidationError::InvalidPlan);
        }
        seen.push(alias.target());
        expected_owner = alias.target();
    }
    if expected_owner != terminal_target {
        return Err(ValidationError::InvalidPlan);
    }
    Ok(())
}

/// Authenticated reason that one root has no usable origin plan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AbsenceKind {
    /// Current canonical HNS Urkel non-inclusion.
    HnsCurrentUrkelNonInclusion = 1,
    /// DNSSEC-authenticated NXDOMAIN.
    DnssecAuthenticatedNxDomain = 2,
    /// DNSSEC-authenticated name with no usable browser endpoint.
    DnssecAuthenticatedNoUsableEndpoint = 3,
    /// Insecure ICANN NXDOMAIN received from the authenticated validating DoH
    /// resolver.
    IcannInsecureNxDomain = 4,
    /// Insecure ICANN name with no usable endpoint, received from the
    /// authenticated validating DoH resolver.
    IcannInsecureNoUsableEndpoint = 5,
}

impl AbsenceKind {
    fn tag(self) -> u8 {
        self as u8
    }
}

/// Typed authenticated absence from one root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAbsence {
    namespace: Namespace,
    query: OriginQuery,
    kind: AbsenceKind,
    provenance: EvidenceProvenance,
    freshness: Freshness,
}

impl ValidatedAbsence {
    /// Creates absence evidence valid for exactly one root and complete origin
    /// query.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidEvidence`] for a cross-root kind or
    /// provenance mismatch.
    pub fn new(
        namespace: Namespace,
        query: OriginQuery,
        kind: AbsenceKind,
        provenance: EvidenceProvenance,
        freshness: Freshness,
    ) -> Result<Self, ValidationError> {
        provenance.validate_for(namespace)?;
        match (namespace, kind, &provenance) {
            (
                Namespace::Hns,
                AbsenceKind::HnsCurrentUrkelNonInclusion
                | AbsenceKind::DnssecAuthenticatedNxDomain
                | AbsenceKind::DnssecAuthenticatedNoUsableEndpoint,
                EvidenceProvenance::Hns { .. },
            )
            | (
                Namespace::Icann,
                AbsenceKind::DnssecAuthenticatedNxDomain
                | AbsenceKind::DnssecAuthenticatedNoUsableEndpoint,
                EvidenceProvenance::IcannDoh {
                    chain_state: IcannChainState::Secure,
                    ..
                },
            )
            | (
                Namespace::Icann,
                AbsenceKind::IcannInsecureNxDomain | AbsenceKind::IcannInsecureNoUsableEndpoint,
                EvidenceProvenance::IcannDoh {
                    chain_state: IcannChainState::ProvenInsecure,
                    ..
                },
            ) => {}
            _ => return Err(ValidationError::InvalidEvidence),
        }
        Ok(Self {
            namespace,
            query,
            kind,
            provenance,
            freshness,
        })
    }

    /// Root whose absence was authenticated.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Complete origin query whose plan is absent.
    #[must_use]
    pub const fn query(&self) -> &OriginQuery {
        &self.query
    }

    /// Queried complete hostname.
    #[must_use]
    pub const fn host(&self) -> &CanonicalHost {
        self.query.host()
    }

    /// Typed absence reason.
    #[must_use]
    pub const fn kind(&self) -> AbsenceKind {
        self.kind
    }

    /// Authenticated evidence lineage.
    #[must_use]
    pub const fn provenance(&self) -> &EvidenceProvenance {
        &self.provenance
    }

    /// Earliest evidence freshness bound.
    #[must_use]
    pub const fn freshness(&self) -> Freshness {
        self.freshness
    }
}

/// Fail-closed reason that one root did not produce presence or authenticated
/// absence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RootFailureKind {
    /// Lookup deadline elapsed.
    Timeout = 1,
    /// Network transport failed.
    Transport = 2,
    /// HNS anchor is unavailable or stale.
    StaleHnsAnchor = 3,
    /// DNSSEC validation is bogus.
    BogusDnssec = 4,
    /// DNSSEC state is indeterminate.
    IndeterminateDnssec = 5,
    /// Configured validating resolver was not authenticated.
    UnauthenticatedResolver = 6,
    /// Response was malformed or internally contradictory.
    MalformedResponse = 7,
    /// Required protocol feature is unsupported.
    Unsupported = 8,
    /// Work was cancelled by a newer lifecycle generation.
    Cancelled = 9,
    /// Internal adapter failure.
    Internal = 10,
    /// Otherwise valid root evidence expired before classification completed.
    StaleEvidence = 11,
}

/// Typed failure from one independent root lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootFailure {
    namespace: Namespace,
    query: OriginQuery,
    kind: RootFailureKind,
    retry_after_unix: Option<u64>,
}

impl RootFailure {
    /// Creates one root-scoped failure.
    #[must_use]
    pub const fn new(
        namespace: Namespace,
        query: OriginQuery,
        kind: RootFailureKind,
        retry_after_unix: Option<u64>,
    ) -> Self {
        Self {
            namespace,
            query,
            kind,
            retry_after_unix,
        }
    }

    /// Failed root.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Complete origin query whose lookup failed.
    #[must_use]
    pub const fn query(&self) -> &OriginQuery {
        &self.query
    }

    /// Queried complete hostname.
    #[must_use]
    pub const fn host(&self) -> &CanonicalHost {
        self.query.host()
    }

    /// Typed failure reason.
    #[must_use]
    pub const fn kind(&self) -> RootFailureKind {
        self.kind
    }

    /// Optional backoff deadline. This never converts the failure into a
    /// negative answer.
    #[must_use]
    pub const fn retry_after_unix(&self) -> Option<u64> {
        self.retry_after_unix
    }
}

/// Independent result from exactly one root.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "lookups are short-lived validated values and keeping the public adapter API allocation-free is intentional"
)]
pub enum RootLookup {
    /// Complete validated plan exists.
    Present(ValidatedOriginPlan),
    /// Complete hostname is authentically absent or has no usable endpoint.
    Absent(ValidatedAbsence),
    /// Lookup is indeterminate and classification must fail closed.
    Failed(RootFailure),
}

/// Bounded, copyable disposition of one root lookup.
///
/// This deliberately reports only whether the complete lookup was present,
/// authentically absent, or failed. It never retains a validated origin plan
/// or authenticated-absence proof.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RootResolutionDisposition {
    /// The complete origin had a validated resolution plan.
    Present = 1,
    /// The complete origin was authentically absent or had no usable endpoint.
    Absent = 2,
    /// The lookup failed and classification remained indeterminate.
    Failed = 3,
}

/// Bounded diagnostic state retained when dual-root classification fails.
///
/// Successful lookups are reduced to a copyable disposition so an error never
/// duplicates a validated origin plan or authenticated-absence proof. Failed
/// lookups retain their typed [`RootFailure`] for safe, root-specific
/// diagnostics and retry policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootResolutionState {
    /// The complete origin had a validated resolution plan.
    Present,
    /// The complete origin was authentically absent or had no usable endpoint.
    Absent,
    /// The lookup failed and classification remained indeterminate.
    Failed(RootFailure),
}

impl RootResolutionState {
    fn from_lookup(lookup: &RootLookup) -> Self {
        match lookup {
            RootLookup::Present(_) => Self::Present,
            RootLookup::Absent(_) => Self::Absent,
            RootLookup::Failed(failure) => Self::Failed(failure.clone()),
        }
    }

    /// Returns the copyable lookup disposition.
    #[must_use]
    pub const fn disposition(&self) -> RootResolutionDisposition {
        match self {
            Self::Present => RootResolutionDisposition::Present,
            Self::Absent => RootResolutionDisposition::Absent,
            Self::Failed(_) => RootResolutionDisposition::Failed,
        }
    }

    /// Returns the typed root failure, if this lookup failed.
    #[must_use]
    pub const fn failure(&self) -> Option<&RootFailure> {
        match self {
            Self::Failed(failure) => Some(failure),
            Self::Present | Self::Absent => None,
        }
    }

    /// Reports whether this lookup failed.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

impl fmt::Display for RootResolutionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Present => formatter.write_str("present"),
            Self::Absent => formatter.write_str("absent"),
            Self::Failed(failure) => write!(formatter, "failed ({:?})", failure.kind()),
        }
    }
}

/// Behavior when both valid plans diverge and no pin/binding exists.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum DefaultPrecedence {
    /// Required first-use ICANN default.
    PreferIcann = 1,
    /// Require an explicit pin instead of selecting either plan.
    FailClosed = 2,
}

impl DefaultPrecedence {
    fn tag(self) -> u8 {
        self as u8
    }
}

/// Per-origin selection inputs supplied by a browser profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SelectionPolicy {
    explicit_pin: Option<Namespace>,
    sticky_binding: Option<Namespace>,
    default_precedence: DefaultPrecedence,
    revision: u64,
}

impl SelectionPolicy {
    /// Creates a selection policy without a pin or previous binding.
    #[must_use]
    pub const fn new(default_precedence: DefaultPrecedence, revision: u64) -> Self {
        Self {
            explicit_pin: None,
            sticky_binding: None,
            default_precedence,
            revision,
        }
    }

    /// Adds the exact origin's explicit user pin.
    #[must_use]
    pub const fn with_explicit_pin(mut self, namespace: Option<Namespace>) -> Self {
        self.explicit_pin = namespace;
        self
    }

    /// Adds the exact origin's last successful persistent binding.
    #[must_use]
    pub const fn with_sticky_binding(mut self, namespace: Option<Namespace>) -> Self {
        self.sticky_binding = namespace;
        self
    }

    /// Explicit pin.
    #[must_use]
    pub const fn explicit_pin(self) -> Option<Namespace> {
        self.explicit_pin
    }

    /// Last successful persistent binding.
    #[must_use]
    pub const fn sticky_binding(self) -> Option<Namespace> {
        self.sticky_binding
    }

    /// Default divergence precedence.
    #[must_use]
    pub const fn default_precedence(self) -> DefaultPrecedence {
        self.default_precedence
    }

    /// Profile binding/policy revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }
}

impl Default for SelectionPolicy {
    fn default() -> Self {
        Self::new(DefaultPrecedence::PreferIcann, 0)
    }
}

/// Reason the selected namespace won precedence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SelectionReason {
    /// Only one root produced a valid plan.
    SingleRoot = 1,
    /// Explicit per-origin user pin.
    ExplicitPin = 2,
    /// Persistent successful per-origin binding.
    StickyBinding = 3,
    /// First-use ICANN default.
    IcannDefault = 4,
}

impl SelectionReason {
    fn tag(self) -> u8 {
        self as u8
    }
}

/// Bit mask describing connection/trust differences between two valid plans.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DivergenceMask(u32);

impl DivergenceMask {
    /// No connection/trust differences.
    pub const NONE: Self = Self(0);
    /// Complete origin query differs.
    pub const ORIGIN_QUERY: Self = Self(ValidatedOriginPlan::ORIGIN_QUERY_BIT);
    /// Alias path differs.
    pub const ALIAS_PATH: Self = Self(ValidatedOriginPlan::ALIAS_PATH_BIT);
    /// Terminal target differs.
    pub const TERMINAL_TARGET: Self = Self(ValidatedOriginPlan::TERMINAL_TARGET_BIT);
    /// Usable endpoint set differs.
    pub const ENDPOINTS: Self = Self(ValidatedOriginPlan::ENDPOINTS_BIT);
    /// HTTPS/SVCB priority differs.
    pub const SERVICE_PRIORITY: Self = Self(ValidatedOriginPlan::SERVICE_PRIORITY_BIT);
    /// Effective HTTPS/SVCB ServiceMode target differs.
    pub const SERVICE_TARGET: Self = Self(ValidatedOriginPlan::SERVICE_TARGET_BIT);
    /// CNAME path from service target to address owner differs.
    pub const ENDPOINT_ALIAS_PATH: Self = Self(ValidatedOriginPlan::ENDPOINT_ALIAS_PATH_BIT);
    /// Final A/AAAA owner differs.
    pub const ENDPOINT_TARGET: Self = Self(ValidatedOriginPlan::ENDPOINT_TARGET_BIT);
    /// Mandatory SVCB keys differ.
    pub const MANDATORY_PARAMETERS: Self = Self(ValidatedOriginPlan::MANDATORY_PARAMETERS_BIT);
    /// Advertised ALPN differs.
    pub const ALPN: Self = Self(ValidatedOriginPlan::ALPN_BIT);
    /// Selected application protocol differs.
    pub const APPLICATION_PROTOCOL: Self = Self(ValidatedOriginPlan::APPLICATION_PROTOCOL_BIT);
    /// Effective port differs.
    pub const EFFECTIVE_PORT: Self = Self(ValidatedOriginPlan::EFFECTIVE_PORT_BIT);
    /// Effective transport differs.
    pub const TRANSPORT: Self = Self(ValidatedOriginPlan::TRANSPORT_BIT);
    /// Connection-used address hints differ.
    pub const CONNECTION_HINTS: Self = Self(ValidatedOriginPlan::CONNECTION_HINTS_BIT);
    /// ECH configuration differs.
    pub const ECH: Self = Self(ValidatedOriginPlan::ECH_BIT);
    /// Other supported SVCB parameters differ.
    pub const SERVICE_PARAMETERS: Self = Self(ValidatedOriginPlan::SERVICE_PARAMETERS_BIT);
    /// Browser trust action differs.
    pub const TLS_POLICY: Self = Self(ValidatedOriginPlan::TLS_POLICY_BIT);
    /// Canonical TLSA RDATA differs.
    pub const TLSA: Self = Self(ValidatedOriginPlan::TLSA_BIT);

    /// Raw stable mask bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether no difference is present.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether every bit in `other` is present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn set_if(&mut self, bit: u32, condition: bool) {
        if condition {
            self.0 |= bit;
        }
    }
}

/// Authoritative five-way dual-root outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "outcomes retain complete evidence from both roots for diagnostics and freshness"
)]
pub enum NamespaceOutcome {
    /// Only HNS has a valid plan.
    HnsOnly {
        /// Selected HNS plan.
        plan: ValidatedOriginPlan,
        /// Authenticated ICANN absence.
        icann_absence: ValidatedAbsence,
        /// Pin, binding, or single-root reason for the selection.
        selection_reason: SelectionReason,
    },
    /// Only ICANN has a valid plan.
    IcannOnly {
        /// Selected ICANN plan.
        plan: ValidatedOriginPlan,
        /// Authenticated HNS absence.
        hns_absence: ValidatedAbsence,
        /// Pin, binding, or single-root reason for the selection.
        selection_reason: SelectionReason,
    },
    /// Both roots produce the same connection/trust behavior.
    BothConvergent {
        /// Namespace whose plan is used.
        selected: Namespace,
        /// Precedence source used for the selected root identity.
        selection_reason: SelectionReason,
        /// Complete HNS plan.
        hns: ValidatedOriginPlan,
        /// Complete ICANN plan.
        icann: ValidatedOriginPlan,
    },
    /// Both roots produce different valid plans.
    BothDivergent {
        /// Namespace selected by explicit precedence.
        selected: Namespace,
        /// Precedence source.
        selection_reason: SelectionReason,
        /// Complete HNS plan.
        hns: ValidatedOriginPlan,
        /// Complete ICANN plan.
        icann: ValidatedOriginPlan,
        /// Exact semantic differences.
        differences: DivergenceMask,
    },
    /// Both roots authentically lack a usable origin.
    Neither {
        /// Authenticated HNS absence.
        hns: ValidatedAbsence,
        /// Authenticated ICANN absence.
        icann: ValidatedAbsence,
    },
}

/// Stable outcome discriminator for status and cache schemas.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum OutcomeKind {
    /// HNS only.
    HnsOnly = 1,
    /// ICANN only.
    IcannOnly = 2,
    /// Both roots converge.
    BothConvergent = 3,
    /// Both roots diverge.
    BothDivergent = 4,
    /// Neither root has a usable origin.
    Neither = 5,
}

impl NamespaceOutcome {
    /// Stable five-way outcome kind.
    #[must_use]
    pub const fn kind(&self) -> OutcomeKind {
        match self {
            Self::HnsOnly { .. } => OutcomeKind::HnsOnly,
            Self::IcannOnly { .. } => OutcomeKind::IcannOnly,
            Self::BothConvergent { .. } => OutcomeKind::BothConvergent,
            Self::BothDivergent { .. } => OutcomeKind::BothDivergent,
            Self::Neither { .. } => OutcomeKind::Neither,
        }
    }

    /// Selected namespace, or `None` for `Neither`.
    #[must_use]
    pub const fn selected_namespace(&self) -> Option<Namespace> {
        match self {
            Self::HnsOnly { .. } => Some(Namespace::Hns),
            Self::IcannOnly { .. } => Some(Namespace::Icann),
            Self::BothConvergent { selected, .. } | Self::BothDivergent { selected, .. } => {
                Some(*selected)
            }
            Self::Neither { .. } => None,
        }
    }

    /// Selection source, or `None` for `Neither`.
    #[must_use]
    pub const fn selection_reason(&self) -> Option<SelectionReason> {
        match self {
            Self::HnsOnly {
                selection_reason, ..
            }
            | Self::IcannOnly {
                selection_reason, ..
            }
            | Self::BothConvergent {
                selection_reason, ..
            }
            | Self::BothDivergent {
                selection_reason, ..
            } => Some(*selection_reason),
            Self::Neither { .. } => None,
        }
    }

    /// Selected complete plan, or `None` for `Neither`.
    #[must_use]
    pub const fn selected_plan(&self) -> Option<&ValidatedOriginPlan> {
        match self {
            Self::HnsOnly { plan, .. } | Self::IcannOnly { plan, .. } => Some(plan),
            Self::BothConvergent {
                selected,
                hns,
                icann,
                ..
            }
            | Self::BothDivergent {
                selected,
                hns,
                icann,
                ..
            } => match selected {
                Namespace::Hns => Some(hns),
                Namespace::Icann => Some(icann),
            },
            Self::Neither { .. } => None,
        }
    }

    /// Divergence mask for `BothDivergent`.
    #[must_use]
    pub const fn divergence(&self) -> Option<DivergenceMask> {
        match self {
            Self::BothDivergent { differences, .. } => Some(*differences),
            _ => None,
        }
    }

    fn hns_network(&self) -> HnsNetwork {
        let provenance = match self {
            Self::HnsOnly { plan, .. }
            | Self::BothConvergent { hns: plan, .. }
            | Self::BothDivergent { hns: plan, .. } => plan.provenance(),
            Self::IcannOnly { hns_absence, .. } => hns_absence.provenance(),
            Self::Neither { hns, .. } => hns.provenance(),
        };
        provenance
            .hns_network()
            .unwrap_or_else(|| unreachable!("validated HNS evidence always carries an HNS network"))
    }

    /// Earliest expiry across both roots' retained decision evidence.
    #[must_use]
    pub fn expires_at_unix(&self) -> u64 {
        match self {
            Self::HnsOnly {
                plan,
                icann_absence,
                ..
            } => plan
                .freshness()
                .expires_at_unix()
                .min(icann_absence.freshness().expires_at_unix()),
            Self::IcannOnly {
                plan, hns_absence, ..
            } => plan
                .freshness()
                .expires_at_unix()
                .min(hns_absence.freshness().expires_at_unix()),
            Self::BothConvergent { hns, icann, .. } | Self::BothDivergent { hns, icann, .. } => hns
                .freshness()
                .expires_at_unix()
                .min(icann.freshness().expires_at_unix()),
            Self::Neither { hns, icann } => hns
                .freshness()
                .expires_at_unix()
                .min(icann.freshness().expires_at_unix()),
        }
    }

    /// Whether every retained evidence item is fresh at `now_unix`.
    #[must_use]
    pub fn is_fresh_at(&self, now_unix: u64) -> bool {
        now_unix < self.expires_at_unix()
            && match self {
                Self::HnsOnly {
                    plan,
                    icann_absence,
                    ..
                } => {
                    plan.freshness().is_fresh_at(now_unix)
                        && icann_absence.freshness().is_fresh_at(now_unix)
                }
                Self::IcannOnly {
                    plan, hns_absence, ..
                } => {
                    plan.freshness().is_fresh_at(now_unix)
                        && hns_absence.freshness().is_fresh_at(now_unix)
                }
                Self::BothConvergent { hns, icann, .. }
                | Self::BothDivergent { hns, icann, .. } => {
                    hns.freshness().is_fresh_at(now_unix) && icann.freshness().is_fresh_at(now_unix)
                }
                Self::Neither { hns, icann } => {
                    hns.freshness().is_fresh_at(now_unix) && icann.freshness().is_fresh_at(now_unix)
                }
            }
    }
}

/// Query- and policy-bound authoritative namespace decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceDecision {
    query: OriginQuery,
    policy: SelectionPolicy,
    outcome: NamespaceOutcome,
}

impl NamespaceDecision {
    /// Exact origin query classified through both roots.
    #[must_use]
    pub const fn query(&self) -> &OriginQuery {
        &self.query
    }

    /// Exact policy snapshot that produced this decision.
    #[must_use]
    pub const fn policy(&self) -> SelectionPolicy {
        self.policy
    }

    /// Five-way authoritative outcome.
    #[must_use]
    pub const fn outcome(&self) -> &NamespaceOutcome {
        &self.outcome
    }

    /// Stable five-way outcome kind.
    #[must_use]
    pub const fn kind(&self) -> OutcomeKind {
        self.outcome.kind()
    }

    /// Selected namespace, or `None` for `Neither`.
    #[must_use]
    pub const fn selected_namespace(&self) -> Option<Namespace> {
        self.outcome.selected_namespace()
    }

    /// Selection source, or `None` for `Neither`.
    #[must_use]
    pub const fn selection_reason(&self) -> Option<SelectionReason> {
        self.outcome.selection_reason()
    }

    /// Selected complete single-root plan, or `None` for `Neither`.
    #[must_use]
    pub const fn selected_plan(&self) -> Option<&ValidatedOriginPlan> {
        self.outcome.selected_plan()
    }

    /// Divergence mask for a divergent outcome.
    #[must_use]
    pub const fn divergence(&self) -> Option<DivergenceMask> {
        self.outcome.divergence()
    }

    /// Canonical HNS network carried by the exact retained lookup evidence.
    #[must_use]
    pub fn hns_network(&self) -> HnsNetwork {
        self.outcome.hns_network()
    }

    /// Earliest absolute expiry across both roots.
    #[must_use]
    pub fn expires_at_unix(&self) -> u64 {
        self.outcome.expires_at_unix()
    }

    /// Whether every retained evidence item is fresh.
    #[must_use]
    pub fn is_fresh_at(&self, now_unix: u64) -> bool {
        self.outcome.is_fresh_at(now_unix)
    }
}

/// Applies the five-way classification and explicit divergence precedence.
///
/// Both root lookups must already be complete and independently validated.
/// A failure from either root makes the result indeterminate and returns
/// [`ClassificationError::RootFailed`]. Stale evidence is rejected at this
/// boundary rather than being left for callers to remember to check.
///
/// # Errors
///
/// Returns a [`ClassificationError`] for failed roots, mismatched query
/// evidence, stale evidence, or fail-closed divergence policy without a
/// pin/binding.
pub fn decide_namespace(
    query: &OriginQuery,
    hns: RootLookup,
    icann: RootLookup,
    policy: SelectionPolicy,
    now_unix: u64,
) -> Result<NamespaceDecision, ClassificationError> {
    validate_lookup(query, Namespace::Hns, &hns, now_unix)?;
    validate_lookup(query, Namespace::Icann, &icann, now_unix)?;

    if matches!(&hns, RootLookup::Failed(_)) || matches!(&icann, RootLookup::Failed(_)) {
        return Err(ClassificationError::RootFailed {
            hns: RootResolutionState::from_lookup(&hns),
            icann: RootResolutionState::from_lookup(&icann),
        });
    }

    let outcome = match (hns, icann) {
        (RootLookup::Present(plan), RootLookup::Absent(icann_absence)) => {
            let selection_reason = select_single_namespace(policy, Namespace::Hns)?;
            NamespaceOutcome::HnsOnly {
                plan,
                icann_absence,
                selection_reason,
            }
        }
        (RootLookup::Absent(hns_absence), RootLookup::Present(plan)) => {
            let selection_reason = select_single_namespace(policy, Namespace::Icann)?;
            NamespaceOutcome::IcannOnly {
                plan,
                hns_absence,
                selection_reason,
            }
        }
        (RootLookup::Absent(hns), RootLookup::Absent(icann)) => {
            NamespaceOutcome::Neither { hns, icann }
        }
        (RootLookup::Present(hns), RootLookup::Present(icann)) => {
            let differences = hns.differences(&icann);
            let (selected, selection_reason) = select_namespace(policy, differences.is_empty())?;
            if differences.is_empty() {
                NamespaceOutcome::BothConvergent {
                    selected,
                    selection_reason,
                    hns,
                    icann,
                }
            } else {
                NamespaceOutcome::BothDivergent {
                    selected,
                    selection_reason,
                    hns,
                    icann,
                    differences,
                }
            }
        }
        (RootLookup::Failed(_), _) | (_, RootLookup::Failed(_)) => {
            unreachable!("root failures returned before outcome matching")
        }
    };
    Ok(NamespaceDecision {
        query: query.clone(),
        policy,
        outcome,
    })
}

fn validate_lookup(
    query: &OriginQuery,
    expected_namespace: Namespace,
    lookup: &RootLookup,
    now_unix: u64,
) -> Result<(), ClassificationError> {
    let (actual_namespace, evidence_query, fresh) = match lookup {
        RootLookup::Present(plan) => (
            plan.namespace(),
            plan.query(),
            Some(plan.freshness().is_fresh_at(now_unix)),
        ),
        RootLookup::Absent(absence) => (
            absence.namespace(),
            absence.query(),
            Some(absence.freshness().is_fresh_at(now_unix)),
        ),
        RootLookup::Failed(failure) => (failure.namespace(), failure.query(), None),
    };
    if actual_namespace != expected_namespace {
        return Err(ClassificationError::RootPositionMismatch {
            expected: expected_namespace,
            actual: actual_namespace,
        });
    }
    if evidence_query != query {
        return Err(ClassificationError::QueryMismatch {
            namespace: expected_namespace,
        });
    }
    if fresh == Some(false) {
        return Err(ClassificationError::StaleEvidence {
            namespace: expected_namespace,
        });
    }
    Ok(())
}

fn select_namespace(
    policy: SelectionPolicy,
    convergent: bool,
) -> Result<(Namespace, SelectionReason), ClassificationError> {
    if let Some(namespace) = policy.explicit_pin() {
        return Ok((namespace, SelectionReason::ExplicitPin));
    }
    if let Some(namespace) = policy.sticky_binding() {
        return Ok((namespace, SelectionReason::StickyBinding));
    }
    match policy.default_precedence() {
        DefaultPrecedence::PreferIcann => Ok((Namespace::Icann, SelectionReason::IcannDefault)),
        DefaultPrecedence::FailClosed if convergent => {
            Ok((Namespace::Icann, SelectionReason::IcannDefault))
        }
        DefaultPrecedence::FailClosed => Err(ClassificationError::DivergenceRequiresSelection),
    }
}

fn select_single_namespace(
    policy: SelectionPolicy,
    available: Namespace,
) -> Result<SelectionReason, ClassificationError> {
    if let Some(namespace) = policy.explicit_pin() {
        return if namespace == available {
            Ok(SelectionReason::ExplicitPin)
        } else {
            Err(ClassificationError::SelectedNamespaceUnavailable {
                namespace,
                selection_reason: SelectionReason::ExplicitPin,
            })
        };
    }
    if let Some(namespace) = policy.sticky_binding() {
        return if namespace == available {
            Ok(SelectionReason::StickyBinding)
        } else {
            Err(ClassificationError::SelectedNamespaceUnavailable {
                namespace,
                selection_reason: SelectionReason::StickyBinding,
            })
        };
    }
    Ok(SelectionReason::SingleRoot)
}

/// Stable SHA-256 decision identity used to partition transport state.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DecisionFingerprint([u8; 32]);

impl DecisionFingerprint {
    /// Raw SHA-256 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hexadecimal representation.
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "both hexadecimal table indices are masked to four bits"
    )]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

impl fmt::Debug for DecisionFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DecisionFingerprint")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for DecisionFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// Computes the normalized query-, policy-, and outcome-bound decision
/// identity.
///
/// Freshness timestamps, TTL values, and RRSIG/proof bytes are intentionally
/// excluded. Resolver configuration belongs to [`DecisionCacheKey`]. The
/// exact policy snapshot and selected namespace are included so a pin/binding
/// change cannot reuse old transport state.
#[must_use]
pub fn decision_fingerprint(decision: &NamespaceDecision) -> DecisionFingerprint {
    let mut input = FingerprintInput::new(b"hns-namespace-decision-v1");
    input.u16(COMPARISON_SCHEMA_VERSION);
    input.query(decision.query());
    let policy = decision.policy();
    input.u64(policy.revision());
    input.option_namespace(policy.explicit_pin());
    input.option_namespace(policy.sticky_binding());
    input.u8(policy.default_precedence().tag());
    let outcome = decision.outcome();
    input.u8(outcome.kind() as u8);
    input.option_namespace(outcome.selected_namespace());
    input.option_selection_reason(outcome.selection_reason());
    match outcome {
        NamespaceOutcome::HnsOnly {
            plan,
            icann_absence,
            ..
        } => {
            input.plan(plan);
            input.absence(icann_absence);
        }
        NamespaceOutcome::IcannOnly {
            plan, hns_absence, ..
        } => {
            input.plan(plan);
            input.absence(hns_absence);
        }
        NamespaceOutcome::BothConvergent { hns, icann, .. } => {
            input.plan(hns);
            input.plan(icann);
        }
        NamespaceOutcome::BothDivergent {
            hns,
            icann,
            differences,
            ..
        } => {
            input.plan(hns);
            input.plan(icann);
            input.u32(differences.bits());
        }
        NamespaceOutcome::Neither { hns, icann } => {
            input.absence(hns);
            input.absence(icann);
        }
    }
    DecisionFingerprint(sha256(&input.finish()))
}

/// Complete cache-key input for one dual-root decision.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DecisionCacheKey {
    decision_fingerprint: DecisionFingerprint,
    query: OriginQuery,
    hns_network: HnsNetwork,
    resolver_configuration: [u8; 32],
    trust_anchor_generation: u64,
    binding_revision: u64,
    comparison_schema_version: u16,
}

impl DecisionCacheKey {
    /// Creates a cache key derived from the actual decision and bound to all
    /// external authority generations.
    #[must_use]
    pub fn new(
        decision: &NamespaceDecision,
        resolver_configuration: [u8; 32],
        trust_anchor_generation: u64,
    ) -> Self {
        Self {
            decision_fingerprint: decision_fingerprint(decision),
            query: decision.query().clone(),
            hns_network: decision.hns_network(),
            resolver_configuration,
            trust_anchor_generation,
            binding_revision: decision.policy().revision(),
            comparison_schema_version: COMPARISON_SCHEMA_VERSION,
        }
    }

    /// Query-, policy-, selected-root-, and plan-bound cached decision.
    #[must_use]
    pub const fn decision_fingerprint(&self) -> DecisionFingerprint {
        self.decision_fingerprint
    }

    /// Canonical origin query.
    #[must_use]
    pub const fn query(&self) -> &OriginQuery {
        &self.query
    }

    /// Canonical HNS network partition.
    #[must_use]
    pub const fn hns_network(&self) -> HnsNetwork {
        self.hns_network
    }

    /// Stable SHA-256 identity for cache indexing.
    #[must_use]
    pub fn fingerprint(&self) -> DecisionFingerprint {
        let mut input = FingerprintInput::new(b"hns-namespace-cache-key-v1");
        input.u16(self.comparison_schema_version);
        input.bytes(self.decision_fingerprint.as_bytes());
        input.query(&self.query);
        input.u8(self.hns_network.tag());
        input.bytes(&self.resolver_configuration);
        input.u64(self.trust_anchor_generation);
        input.u64(self.binding_revision);
        DecisionFingerprint(sha256(&input.finish()))
    }
}

/// Input/plan validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidationError {
    /// Host is not one canonical DNS name.
    InvalidHost,
    /// Origin query has no usable protocol capability.
    InvalidQuery,
    /// A bounded field exceeds the contract limit.
    BoundExceeded,
    /// Origin plan is internally inconsistent.
    InvalidPlan,
    /// Evidence provenance, absence kind, or freshness is invalid.
    InvalidEvidence,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHost => "invalid canonical DNS host",
            Self::InvalidQuery => "invalid origin query",
            Self::BoundExceeded => "namespace contract bound exceeded",
            Self::InvalidPlan => "origin plan is internally inconsistent",
            Self::InvalidEvidence => "root evidence is invalid",
        })
    }
}

impl std::error::Error for ValidationError {}

/// Fail-closed classification failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClassificationError {
    /// One or both root lookups failed. A nonfailed root's successful
    /// disposition is retained without its validated plan or absence proof.
    RootFailed {
        /// Bounded HNS lookup state.
        hns: RootResolutionState,
        /// Bounded ICANN lookup state.
        icann: RootResolutionState,
    },
    /// Evidence was supplied in the wrong root position.
    RootPositionMismatch {
        /// Root required by the input slot.
        expected: Namespace,
        /// Root carried by the evidence.
        actual: Namespace,
    },
    /// Evidence belongs to another scheme, hostname, port, or protocol
    /// capability set.
    QueryMismatch {
        /// Root whose complete origin query mismatched.
        namespace: Namespace,
    },
    /// Presence or authenticated-absence evidence is outside its validity
    /// interval.
    StaleEvidence {
        /// Root whose evidence is stale or not yet valid.
        namespace: Namespace,
    },
    /// A pin or persistent binding names a root that is authentically absent.
    /// Callers must perform an explicit state-isolated namespace switch rather
    /// than silently selecting the other root.
    SelectedNamespaceUnavailable {
        /// Bound namespace that is unavailable.
        namespace: Namespace,
        /// Whether the unavailable selection came from a pin or binding.
        selection_reason: SelectionReason,
    },
    /// Both roots differ and policy requires an explicit selection.
    DivergenceRequiresSelection,
}

impl fmt::Display for ClassificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootFailed { hns, icann } => write!(
                formatter,
                "dual-root classification is indeterminate (HNS: {hns}, ICANN: {icann})"
            ),
            Self::RootPositionMismatch { expected, actual } => write!(
                formatter,
                "root evidence position mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::QueryMismatch { namespace } => {
                write!(
                    formatter,
                    "{namespace:?} evidence belongs to another origin query"
                )
            }
            Self::StaleEvidence { namespace } => {
                write!(
                    formatter,
                    "{namespace:?} evidence is outside its validity interval"
                )
            }
            Self::SelectedNamespaceUnavailable {
                namespace,
                selection_reason,
            } => write!(
                formatter,
                "{selection_reason:?} namespace {namespace:?} is authentically absent"
            ),
            Self::DivergenceRequiresSelection => {
                formatter.write_str("divergent roots require an explicit namespace selection")
            }
        }
    }
}

impl std::error::Error for ClassificationError {}

struct FingerprintInput {
    bytes: Vec<u8>,
}

impl FingerprintInput {
    fn new(domain: &[u8]) -> Self {
        let mut value = Self { bytes: Vec::new() };
        value.bytes(domain);
        value
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u64(u64::try_from(value.len()).unwrap_or(u64::MAX));
        self.bytes.extend_from_slice(value);
    }

    fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn option_namespace(&mut self, value: Option<Namespace>) {
        self.u8(value.map_or(0, Namespace::tag));
    }

    fn option_selection_reason(&mut self, value: Option<SelectionReason>) {
        self.u8(value.map_or(0, SelectionReason::tag));
    }

    fn query(&mut self, query: &OriginQuery) {
        self.string(query.host().as_str());
        self.u8(query.scheme().tag());
        self.u16(query.origin_port().get());
        self.u8(query.supported_protocols().flags());
    }

    fn absence(&mut self, absence: &ValidatedAbsence) {
        self.u8(absence.namespace().tag());
        self.provenance_authority(absence.provenance());
        self.query(absence.query());
        self.u8(absence.kind().tag());
    }

    fn plan(&mut self, plan: &ValidatedOriginPlan) {
        self.u8(plan.namespace().tag());
        self.provenance_authority(plan.provenance());
        self.query(plan.query());
        self.u64(u64::try_from(plan.alias_path().len()).unwrap_or(u64::MAX));
        for alias in plan.alias_path() {
            self.u8(alias.kind().tag());
            self.string(alias.owner().as_str());
            self.string(alias.target().as_str());
        }
        self.string(plan.terminal_target().as_str());
        self.u64(u64::try_from(plan.endpoint_alias_path().len()).unwrap_or(u64::MAX));
        for alias in plan.endpoint_alias_path() {
            self.u8(alias.kind().tag());
            self.string(alias.owner().as_str());
            self.string(alias.target().as_str());
        }
        self.string(plan.endpoint_target().as_str());
        self.u64(u64::try_from(plan.endpoints().len()).unwrap_or(u64::MAX));
        for endpoint in plan.endpoints() {
            self.socket_addr(*endpoint);
        }
        self.service(plan.service());
        self.u8(plan.tls_policy().tag());
        self.u64(u64::try_from(plan.tlsa_records().len()).unwrap_or(u64::MAX));
        for record in plan.tlsa_records() {
            self.bytes(record.rdata());
        }
    }

    fn provenance_authority(&mut self, provenance: &EvidenceProvenance) {
        match provenance {
            EvidenceProvenance::Hns { network, .. } => {
                self.u8(1);
                self.u8(network.tag());
            }
            EvidenceProvenance::IcannDoh { .. } => self.u8(2),
        }
    }

    fn socket_addr(&mut self, endpoint: SocketAddr) {
        match endpoint.ip() {
            IpAddr::V4(address) => {
                self.u8(4);
                self.bytes(&address.octets());
            }
            IpAddr::V6(address) => {
                self.u8(6);
                self.bytes(&address.octets());
            }
        }
        self.u16(endpoint.port());
    }

    fn service(&mut self, service: &ServiceBinding) {
        match service.priority() {
            Some(priority) => {
                self.u8(1);
                self.u16(priority);
            }
            None => self.u8(0),
        }
        self.string(service.service_target().as_str());
        self.u64(u64::try_from(service.mandatory_keys().len()).unwrap_or(u64::MAX));
        for key in service.mandatory_keys() {
            self.u16(*key);
        }
        self.u64(u64::try_from(service.advertised_alpn().len()).unwrap_or(u64::MAX));
        for alpn in service.advertised_alpn() {
            self.bytes(alpn);
        }
        self.u8(service.selected_protocol().tag());
        self.u16(service.effective_port().get());
        self.u8(service.transport().tag());
        self.u64(u64::try_from(service.connection_hints().len()).unwrap_or(u64::MAX));
        for hint in service.connection_hints() {
            match hint {
                IpAddr::V4(address) => {
                    self.u8(4);
                    self.bytes(&address.octets());
                }
                IpAddr::V6(address) => {
                    self.u8(6);
                    self.bytes(&address.octets());
                }
            }
        }
        match service.ech_config() {
            Some(ech) => {
                self.u8(1);
                self.bytes(ech);
            }
            None => self.u8(0),
        }
        self.u64(u64::try_from(service.parameters().len()).unwrap_or(u64::MAX));
        for parameter in service.parameters() {
            self.u16(parameter.key());
            self.bytes(parameter.value());
        }
    }
}

#[allow(
    clippy::indexing_slicing,
    clippy::many_single_char_names,
    clippy::too_many_lines,
    reason = "SHA-256 uses the standard eight working variables and fixed algorithm-bounded rounds"
)]
fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let bit_len = u64::try_from(input.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut output = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        let start = index * 4;
        output[start..start + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures fail immediately when their declared invariant is invalid"
)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const NOW: u64 = 1_700_000_000;

    fn host(value: &str) -> CanonicalHost {
        CanonicalHost::parse(value).unwrap()
    }

    fn freshness(expires_delta: u64) -> Freshness {
        Freshness::new(NOW, NOW + expires_delta).unwrap()
    }

    fn provenance(namespace: Namespace, variant: u8) -> EvidenceProvenance {
        match namespace {
            Namespace::Hns => EvidenceProvenance::Hns {
                network: HnsNetwork::Mainnet,
                tree_root: [variant.wrapping_add(1); 32],
                height: u32::from(variant),
            },
            Namespace::Icann => EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
        }
    }

    fn service_input(port: u16, protocol: ApplicationProtocol) -> ServiceBindingInput {
        let alpn = match protocol {
            ApplicationProtocol::Http11 => b"http/1.1".to_vec(),
            ApplicationProtocol::Http2 => b"h2".to_vec(),
            ApplicationProtocol::Http3 => b"h3".to_vec(),
        };
        let mut alpn_wire = vec![u8::try_from(alpn.len()).unwrap()];
        alpn_wire.extend_from_slice(&alpn);
        ServiceBindingInput {
            priority: Some(1),
            service_target: host("edge.example"),
            mandatory_keys: vec![1, 3],
            advertised_alpn: vec![alpn],
            selected_protocol: protocol,
            effective_port: NonZeroU16::new(port).unwrap(),
            transport: if protocol == ApplicationProtocol::Http3 {
                ServiceTransport::Udp
            } else {
                ServiceTransport::Tcp
            },
            connection_hints: Vec::new(),
            ech_config: Some(vec![1, 2, 3]),
            parameters: vec![
                ServiceParameter::new(1, alpn_wire).unwrap(),
                ServiceParameter::new(3, port.to_be_bytes().to_vec()).unwrap(),
                ServiceParameter::new(5, vec![1, 2, 3]).unwrap(),
            ],
        }
    }

    fn service(port: u16, protocol: ApplicationProtocol) -> ServiceBinding {
        ServiceBinding::new(service_input(port, protocol)).unwrap()
    }

    fn default_http11_service_input(
        advertised_alpn: &[&[u8]],
        no_default_alpn: bool,
    ) -> ServiceBindingInput {
        let advertised_alpn = advertised_alpn
            .iter()
            .map(|identifier| identifier.to_vec())
            .collect::<Vec<_>>();
        let mut alpn_wire = Vec::new();
        for identifier in &advertised_alpn {
            alpn_wire.push(u8::try_from(identifier.len()).unwrap());
            alpn_wire.extend_from_slice(identifier);
        }
        let mut input = service_input(443, ApplicationProtocol::Http11);
        input.advertised_alpn = advertised_alpn;
        *input
            .parameters
            .iter_mut()
            .find(|parameter| parameter.key() == 1)
            .expect("ALPN parameter") = ServiceParameter::new(1, alpn_wire).unwrap();
        if no_default_alpn {
            input
                .parameters
                .push(ServiceParameter::new(2, Vec::new()).unwrap());
        }
        input
    }

    fn plan(namespace: Namespace, endpoint_last_octet: u8) -> ValidatedOriginPlan {
        let origin = host("www.example");
        let terminal = host("edge.example");
        ValidatedOriginPlan::new(OriginPlanInput {
            namespace,
            query: query(),
            alias_path: vec![AliasStep::new(AliasKind::Cname, origin, terminal.clone()).unwrap()],
            terminal_target: terminal,
            endpoint_alias_path: Vec::new(),
            endpoint_target: host("edge.example"),
            endpoints: vec![
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, endpoint_last_octet)),
                    443,
                ),
            ],
            service: service(443, ApplicationProtocol::Http2),
            tls_policy: TlsTrustPolicy::Dane,
            tlsa_records: vec![
                CanonicalTlsa::new({
                    let mut rdata = vec![3, 1, 1];
                    rdata.extend_from_slice(&[endpoint_last_octet; 32]);
                    rdata
                })
                .unwrap(),
            ],
            provenance: provenance(namespace, endpoint_last_octet),
            freshness: freshness(u64::from(endpoint_last_octet) + 30),
        })
        .unwrap()
    }

    fn absence(namespace: Namespace) -> ValidatedAbsence {
        let kind = match namespace {
            Namespace::Hns => AbsenceKind::HnsCurrentUrkelNonInclusion,
            Namespace::Icann => AbsenceKind::DnssecAuthenticatedNxDomain,
        };
        ValidatedAbsence::new(
            namespace,
            query(),
            kind,
            provenance(namespace, 4),
            freshness(60),
        )
        .unwrap()
    }

    fn query() -> OriginQuery {
        OriginQuery::new(
            host("www.example"),
            OriginScheme::Https,
            None,
            ProtocolCapabilities::all(),
        )
    }

    #[test]
    fn canonical_host_is_syntax_only_and_never_uses_an_iana_list() {
        assert_eq!(host("WWW.Example.").as_str(), "www.example");
        assert_eq!(host("singlelabel").as_str(), "singlelabel");
        for invalid in [
            "",
            " example",
            "example ",
            "example..",
            "_service.example",
            "-bad.example",
            "bad-.example",
            "127.0.0.1",
            "::1",
            "bücher.example",
        ] {
            assert_eq!(
                CanonicalHost::parse(invalid),
                Err(ValidationError::InvalidHost)
            );
        }
    }

    #[test]
    fn five_outcome_table_is_explicit() {
        let hns = plan(Namespace::Hns, 10);
        let icann_same = plan(Namespace::Icann, 10);
        let icann_different = plan(Namespace::Icann, 11);

        assert!(matches!(
            decide_namespace(
                &query(),
                RootLookup::Present(hns.clone()),
                RootLookup::Absent(absence(Namespace::Icann)),
                SelectionPolicy::default(),
                NOW,
            )
            .unwrap(),
            NamespaceDecision {
                outcome: NamespaceOutcome::HnsOnly { .. },
                ..
            }
        ));
        assert!(matches!(
            decide_namespace(
                &query(),
                RootLookup::Absent(absence(Namespace::Hns)),
                RootLookup::Present(icann_same.clone()),
                SelectionPolicy::default(),
                NOW,
            )
            .unwrap(),
            NamespaceDecision {
                outcome: NamespaceOutcome::IcannOnly { .. },
                ..
            }
        ));
        assert!(matches!(
            decide_namespace(
                &query(),
                RootLookup::Present(hns.clone()),
                RootLookup::Present(icann_same),
                SelectionPolicy::default(),
                NOW,
            )
            .unwrap(),
            NamespaceDecision {
                outcome: NamespaceOutcome::BothConvergent {
                    selected: Namespace::Icann,
                    ..
                },
                ..
            }
        ));
        assert!(matches!(
            decide_namespace(
                &query(),
                RootLookup::Present(hns),
                RootLookup::Present(icann_different),
                SelectionPolicy::default(),
                NOW,
            )
            .unwrap(),
            NamespaceDecision {
                outcome: NamespaceOutcome::BothDivergent {
                    selected: Namespace::Icann,
                    ..
                },
                ..
            }
        ));
        assert!(matches!(
            decide_namespace(
                &query(),
                RootLookup::Absent(absence(Namespace::Hns)),
                RootLookup::Absent(absence(Namespace::Icann)),
                SelectionPolicy::default(),
                NOW,
            )
            .unwrap(),
            NamespaceDecision {
                outcome: NamespaceOutcome::Neither { .. },
                ..
            }
        ));
    }

    #[test]
    fn any_root_failure_prevents_only_or_neither() {
        let hns_failure = RootFailure::new(
            Namespace::Hns,
            query(),
            RootFailureKind::StaleHnsAnchor,
            None,
        );
        let error = decide_namespace(
            &query(),
            RootLookup::Failed(hns_failure.clone()),
            RootLookup::Present(plan(Namespace::Icann, 10)),
            SelectionPolicy::default(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(
            error,
            ClassificationError::RootFailed {
                hns: RootResolutionState::Failed(hns_failure.clone()),
                icann: RootResolutionState::Present,
            }
        );
        let hns_state = RootResolutionState::Failed(hns_failure);
        assert_eq!(hns_state.disposition(), RootResolutionDisposition::Failed);
        assert_eq!(
            hns_state.failure().map(RootFailure::kind),
            Some(RootFailureKind::StaleHnsAnchor)
        );
        assert!(hns_state.is_failed());
        assert_eq!(
            error.to_string(),
            "dual-root classification is indeterminate (HNS: failed (StaleHnsAnchor), ICANN: present)"
        );

        let icann_failure = RootFailure::new(
            Namespace::Icann,
            query(),
            RootFailureKind::BogusDnssec,
            None,
        );
        let error = decide_namespace(
            &query(),
            RootLookup::Absent(absence(Namespace::Hns)),
            RootLookup::Failed(icann_failure.clone()),
            SelectionPolicy::default(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(
            error,
            ClassificationError::RootFailed {
                hns: RootResolutionState::Absent,
                icann: RootResolutionState::Failed(icann_failure),
            }
        );
        assert_eq!(
            RootResolutionState::Absent.disposition(),
            RootResolutionDisposition::Absent
        );
        assert_eq!(RootResolutionState::Absent.failure(), None);
        assert!(!RootResolutionState::Absent.is_failed());
    }

    #[test]
    fn both_root_failures_retain_their_typed_reasons() {
        let hns_failure =
            RootFailure::new(Namespace::Hns, query(), RootFailureKind::Transport, None);
        let icann_failure = RootFailure::new(
            Namespace::Icann,
            query(),
            RootFailureKind::BogusDnssec,
            Some(NOW + 5),
        );

        assert_eq!(
            decide_namespace(
                &query(),
                RootLookup::Failed(hns_failure.clone()),
                RootLookup::Failed(icann_failure.clone()),
                SelectionPolicy::default(),
                NOW,
            ),
            Err(ClassificationError::RootFailed {
                hns: RootResolutionState::Failed(hns_failure),
                icann: RootResolutionState::Failed(icann_failure),
            })
        );
    }

    #[test]
    fn divergence_precedence_is_pin_then_sticky_then_icann_default() {
        let hns = RootLookup::Present(plan(Namespace::Hns, 10));
        let icann = RootLookup::Present(plan(Namespace::Icann, 11));

        let pinned = decide_namespace(
            &query(),
            hns.clone(),
            icann.clone(),
            SelectionPolicy::default().with_explicit_pin(Some(Namespace::Hns)),
            NOW,
        )
        .unwrap();
        assert_eq!(pinned.selected_namespace(), Some(Namespace::Hns));
        assert_eq!(
            pinned.selection_reason(),
            Some(SelectionReason::ExplicitPin)
        );

        let sticky = decide_namespace(
            &query(),
            hns.clone(),
            icann.clone(),
            SelectionPolicy::default().with_sticky_binding(Some(Namespace::Hns)),
            NOW,
        )
        .unwrap();
        assert_eq!(sticky.selected_namespace(), Some(Namespace::Hns));
        assert_eq!(
            sticky.selection_reason(),
            Some(SelectionReason::StickyBinding)
        );

        let defaulted =
            decide_namespace(&query(), hns, icann, SelectionPolicy::default(), NOW).unwrap();
        assert_eq!(defaulted.selected_namespace(), Some(Namespace::Icann));
        assert_eq!(
            defaulted.selection_reason(),
            Some(SelectionReason::IcannDefault)
        );
    }

    #[test]
    fn single_root_cannot_silently_replace_a_pin_or_sticky_binding() {
        let hns_only = || {
            (
                RootLookup::Present(plan(Namespace::Hns, 10)),
                RootLookup::Absent(absence(Namespace::Icann)),
            )
        };
        let (hns, icann) = hns_only();
        assert_eq!(
            decide_namespace(
                &query(),
                hns,
                icann,
                SelectionPolicy::default().with_explicit_pin(Some(Namespace::Icann)),
                NOW,
            ),
            Err(ClassificationError::SelectedNamespaceUnavailable {
                namespace: Namespace::Icann,
                selection_reason: SelectionReason::ExplicitPin,
            })
        );

        let (hns, icann) = hns_only();
        assert_eq!(
            decide_namespace(
                &query(),
                hns,
                icann,
                SelectionPolicy::default().with_sticky_binding(Some(Namespace::Icann)),
                NOW,
            ),
            Err(ClassificationError::SelectedNamespaceUnavailable {
                namespace: Namespace::Icann,
                selection_reason: SelectionReason::StickyBinding,
            })
        );

        let (hns, icann) = hns_only();
        let explicitly_hns = decide_namespace(
            &query(),
            hns,
            icann,
            SelectionPolicy::default()
                .with_sticky_binding(Some(Namespace::Icann))
                .with_explicit_pin(Some(Namespace::Hns)),
            NOW,
        )
        .unwrap();
        assert_eq!(
            explicitly_hns.selection_reason(),
            Some(SelectionReason::ExplicitPin)
        );
    }

    #[test]
    fn fail_closed_default_requires_selection_only_for_divergence() {
        let policy = SelectionPolicy::new(DefaultPrecedence::FailClosed, 1);
        assert_eq!(
            decide_namespace(
                &query(),
                RootLookup::Present(plan(Namespace::Hns, 10)),
                RootLookup::Present(plan(Namespace::Icann, 11)),
                policy,
                NOW,
            ),
            Err(ClassificationError::DivergenceRequiresSelection)
        );
        assert!(matches!(
            decide_namespace(
                &query(),
                RootLookup::Present(plan(Namespace::Hns, 10)),
                RootLookup::Present(plan(Namespace::Icann, 10)),
                policy,
                NOW,
            )
            .unwrap(),
            NamespaceDecision {
                outcome: NamespaceOutcome::BothConvergent { .. },
                ..
            }
        ));
    }

    #[test]
    fn record_order_ttl_and_provenance_do_not_break_convergence() {
        let left = plan(Namespace::Hns, 10);
        let mut input = OriginPlanInput {
            namespace: Namespace::Icann,
            query: left.query().clone(),
            alias_path: left.alias_path().to_vec(),
            terminal_target: left.terminal_target().clone(),
            endpoint_alias_path: left.endpoint_alias_path().to_vec(),
            endpoint_target: left.endpoint_target().clone(),
            endpoints: left.endpoints().iter().rev().copied().collect(),
            service: left.service().clone(),
            tls_policy: left.tls_policy(),
            tlsa_records: left.tlsa_records().iter().rev().cloned().collect(),
            provenance: provenance(Namespace::Icann, 99),
            freshness: freshness(5),
        };
        input
            .endpoints
            .push(*left.endpoints().first().expect("fixture endpoint"));
        let right = ValidatedOriginPlan::new(input).unwrap();
        assert!(left.equivalent_to(&right));
        assert_eq!(left.differences(&right), DivergenceMask::NONE);
    }

    #[test]
    fn partial_endpoint_overlap_and_trust_changes_are_divergent() {
        let left = plan(Namespace::Hns, 10);
        let right = plan(Namespace::Icann, 11);
        assert!(left.differences(&right).contains(DivergenceMask::ENDPOINTS));

        let webpki = ValidatedOriginPlan::new(OriginPlanInput {
            namespace: Namespace::Icann,
            query: left.query().clone(),
            alias_path: left.alias_path().to_vec(),
            terminal_target: left.terminal_target().clone(),
            endpoint_alias_path: left.endpoint_alias_path().to_vec(),
            endpoint_target: left.endpoint_target().clone(),
            endpoints: left.endpoints().to_vec(),
            service: left.service().clone(),
            tls_policy: TlsTrustPolicy::WebPkiAuthenticatedAbsence,
            tlsa_records: Vec::new(),
            provenance: provenance(Namespace::Icann, 1),
            freshness: freshness(60),
        })
        .unwrap();
        assert!(
            left.differences(&webpki)
                .contains(DivergenceMask::TLS_POLICY)
        );
    }

    #[test]
    fn service_protocol_and_transport_must_form_one_coherent_plan() {
        let mut input = ServiceBindingInput {
            priority: Some(1),
            service_target: host("edge.example"),
            mandatory_keys: Vec::new(),
            advertised_alpn: vec![b"h3".to_vec()],
            selected_protocol: ApplicationProtocol::Http3,
            effective_port: NonZeroU16::new(443).unwrap(),
            transport: ServiceTransport::Tcp,
            connection_hints: Vec::new(),
            ech_config: None,
            parameters: vec![ServiceParameter::new(1, vec![2, b'h', b'3']).unwrap()],
        };
        assert_eq!(
            ServiceBinding::new(input.clone()),
            Err(ValidationError::InvalidPlan)
        );
        input.transport = ServiceTransport::Udp;
        assert!(ServiceBinding::new(input).is_ok());
    }

    #[test]
    fn http11_default_is_valid_with_nonempty_raw_alpn() {
        let input = default_http11_service_input(&[b"h3", b"h2"], false);
        let binding = ServiceBinding::new(input).unwrap();

        assert_eq!(binding.advertised_alpn(), &[b"h3".to_vec(), b"h2".to_vec()]);
        assert_eq!(
            service_parameter(binding.parameters(), 1),
            Some([2, b'h', b'3', 2, b'h', b'2'].as_slice())
        );
        assert_eq!(binding.selected_protocol(), ApplicationProtocol::Http11);
    }

    #[test]
    fn no_default_alpn_requires_explicit_http11() {
        assert_eq!(
            ServiceBinding::new(default_http11_service_input(&[b"h3", b"h2"], true)),
            Err(ValidationError::InvalidPlan)
        );

        let binding = ServiceBinding::new(default_http11_service_input(
            &[b"h3", b"h2", b"http/1.1"],
            true,
        ))
        .unwrap();
        assert_eq!(binding.selected_protocol(), ApplicationProtocol::Http11);
    }

    #[test]
    fn http2_and_http3_require_explicit_raw_alpn_ids() {
        let mut http2 = default_http11_service_input(&[b"h3"], false);
        http2.selected_protocol = ApplicationProtocol::Http2;
        assert_eq!(
            ServiceBinding::new(http2),
            Err(ValidationError::InvalidPlan)
        );

        let mut http3 = default_http11_service_input(&[b"h2"], false);
        http3.selected_protocol = ApplicationProtocol::Http3;
        http3.transport = ServiceTransport::Udp;
        assert_eq!(
            ServiceBinding::new(http3),
            Err(ValidationError::InvalidPlan)
        );
    }

    #[test]
    fn raw_alpn_semantics_remain_in_equivalence_and_fingerprints() {
        let plan_with_service = |namespace, service| {
            let baseline = plan(namespace, 10);
            ValidatedOriginPlan::new(OriginPlanInput {
                namespace,
                query: baseline.query().clone(),
                alias_path: baseline.alias_path().to_vec(),
                terminal_target: baseline.terminal_target().clone(),
                endpoint_alias_path: baseline.endpoint_alias_path().to_vec(),
                endpoint_target: baseline.endpoint_target().clone(),
                endpoints: baseline.endpoints().to_vec(),
                service,
                tls_policy: baseline.tls_policy(),
                tlsa_records: baseline.tlsa_records().to_vec(),
                provenance: baseline.provenance().clone(),
                freshness: baseline.freshness(),
            })
            .unwrap()
        };
        let h3_then_h2 = plan_with_service(
            Namespace::Hns,
            ServiceBinding::new(default_http11_service_input(&[b"h3", b"h2"], false)).unwrap(),
        );
        let h2_then_h3 = plan_with_service(
            Namespace::Hns,
            ServiceBinding::new(default_http11_service_input(&[b"h2", b"h3"], false)).unwrap(),
        );

        assert!(!h3_then_h2.equivalent_to(&h2_then_h3));
        let differences = h3_then_h2.differences(&h2_then_h3);
        assert!(differences.contains(DivergenceMask::ALPN));
        assert!(differences.contains(DivergenceMask::SERVICE_PARAMETERS));

        let decision_for = |plan| {
            decide_namespace(
                &query(),
                RootLookup::Present(plan),
                RootLookup::Absent(absence(Namespace::Icann)),
                SelectionPolicy::default(),
                NOW,
            )
            .unwrap()
        };
        assert_ne!(
            decision_fingerprint(&decision_for(h3_then_h2)),
            decision_fingerprint(&decision_for(h2_then_h3))
        );
    }

    #[test]
    fn cleartext_origins_reject_service_mode_and_quic_tls_protocols() {
        let cleartext_query = OriginQuery::new(
            host("www.example"),
            OriginScheme::Http,
            None,
            ProtocolCapabilities::all(),
        );
        let cleartext_service = ServiceBinding::new(ServiceBindingInput {
            priority: None,
            service_target: host("edge.example"),
            mandatory_keys: Vec::new(),
            advertised_alpn: Vec::new(),
            selected_protocol: ApplicationProtocol::Http11,
            effective_port: NonZeroU16::new(80).unwrap(),
            transport: ServiceTransport::Tcp,
            connection_hints: Vec::new(),
            ech_config: None,
            parameters: Vec::new(),
        })
        .unwrap();
        let mut input = OriginPlanInput {
            namespace: Namespace::Hns,
            query: cleartext_query,
            alias_path: vec![
                AliasStep::new(AliasKind::Cname, host("www.example"), host("edge.example"))
                    .unwrap(),
            ],
            terminal_target: host("edge.example"),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host("edge.example"),
            endpoints: vec!["203.0.113.10:80".parse().unwrap()],
            service: cleartext_service,
            tls_policy: TlsTrustPolicy::Cleartext,
            tlsa_records: Vec::new(),
            provenance: provenance(Namespace::Hns, 10),
            freshness: freshness(60),
        };
        assert!(ValidatedOriginPlan::new(input.clone()).is_ok());

        input.service = service(80, ApplicationProtocol::Http3);
        assert_eq!(
            ValidatedOriginPlan::new(input),
            Err(ValidationError::InvalidPlan)
        );
    }

    #[test]
    fn service_binding_rejects_alias_mode_and_malformed_mandatory_alpn_or_hints() {
        let mut input = service_input(443, ApplicationProtocol::Http2);
        input.mandatory_keys = vec![1; MAX_SERVICE_PARAMETERS + 1];
        assert_eq!(
            ServiceBinding::new(input),
            Err(ValidationError::BoundExceeded)
        );

        let mut input = service_input(443, ApplicationProtocol::Http2);
        input.connection_hints = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); MAX_ENDPOINTS + 1];
        assert_eq!(
            ServiceBinding::new(input),
            Err(ValidationError::BoundExceeded)
        );

        let mut input = service_input(443, ApplicationProtocol::Http2);
        input.priority = Some(0);
        assert_eq!(
            ServiceBinding::new(input),
            Err(ValidationError::InvalidPlan)
        );

        let mut input = service_input(443, ApplicationProtocol::Http2);
        input.priority = None;
        assert_eq!(
            ServiceBinding::new(input),
            Err(ValidationError::InvalidPlan)
        );

        let mut input = service_input(443, ApplicationProtocol::Http2);
        input.parameters.retain(|parameter| parameter.key() != 3);
        assert_eq!(
            ServiceBinding::new(input),
            Err(ValidationError::InvalidPlan)
        );

        let mut input = service_input(443, ApplicationProtocol::Http2);
        input.mandatory_keys.push(65_000);
        input
            .parameters
            .push(ServiceParameter::new(65_000, vec![1]).unwrap());
        assert_eq!(
            ServiceBinding::new(input),
            Err(ValidationError::InvalidPlan)
        );

        let mut input = service_input(443, ApplicationProtocol::Http2);
        input.advertised_alpn = vec![b"http/1.1".to_vec()];
        *input
            .parameters
            .iter_mut()
            .find(|parameter| parameter.key() == 1)
            .expect("ALPN parameter") =
            ServiceParameter::new(1, vec![8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'])
                .unwrap();
        assert_eq!(
            ServiceBinding::new(input),
            Err(ValidationError::InvalidPlan)
        );

        let mut input = service_input(443, ApplicationProtocol::Http2);
        input.connection_hints = vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))];
        input
            .parameters
            .push(ServiceParameter::new(4, vec![198, 51, 100, 7]).unwrap());
        let service = ServiceBinding::new(input).unwrap();
        let mut plan_input = OriginPlanInput {
            namespace: Namespace::Hns,
            query: query(),
            alias_path: vec![
                AliasStep::new(AliasKind::Cname, host("www.example"), host("edge.example"))
                    .unwrap(),
            ],
            terminal_target: host("edge.example"),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host("edge.example"),
            endpoints: vec!["203.0.113.10:443".parse().unwrap()],
            service,
            tls_policy: TlsTrustPolicy::Dane,
            tlsa_records: plan(Namespace::Hns, 10).tlsa_records().to_vec(),
            provenance: provenance(Namespace::Hns, 10),
            freshness: freshness(60),
        };
        assert_eq!(
            ValidatedOriginPlan::new(plan_input.clone()),
            Err(ValidationError::InvalidPlan)
        );
        plan_input
            .endpoints
            .push("198.51.100.7:443".parse().unwrap());
        assert!(ValidatedOriginPlan::new(plan_input).is_ok());
    }

    #[test]
    fn service_mode_target_and_complete_origin_query_affect_convergence() {
        let left = plan(Namespace::Hns, 10);
        let mut target_changed_input = OriginPlanInput {
            namespace: Namespace::Icann,
            query: left.query().clone(),
            alias_path: left.alias_path().to_vec(),
            terminal_target: left.terminal_target().clone(),
            endpoint_alias_path: left.endpoint_alias_path().to_vec(),
            endpoint_target: left.endpoint_target().clone(),
            endpoints: left.endpoints().to_vec(),
            service: left.service().clone(),
            tls_policy: left.tls_policy(),
            tlsa_records: left.tlsa_records().to_vec(),
            provenance: provenance(Namespace::Icann, 10),
            freshness: freshness(60),
        };
        target_changed_input.service.service_target = host("other-edge.example");
        target_changed_input.endpoint_target = host("other-edge.example");
        let target_changed = ValidatedOriginPlan::new(target_changed_input).unwrap();
        assert!(
            left.differences(&target_changed)
                .contains(DivergenceMask::SERVICE_TARGET)
        );
        assert!(
            left.differences(&target_changed)
                .contains(DivergenceMask::ENDPOINT_TARGET)
        );

        let endpoint_alias = ValidatedOriginPlan::new(OriginPlanInput {
            namespace: Namespace::Icann,
            query: left.query().clone(),
            alias_path: left.alias_path().to_vec(),
            terminal_target: left.terminal_target().clone(),
            endpoint_alias_path: vec![
                AliasStep::new(
                    AliasKind::Cname,
                    host("edge.example"),
                    host("address.example"),
                )
                .unwrap(),
            ],
            endpoint_target: host("address.example"),
            endpoints: left.endpoints().to_vec(),
            service: left.service().clone(),
            tls_policy: left.tls_policy(),
            tlsa_records: left.tlsa_records().to_vec(),
            provenance: provenance(Namespace::Icann, 10),
            freshness: freshness(60),
        })
        .unwrap();
        assert!(
            left.differences(&endpoint_alias)
                .contains(DivergenceMask::ENDPOINT_ALIAS_PATH)
        );

        let mut cross_path_cycle = OriginPlanInput {
            namespace: Namespace::Icann,
            query: left.query().clone(),
            alias_path: left.alias_path().to_vec(),
            terminal_target: left.terminal_target().clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host("www.example"),
            endpoints: left.endpoints().to_vec(),
            service: left.service().clone(),
            tls_policy: left.tls_policy(),
            tlsa_records: left.tlsa_records().to_vec(),
            provenance: provenance(Namespace::Icann, 10),
            freshness: freshness(60),
        };
        cross_path_cycle.service.service_target = host("www.example");
        assert_eq!(
            ValidatedOriginPlan::new(cross_path_cycle),
            Err(ValidationError::InvalidPlan)
        );

        let mut query_changed = target_changed;
        query_changed.query = OriginQuery::new(
            host("www.example"),
            OriginScheme::Wss,
            None,
            ProtocolCapabilities::all(),
        );
        assert!(
            left.differences(&query_changed)
                .contains(DivergenceMask::ORIGIN_QUERY)
        );
        assert!(!left.equivalent_to(&query_changed));
    }

    #[test]
    fn tlsa_requires_supported_nonempty_dane_association() {
        assert_eq!(
            CanonicalTlsa::new(vec![3, 1, 1]),
            Err(ValidationError::InvalidPlan)
        );
        assert_eq!(
            CanonicalTlsa::new({
                let mut rdata = vec![1, 1, 1];
                rdata.extend_from_slice(&[7; 32]);
                rdata
            }),
            Err(ValidationError::InvalidPlan)
        );
        assert_eq!(
            CanonicalTlsa::new({
                let mut rdata = vec![3, 1, 1];
                rdata.extend_from_slice(&[7; 31]);
                rdata
            }),
            Err(ValidationError::InvalidPlan)
        );
        assert!(
            CanonicalTlsa::new({
                let mut rdata = vec![2, 0, 2];
                rdata.extend_from_slice(&[7; 64]);
                rdata
            })
            .is_ok()
        );
    }

    #[test]
    fn origin_plan_rejects_cross_root_mixing_and_bad_aliases() {
        let mut input = OriginPlanInput {
            namespace: Namespace::Hns,
            query: query(),
            alias_path: Vec::new(),
            terminal_target: host("other.example"),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host("edge.example"),
            endpoints: vec!["203.0.113.1:443".parse().unwrap()],
            service: service(443, ApplicationProtocol::Http2),
            tls_policy: TlsTrustPolicy::Dane,
            tlsa_records: vec![
                CanonicalTlsa::new({
                    let mut rdata = vec![3, 1, 1];
                    rdata.extend_from_slice(&[1; 32]);
                    rdata
                })
                .unwrap(),
            ],
            provenance: provenance(Namespace::Icann, 1),
            freshness: freshness(60),
        };
        assert_eq!(
            ValidatedOriginPlan::new(input.clone()),
            Err(ValidationError::InvalidEvidence)
        );
        input.provenance = provenance(Namespace::Hns, 1);
        assert_eq!(
            ValidatedOriginPlan::new(input),
            Err(ValidationError::InvalidPlan)
        );
    }

    #[test]
    fn evidence_query_and_root_positions_are_bound() {
        let wrong_query = OriginQuery::new(
            host("www.example"),
            OriginScheme::Wss,
            None,
            ProtocolCapabilities::all(),
        );
        let wrong_evidence = ValidatedAbsence::new(
            Namespace::Icann,
            wrong_query,
            AbsenceKind::DnssecAuthenticatedNxDomain,
            provenance(Namespace::Icann, 1),
            freshness(60),
        )
        .unwrap();
        assert_eq!(
            decide_namespace(
                &query(),
                RootLookup::Present(plan(Namespace::Hns, 10)),
                RootLookup::Absent(wrong_evidence),
                SelectionPolicy::default(),
                NOW,
            ),
            Err(ClassificationError::QueryMismatch {
                namespace: Namespace::Icann,
            })
        );
    }

    #[test]
    fn decision_fingerprint_ignores_freshness_but_binds_selection_and_plan() {
        let hns = plan(Namespace::Hns, 10);
        let icann = plan(Namespace::Icann, 11);
        let icann_selected = decide_namespace(
            &query(),
            RootLookup::Present(hns.clone()),
            RootLookup::Present(icann.clone()),
            SelectionPolicy::new(DefaultPrecedence::PreferIcann, 4),
            NOW,
        )
        .unwrap();
        let hns_selected = decide_namespace(
            &query(),
            RootLookup::Present(hns.clone()),
            RootLookup::Present(icann.clone()),
            SelectionPolicy::new(DefaultPrecedence::PreferIcann, 4)
                .with_explicit_pin(Some(Namespace::Hns)),
            NOW,
        )
        .unwrap();
        let revision_changed = decide_namespace(
            &query(),
            RootLookup::Present(hns),
            RootLookup::Present(icann),
            SelectionPolicy::new(DefaultPrecedence::PreferIcann, 5),
            NOW,
        )
        .unwrap();
        assert_ne!(
            decision_fingerprint(&icann_selected),
            decision_fingerprint(&hns_selected)
        );
        assert_ne!(
            decision_fingerprint(&icann_selected),
            decision_fingerprint(&revision_changed)
        );

        let mut refreshed_hns = plan(Namespace::Hns, 10);
        refreshed_hns.freshness = freshness(20);
        refreshed_hns.provenance = EvidenceProvenance::Hns {
            network: HnsNetwork::Mainnet,
            tree_root: [77; 32],
            height: 77,
        };
        let mut refreshed_icann = plan(Namespace::Icann, 11);
        refreshed_icann.freshness = freshness(25);
        let refreshed = decide_namespace(
            &query(),
            RootLookup::Present(refreshed_hns.clone()),
            RootLookup::Present(refreshed_icann),
            SelectionPolicy::new(DefaultPrecedence::PreferIcann, 4),
            NOW,
        )
        .unwrap();
        assert_eq!(
            decision_fingerprint(&icann_selected),
            decision_fingerprint(&refreshed)
        );

        refreshed_hns.provenance = EvidenceProvenance::Hns {
            network: HnsNetwork::Testnet,
            tree_root: [77; 32],
            height: 77,
        };
        let changed_network = decide_namespace(
            &query(),
            RootLookup::Present(refreshed_hns),
            RootLookup::Present(plan(Namespace::Icann, 11)),
            SelectionPolicy::new(DefaultPrecedence::PreferIcann, 4),
            NOW,
        )
        .unwrap();
        assert_ne!(
            decision_fingerprint(&icann_selected),
            decision_fingerprint(&changed_network)
        );

        let wss_query = OriginQuery::new(
            host("www.example"),
            OriginScheme::Wss,
            None,
            ProtocolCapabilities::all(),
        );
        let mut wss_hns = plan(Namespace::Hns, 10);
        let mut wss_icann = plan(Namespace::Icann, 11);
        wss_hns.query = wss_query.clone();
        wss_icann.query = wss_query.clone();
        let wss_decision = decide_namespace(
            &wss_query,
            RootLookup::Present(wss_hns),
            RootLookup::Present(wss_icann),
            SelectionPolicy::new(DefaultPrecedence::PreferIcann, 4),
            NOW,
        )
        .unwrap();
        assert_ne!(
            decision_fingerprint(&icann_selected),
            decision_fingerprint(&wss_decision)
        );
    }

    #[test]
    fn freshness_uses_earliest_root_expiry() {
        let outcome = decide_namespace(
            &query(),
            RootLookup::Present(plan(Namespace::Hns, 10)),
            RootLookup::Present(plan(Namespace::Icann, 11)),
            SelectionPolicy::default(),
            NOW,
        )
        .unwrap();
        assert_eq!(outcome.expires_at_unix(), NOW + 40);
        assert!(outcome.is_fresh_at(NOW + 39));
        assert!(!outcome.is_fresh_at(NOW + 40));
    }

    #[test]
    fn convergent_outcome_retains_both_roots_and_their_earliest_expiry() {
        let hns = plan(Namespace::Hns, 10);
        let mut icann = plan(Namespace::Icann, 10);
        icann.freshness = freshness(5);
        let outcome = decide_namespace(
            &query(),
            RootLookup::Present(hns),
            RootLookup::Present(icann),
            SelectionPolicy::default(),
            NOW,
        )
        .unwrap();
        assert_eq!(outcome.expires_at_unix(), NOW + 5);
        assert!(matches!(
            outcome,
            NamespaceDecision {
                outcome: NamespaceOutcome::BothConvergent {
                    selected: Namespace::Icann,
                    hns: ValidatedOriginPlan {
                        namespace: Namespace::Hns,
                        ..
                    },
                    icann: ValidatedOriginPlan {
                        namespace: Namespace::Icann,
                        ..
                    },
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn classifier_rejects_stale_evidence_at_the_authority_boundary() {
        assert_eq!(
            decide_namespace(
                &query(),
                RootLookup::Present(plan(Namespace::Hns, 10)),
                RootLookup::Present(plan(Namespace::Icann, 10)),
                SelectionPolicy::default(),
                NOW + 40,
            ),
            Err(ClassificationError::StaleEvidence {
                namespace: Namespace::Hns,
            })
        );
    }

    #[test]
    fn icann_absence_and_tls_policy_require_matching_dnssec_state() {
        let insecure = EvidenceProvenance::IcannDoh {
            chain_state: IcannChainState::ProvenInsecure,
        };
        assert_eq!(
            ValidatedAbsence::new(
                Namespace::Icann,
                query(),
                AbsenceKind::DnssecAuthenticatedNxDomain,
                insecure.clone(),
                freshness(60),
            ),
            Err(ValidationError::InvalidEvidence)
        );

        let base = plan(Namespace::Icann, 10);
        let input = OriginPlanInput {
            namespace: Namespace::Icann,
            query: base.query().clone(),
            alias_path: base.alias_path().to_vec(),
            terminal_target: base.terminal_target().clone(),
            endpoint_alias_path: base.endpoint_alias_path().to_vec(),
            endpoint_target: base.endpoint_target().clone(),
            endpoints: base.endpoints().to_vec(),
            service: base.service().clone(),
            tls_policy: TlsTrustPolicy::Dane,
            tlsa_records: base.tlsa_records().to_vec(),
            provenance: insecure,
            freshness: freshness(60),
        };
        assert_eq!(
            ValidatedOriginPlan::new(input),
            Err(ValidationError::InvalidEvidence)
        );
    }

    #[test]
    fn cache_key_binds_configuration_and_comparison_schema() {
        let decision = decide_namespace(
            &query(),
            RootLookup::Present(plan(Namespace::Hns, 10)),
            RootLookup::Present(plan(Namespace::Icann, 11)),
            SelectionPolicy::new(DefaultPrecedence::PreferIcann, 4),
            NOW,
        )
        .unwrap();
        let key = DecisionCacheKey::new(&decision, [2; 32], 3);
        let changed_configuration = DecisionCacheKey::new(&decision, [3; 32], 3);
        let changed_anchor = DecisionCacheKey::new(&decision, [2; 32], 4);

        let changed_policy_decision = decide_namespace(
            &query(),
            RootLookup::Present(plan(Namespace::Hns, 10)),
            RootLookup::Present(plan(Namespace::Icann, 11)),
            SelectionPolicy::new(DefaultPrecedence::PreferIcann, 4)
                .with_explicit_pin(Some(Namespace::Hns)),
            NOW,
        )
        .unwrap();
        let changed_policy = DecisionCacheKey::new(&changed_policy_decision, [2; 32], 3);

        let mut changed_network_hns = plan(Namespace::Hns, 10);
        changed_network_hns.provenance = EvidenceProvenance::Hns {
            network: HnsNetwork::Testnet,
            tree_root: [11; 32],
            height: 10,
        };
        let changed_network_decision = decide_namespace(
            &query(),
            RootLookup::Present(changed_network_hns),
            RootLookup::Present(plan(Namespace::Icann, 11)),
            SelectionPolicy::new(DefaultPrecedence::PreferIcann, 4),
            NOW,
        )
        .unwrap();
        let changed_network = DecisionCacheKey::new(&changed_network_decision, [2; 32], 3);

        assert_eq!(key.query(), decision.query());
        assert_eq!(key.hns_network(), HnsNetwork::Mainnet);
        assert_eq!(key.decision_fingerprint(), decision_fingerprint(&decision));
        assert_ne!(key.fingerprint(), changed_configuration.fingerprint());
        assert_ne!(key.fingerprint(), changed_anchor.fingerprint());
        assert_ne!(key.fingerprint(), changed_policy.fingerprint());
        assert_ne!(key.fingerprint(), changed_network.fingerprint());
    }

    #[test]
    fn internal_sha256_matches_standard_vector() {
        assert_eq!(
            DecisionFingerprint(sha256(b"abc")).to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
