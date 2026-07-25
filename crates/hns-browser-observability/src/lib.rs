//! Bounded shared status for mobile and Chromium Handshake browser products.
//!
//! Transport is reported independently from cryptographic evidence. Status
//! contains no query names, URLs, certificate bytes, DNS payloads, or secrets.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "HNS, DNSSEC, TLSA, DANE, ODoH, and HNSR are protocol names"
)]

use hns_resolution_policy::{
    ChainAnchor, HnsrPolicy, Network, PolicySnapshot, ProviderPolicy, ResolutionTransport,
    ValidationEvidence, WireProfile,
};
use thiserror::Error;

/// Current shared status schema.
pub const STATUS_SCHEMA_VERSION: u16 = 1;
/// Maximum bytes in any reported transport identity.
pub const MAX_IDENTITY_BYTES: usize = 256;
/// Maximum unsupported-evidence entries in one snapshot.
pub const MAX_UNSUPPORTED_EVIDENCE: usize = 64;

/// Provider lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReadinessState {
    /// Role is disabled by policy.
    #[default]
    Disabled = 0,
    /// Role is starting but cannot yet accept work.
    Starting = 1,
    /// Role can accept bounded work.
    Ready = 2,
    /// Admission is temporarily rate limited.
    RateLimited = 3,
    /// A recoverable dependency is unavailable.
    Degraded = 4,
    /// A policy/runtime transition revoked the role.
    Revoked = 5,
}

/// Readiness for every independently advertised provider role.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderReadiness {
    /// HIP #76 DNS relay.
    pub dns_relay: ReadinessState,
    /// HIP #77 ODoH proxy.
    pub odoh_proxy: ReadinessState,
    /// HIP #77 ODoH target.
    pub odoh_target: ReadinessState,
    /// HNSR endpoint.
    pub hnsr_endpoint: ReadinessState,
    /// HNSR relay.
    pub hnsr_relay: ReadinessState,
    /// Experimental market gossip.
    pub market_gossip: ReadinessState,
}

/// Aggregated, name-free rate-limit status.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RateLimitState {
    /// Currently executing requests.
    pub in_flight: u32,
    /// Configured finite concurrency.
    pub max_concurrency: u32,
    /// Admitted requests in the current window.
    pub window_requests: u64,
    /// Configured finite requests per window.
    pub window_limit: u64,
    /// Lifetime rejected request count.
    pub rejected_total: u64,
    /// Whether new work is currently limited.
    pub limited: bool,
}

impl RateLimitState {
    fn validate(self) -> Result<(), StatusError> {
        if (self.max_concurrency == 0) != (self.window_limit == 0) {
            return Err(StatusError::InvalidRateLimit);
        }
        if self.max_concurrency == 0 {
            if self.in_flight != 0 || self.window_requests != 0 || self.limited {
                return Err(StatusError::InvalidRateLimit);
            }
            return Ok(());
        }
        if self.in_flight > self.max_concurrency || self.window_requests > self.window_limit {
            return Err(StatusError::InvalidRateLimit);
        }
        let saturated =
            self.in_flight == self.max_concurrency || self.window_requests == self.window_limit;
        if self.limited != saturated {
            return Err(StatusError::InvalidRateLimit);
        }
        Ok(())
    }
}

/// Stable degraded-state reason.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DegradedReason {
    /// Validated headers do not meet currency policy.
    HeadersStale = 1,
    /// Header synchronization has no usable peer.
    HeaderSyncUnavailable = 2,
    /// A current name proof could not be obtained.
    ProofUnavailable = 3,
    /// No policy-permitted DNS transport is ready.
    ResolutionTransportUnavailable = 4,
    /// Local DNSSEC validation failed.
    DnssecFailure = 5,
    /// A secure supported TLSA record is unavailable.
    TlsaFailure = 6,
    /// Local DANE origin validation failed.
    DaneFailure = 7,
    /// Platform browser bridge is unavailable.
    BrowserBridgeUnavailable = 8,
    /// An enabled provider dependency is unavailable.
    ProviderUnavailable = 9,
}

/// Stable revocation reason.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationReason {
    /// Persistent policy changed.
    PolicyChanged = 1,
    /// Runtime session or generation changed.
    RuntimeChanged = 2,
    /// Handshake network changed.
    NetworkChanged = 3,
    /// Experimental registry profile or fingerprint changed.
    RegistryChanged = 4,
    /// Provider role was disabled.
    ProviderDisabled = 5,
    /// Runtime stopped.
    Stopped = 6,
}

/// Evidence category that could not be evaluated.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceKind {
    /// Handshake header/Urkel proof.
    HnsProof = 0,
    /// Chain currency.
    ChainCurrency = 1,
    /// DNSSEC.
    Dnssec = 2,
    /// TLSA.
    Tlsa = 3,
    /// DANE.
    Dane = 4,
    /// Origin SNI.
    OriginSni = 5,
    /// Experimental transport protocol.
    TransportProtocol = 6,
}

/// Bounded unsupported-evidence detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedEvidence {
    /// Evidence category.
    pub kind: EvidenceKind,
    /// Protocol algorithm, selector, usage, version, or local reason code.
    pub code: u16,
}

/// Identity fields for the actually selected DNS transport.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransportIdentities {
    /// Relay or P2P peer.
    pub peer: Option<String>,
    /// ODoH proxy.
    pub proxy: Option<String>,
    /// ODoH target.
    pub target: Option<String>,
    /// Whether privacy policy allowed and used direct-relay fallback.
    pub direct_relay_fallback: bool,
}

/// Inputs for one checked status snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusInput {
    /// Runtime session identifier.
    pub runtime_session: [u8; 16],
    /// Runtime generation.
    pub runtime_generation: u64,
    /// Monotonic event sequence.
    pub event_sequence: u64,
    /// Handshake network.
    pub network: Network,
    /// Current policy snapshot and generation.
    pub policy: PolicySnapshot,
    /// Current locally validated chain anchor.
    pub chain_anchor: Option<ChainAnchor>,
    /// Actual selected DNS transport, not the authoritative nameserver.
    pub actual_transport: ResolutionTransport,
    /// Actual intermediary identities.
    pub identities: TransportIdentities,
    /// Negotiated experimental registry profile.
    pub registry_profile: WireProfile,
    /// Exact canonical registry fingerprint.
    pub registry_fingerprint: [u8; 32],
    /// Negotiated protocol/status version.
    pub protocol_version: u16,
    /// Readiness of every provider role.
    pub provider_readiness: ProviderReadiness,
    /// Aggregate rate-limit state without qnames.
    pub rate_limits: RateLimitState,
    /// Current local validation evidence.
    pub evidence: ValidationEvidence,
    /// Recoverable degraded reason.
    pub degraded_reason: Option<DegradedReason>,
    /// Revocation reason.
    pub revocation_reason: Option<RevocationReason>,
    /// Unsupported evidence details.
    pub unsupported_evidence: Vec<UnsupportedEvidence>,
}

/// Checked, immutable browser security status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserStatus {
    input: StatusInput,
}

impl BrowserStatus {
    /// Validate all cross-field invariants and construct one snapshot.
    pub fn new(input: StatusInput) -> Result<Self, StatusError> {
        if input.runtime_generation == 0
            || input.event_sequence == u64::MAX
            || input.policy.generation() == 0
        {
            return Err(StatusError::InvalidGeneration);
        }
        validate_identities(input.actual_transport, &input.identities)?;
        validate_provider_readiness(
            input.policy.config().providers,
            input.policy.config().hnsr,
            input.provider_readiness,
        )?;
        input.rate_limits.validate()?;
        if input.unsupported_evidence.len() > MAX_UNSUPPORTED_EVIDENCE {
            return Err(StatusError::UnsupportedEvidenceLimit);
        }
        if matches!(
            input.evidence.hns_proof,
            hns_resolution_policy::EvidenceState::Verified
        ) && input.chain_anchor.is_none()
        {
            return Err(StatusError::MissingChainAnchor);
        }
        if input.evidence.fully_verified()
            && input.actual_transport == ResolutionTransport::Unavailable
        {
            return Err(StatusError::VerifiedWithoutTransport);
        }
        if input.actual_transport != ResolutionTransport::Unavailable
            && (input.registry_fingerprint == [0; 32] || input.protocol_version == 0)
        {
            return Err(StatusError::MissingProtocolIdentity);
        }
        if input.degraded_reason.is_some() && input.revocation_reason.is_some() {
            return Err(StatusError::ConflictingFailureReasons);
        }
        Ok(Self { input })
    }

    /// Shared schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        STATUS_SCHEMA_VERSION
    }

    /// Runtime session.
    #[must_use]
    pub const fn runtime_session(&self) -> [u8; 16] {
        self.input.runtime_session
    }

    /// Runtime generation.
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.input.runtime_generation
    }

    /// Policy generation.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.input.policy.generation()
    }

    /// Event sequence.
    #[must_use]
    pub const fn event_sequence(&self) -> u64 {
        self.input.event_sequence
    }

    /// Handshake network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.input.network
    }

    /// Validated chain anchor.
    #[must_use]
    pub const fn chain_anchor(&self) -> Option<ChainAnchor> {
        self.input.chain_anchor
    }

    /// Complete current transport policy.
    #[must_use]
    pub const fn transport_policy(&self) -> PolicySnapshot {
        self.input.policy
    }

    /// Actually selected transport.
    #[must_use]
    pub const fn actual_transport(&self) -> ResolutionTransport {
        self.input.actual_transport
    }

    /// Actual intermediary identities.
    #[must_use]
    pub const fn identities(&self) -> &TransportIdentities {
        &self.input.identities
    }

    /// Registry profile.
    #[must_use]
    pub const fn registry_profile(&self) -> WireProfile {
        self.input.registry_profile
    }

    /// Canonical registry fingerprint.
    #[must_use]
    pub const fn registry_fingerprint(&self) -> [u8; 32] {
        self.input.registry_fingerprint
    }

    /// Negotiated protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.input.protocol_version
    }

    /// Explicit HNSR mode.
    #[must_use]
    pub const fn hnsr_mode(&self) -> HnsrPolicy {
        self.input.policy.config().hnsr
    }

    /// Explicit provider roles.
    #[must_use]
    pub const fn provider_roles(&self) -> ProviderPolicy {
        self.input.policy.config().providers
    }

    /// Provider readiness.
    #[must_use]
    pub const fn provider_readiness(&self) -> ProviderReadiness {
        self.input.provider_readiness
    }

    /// Aggregate rate-limit state.
    #[must_use]
    pub const fn rate_limits(&self) -> RateLimitState {
        self.input.rate_limits
    }

    /// Local evidence states.
    #[must_use]
    pub const fn evidence(&self) -> ValidationEvidence {
        self.input.evidence
    }

    /// Current degraded reason.
    #[must_use]
    pub const fn degraded_reason(&self) -> Option<DegradedReason> {
        self.input.degraded_reason
    }

    /// Current revocation reason.
    #[must_use]
    pub const fn revocation_reason(&self) -> Option<RevocationReason> {
        self.input.revocation_reason
    }

    /// Unsupported evidence details.
    #[must_use]
    pub fn unsupported_evidence(&self) -> &[UnsupportedEvidence] {
        &self.input.unsupported_evidence
    }
}

fn validate_identities(
    transport: ResolutionTransport,
    identities: &TransportIdentities,
) -> Result<(), StatusError> {
    for identity in [
        identities.peer.as_deref(),
        identities.proxy.as_deref(),
        identities.target.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if identity.is_empty() || identity.len() > MAX_IDENTITY_BYTES {
            return Err(StatusError::InvalidIdentity);
        }
    }
    match transport {
        ResolutionTransport::HandshakeP2pOdoh => {
            let proxy = identities
                .proxy
                .as_deref()
                .ok_or(StatusError::MissingIdentity)?;
            let target = identities
                .target
                .as_deref()
                .ok_or(StatusError::MissingIdentity)?;
            if proxy == target || identities.peer.is_some() || identities.direct_relay_fallback {
                return Err(StatusError::InvalidTransportContext);
            }
        }
        ResolutionTransport::HandshakeP2pDnsRelay => {
            if identities.peer.is_none()
                || identities.proxy.is_some()
                || identities.target.is_some()
            {
                return Err(StatusError::InvalidTransportContext);
            }
        }
        ResolutionTransport::DirectAuthoritativeUdp
        | ResolutionTransport::DirectAuthoritativeTcp
        | ResolutionTransport::AuthenticatedAuthoritativeDoh => {
            if identities.peer.is_some()
                || identities.proxy.is_some()
                || identities.target.is_some()
                || identities.direct_relay_fallback
            {
                return Err(StatusError::InvalidTransportContext);
            }
        }
        ResolutionTransport::Unavailable => {
            if identities != &TransportIdentities::default() {
                return Err(StatusError::InvalidTransportContext);
            }
        }
    }
    Ok(())
}

fn validate_provider_readiness(
    roles: ProviderPolicy,
    hnsr: HnsrPolicy,
    readiness: ProviderReadiness,
) -> Result<(), StatusError> {
    let endpoint_enabled = hnsr.endpoint_enabled();
    let relay_enabled = hnsr.relay_enabled();
    for (enabled, state) in [
        (roles.dns_relay, readiness.dns_relay),
        (roles.odoh_proxy, readiness.odoh_proxy),
        (roles.odoh_target, readiness.odoh_target),
        (endpoint_enabled, readiness.hnsr_endpoint),
        (relay_enabled, readiness.hnsr_relay),
        (roles.market_gossip, readiness.market_gossip),
    ] {
        if !enabled && !matches!(state, ReadinessState::Disabled | ReadinessState::Revoked) {
            return Err(StatusError::InvalidProviderReadiness);
        }
        if enabled && state == ReadinessState::Disabled {
            return Err(StatusError::InvalidProviderReadiness);
        }
    }
    Ok(())
}

/// Invalid status or cross-field inconsistency.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum StatusError {
    /// A runtime or policy generation is invalid.
    #[error("invalid status generation")]
    InvalidGeneration,
    /// An identity is empty or exceeds its byte bound.
    #[error("invalid transport identity")]
    InvalidIdentity,
    /// The selected transport requires an absent identity.
    #[error("missing transport identity")]
    MissingIdentity,
    /// Identity/fallback fields conflict with the actual transport.
    #[error("invalid actual-transport context")]
    InvalidTransportContext,
    /// Provider readiness conflicts with explicit provider policy.
    #[error("provider readiness conflicts with provider roles")]
    InvalidProviderReadiness,
    /// Rate-limit counters or saturation state are inconsistent.
    #[error("invalid rate-limit state")]
    InvalidRateLimit,
    /// Too many unsupported-evidence details were supplied.
    #[error("unsupported-evidence detail bound exceeded")]
    UnsupportedEvidenceLimit,
    /// Verified HNS proof state has no chain anchor.
    #[error("verified HNS evidence has no chain anchor")]
    MissingChainAnchor,
    /// Complete verified evidence cannot have an unavailable transport.
    #[error("verified result has no actual transport")]
    VerifiedWithoutTransport,
    /// Active transport has no registry fingerprint or protocol version.
    #[error("actual transport has no protocol identity")]
    MissingProtocolIdentity,
    /// Degraded and revoked reasons cannot both be current.
    #[error("status is both degraded and revoked")]
    ConflictingFailureReasons,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately when a locally constructed status fixture is invalid"
)]
mod tests {
    use hns_resolution_policy::{
        DnsRelayRequesterPolicy, EvidenceState, HnsrPolicy, ObliviousDnsPolicy, PolicyConfig,
        ProviderPolicy, ValidationEvidence,
    };

    use super::*;

    fn policy() -> PolicySnapshot {
        PolicySnapshot::new(
            7,
            PolicyConfig {
                dns_relay_requester: DnsRelayRequesterPolicy::Auto,
                oblivious_dns: ObliviousDnsPolicy::Preferred,
                hnsr: HnsrPolicy::disabled().with_endpoint(true),
                authenticated_authoritative_doh: true,
                providers: ProviderPolicy {
                    dns_relay: true,
                    odoh_proxy: false,
                    odoh_target: false,
                    market_gossip: false,
                },
                wire_profile: WireProfile::DenuoV1,
                allow_legacy_regtest_compatibility: false,
            },
        )
        .unwrap()
    }

    fn input() -> StatusInput {
        StatusInput {
            runtime_session: [7; 16],
            runtime_generation: 4,
            event_sequence: 9,
            network: Network::Mainnet,
            policy: policy(),
            chain_anchor: Some(ChainAnchor {
                height: 123,
                tree_root: [4; 32],
            }),
            actual_transport: ResolutionTransport::HandshakeP2pDnsRelay,
            identities: TransportIdentities {
                peer: Some("peer-a".to_owned()),
                ..TransportIdentities::default()
            },
            registry_profile: WireProfile::DenuoV1,
            registry_fingerprint: [8; 32],
            protocol_version: 1,
            provider_readiness: ProviderReadiness {
                dns_relay: ReadinessState::Ready,
                hnsr_endpoint: ReadinessState::Starting,
                ..ProviderReadiness::default()
            },
            rate_limits: RateLimitState {
                in_flight: 2,
                max_concurrency: 8,
                window_requests: 5,
                window_limit: 10,
                rejected_total: 1,
                limited: false,
            },
            evidence: ValidationEvidence {
                hns_proof: EvidenceState::Verified,
                dnssec: EvidenceState::Verified,
                tlsa: EvidenceState::Verified,
                dane: EvidenceState::Verified,
                chain_current: EvidenceState::Verified,
                origin_sni: EvidenceState::Verified,
            },
            degraded_reason: None,
            revocation_reason: None,
            unsupported_evidence: Vec::new(),
        }
    }

    #[test]
    fn exposes_every_required_status_dimension() {
        let status = BrowserStatus::new(input()).unwrap();
        assert_eq!(status.schema_version(), 1);
        assert_eq!(status.policy_generation(), 7);
        assert_eq!(
            status.actual_transport(),
            ResolutionTransport::HandshakeP2pDnsRelay
        );
        assert_eq!(status.identities().peer.as_deref(), Some("peer-a"));
        assert_eq!(
            status.hnsr_mode(),
            HnsrPolicy::disabled().with_endpoint(true)
        );
        assert!(status.provider_roles().dns_relay);
        assert_eq!(status.provider_readiness().dns_relay, ReadinessState::Ready);
        assert!(status.evidence().fully_verified());
    }

    #[test]
    fn transport_identity_and_protocol_context_fail_closed() {
        let mut status = input();
        status.actual_transport = ResolutionTransport::HandshakeP2pOdoh;
        assert_eq!(
            BrowserStatus::new(status.clone()),
            Err(StatusError::MissingIdentity)
        );
        status.identities = TransportIdentities {
            proxy: Some("same".to_owned()),
            target: Some("same".to_owned()),
            ..TransportIdentities::default()
        };
        assert_eq!(
            BrowserStatus::new(status),
            Err(StatusError::InvalidTransportContext)
        );

        let mut status = input();
        status.registry_fingerprint = [0; 32];
        assert_eq!(
            BrowserStatus::new(status),
            Err(StatusError::MissingProtocolIdentity)
        );
    }

    #[test]
    fn explicit_unattempted_stale_unsupported_and_revoked_states_survive() {
        let mut status = input();
        status.actual_transport = ResolutionTransport::Unavailable;
        status.identities = TransportIdentities::default();
        status.registry_fingerprint = [0; 32];
        status.protocol_version = 0;
        status.chain_anchor = None;
        status.evidence = ValidationEvidence::not_attempted();
        status.evidence.hns_proof = EvidenceState::Stale;
        status.evidence.dnssec = EvidenceState::Unsupported;
        status.evidence.tlsa = EvidenceState::Unavailable;
        status.evidence.dane = EvidenceState::Revoked;
        status.evidence.origin_sni = EvidenceState::Failed;
        status.unsupported_evidence.push(UnsupportedEvidence {
            kind: EvidenceKind::Dnssec,
            code: 253,
        });
        status.degraded_reason = Some(DegradedReason::HeadersStale);
        let status = BrowserStatus::new(status).unwrap();
        assert_eq!(status.evidence().hns_proof, EvidenceState::Stale);
        assert_eq!(status.evidence().dnssec, EvidenceState::Unsupported);
        assert_eq!(status.evidence().dane, EvidenceState::Revoked);
        assert_eq!(status.unsupported_evidence().len(), 1);
    }

    #[test]
    fn provider_and_rate_limit_invariants_reject_misreporting() {
        let mut status = input();
        status.provider_readiness.odoh_proxy = ReadinessState::Ready;
        assert_eq!(
            BrowserStatus::new(status),
            Err(StatusError::InvalidProviderReadiness)
        );

        let mut status = input();
        status.rate_limits.in_flight = status.rate_limits.max_concurrency;
        assert_eq!(
            BrowserStatus::new(status),
            Err(StatusError::InvalidRateLimit)
        );
    }
}
