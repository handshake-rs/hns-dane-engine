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

use hns_browser_runtime::{AuthorityState, RUNTIME_SCHEMA_VERSION, RuntimeSnapshot};
pub use hns_icann_dane::IcannDnssecStatus;
pub use hns_namespace_resolution::{Namespace, OutcomeKind, RootFailureKind, SelectionReason};
use hns_resolution_policy::{
    ChainAnchor, HnsrPolicy, Network, PolicySnapshot, ProviderPolicy, ResolutionTransport,
    ValidationEvidence, WireProfile,
};
use thiserror::Error;

/// Current shared status schema.
pub const STATUS_SCHEMA_VERSION: u16 = 2;
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

impl ProviderReadiness {
    /// Construct starting/disabled readiness directly from persistent policy.
    ///
    /// Every enabled role begins in [`ReadinessState::Starting`]; every
    /// disabled role remains [`ReadinessState::Disabled`]. Adapters can then
    /// replace enabled fields with their observed ready, limited, degraded, or
    /// revoked states.
    #[must_use]
    pub const fn from_policy(policy: PolicySnapshot) -> Self {
        let config = policy.config();
        Self {
            dns_relay: initial_readiness(config.providers.dns_relay),
            odoh_proxy: initial_readiness(config.providers.odoh_proxy),
            odoh_target: initial_readiness(config.providers.odoh_target),
            hnsr_endpoint: initial_readiness(config.hnsr.endpoint_enabled()),
            hnsr_relay: initial_readiness(config.hnsr.relay_enabled()),
            market_gossip: initial_readiness(config.providers.market_gossip),
        }
    }
}

const fn initial_readiness(enabled: bool) -> ReadinessState {
    if enabled {
        ReadinessState::Starting
    } else {
        ReadinessState::Disabled
    }
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

/// Name-free browser trust action for the ICANN TLS path.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcannTlsAction {
    /// Secure TLSA data is present and local DANE must be enforced.
    EnforceDane = 1,
    /// Secure authenticated denial permits WebPKI.
    WebPkiAuthenticatedAbsence = 2,
    /// A proven-insecure delegation permits WebPKI.
    WebPkiInsecureDelegation = 3,
    /// DNSSEC, resolver authentication, or TLSA/DANE evidence failed closed.
    FailClosed = 4,
}

/// Inputs for one checked status snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusInput {
    /// One atomically read runtime tuple, including authority state.
    pub runtime: RuntimeSnapshot,
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
    /// Full-host dual-root outcome kind, without the queried name or plans.
    pub namespace_outcome: Option<OutcomeKind>,
    /// Name-free HNS root lookup failure, when classification failed.
    pub hns_root_failure: Option<RootFailureKind>,
    /// Name-free ICANN root lookup failure, when classification failed.
    pub icann_root_failure: Option<RootFailureKind>,
    /// Namespace selected for the current decision.
    pub selected_namespace: Option<Namespace>,
    /// Stable reason for the namespace selection.
    pub selection_reason: Option<SelectionReason>,
    /// Name-free, query/policy/plan-bound namespace decision fingerprint.
    pub decision_fingerprint: Option<[u8; 32]>,
    /// Current ICANN DANE/WebPKI/fail-closed action.
    ///
    /// This may be `None` when no namespace decision exists or when the
    /// selected origin scheme is intentionally cleartext.
    pub icann_tls_action: Option<IcannTlsAction>,
    /// Canonical validating-DoH DNSSEC disposition for the ICANN action.
    pub icann_dnssec_status: Option<IcannDnssecStatus>,
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
        if input.runtime.schema_version() != RUNTIME_SCHEMA_VERSION
            || input.runtime.generation() == 0
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
        if is_experimental_p2p(input.actual_transport) {
            if input.registry_fingerprint == [0; 32] || input.protocol_version == 0 {
                return Err(StatusError::MissingProtocolIdentity);
            }
        } else if input.registry_fingerprint != [0; 32] || input.protocol_version != 0 {
            return Err(StatusError::UnexpectedProtocolIdentity);
        }
        validate_failure_reasons(
            input.runtime.authority_state(),
            input.degraded_reason,
            input.revocation_reason,
        )?;
        validate_namespace_context(&input)?;
        validate_icann_tls_context(
            input.selected_namespace == Some(Namespace::Icann),
            input.icann_root_failure,
            input.icann_tls_action,
            input.icann_dnssec_status,
            input.evidence,
        )?;
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
        self.input.runtime.session_bytes()
    }

    /// Runtime generation.
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.input.runtime.generation()
    }

    /// Policy generation.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.input.policy.generation()
    }

    /// Event sequence.
    #[must_use]
    pub const fn event_sequence(&self) -> u64 {
        self.input.runtime.event_sequence()
    }

    /// Atomically bound runtime tuple used to construct this status.
    #[must_use]
    pub const fn runtime_snapshot(&self) -> RuntimeSnapshot {
        self.input.runtime
    }

    /// Current browser authority state.
    #[must_use]
    pub const fn authority_state(&self) -> AuthorityState {
        self.input.runtime.authority_state()
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

    /// Full-host dual-root outcome kind.
    #[must_use]
    pub const fn namespace_outcome(&self) -> Option<OutcomeKind> {
        self.input.namespace_outcome
    }

    /// Name-free HNS root lookup failure.
    #[must_use]
    pub const fn hns_root_failure(&self) -> Option<RootFailureKind> {
        self.input.hns_root_failure
    }

    /// Name-free ICANN root lookup failure.
    #[must_use]
    pub const fn icann_root_failure(&self) -> Option<RootFailureKind> {
        self.input.icann_root_failure
    }

    /// Namespace selected by the current decision.
    #[must_use]
    pub const fn selected_namespace(&self) -> Option<Namespace> {
        self.input.selected_namespace
    }

    /// Stable namespace-selection reason.
    #[must_use]
    pub const fn selection_reason(&self) -> Option<SelectionReason> {
        self.input.selection_reason
    }

    /// Name-free namespace decision fingerprint.
    #[must_use]
    pub const fn decision_fingerprint(&self) -> Option<[u8; 32]> {
        self.input.decision_fingerprint
    }

    /// Current ICANN TLS action.
    #[must_use]
    pub const fn icann_tls_action(&self) -> Option<IcannTlsAction> {
        self.input.icann_tls_action
    }

    /// Canonical validating-DoH DNSSEC disposition for the ICANN action.
    #[must_use]
    pub const fn icann_dnssec_status(&self) -> Option<IcannDnssecStatus> {
        self.input.icann_dnssec_status
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

const fn is_experimental_p2p(transport: ResolutionTransport) -> bool {
    matches!(
        transport,
        ResolutionTransport::HandshakeP2pOdoh | ResolutionTransport::HandshakeP2pDnsRelay
    )
}

fn validate_failure_reasons(
    authority: AuthorityState,
    degraded: Option<DegradedReason>,
    revoked: Option<RevocationReason>,
) -> Result<(), StatusError> {
    if degraded.is_some() && revoked.is_some() {
        return Err(StatusError::ConflictingFailureReasons);
    }
    match authority {
        AuthorityState::Degraded => {
            if degraded.is_none() {
                return Err(StatusError::MissingFailureReason);
            }
        }
        AuthorityState::Revoked => {
            if revoked.is_none() {
                return Err(StatusError::MissingFailureReason);
            }
            if revoked == Some(RevocationReason::Stopped) {
                return Err(StatusError::FailureReasonMismatch);
            }
        }
        AuthorityState::Stopped => {
            if revoked.is_none() {
                return Err(StatusError::MissingFailureReason);
            }
            if revoked != Some(RevocationReason::Stopped) {
                return Err(StatusError::FailureReasonMismatch);
            }
        }
        AuthorityState::Uninitialized
        | AuthorityState::LocalStateOpened
        | AuthorityState::HeaderSyncing
        | AuthorityState::HeaderCurrent
        | AuthorityState::ProofReady
        | AuthorityState::ResolutionTransportReady
        | AuthorityState::DnssecVerified
        | AuthorityState::DaneOriginVerified
        | AuthorityState::BrowserBridgeReady
        | AuthorityState::Active => {
            if degraded.is_some() || revoked.is_some() {
                return Err(StatusError::FailureReasonMismatch);
            }
        }
    }
    Ok(())
}

fn validate_namespace_context(input: &StatusInput) -> Result<(), StatusError> {
    if input.decision_fingerprint == Some([0; 32]) {
        return Err(StatusError::InvalidDecisionFingerprint);
    }
    if input.namespace_outcome.is_some()
        && (input.hns_root_failure.is_some() || input.icann_root_failure.is_some())
    {
        return Err(StatusError::InvalidNamespaceContext);
    }

    match input.namespace_outcome {
        None => {
            if input.selected_namespace.is_some()
                || input.selection_reason.is_some()
                || input.decision_fingerprint.is_some()
            {
                return Err(StatusError::InvalidNamespaceContext);
            }
        }
        Some(OutcomeKind::Neither) => {
            if input.selected_namespace.is_some()
                || input.selection_reason.is_some()
                || input.decision_fingerprint.is_none()
                || input.actual_transport != ResolutionTransport::Unavailable
            {
                return Err(StatusError::InvalidNamespaceContext);
            }
        }
        Some(OutcomeKind::HnsOnly) => {
            if input.selected_namespace != Some(Namespace::Hns)
                || input.selection_reason.is_none()
                || input.decision_fingerprint.is_none()
            {
                return Err(StatusError::InvalidNamespaceContext);
            }
        }
        Some(OutcomeKind::IcannOnly) => {
            if input.selected_namespace != Some(Namespace::Icann)
                || input.selection_reason.is_none()
                || input.decision_fingerprint.is_none()
            {
                return Err(StatusError::InvalidNamespaceContext);
            }
        }
        Some(OutcomeKind::BothConvergent | OutcomeKind::BothDivergent) => {
            if input.selected_namespace.is_none()
                || input.selection_reason.is_none()
                || input.decision_fingerprint.is_none()
            {
                return Err(StatusError::InvalidNamespaceContext);
            }
        }
    }
    if !valid_namespace_selection(
        input.namespace_outcome,
        input.selected_namespace,
        input.selection_reason,
    ) {
        return Err(StatusError::InvalidNamespaceContext);
    }

    let selected_icann = input.selected_namespace == Some(Namespace::Icann);
    let failed_icann = input.icann_root_failure.is_some();
    let failed_hns_only = input.hns_root_failure.is_some() && !failed_icann;
    let used_icann_doh = input.actual_transport == ResolutionTransport::ValidatingIcannDoh;
    if selected_icann && !used_icann_doh {
        return Err(StatusError::InvalidIcannTlsContext);
    }
    if failed_icann && !used_icann_doh {
        return Err(StatusError::InvalidIcannTlsContext);
    }
    if failed_hns_only && input.actual_transport != ResolutionTransport::Unavailable {
        return Err(StatusError::InvalidNamespaceContext);
    }
    if used_icann_doh && !selected_icann && !failed_icann {
        return Err(StatusError::InvalidIcannTlsContext);
    }
    if !selected_icann
        && !failed_icann
        && (input.icann_tls_action.is_some() || input.icann_dnssec_status.is_some())
    {
        return Err(StatusError::InvalidIcannTlsContext);
    }
    if failed_icann && input.icann_tls_action != Some(IcannTlsAction::FailClosed) {
        return Err(StatusError::InvalidIcannTlsContext);
    }
    Ok(())
}

fn validate_icann_tls_context(
    selected_icann: bool,
    root_failure: Option<RootFailureKind>,
    action: Option<IcannTlsAction>,
    dnssec_status: Option<IcannDnssecStatus>,
    evidence: ValidationEvidence,
) -> Result<(), StatusError> {
    use hns_resolution_policy::EvidenceState::{NotAttempted, Unavailable, Verified};

    let dane =
        evidence.dnssec == Verified && evidence.tlsa == Verified && evidence.dane == Verified;
    let webpki = evidence.dnssec == Verified
        && evidence.tlsa == Unavailable
        && matches!(evidence.dane, NotAttempted | Unavailable);

    let valid = match action {
        None if selected_icann => {
            evidence.dnssec == Verified
                && evidence.tlsa == NotAttempted
                && evidence.dane == NotAttempted
                && matches!(
                    dnssec_status,
                    Some(IcannDnssecStatus::Secure | IcannDnssecStatus::InsecureDelegation)
                )
        }
        None => root_failure.is_none() && dnssec_status.is_none(),
        Some(IcannTlsAction::EnforceDane) => {
            selected_icann && dnssec_status == Some(IcannDnssecStatus::Secure) && dane
        }
        Some(IcannTlsAction::WebPkiAuthenticatedAbsence) => {
            selected_icann && dnssec_status == Some(IcannDnssecStatus::Secure) && webpki
        }
        Some(IcannTlsAction::WebPkiInsecureDelegation) => {
            selected_icann && dnssec_status == Some(IcannDnssecStatus::InsecureDelegation) && webpki
        }
        Some(IcannTlsAction::FailClosed) if root_failure.is_some() => {
            validate_icann_failure_context(root_failure, dnssec_status, evidence)
                && !dane
                && !webpki
        }
        Some(IcannTlsAction::FailClosed) => {
            selected_icann
                && matches!(
                    dnssec_status,
                    Some(IcannDnssecStatus::Secure | IcannDnssecStatus::InsecureDelegation)
                )
                && evidence.dnssec == Verified
                && !dane
                && !webpki
        }
    };
    if valid {
        Ok(())
    } else {
        Err(StatusError::InvalidIcannTlsContext)
    }
}

fn validate_icann_failure_context(
    root_failure: Option<RootFailureKind>,
    dnssec_status: Option<IcannDnssecStatus>,
    evidence: ValidationEvidence,
) -> bool {
    use hns_resolution_policy::EvidenceState::{Failed, NotAttempted, Unavailable};

    match root_failure {
        Some(RootFailureKind::BogusDnssec) => {
            dnssec_status == Some(IcannDnssecStatus::Bogus) && evidence.dnssec == Failed
        }
        Some(RootFailureKind::IndeterminateDnssec) => {
            dnssec_status == Some(IcannDnssecStatus::Indeterminate)
                && matches!(evidence.dnssec, NotAttempted | Unavailable)
        }
        Some(
            RootFailureKind::Timeout
            | RootFailureKind::Transport
            | RootFailureKind::UnauthenticatedResolver
            | RootFailureKind::MalformedResponse
            | RootFailureKind::Unsupported
            | RootFailureKind::Cancelled
            | RootFailureKind::Internal
            | RootFailureKind::StaleEvidence,
        ) => {
            dnssec_status.is_none()
                && evidence.dnssec != hns_resolution_policy::EvidenceState::Verified
        }
        Some(RootFailureKind::StaleHnsAnchor) | None => false,
    }
}

const fn valid_namespace_selection(
    outcome: Option<OutcomeKind>,
    selected: Option<Namespace>,
    reason: Option<SelectionReason>,
) -> bool {
    matches!(
        (outcome, selected, reason),
        (None | Some(OutcomeKind::Neither), None, None)
            | (
                Some(OutcomeKind::HnsOnly),
                Some(Namespace::Hns),
                Some(
                    SelectionReason::SingleRoot
                        | SelectionReason::ExplicitPin
                        | SelectionReason::StickyBinding,
                ),
            )
            | (
                Some(OutcomeKind::IcannOnly),
                Some(Namespace::Icann),
                Some(
                    SelectionReason::SingleRoot
                        | SelectionReason::ExplicitPin
                        | SelectionReason::StickyBinding,
                ),
            )
            | (
                Some(OutcomeKind::BothConvergent | OutcomeKind::BothDivergent),
                Some(Namespace::Hns),
                Some(SelectionReason::ExplicitPin | SelectionReason::StickyBinding),
            )
            | (
                Some(OutcomeKind::BothConvergent | OutcomeKind::BothDivergent),
                Some(Namespace::Icann),
                Some(
                    SelectionReason::ExplicitPin
                        | SelectionReason::StickyBinding
                        | SelectionReason::IcannDefault,
                ),
            )
    )
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
        | ResolutionTransport::AuthenticatedAuthoritativeDoh
        | ResolutionTransport::ValidatingIcannDoh => {
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
    /// Experimental P2P transport lacks registry fingerprint or protocol.
    #[error("experimental P2P transport has no protocol identity")]
    MissingProtocolIdentity,
    /// A non-P2P transport carried experimental registry identity.
    #[error("non-P2P transport carries experimental protocol identity")]
    UnexpectedProtocolIdentity,
    /// Degraded and revoked reasons cannot both be current.
    #[error("status is both degraded and revoked")]
    ConflictingFailureReasons,
    /// Degraded, revoked, or stopped authority omitted its required reason.
    #[error("authority state requires a failure reason")]
    MissingFailureReason,
    /// A failure reason conflicts with the current authority state.
    #[error("failure reason conflicts with authority state")]
    FailureReasonMismatch,
    /// Namespace outcome, selection, reason, and fingerprint are inconsistent.
    #[error("invalid name-free namespace decision context")]
    InvalidNamespaceContext,
    /// A present decision fingerprint cannot use the all-zero sentinel.
    #[error("invalid namespace decision fingerprint")]
    InvalidDecisionFingerprint,
    /// ICANN TLS action conflicts with the explicit evidence states.
    #[error("ICANN TLS action conflicts with validation evidence")]
    InvalidIcannTlsContext,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately when a locally constructed status fixture is invalid"
)]
mod tests {
    use hns_browser_runtime::{BrowserRuntime, RuntimeSessionId};
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

    fn active_runtime(session_byte: u8, dane_applies: bool) -> RuntimeSnapshot {
        let mut runtime = BrowserRuntime::new(RuntimeSessionId::new([session_byte; 16]).unwrap());
        for state in [
            AuthorityState::LocalStateOpened,
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
            AuthorityState::DnssecVerified,
        ] {
            runtime.transition(state).unwrap();
        }
        if dane_applies {
            runtime
                .transition(AuthorityState::DaneOriginVerified)
                .unwrap();
        }
        runtime
            .transition(AuthorityState::BrowserBridgeReady)
            .unwrap();
        runtime.transition(AuthorityState::Active).unwrap();
        runtime.snapshot()
    }

    fn input() -> StatusInput {
        let policy = policy();
        let mut provider_readiness = ProviderReadiness::from_policy(policy);
        provider_readiness.dns_relay = ReadinessState::Ready;
        StatusInput {
            runtime: active_runtime(7, true),
            network: Network::Mainnet,
            policy,
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
            provider_readiness,
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
            namespace_outcome: None,
            hns_root_failure: None,
            icann_root_failure: None,
            selected_namespace: None,
            selection_reason: None,
            decision_fingerprint: None,
            icann_tls_action: None,
            icann_dnssec_status: None,
            degraded_reason: None,
            revocation_reason: None,
            unsupported_evidence: Vec::new(),
        }
    }

    #[test]
    fn exposes_every_required_status_dimension() {
        let status = BrowserStatus::new(input()).unwrap();
        assert_eq!(status.schema_version(), 2);
        assert_eq!(status.authority_state(), AuthorityState::Active);
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
    fn runtime_tuple_is_bound_as_one_snapshot() {
        let input = input();
        let expected = input.runtime;
        let status = BrowserStatus::new(input).unwrap();
        assert_eq!(status.runtime_snapshot(), expected);
        assert_eq!(status.runtime_session(), expected.session_bytes());
        assert_eq!(status.runtime_generation(), expected.generation());
        assert_eq!(status.event_sequence(), expected.event_sequence());
        assert_eq!(status.authority_state(), expected.authority_state());
    }

    #[test]
    fn p2p_transport_identity_and_protocol_context_fail_closed() {
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
    fn registry_identity_is_present_exactly_for_p2p_transport() {
        let mut status = input();
        status.actual_transport = ResolutionTransport::DirectAuthoritativeTcp;
        status.identities = TransportIdentities::default();
        assert_eq!(
            BrowserStatus::new(status.clone()),
            Err(StatusError::UnexpectedProtocolIdentity)
        );
        status.registry_fingerprint = [0; 32];
        status.protocol_version = 0;
        let status = BrowserStatus::new(status).unwrap();
        assert_eq!(
            status.actual_transport(),
            ResolutionTransport::DirectAuthoritativeTcp
        );
        assert_eq!(status.registry_fingerprint(), [0; 32]);
        assert_eq!(status.protocol_version(), 0);
    }

    #[test]
    fn explicit_unattempted_stale_unsupported_and_revoked_states_survive() {
        let mut status = input();
        let mut runtime = BrowserRuntime::new(RuntimeSessionId::new([12; 16]).unwrap());
        runtime.transition(AuthorityState::Degraded).unwrap();
        status.runtime = runtime.snapshot();
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
    fn provider_readiness_is_policy_derived_and_disabled_roles_stay_disabled() {
        let mut config = policy().config();
        config.providers = ProviderPolicy {
            dns_relay: false,
            odoh_proxy: false,
            odoh_target: false,
            market_gossip: false,
        };
        config.hnsr = HnsrPolicy::disabled();
        let disabled_policy = PolicySnapshot::new(8, config).unwrap();
        let readiness = ProviderReadiness::from_policy(disabled_policy);
        assert_eq!(readiness, ProviderReadiness::default());

        let mut status = input();
        status.policy = disabled_policy;
        status.provider_readiness = readiness;
        status.actual_transport = ResolutionTransport::Unavailable;
        status.identities = TransportIdentities::default();
        status.registry_fingerprint = [0; 32];
        status.protocol_version = 0;
        status.chain_anchor = None;
        status.evidence = ValidationEvidence::not_attempted();
        BrowserStatus::new(status.clone()).unwrap();

        status.provider_readiness.odoh_proxy = ReadinessState::Ready;
        assert_eq!(
            BrowserStatus::new(status),
            Err(StatusError::InvalidProviderReadiness)
        );
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

    #[test]
    fn authority_state_enforces_failure_reason_consistency() {
        let mut runtime = BrowserRuntime::new(RuntimeSessionId::new([9; 16]).unwrap());
        runtime.transition(AuthorityState::Degraded).unwrap();
        let mut status = input();
        status.runtime = runtime.snapshot();
        status.chain_anchor = None;
        status.actual_transport = ResolutionTransport::Unavailable;
        status.identities = TransportIdentities::default();
        status.registry_fingerprint = [0; 32];
        status.protocol_version = 0;
        status.evidence = ValidationEvidence::not_attempted();
        assert_eq!(
            BrowserStatus::new(status.clone()),
            Err(StatusError::MissingFailureReason)
        );
        status.degraded_reason = Some(DegradedReason::HeaderSyncUnavailable);
        BrowserStatus::new(status.clone()).unwrap();

        status.revocation_reason = Some(RevocationReason::RuntimeChanged);
        assert_eq!(
            BrowserStatus::new(status),
            Err(StatusError::ConflictingFailureReasons)
        );

        let mut stopped = BrowserRuntime::new(RuntimeSessionId::new([10; 16]).unwrap());
        stopped.transition(AuthorityState::Stopped).unwrap();
        let mut status = input();
        status.runtime = stopped.snapshot();
        status.chain_anchor = None;
        status.actual_transport = ResolutionTransport::Unavailable;
        status.identities = TransportIdentities::default();
        status.registry_fingerprint = [0; 32];
        status.protocol_version = 0;
        status.evidence = ValidationEvidence::revoked();
        status.revocation_reason = Some(RevocationReason::PolicyChanged);
        assert_eq!(
            BrowserStatus::new(status.clone()),
            Err(StatusError::FailureReasonMismatch)
        );
        status.revocation_reason = Some(RevocationReason::Stopped);
        BrowserStatus::new(status).unwrap();
    }

    #[test]
    fn failure_reason_matrix_is_exhaustive_for_every_authority_state() {
        let states = [
            AuthorityState::Uninitialized,
            AuthorityState::LocalStateOpened,
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
            AuthorityState::DnssecVerified,
            AuthorityState::DaneOriginVerified,
            AuthorityState::BrowserBridgeReady,
            AuthorityState::Active,
            AuthorityState::Degraded,
            AuthorityState::Revoked,
            AuthorityState::Stopped,
        ];
        let degraded_options = [None, Some(DegradedReason::ResolutionTransportUnavailable)];
        let revocation_options = [
            None,
            Some(RevocationReason::PolicyChanged),
            Some(RevocationReason::Stopped),
        ];

        for authority in states {
            for degraded in degraded_options {
                for revoked in revocation_options {
                    let expected = match authority {
                        AuthorityState::Degraded => degraded.is_some() && revoked.is_none(),
                        AuthorityState::Revoked => {
                            degraded.is_none()
                                && revoked.is_some()
                                && revoked != Some(RevocationReason::Stopped)
                        }
                        AuthorityState::Stopped => {
                            degraded.is_none() && revoked == Some(RevocationReason::Stopped)
                        }
                        _ => degraded.is_none() && revoked.is_none(),
                    };
                    assert_eq!(
                        validate_failure_reasons(authority, degraded, revoked).is_ok(),
                        expected,
                        "unexpected reason result for {authority:?}, {degraded:?}, {revoked:?}"
                    );
                }
            }
        }
    }

    fn icann_input(action: IcannTlsAction) -> StatusInput {
        let mut status = input();
        status.runtime = active_runtime(11, action == IcannTlsAction::EnforceDane);
        status.actual_transport = ResolutionTransport::ValidatingIcannDoh;
        status.identities = TransportIdentities::default();
        status.registry_fingerprint = [0; 32];
        status.protocol_version = 0;
        status.chain_anchor = None;
        status.namespace_outcome = Some(OutcomeKind::IcannOnly);
        status.selected_namespace = Some(Namespace::Icann);
        status.selection_reason = Some(SelectionReason::SingleRoot);
        status.decision_fingerprint = Some([11; 32]);
        status.icann_tls_action = Some(action);
        status.icann_dnssec_status = Some(if action == IcannTlsAction::WebPkiInsecureDelegation {
            IcannDnssecStatus::InsecureDelegation
        } else {
            IcannDnssecStatus::Secure
        });
        status.evidence = ValidationEvidence::not_attempted();
        status
    }

    fn failed_icann_input(
        failure: RootFailureKind,
        dnssec_status: Option<IcannDnssecStatus>,
        evidence: ValidationEvidence,
    ) -> StatusInput {
        let mut status = input();
        status.runtime = active_runtime(11, false);
        status.actual_transport = ResolutionTransport::ValidatingIcannDoh;
        status.identities = TransportIdentities::default();
        status.registry_fingerprint = [0; 32];
        status.protocol_version = 0;
        status.chain_anchor = None;
        status.namespace_outcome = None;
        status.hns_root_failure = None;
        status.icann_root_failure = Some(failure);
        status.selected_namespace = None;
        status.selection_reason = None;
        status.decision_fingerprint = None;
        status.icann_tls_action = Some(IcannTlsAction::FailClosed);
        status.icann_dnssec_status = dnssec_status;
        status.evidence = evidence;
        status
    }

    #[test]
    fn reports_icann_dane_without_names_or_registry_metadata() {
        let mut status = icann_input(IcannTlsAction::EnforceDane);
        status.evidence.dnssec = EvidenceState::Verified;
        status.evidence.tlsa = EvidenceState::Verified;
        status.evidence.dane = EvidenceState::Verified;
        let status = BrowserStatus::new(status).unwrap();
        assert_eq!(
            status.actual_transport(),
            ResolutionTransport::ValidatingIcannDoh
        );
        assert_eq!(status.icann_tls_action(), Some(IcannTlsAction::EnforceDane));
        assert_eq!(status.selected_namespace(), Some(Namespace::Icann));
        assert_eq!(status.decision_fingerprint(), Some([11; 32]));
    }

    #[test]
    fn webpki_authenticated_absence_becomes_active_without_claiming_dane() {
        let mut status = icann_input(IcannTlsAction::WebPkiAuthenticatedAbsence);
        status.evidence.dnssec = EvidenceState::Verified;
        status.evidence.tlsa = EvidenceState::Unavailable;
        status.evidence.dane = EvidenceState::NotAttempted;
        let status = BrowserStatus::new(status).unwrap();
        assert_eq!(status.authority_state(), AuthorityState::Active);
        assert_eq!(status.evidence().dane, EvidenceState::NotAttempted);
        assert_eq!(
            status.icann_tls_action(),
            Some(IcannTlsAction::WebPkiAuthenticatedAbsence)
        );
    }

    #[test]
    fn bogus_icann_evidence_is_explicitly_fail_closed() {
        let mut evidence = ValidationEvidence::not_attempted();
        evidence.dnssec = EvidenceState::Failed;
        let mut status = failed_icann_input(
            RootFailureKind::BogusDnssec,
            Some(IcannDnssecStatus::Bogus),
            evidence,
        );
        status.icann_tls_action = None;
        assert_eq!(
            BrowserStatus::new(status.clone()),
            Err(StatusError::InvalidIcannTlsContext)
        );
        status.icann_tls_action = Some(IcannTlsAction::FailClosed);
        status.actual_transport = ResolutionTransport::Unavailable;
        assert_eq!(
            BrowserStatus::new(status.clone()),
            Err(StatusError::InvalidIcannTlsContext)
        );
        status.actual_transport = ResolutionTransport::ValidatingIcannDoh;
        let status = BrowserStatus::new(status).unwrap();
        assert_eq!(status.namespace_outcome(), None);
        assert_eq!(status.selected_namespace(), None);
        assert_eq!(
            status.icann_root_failure(),
            Some(RootFailureKind::BogusDnssec)
        );
        assert_eq!(status.icann_tls_action(), Some(IcannTlsAction::FailClosed));
        assert_ne!(status.evidence().dnssec, EvidenceState::Unavailable);
    }

    #[test]
    fn indeterminate_icann_dnssec_remains_explicitly_fail_closed() {
        let mut evidence = ValidationEvidence::not_attempted();
        evidence.dnssec = EvidenceState::Unavailable;
        evidence.tlsa = EvidenceState::Unavailable;
        evidence.dane = EvidenceState::Unavailable;
        let status = failed_icann_input(
            RootFailureKind::IndeterminateDnssec,
            Some(IcannDnssecStatus::Indeterminate),
            evidence,
        );
        let status = BrowserStatus::new(status).unwrap();
        assert_eq!(status.evidence().dnssec, EvidenceState::Unavailable);
        assert_eq!(status.icann_tls_action(), Some(IcannTlsAction::FailClosed));
    }

    #[test]
    fn hns_only_root_failure_clears_transport_provenance() {
        let mut status = input();
        status.chain_anchor = None;
        status.identities = TransportIdentities::default();
        status.registry_fingerprint = [0; 32];
        status.protocol_version = 0;
        status.evidence = ValidationEvidence::not_attempted();
        status.hns_root_failure = Some(RootFailureKind::StaleHnsAnchor);
        status.actual_transport = ResolutionTransport::DirectAuthoritativeTcp;
        assert_eq!(
            BrowserStatus::new(status.clone()),
            Err(StatusError::InvalidNamespaceContext)
        );
        status.actual_transport = ResolutionTransport::Unavailable;
        let status = BrowserStatus::new(status).unwrap();
        assert_eq!(status.actual_transport(), ResolutionTransport::Unavailable);
    }

    #[test]
    fn post_selection_dane_failure_retains_the_namespace_outcome() {
        let mut status = icann_input(IcannTlsAction::FailClosed);
        status.evidence.dnssec = EvidenceState::Verified;
        status.evidence.tlsa = EvidenceState::Verified;
        status.evidence.dane = EvidenceState::Failed;
        let status = BrowserStatus::new(status).unwrap();
        assert_eq!(status.namespace_outcome(), Some(OutcomeKind::IcannOnly));
        assert_eq!(status.selected_namespace(), Some(Namespace::Icann));
        assert_eq!(status.icann_root_failure(), None);
        assert_eq!(
            status.icann_dnssec_status(),
            Some(IcannDnssecStatus::Secure)
        );
    }

    #[test]
    fn stale_revoked_and_not_attempted_icann_evidence_can_fail_closed() {
        for (failure, evidence) in [
            (
                RootFailureKind::StaleEvidence,
                ValidationEvidence {
                    dnssec: EvidenceState::Stale,
                    tlsa: EvidenceState::Unavailable,
                    dane: EvidenceState::Unavailable,
                    ..ValidationEvidence::not_attempted()
                },
            ),
            (
                RootFailureKind::Cancelled,
                ValidationEvidence {
                    dnssec: EvidenceState::Unavailable,
                    tlsa: EvidenceState::Revoked,
                    dane: EvidenceState::Unavailable,
                    ..ValidationEvidence::not_attempted()
                },
            ),
            (
                RootFailureKind::Cancelled,
                ValidationEvidence::not_attempted(),
            ),
        ] {
            let status = failed_icann_input(failure, None, evidence);
            let status = BrowserStatus::new(status).unwrap();
            assert_eq!(status.icann_tls_action(), Some(IcannTlsAction::FailClosed));
        }
    }

    #[test]
    fn icann_tls_actions_cannot_reinterpret_failure_or_fallback_evidence() {
        let mut authenticated_absence = icann_input(IcannTlsAction::WebPkiAuthenticatedAbsence);
        authenticated_absence.evidence.dnssec = EvidenceState::Verified;
        authenticated_absence.evidence.tlsa = EvidenceState::Unavailable;
        authenticated_absence.evidence.dane = EvidenceState::NotAttempted;
        BrowserStatus::new(authenticated_absence.clone()).unwrap();

        let mut indeterminate = authenticated_absence.clone();
        indeterminate.evidence.dnssec = EvidenceState::Unavailable;
        indeterminate.evidence.dane = EvidenceState::Unavailable;
        assert_eq!(
            BrowserStatus::new(indeterminate.clone()),
            Err(StatusError::InvalidIcannTlsContext)
        );
        indeterminate.icann_tls_action = Some(IcannTlsAction::FailClosed);
        assert_eq!(
            BrowserStatus::new(indeterminate),
            Err(StatusError::InvalidIcannTlsContext)
        );

        let mut failure_as_fallback = authenticated_absence.clone();
        failure_as_fallback.evidence.dnssec = EvidenceState::Failed;
        assert_eq!(
            BrowserStatus::new(failure_as_fallback),
            Err(StatusError::InvalidIcannTlsContext)
        );

        let mut fallback_as_failure = authenticated_absence.clone();
        fallback_as_failure.icann_tls_action = Some(IcannTlsAction::FailClosed);
        assert_eq!(
            BrowserStatus::new(fallback_as_failure),
            Err(StatusError::InvalidIcannTlsContext)
        );

        let mut absence_as_insecure = authenticated_absence;
        absence_as_insecure.icann_tls_action = Some(IcannTlsAction::WebPkiInsecureDelegation);
        assert_eq!(
            BrowserStatus::new(absence_as_insecure),
            Err(StatusError::InvalidIcannTlsContext)
        );

        let mut dane = icann_input(IcannTlsAction::EnforceDane);
        dane.evidence.dnssec = EvidenceState::Verified;
        dane.evidence.tlsa = EvidenceState::Verified;
        dane.evidence.dane = EvidenceState::Verified;
        BrowserStatus::new(dane.clone()).unwrap();
        let mut dane_as_failure = dane.clone();
        dane_as_failure.icann_tls_action = Some(IcannTlsAction::FailClosed);
        assert_eq!(
            BrowserStatus::new(dane_as_failure),
            Err(StatusError::InvalidIcannTlsContext)
        );
        dane.evidence.dane = EvidenceState::Unavailable;
        assert_eq!(
            BrowserStatus::new(dane),
            Err(StatusError::InvalidIcannTlsContext)
        );

        let mut insecure = icann_input(IcannTlsAction::WebPkiInsecureDelegation);
        insecure.evidence.dnssec = EvidenceState::Verified;
        insecure.evidence.tlsa = EvidenceState::Unavailable;
        insecure.evidence.dane = EvidenceState::Unavailable;
        BrowserStatus::new(insecure.clone()).unwrap();
        insecure.icann_tls_action = Some(IcannTlsAction::WebPkiAuthenticatedAbsence);
        assert_eq!(
            BrowserStatus::new(insecure),
            Err(StatusError::InvalidIcannTlsContext)
        );
    }

    #[test]
    fn reports_divergent_root_selection_without_hostname_data() {
        let mut status = input();
        status.namespace_outcome = Some(OutcomeKind::BothDivergent);
        status.selected_namespace = Some(Namespace::Hns);
        status.selection_reason = Some(SelectionReason::ExplicitPin);
        status.decision_fingerprint = Some([12; 32]);
        status.icann_tls_action = None;
        let status = BrowserStatus::new(status).unwrap();
        assert_eq!(status.namespace_outcome(), Some(OutcomeKind::BothDivergent));
        assert_eq!(status.selected_namespace(), Some(Namespace::Hns));
        assert_eq!(
            status.selection_reason(),
            Some(SelectionReason::ExplicitPin)
        );
    }

    #[test]
    fn selected_icann_cleartext_may_omit_tls_action() {
        let mut status = icann_input(IcannTlsAction::FailClosed);
        status.icann_tls_action = None;
        status.evidence = ValidationEvidence::not_attempted();
        status.evidence.dnssec = EvidenceState::Verified;
        BrowserStatus::new(status).unwrap();
    }

    #[test]
    fn selected_icann_cleartext_still_requires_validated_dnssec() {
        for dnssec in [
            EvidenceState::Failed,
            EvidenceState::Unavailable,
            EvidenceState::Unsupported,
            EvidenceState::NotAttempted,
            EvidenceState::Stale,
            EvidenceState::Revoked,
        ] {
            let mut status = icann_input(IcannTlsAction::FailClosed);
            status.icann_tls_action = None;
            status.evidence = ValidationEvidence::not_attempted();
            status.evidence.dnssec = dnssec;
            assert_eq!(
                BrowserStatus::new(status),
                Err(StatusError::InvalidIcannTlsContext)
            );
        }
    }

    #[test]
    fn namespace_selection_reason_matrix_matches_the_classifier() {
        let outcomes = [
            OutcomeKind::HnsOnly,
            OutcomeKind::IcannOnly,
            OutcomeKind::BothConvergent,
            OutcomeKind::BothDivergent,
            OutcomeKind::Neither,
        ];
        let selections = [None, Some(Namespace::Hns), Some(Namespace::Icann)];
        let reasons = [
            None,
            Some(SelectionReason::SingleRoot),
            Some(SelectionReason::ExplicitPin),
            Some(SelectionReason::StickyBinding),
            Some(SelectionReason::IcannDefault),
        ];

        for outcome in outcomes {
            for selected in selections {
                for reason in reasons {
                    let expected = matches!(
                        (outcome, selected, reason),
                        (OutcomeKind::Neither, None, None)
                            | (
                                OutcomeKind::HnsOnly,
                                Some(Namespace::Hns),
                                Some(
                                    SelectionReason::SingleRoot
                                        | SelectionReason::ExplicitPin
                                        | SelectionReason::StickyBinding,
                                ),
                            )
                            | (
                                OutcomeKind::IcannOnly,
                                Some(Namespace::Icann),
                                Some(
                                    SelectionReason::SingleRoot
                                        | SelectionReason::ExplicitPin
                                        | SelectionReason::StickyBinding,
                                ),
                            )
                            | (
                                OutcomeKind::BothConvergent | OutcomeKind::BothDivergent,
                                Some(Namespace::Hns),
                                Some(SelectionReason::ExplicitPin | SelectionReason::StickyBinding),
                            )
                            | (
                                OutcomeKind::BothConvergent | OutcomeKind::BothDivergent,
                                Some(Namespace::Icann),
                                Some(
                                    SelectionReason::ExplicitPin
                                        | SelectionReason::StickyBinding
                                        | SelectionReason::IcannDefault,
                                ),
                            )
                    );
                    assert_eq!(
                        valid_namespace_selection(Some(outcome), selected, reason),
                        expected,
                        "unexpected selection matrix result for {outcome:?}, {selected:?}, {reason:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn namespace_decision_fields_are_structurally_bound() {
        let mut status = input();
        status.namespace_outcome = Some(OutcomeKind::IcannOnly);
        status.selected_namespace = Some(Namespace::Hns);
        status.selection_reason = Some(SelectionReason::SingleRoot);
        status.decision_fingerprint = Some([13; 32]);
        assert_eq!(
            BrowserStatus::new(status),
            Err(StatusError::InvalidNamespaceContext)
        );

        let mut status = input();
        status.namespace_outcome = Some(OutcomeKind::Neither);
        status.decision_fingerprint = Some([0; 32]);
        assert_eq!(
            BrowserStatus::new(status),
            Err(StatusError::InvalidDecisionFingerprint)
        );

        let mut status = input();
        status.namespace_outcome = Some(OutcomeKind::Neither);
        status.selected_namespace = None;
        status.selection_reason = None;
        status.decision_fingerprint = Some([15; 32]);
        assert_eq!(
            BrowserStatus::new(status),
            Err(StatusError::InvalidNamespaceContext)
        );

        let mut status = input();
        status.namespace_outcome = Some(OutcomeKind::BothDivergent);
        status.selected_namespace = Some(Namespace::Hns);
        status.selection_reason = Some(SelectionReason::ExplicitPin);
        status.decision_fingerprint = Some([14; 32]);
        status.icann_tls_action = Some(IcannTlsAction::FailClosed);
        assert_eq!(
            BrowserStatus::new(status),
            Err(StatusError::InvalidIcannTlsContext)
        );
    }
}
