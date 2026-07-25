//! Runtime-independent HNS browser engine facade.
//!
//! Native adapters supply transport bytes, a presented leaf certificate, and
//! prerequisite local cryptographic verdicts. The engine supplies
//! deterministic state, query correlation, local DANE-EE matching, policy
//! generation revocation, and structured provenance.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "protocol acronyms, shared EngineError, and explicit facade names are intentional"
)]

use std::fmt;
use std::sync::RwLock;

use hns_browser_observability::{
    BrowserStatus, DegradedReason, ProviderReadiness, RateLimitState, RevocationReason,
    StatusError, StatusInput, TransportIdentities, UnsupportedEvidence,
};
pub use hns_browser_runtime::AuthorityState;
use hns_browser_runtime::{BrowserRuntime, RuntimeError, RuntimeStamp};
use hns_dane::{DaneLimits, DaneMatch, verify_dane_chain, verify_dane_ee};
use hns_dns_wire::{Message, ParseLimits, Query, Rdata, RecordType, Tlsa};
pub use hns_gateway::{Gateway, GatewayLimits};
use hns_resolution_policy::{
    Admission, ChainAnchor, EvidenceState, Network, PolicyConfig, PolicyController, PolicyError,
    PolicySnapshot, PolicyTransition, ResolutionProvenance, ResolutionTransport, TransportPlan,
    ValidationEvidence,
};
use hns_resolver::ValidatedTlsa;

/// Stable Rust facade API version.
pub const ENGINE_API_VERSION: u32 = 1;
/// Maximum UTF-8 bytes accepted for one transport identity.
pub const MAX_TRANSPORT_IDENTITY_BYTES: usize = 256;

/// Engine construction configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineConfig {
    /// Caller-generated runtime session ID.
    pub runtime_session: [u8; 16],
    /// Handshake network.
    pub network: Network,
    /// Persisted policy snapshot.
    pub policy: PolicySnapshot,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            runtime_session: [0; 16],
            network: Network::Mainnet,
            policy: PolicySnapshot::default(),
        }
    }
}

/// Immutable structured engine status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineSnapshot {
    /// Facade schema version.
    pub schema_version: u16,
    /// Runtime session ID.
    pub runtime_session: [u8; 16],
    /// Runtime generation.
    pub runtime_generation: u64,
    /// Monotonic event sequence.
    pub event_sequence: u64,
    /// Handshake network.
    pub network: Network,
    /// Authority state.
    pub authority_state: AuthorityState,
    /// Persistent policy.
    pub policy: PolicySnapshot,
}

/// Runtime-owned fields needed to produce shared status.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObservabilityRuntime {
    /// Exact canonical experimental registry fingerprint.
    pub registry_fingerprint: [u8; 32],
    /// Negotiated protocol/status version.
    pub protocol_version: u16,
    /// Provider readiness after socket/storage admission.
    pub provider_readiness: ProviderReadiness,
    /// Name-free aggregate rate-limit status.
    pub rate_limits: RateLimitState,
    /// Recoverable degraded reason.
    pub degraded_reason: Option<DegradedReason>,
    /// Revocation reason.
    pub revocation_reason: Option<RevocationReason>,
    /// Bounded unsupported evidence details.
    pub unsupported_evidence: Vec<UnsupportedEvidence>,
}

/// A query and transport admission bound to engine generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionAttempt {
    runtime_stamp: RuntimeStamp,
    admission: Admission,
    query: Query,
}

impl ResolutionAttempt {
    /// Runtime session at admission.
    #[must_use]
    pub const fn runtime_session(&self) -> [u8; 16] {
        self.runtime_stamp.session()
    }

    /// Runtime generation at admission.
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_stamp.generation()
    }

    /// Policy generation at admission.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.admission.policy_generation
    }

    /// Actual transport for this attempt.
    #[must_use]
    pub const fn transport(&self) -> ResolutionTransport {
        self.admission.transport
    }

    /// Correlated query.
    #[must_use]
    pub const fn query(&self) -> &Query {
        &self.query
    }
}

/// Owned, structurally correlated DNS response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedResponse {
    attempt_stamp: RuntimeStamp,
    message: Message,
    untrusted_ad_claim: bool,
}

impl ParsedResponse {
    /// Parsed response message.
    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.message
    }

    /// Remote AD assertion. This is never local validation evidence.
    #[must_use]
    pub const fn untrusted_ad_claim(&self) -> bool {
        self.untrusted_ad_claim
    }
}

/// Optional identities and chain anchor attached to a completed resolution.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompletionContext {
    /// Locally validated chain anchor.
    pub chain_anchor: Option<ChainAnchor>,
    /// Relay or P2P peer identity.
    pub peer_identity: Option<String>,
    /// ODoH proxy identity.
    pub proxy_identity: Option<String>,
    /// ODoH target identity.
    pub target_identity: Option<String>,
    /// Whether ODoH privacy downgraded to direct relay.
    pub direct_relay_fallback: bool,
}

/// Local evidence required before the engine performs TLSA/DANE matching.
///
/// TLSA and DANE fields are deliberately absent: the engine derives them from
/// the correlated response and presented certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalDanePrerequisites {
    /// Verified Handshake state and Urkel proof.
    pub hns_proof: EvidenceState,
    /// Locally verified DNSSEC chain covering the correlated TLSA RRset.
    pub dnssec: EvidenceState,
    /// Chain currency sufficiency.
    pub chain_current: EvidenceState,
    /// Origin SNI match for the presented TLS certificate.
    pub origin_sni: EvidenceState,
}

/// Inputs for engine-owned DNSSEC and DANE completion.
#[derive(Clone, Copy, Debug)]
pub struct ValidatedDaneInput<'a> {
    /// Non-forgeable resolver result carrying HNS header-to-DNSSEC lineage.
    pub validated: &'a ValidatedTlsa,
    /// TLS server chain, leaf first.
    pub certificate_chain_der: &'a [&'a [u8]],
    /// Exact SNI sent to the TLS origin.
    pub origin_sni: &'a str,
    /// Explicit certificate validation time for DANE-TA.
    pub validation_unix_time: i64,
    /// DANE resource bounds.
    pub limits: DaneLimits,
}

impl LocalDanePrerequisites {
    const fn fully_verified(self) -> bool {
        matches!(self.hns_proof, EvidenceState::Verified)
            && matches!(self.dnssec, EvidenceState::Verified)
            && matches!(self.chain_current, EvidenceState::Verified)
            && matches!(self.origin_sni, EvidenceState::Verified)
    }
}

/// Completed provenance plus the locally matched TLSA record details.
#[derive(Clone, Eq, PartialEq)]
pub struct DaneCompletion {
    provenance: ResolutionProvenance,
    dane_match: DaneMatch,
    origin_sni: Option<String>,
    bridge_valid_from: Option<u64>,
    bridge_valid_until: Option<u64>,
}

impl DaneCompletion {
    /// Fully verified HNS HTTPS provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ResolutionProvenance {
        &self.provenance
    }

    /// Match derived locally from the correlated TLSA answer and certificate.
    #[must_use]
    pub const fn dane_match(&self) -> DaneMatch {
        self.dane_match
    }

    /// Exact strict-path origin, absent for the legacy prerequisite API.
    #[must_use]
    pub fn origin_sni(&self) -> Option<&str> {
        self.origin_sni.as_deref()
    }
}

impl fmt::Debug for DaneCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaneCompletion")
            .field("provenance", &self.provenance)
            .field("dane_match", &self.dane_match)
            .field(
                "origin_sni",
                &self.origin_sni.as_ref().map(|_| "[redacted]"),
            )
            .field("bridge_valid_from", &self.bridge_valid_from)
            .field("bridge_valid_until", &self.bridge_valid_until)
            .finish()
    }
}

/// Non-forgeable current-generation permission for an exact browser origin.
#[derive(Clone, Eq, PartialEq)]
pub struct BrowserBridgeAuthorization {
    runtime_session: [u8; 16],
    runtime_generation: u64,
    policy_generation: u64,
    event_sequence: u64,
    valid_from: u64,
    valid_until: u64,
    origin: String,
}

impl BrowserBridgeAuthorization {
    /// Runtime session that issued the authorization.
    #[must_use]
    pub const fn runtime_session(&self) -> [u8; 16] {
        self.runtime_session
    }

    /// Runtime generation that issued the authorization.
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    /// Policy generation that issued the authorization.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Authorization event sequence.
    #[must_use]
    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    /// First chain-currency time at which this grant may be consumed.
    #[must_use]
    pub const fn valid_from(&self) -> u64 {
        self.valid_from
    }

    /// Last chain-currency time at which this grant may be consumed.
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }

    /// Exact normalized origin SNI.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

impl fmt::Debug for BrowserBridgeAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserBridgeAuthorization")
            .field("runtime_session", &self.runtime_session)
            .field("runtime_generation", &self.runtime_generation)
            .field("policy_generation", &self.policy_generation)
            .field("event_sequence", &self.event_sequence)
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .field("origin", &"[redacted]")
            .finish()
    }
}

#[derive(Debug)]
struct EngineState {
    runtime: BrowserRuntime,
    network: Network,
    policy: PolicyController,
    last_provenance: Option<ResolutionProvenance>,
    last_evidence: ValidationEvidence,
}

/// Thread-safe deterministic browser engine.
#[derive(Debug)]
pub struct Engine {
    state: RwLock<EngineState>,
}

impl Engine {
    /// Create an engine from a checked configuration.
    #[must_use]
    pub fn new(config: EngineConfig) -> Self {
        Self {
            state: RwLock::new(EngineState {
                runtime: BrowserRuntime::new(config.runtime_session),
                network: config.network,
                policy: PolicyController::new(config.policy),
                last_provenance: None,
                last_evidence: ValidationEvidence::not_attempted(),
            }),
        }
    }

    /// Create from a versioned persisted policy blob.
    pub fn from_persisted(
        runtime_session: [u8; 16],
        network: Network,
        policy: &[u8],
    ) -> Result<Self, EngineError> {
        let policy = PolicySnapshot::decode(policy)?;
        Ok(Self::new(EngineConfig {
            runtime_session,
            network,
            policy,
        }))
    }

    /// Read structured status.
    pub fn snapshot(&self) -> Result<EngineSnapshot, EngineError> {
        let state = self.state.read().map_err(|_| EngineError::LockPoisoned)?;
        let runtime = state.runtime.snapshot();
        Ok(EngineSnapshot {
            schema_version: runtime.schema_version,
            runtime_session: runtime.session,
            runtime_generation: runtime.generation,
            event_sequence: runtime.event_sequence,
            network: state.network,
            authority_state: runtime.authority_state,
            policy: state.policy.snapshot(),
        })
    }

    /// Export the exact persistent policy representation.
    pub fn export_policy(&self) -> Result<[u8; 32], EngineError> {
        Ok(self.snapshot()?.policy.encode())
    }

    /// Read the direct-authoritative-first current plan.
    pub fn transport_plan(&self) -> Result<TransportPlan, EngineError> {
        let state = self.state.read().map_err(|_| EngineError::LockPoisoned)?;
        Ok(state.policy.transport_plan())
    }

    /// Begin one bounded fail-closed transport gateway under current policy.
    pub fn begin_gateway(&self, limits: GatewayLimits) -> Result<Gateway, EngineError> {
        let state = self.state.read().map_err(|_| EngineError::LockPoisoned)?;
        Gateway::new(state.policy.snapshot(), limits).map_err(EngineError::Gateway)
    }

    /// Produce the complete, bounded shared browser status.
    pub fn observability_status(
        &self,
        runtime: ObservabilityRuntime,
    ) -> Result<BrowserStatus, EngineError> {
        let state = self.state.read().map_err(|_| EngineError::LockPoisoned)?;
        let runtime_snapshot = state.runtime.snapshot();
        match runtime_snapshot.authority_state {
            AuthorityState::Degraded if runtime.degraded_reason.is_none() => {
                return Err(EngineError::MissingObservabilityReason);
            }
            AuthorityState::Revoked | AuthorityState::Stopped
                if runtime.revocation_reason.is_none() =>
            {
                return Err(EngineError::MissingObservabilityReason);
            }
            AuthorityState::Degraded => {
                if runtime.revocation_reason.is_some() {
                    return Err(EngineError::InvalidObservabilityReason);
                }
            }
            AuthorityState::Revoked | AuthorityState::Stopped => {
                if runtime.degraded_reason.is_some() {
                    return Err(EngineError::InvalidObservabilityReason);
                }
            }
            _ if runtime.degraded_reason.is_some() || runtime.revocation_reason.is_some() => {
                return Err(EngineError::InvalidObservabilityReason);
            }
            _ => {}
        }
        let provenance = state.last_provenance.as_ref();
        let identities = provenance.map_or_else(TransportIdentities::default, |provenance| {
            TransportIdentities {
                peer: provenance.peer_identity.clone(),
                proxy: provenance.proxy_identity.clone(),
                target: provenance.target_identity.clone(),
                direct_relay_fallback: provenance.direct_relay_fallback,
            }
        });
        BrowserStatus::new(StatusInput {
            runtime_session: runtime_snapshot.session,
            runtime_generation: runtime_snapshot.generation,
            event_sequence: runtime_snapshot.event_sequence,
            network: state.network,
            policy: state.policy.snapshot(),
            chain_anchor: provenance.and_then(|provenance| provenance.chain_anchor),
            actual_transport: provenance.map_or(ResolutionTransport::Unavailable, |provenance| {
                provenance.transport
            }),
            identities,
            registry_profile: state.policy.snapshot().config().wire_profile,
            registry_fingerprint: runtime.registry_fingerprint,
            protocol_version: runtime.protocol_version,
            provider_readiness: runtime.provider_readiness,
            rate_limits: runtime.rate_limits,
            evidence: provenance.map_or(state.last_evidence, |provenance| provenance.evidence),
            degraded_reason: runtime.degraded_reason,
            revocation_reason: runtime.revocation_reason,
            unsupported_evidence: runtime.unsupported_evidence,
        })
        .map_err(EngineError::Status)
    }

    /// Replace policy and increment runtime generation when it changes.
    pub fn update_policy(
        &self,
        expected_policy_generation: u64,
        next: PolicyConfig,
    ) -> Result<PolicyTransition, EngineError> {
        let mut state = self.state.write().map_err(|_| EngineError::LockPoisoned)?;
        let changed = state.policy.snapshot().config() != next;
        if changed {
            state
                .runtime
                .ensure_policy_change_capacity()
                .map_err(map_runtime_error)?;
        }
        let transition = state.policy.replace(expected_policy_generation, next)?;
        if transition.changed {
            state.runtime.policy_changed().map_err(map_runtime_error)?;
            state.last_provenance = None;
            state.last_evidence = ValidationEvidence::revoked();
        }
        Ok(transition)
    }

    /// Replace policy from a persistence blob whose generation must match.
    pub fn update_policy_blob(
        &self,
        expected_policy_generation: u64,
        blob: &[u8],
    ) -> Result<PolicyTransition, EngineError> {
        let decoded = PolicySnapshot::decode(blob)?;
        if decoded.generation() != expected_policy_generation {
            return Err(EngineError::Policy(PolicyError::StaleGeneration));
        }
        self.update_policy(expected_policy_generation, decoded.config())
    }

    /// Advance the explicit authority state machine.
    pub fn advance_authority_state(
        &self,
        next: AuthorityState,
    ) -> Result<EngineSnapshot, EngineError> {
        let mut state = self.state.write().map_err(|_| EngineError::LockPoisoned)?;
        state.runtime.transition(next).map_err(map_runtime_error)?;
        match next {
            AuthorityState::Degraded => {
                state.last_provenance = None;
                state.last_evidence = unavailable_evidence();
            }
            AuthorityState::Revoked | AuthorityState::Stopped => {
                state.last_provenance = None;
                state.last_evidence = ValidationEvidence::revoked();
            }
            _ => {}
        }
        drop(state);
        self.snapshot()
    }

    /// Admit one exact query on one current transport.
    pub fn admit_resolution(
        &self,
        transport: ResolutionTransport,
        query: Query,
    ) -> Result<ResolutionAttempt, EngineError> {
        let mut state = self.state.write().map_err(|_| EngineError::LockPoisoned)?;
        if !matches!(
            state.runtime.authority_state(),
            AuthorityState::ResolutionTransportReady
                | AuthorityState::DnssecVerified
                | AuthorityState::DaneOriginVerified
                | AuthorityState::BrowserBridgeReady
                | AuthorityState::Active
        ) {
            return Err(EngineError::AuthorityNotReady);
        }
        let admission = state.policy.admit(transport)?;
        let runtime_stamp = state.runtime.admit_event().map_err(map_runtime_error)?;
        Ok(ResolutionAttempt {
            runtime_stamp,
            admission,
            query,
        })
    }

    /// Parse and correlate transport bytes, rejecting revoked generations.
    pub fn parse_response(
        &self,
        attempt: &ResolutionAttempt,
        response: &[u8],
        limits: ParseLimits,
    ) -> Result<ParsedResponse, EngineError> {
        let state = self.state.read().map_err(|_| EngineError::LockPoisoned)?;
        ensure_current(&state, attempt)?;
        let message = Message::parse_with_limits(response, limits)?;
        let correlated = attempt.query.correlate(&message)?;
        let untrusted_ad_claim = correlated.untrusted_ad_claim();
        drop(state);
        Ok(ParsedResponse {
            attempt_stamp: attempt.runtime_stamp,
            message,
            untrusted_ad_claim,
        })
    }

    /// Complete a TLSA response after matching its RRset to the leaf certificate.
    ///
    /// The query must be an exact class-IN TLSA query. Only same-owner TLSA
    /// answers from the already correlated response are considered; CNAME
    /// chasing and fallback trust paths are intentionally absent.
    pub fn complete_resolution_with_local_dane(
        &self,
        attempt: &ResolutionAttempt,
        response: &ParsedResponse,
        prerequisites: LocalDanePrerequisites,
        certificate_der: &[u8],
        limits: DaneLimits,
        context: CompletionContext,
    ) -> Result<DaneCompletion, EngineError> {
        if response.attempt_stamp != attempt.runtime_stamp {
            return Err(EngineError::ResponseAttemptMismatch);
        }
        if response.message.header.flags.rcode() != 0 {
            return Err(EngineError::UnsuccessfulDnsResponse);
        }
        if attempt.query.question.record_type != RecordType::Tlsa
            || attempt.query.question.class != hns_dns_wire::CLASS_IN
        {
            return Err(EngineError::ExpectedTlsaQuery);
        }
        if !prerequisites.fully_verified() {
            return Err(EngineError::Policy(PolicyError::UnverifiedEvidence));
        }
        let records = exact_tlsa_answers(attempt, response);
        let dane_match = verify_dane_ee(certificate_der, &records, limits)?;
        let evidence = ValidationEvidence {
            hns_proof: prerequisites.hns_proof,
            dnssec: prerequisites.dnssec,
            tlsa: EvidenceState::Verified,
            dane: EvidenceState::Verified,
            chain_current: prerequisites.chain_current,
            origin_sni: prerequisites.origin_sni,
        };
        let provenance = self.complete_resolution(attempt, response, evidence, context)?;
        Ok(DaneCompletion {
            provenance,
            dane_match,
            origin_sni: None,
            bridge_valid_from: None,
            bridge_valid_until: None,
        })
    }

    /// Complete from non-forgeable local DNSSEC/TLSA evidence.
    ///
    /// The terminal response must carry the exact RRset represented by
    /// `validated`. The supplied origin SNI must equal the original TLSA base
    /// domain. DANE-EE or DANE-TA matching is then performed locally with no
    /// WebPKI fallback.
    pub fn complete_resolution_with_validated_tlsa(
        &self,
        attempt: &ResolutionAttempt,
        response: &ParsedResponse,
        input: ValidatedDaneInput<'_>,
        mut context: CompletionContext,
    ) -> Result<DaneCompletion, EngineError> {
        if response.attempt_stamp != attempt.runtime_stamp {
            return Err(EngineError::ResponseAttemptMismatch);
        }
        if response.message.header.flags.rcode() != 0 {
            return Err(EngineError::UnsuccessfulDnsResponse);
        }
        if attempt.query.question.record_type != RecordType::Tlsa
            || attempt.query.question.class != hns_dns_wire::CLASS_IN
            || attempt.query.question.name != *input.validated.terminal_owner()
        {
            return Err(EngineError::ExpectedTlsaQuery);
        }
        let hns_authority = input
            .validated
            .hns_authority()
            .ok_or(EngineError::MissingHnsAuthority)?;
        if input.validation_unix_time != i64::from(hns_authority.validation_time()) {
            return Err(EngineError::ValidationTimeMismatch);
        }
        if network_id(self.snapshot()?.network) != hns_authority.anchor().network().id() {
            return Err(EngineError::HnsNetworkMismatch);
        }
        if input.origin_sni != input.validated.base_domain_ascii() {
            return Err(EngineError::OriginSniMismatch);
        }
        let response_records = exact_tlsa_answers(attempt, response);
        if response_records != input.validated.records() {
            return Err(EngineError::ResponseEvidenceMismatch);
        }
        let dane_match = verify_dane_chain(
            input.certificate_chain_der,
            input.validated.base_domain_ascii(),
            input.validated.records(),
            input.validation_unix_time,
            input.limits,
        )?;
        let derived_anchor = ChainAnchor {
            height: hns_authority.anchor().height().get(),
            tree_root: hns_authority.anchor().tree_root().into_bytes(),
        };
        if context
            .chain_anchor
            .is_some_and(|provided| provided != derived_anchor)
        {
            return Err(EngineError::ChainAnchorMismatch);
        }
        context.chain_anchor = Some(derived_anchor);
        let evidence = ValidationEvidence {
            hns_proof: EvidenceState::Verified,
            dnssec: EvidenceState::Verified,
            tlsa: EvidenceState::Verified,
            dane: EvidenceState::Verified,
            chain_current: EvidenceState::Verified,
            origin_sni: EvidenceState::Verified,
        };
        let provenance = self.complete_resolution(attempt, response, evidence, context)?;
        Ok(DaneCompletion {
            provenance,
            dane_match,
            origin_sni: Some(input.origin_sni.trim_end_matches('.').to_ascii_lowercase()),
            bridge_valid_from: Some(hns_authority.anchor().validated_at().get()),
            bridge_valid_until: Some(hns_authority.anchor().valid_until().get()),
        })
    }

    /// Authorize the exact strict-path origin for the browser bridge.
    ///
    /// The completion must still be this engine's latest current-generation
    /// provenance. Legacy caller-prerequisite completions cannot mint a bridge
    /// authorization because they carry no engine-verified origin binding.
    pub fn authorize_browser_bridge(
        &self,
        completion: &DaneCompletion,
        now: u64,
    ) -> Result<BrowserBridgeAuthorization, EngineError> {
        let origin = completion
            .origin_sni
            .as_ref()
            .ok_or(EngineError::LegacyCompletionNotBridgeable)?;
        let valid_from = completion
            .bridge_valid_from
            .ok_or(EngineError::LegacyCompletionNotBridgeable)?;
        let valid_until = completion
            .bridge_valid_until
            .ok_or(EngineError::LegacyCompletionNotBridgeable)?;
        if now < valid_from {
            return Err(EngineError::CompletionNotYetValid);
        }
        if now > valid_until {
            return Err(EngineError::CompletionExpired);
        }
        let mut state = self.state.write().map_err(|_| EngineError::LockPoisoned)?;
        let runtime_before = state.runtime.snapshot();
        if !matches!(
            runtime_before.authority_state,
            AuthorityState::DaneOriginVerified
                | AuthorityState::BrowserBridgeReady
                | AuthorityState::Active
        ) {
            return Err(EngineError::AuthorityNotReady);
        }
        if state.last_provenance.as_ref() != Some(&completion.provenance)
            || completion.provenance.runtime_session != runtime_before.session
            || completion.provenance.runtime_generation != runtime_before.generation
            || completion.provenance.policy_generation != state.policy.snapshot().generation()
            || !completion.provenance.evidence.fully_verified()
        {
            return Err(EngineError::CompletionNotCurrent);
        }
        if runtime_before.authority_state == AuthorityState::DaneOriginVerified {
            state
                .runtime
                .transition(AuthorityState::BrowserBridgeReady)
                .map_err(map_runtime_error)?;
        } else {
            state.runtime.admit_event().map_err(map_runtime_error)?;
        }
        let runtime = state.runtime.snapshot();
        Ok(BrowserBridgeAuthorization {
            runtime_session: runtime.session,
            runtime_generation: runtime.generation,
            policy_generation: state.policy.snapshot().generation(),
            event_sequence: runtime.event_sequence,
            valid_from,
            valid_until,
            origin: origin.clone(),
        })
    }

    fn complete_resolution(
        &self,
        attempt: &ResolutionAttempt,
        response: &ParsedResponse,
        evidence: ValidationEvidence,
        context: CompletionContext,
    ) -> Result<ResolutionProvenance, EngineError> {
        validate_completion_context(attempt.transport(), &context)?;
        let mut state = self.state.write().map_err(|_| EngineError::LockPoisoned)?;
        ensure_current(&state, attempt)?;
        if !matches!(
            state.runtime.authority_state(),
            AuthorityState::DnssecVerified
                | AuthorityState::DaneOriginVerified
                | AuthorityState::BrowserBridgeReady
                | AuthorityState::Active
        ) {
            return Err(EngineError::AuthorityNotReady);
        }
        if state.runtime.authority_state() == AuthorityState::DnssecVerified {
            state
                .runtime
                .transition(AuthorityState::DaneOriginVerified)
                .map_err(map_runtime_error)?;
        } else {
            state.runtime.admit_event().map_err(map_runtime_error)?;
        }
        let runtime = state.runtime.snapshot();
        let provenance = ResolutionProvenance {
            schema_version: 1,
            runtime_session: runtime.session,
            runtime_generation: runtime.generation,
            policy_generation: attempt.admission.policy_generation,
            event_sequence: runtime.event_sequence,
            network: state.network,
            chain_anchor: context.chain_anchor,
            transport: attempt.admission.transport,
            peer_identity: context.peer_identity,
            proxy_identity: context.proxy_identity,
            target_identity: context.target_identity,
            direct_relay_fallback: context.direct_relay_fallback,
            registry_profile: state.policy.snapshot().config().wire_profile,
            evidence,
            untrusted_ad_claim: response.untrusted_ad_claim,
        };
        provenance.require_verified_hns_https()?;
        state.last_provenance = Some(provenance.clone());
        state.last_evidence = provenance.evidence;
        Ok(provenance)
    }
}

fn exact_tlsa_answers(attempt: &ResolutionAttempt, response: &ParsedResponse) -> Vec<Tlsa> {
    response
        .message
        .answers
        .iter()
        .filter(|record| {
            record.name == attempt.query.question.name
                && record.record_type == RecordType::Tlsa
                && record.class == attempt.query.question.class
        })
        .filter_map(|record| match &record.rdata {
            Rdata::Tlsa(tlsa) => Some(tlsa.clone()),
            _ => None,
        })
        .collect()
}

const fn network_id(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Testnet => 1,
        Network::Regtest => 2,
        Network::Simnet => 3,
    }
}

const fn unavailable_evidence() -> ValidationEvidence {
    ValidationEvidence {
        hns_proof: EvidenceState::Unavailable,
        dnssec: EvidenceState::Unavailable,
        tlsa: EvidenceState::Unavailable,
        dane: EvidenceState::Unavailable,
        chain_current: EvidenceState::Unavailable,
        origin_sni: EvidenceState::Unavailable,
    }
}

fn ensure_current(state: &EngineState, attempt: &ResolutionAttempt) -> Result<(), EngineError> {
    if !state.runtime.admits(attempt.runtime_stamp) {
        return Err(EngineError::StaleRuntimeGeneration);
    }
    state.policy.accept_completion(attempt.admission)?;
    Ok(())
}

const fn map_runtime_error(error: RuntimeError) -> EngineError {
    match error {
        RuntimeError::InvalidAuthorityTransition => EngineError::InvalidAuthorityTransition,
        RuntimeError::CounterExhausted => EngineError::GenerationExhausted,
        RuntimeError::Stopped | RuntimeError::AuthorityNotReady => EngineError::AuthorityNotReady,
    }
}

fn validate_completion_context(
    transport: ResolutionTransport,
    context: &CompletionContext,
) -> Result<(), EngineError> {
    for identity in [
        context.peer_identity.as_deref(),
        context.proxy_identity.as_deref(),
        context.target_identity.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if identity.is_empty() || identity.len() > MAX_TRANSPORT_IDENTITY_BYTES {
            return Err(EngineError::InvalidTransportIdentity);
        }
    }

    match transport {
        ResolutionTransport::HandshakeP2pOdoh => {
            let proxy = context
                .proxy_identity
                .as_deref()
                .ok_or(EngineError::MissingTransportIdentity)?;
            let target = context
                .target_identity
                .as_deref()
                .ok_or(EngineError::MissingTransportIdentity)?;
            if proxy == target {
                return Err(EngineError::ProxyTargetNotSeparated);
            }
            if context.direct_relay_fallback {
                return Err(EngineError::InvalidCompletionContext);
            }
        }
        ResolutionTransport::HandshakeP2pDnsRelay => {
            if context.peer_identity.is_none() {
                return Err(EngineError::MissingTransportIdentity);
            }
        }
        ResolutionTransport::DirectAuthoritativeUdp
        | ResolutionTransport::DirectAuthoritativeTcp
        | ResolutionTransport::AuthenticatedAuthoritativeDoh => {
            if context.direct_relay_fallback {
                return Err(EngineError::InvalidCompletionContext);
            }
        }
        ResolutionTransport::Unavailable => return Err(EngineError::InvalidCompletionContext),
    }
    Ok(())
}

/// Facade failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineError {
    /// Internal lock was poisoned by a caller panic.
    LockPoisoned,
    /// Runtime or event generation cannot advance.
    GenerationExhausted,
    /// Authority state transition is invalid.
    InvalidAuthorityTransition,
    /// Local authority prerequisites are not ready.
    AuthorityNotReady,
    /// Work belongs to an older runtime generation.
    StaleRuntimeGeneration,
    /// Parsed response belongs to another attempt.
    ResponseAttemptMismatch,
    /// A TLSA response carried a nonzero DNS response code.
    UnsuccessfulDnsResponse,
    /// Completion was attempted for a query other than class-IN TLSA.
    ExpectedTlsaQuery,
    /// An intermediary path omitted its required identity.
    MissingTransportIdentity,
    /// An intermediary identity is empty or exceeds its bound.
    InvalidTransportIdentity,
    /// ODoH proxy and target identities are not distinct.
    ProxyTargetNotSeparated,
    /// Completion context conflicts with the admitted transport.
    InvalidCompletionContext,
    /// Locally validated TLSA evidence does not match the terminal response.
    ResponseEvidenceMismatch,
    /// Actual origin SNI differs from the original TLSA base domain.
    OriginSniMismatch,
    /// Resolver evidence was not rooted in a current verified HNS resource.
    MissingHnsAuthority,
    /// DNSSEC/certificate time differs from the HNS authority validation time.
    ValidationTimeMismatch,
    /// Resolver evidence belongs to another Handshake network.
    HnsNetworkMismatch,
    /// Caller-supplied provenance conflicts with the derived HNS anchor.
    ChainAnchorMismatch,
    /// Legacy prerequisite completion has no engine-verified origin binding.
    LegacyCompletionNotBridgeable,
    /// Completion is no longer the engine's latest current-generation result.
    CompletionNotCurrent,
    /// Completion's chain-currency validity window elapsed.
    CompletionExpired,
    /// Completion predates the beginning of its chain-currency validity window.
    CompletionNotYetValid,
    /// Degraded/revoked/stopped status omitted its reason.
    MissingObservabilityReason,
    /// A status reason conflicts with the current authority state.
    InvalidObservabilityReason,
    /// DNS wire failure.
    Wire(hns_dns_wire::Error),
    /// Local TLSA/DANE matching failure.
    Dane(hns_dane::DaneError),
    /// Policy failure.
    Policy(PolicyError),
    /// Shared observability snapshot failed invariant checks.
    Status(StatusError),
    /// Fail-closed transport gateway rejected its bounds or lifecycle.
    Gateway(hns_gateway::GatewayError),
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockPoisoned => formatter.write_str("engine state lock poisoned"),
            Self::GenerationExhausted => formatter.write_str("engine generation exhausted"),
            Self::InvalidAuthorityTransition => {
                formatter.write_str("invalid browser authority state transition")
            }
            Self::AuthorityNotReady => formatter.write_str("browser authority state is not ready"),
            Self::StaleRuntimeGeneration => formatter.write_str("stale runtime generation"),
            Self::ResponseAttemptMismatch => {
                formatter.write_str("DNS response and resolution attempt mismatch")
            }
            Self::UnsuccessfulDnsResponse => {
                formatter.write_str("TLSA response has a nonzero DNS response code")
            }
            Self::ExpectedTlsaQuery => {
                formatter.write_str("local DANE completion requires a class-IN TLSA query")
            }
            Self::MissingTransportIdentity => {
                formatter.write_str("required transport identity is missing")
            }
            Self::InvalidTransportIdentity => {
                formatter.write_str("transport identity is empty or too long")
            }
            Self::ProxyTargetNotSeparated => {
                formatter.write_str("ODoH proxy and target identities are not distinct")
            }
            Self::InvalidCompletionContext => {
                formatter.write_str("completion context conflicts with selected transport")
            }
            Self::ResponseEvidenceMismatch => {
                formatter.write_str("validated TLSA evidence does not match terminal response")
            }
            Self::OriginSniMismatch => {
                formatter.write_str("origin SNI does not match the TLSA base domain")
            }
            Self::MissingHnsAuthority => {
                formatter.write_str("validated TLSA lacks on-chain HNS authority evidence")
            }
            Self::ValidationTimeMismatch => formatter
                .write_str("DANE validation time does not match HNS DNSSEC validation time"),
            Self::HnsNetworkMismatch => {
                formatter.write_str("HNS authority evidence belongs to another network")
            }
            Self::ChainAnchorMismatch => {
                formatter.write_str("completion context conflicts with derived HNS chain anchor")
            }
            Self::LegacyCompletionNotBridgeable => {
                formatter.write_str("legacy DANE completion cannot authorize a browser bridge")
            }
            Self::CompletionNotCurrent => {
                formatter.write_str("DANE completion is not current for this engine")
            }
            Self::CompletionExpired => {
                formatter.write_str("DANE completion chain-currency window expired")
            }
            Self::CompletionNotYetValid => {
                formatter.write_str("DANE completion chain-currency window has not begun")
            }
            Self::MissingObservabilityReason => {
                formatter.write_str("authority state requires an observability reason")
            }
            Self::InvalidObservabilityReason => {
                formatter.write_str("observability reason conflicts with authority state")
            }
            Self::Wire(error) => write!(formatter, "DNS wire error: {error}"),
            Self::Dane(error) => write!(formatter, "DANE error: {error}"),
            Self::Policy(error) => write!(formatter, "policy error: {error}"),
            Self::Status(error) => write!(formatter, "observability status error: {error}"),
            Self::Gateway(error) => write!(formatter, "transport gateway error: {error}"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Dane(error) => Some(error),
            Self::Policy(error) => Some(error),
            Self::Status(error) => Some(error),
            Self::Gateway(error) => Some(error),
            _ => None,
        }
    }
}

impl From<hns_dns_wire::Error> for EngineError {
    fn from(value: hns_dns_wire::Error) -> Self {
        Self::Wire(value)
    }
}

impl From<hns_dane::DaneError> for EngineError {
    fn from(value: hns_dane::DaneError) -> Self {
        Self::Dane(value)
    }
}

impl From<PolicyError> for EngineError {
    fn from(value: PolicyError) -> Self {
        Self::Policy(value)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests intentionally fail immediately on invalid fixtures"
)]
mod tests {
    use super::*;
    use hns_browser_testkit::{STRICT_HNS_ORIGIN, StrictRegtestDaneFixture};
    use hns_dns_wire::{Flags, Header, Name, ResourceRecord};
    use hns_resolution_policy::{DnsRelayRequesterPolicy, EvidenceState, ObliviousDnsPolicy};

    const RESPONSE_WITH_UNTRUSTED_AD: &[u8] =
        b"\x12\x34\x84\x20\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01";

    fn ready_engine_in_session(runtime_session: [u8; 16], network: Network) -> Engine {
        let engine = Engine::new(EngineConfig {
            runtime_session,
            network,
            policy: PolicySnapshot::default(),
        });
        for state in [
            AuthorityState::LocalStateOpened,
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
            AuthorityState::DnssecVerified,
        ] {
            engine.advance_authority_state(state).unwrap();
        }
        engine
    }

    fn ready_engine_on(network: Network) -> Engine {
        ready_engine_in_session([7; 16], network)
    }

    fn ready_engine() -> Engine {
        ready_engine_on(Network::Mainnet)
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let compact: Vec<u8> = input
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        assert!(compact.len().is_multiple_of(2));
        compact
            .chunks_exact(2)
            .map(|pair| {
                let high = char::from(*pair.first().unwrap()).to_digit(16).unwrap();
                let low = char::from(*pair.get(1).unwrap()).to_digit(16).unwrap();
                u8::try_from((high << 4) | low).unwrap()
            })
            .collect()
    }

    fn certificate() -> Vec<u8> {
        decode_hex(include_str!(
            "../../../fixtures/dane/self-signed-cert.der.hex"
        ))
    }

    fn verified_prerequisites() -> LocalDanePrerequisites {
        LocalDanePrerequisites {
            hns_proof: EvidenceState::Verified,
            dnssec: EvidenceState::Verified,
            chain_current: EvidenceState::Verified,
            origin_sni: EvidenceState::Verified,
        }
    }

    fn tlsa_exchange(tlsa: Tlsa) -> (Query, Vec<u8>) {
        let query = Query::new(
            0x1234,
            Name::from_ascii("_443._tcp.example").unwrap(),
            RecordType::Tlsa,
        )
        .unwrap();
        let response = Message {
            header: Header {
                id: query.id,
                flags: Flags::from_bits(0x8420),
                question_count: 1,
                answer_count: 1,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![query.question.clone()],
            answers: vec![ResourceRecord {
                name: query.question.name.clone(),
                record_type: RecordType::Tlsa,
                class: hns_dns_wire::CLASS_IN,
                ttl: 300,
                rdata: Rdata::Tlsa(tlsa),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode(u16::MAX.into())
        .unwrap();
        (query, response)
    }

    fn exact_certificate_exchange() -> (Query, Vec<u8>, Vec<u8>) {
        let certificate = certificate();
        let (query, response) = tlsa_exchange(Tlsa {
            usage: 3,
            selector: 0,
            matching_type: 0,
            association_data: certificate.clone(),
        });
        (query, response, certificate)
    }

    #[test]
    fn correlates_then_derives_local_dane_evidence() {
        let engine = ready_engine();
        let (query, response, certificate) = exact_certificate_exchange();
        let attempt = engine
            .admit_resolution(ResolutionTransport::HandshakeP2pOdoh, query)
            .unwrap();
        let parsed = engine
            .parse_response(&attempt, &response, ParseLimits::requester())
            .unwrap();
        let completed = engine
            .complete_resolution_with_local_dane(
                &attempt,
                &parsed,
                verified_prerequisites(),
                &certificate,
                DaneLimits::default(),
                CompletionContext {
                    proxy_identity: Some("proxy-peer".to_owned()),
                    target_identity: Some("target-peer".to_owned()),
                    ..CompletionContext::default()
                },
            )
            .unwrap();

        assert!(completed.provenance().untrusted_ad_claim);
        assert!(completed.provenance().evidence.fully_verified());
        assert_eq!(completed.dane_match().record_index(), 0);
        assert_eq!(completed.dane_match().selector() as u8, 0);
        assert_eq!(completed.dane_match().matching_type() as u8, 0);
        assert_eq!(completed.origin_sni(), None);
        assert!(matches!(
            engine.authorize_browser_bridge(&completed, 0),
            Err(EngineError::LegacyCompletionNotBridgeable)
        ));
        assert_eq!(
            engine.snapshot().unwrap().authority_state,
            AuthorityState::DaneOriginVerified
        );
    }

    #[test]
    fn rejects_attempt_replay_from_another_runtime_session() {
        let first = ready_engine_in_session([7; 16], Network::Mainnet);
        let second = ready_engine_in_session([8; 16], Network::Mainnet);
        let (query, response, _) = exact_certificate_exchange();
        let attempt = first
            .admit_resolution(ResolutionTransport::DirectAuthoritativeTcp, query)
            .unwrap();
        assert_eq!(attempt.runtime_session(), [7; 16]);
        assert!(
            first
                .parse_response(&attempt, &response, ParseLimits::requester())
                .is_ok()
        );
        assert!(matches!(
            second.parse_response(&attempt, &response, ParseLimits::requester()),
            Err(EngineError::StaleRuntimeGeneration)
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the end-to-end test keeps DNSSEC, resolver, SNI, and DANE evidence in one flow"
    )]
    fn engine_consumes_local_dnssec_tlsa_and_rejects_sni_mismatch() {
        let engine = ready_engine_on(Network::Regtest);
        let fixture = StrictRegtestDaneFixture::new().unwrap();
        let validation_time = fixture.validation_time();
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
        let chain = [fixture.certificate()];
        assert!(matches!(
            engine.complete_resolution_with_validated_tlsa(
                &attempt,
                &parsed,
                ValidatedDaneInput {
                    validated: &validated,
                    certificate_chain_der: &chain,
                    origin_sni: "wrong.alpha",
                    validation_unix_time: i64::from(validation_time),
                    limits: DaneLimits::default(),
                },
                CompletionContext::default(),
            ),
            Err(EngineError::OriginSniMismatch)
        ));
        let completed = engine
            .complete_resolution_with_validated_tlsa(
                &attempt,
                &parsed,
                ValidatedDaneInput {
                    validated: &validated,
                    certificate_chain_der: &chain,
                    origin_sni: STRICT_HNS_ORIGIN,
                    validation_unix_time: i64::from(validation_time),
                    limits: DaneLimits::default(),
                },
                CompletionContext::default(),
            )
            .unwrap();
        assert!(completed.provenance().evidence.fully_verified());
        assert!(completed.provenance().untrusted_ad_claim);
        assert_eq!(
            completed.provenance().chain_anchor,
            Some(ChainAnchor {
                height: 1,
                tree_root: fixture.authority().anchor().tree_root().into_bytes(),
            })
        );
        assert_eq!(
            completed.dane_match().usage(),
            hns_dane::CertificateUsage::DaneEe
        );
        assert_eq!(completed.origin_sni(), Some(STRICT_HNS_ORIGIN));
        assert!(matches!(
            engine.authorize_browser_bridge(&completed, u64::from(validation_time - 1)),
            Err(EngineError::CompletionNotYetValid)
        ));
        let bridge = engine
            .authorize_browser_bridge(&completed, u64::from(validation_time))
            .unwrap();
        assert_eq!(bridge.origin(), STRICT_HNS_ORIGIN);
        assert_eq!(bridge.runtime_session(), [7; 16]);
        assert_eq!(bridge.valid_from(), u64::from(validation_time));
        assert!(bridge.valid_until() >= u64::from(validation_time));
        assert!(matches!(
            engine.authorize_browser_bridge(&completed, bridge.valid_until() + 1),
            Err(EngineError::CompletionExpired)
        ));
        assert_eq!(
            engine.snapshot().unwrap().authority_state,
            AuthorityState::BrowserBridgeReady
        );
        assert!(!format!("{bridge:?}").contains(STRICT_HNS_ORIGIN));
        let status = engine
            .observability_status(ObservabilityRuntime {
                registry_fingerprint: [8; 32],
                protocol_version: 1,
                ..ObservabilityRuntime::default()
            })
            .unwrap();
        assert_eq!(
            status.actual_transport(),
            ResolutionTransport::DirectAuthoritativeTcp
        );
        assert_eq!(status.chain_anchor(), completed.provenance().chain_anchor);
        assert!(status.evidence().fully_verified());
    }

    #[test]
    fn observability_requires_reasons_and_clears_verified_state_when_degraded() {
        let engine = ready_engine();
        let initial = engine
            .observability_status(ObservabilityRuntime::default())
            .unwrap();
        assert_eq!(initial.actual_transport(), ResolutionTransport::Unavailable);
        assert_eq!(initial.evidence(), ValidationEvidence::not_attempted());

        engine
            .advance_authority_state(AuthorityState::Degraded)
            .unwrap();
        assert!(matches!(
            engine.observability_status(ObservabilityRuntime::default()),
            Err(EngineError::MissingObservabilityReason)
        ));
        let degraded = engine
            .observability_status(ObservabilityRuntime {
                degraded_reason: Some(DegradedReason::HeaderSyncUnavailable),
                ..ObservabilityRuntime::default()
            })
            .unwrap();
        assert_eq!(
            degraded.degraded_reason(),
            Some(DegradedReason::HeaderSyncUnavailable)
        );
        assert_eq!(degraded.evidence().hns_proof, EvidenceState::Unavailable);
    }

    #[test]
    fn rejects_non_tlsa_queries_wrong_owner_and_certificate_mismatch() {
        let engine = ready_engine();
        let query =
            Query::new(0x1234, Name::from_ascii("example").unwrap(), RecordType::A).unwrap();
        let attempt = engine
            .admit_resolution(ResolutionTransport::DirectAuthoritativeTcp, query)
            .unwrap();
        let parsed = engine
            .parse_response(
                &attempt,
                RESPONSE_WITH_UNTRUSTED_AD,
                ParseLimits::requester(),
            )
            .unwrap();
        assert!(matches!(
            engine.complete_resolution_with_local_dane(
                &attempt,
                &parsed,
                verified_prerequisites(),
                &certificate(),
                DaneLimits::default(),
                CompletionContext::default(),
            ),
            Err(EngineError::ExpectedTlsaQuery)
        ));

        let certificate = certificate();
        let (query, mut response) = tlsa_exchange(Tlsa {
            usage: 3,
            selector: 0,
            matching_type: 0,
            association_data: certificate.clone(),
        });
        *response.get_mut(3).unwrap() |= 3;
        let attempt = engine
            .admit_resolution(ResolutionTransport::DirectAuthoritativeTcp, query)
            .unwrap();
        let parsed = engine
            .parse_response(&attempt, &response, ParseLimits::requester())
            .unwrap();
        assert!(matches!(
            engine.complete_resolution_with_local_dane(
                &attempt,
                &parsed,
                verified_prerequisites(),
                &certificate,
                DaneLimits::default(),
                CompletionContext::default(),
            ),
            Err(EngineError::UnsuccessfulDnsResponse)
        ));

        let (query, mut response) = tlsa_exchange(Tlsa {
            usage: 3,
            selector: 0,
            matching_type: 0,
            association_data: certificate.clone(),
        });
        let answer_owner_first_byte = 12 + query.question.name.wire_len() + 4 + 1;
        *response.get_mut(answer_owner_first_byte).unwrap() = b'x';
        let attempt = engine
            .admit_resolution(ResolutionTransport::DirectAuthoritativeTcp, query)
            .unwrap();
        let parsed = engine
            .parse_response(&attempt, &response, ParseLimits::requester())
            .unwrap();
        assert!(matches!(
            engine.complete_resolution_with_local_dane(
                &attempt,
                &parsed,
                verified_prerequisites(),
                &certificate,
                DaneLimits::default(),
                CompletionContext::default(),
            ),
            Err(EngineError::Dane(hns_dane::DaneError::MissingTlsa))
        ));

        let (query, response, mut wrong_certificate) = exact_certificate_exchange();
        let last = wrong_certificate.len() - 1;
        *wrong_certificate.get_mut(last).unwrap() ^= 1;
        let attempt = engine
            .admit_resolution(ResolutionTransport::DirectAuthoritativeTcp, query)
            .unwrap();
        let parsed = engine
            .parse_response(&attempt, &response, ParseLimits::requester())
            .unwrap();
        assert!(matches!(
            engine.complete_resolution_with_local_dane(
                &attempt,
                &parsed,
                verified_prerequisites(),
                &wrong_certificate,
                DaneLimits::default(),
                CompletionContext::default(),
            ),
            Err(EngineError::Dane(hns_dane::DaneError::Mismatch))
        ));
    }

    #[test]
    fn policy_update_rejects_stale_response() {
        let engine = ready_engine();
        let query =
            Query::new(0x1234, Name::from_ascii("example").unwrap(), RecordType::A).unwrap();
        let attempt = engine
            .admit_resolution(ResolutionTransport::HandshakeP2pDnsRelay, query)
            .unwrap();
        let mut policy = engine.snapshot().unwrap().policy.config();
        policy.dns_relay_requester = DnsRelayRequesterPolicy::Disabled;
        policy.oblivious_dns = ObliviousDnsPolicy::Required;
        engine.update_policy(1, policy).unwrap();

        assert!(matches!(
            engine.parse_response(
                &attempt,
                RESPONSE_WITH_UNTRUSTED_AD,
                ParseLimits::requester()
            ),
            Err(EngineError::StaleRuntimeGeneration)
        ));
    }

    #[test]
    fn engine_gateway_revokes_on_policy_generation_change() {
        let engine = ready_engine();
        let before = engine.snapshot().unwrap().policy;
        let mut gateway = engine.begin_gateway(GatewayLimits::default()).unwrap();
        let attempt = gateway.next_attempt(before, 100).unwrap();
        assert_eq!(
            attempt.transport(),
            ResolutionTransport::DirectAuthoritativeUdp
        );

        let mut next = before.config();
        next.authenticated_authoritative_doh = false;
        engine.update_policy(before.generation(), next).unwrap();
        let after = engine.snapshot().unwrap().policy;
        assert!(matches!(
            gateway.next_attempt(after, 101),
            Err(hns_gateway::GatewayError::StalePolicy)
        ));
        assert!(matches!(
            gateway.next_attempt(before, 101),
            Err(hns_gateway::GatewayError::Terminal)
        ));
    }

    #[test]
    fn odoh_completion_requires_distinct_bounded_identities() {
        let engine = ready_engine();
        let (query, response, certificate) = exact_certificate_exchange();
        let attempt = engine
            .admit_resolution(ResolutionTransport::HandshakeP2pOdoh, query)
            .unwrap();
        let parsed = engine
            .parse_response(&attempt, &response, ParseLimits::requester())
            .unwrap();

        assert!(matches!(
            engine.complete_resolution_with_local_dane(
                &attempt,
                &parsed,
                verified_prerequisites(),
                &certificate,
                DaneLimits::default(),
                CompletionContext::default()
            ),
            Err(EngineError::MissingTransportIdentity)
        ));
        assert!(matches!(
            engine.complete_resolution_with_local_dane(
                &attempt,
                &parsed,
                verified_prerequisites(),
                &certificate,
                DaneLimits::default(),
                CompletionContext {
                    proxy_identity: Some("same-peer".to_owned()),
                    target_identity: Some("same-peer".to_owned()),
                    ..CompletionContext::default()
                }
            ),
            Err(EngineError::ProxyTargetNotSeparated)
        ));
        assert!(matches!(
            engine.complete_resolution_with_local_dane(
                &attempt,
                &parsed,
                verified_prerequisites(),
                &certificate,
                DaneLimits::default(),
                CompletionContext {
                    proxy_identity: Some("p".repeat(MAX_TRANSPORT_IDENTITY_BYTES + 1)),
                    target_identity: Some("target".to_owned()),
                    ..CompletionContext::default()
                }
            ),
            Err(EngineError::InvalidTransportIdentity)
        ));
    }

    #[test]
    fn persisted_policy_survives_restart() {
        let engine = Engine::new(EngineConfig::default());
        let mut policy = engine.snapshot().unwrap().policy.config();
        policy.dns_relay_requester = DnsRelayRequesterPolicy::Disabled;
        engine.update_policy(1, policy).unwrap();
        let blob = engine.export_policy().unwrap();

        let reopened = Engine::from_persisted([9; 16], Network::Testnet, &blob).unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().policy,
            engine.snapshot().unwrap().policy
        );
        assert!(
            !reopened
                .transport_plan()
                .unwrap()
                .contains(ResolutionTransport::HandshakeP2pDnsRelay)
        );
    }
}
