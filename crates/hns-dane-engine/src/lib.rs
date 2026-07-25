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

use hns_dane::{DaneLimits, DaneMatch, verify_dane_chain, verify_dane_ee};
use hns_dns_wire::{Message, ParseLimits, Query, Rdata, RecordType, Tlsa};
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

/// Browser authority state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityState {
    /// No local state has been opened.
    Uninitialized = 0,
    /// Local stores are available.
    LocalStateOpened = 1,
    /// Validated headers are synchronizing.
    HeaderSyncing = 2,
    /// Validated headers satisfy currency policy.
    HeaderCurrent = 3,
    /// Verified Urkel proof service is ready.
    ProofReady = 4,
    /// At least one policy-permitted DNS transport is ready.
    ResolutionTransportReady = 5,
    /// Current origin DNSSEC evidence is verified.
    DnssecVerified = 6,
    /// Current origin DANE evidence is verified.
    DaneOriginVerified = 7,
    /// Platform bridge is ready.
    BrowserBridgeReady = 8,
    /// Browser engine is active.
    Active = 9,
    /// A recoverable prerequisite is unavailable.
    Degraded = 10,
    /// Security state or policy was revoked.
    Revoked = 11,
    /// Runtime is stopped.
    Stopped = 12,
}

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

/// A query and transport admission bound to engine generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionAttempt {
    runtime_generation: u64,
    event_sequence: u64,
    admission: Admission,
    query: Query,
}

impl ResolutionAttempt {
    /// Runtime generation at admission.
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
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
    attempt_event_sequence: u64,
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

/// Local Handshake authority prerequisites for the engine-owned DNSSEC path.
///
/// DNSSEC, TLSA, DANE, and origin-SNI evidence are absent because the engine
/// derives them from [`ValidatedTlsa`], the certificate chain, and the exact
/// SNI string supplied to the origin transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalHnsPrerequisites {
    /// Verified Handshake state and Urkel proof.
    pub hns_proof: EvidenceState,
    /// Chain currency sufficiency.
    pub chain_current: EvidenceState,
}

impl LocalHnsPrerequisites {
    const fn fully_verified(self) -> bool {
        matches!(self.hns_proof, EvidenceState::Verified)
            && matches!(self.chain_current, EvidenceState::Verified)
    }
}

/// Inputs for engine-owned DNSSEC and DANE completion.
#[derive(Clone, Copy, Debug)]
pub struct ValidatedDaneInput<'a> {
    /// Verified local Handshake prerequisites.
    pub prerequisites: LocalHnsPrerequisites,
    /// Non-forgeable resolver result.
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaneCompletion {
    /// Fully verified HNS HTTPS provenance.
    pub provenance: ResolutionProvenance,
    /// Match derived locally from the correlated TLSA answer and certificate.
    pub dane_match: DaneMatch,
}

#[derive(Debug)]
struct EngineState {
    runtime_session: [u8; 16],
    runtime_generation: u64,
    event_sequence: u64,
    network: Network,
    authority_state: AuthorityState,
    policy: PolicyController,
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
                runtime_session: config.runtime_session,
                runtime_generation: 1,
                event_sequence: 0,
                network: config.network,
                authority_state: AuthorityState::Uninitialized,
                policy: PolicyController::new(config.policy),
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
        Ok(EngineSnapshot {
            schema_version: 1,
            runtime_session: state.runtime_session,
            runtime_generation: state.runtime_generation,
            event_sequence: state.event_sequence,
            network: state.network,
            authority_state: state.authority_state,
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

    /// Replace policy and increment runtime generation when it changes.
    pub fn update_policy(
        &self,
        expected_policy_generation: u64,
        next: PolicyConfig,
    ) -> Result<PolicyTransition, EngineError> {
        let mut state = self.state.write().map_err(|_| EngineError::LockPoisoned)?;
        let changed = state.policy.snapshot().config() != next;
        if changed && (state.runtime_generation == u64::MAX || state.event_sequence == u64::MAX) {
            return Err(EngineError::GenerationExhausted);
        }
        let transition = state.policy.replace(expected_policy_generation, next)?;
        if transition.changed {
            state.runtime_generation += 1;
            state.event_sequence += 1;
            if state.authority_state != AuthorityState::Stopped {
                state.authority_state = AuthorityState::Revoked;
            }
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
        if !valid_authority_transition(state.authority_state, next) {
            return Err(EngineError::InvalidAuthorityTransition);
        }
        let next_event_sequence = state
            .event_sequence
            .checked_add(1)
            .ok_or(EngineError::GenerationExhausted)?;
        state.authority_state = next;
        state.event_sequence = next_event_sequence;
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
            state.authority_state,
            AuthorityState::ResolutionTransportReady
                | AuthorityState::DnssecVerified
                | AuthorityState::DaneOriginVerified
                | AuthorityState::BrowserBridgeReady
                | AuthorityState::Active
        ) {
            return Err(EngineError::AuthorityNotReady);
        }
        let admission = state.policy.admit(transport)?;
        state.event_sequence = state
            .event_sequence
            .checked_add(1)
            .ok_or(EngineError::GenerationExhausted)?;
        Ok(ResolutionAttempt {
            runtime_generation: state.runtime_generation,
            event_sequence: state.event_sequence,
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
            attempt_event_sequence: attempt.event_sequence,
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
        if response.attempt_event_sequence != attempt.event_sequence {
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
        context: CompletionContext,
    ) -> Result<DaneCompletion, EngineError> {
        if response.attempt_event_sequence != attempt.event_sequence {
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
        if !input.prerequisites.fully_verified() {
            return Err(EngineError::Policy(PolicyError::UnverifiedEvidence));
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
        let evidence = ValidationEvidence {
            hns_proof: input.prerequisites.hns_proof,
            dnssec: EvidenceState::Verified,
            tlsa: EvidenceState::Verified,
            dane: EvidenceState::Verified,
            chain_current: input.prerequisites.chain_current,
            origin_sni: EvidenceState::Verified,
        };
        let provenance = self.complete_resolution(attempt, response, evidence, context)?;
        Ok(DaneCompletion {
            provenance,
            dane_match,
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
            state.authority_state,
            AuthorityState::DnssecVerified
                | AuthorityState::DaneOriginVerified
                | AuthorityState::BrowserBridgeReady
                | AuthorityState::Active
        ) {
            return Err(EngineError::AuthorityNotReady);
        }
        state.event_sequence = state
            .event_sequence
            .checked_add(1)
            .ok_or(EngineError::GenerationExhausted)?;
        if state.authority_state == AuthorityState::DnssecVerified {
            state.authority_state = AuthorityState::DaneOriginVerified;
        }
        let provenance = ResolutionProvenance {
            schema_version: 1,
            runtime_session: state.runtime_session,
            runtime_generation: state.runtime_generation,
            policy_generation: attempt.admission.policy_generation,
            event_sequence: state.event_sequence,
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

fn ensure_current(state: &EngineState, attempt: &ResolutionAttempt) -> Result<(), EngineError> {
    if attempt.runtime_generation != state.runtime_generation {
        return Err(EngineError::StaleRuntimeGeneration);
    }
    state.policy.accept_completion(attempt.admission)?;
    Ok(())
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

const fn valid_authority_transition(current: AuthorityState, next: AuthorityState) -> bool {
    use AuthorityState::{
        Active, BrowserBridgeReady, DaneOriginVerified, Degraded, DnssecVerified, HeaderCurrent,
        HeaderSyncing, LocalStateOpened, ProofReady, ResolutionTransportReady, Revoked, Stopped,
        Uninitialized,
    };
    matches!(
        (current, next),
        (Uninitialized, LocalStateOpened)
            | (LocalStateOpened | Degraded | Revoked, HeaderSyncing)
            | (HeaderSyncing, HeaderCurrent)
            | (HeaderCurrent, ProofReady)
            | (ProofReady, ResolutionTransportReady)
            | (ResolutionTransportReady, DnssecVerified)
            | (DnssecVerified, DaneOriginVerified)
            | (DaneOriginVerified, BrowserBridgeReady)
            | (BrowserBridgeReady, Active)
            | (
                Uninitialized
                    | LocalStateOpened
                    | HeaderSyncing
                    | HeaderCurrent
                    | ProofReady
                    | ResolutionTransportReady
                    | DnssecVerified
                    | DaneOriginVerified
                    | BrowserBridgeReady
                    | Active,
                Degraded | Revoked | Stopped
            )
            | (Degraded | Revoked, Stopped)
    )
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
    /// DNS wire failure.
    Wire(hns_dns_wire::Error),
    /// Local TLSA/DANE matching failure.
    Dane(hns_dane::DaneError),
    /// Policy failure.
    Policy(PolicyError),
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
            Self::Wire(error) => write!(formatter, "DNS wire error: {error}"),
            Self::Dane(error) => write!(formatter, "DANE error: {error}"),
            Self::Policy(error) => write!(formatter, "policy error: {error}"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Dane(error) => Some(error),
            Self::Policy(error) => Some(error),
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
    use hns_dns_wire::{Dnskey, Ds, Flags, Header, Name, ResourceRecord, Rrsig};
    use hns_dnssec::{
        ALGORITHM_RSASHA256, DnssecLimits, authenticate_dnskeys, dnskey_tag, rrsig_signed_data,
    };
    use hns_resolution_policy::{DnsRelayRequesterPolicy, EvidenceState, ObliviousDnsPolicy};
    use hns_resolver::{ResolutionStep, ResolverLimits, TlsaResolution};
    use openssl::hash::{MessageDigest, hash};
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;

    const RESPONSE_WITH_UNTRUSTED_AD: &[u8] =
        b"\x12\x34\x84\x20\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01";

    fn ready_engine() -> Engine {
        let engine = Engine::new(EngineConfig {
            runtime_session: [7; 16],
            ..EngineConfig::default()
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

    fn rsa_dnskey(rsa: &Rsa<Private>) -> Dnskey {
        let exponent = rsa.e().to_vec();
        let modulus = rsa.n().to_vec();
        let mut public_key = Vec::new();
        public_key.push(u8::try_from(exponent.len()).unwrap());
        public_key.extend_from_slice(&exponent);
        public_key.extend_from_slice(&modulus);
        Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: ALGORITHM_RSASHA256,
            public_key,
        }
    }

    fn sign_rrset(
        records: &[ResourceRecord],
        signer_name: Name,
        key: &Dnskey,
        key_pair: &PKey<Private>,
    ) -> ResourceRecord {
        let first = records.first().unwrap();
        let mut signature = Rrsig {
            type_covered: first.record_type,
            algorithm: key.algorithm,
            labels: u8::try_from(first.name.labels().len()).unwrap(),
            original_ttl: first.ttl,
            expiration: 2_000,
            inception: 1_000,
            key_tag: dnskey_tag(key),
            signer: signer_name,
            signature: Vec::new(),
        };
        let signed = rrsig_signed_data(records, &signature, 1024 * 1024).unwrap();
        let mut crypto_signer = Signer::new(MessageDigest::sha256(), key_pair).unwrap();
        crypto_signer.update(&signed).unwrap();
        signature.signature = crypto_signer.sign_to_vec().unwrap();
        ResourceRecord {
            name: first.name.clone(),
            record_type: RecordType::Rrsig,
            class: hns_dns_wire::CLASS_IN,
            ttl: first.ttl,
            rdata: Rdata::Rrsig(signature),
        }
    }

    fn authenticated_example_keys() -> (hns_dnssec::AuthenticatedDnskeys, PKey<Private>, Dnskey) {
        let zone = Name::from_ascii("example.").unwrap();
        let rsa = Rsa::generate(1024).unwrap();
        let key = rsa_dnskey(&rsa);
        let key_pair = PKey::from_rsa(rsa).unwrap();
        let dnskeys = vec![ResourceRecord {
            name: zone.clone(),
            record_type: RecordType::Dnskey,
            class: hns_dns_wire::CLASS_IN,
            ttl: 300,
            rdata: Rdata::Dnskey(key.clone()),
        }];
        let signatures = vec![sign_rrset(&dnskeys, zone.clone(), &key, &key_pair)];
        let mut key_rdata = Vec::new();
        key_rdata.extend_from_slice(&key.flags.to_be_bytes());
        key_rdata.push(key.protocol);
        key_rdata.push(key.algorithm);
        key_rdata.extend_from_slice(&key.public_key);
        let mut digest_input = Vec::new();
        zone.encode(&mut digest_input).unwrap();
        digest_input.extend_from_slice(&key_rdata);
        let ds = vec![ResourceRecord {
            name: zone.clone(),
            record_type: RecordType::Ds,
            class: hns_dns_wire::CLASS_IN,
            ttl: 300,
            rdata: Rdata::Ds(Ds {
                key_tag: dnskey_tag(&key),
                algorithm: key.algorithm,
                digest_type: 2,
                digest: hash(MessageDigest::sha256(), &digest_input)
                    .unwrap()
                    .to_vec(),
            }),
        }];
        (
            authenticate_dnskeys(
                &zone,
                &ds,
                &dnskeys,
                &signatures,
                1_500,
                DnssecLimits::default(),
            )
            .unwrap(),
            key_pair,
            key,
        )
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

        assert!(completed.provenance.untrusted_ad_claim);
        assert!(completed.provenance.evidence.fully_verified());
        assert_eq!(completed.dane_match.record_index(), 0);
        assert_eq!(completed.dane_match.selector() as u8, 0);
        assert_eq!(completed.dane_match.matching_type() as u8, 0);
        assert_eq!(
            engine.snapshot().unwrap().authority_state,
            AuthorityState::DaneOriginVerified
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the end-to-end test keeps DNSSEC, resolver, SNI, and DANE evidence in one flow"
    )]
    fn engine_consumes_local_dnssec_tlsa_and_rejects_sni_mismatch() {
        let engine = ready_engine();
        let certificate = certificate();
        let (keys, key_pair, key) = authenticated_example_keys();
        let mut resolution = TlsaResolution::for_https(
            Name::from_ascii("example.").unwrap(),
            ResolverLimits::default(),
        )
        .unwrap();
        let query = resolution.query(0x4242).unwrap();
        let tlsa_records = vec![ResourceRecord {
            name: query.question.name.clone(),
            record_type: RecordType::Tlsa,
            class: hns_dns_wire::CLASS_IN,
            ttl: 300,
            rdata: Rdata::Tlsa(Tlsa {
                usage: 3,
                selector: 0,
                matching_type: 0,
                association_data: certificate.clone(),
            }),
        }];
        let response = Message {
            header: Header {
                id: query.id,
                flags: Flags::from_bits(0x8420),
                question_count: 1,
                answer_count: 2,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![query.question.clone()],
            answers: vec![
                tlsa_records.first().unwrap().clone(),
                sign_rrset(
                    &tlsa_records,
                    Name::from_ascii("example.").unwrap(),
                    &key,
                    &key_pair,
                ),
            ],
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode(u16::MAX.into())
        .unwrap();
        let attempt = engine
            .admit_resolution(ResolutionTransport::DirectAuthoritativeTcp, query.clone())
            .unwrap();
        let parsed = engine
            .parse_response(&attempt, &response, ParseLimits::requester())
            .unwrap();
        let validated = match resolution
            .accept_response(&query, parsed.message(), &[&keys], 1_500)
            .unwrap()
        {
            ResolutionStep::Complete(validated) => Some(validated),
            ResolutionStep::FollowCname(_) => None,
        }
        .unwrap();
        let chain = [&certificate[..]];
        let prerequisites = LocalHnsPrerequisites {
            hns_proof: EvidenceState::Verified,
            chain_current: EvidenceState::Verified,
        };
        assert!(matches!(
            engine.complete_resolution_with_validated_tlsa(
                &attempt,
                &parsed,
                ValidatedDaneInput {
                    prerequisites,
                    validated: &validated,
                    certificate_chain_der: &chain,
                    origin_sni: "wrong.example",
                    validation_unix_time: i64::MAX,
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
                    prerequisites,
                    validated: &validated,
                    certificate_chain_der: &chain,
                    origin_sni: "example",
                    validation_unix_time: i64::MAX,
                    limits: DaneLimits::default(),
                },
                CompletionContext::default(),
            )
            .unwrap();
        assert!(completed.provenance.evidence.fully_verified());
        assert!(completed.provenance.untrusted_ad_claim);
        assert_eq!(
            completed.dane_match.usage(),
            hns_dane::CertificateUsage::DaneEe
        );
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
