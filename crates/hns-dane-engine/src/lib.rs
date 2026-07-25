//! Runtime-independent HNS browser engine facade.
//!
//! Native adapters supply transport bytes and local cryptographic verdicts.
//! The engine supplies deterministic state, query correlation, policy
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

use hns_dns_wire::{Message, ParseLimits, Query};
use hns_resolution_policy::{
    Admission, ChainAnchor, Network, PolicyConfig, PolicyController, PolicyError, PolicySnapshot,
    PolicyTransition, ResolutionProvenance, ResolutionTransport, TransportPlan, ValidationEvidence,
};

/// Stable Rust facade API version.
pub const ENGINE_API_VERSION: u32 = 1;

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
        let changed = state.policy.snapshot().config != next;
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
        if decoded.generation != expected_policy_generation {
            return Err(EngineError::Policy(PolicyError::StaleGeneration));
        }
        self.update_policy(expected_policy_generation, decoded.config)
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
        state.authority_state = next;
        state.event_sequence = state
            .event_sequence
            .checked_add(1)
            .ok_or(EngineError::GenerationExhausted)?;
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

    /// Complete a response only with fully verified local evidence.
    pub fn complete_resolution(
        &self,
        attempt: &ResolutionAttempt,
        response: &ParsedResponse,
        evidence: ValidationEvidence,
        context: CompletionContext,
    ) -> Result<ResolutionProvenance, EngineError> {
        if response.attempt_event_sequence != attempt.event_sequence {
            return Err(EngineError::ResponseAttemptMismatch);
        }
        if !evidence.fully_verified() {
            return Err(EngineError::Policy(PolicyError::UnverifiedEvidence));
        }
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
            registry_profile: state.policy.snapshot().config.wire_profile,
            evidence,
            untrusted_ad_claim: response.untrusted_ad_claim,
        };
        provenance.require_verified_hns_https()?;
        Ok(provenance)
    }
}

fn ensure_current(state: &EngineState, attempt: &ResolutionAttempt) -> Result<(), EngineError> {
    if attempt.runtime_generation != state.runtime_generation {
        return Err(EngineError::StaleRuntimeGeneration);
    }
    state.policy.accept_completion(attempt.admission)?;
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
    /// DNS wire failure.
    Wire(hns_dns_wire::Error),
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
            Self::Wire(error) => write!(formatter, "DNS wire error: {error}"),
            Self::Policy(error) => write!(formatter, "policy error: {error}"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
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
    use hns_dns_wire::{Name, RecordType};
    use hns_resolution_policy::{DnsRelayRequesterPolicy, EvidenceState, ObliviousDnsPolicy};

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

    fn verified_evidence() -> ValidationEvidence {
        ValidationEvidence {
            hns_proof: EvidenceState::Verified,
            dnssec: EvidenceState::Verified,
            tlsa: EvidenceState::Verified,
            dane: EvidenceState::Verified,
            chain_current: EvidenceState::Verified,
            origin_sni: EvidenceState::Verified,
        }
    }

    #[test]
    fn correlates_then_requires_local_evidence() {
        let engine = ready_engine();
        let query =
            Query::new(0x1234, Name::from_ascii("example").unwrap(), RecordType::A).unwrap();
        let attempt = engine
            .admit_resolution(ResolutionTransport::HandshakeP2pOdoh, query)
            .unwrap();
        let parsed = engine
            .parse_response(
                &attempt,
                RESPONSE_WITH_UNTRUSTED_AD,
                ParseLimits::requester(),
            )
            .unwrap();
        let provenance = engine
            .complete_resolution(
                &attempt,
                &parsed,
                verified_evidence(),
                CompletionContext {
                    proxy_identity: Some("proxy-peer".to_owned()),
                    target_identity: Some("target-peer".to_owned()),
                    ..CompletionContext::default()
                },
            )
            .unwrap();

        assert!(provenance.untrusted_ad_claim);
        assert!(provenance.evidence.fully_verified());
        assert_eq!(
            engine.snapshot().unwrap().authority_state,
            AuthorityState::DaneOriginVerified
        );
    }

    #[test]
    fn policy_update_rejects_stale_response() {
        let engine = ready_engine();
        let query =
            Query::new(0x1234, Name::from_ascii("example").unwrap(), RecordType::A).unwrap();
        let attempt = engine
            .admit_resolution(ResolutionTransport::HandshakeP2pDnsRelay, query)
            .unwrap();
        let mut policy = engine.snapshot().unwrap().policy.config;
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
    fn persisted_policy_survives_restart() {
        let engine = Engine::new(EngineConfig::default());
        let mut policy = engine.snapshot().unwrap().policy.config;
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
