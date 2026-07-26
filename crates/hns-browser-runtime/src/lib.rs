//! Session-bound lifecycle for HNS browser authority.
//!
//! The runtime owns the monotonically increasing generation and event clock
//! shared by mobile and Chromium adapters. Admission stamps include the
//! runtime session so work cannot be replayed into another engine instance,
//! even when both instances happen to have the same generation.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;

/// Shared browser-runtime status schema.
pub const RUNTIME_SCHEMA_VERSION: u16 = 2;

/// Checked, nonzero identity for one browser-runtime start.
///
/// Callers must generate a fresh, unpredictable value for every process
/// start. This type rejects the all-zero sentinel, but uniqueness and
/// unpredictability remain caller responsibilities.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeSessionId([u8; 16]);

impl RuntimeSessionId {
    /// Construct a checked runtime session identity.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::ZeroSession`] for the all-zero sentinel.
    pub const fn new(bytes: [u8; 16]) -> Result<Self, RuntimeError> {
        if u128::from_be_bytes(bytes) == 0 {
            Err(RuntimeError::ZeroSession)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Return the exact opaque session bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Borrow the exact opaque session bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl TryFrom<[u8; 16]> for RuntimeSessionId {
    type Error = RuntimeError;

    fn try_from(value: [u8; 16]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Browser authority state required by the browser resolution model.
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

/// Immutable runtime status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSnapshot {
    /// Status schema version.
    schema_version: u16,
    /// Caller-supplied per-start runtime session, which must be unique.
    session: RuntimeSessionId,
    /// Monotonic generation invalidated by policy changes.
    generation: u64,
    /// Monotonic event sequence within this session.
    event_sequence: u64,
    /// Current authority state.
    authority_state: AuthorityState,
}

impl RuntimeSnapshot {
    /// Runtime status schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Checked runtime session identity.
    #[must_use]
    pub const fn session_id(&self) -> RuntimeSessionId {
        self.session
    }

    /// Exact opaque runtime session bytes.
    #[must_use]
    pub const fn session_bytes(&self) -> [u8; 16] {
        self.session.into_bytes()
    }

    /// Current runtime generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Current monotonic event sequence.
    #[must_use]
    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    /// Current browser authority state.
    #[must_use]
    pub const fn authority_state(&self) -> AuthorityState {
        self.authority_state
    }
}

/// Opaque admission identity for work begun in one runtime session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeStamp {
    session: RuntimeSessionId,
    generation: u64,
    event_sequence: u64,
}

impl RuntimeStamp {
    /// Runtime session that admitted this work.
    #[must_use]
    pub const fn session(self) -> [u8; 16] {
        self.session.into_bytes()
    }

    /// Runtime generation that admitted this work.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Admission event sequence.
    #[must_use]
    pub const fn event_sequence(self) -> u64 {
        self.event_sequence
    }
}

/// Deterministic authority lifecycle and session clock.
///
/// This type is deliberately neither [`Clone`] nor [`Copy`]: duplicating it
/// would fork the monotonic event clock for one session.
#[derive(Debug, Eq, PartialEq)]
pub struct BrowserRuntime {
    session: RuntimeSessionId,
    generation: u64,
    event_sequence: u64,
    invalidation_sequence: u64,
    authority_state: AuthorityState,
}

impl BrowserRuntime {
    /// Start a fresh runtime session at generation one.
    #[must_use]
    pub const fn new(session: RuntimeSessionId) -> Self {
        Self {
            session,
            generation: 1,
            event_sequence: 0,
            invalidation_sequence: 0,
            authority_state: AuthorityState::Uninitialized,
        }
    }

    /// Read the complete immutable status.
    #[must_use]
    pub const fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            schema_version: RUNTIME_SCHEMA_VERSION,
            session: self.session,
            generation: self.generation,
            event_sequence: self.event_sequence,
            authority_state: self.authority_state,
        }
    }

    /// Current authority state.
    #[must_use]
    pub const fn authority_state(&self) -> AuthorityState {
        self.authority_state
    }

    /// Whether policy revocation can advance both monotonic counters.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::CounterExhausted`] if either counter is at its
    /// maximum value.
    pub const fn ensure_policy_change_capacity(&self) -> Result<(), RuntimeError> {
        if self.generation == u64::MAX || self.event_sequence == u64::MAX {
            return Err(RuntimeError::CounterExhausted);
        }
        Ok(())
    }

    /// Revoke prior work after a committed policy change.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::CounterExhausted`] if the generation or event
    /// sequence cannot advance.
    pub fn policy_changed(&mut self) -> Result<RuntimeSnapshot, RuntimeError> {
        self.ensure_policy_change_capacity()?;
        self.generation += 1;
        self.event_sequence += 1;
        self.invalidation_sequence = self.event_sequence;
        if self.authority_state != AuthorityState::Stopped {
            self.authority_state = AuthorityState::Revoked;
        }
        Ok(self.snapshot())
    }

    /// Advance the exact browser authority state machine.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidAuthorityTransition`] for an edge outside
    /// the required state graph, or [`RuntimeError::CounterExhausted`] if the
    /// event sequence cannot advance.
    pub fn transition(&mut self, next: AuthorityState) -> Result<RuntimeSnapshot, RuntimeError> {
        if !valid_authority_transition(self.authority_state, next) {
            return Err(RuntimeError::InvalidAuthorityTransition);
        }
        let event_sequence = self
            .event_sequence
            .checked_add(1)
            .ok_or(RuntimeError::CounterExhausted)?;
        self.event_sequence = event_sequence;
        if matches!(
            next,
            AuthorityState::Degraded | AuthorityState::Revoked | AuthorityState::Stopped
        ) {
            self.invalidation_sequence = event_sequence;
        }
        self.authority_state = next;
        Ok(self.snapshot())
    }

    /// Record an admitted operation and bind it to this session/generation.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::AuthorityNotReady`] before transport readiness,
    /// [`RuntimeError::Stopped`] after terminal shutdown, or
    /// [`RuntimeError::CounterExhausted`] if the event sequence cannot advance.
    pub fn admit_event(&mut self) -> Result<RuntimeStamp, RuntimeError> {
        if self.authority_state == AuthorityState::Stopped {
            return Err(RuntimeError::Stopped);
        }
        if !matches!(
            self.authority_state,
            AuthorityState::ResolutionTransportReady
                | AuthorityState::DnssecVerified
                | AuthorityState::DaneOriginVerified
                | AuthorityState::BrowserBridgeReady
                | AuthorityState::Active
        ) {
            return Err(RuntimeError::AuthorityNotReady);
        }
        self.event_sequence = self
            .event_sequence
            .checked_add(1)
            .ok_or(RuntimeError::CounterExhausted)?;
        Ok(RuntimeStamp {
            session: self.session,
            generation: self.generation,
            event_sequence: self.event_sequence,
        })
    }

    /// Check that a stamp belongs to current, already-admitted work.
    #[must_use]
    pub fn admits(&self, stamp: RuntimeStamp) -> bool {
        authority_admits_work(self.authority_state)
            && stamp.session == self.session
            && stamp.generation == self.generation
            && stamp.event_sequence > self.invalidation_sequence
            && stamp.event_sequence <= self.event_sequence
    }
}

const fn authority_admits_work(state: AuthorityState) -> bool {
    matches!(
        state,
        AuthorityState::ResolutionTransportReady
            | AuthorityState::DnssecVerified
            | AuthorityState::DaneOriginVerified
            | AuthorityState::BrowserBridgeReady
            | AuthorityState::Active
    )
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
            | (
                ResolutionTransportReady,
                DnssecVerified | BrowserBridgeReady
            )
            | (DnssecVerified, DaneOriginVerified | BrowserBridgeReady)
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

/// Browser-runtime lifecycle or counter failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    /// The all-zero runtime session sentinel is forbidden.
    ZeroSession,
    /// Requested authority transition is not in the required state graph.
    InvalidAuthorityTransition,
    /// A monotonic generation or event counter cannot advance.
    CounterExhausted,
    /// Operations cannot be admitted after the terminal stopped state.
    Stopped,
    /// Resolution work was requested before the authority transport was ready.
    AuthorityNotReady,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSession => formatter.write_str("runtime session must be nonzero"),
            Self::InvalidAuthorityTransition => {
                formatter.write_str("invalid browser authority state transition")
            }
            Self::CounterExhausted => formatter.write_str("browser runtime counter exhausted"),
            Self::Stopped => formatter.write_str("browser runtime is stopped"),
            Self::AuthorityNotReady => {
                formatter.write_str("browser runtime authority is not ready")
            }
        }
    }
}

impl Error for RuntimeError {}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid lifecycle fixtures"
)]
mod tests {
    use super::*;

    const ALL_STATES: [AuthorityState; 13] = [
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

    const ALLOWED_TRANSITIONS: &[(AuthorityState, AuthorityState)] = &[
        (
            AuthorityState::Uninitialized,
            AuthorityState::LocalStateOpened,
        ),
        (
            AuthorityState::LocalStateOpened,
            AuthorityState::HeaderSyncing,
        ),
        (AuthorityState::HeaderSyncing, AuthorityState::HeaderCurrent),
        (AuthorityState::HeaderCurrent, AuthorityState::ProofReady),
        (
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
        ),
        (
            AuthorityState::ResolutionTransportReady,
            AuthorityState::DnssecVerified,
        ),
        (
            AuthorityState::ResolutionTransportReady,
            AuthorityState::BrowserBridgeReady,
        ),
        (
            AuthorityState::DnssecVerified,
            AuthorityState::DaneOriginVerified,
        ),
        (
            AuthorityState::DnssecVerified,
            AuthorityState::BrowserBridgeReady,
        ),
        (
            AuthorityState::DaneOriginVerified,
            AuthorityState::BrowserBridgeReady,
        ),
        (AuthorityState::BrowserBridgeReady, AuthorityState::Active),
        (AuthorityState::Degraded, AuthorityState::HeaderSyncing),
        (AuthorityState::Revoked, AuthorityState::HeaderSyncing),
        (AuthorityState::Degraded, AuthorityState::Stopped),
        (AuthorityState::Revoked, AuthorityState::Stopped),
    ];

    fn session(byte: u8) -> RuntimeSessionId {
        RuntimeSessionId::new([byte; 16]).unwrap()
    }

    fn make_resolution_ready(runtime: &mut BrowserRuntime) {
        for state in [
            AuthorityState::LocalStateOpened,
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
        ] {
            runtime.transition(state).unwrap();
        }
    }

    #[test]
    fn advances_only_through_the_required_authority_graph() {
        let mut runtime = BrowserRuntime::new(session(1));
        for state in [
            AuthorityState::LocalStateOpened,
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
            AuthorityState::DnssecVerified,
            AuthorityState::DaneOriginVerified,
            AuthorityState::BrowserBridgeReady,
            AuthorityState::Active,
        ] {
            runtime.transition(state).unwrap();
        }
        assert_eq!(runtime.authority_state(), AuthorityState::Active);
        assert_eq!(runtime.snapshot().event_sequence, 9);
        assert_eq!(
            runtime.transition(AuthorityState::HeaderCurrent),
            Err(RuntimeError::InvalidAuthorityTransition)
        );
        assert_eq!(runtime.authority_state(), AuthorityState::Active);
    }

    #[test]
    fn failure_paths_are_explicit_and_stopped_is_terminal() {
        let mut runtime = BrowserRuntime::new(session(2));
        assert_eq!(runtime.admit_event(), Err(RuntimeError::AuthorityNotReady));
        runtime.transition(AuthorityState::Degraded).unwrap();
        runtime.transition(AuthorityState::HeaderSyncing).unwrap();
        runtime.transition(AuthorityState::Revoked).unwrap();
        runtime.transition(AuthorityState::Stopped).unwrap();
        assert_eq!(
            runtime.transition(AuthorityState::HeaderSyncing),
            Err(RuntimeError::InvalidAuthorityTransition)
        );
        assert_eq!(runtime.admit_event(), Err(RuntimeError::Stopped));
    }

    #[test]
    fn policy_change_revokes_and_advances_both_clocks() {
        let mut runtime = BrowserRuntime::new(session(3));
        runtime
            .transition(AuthorityState::LocalStateOpened)
            .unwrap();
        let before = runtime.snapshot();
        let after = runtime.policy_changed().unwrap();
        assert_eq!(after.generation, before.generation + 1);
        assert_eq!(after.event_sequence, before.event_sequence + 1);
        assert_eq!(after.authority_state, AuthorityState::Revoked);
    }

    #[test]
    fn admission_stamps_reject_other_sessions_generations_and_future_events() {
        let mut first = BrowserRuntime::new(session(4));
        let mut second = BrowserRuntime::new(session(5));
        make_resolution_ready(&mut first);
        make_resolution_ready(&mut second);
        let first_stamp = first.admit_event().unwrap();
        let second_stamp = second.admit_event().unwrap();
        assert!(first.admits(first_stamp));
        assert!(!first.admits(second_stamp));

        first.policy_changed().unwrap();
        assert!(!first.admits(first_stamp));

        let future = RuntimeStamp {
            session: first.snapshot().session,
            generation: first.snapshot().generation,
            event_sequence: first.snapshot().event_sequence + 1,
        };
        assert!(!first.admits(future));
    }

    #[test]
    fn rejects_zero_runtime_session() {
        assert_eq!(
            RuntimeSessionId::new([0; 16]),
            Err(RuntimeError::ZeroSession)
        );
        assert_eq!(
            RuntimeSessionId::try_from([0; 16]),
            Err(RuntimeError::ZeroSession)
        );
        assert_eq!(session(9).into_bytes(), [9; 16]);
    }

    #[test]
    fn authority_discriminants_remain_stable() {
        for (index, state) in ALL_STATES.into_iter().enumerate() {
            assert_eq!(usize::from(state as u8), index);
        }
    }

    #[test]
    fn transition_matrix_is_exhaustive() {
        for current in ALL_STATES {
            for next in ALL_STATES {
                let expected = ALLOWED_TRANSITIONS.contains(&(current, next))
                    || (matches!(
                        current,
                        AuthorityState::Uninitialized
                            | AuthorityState::LocalStateOpened
                            | AuthorityState::HeaderSyncing
                            | AuthorityState::HeaderCurrent
                            | AuthorityState::ProofReady
                            | AuthorityState::ResolutionTransportReady
                            | AuthorityState::DnssecVerified
                            | AuthorityState::DaneOriginVerified
                            | AuthorityState::BrowserBridgeReady
                            | AuthorityState::Active
                    ) && matches!(
                        next,
                        AuthorityState::Degraded
                            | AuthorityState::Revoked
                            | AuthorityState::Stopped
                    ));
                assert_eq!(
                    valid_authority_transition(current, next),
                    expected,
                    "unexpected transition result for {current:?} -> {next:?}"
                );
            }
        }
    }

    #[test]
    fn bridge_can_start_before_navigation_and_after_icann_authenticated_absence() {
        let mut startup = BrowserRuntime::new(session(6));
        make_resolution_ready(&mut startup);
        startup
            .transition(AuthorityState::BrowserBridgeReady)
            .unwrap();
        startup.transition(AuthorityState::Active).unwrap();
        assert_eq!(startup.authority_state(), AuthorityState::Active);

        let mut webpki = BrowserRuntime::new(session(7));
        make_resolution_ready(&mut webpki);
        webpki.transition(AuthorityState::DnssecVerified).unwrap();
        webpki
            .transition(AuthorityState::BrowserBridgeReady)
            .unwrap();
        webpki.transition(AuthorityState::Active).unwrap();
        assert_eq!(webpki.authority_state(), AuthorityState::Active);
    }

    #[test]
    fn admitted_stamp_is_rejected_while_degraded_revoked_or_stopped() {
        for terminal in [
            AuthorityState::Degraded,
            AuthorityState::Revoked,
            AuthorityState::Stopped,
        ] {
            let mut runtime = BrowserRuntime::new(session(8));
            make_resolution_ready(&mut runtime);
            let stamp = runtime.admit_event().unwrap();
            assert!(runtime.admits(stamp));
            runtime.transition(terminal).unwrap();
            assert!(!runtime.admits(stamp), "stamp survived {terminal:?}");
        }
    }

    #[test]
    fn admitted_stamp_cannot_resurrect_after_failure_recovery() {
        for failure in [AuthorityState::Degraded, AuthorityState::Revoked] {
            let mut runtime = BrowserRuntime::new(session(10));
            make_resolution_ready(&mut runtime);
            let stale = runtime.admit_event().unwrap();
            runtime.transition(failure).unwrap();
            for state in [
                AuthorityState::HeaderSyncing,
                AuthorityState::HeaderCurrent,
                AuthorityState::ProofReady,
                AuthorityState::ResolutionTransportReady,
            ] {
                runtime.transition(state).unwrap();
            }
            assert!(
                !runtime.admits(stale),
                "stamp resurrected after {failure:?} recovery"
            );
            let current = runtime.admit_event().unwrap();
            assert!(runtime.admits(current));
        }
    }

    #[test]
    fn maximum_event_sequence_is_a_valid_final_snapshot() {
        let mut runtime = BrowserRuntime::new(session(11));
        runtime.event_sequence = u64::MAX - 1;
        let snapshot = runtime
            .transition(AuthorityState::LocalStateOpened)
            .unwrap();
        assert_eq!(snapshot.event_sequence(), u64::MAX);
        assert_eq!(
            runtime.transition(AuthorityState::HeaderSyncing),
            Err(RuntimeError::CounterExhausted)
        );
    }
}
