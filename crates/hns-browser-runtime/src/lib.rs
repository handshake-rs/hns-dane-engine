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
pub const RUNTIME_SCHEMA_VERSION: u16 = 1;

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
    pub schema_version: u16,
    /// Caller-supplied per-start runtime session, which must be unique.
    pub session: [u8; 16],
    /// Monotonic generation invalidated by policy changes.
    pub generation: u64,
    /// Monotonic event sequence within this session.
    pub event_sequence: u64,
    /// Current authority state.
    pub authority_state: AuthorityState,
}

/// Opaque admission identity for work begun in one runtime session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeStamp {
    session: [u8; 16],
    generation: u64,
    event_sequence: u64,
}

impl RuntimeStamp {
    /// Runtime session that admitted this work.
    #[must_use]
    pub const fn session(self) -> [u8; 16] {
        self.session
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserRuntime {
    session: [u8; 16],
    generation: u64,
    event_sequence: u64,
    authority_state: AuthorityState,
}

impl BrowserRuntime {
    /// Start a fresh runtime session at generation one.
    #[must_use]
    pub const fn new(session: [u8; 16]) -> Self {
        Self {
            session,
            generation: 1,
            event_sequence: 0,
            authority_state: AuthorityState::Uninitialized,
        }
    }

    /// Read the complete immutable status.
    #[must_use]
    pub const fn snapshot(self) -> RuntimeSnapshot {
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
    pub const fn authority_state(self) -> AuthorityState {
        self.authority_state
    }

    /// Whether policy revocation can advance both monotonic counters.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::CounterExhausted`] if either counter is at its
    /// maximum value.
    pub const fn ensure_policy_change_capacity(self) -> Result<(), RuntimeError> {
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
        self.event_sequence = self
            .event_sequence
            .checked_add(1)
            .ok_or(RuntimeError::CounterExhausted)?;
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
    pub fn admits(self, stamp: RuntimeStamp) -> bool {
        stamp.session == self.session
            && stamp.generation == self.generation
            && stamp.event_sequence <= self.event_sequence
    }
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

/// Browser-runtime lifecycle or counter failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
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
        let mut runtime = BrowserRuntime::new([1; 16]);
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
        let mut runtime = BrowserRuntime::new([2; 16]);
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
        let mut runtime = BrowserRuntime::new([3; 16]);
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
        let mut first = BrowserRuntime::new([4; 16]);
        let mut second = BrowserRuntime::new([5; 16]);
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
}
