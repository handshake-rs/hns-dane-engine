//! Fail-closed transport orchestration for HNS browser resolution.
//!
//! The gateway consumes the typed policy plan and never accepts a
//! caller-selected transport. Only reachability, timeout, and explicitly
//! unsupported-path failures advance to the next candidate. Authentication or
//! protocol failures terminate the resolution so another path cannot turn
//! bogus evidence into a successful downgrade.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "HNS, DNS, ODoH, and P2P are protocol names"
)]

use hns_resolution_policy::{PolicySnapshot, ResolutionTransport, TransportPlan};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

static NEXT_GATEWAY_ID: AtomicU64 = AtomicU64::new(1);

/// Default deadline for one transport attempt.
pub const DEFAULT_ATTEMPT_TIMEOUT_SECONDS: u64 = 10;
/// Default maximum accepted DNS response bytes.
pub const DEFAULT_MAXIMUM_RESPONSE_BYTES: usize = 65_535;
/// Default maximum intermediary identity bytes.
pub const DEFAULT_MAXIMUM_IDENTITY_BYTES: usize = 256;

/// Bounds applied before an adapter response can enter DNS parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayLimits {
    /// Per-attempt deadline.
    pub attempt_timeout_seconds: u64,
    /// Maximum response body.
    pub maximum_response_bytes: usize,
    /// Maximum UTF-8 bytes in each intermediary identity.
    pub maximum_identity_bytes: usize,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            attempt_timeout_seconds: DEFAULT_ATTEMPT_TIMEOUT_SECONDS,
            maximum_response_bytes: DEFAULT_MAXIMUM_RESPONSE_BYTES,
            maximum_identity_bytes: DEFAULT_MAXIMUM_IDENTITY_BYTES,
        }
    }
}

impl GatewayLimits {
    fn validate(self) -> Result<Self, GatewayError> {
        if self.attempt_timeout_seconds == 0
            || self.attempt_timeout_seconds > 300
            || self.maximum_response_bytes == 0
            || self.maximum_response_bytes > DEFAULT_MAXIMUM_RESPONSE_BYTES
            || self.maximum_identity_bytes == 0
            || self.maximum_identity_bytes > 4_096
        {
            return Err(GatewayError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Transport-level failure reported by one adapter.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportFailure {
    /// Destination could not be reached.
    Unreachable = 0,
    /// The attempt reached its finite deadline.
    Timeout = 1,
    /// This build/runtime does not implement the candidate.
    Unsupported = 2,
    /// A valid UDP response requested standards-defined TCP retry.
    Truncated = 3,
    /// Response framing or transport protocol was malformed.
    Malformed = 4,
    /// Required endpoint or intermediary authentication failed.
    AuthenticationFailed = 5,
    /// Runtime lifecycle cancelled the resolution.
    Cancelled = 6,
}

impl TransportFailure {
    const fn permits_fallback_from(self, transport: ResolutionTransport) -> bool {
        matches!(self, Self::Unreachable | Self::Timeout | Self::Unsupported)
            || (matches!(self, Self::Truncated)
                && matches!(transport, ResolutionTransport::DirectAuthoritativeUdp))
    }
}

/// Bounded identities observed on an intermediary path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GatewayIdentities {
    /// P2P relay/peer identity.
    pub peer: Option<String>,
    /// ODoH proxy identity.
    pub proxy: Option<String>,
    /// ODoH authenticated-target identity.
    pub target: Option<String>,
}

/// Adapter result for one exact gateway attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttemptOutcome {
    /// Bounded DNS response bytes and actual intermediary identities.
    Response {
        /// DNS response wire bytes.
        bytes: Vec<u8>,
        /// Identities observed by the adapter.
        identities: GatewayIdentities,
    },
    /// Transport failed before a response could be admitted.
    Failure(TransportFailure),
}

/// Opaque exact attempt token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayAttempt {
    instance_id: u64,
    policy_generation: u64,
    sequence: u64,
    candidate_index: usize,
    transport: ResolutionTransport,
    deadline: u64,
}

impl GatewayAttempt {
    /// Policy generation that admitted this attempt.
    #[must_use]
    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }

    /// Monotonic attempt sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Policy-selected transport.
    #[must_use]
    pub const fn transport(self) -> ResolutionTransport {
        self.transport
    }

    /// Absolute adapter response deadline.
    #[must_use]
    pub const fn deadline(self) -> u64 {
        self.deadline
    }
}

/// Successful actual transport selection.
#[derive(Debug, Eq, PartialEq)]
pub struct GatewaySelection {
    policy_generation: u64,
    transport: ResolutionTransport,
    response: Vec<u8>,
    identities: GatewayIdentities,
    direct_relay_fallback: bool,
}

impl GatewaySelection {
    /// Policy generation of the completed plan.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Actual selected DNS transport.
    #[must_use]
    pub const fn transport(&self) -> ResolutionTransport {
        self.transport
    }

    /// Bounded response bytes.
    #[must_use]
    pub fn response(&self) -> &[u8] {
        &self.response
    }

    /// Actual intermediary identities.
    #[must_use]
    pub const fn identities(&self) -> &GatewayIdentities {
        &self.identities
    }

    /// Whether an attempted ODoH path downgraded to direct P2P relay.
    #[must_use]
    pub const fn direct_relay_fallback(&self) -> bool {
        self.direct_relay_fallback
    }

    /// Consume the one-shot selection into its admitted fields.
    #[must_use]
    pub fn into_parts(self) -> (u64, ResolutionTransport, Vec<u8>, GatewayIdentities, bool) {
        (
            self.policy_generation,
            self.transport,
            self.response,
            self.identities,
            self.direct_relay_fallback,
        )
    }
}

/// Result of completing one gateway attempt.
#[derive(Debug, Eq, PartialEq)]
pub enum GatewayStep {
    /// A retryable transport failure left another policy candidate.
    RetryAvailable,
    /// One actual transport returned an admitted bounded response.
    Selected(GatewaySelection),
    /// Every permitted candidate failed for a retryable reason.
    Unavailable,
}

/// One bounded direct-first gateway resolution.
#[derive(Debug)]
pub struct Gateway {
    instance_id: u64,
    limits: GatewayLimits,
    policy: PolicySnapshot,
    plan: TransportPlan,
    next_candidate: usize,
    sequence: u64,
    active: Option<GatewayAttempt>,
    terminal: bool,
    odoh_attempted: bool,
}

impl Gateway {
    /// Create from the exact current persistent policy.
    pub fn new(policy: PolicySnapshot, limits: GatewayLimits) -> Result<Self, GatewayError> {
        let limits = limits.validate()?;
        let instance_id = NEXT_GATEWAY_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| GatewayError::InstanceSequenceExhausted)?;
        Ok(Self {
            instance_id,
            limits,
            policy,
            plan: TransportPlan::for_policy(policy.config()),
            next_candidate: 0,
            sequence: 0,
            active: None,
            terminal: false,
            odoh_attempted: false,
        })
    }

    /// Exact direct-first typed plan.
    #[must_use]
    pub const fn plan(&self) -> &TransportPlan {
        &self.plan
    }

    /// Begin the next policy-selected candidate.
    pub fn next_attempt(
        &mut self,
        current_policy: PolicySnapshot,
        now: u64,
    ) -> Result<GatewayAttempt, GatewayError> {
        self.ensure_current_policy(current_policy)?;
        if self.terminal {
            return Err(GatewayError::Terminal);
        }
        if self.active.is_some() {
            return Err(GatewayError::AttemptAlreadyActive);
        }
        let transport = self
            .plan
            .as_slice()
            .get(self.next_candidate)
            .copied()
            .ok_or(GatewayError::NoCandidate)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(GatewayError::SequenceExhausted)?;
        let deadline = now
            .checked_add(self.limits.attempt_timeout_seconds)
            .ok_or(GatewayError::TimeOverflow)?;
        let attempt = GatewayAttempt {
            instance_id: self.instance_id,
            policy_generation: self.policy.generation(),
            sequence,
            candidate_index: self.next_candidate,
            transport,
            deadline,
        };
        self.next_candidate += 1;
        self.sequence = sequence;
        self.odoh_attempted |= transport == ResolutionTransport::HandshakeP2pOdoh;
        self.active = Some(attempt);
        Ok(attempt)
    }

    /// Complete the exact active attempt.
    pub fn complete(
        &mut self,
        current_policy: PolicySnapshot,
        attempt: GatewayAttempt,
        outcome: AttemptOutcome,
        now: u64,
    ) -> Result<GatewayStep, GatewayError> {
        self.ensure_current_policy(current_policy)?;
        let active = self.active.ok_or(GatewayError::NoActiveAttempt)?;
        if active != attempt {
            return Err(GatewayError::AttemptMismatch);
        }
        self.active = None;

        if now > attempt.deadline {
            return self.retry_or_unavailable(TransportFailure::Timeout, attempt.transport);
        }
        match outcome {
            AttemptOutcome::Failure(failure) => {
                self.retry_or_unavailable(failure, attempt.transport)
            }
            AttemptOutcome::Response { bytes, identities } => {
                if let Err(error) = self.validate_response(&bytes, &identities, attempt.transport) {
                    self.terminal = true;
                    return Err(error);
                }
                self.terminal = true;
                Ok(GatewayStep::Selected(GatewaySelection {
                    policy_generation: self.policy.generation(),
                    transport: attempt.transport,
                    response: bytes,
                    identities,
                    direct_relay_fallback: attempt.transport
                        == ResolutionTransport::HandshakeP2pDnsRelay
                        && self.odoh_attempted,
                }))
            }
        }
    }

    /// Revoke the in-flight plan after any policy-generation change.
    pub fn revoke(&mut self) {
        self.active = None;
        self.terminal = true;
    }

    fn retry_or_unavailable(
        &mut self,
        failure: TransportFailure,
        transport: ResolutionTransport,
    ) -> Result<GatewayStep, GatewayError> {
        if !failure.permits_fallback_from(transport) {
            self.terminal = true;
            return Err(GatewayError::TerminalTransportFailure(failure));
        }
        if self.next_candidate < self.plan.as_slice().len() {
            Ok(GatewayStep::RetryAvailable)
        } else {
            self.terminal = true;
            Ok(GatewayStep::Unavailable)
        }
    }

    fn ensure_current_policy(&mut self, current: PolicySnapshot) -> Result<(), GatewayError> {
        if current.generation() != self.policy.generation()
            || current.config() != self.policy.config()
        {
            self.revoke();
            return Err(GatewayError::StalePolicy);
        }
        Ok(())
    }

    fn validate_response(
        &self,
        bytes: &[u8],
        identities: &GatewayIdentities,
        transport: ResolutionTransport,
    ) -> Result<(), GatewayError> {
        if bytes.is_empty() || bytes.len() > self.limits.maximum_response_bytes {
            return Err(GatewayError::InvalidResponseSize);
        }
        for identity in [
            identities.peer.as_deref(),
            identities.proxy.as_deref(),
            identities.target.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if identity.is_empty() || identity.len() > self.limits.maximum_identity_bytes {
                return Err(GatewayError::InvalidIdentity);
            }
        }
        match transport {
            ResolutionTransport::HandshakeP2pOdoh => {
                let proxy = identities
                    .proxy
                    .as_deref()
                    .ok_or(GatewayError::MissingIdentity)?;
                let target = identities
                    .target
                    .as_deref()
                    .ok_or(GatewayError::MissingIdentity)?;
                if identities.peer.is_some() || proxy == target {
                    return Err(GatewayError::InvalidIdentityTopology);
                }
            }
            ResolutionTransport::HandshakeP2pDnsRelay => {
                if identities.peer.is_none()
                    || identities.proxy.is_some()
                    || identities.target.is_some()
                {
                    return Err(GatewayError::InvalidIdentityTopology);
                }
            }
            ResolutionTransport::DirectAuthoritativeUdp
            | ResolutionTransport::DirectAuthoritativeTcp
            | ResolutionTransport::AuthenticatedAuthoritativeDoh => {
                if identities != &GatewayIdentities::default() {
                    return Err(GatewayError::InvalidIdentityTopology);
                }
            }
            ResolutionTransport::Unavailable | ResolutionTransport::ValidatingIcannDoh => {
                return Err(GatewayError::UnavailableTransport);
            }
        }
        Ok(())
    }
}

/// Gateway policy, attempt, bound, or terminal failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GatewayError {
    /// Configured bounds are zero or excessive.
    #[error("invalid HNS gateway limits")]
    InvalidLimits,
    /// The gateway's policy generation or effective policy changed.
    #[error("HNS gateway policy is stale")]
    StalePolicy,
    /// A candidate is already awaiting completion.
    #[error("HNS gateway attempt is already active")]
    AttemptAlreadyActive,
    /// No attempt is active.
    #[error("HNS gateway has no active attempt")]
    NoActiveAttempt,
    /// Completion token differs from the exact active attempt.
    #[error("HNS gateway completion does not match the active attempt")]
    AttemptMismatch,
    /// The policy plan has no remaining candidate.
    #[error("HNS gateway has no remaining transport candidate")]
    NoCandidate,
    /// A selected or failed plan is terminal.
    #[error("HNS gateway is terminal")]
    Terminal,
    /// Attempt counter cannot advance.
    #[error("HNS gateway attempt sequence exhausted")]
    SequenceExhausted,
    /// Process-local gateway instance counter cannot advance.
    #[error("HNS gateway instance sequence exhausted")]
    InstanceSequenceExhausted,
    /// Deadline arithmetic overflowed.
    #[error("HNS gateway deadline overflow")]
    TimeOverflow,
    /// A non-retryable transport failure terminated the resolution.
    #[error("HNS gateway transport failed closed: {0:?}")]
    TerminalTransportFailure(TransportFailure),
    /// Response is empty or exceeds the DNS wire bound.
    #[error("HNS gateway response size is invalid")]
    InvalidResponseSize,
    /// Required intermediary identity is absent.
    #[error("HNS gateway intermediary identity is missing")]
    MissingIdentity,
    /// Intermediary identity is empty or excessive.
    #[error("HNS gateway intermediary identity is invalid")]
    InvalidIdentity,
    /// Identities do not match the selected transport.
    #[error("HNS gateway intermediary topology is invalid")]
    InvalidIdentityTopology,
    /// Unavailable is a status, never an attempt transport.
    #[error("unavailable cannot carry a gateway response")]
    UnavailableTransport,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid deterministic gateway fixtures"
)]
mod tests {
    use hns_resolution_policy::{ObliviousDnsPolicy, PolicyConfig, ProviderPolicy, WireProfile};

    use super::*;

    fn policy() -> PolicySnapshot {
        PolicySnapshot::default()
    }

    fn failure_then_next(
        gateway: &mut Gateway,
        snapshot: PolicySnapshot,
        now: u64,
    ) -> GatewayAttempt {
        let attempt = gateway.next_attempt(snapshot, now).unwrap();
        assert_eq!(
            gateway
                .complete(
                    snapshot,
                    attempt,
                    AttemptOutcome::Failure(TransportFailure::Unreachable),
                    now
                )
                .unwrap(),
            GatewayStep::RetryAvailable
        );
        attempt
    }

    #[test]
    fn follows_direct_first_plan_and_derives_relay_downgrade() {
        let snapshot = policy();
        let mut gateway = Gateway::new(snapshot, GatewayLimits::default()).unwrap();
        assert_eq!(
            gateway.plan().as_slice(),
            [
                ResolutionTransport::DirectAuthoritativeUdp,
                ResolutionTransport::DirectAuthoritativeTcp,
                ResolutionTransport::AuthenticatedAuthoritativeDoh,
                ResolutionTransport::HandshakeP2pOdoh,
                ResolutionTransport::HandshakeP2pDnsRelay,
            ]
        );
        for expected in [
            ResolutionTransport::DirectAuthoritativeUdp,
            ResolutionTransport::DirectAuthoritativeTcp,
            ResolutionTransport::AuthenticatedAuthoritativeDoh,
            ResolutionTransport::HandshakeP2pOdoh,
        ] {
            assert_eq!(
                failure_then_next(&mut gateway, snapshot, 100).transport(),
                expected
            );
        }
        let relay = gateway.next_attempt(snapshot, 100).unwrap();
        assert_eq!(relay.transport(), ResolutionTransport::HandshakeP2pDnsRelay);
        let selected = gateway
            .complete(
                snapshot,
                relay,
                AttemptOutcome::Response {
                    bytes: vec![1, 2, 3],
                    identities: GatewayIdentities {
                        peer: Some("relay-peer".to_owned()),
                        ..GatewayIdentities::default()
                    },
                },
                100,
            )
            .unwrap();
        let selected = match selected {
            GatewayStep::Selected(selected) => Some(selected),
            GatewayStep::RetryAvailable | GatewayStep::Unavailable => None,
        }
        .unwrap();
        assert!(selected.direct_relay_fallback());
        assert_eq!(
            selected.transport(),
            ResolutionTransport::HandshakeP2pDnsRelay
        );
    }

    #[test]
    fn malformed_and_authentication_failures_are_terminal() {
        for failure in [
            TransportFailure::Malformed,
            TransportFailure::AuthenticationFailed,
            TransportFailure::Cancelled,
        ] {
            let snapshot = policy();
            let mut gateway = Gateway::new(snapshot, GatewayLimits::default()).unwrap();
            let attempt = gateway.next_attempt(snapshot, 100).unwrap();
            assert!(matches!(
                gateway.complete(
                    snapshot,
                    attempt,
                    AttemptOutcome::Failure(failure),
                    100
                ),
                Err(GatewayError::TerminalTransportFailure(actual)) if actual == failure
            ));
            assert!(matches!(
                gateway.next_attempt(snapshot, 100),
                Err(GatewayError::Terminal)
            ));
        }
    }

    #[test]
    fn enforces_response_bounds_and_transport_identity_topology() {
        let mut config = PolicyConfig {
            authenticated_authoritative_doh: false,
            oblivious_dns: ObliviousDnsPolicy::Required,
            providers: ProviderPolicy::default(),
            wire_profile: WireProfile::DenuoV1,
            ..PolicyConfig::default()
        };
        let snapshot = PolicySnapshot::new(9, config).unwrap();
        let mut gateway = Gateway::new(snapshot, GatewayLimits::default()).unwrap();
        failure_then_next(&mut gateway, snapshot, 100);
        failure_then_next(&mut gateway, snapshot, 100);
        let odoh = gateway.next_attempt(snapshot, 100).unwrap();
        assert!(matches!(
            gateway.complete(
                snapshot,
                odoh,
                AttemptOutcome::Response {
                    bytes: vec![1],
                    identities: GatewayIdentities {
                        proxy: Some("same".to_owned()),
                        target: Some("same".to_owned()),
                        ..GatewayIdentities::default()
                    },
                },
                100
            ),
            Err(GatewayError::InvalidIdentityTopology)
        ));
        assert!(matches!(
            gateway.next_attempt(snapshot, 100),
            Err(GatewayError::Terminal)
        ));

        config.oblivious_dns = ObliviousDnsPolicy::Disabled;
        let direct = PolicySnapshot::new(10, config).unwrap();
        let mut gateway = Gateway::new(
            direct,
            GatewayLimits {
                maximum_response_bytes: 2,
                ..GatewayLimits::default()
            },
        )
        .unwrap();
        let attempt = gateway.next_attempt(direct, 100).unwrap();
        assert!(matches!(
            gateway.complete(
                direct,
                attempt,
                AttemptOutcome::Response {
                    bytes: vec![1, 2, 3],
                    identities: GatewayIdentities::default(),
                },
                100
            ),
            Err(GatewayError::InvalidResponseSize)
        ));
    }

    #[test]
    fn rejects_stale_policy_mismatched_tokens_and_late_responses() {
        let snapshot = policy();
        let mut gateway = Gateway::new(snapshot, GatewayLimits::default()).unwrap();
        let attempt = gateway.next_attempt(snapshot, 100).unwrap();
        assert!(matches!(
            gateway.next_attempt(snapshot, 100),
            Err(GatewayError::AttemptAlreadyActive)
        ));

        let mut other = Gateway::new(snapshot, GatewayLimits::default()).unwrap();
        let foreign = other.next_attempt(snapshot, 100).unwrap();
        assert!(matches!(
            gateway.complete(
                snapshot,
                foreign,
                AttemptOutcome::Failure(TransportFailure::Timeout),
                100
            ),
            Err(GatewayError::AttemptMismatch)
        ));
        assert_eq!(
            gateway
                .complete(
                    snapshot,
                    attempt,
                    AttemptOutcome::Response {
                        bytes: vec![1],
                        identities: GatewayIdentities::default(),
                    },
                    111
                )
                .unwrap(),
            GatewayStep::RetryAvailable
        );

        let changed = PolicySnapshot::new(snapshot.generation() + 1, snapshot.config()).unwrap();
        assert!(matches!(
            gateway.next_attempt(changed, 112),
            Err(GatewayError::StalePolicy)
        ));
        assert!(matches!(
            gateway.next_attempt(snapshot, 112),
            Err(GatewayError::Terminal)
        ));
    }

    #[test]
    fn valid_udp_truncation_advances_only_to_direct_tcp() {
        let snapshot = policy();
        let mut gateway = Gateway::new(snapshot, GatewayLimits::default()).unwrap();
        let udp = gateway.next_attempt(snapshot, 100).unwrap();
        assert_eq!(udp.transport(), ResolutionTransport::DirectAuthoritativeUdp);
        assert_eq!(
            gateway
                .complete(
                    snapshot,
                    udp,
                    AttemptOutcome::Failure(TransportFailure::Truncated),
                    100
                )
                .unwrap(),
            GatewayStep::RetryAvailable
        );
        let tcp = gateway.next_attempt(snapshot, 100).unwrap();
        assert_eq!(tcp.transport(), ResolutionTransport::DirectAuthoritativeTcp);
        let selected = gateway
            .complete(
                snapshot,
                tcp,
                AttemptOutcome::Response {
                    bytes: vec![1],
                    identities: GatewayIdentities::default(),
                },
                100,
            )
            .unwrap();
        assert!(matches!(
            selected,
            GatewayStep::Selected(selection)
                if selection.transport() == ResolutionTransport::DirectAuthoritativeTcp
                    && !selection.direct_relay_fallback()
        ));
    }

    #[test]
    fn unsupported_final_candidate_reports_unavailable() {
        let config = PolicyConfig {
            authenticated_authoritative_doh: false,
            oblivious_dns: ObliviousDnsPolicy::Disabled,
            dns_relay_requester: hns_resolution_policy::DnsRelayRequesterPolicy::Disabled,
            ..PolicyConfig::default()
        };
        let snapshot = PolicySnapshot::new(3, config).unwrap();
        let mut gateway = Gateway::new(snapshot, GatewayLimits::default()).unwrap();
        let first = gateway.next_attempt(snapshot, 100).unwrap();
        assert_eq!(
            gateway
                .complete(
                    snapshot,
                    first,
                    AttemptOutcome::Failure(TransportFailure::Unsupported),
                    100
                )
                .unwrap(),
            GatewayStep::RetryAvailable
        );
        let second = gateway.next_attempt(snapshot, 100).unwrap();
        assert_eq!(
            gateway
                .complete(
                    snapshot,
                    second,
                    AttemptOutcome::Failure(TransportFailure::Unsupported),
                    100
                )
                .unwrap(),
            GatewayStep::Unavailable
        );
    }
}
