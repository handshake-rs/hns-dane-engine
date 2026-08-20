//! Fenced native broker for durable HRM/HNSA authority.
//!
//! This module composes the production authority state and lease primitives
//! from `hns-service-authority`. Platform integrations remain responsible for
//! a real exclusive lease, authenticated storage, an external rollback floor,
//! trusted time, and authenticated current Handshake state. The broker fixes
//! their ordering and prevents a current authority guard from escaping the
//! lease-scoped callback.

use std::any::Any;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::error::Error;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

pub use hns_hrm::validation::{ResolvedManifest, ValidationLimits};
pub use hns_rollback_journal::RollbackProtectionClass;
pub use hns_service_authority::authority_state::{
    CurrentCommittedNamedService, NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot,
    NamedServiceAuthorityStorageState,
};
use hns_service_authority::authority_state::{
    NamedServiceAuthorityCommitError, NamedServiceAuthorityError,
    NamedServiceAuthorityOperationError, NamedServiceAuthorityState,
};
pub use hns_service_authority::hrm::{NamedServiceIdentity, NamedServicePolicy};
pub use hns_service_authority::lease::{
    AuthorityLeaseKey, AuthorityLeaseWitness, FencedLeaseGuard, FencingToken, StorageNamespaceId,
};
use hns_service_authority::lease::{
    HeldAuthorityLease, LeaseAcquireError, LeaseError, LeaseScopeError,
};

/// Default number of subject aggregates retained by one live native broker.
pub const DEFAULT_HRM_HNSA_LIVE_SUBJECTS: usize = 64;
/// Default maximum service observations retained in one subject aggregate.
pub const DEFAULT_HRM_HNSA_AUTHORITY_ENTRIES: usize = 64;
/// Hard broker-side bound on live subject aggregates.
pub const MAX_HRM_HNSA_LIVE_SUBJECTS: usize = 1_024;

/// Immutable limits and durable namespace identity for one broker.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HrmHnsaAuthorityBrokerConfig {
    storage_namespace_id: StorageNamespaceId,
    maximum_live_subjects: usize,
    authority_entry_capacity: usize,
    validation_limits: ValidationLimits,
    rollback_protection: RollbackProtectionClass,
}

impl HrmHnsaAuthorityBrokerConfig {
    /// Construct a bounded broker configuration.
    ///
    /// Production authority requires a rollback domain independent of the
    /// replayable protocol snapshot. The classification remains an honest
    /// backend claim, not proof that the platform actually provides it.
    pub fn new(
        storage_namespace_id: [u8; 32],
        maximum_live_subjects: usize,
        authority_entry_capacity: usize,
        validation_limits: ValidationLimits,
        rollback_protection: RollbackProtectionClass,
    ) -> Result<Self, HrmHnsaAuthorityBrokerConfigError> {
        let storage_namespace_id = StorageNamespaceId::new(storage_namespace_id)
            .map_err(HrmHnsaAuthorityBrokerConfigError::Lease)?;
        if !(1..=MAX_HRM_HNSA_LIVE_SUBJECTS).contains(&maximum_live_subjects) {
            return Err(HrmHnsaAuthorityBrokerConfigError::InvalidLiveSubjectCapacity);
        }
        if !(1..=hns_service_authority::authority_state::MAX_NAMED_SERVICE_AUTHORITY_ENTRIES)
            .contains(&authority_entry_capacity)
        {
            return Err(HrmHnsaAuthorityBrokerConfigError::InvalidAuthorityEntryCapacity);
        }
        if !rollback_protection.has_independent_rollback_domain() {
            return Err(HrmHnsaAuthorityBrokerConfigError::InadequateRollbackProtection);
        }
        Ok(Self {
            storage_namespace_id,
            maximum_live_subjects,
            authority_entry_capacity,
            validation_limits,
            rollback_protection,
        })
    }

    /// Stable authenticated storage namespace shared by every native context.
    #[must_use]
    pub const fn storage_namespace_id(self) -> StorageNamespaceId {
        self.storage_namespace_id
    }

    /// Maximum subject aggregates retained by this broker instance.
    #[must_use]
    pub const fn maximum_live_subjects(self) -> usize {
        self.maximum_live_subjects
    }

    /// Maximum service observations or tombstones in one subject aggregate.
    #[must_use]
    pub const fn authority_entry_capacity(self) -> usize {
        self.authority_entry_capacity
    }

    /// Bounded HRM validation policy applied to every operation.
    #[must_use]
    pub const fn validation_limits(self) -> ValidationLimits {
        self.validation_limits
    }

    /// Honest minimum protection classification required from the backend.
    #[must_use]
    pub const fn rollback_protection(self) -> RollbackProtectionClass {
        self.rollback_protection
    }
}

impl fmt::Debug for HrmHnsaAuthorityBrokerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HrmHnsaAuthorityBrokerConfig")
            .field("storage_namespace_id", &"<opaque>")
            .field("maximum_live_subjects", &self.maximum_live_subjects)
            .field("authority_entry_capacity", &self.authority_entry_capacity)
            .field("validation_limits", &self.validation_limits)
            .field("rollback_protection", &self.rollback_protection)
            .finish()
    }
}

/// Invalid immutable broker configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HrmHnsaAuthorityBrokerConfigError {
    /// The durable namespace or lease identity is invalid.
    Lease(LeaseError),
    /// The live-subject bound is zero or exceeds the broker hard limit.
    InvalidLiveSubjectCapacity,
    /// The per-subject service-observation bound is invalid.
    InvalidAuthorityEntryCapacity,
    /// The snapshot and rollback floor share one replayable rollback domain.
    InadequateRollbackProtection,
    /// The backend honestly reports a different protection class.
    RollbackProtectionMismatch,
}

impl fmt::Display for HrmHnsaAuthorityBrokerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lease(error) => error.fmt(formatter),
            Self::InvalidLiveSubjectCapacity => {
                formatter.write_str("HRM/HNSA broker live-subject capacity must be in 1..=1024")
            }
            Self::InvalidAuthorityEntryCapacity => {
                formatter.write_str("HRM/HNSA authority entry capacity must be in 1..=1024")
            }
            Self::InadequateRollbackProtection => formatter
                .write_str("HRM/HNSA production authority requires an independent rollback domain"),
            Self::RollbackProtectionMismatch => formatter.write_str(
                "HRM/HNSA backend rollback protection differs from broker configuration",
            ),
        }
    }
}

impl Error for HrmHnsaAuthorityBrokerConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Lease(error) => Some(error),
            _ => None,
        }
    }
}

/// Trusted native services required by [`HrmHnsaAuthorityBroker`].
///
/// This is a security-critical platform contract, not a convenience storage
/// trait. Implementations must satisfy all of the following:
///
/// - `acquire_authority_lease` returns a real non-cloneable namespace-wide
///   exclusion guard with a monotonic nonzero fencing token;
/// - `load_authority_state` returns `Absent` only before the namespace has ever
///   been initialized. Once initialized, missing/evicted state is an error;
/// - `Present` bytes are authenticated and `minimum_revision` comes from a
///   non-evictable rollback domain independent of those bytes;
/// - `persist_authority_state` atomically validates namespace, fencing token,
///   exact prior revision and complete fingerprint while updating the
///   authenticated snapshot, initialized marker, and external revision floor;
/// - an outcome-ambiguous write is reconciled exactly before a later load can
///   return usable state; and
/// - `retrieve_current_manifest` starts all fallible current-namestate and
///   envelope I/O only when called, after the broker has durably acknowledged
///   the operation's exact trusted time.
///
/// A no-op lease, an unkeyed checksum, a pointwise fence check, page/extension
/// storage, or a caller-constructed [`ResolvedManifest`] does not implement
/// this contract.
pub trait HrmHnsaAuthorityBackend {
    /// Unified trusted-backend failure.
    type Error: Error + 'static;
    /// Owned real lease guard retained through the complete callback.
    type AuthorityLease: FencedLeaseGuard<AuthorityLeaseKey>;

    /// Honest minimum rollback protection actually supplied by this backend.
    fn rollback_protection(&self) -> RollbackProtectionClass;

    /// Acquire exclusive authority-subject ownership for the exact key.
    fn acquire_authority_lease(
        &self,
        key: &AuthorityLeaseKey,
    ) -> Result<Self::AuthorityLease, Self::Error>;

    /// Obtain one trusted whole-Unix-second operation time.
    fn trusted_time(&self) -> Result<u64, Self::Error>;

    /// Load authenticated state and its external floor while the lease is held.
    fn load_authority_state(
        &self,
        lease: &AuthorityLeaseWitness<'_>,
    ) -> Result<NamedServiceAuthorityStorageState, Self::Error>;

    /// Apply one exact fenced CAS and durably acknowledge the complete result.
    fn persist_authority_state(
        &self,
        expectation: NamedServiceAuthorityExpectation,
        snapshot: &NamedServiceAuthoritySnapshot,
    ) -> Result<(), Self::Error>;

    /// Retrieve authenticated current HNS state and its hash-matched HRM bytes.
    fn retrieve_current_manifest(
        &self,
        lease: &AuthorityLeaseWitness<'_>,
        identity: &NamedServiceIdentity,
        trusted_now: u64,
    ) -> Result<ResolvedManifest, Self::Error>;
}

/// Failure from one exact broker-scoped authority operation.
#[derive(Debug)]
pub enum HrmHnsaAuthorityBrokerError<B, O> {
    /// Trusted platform backend failure.
    Backend(B),
    /// Canonical HRM/HNSA validation or durable-state failure.
    Authority(NamedServiceAuthorityError),
    /// Lease acquisition, loss, expiry, revocation, or fence replacement.
    Lease(LeaseError),
    /// The bounded live broker cannot admit another subject aggregate.
    SubjectCapacity,
    /// The caller-owned dependent operation failed while authority was held.
    Operation(O),
}

impl<B: fmt::Display, O: fmt::Display> fmt::Display for HrmHnsaAuthorityBrokerError<B, O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(error) => write!(formatter, "HRM/HNSA backend failed: {error}"),
            Self::Authority(error) => error.fmt(formatter),
            Self::Lease(error) => error.fmt(formatter),
            Self::SubjectCapacity => {
                formatter.write_str("HRM/HNSA broker live-subject capacity is exhausted")
            }
            Self::Operation(error) => error.fmt(formatter),
        }
    }
}

impl<B, O> Error for HrmHnsaAuthorityBrokerError<B, O>
where
    B: Error + 'static,
    O: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Backend(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::Lease(error) => Some(error),
            Self::Operation(error) => Some(error),
            Self::SubjectCapacity => None,
        }
    }
}

/// Sole live native owner of bounded HRM/HNSA subject aggregates.
///
/// The broker is deliberately non-cloneable. Cross-process and independently
/// restored currentness still comes from the backend's real fenced lease and
/// authenticated storage, not from this Rust ownership alone.
pub struct HrmHnsaAuthorityBroker<B> {
    config: HrmHnsaAuthorityBrokerConfig,
    backend: B,
    states: BTreeMap<AuthorityLeaseKey, NamedServiceAuthorityState>,
}

impl<B: HrmHnsaAuthorityBackend> HrmHnsaAuthorityBroker<B> {
    /// Bind one backend to an immutable exact namespace and limit set.
    pub fn new(
        config: HrmHnsaAuthorityBrokerConfig,
        backend: B,
    ) -> Result<Self, HrmHnsaAuthorityBrokerConfigError> {
        if backend.rollback_protection() != config.rollback_protection() {
            return Err(HrmHnsaAuthorityBrokerConfigError::RollbackProtectionMismatch);
        }
        Ok(Self {
            config,
            backend,
            states: BTreeMap::new(),
        })
    }

    /// Immutable broker configuration.
    #[must_use]
    pub const fn config(&self) -> HrmHnsaAuthorityBrokerConfig {
        self.config
    }

    /// Number of subject aggregates retained by this live broker.
    #[must_use]
    pub fn live_subjects(&self) -> usize {
        self.states.len()
    }

    /// Borrow the backend for platform diagnostics that confer no authority.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Validate, durably commit, rebind, and use one exact current HNSA result.
    ///
    /// The callback receives either the exact active service or its exact
    /// withdrawal tombstone through [`CurrentCommittedNamedService`]. It runs
    /// only after trusted time and authority state are durably acknowledged,
    /// and its result is withheld until the lease passes the release-boundary
    /// check. The callback must not publish an irreversible effect when using
    /// an expiring/revocable guard unless the backend owns a fenced promotion
    /// mechanism. Read-only consumers are the intended initial integration.
    ///
    /// Panics are caught inside the lease scope so its final currentness check
    /// still runs and the exact in-memory pending proposal remains retained;
    /// the original panic is resumed after the owned guard is released.
    pub fn with_current_named_service<T, O, F>(
        &mut self,
        identity: &NamedServiceIdentity,
        policy: &NamedServicePolicy,
        operation: F,
    ) -> Result<T, HrmHnsaAuthorityBrokerError<B::Error, O>>
    where
        F: for<'authority> FnOnce(
            &'authority CurrentCommittedNamedService<'authority>,
        ) -> Result<T, O>,
    {
        identity
            .validate()
            .map_err(NamedServiceAuthorityError::from)
            .map_err(HrmHnsaAuthorityBrokerError::Authority)?;
        policy
            .validate()
            .map_err(NamedServiceAuthorityError::from)
            .map_err(HrmHnsaAuthorityBrokerError::Authority)?;

        let key = AuthorityLeaseKey::new(
            self.config.storage_namespace_id(),
            identity.network_magic,
            identity.name_hash,
        );
        if !self.states.contains_key(&key)
            && self.states.len() >= self.config.maximum_live_subjects()
        {
            return Err(HrmHnsaAuthorityBrokerError::SubjectCapacity);
        }

        let held = HeldAuthorityLease::acquire(key, |requested| {
            self.backend.acquire_authority_lease(requested)
        })
        .map_err(map_lease_acquire)?;
        let backend = &self.backend;
        let states = &mut self.states;
        let config = self.config;
        let mut panic_payload: Option<Box<dyn Any + Send>> = None;
        let scoped = held.run(|lease| {
            let attempted = catch_unwind(AssertUnwindSafe(|| {
                run_scoped(config, backend, states, lease, identity, policy, operation)
            }));
            match attempted {
                Ok(result) => result.map(Some),
                Err(payload) => {
                    panic_payload = Some(payload);
                    Ok(None)
                }
            }
        });

        if let Some(payload) = panic_payload {
            resume_unwind(payload);
        }
        match scoped {
            Ok(Some(value)) => Ok(value),
            Ok(None) => Err(HrmHnsaAuthorityBrokerError::Authority(
                NamedServiceAuthorityError::InvalidSnapshot(
                    "broker panic containment lost its panic payload",
                ),
            )),
            Err(LeaseScopeError::Operation(error)) => Err(error),
            Err(LeaseScopeError::Lease(error)) => Err(HrmHnsaAuthorityBrokerError::Lease(error)),
        }
    }
}

impl<B> fmt::Debug for HrmHnsaAuthorityBroker<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HrmHnsaAuthorityBroker")
            .field("config", &self.config)
            .field("backend", &"<trusted>")
            .field("live_subjects", &self.states.len())
            .finish()
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the scoped operation makes each authority, lease, policy, and callback binding explicit"
)]
fn run_scoped<B, T, O, F>(
    config: HrmHnsaAuthorityBrokerConfig,
    backend: &B,
    states: &mut BTreeMap<AuthorityLeaseKey, NamedServiceAuthorityState>,
    lease: &AuthorityLeaseWitness<'_>,
    identity: &NamedServiceIdentity,
    policy: &NamedServicePolicy,
    operation: F,
) -> Result<T, HrmHnsaAuthorityBrokerError<B::Error, O>>
where
    B: HrmHnsaAuthorityBackend,
    F: for<'authority> FnOnce(&'authority CurrentCommittedNamedService<'authority>) -> Result<T, O>,
{
    lease
        .ensure_held()
        .map_err(HrmHnsaAuthorityBrokerError::Lease)?;
    let trusted_now = backend
        .trusted_time()
        .map_err(HrmHnsaAuthorityBrokerError::Backend)?;
    let key = *lease.key();

    if let Entry::Vacant(entry) = states.entry(key) {
        let loaded = backend
            .load_authority_state(lease)
            .map_err(HrmHnsaAuthorityBrokerError::Backend)?;
        lease
            .ensure_held()
            .map_err(HrmHnsaAuthorityBrokerError::Lease)?;
        let state = match loaded {
            NamedServiceAuthorityStorageState::Absent => NamedServiceAuthorityState::new(
                identity.network_magic,
                identity.name_hash,
                config.authority_entry_capacity(),
                trusted_now,
            ),
            NamedServiceAuthorityStorageState::Present {
                encoded,
                minimum_revision,
            } => NamedServiceAuthorityState::restore(
                &encoded,
                identity.network_magic,
                identity.name_hash,
                config.authority_entry_capacity(),
                minimum_revision,
                trusted_now,
            ),
        }
        .map_err(HrmHnsaAuthorityBrokerError::Authority)?;
        entry.insert(state);
    }

    let state = states.get_mut(&key).ok_or_else(|| {
        HrmHnsaAuthorityBrokerError::Authority(NamedServiceAuthorityError::InvalidSnapshot(
            "broker lost its live subject aggregate",
        ))
    })?;
    let mut reconfirmed = state
        .reconfirm(lease, |witness| backend.load_authority_state(witness))
        .map_err(map_commit_error)?;
    let mut persist = |expectation, snapshot: &NamedServiceAuthoritySnapshot| {
        backend.persist_authority_state(expectation, snapshot)
    };
    let committed = reconfirmed
        .retrieve_validate_and_observe(
            trusted_now,
            |operation_time| backend.retrieve_current_manifest(lease, identity, operation_time),
            identity,
            policy,
            config.validation_limits(),
            &mut persist,
        )
        .map_err(map_operation_error)?;
    let current = reconfirmed
        .bind_current_at(&committed, trusted_now)
        .map_err(HrmHnsaAuthorityBrokerError::Authority)?;
    current
        .ensure_lease_held()
        .map_err(HrmHnsaAuthorityBrokerError::Authority)?;
    let result = operation(&current).map_err(HrmHnsaAuthorityBrokerError::Operation);
    current
        .ensure_lease_held()
        .map_err(HrmHnsaAuthorityBrokerError::Authority)?;
    result
}

fn map_lease_acquire<B, O>(error: LeaseAcquireError<B>) -> HrmHnsaAuthorityBrokerError<B, O> {
    match error {
        LeaseAcquireError::Backend(error) => HrmHnsaAuthorityBrokerError::Backend(error),
        LeaseAcquireError::Lease(error) => HrmHnsaAuthorityBrokerError::Lease(error),
    }
}

fn map_commit_error<B, O>(
    error: NamedServiceAuthorityCommitError<B>,
) -> HrmHnsaAuthorityBrokerError<B, O> {
    match error {
        NamedServiceAuthorityCommitError::Authority(error) => {
            HrmHnsaAuthorityBrokerError::Authority(error)
        }
        NamedServiceAuthorityCommitError::Persistence(error) => {
            HrmHnsaAuthorityBrokerError::Backend(error)
        }
    }
}

fn map_operation_error<B, O>(
    error: NamedServiceAuthorityOperationError<B, B>,
) -> HrmHnsaAuthorityBrokerError<B, O> {
    match error {
        NamedServiceAuthorityOperationError::Retrieval(error)
        | NamedServiceAuthorityOperationError::Persistence(error) => {
            HrmHnsaAuthorityBrokerError::Backend(error)
        }
        NamedServiceAuthorityOperationError::Authority(error) => {
            HrmHnsaAuthorityBrokerError::Authority(error)
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests fail immediately while constructing deterministic signed fixtures and exercising panic containment"
)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::rc::Rc;

    use hns_hrm::model::{Controller, Envelope, Payload, VERSION, public_key};
    use hns_hrm::validation::AuthenticatedNameState;
    use hns_service_authority::hrm::{
        NamedServiceAttributes, ServiceDelegationConstraints, named_service_resource,
        service_controller_delegation,
    };

    use super::*;

    const NETWORK_MAGIC: u32 = 0xae38_95cf;
    const SUBJECT: [u8; 32] = [7; 32];
    const STORAGE_NAMESPACE: [u8; 32] = [8; 32];
    const NOW: u64 = 1_700_000_300;
    const PROFILE_ID: u16 = 0x8001;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Acquire,
        TrustedTime,
        Load,
        Persist(u64),
        Retrieve,
        Callback,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestBackendError {
        MissingInitializedState,
        Retrieval,
        Cas,
    }

    impl fmt::Display for TestBackendError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::MissingInitializedState => {
                    formatter.write_str("initialized authority state is missing")
                }
                Self::Retrieval => formatter.write_str("manifest retrieval failed"),
                Self::Cas => formatter.write_str("authority CAS failed"),
            }
        }
    }

    impl Error for TestBackendError {}

    #[derive(Debug)]
    struct TestGuard {
        key: AuthorityLeaseKey,
        fence: Rc<Cell<u64>>,
        held: Rc<Cell<bool>>,
        checks: Rc<Cell<u64>>,
    }

    impl FencedLeaseGuard<AuthorityLeaseKey> for TestGuard {
        fn key(&self) -> &AuthorityLeaseKey {
            &self.key
        }

        fn fencing_token(&self) -> FencingToken {
            FencingToken::new(self.fence.get()).expect("nonzero test fence")
        }

        fn ensure_held(&self) -> Result<(), LeaseError> {
            self.checks.set(self.checks.get().saturating_add(1));
            self.held.get().then_some(()).ok_or(LeaseError::Lost)
        }
    }

    #[derive(Default)]
    struct DurableState {
        initialized: bool,
        encoded: Option<Vec<u8>>,
        minimum_revision: u64,
    }

    struct TestBackend {
        protection: RollbackProtectionClass,
        events: Rc<RefCell<Vec<Event>>>,
        trusted_now: Cell<u64>,
        held: Rc<Cell<bool>>,
        fence: Rc<Cell<u64>>,
        checks: Rc<Cell<u64>>,
        durable: RefCell<DurableState>,
        manifests: RefCell<VecDeque<Result<ResolvedManifest, TestBackendError>>>,
    }

    impl TestBackend {
        fn new(
            manifests: impl IntoIterator<Item = Result<ResolvedManifest, TestBackendError>>,
        ) -> Self {
            Self {
                protection: RollbackProtectionClass::IndependentLocalRoot,
                events: Rc::new(RefCell::new(Vec::new())),
                trusted_now: Cell::new(NOW),
                held: Rc::new(Cell::new(true)),
                fence: Rc::new(Cell::new(1)),
                checks: Rc::new(Cell::new(0)),
                durable: RefCell::new(DurableState::default()),
                manifests: RefCell::new(manifests.into_iter().collect()),
            }
        }

        fn exact_namespace() -> StorageNamespaceId {
            StorageNamespaceId::new(STORAGE_NAMESPACE).expect("test namespace")
        }

        fn verify_expectation(
            &self,
            expectation: NamedServiceAuthorityExpectation,
            durable: &DurableState,
        ) -> Result<(), TestBackendError> {
            if expectation.storage_namespace_id() != Self::exact_namespace()
                || expectation.fencing_token().get() != self.fence.get()
            {
                return Err(TestBackendError::Cas);
            }
            match expectation {
                NamedServiceAuthorityExpectation::Absent { .. }
                    if !durable.initialized && durable.encoded.is_none() =>
                {
                    Ok(())
                }
                NamedServiceAuthorityExpectation::Exact {
                    revision,
                    fingerprint,
                    ..
                } => {
                    let encoded = durable.encoded.as_deref().ok_or(TestBackendError::Cas)?;
                    let current = NamedServiceAuthoritySnapshot::decode(encoded)
                        .map_err(|_| TestBackendError::Cas)?;
                    if current.revision() == revision
                        && current.fingerprint().map_err(|_| TestBackendError::Cas)? == fingerprint
                    {
                        Ok(())
                    } else {
                        Err(TestBackendError::Cas)
                    }
                }
                NamedServiceAuthorityExpectation::Absent { .. } => Err(TestBackendError::Cas),
            }
        }
    }

    impl HrmHnsaAuthorityBackend for TestBackend {
        type Error = TestBackendError;
        type AuthorityLease = TestGuard;

        fn rollback_protection(&self) -> RollbackProtectionClass {
            self.protection
        }

        fn acquire_authority_lease(
            &self,
            key: &AuthorityLeaseKey,
        ) -> Result<Self::AuthorityLease, Self::Error> {
            self.events.borrow_mut().push(Event::Acquire);
            Ok(TestGuard {
                key: *key,
                fence: Rc::clone(&self.fence),
                held: Rc::clone(&self.held),
                checks: Rc::clone(&self.checks),
            })
        }

        fn trusted_time(&self) -> Result<u64, Self::Error> {
            self.events.borrow_mut().push(Event::TrustedTime);
            Ok(self.trusted_now.get())
        }

        fn load_authority_state(
            &self,
            _: &AuthorityLeaseWitness<'_>,
        ) -> Result<NamedServiceAuthorityStorageState, Self::Error> {
            self.events.borrow_mut().push(Event::Load);
            let durable = self.durable.borrow();
            match (&durable.encoded, durable.initialized) {
                (None, false) => Ok(NamedServiceAuthorityStorageState::Absent),
                (Some(encoded), true) => Ok(NamedServiceAuthorityStorageState::Present {
                    encoded: encoded.clone(),
                    minimum_revision: durable.minimum_revision,
                }),
                _ => Err(TestBackendError::MissingInitializedState),
            }
        }

        fn persist_authority_state(
            &self,
            expectation: NamedServiceAuthorityExpectation,
            snapshot: &NamedServiceAuthoritySnapshot,
        ) -> Result<(), Self::Error> {
            self.events
                .borrow_mut()
                .push(Event::Persist(snapshot.revision()));
            let mut durable = self.durable.borrow_mut();
            self.verify_expectation(expectation, &durable)?;
            durable.encoded = Some(snapshot.encode().map_err(|_| TestBackendError::Cas)?);
            durable.initialized = true;
            durable.minimum_revision = durable.minimum_revision.max(snapshot.revision());
            Ok(())
        }

        fn retrieve_current_manifest(
            &self,
            lease: &AuthorityLeaseWitness<'_>,
            identity: &NamedServiceIdentity,
            trusted_now: u64,
        ) -> Result<ResolvedManifest, Self::Error> {
            lease
                .ensure_held()
                .map_err(|_| TestBackendError::Retrieval)?;
            if identity.network_magic != NETWORK_MAGIC
                || identity.name_hash != SUBJECT
                || trusted_now != self.trusted_now.get()
            {
                return Err(TestBackendError::Retrieval);
            }
            self.events.borrow_mut().push(Event::Retrieve);
            self.manifests
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(TestBackendError::Retrieval))
        }
    }

    fn identity() -> NamedServiceIdentity {
        NamedServiceIdentity::new(NETWORK_MAGIC, SUBJECT, "wallet", PROFILE_ID)
            .expect("test identity")
    }

    fn policy() -> NamedServicePolicy {
        NamedServicePolicy {
            application_profile_id: PROFILE_ID,
            allowed_profile_flags: 0,
            required_profile_flags: 0,
            expected_profile_constraints_hash: [0; 32],
            allowed_endpoint_capabilities: 1,
            required_endpoint_capabilities: 1,
            expected_endpoint_constraints_hash: [0; 32],
            maximum_endpoint_lifetime: 3_600,
        }
    }

    fn config(maximum_live_subjects: usize) -> HrmHnsaAuthorityBrokerConfig {
        HrmHnsaAuthorityBrokerConfig::new(
            STORAGE_NAMESPACE,
            maximum_live_subjects,
            4,
            ValidationLimits::default(),
            RollbackProtectionClass::IndependentLocalRoot,
        )
        .expect("test broker config")
    }

    fn resolved_manifest(sequence: u64, active: bool) -> ResolvedManifest {
        let hrm_private_key = [1; 32];
        let service_private_key = [2; 32];
        let controller =
            Controller::secp256k1(public_key(&hrm_private_key).expect("HRM controller public key"))
                .expect("HRM controller");
        let identity = identity();
        let (resources, delegations) = if active {
            let resource = named_service_resource(
                &identity,
                NamedServiceAttributes {
                    profile_flags: 0,
                    profile_constraints_hash: [0; 32],
                    presentation: None,
                },
                NOW - 10,
                NOW + 1_000,
            )
            .expect("named service resource");
            let delegation = service_controller_delegation(
                &identity,
                &resource,
                public_key(&service_private_key).expect("service controller public key"),
                ServiceDelegationConstraints {
                    service_generation: 1,
                    max_endpoint_lifetime: 3_600,
                    allowed_endpoint_capabilities: 1,
                    endpoint_constraints_hash: [0; 32],
                },
                NOW - 10,
                NOW + 1_000,
                NOW - 10,
                NOW + 1_000,
            )
            .expect("service controller delegation");
            (vec![resource], vec![delegation])
        } else {
            (Vec::new(), Vec::new())
        };
        let envelope = Envelope::sign(
            Payload {
                version: VERSION,
                subject: SUBJECT,
                sequence,
                issued_at: NOW - 10,
                expires_at: NOW + 1_000,
                controller,
                resources,
                delegations,
                extensions: None,
            },
            NETWORK_MAGIC,
            &hrm_private_key,
        )
        .expect("signed HRM envelope");
        let envelope_hash = envelope.envelope_hash().expect("HRM envelope hash");
        let envelope = envelope.encode().expect("HRM envelope encoding");
        let mut chain_work = [0; 32];
        chain_work[24..].copy_from_slice(&sequence.to_be_bytes());
        ResolvedManifest {
            name_state: AuthenticatedNameState {
                network_magic: NETWORK_MAGIC,
                subject: SUBJECT,
                has_current_owner: true,
                revoked: false,
                expired: false,
                finality_accepted: true,
                chain_height: 100 + u32::try_from(sequence).expect("test sequence height"),
                chain_work,
                chain_anchor: [u8::try_from(sequence).expect("test sequence anchor"); 32],
                accepted_reorganization: None,
                commitment_records: vec![vec![
                    "hrm1".to_owned(),
                    format!("seq={sequence}"),
                    format!("hash=sha256:{}", base64url(&envelope_hash)),
                    "uri=https://example.test/hrm".to_owned(),
                ]],
            },
            envelope,
        }
    }

    fn base64url(input: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::with_capacity(input.len().saturating_mul(4).div_ceil(3));
        for chunk in input.chunks(3) {
            let word = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            output.push(TABLE[((word >> 18) & 63) as usize] as char);
            output.push(TABLE[((word >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                output.push(TABLE[((word >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                output.push(TABLE[(word & 63) as usize] as char);
            }
        }
        output
    }

    #[test]
    fn persists_time_and_authority_before_releasing_current_active_service() {
        let backend = TestBackend::new([Ok(resolved_manifest(1, true))]);
        let events = Rc::clone(&backend.events);
        let mut broker = HrmHnsaAuthorityBroker::new(config(4), backend).expect("broker");
        let selected = broker
            .with_current_named_service(&identity(), &policy(), |current| {
                events.borrow_mut().push(Event::Callback);
                assert_eq!(current.authority_revision(), 1);
                assert_eq!(current.trusted_time_high_water(), NOW);
                let active = current.active().expect("active service");
                assert_eq!(active.identity(), &identity());
                assert_eq!(active.service_generation(), 1);
                Ok::<_, Infallible>(active.resource_id())
            })
            .expect("current service");
        assert_eq!(selected, identity().resource_id().expect("resource ID"));
        assert_eq!(broker.live_subjects(), 1);
        assert_eq!(
            events.borrow().as_slice(),
            &[
                Event::Acquire,
                Event::TrustedTime,
                Event::Load,
                Event::Load,
                Event::Persist(0),
                Event::Retrieve,
                Event::Persist(1),
                Event::Callback,
            ]
        );
        let durable = broker.backend().durable.borrow();
        assert!(durable.initialized);
        assert_eq!(durable.minimum_revision, 1);
        assert!(durable.encoded.is_some());
        let debug = format!("{broker:?}");
        assert!(debug.contains("<opaque>"));
        assert!(!debug.contains("8, 8, 8"));
    }

    #[test]
    fn withdrawal_is_committed_and_bound_under_the_same_lease() {
        let backend = TestBackend::new([
            Ok(resolved_manifest(1, true)),
            Ok(resolved_manifest(2, false)),
        ]);
        let mut broker = HrmHnsaAuthorityBroker::new(config(4), backend).expect("broker");
        broker
            .with_current_named_service(&identity(), &policy(), |current| {
                assert!(current.active().is_some());
                Ok::<_, Infallible>(())
            })
            .expect("active service");
        let withdrawn = broker
            .with_current_named_service(&identity(), &policy(), |current| {
                assert!(current.active().is_none());
                assert!(current.is_withdrawn());
                assert!(current.withdrawal().is_some());
                Ok::<_, Infallible>(current.authority_revision())
            })
            .expect("withdrawal");
        assert_eq!(withdrawn, 2);
        assert_eq!(broker.backend().durable.borrow().minimum_revision, 2);
    }

    #[test]
    fn failed_retrieval_still_durably_advances_trusted_time() {
        let backend = TestBackend::new([
            Ok(resolved_manifest(1, true)),
            Err(TestBackendError::Retrieval),
        ]);
        let events = Rc::clone(&backend.events);
        let mut broker = HrmHnsaAuthorityBroker::new(config(4), backend).expect("broker");
        broker
            .with_current_named_service(&identity(), &policy(), |_| Ok::<_, Infallible>(()))
            .expect("initial authority");
        events.borrow_mut().clear();
        broker.backend().trusted_now.set(NOW + 10);
        let called = Cell::new(false);
        let result = broker.with_current_named_service(&identity(), &policy(), |_| {
            called.set(true);
            Ok::<_, Infallible>(())
        });
        assert!(matches!(
            result,
            Err(HrmHnsaAuthorityBrokerError::Backend(
                TestBackendError::Retrieval
            ))
        ));
        assert!(!called.get());
        assert_eq!(
            events.borrow().as_slice(),
            &[
                Event::Acquire,
                Event::TrustedTime,
                Event::Load,
                Event::Persist(2),
                Event::Retrieve,
            ]
        );
        assert_eq!(broker.backend().durable.borrow().minimum_revision, 2);
    }

    #[test]
    fn lease_loss_suppresses_a_callback_result_and_missing_initialized_state_fails_closed() {
        let backend = TestBackend::new([
            Ok(resolved_manifest(1, true)),
            Ok(resolved_manifest(1, true)),
        ]);
        let held = Rc::clone(&backend.held);
        let mut broker = HrmHnsaAuthorityBroker::new(config(4), backend).expect("broker");
        broker
            .with_current_named_service(&identity(), &policy(), |_| Ok::<_, Infallible>(()))
            .expect("initial authority");
        let result = broker.with_current_named_service(&identity(), &policy(), |_| {
            held.set(false);
            Ok::<_, Infallible>(41_u8)
        });
        assert!(matches!(
            result,
            Err(HrmHnsaAuthorityBrokerError::Lease(LeaseError::Lost))
        ));

        held.set(true);
        broker.backend().durable.borrow_mut().encoded = None;
        let result =
            broker.with_current_named_service(&identity(), &policy(), |_| Ok::<_, Infallible>(()));
        assert!(matches!(
            result,
            Err(HrmHnsaAuthorityBrokerError::Backend(
                TestBackendError::MissingInitializedState
            ))
        ));
    }

    #[test]
    fn panic_runs_the_release_boundary_check_and_retains_live_state() {
        let backend = TestBackend::new([Ok(resolved_manifest(1, true))]);
        let checks = Rc::clone(&backend.checks);
        let mut broker = HrmHnsaAuthorityBroker::new(config(4), backend).expect("broker");
        let before = checks.get();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _: Result<(), HrmHnsaAuthorityBrokerError<TestBackendError, Infallible>> = broker
                .with_current_named_service(&identity(), &policy(), |_| {
                    panic!("consumer panic fixture")
                });
        }));
        assert!(result.is_err());
        assert!(checks.get() > before + 1);
        assert_eq!(broker.live_subjects(), 1);
    }

    #[test]
    fn configuration_and_live_subject_bounds_fail_closed() {
        assert!(matches!(
            HrmHnsaAuthorityBrokerConfig::new(
                [0; 32],
                1,
                1,
                ValidationLimits::default(),
                RollbackProtectionClass::IndependentLocalRoot,
            ),
            Err(HrmHnsaAuthorityBrokerConfigError::Lease(
                LeaseError::ZeroStorageNamespace
            ))
        ));
        assert!(matches!(
            HrmHnsaAuthorityBrokerConfig::new(
                STORAGE_NAMESPACE,
                1,
                1,
                ValidationLimits::default(),
                RollbackProtectionClass::IntegrityOnlySameRollbackDomain,
            ),
            Err(HrmHnsaAuthorityBrokerConfigError::InadequateRollbackProtection)
        ));

        let backend = TestBackend::new([Ok(resolved_manifest(1, true))]);
        let events = Rc::clone(&backend.events);
        let mut broker = HrmHnsaAuthorityBroker::new(config(1), backend).expect("broker");
        broker
            .with_current_named_service(&identity(), &policy(), |_| Ok::<_, Infallible>(()))
            .expect("first subject");
        events.borrow_mut().clear();
        let another = NamedServiceIdentity::new(NETWORK_MAGIC, [9; 32], "wallet", PROFILE_ID)
            .expect("second identity");
        let result =
            broker.with_current_named_service(&another, &policy(), |_| Ok::<_, Infallible>(()));
        assert!(matches!(
            result,
            Err(HrmHnsaAuthorityBrokerError::SubjectCapacity)
        ));
        assert!(events.borrow().is_empty());
    }
}
