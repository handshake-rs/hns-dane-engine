//! Dual-fenced native broker for current HRM/HNSA-backed HNSR routes.
//!
//! This module composes the canonical authority and requester state machines.
//! Platform integrations still supply real cross-process leases, authenticated
//! storage with independent rollback floors, trusted time, current HNS/HRM
//! retrieval, and a complete raw HNSR response batch. The broker fixes the
//! lease, time, persistence, validation, and callback ordering shared by every
//! native browser, extension, mobile, and wallet consumer.

use std::any::Any;
use std::error::Error;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

pub use hns_hnsr_protocol::{
    CurrentNamedRouteV3, HnsrProtocolError, HrmNamedRoutePolicy, NamedRouteV3OperationLeaseWitness,
    NamedRouteV3RequesterExpectation, NamedRouteV3RequesterLeaseKey, NamedRouteV3RequesterSnapshot,
    NamedRouteV3RequesterStorageState,
};
use hns_hnsr_protocol::{
    HeldNamedRouteV3OperationLeases, MAX_STORED_RECORDS, NamedRouteV3LeaseAcquireError,
    NamedRouteV3LeaseScopeError, NamedRouteV3RequesterOperationError, NamedRouteV3RequesterState,
    named_route_key_v3,
};
use hns_service_authority::authority_state::NamedServiceAuthorityError;
use hns_service_authority::lease::{LeaseAcquireError, LeaseError};

use crate::hrm_hnsa_broker::{
    AuthorityLeaseKey, FencedLeaseGuard, HrmHnsaAuthorityBackend, HrmHnsaAuthorityBroker,
    HrmHnsaAuthorityBrokerConfig, HrmHnsaAuthorityBrokerConfigError, HrmHnsaAuthorityBrokerError,
    NamedServiceIdentity, NamedServicePolicy, RollbackProtectionClass, StorageNamespaceId,
};

/// Default permanent requester observations retained by one native broker.
pub const DEFAULT_HRM_HNSA_HNSR_REQUESTER_ENTRIES: usize = 1_024;
/// Protocol hard bound for one permanent multi-origin requester aggregate.
pub const MAX_HRM_HNSA_HNSR_REQUESTER_ENTRIES: usize = MAX_STORED_RECORDS;

/// Immutable authority and requester lineage configuration.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HrmHnsaHnsrRequesterBrokerConfig {
    authority: HrmHnsaAuthorityBrokerConfig,
    requester_storage_namespace_id: StorageNamespaceId,
    network_magic: u32,
    requester_entry_capacity: usize,
    requester_rollback_protection: RollbackProtectionClass,
}

impl HrmHnsaHnsrRequesterBrokerConfig {
    /// Construct one exact-network requester configuration.
    ///
    /// Authority and requester snapshots are distinct durable lineages and
    /// therefore require distinct storage namespace IDs and independently
    /// protected revision floors.
    pub fn new(
        authority: HrmHnsaAuthorityBrokerConfig,
        requester_storage_namespace_id: [u8; 32],
        network_magic: u32,
        requester_entry_capacity: usize,
        requester_rollback_protection: RollbackProtectionClass,
    ) -> Result<Self, HrmHnsaHnsrRequesterBrokerConfigError> {
        let requester_storage_namespace_id =
            StorageNamespaceId::new(requester_storage_namespace_id)
                .map_err(HrmHnsaHnsrRequesterBrokerConfigError::Lease)?;
        if requester_storage_namespace_id == authority.storage_namespace_id() {
            return Err(HrmHnsaHnsrRequesterBrokerConfigError::SharedStorageNamespace);
        }
        if !(1..=MAX_HRM_HNSA_HNSR_REQUESTER_ENTRIES).contains(&requester_entry_capacity) {
            return Err(HrmHnsaHnsrRequesterBrokerConfigError::InvalidRequesterEntryCapacity);
        }
        if !requester_rollback_protection.has_independent_rollback_domain() {
            return Err(
                HrmHnsaHnsrRequesterBrokerConfigError::InadequateRequesterRollbackProtection,
            );
        }
        Ok(Self {
            authority,
            requester_storage_namespace_id,
            network_magic,
            requester_entry_capacity,
            requester_rollback_protection,
        })
    }

    /// Subject-wide authority lineage configuration.
    #[must_use]
    pub const fn authority(self) -> HrmHnsaAuthorityBrokerConfig {
        self.authority
    }

    /// Namespace for the one whole multi-origin requester aggregate.
    #[must_use]
    pub const fn requester_storage_namespace_id(self) -> StorageNamespaceId {
        self.requester_storage_namespace_id
    }

    /// Exact Handshake network accepted by this requester aggregate.
    #[must_use]
    pub const fn network_magic(self) -> u32 {
        self.network_magic
    }

    /// Permanent requester observation capacity; entries are never evicted.
    #[must_use]
    pub const fn requester_entry_capacity(self) -> usize {
        self.requester_entry_capacity
    }

    /// Minimum honest protection classification required from the backend.
    #[must_use]
    pub const fn requester_rollback_protection(self) -> RollbackProtectionClass {
        self.requester_rollback_protection
    }
}

impl fmt::Debug for HrmHnsaHnsrRequesterBrokerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HrmHnsaHnsrRequesterBrokerConfig")
            .field("authority", &self.authority)
            .field("requester_storage_namespace_id", &"<opaque>")
            .field("network_magic", &self.network_magic)
            .field("requester_entry_capacity", &self.requester_entry_capacity)
            .field(
                "requester_rollback_protection",
                &self.requester_rollback_protection,
            )
            .finish()
    }
}

/// Invalid immutable combined-broker configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HrmHnsaHnsrRequesterBrokerConfigError {
    /// The embedded authority configuration or backend is invalid.
    Authority(HrmHnsaAuthorityBrokerConfigError),
    /// The requester namespace identity is invalid.
    Lease(LeaseError),
    /// Authority and requester lineages reused one namespace identity.
    SharedStorageNamespace,
    /// The permanent requester bound is zero or exceeds the protocol maximum.
    InvalidRequesterEntryCapacity,
    /// The requester snapshot and revision floor share one replayable domain.
    InadequateRequesterRollbackProtection,
    /// The backend honestly reports a different requester protection class.
    RequesterRollbackProtectionMismatch,
}

impl fmt::Display for HrmHnsaHnsrRequesterBrokerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => error.fmt(formatter),
            Self::Lease(error) => error.fmt(formatter),
            Self::SharedStorageNamespace => formatter.write_str(
                "HRM/HNSA authority and HNSR requester lineages require distinct namespaces",
            ),
            Self::InvalidRequesterEntryCapacity => write!(
                formatter,
                "HNSR requester entry capacity must be in 1..={MAX_HRM_HNSA_HNSR_REQUESTER_ENTRIES}",
            ),
            Self::InadequateRequesterRollbackProtection => formatter.write_str(
                "HNSR production requester state requires an independent rollback domain",
            ),
            Self::RequesterRollbackProtectionMismatch => formatter.write_str(
                "HNSR requester backend rollback protection differs from broker configuration",
            ),
        }
    }
}

impl Error for HrmHnsaHnsrRequesterBrokerConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Lease(error) => Some(error),
            _ => None,
        }
    }
}

/// Trusted native services required by [`HrmHnsaHnsrRequesterBroker`].
///
/// This extends [`HrmHnsaAuthorityBackend`] with the distinct permanent HNSR
/// requester lineage. Implementations must additionally satisfy all of the
/// following:
///
/// - `acquire_requester_lease` returns a real non-cloneable, cross-process
///   exclusion guard for the complete multi-origin aggregate, with a monotonic
///   nonzero fencing token independent of the authority lineage;
/// - `load_requester_state` returns authenticated bytes and a non-evictable
///   external revision floor, and returns `Absent` only before the aggregate
///   has ever been initialized;
/// - `persist_requester_state` atomically checks namespace, fencing token,
///   exact prior revision and complete fingerprint while installing the whole
///   snapshot, initialized marker, and independent revision floor;
/// - ambiguous writes are exactly reconciled before later use; and
/// - `retrieve_complete_raw_route_batch` begins every fallible transport and
///   response-acquisition action only when invoked, after requester trusted
///   time is durably acknowledged, and returns the complete raw response batch
///   for the exact route key.
///
/// Per-origin locks or snapshots, page/extension storage without a trusted
/// broker, decoded caller-supplied routes, and incomplete/paginated batches do
/// not implement this contract.
pub trait HrmHnsaHnsrRequesterBackend: HrmHnsaAuthorityBackend {
    /// Owned real requester guard retained with authority through the callback.
    type RequesterLease: FencedLeaseGuard<NamedRouteV3RequesterLeaseKey>;

    /// Honest requester rollback protection actually supplied by the backend.
    fn requester_rollback_protection(&self) -> RollbackProtectionClass;

    /// Acquire exclusive ownership of the complete requester aggregate.
    fn acquire_requester_lease(
        &self,
        key: &NamedRouteV3RequesterLeaseKey,
    ) -> Result<Self::RequesterLease, Self::Error>;

    /// Load the latest authenticated whole requester aggregate under both leases.
    fn load_requester_state(
        &self,
        lease: &NamedRouteV3OperationLeaseWitness<'_>,
    ) -> Result<NamedRouteV3RequesterStorageState, Self::Error>;

    /// Apply one exact fenced whole-aggregate CAS and durably acknowledge it.
    fn persist_requester_state(
        &self,
        expectation: NamedRouteV3RequesterExpectation,
        snapshot: &NamedRouteV3RequesterSnapshot,
    ) -> Result<(), Self::Error>;

    /// Retrieve the complete untrusted raw route batch for one stable route key.
    fn retrieve_complete_raw_route_batch(
        &self,
        lease: &NamedRouteV3OperationLeaseWitness<'_>,
        route_key: &[u8; 32],
        trusted_now: u64,
    ) -> Result<Vec<Vec<u8>>, Self::Error>;
}

/// Failure from one exact dual-fenced current-route operation.
#[derive(Debug)]
pub enum HrmHnsaHnsrRequesterBrokerError<B, O> {
    /// Trusted platform backend failure.
    Backend(B),
    /// Canonical HRM/HNSA validation or durable-state failure.
    Authority(NamedServiceAuthorityError),
    /// Canonical HNSR requester, decoding, reduction, or binding failure.
    Requester(HnsrProtocolError),
    /// Either ordered lease was unavailable, lost, expired, or replaced.
    Lease(LeaseError),
    /// The bounded authority broker cannot admit another subject aggregate.
    SubjectCapacity,
    /// The caller-owned dependent operation failed while both leases were held.
    Operation(O),
}

impl<B: fmt::Display, O: fmt::Display> fmt::Display for HrmHnsaHnsrRequesterBrokerError<B, O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(error) => write!(formatter, "HRM/HNSA/HNSR backend failed: {error}"),
            Self::Authority(error) => error.fmt(formatter),
            Self::Requester(error) => error.fmt(formatter),
            Self::Lease(error) => error.fmt(formatter),
            Self::SubjectCapacity => {
                formatter.write_str("HRM/HNSA broker live-subject capacity is exhausted")
            }
            Self::Operation(error) => error.fmt(formatter),
        }
    }
}

impl<B, O> Error for HrmHnsaHnsrRequesterBrokerError<B, O>
where
    B: Error + 'static,
    O: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Backend(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::Requester(error) => Some(error),
            Self::Lease(error) => Some(error),
            Self::Operation(error) => Some(error),
            Self::SubjectCapacity => None,
        }
    }
}

/// Sole live owner of one requester aggregate and bounded authority subjects.
///
/// The broker is deliberately non-cloneable. Currentness across other
/// processes or restored instances comes from the backend's real ordered
/// leases and authenticated lineages, not this Rust ownership alone.
pub struct HrmHnsaHnsrRequesterBroker<B> {
    config: HrmHnsaHnsrRequesterBrokerConfig,
    authority: HrmHnsaAuthorityBroker<B>,
    requester: Option<NamedRouteV3RequesterState>,
}

impl<B: HrmHnsaHnsrRequesterBackend> HrmHnsaHnsrRequesterBroker<B> {
    /// Bind one trusted backend to exact authority and requester lineages.
    pub fn new(
        config: HrmHnsaHnsrRequesterBrokerConfig,
        backend: B,
    ) -> Result<Self, HrmHnsaHnsrRequesterBrokerConfigError> {
        if backend.requester_rollback_protection() != config.requester_rollback_protection() {
            return Err(HrmHnsaHnsrRequesterBrokerConfigError::RequesterRollbackProtectionMismatch);
        }
        let authority = HrmHnsaAuthorityBroker::new(config.authority(), backend)
            .map_err(HrmHnsaHnsrRequesterBrokerConfigError::Authority)?;
        Ok(Self {
            config,
            authority,
            requester: None,
        })
    }

    /// Immutable combined-broker configuration.
    #[must_use]
    pub const fn config(&self) -> HrmHnsaHnsrRequesterBrokerConfig {
        self.config
    }

    /// Number of subject-wide authority aggregates retained in memory.
    #[must_use]
    pub fn live_authority_subjects(&self) -> usize {
        self.authority.live_subjects()
    }

    /// Whether the permanent requester aggregate has been loaded in this process.
    #[must_use]
    pub const fn requester_loaded(&self) -> bool {
        self.requester.is_some()
    }

    /// Borrow the backend for platform diagnostics that confer no authority.
    #[must_use]
    pub const fn backend(&self) -> &B {
        self.authority.backend()
    }

    /// Establish and use one exact current HRM/HNSA-backed named route.
    ///
    /// The broker validates inputs before acquiring the authority-subject lease
    /// and then the requester-aggregate lease in the protocol-fixed order. It
    /// holds both while selecting one trusted time, committing current
    /// authority, advancing requester time before raw retrieval, reducing and
    /// persisting the complete response batch, binding the exact route, and
    /// running the dependent callback. The callback's owned result is withheld
    /// until both release-boundary checks pass.
    ///
    /// The callback should establish the profile-authenticated inner session
    /// before returning success. An expiring/revocable platform guard requires
    /// broker-owned fenced promotion for irreversible effects; a final point
    /// check alone is not sufficient.
    pub fn with_current_named_route<T, O, F>(
        &mut self,
        identity: &NamedServiceIdentity,
        authority_policy: &NamedServicePolicy,
        endpoint_key: &[u8; 33],
        route_policy: HrmNamedRoutePolicy,
        operation: F,
    ) -> Result<T, HrmHnsaHnsrRequesterBrokerError<B::Error, O>>
    where
        F: for<'route> FnOnce(&'route CurrentNamedRouteV3<'route>) -> Result<T, O>,
    {
        identity
            .validate()
            .map_err(NamedServiceAuthorityError::from)
            .map_err(HrmHnsaHnsrRequesterBrokerError::Authority)?;
        authority_policy
            .validate()
            .map_err(NamedServiceAuthorityError::from)
            .map_err(HrmHnsaHnsrRequesterBrokerError::Authority)?;
        if identity.network_magic != self.config.network_magic() {
            return Err(HrmHnsaHnsrRequesterBrokerError::Requester(
                HnsrProtocolError::Invalid("named-route requester network mismatch"),
            ));
        }
        let route_key =
            named_route_key_v3(identity).map_err(HrmHnsaHnsrRequesterBrokerError::Requester)?;
        let authority_key = AuthorityLeaseKey::new(
            self.config.authority().storage_namespace_id(),
            identity.network_magic,
            identity.name_hash,
        );
        let requester_key = NamedRouteV3RequesterLeaseKey::new(
            self.config.requester_storage_namespace_id(),
            self.config.network_magic(),
        );
        let backend = self.authority.backend();
        let held = HeldNamedRouteV3OperationLeases::acquire(
            authority_key,
            requester_key,
            |key| backend.acquire_authority_lease(key),
            |key| backend.acquire_requester_lease(key),
        )
        .map_err(map_lease_acquire)?;

        let mut panic_payload: Option<Box<dyn Any + Send>> = None;
        let scoped = held.run(|lease| {
            let attempted = catch_unwind(AssertUnwindSafe(|| {
                run_dual_scoped(
                    self,
                    lease,
                    &route_key,
                    identity,
                    authority_policy,
                    endpoint_key,
                    route_policy,
                    operation,
                )
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
            Ok(None) => Err(HrmHnsaHnsrRequesterBrokerError::Requester(
                HnsrProtocolError::Invalid("broker panic containment lost its panic payload"),
            )),
            Err(NamedRouteV3LeaseScopeError::Operation(error)) => Err(error),
            Err(
                NamedRouteV3LeaseScopeError::Authority(error)
                | NamedRouteV3LeaseScopeError::Requester(error),
            ) => Err(HrmHnsaHnsrRequesterBrokerError::Lease(error)),
        }
    }
}

impl<B: HrmHnsaAuthorityBackend> fmt::Debug for HrmHnsaHnsrRequesterBroker<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HrmHnsaHnsrRequesterBroker")
            .field("config", &self.config)
            .field("backend", &"<trusted>")
            .field("live_authority_subjects", &self.authority.live_subjects())
            .field("requester_loaded", &self.requester.is_some())
            .finish()
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the operation explicitly binds both state lineages, one time, one route key, and both policies"
)]
fn run_dual_scoped<B, T, O, F>(
    broker: &mut HrmHnsaHnsrRequesterBroker<B>,
    lease: &NamedRouteV3OperationLeaseWitness<'_>,
    route_key: &[u8; 32],
    identity: &NamedServiceIdentity,
    authority_policy: &NamedServicePolicy,
    endpoint_key: &[u8; 33],
    route_policy: HrmNamedRoutePolicy,
    operation: F,
) -> Result<T, HrmHnsaHnsrRequesterBrokerError<B::Error, O>>
where
    B: HrmHnsaHnsrRequesterBackend,
    F: for<'route> FnOnce(&'route CurrentNamedRouteV3<'route>) -> Result<T, O>,
{
    lease
        .ensure_held()
        .map_err(HrmHnsaHnsrRequesterBrokerError::Lease)?;
    let trusted_now = broker
        .authority
        .backend()
        .trusted_time()
        .map_err(HrmHnsaHnsrRequesterBrokerError::Backend)?;
    let config = broker.config;
    let authority_result = broker.authority.with_current_named_service_under_lease(
        lease.authority(),
        trusted_now,
        identity,
        authority_policy,
        |backend, committed_service| {
            run_requester_scoped(
                config,
                &mut broker.requester,
                backend,
                lease,
                trusted_now,
                route_key,
                endpoint_key,
                committed_service,
                route_policy,
                operation,
            )
        },
    );
    map_authority_result(authority_result)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the scoped requester operation keeps every authority, route, time, lease, and callback binding explicit"
)]
fn run_requester_scoped<B, T, O, F>(
    config: HrmHnsaHnsrRequesterBrokerConfig,
    requester: &mut Option<NamedRouteV3RequesterState>,
    backend: &B,
    lease: &NamedRouteV3OperationLeaseWitness<'_>,
    trusted_now: u64,
    route_key: &[u8; 32],
    endpoint_key: &[u8; 33],
    committed_service: &hns_service_authority::authority_state::CurrentCommittedNamedService<'_>,
    route_policy: HrmNamedRoutePolicy,
    operation: F,
) -> Result<T, RequesterScopedError<B::Error, O>>
where
    B: HrmHnsaHnsrRequesterBackend,
    F: for<'route> FnOnce(&'route CurrentNamedRouteV3<'route>) -> Result<T, O>,
{
    lease
        .ensure_held()
        .map_err(|error| RequesterScopedError::Requester(lease_error(error)))?;

    let mut first_loaded = None;
    if requester.is_none() {
        let loaded = backend
            .load_requester_state(lease)
            .map_err(RequesterScopedError::Backend)?;
        let state = match loaded {
            NamedRouteV3RequesterStorageState::Absent => {
                first_loaded = Some(NamedRouteV3RequesterStorageState::Absent);
                NamedRouteV3RequesterState::new(
                    config.network_magic(),
                    config.requester_entry_capacity(),
                    trusted_now,
                )
            }
            NamedRouteV3RequesterStorageState::Present {
                encoded,
                minimum_revision,
            } => {
                let snapshot = NamedRouteV3RequesterSnapshot::decode(&encoded);
                first_loaded = Some(NamedRouteV3RequesterStorageState::Present {
                    encoded,
                    minimum_revision,
                });
                snapshot.and_then(|snapshot| {
                    NamedRouteV3RequesterState::restore(
                        config.network_magic(),
                        config.requester_entry_capacity(),
                        snapshot,
                        minimum_revision,
                        trusted_now,
                    )
                })
            }
        }
        .map_err(RequesterScopedError::Requester)?;
        *requester = Some(state);
    }

    let state = requester.as_mut().ok_or_else(|| {
        RequesterScopedError::Requester(HnsrProtocolError::Invalid(
            "broker lost its live requester aggregate",
        ))
    })?;
    let mut load_backend_error = None;
    let reconfirmed = state.reconfirm(lease, |_| {
        if let Some(loaded) = first_loaded.take() {
            return Ok(loaded);
        }
        match backend.load_requester_state(lease) {
            Ok(loaded) => Ok(loaded),
            Err(error) => {
                load_backend_error = Some(error);
                Err(HnsrProtocolError::Invalid(
                    "trusted requester-state load failed",
                ))
            }
        }
    });
    if let Some(error) = load_backend_error {
        return Err(RequesterScopedError::Backend(error));
    }
    let mut reconfirmed = reconfirmed.map_err(RequesterScopedError::Requester)?;

    let mut persistence_backend_error = None;
    let current = reconfirmed.retrieve_select_and_observe_current_persisted(
        trusted_now,
        |operation_time| {
            backend.retrieve_complete_raw_route_batch(lease, route_key, operation_time)
        },
        endpoint_key,
        committed_service,
        route_policy,
        |expectation, snapshot| match backend.persist_requester_state(expectation, snapshot) {
            Ok(()) => Ok(()),
            Err(error) => {
                persistence_backend_error = Some(error);
                Err(HnsrProtocolError::Invalid(
                    "trusted requester-state persistence failed",
                ))
            }
        },
    );
    if let Some(error) = persistence_backend_error {
        return Err(RequesterScopedError::Backend(error));
    }
    let current = match current {
        Ok(current) => current,
        Err(NamedRouteV3RequesterOperationError::Retrieval(error)) => {
            return Err(RequesterScopedError::Backend(error));
        }
        Err(NamedRouteV3RequesterOperationError::Requester(error)) => {
            return Err(RequesterScopedError::Requester(error));
        }
    };
    current
        .ensure_leases_held()
        .map_err(RequesterScopedError::Requester)?;
    let result = operation(&current).map_err(RequesterScopedError::Operation);
    current
        .ensure_leases_held()
        .map_err(RequesterScopedError::Requester)?;
    result
}

#[derive(Debug)]
enum RequesterScopedError<B, O> {
    Backend(B),
    Requester(HnsrProtocolError),
    Operation(O),
}

fn map_lease_acquire<B, O>(
    error: NamedRouteV3LeaseAcquireError<B, B>,
) -> HrmHnsaHnsrRequesterBrokerError<B, O> {
    match error {
        NamedRouteV3LeaseAcquireError::BindingMismatch => {
            HrmHnsaHnsrRequesterBrokerError::Requester(HnsrProtocolError::Invalid(
                "authority and requester leases belong to different networks",
            ))
        }
        NamedRouteV3LeaseAcquireError::Authority(LeaseAcquireError::Backend(error))
        | NamedRouteV3LeaseAcquireError::Requester(LeaseAcquireError::Backend(error)) => {
            HrmHnsaHnsrRequesterBrokerError::Backend(error)
        }
        NamedRouteV3LeaseAcquireError::Authority(LeaseAcquireError::Lease(error))
        | NamedRouteV3LeaseAcquireError::Requester(LeaseAcquireError::Lease(error))
        | NamedRouteV3LeaseAcquireError::AuthorityLost(error) => {
            HrmHnsaHnsrRequesterBrokerError::Lease(error)
        }
    }
}

fn map_authority_result<B, O, T>(
    result: Result<T, HrmHnsaAuthorityBrokerError<B, RequesterScopedError<B, O>>>,
) -> Result<T, HrmHnsaHnsrRequesterBrokerError<B, O>> {
    result.map_err(|error| match error {
        HrmHnsaAuthorityBrokerError::Backend(error)
        | HrmHnsaAuthorityBrokerError::Operation(RequesterScopedError::Backend(error)) => {
            HrmHnsaHnsrRequesterBrokerError::Backend(error)
        }
        HrmHnsaAuthorityBrokerError::Authority(error) => {
            HrmHnsaHnsrRequesterBrokerError::Authority(error)
        }
        HrmHnsaAuthorityBrokerError::Lease(error) => HrmHnsaHnsrRequesterBrokerError::Lease(error),
        HrmHnsaAuthorityBrokerError::SubjectCapacity => {
            HrmHnsaHnsrRequesterBrokerError::SubjectCapacity
        }
        HrmHnsaAuthorityBrokerError::Operation(RequesterScopedError::Requester(error)) => {
            HrmHnsaHnsrRequesterBrokerError::Requester(error)
        }
        HrmHnsaAuthorityBrokerError::Operation(RequesterScopedError::Operation(error)) => {
            HrmHnsaHnsrRequesterBrokerError::Operation(error)
        }
    })
}

fn lease_error(error: LeaseError) -> HnsrProtocolError {
    match error {
        LeaseError::ZeroStorageNamespace
        | LeaseError::ZeroFencingToken
        | LeaseError::KeyMismatch
        | LeaseError::FenceChanged
        | LeaseError::Lost => HnsrProtocolError::Invalid("named-route operation lease was lost"),
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

    use hns_hnsr_protocol::{NamedRouteRecordV3, RelayTicket, public_key};
    use hns_hrm::model::{Controller, Envelope, Payload, VERSION, public_key as hrm_public_key};
    use hns_hrm::validation::{
        AuthenticatedNameState, ResolvedManifest, RollbackObservations, ValidationLimits,
        validate_current_manifest,
    };
    use hns_service_authority::authority_state::{
        NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot,
        NamedServiceAuthorityStorageState,
    };
    use hns_service_authority::hrm::{
        EndpointDelegationV1, NamedServiceAttributes, ServiceDelegationConstraints,
        VerifiedNamedService, named_service_resource, observe_named_service,
        service_controller_delegation,
    };
    use hns_service_authority::lease::{AuthorityLeaseWitness, FencingToken};

    use super::*;

    const NETWORK_MAGIC: u32 = 0xae38_95cf;
    const SUBJECT: [u8; 32] = [7; 32];
    const AUTHORITY_NAMESPACE: [u8; 32] = [8; 32];
    const REQUESTER_NAMESPACE: [u8; 32] = [9; 32];
    const NOW: u64 = 1_700_000_300;
    const PROFILE_ID: u16 = 0x8001;
    const SERVICE_PRIVATE_KEY: [u8; 32] = [2; 32];
    const ENDPOINT_PRIVATE_KEY: [u8; 32] = [4; 32];
    const RELAY_PRIVATE_KEY: [u8; 32] = [5; 32];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        AcquireAuthority,
        AcquireRequester,
        TrustedTime,
        LoadAuthority,
        PersistAuthority(u64),
        RetrieveManifest,
        LoadRequester,
        PersistRequester(u64),
        RetrieveRoutes,
        Callback,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestBackendError {
        MissingAuthority,
        MissingRequester,
        Manifest,
        Routes,
        AuthorityCas,
        RequesterCas,
    }

    impl fmt::Display for TestBackendError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::MissingAuthority => formatter.write_str("initialized authority is missing"),
                Self::MissingRequester => formatter.write_str("initialized requester is missing"),
                Self::Manifest => formatter.write_str("manifest retrieval failed"),
                Self::Routes => formatter.write_str("route retrieval failed"),
                Self::AuthorityCas => formatter.write_str("authority CAS failed"),
                Self::RequesterCas => formatter.write_str("requester CAS failed"),
            }
        }
    }

    impl Error for TestBackendError {}

    #[derive(Debug)]
    struct AuthorityGuard {
        key: AuthorityLeaseKey,
        fence: Rc<Cell<u64>>,
        held: Rc<Cell<bool>>,
        checks: Rc<Cell<u64>>,
    }

    impl FencedLeaseGuard<AuthorityLeaseKey> for AuthorityGuard {
        fn key(&self) -> &AuthorityLeaseKey {
            &self.key
        }

        fn fencing_token(&self) -> FencingToken {
            FencingToken::new(self.fence.get()).expect("nonzero authority fence")
        }

        fn ensure_held(&self) -> Result<(), LeaseError> {
            self.checks.set(self.checks.get().saturating_add(1));
            self.held.get().then_some(()).ok_or(LeaseError::Lost)
        }
    }

    #[derive(Debug)]
    struct RequesterGuard {
        key: NamedRouteV3RequesterLeaseKey,
        fence: Rc<Cell<u64>>,
        held: Rc<Cell<bool>>,
        checks: Rc<Cell<u64>>,
    }

    impl FencedLeaseGuard<NamedRouteV3RequesterLeaseKey> for RequesterGuard {
        fn key(&self) -> &NamedRouteV3RequesterLeaseKey {
            &self.key
        }

        fn fencing_token(&self) -> FencingToken {
            FencingToken::new(self.fence.get()).expect("nonzero requester fence")
        }

        fn ensure_held(&self) -> Result<(), LeaseError> {
            self.checks.set(self.checks.get().saturating_add(1));
            self.held.get().then_some(()).ok_or(LeaseError::Lost)
        }
    }

    #[derive(Default)]
    struct DurableLineage {
        initialized: bool,
        encoded: Option<Vec<u8>>,
        minimum_revision: u64,
    }

    struct TestBackend {
        authority_protection: RollbackProtectionClass,
        requester_protection: RollbackProtectionClass,
        events: Rc<RefCell<Vec<Event>>>,
        trusted_now: Cell<u64>,
        authority_held: Rc<Cell<bool>>,
        requester_held: Rc<Cell<bool>>,
        authority_fence: Rc<Cell<u64>>,
        requester_fence: Rc<Cell<u64>>,
        authority_checks: Rc<Cell<u64>>,
        requester_checks: Rc<Cell<u64>>,
        authority_durable: RefCell<DurableLineage>,
        requester_durable: RefCell<DurableLineage>,
        fail_next_requester_persist: Cell<bool>,
        manifests: RefCell<VecDeque<Result<ResolvedManifest, TestBackendError>>>,
        routes: RefCell<VecDeque<Result<Vec<Vec<u8>>, TestBackendError>>>,
    }

    impl TestBackend {
        fn new(
            manifests: impl IntoIterator<Item = Result<ResolvedManifest, TestBackendError>>,
            routes: impl IntoIterator<Item = Result<Vec<Vec<u8>>, TestBackendError>>,
        ) -> Self {
            Self {
                authority_protection: RollbackProtectionClass::IndependentLocalRoot,
                requester_protection: RollbackProtectionClass::IndependentLocalRoot,
                events: Rc::new(RefCell::new(Vec::new())),
                trusted_now: Cell::new(NOW),
                authority_held: Rc::new(Cell::new(true)),
                requester_held: Rc::new(Cell::new(true)),
                authority_fence: Rc::new(Cell::new(11)),
                requester_fence: Rc::new(Cell::new(29)),
                authority_checks: Rc::new(Cell::new(0)),
                requester_checks: Rc::new(Cell::new(0)),
                authority_durable: RefCell::new(DurableLineage::default()),
                requester_durable: RefCell::new(DurableLineage::default()),
                fail_next_requester_persist: Cell::new(false),
                manifests: RefCell::new(manifests.into_iter().collect()),
                routes: RefCell::new(routes.into_iter().collect()),
            }
        }

        fn authority_namespace() -> StorageNamespaceId {
            StorageNamespaceId::new(AUTHORITY_NAMESPACE).expect("authority namespace")
        }

        fn requester_namespace() -> StorageNamespaceId {
            StorageNamespaceId::new(REQUESTER_NAMESPACE).expect("requester namespace")
        }

        fn verify_authority_expectation(
            &self,
            expectation: NamedServiceAuthorityExpectation,
            durable: &DurableLineage,
        ) -> Result<(), TestBackendError> {
            if expectation.storage_namespace_id() != Self::authority_namespace()
                || expectation.fencing_token().get() != self.authority_fence.get()
            {
                return Err(TestBackendError::AuthorityCas);
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
                    let encoded = durable
                        .encoded
                        .as_deref()
                        .ok_or(TestBackendError::AuthorityCas)?;
                    let current = NamedServiceAuthoritySnapshot::decode(encoded)
                        .map_err(|_| TestBackendError::AuthorityCas)?;
                    if current.revision() == revision
                        && current
                            .fingerprint()
                            .map_err(|_| TestBackendError::AuthorityCas)?
                            == fingerprint
                    {
                        Ok(())
                    } else {
                        Err(TestBackendError::AuthorityCas)
                    }
                }
                NamedServiceAuthorityExpectation::Absent { .. } => {
                    Err(TestBackendError::AuthorityCas)
                }
            }
        }

        fn verify_requester_expectation(
            &self,
            expectation: NamedRouteV3RequesterExpectation,
            durable: &DurableLineage,
        ) -> Result<(), TestBackendError> {
            if expectation.storage_namespace_id() != Self::requester_namespace()
                || expectation.fencing_token().get() != self.requester_fence.get()
            {
                return Err(TestBackendError::RequesterCas);
            }
            match expectation {
                NamedRouteV3RequesterExpectation::Absent { .. }
                    if !durable.initialized && durable.encoded.is_none() =>
                {
                    Ok(())
                }
                NamedRouteV3RequesterExpectation::Exact {
                    revision,
                    fingerprint,
                    ..
                } => {
                    let encoded = durable
                        .encoded
                        .as_deref()
                        .ok_or(TestBackendError::RequesterCas)?;
                    let current = NamedRouteV3RequesterSnapshot::decode(encoded)
                        .map_err(|_| TestBackendError::RequesterCas)?;
                    if current.revision() == revision && current.fingerprint() == fingerprint {
                        Ok(())
                    } else {
                        Err(TestBackendError::RequesterCas)
                    }
                }
                NamedRouteV3RequesterExpectation::Absent { .. } => {
                    Err(TestBackendError::RequesterCas)
                }
            }
        }
    }

    impl HrmHnsaAuthorityBackend for TestBackend {
        type Error = TestBackendError;
        type AuthorityLease = AuthorityGuard;

        fn rollback_protection(&self) -> RollbackProtectionClass {
            self.authority_protection
        }

        fn acquire_authority_lease(
            &self,
            key: &AuthorityLeaseKey,
        ) -> Result<Self::AuthorityLease, Self::Error> {
            self.events.borrow_mut().push(Event::AcquireAuthority);
            Ok(AuthorityGuard {
                key: *key,
                fence: Rc::clone(&self.authority_fence),
                held: Rc::clone(&self.authority_held),
                checks: Rc::clone(&self.authority_checks),
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
            self.events.borrow_mut().push(Event::LoadAuthority);
            let durable = self.authority_durable.borrow();
            match (&durable.encoded, durable.initialized) {
                (None, false) => Ok(NamedServiceAuthorityStorageState::Absent),
                (Some(encoded), true) => Ok(NamedServiceAuthorityStorageState::Present {
                    encoded: encoded.clone(),
                    minimum_revision: durable.minimum_revision,
                }),
                _ => Err(TestBackendError::MissingAuthority),
            }
        }

        fn persist_authority_state(
            &self,
            expectation: NamedServiceAuthorityExpectation,
            snapshot: &NamedServiceAuthoritySnapshot,
        ) -> Result<(), Self::Error> {
            self.events
                .borrow_mut()
                .push(Event::PersistAuthority(snapshot.revision()));
            let mut durable = self.authority_durable.borrow_mut();
            self.verify_authority_expectation(expectation, &durable)?;
            durable.encoded = Some(
                snapshot
                    .encode()
                    .map_err(|_| TestBackendError::AuthorityCas)?,
            );
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
                .map_err(|_| TestBackendError::Manifest)?;
            if identity != &identity_value() || trusted_now != self.trusted_now.get() {
                return Err(TestBackendError::Manifest);
            }
            self.events.borrow_mut().push(Event::RetrieveManifest);
            self.manifests
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(TestBackendError::Manifest))
        }
    }

    impl HrmHnsaHnsrRequesterBackend for TestBackend {
        type RequesterLease = RequesterGuard;

        fn requester_rollback_protection(&self) -> RollbackProtectionClass {
            self.requester_protection
        }

        fn acquire_requester_lease(
            &self,
            key: &NamedRouteV3RequesterLeaseKey,
        ) -> Result<Self::RequesterLease, Self::Error> {
            self.events.borrow_mut().push(Event::AcquireRequester);
            Ok(RequesterGuard {
                key: *key,
                fence: Rc::clone(&self.requester_fence),
                held: Rc::clone(&self.requester_held),
                checks: Rc::clone(&self.requester_checks),
            })
        }

        fn load_requester_state(
            &self,
            lease: &NamedRouteV3OperationLeaseWitness<'_>,
        ) -> Result<NamedRouteV3RequesterStorageState, Self::Error> {
            lease.ensure_held().map_err(|_| TestBackendError::Routes)?;
            self.events.borrow_mut().push(Event::LoadRequester);
            let durable = self.requester_durable.borrow();
            match (&durable.encoded, durable.initialized) {
                (None, false) => Ok(NamedRouteV3RequesterStorageState::Absent),
                (Some(encoded), true) => Ok(NamedRouteV3RequesterStorageState::Present {
                    encoded: encoded.clone(),
                    minimum_revision: durable.minimum_revision,
                }),
                _ => Err(TestBackendError::MissingRequester),
            }
        }

        fn persist_requester_state(
            &self,
            expectation: NamedRouteV3RequesterExpectation,
            snapshot: &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), Self::Error> {
            self.events
                .borrow_mut()
                .push(Event::PersistRequester(snapshot.revision()));
            if self.fail_next_requester_persist.replace(false) {
                return Err(TestBackendError::RequesterCas);
            }
            let mut durable = self.requester_durable.borrow_mut();
            self.verify_requester_expectation(expectation, &durable)?;
            durable.encoded = Some(snapshot.encode());
            durable.initialized = true;
            durable.minimum_revision = durable.minimum_revision.max(snapshot.revision());
            Ok(())
        }

        fn retrieve_complete_raw_route_batch(
            &self,
            lease: &NamedRouteV3OperationLeaseWitness<'_>,
            route_key: &[u8; 32],
            trusted_now: u64,
        ) -> Result<Vec<Vec<u8>>, Self::Error> {
            lease.ensure_held().map_err(|_| TestBackendError::Routes)?;
            if route_key != &named_route_key_v3(&identity_value()).expect("deterministic route key")
                || trusted_now != self.trusted_now.get()
            {
                return Err(TestBackendError::Routes);
            }
            self.events.borrow_mut().push(Event::RetrieveRoutes);
            self.routes
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(TestBackendError::Routes))
        }
    }

    fn identity_value() -> NamedServiceIdentity {
        NamedServiceIdentity::new(NETWORK_MAGIC, SUBJECT, "wallet", PROFILE_ID)
            .expect("test identity")
    }

    fn authority_policy() -> NamedServicePolicy {
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

    fn route_policy() -> HrmNamedRoutePolicy {
        HrmNamedRoutePolicy {
            maximum_route_lifetime: 900,
            allowed_service_flags: 0,
            required_service_flags: 0,
            expected_service_constraints_hash: [0; 32],
            allowed_endpoint_capabilities: 1,
            required_endpoint_capabilities: 1,
            expected_endpoint_constraints_hash: [0; 32],
            allow_private_relays: true,
        }
    }

    fn authority_config() -> HrmHnsaAuthorityBrokerConfig {
        HrmHnsaAuthorityBrokerConfig::new(
            AUTHORITY_NAMESPACE,
            4,
            4,
            ValidationLimits::default(),
            RollbackProtectionClass::IndependentLocalRoot,
        )
        .expect("authority config")
    }

    fn combined_config() -> HrmHnsaHnsrRequesterBrokerConfig {
        HrmHnsaHnsrRequesterBrokerConfig::new(
            authority_config(),
            REQUESTER_NAMESPACE,
            NETWORK_MAGIC,
            16,
            RollbackProtectionClass::IndependentLocalRoot,
        )
        .expect("combined config")
    }

    fn resolved_manifest(sequence: u64, active: bool) -> ResolvedManifest {
        let hrm_private_key = [1; 32];
        let controller = Controller::secp256k1(
            hrm_public_key(&hrm_private_key).expect("HRM controller public key"),
        )
        .expect("HRM controller");
        let identity = identity_value();
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
                hrm_public_key(&SERVICE_PRIVATE_KEY).expect("service public key"),
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
                chain_height: 100 + u32::try_from(sequence).expect("test height"),
                chain_work,
                chain_anchor: [u8::try_from(sequence).expect("test anchor"); 32],
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

    fn verified_service() -> VerifiedNamedService {
        let manifest = validate_current_manifest(
            resolved_manifest(1, true),
            NETWORK_MAGIC,
            SUBJECT,
            NOW,
            ValidationLimits::default(),
            &RollbackObservations::new(),
        )
        .expect("validated manifest");
        observe_named_service(&manifest, &identity_value(), &authority_policy(), None)
            .expect("named service observation")
            .into_active()
            .expect("active named service")
    }

    fn signed_route(route_sequence: u64) -> NamedRouteRecordV3 {
        let service = verified_service();
        let endpoint_key = public_key(&ENDPOINT_PRIVATE_KEY).expect("endpoint public key");
        let relay_key = public_key(&RELAY_PRIVATE_KEY).expect("relay public key");
        let mut endpoint = EndpointDelegationV1 {
            version: hns_service_authority::hrm::VERSION,
            network_magic: NETWORK_MAGIC,
            service_resource_id: service.resource_id(),
            service_delegation_id: service.delegation_id(),
            service_generation: service.service_generation(),
            endpoint_key,
            endpoint_sequence: 1,
            issued_at: NOW - 10,
            expires_at: NOW + 700,
            capabilities: 1,
            constraints_hash: [0; 32],
            service_signature: Vec::new(),
        };
        endpoint
            .sign_uncommitted(&service, NOW, &SERVICE_PRIVATE_KEY)
            .expect("signed endpoint delegation");
        let mut ticket = RelayTicket {
            network_magic: NETWORK_MAGIC,
            profile: PROFILE_ID,
            transport: 0,
            host_type: 1,
            host: [0; 16],
            port: 12_038,
            relay_key,
            endpoint_key,
            reservation_id: [6; 16],
            issued_at: NOW - 10,
            expires_at: NOW + 600,
            max_active_circuits: 1,
            max_bytes_per_circuit: 1_024,
            max_total_bytes: 4_096,
            flags: 0,
            relay_signature: Vec::new(),
            endpoint_signature: Vec::new(),
        };
        ticket
            .sign_relay(&RELAY_PRIVATE_KEY)
            .expect("relay signature");
        ticket
            .sign_endpoint(&ENDPOINT_PRIVATE_KEY)
            .expect("endpoint ticket confirmation");
        let mut route = NamedRouteRecordV3 {
            route_key: named_route_key_v3(service.identity()).expect("route key"),
            profile_id: PROFILE_ID,
            record_sequence: route_sequence,
            issued_at: NOW - 5,
            expires_at: NOW + 500,
            service_resource_id: service.resource_id(),
            service_delegation_id: service.delegation_id(),
            service_generation: service.service_generation(),
            service_controller_key: service.service_controller_key(),
            endpoint_delegation: endpoint,
            tickets: vec![ticket],
            endpoint_signature: Vec::new(),
        };
        route.sign(&ENDPOINT_PRIVATE_KEY).expect("route signature");
        route
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

    fn encoded_routes(sequences: &[u64]) -> Vec<Vec<u8>> {
        sequences
            .iter()
            .map(|sequence| {
                signed_route(*sequence)
                    .encode()
                    .expect("canonical signed route")
            })
            .collect()
    }

    #[test]
    fn orders_dual_leases_both_durable_lineages_and_complete_batch_before_callback() {
        let backend = TestBackend::new(
            [Ok(resolved_manifest(1, true))],
            [Ok(encoded_routes(&[2, 1]))],
        );
        let events = Rc::clone(&backend.events);
        let endpoint_key = signed_route(1).endpoint_delegation.endpoint_key;
        let mut broker =
            HrmHnsaHnsrRequesterBroker::new(combined_config(), backend).expect("broker");
        let selected = broker
            .with_current_named_route(
                &identity_value(),
                &authority_policy(),
                &endpoint_key,
                route_policy(),
                |current| {
                    events.borrow_mut().push(Event::Callback);
                    assert_eq!(current.route_sequence(), 2);
                    assert_eq!(current.endpoint_sequence(), 1);
                    assert_eq!(current.authority_revision(), 1);
                    assert_eq!(current.requester_revision(), 1);
                    assert_eq!(current.authority_trusted_time(), NOW);
                    Ok::<_, Infallible>(current.cache_until())
                },
            )
            .expect("current named route");
        assert_eq!(selected, NOW + 500);
        assert!(broker.requester_loaded());
        assert_eq!(broker.live_authority_subjects(), 1);

        let events = events.borrow();
        assert_eq!(events[0], Event::AcquireAuthority);
        assert_eq!(events[1], Event::AcquireRequester);
        let manifest_retrieval = events
            .iter()
            .position(|event| *event == Event::RetrieveManifest)
            .expect("manifest retrieval");
        let route_retrieval = events
            .iter()
            .position(|event| *event == Event::RetrieveRoutes)
            .expect("route retrieval");
        let callback = events
            .iter()
            .position(|event| *event == Event::Callback)
            .expect("callback");
        assert!(
            events[..manifest_retrieval]
                .iter()
                .any(|event| matches!(event, Event::PersistAuthority(_)))
        );
        assert!(
            events[..route_retrieval]
                .iter()
                .any(|event| matches!(event, Event::PersistAuthority(1)))
        );
        assert!(
            events[..route_retrieval]
                .iter()
                .any(|event| matches!(event, Event::PersistRequester(0)))
        );
        assert!(
            events[route_retrieval..callback]
                .iter()
                .any(|event| matches!(event, Event::PersistRequester(1)))
        );
    }

    #[test]
    fn failed_requester_cas_stays_pending_and_retries_before_route_retrieval() {
        let backend = TestBackend::new(
            [
                Ok(resolved_manifest(1, true)),
                Ok(resolved_manifest(1, true)),
            ],
            [Ok(encoded_routes(&[1]))],
        );
        backend.fail_next_requester_persist.set(true);
        let events = Rc::clone(&backend.events);
        let endpoint_key = signed_route(1).endpoint_delegation.endpoint_key;
        let mut broker =
            HrmHnsaHnsrRequesterBroker::new(combined_config(), backend).expect("broker");
        let first = broker.with_current_named_route(
            &identity_value(),
            &authority_policy(),
            &endpoint_key,
            route_policy(),
            |_| Ok::<_, Infallible>(()),
        );
        assert!(matches!(
            first,
            Err(HrmHnsaHnsrRequesterBrokerError::Backend(
                TestBackendError::RequesterCas
            ))
        ));
        assert!(broker.requester_loaded());
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|event| **event == Event::RetrieveRoutes)
                .count(),
            0
        );

        broker
            .with_current_named_route(
                &identity_value(),
                &authority_policy(),
                &endpoint_key,
                route_policy(),
                |_| Ok::<_, Infallible>(()),
            )
            .expect("exact pending retry then route");
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|event| **event == Event::RetrieveRoutes)
                .count(),
            1
        );
        assert_eq!(
            broker.backend().requester_durable.borrow().minimum_revision,
            1
        );
    }

    #[test]
    fn withdrawal_advances_both_times_and_never_releases_a_route_callback() {
        let backend = TestBackend::new(
            [
                Ok(resolved_manifest(1, true)),
                Ok(resolved_manifest(2, false)),
            ],
            [Ok(encoded_routes(&[1])), Ok(Vec::new())],
        );
        let endpoint_key = signed_route(1).endpoint_delegation.endpoint_key;
        let mut broker =
            HrmHnsaHnsrRequesterBroker::new(combined_config(), backend).expect("broker");
        broker
            .with_current_named_route(
                &identity_value(),
                &authority_policy(),
                &endpoint_key,
                route_policy(),
                |_| Ok::<_, Infallible>(()),
            )
            .expect("initial current route");
        broker.backend().trusted_now.set(NOW + 10);
        let callback_called = Cell::new(false);
        let withdrawn = broker.with_current_named_route(
            &identity_value(),
            &authority_policy(),
            &endpoint_key,
            route_policy(),
            |_| {
                callback_called.set(true);
                Ok::<_, Infallible>(())
            },
        );
        assert!(matches!(
            withdrawn,
            Err(HrmHnsaHnsrRequesterBrokerError::Requester(_))
        ));
        assert!(!callback_called.get());
        let authority = NamedServiceAuthoritySnapshot::decode(
            broker
                .backend()
                .authority_durable
                .borrow()
                .encoded
                .as_deref()
                .expect("authority snapshot"),
        )
        .expect("decoded authority snapshot");
        let requester = NamedRouteV3RequesterSnapshot::decode(
            broker
                .backend()
                .requester_durable
                .borrow()
                .encoded
                .as_deref()
                .expect("requester snapshot"),
        )
        .expect("decoded requester snapshot");
        assert_eq!(authority.trusted_time_high_water(), NOW + 10);
        assert_eq!(requester.trusted_time_high_water(), NOW + 10);
    }

    #[test]
    fn requester_lease_loss_suppresses_the_callback_result() {
        let backend =
            TestBackend::new([Ok(resolved_manifest(1, true))], [Ok(encoded_routes(&[1]))]);
        let requester_held = Rc::clone(&backend.requester_held);
        let endpoint_key = signed_route(1).endpoint_delegation.endpoint_key;
        let mut broker =
            HrmHnsaHnsrRequesterBroker::new(combined_config(), backend).expect("broker");
        let callback_called = Cell::new(false);
        let result = broker.with_current_named_route(
            &identity_value(),
            &authority_policy(),
            &endpoint_key,
            route_policy(),
            |_| {
                callback_called.set(true);
                requester_held.set(false);
                Ok::<_, Infallible>(42_u64)
            },
        );
        assert!(callback_called.get());
        assert!(matches!(
            result,
            Err(HrmHnsaHnsrRequesterBrokerError::Lease(LeaseError::Lost))
        ));
    }

    #[test]
    fn initialized_requester_absence_fails_closed_before_retrieval() {
        let backend =
            TestBackend::new([Ok(resolved_manifest(1, true))], [Ok(encoded_routes(&[1]))]);
        backend.requester_durable.borrow_mut().initialized = true;
        let events = Rc::clone(&backend.events);
        let endpoint_key = signed_route(1).endpoint_delegation.endpoint_key;
        let mut broker =
            HrmHnsaHnsrRequesterBroker::new(combined_config(), backend).expect("broker");
        let result = broker.with_current_named_route(
            &identity_value(),
            &authority_policy(),
            &endpoint_key,
            route_policy(),
            |_| Ok::<_, Infallible>(()),
        );
        assert!(matches!(
            result,
            Err(HrmHnsaHnsrRequesterBrokerError::Backend(
                TestBackendError::MissingRequester
            ))
        ));
        assert!(!events.borrow().contains(&Event::RetrieveRoutes));
    }

    #[test]
    fn panic_runs_both_release_checks_and_configuration_rejects_shared_lineages() {
        let backend =
            TestBackend::new([Ok(resolved_manifest(1, true))], [Ok(encoded_routes(&[1]))]);
        let authority_checks = Rc::clone(&backend.authority_checks);
        let requester_checks = Rc::clone(&backend.requester_checks);
        let endpoint_key = signed_route(1).endpoint_delegation.endpoint_key;
        let mut broker =
            HrmHnsaHnsrRequesterBroker::new(combined_config(), backend).expect("broker");
        let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _: Result<(), HrmHnsaHnsrRequesterBrokerError<TestBackendError, Infallible>> =
                broker.with_current_named_route(
                    &identity_value(),
                    &authority_policy(),
                    &endpoint_key,
                    route_policy(),
                    |_| panic!("dependent operation panic"),
                );
        }));
        assert!(panic.is_err());
        assert!(authority_checks.get() >= 10);
        assert!(requester_checks.get() >= 8);
        assert!(broker.requester_loaded());

        assert!(matches!(
            HrmHnsaHnsrRequesterBrokerConfig::new(
                authority_config(),
                AUTHORITY_NAMESPACE,
                NETWORK_MAGIC,
                16,
                RollbackProtectionClass::IndependentLocalRoot,
            ),
            Err(HrmHnsaHnsrRequesterBrokerConfigError::SharedStorageNamespace)
        ));
        assert!(matches!(
            HrmHnsaHnsrRequesterBrokerConfig::new(
                authority_config(),
                REQUESTER_NAMESPACE,
                NETWORK_MAGIC,
                0,
                RollbackProtectionClass::IndependentLocalRoot,
            ),
            Err(HrmHnsaHnsrRequesterBrokerConfigError::InvalidRequesterEntryCapacity)
        ));
    }
}
