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

mod hnsa_route;
mod hnsr_transport;
mod hrm_hnsa_broker;
mod private_transport;

mod authority_sealed {
    pub trait Sealed {}
}

pub use hns_hnsr_protocol::{
    DEFAULT_WINDOW, HNS_CHAT_V1, HNS_NODE_V1, HNS_WEB_V1, HnsrActionId, HnsrPacket, HnsrPeerId,
    HnsrRequesterConfig, HnsrRequesterEvent, HnsrRoute, HnsrRuntimeStatus, NamedRoutePolicy,
    OpaqueRelayConfig, QueuedHnsrRoute, RelayConfig, RelayLimits, RelayTicket,
};
pub use hnsa_route::{
    HnsaNamedRouteContext, HnsaNamedRouteRequest, HnsaNamedRouteState, HnsaRelayEndpoint,
    HnsaRouteError, MAX_HNSA_NAMED_ROUTE_ENDPOINTS, MAX_HNSA_NAMED_ROUTE_STATE_BYTES,
    SelectedHnsaNamedRoute,
};
pub use hnsr_transport::{
    AuthenticatedHnsrPeer, HNSR_TRANSPORT_SCHEMA_VERSION, HnsrOpaqueRelayRuntime,
    HnsrRequesterRuntime, HnsrRuntimeExport, HnsrTransportAuthorityContext, HnsrTransportBinding,
    HnsrTransportError, HnsrTransportRevocationReason, HnsrTransportRole, HnsrTransportState,
    HnsrTransportStatus, MAX_HNSR_RUNTIME_SNAPSHOT_BYTES,
};
pub use hrm_hnsa_broker::{
    AuthorityLeaseKey, AuthorityLeaseWitness, CurrentCommittedNamedService,
    DEFAULT_HRM_HNSA_AUTHORITY_ENTRIES, DEFAULT_HRM_HNSA_LIVE_SUBJECTS, FencedLeaseGuard,
    FencingToken, HrmHnsaAuthorityBackend, HrmHnsaAuthorityBroker, HrmHnsaAuthorityBrokerConfig,
    HrmHnsaAuthorityBrokerConfigError, HrmHnsaAuthorityBrokerError, MAX_HRM_HNSA_LIVE_SUBJECTS,
    NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot,
    NamedServiceAuthorityStorageState, NamedServiceIdentity, NamedServicePolicy, ResolvedManifest,
    RollbackProtectionClass, StorageNamespaceId, ValidationLimits,
};

pub use private_transport::{
    MAX_CACHED_ODOH_TARGETS, MAX_ODOH_TARGET_CACHE_BLOB_BYTES,
    MAX_PERSISTED_ODOH_TARGET_RECORD_BYTES, OdohRequesterRuntime, OdohRequesterState,
    OdohRequesterStatus, OdohTargetCacheExport, OdohTargetInstall,
    PRIVATE_TRANSPORT_SCHEMA_VERSION, PrivateTransportAuthority, PrivateTransportAuthorityContext,
    PrivateTransportBinding, PrivateTransportError, PrivateTransportRevocationReason,
};

use std::fmt;
use std::sync::RwLock;

use hns_browser_observability::{
    BrowserStatus, DegradedReason, IcannDnssecStatus, IcannTlsAction, OutcomeKind,
    ProviderReadiness, RateLimitState, RevocationReason, RootFailureKind, SelectionReason,
    StatusError, StatusInput, TransportIdentities, UnsupportedEvidence,
};
pub use hns_browser_runtime::{AuthorityState, BrowserRuntime, RuntimeSessionId};
use hns_browser_runtime::{RuntimeError, RuntimeStamp};
use hns_dane::{DaneLimits, DaneMatch, verify_dane_chain, verify_dane_ee};
use hns_dns_wire::{Message, ParseLimits, Query, Rdata, RecordType, Tlsa};
pub use hns_gateway::{Gateway, GatewayLimits, GatewaySelection};
use hns_namespace_resolution::{EvidenceProvenance, ServiceTransport, decision_fingerprint};
pub use hns_namespace_resolution::{
    HnsNetwork, Namespace, NamespaceDecision, OriginScheme, TlsTrustPolicy,
};
pub use hns_p2p_transport::{
    AdapterFailure, AdmittedDnsResponse, AuthenticatedPeer, DENUO_EXTENSION_SERVICE,
    DirectTargetLocator, DnsRelayRequester, ExperimentalExchange, ExperimentalNetwork,
    ExperimentalPeerState, ExperimentalRequest, ExperimentalResponse, ExperimentalWireProfile,
    FetchedOdohTargetConfig, NegotiatedRegistry, ODOH_SERVICE, OdohRequester, P2pTransportError,
    PeerIdentity, PeerProtocolError, ProtocolRange, RegistryHello, RequesterLimits, ServiceMask,
    VerifiedOdohTarget,
};
use hns_resolution_policy::{
    Admission, ChainAnchor, EvidenceState, Network, PolicyConfig, PolicyController, PolicyError,
    PolicySnapshot, PolicyTransition, ResolutionProvenance, ResolutionTransport, TransportPlan,
    ValidationEvidence, WireProfile,
};
use hns_resolver::ValidatedTlsa;

/// Stable Rust facade API version.
pub const ENGINE_API_VERSION: u32 = 3;
/// Maximum UTF-8 bytes accepted for one transport identity.
pub const MAX_TRANSPORT_IDENTITY_BYTES: usize = 256;

/// Engine construction configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineConfig {
    /// Checked caller-generated runtime session ID.
    pub runtime_session: RuntimeSessionId,
    /// Handshake network.
    pub network: Network,
    /// Persisted policy snapshot.
    pub policy: PolicySnapshot,
}

impl EngineConfig {
    /// Construct a configuration from an already checked runtime session.
    #[must_use]
    pub const fn new(
        runtime_session: RuntimeSessionId,
        network: Network,
        policy: PolicySnapshot,
    ) -> Self {
        Self {
            runtime_session,
            network,
            policy,
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

impl EngineSnapshot {
    /// Canonical Handshake network identity for cross-crate authority binding.
    #[must_use]
    pub const fn hns_network(self) -> HnsNetwork {
        match self.network {
            Network::Mainnet => HnsNetwork::Mainnet,
            Network::Testnet => HnsNetwork::Testnet,
            Network::Regtest => HnsNetwork::Regtest,
            Network::Simnet => HnsNetwork::Simnet,
        }
    }
}

/// Exact URL origin whose namespace decision is being authorized.
///
/// This value is derived from [`NamespaceDecision::query`]. It deliberately
/// retains the URL-origin port, not an HTTPS/SVCB-selected backend port: two
/// pages have the same logical authority only when scheme, canonical host,
/// and URL port all match.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalOrigin {
    scheme: OriginScheme,
    host: String,
    port: u16,
}

impl LogicalOrigin {
    /// Derive an exact logical origin from an authoritative decision query.
    #[must_use]
    pub fn from_namespace_decision(decision: &NamespaceDecision) -> Self {
        let query = decision.query();
        Self {
            scheme: query.scheme(),
            host: query.host().as_str().to_owned(),
            port: query.origin_port().get(),
        }
    }

    /// URL scheme selected by the platform parser.
    #[must_use]
    pub const fn scheme(&self) -> OriginScheme {
        self.scheme
    }

    /// Canonical lower-case ASCII DNS host without a root dot.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Effective URL-origin port (explicit or the scheme default).
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Whether the origin uses a TLS-protected URL scheme.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.scheme.uses_tls()
    }
}

/// Authentication path bound to an origin context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthenticatedContextStatus {
    /// No successful TLS authentication was supplied.
    Unauthenticated = 0,
    /// The selected HNS origin was verified with current DANE evidence.
    HnsDaneVerified = 1,
    /// The selected ICANN origin was verified with DNSSEC-backed DANE.
    IcannDaneVerified = 2,
    /// ICANN TLSA absence was authenticated before successful WebPKI.
    IcannWebPkiAuthenticatedAbsence = 3,
    /// ICANN delegation insecurity was proven before successful WebPKI.
    IcannWebPkiInsecureDelegation = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IcannTlsAuthenticationKind {
    DaneVerified,
    WebPkiVerified,
}

/// Exact decision-bound request presented to the trusted ICANN TLS adapter.
///
/// Fields are private so the adapter must inspect the engine-derived logical
/// origin and decision identity rather than accepting page-supplied fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcannOriginAuthenticationRequest {
    logical_origin: LogicalOrigin,
    service_port: u16,
    decision_fingerprint: [u8; 32],
    hns_network: HnsNetwork,
    tls_policy: TlsTrustPolicy,
    valid_until: u64,
    runtime_stamp: RuntimeStamp,
    policy_generation: u64,
}

impl IcannOriginAuthenticationRequest {
    /// Exact HTTPS logical origin whose platform TLS result is requested.
    #[must_use]
    pub const fn logical_origin(&self) -> &LogicalOrigin {
        &self.logical_origin
    }

    /// Exact effective TCP service port selected by the ICANN plan.
    #[must_use]
    pub const fn service_port(&self) -> u16 {
        self.service_port
    }

    /// Complete query/policy/outcome identity being authenticated.
    #[must_use]
    pub const fn decision_fingerprint(&self) -> [u8; 32] {
        self.decision_fingerprint
    }

    /// HNS network retained by the dual-root decision.
    #[must_use]
    pub const fn hns_network(&self) -> HnsNetwork {
        self.hns_network
    }

    /// Exact TLS policy selected by the ICANN plan.
    #[must_use]
    pub const fn tls_policy(&self) -> TlsTrustPolicy {
        self.tls_policy
    }

    /// Exclusive expiry of the complete dual-root decision.
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }

    /// Mint an opaque token after locally verifying ICANN DANE.
    ///
    /// This method is a trusted-adapter boundary. Calling it asserts that the
    /// embedding browser verified the exact request against local TLS state.
    #[must_use]
    pub fn attest_dane_verified(&self) -> IcannOriginAuthentication {
        IcannOriginAuthentication {
            request: self.clone(),
            kind: IcannTlsAuthenticationKind::DaneVerified,
        }
    }

    /// Mint an opaque token after locally verifying ICANN WebPKI.
    ///
    /// This method is a trusted-adapter boundary. Calling it asserts that the
    /// embedding browser verified the exact request against local TLS state.
    #[must_use]
    pub fn attest_webpki_verified(&self) -> IcannOriginAuthentication {
        IcannOriginAuthentication {
            request: self.clone(),
            kind: IcannTlsAuthenticationKind::WebPkiVerified,
        }
    }
}

/// Opaque exact-decision token minted by a trusted ICANN TLS adapter.
///
/// All fields are private. The engine accepts the token only for the identical
/// origin, selected service, complete decision fingerprint, network, policy,
/// expiry, runtime admission stamp, and policy generation.
pub struct IcannOriginAuthentication {
    request: IcannOriginAuthenticationRequest,
    kind: IcannTlsAuthenticationKind,
}

/// Trusted embedding-browser security principal for ICANN TLS authentication.
///
/// The engine invokes this callback with an exact decision-bound request and
/// immediately mints a private [`AuthenticatedOriginContext`]. A page must
/// never implement or influence this callback. Rust cannot isolate malicious
/// code in the same process; the adapter implementation is therefore an
/// explicit security principal and must consult the browser's local TLS state.
pub trait TrustedIcannOriginAuthenticator {
    /// Authenticate the exact request, or return `None` to deny it.
    fn authenticate(
        &self,
        request: &IcannOriginAuthenticationRequest,
    ) -> Option<IcannOriginAuthentication>;
}

impl<F> TrustedIcannOriginAuthenticator for F
where
    F: Fn(&IcannOriginAuthenticationRequest) -> Option<IcannOriginAuthentication>,
{
    fn authenticate(
        &self,
        request: &IcannOriginAuthenticationRequest,
    ) -> Option<IcannOriginAuthentication> {
        self(request)
    }
}

/// Authentication evidence atomically stamped to one namespace decision.
///
/// Fields are private so consumers cannot splice an authenticated status from
/// one origin or decision into another. The engine's three `bind_*_context`
/// methods are the only constructors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedOriginContext {
    logical_origin: LogicalOrigin,
    selected_namespace: Option<Namespace>,
    status: AuthenticatedContextStatus,
    runtime_session: [u8; 16],
    runtime_generation: u64,
    policy_generation: u64,
    event_sequence: u64,
    admission_stamp: Option<RuntimeStamp>,
    decision_fingerprint: [u8; 32],
    valid_from: u64,
    valid_until: u64,
}

impl AuthenticatedOriginContext {
    /// Exact logical origin authenticated by this context.
    #[must_use]
    pub const fn logical_origin(&self) -> &LogicalOrigin {
        &self.logical_origin
    }

    /// Namespace selected by the bound dual-root decision.
    #[must_use]
    pub const fn selected_namespace(&self) -> Option<Namespace> {
        self.selected_namespace
    }

    /// Exact authentication path, or `Unauthenticated`.
    #[must_use]
    pub const fn status(&self) -> AuthenticatedContextStatus {
        self.status
    }

    /// Runtime session that stamped this context.
    #[must_use]
    pub const fn runtime_session(&self) -> [u8; 16] {
        self.runtime_session
    }

    /// Runtime generation that stamped this context.
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    /// Policy generation that stamped this context.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Authority event sequence that stamped this context.
    #[must_use]
    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    /// Exact query/policy/outcome decision identity.
    #[must_use]
    pub const fn decision_fingerprint(&self) -> [u8; 32] {
        self.decision_fingerprint
    }

    /// First time at which the authentication may be consumed.
    #[must_use]
    pub const fn valid_from(&self) -> u64 {
        self.valid_from
    }

    /// Exclusive decision/authentication expiry bound.
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

/// Closed fail-closed reason for denying wallet-provider injection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ProviderInjectionDenialReason {
    /// Cleartext HTTP/WebSocket origins never receive a wallet provider.
    InsecureOrigin = 1,
    /// The authoritative dual-root result selected no usable namespace.
    NoSelectedNamespace = 2,
    /// No successful authentication is bound to the context.
    UnauthenticatedContext = 3,
    /// The context belongs to another logical origin.
    OriginMismatch = 4,
    /// The context belongs to another selected namespace.
    NamespaceMismatch = 5,
    /// The context belongs to another authoritative namespace decision.
    DecisionMismatch = 6,
    /// Namespace evidence is not fresh at the decision time.
    DecisionStale = 7,
    /// HNS evidence belongs to another configured network.
    NetworkMismatch = 8,
    /// The context belongs to another runtime session.
    StaleRuntimeSession = 9,
    /// The context belongs to an older runtime generation.
    StaleRuntimeGeneration = 10,
    /// The context belongs to an older policy generation.
    StalePolicyGeneration = 11,
    /// The authentication stamp predates a security-invalidating runtime event.
    StaleAuthenticationEvent = 12,
    /// Browser authority has not reached an injection-capable state.
    AuthorityNotReady = 13,
    /// Browser authority entered a recoverable degraded state.
    AuthorityDegraded = 14,
    /// Browser authority was explicitly revoked.
    AuthorityRevoked = 15,
    /// Browser authority was stopped.
    AuthorityStopped = 16,
    /// Authentication path conflicts with the selected plan's TLS policy.
    AuthenticationPolicyMismatch = 17,
    /// Authentication predates its validity interval.
    AuthenticationNotYetValid = 18,
    /// Authentication or decision evidence expired.
    AuthenticationExpired = 19,
    /// TLS-protected but non-HTTPS schemes are outside provider injection.
    UnsupportedOriginScheme = 20,
}

/// All-outcomes wallet-provider injection decision.
///
/// Consumers must inspect [`Self::permitted`] and must not infer permission
/// from authority state, namespace selection, or authentication alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderInjectionDecision {
    logical_origin: LogicalOrigin,
    selected_namespace: Option<Namespace>,
    authenticated_context: AuthenticatedContextStatus,
    runtime_session: [u8; 16],
    runtime_generation: u64,
    policy_generation: u64,
    event_sequence: u64,
    decision_fingerprint: [u8; 32],
    authority_state: AuthorityState,
    permitted: bool,
    denial_reason: Option<ProviderInjectionDenialReason>,
}

impl ProviderInjectionDecision {
    /// Exact URL origin evaluated for injection.
    #[must_use]
    pub const fn logical_origin(&self) -> &LogicalOrigin {
        &self.logical_origin
    }

    /// Namespace selected by the authoritative decision.
    #[must_use]
    pub const fn selected_namespace(&self) -> Option<Namespace> {
        self.selected_namespace
    }

    /// Authentication path presented for this decision.
    #[must_use]
    pub const fn authenticated_context(&self) -> AuthenticatedContextStatus {
        self.authenticated_context
    }

    /// Current browser-authority runtime session.
    #[must_use]
    pub const fn runtime_session(&self) -> [u8; 16] {
        self.runtime_session
    }

    /// Current browser-authority runtime generation.
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    /// Current policy generation.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Current browser-authority event sequence.
    #[must_use]
    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    /// Exact authoritative namespace-decision identity.
    #[must_use]
    pub const fn decision_fingerprint(&self) -> [u8; 32] {
        self.decision_fingerprint
    }

    /// Current browser authority state used for the atomic result.
    #[must_use]
    pub const fn authority_state(&self) -> AuthorityState {
        self.authority_state
    }

    /// Whether wallet-provider injection is permitted.
    #[must_use]
    pub const fn permitted(&self) -> bool {
        self.permitted
    }

    /// Closed denial reason; absent exactly when permission is granted.
    #[must_use]
    pub const fn denial_reason(&self) -> Option<ProviderInjectionDenialReason> {
        self.denial_reason
    }
}

/// Opaque, engine-issued authority for one exact provider-injection boundary.
///
/// The fields are private and the type is deliberately neither `Clone` nor
/// serializable. A trusted native browser integration may inspect its typed
/// bindings and move it into the provider host, but must never expose it to
/// page JavaScript or treat its fields as caller-provided policy. Use
/// [`Engine::revalidate_provider_authority`] to consume and replace it before a
/// navigation installs the provider and whenever navigation, namespace, or a
/// security-invalidating runtime/policy event may have advanced.
pub struct ProviderAuthorityContext {
    origin_context: AuthenticatedOriginContext,
    selected_namespace: Namespace,
    hns_network: HnsNetwork,
    service_port: u16,
    tls_policy: TlsTrustPolicy,
}

impl ProviderAuthorityContext {
    /// Exact HTTPS logical origin authorized for provider injection.
    #[must_use]
    pub const fn logical_origin(&self) -> &LogicalOrigin {
        self.origin_context.logical_origin()
    }

    /// Exact namespace selected for this authority.
    #[must_use]
    pub const fn selected_namespace(&self) -> Namespace {
        self.selected_namespace
    }

    /// Trusted authentication path admitted by the engine.
    #[must_use]
    pub const fn authenticated_context(&self) -> AuthenticatedContextStatus {
        self.origin_context.status()
    }

    /// Handshake network bound by the complete namespace decision.
    #[must_use]
    pub const fn hns_network(&self) -> HnsNetwork {
        self.hns_network
    }

    /// Exact TCP service port selected by the authoritative plan.
    #[must_use]
    pub const fn service_port(&self) -> u16 {
        self.service_port
    }

    /// Exact TLS policy admitted for the selected plan.
    #[must_use]
    pub const fn tls_policy(&self) -> TlsTrustPolicy {
        self.tls_policy
    }

    /// Browser-authority process session bound to this context.
    #[must_use]
    pub const fn runtime_session(&self) -> [u8; 16] {
        self.origin_context.runtime_session()
    }

    /// Browser-authority generation bound to this context.
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.origin_context.runtime_generation()
    }

    /// Persistent trust-policy generation bound to this context.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.origin_context.policy_generation()
    }

    /// Exact authority event bound to this context.
    #[must_use]
    pub const fn event_sequence(&self) -> u64 {
        self.origin_context.event_sequence()
    }

    /// Complete query, plan, root outcome, evidence, and policy identity.
    #[must_use]
    pub const fn decision_fingerprint(&self) -> [u8; 32] {
        self.origin_context.decision_fingerprint()
    }

    /// First time at which this authority may be consumed.
    #[must_use]
    pub const fn valid_from(&self) -> u64 {
        self.origin_context.valid_from()
    }

    /// Exclusive expiry of this authority.
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.origin_context.valid_until()
    }

    fn matches_decision(&self, decision: &NamespaceDecision) -> bool {
        let Some(plan) = decision.selected_plan() else {
            return false;
        };
        self.logical_origin() == &LogicalOrigin::from_namespace_decision(decision)
            && decision.selected_namespace() == Some(self.selected_namespace)
            && decision.hns_network() == self.hns_network
            && plan.service().transport() == ServiceTransport::Tcp
            && plan.service().effective_port().get() == self.service_port
            && plan.tls_policy() == self.tls_policy
            && *decision_fingerprint(decision).as_bytes() == self.decision_fingerprint()
    }
}

impl fmt::Debug for ProviderAuthorityContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAuthorityContext")
            .field("logical_origin", &"[redacted]")
            .field("selected_namespace", &self.selected_namespace)
            .field("authenticated_context", &self.authenticated_context())
            .field("hns_network", &self.hns_network)
            .field("service_port", &self.service_port)
            .field("tls_policy", &self.tls_policy)
            .field("runtime_session", &self.runtime_session())
            .field("runtime_generation", &self.runtime_generation())
            .field("policy_generation", &self.policy_generation())
            .field("event_sequence", &self.event_sequence())
            .field("decision_fingerprint", &"[redacted]")
            .field("valid_from", &self.valid_from())
            .field("valid_until", &self.valid_until())
            .finish_non_exhaustive()
    }
}

/// Typed result of requesting a provider authority from the engine.
///
/// Only `Authorized` carries a context usable by trusted browser code. A
/// denied result cannot be converted into an authority by inspecting its
/// status fields.
#[derive(Debug)]
#[must_use = "provider authority outcomes must be matched before injection"]
pub enum ProviderAuthorityOutcome {
    /// The engine minted an opaque authority for the exact current decision.
    Authorized(ProviderAuthorityContext),
    /// Injection was denied with the complete typed decision and reason.
    Denied(ProviderInjectionDecision),
}

impl ProviderAuthorityOutcome {
    /// Whether this outcome contains an engine-issued authority context.
    #[must_use]
    pub const fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorized(_))
    }

    /// Borrow the authority context, if injection was authorized.
    #[must_use]
    pub const fn context(&self) -> Option<&ProviderAuthorityContext> {
        match self {
            Self::Authorized(context) => Some(context),
            Self::Denied(_) => None,
        }
    }

    /// Borrow the typed denial, if injection was denied.
    #[must_use]
    pub const fn denial(&self) -> Option<&ProviderInjectionDecision> {
        match self {
            Self::Authorized(_) => None,
            Self::Denied(decision) => Some(decision),
        }
    }

    /// Consume an authorized outcome without reconstructing trust policy.
    pub fn into_context(self) -> Result<ProviderAuthorityContext, ProviderInjectionDecision> {
        match self {
            Self::Authorized(context) => Ok(context),
            Self::Denied(decision) => Err(decision),
        }
    }
}

/// Runtime-owned fields needed to produce shared status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservabilityRuntime {
    /// Exact canonical experimental registry fingerprint.
    pub registry_fingerprint: [u8; 32],
    /// Negotiated protocol/status version.
    pub protocol_version: u16,
    /// Provider readiness after socket/storage admission.
    pub provider_readiness: ProviderReadiness,
    /// Name-free aggregate rate-limit status.
    pub rate_limits: RateLimitState,
    /// Full-host dual-root outcome kind, without names or plans.
    pub namespace_outcome: Option<OutcomeKind>,
    /// Name-free HNS root lookup failure.
    pub hns_root_failure: Option<RootFailureKind>,
    /// Name-free ICANN root lookup failure.
    pub icann_root_failure: Option<RootFailureKind>,
    /// Namespace selected for the current decision.
    pub selected_namespace: Option<Namespace>,
    /// Stable namespace-selection reason.
    pub selection_reason: Option<SelectionReason>,
    /// Name-free namespace decision fingerprint.
    pub decision_fingerprint: Option<[u8; 32]>,
    /// Current ICANN DANE/WebPKI/fail-closed action.
    ///
    /// This may be absent for an intentionally cleartext scheme.
    pub icann_tls_action: Option<IcannTlsAction>,
    /// Canonical validating-DoH DNSSEC disposition for the ICANN action.
    pub icann_dnssec_status: Option<IcannDnssecStatus>,
    /// ICANN validating-DoH evidence for a selected plan or failed lookup.
    ///
    /// This is required when `selected_namespace` is ICANN or
    /// `icann_root_failure` is present. Secondary-root evidence does not
    /// belong in a successful selected-plan status.
    pub icann_evidence: Option<ValidationEvidence>,
    /// Recoverable degraded reason.
    pub degraded_reason: Option<DegradedReason>,
    /// Revocation reason.
    pub revocation_reason: Option<RevocationReason>,
    /// Bounded unsupported evidence details.
    pub unsupported_evidence: Vec<UnsupportedEvidence>,
}

impl ObservabilityRuntime {
    /// Construct status inputs whose provider readiness is derived from policy.
    #[must_use]
    pub fn for_policy(policy: PolicySnapshot) -> Self {
        Self {
            registry_fingerprint: [0; 32],
            protocol_version: 0,
            provider_readiness: ProviderReadiness::from_policy(policy),
            rate_limits: RateLimitState::default(),
            namespace_outcome: None,
            hns_root_failure: None,
            icann_root_failure: None,
            selected_namespace: None,
            selection_reason: None,
            decision_fingerprint: None,
            icann_tls_action: None,
            icann_dnssec_status: None,
            icann_evidence: None,
            degraded_reason: None,
            revocation_reason: None,
            unsupported_evidence: Vec::new(),
        }
    }
}

impl Default for ObservabilityRuntime {
    fn default() -> Self {
        Self::for_policy(PolicySnapshot::default())
    }
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

/// Gateway-selected response atomically admitted to the current engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayResolution {
    attempt: ResolutionAttempt,
    response: ParsedResponse,
    context: CompletionContext,
}

impl GatewayResolution {
    /// Current-generation resolution attempt.
    #[must_use]
    pub const fn attempt(&self) -> &ResolutionAttempt {
        &self.attempt
    }

    /// Locally parsed and correlated gateway response.
    #[must_use]
    pub const fn response(&self) -> &ParsedResponse {
        &self.response
    }

    /// Gateway-derived intermediary identities and downgrade state.
    #[must_use]
    pub const fn context(&self) -> &CompletionContext {
        &self.context
    }

    /// Consume into the three inputs used by local DNSSEC/DANE completion.
    #[must_use]
    pub fn into_parts(self) -> (ResolutionAttempt, ParsedResponse, CompletionContext) {
        (self.attempt, self.response, self.context)
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
    admission_stamp: RuntimeStamp,
    provenance: ResolutionProvenance,
    dane_match: DaneMatch,
    origin_sni: Option<String>,
    bridge_service_port: Option<u16>,
    bridge_tlsa_records: Option<Vec<Vec<u8>>>,
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

    /// Exact TCP TLSA service port, absent for the legacy prerequisite API.
    #[must_use]
    pub const fn bridge_service_port(&self) -> Option<u16> {
        self.bridge_service_port
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
            .field("bridge_service_port", &self.bridge_service_port)
            .field(
                "bridge_tlsa_records",
                &self.bridge_tlsa_records.as_ref().map(Vec::len),
            )
            .field("bridge_valid_from", &self.bridge_valid_from)
            .field("bridge_valid_until", &self.bridge_valid_until)
            .finish_non_exhaustive()
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
    service_port: u16,
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

    /// Exact TCP TLSA service port authenticated for the origin.
    #[must_use]
    pub const fn service_port(&self) -> u16 {
        self.service_port
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
            .field("service_port", &self.service_port)
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
        let runtime_session = RuntimeSessionId::new(runtime_session).map_err(map_runtime_error)?;
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
            schema_version: runtime.schema_version(),
            runtime_session: runtime.session_bytes(),
            runtime_generation: runtime.generation(),
            event_sequence: runtime.event_sequence(),
            network: state.network,
            authority_state: runtime.authority_state(),
            policy: state.policy.snapshot(),
        })
    }

    /// Mint a private unauthenticated context for an all-outcomes denial.
    pub fn bind_unauthenticated_origin_context(
        &self,
        decision: &NamespaceDecision,
        now: u64,
    ) -> Result<AuthenticatedOriginContext, EngineError> {
        let state = self.state.read().map_err(|_| EngineError::LockPoisoned)?;
        Ok(stamp_origin_context(
            &state,
            decision,
            AuthenticatedContextStatus::Unauthenticated,
            now,
            decision.expires_at_unix(),
            None,
        ))
    }

    /// Bind an exact ICANN decision through the trusted browser TLS principal.
    ///
    /// The callback receives the engine-derived HTTPS origin, complete decision
    /// fingerprint, selected TLS policy, network, and expiry. Its result cannot
    /// be retained and rebound to another decision: the engine immediately
    /// stamps it into a private context under the current runtime generations.
    pub fn bind_icann_origin_context<A: TrustedIcannOriginAuthenticator>(
        &self,
        decision: &NamespaceDecision,
        authenticator: &A,
        now: u64,
    ) -> Result<AuthenticatedOriginContext, EngineError> {
        let logical_origin = LogicalOrigin::from_namespace_decision(decision);
        let plan = decision
            .selected_plan()
            .ok_or(EngineError::ProviderAuthenticationMismatch)?;
        if logical_origin.scheme() != OriginScheme::Https
            || decision.selected_namespace() != Some(Namespace::Icann)
            || plan.service().transport() != ServiceTransport::Tcp
            || !decision.is_fresh_at(now)
        {
            return Err(EngineError::ProviderAuthenticationMismatch);
        }
        let mut state = self.state.write().map_err(|_| EngineError::LockPoisoned)?;
        let runtime = state.runtime.snapshot();
        let policy_generation = state.policy.snapshot().generation();
        if !network_matches(state.network, decision.hns_network())
            || !matches!(
                runtime.authority_state(),
                AuthorityState::BrowserBridgeReady | AuthorityState::Active
            )
        {
            return Err(EngineError::ProviderAuthenticationMismatch);
        }
        let authentication_stamp = state.runtime.admit_event().map_err(map_runtime_error)?;
        let request = IcannOriginAuthenticationRequest {
            logical_origin,
            service_port: plan.service().effective_port().get(),
            decision_fingerprint: *decision_fingerprint(decision).as_bytes(),
            hns_network: decision.hns_network(),
            tls_policy: plan.tls_policy(),
            valid_until: decision.expires_at_unix(),
            runtime_stamp: authentication_stamp,
            policy_generation,
        };
        drop(state);
        let authentication = authenticator
            .authenticate(&request)
            .ok_or(EngineError::ProviderAuthenticationMismatch)?;
        if authentication.request != request {
            return Err(EngineError::ProviderAuthenticationMismatch);
        }
        let status = match (request.tls_policy, authentication.kind) {
            (TlsTrustPolicy::Dane, IcannTlsAuthenticationKind::DaneVerified) => {
                AuthenticatedContextStatus::IcannDaneVerified
            }
            (
                TlsTrustPolicy::WebPkiAuthenticatedAbsence,
                IcannTlsAuthenticationKind::WebPkiVerified,
            ) => AuthenticatedContextStatus::IcannWebPkiAuthenticatedAbsence,
            (
                TlsTrustPolicy::WebPkiInsecureDelegation,
                IcannTlsAuthenticationKind::WebPkiVerified,
            ) => AuthenticatedContextStatus::IcannWebPkiInsecureDelegation,
            _ => return Err(EngineError::ProviderAuthenticationMismatch),
        };
        let mut state = self.state.write().map_err(|_| EngineError::LockPoisoned)?;
        if !network_matches(state.network, decision.hns_network())
            || state.policy.snapshot().generation() != request.policy_generation
            || !state.runtime.admits(request.runtime_stamp)
            || !decision.is_fresh_at(now)
        {
            return Err(EngineError::ProviderAuthenticationMismatch);
        }
        let context_stamp = state.runtime.admit_event().map_err(map_runtime_error)?;
        Ok(stamp_origin_context(
            &state,
            decision,
            status,
            now,
            decision.expires_at_unix(),
            Some(context_stamp),
        ))
    }

    /// Atomically bind a strict HNS completion to one exact namespace decision.
    ///
    /// The selected decision must be HTTPS/HNS/DANE and must carry the same
    /// effective TCP service port, canonical TLSA RRset, HNS network, and exact
    /// proof height/tree root as the completion. Only then is a private context
    /// minted from the current runtime session/generation/event tuple.
    pub fn bind_hns_origin_context(
        &self,
        decision: &NamespaceDecision,
        completion: &DaneCompletion,
        now: u64,
    ) -> Result<AuthenticatedOriginContext, EngineError> {
        let logical_origin = LogicalOrigin::from_namespace_decision(decision);
        let origin = completion
            .origin_sni
            .as_ref()
            .ok_or(EngineError::LegacyCompletionNotBridgeable)?;
        let service_port = completion
            .bridge_service_port
            .ok_or(EngineError::UnsupportedBridgeService)?;
        let records = completion
            .bridge_tlsa_records
            .as_ref()
            .ok_or(EngineError::LegacyCompletionNotBridgeable)?;
        let valid_from = completion
            .bridge_valid_from
            .ok_or(EngineError::LegacyCompletionNotBridgeable)?;
        let completion_valid_until = completion
            .bridge_valid_until
            .ok_or(EngineError::LegacyCompletionNotBridgeable)?;
        if now < valid_from {
            return Err(EngineError::CompletionNotYetValid);
        }
        if now > completion_valid_until {
            return Err(EngineError::CompletionExpired);
        }
        let Some(plan) = decision.selected_plan() else {
            return Err(EngineError::ProviderAuthenticationMismatch);
        };
        let plan_records_match =
            plan.tlsa_records().len() == records.len()
                && plan.tlsa_records().iter().zip(records).all(
                    |(plan_record, completion_record)| plan_record.rdata() == completion_record,
                );
        let anchor_matches = completion.provenance.chain_anchor.is_some_and(|anchor| {
            matches!(
                plan.provenance(),
                EvidenceProvenance::Hns {
                    network,
                    tree_root,
                    height,
                } if *network == decision.hns_network()
                    && *tree_root == anchor.tree_root
                    && *height == anchor.height
            )
        });
        if logical_origin.scheme() != OriginScheme::Https
            || logical_origin.host() != origin
            || decision.selected_namespace() != Some(Namespace::Hns)
            || plan.tls_policy() != TlsTrustPolicy::Dane
            || plan.service().transport() != ServiceTransport::Tcp
            || plan.service().effective_port().get() != service_port
            || !decision.is_fresh_at(now)
            || !plan_records_match
            || !anchor_matches
        {
            return Err(EngineError::ProviderAuthenticationMismatch);
        }

        let mut state = self.state.write().map_err(|_| EngineError::LockPoisoned)?;
        let runtime_before = state.runtime.snapshot();
        if !network_matches(state.network, decision.hns_network())
            || !matches!(
                runtime_before.authority_state(),
                AuthorityState::DaneOriginVerified
                    | AuthorityState::BrowserBridgeReady
                    | AuthorityState::Active
            )
        {
            return Err(EngineError::ProviderAuthenticationMismatch);
        }
        if !completion_is_current(&state, completion) {
            return Err(EngineError::CompletionNotCurrent);
        }
        if runtime_before.authority_state() == AuthorityState::DaneOriginVerified {
            state
                .runtime
                .transition(AuthorityState::BrowserBridgeReady)
                .map_err(map_runtime_error)?;
        }
        let context_stamp = state.runtime.admit_event().map_err(map_runtime_error)?;
        Ok(stamp_origin_context(
            &state,
            decision,
            AuthenticatedContextStatus::HnsDaneVerified,
            valid_from,
            decision
                .expires_at_unix()
                .min(completion_valid_until.saturating_add(1)),
            Some(context_stamp),
        ))
    }

    /// Atomically decide whether the wallet provider may be injected.
    ///
    /// Every call returns a typed allow-or-deny outcome. A denial is normal
    /// policy output rather than an error; errors are reserved for internal
    /// engine failures such as a poisoned lock. This report is suitable for
    /// trusted UI and diagnostics. Browser integrations that will actually
    /// install a provider must use [`Self::authorize_provider_injection`] and
    /// retain its opaque [`ProviderAuthorityContext`].
    pub fn provider_injection_decision(
        &self,
        decision: &NamespaceDecision,
        context: &AuthenticatedOriginContext,
        now: u64,
    ) -> Result<ProviderInjectionDecision, EngineError> {
        let state = self.state.read().map_err(|_| EngineError::LockPoisoned)?;
        Ok(evaluate_provider_injection(&state, decision, context, now))
    }

    /// Validate policy and mint an opaque provider authority on exact success.
    ///
    /// The typed outcome prevents a denied status report from being mistaken
    /// for a capability. The authorized context contains no wallet state or
    /// permissions and is valid only for the exact origin, selected namespace,
    /// plan, runtime session/generation/event, policy generation, and lifetime
    /// checked by [`Self::provider_injection_decision`].
    pub fn authorize_provider_injection(
        &self,
        decision: &NamespaceDecision,
        context: &AuthenticatedOriginContext,
        now: u64,
    ) -> Result<ProviderAuthorityOutcome, EngineError> {
        let state = self.state.read().map_err(|_| EngineError::LockPoisoned)?;
        let evaluation = evaluate_provider_injection(&state, decision, context, now);
        Ok(provider_authority_outcome(
            decision,
            context.clone(),
            evaluation,
            now,
        ))
    }

    /// Revalidate an existing provider authority against current engine state.
    ///
    /// Revalidation consumes the old, non-cloneable context. A successful
    /// result contains a replacement whose lifetime is narrowed to the current
    /// decision; a denial contains no reusable authority. Any navigation or
    /// namespace mismatch, security-invalidating runtime transition, process
    /// session, runtime generation, policy generation, or expiry change returns
    /// a typed denial. Ordinary later admissions do not revoke the context.
    /// Browser products therefore do not need to reproduce the engine's
    /// trust-policy matrix.
    pub fn revalidate_provider_authority(
        &self,
        decision: &NamespaceDecision,
        authority: ProviderAuthorityContext,
        now: u64,
    ) -> Result<ProviderAuthorityOutcome, EngineError> {
        let state = self.state.read().map_err(|_| EngineError::LockPoisoned)?;
        let mut evaluation =
            evaluate_provider_injection(&state, decision, &authority.origin_context, now);
        if evaluation.permitted() && !authority.matches_decision(decision) {
            evaluation.permitted = false;
            evaluation.denial_reason = Some(ProviderInjectionDenialReason::DecisionMismatch);
        }
        Ok(provider_authority_outcome(
            decision,
            authority.origin_context,
            evaluation,
            now,
        ))
    }

    /// Check an opaque provider authority without consuming or reconstructing it.
    ///
    /// This is the native publication boundary: ordinary later admissions do
    /// not revoke the authority, while lifecycle invalidation, policy/runtime
    /// replacement, network mismatch, or expiry rejects it. The context must
    /// remain private to trusted native code.
    pub fn provider_authority_is_current(
        &self,
        authority: &ProviderAuthorityContext,
        now: u64,
    ) -> Result<bool, EngineError> {
        let state = self.state.read().map_err(|_| EngineError::LockPoisoned)?;
        Ok(provider_authority_is_current_in_state(
            &state, authority, now,
        ))
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
        let provenance = state.last_provenance.as_ref();
        let selected_icann = runtime.selected_namespace == Some(Namespace::Icann);
        let failed_icann = runtime.icann_root_failure.is_some();
        let icann_context = selected_icann || failed_icann;
        let classification_failed =
            runtime.hns_root_failure.is_some() || runtime.icann_root_failure.is_some();
        let neither = runtime.namespace_outcome == Some(OutcomeKind::Neither);
        let (chain_anchor, actual_transport, identities, evidence) = if icann_context {
            let evidence = runtime
                .icann_evidence
                .ok_or(EngineError::MissingIcannEvidence)?;
            (
                None,
                ResolutionTransport::ValidatingIcannDoh,
                TransportIdentities::default(),
                evidence,
            )
        } else if neither || classification_failed {
            if runtime.icann_evidence.is_some() {
                return Err(EngineError::UnexpectedIcannEvidence);
            }
            (
                None,
                ResolutionTransport::Unavailable,
                TransportIdentities::default(),
                ValidationEvidence::not_attempted(),
            )
        } else {
            if runtime.icann_evidence.is_some() {
                return Err(EngineError::UnexpectedIcannEvidence);
            }
            let identities = provenance.map_or_else(TransportIdentities::default, |provenance| {
                TransportIdentities {
                    peer: provenance.peer_identity.clone(),
                    proxy: provenance.proxy_identity.clone(),
                    target: provenance.target_identity.clone(),
                    direct_relay_fallback: provenance.direct_relay_fallback,
                }
            });
            (
                provenance.and_then(|provenance| provenance.chain_anchor),
                provenance.map_or(ResolutionTransport::Unavailable, |provenance| {
                    provenance.transport
                }),
                identities,
                provenance.map_or(state.last_evidence, |provenance| provenance.evidence),
            )
        };
        let experimental_p2p = matches!(
            actual_transport,
            ResolutionTransport::HandshakeP2pOdoh | ResolutionTransport::HandshakeP2pDnsRelay
        );
        BrowserStatus::new(StatusInput {
            runtime: runtime_snapshot,
            network: state.network,
            policy: state.policy.snapshot(),
            chain_anchor,
            actual_transport,
            identities,
            registry_profile: state.policy.snapshot().config().wire_profile,
            registry_fingerprint: if experimental_p2p {
                runtime.registry_fingerprint
            } else {
                [0; 32]
            },
            protocol_version: if experimental_p2p {
                runtime.protocol_version
            } else {
                0
            },
            provider_readiness: runtime.provider_readiness,
            rate_limits: runtime.rate_limits,
            evidence,
            namespace_outcome: runtime.namespace_outcome,
            hns_root_failure: runtime.hns_root_failure,
            icann_root_failure: runtime.icann_root_failure,
            selected_namespace: runtime.selected_namespace,
            selection_reason: runtime.selection_reason,
            decision_fingerprint: runtime.decision_fingerprint,
            icann_tls_action: runtime.icann_tls_action,
            icann_dnssec_status: runtime.icann_dnssec_status,
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
        if !resolution_transport_ready(state.runtime.authority_state()) {
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

    /// Atomically admit a gateway selection under the current policy/runtime.
    ///
    /// Response bytes are parsed and exactly correlated before an engine event
    /// is consumed. The selection's policy generation, selected transport,
    /// identities, and privacy-downgrade state are then admitted together
    /// under one write lock, so callers cannot substitute completion context.
    pub fn admit_gateway_selection(
        &self,
        selection: GatewaySelection,
        query: Query,
        limits: ParseLimits,
    ) -> Result<GatewayResolution, EngineError> {
        let (policy_generation, transport, response, identities, direct_relay_fallback) =
            selection.into_parts();
        let message = Message::parse_with_limits(&response, limits)?;
        let correlated = query.correlate(&message)?;
        let untrusted_ad_claim = correlated.untrusted_ad_claim();
        let context = CompletionContext {
            chain_anchor: None,
            peer_identity: identities.peer,
            proxy_identity: identities.proxy,
            target_identity: identities.target,
            direct_relay_fallback,
        };
        validate_completion_context(transport, &context)?;

        let mut state = self.state.write().map_err(|_| EngineError::LockPoisoned)?;
        if state.policy.snapshot().generation() != policy_generation {
            return Err(EngineError::StaleGatewaySelection);
        }
        if !resolution_transport_ready(state.runtime.authority_state()) {
            return Err(EngineError::AuthorityNotReady);
        }
        let admission = state.policy.admit(transport)?;
        let runtime_stamp = state.runtime.admit_event().map_err(map_runtime_error)?;
        drop(state);

        Ok(GatewayResolution {
            response: ParsedResponse {
                attempt_stamp: runtime_stamp,
                message,
                untrusted_ad_claim,
            },
            attempt: ResolutionAttempt {
                runtime_stamp,
                admission,
                query,
            },
            context,
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
            admission_stamp: attempt.runtime_stamp,
            provenance,
            dane_match,
            origin_sni: None,
            bridge_service_port: None,
            bridge_tlsa_records: None,
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
            admission_stamp: attempt.runtime_stamp,
            provenance,
            dane_match,
            origin_sni: Some(input.origin_sni.trim_end_matches('.').to_ascii_lowercase()),
            bridge_service_port: tlsa_tcp_service_port(input.validated.requested_owner()),
            bridge_tlsa_records: Some(canonical_tlsa_rdata(input.validated.records())),
            bridge_valid_from: Some(hns_authority.anchor().validated_at().get()),
            bridge_valid_until: Some(hns_authority.anchor().valid_until().get()),
        })
    }

    /// Authorize the exact strict-path origin for the browser bridge.
    ///
    /// The completion must retain an admitted stamp in this engine's current
    /// security epoch. Legacy caller-prerequisite completions cannot mint a
    /// bridge authorization because they carry no engine-verified origin
    /// binding.
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
        let service_port = completion
            .bridge_service_port
            .ok_or(EngineError::UnsupportedBridgeService)?;
        if now < valid_from {
            return Err(EngineError::CompletionNotYetValid);
        }
        if now > valid_until {
            return Err(EngineError::CompletionExpired);
        }
        let mut state = self.state.write().map_err(|_| EngineError::LockPoisoned)?;
        let runtime_before = state.runtime.snapshot();
        if !matches!(
            runtime_before.authority_state(),
            AuthorityState::DaneOriginVerified
                | AuthorityState::BrowserBridgeReady
                | AuthorityState::Active
        ) {
            return Err(EngineError::AuthorityNotReady);
        }
        if !completion_is_current(&state, completion) {
            return Err(EngineError::CompletionNotCurrent);
        }
        if runtime_before.authority_state() == AuthorityState::DaneOriginVerified {
            state
                .runtime
                .transition(AuthorityState::BrowserBridgeReady)
                .map_err(map_runtime_error)?;
        } else {
            state.runtime.admit_event().map_err(map_runtime_error)?;
        }
        let runtime = state.runtime.snapshot();
        Ok(BrowserBridgeAuthorization {
            runtime_session: runtime.session_bytes(),
            runtime_generation: runtime.generation(),
            policy_generation: state.policy.snapshot().generation(),
            event_sequence: runtime.event_sequence(),
            valid_from,
            valid_until,
            origin: origin.clone(),
            service_port,
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
            runtime_session: runtime.session_bytes(),
            runtime_generation: runtime.generation(),
            policy_generation: attempt.admission.policy_generation,
            event_sequence: runtime.event_sequence(),
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

fn stamp_origin_context(
    state: &EngineState,
    decision: &NamespaceDecision,
    status: AuthenticatedContextStatus,
    valid_from: u64,
    valid_until: u64,
    admission_stamp: Option<RuntimeStamp>,
) -> AuthenticatedOriginContext {
    let runtime = state.runtime.snapshot();
    let (runtime_session, runtime_generation, event_sequence) = admission_stamp.map_or(
        (
            runtime.session_bytes(),
            runtime.generation(),
            runtime.event_sequence(),
        ),
        |stamp| (stamp.session(), stamp.generation(), stamp.event_sequence()),
    );
    AuthenticatedOriginContext {
        logical_origin: LogicalOrigin::from_namespace_decision(decision),
        selected_namespace: decision.selected_namespace(),
        status,
        runtime_session,
        runtime_generation,
        policy_generation: state.policy.snapshot().generation(),
        event_sequence,
        admission_stamp,
        decision_fingerprint: *decision_fingerprint(decision).as_bytes(),
        valid_from,
        valid_until,
    }
}

fn evaluate_provider_injection(
    state: &EngineState,
    decision: &NamespaceDecision,
    context: &AuthenticatedOriginContext,
    now: u64,
) -> ProviderInjectionDecision {
    let runtime = state.runtime.snapshot();
    let logical_origin = LogicalOrigin::from_namespace_decision(decision);
    let selected_namespace = decision.selected_namespace();
    let fingerprint = *decision_fingerprint(decision).as_bytes();
    let policy_generation = state.policy.snapshot().generation();
    let authority_state = runtime.authority_state();

    let denial_reason = if !logical_origin.is_secure() {
        Some(ProviderInjectionDenialReason::InsecureOrigin)
    } else if logical_origin.scheme() != OriginScheme::Https {
        Some(ProviderInjectionDenialReason::UnsupportedOriginScheme)
    } else if selected_namespace.is_none() {
        Some(ProviderInjectionDenialReason::NoSelectedNamespace)
    } else if context.status == AuthenticatedContextStatus::Unauthenticated {
        Some(ProviderInjectionDenialReason::UnauthenticatedContext)
    } else if context.logical_origin != logical_origin {
        Some(ProviderInjectionDenialReason::OriginMismatch)
    } else if context.selected_namespace != selected_namespace {
        Some(ProviderInjectionDenialReason::NamespaceMismatch)
    } else if context.decision_fingerprint != fingerprint {
        Some(ProviderInjectionDenialReason::DecisionMismatch)
    } else if !decision.is_fresh_at(now) {
        Some(ProviderInjectionDenialReason::DecisionStale)
    } else if !network_matches(state.network, decision.hns_network()) {
        Some(ProviderInjectionDenialReason::NetworkMismatch)
    } else if let Some(reason) = authority_denial(authority_state) {
        Some(reason)
    } else if context.runtime_session != runtime.session_bytes() {
        Some(ProviderInjectionDenialReason::StaleRuntimeSession)
    } else if context.runtime_generation != runtime.generation() {
        Some(ProviderInjectionDenialReason::StaleRuntimeGeneration)
    } else if context.policy_generation != policy_generation {
        Some(ProviderInjectionDenialReason::StalePolicyGeneration)
    } else if !authenticated_context_is_admitted(state, context) {
        Some(ProviderInjectionDenialReason::StaleAuthenticationEvent)
    } else {
        authentication_policy_denial(decision, context.status)
            .or_else(|| {
                (now < context.valid_from)
                    .then_some(ProviderInjectionDenialReason::AuthenticationNotYetValid)
            })
            .or_else(|| {
                (now >= context.valid_until)
                    .then_some(ProviderInjectionDenialReason::AuthenticationExpired)
            })
    };

    ProviderInjectionDecision {
        logical_origin,
        selected_namespace,
        authenticated_context: context.status,
        runtime_session: runtime.session_bytes(),
        runtime_generation: runtime.generation(),
        policy_generation,
        event_sequence: runtime.event_sequence(),
        decision_fingerprint: fingerprint,
        authority_state,
        permitted: denial_reason.is_none(),
        denial_reason,
    }
}

fn provider_authority_outcome(
    decision: &NamespaceDecision,
    mut context: AuthenticatedOriginContext,
    mut evaluation: ProviderInjectionDecision,
    now: u64,
) -> ProviderAuthorityOutcome {
    if !evaluation.permitted() {
        return ProviderAuthorityOutcome::Denied(evaluation);
    }
    let (Some(selected_namespace), Some(plan)) =
        (decision.selected_namespace(), decision.selected_plan())
    else {
        evaluation.permitted = false;
        evaluation.denial_reason = Some(ProviderInjectionDenialReason::NoSelectedNamespace);
        return ProviderAuthorityOutcome::Denied(evaluation);
    };
    if plan.service().transport() != ServiceTransport::Tcp {
        evaluation.permitted = false;
        evaluation.denial_reason =
            Some(ProviderInjectionDenialReason::AuthenticationPolicyMismatch);
        return ProviderAuthorityOutcome::Denied(evaluation);
    }
    context.valid_from = context.valid_from.max(now);
    context.valid_until = context.valid_until.min(decision.expires_at_unix());
    ProviderAuthorityOutcome::Authorized(ProviderAuthorityContext {
        origin_context: context,
        selected_namespace,
        hns_network: decision.hns_network(),
        service_port: plan.service().effective_port().get(),
        tls_policy: plan.tls_policy(),
    })
}

fn authenticated_context_is_admitted(
    state: &EngineState,
    context: &AuthenticatedOriginContext,
) -> bool {
    context.admission_stamp.is_some_and(|stamp| {
        stamp.session() == context.runtime_session
            && stamp.generation() == context.runtime_generation
            && stamp.event_sequence() == context.event_sequence
            && state.runtime.admits(stamp)
    })
}

fn provider_authority_is_current_in_state(
    state: &EngineState,
    authority: &ProviderAuthorityContext,
    now: u64,
) -> bool {
    let runtime = state.runtime.snapshot();
    let context = &authority.origin_context;
    let authentication_matches = matches!(
        (
            authority.selected_namespace,
            authority.tls_policy,
            context.status
        ),
        (
            Namespace::Hns,
            TlsTrustPolicy::Dane,
            AuthenticatedContextStatus::HnsDaneVerified
        ) | (
            Namespace::Icann,
            TlsTrustPolicy::Dane,
            AuthenticatedContextStatus::IcannDaneVerified
        ) | (
            Namespace::Icann,
            TlsTrustPolicy::WebPkiAuthenticatedAbsence,
            AuthenticatedContextStatus::IcannWebPkiAuthenticatedAbsence
        ) | (
            Namespace::Icann,
            TlsTrustPolicy::WebPkiInsecureDelegation,
            AuthenticatedContextStatus::IcannWebPkiInsecureDelegation
        )
    );
    authority_denial(runtime.authority_state()).is_none()
        && context.logical_origin.is_secure()
        && context.logical_origin.scheme() == OriginScheme::Https
        && context.selected_namespace == Some(authority.selected_namespace)
        && authority.service_port != 0
        && authentication_matches
        && context.runtime_session == runtime.session_bytes()
        && context.runtime_generation == runtime.generation()
        && context.policy_generation == state.policy.snapshot().generation()
        && network_matches(state.network, authority.hns_network)
        && authenticated_context_is_admitted(state, context)
        && now >= context.valid_from
        && now < context.valid_until
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

fn canonical_tlsa_rdata(records: &[Tlsa]) -> Vec<Vec<u8>> {
    let mut canonical = records
        .iter()
        .map(|record| {
            let mut rdata = Vec::with_capacity(3 + record.association_data.len());
            rdata.push(record.usage);
            rdata.push(record.selector);
            rdata.push(record.matching_type);
            rdata.extend_from_slice(&record.association_data);
            rdata
        })
        .collect::<Vec<_>>();
    canonical.sort_unstable();
    canonical.dedup();
    canonical
}

fn tlsa_tcp_service_port(owner: &hns_dns_wire::Name) -> Option<u16> {
    let labels = owner.labels();
    let port_label = labels.first()?.strip_prefix(b"_")?;
    if labels.get(1)?.as_slice() != b"_tcp" {
        return None;
    }
    let port = std::str::from_utf8(port_label).ok()?.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

const fn network_id(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Testnet => 1,
        Network::Regtest => 2,
        Network::Simnet => 3,
    }
}

const fn network_matches(network: Network, hns_network: HnsNetwork) -> bool {
    matches!(
        (network, hns_network),
        (Network::Mainnet, HnsNetwork::Mainnet)
            | (Network::Testnet, HnsNetwork::Testnet)
            | (Network::Regtest, HnsNetwork::Regtest)
            | (Network::Simnet, HnsNetwork::Simnet)
    )
}

const fn authority_denial(state: AuthorityState) -> Option<ProviderInjectionDenialReason> {
    match state {
        AuthorityState::BrowserBridgeReady | AuthorityState::Active => None,
        AuthorityState::Degraded => Some(ProviderInjectionDenialReason::AuthorityDegraded),
        AuthorityState::Revoked => Some(ProviderInjectionDenialReason::AuthorityRevoked),
        AuthorityState::Stopped => Some(ProviderInjectionDenialReason::AuthorityStopped),
        AuthorityState::Uninitialized
        | AuthorityState::LocalStateOpened
        | AuthorityState::HeaderSyncing
        | AuthorityState::HeaderCurrent
        | AuthorityState::ProofReady
        | AuthorityState::ResolutionTransportReady
        | AuthorityState::DnssecVerified
        | AuthorityState::DaneOriginVerified => {
            Some(ProviderInjectionDenialReason::AuthorityNotReady)
        }
    }
}

fn authentication_policy_denial(
    decision: &NamespaceDecision,
    status: AuthenticatedContextStatus,
) -> Option<ProviderInjectionDenialReason> {
    let Some(plan) = decision.selected_plan() else {
        return Some(ProviderInjectionDenialReason::AuthenticationPolicyMismatch);
    };
    let matches = matches!(
        (decision.selected_namespace(), plan.tls_policy(), status),
        (
            Some(Namespace::Hns),
            TlsTrustPolicy::Dane,
            AuthenticatedContextStatus::HnsDaneVerified
        ) | (
            Some(Namespace::Icann),
            TlsTrustPolicy::Dane,
            AuthenticatedContextStatus::IcannDaneVerified
        ) | (
            Some(Namespace::Icann),
            TlsTrustPolicy::WebPkiAuthenticatedAbsence,
            AuthenticatedContextStatus::IcannWebPkiAuthenticatedAbsence
        ) | (
            Some(Namespace::Icann),
            TlsTrustPolicy::WebPkiInsecureDelegation,
            AuthenticatedContextStatus::IcannWebPkiInsecureDelegation
        )
    );
    (!matches).then_some(ProviderInjectionDenialReason::AuthenticationPolicyMismatch)
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

fn completion_is_current(state: &EngineState, completion: &DaneCompletion) -> bool {
    let runtime = state.runtime.snapshot();
    let provenance = &completion.provenance;
    state.runtime.admits(completion.admission_stamp)
        && completion.admission_stamp.session() == provenance.runtime_session
        && completion.admission_stamp.generation() == provenance.runtime_generation
        && completion.admission_stamp.event_sequence() <= provenance.event_sequence
        && provenance.runtime_session == runtime.session_bytes()
        && provenance.runtime_generation == runtime.generation()
        && provenance.event_sequence <= runtime.event_sequence()
        && provenance.policy_generation == state.policy.snapshot().generation()
        && provenance.network == state.network
        && provenance.evidence.fully_verified()
}

const fn resolution_transport_ready(state: AuthorityState) -> bool {
    matches!(
        state,
        AuthorityState::ResolutionTransportReady
            | AuthorityState::DnssecVerified
            | AuthorityState::DaneOriginVerified
            | AuthorityState::BrowserBridgeReady
            | AuthorityState::Active
    )
}

const fn map_runtime_error(error: RuntimeError) -> EngineError {
    match error {
        RuntimeError::ZeroSession => EngineError::InvalidRuntimeSession,
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
            if context.peer_identity.is_some() || context.direct_relay_fallback {
                return Err(EngineError::InvalidCompletionContext);
            }
        }
        ResolutionTransport::HandshakeP2pDnsRelay => {
            if context.peer_identity.is_none() {
                return Err(EngineError::MissingTransportIdentity);
            }
            if context.proxy_identity.is_some() || context.target_identity.is_some() {
                return Err(EngineError::InvalidCompletionContext);
            }
        }
        ResolutionTransport::DirectAuthoritativeUdp
        | ResolutionTransport::DirectAuthoritativeTcp
        | ResolutionTransport::AuthenticatedAuthoritativeDoh
        | ResolutionTransport::UserConfiguredRecursiveHnsDoh => {
            if context.peer_identity.is_some()
                || context.proxy_identity.is_some()
                || context.target_identity.is_some()
                || context.direct_relay_fallback
            {
                return Err(EngineError::InvalidCompletionContext);
            }
        }
        ResolutionTransport::Unavailable
        | ResolutionTransport::ValidatingIcannDoh
        | ResolutionTransport::LocalHnsProof => {
            return Err(EngineError::InvalidCompletionContext);
        }
    }
    Ok(())
}

/// Facade failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineError {
    /// Runtime session uses the forbidden all-zero sentinel.
    InvalidRuntimeSession,
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
    /// Gateway selection belongs to an older policy generation.
    StaleGatewaySelection,
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
    /// The validated TLSA owner is not a nonzero TCP service usable by the bridge.
    UnsupportedBridgeService,
    /// TLS evidence does not bind the exact provider namespace decision.
    ProviderAuthenticationMismatch,
    /// Completion is no longer admitted in the engine's current security epoch.
    CompletionNotCurrent,
    /// Completion's chain-currency validity window elapsed.
    CompletionExpired,
    /// Completion predates the beginning of its chain-currency validity window.
    CompletionNotYetValid,
    /// ICANN selection or root failure omitted explicit validation evidence.
    MissingIcannEvidence,
    /// ICANN evidence was supplied without ICANN selection or root failure.
    UnexpectedIcannEvidence,
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
            Self::InvalidRuntimeSession => formatter.write_str("runtime session must be nonzero"),
            Self::LockPoisoned => formatter.write_str("engine state lock poisoned"),
            Self::GenerationExhausted => formatter.write_str("engine generation exhausted"),
            Self::InvalidAuthorityTransition => {
                formatter.write_str("invalid browser authority state transition")
            }
            Self::AuthorityNotReady => formatter.write_str("browser authority state is not ready"),
            Self::StaleRuntimeGeneration => formatter.write_str("stale runtime generation"),
            Self::StaleGatewaySelection => {
                formatter.write_str("gateway selection belongs to a stale policy generation")
            }
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
            Self::UnsupportedBridgeService => {
                formatter.write_str("DANE completion does not authenticate a supported TCP service")
            }
            Self::ProviderAuthenticationMismatch => formatter
                .write_str("TLS evidence does not bind the exact provider namespace decision"),
            Self::CompletionNotCurrent => {
                formatter.write_str("DANE completion is not current for this engine")
            }
            Self::CompletionExpired => {
                formatter.write_str("DANE completion chain-currency window expired")
            }
            Self::CompletionNotYetValid => {
                formatter.write_str("DANE completion chain-currency window has not begun")
            }
            Self::MissingIcannEvidence => formatter
                .write_str("ICANN selection or lookup failure requires validation evidence"),
            Self::UnexpectedIcannEvidence => {
                formatter.write_str("ICANN evidence requires an ICANN selection or lookup failure")
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use hns_browser_testkit::{STRICT_HNS_ORIGIN, StrictRegtestDaneFixture};
    use hns_dns_wire::{Flags, Header, Name, ResourceRecord};
    use hns_namespace_resolution::{
        AbsenceKind, ApplicationProtocol, CanonicalHost, CanonicalTlsa, EvidenceProvenance,
        Freshness, IcannChainState, OriginPlanInput, OriginQuery, ProtocolCapabilities, RootLookup,
        SelectionPolicy, ServiceBinding, ServiceBindingInput, ServiceParameter, ServiceTransport,
        ValidatedAbsence, ValidatedOriginPlan, decide_namespace,
    };
    use hns_resolution_policy::{DnsRelayRequesterPolicy, EvidenceState, ObliviousDnsPolicy};

    const AUTHORITY_NOW: u64 = 1_700_000_000;

    const RESPONSE_WITH_UNTRUSTED_AD: &[u8] =
        b"\x12\x34\x84\x20\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01";

    fn ready_engine_in_session(runtime_session: [u8; 16], network: Network) -> Engine {
        let engine = Engine::new(EngineConfig {
            runtime_session: RuntimeSessionId::new(runtime_session).unwrap(),
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

    fn active_engine_without_dane() -> Engine {
        let engine = ready_engine_in_session([13; 16], Network::Mainnet);
        engine
            .advance_authority_state(AuthorityState::BrowserBridgeReady)
            .unwrap();
        engine
            .advance_authority_state(AuthorityState::Active)
            .unwrap();
        engine
    }

    fn active_engine_in_session(session: [u8; 16], network: Network) -> Engine {
        let engine = ready_engine_in_session(session, network);
        engine
            .advance_authority_state(AuthorityState::BrowserBridgeReady)
            .unwrap();
        engine
            .advance_authority_state(AuthorityState::Active)
            .unwrap();
        engine
    }

    fn authority_query(host: &str, scheme: OriginScheme) -> OriginQuery {
        OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            scheme,
            None,
            ProtocolCapabilities::all(),
        )
    }

    fn authority_provenance(namespace: Namespace, network: HnsNetwork) -> EvidenceProvenance {
        match namespace {
            Namespace::Hns => EvidenceProvenance::Hns {
                network,
                tree_root: [21; 32],
                height: 42,
            },
            Namespace::Icann => EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
        }
    }

    fn authority_freshness() -> Freshness {
        Freshness::new(AUTHORITY_NOW - 10, AUTHORITY_NOW + 100).unwrap()
    }

    fn authority_absence(
        namespace: Namespace,
        query: &OriginQuery,
        network: HnsNetwork,
    ) -> ValidatedAbsence {
        ValidatedAbsence::new(
            namespace,
            query.clone(),
            match namespace {
                Namespace::Hns => AbsenceKind::HnsCurrentUrkelNonInclusion,
                Namespace::Icann => AbsenceKind::DnssecAuthenticatedNxDomain,
            },
            authority_provenance(namespace, network),
            authority_freshness(),
        )
        .unwrap()
    }

    fn authority_plan(
        namespace: Namespace,
        query: &OriginQuery,
        tls_policy: TlsTrustPolicy,
        network: HnsNetwork,
    ) -> ValidatedOriginPlan {
        let port = query.origin_port();
        let target = query.host().clone();
        let service = ServiceBinding::new(ServiceBindingInput {
            priority: None,
            service_target: target.clone(),
            mandatory_keys: Vec::new(),
            advertised_alpn: Vec::new(),
            selected_protocol: ApplicationProtocol::Http11,
            effective_port: port,
            transport: ServiceTransport::Tcp,
            connection_hints: Vec::new(),
            ech_config: None,
            parameters: Vec::new(),
        })
        .unwrap();
        let tlsa_records = if tls_policy == TlsTrustPolicy::Dane {
            vec![CanonicalTlsa::new(vec![3, 0, 0, 1]).unwrap()]
        } else {
            Vec::new()
        };
        ValidatedOriginPlan::new(OriginPlanInput {
            namespace,
            query: query.clone(),
            alias_path: Vec::new(),
            terminal_target: target.clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: target,
            endpoints: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                port.get(),
            )],
            service,
            tls_policy,
            tlsa_records,
            provenance: authority_provenance(namespace, network),
            freshness: authority_freshness(),
        })
        .unwrap()
    }

    fn authority_decision(
        host: &str,
        scheme: OriginScheme,
        selected: Namespace,
        network: HnsNetwork,
    ) -> NamespaceDecision {
        let tls_policy = match (selected, scheme.uses_tls()) {
            (_, false) => TlsTrustPolicy::Cleartext,
            (Namespace::Hns, true) => TlsTrustPolicy::Dane,
            (Namespace::Icann, true) => TlsTrustPolicy::WebPkiAuthenticatedAbsence,
        };
        authority_decision_with_tls_policy(host, scheme, selected, network, tls_policy)
    }

    fn authority_decision_with_tls_policy(
        host: &str,
        scheme: OriginScheme,
        selected: Namespace,
        network: HnsNetwork,
        tls_policy: TlsTrustPolicy,
    ) -> NamespaceDecision {
        let query = authority_query(host, scheme);
        let selected_lookup =
            RootLookup::Present(authority_plan(selected, &query, tls_policy, network));
        let absent = match selected {
            Namespace::Hns => {
                RootLookup::Absent(authority_absence(Namespace::Icann, &query, network))
            }
            Namespace::Icann => {
                RootLookup::Absent(authority_absence(Namespace::Hns, &query, network))
            }
        };
        let (hns, icann) = match selected {
            Namespace::Hns => (selected_lookup, absent),
            Namespace::Icann => (absent, selected_lookup),
        };
        decide_namespace(
            &query,
            hns,
            icann,
            SelectionPolicy::default(),
            AUTHORITY_NOW,
        )
        .unwrap()
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "the test adapter implements the optional trusted-authenticator result"
    )]
    fn trusted_icann_webpki(
        request: &IcannOriginAuthenticationRequest,
    ) -> Option<IcannOriginAuthentication> {
        Some(request.attest_webpki_verified())
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "the test adapter implements the optional trusted-authenticator result"
    )]
    fn trusted_icann_dane(
        request: &IcannOriginAuthenticationRequest,
    ) -> Option<IcannOriginAuthentication> {
        Some(request.attest_dane_verified())
    }

    fn no_root_decision(
        host: &str,
        scheme: OriginScheme,
        network: HnsNetwork,
    ) -> NamespaceDecision {
        let query = authority_query(host, scheme);
        decide_namespace(
            &query,
            RootLookup::Absent(authority_absence(Namespace::Hns, &query, network)),
            RootLookup::Absent(authority_absence(Namespace::Icann, &query, network)),
            SelectionPolicy::default(),
            AUTHORITY_NOW,
        )
        .unwrap()
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "splice tests vary each origin/plan binding independently"
    )]
    fn hns_decision_for_completion(
        completion: &DaneCompletion,
        scheme: OriginScheme,
        origin_port: u16,
        service_port: u16,
        network: HnsNetwork,
        tree_root: [u8; 32],
        tlsa_records: Vec<Vec<u8>>,
    ) -> NamespaceDecision {
        let host = CanonicalHost::parse(completion.origin_sni.as_ref().unwrap()).unwrap();
        let explicit_port = (origin_port != scheme.default_port().get())
            .then(|| std::num::NonZeroU16::new(origin_port).unwrap());
        let query = OriginQuery::new(
            host.clone(),
            scheme,
            explicit_port,
            ProtocolCapabilities::all(),
        );
        let service_port = std::num::NonZeroU16::new(service_port).unwrap();
        let priority = (service_port != query.origin_port()).then_some(1);
        let parameters = priority.map_or_else(Vec::new, |_| {
            vec![ServiceParameter::new(3, service_port.get().to_be_bytes().to_vec()).unwrap()]
        });
        let service = ServiceBinding::new(ServiceBindingInput {
            priority,
            service_target: host.clone(),
            mandatory_keys: Vec::new(),
            advertised_alpn: Vec::new(),
            selected_protocol: ApplicationProtocol::Http11,
            effective_port: service_port,
            transport: ServiceTransport::Tcp,
            connection_hints: Vec::new(),
            ech_config: None,
            parameters,
        })
        .unwrap();
        let valid_from = completion.bridge_valid_from.unwrap();
        let expires_at = completion
            .bridge_valid_until
            .unwrap()
            .checked_add(1)
            .unwrap();
        let freshness = Freshness::new(valid_from, expires_at).unwrap();
        let anchor = completion.provenance.chain_anchor.unwrap();
        let hns_plan = ValidatedOriginPlan::new(OriginPlanInput {
            namespace: Namespace::Hns,
            query: query.clone(),
            alias_path: Vec::new(),
            terminal_target: host.clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host,
            endpoints: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                service_port.get(),
            )],
            service,
            tls_policy: TlsTrustPolicy::Dane,
            tlsa_records: tlsa_records
                .into_iter()
                .map(|rdata| CanonicalTlsa::new(rdata).unwrap())
                .collect(),
            provenance: EvidenceProvenance::Hns {
                network,
                tree_root,
                height: anchor.height,
            },
            freshness,
        })
        .unwrap();
        let icann_absence = ValidatedAbsence::new(
            Namespace::Icann,
            query.clone(),
            AbsenceKind::DnssecAuthenticatedNxDomain,
            EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
            freshness,
        )
        .unwrap();
        decide_namespace(
            &query,
            RootLookup::Present(hns_plan),
            RootLookup::Absent(icann_absence),
            SelectionPolicy::default(),
            valid_from,
        )
        .unwrap()
    }

    fn icann_observability(
        action: IcannTlsAction,
        evidence: Option<ValidationEvidence>,
    ) -> ObservabilityRuntime {
        ObservabilityRuntime {
            registry_fingerprint: [99; 32],
            protocol_version: 99,
            namespace_outcome: Some(OutcomeKind::IcannOnly),
            selected_namespace: Some(Namespace::Icann),
            selection_reason: Some(SelectionReason::SingleRoot),
            decision_fingerprint: Some([13; 32]),
            icann_tls_action: Some(action),
            icann_dnssec_status: Some(if action == IcannTlsAction::WebPkiInsecureDelegation {
                IcannDnssecStatus::InsecureDelegation
            } else {
                IcannDnssecStatus::Secure
            }),
            icann_evidence: evidence,
            ..ObservabilityRuntime::default()
        }
    }

    fn failed_icann_observability(
        failure: RootFailureKind,
        dnssec_status: Option<IcannDnssecStatus>,
        evidence: ValidationEvidence,
    ) -> ObservabilityRuntime {
        ObservabilityRuntime {
            registry_fingerprint: [99; 32],
            protocol_version: 99,
            icann_root_failure: Some(failure),
            icann_tls_action: Some(IcannTlsAction::FailClosed),
            icann_dnssec_status: dnssec_status,
            icann_evidence: Some(evidence),
            ..ObservabilityRuntime::default()
        }
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
        decode_hex(include_str!("../fixtures/dane/self-signed-cert.der.hex"))
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

    fn strict_hns_completion(engine: &Engine) -> (DaneCompletion, NamespaceDecision, u64) {
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
        let completion = engine
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
        let anchor = completion.provenance().chain_anchor.unwrap();
        let decision = hns_decision_for_completion(
            &completion,
            OriginScheme::Https,
            443,
            443,
            HnsNetwork::Regtest,
            anchor.tree_root,
            completion.bridge_tlsa_records.clone().unwrap(),
        );
        (completion, decision, u64::from(validation_time))
    }

    fn odoh_gateway_selection(engine: &Engine, response: &[u8]) -> Option<GatewaySelection> {
        let policy = engine.snapshot().unwrap().policy;
        let mut gateway = engine.begin_gateway(GatewayLimits::default()).unwrap();
        let mut now = 100_u64;
        loop {
            let attempt = gateway.next_attempt(policy, now).unwrap();
            let outcome = if attempt.transport() == ResolutionTransport::HandshakeP2pOdoh {
                hns_gateway::AttemptOutcome::Response {
                    bytes: response.to_owned(),
                    identities: hns_gateway::GatewayIdentities {
                        proxy: Some("brontide:proxy".to_owned()),
                        target: Some("brontide:target".to_owned()),
                        ..hns_gateway::GatewayIdentities::default()
                    },
                }
            } else {
                hns_gateway::AttemptOutcome::Failure(hns_gateway::TransportFailure::Unsupported)
            };
            match gateway.complete(policy, attempt, outcome, now).unwrap() {
                hns_gateway::GatewayStep::RetryAvailable => {
                    now = now.checked_add(1).unwrap();
                }
                hns_gateway::GatewayStep::Selected(selection) => return Some(selection),
                hns_gateway::GatewayStep::Unavailable => return None,
            }
        }
    }

    #[test]
    fn provider_injection_allows_exact_current_icann_context() {
        let engine = active_engine_without_dane();
        let decision = authority_decision(
            "wallet.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let context = engine
            .bind_icann_origin_context(&decision, &trusted_icann_webpki, AUTHORITY_NOW)
            .unwrap();
        let outcome = engine
            .provider_injection_decision(&decision, &context, AUTHORITY_NOW)
            .unwrap();

        assert!(outcome.permitted());
        assert_eq!(outcome.denial_reason(), None);
        assert_eq!(outcome.logical_origin().host(), "wallet.example");
        assert_eq!(outcome.logical_origin().port(), 443);
        assert_eq!(outcome.selected_namespace(), Some(Namespace::Icann));
        assert_eq!(
            outcome.authenticated_context(),
            AuthenticatedContextStatus::IcannWebPkiAuthenticatedAbsence
        );

        let authority = engine
            .authorize_provider_injection(&decision, &context, AUTHORITY_NOW)
            .unwrap()
            .into_context()
            .unwrap();
        assert_eq!(authority.logical_origin().host(), "wallet.example");
        assert_eq!(authority.logical_origin().port(), 443);
        assert_eq!(authority.selected_namespace(), Namespace::Icann);
        assert_eq!(authority.hns_network(), HnsNetwork::Mainnet);
        assert_eq!(authority.service_port(), 443);
        assert_eq!(
            authority.tls_policy(),
            TlsTrustPolicy::WebPkiAuthenticatedAbsence
        );
        assert_eq!(authority.runtime_session(), [13; 16]);
        assert_eq!(authority.runtime_generation(), 1);
        assert_eq!(authority.policy_generation(), 1);
        assert_eq!(authority.valid_until(), AUTHORITY_NOW + 100);
        assert!(!format!("{authority:?}").contains("wallet.example"));

        let refreshed = engine
            .revalidate_provider_authority(&decision, authority, AUTHORITY_NOW)
            .unwrap();
        assert!(refreshed.is_authorized());
        assert!(refreshed.context().is_some());
        assert!(refreshed.denial().is_none());
    }

    #[test]
    fn icann_context_survives_unrelated_admissions() {
        let engine = active_engine_without_dane();
        let decision = authority_decision(
            "wallet.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let (query, _, _) = exact_certificate_exchange();
        let authenticate = |request: &IcannOriginAuthenticationRequest| {
            engine
                .admit_resolution(ResolutionTransport::DirectAuthoritativeTcp, query.clone())
                .unwrap();
            Some(request.attest_webpki_verified())
        };
        let context = engine
            .bind_icann_origin_context(&decision, &authenticate, AUTHORITY_NOW)
            .unwrap();
        let context_event = context.event_sequence();
        engine
            .admit_resolution(ResolutionTransport::DirectAuthoritativeTcp, query)
            .unwrap();
        assert!(engine.snapshot().unwrap().event_sequence > context_event);
        assert!(
            engine
                .provider_injection_decision(&decision, &context, AUTHORITY_NOW)
                .unwrap()
                .permitted()
        );
        let authority = engine
            .authorize_provider_injection(&decision, &context, AUTHORITY_NOW)
            .unwrap()
            .into_context()
            .unwrap();
        assert!(
            engine
                .provider_authority_is_current(&authority, AUTHORITY_NOW)
                .unwrap()
        );
    }

    #[test]
    fn provider_authority_revalidation_fails_closed_after_binding_changes() {
        let engine = active_engine_without_dane();
        let decision = authority_decision(
            "wallet.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let context = engine
            .bind_icann_origin_context(&decision, &trusted_icann_webpki, AUTHORITY_NOW)
            .unwrap();
        let authority = engine
            .authorize_provider_injection(&decision, &context, AUTHORITY_NOW)
            .unwrap()
            .into_context()
            .unwrap();

        let other_origin = authority_decision(
            "other.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let denied = engine
            .revalidate_provider_authority(&other_origin, authority, AUTHORITY_NOW)
            .unwrap();
        assert!(!denied.is_authorized());
        assert_eq!(
            denied
                .denial()
                .and_then(ProviderInjectionDecision::denial_reason),
            Some(ProviderInjectionDenialReason::OriginMismatch)
        );

        let authority = engine
            .authorize_provider_injection(&decision, &context, AUTHORITY_NOW)
            .unwrap()
            .into_context()
            .unwrap();
        engine
            .advance_authority_state(AuthorityState::Degraded)
            .unwrap();
        let denied = engine
            .revalidate_provider_authority(&decision, authority, AUTHORITY_NOW)
            .unwrap();
        assert_eq!(
            denied
                .denial()
                .and_then(ProviderInjectionDecision::denial_reason),
            Some(ProviderInjectionDenialReason::AuthorityDegraded)
        );

        for state in [
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
            AuthorityState::BrowserBridgeReady,
            AuthorityState::Active,
        ] {
            engine.advance_authority_state(state).unwrap();
        }
        assert_eq!(
            engine
                .provider_injection_decision(&decision, &context, AUTHORITY_NOW)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::StaleAuthenticationEvent)
        );
    }

    #[test]
    fn icann_tokens_are_exact_decision_bound_and_policy_typed() {
        use std::cell::RefCell;

        let engine = active_engine_without_dane();
        let first = authority_decision(
            "wallet.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let saved_request = RefCell::new(None);
        let capture = |request: &IcannOriginAuthenticationRequest| {
            assert_eq!(request.logical_origin().host(), "wallet.example");
            assert_eq!(request.logical_origin().port(), 443);
            assert_eq!(request.service_port(), 443);
            assert_eq!(request.hns_network(), HnsNetwork::Mainnet);
            assert_eq!(
                request.tls_policy(),
                TlsTrustPolicy::WebPkiAuthenticatedAbsence
            );
            assert_eq!(request.valid_until(), AUTHORITY_NOW + 100);
            saved_request.replace(Some(request.clone()));
            Some(request.attest_webpki_verified())
        };
        assert!(
            engine
                .bind_icann_origin_context(&first, &capture, AUTHORITY_NOW)
                .is_ok()
        );

        let second = authority_decision(
            "other.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let replay = |_: &IcannOriginAuthenticationRequest| {
            Some(
                saved_request
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .attest_webpki_verified(),
            )
        };
        assert!(matches!(
            engine.bind_icann_origin_context(&second, &replay, AUTHORITY_NOW),
            Err(EngineError::ProviderAuthenticationMismatch)
        ));

        let dane = authority_decision_with_tls_policy(
            "dane.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
            TlsTrustPolicy::Dane,
        );
        assert!(matches!(
            engine.bind_icann_origin_context(&dane, &trusted_icann_webpki, AUTHORITY_NOW),
            Err(EngineError::ProviderAuthenticationMismatch)
        ));
        let dane_context = engine
            .bind_icann_origin_context(&dane, &trusted_icann_dane, AUTHORITY_NOW)
            .unwrap();
        let outcome = engine
            .provider_injection_decision(&dane, &dane_context, AUTHORITY_NOW)
            .unwrap();
        assert!(outcome.permitted());
        assert_eq!(
            outcome.authenticated_context(),
            AuthenticatedContextStatus::IcannDaneVerified
        );
    }

    #[test]
    fn provider_injection_denies_origin_namespace_and_network_substitution() {
        let engine = active_engine_without_dane();
        let icann = authority_decision(
            "wallet.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let context = engine
            .bind_icann_origin_context(&icann, &trusted_icann_webpki, AUTHORITY_NOW)
            .unwrap();

        let other_origin = authority_decision(
            "other.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        assert_eq!(
            engine
                .provider_injection_decision(&other_origin, &context, AUTHORITY_NOW)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::OriginMismatch)
        );

        let other_namespace = authority_decision(
            "wallet.example",
            OriginScheme::Https,
            Namespace::Hns,
            HnsNetwork::Mainnet,
        );
        assert_eq!(
            engine
                .provider_injection_decision(&other_namespace, &context, AUTHORITY_NOW)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::NamespaceMismatch)
        );

        let other_network = authority_decision(
            "wallet.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Testnet,
        );
        let testnet_engine = active_engine_in_session([13; 16], Network::Testnet);
        let other_network_context = testnet_engine
            .bind_icann_origin_context(&other_network, &trusted_icann_webpki, AUTHORITY_NOW)
            .unwrap();
        assert_eq!(
            engine
                .provider_injection_decision(&other_network, &other_network_context, AUTHORITY_NOW,)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::NetworkMismatch)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the denial matrix keeps related authority and scheme outcomes together"
    )]
    fn provider_injection_denies_stale_degraded_and_insecure_contexts() {
        let engine = active_engine_without_dane();
        let decision = authority_decision(
            "wallet.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let context = engine
            .bind_icann_origin_context(&decision, &trusted_icann_webpki, AUTHORITY_NOW)
            .unwrap();
        assert_eq!(
            engine
                .provider_injection_decision(&decision, &context, AUTHORITY_NOW + 100)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::DecisionStale)
        );

        let unauthenticated = engine
            .bind_unauthenticated_origin_context(&decision, AUTHORITY_NOW)
            .unwrap();
        assert_eq!(
            engine
                .provider_injection_decision(&decision, &unauthenticated, AUTHORITY_NOW)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::UnauthenticatedContext)
        );

        engine
            .advance_authority_state(AuthorityState::Degraded)
            .unwrap();
        assert_eq!(
            engine
                .provider_injection_decision(&decision, &context, AUTHORITY_NOW)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::AuthorityDegraded)
        );

        let active = active_engine_without_dane();
        let insecure = authority_decision(
            "wallet.example",
            OriginScheme::Http,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let insecure_context = active
            .bind_unauthenticated_origin_context(&insecure, AUTHORITY_NOW)
            .unwrap();
        assert_eq!(
            active
                .provider_injection_decision(&insecure, &insecure_context, AUTHORITY_NOW)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::InsecureOrigin)
        );

        let websocket = authority_decision(
            "wallet.example",
            OriginScheme::Ws,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let websocket_context = active
            .bind_unauthenticated_origin_context(&websocket, AUTHORITY_NOW)
            .unwrap();
        assert_eq!(
            active
                .provider_injection_decision(&websocket, &websocket_context, AUTHORITY_NOW)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::InsecureOrigin)
        );

        let secure_websocket = authority_decision(
            "wallet.example",
            OriginScheme::Wss,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let secure_websocket_context = active
            .bind_unauthenticated_origin_context(&secure_websocket, AUTHORITY_NOW)
            .unwrap();
        assert_eq!(
            active
                .provider_injection_decision(
                    &secure_websocket,
                    &secure_websocket_context,
                    AUTHORITY_NOW,
                )
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::UnsupportedOriginScheme)
        );

        let neither = no_root_decision("missing.example", OriginScheme::Https, HnsNetwork::Mainnet);
        let neither_context = active
            .bind_unauthenticated_origin_context(&neither, AUTHORITY_NOW)
            .unwrap();
        assert_eq!(
            active
                .provider_injection_decision(&neither, &neither_context, AUTHORITY_NOW)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::NoSelectedNamespace)
        );
    }

    #[test]
    fn provider_injection_denies_revoked_and_stopped_authority() {
        let decision = authority_decision(
            "wallet.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        for (state, reason) in [
            (
                AuthorityState::Revoked,
                ProviderInjectionDenialReason::AuthorityRevoked,
            ),
            (
                AuthorityState::Stopped,
                ProviderInjectionDenialReason::AuthorityStopped,
            ),
        ] {
            let engine = active_engine_without_dane();
            let context = engine
                .bind_icann_origin_context(&decision, &trusted_icann_webpki, AUTHORITY_NOW)
                .unwrap();
            engine.advance_authority_state(state).unwrap();
            assert_eq!(
                engine
                    .provider_injection_decision(&decision, &context, AUTHORITY_NOW)
                    .unwrap()
                    .denial_reason(),
                Some(reason)
            );
        }
    }

    #[test]
    fn provider_injection_rejects_runtime_session_and_generation_replay() {
        let decision = authority_decision(
            "wallet.example",
            OriginScheme::Https,
            Namespace::Icann,
            HnsNetwork::Mainnet,
        );
        let first = active_engine_in_session([31; 16], Network::Mainnet);
        let context = first
            .bind_icann_origin_context(&decision, &trusted_icann_webpki, AUTHORITY_NOW)
            .unwrap();
        let second = active_engine_in_session([32; 16], Network::Mainnet);
        assert_eq!(
            second
                .provider_injection_decision(&decision, &context, AUTHORITY_NOW)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::StaleRuntimeSession)
        );

        let mut next_policy = first.snapshot().unwrap().policy.config();
        next_policy.user_configured_recursive_hns_doh =
            !next_policy.user_configured_recursive_hns_doh;
        first
            .update_policy(first.snapshot().unwrap().policy.generation(), next_policy)
            .unwrap();
        for state in [
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
            AuthorityState::BrowserBridgeReady,
            AuthorityState::Active,
        ] {
            first.advance_authority_state(state).unwrap();
        }
        assert_eq!(
            first
                .provider_injection_decision(&decision, &context, AUTHORITY_NOW)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::StaleRuntimeGeneration)
        );
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
    fn interleaved_hns_completions_retain_exact_authority() {
        let engine = ready_engine_on(Network::Regtest);
        let (first_completion, first_decision, now) = strict_hns_completion(&engine);
        let (second_completion, second_decision, _) = strict_hns_completion(&engine);

        let first_context = engine
            .bind_hns_origin_context(&first_decision, &first_completion, now)
            .unwrap();
        let second_context = engine
            .bind_hns_origin_context(&second_decision, &second_completion, now)
            .unwrap();

        assert!(
            engine
                .provider_injection_decision(&first_decision, &first_context, now)
                .unwrap()
                .permitted()
        );
        assert!(
            engine
                .provider_injection_decision(&second_decision, &second_context, now)
                .unwrap()
                .permitted()
        );
        assert!(
            engine
                .authorize_browser_bridge(&first_completion, now)
                .is_ok()
        );

        engine
            .advance_authority_state(AuthorityState::Degraded)
            .unwrap();
        for state in [
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
            AuthorityState::BrowserBridgeReady,
            AuthorityState::Active,
        ] {
            engine.advance_authority_state(state).unwrap();
        }
        assert_eq!(
            engine
                .provider_injection_decision(&first_decision, &first_context, now)
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::StaleAuthenticationEvent)
        );
        assert!(matches!(
            engine.bind_hns_origin_context(&first_decision, &first_completion, now),
            Err(EngineError::CompletionNotCurrent)
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

        let anchor = completed.provenance().chain_anchor.unwrap();
        let exact_records = completed.bridge_tlsa_records.clone().unwrap();
        let exact_decision = hns_decision_for_completion(
            &completed,
            OriginScheme::Https,
            443,
            443,
            HnsNetwork::Regtest,
            anchor.tree_root,
            exact_records.clone(),
        );
        let origin_context = engine
            .bind_hns_origin_context(&exact_decision, &completed, u64::from(validation_time))
            .unwrap();
        assert!(
            engine
                .provider_injection_decision(
                    &exact_decision,
                    &origin_context,
                    u64::from(validation_time),
                )
                .unwrap()
                .permitted()
        );

        let different_origin_port = hns_decision_for_completion(
            &completed,
            OriginScheme::Https,
            444,
            443,
            HnsNetwork::Regtest,
            anchor.tree_root,
            exact_records.clone(),
        );
        assert_eq!(
            engine
                .provider_injection_decision(
                    &different_origin_port,
                    &origin_context,
                    u64::from(validation_time),
                )
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::OriginMismatch)
        );

        let different_service_port = hns_decision_for_completion(
            &completed,
            OriginScheme::Https,
            443,
            444,
            HnsNetwork::Regtest,
            anchor.tree_root,
            exact_records.clone(),
        );
        assert!(matches!(
            engine.bind_hns_origin_context(
                &different_service_port,
                &completed,
                u64::from(validation_time),
            ),
            Err(EngineError::ProviderAuthenticationMismatch)
        ));

        let mut different_records = exact_records.clone();
        *different_records
            .first_mut()
            .and_then(|record| record.last_mut())
            .unwrap() ^= 1;
        let different_tlsa = hns_decision_for_completion(
            &completed,
            OriginScheme::Https,
            443,
            443,
            HnsNetwork::Regtest,
            anchor.tree_root,
            different_records,
        );
        assert!(matches!(
            engine
                .bind_hns_origin_context(&different_tlsa, &completed, u64::from(validation_time),),
            Err(EngineError::ProviderAuthenticationMismatch)
        ));
        assert_eq!(
            engine
                .provider_injection_decision(
                    &different_tlsa,
                    &origin_context,
                    u64::from(validation_time),
                )
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::DecisionMismatch)
        );

        let mut different_root = anchor.tree_root;
        different_root[0] ^= 1;
        let different_provenance = hns_decision_for_completion(
            &completed,
            OriginScheme::Https,
            443,
            443,
            HnsNetwork::Regtest,
            different_root,
            exact_records.clone(),
        );
        assert!(matches!(
            engine.bind_hns_origin_context(
                &different_provenance,
                &completed,
                u64::from(validation_time),
            ),
            Err(EngineError::ProviderAuthenticationMismatch)
        ));

        let different_network = hns_decision_for_completion(
            &completed,
            OriginScheme::Https,
            443,
            443,
            HnsNetwork::Testnet,
            anchor.tree_root,
            exact_records.clone(),
        );
        assert!(matches!(
            engine.bind_hns_origin_context(
                &different_network,
                &completed,
                u64::from(validation_time),
            ),
            Err(EngineError::ProviderAuthenticationMismatch)
        ));

        let websocket = hns_decision_for_completion(
            &completed,
            OriginScheme::Wss,
            443,
            443,
            HnsNetwork::Regtest,
            anchor.tree_root,
            exact_records,
        );
        assert!(matches!(
            engine.bind_hns_origin_context(&websocket, &completed, u64::from(validation_time),),
            Err(EngineError::ProviderAuthenticationMismatch)
        ));
        assert_eq!(
            engine
                .provider_injection_decision(
                    &websocket,
                    &origin_context,
                    u64::from(validation_time),
                )
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::UnsupportedOriginScheme)
        );

        assert_eq!(
            engine
                .provider_injection_decision(
                    &exact_decision,
                    &origin_context,
                    exact_decision.expires_at_unix(),
                )
                .unwrap()
                .denial_reason(),
            Some(ProviderInjectionDenialReason::DecisionStale)
        );
        assert!(matches!(
            engine.bind_hns_origin_context(
                &exact_decision,
                &completed,
                exact_decision.expires_at_unix(),
            ),
            Err(EngineError::CompletionExpired)
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
        assert_eq!(status.registry_fingerprint(), [0; 32]);
        assert_eq!(status.protocol_version(), 0);
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
            Err(EngineError::Status(StatusError::MissingFailureReason))
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
    fn observability_facade_reports_selected_icann_dane_and_webpki() {
        let engine = active_engine_without_dane();

        let mut dane = ValidationEvidence::not_attempted();
        dane.dnssec = EvidenceState::Verified;
        dane.tlsa = EvidenceState::Verified;
        dane.dane = EvidenceState::Verified;
        let status = engine
            .observability_status(icann_observability(IcannTlsAction::EnforceDane, Some(dane)))
            .unwrap();
        assert_eq!(
            status.actual_transport(),
            ResolutionTransport::ValidatingIcannDoh
        );
        assert_eq!(status.chain_anchor(), None);
        assert_eq!(status.identities(), &TransportIdentities::default());
        assert_eq!(status.registry_fingerprint(), [0; 32]);
        assert_eq!(status.protocol_version(), 0);
        assert_eq!(status.evidence(), dane);

        let mut authenticated_absence = ValidationEvidence::not_attempted();
        authenticated_absence.dnssec = EvidenceState::Verified;
        authenticated_absence.tlsa = EvidenceState::Unavailable;
        let status = engine
            .observability_status(icann_observability(
                IcannTlsAction::WebPkiAuthenticatedAbsence,
                Some(authenticated_absence),
            ))
            .unwrap();
        assert_eq!(
            status.icann_tls_action(),
            Some(IcannTlsAction::WebPkiAuthenticatedAbsence)
        );
        assert_eq!(status.evidence().dane, EvidenceState::NotAttempted);

        let mut proven_insecure = authenticated_absence;
        proven_insecure.dane = EvidenceState::Unavailable;
        let status = engine
            .observability_status(icann_observability(
                IcannTlsAction::WebPkiInsecureDelegation,
                Some(proven_insecure),
            ))
            .unwrap();
        assert_eq!(
            status.icann_tls_action(),
            Some(IcannTlsAction::WebPkiInsecureDelegation)
        );
    }

    #[test]
    fn observability_facade_keeps_bogus_and_indeterminate_icann_fail_closed() {
        let engine = active_engine_without_dane();

        let mut bogus = ValidationEvidence::not_attempted();
        bogus.dnssec = EvidenceState::Failed;
        let status = engine
            .observability_status(failed_icann_observability(
                RootFailureKind::BogusDnssec,
                Some(IcannDnssecStatus::Bogus),
                bogus,
            ))
            .unwrap();
        assert_eq!(status.namespace_outcome(), None);
        assert_eq!(status.selected_namespace(), None);
        assert_eq!(
            status.icann_root_failure(),
            Some(RootFailureKind::BogusDnssec)
        );
        assert_eq!(status.icann_tls_action(), Some(IcannTlsAction::FailClosed));
        assert_eq!(status.evidence().dnssec, EvidenceState::Failed);

        let mut missing_action = failed_icann_observability(
            RootFailureKind::BogusDnssec,
            Some(IcannDnssecStatus::Bogus),
            bogus,
        );
        missing_action.icann_tls_action = None;
        assert!(matches!(
            engine.observability_status(missing_action),
            Err(EngineError::Status(StatusError::InvalidIcannTlsContext))
        ));

        let mut indeterminate = ValidationEvidence::not_attempted();
        indeterminate.dnssec = EvidenceState::Unavailable;
        indeterminate.tlsa = EvidenceState::Unavailable;
        indeterminate.dane = EvidenceState::Unavailable;
        let status = engine
            .observability_status(failed_icann_observability(
                RootFailureKind::IndeterminateDnssec,
                Some(IcannDnssecStatus::Indeterminate),
                indeterminate,
            ))
            .unwrap();
        assert_eq!(status.evidence().dnssec, EvidenceState::Unavailable);
        assert_eq!(status.icann_tls_action(), Some(IcannTlsAction::FailClosed));
    }

    #[test]
    fn observability_facade_requires_evidence_for_selected_or_failed_icann() {
        let engine = active_engine_without_dane();
        assert!(matches!(
            engine.observability_status(icann_observability(
                IcannTlsAction::WebPkiAuthenticatedAbsence,
                None,
            )),
            Err(EngineError::MissingIcannEvidence)
        ));

        let runtime = ObservabilityRuntime {
            icann_evidence: Some(ValidationEvidence::not_attempted()),
            ..ObservabilityRuntime::default()
        };
        assert!(matches!(
            engine.observability_status(runtime),
            Err(EngineError::UnexpectedIcannEvidence)
        ));

        let mut failed = failed_icann_observability(
            RootFailureKind::BogusDnssec,
            Some(IcannDnssecStatus::Bogus),
            ValidationEvidence {
                dnssec: EvidenceState::Failed,
                ..ValidationEvidence::not_attempted()
            },
        );
        failed.icann_evidence = None;
        assert!(matches!(
            engine.observability_status(failed),
            Err(EngineError::MissingIcannEvidence)
        ));
    }

    #[test]
    fn neither_outcome_cannot_reuse_prior_hns_provenance() {
        let engine = ready_engine();
        let (query, response, certificate) = exact_certificate_exchange();
        let attempt = engine
            .admit_resolution(ResolutionTransport::DirectAuthoritativeTcp, query)
            .unwrap();
        let parsed = engine
            .parse_response(&attempt, &response, ParseLimits::requester())
            .unwrap();
        engine
            .complete_resolution_with_local_dane(
                &attempt,
                &parsed,
                verified_prerequisites(),
                &certificate,
                DaneLimits::default(),
                CompletionContext::default(),
            )
            .unwrap();

        let status = engine
            .observability_status(ObservabilityRuntime {
                namespace_outcome: Some(OutcomeKind::Neither),
                decision_fingerprint: Some([21; 32]),
                ..ObservabilityRuntime::default()
            })
            .unwrap();
        assert_eq!(status.actual_transport(), ResolutionTransport::Unavailable);
        assert_eq!(status.chain_anchor(), None);
        assert_eq!(status.identities(), &TransportIdentities::default());
        assert_eq!(status.evidence(), ValidationEvidence::not_attempted());
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
    fn gateway_selection_atomically_binds_response_and_identities() {
        let engine = ready_engine();
        let (query, response, _) = exact_certificate_exchange();
        let selection = odoh_gateway_selection(&engine, &response).unwrap();
        let admitted = engine
            .admit_gateway_selection(selection, query, ParseLimits::requester())
            .unwrap();
        assert_eq!(
            admitted.attempt().transport(),
            ResolutionTransport::HandshakeP2pOdoh
        );
        assert_eq!(
            admitted.context().proxy_identity.as_deref(),
            Some("brontide:proxy")
        );
        assert_eq!(
            admitted.context().target_identity.as_deref(),
            Some("brontide:target")
        );
        assert_eq!(admitted.response().message().header.id, 0x1234);
    }

    #[test]
    fn stale_gateway_selection_consumes_no_engine_event() {
        let engine = ready_engine();
        let (query, response, _) = exact_certificate_exchange();
        let selection = odoh_gateway_selection(&engine, &response).unwrap();
        let before = engine.snapshot().unwrap();
        let mut next = before.policy.config();
        next.authenticated_authoritative_doh = !next.authenticated_authoritative_doh;
        engine
            .update_policy(before.policy.generation(), next)
            .unwrap();
        let after_update = engine.snapshot().unwrap();
        assert!(matches!(
            engine.admit_gateway_selection(selection, query, ParseLimits::requester()),
            Err(EngineError::StaleGatewaySelection)
        ));
        assert_eq!(
            engine.snapshot().unwrap().event_sequence,
            after_update.event_sequence
        );
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
    fn completion_identity_topology_matches_observability() {
        assert!(matches!(
            validate_completion_context(
                ResolutionTransport::HandshakeP2pOdoh,
                &CompletionContext {
                    peer_identity: Some("extra-peer".to_owned()),
                    proxy_identity: Some("proxy".to_owned()),
                    target_identity: Some("target".to_owned()),
                    ..CompletionContext::default()
                }
            ),
            Err(EngineError::InvalidCompletionContext)
        ));
        assert!(matches!(
            validate_completion_context(
                ResolutionTransport::HandshakeP2pDnsRelay,
                &CompletionContext {
                    peer_identity: Some("relay".to_owned()),
                    proxy_identity: Some("extra-proxy".to_owned()),
                    ..CompletionContext::default()
                }
            ),
            Err(EngineError::InvalidCompletionContext)
        ));
        assert!(matches!(
            validate_completion_context(
                ResolutionTransport::DirectAuthoritativeTcp,
                &CompletionContext {
                    peer_identity: Some("extra-peer".to_owned()),
                    ..CompletionContext::default()
                }
            ),
            Err(EngineError::InvalidCompletionContext)
        ));
    }

    #[test]
    fn persisted_policy_survives_restart() {
        let engine = Engine::new(EngineConfig::new(
            RuntimeSessionId::new([8; 16]).unwrap(),
            Network::Mainnet,
            PolicySnapshot::default(),
        ));
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

    #[test]
    fn persisted_engine_rejects_zero_runtime_session() {
        let policy = PolicySnapshot::default().encode();
        assert!(matches!(
            Engine::from_persisted([0; 16], Network::Mainnet, &policy),
            Err(EngineError::InvalidRuntimeSession)
        ));
    }
}
