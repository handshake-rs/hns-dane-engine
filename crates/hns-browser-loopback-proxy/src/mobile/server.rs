//! Authenticated, scoped HTTP/1 loopback proxy lifecycle.

use crate::auth::ProxyAuthorization;
use crate::backend::{
    BackendError, CancellationToken, ProxyBackend, ProxyHeader, ProxyRequest, ProxyRequestBody,
    ProxyResponse, ProxyResponseBody, ProxyTunnel, ProxyTunnelOpen,
};
use crate::certificate::LocalTlsIdentityStore;
use crate::config::{ProxyConfig, ProxyLimits, ProxyRoutingMode, ProxyTimeouts};
use crate::endpoint::ProxyEndpoint;
use crate::event::{
    BackendFailureKind, ClientRejectionReason, LifecycleEvent, ObservedHost, ObservedMethod,
    ProxyEvent, ProxyObserver, RequestPhase, RequestRejectionReason, StopReason,
};
use crate::host::HostScopeError;
use crate::http1::{
    AbsoluteTarget, Authority, BodyFraming, Http1Error, RequestHead, RequestTarget, Scheme,
    determine_body_framing, read_request_body, read_request_head, sanitize_forward_headers,
    sanitize_upgrade_forward_headers,
};
use crate::icann::{
    FailClosedIcannNetwork, IcannNetwork, IcannNetworkError, MAX_RESOLVED_ADDRESSES,
};
use crate::listener::{
    ClientHandler, ListenerExitHandler, ListenerExitPhase, ListenerExitReason, OwnedListener,
    RejectionHandler,
};
use crate::metadata::{
    NoopProxyResponseMetadataObserver, ProxyResponseMetadataObservation,
    ProxyResponseMetadataObserver,
};
use crate::rate_limit::{
    RateLimitConfig, RateLimitConfigError, RateLimitDecision, RateLimitScope, RequestRateLimiter,
};
use crate::response::{
    encode_response_head, encode_upgrade_response_head, sanitize_response_headers,
};
use crate::tls::{TlsStream, accept_local_tls};
use hns_core::network_policy::{
    is_browser_blocked_port, is_browser_special_use_host, is_publicly_routable,
};
use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex as StdMutex};
use std::thread::ThreadId;
use std::time::{Duration, Instant};
use thiserror::Error;

const RESPONSE_COPY_BUFFER_BYTES: usize = 16 * 1024;
const TUNNEL_COPY_BUFFER_BYTES: usize = 16 * 1024;
const TUNNEL_CLIENT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const CONNECT_ESTABLISHED_RESPONSE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const MAX_INFORMATIONAL_RESPONSES: usize = 8;
const MAX_ICANN_RESPONSE_HEADERS: usize = 256;
const MAX_ICANN_CHUNK_LINE_BYTES: usize = 8 * 1024;
const MAX_ICANN_TRAILER_BYTES: usize = 64 * 1024;

/// Failure to start a proxy generation. No listener or credential is retained
/// after this error is returned.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("unable to generate mandatory loopback proxy credentials")]
    Authorization(#[source] crate::AuthorizationGenerationError),
    #[error("invalid loopback proxy rate-limit configuration")]
    RateLimit(#[source] RateLimitConfigError),
    #[error("unable to start the IPv4 loopback proxy listener")]
    Listener(#[source] io::Error),
}

/// One owned proxy generation and all of its listener/client work.
pub struct RunningProxy {
    endpoint: ProxyEndpoint,
    listener: OwnedListener,
    tls_identities: Arc<LocalTlsIdentityStore>,
    observer: Arc<dyn ProxyObserver>,
    generation: u64,
    stop_state: Arc<ProxyStopState>,
}

impl RunningProxy {
    /// Starts a fresh authenticated proxy on an operating-system-selected
    /// IPv4 loopback port.
    pub fn start(
        config: ProxyConfig,
        backend: Arc<dyn ProxyBackend>,
        observer: Arc<dyn ProxyObserver>,
    ) -> Result<Self, ProxyError> {
        Self::start_with_metadata_observer(
            config,
            backend,
            observer,
            Arc::new(NoopProxyResponseMetadataObserver),
        )
    }

    /// Starts a fresh authenticated proxy with an independent observer for
    /// trusted metadata removed from validated browser response heads.
    pub fn start_with_metadata_observer(
        config: ProxyConfig,
        backend: Arc<dyn ProxyBackend>,
        observer: Arc<dyn ProxyObserver>,
        metadata_observer: Arc<dyn ProxyResponseMetadataObserver>,
    ) -> Result<Self, ProxyError> {
        Self::start_with_metadata_observer_and_icann_network(
            config,
            backend,
            observer,
            metadata_observer,
            Arc::new(FailClosedIcannNetwork),
        )
    }

    /// Starts with an injectable ICANN resolver/dialer. Scoped generations
    /// never invoke this boundary; whole-browser generations invoke it only
    /// after shared name classification and destination policy checks.
    pub fn start_with_metadata_observer_and_icann_network(
        config: ProxyConfig,
        backend: Arc<dyn ProxyBackend>,
        observer: Arc<dyn ProxyObserver>,
        metadata_observer: Arc<dyn ProxyResponseMetadataObserver>,
        icann_network: Arc<dyn IcannNetwork>,
    ) -> Result<Self, ProxyError> {
        let authorization =
            Arc::new(ProxyAuthorization::generate().map_err(ProxyError::Authorization)?);
        let limits = config.limits();
        let timeouts = config.timeouts();
        let generation = config.instance().generation();
        let rate_limiter =
            RequestRateLimiter::new(rate_limit_config(limits)).map_err(ProxyError::RateLimit)?;
        let cancellation = CancellationToken::new();
        let tls_identities = Arc::new(LocalTlsIdentityStore::new(config.instance().clone()));
        let stop_state = Arc::new(ProxyStopState::new());
        let context = Arc::new(ServerContext {
            authorization: Arc::clone(&authorization),
            hns_scope: config.hns_scope().cloned(),
            routing_mode: config.routing_mode(),
            limits,
            timeouts,
            backend,
            observer: Arc::clone(&observer),
            metadata_observer,
            generation,
            rate_limiter,
            tls_identities: Arc::clone(&tls_identities),
            icann_network,
        });

        let client_context = Arc::clone(&context);
        let client_handler: Arc<ClientHandler> = Arc::new(move |stream, peer, token| {
            handle_client(stream, peer, token, &client_context);
        });
        let rejection_observer = Arc::clone(&observer);
        let rejection_handler: Arc<RejectionHandler> = Arc::new(move |mut stream, _, _| {
            let _result = stream.set_write_timeout(Some(timeouts.socket_timeout()));
            observe(
                rejection_observer.as_ref(),
                ProxyEvent::ClientRejected {
                    generation,
                    reason: ClientRejectionReason::ActiveClientLimit,
                },
            );
            let _result = write_error_response(
                &mut stream,
                429,
                "Too Many Requests",
                &[("Retry-After", "1".to_owned())],
            );
            let _result = stream.shutdown(Shutdown::Both);
        });
        let exit_handler = listener_exit_handler(
            Arc::clone(&tls_identities),
            Arc::clone(&observer),
            generation,
            Arc::clone(&stop_state),
        );

        let listener = OwnedListener::start(
            SocketAddr::V4(config.bind().socket_addr()),
            limits.max_active_clients(),
            cancellation,
            client_handler,
            rejection_handler,
            exit_handler,
        )
        .map_err(ProxyError::Listener)?;
        let endpoint = ProxyEndpoint::new(
            config.instance().clone(),
            listener.local_addr(),
            authorization,
        );
        observe(
            observer.as_ref(),
            ProxyEvent::Lifecycle {
                generation,
                event: LifecycleEvent::Listening {
                    port: endpoint.port(),
                },
            },
        );
        stop_state.publish_listening();

        Ok(Self {
            endpoint,
            listener,
            tls_identities,
            observer,
            generation,
            stop_state,
        })
    }

    pub fn endpoint(&self) -> &ProxyEndpoint {
        &self.endpoint
    }

    pub fn active_clients(&self) -> usize {
        self.listener.active_clients()
    }

    pub fn is_stopped(&self) -> bool {
        self.stop_state.completed.load(Ordering::Acquire)
    }

    pub fn is_stop_requested(&self) -> bool {
        self.stop_state.requested.load(Ordering::Acquire)
    }

    /// Matches a platform proxy-authentication challenge only while this
    /// generation remains live and unrevoked.
    pub fn matches_authentication_challenge(&self, host: &str, port: u16, realm: &str) -> bool {
        !self.is_stop_requested()
            && self.endpoint.matches_challenge(host, port, realm)
            && !self.is_stop_requested()
    }

    /// Returns informational, generation-bound pin metadata after an
    /// authenticated CONNECT has prepared this exact canonical host. The pin
    /// cannot authorize certificate DER; native trust hooks must call
    /// [`Self::matches_local_certificate`] through this live proxy handle.
    pub fn local_certificate_pin(&self, host: &str) -> Option<crate::LocalCertificatePin> {
        if self.stop_state.requested.load(Ordering::Acquire) {
            return None;
        }
        let host = crate::NormalizedHost::parse(host).ok()?;
        self.tls_identities.pin(&host)
    }

    /// Verifies browser challenge DER against the active generation's exact
    /// host identity. Unknown, malformed, oversized, or stopped lookups fail.
    pub fn matches_local_certificate(&self, host: &str, certificate_der: &[u8]) -> bool {
        if self.stop_state.requested.load(Ordering::Acquire) {
            return false;
        }
        let Ok(host) = crate::NormalizedHost::parse(host) else {
            return false;
        };
        self.tls_identities.matches_der(&host, certificate_der)
            && !self.stop_state.requested.load(Ordering::Acquire)
    }

    /// Cancels socket/backend work and, from an external control thread, joins
    /// the listener and every client worker. Repeated and concurrent calls are
    /// safe. A reentrant observer callback requests cancellation; the next
    /// external call completes the join.
    pub fn request_stop(&self) {
        self.stop_state.requested.store(true, Ordering::Release);
        self.listener.request_stop();
        self.tls_identities.deactivate();
    }

    /// Requests immediate revocation and cancellation, then joins the listener
    /// and every client worker. Platform UI threads may call
    /// [`Self::request_stop`] first and complete this blocking join on a
    /// lifecycle worker.
    pub fn stop(&self) {
        self.request_stop();
        if !self
            .stop_state
            .announcement
            .announce(self.observer.as_ref(), self.generation)
        {
            return;
        }
        let joined = self.listener.stop();
        if joined {
            self.stop_state.complete(
                self.observer.as_ref(),
                self.generation,
                StopReason::Requested,
            );
        }
    }
}

struct ProxyStopState {
    requested: AtomicBool,
    completed: AtomicBool,
    announcement: StopAnnouncement,
    listening_published: StdMutex<bool>,
    listening_changed: Condvar,
}

impl ProxyStopState {
    fn new() -> Self {
        Self {
            requested: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            announcement: StopAnnouncement::new(),
            listening_published: StdMutex::new(false),
            listening_changed: Condvar::new(),
        }
    }

    fn publish_listening(&self) {
        let mut published = self
            .listening_published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *published = true;
        self.listening_changed.notify_all();
    }

    fn wait_for_listening(&self) {
        let mut published = self
            .listening_published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while !*published {
            published = self
                .listening_changed
                .wait(published)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    fn complete(&self, observer: &dyn ProxyObserver, generation: u64, reason: StopReason) {
        if !self.completed.swap(true, Ordering::AcqRel) {
            observe(
                observer,
                ProxyEvent::Lifecycle {
                    generation,
                    event: LifecycleEvent::Stopped { reason },
                },
            );
        }
    }
}

struct StopAnnouncement {
    state: StdMutex<StopAnnouncementState>,
    emitted: Condvar,
}

impl StopAnnouncement {
    fn new() -> Self {
        Self {
            state: StdMutex::new(StopAnnouncementState::Pending),
            emitted: Condvar::new(),
        }
    }

    /// Emits `Stopping` exactly once before any concurrent caller can join and
    /// emit `Stopped`. A reentrant call from that observer returns after
    /// revocation instead of waiting on its own announcement.
    fn announce(&self, observer: &dyn ProxyObserver, generation: u64) -> bool {
        let current = std::thread::current().id();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            match &*state {
                StopAnnouncementState::Pending => {
                    *state = StopAnnouncementState::Emitting(current);
                    drop(state);
                    observe(
                        observer,
                        ProxyEvent::Lifecycle {
                            generation,
                            event: LifecycleEvent::Stopping,
                        },
                    );
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *state = StopAnnouncementState::Emitted;
                    self.emitted.notify_all();
                    return true;
                }
                StopAnnouncementState::Emitting(owner) if *owner == current => return false,
                StopAnnouncementState::Emitting(_) => {
                    state = self
                        .emitted
                        .wait(state)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                StopAnnouncementState::Emitted => return true,
            }
        }
    }
}

fn listener_exit_handler(
    tls_identities: Arc<LocalTlsIdentityStore>,
    observer: Arc<dyn ProxyObserver>,
    generation: u64,
    stop_state: Arc<ProxyStopState>,
) -> Arc<ListenerExitHandler> {
    Arc::new(move |phase| match phase {
        ListenerExitPhase::FailureDetected => {
            stop_state.requested.store(true, Ordering::Release);
            tls_identities.deactivate();
            stop_state.wait_for_listening();
            let _announced = stop_state
                .announcement
                .announce(observer.as_ref(), generation);
        }
        ListenerExitPhase::Quiesced(reason) => {
            stop_state.requested.store(true, Ordering::Release);
            tls_identities.deactivate();
            stop_state.wait_for_listening();
            let _announced = stop_state
                .announcement
                .announce(observer.as_ref(), generation);
            let reason = match reason {
                ListenerExitReason::Requested => StopReason::Requested,
                ListenerExitReason::ListenerFailure => StopReason::ListenerFailure,
            };
            stop_state.complete(observer.as_ref(), generation, reason);
        }
    })
}

#[derive(Debug)]
enum StopAnnouncementState {
    Pending,
    Emitting(ThreadId),
    Emitted,
}

impl fmt::Debug for RunningProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunningProxy")
            .field("endpoint", &self.endpoint)
            .field("active_clients", &self.active_clients())
            .field(
                "stop_requested",
                &self.stop_state.requested.load(Ordering::Acquire),
            )
            .field("stop_completed", &self.is_stopped())
            .finish()
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ServerContext {
    authorization: Arc<ProxyAuthorization>,
    hns_scope: Option<crate::HostScope>,
    routing_mode: ProxyRoutingMode,
    limits: ProxyLimits,
    timeouts: ProxyTimeouts,
    backend: Arc<dyn ProxyBackend>,
    observer: Arc<dyn ProxyObserver>,
    metadata_observer: Arc<dyn ProxyResponseMetadataObserver>,
    generation: u64,
    rate_limiter: RequestRateLimiter,
    tls_identities: Arc<LocalTlsIdentityStore>,
    icann_network: Arc<dyn IcannNetwork>,
}

fn handle_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    cancellation: CancellationToken,
    context: &ServerContext,
) {
    if !peer.ip().is_loopback() {
        observe_client_rejection(context, ClientRejectionReason::InvalidPeer);
        let _result = stream.shutdown(Shutdown::Both);
        return;
    }
    if cancellation.is_cancelled() {
        observe_client_rejection(context, ClientRejectionReason::Cancelled);
        let _result = stream.shutdown(Shutdown::Both);
        return;
    }

    let _result = stream.set_nodelay(true);
    if stream
        .set_write_timeout(Some(context.timeouts.socket_timeout()))
        .is_err()
    {
        observe_client_rejection(context, ClientRejectionReason::InvalidRequest);
        return;
    }

    let head = {
        let mut reader =
            DeadlineReader::new(&mut stream, context.timeouts.request_header_timeout());
        match read_request_head(&mut reader, context.limits.max_header_bytes()) {
            Ok(head) => head,
            Err(error) => {
                observe_client_rejection(context, ClientRejectionReason::InvalidRequest);
                let (status, reason) = request_error_status(&error);
                let _result = write_error_response(&mut stream, status, reason, &[]);
                return;
            }
        }
    };

    // Authentication is evaluated before the request target is interpreted,
    // classified, scoped, rate-limited, or sent to the backend.
    if !context
        .authorization
        .verify_header_values(head.header_values(crate::PROXY_AUTHORIZATION_HEADER))
    {
        observe_client_rejection(context, ClientRejectionReason::AuthenticationRequired);
        let _result = write_error_response(
            &mut stream,
            407,
            "Proxy Authentication Required",
            &[(
                crate::PROXY_AUTHENTICATE_HEADER,
                context.authorization.challenge_header_value(),
            )],
        );
        return;
    }

    let target = match head.validated_target(None) {
        Ok(target) => target,
        Err(error) => {
            observe_client_rejection(context, ClientRejectionReason::InvalidRequest);
            let _result =
                write_error_response(&mut stream, error.status_code(), error.reason_phrase(), &[]);
            return;
        }
    };
    let method = ObservedMethod::from_token(head.method());
    let admitted_host = match admit_target_host(context, target.authority().host()) {
        Ok(host) => host,
        Err(error) => {
            let (status_reason, rejection) = route_rejection(error);
            if let Ok(host) = crate::NormalizedHost::parse(target.authority().host()) {
                observe_request(
                    context,
                    &host,
                    method,
                    RequestPhase::Rejected { reason: rejection },
                );
            }
            let _result = write_error_response(&mut stream, 403, status_reason, &[]);
            return;
        }
    };
    if is_browser_blocked_port(target.authority().port()) {
        reject_routed_request(
            &mut stream,
            context,
            admitted_host.as_str(),
            method,
            403,
            "Destination Port Denied",
            RequestRejectionReason::InvalidRequest,
            false,
        );
        return;
    }
    observe_request(
        context,
        admitted_host.as_str(),
        method,
        RequestPhase::Accepted,
    );

    match (admitted_host, target) {
        (AdmittedHost::Hns(canonical_host), RequestTarget::Absolute(absolute)) => {
            handle_direct_http(
                &mut stream,
                &head,
                &absolute,
                &canonical_host,
                method,
                &cancellation,
                context,
            )
        }
        (AdmittedHost::Hns(canonical_host), RequestTarget::Connect(authority)) => handle_connect(
            stream,
            &head,
            authority,
            canonical_host,
            InterceptedConnectClass::Hns,
            method,
            &cancellation,
            context,
        ),
        (AdmittedHost::Icann(icann_host), RequestTarget::Absolute(absolute)) => handle_icann_http(
            &mut stream,
            &head,
            &absolute,
            &icann_host,
            method,
            &cancellation,
            context,
        ),
        (
            AdmittedHost::Icann(icann_host @ IcannHost::Address { .. }),
            RequestTarget::Connect(authority),
        ) => handle_icann_connect(
            stream,
            &head,
            authority,
            icann_host,
            method,
            &cancellation,
            context,
        ),
        (host, RequestTarget::Origin(_)) => reject_routed_request(
            &mut stream,
            context,
            host.as_str(),
            method,
            400,
            "Bad Request",
            RequestRejectionReason::InvalidRequest,
            false,
        ),
    }
}

enum AdmittedHost {
    Hns(crate::NormalizedHost),
    Icann(IcannHost),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InterceptedConnectClass {
    Hns,
    Icann,
}

impl AdmittedHost {
    fn as_str(&self) -> &str {
        match self {
            Self::Hns(host) => host.as_str(),
            Self::Icann(host) => host.as_str(),
        }
    }
}

enum IcannHost {
    Address {
        address: std::net::IpAddr,
        text: String,
    },
}

impl IcannHost {
    fn as_str(&self) -> &str {
        match self {
            Self::Address { text, .. } => text,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteRejection {
    Scope(HostScopeError),
    SpecialUse,
    PrivateAddress,
    InvalidClass,
}

fn admit_target_host(
    context: &ServerContext,
    raw_host: &str,
) -> Result<AdmittedHost, RouteRejection> {
    if context.routing_mode == ProxyRoutingMode::ScopedHns {
        return context
            .hns_scope
            .as_ref()
            .ok_or(RouteRejection::InvalidClass)?
            .authorize(raw_host)
            .map(AdmittedHost::Hns)
            .map_err(RouteRejection::Scope);
    }

    if let Ok(address) = raw_host.parse::<std::net::IpAddr>() {
        if !is_publicly_routable(address) {
            return Err(RouteRejection::PrivateAddress);
        }
        return Ok(AdmittedHost::Icann(IcannHost::Address {
            address,
            text: address.to_string(),
        }));
    }
    let host = crate::NormalizedHost::parse(raw_host)
        .map_err(|error| RouteRejection::Scope(HostScopeError::InvalidHost(error)))?;
    if is_browser_special_use_host(host.as_str()) {
        Err(RouteRejection::SpecialUse)
    } else {
        // Every syntactically valid DNS name enters the shared authenticated
        // backend. The backend retains the complete dual-root plan; the
        // loopback boundary must never route from a suffix/IANA classifier.
        Ok(AdmittedHost::Hns(host))
    }
}

#[derive(Clone, Copy)]
struct HttpRoute<'a> {
    scheme: Scheme,
    authority: &'a Authority,
    path_and_query: &'a str,
}

#[allow(clippy::too_many_arguments)]
fn handle_direct_http(
    stream: &mut TcpStream,
    head: &RequestHead,
    absolute: &AbsoluteTarget,
    canonical_host: &crate::NormalizedHost,
    method: ObservedMethod,
    cancellation: &CancellationToken,
    context: &ServerContext,
) {
    let route = HttpRoute {
        scheme: absolute.scheme(),
        authority: absolute.authority(),
        path_and_query: absolute.path_and_query(),
    };
    let is_upgrade =
        matches!(absolute.scheme(), Scheme::Ws | Scheme::Wss) || requests_upgrade(head);
    let likely_main_frame =
        !is_upgrade && is_likely_main_frame_navigation(head, route.path_and_query);
    if !admit_rate(stream, context, canonical_host, method, likely_main_frame) {
        return;
    }

    if is_upgrade {
        handle_admitted_upgrade(
            stream,
            head,
            route,
            canonical_host,
            method,
            cancellation,
            context,
        );
    } else {
        handle_admitted_http(
            stream,
            head,
            route,
            canonical_host,
            method,
            cancellation,
            context,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_icann_http(
    stream: &mut TcpStream,
    head: &RequestHead,
    absolute: &AbsoluteTarget,
    host: &IcannHost,
    method: ObservedMethod,
    cancellation: &CancellationToken,
    context: &ServerContext,
) {
    let route = HttpRoute {
        scheme: absolute.scheme(),
        authority: absolute.authority(),
        path_and_query: absolute.path_and_query(),
    };
    if !matches!(route.scheme, Scheme::Http | Scheme::Ws) {
        reject_routed_request(
            stream,
            context,
            host.as_str(),
            method,
            400,
            "ICANN HTTPS Requires CONNECT",
            RequestRejectionReason::InvalidRequest,
            false,
        );
        return;
    }
    if is_browser_blocked_port(route.authority.port()) {
        reject_routed_request(
            stream,
            context,
            host.as_str(),
            method,
            403,
            "ICANN Destination Port Denied",
            RequestRejectionReason::InvalidRequest,
            false,
        );
        return;
    }
    let is_upgrade = route.scheme == Scheme::Ws || requests_upgrade(head);
    let likely_main_frame =
        !is_upgrade && is_likely_main_frame_navigation(head, route.path_and_query);
    if !admit_rate(stream, context, host.as_str(), method, likely_main_frame) {
        return;
    }
    if is_upgrade {
        handle_icann_upgrade(stream, head, route, host, method, cancellation, context);
    } else {
        handle_icann_request(
            stream,
            head,
            route,
            host,
            method,
            likely_main_frame,
            cancellation,
            context,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_icann_connect(
    mut client: TcpStream,
    head: &RequestHead,
    authority: Authority,
    host: IcannHost,
    method: ObservedMethod,
    cancellation: &CancellationToken,
    context: &ServerContext,
) {
    if requests_upgrade(head) || head.header_values("expect").next().is_some() {
        reject_routed_request(
            &mut client,
            context,
            host.as_str(),
            method,
            400,
            "Invalid ICANN CONNECT",
            RequestRejectionReason::InvalidRequest,
            false,
        );
        return;
    }
    let framing = match determine_body_framing(head.headers()) {
        Ok(framing) => framing,
        Err(error) => {
            let (status, reason) = request_error_status(&error);
            reject_routed_request(
                &mut client,
                context,
                host.as_str(),
                method,
                status,
                reason,
                RequestRejectionReason::InvalidRequest,
                false,
            );
            return;
        }
    };
    if !matches!(framing, BodyFraming::None | BodyFraming::ContentLength(0)) {
        reject_routed_request(
            &mut client,
            context,
            host.as_str(),
            method,
            400,
            "ICANN CONNECT Body Unsupported",
            RequestRejectionReason::InvalidRequest,
            false,
        );
        return;
    }
    if is_browser_blocked_port(authority.port()) {
        reject_routed_request(
            &mut client,
            context,
            host.as_str(),
            method,
            403,
            "ICANN Destination Port Denied",
            RequestRejectionReason::InvalidRequest,
            false,
        );
        return;
    }
    if !admit_rate(&mut client, context, host.as_str(), method, false) {
        return;
    }

    let started = Instant::now();
    let mut origin = match dial_icann(&host, authority.port(), cancellation, context) {
        Ok(origin) => origin,
        Err(error) => {
            observe_icann_failure(context, host.as_str(), method, started, error);
            if !cancellation.is_cancelled() {
                let (status, reason) = icann_route_error_response(error);
                let _result = write_error_response(&mut client, status, reason, &[]);
            }
            return;
        }
    };
    if client.clear_client_read_deadline().is_err()
        || client.write_all(CONNECT_ESTABLISHED_RESPONSE).is_err()
        || client.flush().is_err()
    {
        return;
    }
    observe_request(
        context,
        host.as_str(),
        method,
        RequestPhase::Completed {
            status_code: 200,
            elapsed: started.elapsed(),
        },
    );
    let _outcome = pump_tunnel(&mut client, origin.as_mut(), cancellation);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IcannRouteError {
    Cancelled,
    Resolution,
    AddressDenied,
    Connection,
    InvalidResponse,
}

fn dial_icann(
    host: &IcannHost,
    port: u16,
    cancellation: &CancellationToken,
    context: &ServerContext,
) -> Result<Box<dyn crate::ProxyTunnelIo>, IcannRouteError> {
    if cancellation.is_cancelled() {
        return Err(IcannRouteError::Cancelled);
    }
    let addresses = match host {
        IcannHost::Address { address, .. } => vec![SocketAddr::new(*address, port)],
    };
    if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ADDRESSES {
        return Err(IcannRouteError::Resolution);
    }
    let mut unique = HashSet::new();
    let mut public = Vec::new();
    for address in addresses {
        if address.port() != port || !is_publicly_routable(address.ip()) {
            continue;
        }
        if unique.insert(address) {
            public.push(address);
        }
    }
    if public.is_empty() {
        return Err(IcannRouteError::AddressDenied);
    }

    let now = Instant::now();
    let deadline = now
        .checked_add(context.timeouts.socket_timeout())
        .unwrap_or(now);
    for address in public {
        if cancellation.is_cancelled() {
            return Err(IcannRouteError::Cancelled);
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(IcannRouteError::Connection);
        };
        if remaining.is_zero() {
            return Err(IcannRouteError::Connection);
        }
        let connected = catch_unwind(AssertUnwindSafe(|| {
            context
                .icann_network
                .connect(address, remaining, cancellation)
        }))
        .unwrap_or(Err(IcannNetworkError::ConnectionFailed));
        match connected {
            Ok(stream) => return Ok(stream),
            Err(IcannNetworkError::Cancelled) => return Err(IcannRouteError::Cancelled),
            Err(IcannNetworkError::ResolutionFailed | IcannNetworkError::ConnectionFailed) => {}
        }
    }
    Err(IcannRouteError::Connection)
}

#[allow(clippy::too_many_arguments)]
fn handle_icann_request(
    client: &mut TcpStream,
    head: &RequestHead,
    route: HttpRoute<'_>,
    host: &IcannHost,
    method: ObservedMethod,
    likely_main_frame: bool,
    cancellation: &CancellationToken,
    context: &ServerContext,
) {
    let started = Instant::now();
    let framing = match determine_body_framing(head.headers()) {
        Ok(framing) => framing,
        Err(error) => {
            reject_icann_http_error(client, context, host, method, likely_main_frame, &error);
            return;
        }
    };
    if matches!(framing, BodyFraming::ContentLength(length) if length > context.limits.max_body_bytes())
    {
        reject_icann_http_error(
            client,
            context,
            host,
            method,
            likely_main_frame,
            &Http1Error::BodyTooLarge,
        );
        return;
    }
    let expects_continue = match expects_continue(head) {
        Ok(value) => value,
        Err(()) => {
            reject_routed_request(
                client,
                context,
                host.as_str(),
                method,
                417,
                "Expectation Failed",
                RequestRejectionReason::InvalidRequest,
                likely_main_frame,
            );
            return;
        }
    };
    let headers = match build_icann_forward_headers(head, route, host.as_str(), false) {
        Ok(headers) => headers,
        Err(error) => {
            reject_icann_http_error(client, context, host, method, likely_main_frame, &error);
            return;
        }
    };
    if expects_continue
        && !matches!(framing, BodyFraming::None)
        && (client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() || client.flush().is_err())
    {
        return;
    }
    let body = {
        let mut reader = DeadlineReader::new(client, context.timeouts.socket_timeout());
        match read_request_body(&mut reader, framing, context.limits.max_body_bytes()) {
            Ok(body) => body,
            Err(error) => {
                reject_icann_http_error(client, context, host, method, likely_main_frame, &error);
                return;
            }
        }
    };
    if client.clear_client_read_deadline().is_err() || cancellation.is_cancelled() {
        return;
    }
    let request = match encode_icann_request(
        head.method(),
        route.path_and_query,
        &headers,
        (!matches!(framing, BodyFraming::None)).then_some(body.len()),
        false,
        context.limits.max_header_bytes(),
    ) {
        Ok(request) => request,
        Err(()) => {
            reject_routed_request(
                client,
                context,
                host.as_str(),
                method,
                400,
                "Invalid ICANN Request",
                RequestRejectionReason::InvalidRequest,
                likely_main_frame,
            );
            return;
        }
    };
    let mut origin = match dial_icann(host, route.authority.port(), cancellation, context) {
        Ok(origin) => origin,
        Err(error) => {
            observe_icann_failure(context, host.as_str(), method, started, error);
            if !cancellation.is_cancelled() {
                let (status, reason) = icann_route_error_response(error);
                observe_proxy_generated_response(
                    context,
                    host.as_str(),
                    method,
                    status,
                    likely_main_frame,
                );
                let _result = write_error_response(client, status, reason, &[]);
            }
            return;
        }
    };
    if origin.write_all(&request).is_err()
        || (!body.is_empty() && origin.write_all(&body).is_err())
        || origin.flush().is_err()
    {
        observe_icann_failure(
            context,
            host.as_str(),
            method,
            started,
            IcannRouteError::Connection,
        );
        if !cancellation.is_cancelled() {
            let _result = write_error_response(client, 502, "ICANN Upstream Unavailable", &[]);
        }
        return;
    }

    let result = relay_icann_response(
        client,
        origin.as_mut(),
        head.method(),
        cancellation,
        context,
    );
    match result {
        Ok(status_code) => observe_request(
            context,
            host.as_str(),
            method,
            RequestPhase::Completed {
                status_code,
                elapsed: started.elapsed(),
            },
        ),
        Err(error) => {
            observe_icann_failure(context, host.as_str(), method, started, error);
            if !cancellation.is_cancelled() {
                observe_proxy_generated_response(
                    context,
                    host.as_str(),
                    method,
                    502,
                    likely_main_frame,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_icann_upgrade(
    client: &mut TcpStream,
    head: &RequestHead,
    route: HttpRoute<'_>,
    host: &IcannHost,
    method: ObservedMethod,
    cancellation: &CancellationToken,
    context: &ServerContext,
) {
    let started = Instant::now();
    let framing = match determine_body_framing(head.headers()) {
        Ok(framing) => framing,
        Err(error) => {
            reject_icann_http_error(client, context, host, method, false, &error);
            return;
        }
    };
    if !matches!(framing, BodyFraming::None | BodyFraming::ContentLength(0))
        || head.header_values("expect").next().is_some()
    {
        reject_routed_request(
            client,
            context,
            host.as_str(),
            method,
            400,
            "ICANN Protocol Upgrade Body Unsupported",
            RequestRejectionReason::InvalidRequest,
            false,
        );
        return;
    }
    let headers = match build_icann_forward_headers(head, route, host.as_str(), true) {
        Ok(headers) => headers,
        Err(error) => {
            reject_icann_http_error(client, context, host, method, false, &error);
            return;
        }
    };
    let request = match encode_icann_request(
        head.method(),
        route.path_and_query,
        &headers,
        None,
        true,
        context.limits.max_header_bytes(),
    ) {
        Ok(request) => request,
        Err(()) => {
            reject_routed_request(
                client,
                context,
                host.as_str(),
                method,
                400,
                "Invalid ICANN Upgrade Request",
                RequestRejectionReason::InvalidRequest,
                false,
            );
            return;
        }
    };
    if client.clear_client_read_deadline().is_err() || cancellation.is_cancelled() {
        return;
    }
    let mut origin = match dial_icann(host, route.authority.port(), cancellation, context) {
        Ok(origin) => origin,
        Err(error) => {
            observe_icann_failure(context, host.as_str(), method, started, error);
            if !cancellation.is_cancelled() {
                let (status, reason) = icann_route_error_response(error);
                let _result = write_error_response(client, status, reason, &[]);
            }
            return;
        }
    };
    if origin.write_all(&request).is_err() || origin.flush().is_err() {
        observe_icann_failure(
            context,
            host.as_str(),
            method,
            started,
            IcannRouteError::Connection,
        );
        return;
    }
    let response = {
        let mut reader = InactivityReader::new(
            origin.as_mut(),
            cancellation,
            context.timeouts.socket_timeout(),
        );
        read_icann_response_head(
            &mut reader,
            head.method(),
            true,
            context.limits.max_header_bytes(),
        )
    };
    let response = match response {
        Ok(response) if response.status == 101 => response,
        Ok(_) | Err(_) => {
            observe_icann_failure(
                context,
                host.as_str(),
                method,
                started,
                IcannRouteError::InvalidResponse,
            );
            if !cancellation.is_cancelled() {
                let _result =
                    write_error_response(client, 502, "Invalid ICANN Upgrade Response", &[]);
            }
            return;
        }
    };
    let encoded =
        match encode_upgrade_response_head(response.status, &response.reason, &response.headers) {
            Ok(encoded) => encoded,
            Err(_error) => {
                observe_icann_failure(
                    context,
                    host.as_str(),
                    method,
                    started,
                    IcannRouteError::InvalidResponse,
                );
                if !cancellation.is_cancelled() {
                    let _result =
                        write_error_response(client, 502, "Invalid ICANN Upgrade Response", &[]);
                }
                return;
            }
        };
    if client.write_all(encoded.as_bytes()).is_err() || client.flush().is_err() {
        return;
    }
    match pump_tunnel(client, origin.as_mut(), cancellation) {
        TunnelPumpOutcome::Completed => observe_request(
            context,
            host.as_str(),
            method,
            RequestPhase::Completed {
                status_code: 101,
                elapsed: started.elapsed(),
            },
        ),
        TunnelPumpOutcome::OriginIo => observe_icann_failure(
            context,
            host.as_str(),
            method,
            started,
            IcannRouteError::Connection,
        ),
        TunnelPumpOutcome::ClientIo | TunnelPumpOutcome::Cancelled => {}
    }
}

fn build_icann_forward_headers(
    head: &RequestHead,
    route: HttpRoute<'_>,
    host: &str,
    upgrade: bool,
) -> Result<Vec<ProxyHeader>, Http1Error> {
    let sanitized = if upgrade {
        sanitize_upgrade_forward_headers(head.headers())?
    } else {
        sanitize_forward_headers(head.headers())?
    };
    let mut headers: Vec<_> = sanitized
        .into_iter()
        .filter(|header| {
            !header.name().eq_ignore_ascii_case("host")
                && !header.name().eq_ignore_ascii_case("content-length")
                && !header.name().eq_ignore_ascii_case("expect")
                && (upgrade || !header.name().eq_ignore_ascii_case("connection"))
        })
        .map(|header| ProxyHeader::new(header.name(), header.value()))
        .collect();
    let host_value = if host.contains(':') {
        if route.authority.port() == route.scheme.default_port() {
            format!("[{host}]")
        } else {
            format!("[{host}]:{}", route.authority.port())
        }
    } else if route.authority.port() == route.scheme.default_port() {
        host.to_owned()
    } else {
        format!("{host}:{}", route.authority.port())
    };
    headers.push(ProxyHeader::new("Host", host_value));
    Ok(headers)
}

fn encode_icann_request(
    method: &str,
    path_and_query: &str,
    headers: &[ProxyHeader],
    body_len: Option<usize>,
    upgrade: bool,
    max_header_bytes: usize,
) -> Result<Vec<u8>, ()> {
    let mut out = format!("{method} {path_and_query} HTTP/1.1\r\n").into_bytes();
    for header in headers {
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !upgrade {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    if let Some(body_len) = body_len {
        out.extend_from_slice(format!("Content-Length: {body_len}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    if out.len() > max_header_bytes {
        return Err(());
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IcannResponseFraming {
    NoBody { declared_length: Option<u64> },
    ContentLength(u64),
    Chunked,
    CloseDelimited,
    Upgrade,
}

struct IcannResponseHead {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    framing: IcannResponseFraming,
}

fn relay_icann_response(
    client: &mut TcpStream,
    origin: &mut dyn crate::ProxyTunnelIo,
    request_method: &str,
    cancellation: &CancellationToken,
    context: &ServerContext,
) -> Result<u16, IcannRouteError> {
    let mut reader = InactivityReader::new(origin, cancellation, context.timeouts.socket_timeout());
    let response = match read_icann_response_head(
        &mut reader,
        request_method,
        false,
        context.limits.max_header_bytes(),
    ) {
        Ok(response) => response,
        Err(error) => {
            if !cancellation.is_cancelled() {
                let _result = write_error_response(client, 502, "Invalid ICANN Response", &[]);
            }
            return Err(error);
        }
    };
    let status = response.status;
    let sanitized = match sanitize_response_headers(&response.headers) {
        Ok(headers) => headers,
        Err(_error) => {
            if !cancellation.is_cancelled() {
                let _result = write_error_response(client, 502, "Invalid ICANN Response", &[]);
            }
            return Err(IcannRouteError::InvalidResponse);
        }
    };
    let encoded = match encode_icann_response_head(&response, &sanitized, request_method) {
        Ok(encoded) => encoded,
        Err(()) => {
            if !cancellation.is_cancelled() {
                let _result = write_error_response(client, 502, "Invalid ICANN Response", &[]);
            }
            return Err(IcannRouteError::InvalidResponse);
        }
    };
    client
        .write_all(&encoded)
        .map_err(|_error| IcannRouteError::Connection)?;
    match response.framing {
        IcannResponseFraming::NoBody { .. } => {}
        IcannResponseFraming::ContentLength(length) => {
            relay_exact_body(&mut reader, client, length)?;
        }
        IcannResponseFraming::Chunked => {
            relay_chunked_body(&mut reader, client)?;
        }
        IcannResponseFraming::CloseDelimited => {
            relay_close_delimited_body(&mut reader, client)?;
        }
        IcannResponseFraming::Upgrade => return Err(IcannRouteError::InvalidResponse),
    }
    client
        .flush()
        .map_err(|_error| IcannRouteError::Connection)?;
    Ok(status)
}

fn read_icann_response_head(
    reader: &mut impl Read,
    request_method: &str,
    allow_upgrade: bool,
    max_header_bytes: usize,
) -> Result<IcannResponseHead, IcannRouteError> {
    let mut informational = 0_usize;
    loop {
        let bytes = read_icann_head_bytes(reader, max_header_bytes)?;
        let mut parsed_headers = [httparse::EMPTY_HEADER; MAX_ICANN_RESPONSE_HEADERS];
        let mut parsed = httparse::Response::new(&mut parsed_headers);
        let parsed_len = match parsed.parse(&bytes) {
            Ok(httparse::Status::Complete(length)) => length,
            Ok(httparse::Status::Partial) | Err(_) => {
                return Err(IcannRouteError::InvalidResponse);
            }
        };
        if parsed_len != bytes.len() || !has_strict_crlf(&bytes) {
            return Err(IcannRouteError::InvalidResponse);
        }
        let status = parsed.code.ok_or(IcannRouteError::InvalidResponse)?;
        let version = parsed.version.ok_or(IcannRouteError::InvalidResponse)?;
        if version > 1 || !(100..=599).contains(&status) {
            return Err(IcannRouteError::InvalidResponse);
        }
        let reason = parsed.reason.unwrap_or_default().to_owned();
        let mut headers = Vec::with_capacity(parsed.headers.len());
        for header in parsed.headers {
            let value = std::str::from_utf8(header.value)
                .map_err(|_error| IcannRouteError::InvalidResponse)?;
            headers.push((header.name.to_owned(), value.to_owned()));
        }
        if (100..200).contains(&status) {
            if status == 101 {
                if !allow_upgrade {
                    return Err(IcannRouteError::InvalidResponse);
                }
                return Ok(IcannResponseHead {
                    status,
                    reason,
                    headers,
                    framing: IcannResponseFraming::Upgrade,
                });
            }
            if response_content_length(&headers)?.is_some()
                || response_is_chunked(&headers)?.is_some()
            {
                return Err(IcannRouteError::InvalidResponse);
            }
            informational = informational.saturating_add(1);
            if informational > MAX_INFORMATIONAL_RESPONSES {
                return Err(IcannRouteError::InvalidResponse);
            }
            continue;
        }
        let content_length = response_content_length(&headers)?;
        let chunked = response_is_chunked(&headers)?;
        if chunked.is_some() && content_length.is_some() {
            return Err(IcannRouteError::InvalidResponse);
        }
        let no_body =
            request_method.eq_ignore_ascii_case("HEAD") || matches!(status, 204 | 205 | 304);
        if matches!(status, 204 | 205)
            && (content_length.is_some_and(|length| length != 0) || chunked.is_some())
        {
            return Err(IcannRouteError::InvalidResponse);
        }
        let framing = if no_body {
            IcannResponseFraming::NoBody {
                declared_length: content_length,
            }
        } else if chunked.is_some() {
            IcannResponseFraming::Chunked
        } else if let Some(length) = content_length {
            IcannResponseFraming::ContentLength(length)
        } else {
            IcannResponseFraming::CloseDelimited
        };
        return Ok(IcannResponseHead {
            status,
            reason,
            headers,
            framing,
        });
    }
}

fn read_icann_head_bytes(
    reader: &mut impl Read,
    max_header_bytes: usize,
) -> Result<Vec<u8>, IcannRouteError> {
    let mut bytes = Vec::with_capacity(max_header_bytes.min(8 * 1024));
    let mut byte = [0_u8; 1];
    while bytes.len() < max_header_bytes {
        match reader.read(&mut byte) {
            Ok(0) => return Err(IcannRouteError::InvalidResponse),
            Ok(1) => bytes.push(byte[0]),
            Ok(_) => return Err(IcannRouteError::InvalidResponse),
            Err(_error) => return Err(IcannRouteError::Connection),
        }
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
    Err(IcannRouteError::InvalidResponse)
}

fn has_strict_crlf(bytes: &[u8]) -> bool {
    bytes.iter().enumerate().all(|(index, byte)| match byte {
        b'\r' => bytes.get(index + 1) == Some(&b'\n'),
        b'\n' => index > 0 && bytes.get(index - 1) == Some(&b'\r'),
        _ => true,
    })
}

fn response_content_length(headers: &[(String, String)]) -> Result<Option<u64>, IcannRouteError> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str());
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some()
        || value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(IcannRouteError::InvalidResponse);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_error| IcannRouteError::InvalidResponse)
}

fn response_is_chunked(headers: &[(String, String)]) -> Result<Option<()>, IcannRouteError> {
    let values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, value)| value.as_str())
        .collect();
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 1 || !values[0].eq_ignore_ascii_case("chunked") {
        return Err(IcannRouteError::InvalidResponse);
    }
    Ok(Some(()))
}

fn encode_icann_response_head(
    response: &IcannResponseHead,
    headers: &crate::SanitizedResponseHeaders,
    request_method: &str,
) -> Result<Vec<u8>, ()> {
    if !(200..=599).contains(&response.status)
        || !response
            .reason
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
    {
        return Err(());
    }
    let mut encoded = format!("HTTP/1.1 {} {}\r\n", response.status, response.reason).into_bytes();
    for (name, value) in headers.forwarded() {
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(b": ");
        encoded.extend_from_slice(value.as_bytes());
        encoded.extend_from_slice(b"\r\n");
    }
    encoded.extend_from_slice(b"Connection: close\r\n");
    match response.framing {
        IcannResponseFraming::ContentLength(length) => {
            encoded.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
        }
        IcannResponseFraming::NoBody {
            declared_length: Some(length),
        } if request_method.eq_ignore_ascii_case("HEAD") => {
            encoded.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
        }
        IcannResponseFraming::NoBody { .. }
        | IcannResponseFraming::Chunked
        | IcannResponseFraming::CloseDelimited => {}
        IcannResponseFraming::Upgrade => return Err(()),
    }
    encoded.extend_from_slice(b"\r\n");
    if encoded.len() > ProxyLimits::DEFAULT_MAX_HEADER_BYTES {
        return Err(());
    }
    Ok(encoded)
}

fn relay_exact_body(
    reader: &mut impl Read,
    client: &mut impl Write,
    mut remaining: u64,
) -> Result<(), IcannRouteError> {
    let mut buffer = [0_u8; RESPONSE_COPY_BUFFER_BYTES];
    while remaining != 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_error| IcannRouteError::InvalidResponse)?;
        let count = reader
            .read(&mut buffer[..limit])
            .map_err(|_error| IcannRouteError::Connection)?;
        if count == 0 || count > limit {
            return Err(IcannRouteError::InvalidResponse);
        }
        client
            .write_all(&buffer[..count])
            .map_err(|_error| IcannRouteError::Connection)?;
        remaining = remaining
            .checked_sub(count as u64)
            .ok_or(IcannRouteError::InvalidResponse)?;
    }
    Ok(())
}

fn relay_close_delimited_body(
    reader: &mut impl Read,
    client: &mut impl Write,
) -> Result<(), IcannRouteError> {
    let mut buffer = [0_u8; RESPONSE_COPY_BUFFER_BYTES];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_error| IcannRouteError::Connection)?;
        if count == 0 {
            return Ok(());
        }
        if count > buffer.len() {
            return Err(IcannRouteError::InvalidResponse);
        }
        client
            .write_all(&buffer[..count])
            .map_err(|_error| IcannRouteError::Connection)?;
    }
}

fn relay_chunked_body(
    reader: &mut impl Read,
    client: &mut impl Write,
) -> Result<(), IcannRouteError> {
    loop {
        let line = read_icann_crlf_line(reader, MAX_ICANN_CHUNK_LINE_BYTES)?;
        let (size, extensions) = match line.iter().position(|byte| *byte == b';') {
            Some(index) => (&line[..index], &line[index + 1..]),
            None => (line.as_slice(), [].as_slice()),
        };
        if size.is_empty()
            || !size.iter().all(u8::is_ascii_hexdigit)
            || extensions.iter().any(|byte| !(0x20..=0x7e).contains(byte))
        {
            return Err(IcannRouteError::InvalidResponse);
        }
        let size = std::str::from_utf8(size)
            .ok()
            .and_then(|size| u64::from_str_radix(size, 16).ok())
            .ok_or(IcannRouteError::InvalidResponse)?;
        if size == 0 {
            read_icann_trailers(reader)?;
            return Ok(());
        }
        relay_exact_body(reader, client, size)?;
        let mut crlf = [0_u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|_error| IcannRouteError::InvalidResponse)?;
        if crlf != *b"\r\n" {
            return Err(IcannRouteError::InvalidResponse);
        }
    }
}

fn read_icann_trailers(reader: &mut impl Read) -> Result<(), IcannRouteError> {
    let mut consumed = 0_usize;
    let mut fields = 0_usize;
    loop {
        let remaining = MAX_ICANN_TRAILER_BYTES
            .checked_sub(consumed)
            .ok_or(IcannRouteError::InvalidResponse)?;
        let line = read_icann_crlf_line(reader, remaining.min(MAX_ICANN_CHUNK_LINE_BYTES))?;
        consumed = consumed
            .checked_add(line.len() + 2)
            .ok_or(IcannRouteError::InvalidResponse)?;
        if line.is_empty() {
            return Ok(());
        }
        fields = fields.saturating_add(1);
        if fields > MAX_ICANN_RESPONSE_HEADERS
            || !line.contains(&b':')
            || line.iter().any(|byte| *byte < 0x20 && *byte != b'\t')
        {
            return Err(IcannRouteError::InvalidResponse);
        }
    }
}

fn read_icann_crlf_line(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, IcannRouteError> {
    let mut line = Vec::with_capacity(limit.min(256));
    let mut byte = [0_u8; 1];
    while line.len() < limit {
        reader
            .read_exact(&mut byte)
            .map_err(|_error| IcannRouteError::InvalidResponse)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
        if byte[0] == b'\n' {
            return Err(IcannRouteError::InvalidResponse);
        }
    }
    Err(IcannRouteError::InvalidResponse)
}

struct InactivityReader<'a> {
    inner: &'a mut dyn crate::ProxyTunnelIo,
    cancellation: &'a CancellationToken,
    timeout: Duration,
    deadline: Instant,
}

impl<'a> InactivityReader<'a> {
    fn new(
        inner: &'a mut dyn crate::ProxyTunnelIo,
        cancellation: &'a CancellationToken,
        timeout: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            inner,
            cancellation,
            timeout,
            deadline: now.checked_add(timeout).unwrap_or(now),
        }
    }
}

impl Read for InactivityReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.cancellation.is_cancelled() {
                return Err(io::Error::new(
                    // `Read::read_exact` transparently retries `Interrupted`.
                    // Cancellation must be terminal so chunk framing and
                    // trailer reads unwind instead of spinning forever.
                    io::ErrorKind::ConnectionAborted,
                    "proxy cancelled",
                ));
            }
            match self.inner.read(buffer) {
                Ok(count) => {
                    if count != 0 {
                        let now = Instant::now();
                        self.deadline = now.checked_add(self.timeout).unwrap_or(now);
                    }
                    return Ok(count);
                }
                Err(error) if retryable_tunnel_read(&error) && Instant::now() < self.deadline => {}
                Err(error) => return Err(error),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_connect(
    mut stream: TcpStream,
    head: &RequestHead,
    authority: Authority,
    canonical_host: crate::NormalizedHost,
    host_class: InterceptedConnectClass,
    method: ObservedMethod,
    cancellation: &CancellationToken,
    context: &ServerContext,
) {
    if requests_upgrade(head) {
        reject_scoped_request(
            &mut stream,
            context,
            &canonical_host,
            method,
            501,
            match host_class {
                InterceptedConnectClass::Hns => "HNS Protocol Upgrade Unsupported",
                InterceptedConnectClass::Icann => "ICANN Protocol Upgrade Unsupported",
            },
            RequestRejectionReason::InvalidRequest,
        );
        return;
    }
    if head.header_values("expect").next().is_some() {
        reject_scoped_request(
            &mut stream,
            context,
            &canonical_host,
            method,
            417,
            "Expectation Failed",
            RequestRejectionReason::InvalidRequest,
        );
        return;
    }
    let framing = match determine_body_framing(head.headers()) {
        Ok(framing) => framing,
        Err(error) => {
            reject_http_request(&mut stream, context, &canonical_host, method, &error);
            return;
        }
    };
    if !matches!(framing, BodyFraming::None | BodyFraming::ContentLength(0)) {
        reject_scoped_request(
            &mut stream,
            context,
            &canonical_host,
            method,
            400,
            match host_class {
                InterceptedConnectClass::Hns => "HNS CONNECT Body Unsupported",
                InterceptedConnectClass::Icann => "ICANN CONNECT Body Unsupported",
            },
            RequestRejectionReason::InvalidRequest,
        );
        return;
    }
    if host_class == InterceptedConnectClass::Icann && is_browser_blocked_port(authority.port()) {
        reject_scoped_request(
            &mut stream,
            context,
            &canonical_host,
            method,
            403,
            "ICANN Destination Port Denied",
            RequestRejectionReason::InvalidRequest,
        );
        return;
    }
    if cancellation.is_cancelled() {
        observe_request(
            context,
            &canonical_host,
            method,
            RequestPhase::Rejected {
                reason: RequestRejectionReason::Cancelled,
            },
        );
        return;
    }
    if !admit_rate(&mut stream, context, &canonical_host, method, false) {
        return;
    }

    let identity = match context.tls_identities.prepare(&canonical_host) {
        Ok(identity) => identity,
        Err(_error) => {
            reject_scoped_request(
                &mut stream,
                context,
                &canonical_host,
                method,
                503,
                match host_class {
                    InterceptedConnectClass::Hns => "HNS Local TLS Unavailable",
                    InterceptedConnectClass::Icann => "ICANN Local TLS Unavailable",
                },
                RequestRejectionReason::InvalidRequest,
            );
            return;
        }
    };
    debug_assert_eq!(identity.pin().host(), &canonical_host);
    let started = Instant::now();
    if stream.write_all(CONNECT_ESTABLISHED_RESPONSE).is_err() || stream.flush().is_err() {
        return;
    }

    let mut tls = match accept_local_tls(
        stream,
        &identity,
        &canonical_host,
        context.timeouts.socket_timeout(),
        cancellation,
    ) {
        Ok(tls) => tls,
        Err(_error) => {
            let reason = if cancellation.is_cancelled() {
                RequestRejectionReason::Cancelled
            } else {
                RequestRejectionReason::InvalidRequest
            };
            observe_request(
                context,
                &canonical_host,
                method,
                RequestPhase::Rejected { reason },
            );
            return;
        }
    };
    observe_request(
        context,
        &canonical_host,
        method,
        RequestPhase::Completed {
            status_code: 200,
            elapsed: started.elapsed(),
        },
    );
    handle_connected_http(
        &mut tls,
        &authority,
        &canonical_host,
        host_class,
        cancellation,
        context,
    );
    tls.conn.send_close_notify();
    let _result = tls.flush();
}

fn handle_connected_http(
    stream: &mut TlsStream,
    connected_to: &Authority,
    outer_host: &crate::NormalizedHost,
    host_class: InterceptedConnectClass,
    cancellation: &CancellationToken,
    context: &ServerContext,
) {
    let head = {
        let mut reader = DeadlineReader::new(stream, context.timeouts.request_header_timeout());
        match read_request_head(&mut reader, context.limits.max_header_bytes()) {
            Ok(head) => head,
            Err(error) => {
                reject_http_request(stream, context, outer_host, ObservedMethod::Other, &error);
                return;
            }
        }
    };
    let method = ObservedMethod::from_token(head.method());
    let target = match head.validated_target(Some(connected_to)) {
        Ok(target) => target,
        Err(error) => {
            reject_http_request(stream, context, outer_host, method, &error);
            return;
        }
    };
    let canonical_host = match authorize_connected_target(
        context,
        target.authority(),
        connected_to,
        outer_host,
        host_class,
    ) {
        Some(host) => host,
        None => {
            reject_scoped_request(
                stream,
                context,
                outer_host,
                method,
                403,
                match host_class {
                    InterceptedConnectClass::Hns => "HNS Proxy Scope Denied",
                    InterceptedConnectClass::Icann => "ICANN Proxy Scope Denied",
                },
                RequestRejectionReason::HostOutsideScope,
            );
            return;
        }
    };
    observe_request(context, &canonical_host, method, RequestPhase::Accepted);

    match target {
        RequestTarget::Origin(origin) => {
            let route = HttpRoute {
                scheme: Scheme::Https,
                authority: origin.authority(),
                path_and_query: origin.path_and_query(),
            };
            if requests_upgrade(&head) {
                handle_admitted_upgrade(
                    stream,
                    &head,
                    route,
                    &canonical_host,
                    method,
                    cancellation,
                    context,
                );
            } else {
                handle_admitted_http(
                    stream,
                    &head,
                    route,
                    &canonical_host,
                    method,
                    cancellation,
                    context,
                );
            }
        }
        RequestTarget::Absolute(absolute)
            if matches!(absolute.scheme(), Scheme::Https | Scheme::Wss) =>
        {
            let route = HttpRoute {
                scheme: absolute.scheme(),
                authority: absolute.authority(),
                path_and_query: absolute.path_and_query(),
            };
            if absolute.scheme() == Scheme::Wss || requests_upgrade(&head) {
                handle_admitted_upgrade(
                    stream,
                    &head,
                    route,
                    &canonical_host,
                    method,
                    cancellation,
                    context,
                );
            } else {
                handle_admitted_http(
                    stream,
                    &head,
                    route,
                    &canonical_host,
                    method,
                    cancellation,
                    context,
                );
            }
        }
        RequestTarget::Absolute(_) | RequestTarget::Connect(_) => reject_scoped_request(
            stream,
            context,
            &canonical_host,
            method,
            501,
            match host_class {
                InterceptedConnectClass::Hns => "HNS Protocol Upgrade Unsupported",
                InterceptedConnectClass::Icann => "ICANN Protocol Upgrade Unsupported",
            },
            RequestRejectionReason::InvalidRequest,
        ),
    }
}

fn authorize_connected_target(
    context: &ServerContext,
    target: &Authority,
    connected_to: &Authority,
    outer_host: &crate::NormalizedHost,
    host_class: InterceptedConnectClass,
) -> Option<crate::NormalizedHost> {
    if target.port() != connected_to.port() {
        return None;
    }
    let host = crate::NormalizedHost::parse(target.host()).ok()?;
    if host != *outer_host {
        return None;
    }
    match host_class {
        InterceptedConnectClass::Hns if context.routing_mode == ProxyRoutingMode::WholeBrowser => {
            (!is_browser_special_use_host(host.as_str())).then_some(host)
        }
        InterceptedConnectClass::Hns => context
            .hns_scope
            .as_ref()?
            .authorize(host.as_str())
            .ok()
            .filter(|authorized| *authorized == host),
        InterceptedConnectClass::Icann if !is_browser_special_use_host(host.as_str()) => Some(host),
        InterceptedConnectClass::Icann => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_admitted_upgrade<S: ClientIo + ?Sized>(
    stream: &mut S,
    head: &RequestHead,
    route: HttpRoute<'_>,
    canonical_host: &crate::NormalizedHost,
    method: ObservedMethod,
    cancellation: &CancellationToken,
    context: &ServerContext,
) {
    let framing = match determine_body_framing(head.headers()) {
        Ok(framing) => framing,
        Err(error) => {
            reject_http_request(stream, context, canonical_host, method, &error);
            return;
        }
    };
    if !matches!(framing, BodyFraming::None | BodyFraming::ContentLength(0)) {
        reject_scoped_request(
            stream,
            context,
            canonical_host,
            method,
            400,
            "HNS Protocol Upgrade Body Unsupported",
            RequestRejectionReason::InvalidRequest,
        );
        return;
    }
    if head.header_values("expect").next().is_some() {
        reject_scoped_request(
            stream,
            context,
            canonical_host,
            method,
            417,
            "Expectation Failed",
            RequestRejectionReason::InvalidRequest,
        );
        return;
    }
    let headers = match build_upgrade_forward_headers(head, route, canonical_host) {
        Ok(headers) => headers,
        Err(error) => {
            reject_http_request(stream, context, canonical_host, method, &error);
            return;
        }
    };
    if stream.clear_client_read_deadline().is_err() {
        observe_request(
            context,
            canonical_host,
            method,
            RequestPhase::Rejected {
                reason: RequestRejectionReason::InvalidRequest,
            },
        );
        return;
    }
    if cancellation.is_cancelled() {
        observe_request(
            context,
            canonical_host,
            method,
            RequestPhase::Rejected {
                reason: RequestRejectionReason::Cancelled,
            },
        );
        return;
    }

    execute_backend_tunnel(
        stream,
        context,
        canonical_host,
        method,
        ProxyRequest {
            method: head.method().to_owned(),
            scheme: route.scheme.as_str().to_owned(),
            host: canonical_host.as_str().to_owned(),
            port: route.authority.port(),
            path_and_query: route.path_and_query.to_owned(),
            headers,
            body: ProxyRequestBody::Empty,
        },
        cancellation,
    );
}

fn admit_rate<W: Write + ?Sized>(
    stream: &mut W,
    context: &ServerContext,
    canonical_host: &str,
    method: ObservedMethod,
    likely_main_frame: bool,
) -> bool {
    match context.rate_limiter.check(canonical_host, Instant::now()) {
        RateLimitDecision::Allowed => true,
        RateLimitDecision::Limited { scope, retry_after } => {
            let reason = match scope {
                RateLimitScope::Global => RequestRejectionReason::GlobalRateLimit,
                RateLimitScope::Host => RequestRejectionReason::HostRateLimit,
            };
            observe_request(
                context,
                canonical_host,
                method,
                RequestPhase::Rejected { reason },
            );
            observe_proxy_generated_response(
                context,
                canonical_host,
                method,
                429,
                likely_main_frame,
            );
            let _result = write_error_response(
                stream,
                429,
                "Too Many Requests",
                &[("Retry-After", retry_after_seconds(retry_after).to_string())],
            );
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_admitted_http<S: ClientIo + ?Sized>(
    stream: &mut S,
    head: &RequestHead,
    route: HttpRoute<'_>,
    canonical_host: &crate::NormalizedHost,
    method: ObservedMethod,
    cancellation: &CancellationToken,
    context: &ServerContext,
) {
    let likely_main_frame = is_likely_main_frame_navigation(head, route.path_and_query);
    let framing = match determine_body_framing(head.headers()) {
        Ok(framing) => framing,
        Err(error) => {
            reject_http_request_with_status(
                stream,
                context,
                canonical_host,
                method,
                &error,
                likely_main_frame,
            );
            return;
        }
    };
    if matches!(
        framing,
        BodyFraming::ContentLength(length) if length > context.limits.max_body_bytes()
    ) {
        reject_http_request_with_status(
            stream,
            context,
            canonical_host,
            method,
            &Http1Error::BodyTooLarge,
            likely_main_frame,
        );
        return;
    }
    let expects_continue = match expects_continue(head) {
        Ok(expects) => expects,
        Err(()) => {
            reject_scoped_request_with_status(
                stream,
                context,
                canonical_host,
                method,
                417,
                "Expectation Failed",
                RequestRejectionReason::InvalidRequest,
                likely_main_frame,
            );
            return;
        }
    };
    let forward_headers = match build_forward_headers(head, route, canonical_host) {
        Ok(headers) => headers,
        Err(error) => {
            reject_http_request_with_status(
                stream,
                context,
                canonical_host,
                method,
                &error,
                likely_main_frame,
            );
            return;
        }
    };

    if expects_continue
        && !matches!(framing, BodyFraming::None)
        && (stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() || stream.flush().is_err())
    {
        return;
    }
    let body = {
        let mut reader = DeadlineReader::new(stream, context.timeouts.socket_timeout());
        match read_request_body(&mut reader, framing, context.limits.max_body_bytes()) {
            Ok(bytes) => bytes,
            Err(error) => {
                reject_http_request_with_status(
                    stream,
                    context,
                    canonical_host,
                    method,
                    &error,
                    likely_main_frame,
                );
                return;
            }
        }
    };
    if stream.clear_client_read_deadline().is_err() {
        observe_request(
            context,
            canonical_host,
            method,
            RequestPhase::Rejected {
                reason: RequestRejectionReason::InvalidRequest,
            },
        );
        return;
    }
    if cancellation.is_cancelled() {
        observe_request(
            context,
            canonical_host,
            method,
            RequestPhase::Rejected {
                reason: RequestRejectionReason::Cancelled,
            },
        );
        return;
    }

    let request = ProxyRequest {
        method: head.method().to_owned(),
        scheme: route.scheme.as_str().to_owned(),
        host: canonical_host.as_str().to_owned(),
        port: route.authority.port(),
        path_and_query: route.path_and_query.to_owned(),
        headers: forward_headers,
        body: if body.is_empty() {
            ProxyRequestBody::Empty
        } else {
            ProxyRequestBody::Bytes(body)
        },
    };
    execute_backend(
        stream,
        context,
        canonical_host,
        method,
        likely_main_frame,
        head.method(),
        request,
        cancellation,
    );
}

#[allow(clippy::too_many_arguments)]
fn execute_backend<W: Write + ?Sized>(
    stream: &mut W,
    context: &ServerContext,
    host: &crate::NormalizedHost,
    method: ObservedMethod,
    likely_main_frame: bool,
    request_method: &str,
    request: ProxyRequest,
    cancellation: &CancellationToken,
) {
    let started = Instant::now();
    let response = catch_unwind(AssertUnwindSafe(|| {
        context.backend.execute(request, cancellation)
    }))
    .unwrap_or(Err(BackendError::Internal));
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            observe_request(
                context,
                host,
                method,
                RequestPhase::BackendFailed {
                    kind: backend_failure_kind(error),
                    elapsed: started.elapsed(),
                },
            );
            return;
        }
    };
    if cancellation.is_cancelled() {
        return;
    }
    let publication_permit = match catch_unwind(AssertUnwindSafe(|| {
        context
            .backend
            .acquire_publication_permit(&response.publication)
    }))
    .unwrap_or(Err(BackendError::Internal))
    {
        Ok(permit) => permit,
        Err(error) => {
            observe_request(
                context,
                host,
                method,
                RequestPhase::BackendFailed {
                    kind: backend_failure_kind(error),
                    elapsed: started.elapsed(),
                },
            );
            return;
        }
    };
    let status = response.head.status_code;
    let observation_id = response.head.observation_id;
    match write_backend_response(
        stream,
        request_method,
        response,
        cancellation,
        publication_permit,
        |metadata| {
            observe_response_metadata(
                context,
                host,
                method,
                status,
                likely_main_frame,
                observation_id,
                metadata,
            );
        },
    ) {
        Ok(()) => observe_request(
            context,
            host,
            method,
            RequestPhase::Completed {
                status_code: status,
                elapsed: started.elapsed(),
            },
        ),
        Err(WriteBackendError::InvalidBeforeHead) => {
            observe_invalid_response(context, host, method, started.elapsed());
        }
        Err(WriteBackendError::InvalidAfterHead) => {
            observe_invalid_response(context, host, method, started.elapsed());
        }
        Err(WriteBackendError::Io) => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_backend_tunnel<S: ClientIo + ?Sized>(
    client: &mut S,
    context: &ServerContext,
    host: &crate::NormalizedHost,
    method: ObservedMethod,
    request: ProxyRequest,
    cancellation: &CancellationToken,
) {
    let started = Instant::now();
    let request_method = request.method.clone();
    let tunnel = catch_unwind(AssertUnwindSafe(|| {
        context.backend.open_tunnel(request, cancellation)
    }))
    .unwrap_or(Err(BackendError::Internal));
    let opened = match tunnel {
        Ok(opened) => opened,
        Err(error) => {
            observe_request(
                context,
                host,
                method,
                RequestPhase::BackendFailed {
                    kind: backend_failure_kind(error),
                    elapsed: started.elapsed(),
                },
            );
            return;
        }
    };
    if cancellation.is_cancelled() {
        return;
    }
    let publication_permit = match catch_unwind(AssertUnwindSafe(|| {
        let capability = match &opened {
            ProxyTunnelOpen::Tunnel(tunnel) => &tunnel.publication,
            ProxyTunnelOpen::Response(response) => &response.publication,
        };
        context.backend.acquire_publication_permit(capability)
    }))
    .unwrap_or(Err(BackendError::Internal))
    {
        Ok(permit) => permit,
        Err(error) => {
            observe_request(
                context,
                host,
                method,
                RequestPhase::BackendFailed {
                    kind: backend_failure_kind(error),
                    elapsed: started.elapsed(),
                },
            );
            return;
        }
    };
    let ProxyTunnel {
        head,
        stream: mut origin,
        publication: _publication,
    } = match opened {
        ProxyTunnelOpen::Tunnel(tunnel) => tunnel,
        ProxyTunnelOpen::Response(response) => {
            let status = response.head.status_code;
            let observation_id = response.head.observation_id;
            match write_backend_response(
                client,
                &request_method,
                response,
                cancellation,
                publication_permit,
                |metadata| {
                    observe_response_metadata(
                        context,
                        host,
                        method,
                        status,
                        false,
                        observation_id,
                        metadata,
                    );
                },
            ) {
                Ok(()) => observe_request(
                    context,
                    host,
                    method,
                    RequestPhase::Completed {
                        status_code: status,
                        elapsed: started.elapsed(),
                    },
                ),
                Err(WriteBackendError::InvalidBeforeHead) => {
                    observe_invalid_response(context, host, method, started.elapsed());
                }
                Err(WriteBackendError::InvalidAfterHead) => {
                    observe_invalid_response(context, host, method, started.elapsed());
                }
                Err(WriteBackendError::Io) => {}
            }
            return;
        }
    };
    let header_pairs: Vec<_> = head
        .headers
        .into_iter()
        .map(|header| (header.name, header.value))
        .collect();
    let sanitized = match sanitize_response_headers(&header_pairs) {
        Ok(sanitized) => sanitized,
        Err(_error) => {
            observe_invalid_response(context, host, method, started.elapsed());
            if !cancellation.is_cancelled() {
                let _result = write_error_response(client, 502, "Invalid Upstream Response", &[]);
            }
            return;
        }
    };
    let encoded =
        match encode_upgrade_response_head(head.status_code, &head.reason_phrase, &header_pairs) {
            Ok(encoded) => encoded,
            Err(_error) => {
                observe_invalid_response(context, host, method, started.elapsed());
                if !cancellation.is_cancelled() {
                    let _result =
                        write_error_response(client, 502, "Invalid Upstream Response", &[]);
                }
                return;
            }
        };
    if client.write_all(encoded.as_bytes()).is_err() || client.flush().is_err() {
        return;
    }
    drop(publication_permit);
    observe_response_metadata(
        context,
        host,
        method,
        101,
        false,
        head.observation_id,
        sanitized.metadata(),
    );

    match pump_tunnel(client, origin.as_mut(), cancellation) {
        TunnelPumpOutcome::Completed => observe_request(
            context,
            host,
            method,
            RequestPhase::Completed {
                status_code: 101,
                elapsed: started.elapsed(),
            },
        ),
        TunnelPumpOutcome::OriginIo => observe_request(
            context,
            host,
            method,
            RequestPhase::BackendFailed {
                kind: BackendFailureKind::Upstream,
                elapsed: started.elapsed(),
            },
        ),
        TunnelPumpOutcome::ClientIo | TunnelPumpOutcome::Cancelled => {}
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelPumpOutcome {
    Completed,
    ClientIo,
    OriginIo,
    Cancelled,
}

fn pump_tunnel<S: ClientIo + ?Sized>(
    client: &mut S,
    origin: &mut dyn crate::ProxyTunnelIo,
    cancellation: &CancellationToken,
) -> TunnelPumpOutcome {
    let mut client_buffer = [0_u8; TUNNEL_COPY_BUFFER_BYTES];
    let mut origin_buffer = [0_u8; TUNNEL_COPY_BUFFER_BYTES];
    loop {
        if cancellation.is_cancelled() {
            return TunnelPumpOutcome::Cancelled;
        }

        let now = Instant::now();
        let deadline = now.checked_add(TUNNEL_CLIENT_POLL_INTERVAL).unwrap_or(now);
        if client.set_client_read_deadline(deadline).is_err() {
            return TunnelPumpOutcome::ClientIo;
        }
        let client_read = client.read(&mut client_buffer);
        if client.clear_client_read_deadline().is_err() {
            return TunnelPumpOutcome::ClientIo;
        }
        match client_read {
            Ok(0) => return TunnelPumpOutcome::Completed,
            Ok(count) if count > client_buffer.len() => return TunnelPumpOutcome::ClientIo,
            Ok(count) => {
                let write = catch_unwind(AssertUnwindSafe(|| {
                    origin.write_all(&client_buffer[..count])?;
                    origin.flush()
                }));
                match write {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) | Err(_) => return TunnelPumpOutcome::OriginIo,
                }
            }
            Err(error) if retryable_tunnel_read(&error) => {}
            Err(_error) => return TunnelPumpOutcome::ClientIo,
        }

        if cancellation.is_cancelled() {
            return TunnelPumpOutcome::Cancelled;
        }
        let origin_read = catch_unwind(AssertUnwindSafe(|| origin.read(&mut origin_buffer)));
        match origin_read {
            Ok(Ok(0)) => return TunnelPumpOutcome::Completed,
            Ok(Ok(count)) if count > origin_buffer.len() => return TunnelPumpOutcome::OriginIo,
            Ok(Ok(count)) => {
                if client.write_all(&origin_buffer[..count]).is_err() || client.flush().is_err() {
                    return TunnelPumpOutcome::ClientIo;
                }
            }
            Ok(Err(error)) if retryable_tunnel_read(&error) => {}
            Ok(Err(_)) | Err(_) => return TunnelPumpOutcome::OriginIo,
        }
    }
}

fn retryable_tunnel_read(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn observe_invalid_response(
    context: &ServerContext,
    host: &crate::NormalizedHost,
    method: ObservedMethod,
    elapsed: Duration,
) {
    observe_request(
        context,
        host,
        method,
        RequestPhase::BackendFailed {
            kind: BackendFailureKind::InvalidResponse,
            elapsed,
        },
    );
}

fn write_backend_response<W, F>(
    stream: &mut W,
    request_method: &str,
    response: ProxyResponse,
    cancellation: &CancellationToken,
    publication_permit: Box<dyn crate::PublicationPermit + '_>,
    observe_metadata: F,
) -> Result<(), WriteBackendError>
where
    W: Write + ?Sized,
    F: FnOnce(&crate::InternalResponseMetadata),
{
    let ProxyResponse {
        head,
        body,
        publication: _publication,
    } = response;
    let header_pairs: Vec<_> = head
        .headers
        .into_iter()
        .map(|header| (header.name, header.value))
        .collect();
    let headers = sanitize_response_headers(&header_pairs)
        .map_err(|_error| WriteBackendError::InvalidBeforeHead)?;
    let body_len = body.expected_len();
    let encoded = encode_response_head(
        request_method,
        head.status_code,
        &head.reason_phrase,
        &headers,
        body_len,
    )
    .map_err(|_error| WriteBackendError::InvalidBeforeHead)?;
    let body_allowed = encoded.body_allowed();
    stream
        .write_all(encoded.as_bytes())
        .map_err(|_error| WriteBackendError::Io)?;
    stream.flush().map_err(|_error| WriteBackendError::Io)?;
    drop(publication_permit);
    if body_allowed {
        write_response_body(stream, body, cancellation)?;
    }
    observe_metadata(headers.metadata());
    Ok(())
}

fn write_response_body<W: Write + ?Sized>(
    stream: &mut W,
    body: ProxyResponseBody,
    cancellation: &CancellationToken,
) -> Result<(), WriteBackendError> {
    match body {
        ProxyResponseBody::Bytes(bytes) => {
            if cancellation.is_cancelled() {
                return Err(WriteBackendError::Io);
            }
            stream
                .write_all(&bytes)
                .map_err(|_error| WriteBackendError::Io)
        }
        ProxyResponseBody::Stream {
            expected_len,
            mut reader,
        } => copy_exact_response(stream, reader.as_mut(), expected_len, cancellation),
    }
}

fn copy_exact_response<W: Write + ?Sized>(
    stream: &mut W,
    reader: &mut dyn Read,
    mut remaining: u64,
    cancellation: &CancellationToken,
) -> Result<(), WriteBackendError> {
    let mut buffer = [0_u8; RESPONSE_COPY_BUFFER_BYTES];
    while remaining != 0 {
        if cancellation.is_cancelled() {
            return Err(WriteBackendError::Io);
        }
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_error| WriteBackendError::InvalidAfterHead)?;
        let count = catch_unwind(AssertUnwindSafe(|| reader.read(&mut buffer[..limit])))
            .map_err(|_panic| WriteBackendError::InvalidAfterHead)?
            .map_err(|_error| WriteBackendError::InvalidAfterHead)?;
        if count == 0 || count > limit {
            return Err(WriteBackendError::InvalidAfterHead);
        }
        stream
            .write_all(&buffer[..count])
            .map_err(|_error| WriteBackendError::Io)?;
        remaining = remaining
            .checked_sub(count as u64)
            .ok_or(WriteBackendError::InvalidAfterHead)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteBackendError {
    InvalidBeforeHead,
    InvalidAfterHead,
    Io,
}

fn build_forward_headers(
    head: &RequestHead,
    route: HttpRoute<'_>,
    host: &crate::NormalizedHost,
) -> Result<Vec<ProxyHeader>, Http1Error> {
    let mut headers: Vec<_> = sanitize_forward_headers(head.headers())?
        .into_iter()
        .filter(|header| {
            !header.name().eq_ignore_ascii_case("host")
                && !header.name().eq_ignore_ascii_case("content-length")
                && !header.name().eq_ignore_ascii_case("expect")
        })
        .map(|header| ProxyHeader::new(header.name(), header.value()))
        .collect();
    let default_port = route.scheme.default_port();
    let host_value = if route.authority.port() == default_port {
        host.as_str().to_owned()
    } else {
        format!("{}:{}", host.as_str(), route.authority.port())
    };
    headers.push(ProxyHeader::new("Host", host_value));
    Ok(headers)
}

fn build_upgrade_forward_headers(
    head: &RequestHead,
    route: HttpRoute<'_>,
    host: &crate::NormalizedHost,
) -> Result<Vec<ProxyHeader>, Http1Error> {
    let mut headers: Vec<_> = sanitize_upgrade_forward_headers(head.headers())?
        .into_iter()
        .filter(|header| {
            !header.name().eq_ignore_ascii_case("host")
                && !header.name().eq_ignore_ascii_case("content-length")
                && !header.name().eq_ignore_ascii_case("expect")
        })
        .map(|header| ProxyHeader::new(header.name(), header.value()))
        .collect();
    let default_port = route.scheme.default_port();
    let host_value = if route.authority.port() == default_port {
        host.as_str().to_owned()
    } else {
        format!("{}:{}", host.as_str(), route.authority.port())
    };
    headers.push(ProxyHeader::new("Host", host_value));
    Ok(headers)
}

fn expects_continue(head: &RequestHead) -> Result<bool, ()> {
    let mut values = head.header_values("expect");
    let Some(first) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() || !first.eq_ignore_ascii_case("100-continue") {
        return Err(());
    }
    Ok(true)
}

/// Mirrors the Android shell's conservative navigation heuristic without
/// retaining the request target in an observation.
fn is_likely_main_frame_navigation(head: &RequestHead, path_and_query: &str) -> bool {
    if !head.method().eq_ignore_ascii_case("GET") && !head.method().eq_ignore_ascii_case("HEAD") {
        return false;
    }

    // Sec-Fetch-Dest is authoritative when the browser supplies it. In
    // particular, nested navigations (`iframe`) and subresources must not be
    // promoted by the compatibility fallbacks below.
    if let Some(fetch_destination) = head.header_values("sec-fetch-dest").next() {
        return fetch_destination.eq_ignore_ascii_case("document");
    }
    if head
        .header_values("sec-fetch-mode")
        .next()
        .is_some_and(|mode| mode.eq_ignore_ascii_case("navigate"))
    {
        return true;
    }
    if head.header_values("upgrade-insecure-requests").next() == Some("1") {
        return true;
    }
    if head
        .header_values("accept")
        .next()
        .is_some_and(|accept| accept.to_ascii_lowercase().contains("text/html"))
    {
        return true;
    }
    path_and_query == "/"
}

fn requests_upgrade(head: &RequestHead) -> bool {
    head.header_values("upgrade").next().is_some()
        || head
            .header_values("connection")
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

fn reject_http_request<W: Write + ?Sized>(
    stream: &mut W,
    context: &ServerContext,
    host: &crate::NormalizedHost,
    method: ObservedMethod,
    error: &Http1Error,
) {
    reject_http_request_with_status(stream, context, host, method, error, false);
}

fn reject_http_request_with_status<W: Write + ?Sized>(
    stream: &mut W,
    context: &ServerContext,
    host: &crate::NormalizedHost,
    method: ObservedMethod,
    error: &Http1Error,
    likely_main_frame: bool,
) {
    let rejection = if matches!(error, Http1Error::BodyTooLarge) {
        RequestRejectionReason::RequestTooLarge
    } else {
        RequestRejectionReason::InvalidRequest
    };
    let (status, status_reason) = request_error_status(error);
    reject_scoped_request_with_status(
        stream,
        context,
        host,
        method,
        status,
        status_reason,
        rejection,
        likely_main_frame,
    );
}

fn reject_icann_http_error(
    stream: &mut TcpStream,
    context: &ServerContext,
    host: &IcannHost,
    method: ObservedMethod,
    likely_main_frame: bool,
    error: &Http1Error,
) {
    let rejection = if matches!(error, Http1Error::BodyTooLarge) {
        RequestRejectionReason::RequestTooLarge
    } else {
        RequestRejectionReason::InvalidRequest
    };
    let (status, reason) = request_error_status(error);
    reject_routed_request(
        stream,
        context,
        host.as_str(),
        method,
        status,
        reason,
        rejection,
        likely_main_frame,
    );
}

#[allow(clippy::too_many_arguments)]
fn reject_routed_request<W: Write + ?Sized>(
    stream: &mut W,
    context: &ServerContext,
    host: &str,
    method: ObservedMethod,
    status: u16,
    reason: &'static str,
    rejection: RequestRejectionReason,
    likely_main_frame: bool,
) {
    observe_request(
        context,
        host,
        method,
        RequestPhase::Rejected { reason: rejection },
    );
    observe_proxy_generated_response(context, host, method, status, likely_main_frame);
    let _result = write_error_response(stream, status, reason, &[]);
}

fn observe_icann_failure(
    context: &ServerContext,
    host: &str,
    method: ObservedMethod,
    started: Instant,
    error: IcannRouteError,
) {
    let kind = match error {
        IcannRouteError::Cancelled => BackendFailureKind::Cancelled,
        IcannRouteError::Resolution => BackendFailureKind::Resolution,
        IcannRouteError::AddressDenied => BackendFailureKind::PolicyDenied,
        IcannRouteError::Connection => BackendFailureKind::Upstream,
        IcannRouteError::InvalidResponse => BackendFailureKind::InvalidResponse,
    };
    observe_request(
        context,
        host,
        method,
        RequestPhase::BackendFailed {
            kind,
            elapsed: started.elapsed(),
        },
    );
}

fn icann_route_error_response(error: IcannRouteError) -> (u16, &'static str) {
    match error {
        IcannRouteError::Cancelled => (503, "Proxy Request Cancelled"),
        IcannRouteError::Resolution => (502, "ICANN Resolution Failed"),
        IcannRouteError::AddressDenied => (403, "ICANN Destination Denied"),
        IcannRouteError::Connection => (502, "ICANN Upstream Unavailable"),
        IcannRouteError::InvalidResponse => (502, "Invalid ICANN Response"),
    }
}

#[allow(clippy::too_many_arguments)]
fn reject_scoped_request<W: Write + ?Sized>(
    stream: &mut W,
    context: &ServerContext,
    host: &crate::NormalizedHost,
    method: ObservedMethod,
    status: u16,
    reason: &'static str,
    rejection: RequestRejectionReason,
) {
    reject_scoped_request_with_status(
        stream, context, host, method, status, reason, rejection, false,
    );
}

#[allow(clippy::too_many_arguments)]
fn reject_scoped_request_with_status<W: Write + ?Sized>(
    stream: &mut W,
    context: &ServerContext,
    host: &crate::NormalizedHost,
    method: ObservedMethod,
    status: u16,
    reason: &'static str,
    rejection: RequestRejectionReason,
    likely_main_frame: bool,
) {
    observe_request(
        context,
        host,
        method,
        RequestPhase::Rejected { reason: rejection },
    );
    observe_proxy_generated_response(context, host, method, status, likely_main_frame);
    let _result = write_error_response(stream, status, reason, &[]);
}

fn route_rejection(error: RouteRejection) -> (&'static str, RequestRejectionReason) {
    match error {
        RouteRejection::Scope(HostScopeError::OutOfScope) => (
            "HNS Proxy Scope Denied",
            RequestRejectionReason::HostOutsideScope,
        ),
        RouteRejection::Scope(HostScopeError::NotHns | HostScopeError::InvalidHost(_))
        | RouteRejection::SpecialUse
        | RouteRejection::PrivateAddress
        | RouteRejection::InvalidClass => (
            "Proxy Scope Denied",
            RequestRejectionReason::HostOutsideScope,
        ),
    }
}

fn request_error_status(error: &Http1Error) -> (u16, &'static str) {
    match error {
        Http1Error::Io(source)
            if matches!(
                source.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            (408, "Request Timeout")
        }
        _ => (error.status_code(), error.reason_phrase()),
    }
}

#[cfg(test)]
fn backend_error_status(error: BackendError) -> (u16, &'static str) {
    match error {
        BackendError::Cancelled => (503, "Proxy Request Cancelled"),
        BackendError::InvalidRequest => (400, "Invalid Gateway Request"),
        BackendError::PolicyDenied => (403, "Gateway Policy Denied"),
        BackendError::ResolutionFailed => (502, "HNS Resolution Failed"),
        BackendError::TlsValidationFailed => (502, "HNS TLS Validation Failed"),
        BackendError::UpstreamUnavailable => (502, "HNS Upstream Unavailable"),
        BackendError::InvalidResponse => (502, "Invalid Upstream Response"),
        BackendError::ResponseTooLarge => (502, "Upstream Response Too Large"),
        BackendError::UnsupportedUpgrade => (501, "HNS Protocol Upgrade Unsupported"),
        BackendError::Internal => (500, "Proxy Internal Error"),
    }
}

fn backend_failure_kind(error: BackendError) -> BackendFailureKind {
    match error {
        BackendError::Cancelled => BackendFailureKind::Cancelled,
        BackendError::InvalidRequest => BackendFailureKind::InvalidRequest,
        BackendError::PolicyDenied => BackendFailureKind::PolicyDenied,
        BackendError::ResolutionFailed => BackendFailureKind::Resolution,
        BackendError::TlsValidationFailed => BackendFailureKind::TlsValidation,
        BackendError::UpstreamUnavailable => BackendFailureKind::Upstream,
        BackendError::InvalidResponse => BackendFailureKind::InvalidResponse,
        BackendError::ResponseTooLarge => BackendFailureKind::ResponseTooLarge,
        BackendError::UnsupportedUpgrade => BackendFailureKind::InvalidRequest,
        BackendError::Internal => BackendFailureKind::Internal,
    }
}

fn rate_limit_config(limits: ProxyLimits) -> RateLimitConfig {
    RateLimitConfig {
        global_requests: limits.max_requests_per_window(),
        per_host_requests: limits.max_requests_per_host_per_window(),
        window: limits.rate_window(),
        max_tracked_hosts: limits.max_tracked_hosts(),
    }
}

fn retry_after_seconds(duration: Duration) -> u64 {
    duration.as_secs() + u64::from(duration.subsec_nanos() != 0)
}

fn write_error_response<W: Write + ?Sized>(
    stream: &mut W,
    status: u16,
    reason: &'static str,
    extra_headers: &[(&'static str, String)],
) -> io::Result<()> {
    let body = reason.as_bytes();
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"
    )
    .into_bytes();
    for (name, value) in extra_headers {
        response.extend_from_slice(name.as_bytes());
        response.extend_from_slice(b": ");
        response.extend_from_slice(value.as_bytes());
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    response.extend_from_slice(body);
    stream.write_all(&response)?;
    stream.flush()
}

trait ClientIo: Read + Write {
    fn set_client_read_deadline(&mut self, deadline: Instant) -> io::Result<()>;

    fn clear_client_read_deadline(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ClientIo for TcpStream {
    fn set_client_read_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "request deadline elapsed"))?;
        TcpStream::set_read_timeout(self, Some(remaining))
    }

    fn clear_client_read_deadline(&mut self) -> io::Result<()> {
        TcpStream::set_read_timeout(self, None)
    }
}

impl ClientIo for TlsStream {
    fn set_client_read_deadline(&mut self, deadline: Instant) -> io::Result<()> {
        self.sock.set_request_deadline(deadline);
        Ok(())
    }

    fn clear_client_read_deadline(&mut self) -> io::Result<()> {
        self.sock.clear_request_deadline()
    }
}

struct DeadlineReader<'a, S: ClientIo + ?Sized> {
    stream: &'a mut S,
    deadline: Instant,
}

impl<'a, S: ClientIo + ?Sized> DeadlineReader<'a, S> {
    fn new(stream: &'a mut S, timeout: Duration) -> Self {
        let now = Instant::now();
        let deadline = now.checked_add(timeout).unwrap_or(now);
        Self { stream, deadline }
    }
}

impl<S: ClientIo + ?Sized> Read for DeadlineReader<'_, S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request deadline elapsed",
            ));
        }
        self.stream.set_client_read_deadline(self.deadline)?;
        self.stream.read(buffer)
    }
}

fn observe_client_rejection(context: &ServerContext, reason: ClientRejectionReason) {
    observe(
        context.observer.as_ref(),
        ProxyEvent::ClientRejected {
            generation: context.generation,
            reason,
        },
    );
}

fn observe_request(
    context: &ServerContext,
    host: &str,
    method: ObservedMethod,
    phase: RequestPhase,
) {
    let Ok(host) = ObservedHost::new(host) else {
        return;
    };
    observe(
        context.observer.as_ref(),
        ProxyEvent::Request {
            generation: context.generation,
            host,
            method,
            phase,
        },
    );
}

fn observe_response_metadata(
    context: &ServerContext,
    host: &str,
    method: ObservedMethod,
    status_code: u16,
    likely_main_frame: bool,
    observation_id: Option<u64>,
    metadata: &crate::InternalResponseMetadata,
) {
    let Ok(host) = ObservedHost::new(host) else {
        return;
    };
    let observation = ProxyResponseMetadataObservation::new(
        context.generation,
        host,
        method,
        status_code,
        likely_main_frame,
        observation_id,
        metadata.clone(),
    );
    let _result = catch_unwind(AssertUnwindSafe(|| {
        context.metadata_observer.observe(&observation);
    }));
}

fn observe_proxy_generated_response(
    context: &ServerContext,
    host: &str,
    method: ObservedMethod,
    status_code: u16,
    likely_main_frame: bool,
) {
    if !likely_main_frame {
        return;
    }
    observe_response_metadata(
        context,
        host,
        method,
        status_code,
        true,
        None,
        &crate::InternalResponseMetadata::default(),
    );
}

fn observe(observer: &dyn ProxyObserver, event: ProxyEvent) {
    let _result = catch_unwind(AssertUnwindSafe(|| observer.observe(&event)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        NoopProxyObserver, ProxyInstanceId, ProxyResponseHead, ProxyResponseMetadataObservation,
        ProxySessionId, ProxyTunnel, ProxyTunnelIo,
    };
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{
        ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError,
        SignatureScheme, StreamOwned,
    };
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Mutex, mpsc};
    use std::thread;

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);

    fn test_config() -> ProxyConfig {
        ProxyConfig::new(
            ProxyInstanceId::new(ProxySessionId::generate().unwrap(), 1),
            crate::HostScope::new("welcome").unwrap(),
        )
    }

    struct UnusedBackend;

    impl ProxyBackend for UnusedBackend {
        fn execute(
            &self,
            _request: ProxyRequest,
            _cancellation: &CancellationToken,
        ) -> Result<ProxyResponse, BackendError> {
            Err(BackendError::Internal)
        }
    }

    #[derive(Clone)]
    enum ResponsePlan {
        Fixed {
            headers: Vec<ProxyHeader>,
            body: Vec<u8>,
        },
        ShortStream {
            expected_len: u64,
            bytes: Vec<u8>,
        },
    }

    impl ResponsePlan {
        fn plain(body: impl Into<Vec<u8>>) -> Self {
            Self::Fixed {
                headers: vec![ProxyHeader::new("Content-Type", "text/plain")],
                body: body.into(),
            }
        }

        fn response(&self) -> ProxyResponse {
            let (headers, body) = match self {
                Self::Fixed { headers, body } => {
                    (headers.clone(), ProxyResponseBody::Bytes(body.clone()))
                }
                Self::ShortStream {
                    expected_len,
                    bytes,
                } => (
                    vec![ProxyHeader::new("Content-Type", "application/octet-stream")],
                    ProxyResponseBody::Stream {
                        expected_len: *expected_len,
                        reader: Box::new(Cursor::new(bytes.clone())),
                    },
                ),
            };
            ProxyResponse {
                head: ProxyResponseHead {
                    status_code: 200,
                    reason_phrase: "OK".to_owned(),
                    headers,
                    observation_id: None,
                },
                body,
                publication: Default::default(),
            }
        }
    }

    struct RecordingBackend {
        requests: Mutex<Vec<ProxyRequest>>,
        response: ResponsePlan,
    }

    impl RecordingBackend {
        fn new(response: ResponsePlan) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                response,
            }
        }

        fn request_count(&self) -> usize {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
        }

        fn take_requests(&self) -> Vec<ProxyRequest> {
            std::mem::take(
                &mut *self
                    .requests
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            )
        }
    }

    impl ProxyBackend for RecordingBackend {
        fn execute(
            &self,
            request: ProxyRequest,
            _cancellation: &CancellationToken,
        ) -> Result<ProxyResponse, BackendError> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request);
            Ok(self.response.response())
        }
    }

    struct EchoTunnelBackend {
        requests: Mutex<Vec<ProxyRequest>>,
        head: ProxyResponseHead,
        initial_origin_bytes: Vec<u8>,
    }

    impl EchoTunnelBackend {
        fn websocket(initial_origin_bytes: impl Into<Vec<u8>>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                head: ProxyResponseHead {
                    status_code: 101,
                    reason_phrase: "Switching Protocols".to_owned(),
                    headers: vec![
                        ProxyHeader::new("Connection", "keep-alive, Upgrade, X-Origin-Hop"),
                        ProxyHeader::new("Upgrade", "websocket"),
                        ProxyHeader::new("Sec-WebSocket-Accept", "accepted"),
                        ProxyHeader::new("X-Origin-Hop", "secret"),
                        ProxyHeader::new("X-HNS-Security-Path", "secret"),
                    ],
                    observation_id: None,
                },
                initial_origin_bytes: initial_origin_bytes.into(),
            }
        }

        fn with_head(head: ProxyResponseHead) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                head,
                initial_origin_bytes: Vec::new(),
            }
        }

        fn take_requests(&self) -> Vec<ProxyRequest> {
            std::mem::take(
                &mut *self
                    .requests
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            )
        }
    }

    impl ProxyBackend for EchoTunnelBackend {
        fn execute(
            &self,
            _request: ProxyRequest,
            _cancellation: &CancellationToken,
        ) -> Result<ProxyResponse, BackendError> {
            Err(BackendError::Internal)
        }

        fn open_tunnel(
            &self,
            request: ProxyRequest,
            _cancellation: &CancellationToken,
        ) -> Result<ProxyTunnelOpen, BackendError> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request);
            Ok(ProxyTunnelOpen::Tunnel(ProxyTunnel {
                head: self.head.clone(),
                stream: Box::new(EchoTunnelStream {
                    pending: self.initial_origin_bytes.iter().copied().collect(),
                }),
                publication: Default::default(),
            }))
        }
    }

    struct EchoTunnelStream {
        pending: VecDeque<u8>,
    }

    impl Read for EchoTunnelStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.pending.is_empty() {
                thread::sleep(Duration::from_millis(5));
                return Err(io::Error::new(io::ErrorKind::TimedOut, "idle test tunnel"));
            }
            let count = buffer.len().min(self.pending.len());
            for output in &mut buffer[..count] {
                *output = self.pending.pop_front().unwrap();
            }
            Ok(count)
        }
    }

    impl Write for EchoTunnelStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.pending.extend(buffer.iter().copied());
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct HttpRejectingTunnelBackend;

    impl ProxyBackend for HttpRejectingTunnelBackend {
        fn execute(
            &self,
            _request: ProxyRequest,
            _cancellation: &CancellationToken,
        ) -> Result<ProxyResponse, BackendError> {
            Err(BackendError::Internal)
        }

        fn open_tunnel(
            &self,
            _request: ProxyRequest,
            _cancellation: &CancellationToken,
        ) -> Result<ProxyTunnelOpen, BackendError> {
            Ok(ProxyTunnelOpen::Response(ProxyResponse {
                head: ProxyResponseHead {
                    status_code: 404,
                    reason_phrase: "HNS Name Not Found".to_owned(),
                    headers: vec![
                        ProxyHeader::new("Content-Type", "text/plain"),
                        ProxyHeader::new("X-HNS-Security-Path", "verified-non-inclusion"),
                    ],
                    observation_id: None,
                },
                body: ProxyResponseBody::Bytes(b"verified non-inclusion".to_vec()),
                publication: Default::default(),
            }))
        }
    }

    struct CooperativeStreamBackend {
        read_started: Mutex<Option<mpsc::Sender<()>>>,
    }

    impl ProxyBackend for CooperativeStreamBackend {
        fn execute(
            &self,
            _request: ProxyRequest,
            cancellation: &CancellationToken,
        ) -> Result<ProxyResponse, BackendError> {
            let read_started = self
                .read_started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            Ok(ProxyResponse {
                head: ProxyResponseHead {
                    status_code: 200,
                    reason_phrase: "OK".to_owned(),
                    headers: vec![],
                    observation_id: None,
                },
                body: ProxyResponseBody::Stream {
                    expected_len: 1,
                    reader: Box::new(CooperativeCancellationReader {
                        cancellation: cancellation.clone(),
                        read_started,
                    }),
                },
                publication: Default::default(),
            })
        }
    }

    struct CooperativeCancellationReader {
        cancellation: CancellationToken,
        read_started: Option<mpsc::Sender<()>>,
    }

    impl Read for CooperativeCancellationReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            if let Some(read_started) = self.read_started.take() {
                let _result = read_started.send(());
            }
            if self
                .cancellation
                .wait_cancelled_timeout(Duration::from_secs(5))
            {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "proxy generation cancelled",
                ))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "test cancellation did not arrive",
                ))
            }
        }
    }

    struct AcceptedObserver(mpsc::Sender<()>);

    impl ProxyObserver for AcceptedObserver {
        fn observe(&self, event: &ProxyEvent) {
            if matches!(
                event,
                ProxyEvent::Request {
                    phase: RequestPhase::Accepted,
                    ..
                }
            ) {
                let _result = self.0.send(());
            }
        }
    }

    struct CountingIcannNetwork {
        resolve_calls: AtomicUsize,
        connect_calls: AtomicUsize,
        addresses: Vec<SocketAddr>,
        responses: Mutex<VecDeque<Vec<u8>>>,
        written: Arc<Mutex<Vec<u8>>>,
        idle_after_connect: bool,
    }

    impl CountingIcannNetwork {
        fn new(addresses: Vec<SocketAddr>, responses: Vec<Vec<u8>>) -> Self {
            Self {
                resolve_calls: AtomicUsize::new(0),
                connect_calls: AtomicUsize::new(0),
                addresses,
                responses: Mutex::new(responses.into()),
                written: Arc::new(Mutex::new(Vec::new())),
                idle_after_connect: false,
            }
        }

        fn idle(addresses: Vec<SocketAddr>) -> Self {
            Self {
                idle_after_connect: true,
                ..Self::new(addresses, Vec::new())
            }
        }

        fn resolve_calls(&self) -> usize {
            self.resolve_calls.load(AtomicOrdering::Acquire)
        }

        fn connect_calls(&self) -> usize {
            self.connect_calls.load(AtomicOrdering::Acquire)
        }

        fn written(&self) -> Vec<u8> {
            self.written
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl IcannNetwork for CountingIcannNetwork {
        fn resolve(
            &self,
            _host: &str,
            _port: u16,
            cancellation: &CancellationToken,
        ) -> Result<Vec<SocketAddr>, IcannNetworkError> {
            self.resolve_calls.fetch_add(1, AtomicOrdering::AcqRel);
            if cancellation.is_cancelled() {
                Err(IcannNetworkError::Cancelled)
            } else {
                Ok(self.addresses.clone())
            }
        }

        fn connect(
            &self,
            _address: SocketAddr,
            _timeout: Duration,
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn ProxyTunnelIo>, IcannNetworkError> {
            self.connect_calls.fetch_add(1, AtomicOrdering::AcqRel);
            if cancellation.is_cancelled() {
                return Err(IcannNetworkError::Cancelled);
            }
            let response = self
                .responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .unwrap_or_default();
            Ok(Box::new(ScriptedIcannStream {
                response: Cursor::new(response),
                written: Arc::clone(&self.written),
                idle_after_response: self.idle_after_connect,
            }))
        }
    }

    struct ScriptedIcannStream {
        response: Cursor<Vec<u8>>,
        written: Arc<Mutex<Vec<u8>>>,
        idle_after_response: bool,
    }

    impl Read for ScriptedIcannStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.response.read(buffer)?;
            if count == 0 && self.idle_after_response {
                thread::sleep(Duration::from_millis(5));
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "idle ICANN test stream",
                ))
            } else {
                Ok(count)
            }
        }
    }

    impl Write for ScriptedIcannStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.written
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct PendingChunkStream {
        prefix: Cursor<Vec<u8>>,
        pending: Option<mpsc::Sender<()>>,
    }

    impl Read for PendingChunkStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.prefix.read(buffer)?;
            if count != 0 {
                return Ok(count);
            }
            if let Some(pending) = self.pending.take() {
                let _result = pending.send(());
            }
            thread::sleep(Duration::from_millis(5));
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pending chunk framing test read",
            ))
        }
    }

    impl Write for PendingChunkStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn whole_browser_config(scope: Option<&str>) -> ProxyConfig {
        ProxyConfig::whole_browser(
            ProxyInstanceId::new(ProxySessionId::generate().unwrap(), 1),
            scope.map(|root| crate::HostScope::new(root).unwrap()),
        )
    }

    fn start_proxy_with_icann_network(
        config: ProxyConfig,
        backend: Arc<dyn ProxyBackend>,
        network: Arc<dyn IcannNetwork>,
    ) -> RunningProxy {
        RunningProxy::start_with_metadata_observer_and_icann_network(
            config,
            backend,
            Arc::new(NoopProxyObserver),
            Arc::new(NoopProxyResponseMetadataObserver),
            network,
        )
        .unwrap()
    }

    fn start_recording_proxy(backend: Arc<RecordingBackend>) -> RunningProxy {
        RunningProxy::start(test_config(), backend, Arc::new(NoopProxyObserver)).unwrap()
    }

    fn start_recording_proxy_with_metadata(
        backend: Arc<RecordingBackend>,
        metadata_observer: Arc<dyn ProxyResponseMetadataObserver>,
    ) -> RunningProxy {
        RunningProxy::start_with_metadata_observer(
            test_config(),
            backend,
            Arc::new(NoopProxyObserver),
            metadata_observer,
        )
        .unwrap()
    }

    fn send_raw(proxy: &RunningProxy, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(proxy.endpoint().address()).unwrap();
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream.write_all(request).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        match stream.read_to_end(&mut response) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("unable to read proxy response: {error}"),
        }
        response
    }

    fn response_status(response: &[u8]) -> u16 {
        let line_end = response
            .windows(2)
            .position(|pair| pair == b"\r\n")
            .expect("response status line ends");
        std::str::from_utf8(&response[..line_end])
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    }

    fn response_parts(response: &[u8]) -> (&str, &[u8]) {
        let head_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("response head terminates");
        (
            std::str::from_utf8(&response[..head_end + 4]).unwrap(),
            &response[head_end + 4..],
        )
    }

    fn auth_header(proxy: &RunningProxy) -> String {
        format!(
            "Proxy-Authorization: {}\r\n",
            proxy.endpoint().authorization_header_value()
        )
    }

    #[derive(Debug)]
    struct CapturingCertificateVerifier {
        certificate_der: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl ServerCertVerifier for CapturingCertificateVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            *self
                .certificate_der
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some(end_entity.as_ref().to_vec());
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            rustls::crypto::verify_tls12_signature(
                message,
                certificate,
                signature,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            rustls::crypto::verify_tls13_signature(
                message,
                certificate,
                signature,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    fn tls_client_config(
        certificate_der: Arc<Mutex<Option<Vec<u8>>>>,
        alpn_protocols: &[&[u8]],
        enable_sni: bool,
    ) -> Arc<ClientConfig> {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(CapturingCertificateVerifier {
                    certificate_der,
                }))
                .with_no_client_auth();
        config.enable_sni = enable_sni;
        config.alpn_protocols = alpn_protocols
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();
        Arc::new(config)
    }

    fn read_response_head(input: &mut impl Read) -> io::Result<Vec<u8>> {
        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        while response.len() < ProxyLimits::DEFAULT_MAX_HEADER_BYTES {
            if input.read(&mut byte)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "response ended before its head",
                ));
            }
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                return Ok(response);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response head exceeded the test limit",
        ))
    }

    fn begin_authenticated_connect(proxy: &RunningProxy, authority: &str) -> TcpStream {
        let mut stream = TcpStream::connect(proxy.endpoint().address()).unwrap();
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
        let request = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{}\r\n",
            auth_header(proxy)
        );
        stream.write_all(request.as_bytes()).unwrap();
        stream.flush().unwrap();
        let response = read_response_head(&mut stream).unwrap();
        assert_eq!(response_status(&response), 200, "{response:?}");
        stream
    }

    fn complete_tls_handshake(
        stream: TcpStream,
        server_name: &str,
        enable_sni: bool,
        alpn_protocols: &[&[u8]],
    ) -> io::Result<(StreamOwned<ClientConnection, TcpStream>, Vec<u8>)> {
        let certificate_der = Arc::new(Mutex::new(None));
        let config = tls_client_config(Arc::clone(&certificate_der), alpn_protocols, enable_sni);
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let connection = ClientConnection::new(config, server_name)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut tls = StreamOwned::new(connection, stream);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock)?;
        }
        let certificate_der = certificate_der
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| io::Error::other("server did not present a certificate"))?;
        Ok((tls, certificate_der))
    }

    fn send_tls_request(
        proxy: &RunningProxy,
        authority: &str,
        certificate_host: &str,
        request: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let stream = begin_authenticated_connect(proxy, authority);
        assert!(proxy.local_certificate_pin(certificate_host).is_some());
        let (mut tls, certificate_der) =
            complete_tls_handshake(stream, certificate_host, true, &[b"h2", b"http/1.1"]).unwrap();
        assert_eq!(tls.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
        tls.write_all(request).unwrap();
        tls.flush().unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).unwrap();
        (response, certificate_der)
    }

    fn wait_for_active_clients(proxy: &RunningProxy, expected: usize) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        while proxy.active_clients() != expected && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(proxy.active_clients(), expected);
    }

    fn assert_connection_closed(mut stream: TcpStream) {
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                        | io::ErrorKind::UnexpectedEof
                ) => {}
            result => panic!("expected a closed proxy connection, got {result:?}"),
        }
    }

    fn parsed_test_head(method: &str, headers: &[(&str, &str)]) -> RequestHead {
        let mut request = format!("{method} http://welcome/ HTTP/1.1\r\nHost: welcome\r\n");
        for (name, value) in headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        crate::parse_request_head(request.as_bytes()).unwrap()
    }

    #[test]
    fn likely_main_frame_classification_treats_fetch_destination_as_authoritative() {
        let classify = |method, path, headers: &[(&str, &str)]| {
            is_likely_main_frame_navigation(&parsed_test_head(method, headers), path)
        };

        assert!(classify(
            "GET",
            "/asset.js",
            &[("Sec-Fetch-Dest", "document")]
        ));
        assert!(!classify(
            "HEAD",
            "/asset.js",
            &[
                ("Sec-Fetch-Dest", "IFRAME"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Accept", "text/html"),
            ]
        ));
        assert!(!classify(
            "GET",
            "/",
            &[
                ("Sec-Fetch-Dest", "script"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Accept", "text/html"),
            ],
        ));
        assert!(!classify(
            "GET",
            "/",
            &[
                ("Sec-Fetch-Dest", "future-subresource"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Upgrade-Insecure-Requests", "1"),
                ("Accept", "text/html"),
            ],
        ));
        assert!(classify(
            "GET",
            "/asset.js",
            &[("Sec-Fetch-Mode", "navigate")],
        ));
        assert!(classify(
            "GET",
            "/asset.js",
            &[("Upgrade-Insecure-Requests", "1")],
        ));
        assert!(classify(
            "GET",
            "/asset.js",
            &[("Accept", "application/xhtml+xml, TEXT/HTML;q=0.9")],
        ));
        assert!(classify("GET", "/", &[]));
        assert!(!classify("GET", "/?private=1", &[]));
        assert!(!classify("GET", "/asset.css", &[]));
        assert!(!classify("POST", "/", &[("Sec-Fetch-Dest", "document")],));
    }

    #[test]
    fn starts_on_ephemeral_loopback_with_fresh_redacted_credentials() {
        let first = RunningProxy::start(
            test_config(),
            Arc::new(UnusedBackend),
            Arc::new(NoopProxyObserver),
        )
        .unwrap();
        let second = RunningProxy::start(
            test_config(),
            Arc::new(UnusedBackend),
            Arc::new(NoopProxyObserver),
        )
        .unwrap();

        assert!(first.endpoint().address().ip().is_loopback());
        assert_ne!(first.endpoint().port(), 0);
        assert_ne!(first.endpoint().realm(), second.endpoint().realm());
        assert_ne!(first.endpoint().password(), second.endpoint().password());
        let debug = format!("{first:?}");
        assert!(!debug.contains(first.endpoint().realm()));
        assert!(!debug.contains(first.endpoint().password()));
        first.stop();
        first.stop();
        second.stop();
        assert!(first.is_stopped());
    }

    #[test]
    fn request_stop_revokes_admission_before_the_blocking_join() {
        let proxy = RunningProxy::start(
            test_config(),
            Arc::new(UnusedBackend),
            Arc::new(NoopProxyObserver),
        )
        .unwrap();

        proxy.request_stop();
        assert!(proxy.local_certificate_pin("welcome").is_none());
        assert!(!proxy.matches_local_certificate("welcome", b"certificate"));

        proxy.stop();
        assert!(proxy.is_stopped());
    }

    #[test]
    fn concurrent_stop_emits_lifecycle_events_once_and_in_order() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let event_sink = Arc::clone(&events);
        let observer = move |event: &ProxyEvent| {
            if let ProxyEvent::Lifecycle { event, .. } = event {
                event_sink
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(*event);
            }
        };
        let proxy = Arc::new(
            RunningProxy::start(test_config(), Arc::new(UnusedBackend), Arc::new(observer))
                .unwrap(),
        );
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let callers: Vec<_> = (0..8)
            .map(|_| {
                let proxy = Arc::clone(&proxy);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    proxy.stop();
                })
            })
            .collect();
        barrier.wait();
        for caller in callers {
            caller.join().unwrap();
        }

        assert!(proxy.is_stopped());
        assert_eq!(
            *events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec![
                LifecycleEvent::Listening {
                    port: proxy.endpoint().port(),
                },
                LifecycleEvent::Stopping,
                LifecycleEvent::Stopped {
                    reason: StopReason::Requested,
                },
            ]
        );
    }

    #[test]
    fn stopping_observer_can_reenter_running_proxy_stop() {
        let proxy_slot = Arc::new(Mutex::new(None::<std::sync::Weak<RunningProxy>>));
        let observer_slot = Arc::clone(&proxy_slot);
        let observer = move |event: &ProxyEvent| {
            if matches!(
                event,
                ProxyEvent::Lifecycle {
                    event: LifecycleEvent::Stopping,
                    ..
                }
            ) {
                let proxy = observer_slot
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade);
                if let Some(proxy) = proxy {
                    proxy.stop();
                }
            }
        };
        let proxy = Arc::new(
            RunningProxy::start(test_config(), Arc::new(UnusedBackend), Arc::new(observer))
                .unwrap(),
        );
        *proxy_slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::downgrade(&proxy));

        proxy.stop();

        assert!(proxy.is_stopped());
        assert_eq!(proxy.active_clients(), 0);
    }

    #[test]
    fn final_running_proxy_owner_dropped_from_callback_is_reaped_and_stopped() {
        let proxy_slot = Arc::new(Mutex::new(None::<std::sync::Weak<RunningProxy>>));
        let observer_slot = Arc::clone(&proxy_slot);
        let (upgraded_tx, upgraded_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let (released_tx, released_rx) = mpsc::channel();
        let (stopped_tx, stopped_rx) = mpsc::channel();
        let events = Arc::new(Mutex::new(Vec::new()));
        let event_sink = Arc::clone(&events);
        let observer = move |event: &ProxyEvent| {
            if let ProxyEvent::Lifecycle { event, .. } = event {
                event_sink
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(*event);
                if matches!(event, LifecycleEvent::Stopped { .. }) {
                    let _result = stopped_tx.send(());
                }
                return;
            }
            if matches!(
                event,
                ProxyEvent::Request {
                    phase: RequestPhase::Accepted,
                    ..
                }
            ) {
                let proxy = observer_slot
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade)
                    .unwrap();
                upgraded_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .recv_timeout(TEST_TIMEOUT)
                    .unwrap();
                drop(proxy);
                released_tx.send(()).unwrap();
            }
        };
        let proxy = Arc::new(
            RunningProxy::start(test_config(), Arc::new(UnusedBackend), Arc::new(observer))
                .unwrap(),
        );
        *proxy_slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::downgrade(&proxy));
        let address = proxy.endpoint().address();
        let request = format!(
            "GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n{}\r\n",
            auth_header(&proxy)
        );
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();
        upgraded_rx.recv_timeout(TEST_TIMEOUT).unwrap();

        drop(proxy);
        release_tx.send(()).unwrap();
        released_rx.recv_timeout(TEST_TIMEOUT).unwrap();
        drop(client);
        stopped_rx.recv_timeout(TEST_TIMEOUT).unwrap();
        assert_eq!(
            *events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec![
                LifecycleEvent::Listening {
                    port: address.port(),
                },
                LifecycleEvent::Stopping,
                LifecycleEvent::Stopped {
                    reason: StopReason::Requested,
                },
            ]
        );

        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            match std::net::TcpListener::bind(address) {
                Ok(listener) => {
                    drop(listener);
                    break;
                }
                Err(_) => {
                    assert!(Instant::now() < deadline);
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    #[test]
    fn listener_failure_revokes_pins_and_reports_quiescence_once() {
        let instance = ProxyInstanceId::new(ProxySessionId::generate().unwrap(), 71);
        let identities = Arc::new(LocalTlsIdentityStore::new(instance));
        let host = crate::NormalizedHost::parse("welcome").unwrap();
        drop(identities.prepare(&host).unwrap());
        assert!(identities.pin(&host).is_some());

        let events = Arc::new(Mutex::new(Vec::new()));
        let event_sink = Arc::clone(&events);
        let observer: Arc<dyn ProxyObserver> = Arc::new(move |event: &ProxyEvent| {
            if let ProxyEvent::Lifecycle { event, .. } = event {
                event_sink
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(*event);
            }
        });
        let stop_state = Arc::new(ProxyStopState::new());
        stop_state.publish_listening();
        let handler = listener_exit_handler(
            Arc::clone(&identities),
            Arc::clone(&observer),
            71,
            Arc::clone(&stop_state),
        );

        handler(ListenerExitPhase::FailureDetected);
        assert!(stop_state.requested.load(Ordering::Acquire));
        assert!(!stop_state.completed.load(Ordering::Acquire));
        assert!(identities.pin(&host).is_none());
        assert_eq!(
            *events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec![LifecycleEvent::Stopping]
        );

        handler(ListenerExitPhase::Quiesced(
            ListenerExitReason::ListenerFailure,
        ));
        handler(ListenerExitPhase::Quiesced(
            ListenerExitReason::ListenerFailure,
        ));
        assert!(stop_state.completed.load(Ordering::Acquire));
        assert_eq!(
            *events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec![
                LifecycleEvent::Stopping,
                LifecycleEvent::Stopped {
                    reason: StopReason::ListenerFailure,
                },
            ]
        );
    }

    #[test]
    fn authentication_precedes_target_validation_and_rejects_duplicates() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"unused")));
        let proxy = start_recording_proxy(Arc::clone(&backend));
        let valid = proxy.endpoint().authorization_header_value();
        let cases = [
            "GET not-an-absolute-target HTTP/1.1\r\nHost: mismatch.example\r\n\r\n"
                .to_owned(),
            "GET not-an-absolute-target HTTP/1.1\r\nHost: mismatch.example\r\nProxy-Authorization: Basic d3Jvbmc6d3Jvbmc=\r\n\r\n"
                .to_owned(),
            format!(
                "GET not-an-absolute-target HTTP/1.1\r\nHost: mismatch.example\r\nProxy-Authorization: {valid}\r\nProxy-Authorization: {valid}\r\n\r\n"
            ),
            "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n\r\n".to_owned(),
        ];

        for request in cases {
            let response = send_raw(&proxy, request.as_bytes());
            assert_eq!(response_status(&response), 407, "{request:?}");
            let (head, _) = response_parts(&response);
            assert!(head.contains(&format!(
                "Proxy-Authenticate: Basic realm=\"{}\"",
                proxy.endpoint().realm()
            )));
        }
        assert_eq!(backend.request_count(), 0);

        let request = format!(
            "GET not-an-absolute-target HTTP/1.1\r\nHost: welcome\r\n{}\r\n",
            auth_header(&proxy)
        );
        assert_eq!(response_status(&send_raw(&proxy, request.as_bytes())), 400);
        assert_eq!(backend.request_count(), 0);
        proxy.stop();
    }

    #[test]
    fn rate_limited_connect_does_not_generate_or_publish_an_identity() {
        let limits = ProxyLimits::new(
            ProxyLimits::DEFAULT_MAX_HEADER_BYTES,
            ProxyLimits::DEFAULT_MAX_BODY_BYTES,
            ProxyLimits::DEFAULT_MAX_ACTIVE_CLIENTS,
            1,
            1,
            ProxyLimits::DEFAULT_MAX_TRACKED_HOSTS,
            ProxyLimits::DEFAULT_RATE_WINDOW,
        )
        .unwrap();
        let config = ProxyConfig::with_controls(
            ProxyInstanceId::new(ProxySessionId::generate().unwrap(), 1),
            crate::HostScope::new("welcome").unwrap(),
            limits,
            ProxyTimeouts::default(),
            crate::LoopbackBind::Ipv4,
        );
        let proxy =
            RunningProxy::start(config, Arc::new(UnusedBackend), Arc::new(NoopProxyObserver))
                .unwrap();

        let admitted = format!(
            "GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n{}\r\n",
            auth_header(&proxy)
        );
        assert!(send_raw(&proxy, admitted.as_bytes()).is_empty());
        assert!(proxy.local_certificate_pin("welcome").is_none());

        let limited = format!(
            "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n{}\r\n",
            auth_header(&proxy)
        );
        assert_eq!(response_status(&send_raw(&proxy, limited.as_bytes())), 429);
        assert!(proxy.local_certificate_pin("welcome").is_none());
        proxy.stop();
    }

    #[test]
    fn canonical_forwarding_and_both_header_boundaries_are_enforced() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::Fixed {
            headers: vec![
                ProxyHeader::new("Content-Type", "text/plain"),
                ProxyHeader::new("X-Origin-Keep", "yes"),
                ProxyHeader::new("X-HNS-Security-Path", "dane"),
                ProxyHeader::new("X-HNS-Future", "private"),
                ProxyHeader::new("Connection", "X-Origin-Hop"),
                ProxyHeader::new("X-Origin-Hop", "remove"),
                ProxyHeader::new("Alt-Svc", "h3=\":443\""),
                ProxyHeader::new("Proxy-Authentication-Info", "secret"),
                ProxyHeader::new("Proxy-Future", "secret"),
                ProxyHeader::new("Content-Length", "999"),
                ProxyHeader::new("Transfer-Encoding", "chunked"),
            ],
            body: b"response-body".to_vec(),
        }));
        let proxy = start_recording_proxy(Arc::clone(&backend));
        let body = b"request-body";
        let request = format!(
            "POST http://Sub.WELCOME.:8080/private?q=s3cr3t HTTP/1.1\r\nHost: sub.welcome:8080\r\n{}Proxy-Future: secret\r\nX-HNS-Forged: secret\r\nConnection: keep-alive, X-Remove\r\nProxy-Connection: X-Proxy-Remove\r\nX-Remove: secret\r\nX-Proxy-Remove: secret\r\nKeep-Alive: timeout=5\r\nTE: trailers\r\nTrailer: X-Later\r\nAuthorization: Bearer origin-secret\r\nX-Keep: yes\r\nContent-Length: {}\r\n\r\n",
            auth_header(&proxy),
            body.len()
        );
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(body);

        let response = send_raw(&proxy, &bytes);
        assert_eq!(response_status(&response), 200);
        let (head, response_body) = response_parts(&response);
        assert_eq!(response_body, b"response-body");
        let lower_head = head.to_ascii_lowercase();
        assert!(lower_head.contains("x-origin-keep: yes\r\n"));
        assert!(lower_head.contains("connection: close\r\n"));
        assert!(lower_head.contains("content-length: 13\r\n"));
        for forbidden in [
            "x-hns-",
            "x-origin-hop",
            "alt-svc",
            "proxy-authentication-info",
            "proxy-future",
            "transfer-encoding",
            "content-length: 999",
        ] {
            assert!(
                !lower_head.contains(forbidden),
                "leaked {forbidden}: {head}"
            );
        }

        let requests = backend.take_requests();
        assert_eq!(requests.len(), 1);
        let forwarded = &requests[0];
        assert_eq!(forwarded.method, "POST");
        assert_eq!(forwarded.scheme, "http");
        assert_eq!(forwarded.host, "sub.welcome");
        assert_eq!(forwarded.port, 8080);
        assert_eq!(forwarded.path_and_query, "/private?q=s3cr3t");
        assert_eq!(forwarded.body.as_bytes(), body);
        let forwarded_names: Vec<_> = forwarded
            .headers
            .iter()
            .map(|header| header.name.to_ascii_lowercase())
            .collect();
        assert_eq!(
            forwarded_names
                .iter()
                .filter(|name| *name == "host")
                .count(),
            1
        );
        assert!(!forwarded_names.iter().any(|name| {
            name.starts_with("proxy-")
                || name.starts_with("x-hns-")
                || matches!(
                    name.as_str(),
                    "connection"
                        | "keep-alive"
                        | "te"
                        | "trailer"
                        | "transfer-encoding"
                        | "content-length"
                        | "x-remove"
                        | "x-proxy-remove"
                )
        }));
        assert!(forwarded.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("host") && header.value == "sub.welcome:8080"
        }));
        assert!(forwarded.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("authorization")
                && header.value == "Bearer origin-secret"
        }));
        assert!(
            forwarded.headers.iter().any(|header| {
                header.name.eq_ignore_ascii_case("x-keep") && header.value == "yes"
            })
        );
        proxy.stop();
    }

    #[test]
    fn ordinary_response_delivers_only_sanitized_typed_metadata() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::Fixed {
            headers: vec![
                ProxyHeader::new("Content-Type", "text/plain"),
                ProxyHeader::new("X-HNS-Security-Path", "dane"),
                ProxyHeader::new(
                    "X-HNS-Resolution-Trace",
                    r#"[{"origin_path":"/private?server=secret"}]"#,
                ),
                ProxyHeader::new("X-HNS-Future", "untrusted"),
                ProxyHeader::new("Connection", "X-HNS-Resolver-Policy"),
                ProxyHeader::new("X-HNS-Resolver-Policy", "nominated"),
            ],
            body: b"response-body-secret".to_vec(),
        }));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&observations);
        let observer = Arc::new(move |observation: &ProxyResponseMetadataObservation| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(observation.clone());
        });
        let proxy = start_recording_proxy_with_metadata(Arc::clone(&backend), observer);
        let body = b"request-body-secret";
        let request = format!(
            "GET http://welcome/private?token=request-secret HTTP/1.1\r\nHost: welcome\r\n{}Sec-Fetch-Dest: document\r\nX-Request-Secret: request-header-secret\r\nContent-Length: {}\r\n\r\n",
            auth_header(&proxy),
            body.len(),
        );
        let mut request = request.into_bytes();
        request.extend_from_slice(body);

        let response = send_raw(&proxy, &request);
        assert_eq!(response_status(&response), 200);
        let (head, response_body) = response_parts(&response);
        assert_eq!(response_body, b"response-body-secret");
        assert!(!head.to_ascii_lowercase().contains("x-hns-"));

        let observations = observations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(observations.len(), 1);
        let observation = &observations[0];
        assert_eq!(observation.generation(), 1);
        assert_eq!(observation.host().as_str(), "welcome");
        assert_eq!(observation.method(), ObservedMethod::Get);
        assert_eq!(observation.status_code(), 200);
        assert!(observation.is_likely_main_frame());
        assert_eq!(
            observation.metadata().get("X-HNS-Security-Path"),
            Some("dane")
        );
        assert_eq!(
            observation.metadata().get("X-HNS-Resolution-Trace"),
            Some(r#"[{"origin_path":"/private?server=secret"}]"#)
        );
        assert_eq!(observation.metadata().get("X-HNS-Future"), None);
        assert_eq!(observation.metadata().get("X-HNS-Resolver-Policy"), None);
        let diagnostic = format!("{observation:?}");
        for secret in [
            "private",
            "request-secret",
            "server=secret",
            "request-body-secret",
            "request-header-secret",
        ] {
            assert!(
                !diagnostic.contains(secret),
                "leaked {secret}: {diagnostic}"
            );
        }
        drop(observations);
        proxy.stop();
    }

    #[test]
    fn iframe_response_status_is_not_marked_as_main_frame() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"iframe")));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&observations);
        let observer = Arc::new(move |observation: &ProxyResponseMetadataObservation| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(observation.clone());
        });
        let proxy = start_recording_proxy_with_metadata(backend, observer);
        let request = format!(
            "GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n{}Sec-Fetch-Dest: iframe\r\nSec-Fetch-Mode: navigate\r\nAccept: text/html\r\n\r\n",
            auth_header(&proxy)
        );

        assert_eq!(response_status(&send_raw(&proxy, request.as_bytes())), 200);
        let observations = observations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].status_code(), 200);
        assert!(!observations[0].is_likely_main_frame());
        drop(observations);
        proxy.stop();
    }

    #[test]
    fn invalid_response_head_is_suppressed_without_an_authorized_fallback() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::Fixed {
            headers: vec![
                ProxyHeader::new("X-HNS-TLS-Policy", "dane"),
                ProxyHeader::new("x-hns-tls-policy", "webpki"),
            ],
            body: Vec::new(),
        }));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&observations);
        let observer = Arc::new(move |observation: &ProxyResponseMetadataObservation| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(observation.clone());
        });
        let proxy = start_recording_proxy_with_metadata(backend, observer);
        let request = format!(
            "GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n{}\r\n",
            auth_header(&proxy)
        );

        assert!(send_raw(&proxy, request.as_bytes()).is_empty());
        let observations = observations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(observations.is_empty());
        drop(observations);
        proxy.stop();
    }

    #[test]
    fn backend_failure_cannot_publish_an_unstamped_generated_response() {
        let observations = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&observations);
        let observer = Arc::new(move |observation: &ProxyResponseMetadataObservation| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(observation.clone());
        });
        let proxy = RunningProxy::start_with_metadata_observer(
            test_config(),
            Arc::new(UnusedBackend),
            Arc::new(NoopProxyObserver),
            observer,
        )
        .unwrap();
        let request = format!(
            "GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n{}\r\n",
            auth_header(&proxy)
        );

        assert!(send_raw(&proxy, request.as_bytes()).is_empty());
        let observations = observations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(observations.is_empty());
        drop(observations);
        proxy.stop();
    }

    #[test]
    fn panicking_metadata_observer_does_not_interrupt_response_delivery() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::Fixed {
            headers: vec![ProxyHeader::new("X-HNS-Security-Path", "dane")],
            body: b"ok".to_vec(),
        }));
        let observer = Arc::new(|_observation: &ProxyResponseMetadataObservation| {
            panic!("test metadata observer panic");
        });
        let proxy = start_recording_proxy_with_metadata(Arc::clone(&backend), observer);
        let request = format!(
            "GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n{}\r\n",
            auth_header(&proxy)
        );

        for _ in 0..2 {
            let response = send_raw(&proxy, request.as_bytes());
            assert_eq!(response_status(&response), 200);
            assert_eq!(response_parts(&response).1, b"ok");
        }
        assert_eq!(backend.request_count(), 2);
        proxy.stop();
    }

    #[test]
    fn fixed_and_chunked_request_bodies_are_forwarded_without_framing_fields() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"ok")));
        let proxy = start_recording_proxy(Arc::clone(&backend));
        let fixed = format!(
            "POST http://welcome/fixed HTTP/1.1\r\nHost: welcome\r\n{}Content-Length: 5\r\n\r\nfixed",
            auth_header(&proxy)
        );
        assert_eq!(response_status(&send_raw(&proxy, fixed.as_bytes())), 200);

        let chunked = format!(
            "POST http://welcome/chunked HTTP/1.1\r\nHost: welcome\r\n{}Transfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Origin-Trailer: ignored\r\n\r\n",
            auth_header(&proxy)
        );
        assert_eq!(response_status(&send_raw(&proxy, chunked.as_bytes())), 200);

        let requests = backend.take_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].path_and_query, "/fixed");
        assert_eq!(requests[0].body.as_bytes(), b"fixed");
        assert_eq!(requests[1].path_and_query, "/chunked");
        assert_eq!(requests[1].body.as_bytes(), b"Wikipedia");
        for request in requests {
            assert!(!request.headers.iter().any(|header| {
                header.name.eq_ignore_ascii_case("content-length")
                    || header.name.eq_ignore_ascii_case("transfer-encoding")
                    || header.name.eq_ignore_ascii_case("x-hns-trailer")
                    || header.name.eq_ignore_ascii_case("x-origin-trailer")
            }));
        }
        proxy.stop();
    }

    #[test]
    fn oversized_expect_request_is_rejected_before_continue_or_body_read() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"unused")));
        let proxy = start_recording_proxy(Arc::clone(&backend));
        let request = format!(
            "POST http://welcome/upload HTTP/1.1\r\nHost: welcome\r\n{}Expect: 100-continue\r\nContent-Length: {}\r\n\r\n",
            auth_header(&proxy),
            ProxyLimits::DEFAULT_MAX_BODY_BYTES + 1,
        );

        let response = send_raw(&proxy, request.as_bytes());
        assert_eq!(response_status(&response), 413);
        assert!(!response.starts_with(b"HTTP/1.1 100 Continue"));
        assert_eq!(backend.request_count(), 0);
        proxy.stop();
    }

    #[test]
    fn connect_rejections_before_200_never_publish_a_pin_or_reach_the_backend() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"unused")));
        let proxy = start_recording_proxy(Arc::clone(&backend));
        let valid = proxy.endpoint().authorization_header_value();
        let cases = [
            (
                "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n\r\n".to_owned(),
                407,
            ),
            (
                "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\nProxy-Authorization: Basic d3Jvbmc6d3Jvbmc=\r\n\r\n"
                    .to_owned(),
                407,
            ),
            (
                format!(
                    "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\nProxy-Authorization: {valid}\r\nProxy-Authorization: {valid}\r\n\r\n"
                ),
                407,
            ),
            (
                format!(
                    "CONNECT other:443 HTTP/1.1\r\nHost: other:443\r\n{}\r\n",
                    auth_header(&proxy)
                ),
                403,
            ),
            (
                format!(
                    "CONNECT welcome:443 HTTP/1.1\r\nHost: sub.welcome:443\r\n{}\r\n",
                    auth_header(&proxy)
                ),
                400,
            ),
            (
                format!(
                    "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n{}Content-Length: 1\r\n\r\nx",
                    auth_header(&proxy)
                ),
                400,
            ),
            (
                format!(
                    "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n{}Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                    auth_header(&proxy)
                ),
                400,
            ),
            (
                format!(
                    "CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n{}Expect: 100-continue\r\nContent-Length: 0\r\n\r\n",
                    auth_header(&proxy)
                ),
                417,
            ),
        ];

        for (request, expected_status) in cases {
            let response = send_raw(&proxy, request.as_bytes());
            assert_eq!(response_status(&response), expected_status, "{request:?}");
            assert!(proxy.local_certificate_pin("welcome").is_none());
            assert!(proxy.local_certificate_pin("other").is_none());
            assert!(!proxy.matches_local_certificate("welcome", b"not-a-certificate"));
        }
        assert_eq!(backend.request_count(), 0);
        proxy.stop();
    }

    #[test]
    fn exact_sni_get_and_post_use_https_routes_and_sanitize_both_header_boundaries() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::Fixed {
            headers: vec![
                ProxyHeader::new("Content-Type", "text/plain"),
                ProxyHeader::new("X-Origin-Keep", "yes"),
                ProxyHeader::new("X-HNS-Security-Path", "dane"),
                ProxyHeader::new("Alt-Svc", "h3=\":443\""),
                ProxyHeader::new("Connection", "X-Origin-Hop"),
                ProxyHeader::new("X-Origin-Hop", "remove"),
            ],
            body: b"tls-ok".to_vec(),
        }));
        let proxy = start_recording_proxy(Arc::clone(&backend));

        let get = b"GET /asset?q=1 HTTP/1.1\r\nHost: welcome\r\nProxy-Authorization: forged\r\nProxy-Future: secret\r\nX-HNS-Forged: secret\r\nConnection: close, X-Remove\r\nX-Remove: secret\r\nAuthorization: Bearer origin-secret\r\nX-Keep: yes\r\n\r\n";
        let (get_response, get_certificate) =
            send_tls_request(&proxy, "welcome:443", "welcome", get);
        assert_eq!(response_status(&get_response), 200);
        let (get_head, get_body) = response_parts(&get_response);
        assert_eq!(get_body, b"tls-ok");
        let lower_get_head = get_head.to_ascii_lowercase();
        assert!(lower_get_head.contains("x-origin-keep: yes\r\n"));
        for forbidden in ["x-hns-", "alt-svc", "x-origin-hop"] {
            assert!(!lower_get_head.contains(forbidden), "{get_head}");
        }
        assert!(proxy.matches_local_certificate("welcome", &get_certificate));
        assert!(!proxy.matches_local_certificate("sub.welcome", &get_certificate));

        let post_head = b"POST /submit?q=2 HTTP/1.1\r\nHost: sub.welcome:8443\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nProxy-Future: secret\r\nX-HNS-Forged: secret\r\nX-Keep: post\r\n\r\n";
        let mut post = post_head.to_vec();
        post.extend_from_slice(b"payload");
        let (post_response, post_certificate) =
            send_tls_request(&proxy, "sub.welcome:8443", "sub.welcome", &post);
        assert_eq!(response_status(&post_response), 200);
        assert!(proxy.matches_local_certificate("sub.welcome", &post_certificate));
        assert!(!proxy.matches_local_certificate("welcome", &post_certificate));

        let requests = backend.take_requests();
        assert_eq!(requests.len(), 2);
        let get_request = &requests[0];
        assert_eq!(get_request.method, "GET");
        assert_eq!(get_request.scheme, "https");
        assert_eq!(get_request.host, "welcome");
        assert_eq!(get_request.port, 443);
        assert_eq!(get_request.path_and_query, "/asset?q=1");
        assert!(get_request.body.is_empty());
        assert!(get_request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("host") && header.value == "welcome"
        }));
        assert!(get_request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("authorization")
                && header.value == "Bearer origin-secret"
        }));

        let post_request = &requests[1];
        assert_eq!(post_request.method, "POST");
        assert_eq!(post_request.scheme, "https");
        assert_eq!(post_request.host, "sub.welcome");
        assert_eq!(post_request.port, 8443);
        assert_eq!(post_request.path_and_query, "/submit?q=2");
        assert_eq!(post_request.body.as_bytes(), b"payload");
        assert!(post_request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("host") && header.value == "sub.welcome:8443"
        }));

        for request in requests {
            assert!(!request.headers.iter().any(|header| {
                let name = header.name.to_ascii_lowercase();
                name.starts_with("proxy-")
                    || name.starts_with("x-hns-")
                    || matches!(
                        name.as_str(),
                        "connection" | "content-length" | "transfer-encoding" | "x-remove"
                    )
            }));
        }
        proxy.stop();
    }

    #[test]
    fn wrong_or_missing_sni_and_h2_only_never_reach_the_backend() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"unused")));
        let proxy = start_recording_proxy(Arc::clone(&backend));
        let cases: [(&str, bool, &[&[u8]]); 3] = [
            ("other.welcome", true, &[b"http/1.1"]),
            ("welcome", false, &[b"http/1.1"]),
            ("welcome", true, &[b"h2"]),
        ];

        for (server_name, enable_sni, alpn_protocols) in cases {
            let stream = begin_authenticated_connect(&proxy, "welcome:443");
            assert!(proxy.local_certificate_pin("welcome").is_some());
            assert!(
                complete_tls_handshake(stream, server_name, enable_sni, alpn_protocols).is_err(),
                "unexpectedly accepted SNI={server_name:?}, enabled={enable_sni}, ALPN={alpn_protocols:?}"
            );
        }
        assert_eq!(backend.request_count(), 0);
        proxy.stop();
    }

    #[test]
    fn invalid_connected_targets_never_reach_the_backend() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"unused")));
        let proxy = start_recording_proxy(Arc::clone(&backend));
        let cases: [(&str, &str, &[u8], u16); 6] = [
            (
                "welcome:443",
                "welcome",
                b"GET / HTTP/1.1\r\nHost: other.welcome\r\n\r\n",
                400,
            ),
            (
                "welcome:8443",
                "welcome",
                b"GET / HTTP/1.1\r\nHost: welcome\r\n\r\n",
                400,
            ),
            (
                "welcome:443",
                "welcome",
                b"GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n\r\n",
                400,
            ),
            (
                "welcome:443",
                "welcome",
                b"CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n\r\n",
                400,
            ),
            (
                "welcome:443",
                "welcome",
                b"GET /socket HTTP/1.1\r\nHost: welcome\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                501,
            ),
            (
                "welcome:443",
                "welcome",
                b"GET wss://welcome/socket HTTP/1.1\r\nHost: welcome\r\n\r\n",
                400,
            ),
        ];

        for (authority, server_name, request, expected_status) in cases {
            let (response, _certificate) =
                send_tls_request(&proxy, authority, server_name, request);
            assert_eq!(
                response_status(&response),
                expected_status,
                "authority={authority:?}, request={request:?}"
            );
        }
        assert_eq!(backend.request_count(), 0);
        proxy.stop();
    }

    #[test]
    fn certificate_pins_are_generation_bound_and_revoked_on_stop() {
        let session = ProxySessionId::generate().unwrap();
        let first_backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"first")));
        let second_backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"second")));
        let first = RunningProxy::start(
            ProxyConfig::new(
                ProxyInstanceId::new(session.clone(), 1),
                crate::HostScope::new("welcome").unwrap(),
            ),
            first_backend,
            Arc::new(NoopProxyObserver),
        )
        .unwrap();
        let second = RunningProxy::start(
            ProxyConfig::new(
                ProxyInstanceId::new(session, 2),
                crate::HostScope::new("welcome").unwrap(),
            ),
            second_backend,
            Arc::new(NoopProxyObserver),
        )
        .unwrap();
        let request = b"GET / HTTP/1.1\r\nHost: welcome\r\n\r\n";

        let (first_response, first_certificate) =
            send_tls_request(&first, "welcome:443", "welcome", request);
        let (second_response, second_certificate) =
            send_tls_request(&second, "welcome:443", "welcome", request);
        assert_eq!(response_status(&first_response), 200);
        assert_eq!(response_status(&second_response), 200);
        let first_pin = first.local_certificate_pin("welcome").unwrap();
        let second_pin = second.local_certificate_pin("welcome").unwrap();
        assert_eq!(first_pin.instance().generation(), 1);
        assert_eq!(second_pin.instance().generation(), 2);
        assert_ne!(
            first_pin.certificate_sha256(),
            second_pin.certificate_sha256()
        );
        assert!(first.matches_local_certificate("welcome", &first_certificate));
        assert!(!first.matches_local_certificate("welcome", &second_certificate));
        assert!(second.matches_local_certificate("welcome", &second_certificate));
        assert!(!second.matches_local_certificate("welcome", &first_certificate));

        first.stop();
        assert!(first.local_certificate_pin("welcome").is_none());
        assert!(!first.matches_local_certificate("welcome", &first_certificate));
        assert!(second.local_certificate_pin("welcome").is_some());
        assert!(second.matches_local_certificate("welcome", &second_certificate));
        second.stop();
        assert!(second.local_certificate_pin("welcome").is_none());
        assert!(!second.matches_local_certificate("welcome", &second_certificate));
    }

    #[test]
    fn stop_interrupts_a_partial_client_hello_and_revokes_its_pin() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"unused")));
        let proxy = start_recording_proxy(Arc::clone(&backend));
        let mut stream = begin_authenticated_connect(&proxy, "welcome:443");
        assert!(proxy.local_certificate_pin("welcome").is_some());
        stream
            .write_all(b"\x16\x03\x03\x00\x40\x01\x00\x00")
            .unwrap();
        stream.flush().unwrap();
        wait_for_active_clients(&proxy, 1);

        let started = Instant::now();
        proxy.stop();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(proxy.is_stopped());
        assert_eq!(proxy.active_clients(), 0);
        assert_eq!(backend.request_count(), 0);
        assert!(proxy.local_certificate_pin("welcome").is_none());
        assert!(!proxy.matches_local_certificate("welcome", b"not-a-certificate"));
        assert_connection_closed(stream);
    }

    #[test]
    fn stop_joins_tls_clients_stalled_in_inner_headers_and_bodies() {
        let header_backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"unused")));
        let header_proxy = start_recording_proxy(Arc::clone(&header_backend));
        let header_stream = begin_authenticated_connect(&header_proxy, "welcome:443");
        let (mut header_tls, _certificate) =
            complete_tls_handshake(header_stream, "welcome", true, &[b"http/1.1"]).unwrap();
        header_tls
            .write_all(b"GET / HTTP/1.1\r\nHost: wel")
            .unwrap();
        header_tls.flush().unwrap();
        wait_for_active_clients(&header_proxy, 1);

        let started = Instant::now();
        header_proxy.stop();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(header_proxy.active_clients(), 0);
        assert_eq!(header_backend.request_count(), 0);
        assert!(!matches!(header_tls.read(&mut [0_u8; 1]), Ok(1..)));

        let body_backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"unused")));
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let body_proxy = RunningProxy::start(
            test_config(),
            body_backend.clone(),
            Arc::new(AcceptedObserver(accepted_tx)),
        )
        .unwrap();
        let body_stream = begin_authenticated_connect(&body_proxy, "welcome:443");
        let (mut body_tls, _certificate) =
            complete_tls_handshake(body_stream, "welcome", true, &[b"http/1.1"]).unwrap();
        body_tls
            .write_all(b"POST / HTTP/1.1\r\nHost: welcome\r\nContent-Length: 12\r\n\r\nshort")
            .unwrap();
        body_tls.flush().unwrap();
        accepted_rx.recv_timeout(TEST_TIMEOUT).unwrap();
        accepted_rx.recv_timeout(TEST_TIMEOUT).unwrap();

        let started = Instant::now();
        body_proxy.stop();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(body_proxy.active_clients(), 0);
        assert_eq!(body_backend.request_count(), 0);
        assert!(!matches!(body_tls.read(&mut [0_u8; 1]), Ok(1..)));
    }

    #[test]
    fn direct_websocket_upgrade_is_sanitized_and_copied_bidirectionally() {
        let backend = Arc::new(EchoTunnelBackend::websocket(b"origin"));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&observations);
        let (observed_tx, observed_rx) = mpsc::channel();
        let metadata_observer = Arc::new(move |observation: &ProxyResponseMetadataObservation| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(observation.clone());
            let _result = observed_tx.send(());
        });
        let proxy = RunningProxy::start_with_metadata_observer(
            test_config(),
            backend.clone(),
            Arc::new(NoopProxyObserver),
            metadata_observer,
        )
        .unwrap();
        let mut client = TcpStream::connect(proxy.endpoint().address()).unwrap();
        client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        client.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
        let request = format!(
            "GET ws://welcome/socket?q=1 HTTP/1.1\r\nHost: welcome\r\n{}Connection: keep-alive, Upgrade, X-Secret\r\nUpgrade: websocket\r\nSec-WebSocket-Key: key\r\nSec-WebSocket-Version: 13\r\nX-Secret: remove\r\nX-HNS-Client: remove\r\n\r\n",
            auth_header(&proxy)
        );
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();

        let response = read_response_head(&mut client).unwrap();
        let response_text = std::str::from_utf8(&response).unwrap();
        assert_eq!(response_status(&response), 101);
        assert!(response_text.contains("Connection: Upgrade\r\n"));
        assert!(response_text.contains("Upgrade: websocket\r\n"));
        assert!(response_text.contains("Sec-WebSocket-Accept: accepted\r\n"));
        assert!(!response_text.contains("keep-alive"));
        assert!(!response_text.contains("X-Origin-Hop"));
        assert!(!response_text.contains("X-HNS-"));
        observed_rx.recv_timeout(TEST_TIMEOUT).unwrap();
        {
            let observations = observations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(observations.len(), 1);
            let observation = &observations[0];
            assert_eq!(observation.generation(), 1);
            assert_eq!(observation.host().as_str(), "welcome");
            assert_eq!(observation.method(), ObservedMethod::Get);
            assert_eq!(observation.status_code(), 101);
            assert!(!observation.is_likely_main_frame());
            assert_eq!(
                observation.metadata().get("X-HNS-Security-Path"),
                Some("secret")
            );
            let diagnostic = format!("{observation:?}");
            assert!(!diagnostic.contains("socket"));
            assert!(!diagnostic.contains("q=1"));
            assert!(!diagnostic.contains("secret"));
        }
        let mut from_origin = [0_u8; 6];
        client.read_exact(&mut from_origin).unwrap();
        assert_eq!(&from_origin, b"origin");
        client.write_all(b"client").unwrap();
        client.flush().unwrap();
        let mut echoed = [0_u8; 6];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"client");
        drop(client);

        let requests = backend.take_requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "GET");
        assert_eq!(request.scheme, "ws");
        assert_eq!(request.host, "welcome");
        assert_eq!(request.port, 80);
        assert_eq!(request.path_and_query, "/socket?q=1");
        assert!(request.body.is_empty());
        assert!(request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("connection") && header.value == "Upgrade"
        }));
        assert!(request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("upgrade") && header.value == "websocket"
        }));
        assert!(request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("sec-websocket-key") && header.value == "key"
        }));
        assert!(!request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("proxy-authorization")
                || header.name.eq_ignore_ascii_case("x-secret")
                || header.name.to_ascii_lowercase().starts_with("x-hns-")
        }));
        proxy.stop();
    }

    #[test]
    fn post_connect_wss_upgrade_uses_the_same_rust_tunnel_path() {
        let backend = Arc::new(EchoTunnelBackend::websocket(Vec::new()));
        let proxy =
            RunningProxy::start(test_config(), backend.clone(), Arc::new(NoopProxyObserver))
                .unwrap();
        let stream = begin_authenticated_connect(&proxy, "welcome:443");
        let (mut tls, _certificate) =
            complete_tls_handshake(stream, "welcome", true, &[b"http/1.1"]).unwrap();
        tls.write_all(
            b"GET wss://welcome/socket HTTP/1.1\r\nHost: welcome\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: key\r\nSec-WebSocket-Version: 13\r\n\r\nping",
        )
        .unwrap();
        tls.flush().unwrap();

        let response = read_response_head(&mut tls).unwrap();
        assert_eq!(response_status(&response), 101);
        assert!(
            !std::str::from_utf8(&response)
                .unwrap()
                .contains("X-HNS-Security-Path")
        );
        let mut echoed = [0_u8; 4];
        tls.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping");
        drop(tls);

        let requests = backend.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].scheme, "wss");
        assert_eq!(requests[0].host, "welcome");
        assert_eq!(requests[0].port, 443);
        assert_eq!(requests[0].path_and_query, "/socket");
        proxy.stop();
    }

    #[test]
    fn post_connect_icann_wss_upgrade_uses_the_shared_rust_tunnel_path() {
        let backend = Arc::new(EchoTunnelBackend::websocket(Vec::new()));
        let proxy = RunningProxy::start(
            whole_browser_config(Some("welcome")),
            backend.clone(),
            Arc::new(NoopProxyObserver),
        )
        .unwrap();
        let stream = begin_authenticated_connect(&proxy, "example.com:443");
        let (mut tls, certificate) =
            complete_tls_handshake(stream, "example.com", true, &[b"http/1.1"]).unwrap();
        assert!(proxy.matches_local_certificate("example.com", &certificate));
        tls.write_all(
            b"GET wss://example.com/socket HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: key\r\nSec-WebSocket-Version: 13\r\n\r\nping",
        )
        .unwrap();
        tls.flush().unwrap();

        let response = read_response_head(&mut tls).unwrap();
        assert_eq!(response_status(&response), 101);
        let mut echoed = [0_u8; 4];
        tls.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping");
        drop(tls);

        let requests = backend.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].scheme, "wss");
        assert_eq!(requests[0].host, "example.com");
        assert_eq!(requests[0].port, 443);
        assert_eq!(requests[0].path_and_query, "/socket");
        proxy.stop();
    }

    #[test]
    fn invalid_upgrade_response_fails_before_switching_protocols() {
        let backend = Arc::new(EchoTunnelBackend::with_head(ProxyResponseHead {
            status_code: 200,
            reason_phrase: "OK".to_owned(),
            headers: vec![
                ProxyHeader::new("Connection", "Upgrade"),
                ProxyHeader::new("Upgrade", "websocket"),
                ProxyHeader::new("X-HNS-Security-Path", "must-not-observe"),
            ],
            observation_id: None,
        }));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&observations);
        let metadata_observer = Arc::new(move |observation: &ProxyResponseMetadataObservation| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(observation.clone());
        });
        let proxy = RunningProxy::start_with_metadata_observer(
            test_config(),
            backend.clone(),
            Arc::new(NoopProxyObserver),
            metadata_observer,
        )
        .unwrap();
        let request = format!(
            "GET ws://welcome/socket HTTP/1.1\r\nHost: welcome\r\n{}Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            auth_header(&proxy)
        );

        let response = send_raw(&proxy, request.as_bytes());
        assert_eq!(response_status(&response), 502);
        assert!(!String::from_utf8_lossy(&response).contains("101 Switching Protocols"));
        assert_eq!(backend.take_requests().len(), 1);
        assert!(
            observations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        );
        proxy.stop();
    }

    #[test]
    fn upgrade_backend_can_fail_with_a_bounded_http_response() {
        let observations = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&observations);
        let metadata_observer = Arc::new(move |observation: &ProxyResponseMetadataObservation| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(observation.clone());
        });
        let proxy = RunningProxy::start_with_metadata_observer(
            test_config(),
            Arc::new(HttpRejectingTunnelBackend),
            Arc::new(NoopProxyObserver),
            metadata_observer,
        )
        .unwrap();
        let request = format!(
            "GET ws://welcome/ HTTP/1.1\r\nHost: welcome\r\n{}Connection: Upgrade\r\nUpgrade: websocket\r\nSec-Fetch-Dest: document\r\n\r\n",
            auth_header(&proxy)
        );

        let response = send_raw(&proxy, request.as_bytes());
        assert_eq!(response_status(&response), 404);
        let (head, body) = response_parts(&response);
        assert!(head.contains("Content-Type: text/plain\r\n"));
        assert!(head.contains("Content-Length: 22\r\n"));
        assert!(!head.contains("Upgrade:"));
        assert!(!head.contains("X-HNS-"));
        assert_eq!(body, b"verified non-inclusion");
        let observations = observations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].status_code(), 404);
        assert_eq!(observations[0].method(), ObservedMethod::Get);
        assert!(!observations[0].is_likely_main_frame());
        assert_eq!(
            observations[0].metadata().get("X-HNS-Security-Path"),
            Some("verified-non-inclusion")
        );
        drop(observations);
        proxy.stop();
    }

    #[test]
    fn stop_joins_an_idle_upgrade_without_detached_copy_workers() {
        let backend = Arc::new(EchoTunnelBackend::websocket(Vec::new()));
        let proxy =
            RunningProxy::start(test_config(), backend.clone(), Arc::new(NoopProxyObserver))
                .unwrap();
        let mut client = TcpStream::connect(proxy.endpoint().address()).unwrap();
        client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let request = format!(
            "GET ws://welcome/socket HTTP/1.1\r\nHost: welcome\r\n{}Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            auth_header(&proxy)
        );
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();
        assert_eq!(
            response_status(&read_response_head(&mut client).unwrap()),
            101
        );
        wait_for_active_clients(&proxy, 1);

        let started = Instant::now();
        proxy.stop();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(proxy.is_stopped());
        assert_eq!(proxy.active_clients(), 0);
        assert_eq!(backend.take_requests().len(), 1);
        assert_connection_closed(client);
    }

    #[test]
    fn upgrades_and_out_of_scope_targets_never_reach_the_backend() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"unused")));
        let proxy = start_recording_proxy(Arc::clone(&backend));
        let auth = auth_header(&proxy);
        let cases = [
            (
                format!("CONNECT other:443 HTTP/1.1\r\nHost: other:443\r\n{auth}\r\n"),
                403,
            ),
            (
                format!(
                    "GET http://welcome/socket HTTP/1.1\r\nHost: welcome\r\n{auth}Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                ),
                501,
            ),
            (
                format!("GET ws://welcome/socket HTTP/1.1\r\nHost: welcome\r\n{auth}\r\n"),
                400,
            ),
            (
                format!("GET http://other/ HTTP/1.1\r\nHost: other\r\n{auth}\r\n"),
                403,
            ),
            (
                format!("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n{auth}\r\n"),
                403,
            ),
        ];

        for (request, expected) in cases {
            assert_eq!(
                response_status(&send_raw(&proxy, request.as_bytes())),
                expected,
                "{request:?}"
            );
        }
        assert_eq!(backend.request_count(), 0);
        proxy.stop();
    }

    #[test]
    fn premature_response_stream_eof_closes_without_a_second_response() {
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::ShortStream {
            expected_len: 9,
            bytes: b"tiny".to_vec(),
        }));
        let proxy = start_recording_proxy(Arc::clone(&backend));
        let request = format!(
            "GET http://welcome/stream HTTP/1.1\r\nHost: welcome\r\n{}\r\n",
            auth_header(&proxy)
        );

        let response = send_raw(&proxy, request.as_bytes());
        assert_eq!(response_status(&response), 200);
        let (head, body) = response_parts(&response);
        assert!(head.contains("Content-Length: 9\r\n"));
        assert_eq!(body, b"tiny");
        assert_eq!(
            response
                .windows(b"HTTP/1.1".len())
                .filter(|window| *window == b"HTTP/1.1")
                .count(),
            1
        );
        assert_eq!(backend.request_count(), 1);
        proxy.stop();
    }

    #[test]
    fn stop_closes_clients_stalled_in_partial_headers_and_bodies() {
        let header_backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"unused")));
        let header_proxy = start_recording_proxy(Arc::clone(&header_backend));
        let mut partial_head = TcpStream::connect(header_proxy.endpoint().address()).unwrap();
        partial_head
            .write_all(b"GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n")
            .unwrap();
        wait_for_active_clients(&header_proxy, 1);
        header_proxy.stop();
        assert!(header_proxy.is_stopped());
        assert_eq!(header_proxy.active_clients(), 0);
        assert_eq!(header_backend.request_count(), 0);
        assert_connection_closed(partial_head);

        let body_backend = Arc::new(RecordingBackend::new(ResponsePlan::plain(b"unused")));
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let body_proxy = RunningProxy::start(
            test_config(),
            body_backend.clone(),
            Arc::new(AcceptedObserver(accepted_tx)),
        )
        .unwrap();
        let mut partial_body = TcpStream::connect(body_proxy.endpoint().address()).unwrap();
        let request = format!(
            "POST http://welcome/upload HTTP/1.1\r\nHost: welcome\r\n{}Content-Length: 10\r\n\r\nabc",
            auth_header(&body_proxy)
        );
        partial_body.write_all(request.as_bytes()).unwrap();
        accepted_rx.recv_timeout(TEST_TIMEOUT).unwrap();
        wait_for_active_clients(&body_proxy, 1);
        body_proxy.stop();
        assert!(body_proxy.is_stopped());
        assert_eq!(body_proxy.active_clients(), 0);
        assert_eq!(body_backend.request_count(), 0);
        assert_connection_closed(partial_body);
    }

    #[test]
    fn stop_joins_a_cooperative_backend_response_stream_read() {
        let (read_started_tx, read_started_rx) = mpsc::channel();
        let backend = Arc::new(CooperativeStreamBackend {
            read_started: Mutex::new(Some(read_started_tx)),
        });
        let proxy =
            RunningProxy::start(test_config(), backend, Arc::new(NoopProxyObserver)).unwrap();
        let mut client = TcpStream::connect(proxy.endpoint().address()).unwrap();
        client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        client.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
        let request = format!(
            "GET http://welcome/stream HTTP/1.1\r\nHost: welcome\r\n{}\r\n",
            auth_header(&proxy)
        );
        client.write_all(request.as_bytes()).unwrap();
        client.flush().unwrap();
        read_started_rx.recv_timeout(TEST_TIMEOUT).unwrap();
        let response_head = read_response_head(&mut client).unwrap();
        assert_eq!(response_status(&response_head), 200);
        wait_for_active_clients(&proxy, 1);

        let started = Instant::now();
        proxy.stop();

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(proxy.is_stopped());
        assert_eq!(proxy.active_clients(), 0);
        assert_connection_closed(client);
    }

    #[test]
    fn helper_rounds_retry_after_up_and_maps_backend_failures() {
        assert_eq!(retry_after_seconds(Duration::from_nanos(1)), 1);
        assert_eq!(retry_after_seconds(Duration::from_secs(2)), 2);
        assert_eq!(
            backend_error_status(BackendError::TlsValidationFailed),
            (502, "HNS TLS Validation Failed")
        );
    }

    #[test]
    fn exact_stream_copy_rejects_premature_eof() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || TcpStream::connect(address).unwrap());
        let (mut server, _) = listener.accept().unwrap();
        let _client = client.join().unwrap();

        assert_eq!(
            copy_exact_response(
                &mut server,
                &mut Cursor::new(b"x".to_vec()),
                2,
                &CancellationToken::new(),
            ),
            Err(WriteBackendError::InvalidAfterHead)
        );
    }

    #[test]
    fn publication_permit_is_released_before_a_response_body_read_can_block() {
        struct ReleasePermit(Option<mpsc::Sender<()>>);

        impl crate::PublicationPermit for ReleasePermit {}

        impl Drop for ReleasePermit {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _result = sender.send(());
                }
            }
        }

        struct PermitAwareReader {
            released: Option<mpsc::Receiver<()>>,
            bytes: Cursor<Vec<u8>>,
        }

        impl Read for PermitAwareReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if let Some(released) = self.released.take() {
                    released.recv_timeout(TEST_TIMEOUT).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("response-head permit remained held during body read: {error}"),
                        )
                    })?;
                }
                self.bytes.read(buffer)
            }
        }

        let (released_tx, released_rx) = mpsc::channel();
        let response = ProxyResponse {
            head: ProxyResponseHead {
                status_code: 200,
                reason_phrase: "OK".to_owned(),
                headers: vec![ProxyHeader::new("Content-Type", "text/plain")],
                observation_id: None,
            },
            body: ProxyResponseBody::Stream {
                expected_len: 2,
                reader: Box::new(PermitAwareReader {
                    released: Some(released_rx),
                    bytes: Cursor::new(b"ok".to_vec()),
                }),
            },
            publication: Default::default(),
        };
        let mut output = Vec::new();

        write_backend_response(
            &mut output,
            "GET",
            response,
            &CancellationToken::new(),
            Box::new(ReleasePermit(Some(released_tx))),
            |_| {},
        )
        .unwrap();

        assert!(output.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(output.ends_with(b"\r\n\r\nok"));
    }

    #[test]
    fn whole_browser_scope_is_not_a_namespace_classifier() {
        let network = Arc::new(CountingIcannNetwork::new(
            vec!["1.1.1.1:443".parse().unwrap()],
            Vec::new(),
        ));
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain("dual-root")));
        let proxy = start_proxy_with_icann_network(
            whole_browser_config(Some("welcome")),
            backend.clone(),
            network.clone(),
        );
        for host in ["other", "sub.other"] {
            let request = format!(
                "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n{}\r\n",
                auth_header(&proxy)
            );
            assert_eq!(response_status(&send_raw(&proxy, request.as_bytes())), 200);
        }
        assert_eq!(network.resolve_calls(), 0);
        assert_eq!(network.connect_calls(), 0);
        assert_eq!(backend.request_count(), 2);
        proxy.stop();

        let deny_all_network = Arc::new(CountingIcannNetwork::new(
            vec!["1.1.1.1:443".parse().unwrap()],
            Vec::new(),
        ));
        let whole_browser_backend =
            Arc::new(RecordingBackend::new(ResponsePlan::plain("dual-root")));
        let deny_all = start_proxy_with_icann_network(
            whole_browser_config(None),
            whole_browser_backend.clone(),
            deny_all_network.clone(),
        );
        let request = format!(
            "GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n{}\r\n",
            auth_header(&deny_all)
        );
        assert_eq!(
            response_status(&send_raw(&deny_all, request.as_bytes())),
            200
        );
        assert_eq!(deny_all_network.resolve_calls(), 0);
        assert_eq!(deny_all_network.connect_calls(), 0);
        assert_eq!(whole_browser_backend.request_count(), 1);
        deny_all.stop();
    }

    #[test]
    fn default_scoped_mode_still_rejects_icann_without_network_or_backend() {
        let network = Arc::new(CountingIcannNetwork::new(
            vec!["1.1.1.1:443".parse().unwrap()],
            Vec::new(),
        ));
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain("unused")));
        let proxy = start_proxy_with_icann_network(test_config(), backend.clone(), network.clone());
        let request = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n{}\r\n",
            auth_header(&proxy)
        );
        assert_eq!(response_status(&send_raw(&proxy, request.as_bytes())), 403);
        assert_eq!(network.resolve_calls(), 0);
        assert_eq!(network.connect_calls(), 0);
        assert_eq!(backend.request_count(), 0);
    }

    #[test]
    fn whole_browser_named_icann_connect_uses_the_shared_https_backend() {
        let network = Arc::new(CountingIcannNetwork::new(
            vec!["1.1.1.1:443".parse().unwrap()],
            vec![Vec::new()],
        ));
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain("icann")));
        let proxy = start_proxy_with_icann_network(
            whole_browser_config(Some("welcome")),
            backend.clone(),
            network.clone(),
        );
        let (response, certificate) = send_tls_request(
            &proxy,
            "example.com:443",
            "example.com",
            b"GET /asset?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        assert_eq!(response_status(&response), 200);
        assert_eq!(response_parts(&response).1, b"icann");
        assert!(proxy.matches_local_certificate("example.com", &certificate));
        assert_eq!(network.resolve_calls(), 0);
        assert_eq!(network.connect_calls(), 0);

        let requests = backend.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].scheme, "https");
        assert_eq!(requests[0].host, "example.com");
        assert_eq!(requests[0].port, 443);
        assert_eq!(requests[0].path_and_query, "/asset?q=1");
    }

    #[test]
    fn whole_browser_rejects_special_and_unsafe_targets_before_dial() {
        let private_network = Arc::new(CountingIcannNetwork::new(
            vec!["127.0.0.1:443".parse().unwrap()],
            Vec::new(),
        ));
        let proxy = start_proxy_with_icann_network(
            whole_browser_config(None),
            Arc::new(UnusedBackend),
            private_network.clone(),
        );

        for authority in [
            "example.com:22",
            "localhost:443",
            "127.0.0.1:443",
            "[::1]:443",
        ] {
            let request = format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{}\r\n",
                auth_header(&proxy)
            );
            assert_eq!(response_status(&send_raw(&proxy, request.as_bytes())), 403);
        }
        assert_eq!(private_network.resolve_calls(), 0);
        assert_eq!(private_network.connect_calls(), 0);
    }

    #[test]
    fn whole_browser_forwards_public_ip_http_with_bounded_canonical_framing() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\nX-Test: yes\r\n\r\nhello".to_vec();
        let network = Arc::new(CountingIcannNetwork::new(
            vec!["1.1.1.1:80".parse().unwrap()],
            vec![response],
        ));
        let proxy = start_proxy_with_icann_network(
            whole_browser_config(None),
            Arc::new(UnusedBackend),
            network.clone(),
        );
        let request = format!(
            "GET http://1.1.1.1/path?q=1 HTTP/1.1\r\nHost: 1.1.1.1\r\n{}X-HNS-Forged: no\r\nProxy-Future: no\r\n\r\n",
            auth_header(&proxy)
        );
        let response = send_raw(&proxy, request.as_bytes());
        let (head, body) = response_parts(&response);
        assert_eq!(response_status(&response), 200);
        assert_eq!(body, b"hello");
        assert!(head.contains("Content-Length: 5\r\n"));
        assert!(head.contains("Connection: close\r\n"));
        let forwarded = String::from_utf8(network.written()).unwrap();
        assert!(forwarded.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(forwarded.contains("Host: 1.1.1.1\r\n"));
        assert!(!forwarded.to_ascii_lowercase().contains("proxy-"));
        assert!(!forwarded.to_ascii_lowercase().contains("x-hns-"));
        assert_eq!(network.resolve_calls(), 0);
        assert_eq!(network.connect_calls(), 1);
    }

    #[test]
    fn whole_browser_streams_large_and_chunked_public_ip_bodies_without_total_cap() {
        let large_len = 8 * 1024 * 1024 + 17;
        let mut fixed =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {large_len}\r\n\r\n").into_bytes();
        fixed.resize(fixed.len() + large_len, b'x');
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: ignored\r\n\r\n".to_vec();
        let network = Arc::new(CountingIcannNetwork::new(
            vec!["1.1.1.1:80".parse().unwrap()],
            vec![fixed, chunked],
        ));
        let proxy = start_proxy_with_icann_network(
            whole_browser_config(None),
            Arc::new(UnusedBackend),
            network,
        );
        for (path, expected_len) in [("large", large_len), ("chunked", 9)] {
            let request = format!(
                "GET http://1.1.1.1/{path} HTTP/1.1\r\nHost: 1.1.1.1\r\n{}\r\n",
                auth_header(&proxy)
            );
            let response = send_raw(&proxy, request.as_bytes());
            let (head, body) = response_parts(&response);
            assert_eq!(response_status(&response), 200);
            assert_eq!(body.len(), expected_len);
            if path == "chunked" {
                assert_eq!(body, b"Wikipedia");
                assert!(!head.to_ascii_lowercase().contains("transfer-encoding"));
            }
        }
    }

    #[test]
    fn whole_browser_public_ip_response_framing_handles_head_bodyless_close_and_invalid_lengths() {
        let responses = vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".to_vec(),
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nX-Mode: close\r\n\r\nclose body".to_vec(),
            b"HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx".to_vec(),
            b"HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\nx".to_vec(),
        ];
        let network = Arc::new(CountingIcannNetwork::new(
            vec!["1.1.1.1:80".parse().unwrap()],
            responses,
        ));
        let proxy = start_proxy_with_icann_network(
            whole_browser_config(None),
            Arc::new(UnusedBackend),
            network,
        );
        let cases = [
            ("HEAD", "head", 200, 0),
            ("GET", "204", 204, 0),
            ("GET", "205", 205, 0),
            ("GET", "304", 304, 0),
            ("GET", "close", 200, 10),
            ("GET", "bad-204", 502, "Invalid ICANN Response".len()),
            ("GET", "bad-205", 502, "Invalid ICANN Response".len()),
        ];
        for (method, path, status, body_len) in cases {
            let request = format!(
                "{method} http://1.1.1.1/{path} HTTP/1.1\r\nHost: 1.1.1.1\r\n{}\r\n",
                auth_header(&proxy)
            );
            let response = send_raw(&proxy, request.as_bytes());
            let (head, body) = response_parts(&response);
            assert_eq!(response_status(&response), status, "{path}: {head}");
            assert_eq!(body.len(), body_len, "{path}: {head}");
            if path == "head" {
                assert!(head.contains("Content-Length: 5\r\n"));
            }
            if path == "close" {
                assert_eq!(body, b"close body");
                assert!(!head.to_ascii_lowercase().contains("content-length"));
            }
        }
    }

    #[test]
    fn whole_browser_supports_icann_upgrade_and_public_ip_literals_without_dns() {
        let upgrade = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: accepted\r\n\r\n".to_vec();
        let ip_response = b"HTTP/1.1 204 No Content\r\n\r\n".to_vec();
        let ipv6_response = b"HTTP/1.1 204 No Content\r\n\r\n".to_vec();
        let network = Arc::new(CountingIcannNetwork::new(
            vec!["1.1.1.1:80".parse().unwrap()],
            vec![upgrade, ip_response, ipv6_response],
        ));
        let proxy = start_proxy_with_icann_network(
            whole_browser_config(None),
            Arc::new(UnusedBackend),
            network.clone(),
        );
        let websocket = format!(
            "GET ws://1.1.1.1/socket HTTP/1.1\r\nHost: 1.1.1.1\r\n{}Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: key\r\nSec-WebSocket-Version: 13\r\n\r\n",
            auth_header(&proxy)
        );
        assert_eq!(
            response_status(&send_raw(&proxy, websocket.as_bytes())),
            101
        );
        assert_eq!(network.resolve_calls(), 0);

        let ip = format!(
            "GET http://1.1.1.1/ HTTP/1.1\r\nHost: 1.1.1.1\r\n{}\r\n",
            auth_header(&proxy)
        );
        assert_eq!(response_status(&send_raw(&proxy, ip.as_bytes())), 204);
        assert_eq!(network.resolve_calls(), 0, "public IP literal bypasses DNS");
        let ipv6 = format!(
            "GET http://[2606:4700:4700::1111]/ HTTP/1.1\r\nHost: [2606:4700:4700::1111]\r\n{}\r\n",
            auth_header(&proxy)
        );
        assert_eq!(response_status(&send_raw(&proxy, ipv6.as_bytes())), 204);
        assert_eq!(
            network.resolve_calls(),
            0,
            "public IPv6 literal bypasses DNS"
        );
        assert_eq!(network.connect_calls(), 3);

        let legacy_ipv4 = format!(
            "GET http://0177.0.0.1/ HTTP/1.1\r\nHost: 0177.0.0.1\r\n{}\r\n",
            auth_header(&proxy)
        );
        assert_eq!(
            response_status(&send_raw(&proxy, legacy_ipv4.as_bytes())),
            400
        );
        assert_eq!(network.resolve_calls(), 0);
        assert_eq!(network.connect_calls(), 3);
    }

    #[test]
    fn whole_browser_keeps_active_hns_scope_on_the_existing_backend_path() {
        let network = Arc::new(CountingIcannNetwork::new(Vec::new(), Vec::new()));
        let backend = Arc::new(RecordingBackend::new(ResponsePlan::plain("hns")));
        let proxy = start_proxy_with_icann_network(
            whole_browser_config(Some("welcome")),
            backend.clone(),
            network.clone(),
        );
        let request = format!(
            "GET http://sub.welcome/ HTTP/1.1\r\nHost: sub.welcome\r\n{}\r\n",
            auth_header(&proxy)
        );
        let response = send_raw(&proxy, request.as_bytes());
        assert_eq!(response_status(&response), 200);
        assert_eq!(response_parts(&response).1, b"hns");
        assert_eq!(backend.request_count(), 1);
        assert_eq!(network.resolve_calls(), 0);
        assert_eq!(network.connect_calls(), 0);
    }

    #[test]
    fn stop_cancels_and_joins_idle_icann_response_work() {
        let network = Arc::new(CountingIcannNetwork::idle(vec![
            "1.1.1.1:80".parse().unwrap(),
        ]));
        let proxy = Arc::new(start_proxy_with_icann_network(
            whole_browser_config(None),
            Arc::new(UnusedBackend),
            network.clone(),
        ));
        let worker_proxy = Arc::clone(&proxy);
        let client = thread::spawn(move || {
            let request = format!(
                "GET http://1.1.1.1/idle HTTP/1.1\r\nHost: 1.1.1.1\r\n{}\r\n",
                auth_header(&worker_proxy)
            );
            send_raw(&worker_proxy, request.as_bytes())
        });
        let deadline = Instant::now() + TEST_TIMEOUT;
        while network.connect_calls() == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(network.connect_calls(), 1);
        let started = Instant::now();
        proxy.stop();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(proxy.is_stopped());
        client.join().unwrap();
    }

    #[test]
    fn cancellation_interrupts_all_pending_icann_chunk_framing_reads() {
        for (stage, prefix) in [
            ("chunk-size", b"".as_slice()),
            ("chunk-crlf", b"1\r\nx".as_slice()),
            ("trailer", b"0\r\n".as_slice()),
        ] {
            let cancellation = CancellationToken::new();
            let worker_cancellation = cancellation.clone();
            let (pending_tx, pending_rx) = mpsc::channel();
            let (result_tx, result_rx) = mpsc::channel();
            let prefix = prefix.to_vec();
            let worker = thread::spawn(move || {
                let mut origin = PendingChunkStream {
                    prefix: Cursor::new(prefix),
                    pending: Some(pending_tx),
                };
                let mut reader = InactivityReader::new(
                    &mut origin,
                    &worker_cancellation,
                    Duration::from_secs(5),
                );
                let mut client = Vec::new();
                let started = Instant::now();
                let result = relay_chunked_body(&mut reader, &mut client);
                let _result = result_tx.send((result, started.elapsed()));
            });

            pending_rx
                .recv_timeout(TEST_TIMEOUT)
                .unwrap_or_else(|error| panic!("{stage} read did not become pending: {error}"));
            assert!(cancellation.cancel(), "{stage} cancellation was not new");
            let (result, elapsed) = result_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap_or_else(|error| panic!("{stage} read ignored cancellation: {error}"));

            assert_eq!(result, Err(IcannRouteError::InvalidResponse), "{stage}");
            assert!(elapsed < Duration::from_secs(1), "{stage}: {elapsed:?}");
            worker.join().unwrap();
        }
    }

    #[test]
    fn authentication_challenge_matching_is_revoked_on_stop_request() {
        let proxy = RunningProxy::start(
            test_config(),
            Arc::new(UnusedBackend),
            Arc::new(NoopProxyObserver),
        )
        .unwrap();
        assert!(proxy.matches_authentication_challenge(
            "127.0.0.1",
            proxy.endpoint().port(),
            proxy.endpoint().realm(),
        ));
        assert!(!proxy.matches_authentication_challenge(
            "localhost",
            proxy.endpoint().port(),
            proxy.endpoint().realm(),
        ));
        proxy.request_stop();
        assert!(proxy.is_stop_requested());
        assert!(!proxy.matches_authentication_challenge(
            "127.0.0.1",
            proxy.endpoint().port(),
            proxy.endpoint().realm(),
        ));
        proxy.stop();
    }
}
