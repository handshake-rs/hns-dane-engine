use bytes::{Buf, Bytes};
use hns_dane::{
    DaneCertificateChainValidationInput, DaneDecision, DaneError, DomainTrustMode,
    StatelessDaneConfig, StatelessDaneEvidence, StatelessDaneValidationInput, TlsaRecord,
    WebPkiStatus, evaluate_policy_with_certificate_chain, evaluate_stateless_dane_certificate,
    extract_spki_der,
};
pub use hns_icann_dane::{BrowserTlsDecision, TlsaOwner, TlsaTransport};
use http::{HeaderName, HeaderValue, Request as Http2Request};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use rustls::{Error as RustlsError, StreamOwned};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;
use std::time::{Duration, Instant};
use thiserror::Error;

const MAX_HTTP11_POOL_PER_ORIGIN: usize = 2;
const MAX_HTTP11_POOL_ORIGINS: usize = 64;
const MAX_TLS_POLICY_CACHE_ENTRIES: usize = 256;
const MAX_ALT_SVC_CACHE_ENTRIES: usize = 256;
const MAX_TLS_CAPTURE_ENTRIES: usize = 256;
const MAX_INFORMATIONAL_RESPONSES: usize = 8;
const MAX_HTTP_TRAILER_FIELDS: usize = 128;
const MAX_ALT_SVC_AGE_SECS: u64 = 24 * 60 * 60;
const ALT_SVC_FAILURE_COOLDOWN: Duration = Duration::from_secs(10 * 60);
const TUNNEL_IO_TIMEOUT: Duration = Duration::from_millis(250);
const CONTROLLED_IO_CANCELLED: &str = "controlled transport operation cancelled";
const CONTROLLED_IO_DEADLINE_EXCEEDED: &str = "controlled transport deadline exceeded";
const DNS_MESSAGE_MEDIA_TYPE: &str = "application/dns-message";
const MAX_WEBPKI_ENDPOINT_ATTEMPTS_PER_OPEN: usize = 8;
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginProtocol {
    Http11,
    Http2,
    Http3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub connect_host: Option<String>,
    pub port: u16,
    pub path_and_query: String,
    pub protocol: OriginProtocol,
    pub tls: TlsValidation,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsValidation {
    pub mode: DomainTrustMode,
    pub dnssec_secure: bool,
    pub tlsa_records: Vec<TlsaRecord>,
    pub tlsa_source: Option<TlsaRecordSource>,
    /// Stable digest of the retained dual-root namespace decision and evidence.
    ///
    /// This is part of every connection-reuse key. A request selected through
    /// one namespace therefore cannot reuse a socket, TLS verifier/session, or
    /// Alt-Svc entry created for another namespace decision.
    pub namespace_fingerprint: Option<String>,
    pub service_port: u16,
    pub service_transport: TlsaTransport,
    pub browser_tls_decision: Option<BrowserTlsDecision>,
    pub stateless_dane: StatelessDaneConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsaRecordSource {
    NativeTlsa,
    HnsProofTxt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub dane_decision: DaneDecision,
    pub tls_inspection: Option<TlsCertificateInspection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_len: usize,
    pub dane_decision: DaneDecision,
    pub tls_inspection: Option<TlsCertificateInspection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsCertificateInspection {
    pub end_entity_der: Vec<u8>,
    pub end_entity_spki_der: Vec<u8>,
    pub intermediate_der: Vec<Vec<u8>>,
    pub webpki_status: WebPkiStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportLimits {
    pub max_request_body_bytes: usize,
    pub max_response_header_bytes: usize,
    pub max_response_body_bytes: usize,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("DANE validation failed")]
    DaneFailed,
    #[error("origin transport is not implemented for requested protocol")]
    UnsupportedTransport,
    #[error("origin scheme is unsupported")]
    UnsupportedScheme,
    #[error("HTTP transfer encoding is unsupported")]
    UnsupportedTransferEncoding,
    #[error("HTTP protocol upgrade is unsupported")]
    UnsupportedUpgrade,
    #[error("origin HTTP/2 error: {0}")]
    Http2(String),
    #[error("origin HTTP/3 error: {0}")]
    Http3(String),
    #[error("origin QUIC error: {0}")]
    Quic(String),
    #[error("origin TLS error: {0}")]
    Tls(String),
    #[error("origin request is invalid")]
    InvalidRequest,
    #[error("origin request body exceeds configured limit")]
    RequestTooLarge,
    #[error("origin response exceeds configured limit")]
    ResponseTooLarge,
    #[error("origin response is malformed")]
    MalformedResponse,
    #[error("origin I/O error: {0}")]
    Io(String),
}

pub trait OriginTransport {
    fn fetch(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError>;

    fn open_tunnel(&self, _request: &OriginRequest) -> Result<OriginTunnel, TransportError> {
        Err(TransportError::UnsupportedTransport)
    }

    /// Opens a raw TCP connection to an already-resolved origin endpoint.
    ///
    /// This deliberately performs no TLS handshake. It exists so a browser
    /// can retain end-to-end WebPKI validation after the gateway has selected
    /// an ICANN endpoint and authenticated the TLSA fallback decision. Default
    /// implementations fail closed.
    fn open_webpki_passthrough(
        &self,
        _request: &OriginRequest,
    ) -> Result<OriginWebPkiPassthrough, TransportError> {
        Err(TransportError::UnsupportedTransport)
    }

    /// Opens one of several equivalent, already-resolved WebPKI endpoints.
    ///
    /// Implementations that support multiple candidates must enforce one
    /// aggregate connection budget and return the actual connected peer.
    /// Default implementations support exactly one request so adding address
    /// fallback can never accidentally multiply a transport's timeout.
    fn open_webpki_passthrough_candidates(
        &self,
        requests: &[OriginRequest],
    ) -> Result<SelectedOriginWebPkiPassthrough, TransportError> {
        let mut before_dial = || Ok(());
        self.open_webpki_passthrough_candidates_with_guard(requests, &mut before_dial)
    }

    /// Candidate opener with a guard run immediately before every socket dial.
    ///
    /// Authority wrappers use this boundary to stop a retry batch as soon as
    /// its request stamp is revoked. The default remains fail closed for more
    /// than one candidate.
    fn open_webpki_passthrough_candidates_with_guard(
        &self,
        requests: &[OriginRequest],
        before_dial: &mut dyn FnMut() -> Result<(), TransportError>,
    ) -> Result<SelectedOriginWebPkiPassthrough, TransportError> {
        let [request] = requests else {
            return Err(TransportError::UnsupportedTransport);
        };
        before_dial()?;
        let transport = self.open_webpki_passthrough(request)?;
        let expected_peer = explicit_request_socket_addr(request)?;
        if transport.peer_addr != expected_peer {
            return Err(TransportError::InvalidRequest);
        }
        Ok(SelectedOriginWebPkiPassthrough { transport })
    }

    fn fetch_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        let response = self.fetch(request)?;
        body.write_all(&response.body).map_err(io_error)?;
        Ok(response.into_head())
    }
}

pub trait ReadWrite: Read + Write + Send {}

impl<T: Read + Write + Send> ReadWrite for T {}

/// Independently owned halves of one browser-TLS passthrough socket.
///
/// The split is part of the security/performance contract: a quiet browser
/// upload direction must never serialize a large origin download behind a
/// polling read. Both halves must use bounded I/O waits.
pub struct OriginWebPkiPassthrough {
    /// Peer address read from the connected socket, never copied from DNS.
    pub peer_addr: SocketAddr,
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    pub shutdown: Arc<dyn OriginPassthroughShutdown>,
}

/// Raw WebPKI tunnel selected from an authenticated candidate set.
pub struct SelectedOriginWebPkiPassthrough {
    pub transport: OriginWebPkiPassthrough,
}

/// Out-of-band close used to wake both passthrough directions on
/// cancellation, policy revocation, EOF, or an I/O failure.
///
/// Implementations must be thread-safe, nonblocking, idempotent, and wake
/// both independently owned halves. Either pump direction may call it.
pub trait OriginPassthroughShutdown: Send + Sync {
    fn shutdown(&self);
}

struct TcpPassthroughShutdown(TcpStream);

impl OriginPassthroughShutdown for TcpPassthroughShutdown {
    fn shutdown(&self) {
        let _result = self.0.shutdown(std::net::Shutdown::Both);
    }
}

struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    written: usize,
}

impl<'a> CountingWriter<'a> {
    fn new(inner: &'a mut dyn Write) -> Self {
        Self { inner, written: 0 }
    }

    fn inner_mut(&mut self) -> &mut dyn Write {
        &mut *self.inner
    }
}

impl Write for CountingWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.written = self.written.saturating_add(written);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct ControlledTcpStream<'a, F>
where
    F: Fn() -> bool + Sync,
{
    stream: TcpStream,
    deadline: Instant,
    poll_interval: Duration,
    is_cancelled: &'a F,
}

impl<'a, F> ControlledTcpStream<'a, F>
where
    F: Fn() -> bool + Sync,
{
    fn new(
        stream: TcpStream,
        deadline: Instant,
        poll_interval: Duration,
        is_cancelled: &'a F,
    ) -> Self {
        Self {
            stream,
            deadline,
            poll_interval,
            is_cancelled,
        }
    }

    fn next_timeout(&self) -> std::io::Result<Duration> {
        if (self.is_cancelled)() {
            return Err(std::io::Error::new(
                // `Read::read_exact` and `Write::write_all` transparently
                // retry `Interrupted`. Use a terminal kind so cancellation
                // cannot turn those helpers into a busy loop.
                ErrorKind::ConnectionAborted,
                CONTROLLED_IO_CANCELLED,
            ));
        }
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(ErrorKind::TimedOut, CONTROLLED_IO_DEADLINE_EXCEEDED)
            })?;
        Ok(self.poll_interval.min(remaining))
    }
}

impl<F> Read for ControlledTcpStream<'_, F>
where
    F: Fn() -> bool + Sync,
{
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let timeout = self.next_timeout()?;
            self.stream.set_read_timeout(Some(timeout))?;
            match self.stream.read(buffer) {
                Err(error)
                    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}

impl<F> Write for ControlledTcpStream<'_, F>
where
    F: Fn() -> bool + Sync,
{
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let timeout = self.next_timeout()?;
            self.stream.set_write_timeout(Some(timeout))?;
            match self.stream.write(buffer) {
                Err(error)
                    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.next_timeout()?;
        self.stream.flush()
    }
}

pub struct OriginTunnel {
    pub response_head: Vec<u8>,
    pub stream: Box<dyn ReadWrite>,
    pub dane_decision: DaneDecision,
    pub tls_inspection: Option<TlsCertificateInspection>,
}

pub struct FailClosedTransport;

#[derive(Clone, Debug)]
pub struct TcpHttpTransport {
    connect_timeout: Duration,
    read_timeout: Duration,
    limits: TransportLimits,
    root_store: Arc<RootCertStore>,
    state: Arc<Mutex<TransportState>>,
    webpki_candidate_rotation: Arc<AtomicU64>,
}

#[derive(Debug, Default)]
struct TransportState {
    http11_pool: HashMap<Http11PoolKey, VecDeque<PooledHttp11Connection>>,
    tls_verifiers: HashMap<String, Arc<DaneServerCertVerifier>>,
    tls_resumption: HashMap<String, Resumption>,
    alt_svc: HashMap<AltSvcKey, AltSvcEndpoint>,
    blocked_alt_svc: HashMap<AltSvcKey, Instant>,
}

enum WebPkiPassthroughOpenError {
    Connect(TransportError),
    Terminal(TransportError),
}

impl WebPkiPassthroughOpenError {
    fn into_transport_error(self) -> TransportError {
        match self {
            Self::Connect(error) | Self::Terminal(error) => error,
        }
    }

    fn is_connect_failure(&self) -> bool {
        matches!(self, Self::Connect(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Http11PoolKey {
    scheme: String,
    host: String,
    connect_host: String,
    port: u16,
    tls_key: String,
}

#[derive(Debug)]
enum PooledHttp11Connection {
    Plain(TcpStream),
    Tls {
        stream: Box<StreamOwned<ClientConnection, TcpStream>>,
        dane_decision: DaneDecision,
        tls_inspection: Option<TlsCertificateInspection>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct AltSvcKey {
    scheme: String,
    host: String,
    port: u16,
    namespace_fingerprint: Option<String>,
}

#[derive(Clone, Debug)]
struct AltSvcEndpoint {
    protocol: OriginProtocol,
    port: u16,
    expires_at: Instant,
}

type ParsedHttp11HeaderBlock = (String, u16, Vec<(String, String)>);

fn evict_one_if_at_capacity<K, V>(map: &mut HashMap<K, V>, capacity: usize)
where
    K: Clone + Eq + Hash,
{
    if map.len() < capacity {
        return;
    }
    if let Some(key) = map.keys().next().cloned() {
        map.remove(&key);
    }
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            max_response_header_bytes: DEFAULT_MAX_RESPONSE_HEADER_BYTES,
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
        }
    }
}

impl Default for TcpHttpTransport {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            limits: TransportLimits::default(),
            root_store: Arc::new(default_root_store()),
            state: Arc::new(Mutex::new(TransportState::default())),
            webpki_candidate_rotation: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Default for TlsValidation {
    fn default() -> Self {
        Self {
            mode: DomainTrustMode::IcannWebPki,
            dnssec_secure: false,
            tlsa_records: Vec::new(),
            tlsa_source: None,
            namespace_fingerprint: None,
            service_port: 443,
            service_transport: TlsaTransport::Tcp,
            browser_tls_decision: None,
            stateless_dane: StatelessDaneConfig::default(),
        }
    }
}

impl TlsValidation {
    pub fn hns_strict(dnssec_secure: bool, tlsa_records: Vec<TlsaRecord>) -> Self {
        Self {
            mode: DomainTrustMode::HnsStrict,
            dnssec_secure,
            tlsa_records,
            tlsa_source: None,
            namespace_fingerprint: None,
            service_port: 443,
            service_transport: TlsaTransport::Tcp,
            browser_tls_decision: None,
            stateless_dane: StatelessDaneConfig::default(),
        }
    }
}

impl OriginResponse {
    pub fn into_head(self) -> OriginResponseHead {
        OriginResponseHead {
            status: self.status,
            headers: self.headers,
            body_len: self.body.len(),
            dane_decision: self.dane_decision,
            tls_inspection: self.tls_inspection,
        }
    }
}

impl TcpHttpTransport {
    pub fn new(connect_timeout: Duration, read_timeout: Duration, limits: TransportLimits) -> Self {
        Self {
            connect_timeout,
            read_timeout,
            limits,
            root_store: Arc::new(default_root_store()),
            state: Arc::new(Mutex::new(TransportState::default())),
            webpki_candidate_rotation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_root_store(
        connect_timeout: Duration,
        read_timeout: Duration,
        limits: TransportLimits,
        root_store: RootCertStore,
    ) -> Self {
        Self {
            connect_timeout,
            read_timeout,
            limits,
            root_store: Arc::new(root_store),
            state: Arc::new(Mutex::new(TransportState::default())),
            webpki_candidate_rotation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn limits(&self) -> TransportLimits {
        self.limits
    }

    fn open_explicit_webpki_passthrough(
        &self,
        request: &OriginRequest,
    ) -> Result<OriginWebPkiPassthrough, TransportError> {
        self.open_explicit_webpki_passthrough_with_timeout(request, self.connect_timeout)
            .map_err(WebPkiPassthroughOpenError::into_transport_error)
    }

    fn open_explicit_webpki_passthrough_with_timeout(
        &self,
        request: &OriginRequest,
        connect_timeout: Duration,
    ) -> Result<OriginWebPkiPassthrough, WebPkiPassthroughOpenError> {
        let connect_ip = self
            .validate_explicit_webpki_passthrough_request(request)
            .map_err(WebPkiPassthroughOpenError::Terminal)?;
        if connect_timeout.is_zero() {
            return Err(WebPkiPassthroughOpenError::Connect(TransportError::Io(
                "browser WebPKI endpoint connect deadline exceeded".to_owned(),
            )));
        }
        let expected_peer = SocketAddr::new(connect_ip, request.port);
        let writer = TcpStream::connect_timeout(&expected_peer, connect_timeout)
            .map_err(|error| WebPkiPassthroughOpenError::Connect(io_error(error)))?;
        let peer_addr = writer
            .peer_addr()
            .map_err(|error| WebPkiPassthroughOpenError::Terminal(io_error(error)))?;
        if peer_addr != expected_peer {
            return Err(WebPkiPassthroughOpenError::Terminal(
                TransportError::InvalidRequest,
            ));
        }
        writer
            .set_read_timeout(Some(TUNNEL_IO_TIMEOUT))
            .map_err(|error| WebPkiPassthroughOpenError::Terminal(io_error(error)))?;
        writer
            .set_write_timeout(Some(TUNNEL_IO_TIMEOUT))
            .map_err(|error| WebPkiPassthroughOpenError::Terminal(io_error(error)))?;
        let reader = writer
            .try_clone()
            .map_err(|error| WebPkiPassthroughOpenError::Terminal(io_error(error)))?;
        let shutdown = writer
            .try_clone()
            .map_err(|error| WebPkiPassthroughOpenError::Terminal(io_error(error)))?;
        Ok(OriginWebPkiPassthrough {
            peer_addr,
            reader: Box::new(reader),
            writer: Box::new(writer),
            shutdown: Arc::new(TcpPassthroughShutdown(shutdown)),
        })
    }

    fn validate_explicit_webpki_passthrough_request(
        &self,
        request: &OriginRequest,
    ) -> Result<IpAddr, TransportError> {
        validate_request_common(request, self.limits)?;
        validate_browser_tls_decision(&request.tls)?;
        if !matches!(
            request.scheme.to_ascii_lowercase().as_str(),
            "https" | "wss"
        ) || request.protocol == OriginProtocol::Http3
            || request.tls.mode != DomainTrustMode::IcannWebPki
            || request.tls.namespace_fingerprint.is_none()
            || request.tls.service_transport != TlsaTransport::Tcp
            || !matches!(
                request.tls.browser_tls_decision,
                Some(
                    BrowserTlsDecision::WebPkiAuthenticatedAbsence
                        | BrowserTlsDecision::WebPkiInsecureDelegation
                )
            )
        {
            return Err(TransportError::InvalidRequest);
        }
        request
            .connect_host
            .as_deref()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .ok_or(TransportError::InvalidRequest)
    }

    fn open_explicit_webpki_passthrough_candidates(
        &self,
        requests: &[OriginRequest],
        before_dial: &mut dyn FnMut() -> Result<(), TransportError>,
    ) -> Result<SelectedOriginWebPkiPassthrough, TransportError> {
        let template = requests.first().ok_or(TransportError::InvalidRequest)?;
        for candidate in requests {
            let mut expected = template.clone();
            expected.connect_host = candidate.connect_host.clone();
            if candidate != &expected {
                return Err(TransportError::InvalidRequest);
            }
            // Validate every candidate before opening any socket. A later
            // malformed request must not be hidden by an earlier success.
            self.validate_explicit_webpki_passthrough_request(candidate)?;
        }

        let attempt_count = requests.len().min(MAX_WEBPKI_ENDPOINT_ATTEMPTS_PER_OPEN);
        // Advance one position when the whole plan fits in a single batch.
        // Advancing by `attempt_count` in that case is zero modulo the
        // candidate count and would retry the same dead first endpoint on
        // every browser tunnel. Larger plans retain disjoint bounded batches.
        let rotation_stride = if attempt_count == requests.len() {
            1
        } else {
            attempt_count
        };
        let rotation = self.webpki_candidate_rotation.fetch_add(
            u64::try_from(rotation_stride).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        let candidate_count_u64 = u64::try_from(requests.len()).unwrap_or(u64::MAX);
        let start = usize::try_from(rotation % candidate_count_u64).unwrap_or(0);
        let attempt_indices = bounded_candidate_indices(requests.len(), start);
        let deadline = Instant::now()
            .checked_add(self.connect_timeout)
            .ok_or_else(|| TransportError::Io("invalid WebPKI connect deadline".to_owned()))?;
        let mut last_connect_error = None;
        for (attempt_offset, candidate_index) in attempt_indices.iter().copied().enumerate() {
            before_dial()?;
            let Some(remaining) = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
            else {
                break;
            };
            let connect_timeout = apportioned_connect_timeout(
                remaining,
                attempt_indices.len().saturating_sub(attempt_offset),
                self.connect_timeout,
            );
            let candidate = requests
                .get(candidate_index)
                .ok_or(TransportError::InvalidRequest)?;
            match self.open_explicit_webpki_passthrough_with_timeout(candidate, connect_timeout) {
                Ok(transport) => {
                    return Ok(SelectedOriginWebPkiPassthrough { transport });
                }
                Err(error) if error.is_connect_failure() => {
                    last_connect_error = Some(error.into_transport_error());
                }
                Err(error) => return Err(error.into_transport_error()),
            }
        }
        Err(last_connect_error.unwrap_or_else(|| {
            TransportError::Io("browser WebPKI endpoint connect deadline exceeded".to_owned())
        }))
    }

    /// Performs one HTTP/1.1 request to an explicit IP address while enforcing
    /// one absolute I/O deadline and polling a cooperative cancellation hook.
    /// This path deliberately bypasses connection pooling and Alt-Svc routing.
    pub fn fetch_http11_with_control<F>(
        &self,
        request: &OriginRequest,
        deadline: Instant,
        poll_interval: Duration,
        is_cancelled: F,
    ) -> Result<OriginResponse, TransportError>
    where
        F: Fn() -> bool + Sync,
    {
        validate_request(request, self.limits)?;
        if request.protocol != OriginProtocol::Http11 || poll_interval.is_zero() {
            return Err(TransportError::InvalidRequest);
        }
        let connect_ip = request
            .connect_host
            .as_deref()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .ok_or(TransportError::InvalidRequest)?;
        let connect_address = SocketAddr::new(connect_ip, request.port);
        let remaining = controlled_remaining(deadline, &is_cancelled)?;
        let connect_timeout = self.connect_timeout.min(remaining);
        if connect_timeout.is_zero() {
            return Err(controlled_deadline_error());
        }
        let stream = match TcpStream::connect_timeout(&connect_address, connect_timeout) {
            Ok(stream) => stream,
            Err(error) => {
                controlled_remaining(deadline, &is_cancelled)?;
                return Err(io_error(error));
            }
        };
        controlled_remaining(deadline, &is_cancelled)?;
        let stream = ControlledTcpStream::new(stream, deadline, poll_interval, &is_cancelled);
        let mut body = Vec::new();
        let head = match request.scheme.to_ascii_lowercase().as_str() {
            "http" => {
                let mut stream = stream;
                self.send_http11_stream(&mut stream, request, &mut body)?.0
            }
            "https" => {
                let (config, verifier) = self.client_config(request.tls.clone(), Vec::new())?;
                let server_name = ServerName::try_from(request.host.clone())
                    .map_err(|_| TransportError::InvalidRequest)?;
                verifier.begin_handshake(&request.host);
                let connection = ClientConnection::new(Arc::new(config), server_name)
                    .map_err(|error| verifier.map_handshake_error(tls_error(error)))?;
                let mut tls_stream = StreamOwned::new(connection, stream);
                let (mut head, _) = self
                    .send_http11_stream(&mut tls_stream, request, &mut body)
                    .map_err(|error| verifier.map_handshake_error(error))?;
                let (dane_decision, tls_inspection) = verifier.finish_handshake(&request.host)?;
                head.dane_decision = dane_decision;
                head.tls_inspection = tls_inspection;
                head
            }
            _ => return Err(TransportError::UnsupportedScheme),
        };
        controlled_remaining(deadline, &is_cancelled)?;
        Ok(OriginResponse {
            status: head.status,
            headers: head.headers,
            body,
            dane_decision: head.dane_decision,
            tls_inspection: head.tls_inspection,
        })
    }

    fn fetch_unpromoted(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        match (
            request.scheme.to_ascii_lowercase().as_str(),
            request.protocol,
        ) {
            ("http", OriginProtocol::Http11) => self.fetch_http11(request),
            ("https", OriginProtocol::Http11) => self.fetch_https_http11(request),
            ("https", OriginProtocol::Http2) => self.fetch_https_http2(request),
            ("https", OriginProtocol::Http3) => self.fetch_https_http3(request),
            ("http", _) => Err(TransportError::UnsupportedTransport),
            _ => Err(TransportError::UnsupportedScheme),
        }
    }

    /// Executes one internally constructed RFC 8484 DNS POST.
    ///
    /// DNS queries are replay-safe, so this narrowly scoped path may retry
    /// once on a fresh exact-IP connection when an idle pooled HTTP/1.1
    /// connection has gone stale. Generic POST requests continue through
    /// [`OriginTransport::fetch`] and remain non-replayable.
    pub fn fetch_rfc8484_post(
        &self,
        request: &OriginRequest,
    ) -> Result<OriginResponse, TransportError> {
        if !is_exact_ip_rfc8484_post(request) {
            return Err(TransportError::InvalidRequest);
        }
        self.fetch_https_http11_with_pool_retry(request, true)
    }

    fn fetch_unpromoted_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        match (
            request.scheme.to_ascii_lowercase().as_str(),
            request.protocol,
        ) {
            ("http", OriginProtocol::Http11) => self.fetch_http11_to_writer(request, body),
            ("https", OriginProtocol::Http11) => self.fetch_https_http11_to_writer(request, body),
            ("https", OriginProtocol::Http2) => self.fetch_https_http2_to_writer(request, body),
            ("https", OriginProtocol::Http3) => self.fetch_https_http3_to_writer(request, body),
            ("http", _) => Err(TransportError::UnsupportedTransport),
            _ => Err(TransportError::UnsupportedScheme),
        }
    }

    fn fetch_http11(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        let mut body = Vec::new();
        let head = self.fetch_http11_to_writer(request, &mut body)?;
        Ok(OriginResponse {
            status: head.status,
            headers: head.headers,
            body,
            dane_decision: head.dane_decision,
            tls_inspection: head.tls_inspection,
        })
    }

    fn fetch_http11_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        validate_request(request, self.limits)?;
        let key = self.http11_pool_key(request);
        if let Some(PooledHttp11Connection::Plain(mut stream)) = self.take_http11_connection(&key) {
            let mut attempted_body = CountingWriter::new(body);
            match self.send_plain_http11(&mut stream, request, &mut attempted_body) {
                Ok((head, reusable)) => {
                    if reusable {
                        self.put_http11_connection(key, PooledHttp11Connection::Plain(stream));
                    }
                    return Ok(head);
                }
                Err(error)
                    if attempted_body.written > 0 || !is_safe_retry_method(&request.method) =>
                {
                    return Err(error);
                }
                Err(_) => {}
            }
        }

        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let mut stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;

        let (head, reusable) = self.send_plain_http11(&mut stream, request, body)?;
        if reusable {
            self.put_http11_connection(key, PooledHttp11Connection::Plain(stream));
        }
        Ok(head)
    }

    fn fetch_https_http11(
        &self,
        request: &OriginRequest,
    ) -> Result<OriginResponse, TransportError> {
        self.fetch_https_http11_with_pool_retry(request, false)
    }

    fn fetch_https_http11_with_pool_retry(
        &self,
        request: &OriginRequest,
        replay_stale_rfc8484_post: bool,
    ) -> Result<OriginResponse, TransportError> {
        let mut body = Vec::new();
        let head = self.fetch_https_http11_to_writer_with_pool_retry(
            request,
            &mut body,
            replay_stale_rfc8484_post,
        )?;
        Ok(OriginResponse {
            status: head.status,
            headers: head.headers,
            body,
            dane_decision: head.dane_decision,
            tls_inspection: head.tls_inspection,
        })
    }

    fn fetch_https_http11_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        self.fetch_https_http11_to_writer_with_pool_retry(request, body, false)
    }

    fn fetch_https_http11_to_writer_with_pool_retry(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
        replay_stale_rfc8484_post: bool,
    ) -> Result<OriginResponseHead, TransportError> {
        validate_request(request, self.limits)?;
        let key = self.http11_pool_key(request);
        if let Some(PooledHttp11Connection::Tls {
            mut stream,
            dane_decision,
            tls_inspection,
        }) = self.take_http11_connection(&key)
        {
            let mut attempted_body = CountingWriter::new(body);
            match self.send_tls_http11(stream.as_mut(), request, &mut attempted_body) {
                Ok((mut head, reusable)) => {
                    head.dane_decision = dane_decision.clone();
                    head.tls_inspection = tls_inspection.clone();
                    if reusable {
                        self.put_http11_connection(
                            key,
                            PooledHttp11Connection::Tls {
                                stream,
                                dane_decision,
                                tls_inspection,
                            },
                        );
                    }
                    return Ok(head);
                }
                Err(error)
                    if !may_retry_stale_pooled_request(
                        request,
                        &error,
                        attempted_body.written,
                        replay_stale_rfc8484_post,
                    ) =>
                {
                    return Err(error);
                }
                Err(_) => {}
            }
        }

        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;

        let (config, verifier) = self.client_config(request.tls.clone(), Vec::new())?;
        let server_name = ServerName::try_from(request.host.clone())
            .map_err(|_| TransportError::InvalidRequest)?;
        verifier.begin_handshake(&request.host);
        let connection = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|error| verifier.map_handshake_error(tls_error(error)))?;
        let mut tls_stream = StreamOwned::new(connection, stream);

        let (mut head, reusable) = self
            .send_tls_http11(&mut tls_stream, request, body)
            .map_err(|error| verifier.map_handshake_error(error))?;
        let (dane_decision, tls_inspection) = verifier.finish_handshake(&request.host)?;
        head.dane_decision = dane_decision.clone();
        head.tls_inspection = tls_inspection.clone();
        if reusable {
            self.put_http11_connection(
                key,
                PooledHttp11Connection::Tls {
                    stream: Box::new(tls_stream),
                    dane_decision,
                    tls_inspection,
                },
            );
        }
        Ok(head)
    }

    fn fetch_https_http2(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        let mut body = Vec::new();
        let head = self.fetch_https_http2_to_writer(request, &mut body)?;
        Ok(OriginResponse {
            status: head.status,
            headers: head.headers,
            body,
            dane_decision: head.dane_decision,
            tls_inspection: head.tls_inspection,
        })
    }

    fn fetch_https_http2_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        validate_request(request, self.limits)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(io_error)?;
        runtime.block_on(self.fetch_https_http2_to_writer_async(request, body))
    }

    async fn fetch_https_http2_to_writer_async(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        tokio::time::timeout(
            self.read_timeout,
            self.fetch_https_http2_to_writer_inner(request, body),
        )
        .await
        .map_err(|_| TransportError::Io("HTTP/2 origin request timed out".to_owned()))?
    }

    async fn fetch_https_http2_to_writer_inner(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let stream = connect_async(connection_host, request.port, self.connect_timeout).await?;

        let (config, verifier) = self.client_config(request.tls.clone(), vec![b"h2".to_vec()])?;
        let server_name = ServerName::try_from(request.host.clone())
            .map_err(|_| TransportError::InvalidRequest)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        verifier.begin_handshake(&request.host);
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|error| verifier.map_handshake_error(io_error(error)))?;
        if tls_stream.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(TransportError::UnsupportedTransport);
        }

        let mut h2_builder = h2::client::Builder::new();
        h2_builder.max_header_list_size(
            self.limits.max_response_header_bytes.min(u32::MAX as usize) as u32,
        );
        let (mut sender, connection) = h2_builder.handshake(tls_stream).await.map_err(h2_error)?;
        let connection_task = tokio::spawn(connection);
        let h2_request = build_http2_request(request)?;
        let end_stream = request.body.is_empty();
        let (response, mut send_stream) = sender
            .send_request(h2_request, end_stream)
            .map_err(h2_error)?;
        if !request.body.is_empty() {
            send_stream
                .send_data(Bytes::copy_from_slice(&request.body), true)
                .map_err(h2_error)?;
        }

        let response = response.await.map_err(h2_error)?;
        let status = response.status().as_u16();
        let headers =
            http2_response_headers(response.headers(), self.limits.max_response_header_bytes)?;
        if transfer_encoding(&headers)?.is_some() {
            return Err(TransportError::MalformedResponse);
        }
        let expected_body_len = content_length(&headers)?;
        let mut response_body = response.into_body();
        let no_body = response_has_no_body(&request.method, status);
        let body_len = if no_body {
            ensure_http2_body_empty(&mut response_body).await?;
            0
        } else {
            read_http2_body_to_writer(
                &mut response_body,
                self.limits.max_response_body_bytes,
                body,
            )
            .await?
        };
        if !no_body && expected_body_len.is_some_and(|expected| expected != body_len) {
            return Err(TransportError::MalformedResponse);
        }
        connection_task.abort();

        let (dane_decision, tls_inspection) = verifier.finish_handshake(&request.host)?;
        Ok(OriginResponseHead {
            status,
            headers,
            body_len,
            dane_decision,
            tls_inspection,
        })
    }

    fn fetch_https_http3(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        let mut body = Vec::new();
        let head = self.fetch_https_http3_to_writer(request, &mut body)?;
        Ok(OriginResponse {
            status: head.status,
            headers: head.headers,
            body,
            dane_decision: head.dane_decision,
            tls_inspection: head.tls_inspection,
        })
    }

    fn fetch_https_http3_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        validate_request(request, self.limits)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(io_error)?;
        runtime.block_on(self.fetch_https_http3_to_writer_async(request, body))
    }

    async fn fetch_https_http3_to_writer_async(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        self.fetch_https_http3_to_writer_inner(request, body).await
    }

    async fn fetch_https_http3_to_writer_inner(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let remote = resolve_socket_addr_async(connection_host, request.port).await?;

        let (config, verifier) = self.client_config(request.tls.clone(), vec![b"h3".to_vec()])?;
        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(config)
            .map_err(|error| TransportError::Tls(error.to_string()))?;
        let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
            .map_err(io_error)?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_config)));

        let connecting = endpoint
            .connect(remote, &request.host)
            .map_err(quic_error)?;
        verifier.begin_handshake(&request.host);
        let connection = http3_timeout(self.connect_timeout, "connect", connecting)
            .await?
            .map_err(|error| verifier.map_handshake_error(quic_error(error)))?;
        let close_connection = connection.clone();
        let quic = h3_quinn::Connection::new(connection);
        let (mut driver, mut sender) = http3_timeout(
            self.read_timeout,
            "connection setup",
            h3::client::builder()
                .max_field_section_size(self.limits.max_response_header_bytes as u64)
                .build(quic),
        )
        .await?
        .map_err(h3_connection_error)?;
        let driver_task =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

        let h3_request = build_http2_request(request)?;
        let mut request_stream = http3_timeout(
            self.read_timeout,
            "send request",
            sender.send_request(h3_request),
        )
        .await?
        .map_err(h3_stream_error)?;
        if !request.body.is_empty() {
            http3_timeout(
                self.read_timeout,
                "send request body",
                request_stream.send_data(Bytes::copy_from_slice(&request.body)),
            )
            .await?
            .map_err(h3_stream_error)?;
        }
        http3_timeout(self.read_timeout, "finish request", request_stream.finish())
            .await?
            .map_err(h3_stream_error)?;

        let response = http3_timeout(
            self.read_timeout,
            "receive response headers",
            request_stream.recv_response(),
        )
        .await?
        .map_err(h3_stream_error)?;
        let status = response.status().as_u16();
        let headers =
            http2_response_headers(response.headers(), self.limits.max_response_header_bytes)?;
        if transfer_encoding(&headers)?.is_some() {
            return Err(TransportError::MalformedResponse);
        }
        let expected_body_len = content_length(&headers)?;
        let no_body = response_has_no_body(&request.method, status);
        let body_len = if no_body {
            http3_timeout(
                self.read_timeout,
                "receive empty response body",
                ensure_http3_body_empty(&mut request_stream),
            )
            .await??;
            0
        } else {
            http3_timeout(
                self.read_timeout,
                "receive response body",
                read_http3_body_to_writer(
                    &mut request_stream,
                    self.limits.max_response_body_bytes,
                    body,
                ),
            )
            .await??
        };
        if !no_body && expected_body_len.is_some_and(|expected| expected != body_len) {
            return Err(TransportError::MalformedResponse);
        }

        driver_task.abort();
        close_connection.close(0u32.into(), b"done");

        let (dane_decision, tls_inspection) = verifier.finish_handshake(&request.host)?;
        Ok(OriginResponseHead {
            status,
            headers,
            body_len,
            dane_decision,
            tls_inspection,
        })
    }

    fn open_http11_tunnel(&self, request: &OriginRequest) -> Result<OriginTunnel, TransportError> {
        validate_tunnel_request(request, self.limits)?;
        let scheme = tunnel_origin_scheme(&request.scheme)?;
        let request = OriginRequest {
            scheme,
            protocol: OriginProtocol::Http11,
            ..request.clone()
        };
        match request.scheme.as_str() {
            "http" => self.open_plain_http11_tunnel(&request),
            "https" => self.open_tls_http11_tunnel(&request),
            _ => Err(TransportError::UnsupportedScheme),
        }
    }

    fn open_plain_http11_tunnel(
        &self,
        request: &OriginRequest,
    ) -> Result<OriginTunnel, TransportError> {
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let mut stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        let response_head = self.send_http11_upgrade(&mut stream, request)?;
        stream
            .set_read_timeout(Some(TUNNEL_IO_TIMEOUT))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(TUNNEL_IO_TIMEOUT))
            .map_err(io_error)?;
        Ok(OriginTunnel {
            response_head,
            stream: Box::new(stream),
            dane_decision: DaneDecision::NoTlsa,
            tls_inspection: None,
        })
    }

    fn open_tls_http11_tunnel(
        &self,
        request: &OriginRequest,
    ) -> Result<OriginTunnel, TransportError> {
        let connection_host = request.connect_host.as_deref().unwrap_or(&request.host);
        let stream = connect(connection_host, request.port, self.connect_timeout)?;
        stream
            .set_read_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        stream
            .set_write_timeout(Some(self.read_timeout))
            .map_err(io_error)?;
        let (config, verifier) = self.client_config(request.tls.clone(), Vec::new())?;
        let server_name = ServerName::try_from(request.host.clone())
            .map_err(|_| TransportError::InvalidRequest)?;
        verifier.begin_handshake(&request.host);
        let connection = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|error| verifier.map_handshake_error(tls_error(error)))?;
        let mut tls_stream = StreamOwned::new(connection, stream);
        let response_head = self
            .send_http11_upgrade(&mut tls_stream, request)
            .map_err(|error| verifier.map_handshake_error(error))?;
        tls_stream
            .sock
            .set_read_timeout(Some(TUNNEL_IO_TIMEOUT))
            .map_err(io_error)?;
        tls_stream
            .sock
            .set_write_timeout(Some(TUNNEL_IO_TIMEOUT))
            .map_err(io_error)?;
        let (dane_decision, tls_inspection) = verifier.finish_handshake(&request.host)?;
        Ok(OriginTunnel {
            response_head,
            stream: Box::new(tls_stream),
            dane_decision,
            tls_inspection,
        })
    }

    fn client_config(
        &self,
        tls: TlsValidation,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<(ClientConfig, Arc<DaneServerCertVerifier>), TransportError> {
        validate_browser_tls_decision(&tls)?;
        let tls_key = tls_validation_key(&tls);
        let verifier = self.dane_verifier_for(tls.clone(), &tls_key)?;
        let provider = rustls::crypto::ring::default_provider();

        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(tls_error)?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        config.resumption = self.resumption_for(&tls_key, &alpn_protocols)?;
        config.alpn_protocols = alpn_protocols;
        Ok((config, verifier))
    }

    fn dane_verifier_for(
        &self,
        tls: TlsValidation,
        tls_key: &str,
    ) -> Result<Arc<DaneServerCertVerifier>, TransportError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| TransportError::Tls("transport state lock is poisoned".to_owned()))?;
        if let Some(verifier) = state.tls_verifiers.get(tls_key) {
            return Ok(Arc::clone(verifier));
        }

        let provider = rustls::crypto::ring::default_provider();
        let webpki = WebPkiServerVerifier::builder_with_provider(
            Arc::clone(&self.root_store),
            Arc::new(provider),
        )
        .build()
        .map_err(|error| TransportError::Tls(error.to_string()))?;
        let verifier = Arc::new(DaneServerCertVerifier::new(webpki, tls));
        if !state.tls_verifiers.contains_key(tls_key) {
            evict_one_if_at_capacity(&mut state.tls_verifiers, MAX_TLS_POLICY_CACHE_ENTRIES);
        }
        state
            .tls_verifiers
            .insert(tls_key.to_owned(), Arc::clone(&verifier));
        Ok(verifier)
    }

    fn resumption_for(
        &self,
        tls_key: &str,
        alpn_protocols: &[Vec<u8>],
    ) -> Result<Resumption, TransportError> {
        let key = format!("{tls_key}|alpn={}", alpn_key(alpn_protocols));
        let mut state = self
            .state
            .lock()
            .map_err(|_| TransportError::Tls("transport state lock is poisoned".to_owned()))?;
        if !state.tls_resumption.contains_key(&key) {
            evict_one_if_at_capacity(&mut state.tls_resumption, MAX_TLS_POLICY_CACHE_ENTRIES);
        }
        Ok(state
            .tls_resumption
            .entry(key)
            .or_insert_with(|| Resumption::in_memory_sessions(256))
            .clone())
    }

    fn http11_pool_key(&self, request: &OriginRequest) -> Http11PoolKey {
        Http11PoolKey {
            scheme: request.scheme.to_ascii_lowercase(),
            host: request.host.to_ascii_lowercase(),
            connect_host: request
                .connect_host
                .as_deref()
                .unwrap_or(&request.host)
                .to_ascii_lowercase(),
            port: request.port,
            tls_key: tls_validation_key(&request.tls),
        }
    }

    fn take_http11_connection(&self, key: &Http11PoolKey) -> Option<PooledHttp11Connection> {
        let mut state = self.state.lock().ok()?;
        let connection = state.http11_pool.get_mut(key).and_then(VecDeque::pop_front);
        if state.http11_pool.get(key).is_some_and(VecDeque::is_empty) {
            state.http11_pool.remove(key);
        }
        connection
    }

    fn put_http11_connection(&self, key: Http11PoolKey, connection: PooledHttp11Connection) {
        if let Ok(mut state) = self.state.lock() {
            if !state.http11_pool.contains_key(&key) {
                evict_one_if_at_capacity(&mut state.http11_pool, MAX_HTTP11_POOL_ORIGINS);
            }
            let pool = state.http11_pool.entry(key).or_default();
            if pool.len() >= MAX_HTTP11_POOL_PER_ORIGIN {
                pool.pop_front();
            }
            pool.push_back(connection);
        }
    }

    fn promoted_request(&self, request: &OriginRequest) -> OriginRequest {
        if !request.scheme.eq_ignore_ascii_case("https")
            || request.protocol == OriginProtocol::Http3
            || !is_safe_retry_method(&request.method)
        {
            return request.clone();
        }
        let key = AltSvcKey {
            scheme: "https".to_owned(),
            host: request.host.to_ascii_lowercase(),
            port: request.port,
            namespace_fingerprint: request.tls.namespace_fingerprint.clone(),
        };
        let now = Instant::now();
        let Some(endpoint) = self.state.lock().ok().and_then(|mut state| {
            state
                .alt_svc
                .retain(|_, endpoint| endpoint.expires_at > now);
            state
                .blocked_alt_svc
                .retain(|_, expires_at| *expires_at > now);
            if state.blocked_alt_svc.contains_key(&key) {
                None
            } else {
                state.alt_svc.get(&key).cloned()
            }
        }) else {
            return request.clone();
        };
        if endpoint.port != request.port
            || request.tls.namespace_fingerprint.is_some()
                && protocol_tlsa_transport(endpoint.protocol) != request.tls.service_transport
        {
            return request.clone();
        }
        let mut promoted = request.clone();
        promoted.protocol = endpoint.protocol;
        promoted
    }

    fn record_alt_svc(&self, request: &OriginRequest, headers: &[(String, String)]) {
        if !request.scheme.eq_ignore_ascii_case("https") {
            return;
        }
        let key = AltSvcKey {
            scheme: "https".to_owned(),
            host: request.host.to_ascii_lowercase(),
            port: request.port,
            namespace_fingerprint: request.tls.namespace_fingerprint.clone(),
        };
        let values = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("alt-svc"))
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>();
        if values.is_empty() {
            return;
        }
        if values
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case("clear"))
        {
            if let Ok(mut state) = self.state.lock() {
                state.alt_svc.remove(&key);
                state.blocked_alt_svc.remove(&key);
            }
            return;
        }
        let Some(endpoint) = selected_alt_svc_endpoint(&values, request.port) else {
            return;
        };
        if let Ok(mut state) = self.state.lock() {
            let now = Instant::now();
            state
                .alt_svc
                .retain(|_, endpoint| endpoint.expires_at > now);
            state
                .blocked_alt_svc
                .retain(|_, expires_at| *expires_at > now);
            if state.blocked_alt_svc.contains_key(&key) {
                return;
            }
            if !state.alt_svc.contains_key(&key) {
                evict_one_if_at_capacity(&mut state.alt_svc, MAX_ALT_SVC_CACHE_ENTRIES);
            }
            state.alt_svc.insert(key, endpoint);
        }
    }

    fn suppress_alt_svc(&self, request: &OriginRequest) {
        if !request.scheme.eq_ignore_ascii_case("https") {
            return;
        }
        let key = AltSvcKey {
            scheme: "https".to_owned(),
            host: request.host.to_ascii_lowercase(),
            port: request.port,
            namespace_fingerprint: request.tls.namespace_fingerprint.clone(),
        };
        if let Ok(mut state) = self.state.lock() {
            let now = Instant::now();
            state.alt_svc.remove(&key);
            state
                .blocked_alt_svc
                .retain(|_, expires_at| *expires_at > now);
            if !state.blocked_alt_svc.contains_key(&key) {
                evict_one_if_at_capacity(&mut state.blocked_alt_svc, MAX_ALT_SVC_CACHE_ENTRIES);
            }
            state
                .blocked_alt_svc
                .insert(key, now + ALT_SVC_FAILURE_COOLDOWN);
        }
    }

    fn send_plain_http11(
        &self,
        stream: &mut TcpStream,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<(OriginResponseHead, bool), TransportError> {
        self.send_http11_stream(stream, request, body)
    }

    fn send_tls_http11(
        &self,
        stream: &mut StreamOwned<ClientConnection, TcpStream>,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<(OriginResponseHead, bool), TransportError> {
        self.send_http11_stream(stream, request, body)
    }

    fn send_http11_stream(
        &self,
        stream: &mut impl ReadWrite,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<(OriginResponseHead, bool), TransportError> {
        let request_bytes = build_http_request(request, true)?;
        stream.write_all(&request_bytes).map_err(io_error)?;
        stream.flush().map_err(io_error)?;
        let (head, reusable) =
            parse_http_response_to_writer_reusable(stream, self.limits, &request.method, body)?;
        self.record_alt_svc(request, &head.headers);
        Ok((head, reusable))
    }

    fn send_http11_upgrade(
        &self,
        stream: &mut impl ReadWrite,
        request: &OriginRequest,
    ) -> Result<Vec<u8>, TransportError> {
        let request_bytes = build_http_upgrade_request(request)?;
        stream.write_all(&request_bytes).map_err(io_error)?;
        stream.flush().map_err(io_error)?;
        let response_head =
            read_header_bytes_including_end(stream, self.limits.max_response_header_bytes)?;
        validate_upgrade_response_head(&response_head)?;
        Ok(response_head)
    }
}

impl OriginTransport for FailClosedTransport {
    fn fetch(&self, _request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        Err(TransportError::UnsupportedTransport)
    }
}

impl OriginTransport for TcpHttpTransport {
    fn fetch(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
        let promoted = self.promoted_request(request);
        match self.fetch_unpromoted(&promoted) {
            Ok(response) => Ok(response),
            Err(error) if should_retry_alt_svc_fallback(request, &promoted, &error, 0) => {
                self.suppress_alt_svc(request);
                self.fetch_unpromoted(request)
            }
            Err(error) => Err(error),
        }
    }

    fn open_tunnel(&self, request: &OriginRequest) -> Result<OriginTunnel, TransportError> {
        self.open_http11_tunnel(request)
    }

    fn open_webpki_passthrough(
        &self,
        request: &OriginRequest,
    ) -> Result<OriginWebPkiPassthrough, TransportError> {
        self.open_explicit_webpki_passthrough(request)
    }

    fn open_webpki_passthrough_candidates(
        &self,
        requests: &[OriginRequest],
    ) -> Result<SelectedOriginWebPkiPassthrough, TransportError> {
        let mut before_dial = || Ok(());
        self.open_explicit_webpki_passthrough_candidates(requests, &mut before_dial)
    }

    fn open_webpki_passthrough_candidates_with_guard(
        &self,
        requests: &[OriginRequest],
        before_dial: &mut dyn FnMut() -> Result<(), TransportError>,
    ) -> Result<SelectedOriginWebPkiPassthrough, TransportError> {
        self.open_explicit_webpki_passthrough_candidates(requests, before_dial)
    }

    fn fetch_to_writer(
        &self,
        request: &OriginRequest,
        body: &mut dyn Write,
    ) -> Result<OriginResponseHead, TransportError> {
        let promoted = self.promoted_request(request);
        let mut attempted_body = CountingWriter::new(body);
        match self.fetch_unpromoted_to_writer(&promoted, &mut attempted_body) {
            Ok(head) => Ok(head),
            Err(error)
                if should_retry_alt_svc_fallback(
                    request,
                    &promoted,
                    &error,
                    attempted_body.written,
                ) =>
            {
                self.suppress_alt_svc(request);
                self.fetch_unpromoted_to_writer(request, attempted_body.inner_mut())
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug)]
struct DaneServerCertVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    tls: TlsValidation,
    handshakes: Mutex<HashMap<ThreadId, HandshakeCapture>>,
    last_success: Mutex<HashMap<String, HandshakeCapture>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TlsPolicyFailure {
    DaneAssociationMismatch,
}

#[derive(Clone, Debug, Default)]
struct HandshakeCapture {
    server_name: String,
    decision: Option<DaneDecision>,
    inspection: Option<TlsCertificateInspection>,
    failure: Option<TlsPolicyFailure>,
}

impl DaneServerCertVerifier {
    fn new(webpki: Arc<WebPkiServerVerifier>, tls: TlsValidation) -> Self {
        Self {
            webpki,
            tls,
            handshakes: Mutex::new(HashMap::new()),
            last_success: Mutex::new(HashMap::new()),
        }
    }

    fn begin_handshake(&self, server_name: &str) {
        if let Ok(mut handshakes) = self.handshakes.lock() {
            let thread_id = std::thread::current().id();
            if !handshakes.contains_key(&thread_id) {
                evict_one_if_at_capacity(&mut handshakes, MAX_TLS_CAPTURE_ENTRIES);
            }
            handshakes.insert(
                thread_id,
                HandshakeCapture {
                    server_name: server_name.to_ascii_lowercase(),
                    ..HandshakeCapture::default()
                },
            );
        }
    }

    fn finish_handshake(
        &self,
        server_name: &str,
    ) -> Result<(DaneDecision, Option<TlsCertificateInspection>), TransportError> {
        let capture = self
            .handshakes
            .lock()
            .map_err(|_| TransportError::Tls("TLS handshake lock is poisoned".to_owned()))?
            .remove(&std::thread::current().id());
        if let Some(capture) = capture
            && let Some(decision) = capture.decision
        {
            return Ok((decision, capture.inspection));
        }

        let key = server_name.to_ascii_lowercase();
        let cached = self
            .last_success
            .lock()
            .map_err(|_| TransportError::Tls("TLS handshake cache lock is poisoned".to_owned()))?
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                TransportError::Tls("TLS certificate policy was not evaluated".to_owned())
            })?;
        Ok((
            cached.decision.ok_or_else(|| {
                TransportError::Tls("TLS certificate policy was not evaluated".to_owned())
            })?,
            cached.inspection,
        ))
    }

    fn record_failure(&self, failure: TlsPolicyFailure) -> Result<(), RustlsError> {
        let mut handshakes = self
            .handshakes
            .lock()
            .map_err(|_| RustlsError::General("TLS handshake lock is poisoned".to_owned()))?;
        let capture = handshakes.entry(std::thread::current().id()).or_default();
        capture.failure = Some(failure);
        Ok(())
    }

    fn map_handshake_error(&self, error: TransportError) -> TransportError {
        let failure = self
            .handshakes
            .lock()
            .ok()
            .and_then(|mut handshakes| handshakes.remove(&std::thread::current().id()))
            .and_then(|capture| capture.failure);
        match failure {
            Some(TlsPolicyFailure::DaneAssociationMismatch) => TransportError::DaneFailed,
            None => error,
        }
    }

    fn store_capture(
        &self,
        decision: DaneDecision,
        inspection: TlsCertificateInspection,
    ) -> Result<(), RustlsError> {
        let mut handshakes = self
            .handshakes
            .lock()
            .map_err(|_| RustlsError::General("TLS handshake lock is poisoned".to_owned()))?;
        let capture = handshakes.entry(std::thread::current().id()).or_default();
        capture.decision = Some(decision);
        capture.inspection = Some(inspection);
        let capture = capture.clone();
        let mut last_success = self
            .last_success
            .lock()
            .map_err(|_| RustlsError::General("TLS handshake cache lock is poisoned".to_owned()))?;
        if !capture.server_name.is_empty() {
            if !last_success.contains_key(&capture.server_name) {
                evict_one_if_at_capacity(&mut last_success, MAX_TLS_CAPTURE_ENTRIES);
            }
            last_success.insert(capture.server_name.clone(), capture);
        }
        Ok(())
    }
}

impl ServerCertVerifier for DaneServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let webpki_result = self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let webpki_status = if webpki_result.is_ok() {
            WebPkiStatus::Valid
        } else {
            WebPkiStatus::Invalid
        };

        let intermediate_der = intermediates
            .iter()
            .map(|certificate| certificate.as_ref())
            .collect::<Vec<_>>();
        let mut stateless_dane_evidence = None;
        let mut tlsa_records = self.tls.tlsa_records.as_slice();
        let mut dnssec_secure = self.tls.dnssec_secure;
        if self.tls.stateless_dane.enabled
            && self.tls.mode != DomainTrustMode::IcannWebPki
            && tlsa_records.is_empty()
        {
            let evidence = evaluate_stateless_dane_certificate(StatelessDaneValidationInput {
                cert_der: end_entity.as_ref(),
                host: &server_name.to_str(),
                port: self.tls.service_port,
                accepted_tree_roots: &self.tls.stateless_dane.accepted_tree_roots,
                now_unix: now.as_secs(),
            })
            .map_err(|error| {
                RustlsError::General(format!(
                    "stateless DANE certificate evidence rejected: {error}"
                ))
            })?;
            if matches!(evidence, StatelessDaneEvidence::Tlsa { .. }) {
                dnssec_secure = true;
            }
            stateless_dane_evidence = Some(evidence);
        }
        if let Some(StatelessDaneEvidence::Tlsa { records, .. }) = stateless_dane_evidence.as_ref()
        {
            tlsa_records = records;
        }

        let decision =
            evaluate_policy_with_certificate_chain(DaneCertificateChainValidationInput {
                mode: self.tls.mode,
                dnssec_secure,
                tlsa_records,
                end_entity_der: end_entity.as_ref(),
                intermediate_der: &intermediate_der,
                webpki_status,
            })
            .map(|decision| {
                with_stateless_dane_provenance(decision, stateless_dane_evidence.as_ref())
            });

        match decision {
            Ok(DaneDecision::Failed) => {
                self.record_failure(TlsPolicyFailure::DaneAssociationMismatch)?;
                Err(RustlsError::General(
                    "DANE certificate association did not match".to_owned(),
                ))
            }
            Ok(decision) => {
                let inspection =
                    tls_certificate_inspection(end_entity, intermediates, webpki_status)?;
                self.store_capture(decision, inspection)?;
                Ok(ServerCertVerified::assertion())
            }
            Err(DaneError::WebPkiFailed) => webpki_result,
            Err(error) => Err(RustlsError::General(format!(
                "DANE policy rejected certificate: {error}"
            ))),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

fn with_stateless_dane_provenance(
    decision: DaneDecision,
    evidence: Option<&StatelessDaneEvidence>,
) -> DaneDecision {
    match (decision, evidence) {
        (DaneDecision::Matched(usage), Some(StatelessDaneEvidence::Tlsa { .. })) => {
            DaneDecision::StatelessMatched(usage)
        }
        (decision, _) => decision,
    }
}

fn default_root_store() -> RootCertStore {
    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, TransportError> {
    let mut last_error = None;
    let addresses = (host, port).to_socket_addrs().map_err(io_error)?;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error
        .map(io_error)
        .unwrap_or_else(|| TransportError::Io("no resolved socket addresses".to_owned())))
}

async fn connect_async(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<tokio::net::TcpStream, TransportError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(io_error)?
        .collect::<Vec<_>>();
    let mut last_error = None;
    for address in addresses {
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => last_error = Some(format!("connect to {address} timed out")),
        }
    }

    Err(last_error
        .map(TransportError::Io)
        .unwrap_or_else(|| TransportError::Io("no resolved socket addresses".to_owned())))
}

async fn resolve_socket_addr_async(host: &str, port: u16) -> Result<SocketAddr, TransportError> {
    tokio::net::lookup_host((host, port))
        .await
        .map_err(io_error)?
        .next()
        .ok_or_else(|| TransportError::Io("no resolved socket addresses".to_owned()))
}

fn build_http2_request(request: &OriginRequest) -> Result<Http2Request<()>, TransportError> {
    let nominated_headers = connection_nominated_headers(&request.headers)?;
    let authority = host_header(&request.host, request.port, &request.scheme);
    let uri = format!(
        "{}://{}{}",
        request.scheme, authority, request.path_and_query
    )
    .parse::<http::Uri>()
    .map_err(|_| TransportError::InvalidRequest)?;
    let mut h2_request = Http2Request::builder()
        .method(request.method.as_str())
        .uri(uri)
        .body(())
        .map_err(|_| TransportError::InvalidRequest)?;
    {
        let headers = h2_request.headers_mut();
        if !has_header(&request.headers, "user-agent") && !nominated_headers.contains("user-agent")
        {
            headers.insert(
                HeaderName::from_static("user-agent"),
                HeaderValue::from_static(concat!("hns-dane-browser/", env!("CARGO_PKG_VERSION"))),
            );
        }
        if !has_header(&request.headers, "accept") && !nominated_headers.contains("accept") {
            headers.insert(
                HeaderName::from_static("accept"),
                HeaderValue::from_static("*/*"),
            );
        }
        for (name, value) in &request.headers {
            if is_hop_by_hop_header(name)
                || nominated_headers.contains(&name.to_ascii_lowercase())
                || name.eq_ignore_ascii_case("host")
                || name.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| TransportError::InvalidRequest)?;
            let value = HeaderValue::from_str(value).map_err(|_| TransportError::InvalidRequest)?;
            headers.append(name, value);
        }
        if !request.body.is_empty() {
            headers.insert(
                http::header::CONTENT_LENGTH,
                HeaderValue::from(request.body.len() as u64),
            );
        }
    }
    Ok(h2_request)
}

fn http2_response_headers(
    headers: &http::HeaderMap<HeaderValue>,
    limit: usize,
) -> Result<Vec<(String, String)>, TransportError> {
    let mut total = 0usize;
    let mut parsed = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        // RFC 9113's field section size includes 32 bytes of per-field overhead.
        total = total
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.as_bytes().len()))
            .and_then(|size| size.checked_add(32))
            .filter(|size| *size <= limit)
            .ok_or(TransportError::ResponseTooLarge)?;
        let value = value
            .to_str()
            .map_err(|_| TransportError::MalformedResponse)?;
        if !is_valid_http_field_value(value) {
            return Err(TransportError::MalformedResponse);
        }
        parsed.push((name.as_str().to_owned(), value.to_owned()));
    }
    Ok(parsed)
}

async fn read_http2_body_to_writer(
    stream: &mut h2::RecvStream,
    limit: usize,
    body: &mut dyn Write,
) -> Result<usize, TransportError> {
    let mut total = 0usize;
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.map_err(h2_error)?;
        total = checked_body_len(total, chunk.len(), limit)?;
        body.write_all(&chunk).map_err(io_error)?;
        stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(h2_error)?;
    }
    Ok(total)
}

async fn ensure_http2_body_empty(stream: &mut h2::RecvStream) -> Result<(), TransportError> {
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.map_err(h2_error)?;
        let chunk_len = chunk.len();
        stream
            .flow_control()
            .release_capacity(chunk_len)
            .map_err(h2_error)?;
        if chunk_len != 0 {
            return Err(TransportError::MalformedResponse);
        }
    }
    Ok(())
}

async fn read_http3_body_to_writer<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    limit: usize,
    body: &mut dyn Write,
) -> Result<usize, TransportError>
where
    S: h3::quic::RecvStream,
{
    let mut total = 0usize;
    while let Some(mut chunk) = stream.recv_data().await.map_err(h3_stream_error)? {
        let chunk_len = chunk.remaining();
        total = checked_body_len(total, chunk_len, limit)?;
        let bytes = chunk.copy_to_bytes(chunk_len);
        body.write_all(&bytes).map_err(io_error)?;
    }
    Ok(total)
}

async fn ensure_http3_body_empty<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
) -> Result<(), TransportError>
where
    S: h3::quic::RecvStream,
{
    while let Some(chunk) = stream.recv_data().await.map_err(h3_stream_error)? {
        if chunk.remaining() != 0 {
            return Err(TransportError::MalformedResponse);
        }
    }
    Ok(())
}

async fn http3_timeout<T>(
    timeout: Duration,
    stage: &'static str,
    future: impl std::future::Future<Output = T>,
) -> Result<T, TransportError> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TransportError::Io(format!("HTTP/3 {stage} timed out")))
}

fn validate_request(
    request: &OriginRequest,
    limits: TransportLimits,
) -> Result<(), TransportError> {
    validate_request_common(request, limits)?;

    if is_protocol_upgrade(&request.headers) {
        return Err(TransportError::UnsupportedUpgrade);
    }

    Ok(())
}

fn validate_tunnel_request(
    request: &OriginRequest,
    limits: TransportLimits,
) -> Result<(), TransportError> {
    validate_request_common(request, limits)?;
    if !is_protocol_upgrade(&request.headers) {
        return Err(TransportError::UnsupportedUpgrade);
    }
    if !request.body.is_empty() {
        return Err(TransportError::InvalidRequest);
    }
    Ok(())
}

fn validate_request_common(
    request: &OriginRequest,
    limits: TransportLimits,
) -> Result<(), TransportError> {
    if !is_http_token(&request.method)
        || !is_valid_host(&request.host)
        || request.port == 0
        || !request.path_and_query.starts_with('/')
        || request
            .path_and_query
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(TransportError::InvalidRequest);
    }

    if let Some(connect_host) = &request.connect_host
        && !is_valid_host(connect_host)
    {
        return Err(TransportError::InvalidRequest);
    }

    if request.body.len() > limits.max_request_body_bytes {
        return Err(TransportError::RequestTooLarge);
    }

    for (name, value) in &request.headers {
        if !is_http_token(name) || !is_valid_http_field_value(value) {
            return Err(TransportError::InvalidRequest);
        }
    }
    if request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        .count()
        > 1
    {
        return Err(TransportError::InvalidRequest);
    }
    connection_nominated_headers(&request.headers)?;

    Ok(())
}

fn tunnel_origin_scheme(scheme: &str) -> Result<String, TransportError> {
    match scheme.to_ascii_lowercase().as_str() {
        "http" | "ws" => Ok("http".to_owned()),
        "https" | "wss" => Ok("https".to_owned()),
        _ => Err(TransportError::UnsupportedScheme),
    }
}

fn build_http_request(
    request: &OriginRequest,
    keep_alive: bool,
) -> Result<Vec<u8>, TransportError> {
    let nominated_headers = connection_nominated_headers(&request.headers)?;
    let mut out = Vec::new();
    write!(
        out,
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        request.method.to_ascii_uppercase(),
        request.path_and_query,
        host_header(&request.host, request.port, &request.scheme),
    )
    .map_err(io_error)?;
    if !has_header(&request.headers, "user-agent") && !nominated_headers.contains("user-agent") {
        out.extend_from_slice(
            concat!(
                "User-Agent: hns-dane-browser/",
                env!("CARGO_PKG_VERSION"),
                "\r\n"
            )
            .as_bytes(),
        );
    }
    if !has_header(&request.headers, "accept") && !nominated_headers.contains("accept") {
        out.extend(b"Accept: */*\r\n");
    }

    for (name, value) in &request.headers {
        if is_hop_by_hop_header(name)
            || nominated_headers.contains(&name.to_ascii_lowercase())
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        write!(out, "{name}: {value}\r\n").map_err(io_error)?;
    }

    let connection = if keep_alive { "keep-alive" } else { "close" };
    if request.body.is_empty() {
        write!(out, "Connection: {connection}\r\n\r\n").map_err(io_error)?;
    } else {
        write!(
            out,
            "Content-Length: {}\r\nConnection: {connection}\r\n\r\n",
            request.body.len(),
        )
        .map_err(io_error)?;
        out.extend(&request.body);
    }

    Ok(out)
}

fn build_http_upgrade_request(request: &OriginRequest) -> Result<Vec<u8>, TransportError> {
    let nominated_headers = connection_nominated_headers(&request.headers)?;
    let mut out = Vec::new();
    write!(
        out,
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        request.method.to_ascii_uppercase(),
        request.path_and_query,
        host_header(&request.host, request.port, &request.scheme),
    )
    .map_err(io_error)?;
    if !has_header(&request.headers, "user-agent") && !nominated_headers.contains("user-agent") {
        out.extend_from_slice(
            concat!(
                "User-Agent: hns-dane-browser/",
                env!("CARGO_PKG_VERSION"),
                "\r\n"
            )
            .as_bytes(),
        );
    }
    if !has_header(&request.headers, "accept") && !nominated_headers.contains("accept") {
        out.extend(b"Accept: */*\r\n");
    }

    let mut has_connection_upgrade = false;
    let mut has_upgrade = false;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("proxy-connection")
            || (is_hop_by_hop_header(name)
                && !name.eq_ignore_ascii_case("connection")
                && !name.eq_ignore_ascii_case("upgrade"))
            || (nominated_headers.contains(&name.to_ascii_lowercase())
                && !name.eq_ignore_ascii_case("upgrade"))
        {
            continue;
        }
        if name.eq_ignore_ascii_case("connection") && has_header_token(value, "upgrade") {
            has_connection_upgrade = true;
        }
        if name.eq_ignore_ascii_case("upgrade") {
            has_upgrade = true;
        }
        write!(out, "{name}: {value}\r\n").map_err(io_error)?;
    }
    if !has_connection_upgrade {
        out.extend(b"Connection: Upgrade\r\n");
    }
    if !has_upgrade {
        out.extend(b"Upgrade: websocket\r\n");
    }
    out.extend(b"\r\n");
    Ok(out)
}

fn host_header(host: &str, port: u16, scheme: &str) -> String {
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "https" => 443,
        _ => 80,
    };

    let bracketed_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };

    if port == default_port {
        bracketed_host
    } else {
        format!("{bracketed_host}:{port}")
    }
}

fn parse_http_response_to_writer_reusable(
    stream: &mut impl Read,
    limits: TransportLimits,
    request_method: &str,
    body: &mut dyn Write,
) -> Result<(OriginResponseHead, bool), TransportError> {
    let mut remaining_header_bytes = limits.max_response_header_bytes;
    let mut informational_count = 0usize;
    let (version, status, headers) = loop {
        let header_bytes = read_header_bytes(stream, remaining_header_bytes)?;
        remaining_header_bytes = remaining_header_bytes
            .checked_sub(
                header_bytes
                    .len()
                    .checked_add(4)
                    .ok_or(TransportError::ResponseTooLarge)?,
            )
            .ok_or(TransportError::ResponseTooLarge)?;
        let (version, status, headers) = parse_http11_header_block(&header_bytes)?;
        if (100..200).contains(&status) {
            if status == 101 {
                return Err(TransportError::UnsupportedUpgrade);
            }
            if remaining_header_bytes == 0 {
                return Err(TransportError::ResponseTooLarge);
            }
            if headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
            {
                return Err(TransportError::MalformedResponse);
            }
            if headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            {
                return Err(TransportError::MalformedResponse);
            }
            informational_count = informational_count.saturating_add(1);
            if informational_count > MAX_INFORMATIONAL_RESPONSES {
                return Err(TransportError::MalformedResponse);
            }
            continue;
        }
        break (version, status, headers);
    };

    let mut self_delimited = response_has_no_body(request_method, status);
    let body_len = if self_delimited {
        0
    } else if let Some(transfer_encoding) = transfer_encoding(&headers)? {
        if content_length(&headers)?.is_some() {
            return Err(TransportError::MalformedResponse);
        }
        if transfer_encoding != [TransferCoding::Chunked] {
            return Err(TransportError::UnsupportedTransferEncoding);
        }
        self_delimited = true;
        read_chunked_body_to_writer(
            stream,
            limits.max_response_body_bytes,
            remaining_header_bytes,
            body,
        )?
    } else if let Some(length) = content_length(&headers)? {
        self_delimited = true;
        read_fixed_body_to_writer(stream, length, limits.max_response_body_bytes, body)?
    } else {
        read_until_eof_to_writer(stream, limits.max_response_body_bytes, body)?
    };
    let reusable =
        version.eq_ignore_ascii_case("HTTP/1.1") && self_delimited && !connection_close(&headers);

    Ok((
        OriginResponseHead {
            status,
            headers,
            body_len,
            dane_decision: DaneDecision::NoTlsa,
            tls_inspection: None,
        },
        reusable,
    ))
}

fn parse_http11_header_block(
    header_bytes: &[u8],
) -> Result<ParsedHttp11HeaderBlock, TransportError> {
    let header_text =
        std::str::from_utf8(header_bytes).map_err(|_| TransportError::MalformedResponse)?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or(TransportError::MalformedResponse)?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts
        .next()
        .ok_or(TransportError::MalformedResponse)?;
    let status = status_parts
        .next()
        .ok_or(TransportError::MalformedResponse)?
        .parse::<u16>()
        .map_err(|_| TransportError::MalformedResponse)?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || !(100..=999).contains(&status) {
        return Err(TransportError::MalformedResponse);
    }

    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or(TransportError::MalformedResponse)?;
        if name != name.trim() {
            return Err(TransportError::MalformedResponse);
        }
        let name = name.to_owned();
        let value = value.trim().to_owned();
        if !is_http_token(&name) || !is_valid_http_field_value(&value) {
            return Err(TransportError::MalformedResponse);
        }
        headers.push((name, value));
    }

    Ok((version.to_owned(), status, headers))
}

fn response_has_no_body(request_method: &str, status: u16) -> bool {
    request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
}

fn is_safe_retry_method(method: &str) -> bool {
    matches_ignore_ascii_case(method, &["GET", "HEAD", "OPTIONS", "TRACE"])
}

fn may_retry_stale_pooled_request(
    request: &OriginRequest,
    error: &TransportError,
    response_body_bytes_written: usize,
    replay_stale_rfc8484_post: bool,
) -> bool {
    if response_body_bytes_written != 0 {
        return false;
    }
    if is_safe_retry_method(&request.method) {
        return true;
    }
    replay_stale_rfc8484_post
        && is_exact_ip_rfc8484_post(request)
        && matches!(
            error,
            TransportError::Io(_) | TransportError::Tls(_) | TransportError::MalformedResponse
        )
}

fn is_exact_ip_rfc8484_post(request: &OriginRequest) -> bool {
    request.method.eq_ignore_ascii_case("POST")
        && request.scheme.eq_ignore_ascii_case("https")
        && request.protocol == OriginProtocol::Http11
        && request
            .connect_host
            .as_deref()
            .is_some_and(|host| host.parse::<IpAddr>().is_ok())
        && request.body.len() >= 12
        && has_exactly_one_header_value(request, "content-type", DNS_MESSAGE_MEDIA_TYPE)
        && has_exactly_one_header_value(request, "accept", DNS_MESSAGE_MEDIA_TYPE)
}

fn has_exactly_one_header_value(
    request: &OriginRequest,
    expected_name: &str,
    expected_value: &str,
) -> bool {
    let mut values = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(expected_name))
        .map(|(_, value)| value.trim());
    values
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case(expected_value))
        && values.next().is_none()
}

fn matches_ignore_ascii_case(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

fn read_header_bytes(stream: &mut impl Read, limit: usize) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];

    while out.len() < limit {
        let read = stream.read(&mut byte).map_err(io_error)?;
        if read == 0 {
            return Err(TransportError::MalformedResponse);
        }
        out.push(byte[0]);
        if out.ends_with(b"\r\n\r\n") {
            out.truncate(out.len() - 4);
            return Ok(out);
        }
    }

    Err(TransportError::ResponseTooLarge)
}

fn read_header_bytes_including_end(
    stream: &mut impl Read,
    limit: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];

    while out.len() < limit {
        let read = stream.read(&mut byte).map_err(io_error)?;
        if read == 0 {
            return Err(TransportError::MalformedResponse);
        }
        out.push(byte[0]);
        if out.ends_with(b"\r\n\r\n") {
            return Ok(out);
        }
    }

    Err(TransportError::ResponseTooLarge)
}

fn validate_upgrade_response_head(response_head: &[u8]) -> Result<(), TransportError> {
    let header_text =
        std::str::from_utf8(response_head).map_err(|_| TransportError::MalformedResponse)?;
    let header_text = header_text
        .strip_suffix("\r\n\r\n")
        .ok_or(TransportError::MalformedResponse)?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or(TransportError::MalformedResponse)?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts
        .next()
        .ok_or(TransportError::MalformedResponse)?;
    let status = status_parts
        .next()
        .ok_or(TransportError::MalformedResponse)?
        .parse::<u16>()
        .map_err(|_| TransportError::MalformedResponse)?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || status != 101 {
        return Err(TransportError::MalformedResponse);
    }

    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or(TransportError::MalformedResponse)?;
        if name != name.trim() {
            return Err(TransportError::MalformedResponse);
        }
        let value = value.trim();
        if !is_http_token(name) || !is_valid_http_field_value(value) {
            return Err(TransportError::MalformedResponse);
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    if !headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection") && has_header_token(value, "upgrade")
    }) || !headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("upgrade") && value.eq_ignore_ascii_case("websocket")
    }) {
        return Err(TransportError::MalformedResponse);
    }
    Ok(())
}

fn read_fixed_body_to_writer(
    stream: &mut impl Read,
    length: usize,
    limit: usize,
    body: &mut dyn Write,
) -> Result<usize, TransportError> {
    if length > limit {
        return Err(TransportError::ResponseTooLarge);
    }

    copy_exact_body(stream, body, length)?;
    Ok(length)
}

fn read_until_eof_to_writer(
    stream: &mut impl Read,
    limit: usize,
    body: &mut dyn Write,
) -> Result<usize, TransportError> {
    let mut total = 0usize;
    let mut buffer = [0u8; 16 * 1024];

    loop {
        let read = stream.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            return Ok(total);
        }
        total = checked_body_len(total, read, limit)?;
        body.write_all(&buffer[..read]).map_err(io_error)?;
    }
}

fn read_chunked_body_to_writer(
    stream: &mut impl Read,
    limit: usize,
    trailer_limit: usize,
    body: &mut dyn Write,
) -> Result<usize, TransportError> {
    let mut total = 0usize;

    loop {
        let line = read_crlf_line(stream, 8192)?;
        let size_text = line
            .split(';')
            .next()
            .ok_or(TransportError::MalformedResponse)?
            .trim();
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| TransportError::MalformedResponse)?;

        if size == 0 {
            read_trailers(stream, trailer_limit)?;
            return Ok(total);
        }

        total = checked_body_len(total, size, limit)?;
        copy_exact_body(stream, body, size)?;
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).map_err(io_error)?;
        if crlf != *b"\r\n" {
            return Err(TransportError::MalformedResponse);
        }
    }
}

fn copy_exact_body(
    stream: &mut impl Read,
    body: &mut dyn Write,
    mut length: usize,
) -> Result<(), TransportError> {
    let mut buffer = [0u8; 16 * 1024];
    while length > 0 {
        let count = length.min(buffer.len());
        stream.read_exact(&mut buffer[..count]).map_err(io_error)?;
        body.write_all(&buffer[..count]).map_err(io_error)?;
        length -= count;
    }
    Ok(())
}

fn checked_body_len(current: usize, chunk: usize, limit: usize) -> Result<usize, TransportError> {
    current
        .checked_add(chunk)
        .filter(|size| *size <= limit)
        .ok_or(TransportError::ResponseTooLarge)
}

fn read_trailers(stream: &mut impl Read, limit: usize) -> Result<(), TransportError> {
    let mut remaining = limit;
    let mut fields = 0usize;
    loop {
        let line = read_crlf_line(stream, remaining)?;
        remaining = remaining
            .checked_sub(
                line.len()
                    .checked_add(2)
                    .ok_or(TransportError::ResponseTooLarge)?,
            )
            .ok_or(TransportError::ResponseTooLarge)?;
        if line.is_empty() {
            return Ok(());
        }
        fields = fields.saturating_add(1);
        if fields > MAX_HTTP_TRAILER_FIELDS {
            return Err(TransportError::ResponseTooLarge);
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(TransportError::MalformedResponse)?;
        if name != name.trim()
            || !is_http_token(name)
            || !is_valid_http_field_value(value.trim())
            || matches!(
                name.to_ascii_lowercase().as_str(),
                "content-length" | "transfer-encoding" | "trailer"
            )
        {
            return Err(TransportError::MalformedResponse);
        }
    }
}

fn read_crlf_line(stream: &mut impl Read, limit: usize) -> Result<String, TransportError> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];

    while out.len() < limit {
        let read = stream.read(&mut byte).map_err(io_error)?;
        if read == 0 {
            return Err(TransportError::MalformedResponse);
        }
        out.push(byte[0]);
        if out.ends_with(b"\r\n") {
            out.truncate(out.len() - 2);
            return String::from_utf8(out).map_err(|_| TransportError::MalformedResponse);
        }
    }

    Err(TransportError::ResponseTooLarge)
}

fn content_length(headers: &[(String, String)]) -> Result<Option<usize>, TransportError> {
    let mut value = None;
    for (_, header_value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        let parsed = header_value
            .parse::<usize>()
            .map_err(|_| TransportError::MalformedResponse)?;
        if value.is_some_and(|existing| existing != parsed) {
            return Err(TransportError::MalformedResponse);
        }
        value = Some(parsed);
    }
    Ok(value)
}

fn connection_close(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection") && has_header_token(value, "close")
    })
}

fn has_header(headers: &[(String, String)], expected: &str) -> bool {
    headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(expected))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransferCoding {
    Chunked,
    Unsupported,
}

fn transfer_encoding(
    headers: &[(String, String)],
) -> Result<Option<Vec<TransferCoding>>, TransportError> {
    let mut codings = Vec::new();
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
    {
        for coding in value.split(',') {
            let coding = coding.trim();
            if coding.is_empty() {
                return Err(TransportError::MalformedResponse);
            }
            codings.push(if coding.eq_ignore_ascii_case("chunked") {
                TransferCoding::Chunked
            } else {
                TransferCoding::Unsupported
            });
        }
    }

    Ok((!codings.is_empty()).then_some(codings))
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn connection_nominated_headers(
    headers: &[(String, String)],
) -> Result<HashSet<String>, TransportError> {
    let mut nominated = HashSet::new();
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
    {
        for token in value.split(',').map(str::trim) {
            if token.is_empty() || !is_http_token(token) {
                return Err(TransportError::InvalidRequest);
            }
            nominated.insert(token.to_ascii_lowercase());
        }
    }
    Ok(nominated)
}

fn is_protocol_upgrade(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("upgrade")
            || (name.eq_ignore_ascii_case("connection") && has_header_token(value, "upgrade"))
    })
}

fn has_header_token(value: &str, expected: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|token| token.eq_ignore_ascii_case(expected))
}

fn selected_alt_svc_endpoint(values: &[&str], request_port: u16) -> Option<AltSvcEndpoint> {
    let now = Instant::now();
    let mut best = None;
    for value in values {
        for alternative in value.split(',') {
            let alternative = alternative.trim();
            let (protocol, rest) = alternative.split_once('=')?;
            let protocol = protocol.trim().to_ascii_lowercase();
            let protocol = if protocol == "h3" || protocol.starts_with("h3-") {
                OriginProtocol::Http3
            } else if protocol == "h2" {
                OriginProtocol::Http2
            } else {
                continue;
            };
            let authority = rest.trim_start();
            if !authority.starts_with('"') {
                continue;
            }
            let Some(end_quote) = authority[1..].find('"') else {
                continue;
            };
            let authority_value = &authority[1..1 + end_quote];
            let Some(port) = alt_svc_authority_port(authority_value, request_port) else {
                continue;
            };
            if port != request_port {
                continue;
            }
            let params = &authority[1 + end_quote + 1..];
            let max_age = alt_svc_max_age(params).unwrap_or(MAX_ALT_SVC_AGE_SECS);
            if max_age == 0 {
                continue;
            }
            let endpoint = AltSvcEndpoint {
                protocol,
                port,
                expires_at: now + Duration::from_secs(max_age.min(MAX_ALT_SVC_AGE_SECS)),
            };
            if best.as_ref().is_none_or(|current: &AltSvcEndpoint| {
                protocol_rank(endpoint.protocol) > protocol_rank(current.protocol)
            }) {
                best = Some(endpoint);
            }
        }
    }
    best
}

fn should_retry_alt_svc_fallback(
    original: &OriginRequest,
    promoted: &OriginRequest,
    error: &TransportError,
    body_bytes_written: usize,
) -> bool {
    original.scheme.eq_ignore_ascii_case("https")
        && promoted.scheme.eq_ignore_ascii_case("https")
        && original.protocol != promoted.protocol
        && original.host.eq_ignore_ascii_case(&promoted.host)
        && original.port == promoted.port
        && original.connect_host == promoted.connect_host
        && body_bytes_written == 0
        && is_safe_retry_method(&original.method)
        && is_alt_svc_fallback_error(error)
}

fn is_alt_svc_fallback_error(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Io(_)
            | TransportError::Http2(_)
            | TransportError::Http3(_)
            | TransportError::Quic(_)
            | TransportError::UnsupportedTransport
            | TransportError::UnsupportedTransferEncoding
            | TransportError::MalformedResponse
    )
}

fn alt_svc_authority_port(authority: &str, default_port: u16) -> Option<u16> {
    if authority.is_empty() {
        return Some(default_port);
    }
    if let Some(port_text) = authority.strip_prefix(':') {
        return port_text.parse::<u16>().ok();
    }
    let (_, port_text) = authority.rsplit_once(':')?;
    port_text.parse::<u16>().ok()
}

fn alt_svc_max_age(params: &str) -> Option<u64> {
    params.split(';').find_map(|param| {
        let (name, value) = param.trim().split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("ma")
            .then(|| value.trim().trim_matches('"').parse::<u64>().ok())
            .flatten()
    })
}

fn protocol_rank(protocol: OriginProtocol) -> u8 {
    match protocol {
        OriginProtocol::Http3 => 3,
        OriginProtocol::Http2 => 2,
        OriginProtocol::Http11 => 1,
    }
}

const fn protocol_tlsa_transport(protocol: OriginProtocol) -> TlsaTransport {
    match protocol {
        OriginProtocol::Http11 | OriginProtocol::Http2 => TlsaTransport::Tcp,
        OriginProtocol::Http3 => TlsaTransport::Udp,
    }
}

fn tls_validation_key(tls: &TlsValidation) -> String {
    let mut out = format!(
        "mode={:?};secure={};namespace={:?};port={};transport={:?};browser={:?};records={}",
        tls.mode,
        tls.dnssec_secure,
        tls.namespace_fingerprint,
        tls.service_port,
        tls.service_transport,
        tls.browser_tls_decision,
        tls.tlsa_records.len(),
    );
    for record in &tls.tlsa_records {
        out.push_str(&format!(
            ";{:?}:{:?}:{:?}:",
            record.usage, record.selector, record.matching,
        ));
        append_hash_hex(&mut out, &record.association_data);
    }
    out.push_str(&format!(
        ";stateless={};roots={}",
        tls.stateless_dane.enabled,
        tls.stateless_dane.accepted_tree_roots.len(),
    ));
    for root in &tls.stateless_dane.accepted_tree_roots {
        append_hash_hex(&mut out, root);
    }
    out
}

fn validate_browser_tls_decision(tls: &TlsValidation) -> Result<(), TransportError> {
    let Some(decision) = tls.browser_tls_decision else {
        return Ok(());
    };
    if tls.mode != DomainTrustMode::IcannWebPki {
        return Err(TransportError::InvalidRequest);
    }
    let valid = match decision {
        BrowserTlsDecision::EnforceDane { record_count } => {
            tls.dnssec_secure
                && record_count.get() == tls.tlsa_records.len()
                && !tls.tlsa_records.is_empty()
        }
        BrowserTlsDecision::WebPkiAuthenticatedAbsence => {
            tls.dnssec_secure && tls.tlsa_records.is_empty()
        }
        BrowserTlsDecision::WebPkiInsecureDelegation => {
            !tls.dnssec_secure && tls.tlsa_records.is_empty()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(TransportError::InvalidRequest)
    }
}

fn append_hash_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in Sha256::digest(bytes) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn alpn_key(alpn_protocols: &[Vec<u8>]) -> String {
    alpn_protocols
        .iter()
        .map(|value| String::from_utf8_lossy(value).into_owned())
        .collect::<Vec<_>>()
        .join(",")
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_http_field_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || byte >= b' ' && byte != 0x7f)
}

fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'?' | b'#' | b'@' | b' '))
}

fn controlled_remaining<F>(deadline: Instant, is_cancelled: &F) -> Result<Duration, TransportError>
where
    F: Fn() -> bool + Sync,
{
    if is_cancelled() {
        return Err(TransportError::Io(CONTROLLED_IO_CANCELLED.to_owned()));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(controlled_deadline_error)
}

fn controlled_deadline_error() -> TransportError {
    TransportError::Io(CONTROLLED_IO_DEADLINE_EXCEEDED.to_owned())
}

fn apportioned_connect_timeout(
    remaining: Duration,
    remaining_candidates: usize,
    configured_timeout: Duration,
) -> Duration {
    let divisor = u32::try_from(remaining_candidates)
        .unwrap_or(u32::MAX)
        .max(1);
    let fair_share = remaining / divisor;
    fair_share
        .max(Duration::from_millis(1))
        .min(remaining)
        .min(configured_timeout)
}

fn bounded_candidate_indices(candidate_count: usize, start: usize) -> Vec<usize> {
    if candidate_count == 0 {
        return Vec::new();
    }
    let attempt_count = candidate_count.min(MAX_WEBPKI_ENDPOINT_ATTEMPTS_PER_OPEN);
    let start = start % candidate_count;
    (start..candidate_count)
        .chain(0..start)
        .take(attempt_count)
        .collect()
}

fn explicit_request_socket_addr(request: &OriginRequest) -> Result<SocketAddr, TransportError> {
    let address = request
        .connect_host
        .as_deref()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .ok_or(TransportError::InvalidRequest)?;
    Ok(SocketAddr::new(address, request.port))
}

fn io_error(error: std::io::Error) -> TransportError {
    TransportError::Io(error.to_string())
}

fn tls_error(error: RustlsError) -> TransportError {
    TransportError::Tls(error.to_string())
}

fn h2_error(error: h2::Error) -> TransportError {
    TransportError::Http2(error.to_string())
}

fn h3_connection_error(error: h3::error::ConnectionError) -> TransportError {
    TransportError::Http3(error.to_string())
}

fn h3_stream_error(error: h3::error::StreamError) -> TransportError {
    TransportError::Http3(error.to_string())
}

fn quic_error(error: impl std::fmt::Display) -> TransportError {
    TransportError::Quic(error.to_string())
}

fn tls_certificate_inspection(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    webpki_status: WebPkiStatus,
) -> Result<TlsCertificateInspection, RustlsError> {
    let end_entity_der = end_entity.as_ref().to_vec();
    let end_entity_spki_der = extract_spki_der(&end_entity_der).map_err(|error| {
        RustlsError::General(format!("TLS certificate inspection failed: {error}"))
    })?;
    let intermediate_der = intermediates
        .iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect();
    Ok(TlsCertificateInspection {
        end_entity_der,
        end_entity_spki_der,
        intermediate_der,
        webpki_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_dane::{TlsaMatching, TlsaSelector, TlsaUsage};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};
    use std::io::Read;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn fetches_http_origin_response() {
        let server = TestServer::start(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: yes\r\n\r\nok".to_vec(),
        );
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        let response = transport.fetch(&request(server.address)).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(response.dane_decision, DaneDecision::NoTlsa);
        let raw_request = server.request();
        assert!(raw_request.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(raw_request.contains("Host: example.com"));
        assert!(raw_request.contains("Connection: keep-alive"));
    }

    #[test]
    fn http_fetch_waits_longer_than_tunnel_idle_timeout() {
        let server = TestServer::start_delayed(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
            TUNNEL_IO_TIMEOUT + Duration::from_millis(150),
        );
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        let response = transport.fetch(&request(server.address)).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
    }

    #[test]
    fn webpki_passthrough_uses_only_the_explicit_selected_ip() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
        });
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(address);
        request.scheme = "https".to_owned();
        request.tls.dnssec_secure = true;
        request.tls.namespace_fingerprint = Some("selected-icann".to_owned());
        request.tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence);

        let mut tunnel = transport.open_webpki_passthrough(&request).unwrap();
        assert_eq!(tunnel.peer_addr, address);
        tunnel.writer.write_all(b"ping").unwrap();
        tunnel.writer.flush().unwrap();
        let mut response = [0_u8; 4];
        tunnel.reader.read_exact(&mut response).unwrap();

        assert_eq!(&response, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn webpki_passthrough_candidates_retry_connect_failure_and_report_actual_peer() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let _accepted = listener.accept().unwrap();
        });
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut unavailable = request(address);
        unavailable.scheme = "https".to_owned();
        unavailable.connect_host = Some(Ipv4Addr::new(127, 0, 0, 2).to_string());
        unavailable.tls.dnssec_secure = true;
        unavailable.tls.namespace_fingerprint = Some("selected-icann".to_owned());
        unavailable.tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence);
        let mut available = unavailable.clone();
        available.connect_host = Some(Ipv4Addr::LOCALHOST.to_string());

        let selected = transport
            .open_webpki_passthrough_candidates(&[unavailable, available])
            .unwrap();

        assert_eq!(selected.transport.peer_addr, address);
        drop(selected.transport);
        server.join().unwrap();
    }

    #[test]
    fn webpki_candidate_rotation_advances_when_the_whole_plan_fits_one_batch() {
        use std::sync::atomic::AtomicUsize;

        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let _accepted = listener.accept().unwrap();
            }
        });
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut unavailable = request(address);
        unavailable.scheme = "https".to_owned();
        unavailable.connect_host = Some(Ipv4Addr::new(127, 0, 0, 2).to_string());
        unavailable.tls.dnssec_secure = true;
        unavailable.tls.namespace_fingerprint = Some("selected-icann".to_owned());
        unavailable.tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence);
        let mut available = unavailable.clone();
        available.connect_host = Some(Ipv4Addr::LOCALHOST.to_string());
        let candidates = [unavailable, available];

        let first_guard_calls = AtomicUsize::new(0);
        let mut first_guard = || {
            first_guard_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        };
        let first = transport
            .open_webpki_passthrough_candidates_with_guard(&candidates, &mut first_guard)
            .unwrap();
        assert_eq!(first.transport.peer_addr, address);
        assert_eq!(first_guard_calls.load(Ordering::Acquire), 2);
        drop(first.transport);

        let second_guard_calls = AtomicUsize::new(0);
        let mut second_guard = || {
            second_guard_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        };
        let second = transport
            .open_webpki_passthrough_candidates_with_guard(&candidates, &mut second_guard)
            .unwrap();
        assert_eq!(second.transport.peer_addr, address);
        assert_eq!(
            second_guard_calls.load(Ordering::Acquire),
            1,
            "the next open must rotate directly to the previously viable endpoint"
        );
        drop(second.transport);
        server.join().unwrap();
    }

    #[test]
    fn webpki_candidate_budget_rotates_bounded_batches_with_viable_timeouts() {
        let configured = Duration::from_secs(10);
        assert_eq!(bounded_candidate_indices(32, 0), (0..8).collect::<Vec<_>>());
        assert_eq!(
            bounded_candidate_indices(32, 8),
            (8..16).collect::<Vec<_>>()
        );
        assert_eq!(
            bounded_candidate_indices(32, 24),
            (24..32).collect::<Vec<_>>()
        );
        assert_eq!(
            bounded_candidate_indices(32, 32),
            (0..8).collect::<Vec<_>>()
        );

        let mut remaining = configured;
        for remaining_candidates in (1..=MAX_WEBPKI_ENDPOINT_ATTEMPTS_PER_OPEN).rev() {
            let attempt = apportioned_connect_timeout(remaining, remaining_candidates, configured);
            assert!(!attempt.is_zero());
            assert!(attempt <= remaining);
            remaining -= attempt;
        }

        assert!(remaining.is_zero());
        assert_eq!(
            apportioned_connect_timeout(
                configured,
                MAX_WEBPKI_ENDPOINT_ATTEMPTS_PER_OPEN,
                configured
            ),
            Duration::from_millis(1_250)
        );
    }

    #[test]
    fn webpki_candidate_guard_stops_before_the_next_dial_after_revocation() {
        use std::sync::atomic::AtomicUsize;

        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut unavailable = request(address);
        unavailable.scheme = "https".to_owned();
        unavailable.connect_host = Some(Ipv4Addr::new(127, 0, 0, 2).to_string());
        unavailable.tls.dnssec_secure = true;
        unavailable.tls.namespace_fingerprint = Some("selected-icann".to_owned());
        unavailable.tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence);
        let mut available = unavailable.clone();
        available.connect_host = Some(Ipv4Addr::LOCALHOST.to_string());
        let guard_calls = AtomicUsize::new(0);
        let mut authority_guard = || {
            if guard_calls.fetch_add(1, Ordering::AcqRel) == 0 {
                Ok(())
            } else {
                Err(TransportError::Io(
                    "canonical browser authority revoked in-flight work".to_owned(),
                ))
            }
        };

        let failure = transport
            .open_webpki_passthrough_candidates_with_guard(
                &[unavailable, available],
                &mut authority_guard,
            )
            .err()
            .expect("revoked authority must stop the retry batch");

        assert!(matches!(failure, TransportError::Io(_)));
        assert_eq!(guard_calls.load(Ordering::Acquire), 2);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            ErrorKind::WouldBlock,
            "the guarded second endpoint must never be dialed"
        );
    }

    #[test]
    fn webpki_retry_classification_excludes_post_connect_setup_io() {
        let connect = WebPkiPassthroughOpenError::Connect(TransportError::Io("connect".to_owned()));
        let setup = WebPkiPassthroughOpenError::Terminal(TransportError::Io("setup".to_owned()));

        assert!(connect.is_connect_failure());
        assert!(!setup.is_connect_failure());
    }

    #[test]
    fn webpki_passthrough_candidates_reject_non_equivalent_requests_before_connecting() {
        let transport = TcpHttpTransport::default();
        let mut first = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        first.scheme = "https".to_owned();
        first.tls.dnssec_secure = true;
        first.tls.namespace_fingerprint = Some("selected-icann".to_owned());
        first.tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence);
        let mut different_origin = first.clone();
        different_origin.host = "different.example".to_owned();

        assert!(matches!(
            transport.open_webpki_passthrough_candidates(&[first, different_origin]),
            Err(TransportError::InvalidRequest)
        ));
    }

    #[test]
    fn webpki_passthrough_rejects_dane_and_unresolved_endpoints() {
        let transport = TcpHttpTransport::default();
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        request.scheme = "https".to_owned();
        request.tls.dnssec_secure = true;
        request.tls.namespace_fingerprint = Some("selected-icann".to_owned());
        request.tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence);

        request.connect_host = Some("example.com".to_owned());
        assert!(matches!(
            transport.open_webpki_passthrough(&request),
            Err(TransportError::InvalidRequest)
        ));

        request.connect_host = Some(Ipv4Addr::LOCALHOST.to_string());
        request.tls.tlsa_records.push(TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Sha256,
            association_data: vec![0_u8; 32],
        });
        request.tls.browser_tls_decision = Some(BrowserTlsDecision::EnforceDane {
            record_count: std::num::NonZeroUsize::new(1).unwrap(),
        });
        assert!(matches!(
            transport.open_webpki_passthrough(&request),
            Err(TransportError::InvalidRequest)
        ));
    }

    #[test]
    fn controlled_http11_enforces_one_deadline_across_a_slow_drip_body() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _request = read_test_http_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 256\r\n\r\n")
                .unwrap();
            for _ in 0..256 {
                if stream.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(5),
            TransportLimits::default(),
        );
        let started = Instant::now();

        let error = transport
            .fetch_http11_with_control(
                &request(address),
                started + Duration::from_millis(100),
                Duration::from_millis(10),
                || false,
            )
            .unwrap_err();

        assert_eq!(
            error,
            TransportError::Io(CONTROLLED_IO_DEADLINE_EXCEEDED.to_owned())
        );
        assert!(started.elapsed() < Duration::from_millis(750));
        server.join().unwrap();
    }

    #[test]
    fn controlled_http11_cancellation_interrupts_an_idle_response_read() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let (request_seen_tx, request_seen_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _request = read_test_http_head(&mut stream);
            request_seen_tx.send(()).unwrap();
            let _result = release_rx.recv_timeout(Duration::from_secs(2));
        });
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = Arc::clone(&cancelled);
        let canceller = thread::spawn(move || {
            request_seen_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
            thread::sleep(Duration::from_millis(50));
            cancellation.store(true, Ordering::Release);
        });
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(5),
            TransportLimits::default(),
        );
        let started = Instant::now();

        let error = transport
            .fetch_http11_with_control(
                &request(address),
                started + Duration::from_secs(2),
                Duration::from_millis(10),
                move || cancelled.load(Ordering::Acquire),
            )
            .unwrap_err();

        assert_eq!(
            error,
            TransportError::Io(CONTROLLED_IO_CANCELLED.to_owned())
        );
        assert!(started.elapsed() < Duration::from_millis(750));
        let _result = release_tx.send(());
        canceller.join().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn decodes_chunked_response_body() {
        let server = TestServer::start(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n".to_vec(),
        );
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        let response = transport.fetch(&request(server.address)).unwrap();

        assert_eq!(response.body, b"ok");
    }

    #[test]
    fn consumes_informational_responses_before_final_response() {
        let server = TestServer::start(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                .to_vec(),
        );
        let transport = TcpHttpTransport::default();

        let response = transport.fetch(&request(server.address)).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
    }

    #[test]
    fn rejects_trailers_exceeding_remaining_header_budget() {
        let server = TestServer::start(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Long: 123456789012345678901234567890\r\n\r\n"
                .to_vec(),
        );
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits {
                max_response_header_bytes: 64,
                ..TransportLimits::default()
            },
        );

        assert_eq!(
            transport.fetch(&request(server.address)).unwrap_err(),
            TransportError::ResponseTooLarge
        );
    }

    #[test]
    fn streams_response_body_to_writer() {
        let body = vec![b'a'; 128 * 1024];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Test: streamed\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend(&body);
        let server = TestServer::start(response);
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits {
                max_response_body_bytes: body.len(),
                ..TransportLimits::default()
            },
        );
        let mut streamed = Vec::new();

        let head = transport
            .fetch_to_writer(&request(server.address), &mut streamed)
            .unwrap();

        assert_eq!(head.status, 200);
        assert_eq!(head.body_len, body.len());
        assert_eq!(
            head.headers,
            vec![
                ("Content-Length".to_owned(), body.len().to_string()),
                ("X-Test".to_owned(), "streamed".to_owned())
            ]
        );
        assert_eq!(streamed, body);
    }

    #[test]
    fn reuses_http11_origin_connection() {
        let server = PersistentHttp11Server::start(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo".to_vec(),
        ]);
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        let first = transport.fetch(&request(server.address)).unwrap();
        let second = transport.fetch(&request(server.address)).unwrap();

        assert_eq!(first.body, b"one");
        assert_eq!(second.body, b"two");
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("Connection: keep-alive\r\n"));
        assert!(requests[1].contains("Connection: keep-alive\r\n"));
    }

    #[test]
    fn does_not_retry_a_partial_response_from_a_pooled_connection() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let (retry_tx, retry_rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_test_http_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
            stream.flush().unwrap();

            let _ = read_test_http_head(&mut stream);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n4\r\ncd",
                )
                .unwrap();
            stream.flush().unwrap();
            drop(stream);

            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_millis(400);
            let mut retried = false;
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((_stream, _)) => {
                        retried = true;
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("retry listener failed: {error}"),
                }
            }
            retry_tx.send(retried).unwrap();
        });
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        assert_eq!(transport.fetch(&request(address)).unwrap().body, b"ok");
        let mut streamed = Vec::new();
        assert!(
            transport
                .fetch_to_writer(&request(address), &mut streamed)
                .is_err()
        );

        assert_eq!(streamed, b"ab");
        assert!(!retry_rx.recv_timeout(Duration::from_secs(1)).unwrap());
    }

    #[test]
    fn does_not_replay_an_unsafe_method_after_a_stale_pooled_connection() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let (retry_tx, retry_rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_test_http_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
            stream.flush().unwrap();
            drop(stream);

            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_millis(400);
            let mut retried = false;
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((_stream, _)) => {
                        retried = true;
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("retry listener failed: {error}"),
                }
            }
            retry_tx.send(retried).unwrap();
        });
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        assert_eq!(transport.fetch(&request(address)).unwrap().body, b"ok");
        let mut post = request(address);
        post.method = "POST".to_owned();
        post.body = b"state change".to_vec();
        assert!(transport.fetch(&post).is_err());

        assert!(!retry_rx.recv_timeout(Duration::from_secs(1)).unwrap());
    }

    #[test]
    fn rfc8484_post_retries_once_after_a_stale_pooled_connection() {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
                .unwrap(),
        );
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let (first_closed_tx, first_closed_rx) = mpsc::channel();
        let (requests_tx, requests_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let connection = ServerConnection::new(Arc::clone(&config)).unwrap();
            let mut stream = StreamOwned::new(connection, stream);
            let first = read_test_http_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
            stream.flush().unwrap();
            drop(stream);
            first_closed_tx.send(()).unwrap();

            let (stream, _) = listener.accept().unwrap();
            let connection = ServerConnection::new(config).unwrap();
            let mut stream = StreamOwned::new(connection, stream);
            let second = read_test_http_request(&mut stream);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfresh",
                )
                .unwrap();
            stream.flush().unwrap();
            requests_tx.send(vec![first, second]).unwrap();
        });
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut dns_post = request(address);
        dns_post.method = "POST".to_owned();
        dns_post.scheme = "https".to_owned();
        dns_post.path_and_query = "/dns-query".to_owned();
        dns_post.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&cert_der)]);
        dns_post.headers = vec![
            ("Accept".to_owned(), DNS_MESSAGE_MEDIA_TYPE.to_owned()),
            ("Content-Type".to_owned(), DNS_MESSAGE_MEDIA_TYPE.to_owned()),
        ];
        dns_post.body = vec![0_u8; 12];

        assert_eq!(transport.fetch_rfc8484_post(&dns_post).unwrap().body, b"ok");
        first_closed_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            transport.fetch_rfc8484_post(&dns_post).unwrap().body,
            b"fresh"
        );

        let requests = requests_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| {
            String::from_utf8_lossy(request).starts_with("POST /dns-query HTTP/1.1\r\n")
        }));
        server.join().unwrap();
    }

    #[test]
    fn rfc8484_post_retry_api_rejects_generic_post() {
        let transport = TcpHttpTransport::default();
        let mut post = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        post.method = "POST".to_owned();
        post.scheme = "https".to_owned();
        post.body = vec![0_u8; 12];

        assert_eq!(
            transport.fetch_rfc8484_post(&post),
            Err(TransportError::InvalidRequest)
        );
    }

    #[test]
    fn promotes_https_same_port_alt_svc_to_http2() {
        let server = TlsTestServer::start_alt_svc_h2();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&server.cert_der)]);

        let first = transport.fetch(&request).unwrap();
        let second = transport.fetch(&request).unwrap();

        assert_eq!(first.body, b"h1");
        assert_eq!(second.body, b"h2");
        let requests = server.requests(2);
        assert!(requests[0].starts_with("h1 GET /path?q=1 HTTP/1.1"));
        assert!(requests[1].starts_with("h2 GET https://example.com:"));
        assert!(requests[1].ends_with("/path?q=1"));
    }

    #[test]
    fn does_not_promote_unsafe_method_from_alt_svc() {
        let transport = TcpHttpTransport::default();
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        request.scheme = "https".to_owned();

        transport.record_alt_svc(
            &request,
            &[("Alt-Svc".to_owned(), "h2=\":443\"; ma=60".to_owned())],
        );
        assert_eq!(
            transport.promoted_request(&request).protocol,
            OriginProtocol::Http2
        );

        request.method = "POST".to_owned();
        request.body = b"dns query".to_vec();

        assert_eq!(
            transport.promoted_request(&request).protocol,
            OriginProtocol::Http11
        );
    }

    #[test]
    fn namespace_fingerprint_isolates_alt_svc_and_tls_reuse_keys() {
        let transport = TcpHttpTransport::default();
        let mut hns_request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        hns_request.scheme = "https".to_owned();
        hns_request.tls.namespace_fingerprint = Some("hns-plan".to_owned());

        transport.record_alt_svc(
            &hns_request,
            &[("Alt-Svc".to_owned(), "h2=\":443\"; ma=60".to_owned())],
        );
        assert_eq!(
            transport.promoted_request(&hns_request).protocol,
            OriginProtocol::Http2
        );

        let mut icann_request = hns_request.clone();
        icann_request.tls.namespace_fingerprint = Some("icann-plan".to_owned());
        assert_eq!(
            transport.promoted_request(&icann_request).protocol,
            OriginProtocol::Http11
        );
        assert_ne!(
            transport.http11_pool_key(&hns_request),
            transport.http11_pool_key(&icann_request)
        );
        assert_ne!(
            tls_validation_key(&hns_request.tls),
            tls_validation_key(&icann_request.tls)
        );
    }

    #[test]
    fn namespace_plan_never_promotes_tcp_tlsa_to_http3_udp() {
        let transport = TcpHttpTransport::default();
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        request.scheme = "https".to_owned();
        request.tls.namespace_fingerprint = Some("selected-tcp-plan".to_owned());
        request.tls.service_transport = TlsaTransport::Tcp;

        transport.record_alt_svc(
            &request,
            &[("Alt-Svc".to_owned(), "h3=\":443\"; ma=60".to_owned())],
        );

        let promoted = transport.promoted_request(&request);
        assert_eq!(promoted.protocol, OriginProtocol::Http11);
        assert_eq!(promoted.tls.service_transport, TlsaTransport::Tcp);
    }

    #[test]
    fn falls_back_to_original_https_protocol_when_alt_svc_promotion_fails_before_body() {
        let server = TlsTestServer::start_alt_svc_h2_then_close_then_h1();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&server.cert_der)]);

        let first = transport.fetch(&request).unwrap();
        let mut streamed = Vec::new();
        let second = transport.fetch_to_writer(&request, &mut streamed).unwrap();

        assert_eq!(first.body, b"h1");
        assert_eq!(second.status, 200);
        assert_eq!(second.body_len, 2);
        assert_eq!(streamed, b"fb");
        let requests = server.requests(2);
        assert!(requests[0].starts_with("h1 GET /path?q=1 HTTP/1.1"));
        assert!(requests[1].starts_with("fallback GET /path?q=1 HTTP/1.1"));
    }

    #[test]
    fn opens_http11_upgrade_tunnel_and_preserves_stream_bytes() {
        let server = UpgradeTestServer::start();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.headers.extend([
            ("Connection".to_owned(), "Upgrade".to_owned()),
            ("Upgrade".to_owned(), "websocket".to_owned()),
            (
                "Sec-WebSocket-Key".to_owned(),
                "dGhlIHNhbXBsZSBub25jZQ==".to_owned(),
            ),
            ("Sec-WebSocket-Version".to_owned(), "13".to_owned()),
        ]);

        let mut tunnel = transport.open_tunnel(&request).unwrap();
        tunnel.stream.write_all(b"ping").unwrap();
        tunnel.stream.flush().unwrap();
        let mut echoed = [0u8; 4];
        tunnel.stream.read_exact(&mut echoed).unwrap();

        assert!(tunnel.response_head.starts_with(b"HTTP/1.1 101 "));
        assert_eq!(&echoed, b"ping");
        let raw_request = server.request();
        assert!(raw_request.contains("Connection: Upgrade\r\n"));
        assert!(raw_request.contains("Upgrade: websocket\r\n"));
    }

    #[test]
    fn live_tls_tunnel_dane_association_mismatch_is_typed() {
        let server = TlsTestServer::start();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "wss".to_owned();
        request.headers.extend([
            ("Connection".to_owned(), "Upgrade".to_owned()),
            ("Upgrade".to_owned(), "websocket".to_owned()),
            (
                "Sec-WebSocket-Key".to_owned(),
                "dGhlIHNhbXBsZSBub25jZQ==".to_owned(),
            ),
            ("Sec-WebSocket-Version".to_owned(), "13".to_owned()),
        ]);
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_mismatch(&server.cert_der)]);

        match transport.open_tunnel(&request) {
            Err(error) => assert_eq!(error, TransportError::DaneFailed),
            Ok(_) => panic!("mismatched DANE association must reject the TLS tunnel"),
        }
    }

    #[test]
    fn rejects_unsupported_transfer_encoded_response() {
        let server =
            TestServer::start(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nabc".to_vec());
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        assert_eq!(
            transport.fetch(&request(server.address)).unwrap_err(),
            TransportError::UnsupportedTransferEncoding,
        );
    }

    #[test]
    fn rejects_ambiguous_transfer_encoding_and_content_length() {
        let server = TestServer::start(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\nok\r\n0\r\n\r\n".to_vec(),
        );
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );

        assert_eq!(
            transport.fetch(&request(server.address)).unwrap_err(),
            TransportError::MalformedResponse,
        );
    }

    #[test]
    fn head_response_never_reads_message_body() {
        let server = TestServer::start(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec());
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.method = "HEAD".to_owned();

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert!(response.body.is_empty());
    }

    #[test]
    fn rewrites_request_content_length_from_body() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request.body = b"hi".to_vec();
        request
            .headers
            .push(("Content-Length".to_owned(), "999".to_owned()));

        let bytes = build_http_request(&request, false).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text.matches("Content-Length:").count(), 1);
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(!text.contains("Content-Length: 999\r\n"));
        assert!(text.ends_with("\r\n\r\nhi"));
    }

    #[test]
    fn rewrites_http2_request_content_length_from_body() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        request.scheme = "https".to_owned();
        request.body = b"hi".to_vec();
        request
            .headers
            .push(("Content-Length".to_owned(), "999".to_owned()));

        let h2_request = build_http2_request(&request).unwrap();
        let content_lengths = h2_request
            .headers()
            .get_all("content-length")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(content_lengths, vec!["2"]);
    }

    #[test]
    fn omits_http2_content_length_for_empty_body() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        request.scheme = "https".to_owned();
        request
            .headers
            .push(("Content-Length".to_owned(), "999".to_owned()));

        let h2_request = build_http2_request(&request).unwrap();

        assert!(!h2_request.headers().contains_key("content-length"));
    }

    #[test]
    fn forwards_range_request_header_to_origin() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request
            .headers
            .push(("Range".to_owned(), "bytes=10-19".to_owned()));
        request
            .headers
            .push(("If-Range".to_owned(), "\"abc\"".to_owned()));

        let text = String::from_utf8(build_http_request(&request, false).unwrap()).unwrap();

        assert!(text.contains("Range: bytes=10-19\r\n"));
        assert!(text.contains("If-Range: \"abc\"\r\n"));
    }

    #[test]
    fn caller_accept_header_replaces_default_http11_accept() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request
            .headers
            .push(("Accept".to_owned(), "application/dns-message".to_owned()));

        let text = String::from_utf8(build_http_request(&request, false).unwrap()).unwrap();

        assert_eq!(text.matches("Accept:").count(), 1);
        assert!(text.contains("Accept: application/dns-message\r\n"));
        assert!(!text.contains("Accept: */*\r\n"));
    }

    #[test]
    fn caller_accept_header_replaces_default_http2_accept() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request.scheme = "https".to_owned();
        request.port = 443;
        request.connect_host = None;
        request
            .headers
            .push(("Accept".to_owned(), "application/dns-message".to_owned()));

        let h2_request = build_http2_request(&request).unwrap();
        let accept_values = h2_request
            .headers()
            .get_all("accept")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(accept_values, vec!["application/dns-message"]);
    }

    #[test]
    fn caller_user_agent_replaces_transport_default() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request
            .headers
            .push(("User-Agent".to_owned(), "Browser-UA/1".to_owned()));

        let http11 = String::from_utf8(build_http_request(&request, false).unwrap()).unwrap();
        assert_eq!(http11.matches("User-Agent:").count(), 1);
        assert!(http11.contains("User-Agent: Browser-UA/1\r\n"));
        assert!(!http11.contains("User-Agent: hns-dane-browser/"));

        request.scheme = "https".to_owned();
        request.port = 443;
        let http2 = build_http2_request(&request).unwrap();
        let user_agents = http2
            .headers()
            .get_all("user-agent")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(user_agents, vec!["Browser-UA/1"]);
    }

    #[test]
    fn strips_fields_nominated_by_connection_header() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request.headers.extend([
            ("Connection".to_owned(), "close, X-Internal".to_owned()),
            ("X-Internal".to_owned(), "secret".to_owned()),
            ("X-End-To-End".to_owned(), "visible".to_owned()),
        ]);

        let http11 = String::from_utf8(build_http_request(&request, false).unwrap()).unwrap();
        assert!(!http11.contains("X-Internal:"));
        assert!(http11.contains("X-End-To-End: visible\r\n"));

        request.scheme = "https".to_owned();
        request.port = 443;
        let http2 = build_http2_request(&request).unwrap();
        assert!(!http2.headers().contains_key("x-internal"));
        assert_eq!(http2.headers()["x-end-to-end"], "visible");
    }

    #[test]
    fn upgrade_keeps_required_headers_but_strips_other_nominated_fields() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request.headers.extend([
            ("Connection".to_owned(), "Upgrade, X-Internal".to_owned()),
            ("Upgrade".to_owned(), "websocket".to_owned()),
            ("X-Internal".to_owned(), "secret".to_owned()),
        ]);

        let text = String::from_utf8(build_http_upgrade_request(&request).unwrap()).unwrap();
        assert!(text.contains("Connection: Upgrade, X-Internal\r\n"));
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(!text.contains("X-Internal: secret\r\n"));
    }

    #[test]
    fn rejects_malformed_connection_header_tokens() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request
            .headers
            .push(("Connection".to_owned(), "close, bad token".to_owned()));

        assert_eq!(
            validate_request(&request, TransportLimits::default()).unwrap_err(),
            TransportError::InvalidRequest,
        );
    }

    #[test]
    fn rejects_protocol_upgrade_before_stripping_hop_by_hop_headers() {
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        request
            .headers
            .push(("Connection".to_owned(), "keep-alive, Upgrade".to_owned()));
        request
            .headers
            .push(("Upgrade".to_owned(), "websocket".to_owned()));

        assert_eq!(
            validate_request(&request, TransportLimits::default()).unwrap_err(),
            TransportError::UnsupportedUpgrade,
        );
    }

    #[test]
    fn rejects_oversized_response_body() {
        let server = TestServer::start(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec());
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits {
                max_response_body_bytes: 2,
                ..TransportLimits::default()
            },
        );

        assert_eq!(
            transport.fetch(&request(server.address)).unwrap_err(),
            TransportError::ResponseTooLarge,
        );
    }

    #[test]
    fn fetches_https_with_webpki_fallback() {
        let server = TlsTestServer::start();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(server.cert_der.clone()))
            .unwrap();
        let transport = TcpHttpTransport::with_root_store(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
            roots,
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(response.dane_decision, DaneDecision::WebPkiFallback);
        assert!(server.request().starts_with("GET /path?q=1 HTTP/1.1\r\n"));
    }

    #[test]
    fn enabled_stateless_dane_without_certificate_evidence_fails_closed() {
        let server = TlsTestServer::start();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(server.cert_der.clone()))
            .unwrap();
        let transport = TcpHttpTransport::with_root_store(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
            roots,
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(false, Vec::new());
        request.tls.stateless_dane = StatelessDaneConfig {
            enabled: true,
            accepted_tree_roots: vec![[0x42; 32]],
        };

        let error = transport.fetch(&request).unwrap_err();

        assert!(matches!(
            error,
            TransportError::Io(message)
                if message.contains("strict HNS mode requires DNSSEC-secure TLSA")
        ));
    }

    #[test]
    fn accepted_stateless_tlsa_match_has_stateless_provenance() {
        let evidence = StatelessDaneEvidence::Tlsa {
            records: vec![TlsaRecord {
                usage: TlsaUsage::DaneEe,
                selector: TlsaSelector::FullCertificate,
                matching: TlsaMatching::Exact,
                association_data: b"cert".to_vec(),
            }],
            proof_root: [0x42; 32],
            proof_height: None,
        };
        let StatelessDaneEvidence::Tlsa { records, .. } = &evidence else {
            unreachable!();
        };
        let decision =
            evaluate_policy_with_certificate_chain(DaneCertificateChainValidationInput {
                mode: DomainTrustMode::HnsStrict,
                dnssec_secure: true,
                tlsa_records: records,
                end_entity_der: b"cert",
                intermediate_der: &[],
                webpki_status: WebPkiStatus::Invalid,
            })
            .unwrap();

        assert_eq!(
            with_stateless_dane_provenance(decision, Some(&evidence)),
            DaneDecision::StatelessMatched(TlsaUsage::DaneEe),
        );
        assert_eq!(
            with_stateless_dane_provenance(
                DaneDecision::Matched(TlsaUsage::DaneEe),
                Some(&StatelessDaneEvidence::Missing),
            ),
            DaneDecision::Matched(TlsaUsage::DaneEe),
        );
        assert_eq!(
            with_stateless_dane_provenance(DaneDecision::Failed, Some(&evidence)),
            DaneDecision::Failed,
        );
    }

    #[test]
    fn fetches_https_with_dnssec_tlsa_match() {
        let server = TlsTestServer::start();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&server.cert_der)]);

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(
            response.dane_decision,
            DaneDecision::Matched(TlsaUsage::DaneEe)
        );
        let inspection = response.tls_inspection.expect("TLS inspection");
        assert_eq!(inspection.end_entity_der, server.cert_der);
        assert_eq!(
            inspection.end_entity_spki_der,
            extract_spki_der(&inspection.end_entity_der).unwrap(),
        );
        assert_eq!(inspection.intermediate_der.len(), 0);
        assert_eq!(inspection.webpki_status, WebPkiStatus::Invalid);
    }

    #[test]
    fn live_http11_dane_association_mismatch_is_typed() {
        let server = TlsTestServer::start();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_mismatch(&server.cert_der)]);

        assert_eq!(
            transport.fetch(&request).unwrap_err(),
            TransportError::DaneFailed
        );
    }

    #[test]
    fn live_controlled_http11_dane_association_mismatch_is_typed() {
        let server = TlsTestServer::start();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_mismatch(&server.cert_der)]);

        assert_eq!(
            transport
                .fetch_http11_with_control(
                    &request,
                    Instant::now() + Duration::from_secs(1),
                    Duration::from_millis(10),
                    || false,
                )
                .unwrap_err(),
            TransportError::DaneFailed
        );
    }

    #[test]
    fn fetches_https_http2_with_dnssec_tlsa_match() {
        let server = TlsTestServer::start_h2();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.protocol = OriginProtocol::Http2;
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&server.cert_der)]);

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(
            response.dane_decision,
            DaneDecision::Matched(TlsaUsage::DaneEe),
        );
        let request_text = server.request();
        assert!(request_text.starts_with("GET https://example.com:"));
        assert!(request_text.ends_with("/path?q=1"));
    }

    #[test]
    fn live_http2_dane_association_mismatch_is_typed() {
        let server = TlsTestServer::start_h2();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.protocol = OriginProtocol::Http2;
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_mismatch(&server.cert_der)]);

        assert_eq!(
            transport.fetch(&request).unwrap_err(),
            TransportError::DaneFailed
        );
    }

    #[test]
    fn fetches_single_label_hns_http2_with_proof_spki_sha256() {
        let server = TlsTestServer::start_h2();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let spki = hns_dane::extract_spki_der(&server.cert_der).unwrap();
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.host = "denuoweb".to_owned();
        request.protocol = OriginProtocol::Http2;
        request.tls = TlsValidation::hns_strict(
            true,
            vec![TlsaRecord {
                usage: TlsaUsage::DaneEe,
                selector: TlsaSelector::SubjectPublicKeyInfo,
                matching: TlsaMatching::Sha256,
                association_data: Sha256::digest(spki).to_vec(),
            }],
        );

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(
            response.dane_decision,
            DaneDecision::Matched(TlsaUsage::DaneEe),
        );
        let request_text = server.request();
        assert!(request_text.starts_with("GET https://denuoweb:"));
        assert!(request_text.ends_with("/path?q=1"));
    }

    #[test]
    fn accepts_http2_head_content_length_without_response_data() {
        let server = TlsTestServer::start_h2();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.method = "HEAD".to_owned();
        request.scheme = "https".to_owned();
        request.protocol = OriginProtocol::Http2;
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&server.cert_der)]);

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert!(response.body.is_empty());
        assert!(server.request().starts_with("HEAD https://example.com:"));
    }

    #[test]
    fn fetches_https_http3_with_dnssec_tlsa_match() {
        let server = TlsTestServer::start_h3();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.protocol = OriginProtocol::Http3;
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&server.cert_der)]);

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert_eq!(
            response.dane_decision,
            DaneDecision::Matched(TlsaUsage::DaneEe),
        );
        let request_text = server.request();
        assert!(request_text.starts_with("GET https://example.com:"));
        assert!(request_text.ends_with("/path?q=1"));
    }

    #[test]
    fn live_http3_dane_association_mismatch_is_typed() {
        let server = TlsTestServer::start_h3();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.protocol = OriginProtocol::Http3;
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_mismatch(&server.cert_der)]);

        assert_eq!(
            transport.fetch(&request).unwrap_err(),
            TransportError::DaneFailed
        );
    }

    #[test]
    fn accepts_http3_head_content_length_without_response_data() {
        let server = TlsTestServer::start_h3();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(5),
            Duration::from_secs(5),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.method = "HEAD".to_owned();
        request.scheme = "https".to_owned();
        request.protocol = OriginProtocol::Http3;
        request.tls = TlsValidation::hns_strict(true, vec![tlsa_spki_exact(&server.cert_der)]);

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert!(response.body.is_empty());
        assert!(server.request().starts_with("HEAD https://example.com:"));
    }

    #[test]
    fn fetches_https_with_dane_ta_intermediate_match() {
        let server = TlsTestServer::start_with_intermediate();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(
            true,
            vec![tlsa_spki_exact_with_usage(
                server.intermediate_cert_der.as_ref().unwrap(),
                TlsaUsage::DaneTa,
            )],
        );

        let response = transport.fetch(&request).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(
            response.dane_decision,
            DaneDecision::Matched(TlsaUsage::DaneTa)
        );
        let inspection = response.tls_inspection.expect("TLS inspection");
        assert_eq!(inspection.end_entity_der, server.cert_der);
        assert_eq!(inspection.intermediate_der.len(), 1);
        assert_eq!(
            inspection.intermediate_der[0],
            *server.intermediate_cert_der.as_ref().unwrap(),
        );
    }

    #[test]
    fn rejects_insecure_tlsa_https() {
        let server = TlsTestServer::start();
        let transport = TcpHttpTransport::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            TransportLimits::default(),
        );
        let mut request = request(server.address);
        request.scheme = "https".to_owned();
        request.tls = TlsValidation::hns_strict(false, vec![tlsa_spki_exact(&server.cert_der)]);
        let error = transport.fetch(&request).unwrap_err();

        assert!(
            matches!(error, TransportError::Io(_) | TransportError::Tls(_)),
            "{error:?}",
        );
    }

    #[test]
    fn rejects_invalid_https_server_name() {
        let transport = TcpHttpTransport::default();
        let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)));
        request.scheme = "https".to_owned();
        request.host = "bad host".to_owned();

        assert_eq!(
            transport.fetch(&request).unwrap_err(),
            TransportError::InvalidRequest,
        );
    }

    #[test]
    fn rejects_invalid_request_header() {
        let transport = TcpHttpTransport::default();
        let mut invalid_name_request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
        invalid_name_request
            .headers
            .push(("Bad\r\nHeader".to_owned(), "x".to_owned()));

        assert_eq!(
            transport.fetch(&invalid_name_request).unwrap_err(),
            TransportError::InvalidRequest,
        );

        for value in ["safe\0smuggled", "safe\u{7f}smuggled", "safe\u{1f}smuggled"] {
            let mut request = request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)));
            request
                .headers
                .push(("X-Test".to_owned(), value.to_owned()));
            assert_eq!(
                transport.fetch(&request).unwrap_err(),
                TransportError::InvalidRequest,
            );
        }
    }

    #[test]
    fn rejects_invalid_http11_response_header_value() {
        let server = TestServer::start(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: bad\0value\r\n\r\nok".to_vec(),
        );
        let transport = TcpHttpTransport::default();

        assert_eq!(
            transport.fetch(&request(server.address)).unwrap_err(),
            TransportError::MalformedResponse,
        );
    }

    #[test]
    fn enforces_decoded_http2_header_section_limit() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-test", HeaderValue::from_static("12345678"));

        assert_eq!(
            http2_response_headers(&headers, 45).unwrap_err(),
            TransportError::ResponseTooLarge,
        );
        assert_eq!(http2_response_headers(&headers, 46).unwrap().len(), 1);
    }

    #[test]
    fn fail_closed_transport_rejects_fetch() {
        assert_eq!(
            FailClosedTransport.fetch(&request(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)))),
            Err(TransportError::UnsupportedTransport),
        );
    }

    #[test]
    fn tls_policy_cache_key_uses_collision_resistant_policy_digest() {
        let first = TlsValidation::hns_strict(
            true,
            vec![TlsaRecord {
                usage: TlsaUsage::DaneEe,
                selector: TlsaSelector::SubjectPublicKeyInfo,
                matching: TlsaMatching::Exact,
                association_data: b"first association".to_vec(),
            }],
        );
        let second = TlsValidation::hns_strict(
            true,
            vec![TlsaRecord {
                association_data: b"second association".to_vec(),
                ..first.tlsa_records[0].clone()
            }],
        );

        let first_key = tls_validation_key(&first);
        let second_key = tls_validation_key(&second);
        let mut expected_digest = String::new();
        append_hash_hex(&mut expected_digest, b"first association");
        assert_ne!(first_key, second_key);
        assert!(first_key.contains(&expected_digest));
    }

    #[test]
    fn shared_icann_browser_decision_is_cache_bound_and_must_match_transport_evidence() {
        let mut absence = TlsValidation {
            browser_tls_decision: Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence),
            ..TlsValidation::default()
        };
        assert_eq!(
            validate_browser_tls_decision(&absence),
            Err(TransportError::InvalidRequest)
        );
        absence.dnssec_secure = true;
        assert_eq!(validate_browser_tls_decision(&absence), Ok(()));

        let absence_key = tls_validation_key(&absence);
        let insecure = TlsValidation {
            dnssec_secure: false,
            browser_tls_decision: Some(BrowserTlsDecision::WebPkiInsecureDelegation),
            ..TlsValidation::default()
        };
        assert_eq!(validate_browser_tls_decision(&insecure), Ok(()));
        assert_ne!(absence_key, tls_validation_key(&insecure));

        let mut inconsistent = insecure;
        inconsistent.dnssec_secure = true;
        assert_eq!(
            validate_browser_tls_decision(&inconsistent),
            Err(TransportError::InvalidRequest)
        );
        assert!(matches!(
            TcpHttpTransport::default().client_config(inconsistent, Vec::new()),
            Err(TransportError::InvalidRequest)
        ));
    }

    #[test]
    fn state_maps_are_evicted_at_capacity() {
        let mut map = HashMap::new();
        for value in 0..(MAX_TLS_POLICY_CACHE_ENTRIES + 10) {
            evict_one_if_at_capacity(&mut map, MAX_TLS_POLICY_CACHE_ENTRIES);
            map.insert(value, value);
        }
        assert_eq!(map.len(), MAX_TLS_POLICY_CACHE_ENTRIES);
    }

    fn request(address: SocketAddr) -> OriginRequest {
        OriginRequest {
            method: "GET".to_owned(),
            scheme: "http".to_owned(),
            host: "example.com".to_owned(),
            connect_host: Some(address.ip().to_string()),
            port: address.port(),
            path_and_query: "/path?q=1".to_owned(),
            protocol: OriginProtocol::Http11,
            tls: TlsValidation::default(),
            headers: vec![("Proxy-Connection".to_owned(), "keep-alive".to_owned())],
            body: Vec::new(),
        }
    }

    fn tlsa_spki_exact(cert_der: &[u8]) -> TlsaRecord {
        tlsa_spki_exact_with_usage(cert_der, TlsaUsage::DaneEe)
    }

    fn tlsa_spki_exact_with_usage(cert_der: &[u8], usage: TlsaUsage) -> TlsaRecord {
        TlsaRecord {
            usage,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Exact,
            association_data: hns_dane::extract_spki_der(cert_der).unwrap(),
        }
    }

    fn tlsa_spki_mismatch(cert_der: &[u8]) -> TlsaRecord {
        let mut record = tlsa_spki_exact(cert_der);
        record.association_data[0] ^= 0xff;
        record
    }

    struct TestServer {
        address: SocketAddr,
        request_rx: mpsc::Receiver<String>,
    }

    impl TestServer {
        fn start(response: Vec<u8>) -> Self {
            Self::start_delayed(response, Duration::ZERO)
        }

        fn start_delayed(response: Vec<u8>, delay: Duration) -> Self {
            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let address = listener.local_addr().unwrap();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend(&buffer[..read]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                request_tx
                    .send(String::from_utf8_lossy(&request).into_owned())
                    .unwrap();
                if !delay.is_zero() {
                    thread::sleep(delay);
                }
                stream.write_all(&response).unwrap();
            });

            Self {
                address,
                request_rx,
            }
        }

        fn request(self) -> String {
            self.request_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
        }
    }

    struct PersistentHttp11Server {
        address: SocketAddr,
        request_rx: mpsc::Receiver<String>,
        request_count: usize,
    }

    impl PersistentHttp11Server {
        fn start(responses: Vec<Vec<u8>>) -> Self {
            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let address = listener.local_addr().unwrap();
            let request_count = responses.len();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                for response in responses {
                    let request = read_test_http_head(&mut stream);
                    request_tx
                        .send(String::from_utf8_lossy(&request).into_owned())
                        .unwrap();
                    stream.write_all(&response).unwrap();
                    stream.flush().unwrap();
                }
            });

            Self {
                address,
                request_rx,
                request_count,
            }
        }

        fn requests(self) -> Vec<String> {
            (0..self.request_count)
                .map(|_| {
                    self.request_rx
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap()
                })
                .collect()
        }
    }

    struct UpgradeTestServer {
        address: SocketAddr,
        request_rx: mpsc::Receiver<String>,
    }

    impl UpgradeTestServer {
        fn start() -> Self {
            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let address = listener.local_addr().unwrap();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_test_http_head(&mut stream);
                request_tx
                    .send(String::from_utf8_lossy(&request).into_owned())
                    .unwrap();
                stream
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                    )
                    .unwrap();
                stream.flush().unwrap();
                let mut payload = [0u8; 4];
                stream.read_exact(&mut payload).unwrap();
                stream.write_all(&payload).unwrap();
                stream.flush().unwrap();
            });

            Self {
                address,
                request_rx,
            }
        }

        fn request(self) -> String {
            self.request_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
        }
    }

    fn read_test_http_head(stream: &mut impl Read) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend(&buffer[..read]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        request
    }

    fn read_test_http_request(stream: &mut impl Read) -> Vec<u8> {
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&request);
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let current = request.len();
        request.resize(current + content_length, 0);
        stream.read_exact(&mut request[current..]).unwrap();
        request
    }

    struct TlsTestServer {
        address: SocketAddr,
        cert_der: Vec<u8>,
        intermediate_cert_der: Option<Vec<u8>>,
        request_rx: mpsc::Receiver<String>,
    }

    impl TlsTestServer {
        fn start() -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
            let cert_der = cert.der().to_vec();
            let key_der =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            Self::start_with_chain(vec![cert_der.clone()], key_der, cert_der, None)
        }

        fn start_h2() -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
            let cert_der = cert.der().to_vec();
            let key_der =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
            .unwrap();
            config.alpn_protocols = vec![b"h2".to_vec()];

            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    let (stream, _) = listener.accept().await.unwrap();
                    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut connection = h2::server::handshake(stream).await.unwrap();
                    if let Some(request) = connection.accept().await {
                        let (request, mut respond) = request.unwrap();
                        let is_head = request.method() == http::Method::HEAD;
                        request_tx
                            .send(format!("{} {}", request.method(), request.uri()))
                            .unwrap();
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-length", "2")
                            .header("x-test", "h2")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(response, is_head).unwrap();
                        if !is_head {
                            send.send_data(Bytes::from_static(b"ok"), true).unwrap();
                        }
                        connection.graceful_shutdown();
                        let _ =
                            tokio::time::timeout(Duration::from_millis(100), connection.accept())
                                .await;
                    }
                });
            });

            Self {
                address,
                cert_der,
                intermediate_cert_der: None,
                request_rx,
            }
        }

        fn start_h3() -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
            let cert_der = cert.der().to_vec();
            let key_der =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
            .unwrap();
            config.alpn_protocols = vec![b"h3".to_vec()];

            let server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(config).unwrap(),
            ));
            let (address_tx, address_rx) = mpsc::channel();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let endpoint = quinn::Endpoint::server(
                        server_config,
                        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
                    )
                    .unwrap();
                    address_tx.send(endpoint.local_addr().unwrap()).unwrap();
                    let connecting = endpoint.accept().await.unwrap();
                    let Ok(connection) = connecting.await else {
                        return;
                    };
                    let quic = h3_quinn::Connection::new(connection);
                    let mut connection = h3::server::builder().build(quic).await.unwrap();
                    if let Some(request) = connection.accept().await.unwrap() {
                        let handler = tokio::spawn(async move {
                            let (request, mut stream) = request.resolve_request().await.unwrap();
                            let is_head = request.method() == http::Method::HEAD;
                            request_tx
                                .send(format!("{} {}", request.method(), request.uri()))
                                .unwrap();
                            let response = http::Response::builder()
                                .status(200)
                                .header("content-length", "2")
                                .header("x-test", "h3")
                                .body(())
                                .unwrap();
                            stream.send_response(response).await.unwrap();
                            if !is_head {
                                stream.send_data(Bytes::from_static(b"ok")).await.unwrap();
                            }
                            stream.finish().await.unwrap();
                        });
                        let _ = tokio::time::timeout(Duration::from_secs(1), async {
                            while let Ok(Some(_)) = connection.accept().await {
                                // Drive the connection while the spawned request handler writes.
                            }
                        })
                        .await;
                        handler.await.unwrap();
                    }
                });
            });
            let address = address_rx.recv_timeout(Duration::from_secs(1)).unwrap();

            Self {
                address,
                cert_der,
                intermediate_cert_der: None,
                request_rx,
            }
        }

        fn start_alt_svc_h2() -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
            let cert_der = cert.der().to_vec();
            let key_der =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
            .unwrap();
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let address = listener.local_addr().unwrap();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let config = Arc::new(config);
                let (stream, _) = listener.accept().unwrap();
                let connection = ServerConnection::new(Arc::clone(&config)).unwrap();
                let mut stream = StreamOwned::new(connection, stream);
                let request = read_test_http_head(&mut stream);
                request_tx
                    .send(format!("h1 {}", String::from_utf8_lossy(&request)))
                    .unwrap();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nAlt-Svc: h2=\":{}\"; ma=60\r\nConnection: close\r\n\r\nh1",
                            address.port()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                stream.flush().unwrap();

                let (stream, _) = listener.accept().unwrap();
                stream.set_nonblocking(true).unwrap();
                let acceptor = tokio_rustls::TlsAcceptor::from(config);
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let stream = tokio::net::TcpStream::from_std(stream).unwrap();
                    let stream = acceptor.accept(stream).await.unwrap();
                    let mut connection = h2::server::handshake(stream).await.unwrap();
                    if let Some(request) = connection.accept().await {
                        let (request, mut respond) = request.unwrap();
                        request_tx
                            .send(format!("h2 {} {}", request.method(), request.uri()))
                            .unwrap();
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-length", "2")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(response, false).unwrap();
                        send.send_data(Bytes::from_static(b"h2"), true).unwrap();
                        connection.graceful_shutdown();
                        let _ =
                            tokio::time::timeout(Duration::from_millis(100), connection.accept())
                                .await;
                    }
                });
            });

            Self {
                address,
                cert_der,
                intermediate_cert_der: None,
                request_rx,
            }
        }

        fn start_alt_svc_h2_then_close_then_h1() -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
            let cert_der = cert.der().to_vec();
            let key_der =
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            let mut config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key_der)
            .unwrap();
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let address = listener.local_addr().unwrap();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let config = Arc::new(config);
                {
                    let (stream, _) = listener.accept().unwrap();
                    let connection = ServerConnection::new(Arc::clone(&config)).unwrap();
                    let mut stream = StreamOwned::new(connection, stream);
                    let request = read_test_http_head(&mut stream);
                    request_tx
                        .send(format!("h1 {}", String::from_utf8_lossy(&request)))
                        .unwrap();
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nAlt-Svc: h2=\":{}\"; ma=60\r\nConnection: close\r\n\r\nh1",
                                address.port()
                            )
                            .as_bytes(),
                        )
                        .unwrap();
                    stream.flush().unwrap();
                }

                let (stream, _) = listener.accept().unwrap();
                drop(stream);

                {
                    let (stream, _) = listener.accept().unwrap();
                    let connection = ServerConnection::new(Arc::clone(&config)).unwrap();
                    let mut stream = StreamOwned::new(connection, stream);
                    let request = read_test_http_head(&mut stream);
                    request_tx
                        .send(format!("fallback {}", String::from_utf8_lossy(&request)))
                        .unwrap();
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nfb",
                        )
                        .unwrap();
                    stream.flush().unwrap();
                }
            });

            Self {
                address,
                cert_der,
                intermediate_cert_der: None,
                request_rx,
            }
        }

        fn start_with_intermediate() -> Self {
            let mut intermediate_params =
                rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            intermediate_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::DigitalSignature);
            intermediate_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::KeyCertSign);
            intermediate_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::CrlSign);
            let intermediate_key = rcgen::KeyPair::generate().unwrap();
            let intermediate =
                rcgen::CertifiedIssuer::self_signed(intermediate_params, intermediate_key).unwrap();
            let intermediate_cert_der = intermediate.der().to_vec();

            let mut leaf_params =
                rcgen::CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
            leaf_params.use_authority_key_identifier_extension = true;
            leaf_params
                .key_usages
                .push(rcgen::KeyUsagePurpose::DigitalSignature);
            leaf_params
                .extended_key_usages
                .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
            let leaf_key = rcgen::KeyPair::generate().unwrap();
            let leaf_cert = leaf_params.signed_by(&leaf_key, &intermediate).unwrap();
            let cert_der = leaf_cert.der().to_vec();
            let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

            Self::start_with_chain(
                vec![cert_der.clone(), intermediate_cert_der.clone()],
                key_der,
                cert_der,
                Some(intermediate_cert_der),
            )
        }

        fn start_with_chain(
            cert_chain_der: Vec<Vec<u8>>,
            key_der: PrivateKeyDer<'static>,
            cert_der: Vec<u8>,
            intermediate_cert_der: Option<Vec<u8>>,
        ) -> Self {
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                cert_chain_der
                    .into_iter()
                    .map(CertificateDer::from)
                    .collect(),
                key_der,
            )
            .unwrap();

            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let address = listener.local_addr().unwrap();
            let (request_tx, request_rx) = mpsc::channel();

            thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let connection = ServerConnection::new(Arc::new(config)).unwrap();
                let mut stream = StreamOwned::new(connection, stream);
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    request.extend(&buffer[..read]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = request_tx.send(String::from_utf8_lossy(&request).into_owned());
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = stream.flush();
            });

            Self {
                address,
                cert_der,
                intermediate_cert_der,
                request_rx,
            }
        }

        fn request(self) -> String {
            self.request_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
        }

        fn requests(self, count: usize) -> Vec<String> {
            (0..count)
                .map(|_| {
                    self.request_rx
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap()
                })
                .collect()
        }
    }
}
