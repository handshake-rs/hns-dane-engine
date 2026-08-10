//! Platform-neutral request boundary used by the loopback HTTP server.

use std::any::Any;
use std::fmt;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use thiserror::Error;

/// Cloneable cooperative cancellation shared by a running proxy and backend
/// work started for that proxy generation.
#[derive(Clone, Default)]
pub struct CancellationToken {
    inner: Arc<CancellationState>,
}

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    wait_lock: Mutex<()>,
    changed: Condvar,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels all clones. Returns `true` only for the first cancellation.
    pub(crate) fn cancel(&self) -> bool {
        // Synchronize with the condition-variable handoff so cancellation
        // cannot be notified in the gap between a waiter checking the atomic
        // flag and going to sleep.
        let _guard = self
            .inner
            .wait_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.inner.cancelled.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.inner.changed.notify_all();
        true
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Waits until cancellation or the timeout. Returns whether cancellation
    /// was observed.
    pub fn wait_cancelled_timeout(&self, timeout: Duration) -> bool {
        if self.is_cancelled() {
            return true;
        }
        let guard = self
            .inner
            .wait_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.is_cancelled() {
            return true;
        }
        let _guard = self
            .inner
            .changed
            .wait_timeout_while(guard, timeout, |_| !self.is_cancelled())
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.is_cancelled()
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProxyHeader {
    pub name: String,
    pub value: String,
}

impl ProxyHeader {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

impl fmt::Debug for ProxyHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyHeader(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ProxyRequestBody {
    Empty,
    Bytes(Vec<u8>),
}

impl ProxyRequestBody {
    pub fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Bytes(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Bytes(bytes) => bytes,
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::Bytes(bytes) => bytes,
        }
    }
}

impl fmt::Debug for ProxyRequestBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyRequestBody")
            .field("len", &self.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProxyRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub headers: Vec<ProxyHeader>,
    pub body: ProxyRequestBody,
}

impl fmt::Debug for ProxyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyRequest")
            .field("port", &self.port)
            .field("header_count", &self.headers.len())
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProxyResponseHead {
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: Vec<ProxyHeader>,
    /// Opaque backend-local correlation used only for typed status delivery.
    /// It is never serialized into the proxy response.
    pub observation_id: Option<u64>,
}

impl fmt::Debug for ProxyResponseHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyResponseHead")
            .field("status_code", &self.status_code)
            .field("header_count", &self.headers.len())
            .field("observation_id_present", &self.observation_id.is_some())
            .finish_non_exhaustive()
    }
}

pub enum ProxyResponseBody {
    Bytes(Vec<u8>),
    /// A length-delimited response stream. Readers used by production
    /// backends must have bounded I/O waits and must be released promptly
    /// when the request's cancellation token is cancelled; proxy shutdown
    /// joins rather than detaches client workers.
    Stream {
        expected_len: u64,
        reader: Box<dyn Read + Send>,
    },
}

impl ProxyResponseBody {
    pub fn empty() -> Self {
        Self::Bytes(Vec::new())
    }

    pub fn expected_len(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            Self::Stream { expected_len, .. } => *expected_len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.expected_len() == 0
    }
}

impl fmt::Debug for ProxyResponseBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyResponseBody")
            .field("expected_len", &self.expected_len())
            .finish()
    }
}

pub struct ProxyResponse {
    pub head: ProxyResponseHead,
    pub body: ProxyResponseBody,
    /// Opaque backend-issued authorization for publishing this exact result.
    ///
    /// The server returns this value to the same backend immediately before
    /// flushing the response head. It is never serialized or interpreted by
    /// the proxy.
    pub publication: PublicationCapability,
}

/// One typed HTTP Upgrade response and its live origin connection. The proxy
/// validates and sanitizes the response head before exposing it to a client.
///
/// Production streams must bound every read and write wait. In particular,
/// an otherwise idle `read` must periodically return `TimedOut` or
/// `WouldBlock` so the proxy can observe generation cancellation without
/// detaching tunnel workers.
pub struct ProxyTunnel {
    pub head: ProxyResponseHead,
    pub stream: Box<dyn ProxyTunnelIo>,
    /// Opaque backend-issued authorization for publishing this exact switch.
    pub publication: PublicationCapability,
}

/// Result of opening an Upgrade route. Policy and resolution failures can be
/// returned as a normal bounded HTTP response without falsely switching the
/// client into tunnel mode.
pub enum ProxyTunnelOpen {
    Tunnel(ProxyTunnel),
    Response(ProxyResponse),
}

impl fmt::Debug for ProxyTunnelOpen {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tunnel(tunnel) => formatter.debug_tuple("Tunnel").field(tunnel).finish(),
            Self::Response(response) => formatter.debug_tuple("Response").field(response).finish(),
        }
    }
}

impl fmt::Debug for ProxyTunnel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyTunnel")
            .field("head", &self.head)
            .field("stream", &"<redacted duplex stream>")
            .finish()
    }
}

pub trait ProxyTunnelIo: Read + Write + Send {}

impl<T: Read + Write + Send> ProxyTunnelIo for T {}

impl fmt::Debug for ProxyResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyResponse")
            .field("head", &self.head)
            .field("body", &self.body)
            .finish()
    }
}

/// Opaque authorization bound by a backend to one returned response or tunnel.
///
/// Stateful backends should store the exact admission identity for the work
/// that produced the result. [`ProxyBackend::acquire_publication_permit`] is
/// then responsible for validating that identity atomically with publication.
pub struct PublicationCapability {
    backend_state: Box<dyn Any + Send + Sync>,
}

impl PublicationCapability {
    /// Creates a no-state capability for stateless backends.
    pub fn stateless() -> Self {
        Self::new(())
    }

    /// Wraps backend-private publication state without exposing it to the
    /// platform-neutral server.
    pub fn new<T>(backend_state: T) -> Self
    where
        T: Any + Send + Sync,
    {
        Self {
            backend_state: Box::new(backend_state),
        }
    }

    /// Recovers backend-private state when the capability is returned to the
    /// backend that issued it.
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.backend_state.downcast_ref()
    }
}

impl Default for PublicationCapability {
    fn default() -> Self {
        Self::stateless()
    }
}

impl fmt::Debug for PublicationCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicationCapability(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BackendError {
    #[error("backend operation was cancelled")]
    Cancelled,
    #[error("backend rejected an invalid request")]
    InvalidRequest,
    #[error("backend policy denied the request")]
    PolicyDenied,
    #[error("name resolution failed")]
    ResolutionFailed,
    #[error("upstream TLS validation failed")]
    TlsValidationFailed,
    #[error("upstream service is unavailable")]
    UpstreamUnavailable,
    #[error("upstream returned an invalid response")]
    InvalidResponse,
    #[error("upstream response exceeds the configured limit")]
    ResponseTooLarge,
    #[error("backend does not support HTTP Upgrade tunnelling")]
    UnsupportedUpgrade,
    #[error("internal backend failure")]
    Internal,
}

/// RAII proof that a backend still authorizes response publication.
///
/// Stateful backends may hold a lifecycle lock inside this value. The server
/// keeps it alive through the flushed response head (or HTTP 101 switch) so a
/// concurrent revocation cannot commit between validation and publication.
/// Response bodies and upgraded streams must remain cancellation-aware and,
/// when authority-bound, revalidate their own I/O.
pub trait PublicationPermit {}

impl PublicationPermit for () {}

pub trait ProxyBackend: Send + Sync + 'static {
    /// Executes one admitted request. Implementations must observe
    /// `cancellation` and bound every network/storage wait so proxy shutdown
    /// can join all work. Implementations must not panic: shipping profiles
    /// abort on panic. Errors must remain payload-free at this boundary.
    fn execute(
        &self,
        request: ProxyRequest,
        cancellation: &CancellationToken,
    ) -> Result<ProxyResponse, BackendError>;

    /// Opens one admitted HTTP Upgrade tunnel. Implementations must apply the
    /// same resolution, address, TLS, and DANE policy as [`Self::execute`],
    /// observe `cancellation`, and satisfy the bounded-I/O contract documented
    /// on [`ProxyTunnel`]. The default returns a bounded, stateless 501
    /// response for backends that only implement request/response traffic.
    fn open_tunnel(
        &self,
        _request: ProxyRequest,
        _cancellation: &CancellationToken,
    ) -> Result<ProxyTunnelOpen, BackendError> {
        Ok(ProxyTunnelOpen::Response(ProxyResponse {
            head: ProxyResponseHead {
                status_code: 501,
                reason_phrase: "Upgrade Not Implemented".to_owned(),
                headers: Vec::new(),
                observation_id: None,
            },
            body: ProxyResponseBody::empty(),
            publication: PublicationCapability::stateless(),
        }))
    }

    /// Acquires an authorization held across response publication.
    ///
    /// Stateless backends use the default no-op permit. Stateful backends
    /// return an RAII guard that prevents lifecycle invalidation until the
    /// response head or protocol switch has been flushed.
    fn acquire_publication_permit(
        &self,
        _capability: &PublicationCapability,
    ) -> Result<Box<dyn PublicationPermit + '_>, BackendError> {
        Ok(Box::new(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::thread;
    use std::time::Instant;

    #[test]
    fn cancellation_is_shared_idempotent_and_wakes_waiters() {
        let token = CancellationToken::new();
        let waiter = token.clone();
        let handle = thread::spawn(move || waiter.wait_cancelled_timeout(Duration::from_secs(2)));
        assert!(token.cancel());
        assert!(!token.cancel());
        assert!(handle.join().expect("waiter joins"));
    }

    #[test]
    fn uncancelled_wait_times_out() {
        let token = CancellationToken::new();
        let started = Instant::now();
        assert!(!token.wait_cancelled_timeout(Duration::from_millis(5)));
        assert!(started.elapsed() >= Duration::from_millis(5));
    }

    #[test]
    fn diagnostics_redact_request_secrets_and_payloads() {
        let request = ProxyRequest {
            method: "GET".to_owned(),
            scheme: "https".to_owned(),
            host: "user:secret@example".to_owned(),
            port: 443,
            path_and_query: "/private?token=secret".to_owned(),
            headers: vec![ProxyHeader::new("Authorization", "secret")],
            body: ProxyRequestBody::Bytes(b"secret body".to_vec()),
        };
        let diagnostic = format!("{request:?}");
        for secret in [
            "user",
            "secret",
            "example",
            "private",
            "token",
            "Authorization",
        ] {
            assert!(!diagnostic.contains(secret));
        }
        assert!(diagnostic.contains("header_count"));
        assert!(diagnostic.contains("len"));
    }

    #[test]
    fn response_stream_declares_length_without_debugging_contents() {
        let body = ProxyResponseBody::Stream {
            expected_len: 12,
            reader: Box::new(Cursor::new(b"secret bytes".to_vec())),
        };
        assert_eq!(body.expected_len(), 12);
        assert_eq!(
            format!("{body:?}"),
            "ProxyResponseBody { expected_len: 12 }"
        );
    }
}
