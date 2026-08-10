//! Privacy-preserving proxy observation.
//!
//! Events intentionally have no free-form text fields. A request target,
//! query, header, credential, payload, or backend error detail therefore
//! cannot cross this interface accidentally.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;

/// A validated, canonical ASCII DNS host or public IP literal suitable for
/// diagnostics.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObservedHost(String);

impl ObservedHost {
    pub fn new(host: &str) -> Result<Self, ObservedHostError> {
        if host.is_empty() {
            return Err(ObservedHostError::Empty);
        }
        if host.len() > 253 || !host.is_ascii() {
            return Err(ObservedHostError::InvalidDnsName);
        }
        if let Ok(address) = host.parse::<IpAddr>() {
            if address.to_string() == host.to_ascii_lowercase() {
                return Ok(Self(host.to_ascii_lowercase()));
            }
            return Err(ObservedHostError::InvalidDnsName);
        }
        for label in host.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(ObservedHostError::InvalidDnsName);
            }
            let bytes = label.as_bytes();
            if !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                || !bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            {
                return Err(ObservedHostError::InvalidDnsName);
            }
        }
        Ok(Self(host.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ObservedHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ObservedHost")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ObservedHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<&str> for ObservedHost {
    type Error = ObservedHostError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ObservedHostError {
    #[error("observed host is empty")]
    Empty,
    #[error("observed host is not a canonical ASCII DNS name")]
    InvalidDnsName,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Patch,
    Connect,
    Other,
}

impl ObservedMethod {
    pub fn from_token(method: &str) -> Self {
        if method.eq_ignore_ascii_case("GET") {
            Self::Get
        } else if method.eq_ignore_ascii_case("HEAD") {
            Self::Head
        } else if method.eq_ignore_ascii_case("POST") {
            Self::Post
        } else if method.eq_ignore_ascii_case("PUT") {
            Self::Put
        } else if method.eq_ignore_ascii_case("DELETE") {
            Self::Delete
        } else if method.eq_ignore_ascii_case("OPTIONS") {
            Self::Options
        } else if method.eq_ignore_ascii_case("PATCH") {
            Self::Patch
        } else if method.eq_ignore_ascii_case("CONNECT") {
            Self::Connect
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleEvent {
    Listening { port: u16 },
    Stopping,
    Stopped { reason: StopReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    Requested,
    Cancelled,
    ListenerFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientRejectionReason {
    ActiveClientLimit,
    AuthenticationRequired,
    InvalidRequest,
    Cancelled,
    InvalidPeer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestRejectionReason {
    AuthenticationRequired,
    InvalidRequest,
    HostOutsideScope,
    GlobalRateLimit,
    HostRateLimit,
    RequestTooLarge,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendFailureKind {
    Cancelled,
    InvalidRequest,
    PolicyDenied,
    Resolution,
    TlsValidation,
    Upstream,
    InvalidResponse,
    ResponseTooLarge,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestPhase {
    Accepted,
    Completed {
        status_code: u16,
        elapsed: Duration,
    },
    Rejected {
        reason: RequestRejectionReason,
    },
    BackendFailed {
        kind: BackendFailureKind,
        elapsed: Duration,
    },
}

/// Sanitized events scoped to a monotonically increasing proxy generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyEvent {
    Lifecycle {
        generation: u64,
        event: LifecycleEvent,
    },
    ClientRejected {
        generation: u64,
        reason: ClientRejectionReason,
    },
    Request {
        generation: u64,
        host: ObservedHost,
        method: ObservedMethod,
        phase: RequestPhase,
    },
}

pub trait ProxyObserver: Send + Sync + 'static {
    /// Receives a privacy-bounded event. Implementations must return promptly
    /// and must not panic; shipping profiles abort on panic.
    fn observe(&self, event: &ProxyEvent);
}

impl<F> ProxyObserver for F
where
    F: Fn(&ProxyEvent) + Send + Sync + 'static,
{
    fn observe(&self, event: &ProxyEvent) {
        self(event);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopProxyObserver;

impl ProxyObserver for NoopProxyObserver {
    fn observe(&self, _event: &ProxyEvent) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn observed_host_accepts_only_dns_host_syntax() {
        assert_eq!(
            ObservedHost::new("MiXeD.Example")
                .expect("valid host")
                .as_str(),
            "mixed.example"
        );
        for unsafe_host in [
            "user:pass@example",
            "example/path",
            "example?query",
            "example#fragment",
            "example:443",
            "example header",
            "example%2fpath",
        ] {
            assert!(ObservedHost::new(unsafe_host).is_err(), "{unsafe_host}");
        }
    }

    #[test]
    fn unknown_method_does_not_retain_input() {
        assert_eq!(
            ObservedMethod::from_token("SECRET /path?query"),
            ObservedMethod::Other
        );
        assert_eq!(format!("{:?}", ObservedMethod::Other), "Other");
    }

    #[test]
    fn observer_receives_typed_sanitized_event() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&observed);
        let observer = move |event: &ProxyEvent| {
            sink.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event.clone());
        };
        let event = ProxyEvent::Request {
            generation: 9,
            host: ObservedHost::new("example").expect("valid host"),
            method: ObservedMethod::Get,
            phase: RequestPhase::Rejected {
                reason: RequestRejectionReason::AuthenticationRequired,
            },
        };
        observer.observe(&event);
        assert_eq!(
            observed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_slice(),
            &[event]
        );
    }
}
