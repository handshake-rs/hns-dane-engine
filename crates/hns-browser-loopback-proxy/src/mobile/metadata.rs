//! Typed delivery of trusted, sensitive response metadata.
//!
//! This surface is deliberately separate from [`crate::ProxyEvent`]. It
//! exposes the response status and trusted `X-HNS-*` metadata needed by native
//! browser security UI without adding fields for a request target, query,
//! headers, or body. Trusted metadata values remain sensitive and may
//! themselves contain diagnostic request details; callers must keep them
//! bounded to the in-memory security UI and diagnostics are redacted.

use crate::event::{ObservedHost, ObservedMethod};
use crate::response::InternalResponseMetadata;
use std::fmt;

/// Trusted, sensitive metadata from one validated response head.
///
/// Observations contain no dedicated request-target, query, request-header,
/// response-body, or request-body fields. Allowlisted metadata values may
/// themselves contain request details and must be treated as sensitive. They
/// are redacted from `Debug` output.
#[derive(Clone, Eq, PartialEq)]
pub struct ProxyResponseMetadataObservation {
    generation: u64,
    host: ObservedHost,
    method: ObservedMethod,
    status_code: u16,
    likely_main_frame: bool,
    observation_id: Option<u64>,
    metadata: InternalResponseMetadata,
}

impl ProxyResponseMetadataObservation {
    pub(crate) fn new(
        generation: u64,
        host: ObservedHost,
        method: ObservedMethod,
        status_code: u16,
        likely_main_frame: bool,
        observation_id: Option<u64>,
        metadata: InternalResponseMetadata,
    ) -> Self {
        Self {
            generation,
            host,
            method,
            status_code,
            likely_main_frame,
            observation_id,
            metadata,
        }
    }

    /// Returns the proxy generation that produced this response.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the validated canonical HNS host, without a port or user info.
    pub fn host(&self) -> &ObservedHost {
        &self.host
    }

    /// Returns the request method as a closed, payload-free classification.
    pub fn method(&self) -> ObservedMethod {
        self.method
    }

    /// Returns the validated response status selected for browser delivery.
    /// Observation precedes the socket write, so client disconnects can still
    /// prevent the browser from receiving it.
    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Whether the request matched the browser shell's conservative
    /// main-frame-navigation heuristic.
    pub fn is_likely_main_frame(&self) -> bool {
        self.likely_main_frame
    }

    /// Opaque backend-local typed-status correlation. This value is never
    /// serialized to the browser or native platform ABI.
    pub fn observation_id(&self) -> Option<u64> {
        self.observation_id
    }

    /// Returns allowlisted internal metadata removed from the browser-facing
    /// response head.
    pub fn metadata(&self) -> &InternalResponseMetadata {
        &self.metadata
    }
}

impl fmt::Debug for ProxyResponseMetadataObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyResponseMetadataObservation")
            .field("generation", &self.generation)
            .field("host", &self.host)
            .field("method", &self.method)
            .field("status_code", &self.status_code)
            .field("likely_main_frame", &self.likely_main_frame)
            .field("observation_id_present", &self.observation_id.is_some())
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Observer for validated, browser-relevant, sensitive response metadata.
pub trait ProxyResponseMetadataObserver: Send + Sync + 'static {
    /// Receives one typed, sensitive observation. Implementations must return
    /// promptly, retain it only as narrowly as needed, and must not panic; the
    /// proxy isolates unwinding observers.
    fn observe(&self, observation: &ProxyResponseMetadataObservation);
}

impl<F> ProxyResponseMetadataObserver for F
where
    F: Fn(&ProxyResponseMetadataObservation) + Send + Sync + 'static,
{
    fn observe(&self, observation: &ProxyResponseMetadataObservation) {
        self(observation);
    }
}

/// Metadata observer used by the compatibility [`crate::RunningProxy::start`]
/// entry point.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopProxyResponseMetadataObserver;

impl ProxyResponseMetadataObserver for NoopProxyResponseMetadataObserver {
    fn observe(&self, _observation: &ProxyResponseMetadataObservation) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanitize_response_headers;

    #[test]
    fn observation_debug_redacts_sensitive_metadata_values() {
        let headers = sanitize_response_headers(&[
            (
                "X-HNS-Resolution-Trace".to_owned(),
                "private?token=secret".to_owned(),
            ),
            ("X-HNS-Security-Path".to_owned(), "dane".to_owned()),
        ])
        .unwrap();
        let observation = ProxyResponseMetadataObservation::new(
            7,
            ObservedHost::new("welcome").unwrap(),
            ObservedMethod::Get,
            200,
            true,
            Some(9),
            headers.metadata().clone(),
        );

        assert_eq!(observation.generation(), 7);
        assert_eq!(observation.host().as_str(), "welcome");
        assert_eq!(observation.method(), ObservedMethod::Get);
        assert_eq!(observation.status_code(), 200);
        assert!(observation.is_likely_main_frame());
        assert_eq!(observation.observation_id(), Some(9));
        assert_eq!(
            observation.metadata().get("X-HNS-Security-Path"),
            Some("dane")
        );
        let diagnostic = format!("{observation:?}");
        assert!(!diagnostic.contains("private"));
        assert!(!diagnostic.contains("token"));
        assert!(!diagnostic.contains("secret"));
        assert!(!diagnostic.contains("path"));
        assert!(!diagnostic.contains("query"));
        assert!(!diagnostic.contains("body"));
    }
}
