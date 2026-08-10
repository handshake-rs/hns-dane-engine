use std::collections::HashSet;
use std::fmt;
use thiserror::Error;

const MAX_RESPONSE_HEADERS: usize = 256;
const MAX_RESPONSE_HEAD_BYTES: usize = 64 * 1024;

#[derive(Clone, Default, Eq, PartialEq)]
pub struct InternalResponseMetadata {
    headers: Vec<(String, String)>,
}

impl fmt::Debug for InternalResponseMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalResponseMetadata")
            .field("header_count", &self.headers.len())
            .finish()
    }
}

impl InternalResponseMetadata {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SanitizedResponseHeaders {
    forwarded: Vec<(String, String)>,
    metadata: InternalResponseMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedResponseHead {
    bytes: Vec<u8>,
    body_allowed: bool,
}

impl EncodedResponseHead {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn body_allowed(&self) -> bool {
        self.body_allowed
    }
}

impl fmt::Debug for SanitizedResponseHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedResponseHeaders")
            .field("forwarded_count", &self.forwarded.len())
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl SanitizedResponseHeaders {
    pub fn forwarded(&self) -> &[(String, String)] {
        &self.forwarded
    }

    pub fn metadata(&self) -> &InternalResponseMetadata {
        &self.metadata
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ResponseError {
    #[error("invalid HTTP response status")]
    InvalidStatus,
    #[error("invalid HTTP response reason")]
    InvalidReason,
    #[error("invalid HTTP response header")]
    InvalidHeader,
    #[error("HTTP response headers exceed proxy limits")]
    HeadersTooLarge,
    #[error("HTTP response status does not permit a message body")]
    BodyNotAllowed,
}

pub fn sanitize_response_headers(
    headers: &[(String, String)],
) -> Result<SanitizedResponseHeaders, ResponseError> {
    let connection_fields = validate_response_headers(headers)?;

    let mut forwarded = Vec::with_capacity(headers.len());
    let mut metadata = Vec::new();
    let mut metadata_names = HashSet::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if connection_fields.contains(&lower) {
            continue;
        }
        if is_internal_header(name) {
            if is_trusted_metadata_header(&lower) {
                if !metadata_names.insert(lower) {
                    return Err(ResponseError::InvalidHeader);
                }
                metadata.push((name.clone(), value.clone()));
            }
            continue;
        }
        if is_proxy_managed_response_header(&lower) {
            continue;
        }
        forwarded.push((name.clone(), value.clone()));
    }
    Ok(SanitizedResponseHeaders {
        forwarded,
        metadata: InternalResponseMetadata { headers: metadata },
    })
}

pub fn encode_response_head(
    request_method: &str,
    status: u16,
    reason: &str,
    headers: &SanitizedResponseHeaders,
    body_len: u64,
) -> Result<EncodedResponseHead, ResponseError> {
    if !(200..=599).contains(&status) {
        return Err(ResponseError::InvalidStatus);
    }
    validate_reason(reason)?;
    let status_forbids_body = matches!(status, 204 | 205 | 304);
    if status_forbids_body && body_len != 0 {
        return Err(ResponseError::BodyNotAllowed);
    }
    let body_allowed = !request_method.eq_ignore_ascii_case("HEAD") && !status_forbids_body;
    let mut encoded = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for (name, value) in headers.forwarded() {
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(b": ");
        encoded.extend_from_slice(value.as_bytes());
        encoded.extend_from_slice(b"\r\n");
    }
    encoded.extend_from_slice(b"Connection: close\r\n");
    if !status_forbids_body {
        encoded.extend_from_slice(b"Content-Length: ");
        encoded.extend_from_slice(body_len.to_string().as_bytes());
        encoded.extend_from_slice(b"\r\n");
    }
    encoded.extend_from_slice(b"\r\n");
    if encoded.len() > MAX_RESPONSE_HEAD_BYTES {
        return Err(ResponseError::HeadersTooLarge);
    }
    Ok(EncodedResponseHead {
        bytes: encoded,
        body_allowed,
    })
}

/// Validates and reconstructs a WebSocket Upgrade response. Origin-controlled
/// framing, proxy, internal, and connection-nominated fields are never copied;
/// the two mandatory hop-by-hop fields are emitted canonically by the proxy.
pub fn encode_upgrade_response_head(
    status: u16,
    reason: &str,
    headers: &[(String, String)],
) -> Result<EncodedResponseHead, ResponseError> {
    if status != 101 {
        return Err(ResponseError::InvalidStatus);
    }
    validate_reason(reason)?;
    let connection_fields = validate_response_headers(headers)?;
    let connection_upgrade = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection") && has_header_token(value, "upgrade")
    });
    let upgrade_values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
        .map(|(_, value)| value.as_str())
        .collect();
    if !connection_upgrade
        || upgrade_values.len() != 1
        || !upgrade_values[0].eq_ignore_ascii_case("websocket")
    {
        return Err(ResponseError::InvalidHeader);
    }

    let mut encoded = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if connection_fields.contains(&lower)
            || is_internal_header(name)
            || is_proxy_managed_response_header(&lower)
        {
            continue;
        }
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(b": ");
        encoded.extend_from_slice(value.as_bytes());
        encoded.extend_from_slice(b"\r\n");
    }
    encoded.extend_from_slice(b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
    if encoded.len() > MAX_RESPONSE_HEAD_BYTES {
        return Err(ResponseError::HeadersTooLarge);
    }
    Ok(EncodedResponseHead {
        bytes: encoded,
        body_allowed: false,
    })
}

fn validate_response_headers(
    headers: &[(String, String)],
) -> Result<HashSet<String>, ResponseError> {
    if headers.len() > MAX_RESPONSE_HEADERS {
        return Err(ResponseError::HeadersTooLarge);
    }
    let mut head_bytes = 0usize;
    let mut connection_fields = HashSet::new();
    for (name, value) in headers {
        if !is_http_token(name) || !is_http_field_value(value) {
            return Err(ResponseError::InvalidHeader);
        }
        head_bytes = head_bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .and_then(|total| total.checked_add(4))
            .ok_or(ResponseError::HeadersTooLarge)?;
        if name.eq_ignore_ascii_case("connection") {
            for token in value.split(',').map(str::trim) {
                if !is_http_token(token) {
                    return Err(ResponseError::InvalidHeader);
                }
                connection_fields.insert(token.to_ascii_lowercase());
            }
        }
    }
    if head_bytes > MAX_RESPONSE_HEAD_BYTES {
        return Err(ResponseError::HeadersTooLarge);
    }
    Ok(connection_fields)
}

fn validate_reason(reason: &str) -> Result<(), ResponseError> {
    if reason.len() > MAX_RESPONSE_HEAD_BYTES {
        return Err(ResponseError::HeadersTooLarge);
    }
    if reason.is_empty()
        || reason
            .bytes()
            .any(|byte| byte < b' ' || byte == 0x7f || byte >= 0x80)
    {
        return Err(ResponseError::InvalidReason);
    }
    Ok(())
}

fn has_header_token(value: &str, expected: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|token| token.eq_ignore_ascii_case(expected))
}

fn is_internal_header(name: &str) -> bool {
    name.get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("X-HNS-"))
}

fn is_trusted_metadata_header(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "x-hns-doh-fallback"
            | "x-hns-resolution-trace"
            | "x-hns-resolver-mode"
            | "x-hns-resolver-policy"
            | "x-hns-security-path"
            | "x-hns-tls-policy"
    )
}

fn is_proxy_managed_response_header(lower_name: &str) -> bool {
    lower_name.starts_with("proxy-")
        || matches!(
            lower_name,
            "connection"
                | "alt-svc"
                | "content-length"
                | "keep-alive"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        )
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

fn is_http_field_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_every_internal_and_hop_by_hop_response_header() {
        let headers = vec![
            ("Content-Type".to_owned(), "text/plain".to_owned()),
            ("X-HNS-Security-Path".to_owned(), "dane".to_owned()),
            ("x-hns-future-metadata".to_owned(), "secret".to_owned()),
            (
                "Connection".to_owned(),
                "Keep-Alive, X-Origin-Hop".to_owned(),
            ),
            ("X-Origin-Hop".to_owned(), "remove".to_owned()),
            ("Transfer-Encoding".to_owned(), "chunked".to_owned()),
            ("Content-Length".to_owned(), "999".to_owned()),
            ("Proxy-Future".to_owned(), "secret".to_owned()),
        ];

        let sanitized = sanitize_response_headers(&headers).unwrap();

        assert_eq!(
            sanitized.forwarded(),
            &[("Content-Type".to_owned(), "text/plain".to_owned())]
        );
        assert_eq!(
            sanitized.metadata().get("X-HNS-Security-Path"),
            Some("dane")
        );
        assert_eq!(sanitized.metadata().get("X-HNS-Future-Metadata"), None);
    }

    #[test]
    fn rejects_header_injection_even_for_internal_metadata() {
        let error = sanitize_response_headers(&[(
            "X-HNS-Trace".to_owned(),
            "safe\r\nSet-Cookie: injected=1".to_owned(),
        )])
        .unwrap_err();

        assert_eq!(error, ResponseError::InvalidHeader);
    }

    #[test]
    fn response_head_owns_framing_and_connection_lifecycle() {
        let headers = sanitize_response_headers(&[(
            "Content-Type".to_owned(),
            "application/octet-stream".to_owned(),
        )])
        .unwrap();

        let encoded = encode_response_head("GET", 206, "Partial Content", &headers, 42).unwrap();
        assert!(encoded.body_allowed());
        let text = String::from_utf8(encoded.into_bytes()).unwrap();

        assert!(text.starts_with("HTTP/1.1 206 Partial Content\r\n"));
        assert!(text.contains("Content-Type: application/octet-stream\r\n"));
        assert!(text.contains("Connection: close\r\nContent-Length: 42\r\n\r\n"));
    }

    #[test]
    fn rejects_informational_finals_and_nonempty_bodyless_statuses() {
        let headers = sanitize_response_headers(&[]).unwrap();

        assert_eq!(
            encode_response_head("GET", 101, "Switching Protocols", &headers, 0),
            Err(ResponseError::InvalidStatus)
        );
        assert_eq!(
            encode_response_head("GET", 204, "No Content", &headers, 1),
            Err(ResponseError::BodyNotAllowed)
        );
        let head = encode_response_head("HEAD", 200, "OK", &headers, 12).unwrap();
        assert!(!head.body_allowed());
        assert!(
            String::from_utf8(head.into_bytes())
                .unwrap()
                .contains("Content-Length: 12\r\n")
        );
        assert_eq!(
            encode_response_head(
                "GET",
                200,
                &"x".repeat(MAX_RESPONSE_HEAD_BYTES + 1),
                &headers,
                0,
            ),
            Err(ResponseError::HeadersTooLarge)
        );
    }

    #[test]
    fn rejects_duplicate_trusted_metadata_and_discards_connection_nominated_metadata() {
        let duplicate = vec![
            ("X-HNS-TLS-Policy".to_owned(), "dane".to_owned()),
            ("x-hns-tls-policy".to_owned(), "webpki".to_owned()),
        ];
        assert_eq!(
            sanitize_response_headers(&duplicate),
            Err(ResponseError::InvalidHeader)
        );

        let nominated = vec![
            ("Connection".to_owned(), "X-HNS-Security-Path".to_owned()),
            ("X-HNS-Security-Path".to_owned(), "spoofed".to_owned()),
        ];
        let sanitized = sanitize_response_headers(&nominated).unwrap();
        assert!(sanitized.metadata().is_empty());
    }

    #[test]
    fn upgrade_head_is_canonical_and_strips_internal_and_nominated_fields() {
        let headers = vec![
            (
                "Connection".to_owned(),
                "keep-alive, Upgrade, X-Hop".to_owned(),
            ),
            ("Upgrade".to_owned(), "websocket".to_owned()),
            ("Sec-WebSocket-Accept".to_owned(), "accepted".to_owned()),
            ("X-Hop".to_owned(), "secret".to_owned()),
            ("X-HNS-Security-Path".to_owned(), "dane".to_owned()),
            ("Alt-Svc".to_owned(), "h3=\":443\"".to_owned()),
            ("Content-Length".to_owned(), "999".to_owned()),
        ];

        let encoded = encode_upgrade_response_head(101, "Switching Protocols", &headers).unwrap();
        let text = String::from_utf8(encoded.into_bytes()).unwrap();

        assert!(text.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(text.contains("Sec-WebSocket-Accept: accepted\r\n"));
        assert!(text.ends_with("Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"));
        assert!(!text.contains("keep-alive"));
        assert!(!text.contains("X-Hop"));
        assert!(!text.contains("X-HNS-"));
        assert!(!text.contains("Alt-Svc"));
        assert!(!text.contains("Content-Length"));
    }

    #[test]
    fn upgrade_head_requires_exact_websocket_switching_protocols() {
        let valid = vec![
            ("Connection".to_owned(), "Upgrade".to_owned()),
            ("Upgrade".to_owned(), "websocket".to_owned()),
        ];
        assert_eq!(
            encode_upgrade_response_head(200, "OK", &valid),
            Err(ResponseError::InvalidStatus)
        );
        assert_eq!(
            encode_upgrade_response_head(
                101,
                "Switching Protocols",
                &[("Upgrade".to_owned(), "websocket".to_owned())],
            ),
            Err(ResponseError::InvalidHeader)
        );
        assert_eq!(
            encode_upgrade_response_head(
                101,
                "Switching Protocols",
                &[
                    ("Connection".to_owned(), "Upgrade".to_owned()),
                    ("Upgrade".to_owned(), "h2c".to_owned()),
                ],
            ),
            Err(ResponseError::InvalidHeader)
        );
    }
}
