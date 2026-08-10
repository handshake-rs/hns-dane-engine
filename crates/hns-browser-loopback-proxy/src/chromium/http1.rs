//! Strict, bounded HTTP/1 request parsing for the loopback proxy.
//!
//! This module deliberately reads request heads one byte at a time. A blocking
//! socket may deliver the head and body together, and consuming past the first
//! `CRLFCRLF` would otherwise require a second buffering abstraction at every
//! call site.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

pub const DEFAULT_MAX_REQUEST_HEAD_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 1024 * 1024;
pub const MAX_REQUEST_HEADERS: usize = 256;
pub const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;
pub const MAX_CHUNK_TRAILER_BYTES: usize = 64 * 1024;

const HEAD_END: &[u8; 4] = b"\r\n\r\n";

#[derive(Debug, Error)]
pub enum Http1Error {
    #[error("request I/O failed")]
    Io(#[source] io::Error),
    #[error("request ended before it was complete")]
    UnexpectedEof,
    #[error("request head is too large")]
    HeadTooLarge,
    #[error("request has too many headers")]
    TooManyHeaders,
    #[error("invalid HTTP request line")]
    InvalidRequestLine,
    #[error("unsupported HTTP version")]
    UnsupportedHttpVersion,
    #[error("invalid HTTP request header")]
    InvalidHeader,
    #[error("duplicate Proxy-Authorization header")]
    DuplicateProxyAuthorization,
    #[error("invalid request target")]
    InvalidTarget,
    #[error("invalid request authority")]
    InvalidAuthority,
    #[error("request target does not match the CONNECT authority")]
    TargetMismatch,
    #[error("Host header is required")]
    MissingHost,
    #[error("Host header does not match the request target")]
    HostMismatch,
    #[error("invalid or duplicate Content-Length")]
    InvalidContentLength,
    #[error("ambiguous HTTP request body framing")]
    AmbiguousFraming,
    #[error("unsupported Transfer-Encoding")]
    UnsupportedTransferEncoding,
    #[error("request body is too large")]
    BodyTooLarge,
    #[error("request body ended before it was complete")]
    UnexpectedBodyEof,
    #[error("invalid chunked request body")]
    InvalidChunkedBody,
    #[error("chunked request trailers are too large")]
    TrailersTooLarge,
}

impl Http1Error {
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        match self {
            Self::HeadTooLarge | Self::TooManyHeaders => 431,
            Self::BodyTooLarge => 413,
            Self::UnsupportedTransferEncoding => 501,
            _ => 400,
        }
    }

    #[must_use]
    pub const fn reason_phrase(&self) -> &'static str {
        match self {
            Self::HeadTooLarge | Self::TooManyHeaders => "Request Header Fields Too Large",
            Self::BodyTooLarge => "Payload Too Large",
            Self::UnsupportedTransferEncoding => "Transfer Encoding Unsupported",
            Self::InvalidContentLength => "Bad Content-Length",
            Self::AmbiguousFraming => "Bad Request Framing",
            Self::MissingHost | Self::HostMismatch => "HNS Host Header Mismatch",
            Self::TargetMismatch => "HNS Request Mismatch",
            _ => "Bad Request",
        }
    }
}

impl From<io::Error> for Http1Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Header {
    name: String,
    value: String,
}

impl Header {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Header")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("value_len", &self.value.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RequestHead {
    method: String,
    target: String,
    version: HttpVersion,
    headers: Vec<Header>,
}

impl RequestHead {
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub fn raw_target(&self) -> &str {
        &self.target
    }

    #[must_use]
    pub const fn version(&self) -> HttpVersion {
        self.version
    }

    #[must_use]
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    /// Returns the sole proxy credential field without logging or decoding it.
    pub fn proxy_authorization(&self) -> Result<Option<&str>, Http1Error> {
        let mut values = self.header_values("proxy-authorization");
        let first = values.next();
        if values.next().is_some() {
            return Err(Http1Error::DuplicateProxyAuthorization);
        }
        Ok(first)
    }

    pub fn host_authority(&self, default_port: u16) -> Result<Option<Authority>, Http1Error> {
        let mut values = self.header_values("host");
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(Http1Error::HostMismatch);
        }
        Authority::parse(value, default_port)
            .map(Some)
            .map_err(|_| Http1Error::HostMismatch)
    }

    /// Parses the request target in direct-proxy or post-CONNECT context.
    pub fn request_target(
        &self,
        connected_to: Option<&Authority>,
    ) -> Result<RequestTarget, Http1Error> {
        parse_request_target(&self.method, &self.target, connected_to)
    }

    /// Parses the target and verifies the Host field against its authority.
    pub fn validated_target(
        &self,
        connected_to: Option<&Authority>,
    ) -> Result<RequestTarget, Http1Error> {
        let target = self.request_target(connected_to)?;
        let (expected, default_port) = match &target {
            RequestTarget::Absolute(target) => (&target.authority, target.scheme.default_port()),
            RequestTarget::Connect(authority) => (authority, authority.port),
            RequestTarget::Origin(target) => (&target.authority, 443),
        };
        match self.host_authority(default_port)? {
            Some(host) if host == *expected => Ok(target),
            Some(_) => Err(Http1Error::HostMismatch),
            None if self.version == HttpVersion::Http10 => Ok(target),
            None => Err(Http1Error::MissingHost),
        }
    }
}

impl fmt::Debug for RequestHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestHead")
            .field("method", &self.method)
            .field("target", &"<redacted>")
            .field("version", &self.version)
            .field("header_count", &self.headers.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Authority {
    host: String,
    port: u16,
}

impl Authority {
    pub fn parse(value: &str, default_port: u16) -> Result<Self, Http1Error> {
        parse_authority(value, Some(default_port), false)
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn host_header(&self, default_port: u16) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl fmt::Debug for Authority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Authority")
            .field("host", &"<redacted>")
            .field("port", &self.port)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    Http,
    Https,
    Ws,
    Wss,
}

impl Scheme {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Ws => "ws",
            Self::Wss => "wss",
        }
    }

    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http | Self::Ws => 80,
            Self::Https | Self::Wss => 443,
        }
    }

    #[must_use]
    pub const fn is_secure(self) -> bool {
        matches!(self, Self::Https | Self::Wss)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AbsoluteTarget {
    scheme: Scheme,
    authority: Authority,
    path_and_query: String,
}

impl AbsoluteTarget {
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    #[must_use]
    pub const fn authority(&self) -> &Authority {
        &self.authority
    }

    #[must_use]
    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }
}

impl fmt::Debug for AbsoluteTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AbsoluteTarget")
            .field("scheme", &self.scheme)
            .field("authority", &self.authority)
            .field("path_and_query", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OriginTarget {
    authority: Authority,
    path_and_query: String,
}

impl OriginTarget {
    #[must_use]
    pub const fn authority(&self) -> &Authority {
        &self.authority
    }

    #[must_use]
    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }
}

impl fmt::Debug for OriginTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OriginTarget")
            .field("authority", &self.authority)
            .field("path_and_query", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum RequestTarget {
    Absolute(AbsoluteTarget),
    Connect(Authority),
    Origin(OriginTarget),
}

impl RequestTarget {
    #[must_use]
    pub fn authority(&self) -> &Authority {
        match self {
            Self::Absolute(target) => &target.authority,
            Self::Connect(authority) => authority,
            Self::Origin(target) => &target.authority,
        }
    }

    #[must_use]
    pub fn path_and_query(&self) -> Option<&str> {
        match self {
            Self::Absolute(target) => Some(&target.path_and_query),
            Self::Connect(_) => None,
            Self::Origin(target) => Some(&target.path_and_query),
        }
    }
}

impl fmt::Debug for RequestTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absolute(target) => formatter.debug_tuple("Absolute").field(target).finish(),
            Self::Connect(authority) => formatter.debug_tuple("Connect").field(authority).finish(),
            Self::Origin(target) => formatter.debug_tuple("Origin").field(target).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyFraming {
    None,
    ContentLength(u64),
    Chunked,
}

/// Reads exactly one request head and leaves all body bytes unread.
pub fn read_request_head(
    input: &mut impl Read,
    max_head_bytes: usize,
) -> Result<RequestHead, Http1Error> {
    if max_head_bytes < HEAD_END.len() {
        return Err(Http1Error::HeadTooLarge);
    }
    let mut bytes = Vec::with_capacity(max_head_bytes.min(8 * 1024));
    let mut byte = [0_u8; 1];
    while bytes.len() < max_head_bytes {
        let read = input.read(&mut byte)?;
        if read == 0 {
            return Err(Http1Error::UnexpectedEof);
        }
        bytes.push(byte[0]);
        if bytes.ends_with(HEAD_END) {
            return parse_request_head(&bytes);
        }
    }
    Err(Http1Error::HeadTooLarge)
}

pub fn parse_request_head(bytes: &[u8]) -> Result<RequestHead, Http1Error> {
    if bytes.len() > DEFAULT_MAX_REQUEST_HEAD_BYTES {
        return Err(Http1Error::HeadTooLarge);
    }
    let Some(end) = find_head_end(bytes) else {
        return Err(Http1Error::UnexpectedEof);
    };
    if end != bytes.len() {
        return Err(Http1Error::InvalidHeader);
    }
    validate_crlf(bytes)?;

    let line_end = bytes
        .windows(2)
        .position(|pair| pair == b"\r\n")
        .ok_or(Http1Error::InvalidRequestLine)?;
    let (method, target, version) = parse_request_line(&bytes[..line_end])?;

    // `httparse` remains a second, independent RFC parser layer. The checks
    // below intentionally tighten its accepted grammar for a proxy boundary.
    let mut parsed_headers = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
    let mut parsed = httparse::Request::new(&mut parsed_headers);
    let parsed_len = match parsed.parse(bytes) {
        Ok(httparse::Status::Complete(length)) => length,
        Ok(httparse::Status::Partial) => return Err(Http1Error::UnexpectedEof),
        Err(httparse::Error::TooManyHeaders) => return Err(Http1Error::TooManyHeaders),
        Err(_) => return Err(Http1Error::InvalidHeader),
    };
    if parsed_len != bytes.len()
        || parsed.method != Some(method.as_str())
        || parsed.path != Some(target.as_str())
    {
        return Err(Http1Error::InvalidRequestLine);
    }
    let parsed_version = match parsed.version {
        Some(0) => HttpVersion::Http10,
        Some(1) => HttpVersion::Http11,
        _ => return Err(Http1Error::UnsupportedHttpVersion),
    };
    if parsed_version != version {
        return Err(Http1Error::InvalidRequestLine);
    }

    // Keep the CRLF terminating the last field, but exclude the final empty
    // line. This also yields an empty slice for a request with no fields.
    let raw_headers = &bytes[line_end + 2..bytes.len() - 2];
    let headers = parse_header_block(raw_headers)?;
    if headers.len() != parsed.headers.len() {
        return Err(Http1Error::InvalidHeader);
    }
    Ok(RequestHead {
        method,
        target,
        version,
        headers,
    })
}

pub fn determine_body_framing(headers: &[Header]) -> Result<BodyFraming, Http1Error> {
    let content_lengths: Vec<_> = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
        .collect();
    if content_lengths.len() > 1 {
        return Err(Http1Error::InvalidContentLength);
    }
    let content_length = content_lengths
        .first()
        .map(|header| parse_content_length(&header.value))
        .transpose()?;

    let transfer_encodings: Vec<_> = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
        .collect();
    if !transfer_encodings.is_empty() && content_length.is_some() {
        return Err(Http1Error::AmbiguousFraming);
    }
    if !transfer_encodings.is_empty() {
        if transfer_encodings.len() != 1
            || !transfer_encodings[0].value.eq_ignore_ascii_case("chunked")
        {
            return Err(Http1Error::UnsupportedTransferEncoding);
        }
        return Ok(BodyFraming::Chunked);
    }
    Ok(content_length.map_or(BodyFraming::None, BodyFraming::ContentLength))
}

pub fn read_request_body(
    input: &mut impl Read,
    framing: BodyFraming,
    max_body_bytes: u64,
) -> Result<Vec<u8>, Http1Error> {
    match framing {
        BodyFraming::None => Ok(Vec::new()),
        BodyFraming::ContentLength(length) => read_fixed_body(input, length, max_body_bytes),
        BodyFraming::Chunked => read_chunked_body(input, max_body_bytes),
    }
}

pub fn read_chunked_body(
    input: &mut impl Read,
    max_body_bytes: u64,
) -> Result<Vec<u8>, Http1Error> {
    let mut output = Vec::new();
    let mut total = 0_u64;
    loop {
        let line = read_crlf_line(input, MAX_CHUNK_LINE_BYTES, Http1Error::InvalidChunkedBody)?;
        let (size_text, extensions) = match line.iter().position(|byte| *byte == b';') {
            Some(index) => (&line[..index], &line[index..]),
            None => (line.as_slice(), [].as_slice()),
        };
        if size_text.is_empty() || !size_text.iter().all(u8::is_ascii_hexdigit) {
            return Err(Http1Error::InvalidChunkedBody);
        }
        validate_chunk_extensions(extensions)?;
        let size_text =
            std::str::from_utf8(size_text).map_err(|_| Http1Error::InvalidChunkedBody)?;
        let size =
            u64::from_str_radix(size_text, 16).map_err(|_| Http1Error::InvalidChunkedBody)?;
        if size == 0 {
            read_chunk_trailers(input)?;
            return Ok(output);
        }
        total = total.checked_add(size).ok_or(Http1Error::BodyTooLarge)?;
        if total > max_body_bytes {
            return Err(Http1Error::BodyTooLarge);
        }
        let size_usize = usize::try_from(size).map_err(|_| Http1Error::BodyTooLarge)?;
        let start = output.len();
        let end = start
            .checked_add(size_usize)
            .ok_or(Http1Error::BodyTooLarge)?;
        output
            .try_reserve(size_usize)
            .map_err(|_| Http1Error::BodyTooLarge)?;
        output.resize(end, 0);
        read_exact_body(input, &mut output[start..end])?;
        let mut crlf = [0_u8; 2];
        read_exact_body(input, &mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(Http1Error::InvalidChunkedBody);
        }
    }
}

/// Removes proxy credentials, all `Proxy-*` and `X-HNS-*` fields, standard
/// hop-by-hop fields, and fields nominated by `Connection`/`Proxy-Connection`.
pub fn sanitize_forward_headers(headers: &[Header]) -> Result<Vec<Header>, Http1Error> {
    let nominated = connection_nominated_fields(headers)?;

    Ok(headers
        .iter()
        .filter(|header| {
            let lower = header.name.to_ascii_lowercase();
            !is_hop_by_hop(&lower)
                && !lower.starts_with("proxy-")
                && !lower.starts_with("x-hns-")
                && !nominated.contains(&lower)
        })
        .cloned()
        .collect())
}

/// Removes all proxy/internal/framing fields from a WebSocket handshake while
/// preserving end-to-end WebSocket fields and reconstructing the two required
/// hop-by-hop fields canonically.
pub fn sanitize_upgrade_forward_headers(headers: &[Header]) -> Result<Vec<Header>, Http1Error> {
    let nominated = connection_nominated_fields(headers)?;
    let connection_upgrade = headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("connection")
            && header
                .value
                .split(',')
                .map(str::trim)
                .any(|token| token.eq_ignore_ascii_case("upgrade"))
    });
    let upgrade_values: Vec<_> = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("upgrade"))
        .map(|header| header.value.as_str())
        .collect();
    if !connection_upgrade
        || upgrade_values.len() != 1
        || !upgrade_values[0].eq_ignore_ascii_case("websocket")
    {
        return Err(Http1Error::InvalidHeader);
    }

    let mut sanitized: Vec<_> = headers
        .iter()
        .filter(|header| {
            let lower = header.name.to_ascii_lowercase();
            !is_hop_by_hop(&lower)
                && !lower.starts_with("proxy-")
                && !lower.starts_with("x-hns-")
                && !nominated.contains(&lower)
        })
        .cloned()
        .collect();
    sanitized.push(Header {
        name: "Connection".to_owned(),
        value: "Upgrade".to_owned(),
    });
    sanitized.push(Header {
        name: "Upgrade".to_owned(),
        value: "websocket".to_owned(),
    });
    Ok(sanitized)
}

fn connection_nominated_fields(headers: &[Header]) -> Result<HashSet<String>, Http1Error> {
    let mut nominated = HashSet::new();
    for header in headers.iter().filter(|header| {
        header.name.eq_ignore_ascii_case("connection")
            || header.name.eq_ignore_ascii_case("proxy-connection")
    }) {
        for token in header.value.split(',').map(str::trim) {
            if token.is_empty() || !is_http_token(token.as_bytes()) {
                return Err(Http1Error::InvalidHeader);
            }
            nominated.insert(token.to_ascii_lowercase());
        }
    }
    Ok(nominated)
}

fn parse_request_line(bytes: &[u8]) -> Result<(String, String, HttpVersion), Http1Error> {
    if !bytes.is_ascii() || bytes.contains(&b'\t') {
        return Err(Http1Error::InvalidRequestLine);
    }
    let mut parts = bytes.split(|byte| *byte == b' ');
    let method = parts.next().ok_or(Http1Error::InvalidRequestLine)?;
    let target = parts.next().ok_or(Http1Error::InvalidRequestLine)?;
    let version = parts.next().ok_or(Http1Error::InvalidRequestLine)?;
    if parts.next().is_some()
        || !is_http_token(method)
        || target.is_empty()
        || !target.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(Http1Error::InvalidRequestLine);
    }
    let version = match version {
        b"HTTP/1.0" => HttpVersion::Http10,
        b"HTTP/1.1" => HttpVersion::Http11,
        bytes if bytes.starts_with(b"HTTP/") => return Err(Http1Error::UnsupportedHttpVersion),
        _ => return Err(Http1Error::InvalidRequestLine),
    };
    Ok((
        String::from_utf8(method.to_vec()).map_err(|_| Http1Error::InvalidRequestLine)?,
        String::from_utf8(target.to_vec()).map_err(|_| Http1Error::InvalidRequestLine)?,
        version,
    ))
}

fn parse_header_block(bytes: &[u8]) -> Result<Vec<Header>, Http1Error> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut headers = Vec::new();
    for raw_line in bytes.split(|byte| *byte == b'\n') {
        if raw_line.is_empty() {
            // `bytes` includes the last field's CRLF, so `split` has one
            // terminal empty item. An earlier empty line cannot reach here:
            // `find_head_end` would already have treated it as the head end.
            continue;
        }
        let Some(line) = raw_line.strip_suffix(b"\r") else {
            return Err(Http1Error::InvalidHeader);
        };
        if line.is_empty() || matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(Http1Error::InvalidHeader);
        }
        let separator = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(Http1Error::InvalidHeader)?;
        let name = &line[..separator];
        let value = trim_ows(&line[separator + 1..]);
        if !is_http_token(name) || !is_valid_field_value(value) {
            return Err(Http1Error::InvalidHeader);
        }
        if headers.len() == MAX_REQUEST_HEADERS {
            return Err(Http1Error::TooManyHeaders);
        }
        headers.push(Header {
            name: String::from_utf8(name.to_vec()).map_err(|_| Http1Error::InvalidHeader)?,
            value: String::from_utf8(value.to_vec()).map_err(|_| Http1Error::InvalidHeader)?,
        });
    }
    Ok(headers)
}

fn parse_request_target(
    method: &str,
    target: &str,
    connected_to: Option<&Authority>,
) -> Result<RequestTarget, Http1Error> {
    if method.eq_ignore_ascii_case("CONNECT") {
        if connected_to.is_some() {
            return Err(Http1Error::TargetMismatch);
        }
        return parse_authority(target, None, true).map(RequestTarget::Connect);
    }
    if let Some(connected_to) = connected_to {
        if target.starts_with('/') {
            if target.contains('#') {
                return Err(Http1Error::InvalidTarget);
            }
            return Ok(RequestTarget::Origin(OriginTarget {
                authority: connected_to.clone(),
                path_and_query: target.to_owned(),
            }));
        }
        let absolute = parse_absolute_target(target)?;
        if !absolute.scheme.is_secure() || absolute.authority != *connected_to {
            return Err(Http1Error::TargetMismatch);
        }
        return Ok(RequestTarget::Absolute(absolute));
    }
    parse_absolute_target(target).map(RequestTarget::Absolute)
}

fn parse_absolute_target(target: &str) -> Result<AbsoluteTarget, Http1Error> {
    let (scheme_text, remainder) = target.split_once("://").ok_or(Http1Error::InvalidTarget)?;
    let scheme = if scheme_text.eq_ignore_ascii_case("http") {
        Scheme::Http
    } else if scheme_text.eq_ignore_ascii_case("https") {
        Scheme::Https
    } else if scheme_text.eq_ignore_ascii_case("ws") {
        Scheme::Ws
    } else if scheme_text.eq_ignore_ascii_case("wss") {
        Scheme::Wss
    } else {
        return Err(Http1Error::InvalidTarget);
    };
    if remainder.contains('#') || remainder.contains('\\') {
        return Err(Http1Error::InvalidTarget);
    }
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority_text = &remainder[..authority_end];
    let suffix = &remainder[authority_end..];
    let authority = parse_authority(authority_text, Some(scheme.default_port()), false)?;
    let path_and_query = if suffix.is_empty() {
        "/".to_owned()
    } else if suffix.starts_with('?') {
        format!("/{suffix}")
    } else {
        suffix.to_owned()
    };
    Ok(AbsoluteTarget {
        scheme,
        authority,
        path_and_query,
    })
}

fn parse_authority(
    value: &str,
    default_port: Option<u16>,
    require_explicit_port: bool,
) -> Result<Authority, Http1Error> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || value.contains('@')
        || value.contains('/')
        || value.contains('?')
        || value.contains('#')
        || value.contains('\\')
    {
        return Err(Http1Error::InvalidAuthority);
    }

    let (host, port_text) = if let Some(bracketed) = value.strip_prefix('[') {
        let close = bracketed.find(']').ok_or(Http1Error::InvalidAuthority)?;
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or(Http1Error::InvalidAuthority)?,
            )
        };
        if host.parse::<Ipv6Addr>().is_err() {
            return Err(Http1Error::InvalidAuthority);
        }
        (host, port)
    } else {
        if value.matches(':').count() > 1 {
            return Err(Http1Error::InvalidAuthority);
        }
        match value.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (value, None),
        }
    };
    if host.is_empty() || (require_explicit_port && port_text.is_none()) {
        return Err(Http1Error::InvalidAuthority);
    }
    let port = match port_text {
        Some(text) if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) => text
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(Http1Error::InvalidAuthority)?,
        Some(_) => return Err(Http1Error::InvalidAuthority),
        None => default_port.ok_or(Http1Error::InvalidAuthority)?,
    };
    Ok(Authority {
        host: normalize_host(host)?,
        port,
    })
}

fn normalize_host(host: &str) -> Result<String, Http1Error> {
    if let Ok(address) = host.parse::<Ipv6Addr>() {
        return Ok(address.to_string());
    }
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return Ok(address.to_string());
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(Http1Error::InvalidAuthority);
    }
    let ascii = idna::domain_to_ascii_cow(host.as_bytes(), idna::AsciiDenyList::URL)
        .map_err(|_| Http1Error::InvalidAuthority)?;
    let mut ascii = ascii.to_ascii_lowercase();
    // One terminal root dot is equivalent. Multiple terminal dots contain an
    // empty DNS label and must not collapse to the same authorization scope.
    if ascii.ends_with('.') {
        ascii.pop();
    }
    if ascii.is_empty() || ascii.len() > 253 {
        return Err(Http1Error::InvalidAuthority);
    }
    for label in ascii.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Http1Error::InvalidAuthority);
        }
    }
    Ok(ascii)
}

fn parse_content_length(value: &str) -> Result<u64, Http1Error> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Http1Error::InvalidContentLength);
    }
    value
        .parse::<u64>()
        .map_err(|_| Http1Error::InvalidContentLength)
}

fn read_fixed_body(
    input: &mut impl Read,
    length: u64,
    max_body_bytes: u64,
) -> Result<Vec<u8>, Http1Error> {
    if length > max_body_bytes {
        return Err(Http1Error::BodyTooLarge);
    }
    let length = usize::try_from(length).map_err(|_| Http1Error::BodyTooLarge)?;
    let mut body = Vec::new();
    body.try_reserve_exact(length)
        .map_err(|_| Http1Error::BodyTooLarge)?;
    body.resize(length, 0);
    read_exact_body(input, &mut body)?;
    Ok(body)
}

fn read_exact_body(input: &mut impl Read, mut bytes: &mut [u8]) -> Result<(), Http1Error> {
    while !bytes.is_empty() {
        match input.read(bytes) {
            Ok(0) => return Err(Http1Error::UnexpectedBodyEof),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Http1Error::Io(error)),
        }
    }
    Ok(())
}

fn read_crlf_line(
    input: &mut impl Read,
    limit: usize,
    limit_error: Http1Error,
) -> Result<Vec<u8>, Http1Error> {
    let mut line = Vec::with_capacity(limit.min(256));
    let mut byte = [0_u8; 1];
    while line.len() < limit {
        let read = input.read(&mut byte)?;
        if read == 0 {
            return Err(Http1Error::UnexpectedBodyEof);
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
        if byte[0] == b'\n' {
            return Err(Http1Error::InvalidChunkedBody);
        }
    }
    Err(limit_error)
}

fn read_chunk_trailers(input: &mut impl Read) -> Result<(), Http1Error> {
    let mut consumed = 0_usize;
    let mut count = 0_usize;
    loop {
        let remaining = MAX_CHUNK_TRAILER_BYTES
            .checked_sub(consumed)
            .ok_or(Http1Error::TrailersTooLarge)?;
        if remaining < 2 {
            return Err(Http1Error::TrailersTooLarge);
        }
        let line = read_crlf_line(
            input,
            remaining.min(MAX_CHUNK_LINE_BYTES),
            Http1Error::InvalidChunkedBody,
        )?;
        consumed = consumed
            .checked_add(line.len() + 2)
            .ok_or(Http1Error::TrailersTooLarge)?;
        if line.is_empty() {
            return Ok(());
        }
        count += 1;
        if count > MAX_REQUEST_HEADERS {
            return Err(Http1Error::InvalidChunkedBody);
        }
        let header = parse_single_header_line(&line)?;
        let lower = header.name.to_ascii_lowercase();
        if is_hop_by_hop(&lower)
            || lower == "content-length"
            || lower == "host"
            || lower.starts_with("proxy-")
            || lower.starts_with("x-hns-")
        {
            return Err(Http1Error::InvalidChunkedBody);
        }
    }
}

fn parse_single_header_line(line: &[u8]) -> Result<Header, Http1Error> {
    if line.is_empty() || matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(Http1Error::InvalidChunkedBody);
    }
    let separator = line
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(Http1Error::InvalidChunkedBody)?;
    let name = &line[..separator];
    let value = trim_ows(&line[separator + 1..]);
    if !is_http_token(name) || !is_valid_field_value(value) {
        return Err(Http1Error::InvalidChunkedBody);
    }
    Ok(Header {
        name: String::from_utf8(name.to_vec()).map_err(|_| Http1Error::InvalidChunkedBody)?,
        value: String::from_utf8(value.to_vec()).map_err(|_| Http1Error::InvalidChunkedBody)?,
    })
}

fn validate_chunk_extensions(mut extensions: &[u8]) -> Result<(), Http1Error> {
    while !extensions.is_empty() {
        extensions = extensions
            .strip_prefix(b";")
            .ok_or(Http1Error::InvalidChunkedBody)?;
        let end = extensions
            .iter()
            .position(|byte| *byte == b';')
            .unwrap_or(extensions.len());
        let extension = &extensions[..end];
        extensions = &extensions[end..];
        let (name, value) = match extension.iter().position(|byte| *byte == b'=') {
            Some(index) => (&extension[..index], Some(&extension[index + 1..])),
            None => (extension, None),
        };
        if !is_http_token(name) {
            return Err(Http1Error::InvalidChunkedBody);
        }
        if let Some(value) = value
            && !is_http_token(value)
            && !is_valid_quoted_string(value)
        {
            return Err(Http1Error::InvalidChunkedBody);
        }
    }
    Ok(())
}

fn is_valid_quoted_string(value: &[u8]) -> bool {
    let Some(inner) = value
        .strip_prefix(b"\"")
        .and_then(|value| value.strip_suffix(b"\""))
    else {
        return false;
    };
    let mut escaped = false;
    for byte in inner {
        if escaped {
            if !matches!(*byte, b'\t' | b' '..=b'~') {
                return false;
            }
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if !matches!(*byte, b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~') {
            return false;
        }
    }
    !escaped
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(HEAD_END.len())
        .position(|window| window == HEAD_END)
        .map(|index| index + HEAD_END.len())
}

fn validate_crlf(bytes: &[u8]) -> Result<(), Http1Error> {
    for (index, byte) in bytes.iter().enumerate() {
        if (*byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'))
            || (*byte == b'\n' && index.checked_sub(1).and_then(|i| bytes.get(i)) != Some(&b'\r'))
        {
            return Err(Http1Error::InvalidHeader);
        }
    }
    Ok(())
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_http_token(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(|byte| {
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

fn is_valid_field_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| matches!(*byte, b'\t' | b' '..=b'~'))
}

fn is_hop_by_hop(lower_name: &str) -> bool {
    matches!(
        lower_name,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(text: &str) -> RequestHead {
        parse_request_head(text.as_bytes()).unwrap()
    }

    #[test]
    fn parses_absolute_target_and_preserves_only_routed_path_and_query() {
        let head = parse(
            "GET https://Welcome:8443/private?q=secret HTTP/1.1\r\nHost: welcome:8443\r\n\r\n",
        );
        let RequestTarget::Absolute(target) = head.validated_target(None).unwrap() else {
            panic!("expected absolute target");
        };
        assert_eq!(target.scheme(), Scheme::Https);
        assert_eq!(target.authority().host(), "welcome");
        assert_eq!(target.authority().port(), 8443);
        assert_eq!(target.path_and_query(), "/private?q=secret");
        assert!(!format!("{head:?}").contains("secret"));
        assert!(!format!("{target:?}").contains("private"));
    }

    #[test]
    fn parses_connect_and_post_connect_origin_form() {
        let connect = parse("CONNECT welcome:443 HTTP/1.1\r\nHost: welcome:443\r\n\r\n");
        let RequestTarget::Connect(authority) = connect.validated_target(None).unwrap() else {
            panic!("expected CONNECT target");
        };
        let tunneled =
            parse("POST /submit?q=1 HTTP/1.1\r\nHost: welcome\r\nContent-Length: 2\r\n\r\n");
        let RequestTarget::Origin(target) = tunneled.validated_target(Some(&authority)).unwrap()
        else {
            panic!("expected origin target");
        };
        assert_eq!(target.path_and_query(), "/submit?q=1");
    }

    #[test]
    fn rejects_direct_origin_form_and_mismatched_connected_absolute_form() {
        let origin = parse("GET / HTTP/1.1\r\nHost: welcome\r\n\r\n");
        assert!(matches!(
            origin.request_target(None),
            Err(Http1Error::InvalidTarget)
        ));
        let authority = Authority::parse("welcome", 443).unwrap();
        let other = parse("GET https://other/ HTTP/1.1\r\nHost: other\r\n\r\n");
        assert!(matches!(
            other.request_target(Some(&authority)),
            Err(Http1Error::TargetMismatch)
        ));
    }

    #[test]
    fn rejects_host_mismatch_duplicates_and_missing_http11_host() {
        let mismatch = parse("GET http://welcome/ HTTP/1.1\r\nHost: other\r\n\r\n");
        assert!(matches!(
            mismatch.validated_target(None),
            Err(Http1Error::HostMismatch)
        ));
        let duplicate =
            parse("GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\nHost: welcome\r\n\r\n");
        assert!(matches!(
            duplicate.validated_target(None),
            Err(Http1Error::HostMismatch)
        ));
        let missing = parse("GET http://welcome/ HTTP/1.1\r\nUser-Agent: test\r\n\r\n");
        assert!(matches!(
            missing.validated_target(None),
            Err(Http1Error::MissingHost)
        ));
    }

    #[test]
    fn rejects_request_line_header_and_version_smuggling() {
        for request in [
            "GET  http://welcome/ HTTP/1.1\r\nHost: welcome\r\n\r\n",
            "GET http://welcome/ HTTP/2.0\r\nHost: welcome\r\n\r\n",
            "GET http://welcome/ HTTP/1.1\nHost: welcome\n\n",
            "GET http://welcome/ HTTP/1.1\r\nBad Name: value\r\n\r\n",
            "GET http://welcome/ HTTP/1.1\r\n Folded: value\r\n\r\n",
            "GET http://welcome/ HTTP/1.1\r\nX-Test: bad\u{7f}\r\n\r\n",
        ] {
            assert!(
                parse_request_head(request.as_bytes()).is_err(),
                "accepted {request:?}"
            );
        }
    }

    #[test]
    fn bounded_reader_does_not_consume_a_coalesced_body() {
        let mut input = Cursor::new(
            b"POST http://welcome/upload HTTP/1.1\r\nHost: welcome\r\nContent-Length: 4\r\n\r\ndataafter"
                .to_vec(),
        );
        let head = read_request_head(&mut input, DEFAULT_MAX_REQUEST_HEAD_BYTES).unwrap();
        let framing = determine_body_framing(head.headers()).unwrap();
        assert_eq!(
            read_request_body(&mut input, framing, 1024).unwrap(),
            b"data"
        );
        let mut remainder = String::new();
        input.read_to_string(&mut remainder).unwrap();
        assert_eq!(remainder, "after");
    }

    #[test]
    fn fixed_body_reader_enforces_cap_and_exact_length() {
        assert!(matches!(
            read_request_body(&mut Cursor::new(b"data"), BodyFraming::ContentLength(4), 3,),
            Err(Http1Error::BodyTooLarge)
        ));
        assert!(matches!(
            read_request_body(&mut Cursor::new(b"abc"), BodyFraming::ContentLength(4), 4,),
            Err(Http1Error::UnexpectedBodyEof)
        ));
    }

    #[test]
    fn enforces_head_and_header_count_limits() {
        let request = "GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n\r\n";
        let mut input = Cursor::new(request.as_bytes());
        assert!(matches!(
            read_request_head(&mut input, 8),
            Err(Http1Error::HeadTooLarge)
        ));

        let mut many = String::from("GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\n");
        for index in 0..MAX_REQUEST_HEADERS {
            many.push_str(&format!("X-{index}: x\r\n"));
        }
        many.push_str("\r\n");
        assert!(matches!(
            parse_request_head(many.as_bytes()),
            Err(Http1Error::TooManyHeaders)
        ));
    }

    #[test]
    fn rejects_duplicate_conflicting_and_ambiguous_lengths() {
        for request in [
            "POST http://welcome/ HTTP/1.1\r\nHost: welcome\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n",
            "POST http://welcome/ HTTP/1.1\r\nHost: welcome\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n",
            "POST http://welcome/ HTTP/1.1\r\nHost: welcome\r\nContent-Length: +2\r\n\r\n",
        ] {
            let head = parse(request);
            assert!(matches!(
                determine_body_framing(head.headers()),
                Err(Http1Error::InvalidContentLength)
            ));
        }
        let ambiguous = parse(
            "POST http://welcome/ HTTP/1.1\r\nHost: welcome\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert!(matches!(
            determine_body_framing(ambiguous.headers()),
            Err(Http1Error::AmbiguousFraming)
        ));
    }

    #[test]
    fn only_a_single_chunked_transfer_coding_is_supported() {
        let chunked = parse(
            "POST http://welcome/ HTTP/1.1\r\nHost: welcome\r\nTransfer-Encoding: ChUnKeD\r\n\r\n",
        );
        assert_eq!(
            determine_body_framing(chunked.headers()).unwrap(),
            BodyFraming::Chunked
        );
        for value in [
            "gzip",
            "gzip, chunked",
            "chunked, chunked",
            "chunked;foo=bar",
            "",
        ] {
            let request = format!(
                "POST http://welcome/ HTTP/1.1\r\nHost: welcome\r\nTransfer-Encoding: {value}\r\n\r\n"
            );
            let head = parse(&request);
            assert!(matches!(
                determine_body_framing(head.headers()),
                Err(Http1Error::UnsupportedTransferEncoding)
            ));
        }
    }

    #[test]
    fn decodes_chunked_body_and_consumes_bounded_valid_trailers() {
        let mut input = Cursor::new(
            b"4;kind=test\r\nWiki\r\n5\r\npedia\r\n0\r\nDigest: value\r\n\r\nafter".to_vec(),
        );
        assert_eq!(read_chunked_body(&mut input, 1024).unwrap(), b"Wikipedia");
        let mut remainder = String::new();
        input.read_to_string(&mut remainder).unwrap();
        assert_eq!(remainder, "after");
    }

    #[test]
    fn rejects_bad_chunk_syntax_forbidden_trailers_and_body_overflow() {
        for body in [
            "x\r\n",
            "1\r\naX\r\n0\r\n\r\n",
            "1\na\r\n0\r\n\r\n",
            "0\r\nContent-Length: 1\r\n\r\n",
            "0\r\nX-HNS-Secret: value\r\n\r\n",
        ] {
            assert!(read_chunked_body(&mut Cursor::new(body.as_bytes()), 1024).is_err());
        }
        assert!(matches!(
            read_chunked_body(&mut Cursor::new(b"5\r\nhello\r\n0\r\n\r\n"), 4),
            Err(Http1Error::BodyTooLarge)
        ));
    }

    #[test]
    fn retains_duplicate_proxy_credentials_for_uniform_authentication_rejection() {
        let request = b"GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\nProxy-Authorization: first\r\nProxy-Authorization: second\r\n\r\n";
        let head = parse_request_head(request).unwrap();

        assert!(matches!(
            head.proxy_authorization(),
            Err(Http1Error::DuplicateProxyAuthorization)
        ));
        assert_eq!(head.header_values("proxy-authorization").count(), 2);
    }

    #[test]
    fn sanitizer_removes_hop_proxy_internal_and_connection_nominated_fields() {
        let head = parse(
            "GET http://welcome/ HTTP/1.1\r\nHost: welcome\r\nProxy-Authorization: secret\r\nProxy-Future: secret\r\nX-HNS-Security-Path: forged\r\nX-HNS-Future: secret\r\nConnection: keep-alive, X-Remove\r\nX-Remove: secret\r\nKeep-Alive: timeout=5\r\nTransfer-Encoding: chunked\r\nX-Keep: yes\r\n\r\n",
        );
        assert_eq!(head.proxy_authorization().unwrap(), Some("secret"));
        let sanitized = sanitize_forward_headers(head.headers()).unwrap();
        assert_eq!(sanitized.len(), 2);
        assert_eq!(sanitized[0].name(), "Host");
        assert_eq!(sanitized[1].name(), "X-Keep");
        assert!(!format!("{head:?}").contains("secret"));
        assert!(!format!("{:?}", head.headers()).contains("secret"));
    }

    #[test]
    fn upgrade_sanitizer_reconstructs_websocket_hop_fields() {
        let head = parse(
            "GET ws://welcome/socket HTTP/1.1\r\nHost: welcome\r\nConnection: keep-alive, Upgrade, X-Hop\r\nUpgrade: websocket\r\nX-Hop: secret\r\nSec-WebSocket-Key: key\r\nProxy-Authorization: secret\r\nX-HNS-Trace: secret\r\n\r\n",
        );

        let sanitized = sanitize_upgrade_forward_headers(head.headers()).unwrap();
        let pairs: Vec<_> = sanitized
            .iter()
            .map(|header| (header.name(), header.value()))
            .collect();

        assert!(pairs.contains(&("Host", "welcome")));
        assert!(pairs.contains(&("Sec-WebSocket-Key", "key")));
        assert!(pairs.contains(&("Connection", "Upgrade")));
        assert!(pairs.contains(&("Upgrade", "websocket")));
        assert!(
            !pairs
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("X-Hop"))
        );
        assert!(
            !pairs
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("Proxy-Authorization"))
        );
        assert!(
            !pairs
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("X-HNS-Trace"))
        );
    }

    #[test]
    fn upgrade_sanitizer_requires_a_complete_websocket_signal() {
        for request in [
            "GET / HTTP/1.1\r\nHost: welcome\r\nUpgrade: websocket\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: welcome\r\nConnection: Upgrade\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: welcome\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
        ] {
            assert!(matches!(
                sanitize_upgrade_forward_headers(parse(request).headers()),
                Err(Http1Error::InvalidHeader)
            ));
        }
    }

    #[test]
    fn normalizes_idna_trailing_dot_and_ipv6_authorities() {
        let unicode = Authority::parse("B\u{00fc}cher.Example.", 443).unwrap();
        assert_eq!(unicode.host(), "xn--bcher-kva.example");
        assert!(Authority::parse("welcome..", 443).is_err());
        let ipv6 = Authority::parse("[2001:0db8::1]:8443", 443).unwrap();
        assert_eq!(ipv6.host(), "2001:db8::1");
        assert_eq!(ipv6.host_header(443), "[2001:db8::1]:8443");
    }

    #[test]
    fn maps_framing_errors_to_stable_http_responses() {
        assert_eq!(Http1Error::BodyTooLarge.status_code(), 413);
        assert_eq!(Http1Error::UnsupportedTransferEncoding.status_code(), 501);
        assert_eq!(Http1Error::AmbiguousFraming.status_code(), 400);
        assert_eq!(
            Http1Error::InvalidContentLength.reason_phrase(),
            "Bad Content-Length"
        );
    }
}
