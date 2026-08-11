use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

use crate::LocalCertificateAuthority;
use crate::host::HostScope;

const SESSION_ID_RANDOM_BYTES: usize = 16;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ProxySessionId {
    bytes: [u8; SESSION_ID_RANDOM_BYTES],
    token: String,
}

impl ProxySessionId {
    pub fn generate() -> Result<Self, SessionIdGenerationError> {
        let mut bytes = [0_u8; SESSION_ID_RANDOM_BYTES];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| SessionIdGenerationError)?;
        Self::from_bytes(bytes)
    }

    /// Constructs one checked session while preserving the existing
    /// URL-safe, unpadded platform token representation.
    pub fn from_bytes(
        bytes: [u8; SESSION_ID_RANDOM_BYTES],
    ) -> Result<Self, SessionIdGenerationError> {
        if bytes == [0; SESSION_ID_RANDOM_BYTES] {
            return Err(SessionIdGenerationError);
        }
        Ok(Self {
            token: URL_SAFE_NO_PAD.encode(bytes),
            bytes,
        })
    }

    /// Exact nonzero bytes shared with the canonical browser runtime.
    pub const fn as_bytes(&self) -> &[u8; SESSION_ID_RANDOM_BYTES] {
        &self.bytes
    }

    /// Explicitly exposes the opaque token for platform boundary serialization.
    pub fn as_str(&self) -> &str {
        &self.token
    }
}

impl std::fmt::Debug for ProxySessionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProxySessionId([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProxyInstanceId {
    session: ProxySessionId,
    generation: u64,
}

impl ProxyInstanceId {
    pub fn new(session: ProxySessionId, generation: u64) -> Self {
        Self {
            session,
            generation,
        }
    }

    pub fn session(&self) -> &ProxySessionId {
        &self.session
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum LoopbackBind {
    #[default]
    Ipv4,
}

/// Determines which browser requests one proxy generation may route.
///
/// `DaneBrowser` is the Chromium release mode: every canonical DNS host
/// reaches the same Rust request boundary for dual-root resolution,
/// DNSSEC/TLSA discovery, and origin trust selection. `ScopedHns` remains as a
/// narrow internal substrate for host-scope unit and integration coverage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProxyRoutingMode {
    #[default]
    ScopedHns,
    DaneBrowser,
}

impl LoopbackBind {
    pub const fn socket_addr(self) -> SocketAddrV4 {
        match self {
            Self::Ipv4 => SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyLimits {
    max_header_bytes: usize,
    max_body_bytes: u64,
    max_active_clients: usize,
    max_requests_per_window: usize,
    max_requests_per_host_per_window: usize,
    max_tracked_hosts: usize,
    rate_window: Duration,
}

impl ProxyLimits {
    pub const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
    pub const DEFAULT_MAX_BODY_BYTES: u64 = 1024 * 1024;
    pub const DEFAULT_MAX_ACTIVE_CLIENTS: usize = 64;
    pub const DEFAULT_MAX_REQUESTS_PER_WINDOW: usize = 240;
    pub const DEFAULT_MAX_REQUESTS_PER_HOST_PER_WINDOW: usize =
        Self::DEFAULT_MAX_REQUESTS_PER_WINDOW;
    pub const DEFAULT_MAX_TRACKED_HOSTS: usize = 256;
    pub const DEFAULT_RATE_WINDOW: Duration = Duration::from_secs(10);

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_header_bytes: usize,
        max_body_bytes: u64,
        max_active_clients: usize,
        max_requests_per_window: usize,
        max_requests_per_host_per_window: usize,
        max_tracked_hosts: usize,
        rate_window: Duration,
    ) -> Result<Self, ProxyLimitsError> {
        require_nonzero(max_header_bytes, "max_header_bytes")?;
        require_at_most(
            max_header_bytes,
            Self::DEFAULT_MAX_HEADER_BYTES,
            "max_header_bytes",
        )?;
        if max_body_bytes == 0 {
            return Err(ProxyLimitsError::Zero("max_body_bytes"));
        }
        if max_body_bytes > Self::DEFAULT_MAX_BODY_BYTES {
            return Err(ProxyLimitsError::ExceedsMaximum("max_body_bytes"));
        }
        require_nonzero(max_active_clients, "max_active_clients")?;
        require_at_most(
            max_active_clients,
            Self::DEFAULT_MAX_ACTIVE_CLIENTS,
            "max_active_clients",
        )?;
        require_nonzero(max_requests_per_window, "max_requests_per_window")?;
        require_at_most(
            max_requests_per_window,
            Self::DEFAULT_MAX_REQUESTS_PER_WINDOW,
            "max_requests_per_window",
        )?;
        require_nonzero(
            max_requests_per_host_per_window,
            "max_requests_per_host_per_window",
        )?;
        require_at_most(
            max_requests_per_host_per_window,
            Self::DEFAULT_MAX_REQUESTS_PER_HOST_PER_WINDOW,
            "max_requests_per_host_per_window",
        )?;
        require_nonzero(max_tracked_hosts, "max_tracked_hosts")?;
        require_at_most(
            max_tracked_hosts,
            Self::DEFAULT_MAX_TRACKED_HOSTS,
            "max_tracked_hosts",
        )?;
        if rate_window.is_zero() {
            return Err(ProxyLimitsError::Zero("rate_window"));
        }
        if rate_window > Self::DEFAULT_RATE_WINDOW {
            return Err(ProxyLimitsError::ExceedsMaximum("rate_window"));
        }
        if max_requests_per_host_per_window > max_requests_per_window {
            return Err(ProxyLimitsError::PerHostExceedsGlobal);
        }

        Ok(Self {
            max_header_bytes,
            max_body_bytes,
            max_active_clients,
            max_requests_per_window,
            max_requests_per_host_per_window,
            max_tracked_hosts,
            rate_window,
        })
    }

    pub const fn max_header_bytes(self) -> usize {
        self.max_header_bytes
    }

    pub const fn max_body_bytes(self) -> u64 {
        self.max_body_bytes
    }

    pub const fn max_active_clients(self) -> usize {
        self.max_active_clients
    }

    pub const fn max_requests_per_window(self) -> usize {
        self.max_requests_per_window
    }

    pub const fn max_requests_per_host_per_window(self) -> usize {
        self.max_requests_per_host_per_window
    }

    pub const fn max_tracked_hosts(self) -> usize {
        self.max_tracked_hosts
    }

    pub const fn rate_window(self) -> Duration {
        self.rate_window
    }
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: Self::DEFAULT_MAX_HEADER_BYTES,
            max_body_bytes: Self::DEFAULT_MAX_BODY_BYTES,
            max_active_clients: Self::DEFAULT_MAX_ACTIVE_CLIENTS,
            max_requests_per_window: Self::DEFAULT_MAX_REQUESTS_PER_WINDOW,
            max_requests_per_host_per_window: Self::DEFAULT_MAX_REQUESTS_PER_HOST_PER_WINDOW,
            max_tracked_hosts: Self::DEFAULT_MAX_TRACKED_HOSTS,
            rate_window: Self::DEFAULT_RATE_WINDOW,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyTimeouts {
    request_header_timeout: Duration,
    socket_timeout: Duration,
}

impl ProxyTimeouts {
    pub const DEFAULT_REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
    pub const DEFAULT_SOCKET_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn new(
        request_header_timeout: Duration,
        socket_timeout: Duration,
    ) -> Result<Self, ProxyTimeoutsError> {
        if request_header_timeout.is_zero() {
            return Err(ProxyTimeoutsError::Zero("request_header_timeout"));
        }
        if socket_timeout.is_zero() {
            return Err(ProxyTimeoutsError::Zero("socket_timeout"));
        }
        if request_header_timeout > socket_timeout {
            return Err(ProxyTimeoutsError::HeaderExceedsSocket);
        }
        if request_header_timeout > Self::DEFAULT_REQUEST_HEADER_TIMEOUT {
            return Err(ProxyTimeoutsError::ExceedsMaximum("request_header_timeout"));
        }
        if socket_timeout > Self::DEFAULT_SOCKET_TIMEOUT {
            return Err(ProxyTimeoutsError::ExceedsMaximum("socket_timeout"));
        }
        Ok(Self {
            request_header_timeout,
            socket_timeout,
        })
    }

    pub const fn request_header_timeout(self) -> Duration {
        self.request_header_timeout
    }

    pub const fn socket_timeout(self) -> Duration {
        self.socket_timeout
    }
}

impl Default for ProxyTimeouts {
    fn default() -> Self {
        Self {
            request_header_timeout: Self::DEFAULT_REQUEST_HEADER_TIMEOUT,
            socket_timeout: Self::DEFAULT_SOCKET_TIMEOUT,
        }
    }
}

/// Immutable configuration for one proxy generation.
///
/// Authentication is intentionally absent: `RunningProxy` must generate a mandatory fresh
/// [`crate::auth::ProxyAuthorization`] when it starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyConfig {
    instance: ProxyInstanceId,
    hns_scope: Option<HostScope>,
    local_certificate_authority: Option<LocalCertificateAuthority>,
    limits: ProxyLimits,
    timeouts: ProxyTimeouts,
    bind: LoopbackBind,
    routing_mode: ProxyRoutingMode,
}

impl ProxyConfig {
    pub fn new(instance: ProxyInstanceId, scope: HostScope) -> Self {
        Self {
            instance,
            hns_scope: Some(scope),
            local_certificate_authority: None,
            limits: ProxyLimits::default(),
            timeouts: ProxyTimeouts::default(),
            bind: LoopbackBind::default(),
            routing_mode: ProxyRoutingMode::default(),
        }
    }

    /// Creates a Chromium-style generation which admits canonical HNS and
    /// ICANN DNS names to the native gateway while rejecting special-use,
    /// search, and IP-literal targets.
    pub fn dane_browser(instance: ProxyInstanceId) -> Self {
        Self {
            instance,
            hns_scope: None,
            local_certificate_authority: None,
            limits: ProxyLimits::default(),
            timeouts: ProxyTimeouts::default(),
            bind: LoopbackBind::default(),
            routing_mode: ProxyRoutingMode::DaneBrowser,
        }
    }

    pub fn with_controls(
        instance: ProxyInstanceId,
        scope: HostScope,
        limits: ProxyLimits,
        timeouts: ProxyTimeouts,
        bind: LoopbackBind,
    ) -> Self {
        Self {
            instance,
            hns_scope: Some(scope),
            local_certificate_authority: None,
            limits,
            timeouts,
            bind,
            routing_mode: ProxyRoutingMode::default(),
        }
    }

    pub fn instance(&self) -> &ProxyInstanceId {
        &self.instance
    }

    pub fn with_local_certificate_authority(
        mut self,
        certificate_authority: LocalCertificateAuthority,
    ) -> Self {
        self.local_certificate_authority = Some(certificate_authority);
        self
    }

    pub fn local_certificate_authority(&self) -> Option<&LocalCertificateAuthority> {
        self.local_certificate_authority.as_ref()
    }

    pub fn hns_scope(&self) -> Option<&HostScope> {
        self.hns_scope.as_ref()
    }

    pub const fn limits(&self) -> ProxyLimits {
        self.limits
    }

    pub const fn timeouts(&self) -> ProxyTimeouts {
        self.timeouts
    }

    pub const fn bind(&self) -> LoopbackBind {
        self.bind
    }

    pub const fn routing_mode(&self) -> ProxyRoutingMode {
        self.routing_mode
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("the operating-system random number generator failed")]
pub struct SessionIdGenerationError;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProxyLimitsError {
    #[error("{0} must be nonzero")]
    Zero(&'static str),
    #[error("{0} exceeds the hard proxy maximum")]
    ExceedsMaximum(&'static str),
    #[error("the per-host request limit cannot exceed the global request limit")]
    PerHostExceedsGlobal,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProxyTimeoutsError {
    #[error("{0} must be nonzero")]
    Zero(&'static str),
    #[error("{0} exceeds the hard proxy maximum")]
    ExceedsMaximum(&'static str),
    #[error("the request-header timeout cannot exceed the socket timeout")]
    HeaderExceedsSocket,
}

fn require_nonzero(value: usize, name: &'static str) -> Result<(), ProxyLimitsError> {
    if value == 0 {
        Err(ProxyLimitsError::Zero(name))
    } else {
        Ok(())
    }
}

fn require_at_most(
    value: usize,
    maximum: usize,
    name: &'static str,
) -> Result<(), ProxyLimitsError> {
    if value > maximum {
        Err(ProxyLimitsError::ExceedsMaximum(name))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_fresh_and_debug_redacted() {
        let first = ProxySessionId::generate().unwrap();
        let second = ProxySessionId::generate().unwrap();

        assert_ne!(first, second);
        assert_ne!(first.as_bytes(), &[0; SESSION_ID_RANDOM_BYTES]);
        assert!(!first.as_str().is_empty());
        assert!(!format!("{first:?}").contains(first.as_str()));
    }

    #[test]
    fn checked_session_bytes_retain_the_frozen_base64url_token() {
        let bytes = [0xabu8; SESSION_ID_RANDOM_BYTES];
        let session = ProxySessionId::from_bytes(bytes).unwrap();

        assert_eq!(session.as_bytes(), &bytes);
        assert_eq!(session.as_str(), "q6urq6urq6urq6urq6urqw");
        assert_eq!(
            ProxySessionId::from_bytes([0; SESSION_ID_RANDOM_BYTES]),
            Err(SessionIdGenerationError)
        );
        assert!(!format!("{session:?}").contains(session.as_str()));
    }

    #[test]
    fn instance_debug_preserves_generation_but_redacts_session() {
        let instance = ProxyInstanceId::new(ProxySessionId::generate().unwrap(), 7);
        let debug = format!("{instance:?}");

        assert!(debug.contains("generation: 7"));
        assert!(!debug.contains(instance.session().as_str()));
    }

    #[test]
    fn bind_is_always_ipv4_loopback_and_allows_ephemeral_port() {
        assert_eq!(
            LoopbackBind::Ipv4.socket_addr(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)
        );
    }

    #[test]
    fn default_limits_match_the_android_parity_envelope() {
        let limits = ProxyLimits::default();

        assert_eq!(limits.max_header_bytes(), 64 * 1024);
        assert_eq!(limits.max_body_bytes(), 1024 * 1024);
        assert_eq!(limits.max_active_clients(), 64);
        assert_eq!(limits.max_requests_per_window(), 240);
        assert_eq!(limits.max_requests_per_host_per_window(), 240);
        assert_eq!(limits.max_tracked_hosts(), 256);
        assert_eq!(limits.rate_window(), Duration::from_secs(10));
    }

    #[test]
    fn custom_limits_reject_zero_and_incoherent_values() {
        assert_eq!(
            ProxyLimits::new(0, 1, 1, 1, 1, 1, Duration::from_secs(1)),
            Err(ProxyLimitsError::Zero("max_header_bytes"))
        );
        assert_eq!(
            ProxyLimits::new(1, 1, 1, 3, 4, 1, Duration::from_secs(1)),
            Err(ProxyLimitsError::PerHostExceedsGlobal)
        );
        assert_eq!(
            ProxyLimits::new(1, 1, 1, 1, 1, 1, Duration::ZERO),
            Err(ProxyLimitsError::Zero("rate_window"))
        );
        assert_eq!(
            ProxyLimits::new(
                ProxyLimits::DEFAULT_MAX_HEADER_BYTES + 1,
                1,
                1,
                1,
                1,
                1,
                Duration::from_secs(1),
            ),
            Err(ProxyLimitsError::ExceedsMaximum("max_header_bytes"))
        );
    }

    #[test]
    fn timeouts_match_parity_defaults_and_reject_invalid_ordering() {
        let timeouts = ProxyTimeouts::default();
        assert_eq!(timeouts.request_header_timeout(), Duration::from_secs(5));
        assert_eq!(timeouts.socket_timeout(), Duration::from_secs(30));
        assert_eq!(
            ProxyTimeouts::new(Duration::from_secs(31), Duration::from_secs(30)),
            Err(ProxyTimeoutsError::HeaderExceedsSocket)
        );
        assert_eq!(
            ProxyTimeouts::new(Duration::from_secs(5), Duration::from_secs(31)),
            Err(ProxyTimeoutsError::ExceedsMaximum("socket_timeout"))
        );
    }

    #[test]
    fn proxy_config_is_immutable_and_contains_no_authentication_bypass() {
        let instance = ProxyInstanceId::new(ProxySessionId::generate().unwrap(), 3);
        let scope = HostScope::new("welcome").unwrap();
        let config = ProxyConfig::new(instance.clone(), scope.clone());

        assert_eq!(config.instance(), &instance);
        assert_eq!(config.hns_scope(), Some(&scope));
        assert!(config.local_certificate_authority().is_none());
        assert_eq!(config.routing_mode(), ProxyRoutingMode::ScopedHns);
        assert_eq!(config.bind(), LoopbackBind::Ipv4);
        assert_eq!(config.limits(), ProxyLimits::default());
        assert_eq!(config.timeouts(), ProxyTimeouts::default());
        assert!(!format!("{config:?}").contains(scope.root().as_str()));

        let dane_browser = ProxyConfig::dane_browser(instance);
        assert_eq!(dane_browser.hns_scope(), None);
        assert_eq!(dane_browser.routing_mode(), ProxyRoutingMode::DaneBrowser);
    }
}
