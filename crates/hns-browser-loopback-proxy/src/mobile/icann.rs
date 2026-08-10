//! Bounded ICANN resolver/dial boundary for whole-browser proxy mode.

use crate::{CancellationToken, ProxyTunnelIo};
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

pub(crate) const MAX_RESOLVED_ADDRESSES: usize = 32;

/// Payload-free failure from the native ICANN resolver/dial boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IcannNetworkError {
    #[error("ICANN network operation was cancelled")]
    Cancelled,
    #[error("ICANN name resolution failed")]
    ResolutionFailed,
    #[error("ICANN connection failed")]
    ConnectionFailed,
}

/// Injectable native-network boundary used only after the proxy has
/// classified and admitted an ICANN host.
///
/// `connect` receives an explicit socket address, never a hostname. Returned
/// streams must use bounded writes and periodically return `TimedOut` or
/// `WouldBlock` from idle reads so generation cancellation remains joinable.
pub trait IcannNetwork: Send + Sync + 'static {
    fn resolve(
        &self,
        host: &str,
        port: u16,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SocketAddr>, IcannNetworkError>;

    fn connect(
        &self,
        address: SocketAddr,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn ProxyTunnelIo>, IcannNetworkError>;
}

/// Fail-closed default for callers that have not supplied a bounded native
/// resolver and explicit-address dialer.
#[derive(Clone, Copy, Debug, Default)]
pub struct FailClosedIcannNetwork;

impl IcannNetwork for FailClosedIcannNetwork {
    fn resolve(
        &self,
        _host: &str,
        _port: u16,
        cancellation: &CancellationToken,
    ) -> Result<Vec<SocketAddr>, IcannNetworkError> {
        if cancellation.is_cancelled() {
            Err(IcannNetworkError::Cancelled)
        } else {
            Err(IcannNetworkError::ResolutionFailed)
        }
    }

    fn connect(
        &self,
        _address: SocketAddr,
        _timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn ProxyTunnelIo>, IcannNetworkError> {
        if cancellation.is_cancelled() {
            Err(IcannNetworkError::Cancelled)
        } else {
            Err(IcannNetworkError::ConnectionFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use hns_core::network_policy::{
        is_browser_blocked_port, is_browser_special_use_host, is_publicly_routable,
    };

    #[test]
    fn public_address_policy_rejects_local_private_and_reserved_ranges() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.0.1",
            "198.51.100.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!is_publicly_routable(address.parse().unwrap()), "{address}");
        }
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_publicly_routable(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn unsafe_ports_and_special_use_names_are_rejected() {
        for port in [0, 22, 53, 6000, 6667, 10080] {
            assert!(is_browser_blocked_port(port), "{port}");
        }
        for port in [80, 443, 8080, 8443] {
            assert!(!is_browser_blocked_port(port), "{port}");
        }
        for host in ["localhost", "x.local", "x.internal", "home.arpa"] {
            assert!(is_browser_special_use_host(host), "{host}");
        }
        assert!(!is_browser_special_use_host("example.com"));
    }
}
