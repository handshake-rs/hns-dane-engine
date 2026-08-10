use crate::{ProxyAuthorization, ProxyInstanceId};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

pub struct ProxyEndpoint {
    instance: ProxyInstanceId,
    address: SocketAddr,
    authorization: Arc<ProxyAuthorization>,
}

impl ProxyEndpoint {
    pub(crate) fn new(
        instance: ProxyInstanceId,
        address: SocketAddr,
        authorization: Arc<ProxyAuthorization>,
    ) -> Self {
        Self {
            instance,
            address,
            authorization,
        }
    }

    pub fn instance(&self) -> &ProxyInstanceId {
        &self.instance
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn port(&self) -> u16 {
        self.address.port()
    }

    pub fn realm(&self) -> &str {
        self.authorization.realm()
    }

    pub fn username(&self) -> &str {
        self.authorization.username()
    }

    pub fn password(&self) -> &str {
        self.authorization.password()
    }

    pub fn authorization_header_value(&self) -> String {
        self.authorization.authorization_header_value()
    }

    pub fn matches_challenge(&self, host: &str, port: u16, realm: &str) -> bool {
        self.address.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST)
            && port == self.port()
            && self.authorization.matches_challenge(host, realm)
    }
}

impl fmt::Debug for ProxyEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyEndpoint")
            .field("instance", &self.instance)
            .field("address", &self.address)
            .field("realm", &"[REDACTED]")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProxySessionId;

    #[test]
    fn endpoint_exposes_capability_only_through_explicit_accessors() {
        let authorization = Arc::new(ProxyAuthorization::generate().unwrap());
        let endpoint = ProxyEndpoint::new(
            ProxyInstanceId::new(ProxySessionId::generate().unwrap(), 4),
            "127.0.0.1:43123".parse().unwrap(),
            Arc::clone(&authorization),
        );
        let debug = format!("{endpoint:?}");

        assert!(!debug.contains(endpoint.realm()));
        assert!(!debug.contains(endpoint.username()));
        assert!(!debug.contains(endpoint.password()));
        assert!(authorization.verify_header_value(&endpoint.authorization_header_value()));
        assert!(endpoint.matches_challenge("127.0.0.1", 43123, endpoint.realm()));
        assert!(!endpoint.matches_challenge("127.0.0.1", 43124, endpoint.realm()));
    }
}
