use hns_core::bytes::ParseError;
use hns_core::dns::{
    DnsName, RecordType, ResourceRecord, SVCB_PARAM_ALPN, SVCB_PARAM_MANDATORY,
    SVCB_PARAM_NO_DEFAULT_ALPN, SVCB_PARAM_PORT, SvcbRecord,
};
use hns_core::network_policy::{is_browser_blocked_port, is_publicly_routable};
use hns_dane::{DaneError, DomainTrustMode, StatelessDaneConfig, TlsaRecord};
use hns_icann_dane::{
    BrowserTlsDecision, DiscoveryError as IcannDaneDiscoveryError, DnssecQueryMode,
    IcannDnssecStatus, ResolverAuthentication, TlsaDenial, TlsaOwner, ValidatingDohEvidence,
    decide_browser_tls,
};
use hns_namespace_resolution::{
    ApplicationProtocol, CanonicalHost, CanonicalTlsa, ClassificationError, Namespace,
    NamespaceDecision, OriginQuery, OriginScheme, ProtocolCapabilities, ServiceTransport,
    TlsTrustPolicy, ValidatedOriginPlan, decision_fingerprint,
};
use hns_resolver::{
    NameClass, PreparedNamespaceResolution, ResolutionAnswer, ResolutionRequest, Resolver,
    ResolverError, classify_name,
};
use hns_transport::{
    OriginProtocol, OriginRequest, OriginResponse, OriginResponseHead, OriginTransport,
    OriginTunnel, OriginWebPkiPassthrough, TlsaRecordSource, TlsaTransport, TransportError,
};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroUsize};
use subtle::ConstantTimeEq;
use thiserror::Error;

const MAX_CNAME_CHAIN_LEN: usize = 8;

#[derive(Clone, Eq, PartialEq)]
pub struct GatewayConfig {
    pub bind: SocketAddr,
    pub auth_token: Option<String>,
    pub allow_non_public_origin_addresses: bool,
    pub allow_unsafe_origin_ports: bool,
    pub require_secure_resolution: bool,
    pub hns_https_mode: HnsHttpsMode,
    pub supported_origin_protocols: Vec<OriginProtocol>,
    pub stateless_dane: StatelessDaneConfig,
    pub icann_resolver_authentication: ResolverAuthentication,
    pub icann_dnssec_query_mode: DnssecQueryMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HnsHttpsMode {
    Strict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedTlsaRecords {
    pub browser_tls_decision: Option<BrowserTlsDecision>,
    pub secure: bool,
    pub records: Vec<TlsaRecord>,
    pub source: Option<TlsaRecordSource>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GatewayRequest {
    pub auth_token: Option<String>,
    pub origin: OriginRequest,
    pub resolution: ResolutionRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayResponse {
    pub resolution: ResolutionAnswer,
    pub namespace_decision: Option<NamespaceDecision>,
    pub origin_request: OriginRequest,
    pub origin: OriginResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayResponseHead {
    pub resolution: ResolutionAnswer,
    pub namespace_decision: Option<NamespaceDecision>,
    pub origin_request: OriginRequest,
    pub origin: OriginResponseHead,
}

pub struct GatewayTunnel {
    pub resolution: ResolutionAnswer,
    pub namespace_decision: Option<NamespaceDecision>,
    pub origin_request: OriginRequest,
    pub origin: OriginTunnel,
}

/// Pre-TLS disposition for one authenticated browser CONNECT.
pub enum GatewayConnectDisposition {
    /// The browser must connect to the local TLS terminator because Rust must
    /// inspect and enforce DANE for the selected origin.
    Intercept,
    /// The browser may retain end-to-end WebPKI over this exact, already
    /// resolved ICANN TCP endpoint.
    WebPkiPassthrough(Box<GatewayWebPkiPassthrough>),
}

/// One raw TCP stream whose endpoint and WebPKI fallback were selected by the
/// same dual-root gateway decision.
pub struct GatewayWebPkiPassthrough {
    pub resolution: ResolutionAnswer,
    pub namespace_decision: NamespaceDecision,
    pub origin_request: OriginRequest,
    pub transport: OriginWebPkiPassthrough,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GatewayError {
    #[error("gateway must bind to loopback")]
    NonLoopbackBind,
    #[error("gateway authentication token must not be empty")]
    EmptyAuthToken,
    #[error("gateway authentication failed")]
    Unauthorized,
    #[error("origin host does not match resolution name")]
    HostResolutionMismatch,
    #[error("resolution is not cryptographically secure")]
    InsecureResolution,
    #[error("resolution did not provide an origin address")]
    NoResolvedAddress,
    #[error("origin address is not publicly routable")]
    NonPublicOriginAddress,
    #[error("origin port {0} is blocked by browser network policy")]
    UnsafeOriginPort(u16),
    #[error("TLSA record is invalid: {0}")]
    InvalidTlsa(#[from] DaneError),
    #[error("ICANN DANE discovery failed: {0}")]
    IcannDane(#[from] IcannDaneDiscoveryError),
    #[error("HTTPS/SVCB record is invalid: {0}")]
    InvalidSvcb(ParseError),
    #[error("HTTPS/SVCB service binding is unsupported")]
    UnsupportedSvcb,
    #[error("resolver error: {0}")]
    Resolver(#[from] ResolverError),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}

/// Typed namespace evidence retained when gateway work fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayFailureContext {
    /// Classification succeeded before a later gateway or origin failure.
    NamespaceDecision(Box<NamespaceDecision>),
    /// Dual-root classification itself failed.
    ClassificationError(Box<ClassificationError>),
}

/// Gateway failure plus any typed dual-root evidence available at failure.
#[derive(Debug, Eq, PartialEq)]
pub struct GatewayFailure {
    error: Box<GatewayError>,
    namespace_context: Option<GatewayFailureContext>,
}

impl GatewayFailure {
    fn from_error(error: GatewayError) -> Self {
        let namespace_context = match &error {
            GatewayError::Resolver(ResolverError::NamespaceClassification(error)) => Some(
                GatewayFailureContext::ClassificationError(Box::new(error.clone())),
            ),
            _ => None,
        };
        Self {
            error: Box::new(error),
            namespace_context,
        }
    }

    /// Retains a completed decision across a later gateway failure.
    #[must_use]
    pub fn with_namespace_decision(error: GatewayError, decision: NamespaceDecision) -> Self {
        Self {
            error: Box::new(error),
            namespace_context: Some(GatewayFailureContext::NamespaceDecision(Box::new(decision))),
        }
    }

    /// Underlying gateway error.
    #[must_use]
    pub fn error(&self) -> &GatewayError {
        self.error.as_ref()
    }

    /// Typed namespace evidence available at the failure boundary.
    #[must_use]
    pub const fn namespace_context(&self) -> Option<&GatewayFailureContext> {
        self.namespace_context.as_ref()
    }

    /// Successful namespace decision retained across a later failure.
    #[must_use]
    pub fn namespace_decision(&self) -> Option<&NamespaceDecision> {
        match self.namespace_context.as_ref() {
            Some(GatewayFailureContext::NamespaceDecision(decision)) => Some(decision.as_ref()),
            Some(GatewayFailureContext::ClassificationError(_)) | None => None,
        }
    }

    /// Typed classification failure, without parsing diagnostic JSON.
    #[must_use]
    pub fn classification_error(&self) -> Option<&ClassificationError> {
        match self.namespace_context.as_ref() {
            Some(GatewayFailureContext::ClassificationError(error)) => Some(error.as_ref()),
            Some(GatewayFailureContext::NamespaceDecision(_)) | None => None,
        }
    }

    /// Discards the optional context and returns the compatibility error.
    #[must_use]
    pub fn into_error(self) -> GatewayError {
        *self.error
    }
}

impl From<GatewayError> for GatewayFailure {
    fn from(error: GatewayError) -> Self {
        Self::from_error(error)
    }
}

impl From<ResolverError> for GatewayFailure {
    fn from(error: ResolverError) -> Self {
        Self::from_error(GatewayError::Resolver(error))
    }
}

pub struct Gateway<R, T> {
    config: GatewayConfig,
    resolver: R,
    transport: T,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 15_353),
            auth_token: None,
            allow_non_public_origin_addresses: false,
            allow_unsafe_origin_ports: false,
            require_secure_resolution: true,
            hns_https_mode: HnsHttpsMode::Strict,
            supported_origin_protocols: vec![
                OriginProtocol::Http11,
                OriginProtocol::Http2,
                OriginProtocol::Http3,
            ],
            stateless_dane: StatelessDaneConfig::default(),
            icann_resolver_authentication: ResolverAuthentication::Authenticated,
            icann_dnssec_query_mode: DnssecQueryMode::Validate,
        }
    }
}

impl std::fmt::Debug for GatewayConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayConfig")
            .field("bind", &self.bind)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "allow_non_public_origin_addresses",
                &self.allow_non_public_origin_addresses,
            )
            .field("allow_unsafe_origin_ports", &self.allow_unsafe_origin_ports)
            .field("require_secure_resolution", &self.require_secure_resolution)
            .field("hns_https_mode", &self.hns_https_mode)
            .field(
                "supported_origin_protocols",
                &self.supported_origin_protocols,
            )
            .field("stateless_dane", &self.stateless_dane)
            .field(
                "icann_resolver_authentication",
                &self.icann_resolver_authentication,
            )
            .field("icann_dnssec_query_mode", &self.icann_dnssec_query_mode)
            .finish()
    }
}

impl std::fmt::Debug for GatewayRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayRequest")
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("origin", &self.origin)
            .field("resolution", &self.resolution)
            .finish()
    }
}

impl GatewayConfig {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if !self.bind.ip().is_loopback() {
            return Err(GatewayError::NonLoopbackBind);
        }
        if self.auth_token.as_ref().is_some_and(String::is_empty) {
            return Err(GatewayError::EmptyAuthToken);
        }
        Ok(())
    }
}

impl<R, T> Gateway<R, T>
where
    R: Resolver,
    T: OriginTransport,
{
    pub fn new(config: GatewayConfig, resolver: R, transport: T) -> Result<Self, GatewayError> {
        config.validate()?;
        Ok(Self {
            config,
            resolver,
            transport,
        })
    }

    pub fn handle(&self, request: &GatewayRequest) -> Result<GatewayResponse, GatewayError> {
        self.handle_with_failure_context(request)
            .map_err(GatewayFailure::into_error)
    }

    /// Handles one request while retaining typed namespace evidence on error.
    pub fn handle_with_failure_context(
        &self,
        request: &GatewayRequest,
    ) -> Result<GatewayResponse, GatewayFailure> {
        self.authorize(request).map_err(GatewayFailure::from)?;
        let (resolution, origin_request, namespace_decision) =
            self.resolve_origin_request(request, &self.config.supported_origin_protocols)?;
        let origin = self.transport.fetch(&origin_request).map_err(|error| {
            let error = GatewayError::Transport(error);
            match namespace_decision.as_ref() {
                Some(decision) => GatewayFailure::with_namespace_decision(error, decision.clone()),
                None => GatewayFailure::from(error),
            }
        })?;
        Ok(GatewayResponse {
            resolution,
            namespace_decision,
            origin_request,
            origin,
        })
    }

    pub fn handle_to_writer(
        &self,
        request: &GatewayRequest,
        body: &mut dyn Write,
    ) -> Result<GatewayResponseHead, GatewayError> {
        self.handle_to_writer_with_failure_context(request, body)
            .map_err(GatewayFailure::into_error)
    }

    /// Streams one response while retaining typed namespace evidence on error.
    pub fn handle_to_writer_with_failure_context(
        &self,
        request: &GatewayRequest,
        body: &mut dyn Write,
    ) -> Result<GatewayResponseHead, GatewayFailure> {
        self.authorize(request).map_err(GatewayFailure::from)?;
        let (resolution, origin_request, namespace_decision) =
            self.resolve_origin_request(request, &self.config.supported_origin_protocols)?;
        let origin = self
            .transport
            .fetch_to_writer(&origin_request, body)
            .map_err(|error| {
                let error = GatewayError::Transport(error);
                match namespace_decision.as_ref() {
                    Some(decision) => {
                        GatewayFailure::with_namespace_decision(error, decision.clone())
                    }
                    None => GatewayFailure::from(error),
                }
            })?;
        Ok(GatewayResponseHead {
            resolution,
            namespace_decision,
            origin_request,
            origin,
        })
    }

    pub fn handle_tunnel(&self, request: &GatewayRequest) -> Result<GatewayTunnel, GatewayError> {
        self.handle_tunnel_with_failure_context(request)
            .map_err(GatewayFailure::into_error)
    }

    /// Decides whether an outer browser CONNECT requires local TLS
    /// interception or may retain browser-owned end-to-end WebPKI.
    ///
    /// Passthrough is available only after a complete ICANN namespace
    /// selection and an authenticated TLSA-absence or proven-insecure
    /// delegation decision. DANE, bogus/indeterminate DNSSEC, classification
    /// failures, and unsupported service transports never reach this branch.
    pub fn open_browser_connect_with_failure_context(
        &self,
        request: &GatewayRequest,
    ) -> Result<GatewayConnectDisposition, GatewayFailure> {
        self.authorize(request).map_err(GatewayFailure::from)?;
        let (resolution, mut origin_request, namespace_decision) =
            self.resolve_origin_request(request, &[OriginProtocol::Http11, OriginProtocol::Http2])?;
        let Some(decision) = namespace_decision else {
            return Ok(GatewayConnectDisposition::Intercept);
        };
        let Some(plan) = decision.selected_plan() else {
            return Err(GatewayFailure::with_namespace_decision(
                GatewayError::Resolver(ResolverError::InvalidDnsResponse),
                decision,
            ));
        };
        match selected_browser_connect_uses_webpki(plan, &origin_request.tls) {
            Ok(false) => return Ok(GatewayConnectDisposition::Intercept),
            Ok(true) => {}
            Err(error) => {
                return Err(GatewayFailure::with_namespace_decision(
                    GatewayError::Transport(error),
                    decision,
                ));
            }
        }
        // The plan retains the complete authenticated A/AAAA endpoint set.
        // Keep only addresses allowed by browser origin policy, without ever
        // consulting system DNS, then let the transport try the equivalent
        // candidates under one aggregate connection-time budget.
        let mut candidate_requests = Vec::new();
        for endpoint in plan.endpoints() {
            if endpoint.port() != origin_request.port {
                return Err(GatewayFailure::with_namespace_decision(
                    GatewayError::Resolver(ResolverError::InvalidDnsResponse),
                    decision,
                ));
            }
            let connect_host = endpoint.ip().to_string();
            if self.validate_origin_address(&connect_host).is_err() {
                // Non-public candidates remain part of the authenticated
                // namespace fingerprint, but browser policy forbids opening
                // them unless the gateway was explicitly configured to do so.
                continue;
            }
            let mut candidate_request = origin_request.clone();
            candidate_request.connect_host = Some(connect_host);
            candidate_requests.push(candidate_request);
        }
        if candidate_requests.is_empty() {
            return Err(GatewayFailure::with_namespace_decision(
                GatewayError::NonPublicOriginAddress,
                decision,
            ));
        }
        let selected = self
            .transport
            .open_webpki_passthrough_candidates(&candidate_requests)
            .map_err(|error| {
                GatewayFailure::with_namespace_decision(
                    GatewayError::Transport(error),
                    decision.clone(),
                )
            })?;
        let selected_peer = selected.transport.peer_addr;
        origin_request = candidate_requests
            .iter()
            .find(|candidate| explicit_origin_socket_addr(candidate) == Some(selected_peer))
            .cloned()
            .ok_or_else(|| {
                GatewayFailure::with_namespace_decision(
                    GatewayError::Transport(TransportError::InvalidRequest),
                    decision.clone(),
                )
            })?;
        let transport = selected.transport;
        Ok(GatewayConnectDisposition::WebPkiPassthrough(Box::new(
            GatewayWebPkiPassthrough {
                resolution,
                namespace_decision: decision,
                origin_request,
                transport,
            },
        )))
    }

    /// Opens one tunnel while retaining typed namespace evidence on error.
    pub fn handle_tunnel_with_failure_context(
        &self,
        request: &GatewayRequest,
    ) -> Result<GatewayTunnel, GatewayFailure> {
        self.authorize(request).map_err(GatewayFailure::from)?;
        let (resolution, origin_request, namespace_decision) =
            self.resolve_origin_request(request, &[OriginProtocol::Http11])?;
        let origin = self
            .transport
            .open_tunnel(&origin_request)
            .map_err(|error| {
                let error = GatewayError::Transport(error);
                match namespace_decision.as_ref() {
                    Some(decision) => {
                        GatewayFailure::with_namespace_decision(error, decision.clone())
                    }
                    None => GatewayFailure::from(error),
                }
            })?;
        Ok(GatewayTunnel {
            resolution,
            namespace_decision,
            origin_request,
            origin,
        })
    }

    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn authorize(&self, request: &GatewayRequest) -> Result<(), GatewayError> {
        let Some(expected) = self.config.auth_token.as_deref() else {
            return Ok(());
        };
        let Some(provided) = request.auth_token.as_deref() else {
            return Err(GatewayError::Unauthorized);
        };
        if bool::from(expected.as_bytes().ct_eq(provided.as_bytes())) {
            Ok(())
        } else {
            Err(GatewayError::Unauthorized)
        }
    }

    fn resolve_origin_request(
        &self,
        request: &GatewayRequest,
        supported_origin_protocols: &[OriginProtocol],
    ) -> Result<(ResolutionAnswer, OriginRequest, Option<NamespaceDecision>), GatewayFailure> {
        if !hosts_match(&request.origin.host, &request.resolution.qname) {
            return Err(GatewayError::HostResolutionMismatch.into());
        }
        self.validate_origin_port(request.origin.port)?;

        let namespace_query = namespace_origin_query(&request.origin, supported_origin_protocols)?;
        if let Some(prepared) = self
            .resolver
            .prepare_namespace_resolution(&namespace_query)?
        {
            let decision = prepared.decision.clone();
            return self
                .apply_prepared_namespace_resolution(request, namespace_query, prepared)
                .map_err(|error| GatewayFailure::with_namespace_decision(error, decision));
        }

        let resolution = self.resolver.resolve(&request.resolution)?;
        let name_class = classify_name(&request.origin.host);
        if !resolution.secure && name_class != NameClass::Icann {
            return Err(GatewayError::InsecureResolution.into());
        }

        let mut origin_request = request.origin.clone();
        // Never trust a caller-supplied connection override. The native transport bypasses the
        // browser DNS stack, so the connection address must come from this validated resolution.
        origin_request.connect_host =
            first_resolved_address(&resolution.records, &origin_request.host);
        if origin_request.connect_host.is_none() {
            origin_request.connect_host = self.resolve_origin_address(&origin_request)?;
        }
        let connect_host = origin_request
            .connect_host
            .as_deref()
            .ok_or(GatewayError::NoResolvedAddress)?;
        self.validate_origin_address(connect_host)?;
        if is_tls_origin_scheme(&origin_request.scheme) {
            origin_request.tls.mode =
                domain_trust_mode_for_host(&origin_request.host, self.config.hns_https_mode);
            if origin_request.tls.mode != DomainTrustMode::IcannWebPki {
                origin_request.tls.stateless_dane = self.config.stateless_dane.clone();
            }
            let applied_initial_service_policy = resolution.secure
                && apply_https_service_policy(
                    &resolution.records,
                    &mut origin_request,
                    supported_origin_protocols,
                )?;
            if !applied_initial_service_policy {
                match self
                    .resolve_https_service_policy(&mut origin_request, supported_origin_protocols)
                {
                    Ok(()) => {}
                    Err(error) if optional_https_service_policy_error(&error) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            origin_request.tls.service_port = origin_request.port;
            origin_request.tls.service_transport = match origin_request.protocol {
                OriginProtocol::Http11 | OriginProtocol::Http2 => TlsaTransport::Tcp,
                OriginProtocol::Http3 => TlsaTransport::Udp,
            };
            let resolved_tlsa = self.resolve_tlsa_records(
                &origin_request.host,
                origin_request.port,
                origin_request.tls.service_transport,
            )?;
            origin_request.tls.dnssec_secure = resolved_tlsa.secure;
            origin_request.tls.tlsa_records = resolved_tlsa.records;
            origin_request.tls.tlsa_source = resolved_tlsa.source;
            origin_request.tls.browser_tls_decision = resolved_tlsa.browser_tls_decision;
        }
        self.validate_origin_port(origin_request.port)?;

        Ok((resolution, origin_request, None))
    }

    fn apply_prepared_namespace_resolution(
        &self,
        request: &GatewayRequest,
        namespace_query: OriginQuery,
        prepared: PreparedNamespaceResolution,
    ) -> Result<(ResolutionAnswer, OriginRequest, Option<NamespaceDecision>), GatewayError> {
        let PreparedNamespaceResolution {
            decision,
            selected_answer,
        } = prepared;
        if decision.query() != &namespace_query {
            return Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse));
        }
        let plan = decision
            .selected_plan()
            .ok_or(ResolverError::NamespaceUnavailable)?;
        let selected_answer = selected_answer.ok_or(ResolverError::NamespaceUnavailable)?;
        let endpoint = plan
            .endpoints()
            .iter()
            .copied()
            .find(|endpoint| {
                self.validate_origin_address(&endpoint.ip().to_string())
                    .is_ok()
            })
            .ok_or(GatewayError::NonPublicOriginAddress)?;

        let mut origin_request = request.origin.clone();
        origin_request.connect_host = Some(endpoint.ip().to_string());
        origin_request.port = plan.service().effective_port().get();
        origin_request.protocol = origin_protocol(plan.service().selected_protocol());
        origin_request.tls.namespace_fingerprint = Some(decision_fingerprint(&decision).to_hex());
        self.validate_origin_address(
            origin_request
                .connect_host
                .as_deref()
                .ok_or(GatewayError::NoResolvedAddress)?,
        )?;
        self.validate_origin_port(origin_request.port)?;

        if is_tls_origin_scheme(&origin_request.scheme) {
            apply_selected_tls_plan(
                &mut origin_request,
                plan.namespace(),
                plan.tls_policy(),
                plan.tlsa_records(),
                self.config.hns_https_mode,
                &self.config.stateless_dane,
            )?;
        } else if plan.tls_policy() != TlsTrustPolicy::Cleartext {
            return Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse));
        }
        origin_request.tls.service_port = origin_request.port;
        origin_request.tls.service_transport = tlsa_transport(plan.service().transport());

        Ok((selected_answer, origin_request, Some(decision)))
    }

    fn validate_origin_address(&self, address: &str) -> Result<(), GatewayError> {
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| GatewayError::NonPublicOriginAddress)?;
        if self.config.allow_non_public_origin_addresses || is_publicly_routable(address) {
            Ok(())
        } else {
            Err(GatewayError::NonPublicOriginAddress)
        }
    }

    fn validate_origin_port(&self, port: u16) -> Result<(), GatewayError> {
        if self.config.allow_unsafe_origin_ports || !is_browser_blocked_port(port) {
            Ok(())
        } else {
            Err(GatewayError::UnsafeOriginPort(port))
        }
    }

    fn resolve_tlsa_records(
        &self,
        host: &str,
        port: u16,
        transport: TlsaTransport,
    ) -> Result<ResolvedTlsaRecords, GatewayError> {
        let request = tlsa_resolution_request(host, port, transport)?;
        self.resolve_native_tlsa_records(&request, classify_name(host) == NameClass::Icann)
    }

    fn resolve_native_tlsa_records(
        &self,
        request: &ResolutionRequest,
        allow_insecure_webpki_fallback: bool,
    ) -> Result<ResolvedTlsaRecords, GatewayError> {
        let answer = self.resolver.resolve(request)?;
        if allow_insecure_webpki_fallback {
            return icann_tlsa_records(
                request,
                &answer,
                self.config.icann_resolver_authentication,
                self.config.icann_dnssec_query_mode,
            );
        }

        let records = tlsa_records(&answer.records, &request.qname)?;
        if self.config.require_secure_resolution && !answer.secure && !records.is_empty() {
            return Err(GatewayError::InsecureResolution);
        }

        Ok(ResolvedTlsaRecords {
            browser_tls_decision: None,
            secure: answer.secure,
            source: (!records.is_empty()).then_some(TlsaRecordSource::NativeTlsa),
            records,
        })
    }

    fn resolve_origin_address(
        &self,
        origin: &OriginRequest,
    ) -> Result<Option<String>, GatewayError> {
        for qtype in [RecordType::A, RecordType::Aaaa] {
            let request = ResolutionRequest {
                qname: normalize_host(&origin.host),
                qtype: qtype.code(),
            };
            let answer = self.resolver.resolve(&request)?;
            if !answer.secure && classify_name(&origin.host) != NameClass::Icann {
                return Err(GatewayError::InsecureResolution);
            }
            if let Some(address) = first_resolved_address(&answer.records, &origin.host) {
                return Ok(Some(address));
            }
        }

        Ok(None)
    }

    fn resolve_https_service_policy(
        &self,
        request: &mut OriginRequest,
        supported_origin_protocols: &[OriginProtocol],
    ) -> Result<(), GatewayError> {
        let answer = self.resolver.resolve(&ResolutionRequest {
            qname: normalize_host(&request.host),
            qtype: RecordType::Https.code(),
        })?;
        if !answer.secure && classify_name(&request.host) == NameClass::Icann {
            return Ok(());
        }
        if self.config.require_secure_resolution && !answer.secure {
            return Err(GatewayError::InsecureResolution);
        }
        apply_https_service_policy(&answer.records, request, supported_origin_protocols)?;
        Ok(())
    }
}

fn selected_browser_connect_uses_webpki(
    plan: &ValidatedOriginPlan,
    tls: &hns_transport::TlsValidation,
) -> Result<bool, TransportError> {
    let expected = match (plan.namespace(), plan.tls_policy()) {
        (Namespace::Icann, TlsTrustPolicy::WebPkiAuthenticatedAbsence) => {
            BrowserTlsDecision::WebPkiAuthenticatedAbsence
        }
        (Namespace::Icann, TlsTrustPolicy::WebPkiInsecureDelegation) => {
            BrowserTlsDecision::WebPkiInsecureDelegation
        }
        _ => return Ok(false),
    };
    if tls.browser_tls_decision == Some(expected) && tls.service_transport == TlsaTransport::Tcp {
        Ok(true)
    } else {
        Err(TransportError::InvalidRequest)
    }
}

fn optional_https_service_policy_error(error: &GatewayError) -> bool {
    matches!(error, GatewayError::Resolver(_))
}

impl HnsHttpsMode {
    fn domain_trust_mode(self) -> DomainTrustMode {
        match self {
            HnsHttpsMode::Strict => DomainTrustMode::HnsStrict,
        }
    }
}

fn domain_trust_mode_for_host(host: &str, hns_https_mode: HnsHttpsMode) -> DomainTrustMode {
    match classify_name(host) {
        NameClass::Hns => hns_https_mode.domain_trust_mode(),
        NameClass::Icann | NameClass::Search => DomainTrustMode::IcannWebPki,
    }
}

fn hosts_match(origin_host: &str, qname: &str) -> bool {
    normalize_host(origin_host) == normalize_host(qname)
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn is_tls_origin_scheme(scheme: &str) -> bool {
    scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss")
}

fn explicit_origin_socket_addr(request: &OriginRequest) -> Option<SocketAddr> {
    let address = request.connect_host.as_deref()?.parse::<IpAddr>().ok()?;
    Some(SocketAddr::new(address, request.port))
}

fn namespace_origin_query(
    origin: &OriginRequest,
    supported_origin_protocols: &[OriginProtocol],
) -> Result<OriginQuery, GatewayError> {
    let scheme = match origin.scheme.to_ascii_lowercase().as_str() {
        "http" => OriginScheme::Http,
        "https" => OriginScheme::Https,
        "ws" => OriginScheme::Ws,
        "wss" => OriginScheme::Wss,
        _ => return Err(GatewayError::Resolver(ResolverError::UnsupportedBackend)),
    };
    let host = CanonicalHost::parse(&normalize_host(&origin.host)).map_err(ResolverError::from)?;
    let explicit_port = NonZeroU16::new(origin.port)
        .ok_or(GatewayError::UnsafeOriginPort(origin.port))
        .map(Some)?;
    let protocols = ProtocolCapabilities::new(
        supported_origin_protocols.contains(&OriginProtocol::Http11),
        supported_origin_protocols.contains(&OriginProtocol::Http2),
        supported_origin_protocols.contains(&OriginProtocol::Http3),
    )
    .map_err(ResolverError::from)?;
    Ok(OriginQuery::new(host, scheme, explicit_port, protocols))
}

const fn origin_protocol(protocol: ApplicationProtocol) -> OriginProtocol {
    match protocol {
        ApplicationProtocol::Http11 => OriginProtocol::Http11,
        ApplicationProtocol::Http2 => OriginProtocol::Http2,
        ApplicationProtocol::Http3 => OriginProtocol::Http3,
    }
}

const fn tlsa_transport(transport: ServiceTransport) -> TlsaTransport {
    match transport {
        ServiceTransport::Tcp => TlsaTransport::Tcp,
        ServiceTransport::Udp => TlsaTransport::Udp,
    }
}

fn apply_selected_tls_plan(
    request: &mut OriginRequest,
    namespace: Namespace,
    tls_policy: TlsTrustPolicy,
    canonical_tlsa: &[CanonicalTlsa],
    hns_https_mode: HnsHttpsMode,
    stateless_dane: &StatelessDaneConfig,
) -> Result<(), GatewayError> {
    let records = canonical_tlsa
        .iter()
        .map(|record| TlsaRecord::parse_rdata(record.rdata()).map_err(GatewayError::from))
        .collect::<Result<Vec<_>, _>>()?;
    match (namespace, tls_policy) {
        (Namespace::Hns, TlsTrustPolicy::Dane) => {
            if records.is_empty() {
                return Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse));
            }
            request.tls.mode = hns_https_mode.domain_trust_mode();
            request.tls.stateless_dane = stateless_dane.clone();
            request.tls.dnssec_secure = true;
            request.tls.tlsa_records = records;
            request.tls.tlsa_source = Some(TlsaRecordSource::NativeTlsa);
            request.tls.browser_tls_decision = None;
        }
        (Namespace::Icann, TlsTrustPolicy::Dane) => {
            let record_count = NonZeroUsize::new(records.len())
                .ok_or(GatewayError::Resolver(ResolverError::InvalidDnsResponse))?;
            request.tls.mode = DomainTrustMode::IcannWebPki;
            request.tls.dnssec_secure = true;
            request.tls.tlsa_records = records;
            request.tls.tlsa_source = Some(TlsaRecordSource::NativeTlsa);
            request.tls.browser_tls_decision =
                Some(BrowserTlsDecision::EnforceDane { record_count });
        }
        (Namespace::Icann, TlsTrustPolicy::WebPkiAuthenticatedAbsence) => {
            if !records.is_empty() {
                return Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse));
            }
            request.tls.mode = DomainTrustMode::IcannWebPki;
            request.tls.dnssec_secure = true;
            request.tls.tlsa_records.clear();
            request.tls.tlsa_source = None;
            request.tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence);
        }
        (Namespace::Icann, TlsTrustPolicy::WebPkiInsecureDelegation) => {
            if !records.is_empty() {
                return Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse));
            }
            request.tls.mode = DomainTrustMode::IcannWebPki;
            request.tls.dnssec_secure = false;
            request.tls.tlsa_records.clear();
            request.tls.tlsa_source = None;
            request.tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiInsecureDelegation);
        }
        (
            Namespace::Hns,
            TlsTrustPolicy::Cleartext
            | TlsTrustPolicy::WebPkiAuthenticatedAbsence
            | TlsTrustPolicy::WebPkiInsecureDelegation,
        )
        | (Namespace::Icann, TlsTrustPolicy::Cleartext) => {
            return Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse));
        }
    }
    Ok(())
}

fn first_resolved_address(records: &[ResourceRecord], host: &str) -> Option<String> {
    let owner = DnsName::from_ascii(&normalize_host(host)).ok()?;
    resolved_address_for_owner(records, &owner, 0)
}

fn resolved_address_for_owner(
    records: &[ResourceRecord],
    owner: &DnsName,
    depth: usize,
) -> Option<String> {
    if depth > MAX_CNAME_CHAIN_LEN {
        return None;
    }
    records
        .iter()
        .filter(|record| record.name == *owner)
        .find_map(|record| match record.record_type {
            RecordType::A if record.rdata.len() == 4 => Some(IpAddr::V4(Ipv4Addr::new(
                record.rdata[0],
                record.rdata[1],
                record.rdata[2],
                record.rdata[3],
            ))),
            RecordType::Aaaa if record.rdata.len() == 16 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&record.rdata);
                Some(IpAddr::V6(Ipv6Addr::from(bytes)))
            }
            _ => None,
        })
        .map(|address| address.to_string())
        .or_else(|| {
            let target = cname_target_for_owner(records, owner)?;
            resolved_address_for_owner(records, &target, depth + 1)
        })
}

fn cname_target_for_owner(records: &[ResourceRecord], owner: &DnsName) -> Option<DnsName> {
    let mut candidates = records
        .iter()
        .filter(|record| record.name == *owner && record.record_type == RecordType::Cname);
    let record = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    let (target, end) = DnsName::parse_wire(&record.rdata, 0).ok()?;
    (end == record.rdata.len()).then_some(target)
}

fn tlsa_resolution_request(
    host: &str,
    port: u16,
    transport: TlsaTransport,
) -> Result<ResolutionRequest, IcannDaneDiscoveryError> {
    let owner = TlsaOwner::derive(host, port, transport)?;
    Ok(ResolutionRequest {
        qname: owner.resolver_name().to_owned(),
        qtype: RecordType::Tlsa.code(),
    })
}

fn icann_tlsa_records(
    request: &ResolutionRequest,
    answer: &ResolutionAnswer,
    resolver_authentication: ResolverAuthentication,
    query_mode: DnssecQueryMode,
) -> Result<ResolvedTlsaRecords, GatewayError> {
    // `IcannDohResolver` is fixed to a WebPKI-authenticated endpoint, sets DO,
    // leaves CD clear, and converts transport/HTTP/rcode/parser failures into
    // `ResolverError` before this adapter is called. AD=0 is consequently the
    // successful proven-insecure state; bogus or indeterminate lookup results
    // remain terminal errors.
    let records = if answer.secure {
        tlsa_records(&answer.records, &request.qname)?
    } else {
        Vec::new()
    };
    let decision = decide_browser_tls(ValidatingDohEvidence {
        resolver_authentication,
        query_mode,
        dnssec: if answer.secure {
            IcannDnssecStatus::Secure
        } else {
            IcannDnssecStatus::InsecureDelegation
        },
        tlsa_record_count: records.len(),
        denial: if answer.secure && records.is_empty() {
            TlsaDenial::Authenticated
        } else {
            TlsaDenial::None
        },
    })?;

    match decision {
        BrowserTlsDecision::EnforceDane { .. } => Ok(ResolvedTlsaRecords {
            browser_tls_decision: Some(decision),
            secure: true,
            source: Some(TlsaRecordSource::NativeTlsa),
            records,
        }),
        BrowserTlsDecision::WebPkiAuthenticatedAbsence => Ok(ResolvedTlsaRecords {
            browser_tls_decision: Some(decision),
            secure: true,
            source: None,
            records: Vec::new(),
        }),
        BrowserTlsDecision::WebPkiInsecureDelegation => Ok(ResolvedTlsaRecords {
            browser_tls_decision: Some(decision),
            secure: false,
            source: None,
            records: Vec::new(),
        }),
    }
}

fn tlsa_records(
    records: &[ResourceRecord],
    service_qname: &str,
) -> Result<Vec<TlsaRecord>, GatewayError> {
    let mut owner = DnsName::from_ascii(service_qname)
        .map_err(|_| GatewayError::Resolver(ResolverError::InvalidDnsResponse))?;
    let mut seen = Vec::new();
    let mut followed_cname = false;
    for _depth in 0..=MAX_CNAME_CHAIN_LEN {
        if seen.contains(&owner) {
            return Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse));
        }
        seen.push(owner.clone());
        if records.iter().any(|record| {
            record.name == owner
                && matches!(record.record_type, RecordType::Tlsa | RecordType::Cname)
                && record.class != 1
        }) {
            return Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse));
        }

        let owner_tlsa = records
            .iter()
            .filter(|record| record.record_type == RecordType::Tlsa && record.name == owner)
            .collect::<Vec<_>>();
        let owner_cnames = records
            .iter()
            .filter(|record| record.record_type == RecordType::Cname && record.name == owner)
            .collect::<Vec<_>>();
        if !owner_tlsa.is_empty() && !owner_cnames.is_empty() {
            return Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse));
        }
        if !owner_tlsa.is_empty() {
            return owner_tlsa
                .into_iter()
                .map(|record| TlsaRecord::parse_rdata(&record.rdata).map_err(GatewayError::from))
                .collect();
        }
        let [cname] = owner_cnames.as_slice() else {
            return if owner_cnames.is_empty() {
                if followed_cname {
                    // The clone's response adapter retains AD but drops the
                    // terminal NSEC/NSEC3 authority proof. Do not infer a
                    // negative TLSA result after an alias without that proof.
                    Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse))
                } else {
                    Ok(Vec::new())
                }
            } else {
                Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse))
            };
        };
        let (target, end) = DnsName::parse_wire(&cname.rdata, 0)
            .map_err(|_| GatewayError::Resolver(ResolverError::InvalidDnsResponse))?;
        if end != cname.rdata.len() {
            return Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse));
        }
        owner = target;
        followed_cname = true;
    }
    Err(GatewayError::Resolver(ResolverError::InvalidDnsResponse))
}

fn apply_https_service_policy(
    records: &[ResourceRecord],
    request: &mut OriginRequest,
    supported_protocols: &[OriginProtocol],
) -> Result<bool, GatewayError> {
    let Some(service) = selected_https_service(records, &request.host, supported_protocols)? else {
        return Ok(false);
    };

    request.port = service.port.unwrap_or(request.port);
    request.protocol = service.protocol;
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HttpsServicePolicy {
    protocol: OriginProtocol,
    port: Option<u16>,
}

fn selected_https_service(
    records: &[ResourceRecord],
    host: &str,
    supported_protocols: &[OriginProtocol],
) -> Result<Option<HttpsServicePolicy>, GatewayError> {
    let owner =
        DnsName::from_ascii(&normalize_host(host)).map_err(|_| GatewayError::UnsupportedSvcb)?;
    let mut selected = None;
    let mut saw_service = false;

    for record in records
        .iter()
        .filter(|record| record.record_type == RecordType::Https && record.name == owner)
    {
        saw_service = true;
        let svcb = SvcbRecord::from_record(record).map_err(GatewayError::InvalidSvcb)?;
        if svcb.is_alias_mode() {
            return Err(GatewayError::UnsupportedSvcb);
        }
        if svcb.target_name != DnsName::root() && svcb.target_name != owner {
            return Err(GatewayError::UnsupportedSvcb);
        }
        validate_supported_mandatory_params(&svcb)?;

        let Some(protocol) = selected_alpn_protocol(&svcb, supported_protocols)? else {
            continue;
        };
        let candidate = (
            svcb.svc_priority,
            HttpsServicePolicy {
                protocol,
                port: svcb.port().map_err(GatewayError::InvalidSvcb)?,
            },
        );
        if selected
            .as_ref()
            .is_none_or(|(priority, _)| candidate.0 < *priority)
        {
            selected = Some(candidate);
        }
    }

    if let Some((_, policy)) = selected {
        Ok(Some(policy))
    } else if saw_service {
        Err(GatewayError::UnsupportedSvcb)
    } else {
        Ok(None)
    }
}

fn validate_supported_mandatory_params(svcb: &SvcbRecord) -> Result<(), GatewayError> {
    let Some(value) = svcb.param(SVCB_PARAM_MANDATORY) else {
        return Ok(());
    };
    for chunk in value.chunks_exact(2) {
        let key = u16::from_be_bytes([chunk[0], chunk[1]]);
        if !matches!(
            key,
            SVCB_PARAM_ALPN | SVCB_PARAM_NO_DEFAULT_ALPN | SVCB_PARAM_PORT
        ) {
            return Err(GatewayError::UnsupportedSvcb);
        }
    }
    Ok(())
}

fn selected_alpn_protocol(
    svcb: &SvcbRecord,
    supported_protocols: &[OriginProtocol],
) -> Result<Option<OriginProtocol>, GatewayError> {
    let alpn = svcb.alpn_ids().map_err(GatewayError::InvalidSvcb)?;
    if supports_protocol(supported_protocols, OriginProtocol::Http3)
        && alpn.iter().any(|id| is_http3_alpn(id))
    {
        return Ok(Some(OriginProtocol::Http3));
    }
    if supports_protocol(supported_protocols, OriginProtocol::Http2)
        && alpn.iter().any(|id| id.as_slice() == b"h2")
    {
        return Ok(Some(OriginProtocol::Http2));
    }
    if supports_protocol(supported_protocols, OriginProtocol::Http11)
        && (alpn.iter().any(|id| id.as_slice() == b"http/1.1")
            || svcb.param(SVCB_PARAM_NO_DEFAULT_ALPN).is_none())
    {
        return Ok(Some(OriginProtocol::Http11));
    }
    Ok(None)
}

fn supports_protocol(supported_protocols: &[OriginProtocol], protocol: OriginProtocol) -> bool {
    supported_protocols.contains(&protocol)
}

fn is_http3_alpn(id: &[u8]) -> bool {
    id == b"h3" || id.starts_with(b"h3-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_core::dns::{DnsMessage, DnsName, RecordType, ResourceRecord};
    use hns_dane::{DaneDecision, DaneError, TlsaMatching, TlsaSelector, TlsaUsage};
    use hns_namespace_resolution::{
        AbsenceKind, EvidenceProvenance, Freshness, HnsNetwork, IcannChainState, OriginPlanInput,
        RootFailure, RootFailureKind, RootLookup, RootResolutionState, SelectionPolicy,
        ServiceBinding, ServiceBindingInput, ValidatedAbsence, ValidatedOriginPlan,
        decide_namespace,
    };
    use hns_resolver::{PreparedNamespaceResolution, ResolutionAnswer, Resolver};
    use hns_transport::{
        OriginProtocol, OriginResponse, OriginTransport, OriginTunnel, TlsValidation,
    };
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct StaticResolver {
        secure: bool,
        records: Vec<ResourceRecord>,
    }

    struct ScriptedResolver {
        responses: Vec<(ResolutionRequest, ResolutionAnswer)>,
        requests: Arc<Mutex<Vec<ResolutionRequest>>>,
    }

    struct PreparedResolver {
        prepared: PreparedNamespaceResolution,
        record_calls: Arc<AtomicUsize>,
    }

    struct ClassificationFailingResolver {
        error: ClassificationError,
    }

    impl Resolver for StaticResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            Ok(ResolutionAnswer {
                name: DnsName::root(),
                records: self.records.clone(),
                secure: self.secure,
            })
        }
    }

    impl Resolver for ScriptedResolver {
        fn resolve(&self, request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.requests.lock().unwrap().push(request.clone());
            self.responses
                .iter()
                .find(|(candidate, _)| candidate == request)
                .map(|(_, answer)| answer.clone())
                .ok_or(ResolverError::ProofUnavailable)
        }
    }

    impl Resolver for PreparedResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.record_calls.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::UnsupportedBackend)
        }

        fn prepare_namespace_resolution(
            &self,
            _query: &OriginQuery,
        ) -> Result<Option<PreparedNamespaceResolution>, ResolverError> {
            Ok(Some(self.prepared.clone()))
        }
    }

    impl Resolver for ClassificationFailingResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            Err(ResolverError::UnsupportedBackend)
        }

        fn prepare_namespace_resolution(
            &self,
            _query: &OriginQuery,
        ) -> Result<Option<PreparedNamespaceResolution>, ResolverError> {
            Err(ResolverError::NamespaceClassification(self.error.clone()))
        }
    }

    struct StaticTransport;

    impl OriginTransport for StaticTransport {
        fn fetch(&self, _request: &OriginRequest) -> Result<OriginResponse, TransportError> {
            Ok(OriginResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::NoTlsa,
                tls_inspection: None,
            })
        }
    }

    struct DaneFailingTransport;

    impl OriginTransport for DaneFailingTransport {
        fn fetch(&self, _request: &OriginRequest) -> Result<OriginResponse, TransportError> {
            Err(TransportError::DaneFailed)
        }

        fn open_tunnel(&self, _request: &OriginRequest) -> Result<OriginTunnel, TransportError> {
            Err(TransportError::DaneFailed)
        }
    }

    #[derive(Default)]
    struct CapturingTransport {
        last_request: Mutex<Option<OriginRequest>>,
        last_tunnel_request: Mutex<Option<OriginRequest>>,
        last_passthrough_request: Mutex<Option<OriginRequest>>,
    }

    impl OriginTransport for CapturingTransport {
        fn fetch(&self, request: &OriginRequest) -> Result<OriginResponse, TransportError> {
            *self.last_request.lock().unwrap() = Some(request.clone());
            Ok(OriginResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
                dane_decision: DaneDecision::NoTlsa,
                tls_inspection: None,
            })
        }

        fn open_tunnel(&self, request: &OriginRequest) -> Result<OriginTunnel, TransportError> {
            *self.last_tunnel_request.lock().unwrap() = Some(request.clone());
            Ok(OriginTunnel {
                response_head: b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".to_vec(),
                stream: Box::new(Cursor::new(Vec::<u8>::new())),
                dane_decision: DaneDecision::NoTlsa,
                tls_inspection: None,
            })
        }

        fn open_webpki_passthrough(
            &self,
            request: &OriginRequest,
        ) -> Result<OriginWebPkiPassthrough, TransportError> {
            struct NoopShutdown;

            impl hns_transport::OriginPassthroughShutdown for NoopShutdown {
                fn shutdown(&self) {}
            }

            *self.last_passthrough_request.lock().unwrap() = Some(request.clone());
            Ok(OriginWebPkiPassthrough {
                peer_addr: explicit_origin_socket_addr(request).unwrap(),
                reader: Box::new(Cursor::new(Vec::<u8>::new())),
                writer: Box::new(Cursor::new(Vec::<u8>::new())),
                shutdown: Arc::new(NoopShutdown),
            })
        }
    }

    struct EndpointRetryTransport {
        fail_host: String,
        fail_with_io: bool,
        attempts: Mutex<Vec<OriginRequest>>,
    }

    impl OriginTransport for EndpointRetryTransport {
        fn fetch(&self, _request: &OriginRequest) -> Result<OriginResponse, TransportError> {
            Err(TransportError::UnsupportedTransport)
        }

        fn open_webpki_passthrough(
            &self,
            request: &OriginRequest,
        ) -> Result<OriginWebPkiPassthrough, TransportError> {
            struct NoopShutdown;

            impl hns_transport::OriginPassthroughShutdown for NoopShutdown {
                fn shutdown(&self) {}
            }

            self.attempts.lock().unwrap().push(request.clone());
            if request.connect_host.as_deref() == Some(self.fail_host.as_str()) {
                return if self.fail_with_io {
                    Err(TransportError::Io("endpoint unavailable".to_owned()))
                } else {
                    Err(TransportError::InvalidRequest)
                };
            }
            Ok(OriginWebPkiPassthrough {
                peer_addr: explicit_origin_socket_addr(request).unwrap(),
                reader: Box::new(Cursor::new(Vec::<u8>::new())),
                writer: Box::new(Cursor::new(Vec::<u8>::new())),
                shutdown: Arc::new(NoopShutdown),
            })
        }

        fn open_webpki_passthrough_candidates(
            &self,
            requests: &[OriginRequest],
        ) -> Result<hns_transport::SelectedOriginWebPkiPassthrough, TransportError> {
            let mut last_io_error = None;
            for request in requests {
                match self.open_webpki_passthrough(request) {
                    Ok(transport) => {
                        return Ok(hns_transport::SelectedOriginWebPkiPassthrough { transport });
                    }
                    Err(error @ TransportError::Io(_)) => last_io_error = Some(error),
                    Err(error) => return Err(error),
                }
            }
            Err(last_io_error.unwrap_or(TransportError::InvalidRequest))
        }
    }

    struct UnauthenticatedPeerTransport;

    impl OriginTransport for UnauthenticatedPeerTransport {
        fn fetch(&self, _request: &OriginRequest) -> Result<OriginResponse, TransportError> {
            Err(TransportError::UnsupportedTransport)
        }

        fn open_webpki_passthrough_candidates(
            &self,
            _requests: &[OriginRequest],
        ) -> Result<hns_transport::SelectedOriginWebPkiPassthrough, TransportError> {
            struct NoopShutdown;

            impl hns_transport::OriginPassthroughShutdown for NoopShutdown {
                fn shutdown(&self) {}
            }

            Ok(hns_transport::SelectedOriginWebPkiPassthrough {
                transport: OriginWebPkiPassthrough {
                    peer_addr: "8.8.8.8:443".parse().unwrap(),
                    reader: Box::new(Cursor::new(Vec::<u8>::new())),
                    writer: Box::new(Cursor::new(Vec::<u8>::new())),
                    shutdown: Arc::new(NoopShutdown),
                },
            })
        }
    }

    fn prepared_icann_only(host: &str) -> PreparedNamespaceResolution {
        prepared_icann_only_with_capabilities(host, ProtocolCapabilities::all())
    }

    fn prepared_icann_only_with_capabilities(
        host: &str,
        capabilities: ProtocolCapabilities,
    ) -> PreparedNamespaceResolution {
        let host = CanonicalHost::parse(host).unwrap();
        let query = OriginQuery::new(
            host.clone(),
            OriginScheme::Https,
            NonZeroU16::new(443),
            capabilities,
        );
        let freshness = Freshness::new(1, u64::MAX).unwrap();
        let service = ServiceBinding::new(ServiceBindingInput {
            priority: None,
            service_target: host.clone(),
            mandatory_keys: Vec::new(),
            advertised_alpn: Vec::new(),
            selected_protocol: ApplicationProtocol::Http11,
            effective_port: NonZeroU16::new(443).unwrap(),
            transport: ServiceTransport::Tcp,
            connection_hints: Vec::new(),
            ech_config: None,
            parameters: Vec::new(),
        })
        .unwrap();
        let plan = ValidatedOriginPlan::new(OriginPlanInput {
            namespace: Namespace::Icann,
            query: query.clone(),
            alias_path: Vec::new(),
            terminal_target: host.clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host,
            endpoints: vec!["1.1.1.1:443".parse().unwrap()],
            service,
            tls_policy: TlsTrustPolicy::Dane,
            tlsa_records: vec![
                CanonicalTlsa::new(
                    [vec![3, 1, 1], vec![0xaa; 32]]
                        .into_iter()
                        .flatten()
                        .collect(),
                )
                .unwrap(),
            ],
            provenance: EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
            freshness,
        })
        .unwrap();
        let hns_absence = ValidatedAbsence::new(
            Namespace::Hns,
            query.clone(),
            AbsenceKind::HnsCurrentUrkelNonInclusion,
            EvidenceProvenance::Hns {
                network: HnsNetwork::Mainnet,
                tree_root: [7; 32],
                height: 42,
            },
            freshness,
        )
        .unwrap();
        let decision = decide_namespace(
            &query,
            RootLookup::Absent(hns_absence),
            RootLookup::Present(plan),
            SelectionPolicy::default(),
            2,
        )
        .unwrap();
        PreparedNamespaceResolution {
            decision,
            selected_answer: Some(ResolutionAnswer {
                name: DnsName::from_ascii("example.com").unwrap(),
                records: Vec::new(),
                secure: true,
            }),
        }
    }

    fn prepared_icann_webpki(host: &str) -> PreparedNamespaceResolution {
        prepared_icann_webpki_with_endpoints(host, vec!["1.1.1.1:443".parse().unwrap()])
    }

    fn prepared_icann_webpki_with_endpoints(
        host: &str,
        endpoints: Vec<SocketAddr>,
    ) -> PreparedNamespaceResolution {
        let host = CanonicalHost::parse(host).unwrap();
        let capabilities = ProtocolCapabilities::new(true, true, false).unwrap();
        let query = OriginQuery::new(
            host.clone(),
            OriginScheme::Https,
            NonZeroU16::new(443),
            capabilities,
        );
        let freshness = Freshness::new(1, u64::MAX).unwrap();
        let service = ServiceBinding::new(ServiceBindingInput {
            priority: None,
            service_target: host.clone(),
            mandatory_keys: Vec::new(),
            advertised_alpn: Vec::new(),
            selected_protocol: ApplicationProtocol::Http11,
            effective_port: NonZeroU16::new(443).unwrap(),
            transport: ServiceTransport::Tcp,
            connection_hints: Vec::new(),
            ech_config: None,
            parameters: Vec::new(),
        })
        .unwrap();
        let plan = ValidatedOriginPlan::new(OriginPlanInput {
            namespace: Namespace::Icann,
            query: query.clone(),
            alias_path: Vec::new(),
            terminal_target: host.clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host,
            endpoints,
            service,
            tls_policy: TlsTrustPolicy::WebPkiAuthenticatedAbsence,
            tlsa_records: Vec::new(),
            provenance: EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
            freshness,
        })
        .unwrap();
        let hns_absence = ValidatedAbsence::new(
            Namespace::Hns,
            query.clone(),
            AbsenceKind::HnsCurrentUrkelNonInclusion,
            EvidenceProvenance::Hns {
                network: HnsNetwork::Mainnet,
                tree_root: [7; 32],
                height: 42,
            },
            freshness,
        )
        .unwrap();
        let decision = decide_namespace(
            &query,
            RootLookup::Absent(hns_absence),
            RootLookup::Present(plan),
            SelectionPolicy::default(),
            2,
        )
        .unwrap();
        PreparedNamespaceResolution {
            decision,
            selected_answer: Some(ResolutionAnswer {
                name: DnsName::from_ascii("example.com").unwrap(),
                records: Vec::new(),
                secure: true,
            }),
        }
    }

    fn prepared_hns_dane(host: &str) -> PreparedNamespaceResolution {
        let host = CanonicalHost::parse(host).unwrap();
        let query = OriginQuery::new(
            host.clone(),
            OriginScheme::Https,
            NonZeroU16::new(443),
            ProtocolCapabilities::new(true, true, false).unwrap(),
        );
        let freshness = Freshness::new(1, u64::MAX).unwrap();
        let service = ServiceBinding::new(ServiceBindingInput {
            priority: None,
            service_target: host.clone(),
            mandatory_keys: Vec::new(),
            advertised_alpn: Vec::new(),
            selected_protocol: ApplicationProtocol::Http11,
            effective_port: NonZeroU16::new(443).unwrap(),
            transport: ServiceTransport::Tcp,
            connection_hints: Vec::new(),
            ech_config: None,
            parameters: Vec::new(),
        })
        .unwrap();
        let plan = ValidatedOriginPlan::new(OriginPlanInput {
            namespace: Namespace::Hns,
            query: query.clone(),
            alias_path: Vec::new(),
            terminal_target: host.clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: host.clone(),
            endpoints: vec!["1.1.1.1:443".parse().unwrap()],
            service,
            tls_policy: TlsTrustPolicy::Dane,
            tlsa_records: vec![
                CanonicalTlsa::new({
                    let mut rdata = vec![3, 1, 1];
                    rdata.extend_from_slice(&[0xbb; 32]);
                    rdata
                })
                .unwrap(),
            ],
            provenance: EvidenceProvenance::Hns {
                network: HnsNetwork::Mainnet,
                tree_root: [8; 32],
                height: 43,
            },
            freshness,
        })
        .unwrap();
        let icann_absence = ValidatedAbsence::new(
            Namespace::Icann,
            query.clone(),
            AbsenceKind::DnssecAuthenticatedNxDomain,
            EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
            freshness,
        )
        .unwrap();
        let decision = decide_namespace(
            &query,
            RootLookup::Present(plan),
            RootLookup::Absent(icann_absence),
            SelectionPolicy::default(),
            2,
        )
        .unwrap();
        PreparedNamespaceResolution {
            decision,
            selected_answer: Some(ResolutionAnswer {
                name: DnsName::from_ascii(host.as_str()).unwrap(),
                records: Vec::new(),
                secure: true,
            }),
        }
    }

    #[test]
    fn browser_connect_passthrough_requires_selected_icann_webpki_fallback() {
        let record_calls = Arc::new(AtomicUsize::new(0));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            PreparedResolver {
                prepared: prepared_icann_webpki("example.com"),
                record_calls: Arc::clone(&record_calls),
            },
            CapturingTransport::default(),
        )
        .unwrap();

        let disposition = gateway
            .open_browser_connect_with_failure_context(&request("example.com", "example.com"))
            .unwrap();
        let GatewayConnectDisposition::WebPkiPassthrough(passthrough) = disposition else {
            panic!("authenticated ICANN WebPKI fallback must preserve browser TLS");
        };

        assert_eq!(record_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            passthrough.namespace_decision.selected_namespace(),
            Some(Namespace::Icann)
        );
        assert_eq!(
            passthrough.origin_request.connect_host.as_deref(),
            Some("1.1.1.1")
        );
        assert_eq!(
            passthrough.origin_request.tls.browser_tls_decision,
            Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence)
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
        assert!(
            gateway
                .transport()
                .last_passthrough_request
                .lock()
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn browser_connect_retries_all_selected_public_endpoints_after_io_failure() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            PreparedResolver {
                prepared: prepared_icann_webpki_with_endpoints(
                    "example.com",
                    vec![
                        "8.8.8.8:443".parse().unwrap(),
                        "1.1.1.1:443".parse().unwrap(),
                        "127.0.0.1:443".parse().unwrap(),
                    ],
                ),
                record_calls: Arc::new(AtomicUsize::new(0)),
            },
            EndpointRetryTransport {
                fail_host: "1.1.1.1".to_owned(),
                fail_with_io: true,
                attempts: Mutex::new(Vec::new()),
            },
        )
        .unwrap();

        let disposition = gateway
            .open_browser_connect_with_failure_context(&request("example.com", "example.com"))
            .unwrap();
        let GatewayConnectDisposition::WebPkiPassthrough(passthrough) = disposition else {
            panic!("second selected endpoint must preserve browser TLS");
        };
        let attempts = gateway.transport().attempts.lock().unwrap();

        assert_eq!(
            attempts
                .iter()
                .map(|attempt| attempt.connect_host.as_deref().unwrap())
                .collect::<Vec<_>>(),
            vec!["1.1.1.1", "8.8.8.8"]
        );
        assert!(attempts.iter().all(|attempt| {
            attempt
                .connect_host
                .as_deref()
                .unwrap()
                .parse::<IpAddr>()
                .is_ok()
        }));
        assert_eq!(attempts[0].host, attempts[1].host);
        assert_eq!(attempts[0].port, attempts[1].port);
        assert_eq!(attempts[0].tls, attempts[1].tls);
        assert!(attempts[0].tls.namespace_fingerprint.is_some());
        assert_eq!(
            passthrough.origin_request.connect_host.as_deref(),
            Some("8.8.8.8")
        );
    }

    #[test]
    fn browser_connect_does_not_retry_non_io_policy_failure() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            PreparedResolver {
                prepared: prepared_icann_webpki_with_endpoints(
                    "example.com",
                    vec![
                        "8.8.8.8:443".parse().unwrap(),
                        "1.1.1.1:443".parse().unwrap(),
                    ],
                ),
                record_calls: Arc::new(AtomicUsize::new(0)),
            },
            EndpointRetryTransport {
                fail_host: "1.1.1.1".to_owned(),
                fail_with_io: false,
                attempts: Mutex::new(Vec::new()),
            },
        )
        .unwrap();

        let failure = gateway
            .open_browser_connect_with_failure_context(&request("example.com", "example.com"))
            .err()
            .expect("transport invariant failure must remain terminal");

        assert!(matches!(
            failure.error(),
            GatewayError::Transport(TransportError::InvalidRequest)
        ));
        assert_eq!(gateway.transport().attempts.lock().unwrap().len(), 1);
    }

    #[test]
    fn browser_connect_rejects_transport_peer_outside_authenticated_endpoint_set() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            PreparedResolver {
                prepared: prepared_icann_webpki_with_endpoints(
                    "example.com",
                    vec!["1.1.1.1:443".parse().unwrap()],
                ),
                record_calls: Arc::new(AtomicUsize::new(0)),
            },
            UnauthenticatedPeerTransport,
        )
        .unwrap();

        let failure = gateway
            .open_browser_connect_with_failure_context(&request("example.com", "example.com"))
            .err()
            .expect("the connected peer must belong to the authenticated endpoint set");

        assert!(matches!(
            failure.error(),
            GatewayError::Transport(TransportError::InvalidRequest)
        ));
        assert_eq!(
            failure
                .namespace_decision()
                .and_then(NamespaceDecision::selected_namespace),
            Some(Namespace::Icann)
        );
    }

    #[test]
    fn browser_connect_open_failure_retains_selected_webpki_decision() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            PreparedResolver {
                prepared: prepared_icann_webpki("example.com"),
                record_calls: Arc::new(AtomicUsize::new(0)),
            },
            DaneFailingTransport,
        )
        .unwrap();

        let failure = gateway
            .open_browser_connect_with_failure_context(&request("example.com", "example.com"))
            .err()
            .expect("unsupported raw transport must fail after namespace selection");
        assert!(matches!(
            failure.error(),
            GatewayError::Transport(TransportError::UnsupportedTransport)
        ));
        assert_eq!(
            failure
                .namespace_decision()
                .and_then(NamespaceDecision::selected_namespace),
            Some(Namespace::Icann)
        );
        assert!(matches!(
            failure
                .namespace_decision()
                .and_then(NamespaceDecision::selected_plan)
                .map(ValidatedOriginPlan::tls_policy),
            Some(TlsTrustPolicy::WebPkiAuthenticatedAbsence)
        ));
    }

    #[test]
    fn selected_webpki_plan_rejects_mismatched_browser_tls_invariants() {
        let webpki = prepared_icann_webpki("example.com");
        let plan = webpki.decision.selected_plan().unwrap();
        let mut tls = hns_transport::TlsValidation {
            browser_tls_decision: Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence),
            service_transport: TlsaTransport::Tcp,
            ..Default::default()
        };
        assert_eq!(selected_browser_connect_uses_webpki(plan, &tls), Ok(true));

        tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiInsecureDelegation);
        assert_eq!(
            selected_browser_connect_uses_webpki(plan, &tls),
            Err(TransportError::InvalidRequest)
        );
        tls.browser_tls_decision = Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence);
        tls.service_transport = TlsaTransport::Udp;
        assert_eq!(
            selected_browser_connect_uses_webpki(plan, &tls),
            Err(TransportError::InvalidRequest)
        );

        let dane = prepared_icann_only("example.com");
        assert_eq!(
            selected_browser_connect_uses_webpki(dane.decision.selected_plan().unwrap(), &tls),
            Ok(false)
        );
    }

    #[test]
    fn browser_connect_keeps_icann_dane_on_the_intercept_path() {
        let prepared = prepared_icann_only_with_capabilities(
            "example.com",
            ProtocolCapabilities::new(true, true, false).unwrap(),
        );
        let gateway = Gateway::new(
            GatewayConfig::default(),
            PreparedResolver {
                prepared,
                record_calls: Arc::new(AtomicUsize::new(0)),
            },
            CapturingTransport::default(),
        )
        .unwrap();

        assert!(matches!(
            gateway
                .open_browser_connect_with_failure_context(&request("example.com", "example.com"))
                .unwrap(),
            GatewayConnectDisposition::Intercept
        ));
        assert!(
            gateway
                .transport()
                .last_passthrough_request
                .lock()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn browser_connect_keeps_hns_dane_on_the_intercept_path() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            PreparedResolver {
                prepared: prepared_hns_dane("welcome"),
                record_calls: Arc::new(AtomicUsize::new(0)),
            },
            CapturingTransport::default(),
        )
        .unwrap();

        assert!(matches!(
            gateway
                .open_browser_connect_with_failure_context(&request("welcome", "welcome"))
                .unwrap(),
            GatewayConnectDisposition::Intercept
        ));
        assert!(
            gateway
                .transport()
                .last_passthrough_request
                .lock()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn prepared_dual_root_plan_is_atomic_and_sets_live_fingerprint() {
        let prepared = prepared_icann_only("example.com");
        let expected_fingerprint = decision_fingerprint(&prepared.decision).to_hex();
        let record_calls = Arc::new(AtomicUsize::new(0));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            PreparedResolver {
                prepared,
                record_calls: Arc::clone(&record_calls),
            },
            CapturingTransport::default(),
        )
        .unwrap();

        let response = gateway
            .handle(&request("example.com", "example.com"))
            .unwrap();

        assert_eq!(record_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            response
                .namespace_decision
                .as_ref()
                .and_then(NamespaceDecision::selected_namespace),
            Some(Namespace::Icann)
        );
        assert_eq!(
            response.origin_request.connect_host.as_deref(),
            Some("1.1.1.1")
        );
        assert_eq!(response.origin_request.port, 443);
        assert_eq!(
            response.origin_request.tls.namespace_fingerprint.as_deref(),
            Some(expected_fingerprint.as_str())
        );
        assert_eq!(
            response.origin_request.tls.browser_tls_decision,
            Some(BrowserTlsDecision::EnforceDane {
                record_count: NonZeroUsize::new(1).unwrap(),
            })
        );
    }

    #[test]
    fn contextual_handlers_retain_classification_and_post_selection_decisions() {
        for tunnel in [false, true] {
            let capabilities = if tunnel {
                ProtocolCapabilities::new(true, false, false).unwrap()
            } else {
                ProtocolCapabilities::all()
            };
            let prepared = prepared_icann_only_with_capabilities("example.com", capabilities);
            let expected_decision = prepared.decision.clone();
            let gateway = Gateway::new(
                GatewayConfig::default(),
                PreparedResolver {
                    prepared: prepared.clone(),
                    record_calls: Arc::new(AtomicUsize::new(0)),
                },
                DaneFailingTransport,
            )
            .unwrap();
            let failure = if tunnel {
                match gateway
                    .handle_tunnel_with_failure_context(&request("example.com", "example.com"))
                {
                    Err(failure) => failure,
                    Ok(_) => panic!("DANE-failing tunnel transport must fail"),
                }
            } else {
                gateway
                    .handle_with_failure_context(&request("example.com", "example.com"))
                    .unwrap_err()
            };
            assert_eq!(
                failure.error(),
                &GatewayError::Transport(TransportError::DaneFailed)
            );
            assert_eq!(failure.namespace_decision(), Some(&expected_decision));
            assert_eq!(failure.classification_error(), None);
        }

        let query = prepared_icann_only("example.com").decision.query().clone();
        let classification = ClassificationError::RootFailed {
            hns: RootResolutionState::Absent,
            icann: RootResolutionState::Failed(RootFailure::new(
                Namespace::Icann,
                query,
                RootFailureKind::BogusDnssec,
                None,
            )),
        };
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ClassificationFailingResolver {
                error: classification.clone(),
            },
            StaticTransport,
        )
        .unwrap();
        let failure = gateway
            .handle_with_failure_context(&request("example.com", "example.com"))
            .unwrap_err();
        assert_eq!(failure.classification_error(), Some(&classification));
        assert_eq!(failure.namespace_decision(), None);
    }

    #[test]
    fn rejects_non_loopback_bind() {
        let config = GatewayConfig {
            bind: "0.0.0.0:15353".parse().unwrap(),
            ..GatewayConfig::default()
        };

        assert_eq!(
            config.validate().unwrap_err(),
            GatewayError::NonLoopbackBind
        );
    }

    #[test]
    fn rejects_empty_gateway_auth_token() {
        let config = GatewayConfig {
            auth_token: Some(String::new()),
            ..GatewayConfig::default()
        };

        assert_eq!(config.validate().unwrap_err(), GatewayError::EmptyAuthToken);
    }

    #[test]
    fn configured_gateway_authentication_is_enforced() {
        let config = GatewayConfig {
            auth_token: Some("correct horse battery staple".to_owned()),
            ..GatewayConfig::default()
        };
        assert!(!format!("{config:?}").contains("correct horse"));
        let gateway = Gateway::new(
            config,
            StaticResolver::secure_with_address(),
            StaticTransport,
        )
        .unwrap();
        let mut request = request("name", "name");

        assert_eq!(
            gateway.handle(&request).unwrap_err(),
            GatewayError::Unauthorized
        );
        request.auth_token = Some("wrong".to_owned());
        assert_eq!(
            gateway.handle(&request).unwrap_err(),
            GatewayError::Unauthorized
        );
        request.auth_token = Some("correct horse battery staple".to_owned());
        assert_eq!(gateway.handle(&request).unwrap().origin.status, 200);
    }

    #[test]
    fn rejects_non_public_origin_address_by_default() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![ResourceRecord {
                    name: DnsName::from_ascii("name").unwrap(),
                    record_type: RecordType::A,
                    class: 1,
                    ttl: 60,
                    rdata: vec![169, 254, 169, 254],
                }],
            },
            StaticTransport,
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::NonPublicOriginAddress
        );
    }

    #[test]
    fn non_public_origin_address_requires_explicit_opt_in() {
        let gateway = Gateway::new(
            GatewayConfig {
                allow_non_public_origin_addresses: true,
                ..GatewayConfig::default()
            },
            StaticResolver {
                secure: true,
                records: vec![ResourceRecord {
                    name: DnsName::from_ascii("name").unwrap(),
                    record_type: RecordType::A,
                    class: 1,
                    ttl: 60,
                    rdata: vec![1, 1, 1, 1],
                }],
            },
            StaticTransport,
        )
        .unwrap();

        assert_eq!(
            gateway
                .handle(&request("name", "name"))
                .unwrap()
                .origin
                .status,
            200
        );
    }

    #[test]
    fn ignores_untrusted_connection_override() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver::secure_with_address(),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.origin.connect_host = Some("127.0.0.1".to_owned());

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.connect_host, Some("1.1.1.1".to_owned()));
    }

    #[test]
    fn rejects_browser_blocked_origin_port() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver::secure_with_address(),
            StaticTransport,
        )
        .unwrap();
        let mut request = request("name", "name");
        request.origin.port = 22;

        assert_eq!(
            gateway.handle(&request).unwrap_err(),
            GatewayError::UnsafeOriginPort(22)
        );
    }

    #[test]
    fn rejects_host_resolution_mismatch() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver::secure(),
            StaticTransport,
        )
        .unwrap();

        let request = request("name", "other");

        assert_eq!(
            gateway.handle(&request).unwrap_err(),
            GatewayError::HostResolutionMismatch,
        );
    }

    #[test]
    fn rejects_insecure_resolution_by_default() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver::insecure(),
            StaticTransport,
        )
        .unwrap();

        let request = request("name", "name");

        assert_eq!(
            gateway.handle(&request).unwrap_err(),
            GatewayError::InsecureResolution,
        );
    }

    #[test]
    fn rejects_unsigned_hns_http_origin() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![response(
                    "name",
                    RecordType::A.code(),
                    false,
                    vec![address_record()],
                )],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.origin.scheme = "http".to_owned();
        request.origin.port = 80;

        assert_eq!(
            gateway.handle(&request).unwrap_err(),
            GatewayError::InsecureResolution,
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
    }

    #[test]
    fn returns_resolution_and_origin_response() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver::secure_with_address(),
            StaticTransport,
        )
        .unwrap();

        let response = gateway.handle(&request("name", "name")).unwrap();

        assert!(response.resolution.secure);
        assert_eq!(response.origin.status, 200);
    }

    #[test]
    fn rejects_hns_resolution_without_origin_address() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver::secure(),
            StaticTransport,
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::NoResolvedAddress,
        );
    }

    #[test]
    fn rejects_nameserver_glue_as_origin_address() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![
                    ResourceRecord {
                        name: DnsName::from_ascii("name").unwrap(),
                        record_type: RecordType::Ns,
                        class: 1,
                        ttl: 60,
                        rdata: name_rdata("ns1.name"),
                    },
                    ResourceRecord {
                        name: DnsName::from_ascii("ns1.name").unwrap(),
                        record_type: RecordType::A,
                        class: 1,
                        ttl: 60,
                        rdata: vec![127, 0, 0, 1],
                    },
                ],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::NoResolvedAddress,
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
    }

    #[test]
    fn passes_resolved_address_to_transport() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![ResourceRecord {
                    name: DnsName::from_ascii("name").unwrap(),
                    record_type: RecordType::A,
                    class: 1,
                    ttl: 60,
                    rdata: vec![1, 1, 1, 1],
                }],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        gateway.handle(&request("name", "name")).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.host, "name");
        assert_eq!(captured.connect_host, Some("1.1.1.1".to_owned()));
    }

    #[test]
    fn resolves_origin_address_after_all_root_records_return_delegation_only() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response(
                        "name",
                        u16::MAX,
                        true,
                        vec![ns_record("name", "ns1.name"), ds_record("name")],
                    ),
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response("_443._tcp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.resolution.qtype = u16::MAX;

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.connect_host, Some("1.1.1.1".to_owned()));
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: u16::MAX,
                },
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: RecordType::Https.code(),
                },
                ResolutionRequest {
                    qname: "_443._tcp.name".to_owned(),
                    qtype: RecordType::Tlsa.code(),
                },
            ],
        );
    }

    #[test]
    fn falls_back_to_aaaa_when_delegated_a_has_no_address() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response("name", u16::MAX, true, vec![ds_record("name")]),
                    response("name", RecordType::A.code(), true, vec![]),
                    response(
                        "name",
                        RecordType::Aaaa.code(),
                        true,
                        vec![address_record_v6()],
                    ),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response("_443._tcp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.resolution.qtype = u16::MAX;

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(
            captured.connect_host,
            Some("2606:4700:4700::1111".to_owned())
        );
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .map(|request| request.qtype)
                .collect::<Vec<_>>(),
            vec![
                u16::MAX,
                RecordType::A.code(),
                RecordType::Aaaa.code(),
                RecordType::Https.code(),
                RecordType::Tlsa.code(),
            ],
        );
    }

    #[test]
    fn passes_cname_resolved_address_to_transport() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![
                    cname_record("name", "edge.name"),
                    ResourceRecord {
                        name: DnsName::from_ascii("edge.name").unwrap(),
                        record_type: RecordType::A,
                        class: 1,
                        ttl: 60,
                        rdata: vec![1, 1, 1, 1],
                    },
                ],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        gateway.handle(&request("name", "name")).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.host, "name");
        assert_eq!(captured.connect_host, Some("1.1.1.1".to_owned()));
    }

    #[test]
    fn accepts_compressed_cname_target_from_dns_wire() {
        let message = b"\x12\x34\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x07\x04edge\xc0\x0c\xc0\x29\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x01\x01\x01";
        let parsed = DnsMessage::parse(message).unwrap();

        assert_eq!(
            first_resolved_address(&parsed.answers, "example.com").as_deref(),
            Some("1.1.1.1")
        );
    }

    #[test]
    fn selects_http2_from_https_service_alpn() {
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11, OriginProtocol::Http2]),
            ScriptedResolver::new(
                vec![
                    response(
                        "name",
                        u16::MAX,
                        true,
                        vec![
                            address_record(),
                            https_record("name", 1, ".", vec![alpn_param(&[b"h2"])]),
                        ],
                    ),
                    response("_443._tcp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.resolution.qtype = u16::MAX;

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.protocol, OriginProtocol::Http2);
        assert_eq!(captured.port, 443);
    }

    #[test]
    fn resolves_https_service_policy_when_initial_answer_is_address_only() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11, OriginProtocol::Http2]),
            ScriptedResolver::new(
                vec![
                    response(
                        "www.name",
                        RecordType::A.code(),
                        true,
                        vec![address_record_for("www.name")],
                    ),
                    response(
                        "www.name",
                        RecordType::Https.code(),
                        true,
                        vec![https_record(
                            "www.name",
                            1,
                            ".",
                            vec![alpn_param(&[b"h2"]), port_param(8443)],
                        )],
                    ),
                    response("_8443._tcp.www.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("www.name", "www.name");
        request.resolution.qtype = RecordType::A.code();

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.protocol, OriginProtocol::Http2);
        assert_eq!(captured.port, 8443);
        assert_eq!(captured.tls.service_port, 8443);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "www.name".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "www.name".to_owned(),
                    qtype: RecordType::Https.code(),
                },
                ResolutionRequest {
                    qname: "_8443._tcp.www.name".to_owned(),
                    qtype: RecordType::Tlsa.code(),
                },
            ],
        );
    }

    #[test]
    fn ignores_https_service_policy_resolver_failure_and_still_checks_tlsa() {
        struct HttpsPolicyErrorResolver {
            requests: Arc<Mutex<Vec<ResolutionRequest>>>,
        }

        impl Resolver for HttpsPolicyErrorResolver {
            fn resolve(
                &self,
                request: &ResolutionRequest,
            ) -> Result<ResolutionAnswer, ResolverError> {
                self.requests.lock().unwrap().push(request.clone());
                match RecordType::from_code(request.qtype) {
                    RecordType::A => Ok(ResolutionAnswer {
                        name: DnsName::from_ascii(&request.qname).unwrap(),
                        records: vec![address_record_for(&request.qname)],
                        secure: true,
                    }),
                    RecordType::Https => Err(ResolverError::DnssecFailed),
                    RecordType::Tlsa => Ok(ResolutionAnswer {
                        name: DnsName::from_ascii(&request.qname).unwrap(),
                        records: vec![tlsa_record(&request.qname, vec![3, 1, 0, 0xaa])],
                        secure: true,
                    }),
                    _ => Err(ResolverError::ProofUnavailable),
                }
            }
        }

        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11, OriginProtocol::Http2]),
            HttpsPolicyErrorResolver {
                requests: Arc::clone(&requests),
            },
            CapturingTransport::default(),
        )
        .unwrap();

        gateway.handle(&request("name", "name")).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.protocol, OriginProtocol::Http11);
        assert_eq!(captured.port, 443);
        assert!(captured.tls.dnssec_secure);
        assert_eq!(captured.tls.tlsa_records.len(), 1);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: RecordType::Https.code(),
                },
                ResolutionRequest {
                    qname: "_443._tcp.name".to_owned(),
                    qtype: RecordType::Tlsa.code(),
                },
            ],
        );
    }

    #[test]
    fn selects_http3_and_service_port_from_https_service_alpn() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11, OriginProtocol::Http3]),
            ScriptedResolver::new(
                vec![
                    response(
                        "name",
                        u16::MAX,
                        true,
                        vec![
                            address_record(),
                            https_record(
                                "name",
                                1,
                                ".",
                                vec![alpn_param(&[b"h3"]), port_param(8443)],
                            ),
                        ],
                    ),
                    response("_8443._udp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.resolution.qtype = u16::MAX;

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.protocol, OriginProtocol::Http3);
        assert_eq!(captured.port, 8443);
        assert_eq!(
            requests.lock().unwrap().last().unwrap(),
            &ResolutionRequest {
                qname: "_8443._udp.name".to_owned(),
                qtype: RecordType::Tlsa.code(),
            },
        );
    }

    #[test]
    fn rejects_browser_blocked_https_service_port() {
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11]),
            ScriptedResolver::new(
                vec![
                    response(
                        "name",
                        u16::MAX,
                        true,
                        vec![
                            address_record(),
                            https_record(
                                "name",
                                1,
                                ".",
                                vec![alpn_param(&[b"http/1.1"]), port_param(22)],
                            ),
                        ],
                    ),
                    response("_22._tcp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.resolution.qtype = u16::MAX;

        assert_eq!(
            gateway.handle(&request).unwrap_err(),
            GatewayError::UnsafeOriginPort(22)
        );
    }

    #[test]
    fn defaults_to_http11_when_unsupported_alpn_allows_default_protocols() {
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11]),
            ScriptedResolver::new(
                vec![
                    response(
                        "name",
                        u16::MAX,
                        true,
                        vec![
                            address_record(),
                            https_record("name", 1, ".", vec![alpn_param(&[b"h2"])]),
                        ],
                    ),
                    response("_443._tcp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.resolution.qtype = u16::MAX;

        gateway.handle(&request).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.protocol, OriginProtocol::Http11);
        assert_eq!(captured.port, 443);
    }

    #[test]
    fn rejects_https_service_when_no_supported_alpn_remains() {
        let gateway = Gateway::new(
            gateway_config_with_protocols(vec![OriginProtocol::Http11]),
            StaticResolver {
                secure: true,
                records: vec![
                    address_record(),
                    https_record(
                        "name",
                        1,
                        ".",
                        vec![alpn_param(&[b"h2"]), no_default_alpn_param()],
                    ),
                ],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::UnsupportedSvcb,
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
    }

    #[test]
    fn rejects_https_service_alias_mode_until_alias_resolution_is_supported() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![
                    address_record(),
                    https_record("name", 0, "alias.name", Vec::new()),
                ],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::UnsupportedSvcb,
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
    }

    #[test]
    fn passes_secure_tlsa_records_to_https_transport() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response(
                        "_443._tcp.name",
                        RecordType::Tlsa.code(),
                        true,
                        vec![
                            tlsa_record("_443._tcp.other", vec![3, 1, 0, 0xbb]),
                            tlsa_record("_8443._tcp.name", vec![3, 1, 0, 0xcc]),
                            tlsa_record("_443._tcp.name", vec![3, 1, 0, 0xaa]),
                        ],
                    ),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        gateway.handle(&request("name", "name")).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert!(captured.tls.dnssec_secure);
        assert_eq!(captured.tls.tlsa_records.len(), 1);
        assert_eq!(captured.tls.tlsa_records[0].usage, TlsaUsage::DaneEe);
        assert_eq!(
            captured.tls.tlsa_records[0].selector,
            TlsaSelector::SubjectPublicKeyInfo,
        );
        assert_eq!(captured.tls.tlsa_records[0].matching, TlsaMatching::Exact);
        assert_eq!(captured.tls.tlsa_records[0].association_data, vec![0xaa],);
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "name".to_owned(),
                    qtype: RecordType::Https.code(),
                },
                ResolutionRequest {
                    qname: "_443._tcp.name".to_owned(),
                    qtype: RecordType::Tlsa.code(),
                },
            ],
        );
    }

    #[test]
    fn icann_hosts_use_icann_webpki_tls_mode() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response(
                        "example.com",
                        RecordType::A.code(),
                        true,
                        vec![address_record_for("example.com")],
                    ),
                    response("example.com", RecordType::Https.code(), true, vec![]),
                    response(
                        "_443._tcp.example.com",
                        RecordType::Tlsa.code(),
                        true,
                        vec![],
                    ),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        gateway
            .handle(&request("example.com", "example.com"))
            .unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.tls.mode, DomainTrustMode::IcannWebPki);
        assert!(captured.tls.tlsa_records.is_empty());
        assert_eq!(captured.tls.tlsa_source, None);
        assert_eq!(
            captured.tls.browser_tls_decision,
            Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence),
        );
    }

    #[test]
    fn icann_native_tlsa_records_are_used() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response(
                        "example.com",
                        RecordType::A.code(),
                        true,
                        vec![address_record_for("example.com")],
                    ),
                    response("example.com", RecordType::Https.code(), true, vec![]),
                    response(
                        "_443._tcp.example.com",
                        RecordType::Tlsa.code(),
                        true,
                        vec![tlsa_record("_443._tcp.example.com", vec![3, 1, 1, 0xaa])],
                    ),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        gateway
            .handle(&request("example.com", "example.com"))
            .unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.tls.mode, DomainTrustMode::IcannWebPki);
        assert!(captured.tls.dnssec_secure);
        assert_eq!(captured.tls.tlsa_source, Some(TlsaRecordSource::NativeTlsa));
        assert_eq!(captured.tls.tlsa_records.len(), 1);
        assert_eq!(captured.tls.tlsa_records[0].usage, TlsaUsage::DaneEe);
        assert_eq!(
            captured.tls.tlsa_records[0].selector,
            TlsaSelector::SubjectPublicKeyInfo
        );
        assert_eq!(captured.tls.tlsa_records[0].matching, TlsaMatching::Sha256);
        assert_eq!(captured.tls.tlsa_records[0].association_data, vec![0xaa]);
        assert_eq!(
            captured.tls.browser_tls_decision,
            Some(BrowserTlsDecision::EnforceDane {
                record_count: std::num::NonZeroUsize::new(1).unwrap(),
            }),
        );
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "example.com".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "example.com".to_owned(),
                    qtype: RecordType::Https.code(),
                },
                ResolutionRequest {
                    qname: "_443._tcp.example.com".to_owned(),
                    qtype: RecordType::Tlsa.code(),
                },
            ],
        );
    }

    #[test]
    fn icann_native_tlsa_no_data_does_not_query_txt() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response(
                        "example.com",
                        RecordType::A.code(),
                        true,
                        vec![address_record_for("example.com")],
                    ),
                    response("example.com", RecordType::Https.code(), true, vec![]),
                    response(
                        "_443._tcp.example.com",
                        RecordType::Tlsa.code(),
                        true,
                        vec![],
                    ),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        gateway
            .handle(&request("example.com", "example.com"))
            .unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.tls.mode, DomainTrustMode::IcannWebPki);
        assert!(captured.tls.dnssec_secure);
        assert!(captured.tls.tlsa_records.is_empty());
        assert_eq!(captured.tls.tlsa_source, None);
        assert_eq!(
            captured.tls.browser_tls_decision,
            Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence),
        );
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                ResolutionRequest {
                    qname: "example.com".to_owned(),
                    qtype: RecordType::A.code(),
                },
                ResolutionRequest {
                    qname: "example.com".to_owned(),
                    qtype: RecordType::Https.code(),
                },
                ResolutionRequest {
                    qname: "_443._tcp.example.com".to_owned(),
                    qtype: RecordType::Tlsa.code(),
                },
            ],
        );
    }

    #[test]
    fn icann_unsigned_delegation_ignores_unsigned_tlsa_and_uses_webpki() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response(
                        "example.com",
                        RecordType::A.code(),
                        false,
                        vec![address_record_for("example.com")],
                    ),
                    response("example.com", RecordType::Https.code(), false, vec![]),
                    response(
                        "_443._tcp.example.com",
                        RecordType::Tlsa.code(),
                        false,
                        vec![tlsa_record("_443._tcp.example.com", vec![3, 1, 1, 0xaa])],
                    ),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        gateway
            .handle(&request("example.com", "example.com"))
            .unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.tls.mode, DomainTrustMode::IcannWebPki);
        assert!(!captured.tls.dnssec_secure);
        assert!(captured.tls.tlsa_records.is_empty());
        assert_eq!(captured.tls.tlsa_source, None);
        assert_eq!(
            captured.tls.browser_tls_decision,
            Some(BrowserTlsDecision::WebPkiInsecureDelegation),
        );
        assert_eq!(
            requests.lock().unwrap().last().unwrap().qname,
            "_443._tcp.example.com",
        );
    }

    #[test]
    fn canonical_icann_policy_selects_all_three_successful_discovery_outcomes() {
        let request = ResolutionRequest {
            qname: "_443._tcp.example.com".to_owned(),
            qtype: RecordType::Tlsa.code(),
        };
        for (secure, records, expected) in [
            (
                true,
                vec![tlsa_record("_443._tcp.example.com", vec![3, 1, 1, 0xaa])],
                BrowserTlsDecision::EnforceDane {
                    record_count: std::num::NonZeroUsize::new(1).unwrap(),
                },
            ),
            (
                true,
                Vec::new(),
                BrowserTlsDecision::WebPkiAuthenticatedAbsence,
            ),
            (
                false,
                Vec::new(),
                BrowserTlsDecision::WebPkiInsecureDelegation,
            ),
        ] {
            let gateway = Gateway::new(
                GatewayConfig::default(),
                StaticResolver { secure, records },
                StaticTransport,
            )
            .unwrap();
            let discovery = gateway.resolve_native_tlsa_records(&request, true).unwrap();
            assert_eq!(discovery.browser_tls_decision, Some(expected));
        }
    }

    #[test]
    fn invalid_icann_tlsa_owner_is_terminal_not_webpki() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: false,
                records: Vec::new(),
            },
            StaticTransport,
        )
        .unwrap();

        assert_eq!(
            gateway
                .resolve_tlsa_records("has space.example", 443, TlsaTransport::Tcp)
                .unwrap_err(),
            GatewayError::IcannDane(IcannDaneDiscoveryError::InvalidHost),
        );
    }

    #[test]
    fn unauthenticated_icann_resolver_cannot_select_a_browser_trust_action() {
        let gateway = Gateway::new(
            GatewayConfig {
                icann_resolver_authentication: ResolverAuthentication::Unauthenticated,
                ..GatewayConfig::default()
            },
            StaticResolver {
                secure: true,
                records: Vec::new(),
            },
            StaticTransport,
        )
        .unwrap();

        assert_eq!(
            gateway
                .resolve_tlsa_records("example.com", 443, TlsaTransport::Tcp)
                .unwrap_err(),
            GatewayError::IcannDane(IcannDaneDiscoveryError::UnauthenticatedResolver),
        );
    }

    #[test]
    fn secure_icann_tlsa_cname_reaches_terminal_records_without_webpki_downgrade() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response(
                        "example.com",
                        RecordType::A.code(),
                        true,
                        vec![address_record_for("example.com")],
                    ),
                    response("example.com", RecordType::Https.code(), true, vec![]),
                    response(
                        "_443._tcp.example.com",
                        RecordType::Tlsa.code(),
                        true,
                        vec![
                            cname_record("_443._tcp.example.com", "_443._tcp.edge.example.com"),
                            tlsa_record("_443._tcp.edge.example.com", vec![3, 1, 1, 0xaa]),
                        ],
                    ),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        gateway
            .handle(&request("example.com", "example.com"))
            .unwrap();
        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.tls.tlsa_records.len(), 1);
        assert!(matches!(
            captured.tls.browser_tls_decision,
            Some(BrowserTlsDecision::EnforceDane { record_count })
                if record_count.get() == 1
        ));
    }

    #[test]
    fn malformed_icann_tlsa_cname_shapes_fail_closed() {
        let owner = "_443._tcp.example.com";
        let target = "_443._tcp.edge.example.com";
        for records in [
            vec![cname_record(owner, target)],
            vec![cname_record(owner, target), cname_record(target, owner)],
            vec![
                cname_record(owner, target),
                cname_record(owner, "_443._tcp.other.example.com"),
            ],
            vec![
                cname_record(owner, target),
                tlsa_record(owner, vec![3, 1, 1, 0xaa]),
            ],
        ] {
            assert_eq!(
                tlsa_records(&records, owner).unwrap_err(),
                GatewayError::Resolver(ResolverError::InvalidDnsResponse),
            );
        }
    }

    #[test]
    fn icann_tlsa_resolver_failure_never_becomes_authenticated_absence() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response(
                        "example.com",
                        RecordType::A.code(),
                        true,
                        vec![address_record_for("example.com")],
                    ),
                    response("example.com", RecordType::Https.code(), true, vec![]),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway
                .handle(&request("example.com", "example.com"))
                .unwrap_err(),
            GatewayError::Resolver(ResolverError::ProofUnavailable),
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
    }

    #[test]
    fn http3_derives_udp_tlsa_service_owner() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response(
                        "name",
                        RecordType::Https.code(),
                        true,
                        vec![https_record("name", 1, ".", vec![alpn_param(&[b"h3"])])],
                    ),
                    response("_443._udp.name", RecordType::Tlsa.code(), true, vec![]),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        gateway.handle(&request("name", "name")).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.protocol, OriginProtocol::Http3);
        assert_eq!(captured.tls.service_transport, TlsaTransport::Udp);
        assert_eq!(
            requests.lock().unwrap().last().unwrap().qname,
            "_443._udp.name",
        );
    }

    #[test]
    fn wss_tunnel_uses_hns_tls_policy_and_tlsa_records() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response(
                        "_443._tcp.name",
                        RecordType::Tlsa.code(),
                        true,
                        vec![tlsa_record("_443._tcp.name", vec![3, 1, 0, 0xaa])],
                    ),
                ],
                Arc::clone(&requests),
            ),
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.origin.scheme = "wss".to_owned();
        request.origin.headers = vec![
            ("Connection".to_owned(), "Upgrade".to_owned()),
            ("Upgrade".to_owned(), "websocket".to_owned()),
        ];

        gateway.handle_tunnel(&request).unwrap();

        let captured = gateway
            .transport()
            .last_tunnel_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.scheme, "wss");
        assert_eq!(captured.protocol, OriginProtocol::Http11);
        assert_eq!(captured.tls.mode, DomainTrustMode::HnsStrict);
        assert!(captured.tls.dnssec_secure);
        assert_eq!(captured.tls.tlsa_records.len(), 1);
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .map(|request| request.qtype)
                .collect::<Vec<_>>(),
            vec![
                RecordType::A.code(),
                RecordType::Https.code(),
                RecordType::Tlsa.code(),
            ],
        );
    }

    #[test]
    fn wss_tunnel_rejects_https_service_without_http11() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![
                    address_record(),
                    https_record(
                        "name",
                        1,
                        ".",
                        vec![alpn_param(&[b"h2"]), no_default_alpn_param()],
                    ),
                ],
            },
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.origin.scheme = "wss".to_owned();
        request.origin.headers = vec![
            ("Connection".to_owned(), "Upgrade".to_owned()),
            ("Upgrade".to_owned(), "websocket".to_owned()),
        ];

        assert_eq!(
            gateway.handle_tunnel(&request).err().unwrap(),
            GatewayError::UnsupportedSvcb,
        );
        assert!(
            gateway
                .transport()
                .last_tunnel_request
                .lock()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ignores_tlsa_records_for_other_service_owners() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response(
                        "_443._tcp.name",
                        RecordType::Tlsa.code(),
                        true,
                        vec![
                            tlsa_record("_443._tcp.other", vec![3, 1, 0, 0xbb]),
                            tlsa_record("_8443._tcp.name", vec![3, 1, 0, 0xcc]),
                        ],
                    ),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        gateway.handle(&request("name", "name")).unwrap();

        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert!(captured.tls.dnssec_secure);
        assert!(captured.tls.tlsa_records.is_empty());
        assert_eq!(captured.tls.mode, DomainTrustMode::HnsStrict);
    }

    #[test]
    fn rejects_unsigned_hns_https_origin() {
        let gateway = Gateway::new(
            GatewayConfig {
                hns_https_mode: HnsHttpsMode::Strict,
                supported_origin_protocols: vec![OriginProtocol::Http11, OriginProtocol::Http2],
                ..GatewayConfig::default()
            },
            StaticResolver {
                secure: false,
                records: vec![address_record()],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::InsecureResolution,
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
    }

    #[test]
    fn rejects_unsigned_https_service_policy() {
        let gateway = Gateway::new(
            GatewayConfig {
                hns_https_mode: HnsHttpsMode::Strict,
                ..GatewayConfig::default()
            },
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), false, vec![]),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::InsecureResolution,
        );
    }

    #[test]
    fn rejects_unsigned_https_service_policy_by_default() {
        let gateway = Gateway::new(
            GatewayConfig {
                hns_https_mode: HnsHttpsMode::Strict,
                ..GatewayConfig::default()
            },
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), false, vec![]),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::InsecureResolution,
        );
    }

    #[test]
    fn rejects_insecure_tlsa_resolution_by_default() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response(
                        "_443._tcp.name",
                        RecordType::Tlsa.code(),
                        false,
                        vec![tlsa_record("_443._tcp.name", vec![3, 1, 0, 0xaa])],
                    ),
                ],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::InsecureResolution,
        );
    }

    #[test]
    fn malformed_tlsa_record_fails_closed() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            StaticResolver {
                secure: true,
                records: vec![
                    address_record(),
                    ResourceRecord {
                        name: DnsName::from_ascii("_443._tcp.name").unwrap(),
                        record_type: RecordType::Tlsa,
                        class: 1,
                        ttl: 60,
                        rdata: vec![3, 1],
                    },
                ],
            },
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway.handle(&request("name", "name")).unwrap_err(),
            GatewayError::InvalidTlsa(DaneError::ShortRecord),
        );
    }

    impl StaticResolver {
        fn secure() -> Self {
            Self {
                secure: true,
                records: Vec::new(),
            }
        }

        fn secure_with_address() -> Self {
            Self {
                secure: true,
                records: vec![address_record()],
            }
        }

        fn insecure() -> Self {
            Self {
                secure: false,
                records: Vec::new(),
            }
        }
    }

    impl ScriptedResolver {
        fn new(
            responses: Vec<(ResolutionRequest, ResolutionAnswer)>,
            requests: Arc<Mutex<Vec<ResolutionRequest>>>,
        ) -> Self {
            Self {
                responses,
                requests,
            }
        }
    }

    fn response(
        qname: &str,
        qtype: u16,
        secure: bool,
        records: Vec<ResourceRecord>,
    ) -> (ResolutionRequest, ResolutionAnswer) {
        (
            ResolutionRequest {
                qname: qname.to_owned(),
                qtype,
            },
            ResolutionAnswer {
                name: DnsName::from_ascii(qname).unwrap(),
                records,
                secure,
            },
        )
    }

    fn address_record() -> ResourceRecord {
        address_record_for("name")
    }

    fn address_record_for(name: &str) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(name).unwrap(),
            record_type: RecordType::A,
            class: 1,
            ttl: 60,
            rdata: vec![1, 1, 1, 1],
        }
    }

    fn address_record_v6() -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii("name").unwrap(),
            record_type: RecordType::Aaaa,
            class: 1,
            ttl: 60,
            rdata: "2606:4700:4700::1111"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        }
    }

    fn ns_record(owner: &str, target: &str) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Ns,
            class: 1,
            ttl: 60,
            rdata: name_rdata(target),
        }
    }

    fn ds_record(owner: &str) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Ds,
            class: 1,
            ttl: 60,
            rdata: vec![0x12, 0x34, 13, 2, 0xaa, 0xbb, 0xcc],
        }
    }

    fn tlsa_record(name: &str, rdata: Vec<u8>) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(name).unwrap(),
            record_type: RecordType::Tlsa,
            class: 1,
            ttl: 60,
            rdata,
        }
    }

    fn https_record(
        owner: &str,
        priority: u16,
        target: &str,
        params: Vec<(u16, Vec<u8>)>,
    ) -> ResourceRecord {
        let mut rdata = Vec::new();
        push_u16(&mut rdata, priority);
        if target == "." {
            DnsName::root()
        } else {
            DnsName::from_ascii(target).unwrap()
        }
        .encode_wire(&mut rdata)
        .unwrap();
        for (key, value) in params {
            push_u16(&mut rdata, key);
            push_u16(&mut rdata, value.len() as u16);
            rdata.extend(value);
        }
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Https,
            class: 1,
            ttl: 60,
            rdata,
        }
    }

    fn alpn_param(ids: &[&[u8]]) -> (u16, Vec<u8>) {
        let mut value = Vec::new();
        for id in ids {
            value.push(id.len() as u8);
            value.extend(*id);
        }
        (SVCB_PARAM_ALPN, value)
    }

    fn port_param(port: u16) -> (u16, Vec<u8>) {
        (SVCB_PARAM_PORT, port.to_be_bytes().to_vec())
    }

    fn no_default_alpn_param() -> (u16, Vec<u8>) {
        (SVCB_PARAM_NO_DEFAULT_ALPN, Vec::new())
    }

    fn gateway_config_with_protocols(protocols: Vec<OriginProtocol>) -> GatewayConfig {
        GatewayConfig {
            supported_origin_protocols: protocols,
            ..GatewayConfig::default()
        }
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend(value.to_be_bytes());
    }

    fn cname_record(owner: &str, target: &str) -> ResourceRecord {
        ResourceRecord {
            name: DnsName::from_ascii(owner).unwrap(),
            record_type: RecordType::Cname,
            class: 1,
            ttl: 60,
            rdata: name_rdata(target),
        }
    }

    fn name_rdata(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        DnsName::from_ascii(name)
            .unwrap()
            .encode_wire(&mut out)
            .unwrap();
        out
    }

    fn request(origin_host: &str, qname: &str) -> GatewayRequest {
        GatewayRequest {
            auth_token: None,
            origin: OriginRequest {
                method: "GET".to_owned(),
                scheme: "https".to_owned(),
                host: origin_host.to_owned(),
                connect_host: None,
                port: 443,
                path_and_query: "/".to_owned(),
                protocol: OriginProtocol::Http11,
                tls: TlsValidation::default(),
                headers: Vec::new(),
                body: Vec::new(),
            },
            resolution: ResolutionRequest {
                qname: qname.to_owned(),
                qtype: 1,
            },
        }
    }
}
