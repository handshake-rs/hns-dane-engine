use hns_core::bytes::ParseError;
use hns_core::dns::{
    DnsName, RecordType, ResourceRecord, SVCB_PARAM_ALPN, SVCB_PARAM_MANDATORY,
    SVCB_PARAM_NO_DEFAULT_ALPN, SVCB_PARAM_PORT, SvcbRecord,
};
use hns_core::network_policy::{is_browser_blocked_port, is_publicly_routable};
use hns_dane::{DaneError, DomainTrustMode, StatelessDaneConfig, TlsaRecord};
use hns_icann_dane::{
    BrowserTlsDecision, DnssecQueryMode, IcannDnssecStatus, ResolverAuthentication, TlsaDenial,
    TlsaOwner, TlsaTransport, ValidatingDohEvidence, decide_browser_tls,
};
use hns_namespace_resolution::{
    ApplicationProtocol, CanonicalHost, Namespace, NamespaceDecision, OriginQuery, OriginScheme,
    ProtocolCapabilities, ServiceTransport, TlsTrustPolicy, decision_fingerprint,
};
use hns_resolver::{
    PreparedNamespaceResolution, ResolutionAnswer, ResolutionRequest, Resolver, ResolverError,
};
use hns_transport::{
    OriginProtocol, OriginRequest, OriginResponse, OriginResponseHead, OriginTransport,
    OriginTunnel, TlsaRecordSource, TransportError,
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
    /// Explicit namespace for legacy single-root resolver adapters. Browser
    /// runtimes use `PreparedNamespaceResolution` and ignore this field.
    pub single_root_namespace: Namespace,
    pub supported_origin_protocols: Vec<OriginProtocol>,
    pub stateless_dane: StatelessDaneConfig,
    pub icann_resolver_authentication: ResolverAuthentication,
    pub icann_dnssec_query_mode: DnssecQueryMode,
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
    pub origin_request: OriginRequest,
    pub origin: OriginResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayResponseHead {
    pub resolution: ResolutionAnswer,
    pub origin_request: OriginRequest,
    pub origin: OriginResponseHead,
}

pub struct GatewayTunnel {
    pub resolution: ResolutionAnswer,
    pub origin_request: OriginRequest,
    pub origin: OriginTunnel,
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
    #[error("HTTPS/SVCB record is invalid: {0}")]
    InvalidSvcb(ParseError),
    #[error("HTTPS/SVCB service binding is unsupported")]
    UnsupportedSvcb,
    #[error("resolver error: {0}")]
    Resolver(#[from] ResolverError),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
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
            single_root_namespace: Namespace::Hns,
            supported_origin_protocols: vec![
                OriginProtocol::Http11,
                OriginProtocol::Http2,
                OriginProtocol::Http3,
            ],
            stateless_dane: StatelessDaneConfig::default(),
            icann_resolver_authentication: ResolverAuthentication::Unauthenticated,
            icann_dnssec_query_mode: DnssecQueryMode::DnssecRecordsNotRequested,
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
            .field("single_root_namespace", &self.single_root_namespace)
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
        self.authorize(request)?;
        let (resolution, origin_request) =
            self.resolve_origin_request(request, &self.config.supported_origin_protocols)?;
        let origin = self.transport.fetch(&origin_request)?;
        Ok(GatewayResponse {
            resolution,
            origin_request,
            origin,
        })
    }

    pub fn handle_to_writer(
        &self,
        request: &GatewayRequest,
        body: &mut dyn Write,
    ) -> Result<GatewayResponseHead, GatewayError> {
        self.authorize(request)?;
        let (resolution, origin_request) =
            self.resolve_origin_request(request, &self.config.supported_origin_protocols)?;
        let origin = self.transport.fetch_to_writer(&origin_request, body)?;
        Ok(GatewayResponseHead {
            resolution,
            origin_request,
            origin,
        })
    }

    pub fn handle_to_writer_streaming(
        &self,
        request: &GatewayRequest,
        body: &mut dyn Write,
        on_head: &mut dyn FnMut(&GatewayResponseHead) -> Result<(), TransportError>,
    ) -> Result<GatewayResponseHead, GatewayError> {
        self.authorize(request)?;
        let (resolution, origin_request) =
            self.resolve_origin_request(request, &self.config.supported_origin_protocols)?;
        let observed_resolution = resolution.clone();
        let observed_request = origin_request.clone();
        let mut observe_origin = |origin: &OriginResponseHead| {
            on_head(&GatewayResponseHead {
                resolution: observed_resolution.clone(),
                origin_request: observed_request.clone(),
                origin: origin.clone(),
            })
        };
        let origin =
            self.transport
                .fetch_to_writer_streaming(&origin_request, body, &mut observe_origin)?;
        Ok(GatewayResponseHead {
            resolution,
            origin_request,
            origin,
        })
    }

    pub fn handle_tunnel(&self, request: &GatewayRequest) -> Result<GatewayTunnel, GatewayError> {
        self.authorize(request)?;
        let (resolution, origin_request) =
            self.resolve_origin_request(request, &[OriginProtocol::Http11])?;
        let origin = self.transport.open_tunnel(&origin_request)?;
        Ok(GatewayTunnel {
            resolution,
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
    ) -> Result<(ResolutionAnswer, OriginRequest), GatewayError> {
        if !hosts_match(&request.origin.host, &request.resolution.qname) {
            return Err(GatewayError::HostResolutionMismatch);
        }
        self.validate_origin_port(request.origin.port)?;

        let query = gateway_origin_query(request, supported_origin_protocols)?;
        if let Some(prepared) = self.resolver.prepare_namespace_resolution(&query)? {
            return self.prepared_origin_request(
                request,
                &query,
                supported_origin_protocols,
                prepared,
            );
        }

        // Compatibility path for explicitly configured single-root resolver
        // adapters. Browser runtimes always use the prepared dual-root path
        // above; no static IANA-list classification occurs here.
        let resolution = self.resolver.resolve(&request.resolution)?;
        let selected_namespace = self.config.single_root_namespace;
        if !resolution.secure && selected_namespace != Namespace::Icann {
            return Err(GatewayError::InsecureResolution);
        }

        let mut origin_request = request.origin.clone();
        // Never trust a caller-supplied connection override. The native transport bypasses the
        // browser DNS stack, so the connection address must come from this validated resolution.
        origin_request.connect_host =
            first_resolved_address(&resolution.records, &origin_request.host);
        if origin_request.connect_host.is_none() {
            origin_request.connect_host =
                self.resolve_origin_address(&origin_request, selected_namespace)?;
        }
        let connect_host = origin_request
            .connect_host
            .as_deref()
            .ok_or(GatewayError::NoResolvedAddress)?;
        self.validate_origin_address(connect_host)?;
        if is_tls_origin_scheme(&origin_request.scheme) {
            origin_request.tls.mode = domain_trust_mode_for_namespace(selected_namespace);
            origin_request.tls.namespace_fingerprint = None;
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
                match self.resolve_https_service_policy(
                    &mut origin_request,
                    supported_origin_protocols,
                    selected_namespace,
                ) {
                    Ok(()) => {}
                    Err(error)
                        if selected_namespace != Namespace::Icann
                            && optional_https_service_policy_error(&error) => {}
                    Err(error) => return Err(error),
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
                selected_namespace,
            )?;
            origin_request.tls.dnssec_secure = resolved_tlsa.secure;
            origin_request.tls.tlsa_records = resolved_tlsa.records;
            origin_request.tls.tlsa_source = resolved_tlsa.source;
            origin_request.tls.browser_tls_decision = resolved_tlsa.browser_tls_decision;
        }
        self.validate_origin_port(origin_request.port)?;

        Ok((resolution, origin_request))
    }

    fn prepared_origin_request(
        &self,
        request: &GatewayRequest,
        query: &OriginQuery,
        supported_origin_protocols: &[OriginProtocol],
        prepared: PreparedNamespaceResolution,
    ) -> Result<(ResolutionAnswer, OriginRequest), GatewayError> {
        let PreparedNamespaceResolution {
            decision,
            selected_answer,
        } = prepared;
        validate_prepared_query(query, &decision)?;
        if self.config.stateless_dane.enabled {
            // Certificate-carried stateless DANE evidence is not represented
            // by the canonical dual-root plan. Enabling the legacy mechanism
            // here would bypass the selected plan's exact TLSA authority.
            return Err(ResolverError::InvalidDnsResponse.into());
        }
        let selected = decision
            .selected_namespace()
            .ok_or(ResolverError::NamespaceUnavailable)?;
        let plan = decision
            .selected_plan()
            .ok_or(ResolverError::NamespaceUnavailable)?;
        let selected_answer = selected_answer.ok_or(ResolverError::NamespaceUnavailable)?;
        if plan.service().ech_config().is_some() {
            return Err(GatewayError::UnsupportedSvcb);
        }
        let protocol = origin_protocol(plan.service().selected_protocol());
        if !supported_origin_protocols.contains(&protocol) {
            return Err(GatewayError::UnsupportedSvcb);
        }
        let endpoint = plan
            .endpoints()
            .iter()
            .copied()
            .find(|endpoint| {
                self.config.allow_non_public_origin_addresses || is_publicly_routable(endpoint.ip())
            })
            .ok_or(GatewayError::NoResolvedAddress)?;
        self.validate_origin_port(endpoint.port())?;
        self.validate_origin_address(&endpoint.ip().to_string())?;

        let mut origin_request = request.origin.clone();
        origin_request.connect_host = Some(endpoint.ip().to_string());
        origin_request.port = endpoint.port();
        origin_request.protocol = protocol;
        origin_request.tls.namespace_fingerprint = Some(decision_fingerprint(&decision).to_hex());
        origin_request.tls.service_port = plan.service().effective_port().get();
        origin_request.tls.service_transport = tlsa_transport(plan.service().transport());

        match plan.tls_policy() {
            TlsTrustPolicy::Cleartext => {
                if is_tls_origin_scheme(&origin_request.scheme) {
                    return Err(ResolverError::InvalidDnsResponse.into());
                }
            }
            TlsTrustPolicy::Dane => {
                if !is_tls_origin_scheme(&origin_request.scheme) {
                    return Err(ResolverError::InvalidDnsResponse.into());
                }
                let records = plan
                    .tlsa_records()
                    .iter()
                    .map(|record| TlsaRecord::parse_rdata(record.rdata()))
                    .collect::<Result<Vec<_>, _>>()?;
                let count =
                    NonZeroUsize::new(records.len()).ok_or(ResolverError::InvalidDnsResponse)?;
                origin_request.tls.mode = domain_trust_mode_for_namespace(selected);
                origin_request.tls.dnssec_secure = true;
                origin_request.tls.tlsa_records = records;
                origin_request.tls.tlsa_source = Some(TlsaRecordSource::NativeTlsa);
                origin_request.tls.browser_tls_decision =
                    (selected == Namespace::Icann).then_some(BrowserTlsDecision::EnforceDane {
                        record_count: count,
                    });
            }
            TlsTrustPolicy::WebPkiAuthenticatedAbsence => {
                if selected != Namespace::Icann || !is_tls_origin_scheme(&origin_request.scheme) {
                    return Err(ResolverError::InvalidDnsResponse.into());
                }
                origin_request.tls.mode = DomainTrustMode::IcannWebPki;
                origin_request.tls.dnssec_secure = true;
                origin_request.tls.tlsa_records.clear();
                origin_request.tls.tlsa_source = None;
                origin_request.tls.browser_tls_decision =
                    Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence);
            }
            TlsTrustPolicy::WebPkiInsecureDelegation => {
                if selected != Namespace::Icann || !is_tls_origin_scheme(&origin_request.scheme) {
                    return Err(ResolverError::InvalidDnsResponse.into());
                }
                origin_request.tls.mode = DomainTrustMode::IcannWebPki;
                origin_request.tls.dnssec_secure = false;
                origin_request.tls.tlsa_records.clear();
                origin_request.tls.tlsa_source = None;
                origin_request.tls.browser_tls_decision =
                    Some(BrowserTlsDecision::WebPkiInsecureDelegation);
            }
        }
        Ok((selected_answer, origin_request))
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
        selected_namespace: Namespace,
    ) -> Result<ResolvedTlsaRecords, GatewayError> {
        let request = tlsa_resolution_request(host, port, transport)?;

        self.resolve_native_tlsa_records(&request, selected_namespace == Namespace::Icann)
    }

    fn resolve_native_tlsa_records(
        &self,
        request: &ResolutionRequest,
        allow_insecure_webpki_fallback: bool,
    ) -> Result<ResolvedTlsaRecords, GatewayError> {
        let answer = self.resolver.resolve(request)?;
        // A validating resolver returns AD=0 for a provably insecure
        // delegation and a DNS error (normally SERVFAIL) for bogus DNSSEC.
        // Ignore all unsigned TLSA bytes for ICANN and retain WebPKI; never
        // turn a resolver error into an empty TLSA answer.
        if !answer.secure && allow_insecure_webpki_fallback {
            let browser_tls_decision =
                self.decide_icann_browser_tls(&answer, 0, TlsaDenial::None)?;
            return Ok(ResolvedTlsaRecords {
                browser_tls_decision: Some(browser_tls_decision),
                secure: false,
                records: Vec::new(),
                source: None,
            });
        }
        let records = tlsa_records(&answer.records, &request.qname)?;
        if self.config.require_secure_resolution && !answer.secure && !records.is_empty() {
            return Err(GatewayError::InsecureResolution);
        }

        let browser_tls_decision = allow_insecure_webpki_fallback
            .then(|| {
                self.decide_icann_browser_tls(
                    &answer,
                    records.len(),
                    if records.is_empty() {
                        TlsaDenial::Authenticated
                    } else {
                        TlsaDenial::None
                    },
                )
            })
            .transpose()?;
        Ok(ResolvedTlsaRecords {
            browser_tls_decision,
            secure: answer.secure,
            source: (!records.is_empty()).then_some(TlsaRecordSource::NativeTlsa),
            records,
        })
    }

    fn decide_icann_browser_tls(
        &self,
        answer: &ResolutionAnswer,
        tlsa_record_count: usize,
        denial: TlsaDenial,
    ) -> Result<BrowserTlsDecision, GatewayError> {
        decide_browser_tls(ValidatingDohEvidence {
            resolver_authentication: self.config.icann_resolver_authentication,
            query_mode: self.config.icann_dnssec_query_mode,
            dnssec: if answer.secure {
                IcannDnssecStatus::Secure
            } else {
                IcannDnssecStatus::InsecureDelegation
            },
            tlsa_record_count,
            denial,
        })
        .map_err(|_error| GatewayError::InsecureResolution)
    }

    fn resolve_origin_address(
        &self,
        origin: &OriginRequest,
        selected_namespace: Namespace,
    ) -> Result<Option<String>, GatewayError> {
        for qtype in [RecordType::A, RecordType::Aaaa] {
            let request = ResolutionRequest {
                qname: normalize_host(&origin.host),
                qtype: qtype.code(),
            };
            let answer = self.resolver.resolve(&request)?;
            if !answer.secure && selected_namespace != Namespace::Icann {
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
        selected_namespace: Namespace,
    ) -> Result<(), GatewayError> {
        let answer = self.resolver.resolve(&ResolutionRequest {
            qname: normalize_host(&request.host),
            qtype: RecordType::Https.code(),
        })?;
        if !answer.secure && selected_namespace == Namespace::Icann {
            return Ok(());
        }
        if self.config.require_secure_resolution && !answer.secure {
            return Err(GatewayError::InsecureResolution);
        }
        apply_https_service_policy(&answer.records, request, supported_origin_protocols)?;
        Ok(())
    }
}

fn optional_https_service_policy_error(error: &GatewayError) -> bool {
    matches!(error, GatewayError::Resolver(_))
}

fn domain_trust_mode_for_namespace(namespace: Namespace) -> DomainTrustMode {
    match namespace {
        Namespace::Hns => DomainTrustMode::HnsStrict,
        Namespace::Icann => DomainTrustMode::IcannWebPki,
    }
}

fn validate_prepared_query(
    query: &OriginQuery,
    decision: &NamespaceDecision,
) -> Result<(), GatewayError> {
    if decision.query() != query {
        return Err(ResolverError::InvalidDnsResponse.into());
    }
    Ok(())
}

fn gateway_origin_query(
    request: &GatewayRequest,
    supported_origin_protocols: &[OriginProtocol],
) -> Result<OriginQuery, GatewayError> {
    let host = CanonicalHost::parse(&normalize_host(&request.origin.host))
        .map_err(|_| ResolverError::InvalidDnsResponse)?;
    let scheme = match request.origin.scheme.to_ascii_lowercase().as_str() {
        "http" => OriginScheme::Http,
        "https" => OriginScheme::Https,
        "ws" => OriginScheme::Ws,
        "wss" => OriginScheme::Wss,
        _ => return Err(GatewayError::Transport(TransportError::UnsupportedScheme)),
    };
    let port = NonZeroU16::new(request.origin.port).ok_or(ResolverError::InvalidDnsResponse)?;
    let capabilities = ProtocolCapabilities::new(
        supported_origin_protocols.contains(&OriginProtocol::Http11),
        supported_origin_protocols.contains(&OriginProtocol::Http2),
        supported_origin_protocols.contains(&OriginProtocol::Http3),
    )
    .map_err(|_| ResolverError::InvalidDnsResponse)?;
    Ok(OriginQuery::new(host, scheme, Some(port), capabilities))
}

fn origin_protocol(protocol: ApplicationProtocol) -> OriginProtocol {
    match protocol {
        ApplicationProtocol::Http11 => OriginProtocol::Http11,
        ApplicationProtocol::Http2 => OriginProtocol::Http2,
        ApplicationProtocol::Http3 => OriginProtocol::Http3,
    }
}

fn tlsa_transport(transport: ServiceTransport) -> TlsaTransport {
    match transport {
        ServiceTransport::Tcp => TlsaTransport::Tcp,
        ServiceTransport::Udp => TlsaTransport::Udp,
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
) -> Result<ResolutionRequest, GatewayError> {
    let owner = TlsaOwner::derive(host, port, transport)
        .map_err(|_error| GatewayError::Resolver(ResolverError::InvalidDnsResponse))?;
    Ok(ResolutionRequest {
        qname: owner.resolver_name().to_owned(),
        qtype: RecordType::Tlsa.code(),
    })
}

fn tlsa_records(
    records: &[ResourceRecord],
    service_qname: &str,
) -> Result<Vec<TlsaRecord>, GatewayError> {
    let mut owner = DnsName::from_ascii(service_qname)
        .map_err(|_| GatewayError::Resolver(ResolverError::InvalidDnsResponse))?;
    let mut seen = Vec::new();
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
                Ok(Vec::new())
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
        CanonicalHost, DefaultPrecedence, EvidenceProvenance, Freshness, HnsNetwork,
        IcannChainState, OriginPlanInput, OriginQuery, ProtocolCapabilities, RootLookup,
        SelectionPolicy, ServiceBinding, ServiceBindingInput, ValidatedOriginPlan,
        decide_namespace,
    };
    use hns_resolver::{ResolutionAnswer, Resolver};
    use hns_transport::{
        OriginProtocol, OriginResponse, OriginTransport, OriginTunnel, TlsValidation,
    };
    use std::io::Cursor;
    use std::num::NonZeroU16;
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

    struct PreparedOnlyResolver {
        prepared: PreparedNamespaceResolution,
        resolve_calls: Arc<AtomicUsize>,
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

    impl Resolver for PreparedOnlyResolver {
        fn resolve(&self, _request: &ResolutionRequest) -> Result<ResolutionAnswer, ResolverError> {
            self.resolve_calls.fetch_add(1, Ordering::SeqCst);
            Err(ResolverError::ProofUnavailable)
        }

        fn prepare_namespace_resolution(
            &self,
            _query: &OriginQuery,
        ) -> Result<Option<PreparedNamespaceResolution>, ResolverError> {
            Ok(Some(self.prepared.clone()))
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

    #[derive(Default)]
    struct CapturingTransport {
        last_request: Mutex<Option<OriginRequest>>,
        last_tunnel_request: Mutex<Option<OriginRequest>>,
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
    fn prepared_namespace_plan_performs_zero_follow_up_dns_queries() {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let prepared = prepared_cleartext_resolution();
        let expected_fingerprint = decision_fingerprint(&prepared.decision).to_hex();
        let gateway = Gateway::new(
            GatewayConfig::default(),
            PreparedOnlyResolver {
                prepared,
                resolve_calls: Arc::clone(&resolve_calls),
            },
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.origin.scheme = "http".to_owned();
        request.origin.port = 80;

        gateway.handle(&request).unwrap();

        assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
        let captured = gateway
            .transport()
            .last_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(captured.connect_host.as_deref(), Some("1.1.1.1"));
        assert_eq!(captured.port, 80);
        assert_eq!(captured.protocol, OriginProtocol::Http11);
        assert_eq!(
            captured.tls.namespace_fingerprint.as_deref(),
            Some(expected_fingerprint.as_str())
        );
    }

    #[test]
    fn prepared_namespace_plan_rejects_legacy_stateless_dane_override() {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let gateway = Gateway::new(
            GatewayConfig {
                stateless_dane: StatelessDaneConfig {
                    enabled: true,
                    accepted_tree_roots: vec![[3; 32]],
                },
                ..GatewayConfig::default()
            },
            PreparedOnlyResolver {
                prepared: prepared_cleartext_resolution(),
                resolve_calls: Arc::clone(&resolve_calls),
            },
            CapturingTransport::default(),
        )
        .unwrap();
        let mut request = request("name", "name");
        request.origin.scheme = "http".to_owned();
        request.origin.port = 80;

        assert_eq!(
            gateway.handle(&request).unwrap_err(),
            GatewayError::Resolver(ResolverError::InvalidDnsResponse)
        );
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
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
    fn rejects_unsigned_icann_private_address_before_tls_policy_lookup() {
        let gateway = Gateway::new(
            GatewayConfig {
                single_root_namespace: Namespace::Icann,
                ..GatewayConfig::default()
            },
            ScriptedResolver::new(
                vec![response(
                    "example.com",
                    RecordType::A.code(),
                    false,
                    vec![ResourceRecord {
                        name: DnsName::from_ascii("example.com").unwrap(),
                        record_type: RecordType::A,
                        class: 1,
                        ttl: 60,
                        rdata: vec![127, 0, 0, 1],
                    }],
                )],
                Arc::new(Mutex::new(Vec::new())),
            ),
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway
                .handle(&request("example.com", "example.com"))
                .unwrap_err(),
            GatewayError::NonPublicOriginAddress
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
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
        let mut config = authenticated_icann_gateway_config();
        config.supported_origin_protocols = vec![OriginProtocol::Http11, OriginProtocol::Http2];
        let gateway = Gateway::new(
            config,
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
    fn icann_https_service_policy_resolver_failure_is_terminal() {
        struct IcannHttpsPolicyErrorResolver;

        impl Resolver for IcannHttpsPolicyErrorResolver {
            fn resolve(
                &self,
                request: &ResolutionRequest,
            ) -> Result<ResolutionAnswer, ResolverError> {
                match RecordType::from_code(request.qtype) {
                    RecordType::A => Ok(ResolutionAnswer {
                        name: DnsName::from_ascii(&request.qname).unwrap(),
                        records: vec![address_record_for(&request.qname)],
                        secure: true,
                    }),
                    RecordType::Https => Err(ResolverError::DnssecFailed),
                    _ => panic!("ICANN TLSA lookup must not follow a failed HTTPS/SVCB lookup"),
                }
            }
        }

        let gateway = Gateway::new(
            authenticated_icann_gateway_config(),
            IcannHttpsPolicyErrorResolver,
            CapturingTransport::default(),
        )
        .unwrap();

        assert_eq!(
            gateway
                .handle(&request("example.com", "example.com"))
                .unwrap_err(),
            GatewayError::Resolver(ResolverError::DnssecFailed)
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
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
        assert_eq!(captured.tls.service_transport, TlsaTransport::Udp);
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
            authenticated_icann_gateway_config(),
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
            Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence)
        );
    }

    #[test]
    fn icann_webpki_requires_an_authenticated_validating_resolver_contract() {
        let gateway = Gateway::new(
            GatewayConfig {
                single_root_namespace: Namespace::Icann,
                ..GatewayConfig::default()
            },
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

        assert_eq!(
            gateway
                .handle(&request("example.com", "example.com"))
                .unwrap_err(),
            GatewayError::InsecureResolution
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
    }

    #[test]
    fn icann_native_tlsa_records_are_used() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            authenticated_icann_gateway_config(),
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
        assert!(matches!(
            captured.tls.browser_tls_decision,
            Some(BrowserTlsDecision::EnforceDane { record_count })
                if record_count.get() == 1
        ));
        assert_eq!(captured.tls.tlsa_records[0].usage, TlsaUsage::DaneEe);
        assert_eq!(
            captured.tls.tlsa_records[0].selector,
            TlsaSelector::SubjectPublicKeyInfo
        );
        assert_eq!(captured.tls.tlsa_records[0].matching, TlsaMatching::Sha256);
        assert_eq!(captured.tls.tlsa_records[0].association_data, vec![0xaa]);
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
    fn icann_secure_tlsa_cname_chain_reaches_terminal_records_without_webpki_downgrade() {
        let gateway = Gateway::new(
            authenticated_icann_gateway_config(),
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
                            cname_record("_443._tcp.example.com", "_443._tcp.edge.example.net"),
                            tlsa_record("_443._tcp.edge.example.net", vec![3, 1, 1, 0xaa]),
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
    fn icann_tlsa_cname_loop_fails_closed_instead_of_becoming_absence() {
        let gateway = Gateway::new(
            authenticated_icann_gateway_config(),
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
                            cname_record("_443._tcp.example.com", "_443._tcp.edge.example.net"),
                            cname_record("_443._tcp.edge.example.net", "_443._tcp.example.com"),
                        ],
                    ),
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
            GatewayError::Resolver(ResolverError::InvalidDnsResponse)
        );
        assert!(gateway.transport().last_request.lock().unwrap().is_none());
    }

    #[test]
    fn icann_native_tlsa_no_data_does_not_query_txt() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let gateway = Gateway::new(
            authenticated_icann_gateway_config(),
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
            Some(BrowserTlsDecision::WebPkiAuthenticatedAbsence)
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
            authenticated_icann_gateway_config(),
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
            Some(BrowserTlsDecision::WebPkiInsecureDelegation)
        );
        assert_eq!(
            requests.lock().unwrap().last().unwrap().qname,
            "_443._tcp.example.com",
        );
    }

    #[test]
    fn icann_tlsa_resolver_failure_never_becomes_authenticated_absence() {
        let gateway = Gateway::new(
            authenticated_icann_gateway_config(),
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
    fn oversized_derived_tlsa_owner_is_terminal() {
        let host = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(52),
        ]
        .join(".");

        assert_eq!(
            tlsa_resolution_request(&host, 443, TlsaTransport::Tcp).unwrap_err(),
            GatewayError::Resolver(ResolverError::InvalidDnsResponse)
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
    fn hns_https_transport_never_selects_webpki_fallback() {
        let gateway = Gateway::new(
            GatewayConfig::default(),
            ScriptedResolver::new(
                vec![
                    response("name", RecordType::A.code(), true, vec![address_record()]),
                    response("name", RecordType::Https.code(), true, vec![]),
                    response("_443._tcp.name", RecordType::Tlsa.code(), true, vec![]),
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
        assert_eq!(captured.tls.mode, DomainTrustMode::HnsStrict);
        assert!(captured.tls.dnssec_secure);
        assert!(captured.tls.tlsa_records.is_empty());
    }

    #[test]
    fn rejects_unsigned_hns_https_origin() {
        let gateway = Gateway::new(
            GatewayConfig {
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
            GatewayConfig::default(),
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
            GatewayConfig::default(),
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

    #[test]
    fn non_in_tlsa_record_fails_closed() {
        let mut record = tlsa_record("_443._tcp.example.com", vec![3, 1, 1, 0xaa]);
        record.class = 3;

        assert_eq!(
            tlsa_records(&[record], "_443._tcp.example.com").unwrap_err(),
            GatewayError::Resolver(ResolverError::InvalidDnsResponse)
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

    fn authenticated_icann_gateway_config() -> GatewayConfig {
        GatewayConfig {
            single_root_namespace: Namespace::Icann,
            icann_resolver_authentication: ResolverAuthentication::Authenticated,
            icann_dnssec_query_mode: DnssecQueryMode::Validate,
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

    fn prepared_cleartext_resolution() -> PreparedNamespaceResolution {
        let host = CanonicalHost::parse("name").unwrap();
        let port = NonZeroU16::new(80).unwrap();
        let query = OriginQuery::new(
            host.clone(),
            OriginScheme::Http,
            Some(port),
            ProtocolCapabilities::all(),
        );
        let service = ServiceBinding::new(ServiceBindingInput {
            priority: None,
            service_target: host.clone(),
            mandatory_keys: Vec::new(),
            advertised_alpn: Vec::new(),
            selected_protocol: ApplicationProtocol::Http11,
            effective_port: port,
            transport: ServiceTransport::Tcp,
            connection_hints: Vec::new(),
            ech_config: None,
            parameters: Vec::new(),
        })
        .unwrap();
        let plan = |namespace, provenance| {
            ValidatedOriginPlan::new(OriginPlanInput {
                namespace,
                query: query.clone(),
                alias_path: Vec::new(),
                terminal_target: host.clone(),
                endpoint_alias_path: Vec::new(),
                endpoint_target: host.clone(),
                endpoints: vec![SocketAddr::from(([1, 1, 1, 1], 80))],
                service: service.clone(),
                tls_policy: TlsTrustPolicy::Cleartext,
                tlsa_records: Vec::new(),
                provenance,
                freshness: Freshness::new(90, 110).unwrap(),
            })
            .unwrap()
        };
        let decision = decide_namespace(
            &query,
            RootLookup::Present(plan(
                Namespace::Hns,
                EvidenceProvenance::Hns {
                    network: HnsNetwork::Mainnet,
                    tree_root: [1; 32],
                    height: 1,
                },
            )),
            RootLookup::Present(plan(
                Namespace::Icann,
                EvidenceProvenance::IcannDoh {
                    chain_state: IcannChainState::Secure,
                },
            )),
            SelectionPolicy::new(DefaultPrecedence::PreferIcann, 1),
            100,
        )
        .unwrap();
        PreparedNamespaceResolution {
            decision,
            selected_answer: Some(ResolutionAnswer {
                name: DnsName::from_ascii("name").unwrap(),
                records: vec![address_record()],
                secure: true,
            }),
        }
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
