//! Shared automatic ICANN DANE discovery policy for every browser shell.
//!
//! This crate is deliberately independent of a DNS or TLS implementation. It
//! derives the exact TLSA owner for a canonical origin and converts evidence
//! from a TLS-authenticated validating ICANN DoH resolver into one of two
//! permitted browser actions: enforce securely present TLSA data, or retain
//! WebPKI after authenticated absence or a proven-insecure delegation.
//! Bogus, indeterminate, malformed, and unauthenticated results fail closed.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    reason = "DANE, DNSSEC, DoH, ICANN, TLSA, and WebPKI are protocol names"
)]

use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::str::FromStr;

/// Maximum DNS presentation-name length without a terminating root dot.
pub const MAX_DNS_NAME_BYTES: usize = 253;
/// Maximum DNS label length.
pub const MAX_DNS_LABEL_BYTES: usize = 63;

/// Transport label used in a TLSA owner name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsaTransport {
    /// `_tcp`.
    Tcp,
    /// `_udp`.
    Udp,
    /// `_sctp`.
    Sctp,
}

impl TlsaTransport {
    /// Underscore-prefixed DNS service label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "_tcp",
            Self::Udp => "_udp",
            Self::Sctp => "_sctp",
        }
    }
}

/// Canonical service-prefixed TLSA owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsaOwner {
    host: String,
    resolver_name: String,
    fqdn: String,
    port: u16,
    transport: TlsaTransport,
}

impl TlsaOwner {
    /// Derive `_<port>._<transport>.<host>.` from one canonical ASCII DNS host.
    ///
    /// URL parsers must apply IDNA before this boundary. Case and a terminating
    /// root dot are normalized here. IP literals, empty labels, non-host
    /// characters, zero ports, and DNS names that exceed wire bounds fail.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::InvalidHost`],
    /// [`DiscoveryError::InvalidPort`], or
    /// [`DiscoveryError::NameTooLong`] when the service owner cannot be
    /// represented as one absolute DNS name.
    pub fn derive(host: &str, port: u16, transport: TlsaTransport) -> Result<Self, DiscoveryError> {
        if port == 0 {
            return Err(DiscoveryError::InvalidPort);
        }
        if host.trim() != host {
            return Err(DiscoveryError::InvalidHost);
        }
        let without_root = host.strip_suffix('.').unwrap_or(host);
        if without_root.ends_with('.') {
            return Err(DiscoveryError::InvalidHost);
        }
        let normalized = without_root.to_ascii_lowercase();
        validate_host(&normalized)?;
        let resolver_name = format!("_{port}.{}.{}", transport.label(), normalized);
        if resolver_name.len() > MAX_DNS_NAME_BYTES {
            return Err(DiscoveryError::NameTooLong);
        }
        let fqdn = format!("{resolver_name}.");
        Ok(Self {
            host: normalized,
            resolver_name,
            fqdn,
            port,
            transport,
        })
    }

    /// Canonical origin host without a root dot.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Resolver-friendly owner without a terminating root dot.
    #[must_use]
    pub fn resolver_name(&self) -> &str {
        &self.resolver_name
    }

    /// Absolute DNS owner with a terminating root dot.
    #[must_use]
    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    /// Effective TLS service port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Effective TLS service transport.
    #[must_use]
    pub const fn transport(&self) -> TlsaTransport {
        self.transport
    }
}

impl fmt::Display for TlsaOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.fqdn())
    }
}

/// DNSSEC state reported for a completed lookup by the validating DoH adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcannDnssecStatus {
    /// The terminal TLSA data or authenticated denial is DNSSEC-secure.
    Secure,
    /// The chain proves that the applicable delegation is unsigned.
    InsecureDelegation,
    /// DNSSEC validation failed.
    Bogus,
    /// The adapter could not determine a secure or insecure result.
    Indeterminate,
}

/// Authentication state of the configured validating DoH resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolverAuthentication {
    /// The resolver endpoint passed its configured TLS authentication.
    Authenticated,
    /// The DoH channel did not authenticate the configured resolver.
    Unauthenticated,
}

/// DNSSEC query mode used for the terminal TLSA request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnssecQueryMode {
    /// DNSSEC records were requested and resolver validation remained enabled.
    Validate,
    /// The query disabled validation with the CD bit.
    CheckingDisabled,
    /// The query did not request DNSSEC records with the DO bit.
    DnssecRecordsNotRequested,
}

/// Denial evidence for an empty terminal TLSA result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsaDenial {
    /// No authenticated denial covers TLSA absence.
    None,
    /// Secure NSEC/NSEC3 evidence covers TLSA absence.
    Authenticated,
}

/// Evidence retained from one terminal validating ICANN DoH lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatingDohEvidence {
    /// The configured validating resolver was authenticated by the DoH TLS
    /// channel before this DNS response was accepted.
    pub resolver_authentication: ResolverAuthentication,
    /// DNSSEC request and validation mode.
    pub query_mode: DnssecQueryMode,
    /// Typed DNSSEC outcome. Transport, HTTP, parsing, and response-code errors
    /// must be represented as `Bogus` or `Indeterminate`, never as absence.
    pub dnssec: IcannDnssecStatus,
    /// Number of terminal TLSA records. Unsupported records still count:
    /// secure presence selects DANE and later validation must fail closed.
    pub tlsa_record_count: usize,
    /// Denial evidence for an empty terminal result.
    pub denial: TlsaDenial,
}

/// Defined browser trust action after automatic TLSA discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserTlsDecision {
    /// Secure TLSA data is present and must be enforced instead of WebPKI.
    EnforceDane {
        /// Nonzero number of terminal TLSA records to validate.
        record_count: NonZeroUsize,
    },
    /// TLSA is securely absent, so the connection retains WebPKI.
    WebPkiAuthenticatedAbsence,
    /// The applicable zone is proven insecure, so unsigned TLSA bytes are
    /// ignored and the connection retains WebPKI.
    WebPkiInsecureDelegation,
}

impl BrowserTlsDecision {
    /// Whether this action requires local DANE certificate validation.
    #[must_use]
    pub const fn enforces_dane(self) -> bool {
        matches!(self, Self::EnforceDane { .. })
    }

    /// Whether this action permits WebPKI for the origin.
    #[must_use]
    pub const fn permits_webpki(self) -> bool {
        matches!(
            self,
            Self::WebPkiAuthenticatedAbsence | Self::WebPkiInsecureDelegation
        )
    }
}

/// Convert validating DoH evidence into the only permitted browser actions.
///
/// This function never converts bogus, indeterminate, unauthenticated, or
/// structurally conflicting evidence into “no TLSA.”
///
/// # Errors
///
/// Returns a fail-closed [`DiscoveryError`] when resolver authentication or
/// DNSSEC validation was bypassed, DNSSEC is bogus or indeterminate, or the
/// presence/denial evidence is incomplete or contradictory.
pub fn decide_browser_tls(
    evidence: ValidatingDohEvidence,
) -> Result<BrowserTlsDecision, DiscoveryError> {
    if evidence.resolver_authentication != ResolverAuthentication::Authenticated {
        return Err(DiscoveryError::UnauthenticatedResolver);
    }
    if evidence.query_mode != DnssecQueryMode::Validate {
        return Err(DiscoveryError::ValidationBypassed);
    }

    match evidence.dnssec {
        IcannDnssecStatus::Bogus => Err(DiscoveryError::BogusDnssec),
        IcannDnssecStatus::Indeterminate => Err(DiscoveryError::IndeterminateDnssec),
        IcannDnssecStatus::InsecureDelegation => {
            if evidence.denial == TlsaDenial::Authenticated {
                return Err(DiscoveryError::ConflictingEvidence);
            }
            Ok(BrowserTlsDecision::WebPkiInsecureDelegation)
        }
        IcannDnssecStatus::Secure => match (
            NonZeroUsize::new(evidence.tlsa_record_count),
            evidence.denial,
        ) {
            (Some(record_count), TlsaDenial::None) => {
                Ok(BrowserTlsDecision::EnforceDane { record_count })
            }
            (None, TlsaDenial::Authenticated) => Ok(BrowserTlsDecision::WebPkiAuthenticatedAbsence),
            (Some(_), TlsaDenial::Authenticated) => Err(DiscoveryError::ConflictingEvidence),
            (None, TlsaDenial::None) => Err(DiscoveryError::MissingAuthenticatedDenial),
        },
    }
}

/// Automatic DANE discovery failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// Origin host is empty, non-ASCII, malformed, or an IP literal.
    InvalidHost,
    /// Effective service port is zero.
    InvalidPort,
    /// Derived owner exceeds the DNS presentation/wire bound.
    NameTooLong,
    /// The DoH resolver endpoint was not authenticated.
    UnauthenticatedResolver,
    /// DNSSEC validation was disabled or DNSSEC records were not requested.
    ValidationBypassed,
    /// The validating resolver reported bogus DNSSEC.
    BogusDnssec,
    /// No secure or proven-insecure DNSSEC classification was available.
    IndeterminateDnssec,
    /// Secure empty data lacked authenticated denial.
    MissingAuthenticatedDenial,
    /// Presence, denial, and DNSSEC state contradict one another.
    ConflictingEvidence,
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHost => "invalid canonical DNS host",
            Self::InvalidPort => "TLSA service port must be nonzero",
            Self::NameTooLong => "derived TLSA owner exceeds DNS bounds",
            Self::UnauthenticatedResolver => "validating ICANN DoH resolver is unauthenticated",
            Self::ValidationBypassed => "ICANN DNSSEC validation was bypassed",
            Self::BogusDnssec => "ICANN DNSSEC validation is bogus",
            Self::IndeterminateDnssec => "ICANN DNSSEC validation is indeterminate",
            Self::MissingAuthenticatedDenial => {
                "empty secure TLSA result lacks authenticated denial"
            }
            Self::ConflictingEvidence => "ICANN TLSA evidence is internally conflicting",
        })
    }
}

impl std::error::Error for DiscoveryError {}

fn validate_host(host: &str) -> Result<(), DiscoveryError> {
    if host.is_empty()
        || !host.is_ascii()
        || host.len() > MAX_DNS_NAME_BYTES
        || IpAddr::from_str(host).is_ok()
    {
        return Err(DiscoveryError::InvalidHost);
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > MAX_DNS_LABEL_BYTES
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(DiscoveryError::InvalidHost);
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately when a fixture violates its invariant"
)]
mod tests {
    use super::*;

    fn evidence(
        dnssec: IcannDnssecStatus,
        tlsa_record_count: usize,
        authenticated_denial: bool,
    ) -> ValidatingDohEvidence {
        ValidatingDohEvidence {
            resolver_authentication: ResolverAuthentication::Authenticated,
            query_mode: DnssecQueryMode::Validate,
            dnssec,
            tlsa_record_count,
            denial: if authenticated_denial {
                TlsaDenial::Authenticated
            } else {
                TlsaDenial::None
            },
        }
    }

    #[test]
    fn derives_host_port_and_transport_without_a_hostname_allowlist() {
        let https = TlsaOwner::derive("DANE-TEST.DENUOWEB.COM.", 443, TlsaTransport::Tcp).unwrap();
        assert_eq!(https.host(), "dane-test.denuoweb.com");
        assert_eq!(https.resolver_name(), "_443._tcp.dane-test.denuoweb.com");
        assert_eq!(https.fqdn(), "_443._tcp.dane-test.denuoweb.com.");
        assert_eq!(
            TlsaOwner::derive("example.com", 8443, TlsaTransport::Udp)
                .unwrap()
                .fqdn(),
            "_8443._udp.example.com."
        );
        assert_eq!(
            TlsaOwner::derive("xn--bcher-kva.example", 9443, TlsaTransport::Sctp)
                .unwrap()
                .fqdn(),
            "_9443._sctp.xn--bcher-kva.example."
        );
    }

    #[test]
    fn rejects_non_dns_origins_and_oversized_service_owners() {
        for host in [
            "",
            " example.com",
            "example.com ",
            "example.com..",
            "127.0.0.1",
            "::1",
            "[::1]",
            "has space.example",
            "-bad.example",
            "bad-.example",
            "bücher.example",
        ] {
            assert_eq!(
                TlsaOwner::derive(host, 443, TlsaTransport::Tcp),
                Err(DiscoveryError::InvalidHost)
            );
        }
        assert_eq!(
            TlsaOwner::derive("example.com", 0, TlsaTransport::Tcp),
            Err(DiscoveryError::InvalidPort)
        );

        let long_host = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(52),
        ]
        .join(".");
        assert!(long_host.len() <= MAX_DNS_NAME_BYTES);
        assert_eq!(
            TlsaOwner::derive(&long_host, 443, TlsaTransport::Tcp),
            Err(DiscoveryError::NameTooLong)
        );
    }

    #[test]
    fn secure_presence_enforces_dane_even_for_unsupported_records() {
        let decision = decide_browser_tls(evidence(IcannDnssecStatus::Secure, 2, false)).unwrap();
        assert_eq!(
            decision,
            BrowserTlsDecision::EnforceDane {
                record_count: NonZeroUsize::new(2).unwrap()
            }
        );
        assert!(decision.enforces_dane());
        assert!(!decision.permits_webpki());
    }

    #[test]
    fn only_authenticated_absence_or_insecure_delegation_permits_webpki() {
        let absence = decide_browser_tls(evidence(IcannDnssecStatus::Secure, 0, true)).unwrap();
        assert_eq!(absence, BrowserTlsDecision::WebPkiAuthenticatedAbsence);
        assert!(absence.permits_webpki());

        let insecure =
            decide_browser_tls(evidence(IcannDnssecStatus::InsecureDelegation, 4, false)).unwrap();
        assert_eq!(insecure, BrowserTlsDecision::WebPkiInsecureDelegation);
        assert!(insecure.permits_webpki());
    }

    #[test]
    fn bogus_and_indeterminate_never_become_no_tlsa() {
        assert_eq!(
            decide_browser_tls(evidence(IcannDnssecStatus::Bogus, 0, false)),
            Err(DiscoveryError::BogusDnssec)
        );
        assert_eq!(
            decide_browser_tls(evidence(IcannDnssecStatus::Indeterminate, 0, false)),
            Err(DiscoveryError::IndeterminateDnssec)
        );
        assert_eq!(
            decide_browser_tls(evidence(IcannDnssecStatus::Secure, 0, false)),
            Err(DiscoveryError::MissingAuthenticatedDenial)
        );
    }

    #[test]
    fn resolver_authentication_and_dnssec_query_mode_are_mandatory() {
        let mut untrusted = evidence(IcannDnssecStatus::Secure, 1, false);
        untrusted.resolver_authentication = ResolverAuthentication::Unauthenticated;
        assert_eq!(
            decide_browser_tls(untrusted),
            Err(DiscoveryError::UnauthenticatedResolver)
        );

        let mut no_do = evidence(IcannDnssecStatus::Secure, 1, false);
        no_do.query_mode = DnssecQueryMode::DnssecRecordsNotRequested;
        assert_eq!(
            decide_browser_tls(no_do),
            Err(DiscoveryError::ValidationBypassed)
        );

        let mut checking_disabled = evidence(IcannDnssecStatus::Secure, 1, false);
        checking_disabled.query_mode = DnssecQueryMode::CheckingDisabled;
        assert_eq!(
            decide_browser_tls(checking_disabled),
            Err(DiscoveryError::ValidationBypassed)
        );
    }

    #[test]
    fn contradictory_presence_and_denial_fail_closed() {
        assert_eq!(
            decide_browser_tls(evidence(IcannDnssecStatus::Secure, 1, true)),
            Err(DiscoveryError::ConflictingEvidence)
        );
        assert_eq!(
            decide_browser_tls(evidence(IcannDnssecStatus::InsecureDelegation, 0, true,)),
            Err(DiscoveryError::ConflictingEvidence)
        );
    }
}
