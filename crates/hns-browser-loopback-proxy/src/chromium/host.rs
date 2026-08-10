use std::net::IpAddr;
use std::str::FromStr;

use hns_resolver::{NameClass, classify_name};
use thiserror::Error;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedHost {
    ascii: String,
}

impl NormalizedHost {
    pub fn parse(input: &str) -> Result<Self, HostNormalizationError> {
        if input.is_empty() {
            return Err(HostNormalizationError::Empty);
        }
        if input.trim() != input {
            return Err(HostNormalizationError::SurroundingWhitespace);
        }
        if input.chars().any(is_forbidden_input_character) {
            return Err(HostNormalizationError::ForbiddenCharacter);
        }

        let input = strip_one_terminal_dot(input);
        if input.is_empty() || input.chars().last().is_some_and(is_idna_dot) {
            return Err(HostNormalizationError::InvalidDnsName);
        }
        let ascii = idna::domain_to_ascii_cow(input.as_bytes(), idna::AsciiDenyList::URL)
            .map_err(|_| HostNormalizationError::InvalidIdna)?
            .to_ascii_lowercase();
        validate_ascii_dns_name(&ascii)?;
        if ascii.parse::<IpAddr>().is_ok() || looks_like_legacy_ipv4(&ascii) {
            return Err(HostNormalizationError::IpLiteral);
        }

        Ok(Self { ascii })
    }

    pub fn as_str(&self) -> &str {
        &self.ascii
    }

    pub fn class(&self) -> NameClass {
        classify_name(&self.ascii)
    }

    pub fn is_hns(&self) -> bool {
        self.class() == NameClass::Hns
    }
}

impl AsRef<str> for NormalizedHost {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::ops::Deref for NormalizedHost {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl std::fmt::Debug for NormalizedHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NormalizedHost([REDACTED])")
    }
}

impl std::fmt::Display for NormalizedHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.ascii)
    }
}

impl FromStr for NormalizedHost {
    type Err = HostNormalizationError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostScope {
    root: NormalizedHost,
}

impl HostScope {
    pub fn new(root: impl AsRef<str>) -> Result<Self, HostScopeError> {
        let root = NormalizedHost::parse(root.as_ref())?;
        ensure_hns(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &NormalizedHost {
        &self.root
    }

    pub fn allows(&self, candidate: &str) -> bool {
        self.authorize(candidate).is_ok()
    }

    pub fn allows_normalized(&self, candidate: &NormalizedHost) -> bool {
        candidate.is_hns() && is_equal_or_subdomain(candidate.as_str(), self.root.as_str())
    }

    /// Returns the canonical target only when it is an HNS name inside this immutable scope.
    pub fn authorize(&self, candidate: &str) -> Result<NormalizedHost, HostScopeError> {
        let candidate = NormalizedHost::parse(candidate)?;
        ensure_hns(&candidate)?;
        if !self.allows_normalized(&candidate) {
            return Err(HostScopeError::OutOfScope);
        }
        Ok(candidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HostNormalizationError {
    #[error("host is empty")]
    Empty,
    #[error("host contains surrounding whitespace")]
    SurroundingWhitespace,
    #[error("host contains a forbidden authority character")]
    ForbiddenCharacter,
    #[error("host is not valid strict IDNA")]
    InvalidIdna,
    #[error("host violates DNS name length or label rules")]
    InvalidDnsName,
    #[error("IP literals are outside the HNS proxy boundary")]
    IpLiteral,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HostScopeError {
    #[error(transparent)]
    InvalidHost(#[from] HostNormalizationError),
    #[error("host is not classified in the HNS namespace")]
    NotHns,
    #[error("host is outside the immutable HNS proxy scope")]
    OutOfScope,
}

fn ensure_hns(host: &NormalizedHost) -> Result<(), HostScopeError> {
    if host.is_hns() {
        Ok(())
    } else {
        Err(HostScopeError::NotHns)
    }
}

fn is_equal_or_subdomain(candidate: &str, root: &str) -> bool {
    if candidate == root {
        return true;
    }
    let Some(prefix) = candidate.strip_suffix(root) else {
        return false;
    };
    prefix.ends_with('.')
}

fn is_forbidden_input_character(character: char) -> bool {
    character.is_control()
        || character.is_whitespace()
        || matches!(
            character,
            '/' | ':' | '?' | '#' | '@' | '[' | ']' | '\\' | '<' | '>' | '"'
        )
}

fn strip_one_terminal_dot(input: &str) -> &str {
    input
        .char_indices()
        .next_back()
        .filter(|(_, character)| is_idna_dot(*character))
        .map_or(input, |(index, _)| &input[..index])
}

fn is_idna_dot(character: char) -> bool {
    matches!(character, '.' | '\u{3002}' | '\u{ff0e}' | '\u{ff61}')
}

fn validate_ascii_dns_name(host: &str) -> Result<(), HostNormalizationError> {
    if host.is_empty() || host.len() > 253 || host.ends_with('.') {
        return Err(HostNormalizationError::InvalidDnsName);
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(HostNormalizationError::InvalidDnsName);
    }
    Ok(())
}

fn looks_like_legacy_ipv4(host: &str) -> bool {
    let mut labels = host.split('.');
    let mut count = 0usize;
    let all_numeric = labels.all(|label| {
        count += 1;
        is_ipv4_number(label)
    });
    all_numeric && (1..=4).contains(&count)
}

fn is_ipv4_number(label: &str) -> bool {
    if let Some(hex) = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
    {
        return !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    if label.len() > 1 && label.starts_with('0') {
        return label.bytes().all(|byte| matches!(byte, b'0'..=b'7'));
    }
    !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_case_trailing_dot_and_unicode_with_strict_idna() {
        assert_eq!(
            NormalizedHost::parse("WELCOME.").unwrap().as_str(),
            "welcome"
        );
        assert_eq!(
            NormalizedHost::parse("BÜCHER").unwrap().as_str(),
            "xn--bcher-kva"
        );
        assert_eq!(
            NormalizedHost::parse("café.WELCOME").unwrap().as_str(),
            "xn--caf-dma.welcome"
        );
        assert_eq!(NormalizedHost::parse("🤝").unwrap().as_str(), "xn--5p9h");
        assert_eq!(
            NormalizedHost::parse("welcome。").unwrap().as_str(),
            "welcome"
        );
    }

    #[test]
    fn rejects_authorities_search_input_ip_literals_and_invalid_dns_names() {
        for invalid in [
            "",
            " welcome",
            "welcome ",
            "two words",
            "https://welcome",
            "welcome:443",
            "user@welcome",
            "welcome/path",
            "welcome..",
            ".welcome",
            "-welcome",
            "welcome-",
        ] {
            assert!(NormalizedHost::parse(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            NormalizedHost::parse("127.0.0.1"),
            Err(HostNormalizationError::IpLiteral)
        );
        for legacy_ip in ["2130706433", "0x7f000001", "127.1", "0177.0.0.1"] {
            assert_eq!(
                NormalizedHost::parse(legacy_ip),
                Err(HostNormalizationError::IpLiteral),
                "{legacy_ip}"
            );
        }
        assert!(NormalizedHost::parse("[::1]").is_err());
    }

    #[test]
    fn debug_output_does_not_retain_the_browsing_scope() {
        let host = NormalizedHost::parse("private-history-name").unwrap();
        let scope = HostScope::new(host.as_str()).unwrap();

        assert!(!format!("{host:?}").contains(host.as_str()));
        assert!(!format!("{scope:?}").contains(host.as_str()));
    }

    #[test]
    fn classification_is_delegated_to_the_resolver_policy() {
        assert_eq!(
            NormalizedHost::parse("welcome").unwrap().class(),
            NameClass::Hns
        );
        assert_eq!(
            NormalizedHost::parse("www.welcome").unwrap().class(),
            NameClass::Hns
        );
        assert_eq!(
            NormalizedHost::parse("example.com").unwrap().class(),
            NameClass::Icann
        );
        assert_eq!(
            NormalizedHost::parse("service.localhost").unwrap().class(),
            NameClass::Icann
        );
    }

    #[test]
    fn scope_accepts_only_the_exact_root_and_label_boundary_subdomains() {
        let scope = HostScope::new("Welcome.").unwrap();

        assert!(scope.allows("welcome"));
        assert!(scope.allows("www.welcome"));
        assert!(scope.allows("deep.www.welcome."));
        assert!(!scope.allows("evilwelcome"));
        assert!(!scope.allows("welcome.evil"));
        assert!(!scope.allows("example.com"));
    }

    #[test]
    fn scope_compares_idna_canonical_forms() {
        let scope = HostScope::new("Bücher").unwrap();

        assert!(scope.allows("xn--bcher-kva"));
        assert!(scope.allows("shop.BÜCHER."));
    }

    #[test]
    fn scope_construction_fails_closed_for_non_hns_names() {
        assert_eq!(HostScope::new("example.com"), Err(HostScopeError::NotHns));
        assert_eq!(HostScope::new("localhost"), Err(HostScopeError::NotHns));
        assert_eq!(
            HostScope::new("127.0.0.1"),
            Err(HostScopeError::InvalidHost(
                HostNormalizationError::IpLiteral
            ))
        );
    }

    #[test]
    fn authorize_preserves_invalid_out_of_namespace_and_out_of_scope_failures() {
        let scope = HostScope::new("welcome").unwrap();

        assert_eq!(
            scope.authorize(" welcome"),
            Err(HostScopeError::InvalidHost(
                HostNormalizationError::SurroundingWhitespace
            ))
        );
        assert_eq!(scope.authorize("example.com"), Err(HostScopeError::NotHns));
        assert_eq!(scope.authorize("other"), Err(HostScopeError::OutOfScope));
    }
}
