use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const PROXY_AUTHORIZATION_HEADER: &str = "Proxy-Authorization";
pub const PROXY_AUTHENTICATE_HEADER: &str = "Proxy-Authenticate";

const USERNAME: &str = "hns-browser";
const REALM_RANDOM_BYTES: usize = 12;
const PASSWORD_RANDOM_BYTES: usize = 32;
const MAX_ENCODED_CREDENTIAL_BYTES: usize = 256;

/// Per-instance capability credentials for the loopback proxy.
///
/// There is deliberately no public constructor that accepts credentials. A running proxy must
/// generate a fresh value and require it on every request, including `CONNECT` requests.
pub struct ProxyAuthorization {
    realm: String,
    username: String,
    password: String,
    expected_credentials_digest: [u8; 32],
    expected_credentials_len: usize,
}

impl ProxyAuthorization {
    pub fn generate() -> Result<Self, AuthorizationGenerationError> {
        let random = SystemRandom::new();
        let realm = format!(
            "hns-loopback-{}",
            random_url_token(&random, REALM_RANDOM_BYTES)?
        );
        let password = random_url_token(&random, PASSWORD_RANDOM_BYTES)?;
        Ok(Self::from_generated_parts(realm, password))
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn authorization_header_value(&self) -> String {
        format!("Basic {}", STANDARD.encode(self.credentials()))
    }

    pub fn challenge_header_value(&self) -> String {
        format!("Basic realm=\"{}\"", self.realm)
    }

    /// Verifies exactly one `Proxy-Authorization` value.
    ///
    /// Callers should pass every occurrence of the header so duplicate credentials fail closed.
    pub fn verify_header_values<'a>(&self, values: impl IntoIterator<Item = &'a str>) -> bool {
        let mut values = values.into_iter();
        let Some(value) = values.next() else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        self.verify_header_value(value)
    }

    pub fn verify_header_value(&self, value: &str) -> bool {
        let Some(encoded) = basic_token(value) else {
            return false;
        };
        if encoded.len() > MAX_ENCODED_CREDENTIAL_BYTES {
            return false;
        }
        let Ok(supplied) = STANDARD.decode(encoded) else {
            return false;
        };

        // The digest comparison is fixed-width and constant-time. The separate length comparison
        // only reveals the public, fixed credential format and prevents accepting a hash collision
        // between differently sized inputs.
        let supplied_digest = digest(&SHA256, &supplied);
        let digest_matches = supplied_digest
            .as_ref()
            .ct_eq(&self.expected_credentials_digest)
            .unwrap_u8();
        let length_matches = u8::from(supplied.len() == self.expected_credentials_len);
        (digest_matches & length_matches) == 1
    }

    /// Limits credential challenge handling to this proxy's only supported bind address.
    pub fn matches_challenge(&self, host: &str, challenge_realm: &str) -> bool {
        let host = host.trim();
        let host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        host == "127.0.0.1" && challenge_realm == self.realm
    }

    fn from_generated_parts(realm: String, password: String) -> Self {
        let username = USERNAME.to_owned();
        let credentials = format!("{username}:{password}");
        let credentials_digest = digest(&SHA256, credentials.as_bytes());
        let mut expected_credentials_digest = [0_u8; 32];
        expected_credentials_digest.copy_from_slice(credentials_digest.as_ref());

        Self {
            realm,
            username,
            password,
            expected_credentials_digest,
            expected_credentials_len: credentials.len(),
        }
    }

    fn credentials(&self) -> String {
        format!("{}:{}", self.username, self.password)
    }
}

impl std::fmt::Debug for ProxyAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyAuthorization")
            .field("realm", &"[REDACTED]")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("the operating-system random number generator failed")]
pub struct AuthorizationGenerationError;

fn random_url_token(
    random: &dyn SecureRandom,
    byte_count: usize,
) -> Result<String, AuthorizationGenerationError> {
    let mut bytes = vec![0_u8; byte_count];
    random
        .fill(&mut bytes)
        .map_err(|_| AuthorizationGenerationError)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn basic_token(value: &str) -> Option<&str> {
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, ' ' | '\t'))
    {
        return None;
    }
    let value = value.trim_matches([' ', '\t']);
    let separator = value.find([' ', '\t'])?;
    let (scheme, remainder) = value.split_at(separator);
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }

    let token = remainder.trim_start_matches([' ', '\t']);
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return None;
    }
    Some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization() -> ProxyAuthorization {
        ProxyAuthorization::from_generated_parts(
            "hns-loopback-test-realm".to_owned(),
            "test-password-capability".to_owned(),
        )
    }

    #[test]
    fn generated_authorizations_are_fresh_capabilities() {
        let first = ProxyAuthorization::generate().unwrap();
        let second = ProxyAuthorization::generate().unwrap();

        assert_eq!(first.username(), USERNAME);
        assert!(first.realm().starts_with("hns-loopback-"));
        assert_ne!(first.realm(), second.realm());
        assert_ne!(first.password(), second.password());
        assert!(first.verify_header_value(&first.authorization_header_value()));
    }

    #[test]
    fn verifies_basic_credentials_and_rejects_substitutions() {
        let authorization = authorization();
        let valid = authorization.authorization_header_value();
        let encoded_wrong = STANDARD.encode("hns-browser:wrong-password");

        assert!(authorization.verify_header_value(&valid));
        assert!(authorization.verify_header_value(&valid.replacen("Basic", "bAsIc", 1)));
        assert!(!authorization.verify_header_value(&format!("Basic {encoded_wrong}")));
        assert!(!authorization.verify_header_value("Bearer abc"));
        assert!(!authorization.verify_header_value("Basic !!!"));
        assert!(!authorization.verify_header_value("Basic"));
        assert!(!authorization.verify_header_value("Basic Zm9v YmFy"));
        assert!(!authorization.verify_header_value(&format!("{valid}\r\n")));
    }

    #[test]
    fn requires_exactly_one_authorization_header() {
        let authorization = authorization();
        let valid = authorization.authorization_header_value();

        assert!(!authorization.verify_header_values(std::iter::empty()));
        assert!(authorization.verify_header_values([valid.as_str()]));
        assert!(!authorization.verify_header_values([valid.as_str(), valid.as_str()]));
    }

    #[test]
    fn debug_output_redacts_every_capability_component() {
        let authorization = authorization();
        let debug = format!("{authorization:?}");

        assert!(!debug.contains(authorization.realm()));
        assert!(!debug.contains(authorization.username()));
        assert!(!debug.contains(authorization.password()));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn challenge_matching_is_restricted_to_ipv4_loopback_and_exact_realm() {
        let authorization = authorization();

        assert!(authorization.matches_challenge("127.0.0.1", authorization.realm()));
        assert!(authorization.matches_challenge("[127.0.0.1]", authorization.realm()));
        assert!(!authorization.matches_challenge("localhost", authorization.realm()));
        assert!(!authorization.matches_challenge("::1", authorization.realm()));
        assert!(!authorization.matches_challenge("[[127.0.0.1]]", authorization.realm()));
        assert!(!authorization.matches_challenge("127.0.0.1", "another-realm"));
    }
}
