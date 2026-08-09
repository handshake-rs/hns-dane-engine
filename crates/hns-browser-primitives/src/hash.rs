use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use thiserror::Error;

pub const MAX_HANDSHAKE_NAME_LEN: usize = 63;

#[derive(Clone, Copy, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Hash([u8; 32]);

#[derive(Clone, Copy, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NameHash(Hash);

#[derive(Debug, Error, Eq, PartialEq)]
pub enum HashError {
    #[error("hash hex must decode to 32 bytes")]
    InvalidLength,
    #[error("hash hex is invalid")]
    InvalidHex,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum NameHashError {
    #[error("Handshake name is empty")]
    Empty,
    #[error("Handshake name exceeds 63 bytes")]
    TooLong,
    #[error("Handshake name contains an uppercase character")]
    Uppercase,
    #[error("Handshake name contains an invalid character")]
    InvalidCharacter,
    #[error("Handshake name begins or ends with '-' or '_'")]
    InvalidBoundary,
    #[error("Handshake name is blacklisted")]
    Blacklisted,
}

impl Hash {
    pub const ZERO: Self = Self([0u8; 32]);

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, HashError> {
        if bytes.len() != 32 {
            return Err(HashError::InvalidLength);
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    pub fn from_hex(hex_value: &str) -> Result<Self, HashError> {
        let bytes = hex::decode(hex_value).map_err(|_| HashError::InvalidHex)?;
        Self::from_slice(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl NameHash {
    pub const ZERO: Self = Self(Hash::ZERO);

    pub const fn new(hash: Hash) -> Self {
        Self(hash)
    }

    pub fn from_name(name: &str) -> Result<Self, NameHashError> {
        validate_handshake_name(name)?;
        Ok(Self(sha3_256(&[name.as_bytes()])))
    }

    pub fn as_hash(&self) -> Hash {
        self.0
    }
}

pub fn validate_handshake_name(name: &str) -> Result<(), NameHashError> {
    if name.is_empty() {
        return Err(NameHashError::Empty);
    }
    if name.len() > MAX_HANDSHAKE_NAME_LEN {
        return Err(NameHashError::TooLong);
    }
    if matches!(name, "example" | "invalid" | "local" | "localhost" | "test") {
        return Err(NameHashError::Blacklisted);
    }

    for (index, byte) in name.bytes().enumerate() {
        match byte {
            b'0'..=b'9' | b'a'..=b'z' => {}
            b'A'..=b'Z' => return Err(NameHashError::Uppercase),
            b'-' | b'_' => {
                if index == 0 || index + 1 == name.len() {
                    return Err(NameHashError::InvalidBoundary);
                }
            }
            0x00..=0x7f => return Err(NameHashError::InvalidCharacter),
            _ => return Err(NameHashError::InvalidCharacter),
        }
    }

    Ok(())
}

impl fmt::Debug for Hash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self}")
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for NameHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.0)
    }
}

pub fn blake2b_256(parts: &[&[u8]]) -> Hash {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output size");
    for part in parts {
        hasher.update(part);
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("valid BLAKE2b output buffer");
    Hash::new(out)
}

pub fn blake2b_512(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Blake2bVar::new(64).expect("valid BLAKE2b output size");
    for part in parts {
        hasher.update(part);
    }

    let mut out = [0u8; 64];
    hasher
        .finalize_variable(&mut out)
        .expect("valid BLAKE2b output buffer");
    out
}

pub fn sha3_256(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha3_256::new();
    for part in parts {
        Digest::update(&mut hasher, part);
    }

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Hash::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_hash_matches_hsd_sha3_vector() {
        assert_eq!(
            NameHash::from_name("welcome").unwrap().as_hash(),
            Hash::from_hex("64db51f8f79ca7ec522a6b4ae5fc7e896daac5318b2e82730d7c7926b66d36eb")
                .unwrap(),
        );
    }

    #[test]
    fn validates_handshake_name_rules() {
        assert_eq!(
            validate_handshake_name("").unwrap_err(),
            NameHashError::Empty
        );
        assert_eq!(
            validate_handshake_name(&"a".repeat(64)).unwrap_err(),
            NameHashError::TooLong,
        );
        assert_eq!(
            validate_handshake_name("Welcome").unwrap_err(),
            NameHashError::Uppercase,
        );
        assert_eq!(
            validate_handshake_name("-name").unwrap_err(),
            NameHashError::InvalidBoundary,
        );
        assert_eq!(
            validate_handshake_name("name_").unwrap_err(),
            NameHashError::InvalidBoundary,
        );
        assert_eq!(
            validate_handshake_name("two.words").unwrap_err(),
            NameHashError::InvalidCharacter,
        );
        assert_eq!(
            validate_handshake_name("example").unwrap_err(),
            NameHashError::Blacklisted,
        );
        assert!(validate_handshake_name("valid-name_123").is_ok());
    }
}
