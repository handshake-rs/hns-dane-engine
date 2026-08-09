use hns_core::hash::blake2b_256;
use hns_core::{Hash, NameHash};
use thiserror::Error;

pub const MAX_PROOF_SIZE: usize = 256 * 1024;
pub const URKEL_BITS: usize = 256;
pub const URKEL_HASH_SIZE: usize = 32;

const TYPE_DEADEND: u8 = 0;
const TYPE_SHORT: u8 = 1;
const TYPE_COLLISION: u8 = 2;
const TYPE_EXISTS: u8 = 3;
const INTERNAL_PREFIX: &[u8] = &[0x01];
const SKIP_PREFIX: &[u8] = &[0x02];
const LEAF_PREFIX: &[u8] = &[0x00];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofKind {
    Inclusion,
    NonInclusion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedProof {
    pub kind: ProofKind,
    pub root: Hash,
    pub name_hash: NameHash,
    pub payload: Vec<u8>,
    pub proof: UrkelProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UrkelProof {
    proof_type: u8,
    depth: usize,
    nodes: Vec<UrkelProofNode>,
    body: ProofBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UrkelProofNode {
    prefix: BitPrefix,
    hash: Hash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProofBody {
    Deadend,
    Short {
        prefix: BitPrefix,
        left: Hash,
        right: Hash,
    },
    Collision {
        key: Hash,
        value_hash: Hash,
    },
    Exists {
        value: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BitPrefix {
    size: usize,
    data: Vec<u8>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProofError {
    #[error("proof exceeds maximum size")]
    TooLarge,
    #[error("proof is malformed")]
    Malformed,
    #[error("Urkel verification is not implemented")]
    UnsupportedVerifier,
}

impl ParsedProof {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProofError> {
        Self::parse_for_key(bytes, Hash::ZERO, NameHash::ZERO)
    }

    pub fn parse_for_key(
        bytes: &[u8],
        root: Hash,
        name_hash: NameHash,
    ) -> Result<Self, ProofError> {
        if bytes.len() > MAX_PROOF_SIZE {
            return Err(ProofError::TooLarge);
        }

        let proof = UrkelProof::decode(bytes)?;
        let kind = proof.kind();

        Ok(Self {
            kind,
            root,
            name_hash,
            payload: bytes.to_vec(),
            proof,
        })
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.proof.value()
    }
}

impl UrkelProof {
    pub fn decode(bytes: &[u8]) -> Result<Self, ProofError> {
        if bytes.len() > MAX_PROOF_SIZE {
            return Err(ProofError::TooLarge);
        }

        let mut cursor = Cursor::new(bytes);
        let field = cursor.read_u16_le()?;
        let proof_type = (field >> 14) as u8;
        let depth = (field & !(3 << 14)) as usize;
        if depth > URKEL_BITS {
            return Err(ProofError::Malformed);
        }

        let count = cursor.read_u16_le()? as usize;
        if count > URKEL_BITS {
            return Err(ProofError::Malformed);
        }

        let prefix_bitmap_len = count.div_ceil(8);
        let prefix_bitmap = cursor.read_bytes(prefix_bitmap_len)?.to_vec();
        let mut nodes = Vec::with_capacity(count);
        for index in 0..count {
            let prefix = if has_bit(&prefix_bitmap, index) {
                let prefix = cursor.read_prefix()?;
                if prefix.size == 0 || prefix.size > URKEL_BITS {
                    return Err(ProofError::Malformed);
                }
                prefix
            } else {
                BitPrefix::empty()
            };
            let hash = cursor.read_hash()?;
            nodes.push(UrkelProofNode { prefix, hash });
        }

        let body = match proof_type {
            TYPE_DEADEND => ProofBody::Deadend,
            TYPE_SHORT => {
                let prefix = cursor.read_prefix()?;
                if prefix.size == 0 || prefix.size > URKEL_BITS {
                    return Err(ProofError::Malformed);
                }
                let left = cursor.read_hash()?;
                let right = cursor.read_hash()?;
                ProofBody::Short {
                    prefix,
                    left,
                    right,
                }
            }
            TYPE_COLLISION => {
                let key = cursor.read_hash()?;
                let value_hash = cursor.read_hash()?;
                ProofBody::Collision { key, value_hash }
            }
            TYPE_EXISTS => {
                let size = cursor.read_u16_le()? as usize;
                let value = cursor.read_bytes(size)?.to_vec();
                ProofBody::Exists { value }
            }
            _ => return Err(ProofError::Malformed),
        };

        if !cursor.is_finished() {
            return Err(ProofError::Malformed);
        }

        let proof = Self {
            proof_type,
            depth,
            nodes,
            body,
        };
        if !proof.is_sane() {
            return Err(ProofError::Malformed);
        }
        Ok(proof)
    }

    pub fn kind(&self) -> ProofKind {
        if self.proof_type == TYPE_EXISTS {
            ProofKind::Inclusion
        } else {
            ProofKind::NonInclusion
        }
    }

    pub fn value(&self) -> Option<&[u8]> {
        match &self.body {
            ProofBody::Exists { value } => Some(value),
            _ => None,
        }
    }

    pub fn verify(&self, root: Hash, key: Hash) -> bool {
        if !self.is_sane() {
            return false;
        }

        let leaf = match &self.body {
            ProofBody::Deadend => Hash::ZERO,
            ProofBody::Short {
                prefix,
                left,
                right,
            } => {
                if prefix.has(key.as_bytes(), self.depth) {
                    return false;
                }
                hash_internal(prefix, *left, *right)
            }
            ProofBody::Collision {
                key: other,
                value_hash,
            } => {
                if *other == key {
                    return false;
                }
                hash_leaf(*other, *value_hash)
            }
            ProofBody::Exists { value } => hash_value(key, value),
        };

        let mut next = leaf;
        let mut depth = self.depth;
        for node in self.nodes.iter().rev() {
            if depth < node.prefix.size + 1 {
                return false;
            }

            depth -= 1;
            next = if has_bit(key.as_bytes(), depth) {
                hash_internal(&node.prefix, node.hash, next)
            } else {
                hash_internal(&node.prefix, next, node.hash)
            };

            depth -= node.prefix.size;
            if !node.prefix.has(key.as_bytes(), depth) {
                return false;
            }
        }

        depth == 0 && next == root
    }

    fn is_sane(&self) -> bool {
        if self.depth > URKEL_BITS || self.nodes.len() > URKEL_BITS {
            return false;
        }
        if self.nodes.iter().any(|node| node.prefix.size > URKEL_BITS) {
            return false;
        }

        match &self.body {
            ProofBody::Deadend => self.proof_type == TYPE_DEADEND,
            ProofBody::Short {
                prefix,
                left: _,
                right: _,
            } => self.proof_type == TYPE_SHORT && prefix.size > 0 && prefix.size <= URKEL_BITS,
            ProofBody::Collision { .. } => self.proof_type == TYPE_COLLISION,
            ProofBody::Exists { value } => self.proof_type == TYPE_EXISTS && value.len() <= 0xffff,
        }
    }
}

pub trait ProofVerifier {
    fn verify(&self, proof: &ParsedProof, expected_root: Hash) -> Result<bool, ProofError>;
}

pub struct FailClosedProofVerifier;

pub struct UrkelProofVerifier;

impl ProofVerifier for FailClosedProofVerifier {
    fn verify(&self, _proof: &ParsedProof, _expected_root: Hash) -> Result<bool, ProofError> {
        Err(ProofError::UnsupportedVerifier)
    }
}

impl ProofVerifier for UrkelProofVerifier {
    fn verify(&self, proof: &ParsedProof, expected_root: Hash) -> Result<bool, ProofError> {
        if proof.root != expected_root {
            return Ok(false);
        }
        Ok(proof.proof.verify(expected_root, proof.name_hash.as_hash()))
    }
}

impl BitPrefix {
    fn empty() -> Self {
        Self {
            size: 0,
            data: Vec::new(),
        }
    }

    fn encoded_len(&self) -> usize {
        let len_len = if self.size >= 0x80 { 2 } else { 1 };
        len_len + self.data.len()
    }

    fn has(&self, key: &[u8], depth: usize) -> bool {
        self.count(key, depth) == self.size
    }

    fn count(&self, key: &[u8], depth: usize) -> usize {
        let key_bits = key.len() * 8;
        if depth >= key_bits {
            return 0;
        }

        let len = self.size.min(key_bits - depth);
        let mut matched = 0usize;
        for index in 0..len {
            if has_bit(&self.data, index) != has_bit(key, depth + index) {
                break;
            }
            matched += 1;
        }
        matched
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_u16_le(&mut self) -> Result<u16, ProofError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_hash(&mut self) -> Result<Hash, ProofError> {
        let bytes = self.read_bytes(URKEL_HASH_SIZE)?;
        Hash::from_slice(bytes).map_err(|_| ProofError::Malformed)
    }

    fn read_prefix(&mut self) -> Result<BitPrefix, ProofError> {
        let start = self.offset;
        let first = *self.data.get(self.offset).ok_or(ProofError::Malformed)?;
        self.offset += 1;

        let size = if first & 0x80 != 0 {
            let second = *self.data.get(self.offset).ok_or(ProofError::Malformed)?;
            self.offset += 1;
            ((first as usize - 0x80) << 8) | second as usize
        } else {
            first as usize
        };

        let byte_len = size.div_ceil(8);
        let data = self.read_bytes(byte_len)?.to_vec();
        let prefix = BitPrefix { size, data };
        if self.offset - start != prefix.encoded_len() {
            return Err(ProofError::Malformed);
        }
        Ok(prefix)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ProofError> {
        let end = self.offset.checked_add(len).ok_or(ProofError::Malformed)?;
        let bytes = self
            .data
            .get(self.offset..end)
            .ok_or(ProofError::Malformed)?;
        self.offset = end;
        Ok(bytes)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.data.len()
    }
}

fn has_bit(key: &[u8], index: usize) -> bool {
    let byte = key.get(index / 8).copied().unwrap_or(0);
    let bit = index & 7;
    (byte >> (7 - bit)) & 1 != 0
}

fn hash_internal(prefix: &BitPrefix, left: Hash, right: Hash) -> Hash {
    if prefix.size == 0 {
        return blake2b_256(&[INTERNAL_PREFIX, left.as_bytes(), right.as_bytes()]);
    }

    let size = (prefix.size as u16).to_le_bytes();
    blake2b_256(&[
        SKIP_PREFIX,
        &size,
        &prefix.data,
        left.as_bytes(),
        right.as_bytes(),
    ])
}

fn hash_leaf(key: Hash, value_hash: Hash) -> Hash {
    blake2b_256(&[LEAF_PREFIX, key.as_bytes(), value_hash.as_bytes()])
}

fn hash_value(key: Hash, value: &[u8]) -> Hash {
    hash_leaf(key, blake2b_256(&[value]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_proof_payload() {
        let payload = exists_payload(b"dns");
        let root = hash_value(hash(3), b"dns");
        let proof = ParsedProof::parse_for_key(&payload, root, NameHash::new(hash(3))).unwrap();

        assert_eq!(proof.kind, ProofKind::Inclusion);
        assert_eq!(proof.value(), Some(b"dns".as_slice()));
        assert_eq!(proof.payload, payload);
    }

    #[test]
    fn verifies_inclusion_proof() {
        let key = hash(3);
        let value = b"resource";
        let root = hash_value(key, value);
        let proof =
            ParsedProof::parse_for_key(&exists_payload(value), root, NameHash::new(key)).unwrap();

        assert!(UrkelProofVerifier.verify(&proof, root).unwrap());
        assert!(!UrkelProofVerifier.verify(&proof, hash(9)).unwrap());
    }

    #[test]
    fn verifies_deadend_absence_proof() {
        let proof =
            ParsedProof::parse_for_key(&deadend_payload(0), Hash::ZERO, NameHash::new(hash(7)))
                .unwrap();

        assert_eq!(proof.kind, ProofKind::NonInclusion);
        assert!(UrkelProofVerifier.verify(&proof, Hash::ZERO).unwrap());
    }

    #[test]
    fn verifies_collision_absence_proof() {
        let query = hash(1);
        let other = hash(2);
        let value_hash = blake2b_256(&[b"other"]);
        let root = hash_leaf(other, value_hash);
        let payload = collision_payload(0, other, value_hash);
        let proof = ParsedProof::parse_for_key(&payload, root, NameHash::new(query)).unwrap();

        assert_eq!(proof.kind, ProofKind::NonInclusion);
        assert!(UrkelProofVerifier.verify(&proof, root).unwrap());

        let same_key = ParsedProof::parse_for_key(&payload, root, NameHash::new(other)).unwrap();
        assert!(!UrkelProofVerifier.verify(&same_key, root).unwrap());
    }

    #[test]
    fn verifies_short_absence_proof() {
        let query = hash_with_first_bit(false);
        let prefix = prefix_from_bits(&[true]);
        let left = hash(1);
        let right = hash(2);
        let root = hash_internal(&prefix, left, right);
        let proof = ParsedProof::parse_for_key(
            &short_payload(0, &prefix, left, right),
            root,
            NameHash::new(query),
        )
        .unwrap();

        assert_eq!(proof.kind, ProofKind::NonInclusion);
        assert!(UrkelProofVerifier.verify(&proof, root).unwrap());
    }

    #[test]
    fn verifies_inclusion_with_sibling_path() {
        let key = hash_with_first_bit(false);
        let sibling = hash(9);
        let value = b"value";
        let leaf = hash_value(key, value);
        let root = hash_internal(&BitPrefix::empty(), leaf, sibling);
        let payload =
            proof_with_nodes_payload(TYPE_EXISTS, 1, &[(BitPrefix::empty(), sibling)], |out| {
                write_u16_le(out, value.len() as u16);
                out.extend(value);
            });
        let proof = ParsedProof::parse_for_key(&payload, root, NameHash::new(key)).unwrap();

        assert!(UrkelProofVerifier.verify(&proof, root).unwrap());
    }

    #[test]
    fn rejects_malformed_or_trailing_proof() {
        assert_eq!(
            ParsedProof::parse(&[0u8]).unwrap_err(),
            ProofError::Malformed
        );

        let mut payload = exists_payload(b"dns");
        payload.push(0);
        assert_eq!(
            ParsedProof::parse(&payload).unwrap_err(),
            ProofError::Malformed
        );
    }

    #[test]
    fn fail_closed_verifier_still_fails_closed() {
        let proof = ParsedProof::parse(&exists_payload(b"dns")).unwrap();

        assert_eq!(
            FailClosedProofVerifier
                .verify(&proof, Hash::ZERO)
                .unwrap_err(),
            ProofError::UnsupportedVerifier,
        );
    }

    fn exists_payload(value: &[u8]) -> Vec<u8> {
        proof_with_nodes_payload(TYPE_EXISTS, 0, &[], |out| {
            write_u16_le(out, value.len() as u16);
            out.extend(value);
        })
    }

    fn deadend_payload(depth: u16) -> Vec<u8> {
        proof_with_nodes_payload(TYPE_DEADEND, depth, &[], |_| {})
    }

    fn collision_payload(depth: u16, key: Hash, value_hash: Hash) -> Vec<u8> {
        proof_with_nodes_payload(TYPE_COLLISION, depth, &[], |out| {
            out.extend(key.as_bytes());
            out.extend(value_hash.as_bytes());
        })
    }

    fn short_payload(depth: u16, prefix: &BitPrefix, left: Hash, right: Hash) -> Vec<u8> {
        proof_with_nodes_payload(TYPE_SHORT, depth, &[], |out| {
            write_prefix(out, prefix);
            out.extend(left.as_bytes());
            out.extend(right.as_bytes());
        })
    }

    fn proof_with_nodes_payload<F>(
        proof_type: u8,
        depth: u16,
        nodes: &[(BitPrefix, Hash)],
        write_body: F,
    ) -> Vec<u8>
    where
        F: FnOnce(&mut Vec<u8>),
    {
        let mut out = Vec::new();
        write_u16_le(&mut out, ((proof_type as u16) << 14) | depth);
        write_u16_le(&mut out, nodes.len() as u16);
        let bitmap_len = nodes.len().div_ceil(8);
        let bitmap_start = out.len();
        out.resize(out.len() + bitmap_len, 0);
        for (index, (prefix, hash)) in nodes.iter().enumerate() {
            if prefix.size != 0 {
                set_bit(&mut out[bitmap_start..bitmap_start + bitmap_len], index);
                write_prefix(&mut out, prefix);
            }
            out.extend(hash.as_bytes());
        }
        write_body(&mut out);
        out
    }

    fn write_prefix(out: &mut Vec<u8>, prefix: &BitPrefix) {
        if prefix.size >= 0x80 {
            out.push(0x80 | ((prefix.size >> 8) as u8));
        }
        out.push(prefix.size as u8);
        out.extend(&prefix.data);
    }

    fn write_u16_le(out: &mut Vec<u8>, value: u16) {
        out.extend(value.to_le_bytes());
    }

    fn prefix_from_bits(bits: &[bool]) -> BitPrefix {
        let mut data = vec![0u8; bits.len().div_ceil(8)];
        for (index, bit) in bits.iter().copied().enumerate() {
            if bit {
                set_bit(&mut data, index);
            }
        }
        BitPrefix {
            size: bits.len(),
            data,
        }
    }

    fn set_bit(bytes: &mut [u8], index: usize) {
        bytes[index / 8] |= 1 << (7 - (index & 7));
    }

    fn hash(value: u8) -> Hash {
        Hash::new([value; 32])
    }

    fn hash_with_first_bit(bit: bool) -> Hash {
        let mut bytes = [0u8; 32];
        if bit {
            bytes[0] = 0x80;
        }
        Hash::new(bytes)
    }
}
