//! Locally verified Handshake filtered-block evidence for embedded wallets.
//!
//! Peers provide bloom-filter matches, MerkleBlock payloads, and transactions.
//! This crate treats all of them as untrusted until the partial Merkle tree is
//! bound to a consensus-validated [`hns_light_chain::HeaderEntry`] and every
//! advertised transaction hash is exactly correlated. The wallet therefore
//! persists headers and its own coins, names, and boards rather than a pruned
//! global transaction or name index.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "HSD/BIP37 formulas intentionally convert bounded f64 sizes; HNS, BIP37, and P2P are protocol names"
)]

use std::collections::{BTreeMap, HashSet};

use blake2::Blake2b;
use blake2::digest::{Digest, consts::U32};
use hns_encoding::{DecodeError, Decoder, Encoder};
use hns_header_consensus::{HEADER_SIZE, Header, HeaderError};
use hns_light_chain::HeaderEntry;
use hns_p2p_wire::{Inventory, InventoryKind, MAX_INVENTORY_ITEMS, Packet};
use hns_primitives::{BlockHash, MerkleRoot, TransactionHash};
use hns_transaction::{Transaction, TransactionError};
use thiserror::Error;

/// HSD/Bitcoin policy maximum bloom-filter byte length.
pub const MAX_BLOOM_FILTER_BYTES: usize = 36_000;
/// HSD/Bitcoin policy maximum bloom-filter hash function count.
pub const MAX_BLOOM_HASH_FUNCTIONS: u32 = 50;
/// HSD maximum element length accepted by `filteradd`.
pub const MAX_FILTER_ADD_ELEMENT_BYTES: usize = 520;
/// HSD's maximum plausible transactions in a one-megabyte base block.
pub const MAX_FILTERED_BLOCK_TRANSACTIONS: usize = 1_000_000 / 60;
/// Maximum flags needed by a full partial tree with the transaction bound.
pub const MAX_PARTIAL_MERKLE_FLAG_BYTES: usize = (MAX_FILTERED_BLOCK_TRANSACTIONS * 2).div_ceil(8);
/// Strict upper bound for one canonical HSD MerkleBlock payload.
pub const MAX_MERKLE_BLOCK_PAYLOAD_BYTES: usize =
    HEADER_SIZE + 4 + 9 + MAX_FILTERED_BLOCK_TRANSACTIONS * 32 + 9 + MAX_PARTIAL_MERKLE_FLAG_BYTES;

const LN_2: f64 = std::f64::consts::LN_2;
const LN_2_SQUARED: f64 = LN_2 * LN_2;
const BLOOM_TWEAK_MULTIPLIER: u32 = 0xfba4_c795;

/// HSD bloom-filter automatic outpoint update mode.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BloomUpdate {
    /// Never add matching output outpoints automatically.
    None = 0,
    /// Add every matching output outpoint.
    All = 1,
    /// Add only matching pubkey-style output outpoints.
    PubkeyOnly = 2,
}

impl TryFrom<u8> for BloomUpdate {
    type Error = BloomError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::All),
            2 => Ok(Self::PubkeyOnly),
            _ => Err(BloomError::InvalidUpdate),
        }
    }
}

/// Exact HSD-compatible BIP37 bloom filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HsdBloomFilter {
    bytes: Vec<u8>,
    hash_functions: u32,
    tweak: u32,
    update: BloomUpdate,
}

impl HsdBloomFilter {
    /// Construct a policy-bounded filter from its exact bit and hash counts.
    pub fn new(
        size_bits: usize,
        hash_functions: u32,
        tweak: u32,
        update: BloomUpdate,
    ) -> Result<Self, BloomError> {
        let size_bits = size_bits.max(8);
        if size_bits > MAX_BLOOM_FILTER_BYTES * 8 {
            return Err(BloomError::FilterTooLarge);
        }
        let hash_functions = hash_functions.max(1);
        if hash_functions > MAX_BLOOM_HASH_FUNCTIONS {
            return Err(BloomError::TooManyHashFunctions);
        }
        let size_bytes = (size_bits - (size_bits & 7)) / 8;
        Ok(Self {
            bytes: vec![0; size_bytes],
            hash_functions,
            tweak,
            update,
        })
    }

    /// Construct the same rate-derived shape as HSD `BloomFilter.fromRate`.
    ///
    /// The caller supplies a fresh unpredictable tweak; this runtime-independent
    /// crate intentionally does not own an operating-system RNG.
    pub fn from_rate(
        expected_items: usize,
        false_positive_rate: f64,
        tweak: u32,
        update: BloomUpdate,
    ) -> Result<Self, BloomError> {
        if expected_items == 0 {
            return Err(BloomError::ZeroExpectedItems);
        }
        if !false_positive_rate.is_finite()
            || false_positive_rate <= 0.0
            || false_positive_rate >= 1.0
        {
            return Err(BloomError::InvalidFalsePositiveRate);
        }
        let expected_items_float = expected_items as f64;
        let calculated_bits =
            (-expected_items_float * false_positive_rate.ln() / LN_2_SQUARED).floor();
        if !calculated_bits.is_finite() || calculated_bits > (MAX_BLOOM_FILTER_BYTES * 8) as f64 {
            return Err(BloomError::FilterTooLarge);
        }
        let size_bits = (calculated_bits as usize).max(8);
        let hash_functions =
            ((size_bits as f64 / expected_items_float * LN_2).floor() as u32).max(1);
        Self::new(size_bits, hash_functions, tweak, update)
    }

    /// Number of bits in the filter.
    #[must_use]
    pub fn size_bits(&self) -> usize {
        self.bytes.len() * 8
    }

    /// Number of Murmur3 functions applied to each element.
    #[must_use]
    pub const fn hash_functions(&self) -> u32 {
        self.hash_functions
    }

    /// Connection-scoped Murmur3 tweak.
    #[must_use]
    pub const fn tweak(&self) -> u32 {
        self.tweak
    }

    /// Automatic outpoint update mode.
    #[must_use]
    pub const fn update(&self) -> BloomUpdate {
        self.update
    }

    /// Insert one script, address hash, name hash, transaction hash, or outpoint.
    pub fn insert(&mut self, value: &[u8]) -> Result<(), BloomError> {
        let size = self.size_bits();
        for function in 0..self.hash_functions {
            let index = bloom_hash(value, function, self.tweak) as usize % size;
            let byte = self
                .bytes
                .get_mut(index >> 3)
                .ok_or(BloomError::InternalInvariant)?;
            *byte |= 1_u8 << (index & 7);
        }
        Ok(())
    }

    /// Return false only when the element is definitely absent.
    #[must_use]
    pub fn contains(&self, value: &[u8]) -> bool {
        let size = self.size_bits();
        (0..self.hash_functions).all(|function| {
            let index = bloom_hash(value, function, self.tweak) as usize % size;
            self.bytes
                .get(index >> 3)
                .is_some_and(|byte| byte & (1_u8 << (index & 7)) != 0)
        })
    }

    /// Canonical HSD `filterload` payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::with_capacity(self.bytes.len() + 12);
        encoder.put_varbytes(&self.bytes);
        encoder.put_u32_le(self.hash_functions);
        encoder.put_u32_le(self.tweak);
        encoder.put_u8(self.update as u8);
        encoder.into_bytes()
    }

    /// Decode one complete, canonical, policy-bounded HSD filter payload.
    pub fn decode_strict(input: &[u8]) -> Result<Self, BloomError> {
        let mut decoder = Decoder::new(input);
        let bytes = decoder.read_varbytes(MAX_BLOOM_FILTER_BYTES, "bloom filter")?;
        let hash_functions = decoder.read_u32_le()?;
        let tweak = decoder.read_u32_le()?;
        let update = BloomUpdate::try_from(decoder.read_u8()?)?;
        decoder.finish()?;
        if bytes.is_empty() {
            return Err(BloomError::EmptyFilter);
        }
        if hash_functions == 0 {
            return Err(BloomError::ZeroHashFunctions);
        }
        if hash_functions > MAX_BLOOM_HASH_FUNCTIONS {
            return Err(BloomError::TooManyHashFunctions);
        }
        Ok(Self {
            bytes,
            hash_functions,
            tweak,
            update,
        })
    }

    /// Standard P2P packet that installs this complete filter on a peer.
    #[must_use]
    pub fn load_packet(&self) -> Packet {
        Packet::FilterLoad(self.encode())
    }

    /// Add an element locally and return the matching HSD `filteradd` packet.
    pub fn add_packet(&mut self, value: &[u8]) -> Result<Packet, BloomError> {
        if value.len() > MAX_FILTER_ADD_ELEMENT_BYTES {
            return Err(BloomError::ElementTooLarge);
        }
        self.insert(value)?;
        let mut encoder = Encoder::with_capacity(value.len() + 9);
        encoder.put_varbytes(value);
        Ok(Packet::FilterAdd(encoder.into_bytes()))
    }
}

/// Request locally known headers as HSD filtered blocks.
pub fn request_filtered_blocks(headers: &[HeaderEntry]) -> Result<Packet, WalletEvidenceError> {
    if headers.is_empty() {
        return Err(WalletEvidenceError::EmptyBlockRequest);
    }
    if headers.len() > MAX_INVENTORY_ITEMS {
        return Err(WalletEvidenceError::TooManyBlockRequests);
    }
    Ok(Packet::GetData(
        headers
            .iter()
            .map(|entry| Inventory {
                kind: InventoryKind::FilteredBlock,
                hash: entry.hash().into_bytes(),
            })
            .collect(),
    ))
}

/// One transaction hash proven into the expected header's Merkle root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchedTransaction {
    hash: TransactionHash,
    index: u32,
}

impl MatchedTransaction {
    /// Canonical non-witness transaction hash.
    #[must_use]
    pub const fn hash(self) -> TransactionHash {
        self.hash
    }

    /// Zero-based transaction index in the block.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }
}

/// Partial-Merkle evidence bound to one locally consensus-validated header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletBlockEvidence {
    header: HeaderEntry,
    total_transactions: u32,
    matches: Vec<MatchedTransaction>,
}

impl WalletBlockEvidence {
    /// Decode and verify one complete HSD MerkleBlock payload for `header`.
    pub fn decode_for_header(
        input: &[u8],
        header: HeaderEntry,
    ) -> Result<Self, WalletEvidenceError> {
        let decoded = decode_partial_merkle(input, header.hash(), header.merkle_root())?;
        Ok(Self {
            header,
            total_transactions: decoded.total_transactions,
            matches: decoded.matches,
        })
    }

    /// Validated local header entry that anchors this evidence.
    #[must_use]
    pub const fn header(&self) -> HeaderEntry {
        self.header
    }

    /// Total transactions committed by the block.
    #[must_use]
    pub const fn total_transactions(&self) -> u32 {
        self.total_transactions
    }

    /// Bloom-matched transactions proven into the block.
    #[must_use]
    pub fn matches(&self) -> &[MatchedTransaction] {
        &self.matches
    }

    /// Start exact correlation of the transaction packets following MerkleBlock.
    pub fn collect(self) -> Result<FilteredBlockCollector, WalletEvidenceError> {
        FilteredBlockCollector::new(self)
    }
}

/// Correlates transaction packets following one verified HSD MerkleBlock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilteredBlockCollector {
    evidence: WalletBlockEvidence,
    pending: BTreeMap<TransactionHash, u32>,
    transactions: BTreeMap<u32, Transaction>,
}

impl FilteredBlockCollector {
    fn new(evidence: WalletBlockEvidence) -> Result<Self, WalletEvidenceError> {
        let mut pending = BTreeMap::new();
        for matched in &evidence.matches {
            if pending.insert(matched.hash, matched.index).is_some() {
                return Err(WalletEvidenceError::DuplicateMatchedTransaction);
            }
        }
        Ok(Self {
            evidence,
            pending,
            transactions: BTreeMap::new(),
        })
    }

    /// Number of exact transaction packets still required.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.pending.len()
    }

    /// Admit one transaction only when its canonical hash was proven by the tree.
    pub fn admit(&mut self, transaction: Transaction) -> Result<usize, WalletEvidenceError> {
        let hash = transaction.transaction_hash()?;
        let index = self
            .pending
            .remove(&hash)
            .ok_or(WalletEvidenceError::UnexpectedTransaction)?;
        if self.transactions.insert(index, transaction).is_some() {
            return Err(WalletEvidenceError::DuplicateTransactionIndex);
        }
        Ok(self.pending.len())
    }

    /// Finish only after every proven match has arrived exactly once.
    pub fn finish(self) -> Result<VerifiedWalletBlock, WalletEvidenceError> {
        if !self.pending.is_empty() {
            return Err(WalletEvidenceError::MissingTransactions);
        }
        Ok(VerifiedWalletBlock {
            evidence: self.evidence,
            transactions: self.transactions.into_values().collect(),
        })
    }
}

/// Complete matched transaction set for one locally validated block header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWalletBlock {
    evidence: WalletBlockEvidence,
    transactions: Vec<Transaction>,
}

impl VerifiedWalletBlock {
    /// Verified partial-tree evidence.
    #[must_use]
    pub const fn evidence(&self) -> &WalletBlockEvidence {
        &self.evidence
    }

    /// Matched transactions ordered by their position in the block.
    #[must_use]
    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }
}

#[derive(Debug)]
struct DecodedPartialMerkle {
    total_transactions: u32,
    matches: Vec<MatchedTransaction>,
}

fn decode_partial_merkle(
    input: &[u8],
    expected_hash: BlockHash,
    expected_merkle_root: MerkleRoot,
) -> Result<DecodedPartialMerkle, WalletEvidenceError> {
    if input.len() > MAX_MERKLE_BLOCK_PAYLOAD_BYTES {
        return Err(WalletEvidenceError::MerkleBlockTooLarge);
    }
    let mut decoder = Decoder::new(input);
    let header = Header::decode(decoder.read_slice(HEADER_SIZE)?)?;
    if header.block_hash() != expected_hash || header.merkle_root != expected_merkle_root {
        return Err(WalletEvidenceError::WrongHeader);
    }
    let total_transactions = decoder.read_u32_le()?;
    let total = total_transactions as usize;
    if total == 0 {
        return Err(WalletEvidenceError::ZeroTransactions);
    }
    if total > MAX_FILTERED_BLOCK_TRANSACTIONS {
        return Err(WalletEvidenceError::TooManyTransactions);
    }
    let hash_count = decoder.read_compact_usize(total, "partial Merkle hashes")?;
    let mut hashes = Vec::with_capacity(hash_count);
    for _ in 0..hash_count {
        hashes.push(decoder.read_array()?);
    }
    let flags = decoder.read_varbytes(MAX_PARTIAL_MERKLE_FLAG_BYTES, "partial Merkle flags")?;
    decoder.finish()?;
    if hashes.len() > total {
        return Err(WalletEvidenceError::TooManyHashes);
    }
    if flags.len().saturating_mul(8) < hashes.len() {
        return Err(WalletEvidenceError::FlagsTooSmall);
    }

    let mut height = 0_usize;
    while tree_width(total, height) > 1 {
        height = height
            .checked_add(1)
            .ok_or(WalletEvidenceError::ArithmeticOverflow)?;
    }
    let mut reader = PartialTreeReader {
        total,
        flags: &flags,
        hashes: &hashes,
        bits_used: 0,
        hashes_used: 0,
        matches: Vec::new(),
        matched_hashes: HashSet::new(),
    };
    let root = reader.traverse(height, 0)?;
    if reader.bits_used.div_ceil(8) != flags.len() {
        return Err(WalletEvidenceError::UnusedFlagBits);
    }
    if reader.hashes_used != hashes.len() {
        return Err(WalletEvidenceError::UnusedHashes);
    }
    if root != header.merkle_root.into_bytes() {
        return Err(WalletEvidenceError::MerkleRootMismatch);
    }
    Ok(DecodedPartialMerkle {
        total_transactions,
        matches: reader.matches,
    })
}

struct PartialTreeReader<'a> {
    total: usize,
    flags: &'a [u8],
    hashes: &'a [[u8; 32]],
    bits_used: usize,
    hashes_used: usize,
    matches: Vec<MatchedTransaction>,
    matched_hashes: HashSet<TransactionHash>,
}

impl PartialTreeReader<'_> {
    fn traverse(
        &mut self,
        height: usize,
        position: usize,
    ) -> Result<[u8; 32], WalletEvidenceError> {
        let parent = self.read_bit()?;
        if height == 0 || !parent {
            let hash = self.read_hash()?;
            if height == 0 && parent {
                let transaction_hash = TransactionHash::new(hash);
                if !self.matched_hashes.insert(transaction_hash) {
                    return Err(WalletEvidenceError::DuplicateMatchedTransaction);
                }
                let index =
                    u32::try_from(position).map_err(|_| WalletEvidenceError::ArithmeticOverflow)?;
                self.matches.push(MatchedTransaction {
                    hash: transaction_hash,
                    index,
                });
                return Ok(hash_leaf(hash));
            }
            return Ok(hash);
        }

        let child_height = height
            .checked_sub(1)
            .ok_or(WalletEvidenceError::ArithmeticOverflow)?;
        let left_position = position
            .checked_mul(2)
            .ok_or(WalletEvidenceError::ArithmeticOverflow)?;
        let left = self.traverse(child_height, left_position)?;
        let right = if left_position
            .checked_add(1)
            .ok_or(WalletEvidenceError::ArithmeticOverflow)?
            < tree_width(self.total, child_height)
        {
            self.traverse(child_height, left_position + 1)?
        } else {
            hash_empty()
        };
        Ok(hash_internal(left, right))
    }

    fn read_bit(&mut self) -> Result<bool, WalletEvidenceError> {
        let byte = self
            .flags
            .get(self.bits_used / 8)
            .ok_or(WalletEvidenceError::ExhaustedFlags)?;
        let bit = byte & (1_u8 << (self.bits_used % 8)) != 0;
        self.bits_used = self
            .bits_used
            .checked_add(1)
            .ok_or(WalletEvidenceError::ArithmeticOverflow)?;
        Ok(bit)
    }

    fn read_hash(&mut self) -> Result<[u8; 32], WalletEvidenceError> {
        let hash = self
            .hashes
            .get(self.hashes_used)
            .copied()
            .ok_or(WalletEvidenceError::ExhaustedHashes)?;
        self.hashes_used = self
            .hashes_used
            .checked_add(1)
            .ok_or(WalletEvidenceError::ArithmeticOverflow)?;
        Ok(hash)
    }
}

fn tree_width(total: usize, height: usize) -> usize {
    let step = 1_usize << height;
    total.div_ceil(step)
}

fn hash_empty() -> [u8; 32] {
    blake2b_256(&[&[]])
}

fn hash_leaf(hash: [u8; 32]) -> [u8; 32] {
    blake2b_256(&[&[0], &hash])
}

fn hash_internal(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    blake2b_256(&[&[1], &left, &right])
}

fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn bloom_hash(value: &[u8], function: u32, tweak: u32) -> u32 {
    let seed = function
        .wrapping_mul(BLOOM_TWEAK_MULTIPLIER)
        .wrapping_add(tweak);
    murmur3(value, seed)
}

fn murmur3(value: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;

    let mut hash = seed;
    let mut chunks = value.chunks_exact(4);
    for chunk in &mut chunks {
        let [first, second, third, fourth] = chunk else {
            continue;
        };
        let mut word = u32::from_le_bytes([*first, *second, *third, *fourth]);
        word = word.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        hash ^= word;
        hash = hash
            .rotate_left(13)
            .wrapping_mul(5)
            .wrapping_add(0xe654_6b64);
    }

    let remainder = chunks.remainder();
    let mut tail = 0_u32;
    if let Some(byte) = remainder.get(2) {
        tail ^= u32::from(*byte) << 16;
    }
    if let Some(byte) = remainder.get(1) {
        tail ^= u32::from(*byte) << 8;
    }
    if let Some(byte) = remainder.first() {
        tail ^= u32::from(*byte);
        tail = tail.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        hash ^= tail;
    }

    hash ^= value.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85eb_ca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2_ae35);
    hash ^ (hash >> 16)
}

/// BIP37 filter construction or encoding failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum BloomError {
    /// Expected item count must be nonzero.
    #[error("expected bloom-filter item count is zero")]
    ZeroExpectedItems,
    /// False-positive rate must be finite and strictly between zero and one.
    #[error("invalid bloom-filter false-positive rate")]
    InvalidFalsePositiveRate,
    /// Filter exceeds HSD's 36,000-byte peer policy.
    #[error("bloom filter exceeds HSD policy size")]
    FilterTooLarge,
    /// Filter exceeds HSD's 50-function peer policy.
    #[error("bloom filter exceeds HSD hash-function policy")]
    TooManyHashFunctions,
    /// A wire filter may not have zero hash functions.
    #[error("bloom filter has zero hash functions")]
    ZeroHashFunctions,
    /// A wire filter may not be empty.
    #[error("bloom filter is empty")]
    EmptyFilter,
    /// Update byte is outside HSD's defined range.
    #[error("invalid bloom-filter update mode")]
    InvalidUpdate,
    /// `filteradd` elements are limited to HSD's script-push bound.
    #[error("filteradd element exceeds HSD policy size")]
    ElementTooLarge,
    /// Canonical little-endian wire decoding failed.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// An impossible locally constructed index was out of range.
    #[error("bloom-filter internal invariant failed")]
    InternalInvariant,
}

/// Filtered-block proof or exact transaction-correlation failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WalletEvidenceError {
    /// At least one validated header is required per request.
    #[error("filtered-block request is empty")]
    EmptyBlockRequest,
    /// One packet cannot exceed the shared standard inventory bound.
    #[error("filtered-block request exceeds the standard inventory bound")]
    TooManyBlockRequests,
    /// MerkleBlock exceeds the strict maximum canonical payload.
    #[error("MerkleBlock payload exceeds the local allocation bound")]
    MerkleBlockTooLarge,
    /// Canonical little-endian wire decoding failed.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// Embedded canonical Handshake header was malformed.
    #[error(transparent)]
    Header(#[from] HeaderError),
    /// Embedded header was not the locally validated requested block.
    #[error("MerkleBlock header does not match the requested validated header")]
    WrongHeader,
    /// A block cannot commit zero transactions.
    #[error("MerkleBlock declares zero transactions")]
    ZeroTransactions,
    /// Transaction total exceeds HSD's block-size-derived bound.
    #[error("MerkleBlock declares too many transactions")]
    TooManyTransactions,
    /// Partial tree supplied more hashes than transactions.
    #[error("MerkleBlock contains too many hashes")]
    TooManyHashes,
    /// Flag bitfield cannot describe all supplied hashes.
    #[error("MerkleBlock flag bitfield is too small")]
    FlagsTooSmall,
    /// Traversal exhausted the exact flag bitfield.
    #[error("MerkleBlock traversal exhausted flag bits")]
    ExhaustedFlags,
    /// Traversal exhausted the exact hash vector.
    #[error("MerkleBlock traversal exhausted hashes")]
    ExhaustedHashes,
    /// Canonical traversal did not consume the complete flag byte vector.
    #[error("MerkleBlock contains unused flag bytes")]
    UnusedFlagBits,
    /// Canonical traversal did not consume the complete hash vector.
    #[error("MerkleBlock contains unused hashes")]
    UnusedHashes,
    /// Reconstructed root differs from the committed header root.
    #[error("MerkleBlock root does not match the validated header")]
    MerkleRootMismatch,
    /// Matched transaction hash appeared more than once.
    #[error("MerkleBlock repeats a matched transaction hash")]
    DuplicateMatchedTransaction,
    /// Peer sent a transaction not proven by this MerkleBlock.
    #[error("transaction was not matched by the current MerkleBlock")]
    UnexpectedTransaction,
    /// Two correlated transactions claimed the same block index.
    #[error("duplicate matched transaction index")]
    DuplicateTransactionIndex,
    /// Not every matched transaction packet arrived.
    #[error("matched transaction packets are incomplete")]
    MissingTransactions,
    /// Transaction hashing/encoding failed.
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    /// Bounded index arithmetic overflowed.
    #[error("filtered-block arithmetic overflow")]
    ArithmeticOverflow,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid deterministic fixtures"
)]
mod tests {
    use hns_header_consensus::Network;
    use hns_primitives::BlockTime;

    use super::*;

    #[test]
    fn murmur3_and_hsd_filter_encoding_match_reference_vectors() {
        assert_eq!(murmur3(b"hello", 0), 0x248b_fa47);

        let mut filter = HsdBloomFilter::new(24, 5, 0, BloomUpdate::All).unwrap();
        filter
            .insert(&hex::decode("99108ad8ed9bb6274d3980bab5a85c048f0950c8").unwrap())
            .unwrap();
        filter
            .insert(&hex::decode("b5a2c786d9ef4658287ced5914b37a1b4aa32eee").unwrap())
            .unwrap();
        filter
            .insert(&hex::decode("b9300670b4c5366e95b2699e8b18bc75e5f729c5").unwrap())
            .unwrap();
        assert_eq!(hex::encode(filter.encode()), "03614e9b050000000000000001");
        assert_eq!(
            HsdBloomFilter::decode_strict(&filter.encode()).unwrap(),
            filter
        );

        let shape = HsdBloomFilter::from_rate(20_000, 0.001, 7, BloomUpdate::All).unwrap();
        assert_eq!(shape.size_bits(), 287_544);
        assert_eq!(shape.hash_functions(), 9);
    }

    #[test]
    fn filter_packets_are_standard_and_policy_bounded() {
        let mut filter = HsdBloomFilter::new(64, 3, 9, BloomUpdate::All).unwrap();
        assert!(matches!(filter.load_packet(), Packet::FilterLoad(_)));
        let add = filter.add_packet(&[4; 32]).unwrap();
        assert_eq!(add, Packet::FilterAdd([vec![32], vec![4; 32]].concat()));
        assert!(filter.contains(&[4; 32]));
        assert!(matches!(
            filter.add_packet(&vec![0; MAX_FILTER_ADD_ELEMENT_BYTES + 1]),
            Err(BloomError::ElementTooLarge)
        ));
    }

    #[test]
    fn verifies_genesis_zero_match_tree_against_validated_header() {
        let now = BlockTime::new(1_700_000_000);
        let chain = hns_light_chain::LightChain::from_genesis(
            Network::Regtest,
            now,
            hns_light_chain::ChainLimits::default(),
        )
        .unwrap();
        let entry = chain.tip();
        let header = Network::Regtest.parameters().genesis_header();
        let mut encoder = Encoder::new();
        encoder.put_bytes(&header.encode());
        encoder.put_u32_le(1);
        encoder.put_compact_size(1);
        encoder.put_bytes(header.merkle_root.as_bytes());
        encoder.put_varbytes(&[0]);

        let evidence =
            WalletBlockEvidence::decode_for_header(&encoder.into_bytes(), entry).unwrap();
        assert_eq!(evidence.header(), entry);
        assert_eq!(evidence.total_transactions(), 1);
        assert!(evidence.matches().is_empty());
        assert!(evidence.collect().unwrap().finish().is_ok());
    }

    #[test]
    fn matched_tree_and_collector_require_exact_transaction_hash() {
        let transaction = Transaction {
            version: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
        };
        let transaction_hash = transaction.transaction_hash().unwrap();
        let header = Header {
            merkle_root: hash_leaf(transaction_hash.into_bytes()).into(),
            ..Header::default()
        };
        let expected_hash = header.block_hash();
        let mut encoder = Encoder::new();
        encoder.put_bytes(&header.encode());
        encoder.put_u32_le(1);
        encoder.put_compact_size(1);
        encoder.put_bytes(transaction_hash.as_bytes());
        encoder.put_varbytes(&[1]);
        let decoded =
            decode_partial_merkle(&encoder.into_bytes(), expected_hash, header.merkle_root)
                .unwrap();
        assert_eq!(decoded.matches.len(), 1);

        let chain = hns_light_chain::LightChain::from_genesis(
            Network::Regtest,
            BlockTime::new(1_700_000_000),
            hns_light_chain::ChainLimits::default(),
        )
        .unwrap();
        let evidence = WalletBlockEvidence {
            header: chain.tip(),
            total_transactions: 1,
            matches: decoded.matches,
        };
        let mut collector = evidence.collect().unwrap();
        assert_eq!(collector.admit(transaction.clone()).unwrap(), 0);
        assert!(matches!(
            collector.admit(transaction),
            Err(WalletEvidenceError::UnexpectedTransaction)
        ));
        let complete = collector.finish().unwrap();
        assert_eq!(complete.transactions().len(), 1);
    }

    #[test]
    fn rejects_wrong_header_root_and_noncanonical_tree_consumption() {
        let header = Header {
            merkle_root: hash_leaf([3; 32]).into(),
            ..Header::default()
        };
        let expected_hash = header.block_hash();
        let mut encoder = Encoder::new();
        encoder.put_bytes(&header.encode());
        encoder.put_u32_le(1);
        encoder.put_compact_size(1);
        encoder.put_bytes(&[4; 32]);
        encoder.put_varbytes(&[1]);
        assert!(matches!(
            decode_partial_merkle(&encoder.into_bytes(), expected_hash, header.merkle_root),
            Err(WalletEvidenceError::MerkleRootMismatch)
        ));

        let mut encoder = Encoder::new();
        encoder.put_bytes(&header.encode());
        encoder.put_u32_le(1);
        encoder.put_compact_size(1);
        encoder.put_bytes(&[3; 32]);
        encoder.put_varbytes(&[0, 0]);
        assert!(matches!(
            decode_partial_merkle(&encoder.into_bytes(), expected_hash, header.merkle_root),
            Err(WalletEvidenceError::UnusedFlagBits)
        ));
    }
}
