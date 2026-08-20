//! Locally validated Handshake header chains and name-tree resources.
//!
//! This crate starts at the selected network genesis, validates every
//! contiguous header with the shared `hns-rs` consensus implementation, and
//! retains exactly the history required by Handshake's median-time and
//! difficulty rules. A current-chain attestation can then verify one strict
//! HSD Urkel inclusion proof and decode the committed `NameState` and resource.
//! The resulting [`VerifiedHnsResource`] has private fields so downstream
//! DNSSEC code cannot manufacture a Handshake trust anchor.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "Handshake, DNSSEC, Urkel, and HSD are protocol names"
)]

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};

use blake2::Blake2b;
use blake2::digest::{Digest, consts::U32};
use hns_covenants::{MAX_RESOURCE_SIZE, Resource as CovenantResource, hash_name, validate_name};
use hns_encoding::{DecodeError, Decoder, Encoder};
use hns_header_consensus::{
    DifficultyPoint, Header, HeaderError, HeaderValidationContext, Network, expected_next_bits,
    validate_header,
};
use hns_primitives::{
    BlockHash, BlockTime, Chainwork, CompactTarget, Height, MerkleRoot, NameHash, TreeRoot,
};
use hns_urkel_proof::{HsdUrkelProof, UrkelError};
use thiserror::Error;

/// Handshake median-time-past window.
pub const MEDIAN_TIME_SPAN: usize = 11;
/// Headers needed for both three-block suitable points around a 144-block window.
pub const REQUIRED_DIFFICULTY_HISTORY: usize = 147;
/// Default maximum headers accepted in one transactional batch.
pub const DEFAULT_MAX_HEADERS_PER_BATCH: usize = 4_096;
/// Hard upper bound for a configured atomic header batch.
pub const MAX_HEADERS_PER_BATCH_LIMIT: usize = 4_096;
/// Maximum exponential locator entries for a 32-bit height plus genesis.
pub const MAX_LOCATOR_HASHES: usize = 43;
/// Maximum encoded authenticated light-chain checkpoint.
pub const MAX_LIGHT_CHAIN_SNAPSHOT_BYTES: usize = 64 * 1024;
const LIGHT_CHAIN_SNAPSHOT_MAGIC: &[u8] = b"HNS-LIGHT-CHAIN-SNAPSHOT\0";
const LIGHT_CHAIN_SNAPSHOT_SCHEMA: u16 = 1;
const LIGHT_CHAIN_SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"HNS-LIGHT-CHAIN-SNAPSHOT-V1\0";
/// HSD currently assigns resource record tags zero through six.
const MAX_KNOWN_RESOURCE_KIND: u8 = 6;
/// Bits assigned in HSD's serialized `NameState` field.
const NAME_STATE_KNOWN_FIELD_BITS: u16 = 0x03ff;
/// Maximum expanded labels in an HNS resource name.
const MAX_RESOURCE_NAME_LABELS: usize = 127;
/// Maximum compression pointers followed in one HNS resource name.
const MAX_RESOURCE_NAME_JUMPS: usize = 16;

/// One fully validated header summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderEntry {
    height: Height,
    hash: BlockHash,
    previous_block: BlockHash,
    tree_root: TreeRoot,
    merkle_root: MerkleRoot,
    time: BlockTime,
    bits: hns_primitives::CompactTarget,
    chainwork: Chainwork,
}

impl HeaderEntry {
    /// Header height.
    #[must_use]
    pub const fn height(self) -> Height {
        self.height
    }

    /// Consensus block hash.
    #[must_use]
    pub const fn hash(self) -> BlockHash {
        self.hash
    }

    /// Previous block hash committed by the validated header.
    #[must_use]
    pub const fn previous_block(self) -> BlockHash {
        self.previous_block
    }

    /// Committed Urkel root.
    #[must_use]
    pub const fn tree_root(self) -> TreeRoot {
        self.tree_root
    }

    /// Transaction Merkle root committed by the validated header.
    #[must_use]
    pub const fn merkle_root(self) -> MerkleRoot {
        self.merkle_root
    }

    /// Header timestamp.
    #[must_use]
    pub const fn time(self) -> BlockTime {
        self.time
    }

    /// Compact proof-of-work target.
    #[must_use]
    pub const fn bits(self) -> hns_primitives::CompactTarget {
        self.bits
    }

    /// Cumulative chainwork through this header.
    #[must_use]
    pub const fn chainwork(self) -> Chainwork {
        self.chainwork
    }

    const fn difficulty_point(self) -> DifficultyPoint {
        DifficultyPoint {
            height: self.height,
            time: self.time,
            bits: self.bits,
            chainwork: self.chainwork,
        }
    }
}

/// Bounds for header admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainLimits {
    /// Maximum headers accepted atomically by [`LightChain::append_batch`].
    pub max_headers_per_batch: usize,
}

impl Default for ChainLimits {
    fn default() -> Self {
        Self {
            max_headers_per_batch: DEFAULT_MAX_HEADERS_PER_BATCH,
        }
    }
}

impl ChainLimits {
    fn validate(self) -> Result<Self, LightChainError> {
        if self.max_headers_per_batch == 0
            || self.max_headers_per_batch > MAX_HEADERS_PER_BATCH_LIMIT
        {
            return Err(LightChainError::InvalidLimit);
        }
        Ok(self)
    }
}

/// Caller-held rollback floor for an authenticated checkpoint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChainSnapshotFloor {
    /// Lowest acceptable validated height.
    pub minimum_height: Height,
    /// Lowest acceptable cumulative proof of work.
    pub minimum_chainwork: Chainwork,
}

/// Currency requirements applied before a name proof becomes authoritative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrencyPolicy {
    /// Explicit local wall-clock time.
    pub now: BlockTime,
    /// Maximum permitted age of the validated tip.
    pub maximum_tip_age_seconds: u64,
    /// Minimum acceptable validated height.
    pub minimum_height: Height,
    /// Minimum acceptable cumulative work.
    pub minimum_chainwork: Chainwork,
}

/// A linear, consensus-validated Handshake header chain.
///
/// The implementation intentionally admits only a contiguous extension of its
/// current tip. Fork download, best-chain selection, and persisted checkpoint
/// recovery belong in `hns-light-sync`; this type is the consensus gate that
/// such a synchronizer must use.
#[derive(Clone, Debug)]
pub struct LightChain {
    network: Network,
    limits: ChainLimits,
    history: VecDeque<HeaderEntry>,
    tip: HeaderEntry,
}

impl LightChain {
    /// Open the selected network at its canonical genesis header.
    pub fn from_genesis(
        network: Network,
        now: BlockTime,
        limits: ChainLimits,
    ) -> Result<Self, LightChainError> {
        let limits = limits.validate()?;
        let parameters = network.parameters();
        let header = parameters.genesis_header();
        let proof = validate_header(
            parameters,
            &header,
            HeaderValidationContext {
                height: Height::new(0),
                previous_block: BlockHash::default(),
                median_time: BlockTime::new(0),
                now,
                expected_bits: parameters.pow.bits,
            },
        )?;
        let mut history = VecDeque::with_capacity(REQUIRED_DIFFICULTY_HISTORY);
        let tip = entry_from_header(Height::new(0), &header, proof);
        history.push_back(tip);
        Ok(Self {
            network,
            limits,
            history,
            tip,
        })
    }

    /// Selected Handshake network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Current validated tip.
    #[must_use]
    pub const fn tip(&self) -> HeaderEntry {
        self.tip
    }

    /// Encode the exact consensus lookback window for an authenticated store.
    ///
    /// The checksum detects accidental corruption; it does not authenticate or
    /// rollback-protect the bytes. Callers must persist the blob in their
    /// wallet-owned authenticated store and retain a monotonic floor.
    pub fn encode_authenticated_snapshot(&self) -> Result<Vec<u8>, LightChainError> {
        let mut encoder = Encoder::with_capacity(MAX_LIGHT_CHAIN_SNAPSHOT_BYTES);
        encoder.put_bytes(LIGHT_CHAIN_SNAPSHOT_MAGIC);
        encoder.put_u16_le(LIGHT_CHAIN_SNAPSHOT_SCHEMA);
        encoder.put_u8(self.network.id());
        encoder.put_u32_le(
            u32::try_from(self.limits.max_headers_per_batch)
                .map_err(|_| LightChainError::InvalidSnapshot)?,
        );
        encoder.put_u16_le(
            u16::try_from(self.history.len()).map_err(|_| LightChainError::InvalidSnapshot)?,
        );
        for entry in &self.history {
            encode_header_entry(&mut encoder, *entry);
        }
        let mut snapshot_bytes = encoder.into_bytes();
        let checksum = snapshot_checksum(&snapshot_bytes);
        snapshot_bytes.extend_from_slice(&checksum);
        if snapshot_bytes.len() > MAX_LIGHT_CHAIN_SNAPSHOT_BYTES {
            return Err(LightChainError::SnapshotTooLarge);
        }
        Ok(snapshot_bytes)
    }

    /// Restore a structurally exact checkpoint from an authenticated store.
    ///
    /// `expected_network` prevents cross-network reuse and `floor` prevents an
    /// older otherwise authentic checkpoint from replacing caller-held state.
    pub fn decode_authenticated_snapshot(
        input: &[u8],
        expected_network: Network,
        floor: ChainSnapshotFloor,
    ) -> Result<Self, LightChainError> {
        if input.len() > MAX_LIGHT_CHAIN_SNAPSHOT_BYTES {
            return Err(LightChainError::SnapshotTooLarge);
        }
        let payload_length = input
            .len()
            .checked_sub(32)
            .ok_or(LightChainError::InvalidSnapshot)?;
        let (payload, encoded_checksum) = input.split_at(payload_length);
        if encoded_checksum != snapshot_checksum(payload) {
            return Err(LightChainError::SnapshotChecksumMismatch);
        }
        let mut decoder = Decoder::new(payload);
        if decoder.read_slice(LIGHT_CHAIN_SNAPSHOT_MAGIC.len())? != LIGHT_CHAIN_SNAPSHOT_MAGIC
            || decoder.read_u16_le()? != LIGHT_CHAIN_SNAPSHOT_SCHEMA
        {
            return Err(LightChainError::UnsupportedSnapshot);
        }
        let network = decode_network(decoder.read_u8()?)?;
        if network != expected_network {
            return Err(LightChainError::SnapshotNetworkMismatch);
        }
        let limits = ChainLimits {
            max_headers_per_batch: usize::try_from(decoder.read_u32_le()?)
                .map_err(|_| LightChainError::InvalidSnapshot)?,
        }
        .validate()?;
        let count = usize::from(decoder.read_u16_le()?);
        if count == 0 || count > REQUIRED_DIFFICULTY_HISTORY {
            return Err(LightChainError::InvalidSnapshot);
        }
        let mut history = VecDeque::with_capacity(count);
        for _ in 0..count {
            history.push_back(decode_header_entry(&mut decoder)?);
        }
        decoder.finish()?;
        validate_snapshot_history(expected_network, limits, &history, floor)?;
        let tip = history
            .back()
            .copied()
            .ok_or(LightChainError::InvalidSnapshot)?;
        Ok(Self {
            network,
            limits,
            history,
            tip,
        })
    }

    /// Build a standard recent-first exponential block locator ending at genesis.
    #[must_use]
    pub fn locator(&self) -> Vec<BlockHash> {
        let mut locator = Vec::with_capacity(MAX_LOCATOR_HASHES);
        let mut height = self.tip.height.get();
        let mut step = 1_u32;
        loop {
            let entry = self.entry_at(height).ok();
            let Some(entry) = entry else {
                break;
            };
            locator.push(entry.hash);
            if height == 0 {
                break;
            }
            if locator.len() >= 10 {
                step = step.saturating_mul(2);
            }
            height = height.saturating_sub(step);
        }
        let genesis = self.network.parameters().genesis_hash;
        if locator.last().copied() != Some(genesis) {
            locator.push(genesis);
        }
        locator
    }

    /// Append one header after all consensus checks.
    pub fn append(
        &mut self,
        header: &Header,
        now: BlockTime,
    ) -> Result<HeaderEntry, LightChainError> {
        let tip = self.tip();
        let next_height = tip
            .height
            .get()
            .checked_add(1)
            .map(Height::new)
            .ok_or(LightChainError::HeightOverflow)?;
        let parameters = self.network.parameters();
        let (first_suitable, last_suitable) =
            if tip.height.get() >= parameters.pow.target_window.saturating_add(2) {
                let ancestor_height = tip
                    .height
                    .get()
                    .checked_sub(parameters.pow.target_window)
                    .ok_or(LightChainError::MissingDifficultyHistory)?;
                (
                    Some(self.suitable_entry(ancestor_height)?.difficulty_point()),
                    Some(self.suitable_entry(tip.height.get())?.difficulty_point()),
                )
            } else {
                (None, None)
            };
        let expected_bits = expected_next_bits(
            parameters.pow,
            header.time,
            tip.difficulty_point(),
            first_suitable,
            last_suitable,
        )?;
        let proof = validate_header(
            parameters,
            header,
            HeaderValidationContext {
                height: next_height,
                previous_block: tip.hash,
                median_time: self.median_time_past(),
                now,
                expected_bits,
            },
        )?;
        let chainwork = tip.chainwork.checked_add(proof)?;
        let entry = entry_from_header(next_height, header, chainwork);
        self.history.push_back(entry);
        while self.history.len() > REQUIRED_DIFFICULTY_HISTORY {
            self.history.pop_front();
        }
        self.tip = entry;
        Ok(entry)
    }

    /// Append a bounded batch transactionally.
    ///
    /// No prefix is retained if any header fails.
    pub fn append_batch(
        &mut self,
        headers: &[Header],
        now: BlockTime,
    ) -> Result<HeaderEntry, LightChainError> {
        if headers.is_empty() || headers.len() > self.limits.max_headers_per_batch {
            return Err(LightChainError::HeaderBatchLimit);
        }
        let mut candidate = self.clone();
        for header in headers {
            candidate.append(header, now)?;
        }
        let tip = candidate.tip();
        *self = candidate;
        Ok(tip)
    }

    /// Require explicit tip-age, height, and work currency.
    pub fn require_current(&self, policy: CurrencyPolicy) -> Result<CurrentChain, LightChainError> {
        let tip = self.tip();
        if tip.height < policy.minimum_height {
            return Err(LightChainError::InsufficientHeight);
        }
        if tip.chainwork < policy.minimum_chainwork {
            return Err(LightChainError::InsufficientChainwork);
        }
        let valid_until = tip
            .time
            .get()
            .checked_add(policy.maximum_tip_age_seconds)
            .ok_or(LightChainError::TimeOverflow)?;
        if policy.now.get() > valid_until {
            return Err(LightChainError::StaleTip);
        }
        if tip.time.get() > policy.now.get().saturating_add(7_200) {
            return Err(LightChainError::FutureTip);
        }
        Ok(CurrentChain {
            anchor: HnsAnchor {
                network: self.network,
                height: tip.height,
                block_hash: tip.hash,
                tree_root: tip.tree_root,
                chainwork: tip.chainwork,
                validated_at: policy.now,
                valid_until: BlockTime::new(valid_until),
            },
        })
    }

    /// Consensus median-time-past of the current tip's trailing window.
    ///
    /// Wallet transaction and name-action policy uses this exact parent-chain
    /// clock; wall time and the tip header's raw timestamp are not substitutes.
    #[must_use]
    pub fn median_time_past(&self) -> BlockTime {
        let mut times = self
            .history
            .iter()
            .rev()
            .take(MEDIAN_TIME_SPAN)
            .map(|entry| entry.time.get())
            .collect::<Vec<_>>();
        times.sort_unstable();
        BlockTime::new(
            times
                .get(times.len() / 2)
                .copied()
                .unwrap_or(self.tip.time.get()),
        )
    }

    fn suitable_entry(&self, height: u32) -> Result<HeaderEntry, LightChainError> {
        let first_height = height
            .checked_sub(2)
            .ok_or(LightChainError::MissingDifficultyHistory)?;
        let mut entries = [
            self.entry_at(first_height)?,
            self.entry_at(first_height + 1)?,
            self.entry_at(height)?,
        ];
        entries.sort_by_key(|entry| entry.time);
        Ok(entries[1])
    }

    fn entry_at(&self, height: u32) -> Result<HeaderEntry, LightChainError> {
        self.history
            .iter()
            .find(|entry| entry.height.get() == height)
            .copied()
            .ok_or(LightChainError::MissingDifficultyHistory)
    }
}

/// A chain tip that passed explicit currency policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentChain {
    anchor: HnsAnchor,
}

impl CurrentChain {
    /// Currency-checked anchor metadata.
    #[must_use]
    pub const fn anchor(self) -> HnsAnchor {
        self.anchor
    }

    /// Verify one canonical HSD inclusion proof and decode its committed name state.
    pub fn verify_name_resource(
        &self,
        name: &[u8],
        proof_bytes: &[u8],
    ) -> Result<VerifiedHnsResource, LightChainError> {
        let name_hash = hash_name(name)?;
        let proof = HsdUrkelProof::decode_strict(proof_bytes)?;
        let name_state = proof
            .verify(self.anchor.tree_root, name_hash)?
            .ok_or(LightChainError::NameNotFound)?;
        let decoded = decode_name_state(&name_state, name, self.anchor.height)?;
        let resource = HnsResource::decode(&decoded.resource)?;
        Ok(VerifiedHnsResource {
            anchor: self.anchor,
            name_hash,
            name: name.to_vec(),
            state_height: decoded.height,
            renewal_height: decoded.renewal,
            resource,
        })
    }
}

/// Metadata for the exact current header that authenticated a resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsAnchor {
    network: Network,
    height: Height,
    block_hash: BlockHash,
    tree_root: TreeRoot,
    chainwork: Chainwork,
    validated_at: BlockTime,
    valid_until: BlockTime,
}

impl HnsAnchor {
    /// Handshake network.
    #[must_use]
    pub const fn network(self) -> Network {
        self.network
    }

    /// Header height.
    #[must_use]
    pub const fn height(self) -> Height {
        self.height
    }

    /// Header block hash.
    #[must_use]
    pub const fn block_hash(self) -> BlockHash {
        self.block_hash
    }

    /// Header name-tree root.
    #[must_use]
    pub const fn tree_root(self) -> TreeRoot {
        self.tree_root
    }

    /// Cumulative chainwork.
    #[must_use]
    pub const fn chainwork(self) -> Chainwork {
        self.chainwork
    }

    /// Local time at which currency was checked.
    #[must_use]
    pub const fn validated_at(self) -> BlockTime {
        self.validated_at
    }

    /// Last local time for which the configured age policy holds.
    #[must_use]
    pub const fn valid_until(self) -> BlockTime {
        self.valid_until
    }
}

/// A name resource authenticated by a current Handshake header and Urkel proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHnsResource {
    anchor: HnsAnchor,
    name_hash: NameHash,
    name: Vec<u8>,
    state_height: Height,
    renewal_height: Height,
    resource: HnsResource,
}

impl VerifiedHnsResource {
    /// Exact chain anchor that committed this resource.
    #[must_use]
    pub const fn anchor(&self) -> HnsAnchor {
        self.anchor
    }

    /// Canonical Handshake name hash used as the Urkel key.
    #[must_use]
    pub const fn name_hash(&self) -> NameHash {
        self.name_hash
    }

    /// Lowercase Handshake TLD label.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Name-state creation/reset height.
    #[must_use]
    pub const fn state_height(&self) -> Height {
        self.state_height
    }

    /// Name-state renewal height.
    #[must_use]
    pub const fn renewal_height(&self) -> Height {
        self.renewal_height
    }

    /// Strictly decoded committed HNS resource.
    #[must_use]
    pub const fn resource(&self) -> &HnsResource {
        &self.resource
    }
}

/// Strictly decoded HSD name resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsResource {
    raw: Vec<u8>,
    records: Vec<HnsResourceRecord>,
}

impl HnsResource {
    /// Decode all assigned records and reject unknown tags or trailing fragments.
    pub fn decode(raw: &[u8]) -> Result<Self, LightChainError> {
        if raw.len() > MAX_RESOURCE_SIZE {
            return Err(LightChainError::ResourceTooLarge(raw.len()));
        }
        let mut reader = ResourceReader::new(raw);
        if reader.read_u8()? != 0 {
            return Err(LightChainError::UnsupportedResourceVersion);
        }
        let mut records = Vec::new();
        while !reader.is_finished() {
            let kind = reader.read_u8()?;
            if kind > MAX_KNOWN_RESOURCE_KIND {
                return Err(LightChainError::UnknownResourceRecord(kind));
            }
            let record = match kind {
                0 => HnsResourceRecord::Ds(DelegationSigner {
                    key_tag: reader.read_u16_be()?,
                    algorithm: reader.read_u8()?,
                    digest_type: reader.read_u8()?,
                    digest: reader.read_length_prefixed_bytes()?,
                }),
                1 => HnsResourceRecord::Ns(reader.read_name()?),
                2 => HnsResourceRecord::Glue4 {
                    name: reader.read_name()?,
                    address: Ipv4Addr::from(reader.read_array()?),
                },
                3 => HnsResourceRecord::Glue6 {
                    name: reader.read_name()?,
                    address: Ipv6Addr::from(reader.read_array()?),
                },
                4 => HnsResourceRecord::Synth4(Ipv4Addr::from(reader.read_array()?)),
                5 => HnsResourceRecord::Synth6(Ipv6Addr::from(reader.read_array()?)),
                6 => {
                    let count = usize::from(reader.read_u8()?);
                    let mut strings = Vec::with_capacity(count);
                    for _ in 0..count {
                        strings.push(reader.read_length_prefixed_bytes()?);
                    }
                    HnsResourceRecord::Txt(strings)
                }
                _ => unreachable!("assigned resource kinds are exhaustively matched"),
            };
            records.push(record);
        }
        CovenantResource::new(raw.to_vec())?;
        Ok(Self {
            raw: raw.to_vec(),
            records,
        })
    }

    /// Exact bytes committed in the name state.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// All assigned records in commitment order.
    #[must_use]
    pub fn records(&self) -> &[HnsResourceRecord] {
        &self.records
    }

    /// Iterate the DNSSEC delegation signers in commitment order.
    pub fn delegation_signers(&self) -> impl Iterator<Item = &DelegationSigner> {
        self.records.iter().filter_map(|record| match record {
            HnsResourceRecord::Ds(ds) => Some(ds),
            _ => None,
        })
    }
}

/// One assigned HSD resource record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HnsResourceRecord {
    /// DNSSEC DS record for the TLD zone.
    Ds(DelegationSigner),
    /// Authoritative nameserver.
    Ns(ResourceName),
    /// Nameserver plus IPv4 glue.
    Glue4 {
        /// Nameserver name.
        name: ResourceName,
        /// IPv4 address.
        address: Ipv4Addr,
    },
    /// Nameserver plus IPv6 glue.
    Glue6 {
        /// Nameserver name.
        name: ResourceName,
        /// IPv6 address.
        address: Ipv6Addr,
    },
    /// Synthetic IPv4 nameserver.
    Synth4(Ipv4Addr),
    /// Synthetic IPv6 nameserver.
    Synth6(Ipv6Addr),
    /// HNS TXT strings.
    Txt(Vec<Vec<u8>>),
}

/// One HNS resource DS payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationSigner {
    /// DNSKEY key tag.
    pub key_tag: u16,
    /// DNSSEC algorithm.
    pub algorithm: u8,
    /// DS digest algorithm.
    pub digest_type: u8,
    /// DS digest bytes.
    pub digest: Vec<u8>,
}

/// Expanded uncompressed DNS name from an HNS resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceName {
    labels: Vec<Vec<u8>>,
}

impl ResourceName {
    /// Expanded labels, excluding the terminal root.
    #[must_use]
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }
}

#[derive(Debug)]
struct DecodedNameState {
    resource: Vec<u8>,
    height: Height,
    renewal: Height,
}

fn decode_name_state(
    raw: &[u8],
    expected_name: &[u8],
    tip_height: Height,
) -> Result<DecodedNameState, LightChainError> {
    let mut decoder = Decoder::new(raw);
    let name_length = usize::from(decoder.read_u8()?);
    let name = decoder.read_slice(name_length)?;
    if name != expected_name || !validate_name(name) {
        return Err(LightChainError::NameStateNameMismatch);
    }
    let resource_length = usize::from(decoder.read_u16_le()?);
    if resource_length == 0 {
        return Err(LightChainError::MissingResource);
    }
    if resource_length > MAX_RESOURCE_SIZE {
        return Err(LightChainError::ResourceTooLarge(resource_length));
    }
    let resource = decoder.read_slice(resource_length)?.to_vec();
    let height = Height::new(decoder.read_u32_le()?);
    let renewal = Height::new(decoder.read_u32_le()?);
    let field = decoder.read_u16_le()?;
    if field & !NAME_STATE_KNOWN_FIELD_BITS != 0 {
        return Err(LightChainError::UnknownNameStateField);
    }
    if height > tip_height || renewal > tip_height {
        return Err(LightChainError::FutureNameState);
    }
    if field & (1 << 0) != 0 {
        decoder.read_array::<32>()?;
        let owner_index = decoder.read_compact_size()?;
        if owner_index > u64::from(u32::MAX) {
            return Err(LightChainError::InvalidNameStateValue);
        }
    }
    if field & (1 << 1) != 0 {
        decoder.read_compact_size()?;
    }
    if field & (1 << 2) != 0 {
        decoder.read_compact_size()?;
    }
    for bit in [3_u16, 4, 5] {
        if field & (1 << bit) != 0 {
            let event_height = Height::new(decoder.read_u32_le()?);
            if event_height > tip_height {
                return Err(LightChainError::FutureNameState);
            }
        }
    }
    if field & (1 << 6) != 0 && decoder.read_compact_size()? > u64::from(u32::MAX) {
        return Err(LightChainError::InvalidNameStateValue);
    }
    decoder.finish()?;
    Ok(DecodedNameState {
        resource,
        height,
        renewal,
    })
}

fn entry_from_header(height: Height, header: &Header, chainwork: Chainwork) -> HeaderEntry {
    HeaderEntry {
        height,
        hash: header.block_hash(),
        previous_block: header.previous_block,
        tree_root: header.tree_root,
        merkle_root: header.merkle_root,
        time: header.time,
        bits: header.bits,
        chainwork,
    }
}

fn encode_header_entry(encoder: &mut Encoder, entry: HeaderEntry) {
    encoder.put_u32_le(entry.height.get());
    encoder.put_bytes(entry.hash.as_bytes());
    encoder.put_bytes(entry.previous_block.as_bytes());
    encoder.put_bytes(entry.tree_root.as_bytes());
    encoder.put_bytes(entry.merkle_root.as_bytes());
    encoder.put_u64_le(entry.time.get());
    encoder.put_u32_le(entry.bits.get());
    encoder.put_bytes(&entry.chainwork.to_be_bytes());
}

fn decode_header_entry(decoder: &mut Decoder<'_>) -> Result<HeaderEntry, LightChainError> {
    Ok(HeaderEntry {
        height: Height::new(decoder.read_u32_le()?),
        hash: BlockHash::new(decoder.read_array()?),
        previous_block: BlockHash::new(decoder.read_array()?),
        tree_root: TreeRoot::new(decoder.read_array()?),
        merkle_root: MerkleRoot::new(decoder.read_array()?),
        time: BlockTime::new(decoder.read_u64_le()?),
        bits: CompactTarget::new(decoder.read_u32_le()?),
        chainwork: Chainwork::from_be_bytes(decoder.read_array()?),
    })
}

fn validate_snapshot_history(
    network: Network,
    limits: ChainLimits,
    history: &VecDeque<HeaderEntry>,
    floor: ChainSnapshotFloor,
) -> Result<(), LightChainError> {
    let first = history
        .front()
        .copied()
        .ok_or(LightChainError::InvalidSnapshot)?;
    let tip = history
        .back()
        .copied()
        .ok_or(LightChainError::InvalidSnapshot)?;
    let expected_length = usize::try_from(u64::from(tip.height.get()) + 1)
        .map_err(|_| LightChainError::InvalidSnapshot)?
        .min(REQUIRED_DIFFICULTY_HISTORY);
    if history.len() != expected_length {
        return Err(LightChainError::InvalidSnapshot);
    }
    if history.iter().any(|entry| {
        entry.hash == BlockHash::default()
            || entry.bits.get() == 0
            || entry.chainwork == Chainwork::ZERO
    }) {
        return Err(LightChainError::InvalidSnapshot);
    }
    if tip.height < floor.minimum_height || tip.chainwork < floor.minimum_chainwork {
        return Err(LightChainError::SnapshotRollback);
    }
    if first.height.get() == 0 {
        let expected =
            LightChain::from_genesis(network, network.parameters().genesis_time, limits)?;
        if first != expected.tip {
            return Err(LightChainError::InvalidSnapshot);
        }
    }
    let linear = history.iter().copied().collect::<Vec<_>>();
    for pair in linear.windows(2) {
        validate_snapshot_pair(pair)?;
    }
    Ok(())
}

fn validate_snapshot_pair(pair: &[HeaderEntry]) -> Result<(), LightChainError> {
    let [previous, next] = pair else {
        return Err(LightChainError::InvalidSnapshot);
    };
    if previous.height.get().checked_add(1) != Some(next.height.get())
        || next.previous_block != previous.hash
        || next.chainwork <= previous.chainwork
        || next.bits.get() == 0
    {
        return Err(LightChainError::InvalidSnapshot);
    }
    Ok(())
}

fn decode_network(id: u8) -> Result<Network, LightChainError> {
    match id {
        0 => Ok(Network::Mainnet),
        1 => Ok(Network::Testnet),
        2 => Ok(Network::Regtest),
        3 => Ok(Network::Simnet),
        _ => Err(LightChainError::InvalidSnapshot),
    }
}

fn snapshot_checksum(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(LIGHT_CHAIN_SNAPSHOT_CHECKSUM_DOMAIN);
    hasher.update(payload);
    hasher.finalize().into()
}

struct ResourceReader<'a> {
    input: &'a [u8],
    position: usize,
    known_name_offsets: Vec<usize>,
}

impl<'a> ResourceReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            position: 0,
            known_name_offsets: Vec::new(),
        }
    }

    const fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }

    fn read_u8(&mut self) -> Result<u8, LightChainError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16_be(&mut self) -> Result<u16, LightChainError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], LightChainError> {
        let end = self
            .position
            .checked_add(LENGTH)
            .ok_or(LightChainError::ResourceTruncated)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(LightChainError::ResourceTruncated)?;
        self.position = end;
        bytes
            .try_into()
            .map_err(|_| LightChainError::ResourceTruncated)
    }

    fn read_length_prefixed_bytes(&mut self) -> Result<Vec<u8>, LightChainError> {
        let length = usize::from(self.read_u8()?);
        let end = self
            .position
            .checked_add(length)
            .ok_or(LightChainError::ResourceTruncated)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(LightChainError::ResourceTruncated)?;
        self.position = end;
        Ok(bytes.to_vec())
    }

    fn read_name(&mut self) -> Result<ResourceName, LightChainError> {
        let mut cursor = self.position;
        let mut resume = None;
        let mut labels = Vec::new();
        let mut expanded_wire_length = 1_usize;
        let mut jumps = 0_usize;
        let mut visited = Vec::new();

        loop {
            if visited.contains(&cursor) {
                return Err(LightChainError::ResourceNameCompressionLoop);
            }
            visited.push(cursor);
            let length = *self
                .input
                .get(cursor)
                .ok_or(LightChainError::ResourceTruncated)?;
            if length & 0xc0 == 0xc0 {
                let next = *self
                    .input
                    .get(cursor + 1)
                    .ok_or(LightChainError::ResourceTruncated)?;
                let target = (usize::from(length & 0x3f) << 8) | usize::from(next);
                if target >= cursor || !self.known_name_offsets.contains(&target) {
                    return Err(LightChainError::InvalidResourceNamePointer);
                }
                if resume.is_none() {
                    resume = Some(cursor + 2);
                }
                jumps += 1;
                if jumps > MAX_RESOURCE_NAME_JUMPS {
                    return Err(LightChainError::ResourceNameJumpLimit);
                }
                cursor = target;
                continue;
            }
            if length & 0xc0 != 0 {
                return Err(LightChainError::InvalidResourceName);
            }
            self.known_name_offsets.push(cursor);
            cursor += 1;
            if length == 0 {
                self.position = resume.unwrap_or(cursor);
                return Ok(ResourceName { labels });
            }
            let length = usize::from(length);
            if length > 63 || labels.len() >= MAX_RESOURCE_NAME_LABELS {
                return Err(LightChainError::InvalidResourceName);
            }
            expanded_wire_length = expanded_wire_length
                .checked_add(length + 1)
                .ok_or(LightChainError::InvalidResourceName)?;
            if expanded_wire_length > 255 {
                return Err(LightChainError::InvalidResourceName);
            }
            let end = cursor
                .checked_add(length)
                .ok_or(LightChainError::ResourceTruncated)?;
            let label = self
                .input
                .get(cursor..end)
                .ok_or(LightChainError::ResourceTruncated)?;
            labels.push(label.to_vec());
            cursor = end;
            if resume.is_none() {
                self.position = cursor;
            }
        }
    }
}

/// Header, currency, proof, name-state, or HNS resource failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LightChainError {
    /// Shared header consensus rejected a header.
    #[error("header consensus failure: {0}")]
    Header(#[from] HeaderError),
    /// Shared arithmetic rejected chainwork overflow.
    #[error("chainwork arithmetic failure: {0}")]
    Arithmetic(#[from] hns_primitives::ArithmeticError),
    /// Shared Handshake name/resource validation failed.
    #[error("covenant value failure: {0}")]
    Covenant(#[from] hns_covenants::CovenantError),
    /// Strict Urkel proof parsing or verification failed.
    #[error("Urkel proof failure: {0}")]
    Urkel(#[from] UrkelError),
    /// Strict name-state decoding failed.
    #[error("name-state decoding failure: {0}")]
    NameStateDecode(#[from] DecodeError),
    /// A configured bound is zero or exceeds the hard operational maximum.
    #[error("chain limit is zero or excessive")]
    InvalidLimit,
    /// The header batch is empty or exceeds its bound.
    #[error("header batch exceeds its configured bound")]
    HeaderBatchLimit,
    /// Authenticated checkpoint framing or structural invariants are invalid.
    #[error("invalid authenticated light-chain checkpoint")]
    InvalidSnapshot,
    /// Checkpoint exceeds the fixed allocation bound.
    #[error("light-chain checkpoint exceeds its size bound")]
    SnapshotTooLarge,
    /// Checkpoint checksum differs from its payload.
    #[error("light-chain checkpoint checksum mismatch")]
    SnapshotChecksumMismatch,
    /// Checkpoint schema or magic is unsupported.
    #[error("unsupported light-chain checkpoint schema")]
    UnsupportedSnapshot,
    /// Checkpoint belongs to another Handshake network.
    #[error("light-chain checkpoint network mismatch")]
    SnapshotNetworkMismatch,
    /// Checkpoint falls below the caller-held height or chainwork floor.
    #[error("light-chain checkpoint rollback detected")]
    SnapshotRollback,
    /// The next height cannot be represented.
    #[error("header height overflow")]
    HeightOverflow,
    /// Required retarget history is unavailable.
    #[error("required difficulty history is unavailable")]
    MissingDifficultyHistory,
    /// Time arithmetic overflowed.
    #[error("time arithmetic overflow")]
    TimeOverflow,
    /// Validated height is below policy.
    #[error("validated chain height is insufficient")]
    InsufficientHeight,
    /// Validated cumulative work is below policy.
    #[error("validated cumulative chainwork is insufficient")]
    InsufficientChainwork,
    /// The validated tip is older than policy permits.
    #[error("validated Handshake tip is stale")]
    StaleTip,
    /// The validated tip is more than two hours ahead of the supplied clock.
    #[error("validated Handshake tip is too far in the future")]
    FutureTip,
    /// The proof establishes non-inclusion.
    #[error("Handshake name is absent at the validated tree root")]
    NameNotFound,
    /// Serialized name and proof key disagree.
    #[error("name-state name does not match the requested proof key")]
    NameStateNameMismatch,
    /// Name state carries no HNS resource.
    #[error("name state has no resource")]
    MissingResource,
    /// Resource exceeds the consensus covenant bound.
    #[error("resource length {0} exceeds the Handshake bound")]
    ResourceTooLarge(usize),
    /// Name-state bit field has an unknown assignment.
    #[error("name state contains unknown field bits")]
    UnknownNameStateField,
    /// Name-state heights exceed the committing header.
    #[error("name state contains a future height")]
    FutureNameState,
    /// A bounded name-state integer exceeds its protocol domain.
    #[error("name state contains an out-of-range integer")]
    InvalidNameStateValue,
    /// Resource serialization version is unsupported.
    #[error("unsupported HNS resource version")]
    UnsupportedResourceVersion,
    /// An unassigned HNS resource tag was encountered.
    #[error("unknown HNS resource record tag {0}")]
    UnknownResourceRecord(u8),
    /// Resource record ended prematurely.
    #[error("truncated HNS resource")]
    ResourceTruncated,
    /// Resource DNS name is malformed.
    #[error("malformed DNS name in HNS resource")]
    InvalidResourceName,
    /// Resource compression pointer is forward or not at a known name boundary.
    #[error("invalid DNS compression pointer in HNS resource")]
    InvalidResourceNamePointer,
    /// Resource compression pointer graph loops.
    #[error("DNS compression loop in HNS resource")]
    ResourceNameCompressionLoop,
    /// Resource name exceeds its pointer-following bound.
    #[error("DNS compression jump bound exceeded in HNS resource")]
    ResourceNameJumpLimit,
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests construct compact protocol fixtures and fail immediately"
)]
mod tests {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};

    use super::*;

    fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).unwrap();
        for part in parts {
            hasher.update(part);
        }
        let mut output = [0_u8; 32];
        hasher.finalize_variable(&mut output).unwrap();
        output
    }

    fn name_state(name: &[u8], resource: &[u8], height: u32) -> Vec<u8> {
        let mut state = Vec::new();
        state.push(u8::try_from(name.len()).unwrap());
        state.extend_from_slice(name);
        state.extend_from_slice(&u16::try_from(resource.len()).unwrap().to_le_bytes());
        state.extend_from_slice(resource);
        state.extend_from_slice(&height.to_le_bytes());
        state.extend_from_slice(&height.to_le_bytes());
        state.extend_from_slice(&0_u16.to_le_bytes());
        state
    }

    fn inclusion_proof(value: &[u8]) -> Vec<u8> {
        let mut proof = Vec::new();
        proof.extend_from_slice(&0xc000_u16.to_le_bytes());
        proof.extend_from_slice(&0_u16.to_le_bytes());
        proof.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
        proof.extend_from_slice(value);
        proof
    }

    fn leaf_root(name: &[u8], value: &[u8]) -> TreeRoot {
        let key = hash_name(name).unwrap();
        let value_hash = blake2b_256(&[value]);
        TreeRoot::new(blake2b_256(&[&[0], key.as_bytes(), &value_hash]))
    }

    fn mine_regtest_header(previous: HeaderEntry, tree_root: TreeRoot) -> Header {
        let mut header = Header {
            time: BlockTime::new(previous.time().get() + 1),
            previous_block: previous.hash(),
            tree_root,
            bits: Network::Regtest.parameters().pow.bits,
            ..Header::default()
        };
        while !header.verify_pow() {
            header.nonce = header.nonce.checked_add(1).unwrap();
        }
        header
    }

    fn ds_resource() -> Vec<u8> {
        let mut resource = vec![0, 0];
        resource.extend_from_slice(&0x1234_u16.to_be_bytes());
        resource.extend_from_slice(&[8, 2, 32]);
        resource.extend_from_slice(&[0xab; 32]);
        resource
    }

    #[test]
    fn validates_header_currency_urkel_name_state_and_ds_resource() {
        let genesis_time = Network::Regtest.parameters().genesis_time;
        let now = BlockTime::new(genesis_time.get() + 100);
        let mut chain =
            LightChain::from_genesis(Network::Regtest, now, ChainLimits::default()).unwrap();
        let state = name_state(b"alpha", &ds_resource(), 1);
        let proof = inclusion_proof(&state);
        let header = mine_regtest_header(chain.tip(), leaf_root(b"alpha", &state));
        chain.append(&header, now).unwrap();
        let current = chain
            .require_current(CurrencyPolicy {
                now,
                maximum_tip_age_seconds: 3_600,
                minimum_height: Height::new(1),
                minimum_chainwork: Chainwork::ZERO,
            })
            .unwrap();
        let verified = current.verify_name_resource(b"alpha", &proof).unwrap();
        assert_eq!(verified.anchor().height(), Height::new(1));
        assert_eq!(verified.name(), b"alpha");
        assert_eq!(verified.resource().records().len(), 1);
        assert_eq!(
            verified.resource().delegation_signers().next(),
            Some(&DelegationSigner {
                key_tag: 0x1234,
                algorithm: 8,
                digest_type: 2,
                digest: vec![0xab; 32],
            })
        );

        let mut trailing = proof;
        trailing.push(0);
        assert!(matches!(
            current.verify_name_resource(b"alpha", &trailing),
            Err(LightChainError::Urkel(UrkelError::TrailingBytes(1)))
        ));
    }

    #[test]
    fn header_batches_are_atomic_and_currency_fails_closed() {
        let genesis_time = Network::Regtest.parameters().genesis_time;
        let now = BlockTime::new(genesis_time.get() + 100);
        let mut chain =
            LightChain::from_genesis(Network::Regtest, now, ChainLimits::default()).unwrap();
        let good = mine_regtest_header(chain.tip(), TreeRoot::new([1; 32]));
        let mut bad = good.clone();
        bad.previous_block = BlockHash::new([9; 32]);
        assert!(chain.append_batch(&[good, bad], now).is_err());
        assert_eq!(chain.tip().height(), Height::new(0));
        assert_eq!(
            chain
                .require_current(CurrencyPolicy {
                    now: BlockTime::new(genesis_time.get() + 10_000),
                    maximum_tip_age_seconds: 10,
                    minimum_height: Height::new(0),
                    minimum_chainwork: Chainwork::ZERO,
                })
                .unwrap_err()
                .to_string(),
            "validated Handshake tip is stale"
        );
    }

    #[test]
    fn resource_decoder_handles_names_and_rejects_unknown_or_bad_pointers() {
        let resource = [
            0, 1, 2, b'n', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 2, 0xc0, 2, 127,
            0, 0, 1,
        ];
        let decoded = HnsResource::decode(&resource).unwrap();
        assert_eq!(decoded.records().len(), 2);
        assert!(matches!(
            &decoded.records()[1],
            HnsResourceRecord::Glue4 { name, address }
                if name.labels() == [b"ns".to_vec(), b"example".to_vec()]
                    && *address == Ipv4Addr::LOCALHOST
        ));

        assert!(matches!(
            HnsResource::decode(&[0, 7]),
            Err(LightChainError::UnknownResourceRecord(7))
        ));
        assert!(matches!(
            HnsResource::decode(&[0, 1, 0xc0, 1]),
            Err(LightChainError::InvalidResourceNamePointer)
        ));
    }

    #[test]
    fn retarget_history_window_is_retained() {
        let genesis_time = Network::Regtest.parameters().genesis_time;
        let now = BlockTime::new(genesis_time.get() + 10_000);
        let mut chain =
            LightChain::from_genesis(Network::Regtest, now, ChainLimits::default()).unwrap();
        for value in 1_u32..=160 {
            let byte = u8::try_from(value).unwrap();
            let header = mine_regtest_header(chain.tip(), TreeRoot::new([byte; 32]));
            chain.append(&header, now).unwrap();
        }
        assert_eq!(chain.history.len(), REQUIRED_DIFFICULTY_HISTORY);
        assert_eq!(chain.tip().height(), Height::new(160));
        let locator = chain.locator();
        assert_eq!(locator.first().copied(), Some(chain.tip().hash()));
        assert_eq!(
            locator.last().copied(),
            Some(Network::Regtest.parameters().genesis_hash)
        );
        assert!(locator.len() <= MAX_LOCATOR_HASHES);

        let snapshot = chain.encode_authenticated_snapshot().unwrap();
        let floor = ChainSnapshotFloor {
            minimum_height: chain.tip().height(),
            minimum_chainwork: chain.tip().chainwork(),
        };
        let mut restored =
            LightChain::decode_authenticated_snapshot(&snapshot, Network::Regtest, floor).unwrap();
        assert_eq!(restored.tip(), chain.tip());
        assert_eq!(restored.history, chain.history);
        let next = mine_regtest_header(restored.tip(), TreeRoot::new([161; 32]));
        restored.append(&next, now).unwrap();
        assert_eq!(restored.tip().height(), Height::new(161));

        assert!(matches!(
            LightChain::decode_authenticated_snapshot(
                &snapshot,
                Network::Mainnet,
                ChainSnapshotFloor::default()
            ),
            Err(LightChainError::SnapshotNetworkMismatch)
        ));
        assert!(matches!(
            LightChain::decode_authenticated_snapshot(
                &snapshot,
                Network::Regtest,
                ChainSnapshotFloor {
                    minimum_height: Height::new(161),
                    minimum_chainwork: Chainwork::ZERO,
                }
            ),
            Err(LightChainError::SnapshotRollback)
        ));
        let mut corrupted = snapshot;
        corrupted[LIGHT_CHAIN_SNAPSHOT_MAGIC.len()] ^= 1;
        assert!(matches!(
            LightChain::decode_authenticated_snapshot(
                &corrupted,
                Network::Regtest,
                ChainSnapshotFloor::default()
            ),
            Err(LightChainError::SnapshotChecksumMismatch)
        ));
    }

    #[test]
    fn exposes_consensus_median_time_past_for_wallet_policy() {
        let genesis_time = Network::Regtest.parameters().genesis_time;
        let now = BlockTime::new(genesis_time.get() + 10_000);
        let mut chain =
            LightChain::from_genesis(Network::Regtest, now, ChainLimits::default()).unwrap();
        assert_eq!(chain.median_time_past(), genesis_time);

        for value in 1_u8..=11 {
            let header = mine_regtest_header(chain.tip(), TreeRoot::new([value; 32]));
            chain.append(&header, now).unwrap();
        }
        assert_eq!(
            chain.median_time_past(),
            BlockTime::new(genesis_time.get() + 6)
        );
    }

    #[test]
    fn compact_target_proof_is_nonzero_for_all_network_genesis_targets() {
        for network in [
            Network::Mainnet,
            Network::Testnet,
            Network::Regtest,
            Network::Simnet,
        ] {
            assert!(
                hns_header_consensus::DecodedTarget::from_compact(network.parameters().pow.bits)
                    .proof()
                    .is_some()
            );
        }
    }
}
