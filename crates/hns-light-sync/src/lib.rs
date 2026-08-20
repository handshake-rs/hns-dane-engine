//! Bounded multi-peer Handshake light-header synchronization.
//!
//! A round requests the same locator from a bounded peer set, validates every
//! response independently on a clone of the current chain, chooses the
//! greatest-chainwork result, and requires configurable peer agreement.
//! Equal-work divergent tips fail closed. Durable checkpoints and deep reorg
//! recovery remain storage-adapter responsibilities.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "HNS, P2P, and HSD are protocol names"
)]

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;

use hns_header_consensus::{Header, Network};
use hns_light_chain::{
    ChainLimits, CurrencyPolicy, CurrentChain, HeaderEntry, LightChain, LightChainError,
};
use hns_p2p_wire::{LocatorPacket, MAX_HEADERS};
use hns_primitives::{BlockHash, BlockTime};
use thiserror::Error;

/// Default maximum simultaneously tracked peers.
pub const DEFAULT_MAX_PEERS: usize = 8;
/// Default minimum matching valid responses.
pub const DEFAULT_MINIMUM_PEER_AGREEMENT: usize = 2;
/// Default header round deadline.
pub const DEFAULT_ROUND_TIMEOUT_SECONDS: u64 = 20;
/// Default invalid-round failures before a peer is locally banned.
pub const DEFAULT_MAX_PEER_FAILURES: u32 = 3;

/// Opaque peer identity; debug output never reveals it.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Construct from a stable connection-scoped peer identifier.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerId([redacted])")
    }
}

/// Header synchronization policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncConfig {
    /// Maximum tracked peers.
    pub max_peers: usize,
    /// Minimum peers that must return the selected tip.
    pub minimum_peer_agreement: usize,
    /// Round response deadline.
    pub round_timeout_seconds: u64,
    /// Invalid candidate failures before local ban.
    pub max_peer_failures: u32,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_peers: DEFAULT_MAX_PEERS,
            minimum_peer_agreement: DEFAULT_MINIMUM_PEER_AGREEMENT,
            round_timeout_seconds: DEFAULT_ROUND_TIMEOUT_SECONDS,
            max_peer_failures: DEFAULT_MAX_PEER_FAILURES,
        }
    }
}

impl SyncConfig {
    fn validate(self) -> Result<Self, SyncError> {
        if self.max_peers == 0
            || self.max_peers > 64
            || self.minimum_peer_agreement == 0
            || self.minimum_peer_agreement > self.max_peers
            || self.round_timeout_seconds == 0
            || self.round_timeout_seconds > 300
            || self.max_peer_failures == 0
        {
            return Err(SyncError::InvalidConfig);
        }
        Ok(self)
    }
}

/// Header authority synchronization state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncState {
    /// More validated headers or peer agreement are required.
    HeaderSyncing,
    /// A bounded peer round reports no greater-work extension.
    HeaderCurrent,
    /// No valid/agreed candidate was available.
    Degraded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerRecord {
    advertised_height: u32,
    failures: u32,
    successes: u64,
    banned: bool,
}

/// Name-free per-peer synchronization status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerStatus {
    /// Opaque peer identity.
    pub id: PeerId,
    /// Most recently advertised height.
    pub advertised_height: u32,
    /// Invalid candidate failures.
    pub failures: u32,
    /// Valid candidate responses.
    pub successes: u64,
    /// Whether local failure policy banned this peer.
    pub banned: bool,
}

/// Request shared by every peer selected for one round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderRoundRequest {
    /// Monotonic round generation.
    pub generation: u64,
    /// Standard HSD locator request.
    pub packet: LocatorPacket,
    /// Exact local base tip height.
    pub base_height: u32,
    /// Exact local base tip hash.
    pub base_hash: BlockHash,
    /// Response deadline.
    pub deadline: u64,
}

#[derive(Clone, Debug)]
struct SyncRound {
    request: HeaderRoundRequest,
    requested: HashSet<PeerId>,
    responses: HashMap<PeerId, Vec<Header>>,
}

/// Immutable synchronization summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncStatus {
    /// Current state.
    pub state: SyncState,
    /// State generation.
    pub generation: u64,
    /// Validated tip.
    pub tip: HeaderEntry,
    /// Tracked peers.
    pub peers: usize,
    /// Non-banned peers.
    pub active_peers: usize,
    /// Whether a round is collecting responses.
    pub round_active: bool,
}

/// Completed agreement round plus the exact newly accepted header batch.
///
/// Storage adapters persist `accepted_headers` before starting another round;
/// the consensus engine itself retains only its small retarget lookback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderRoundOutcome {
    /// Resulting synchronization status.
    pub status: SyncStatus,
    /// Exact winning extension, empty only for a no-extension agreement round.
    pub accepted_headers: Vec<Header>,
}

/// Bounded multi-peer header synchronizer.
#[derive(Clone, Debug)]
pub struct HeaderSync {
    config: SyncConfig,
    chain: LightChain,
    state: SyncState,
    generation: u64,
    peers: HashMap<PeerId, PeerRecord>,
    round: Option<SyncRound>,
}

impl HeaderSync {
    /// Begin at canonical network genesis.
    pub fn from_genesis(
        network: Network,
        now: BlockTime,
        chain_limits: ChainLimits,
        config: SyncConfig,
    ) -> Result<Self, SyncError> {
        let config = config.validate()?;
        Ok(Self {
            config,
            chain: LightChain::from_genesis(network, now, chain_limits)?,
            state: SyncState::HeaderSyncing,
            generation: 1,
            peers: HashMap::with_capacity(config.max_peers),
            round: None,
        })
    }

    /// Resume synchronization from a chain restored out of the caller's
    /// authenticated wallet store.
    ///
    /// Peer scores and an in-flight round are deliberately connection-local:
    /// reopening starts in `HeaderSyncing` and requires fresh peer agreement
    /// before current-chain evidence can be issued.
    pub fn from_chain(chain: LightChain, config: SyncConfig) -> Result<Self, SyncError> {
        let config = config.validate()?;
        Ok(Self {
            config,
            chain,
            state: SyncState::HeaderSyncing,
            generation: 1,
            peers: HashMap::with_capacity(config.max_peers),
            round: None,
        })
    }

    /// Current validated chain.
    #[must_use]
    pub const fn chain(&self) -> &LightChain {
        &self.chain
    }

    /// Current name-free summary.
    #[must_use]
    pub fn status(&self) -> SyncStatus {
        SyncStatus {
            state: self.state,
            generation: self.generation,
            tip: self.chain.tip(),
            peers: self.peers.len(),
            active_peers: self.peers.values().filter(|record| !record.banned).count(),
            round_active: self.round.is_some(),
        }
    }

    /// Add one peer with its admitted version height.
    pub fn add_peer(&mut self, id: PeerId, advertised_height: u32) -> Result<(), SyncError> {
        if self.peers.contains_key(&id) {
            return Err(SyncError::DuplicatePeer);
        }
        if self.peers.len() >= self.config.max_peers {
            return Err(SyncError::PeerLimit);
        }
        self.peers.insert(
            id,
            PeerRecord {
                advertised_height,
                failures: 0,
                successes: 0,
                banned: false,
            },
        );
        Ok(())
    }

    /// Remove a disconnected peer and any pending response.
    pub fn remove_peer(&mut self, id: PeerId) -> bool {
        if let Some(round) = &mut self.round {
            round.requested.remove(&id);
            round.responses.remove(&id);
        }
        self.peers.remove(&id).is_some()
    }

    /// Update the peer's current version/announcement height.
    pub fn update_peer_height(
        &mut self,
        id: PeerId,
        advertised_height: u32,
    ) -> Result<(), SyncError> {
        let peer = self.peers.get_mut(&id).ok_or(SyncError::UnknownPeer)?;
        peer.advertised_height = advertised_height;
        if advertised_height > self.chain.tip().height().get() {
            self.state = SyncState::HeaderSyncing;
        }
        Ok(())
    }

    /// Begin one same-base multi-peer header round.
    pub fn begin_round(
        &mut self,
        selected_peers: &[PeerId],
        now: u64,
    ) -> Result<HeaderRoundRequest, SyncError> {
        if self.round.is_some() {
            return Err(SyncError::RoundAlreadyActive);
        }
        let requested = selected_peers.iter().copied().collect::<HashSet<_>>();
        if requested.len() != selected_peers.len()
            || requested.len() < self.config.minimum_peer_agreement
        {
            return Err(SyncError::InsufficientPeers);
        }
        for id in &requested {
            let peer = self.peers.get(id).ok_or(SyncError::UnknownPeer)?;
            if peer.banned {
                return Err(SyncError::PeerBanned);
            }
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(SyncError::GenerationExhausted)?;
        let deadline = now
            .checked_add(self.config.round_timeout_seconds)
            .ok_or(SyncError::TimeOverflow)?;
        let tip = self.chain.tip();
        let request = HeaderRoundRequest {
            generation,
            packet: LocatorPacket {
                locator: self.chain.locator(),
                stop: BlockHash::default(),
            },
            base_height: tip.height().get(),
            base_hash: tip.hash(),
            deadline,
        };
        self.round = Some(SyncRound {
            request: request.clone(),
            requested,
            responses: HashMap::with_capacity(selected_peers.len()),
        });
        self.generation = generation;
        Ok(request)
    }

    /// Submit one bounded response for the active round.
    pub fn submit_headers(
        &mut self,
        generation: u64,
        peer: PeerId,
        headers: Vec<Header>,
        now: u64,
    ) -> Result<(), SyncError> {
        let round = self.round.as_mut().ok_or(SyncError::NoActiveRound)?;
        if generation != round.request.generation {
            return Err(SyncError::StaleRound);
        }
        if now > round.request.deadline {
            return Err(SyncError::RoundExpired);
        }
        if !round.requested.contains(&peer) {
            return Err(SyncError::PeerNotRequested);
        }
        if headers.len() > MAX_HEADERS {
            return Err(SyncError::HeaderResponseLimit);
        }
        if round.responses.contains_key(&peer) {
            return Err(SyncError::DuplicateResponse);
        }
        round.responses.insert(peer, headers);
        Ok(())
    }

    /// Validate all submitted candidates, select greatest chainwork, and require agreement.
    pub fn finish_round(&mut self, now: u64) -> Result<SyncStatus, SyncError> {
        self.finish_round_with_headers(now)
            .map(|outcome| outcome.status)
    }

    /// Finish a round and return every agreed header needed by durable wallet
    /// scanning, rather than discarding the winning batch after validation.
    #[allow(
        clippy::too_many_lines,
        reason = "candidate validation, agreement, peer scoring, and atomic winner installation remain one auditable state transition"
    )]
    pub fn finish_round_with_headers(&mut self, now: u64) -> Result<HeaderRoundOutcome, SyncError> {
        let Some(round) = self.round.take() else {
            return Err(SyncError::NoActiveRound);
        };
        if round.responses.len() < self.config.minimum_peer_agreement {
            if now <= round.request.deadline {
                self.round = Some(round);
                return Err(SyncError::RoundIncomplete);
            }
            self.state = SyncState::Degraded;
            return Err(SyncError::InsufficientResponses);
        }
        if self.chain.tip().hash() != round.request.base_hash
            || self.chain.tip().height().get() != round.request.base_height
        {
            return Err(SyncError::StaleRound);
        }

        let all_requested_responded = round.responses.len() == round.requested.len();
        let mut candidates = Vec::with_capacity(round.responses.len());
        for (peer, headers) in round.responses {
            let mut candidate = self.chain.clone();
            let valid = if headers.is_empty() {
                true
            } else {
                candidate
                    .append_batch(&headers, BlockTime::new(now))
                    .is_ok()
            };
            if valid {
                candidates.push((peer, headers, candidate));
            } else {
                self.record_failure(peer);
            }
        }
        if candidates.is_empty() {
            self.state = SyncState::Degraded;
            return Err(SyncError::NoValidCandidate);
        }
        let maximum_work = candidates
            .iter()
            .map(|(_, _, candidate)| candidate.tip().chainwork())
            .max()
            .ok_or(SyncError::NoValidCandidate)?;
        let best_hashes = candidates
            .iter()
            .filter(|(_, _, candidate)| candidate.tip().chainwork() == maximum_work)
            .map(|(_, _, candidate)| candidate.tip().hash())
            .collect::<HashSet<_>>();
        if best_hashes.len() != 1 {
            self.state = SyncState::Degraded;
            return Err(SyncError::AmbiguousBestChain);
        }
        let best_hash = best_hashes
            .iter()
            .next()
            .copied()
            .ok_or(SyncError::NoValidCandidate)?;
        let supporters = candidates
            .iter()
            .filter(|(_, _, candidate)| candidate.tip().hash() == best_hash)
            .count();
        if supporters < self.config.minimum_peer_agreement {
            self.state = SyncState::Degraded;
            return Err(SyncError::InsufficientAgreement);
        }

        let winning_index = candidates
            .iter()
            .position(|(_, _, candidate)| candidate.tip().hash() == best_hash)
            .ok_or(SyncError::NoValidCandidate)?;
        let accepted_headers = candidates
            .get(winning_index)
            .map(|(_, headers, _)| headers.clone())
            .ok_or(SyncError::NoValidCandidate)?;
        let winner = candidates
            .get(winning_index)
            .map(|(_, _, candidate)| candidate.clone())
            .ok_or(SyncError::NoValidCandidate)?;
        let unchanged = winner.tip().hash() == self.chain.tip().hash();
        for (peer, _, candidate) in &candidates {
            if candidate.tip().hash() == best_hash {
                self.record_success(*peer);
            }
        }
        self.chain = winner;
        let no_active_peer_advertises_an_extension = self.peers.values().all(|record| {
            record.banned || record.advertised_height <= self.chain.tip().height().get()
        });
        self.state = if unchanged
            && all_requested_responded
            && no_active_peer_advertises_an_extension
            && candidates
                .iter()
                .filter(|(_, _, candidate)| candidate.tip().hash() == best_hash)
                .all(|(peer, headers, _)| {
                    headers.is_empty()
                        && self.peers.get(peer).is_some_and(|record| {
                            record.advertised_height <= self.chain.tip().height().get()
                        })
                }) {
            SyncState::HeaderCurrent
        } else {
            SyncState::HeaderSyncing
        };
        Ok(HeaderRoundOutcome {
            status: self.status(),
            accepted_headers,
        })
    }

    /// Issue a current-chain token only after a no-extension agreement round.
    pub fn require_current(&self, policy: CurrencyPolicy) -> Result<CurrentChain, SyncError> {
        if self.state != SyncState::HeaderCurrent {
            return Err(SyncError::NotCurrent);
        }
        self.chain.require_current(policy).map_err(SyncError::Chain)
    }

    /// Name-free status for every tracked peer.
    #[must_use]
    pub fn peer_statuses(&self) -> Vec<PeerStatus> {
        self.peers
            .iter()
            .map(|(id, record)| PeerStatus {
                id: *id,
                advertised_height: record.advertised_height,
                failures: record.failures,
                successes: record.successes,
                banned: record.banned,
            })
            .collect()
    }

    fn record_failure(&mut self, peer: PeerId) {
        if let Some(record) = self.peers.get_mut(&peer) {
            record.failures = record.failures.saturating_add(1);
            if record.failures >= self.config.max_peer_failures {
                record.banned = true;
            }
        }
    }

    fn record_success(&mut self, peer: PeerId) {
        if let Some(record) = self.peers.get_mut(&peer) {
            record.successes = record.successes.saturating_add(1);
            record.failures = record.failures.saturating_sub(1);
        }
    }
}

/// Header synchronization configuration, round, peer, or consensus failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SyncError {
    /// Header consensus/currency gate failed.
    #[error("light-chain failure: {0}")]
    Chain(#[from] LightChainError),
    /// Bounds or agreement policy are invalid.
    #[error("invalid header-sync configuration")]
    InvalidConfig,
    /// Tracked peer bound is full.
    #[error("header-sync peer bound exceeded")]
    PeerLimit,
    /// Peer identity is already tracked.
    #[error("duplicate header-sync peer")]
    DuplicatePeer,
    /// Peer is not tracked.
    #[error("unknown header-sync peer")]
    UnknownPeer,
    /// Peer reached the local invalid-response threshold.
    #[error("header-sync peer is banned")]
    PeerBanned,
    /// Selected peer list is duplicate or below agreement policy.
    #[error("insufficient distinct peers for header round")]
    InsufficientPeers,
    /// Another round is active.
    #[error("header round is already active")]
    RoundAlreadyActive,
    /// No round is active.
    #[error("no active header round")]
    NoActiveRound,
    /// Round generation is stale.
    #[error("stale header round generation")]
    StaleRound,
    /// Round deadline elapsed before submission.
    #[error("header round deadline elapsed")]
    RoundExpired,
    /// Peer was not selected for this round.
    #[error("peer was not requested in this header round")]
    PeerNotRequested,
    /// Peer submitted twice.
    #[error("duplicate peer response in header round")]
    DuplicateResponse,
    /// Response exceeds the standard HSD header bound.
    #[error("header response exceeds standard bound")]
    HeaderResponseLimit,
    /// More responses may arrive before deadline.
    #[error("header round is incomplete")]
    RoundIncomplete,
    /// Deadline elapsed without minimum responses.
    #[error("header round has insufficient responses")]
    InsufficientResponses,
    /// Every candidate failed local consensus validation.
    #[error("header round has no valid candidate")]
    NoValidCandidate,
    /// Equal-work candidates have different tips.
    #[error("header round has ambiguous equal-work tips")]
    AmbiguousBestChain,
    /// Greatest-work candidate lacks minimum peer agreement.
    #[error("greatest-work header candidate lacks peer agreement")]
    InsufficientAgreement,
    /// Current-chain evidence was requested before no-extension agreement.
    #[error("header chain is not current")]
    NotCurrent,
    /// State generation cannot advance.
    #[error("header-sync generation exhausted")]
    GenerationExhausted,
    /// Deadline arithmetic overflowed.
    #[error("header-sync deadline overflow")]
    TimeOverflow,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid local consensus fixtures"
)]
mod tests {
    use hns_primitives::{Chainwork, Height, TreeRoot};

    use super::*;

    fn config(agreement: usize, failures: u32) -> SyncConfig {
        SyncConfig {
            max_peers: 4,
            minimum_peer_agreement: agreement,
            round_timeout_seconds: 10,
            max_peer_failures: failures,
        }
    }

    fn peer(value: u8) -> PeerId {
        PeerId::new([value; 32])
    }

    fn test_sync(agreement: usize, failures: u32, now: u64) -> HeaderSync {
        HeaderSync::from_genesis(
            Network::Regtest,
            BlockTime::new(now),
            ChainLimits::default(),
            config(agreement, failures),
        )
        .unwrap()
    }

    fn mine(previous: HeaderEntry, tree_root: u8) -> Header {
        let mut header = Header {
            time: BlockTime::new(previous.time().get() + 1),
            previous_block: previous.hash(),
            tree_root: TreeRoot::new([tree_root; 32]),
            bits: Network::Regtest.parameters().pow.bits,
            ..Header::default()
        };
        while !header.verify_pow() {
            header.nonce = header.nonce.checked_add(1).unwrap();
        }
        header
    }

    #[test]
    fn requires_agreed_greatest_work_then_empty_current_round() {
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let mut sync = test_sync(2, 3, now);
        sync.add_peer(peer(1), 1).unwrap();
        sync.add_peer(peer(2), 1).unwrap();
        let request = sync.begin_round(&[peer(1), peer(2)], now).unwrap();
        let extension = mine(sync.chain().tip(), 1);
        for id in [peer(1), peer(2)] {
            sync.submit_headers(request.generation, id, vec![extension.clone()], now)
                .unwrap();
        }
        let outcome = sync.finish_round_with_headers(now).unwrap();
        assert_eq!(outcome.accepted_headers, vec![extension]);
        let status = outcome.status;
        assert_eq!(status.tip.height(), Height::new(1));
        assert_eq!(status.state, SyncState::HeaderSyncing);

        let request = sync.begin_round(&[peer(1), peer(2)], now + 1).unwrap();
        for id in [peer(1), peer(2)] {
            sync.submit_headers(request.generation, id, Vec::new(), now + 1)
                .unwrap();
        }
        assert_eq!(
            sync.finish_round(now + 1).unwrap().state,
            SyncState::HeaderCurrent
        );
        assert!(
            sync.require_current(CurrencyPolicy {
                now: BlockTime::new(now),
                maximum_tip_age_seconds: 3_600,
                minimum_height: Height::new(1),
                minimum_chainwork: Chainwork::ZERO,
            })
            .is_ok()
        );
    }

    #[test]
    fn equal_work_divergent_tips_fail_closed() {
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let mut sync = test_sync(2, 3, now);
        sync.add_peer(peer(1), 1).unwrap();
        sync.add_peer(peer(2), 1).unwrap();
        let request = sync.begin_round(&[peer(1), peer(2)], now).unwrap();
        sync.submit_headers(
            request.generation,
            peer(1),
            vec![mine(sync.chain().tip(), 1)],
            now,
        )
        .unwrap();
        sync.submit_headers(
            request.generation,
            peer(2),
            vec![mine(sync.chain().tip(), 2)],
            now,
        )
        .unwrap();
        assert!(matches!(
            sync.finish_round(now),
            Err(SyncError::AmbiguousBestChain)
        ));
        assert_eq!(sync.chain().tip().height(), Height::new(0));
        assert_eq!(sync.status().state, SyncState::Degraded);
    }

    #[test]
    fn invalid_candidates_score_and_ban_only_the_bad_peer() {
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let mut sync = test_sync(1, 1, now);
        sync.add_peer(peer(1), 1).unwrap();
        sync.add_peer(peer(2), 0).unwrap();
        let request = sync.begin_round(&[peer(1), peer(2)], now).unwrap();
        let mut invalid = mine(sync.chain().tip(), 1);
        invalid.previous_block = BlockHash::new([9; 32]);
        sync.submit_headers(request.generation, peer(1), vec![invalid], now)
            .unwrap();
        sync.submit_headers(request.generation, peer(2), Vec::new(), now)
            .unwrap();
        assert_eq!(
            sync.finish_round(now).unwrap().state,
            SyncState::HeaderCurrent
        );
        let statuses = sync.peer_statuses();
        assert!(
            statuses
                .iter()
                .find(|status| status.id == peer(1))
                .is_some_and(|status| status.banned)
        );
        assert!(
            statuses
                .iter()
                .find(|status| status.id == peer(2))
                .is_some_and(|status| !status.banned)
        );
    }

    #[test]
    fn rounds_bound_peers_duplicates_generations_and_deadlines() {
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let mut sync = test_sync(1, 3, now);
        sync.add_peer(peer(1), 0).unwrap();
        assert!(matches!(
            sync.add_peer(peer(1), 0),
            Err(SyncError::DuplicatePeer)
        ));
        let request = sync.begin_round(&[peer(1)], now).unwrap();
        assert_eq!(
            request.packet.locator.first().copied(),
            Some(sync.chain().tip().hash())
        );
        assert!(matches!(
            sync.submit_headers(request.generation + 1, peer(1), Vec::new(), now),
            Err(SyncError::StaleRound)
        ));
        sync.submit_headers(request.generation, peer(1), Vec::new(), now)
            .unwrap();
        let rejected_replacement = mine(sync.chain().tip(), 9);
        assert!(matches!(
            sync.submit_headers(request.generation, peer(1), vec![rejected_replacement], now),
            Err(SyncError::DuplicateResponse)
        ));
        assert_eq!(
            sync.finish_round(now).unwrap().state,
            SyncState::HeaderCurrent
        );

        let mut timed = test_sync(1, 3, now);
        timed.add_peer(peer(1), 0).unwrap();
        let request = timed.begin_round(&[peer(1)], now).unwrap();
        assert!(matches!(
            timed.submit_headers(request.generation, peer(1), Vec::new(), now + 11),
            Err(SyncError::RoundExpired)
        ));
        assert!(matches!(
            timed.finish_round(now + 11),
            Err(SyncError::InsufficientResponses)
        ));
        assert_eq!(timed.status().state, SyncState::Degraded);
    }

    #[test]
    fn current_requires_every_selected_response_and_no_advertised_extension() {
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let mut sync = test_sync(1, 3, now);
        sync.add_peer(peer(1), 0).unwrap();
        sync.add_peer(peer(2), 1).unwrap();
        let request = sync.begin_round(&[peer(1), peer(2)], now).unwrap();
        sync.submit_headers(request.generation, peer(1), Vec::new(), now)
            .unwrap();
        assert_eq!(
            sync.finish_round(now).unwrap().state,
            SyncState::HeaderSyncing
        );

        let request = sync.begin_round(&[peer(1), peer(2)], now + 1).unwrap();
        for id in [peer(1), peer(2)] {
            sync.submit_headers(request.generation, id, Vec::new(), now + 1)
                .unwrap();
        }
        assert_eq!(
            sync.finish_round(now + 1).unwrap().state,
            SyncState::HeaderSyncing
        );

        sync.update_peer_height(peer(2), 0).unwrap();
        let request = sync.begin_round(&[peer(1), peer(2)], now + 2).unwrap();
        for id in [peer(1), peer(2)] {
            sync.submit_headers(request.generation, id, Vec::new(), now + 2)
                .unwrap();
        }
        assert_eq!(
            sync.finish_round(now + 2).unwrap().state,
            SyncState::HeaderCurrent
        );
    }

    #[test]
    fn authenticated_chain_resume_requires_fresh_peer_agreement() {
        let now = Network::Regtest.parameters().genesis_time.get() + 100;
        let mut original = test_sync(1, 3, now);
        original.add_peer(peer(1), 1).unwrap();
        let request = original.begin_round(&[peer(1)], now).unwrap();
        let extension = mine(original.chain().tip(), 1);
        original
            .submit_headers(request.generation, peer(1), vec![extension], now)
            .unwrap();
        original.finish_round(now).unwrap();

        let snapshot = original
            .chain()
            .encode_authenticated_snapshot()
            .unwrap();
        let restored_chain = LightChain::decode_authenticated_snapshot(
            &snapshot,
            Network::Regtest,
            hns_light_chain::ChainSnapshotFloor::default(),
        )
        .unwrap();
        let mut resumed = HeaderSync::from_chain(restored_chain, config(1, 3)).unwrap();

        assert_eq!(resumed.chain().tip(), original.chain().tip());
        assert_eq!(resumed.status().state, SyncState::HeaderSyncing);
        assert!(matches!(
            resumed.require_current(CurrencyPolicy {
                now: BlockTime::new(now),
                maximum_tip_age_seconds: 3_600,
                minimum_height: Height::new(1),
                minimum_chainwork: Chainwork::ZERO,
            }),
            Err(SyncError::NotCurrent)
        ));

        resumed.add_peer(peer(2), 1).unwrap();
        let request = resumed.begin_round(&[peer(2)], now + 1).unwrap();
        resumed
            .submit_headers(request.generation, peer(2), Vec::new(), now + 1)
            .unwrap();
        assert_eq!(
            resumed.finish_round(now + 1).unwrap().state,
            SyncState::HeaderCurrent
        );
    }
}
