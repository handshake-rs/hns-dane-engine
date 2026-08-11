#![allow(
    missing_docs,
    reason = "temporary compatibility adapter preserves the existing product API"
)]

use hns_chain::{ChainError, HeaderChain, HeaderCheckpoint, HeaderStore, StoredHeader};
use hns_core::Height;
use hns_core::network::Network;
use hns_core::{BlockHeader, Hash, NameHash, NameHashError};
use hns_p2p::{
    HeaderSyncAction, HeaderSyncSession, MAX_HEADERS, P2pError, Packet, PeerConnection,
    PeerManager, ProofPacket, SqlitePeerStore, VersionPacket, is_allowed_peer_endpoint,
};
use hns_urkel::{ParsedProof, ProofError, ProofKind, ProofVerifier};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use thiserror::Error;

pub const DEFAULT_LOCATOR_LIMIT: usize = 32;
pub const DEFAULT_OUTBOUND_PEERS: usize = 8;
pub const DEFAULT_MAX_HEADER_BATCHES_PER_PEER: usize = 16;
pub const DEFAULT_SYNC_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_PARALLEL_PEER_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const DEFAULT_MALFORMED_BAN_SECONDS: u64 = 24 * 60 * 60;
pub const DEFAULT_PEER_DISCOVERY_TARGET: usize = 64;
pub const DEFAULT_PEER_DISCOVERY_QUERY_PEERS: usize = 8;
pub const DEFAULT_PARALLEL_PEER_PROBES: usize = 0;
pub const DEFAULT_PARALLEL_HEADER_FETCH_PEERS: usize = 1;
pub const DEFAULT_PEER_HEIGHT_REFRESH_INTERVAL_SECONDS: u64 = 0;
const MAX_HSD_NAME_STATE_NAME_BYTES: usize = 63;
const MAX_HSD_NAME_STATE_DATA_BYTES: usize = 512;
const HSD_NAME_STATE_FIXED_TAIL_BYTES: usize = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderBatchResult {
    pub accepted: usize,
    pub best: Option<StoredHeader>,
}

pub struct HeaderSyncCoordinator<S> {
    chain: HeaderChain<S>,
    locator_limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderSyncRunnerConfig {
    pub preferred_peers: usize,
    pub max_header_batches_per_peer: usize,
    pub discover_peers: bool,
    pub peer_discovery_target: usize,
    pub peer_discovery_query_peers: usize,
    pub parallel_peer_probes: usize,
    pub parallel_header_fetch_peers: usize,
    pub parallel_peer_probe_timeout: Duration,
    pub peer_height_refresh_interval: u64,
    pub checkpoint_header_prefetch: Vec<HeaderCheckpoint>,
    pub timeout: Duration,
    pub stop: Hash,
    pub malformed_ban_seconds: u64,
    /// Test/development escape hatch. Production mainnet and testnet sync must leave this false.
    pub allow_unsafe_peer_endpoints: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderPeerSyncResult {
    pub address: SocketAddr,
    pub remote_height: Height,
    pub accepted: usize,
    pub best: Option<StoredHeader>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderPeerFailure {
    pub address: SocketAddr,
    pub stage: HeaderPeerFailureStage,
    pub error: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderPeerFailureStage {
    Connect,
    Handshake,
    Headers,
    Chain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderSyncRunResult {
    pub attempted: usize,
    pub successful: usize,
    pub accepted: usize,
    pub best: Option<StoredHeader>,
    pub failures: Vec<HeaderPeerFailure>,
}

/// Non-authoritative diagnostic progress from a single header-sync run.
///
/// A snapshot is emitted only after a non-empty batch has passed chain
/// validation and the chain store has accepted it. It intentionally contains
/// no peer-advertised target height and must not be used as readiness evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderSyncProgress {
    pub best_height: Option<Height>,
    pub accepted: usize,
}

pub trait HeaderPeerClient {
    fn handshake(&mut self, session: &mut HeaderSyncSession) -> Result<VersionPacket, P2pError>;

    fn request_headers(
        &mut self,
        session: &mut HeaderSyncSession,
        locator: Vec<Hash>,
        stop: Hash,
    ) -> Result<Vec<BlockHeader>, P2pError>;

    fn request_addresses(&mut self) -> Result<Vec<SocketAddr>, P2pError> {
        Ok(Vec::new())
    }
}

pub trait HeaderPeerConnector {
    type Peer: HeaderPeerClient;

    fn connect(
        &self,
        address: SocketAddr,
        network: &Network,
        timeout: Duration,
    ) -> Result<Self::Peer, P2pError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpHeaderPeerConnector;

pub struct HeaderSyncRunner<C> {
    connector: C,
    network: Network,
    local_version: VersionPacket,
    config: HeaderSyncRunnerConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofValidationResult {
    pub root: Hash,
    pub key: Hash,
    pub kind: ProofKind,
    pub value: Option<Vec<u8>>,
}

pub struct ProofSyncCoordinator<V> {
    verifier: V,
    pending: HashSet<(Hash, Hash)>,
}

pub struct ProofScheduler<V, S> {
    coordinator: ProofSyncCoordinator<V>,
    sink: S,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceValueAnchor {
    pub tree_root: Hash,
    pub height: Height,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedResourceValue {
    pub root_name: String,
    pub name_hash: NameHash,
    pub value: Option<Vec<u8>>,
    pub secure: bool,
    pub anchor: Option<ResourceValueAnchor>,
}

impl VerifiedResourceValue {
    pub fn inclusion(root_name: String, name_hash: NameHash, value: Vec<u8>) -> Self {
        Self {
            root_name,
            name_hash,
            value: Some(value),
            secure: true,
            anchor: None,
        }
    }

    pub fn non_inclusion(root_name: String, name_hash: NameHash) -> Self {
        Self {
            root_name,
            name_hash,
            value: None,
            secure: true,
            anchor: None,
        }
    }

    pub fn with_anchor(mut self, tree_root: Hash, height: Height) -> Self {
        self.anchor = Some(ResourceValueAnchor { tree_root, height });
        self
    }
}

pub trait VerifiedResourceValueSink {
    type Error: std::fmt::Display;

    fn insert_verified_resource_value(
        &self,
        value: VerifiedResourceValue,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SyncError {
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
    #[error("p2p error: {0}")]
    P2p(#[from] P2pError),
    #[error("proof error: {0}")]
    Proof(#[from] ProofError),
    #[error("HNS name is invalid: {0}")]
    InvalidName(#[from] NameHashError),
    #[error("verified resource sink failed: {0}")]
    ResourceSink(String),
    #[error("unexpected sync action")]
    UnexpectedAction,
    #[error("proof response was not requested")]
    UnexpectedProof,
    #[error("proof payload does not match requested root or key")]
    ProofMismatch,
    #[error("proof verification failed")]
    UnverifiedProof,
    #[error("verified inclusion proof did not contain a resource value")]
    MissingProofValue,
    #[error("HSD name state value is malformed")]
    MalformedNameStateValue,
}

impl Default for HeaderSyncRunnerConfig {
    fn default() -> Self {
        Self {
            preferred_peers: DEFAULT_OUTBOUND_PEERS,
            max_header_batches_per_peer: DEFAULT_MAX_HEADER_BATCHES_PER_PEER,
            discover_peers: true,
            peer_discovery_target: DEFAULT_PEER_DISCOVERY_TARGET,
            peer_discovery_query_peers: DEFAULT_PEER_DISCOVERY_QUERY_PEERS,
            parallel_peer_probes: DEFAULT_PARALLEL_PEER_PROBES,
            parallel_header_fetch_peers: DEFAULT_PARALLEL_HEADER_FETCH_PEERS,
            parallel_peer_probe_timeout: DEFAULT_PARALLEL_PEER_PROBE_TIMEOUT,
            peer_height_refresh_interval: DEFAULT_PEER_HEIGHT_REFRESH_INTERVAL_SECONDS,
            checkpoint_header_prefetch: Vec::new(),
            timeout: DEFAULT_SYNC_TIMEOUT,
            stop: Hash::ZERO,
            malformed_ban_seconds: DEFAULT_MALFORMED_BAN_SECONDS,
            allow_unsafe_peer_endpoints: false,
        }
    }
}

impl HeaderSyncRunResult {
    pub fn empty() -> Self {
        Self {
            attempted: 0,
            successful: 0,
            accepted: 0,
            best: None,
            failures: Vec::new(),
        }
    }
}

impl HeaderPeerFailureStage {
    pub fn as_str(self) -> &'static str {
        match self {
            HeaderPeerFailureStage::Connect => "connect",
            HeaderPeerFailureStage::Handshake => "handshake",
            HeaderPeerFailureStage::Headers => "headers",
            HeaderPeerFailureStage::Chain => "chain",
        }
    }
}

impl<T: Read + Write> HeaderPeerClient for PeerConnection<T> {
    fn handshake(&mut self, session: &mut HeaderSyncSession) -> Result<VersionPacket, P2pError> {
        PeerConnection::handshake(self, session)
    }

    fn request_headers(
        &mut self,
        session: &mut HeaderSyncSession,
        locator: Vec<Hash>,
        stop: Hash,
    ) -> Result<Vec<BlockHeader>, P2pError> {
        PeerConnection::request_headers(self, session, locator, stop)
    }

    fn request_addresses(&mut self) -> Result<Vec<SocketAddr>, P2pError> {
        PeerConnection::request_addresses(self)
    }
}

impl HeaderPeerConnector for TcpHeaderPeerConnector {
    type Peer = PeerConnection<std::net::TcpStream>;

    fn connect(
        &self,
        address: SocketAddr,
        network: &Network,
        timeout: Duration,
    ) -> Result<Self::Peer, P2pError> {
        PeerConnection::connect(address, network.clone(), timeout)
    }
}

impl<C> HeaderSyncRunner<C> {
    pub fn new(network: Network, connector: C) -> Self {
        Self {
            connector,
            network,
            local_version: VersionPacket::default(),
            config: HeaderSyncRunnerConfig::default(),
        }
    }

    pub fn with_config(network: Network, connector: C, config: HeaderSyncRunnerConfig) -> Self {
        Self {
            connector,
            network,
            local_version: VersionPacket::default(),
            config,
        }
    }

    pub fn with_local_version(mut self, local_version: VersionPacket) -> Self {
        self.local_version = local_version;
        self
    }

    pub fn config(&self) -> &HeaderSyncRunnerConfig {
        &self.config
    }

    pub fn connector(&self) -> &C {
        &self.connector
    }

    fn peer_endpoint_allowed(&self, address: SocketAddr) -> bool {
        self.config.allow_unsafe_peer_endpoints || is_allowed_peer_endpoint(&self.network, address)
    }

    fn eligible_peer_count(&self, peers: &PeerManager) -> usize {
        peers
            .iter()
            .filter(|peer| self.peer_endpoint_allowed(peer.address))
            .count()
    }

    fn select_outbound_peers(
        &self,
        peers: &PeerManager,
        preferred_count: usize,
        now: u64,
    ) -> Vec<SocketAddr> {
        peers
            .select_outbound(peers.len(), now)
            .into_iter()
            .filter(|address| self.peer_endpoint_allowed(*address))
            .take(preferred_count)
            .collect()
    }

    fn select_discovery_peers(
        &self,
        peers: &PeerManager,
        preferred_count: usize,
        now: u64,
        exclude: &HashSet<SocketAddr>,
    ) -> Vec<SocketAddr> {
        peers
            .select_discovery_outbound(peers.len(), now, exclude)
            .into_iter()
            .filter(|address| self.peer_endpoint_allowed(*address))
            .take(preferred_count)
            .collect()
    }

    fn seed_discovered_peers(
        &self,
        peers: &mut PeerManager,
        discovered: impl IntoIterator<Item = SocketAddr>,
    ) -> usize {
        peers.seed(
            discovered
                .into_iter()
                .filter(|address| self.peer_endpoint_allowed(*address)),
        )
    }
}

impl<C: HeaderPeerConnector> HeaderSyncRunner<C> {
    pub fn sync_once<S: HeaderStore>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        now: u64,
    ) -> Result<HeaderSyncRunResult, SyncError> {
        self.sync_once_inner(coordinator, peers, now, None, &mut |_| {})
    }

    fn sync_once_inner<S: HeaderStore>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        now: u64,
        store: Option<&SqlitePeerStore>,
        progress: &mut dyn FnMut(HeaderSyncProgress),
    ) -> Result<HeaderSyncRunResult, SyncError> {
        let outbound = self.select_outbound_peers(peers, self.config.preferred_peers, now);
        let mut attempted_addresses = HashSet::new();
        let mut result = HeaderSyncRunResult::empty();
        let mut progress = HeaderSyncProgressReporter::new(progress);

        for address in outbound {
            attempted_addresses.insert(address);
            result.attempted = result.attempted.saturating_add(1);
            match self.sync_peer(coordinator, peers, address, now, store, &mut progress)? {
                HeaderPeerSyncOutcome::Success(peer_result) => {
                    result.successful = result.successful.saturating_add(1);
                    result.accepted = result.accepted.saturating_add(peer_result.accepted);
                    result.best = peer_result.best;
                }
                HeaderPeerSyncOutcome::Failure(failure) => result.failures.push(failure),
            }
        }

        self.discover_more_peers(peers, now, &attempted_addresses, store)?;

        Ok(result)
    }

    pub fn sync_once_and_persist<S: HeaderStore>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        store: &SqlitePeerStore,
        now: u64,
    ) -> Result<HeaderSyncRunResult, SyncError> {
        self.sync_once_and_persist_inner(coordinator, peers, store, now, &mut |_| {})
    }

    /// Runs one sequential sync and reports validated chain-store advancement.
    pub fn sync_once_and_persist_with_progress<S, P>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        store: &SqlitePeerStore,
        now: u64,
        mut progress: P,
    ) -> Result<HeaderSyncRunResult, SyncError>
    where
        S: HeaderStore,
        P: FnMut(HeaderSyncProgress),
    {
        self.sync_once_and_persist_inner(coordinator, peers, store, now, &mut progress)
    }

    fn sync_once_and_persist_inner<S: HeaderStore>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        store: &SqlitePeerStore,
        now: u64,
        progress: &mut dyn FnMut(HeaderSyncProgress),
    ) -> Result<HeaderSyncRunResult, SyncError> {
        let result = self.sync_once_inner(coordinator, peers, now, Some(store), progress)?;
        store.save_manager(peers)?;
        Ok(result)
    }

    fn sync_peer<S: HeaderStore>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        address: SocketAddr,
        now: u64,
        store: Option<&SqlitePeerStore>,
        progress: &mut HeaderSyncProgressReporter<'_>,
    ) -> Result<HeaderPeerSyncOutcome, SyncError> {
        let mut peer = match self
            .connector
            .connect(address, &self.network, self.config.timeout)
        {
            Ok(peer) => peer,
            Err(error) => {
                peers.record_transient_failure(address);
                return Ok(HeaderPeerSyncOutcome::Failure(HeaderPeerFailure {
                    address,
                    stage: HeaderPeerFailureStage::Connect,
                    error: error.to_string(),
                }));
            }
        };
        let mut session = HeaderSyncSession::new(self.local_version.clone());
        let remote = match peer.handshake(&mut session) {
            Ok(remote) => remote,
            Err(error) => {
                peers.record_transient_failure(address);
                return Ok(HeaderPeerSyncOutcome::Failure(HeaderPeerFailure {
                    address,
                    stage: HeaderPeerFailureStage::Handshake,
                    error: error.to_string(),
                }));
            }
        };
        // The version height is an unauthenticated advisory claim. Do not
        // persist it as currentness evidence until the peer either agrees it
        // is at/below the validated local tip or supplies a useful extension.
        peers.record_connection(address, now);
        if self.config.discover_peers
            && let Ok(discovered) = peer.request_addresses()
        {
            self.seed_discovered_peers(peers, discovered);
            persist_peer_manager(store, peers)?;
        }
        let mut accepted = 0usize;
        let mut best = coordinator.chain().best_header()?;
        if best
            .as_ref()
            .is_some_and(|best_header| remote.height <= best_header.height)
        {
            peers.record_success(address, remote.height, now);
            persist_peer_manager(store, peers)?;
            return Ok(HeaderPeerSyncOutcome::Success(Box::new(
                HeaderPeerSyncResult {
                    address,
                    remote_height: remote.height,
                    accepted,
                    best,
                },
            )));
        }
        let max_batches = self.config.max_header_batches_per_peer.max(1);
        let mut certified_height = remote.height;
        let mut failed_to_extend_claim = false;

        for _ in 0..max_batches {
            let locator = coordinator.locator()?;
            let headers = match peer.request_headers(&mut session, locator, self.config.stop) {
                Ok(headers) => headers,
                Err(error) => {
                    peers.record_transient_failure(address);
                    return Ok(HeaderPeerSyncOutcome::Failure(HeaderPeerFailure {
                        address,
                        stage: HeaderPeerFailureStage::Headers,
                        error: error.to_string(),
                    }));
                }
            };
            let header_count = headers.len();
            if header_count == 0 {
                if let Some(best_height) = best.as_ref().map(|header| header.height)
                    && remote.height > best_height
                {
                    certified_height = best_height;
                    failed_to_extend_claim = true;
                }
                break;
            }

            match coordinator.ingest_headers(headers) {
                Ok(batch) => {
                    accepted = accepted.saturating_add(batch.accepted);
                    progress.report(&batch);
                    best = batch.best;
                    if header_count < MAX_HEADERS || batch.accepted == 0 {
                        if let Some(best_height) = best.as_ref().map(|header| header.height)
                            && remote.height > best_height
                        {
                            certified_height = best_height;
                            failed_to_extend_claim = true;
                        }
                        break;
                    }
                }
                Err(SyncError::Chain(error)) => {
                    record_chain_failure(
                        peers,
                        address,
                        now,
                        &error,
                        self.config.malformed_ban_seconds,
                    );
                    return match error {
                        ChainError::Storage(_) | ChainError::MissingBestHeader => {
                            Err(SyncError::Chain(error))
                        }
                        ChainError::UnknownParent
                        | ChainError::DuplicateHeader
                        | ChainError::InvalidGenesisHeader
                        | ChainError::InvalidDifficultyBits { .. }
                        | ChainError::InvalidDifficultyWindow
                        | ChainError::InvalidProofOfWork
                        | ChainError::InvalidCheckpoint { .. }
                        | ChainError::Pow(_) => {
                            Ok(HeaderPeerSyncOutcome::Failure(HeaderPeerFailure {
                                address,
                                stage: HeaderPeerFailureStage::Chain,
                                error: error.to_string(),
                            }))
                        }
                    };
                }
                Err(error) => return Err(error),
            }
        }

        peers.record_success(address, certified_height, now);
        if failed_to_extend_claim {
            peers.record_stale_tip(address);
        }
        persist_peer_manager(store, peers)?;
        Ok(HeaderPeerSyncOutcome::Success(Box::new(
            HeaderPeerSyncResult {
                address,
                remote_height: remote.height,
                accepted,
                best,
            },
        )))
    }

    fn discover_more_peers(
        &self,
        peers: &mut PeerManager,
        now: u64,
        attempted_addresses: &HashSet<SocketAddr>,
        store: Option<&SqlitePeerStore>,
    ) -> Result<(), SyncError> {
        if !self.config.discover_peers
            || self.eligible_peer_count(peers) >= self.config.peer_discovery_target
            || self.config.peer_discovery_query_peers == 0
        {
            return Ok(());
        }

        let candidates = self.select_discovery_peers(
            peers,
            self.config.peer_discovery_query_peers,
            now,
            attempted_addresses,
        );
        for address in candidates {
            if self.eligible_peer_count(peers) >= self.config.peer_discovery_target {
                break;
            }

            match self
                .connector
                .connect(address, &self.network, self.config.timeout)
            {
                Ok(mut peer) => {
                    let mut session = HeaderSyncSession::new(self.local_version.clone());
                    match peer.handshake(&mut session) {
                        Ok(_remote) => {
                            if let Ok(discovered) = peer.request_addresses() {
                                self.seed_discovered_peers(peers, discovered);
                                persist_peer_manager(store, peers)?;
                            }
                            record_uncorroborated_transport_success(peers, address, now);
                            persist_peer_manager(store, peers)?;
                        }
                        Err(_) => peers.record_transient_failure(address),
                    }
                }
                Err(_) => peers.record_transient_failure(address),
            }
        }
        Ok(())
    }
}

impl HeaderSyncRunner<TcpHeaderPeerConnector> {
    pub fn sync_once_parallel_and_persist<S: HeaderStore>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        store: &SqlitePeerStore,
        now: u64,
    ) -> Result<HeaderSyncRunResult, SyncError> {
        self.sync_once_parallel_and_persist_with_completion_time(
            coordinator,
            peers,
            store,
            now,
            || now,
        )
    }

    /// Runs one parallel sync while allowing the caller to timestamp the final
    /// corroboration immediately before that network phase begins.
    ///
    /// A complete catch-up can span many bounded peer batches. Reusing the
    /// sync-start timestamp for the final observations can therefore publish
    /// evidence which is already near expiry. The ordinary API above retains a
    /// deterministic fixed timestamp for tests and embedders; long-running
    /// browser runtimes should supply a fresh clock through this method.
    pub fn sync_once_parallel_and_persist_with_completion_time<S, F>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        store: &SqlitePeerStore,
        now: u64,
        completion_time: F,
    ) -> Result<HeaderSyncRunResult, SyncError>
    where
        S: HeaderStore,
        F: FnOnce() -> u64,
    {
        self.sync_once_parallel_and_persist_with_completion_time_and_progress(
            coordinator,
            peers,
            store,
            now,
            completion_time,
            |_| {},
        )
    }

    /// Runs one parallel sync and reports validated chain-store advancement.
    ///
    /// The observer runs synchronously after each non-empty batch is committed
    /// to the supplied coordinator's chain store. Snapshots are diagnostic
    /// only: staged mobile callers must continue to publish the completed store
    /// atomically before treating its height as authoritative.
    pub fn sync_once_parallel_and_persist_with_completion_time_and_progress<S, F, P>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        store: &SqlitePeerStore,
        now: u64,
        completion_time: F,
        mut progress: P,
    ) -> Result<HeaderSyncRunResult, SyncError>
    where
        S: HeaderStore,
        F: FnOnce() -> u64,
        P: FnMut(HeaderSyncProgress),
    {
        self.probe_peers_parallel_and_persist(peers, store, now)?;
        let result = if self.config.parallel_header_fetch_peers > 1 {
            let prefetch =
                self.prefetch_checkpoint_header_ranges_and_persist(coordinator, peers, store, now)?;
            self.sync_once_racing_and_persist(
                coordinator,
                peers,
                store,
                now,
                prefetch,
                &mut progress,
            )
        } else {
            self.sync_once_and_persist_inner(coordinator, peers, store, now, &mut progress)
        }?;
        if let Some(validated_tip) = coordinator
            .chain()
            .best_header()?
            .map(|header| header.height)
        {
            let corroboration_started_at = completion_time().max(now);
            self.corroborate_peer_heights_at_tip_parallel_and_persist(
                peers,
                store,
                corroboration_started_at,
                validated_tip,
            )?;
        }
        Ok(result)
    }

    fn prefetch_checkpoint_header_ranges_and_persist<S: HeaderStore>(
        &self,
        coordinator: &HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        store: &SqlitePeerStore,
        now: u64,
    ) -> Result<HeaderCheckpointPrefetchResult, SyncError> {
        let Some(best) = coordinator.chain().best_header()? else {
            return Ok(HeaderCheckpointPrefetchResult {
                attempted: 0,
                successful: 0,
                ranges: Vec::new(),
                failures: Vec::new(),
            });
        };
        let checkpoints = self
            .config
            .checkpoint_header_prefetch
            .iter()
            .copied()
            .filter(|checkpoint| checkpoint.height > best.height)
            .collect::<Vec<_>>();
        if checkpoints.is_empty() {
            return Ok(HeaderCheckpointPrefetchResult {
                attempted: 0,
                successful: 0,
                ranges: Vec::new(),
                failures: Vec::new(),
            });
        }
        let addresses = self.select_outbound_peers(
            peers,
            self.config
                .parallel_header_fetch_peers
                .max(1)
                .min(checkpoints.len()),
            now,
        );
        if addresses.is_empty() {
            return Ok(HeaderCheckpointPrefetchResult {
                attempted: 0,
                successful: 0,
                ranges: Vec::new(),
                failures: Vec::new(),
            });
        }

        let attempted = checkpoints.len();
        let (sender, receiver) = mpsc::channel();
        for (index, checkpoint) in checkpoints.into_iter().enumerate() {
            let sender = sender.clone();
            let address = addresses[index % addresses.len()];
            let network = self.network.clone();
            let local_version = self.local_version.clone();
            let timeout = self.config.timeout;
            thread::spawn(move || {
                let _ = sender.send(request_tcp_checkpoint_header_range(
                    address,
                    network,
                    local_version,
                    timeout,
                    checkpoint,
                ));
            });
        }
        drop(sender);

        let mut successful = 0usize;
        let mut ranges = Vec::new();
        let mut failures = Vec::new();
        for outcome in receiver {
            match outcome {
                HeaderCheckpointPrefetchOutcome::Success { address, range } => {
                    // The staged range is not authoritative until chain
                    // validation accepts it. A handshake claim must not become
                    // currentness evidence merely because bytes were returned.
                    record_uncorroborated_transport_success(peers, address, now);
                    successful = successful.saturating_add(1);
                    ranges.push(range);
                }
                HeaderCheckpointPrefetchOutcome::Empty { address } => {
                    record_uncorroborated_transport_success(peers, address, now);
                    peers.record_stale_tip(address);
                    successful = successful.saturating_add(1);
                }
                HeaderCheckpointPrefetchOutcome::Failure(failure) => {
                    peers.record_transient_failure(failure.address);
                    failures.push(failure);
                }
            }
            persist_peer_manager(Some(store), peers)?;
        }
        ranges.sort_by_key(|range| range.checkpoint.height);

        Ok(HeaderCheckpointPrefetchResult {
            attempted,
            successful,
            ranges,
            failures,
        })
    }

    fn sync_once_racing_and_persist<S: HeaderStore>(
        &self,
        coordinator: &mut HeaderSyncCoordinator<S>,
        peers: &mut PeerManager,
        store: &SqlitePeerStore,
        now: u64,
        prefetch: HeaderCheckpointPrefetchResult,
        progress: &mut dyn FnMut(HeaderSyncProgress),
    ) -> Result<HeaderSyncRunResult, SyncError> {
        let max_batches = self
            .config
            .preferred_peers
            .max(1)
            .saturating_mul(self.config.max_header_batches_per_peer.max(1));
        let mut result = HeaderSyncRunResult {
            attempted: prefetch.attempted,
            successful: prefetch.successful,
            accepted: 0,
            best: None,
            failures: prefetch.failures,
        };
        let mut staged_ranges = prefetch.ranges;
        let mut progress = HeaderSyncProgressReporter::new(progress);
        let checkpoint_context = CheckpointRangeApplyContext {
            store,
            now,
            malformed_ban_seconds: self.config.malformed_ban_seconds,
        };

        for _ in 0..max_batches {
            apply_ready_checkpoint_ranges(
                coordinator,
                peers,
                checkpoint_context,
                &mut staged_ranges,
                &mut result,
                &mut progress,
            )?;
            let candidates = self.select_outbound_peers(
                peers,
                self.config.parallel_header_fetch_peers.max(1),
                now,
            );
            if candidates.is_empty() {
                break;
            }
            let locator = coordinator.locator()?;
            let local_best_height = coordinator
                .chain()
                .best_header()?
                .map(|header| header.height);
            let batch = race_tcp_header_batch(
                candidates,
                self.network.clone(),
                self.local_version.clone(),
                self.config.timeout,
                locator,
                self.config.stop,
                local_best_height,
            );
            result.attempted = result.attempted.saturating_add(1);

            let (address, remote_height, headers) = match batch {
                HeaderRaceOutcome::Success {
                    address,
                    remote_height,
                    headers,
                    skipped,
                    failures,
                } => {
                    record_race_skipped_peers(peers, skipped, now);
                    record_race_failures(peers, failures, &mut result);
                    persist_peer_manager(Some(store), peers)?;
                    (address, remote_height, headers)
                }
                HeaderRaceOutcome::NoUsefulResponse { skipped, failures } => {
                    let had_skipped = !skipped.is_empty();
                    record_race_skipped_peers(peers, skipped, now);
                    record_race_failures(peers, failures, &mut result);
                    if had_skipped {
                        result.successful = result.successful.saturating_add(1);
                    }
                    persist_peer_manager(Some(store), peers)?;
                    break;
                }
            };

            let header_count = headers.len();
            if header_count == 0 {
                let local_height = coordinator
                    .chain()
                    .best_header()?
                    .map(|header| header.height)
                    .unwrap_or(Height(0));
                peers.record_success(address, local_height.min(remote_height), now);
                if remote_height > local_height {
                    peers.record_stale_tip(address);
                }
                persist_peer_manager(Some(store), peers)?;
                result.successful = result.successful.saturating_add(1);
                break;
            }

            match coordinator.ingest_headers(headers) {
                Ok(batch) => {
                    result.successful = result.successful.saturating_add(1);
                    progress.report(&batch);
                    result.accepted = progress.accepted();
                    result.best = batch.best;
                    let validated_height = result
                        .best
                        .as_ref()
                        .map(|header| header.height)
                        .unwrap_or(Height(0));
                    let failed_to_extend_claim = remote_height > validated_height
                        && (header_count < MAX_HEADERS || batch.accepted == 0);
                    peers.record_success(
                        address,
                        if failed_to_extend_claim {
                            validated_height
                        } else {
                            remote_height
                        },
                        now,
                    );
                    if failed_to_extend_claim {
                        peers.record_stale_tip(address);
                    }
                    persist_peer_manager(Some(store), peers)?;
                    if header_count < MAX_HEADERS || batch.accepted == 0 {
                        break;
                    }
                    apply_ready_checkpoint_ranges(
                        coordinator,
                        peers,
                        checkpoint_context,
                        &mut staged_ranges,
                        &mut result,
                        &mut progress,
                    )?;
                }
                Err(SyncError::Chain(error)) => {
                    record_chain_failure(
                        peers,
                        address,
                        now,
                        &error,
                        self.config.malformed_ban_seconds,
                    );
                    persist_peer_manager(Some(store), peers)?;
                    return match error {
                        ChainError::Storage(_) | ChainError::MissingBestHeader => {
                            Err(SyncError::Chain(error))
                        }
                        ChainError::UnknownParent
                        | ChainError::DuplicateHeader
                        | ChainError::InvalidGenesisHeader
                        | ChainError::InvalidDifficultyBits { .. }
                        | ChainError::InvalidDifficultyWindow
                        | ChainError::InvalidProofOfWork
                        | ChainError::InvalidCheckpoint { .. }
                        | ChainError::Pow(_) => {
                            result.failures.push(HeaderPeerFailure {
                                address,
                                stage: HeaderPeerFailureStage::Chain,
                                error: error.to_string(),
                            });
                            Ok(result)
                        }
                    };
                }
                Err(error) => return Err(error),
            }
        }

        apply_ready_checkpoint_ranges(
            coordinator,
            peers,
            checkpoint_context,
            &mut staged_ranges,
            &mut result,
            &mut progress,
        )?;
        store.save_manager(peers)?;
        Ok(result)
    }

    pub fn probe_peers_parallel_and_persist(
        &self,
        peers: &mut PeerManager,
        store: &SqlitePeerStore,
        now: u64,
    ) -> Result<usize, SyncError> {
        let refresh_due =
            peer_height_refresh_due(peers, now, self.config.peer_height_refresh_interval);
        if !self.config.discover_peers
            || self.config.parallel_peer_probes == 0
            || (peers.len() >= self.config.peer_discovery_target
                && peers.iter().any(|peer| peer.last_height.0 > 0)
                && !refresh_due)
        {
            return Ok(0);
        }

        let candidates = if refresh_due {
            self.select_discovery_peers(
                peers,
                self.config.parallel_peer_probes,
                now,
                &HashSet::new(),
            )
        } else {
            self.select_outbound_peers(peers, self.config.parallel_peer_probes, now)
        };
        if candidates.len() <= 1 {
            return Ok(0);
        }

        thread::scope(|scope| -> Result<usize, SyncError> {
            let (sender, receiver) = mpsc::channel();
            for address in candidates {
                let sender = sender.clone();
                let network = self.network.clone();
                let local_version = self.local_version.clone();
                let timeout = self
                    .config
                    .parallel_peer_probe_timeout
                    .min(self.config.timeout);
                scope.spawn(move || {
                    let _ = sender.send(probe_tcp_header_peer(
                        address,
                        network,
                        local_version,
                        timeout,
                    ));
                });
            }
            drop(sender);

            let mut successful = 0usize;
            for result in receiver {
                match result {
                    ParallelPeerProbe::Success {
                        address,
                        remote_height: _,
                        discovered,
                    } => {
                        record_uncorroborated_transport_success(peers, address, now);
                        self.seed_discovered_peers(peers, discovered);
                        successful = successful.saturating_add(1);
                    }
                    ParallelPeerProbe::Failure(failure) => {
                        peers.record_transient_failure(failure.address);
                    }
                }
                persist_peer_manager(Some(store), peers)?;
            }
            Ok(successful)
        })
    }

    fn corroborate_peer_heights_at_tip_parallel_and_persist(
        &self,
        peers: &mut PeerManager,
        store: &SqlitePeerStore,
        now: u64,
        validated_tip: Height,
    ) -> Result<usize, SyncError> {
        let candidates = self.select_outbound_peers(
            peers,
            self.config
                .parallel_peer_probes
                .max(self.config.parallel_header_fetch_peers)
                .max(3),
            now,
        );
        if candidates.is_empty() {
            return Ok(0);
        }

        thread::scope(|scope| -> Result<usize, SyncError> {
            let (sender, receiver) = mpsc::channel();
            for address in candidates {
                let sender = sender.clone();
                let network = self.network.clone();
                let local_version = self.local_version.clone();
                let timeout = self
                    .config
                    .parallel_peer_probe_timeout
                    .min(self.config.timeout);
                scope.spawn(move || {
                    let _ = sender.send(probe_tcp_header_peer(
                        address,
                        network,
                        local_version,
                        timeout,
                    ));
                });
            }
            drop(sender);

            let mut corroborated = 0usize;
            for result in receiver {
                match result {
                    ParallelPeerProbe::Success {
                        address,
                        remote_height,
                        discovered,
                    } => {
                        if remote_height <= validated_tip {
                            // A peer claim at or below a PoW-validated local tip
                            // cannot force the authority target forward. Diverse
                            // repetitions of this observation establish that
                            // the newly synced tip is current.
                            peers.record_success(address, remote_height, now);
                            corroborated = corroborated.saturating_add(1);
                        } else {
                            // A version-only claim above the validated tip is
                            // not target evidence. The next sync must obtain and
                            // validate the missing header extension.
                            record_uncorroborated_transport_success(peers, address, now);
                        }
                        self.seed_discovered_peers(peers, discovered);
                    }
                    ParallelPeerProbe::Failure(failure) => {
                        peers.record_transient_failure(failure.address);
                    }
                }
                persist_peer_manager(Some(store), peers)?;
            }
            Ok(corroborated)
        })
    }
}

fn peer_height_refresh_due(peers: &PeerManager, now: u64, refresh_interval: u64) -> bool {
    if refresh_interval == 0 {
        return false;
    }
    let cutoff = now.saturating_sub(refresh_interval);
    !peers.iter().any(|peer| {
        peer.last_height.0 > 0
            && peer
                .last_height_observed_at
                .is_some_and(|seen_at| seen_at >= cutoff)
    })
}

enum ParallelPeerProbe {
    Success {
        address: SocketAddr,
        remote_height: Height,
        discovered: Vec<SocketAddr>,
    },
    Failure(HeaderPeerFailure),
}

enum HeaderRaceOutcome {
    Success {
        address: SocketAddr,
        remote_height: Height,
        headers: Vec<BlockHeader>,
        skipped: Vec<HeaderRaceSkipped>,
        failures: Vec<HeaderPeerFailure>,
    },
    NoUsefulResponse {
        skipped: Vec<HeaderRaceSkipped>,
        failures: Vec<HeaderPeerFailure>,
    },
}

struct HeaderRaceSkipped {
    address: SocketAddr,
    certified_height: Height,
    failed_to_extend_claim: bool,
}

struct HeaderCheckpointPrefetchResult {
    attempted: usize,
    successful: usize,
    ranges: Vec<PrefetchedHeaderRange>,
    failures: Vec<HeaderPeerFailure>,
}

struct PrefetchedHeaderRange {
    address: SocketAddr,
    checkpoint: HeaderCheckpoint,
    headers: Vec<BlockHeader>,
}

struct HeaderSyncProgressReporter<'a> {
    accepted: usize,
    callback: &'a mut dyn FnMut(HeaderSyncProgress),
}

impl<'a> HeaderSyncProgressReporter<'a> {
    fn new(callback: &'a mut dyn FnMut(HeaderSyncProgress)) -> Self {
        Self {
            accepted: 0,
            callback,
        }
    }

    fn report(&mut self, batch: &HeaderBatchResult) {
        self.accepted = self.accepted.saturating_add(batch.accepted);
        if batch.accepted == 0 {
            return;
        }

        (self.callback)(HeaderSyncProgress {
            best_height: batch.best.as_ref().map(|header| header.height),
            accepted: self.accepted,
        });
    }

    fn accepted(&self) -> usize {
        self.accepted
    }
}

#[derive(Clone, Copy)]
struct CheckpointRangeApplyContext<'a> {
    store: &'a SqlitePeerStore,
    now: u64,
    malformed_ban_seconds: u64,
}

enum HeaderRacePeerOutcome {
    Success {
        address: SocketAddr,
        remote_height: Height,
        headers: Vec<BlockHeader>,
    },
    Failure(HeaderPeerFailure),
}

enum HeaderCheckpointPrefetchOutcome {
    Success {
        address: SocketAddr,
        range: PrefetchedHeaderRange,
    },
    Empty {
        address: SocketAddr,
    },
    Failure(HeaderPeerFailure),
}

fn race_tcp_header_batch(
    addresses: Vec<SocketAddr>,
    network: Network,
    local_version: VersionPacket,
    timeout: Duration,
    locator: Vec<Hash>,
    stop: Hash,
    local_best_height: Option<Height>,
) -> HeaderRaceOutcome {
    let count = addresses.len();
    let (sender, receiver) = mpsc::channel();
    for address in addresses {
        let sender = sender.clone();
        let network = network.clone();
        let local_version = local_version.clone();
        let locator = locator.clone();
        thread::spawn(move || {
            let _ = sender.send(request_tcp_header_batch(
                address,
                network,
                local_version,
                timeout,
                locator,
                stop,
            ));
        });
    }
    drop(sender);

    let mut failures = Vec::new();
    let mut skipped = Vec::new();
    for _ in 0..count {
        match receiver.recv() {
            Ok(HeaderRacePeerOutcome::Success {
                address,
                remote_height,
                headers,
            }) => {
                if local_best_height.is_some_and(|height| remote_height <= height)
                    || headers.is_empty()
                {
                    let local_height = local_best_height.unwrap_or(Height(0));
                    let failed_to_extend_claim = headers.is_empty() && remote_height > local_height;
                    skipped.push(HeaderRaceSkipped {
                        address,
                        certified_height: if failed_to_extend_claim {
                            local_height
                        } else {
                            remote_height
                        },
                        failed_to_extend_claim,
                    });
                    continue;
                }
                return HeaderRaceOutcome::Success {
                    address,
                    remote_height,
                    headers,
                    skipped,
                    failures,
                };
            }
            Ok(HeaderRacePeerOutcome::Failure(failure)) => failures.push(failure),
            Err(_) => break,
        }
    }
    HeaderRaceOutcome::NoUsefulResponse { skipped, failures }
}

fn request_tcp_header_batch(
    address: SocketAddr,
    network: Network,
    local_version: VersionPacket,
    timeout: Duration,
    locator: Vec<Hash>,
    stop: Hash,
) -> HeaderRacePeerOutcome {
    let mut peer = match PeerConnection::connect(address, network, timeout) {
        Ok(peer) => peer,
        Err(error) => {
            return HeaderRacePeerOutcome::Failure(HeaderPeerFailure {
                address,
                stage: HeaderPeerFailureStage::Connect,
                error: error.to_string(),
            });
        }
    };
    let mut session = HeaderSyncSession::new(local_version);
    let remote = match peer.handshake(&mut session) {
        Ok(remote) => remote,
        Err(error) => {
            return HeaderRacePeerOutcome::Failure(HeaderPeerFailure {
                address,
                stage: HeaderPeerFailureStage::Handshake,
                error: error.to_string(),
            });
        }
    };
    let headers = match peer.request_headers(&mut session, locator, stop) {
        Ok(headers) => headers,
        Err(error) => {
            return HeaderRacePeerOutcome::Failure(HeaderPeerFailure {
                address,
                stage: HeaderPeerFailureStage::Headers,
                error: error.to_string(),
            });
        }
    };
    HeaderRacePeerOutcome::Success {
        address,
        remote_height: remote.height,
        headers,
    }
}

fn request_tcp_checkpoint_header_range(
    address: SocketAddr,
    network: Network,
    local_version: VersionPacket,
    timeout: Duration,
    checkpoint: HeaderCheckpoint,
) -> HeaderCheckpointPrefetchOutcome {
    let mut peer = match PeerConnection::connect(address, network, timeout) {
        Ok(peer) => peer,
        Err(error) => {
            return HeaderCheckpointPrefetchOutcome::Failure(HeaderPeerFailure {
                address,
                stage: HeaderPeerFailureStage::Connect,
                error: error.to_string(),
            });
        }
    };
    let mut session = HeaderSyncSession::new(local_version);
    let _remote = match peer.handshake(&mut session) {
        Ok(remote) => remote,
        Err(error) => {
            return HeaderCheckpointPrefetchOutcome::Failure(HeaderPeerFailure {
                address,
                stage: HeaderPeerFailureStage::Handshake,
                error: error.to_string(),
            });
        }
    };
    let headers = match peer.request_headers(&mut session, vec![checkpoint.hash], Hash::ZERO) {
        Ok(headers) => headers,
        Err(error) => {
            return HeaderCheckpointPrefetchOutcome::Failure(HeaderPeerFailure {
                address,
                stage: HeaderPeerFailureStage::Headers,
                error: error.to_string(),
            });
        }
    };
    if headers.is_empty() {
        return HeaderCheckpointPrefetchOutcome::Empty { address };
    }
    if headers
        .first()
        .is_none_or(|header| header.prev_block != checkpoint.hash)
    {
        return HeaderCheckpointPrefetchOutcome::Failure(HeaderPeerFailure {
            address,
            stage: HeaderPeerFailureStage::Headers,
            error: "checkpoint header range did not start after requested locator".to_owned(),
        });
    }

    HeaderCheckpointPrefetchOutcome::Success {
        address,
        range: PrefetchedHeaderRange {
            address,
            checkpoint,
            headers,
        },
    }
}

fn record_race_skipped_peers(peers: &mut PeerManager, skipped: Vec<HeaderRaceSkipped>, now: u64) {
    for peer in skipped {
        peers.record_success(peer.address, peer.certified_height, now);
        if peer.failed_to_extend_claim {
            peers.record_stale_tip(peer.address);
        }
    }
}

fn record_uncorroborated_transport_success(peers: &mut PeerManager, address: SocketAddr, now: u64) {
    // A successful version/GetAddr exchange proves liveness, not remote chain
    // height. Clear any prior advisory height so refreshing transport metadata
    // cannot make an unvalidated claim fresh currentness evidence.
    peers.clear_observed_height(address);
    peers.record_transport_success(address, now);
}

fn record_race_failures(
    peers: &mut PeerManager,
    failures: Vec<HeaderPeerFailure>,
    result: &mut HeaderSyncRunResult,
) {
    for failure in failures {
        peers.record_transient_failure(failure.address);
        result.failures.push(failure);
    }
}

fn apply_ready_checkpoint_ranges<S: HeaderStore>(
    coordinator: &mut HeaderSyncCoordinator<S>,
    peers: &mut PeerManager,
    context: CheckpointRangeApplyContext<'_>,
    staged_ranges: &mut Vec<PrefetchedHeaderRange>,
    result: &mut HeaderSyncRunResult,
    progress: &mut HeaderSyncProgressReporter<'_>,
) -> Result<bool, SyncError> {
    let mut applied_any = false;

    while let Some(index) = staged_ranges.iter().position(|range| {
        range
            .headers
            .first()
            .is_some_and(|header| coordinator.chain().get_header(header.prev_block).is_some())
    }) {
        let range = staged_ranges.remove(index);
        let address = range.address;
        match coordinator.ingest_headers(range.headers) {
            Ok(batch) => {
                progress.report(&batch);
                result.accepted = progress.accepted();
                result.best = batch.best;
                applied_any = true;
            }
            Err(SyncError::Chain(error)) => {
                record_chain_failure(
                    peers,
                    address,
                    context.now,
                    &error,
                    context.malformed_ban_seconds,
                );
                persist_peer_manager(Some(context.store), peers)?;
                match error {
                    ChainError::Storage(_) | ChainError::MissingBestHeader => {
                        return Err(SyncError::Chain(error));
                    }
                    ChainError::UnknownParent
                    | ChainError::DuplicateHeader
                    | ChainError::InvalidGenesisHeader
                    | ChainError::InvalidDifficultyBits { .. }
                    | ChainError::InvalidDifficultyWindow
                    | ChainError::InvalidProofOfWork
                    | ChainError::InvalidCheckpoint { .. }
                    | ChainError::Pow(_) => {
                        result.failures.push(HeaderPeerFailure {
                            address,
                            stage: HeaderPeerFailureStage::Chain,
                            error: error.to_string(),
                        });
                    }
                }
            }
            Err(error) => return Err(error),
        }
    }

    Ok(applied_any)
}

fn probe_tcp_header_peer(
    address: SocketAddr,
    network: Network,
    local_version: VersionPacket,
    timeout: Duration,
) -> ParallelPeerProbe {
    let mut peer = match PeerConnection::connect(address, network, timeout) {
        Ok(peer) => peer,
        Err(error) => {
            return ParallelPeerProbe::Failure(HeaderPeerFailure {
                address,
                stage: HeaderPeerFailureStage::Connect,
                error: error.to_string(),
            });
        }
    };
    let mut session = HeaderSyncSession::new(local_version);
    let remote = match peer.handshake(&mut session) {
        Ok(remote) => remote,
        Err(error) => {
            return ParallelPeerProbe::Failure(HeaderPeerFailure {
                address,
                stage: HeaderPeerFailureStage::Handshake,
                error: error.to_string(),
            });
        }
    };
    let discovered = peer.request_addresses().unwrap_or_default();
    ParallelPeerProbe::Success {
        address,
        remote_height: remote.height,
        discovered,
    }
}

enum HeaderPeerSyncOutcome {
    Success(Box<HeaderPeerSyncResult>),
    Failure(HeaderPeerFailure),
}

impl<S: HeaderStore> HeaderSyncCoordinator<S> {
    pub fn new(chain: HeaderChain<S>) -> Self {
        Self {
            chain,
            locator_limit: DEFAULT_LOCATOR_LIMIT,
        }
    }

    pub fn with_locator_limit(chain: HeaderChain<S>, locator_limit: usize) -> Self {
        Self {
            chain,
            locator_limit,
        }
    }

    pub fn chain(&self) -> &HeaderChain<S> {
        &self.chain
    }

    pub fn chain_mut(&mut self) -> &mut HeaderChain<S> {
        &mut self.chain
    }

    pub fn into_chain(self) -> HeaderChain<S> {
        self.chain
    }

    pub fn ingest_action(
        &mut self,
        action: HeaderSyncAction,
    ) -> Result<HeaderBatchResult, SyncError> {
        match action {
            HeaderSyncAction::Headers(headers) => self.ingest_headers(headers),
            _ => Err(SyncError::UnexpectedAction),
        }
    }

    pub fn ingest_headers(
        &mut self,
        headers: Vec<BlockHeader>,
    ) -> Result<HeaderBatchResult, SyncError> {
        let accepted = self.chain.insert_headers(headers)?.len();

        Ok(HeaderBatchResult {
            accepted,
            best: self.chain.best_header()?,
        })
    }

    pub fn locator(&self) -> Result<Vec<Hash>, SyncError> {
        self.locator_with_limit(self.locator_limit)
    }

    pub fn locator_with_limit(&self, limit: usize) -> Result<Vec<Hash>, SyncError> {
        let Some(mut current) = self.chain.best_header()? else {
            return Ok(Vec::new());
        };
        let mut locator = Vec::new();
        let mut step = 1usize;

        while locator.len() < limit {
            locator.push(current.hash);
            if current.height.0 == 0 {
                break;
            }

            for _ in 0..step {
                if current.height.0 == 0 {
                    break;
                }

                current = self
                    .chain
                    .get_header(current.header.prev_block)
                    .ok_or(ChainError::UnknownParent)?;
            }

            if locator.len() >= 10 {
                step = step.saturating_mul(2);
            }
        }

        Ok(locator)
    }

    pub fn request_next_headers(
        &self,
        session: &mut HeaderSyncSession,
        stop: Hash,
    ) -> Result<HeaderSyncAction, SyncError> {
        Ok(session.request_headers(self.locator()?, stop)?)
    }
}

impl<V: ProofVerifier> ProofSyncCoordinator<V> {
    pub fn new(verifier: V) -> Self {
        Self {
            verifier,
            pending: HashSet::new(),
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn track_request(&mut self, root: Hash, key: Hash) {
        self.pending.insert((root, key));
    }

    pub fn forget_request(&mut self, root: Hash, key: Hash) -> bool {
        self.pending.remove(&(root, key))
    }

    pub fn request_proof(
        &mut self,
        session: &mut HeaderSyncSession,
        root: Hash,
        key: Hash,
    ) -> HeaderSyncAction {
        let action = session.request_proof(root, key);
        if matches!(action, HeaderSyncAction::Send(Packet::GetProof(_))) {
            self.track_request(root, key);
        }
        action
    }

    pub fn ingest_action(
        &mut self,
        action: HeaderSyncAction,
    ) -> Result<ProofValidationResult, SyncError> {
        match action {
            HeaderSyncAction::Proof(proof) => self.ingest_proof(proof),
            _ => Err(SyncError::UnexpectedAction),
        }
    }

    pub fn ingest_proof(
        &mut self,
        packet: ProofPacket,
    ) -> Result<ProofValidationResult, SyncError> {
        if !self.pending.remove(&(packet.root, packet.key)) {
            return Err(SyncError::UnexpectedProof);
        }

        let proof =
            ParsedProof::parse_for_key(&packet.proof, packet.root, NameHash::new(packet.key))?;
        if proof.root != packet.root || proof.name_hash.as_hash() != packet.key {
            return Err(SyncError::ProofMismatch);
        }

        if !self.verifier.verify(&proof, packet.root)? {
            return Err(SyncError::UnverifiedProof);
        }

        Ok(ProofValidationResult {
            root: packet.root,
            key: packet.key,
            kind: proof.kind,
            value: proof.value().map(<[u8]>::to_vec),
        })
    }
}

impl<V: ProofVerifier, S: VerifiedResourceValueSink> ProofScheduler<V, S> {
    pub fn new(verifier: V, sink: S) -> Self {
        Self {
            coordinator: ProofSyncCoordinator::new(verifier),
            sink,
        }
    }

    pub fn with_coordinator(coordinator: ProofSyncCoordinator<V>, sink: S) -> Self {
        Self { coordinator, sink }
    }

    pub fn pending_len(&self) -> usize {
        self.coordinator.pending_len()
    }

    pub fn coordinator(&self) -> &ProofSyncCoordinator<V> {
        &self.coordinator
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn into_parts(self) -> (ProofSyncCoordinator<V>, S) {
        (self.coordinator, self.sink)
    }

    pub fn request_and_store<T: Read + Write>(
        &mut self,
        peer: &mut PeerConnection<T>,
        session: &mut HeaderSyncSession,
        root_name: &str,
        root: Hash,
    ) -> Result<ProofValidationResult, SyncError> {
        let name_hash = NameHash::from_name(root_name)?;
        self.request_hash_and_store_with_height(peer, session, root_name, root, name_hash, None)
    }

    pub fn request_and_store_at_height<T: Read + Write>(
        &mut self,
        peer: &mut PeerConnection<T>,
        session: &mut HeaderSyncSession,
        root_name: &str,
        root: Hash,
        proof_height: Height,
    ) -> Result<ProofValidationResult, SyncError> {
        let name_hash = NameHash::from_name(root_name)?;
        self.request_hash_and_store_with_height(
            peer,
            session,
            root_name,
            root,
            name_hash,
            Some(proof_height),
        )
    }

    pub fn request_hash_and_store<T: Read + Write>(
        &mut self,
        peer: &mut PeerConnection<T>,
        session: &mut HeaderSyncSession,
        root_name: &str,
        root: Hash,
        name_hash: NameHash,
    ) -> Result<ProofValidationResult, SyncError> {
        self.request_hash_and_store_with_height(peer, session, root_name, root, name_hash, None)
    }

    pub fn request_hash_and_store_at_height<T: Read + Write>(
        &mut self,
        peer: &mut PeerConnection<T>,
        session: &mut HeaderSyncSession,
        root_name: &str,
        root: Hash,
        name_hash: NameHash,
        proof_height: Height,
    ) -> Result<ProofValidationResult, SyncError> {
        self.request_hash_and_store_with_height(
            peer,
            session,
            root_name,
            root,
            name_hash,
            Some(proof_height),
        )
    }

    fn request_hash_and_store_with_height<T: Read + Write>(
        &mut self,
        peer: &mut PeerConnection<T>,
        session: &mut HeaderSyncSession,
        root_name: &str,
        root: Hash,
        name_hash: NameHash,
        proof_height: Option<Height>,
    ) -> Result<ProofValidationResult, SyncError> {
        let key = name_hash.as_hash();
        match self.coordinator.request_proof(session, root, key) {
            HeaderSyncAction::Send(packet) => {
                if let Err(error) = peer.send_packet(&packet) {
                    self.coordinator.forget_request(root, key);
                    return Err(error.into());
                }
            }
            HeaderSyncAction::Disconnect(reason) => {
                return Err(SyncError::P2p(P2pError::SessionDisconnected(reason)));
            }
            HeaderSyncAction::Ready | HeaderSyncAction::Headers(_) | HeaderSyncAction::Proof(_) => {
                return Err(SyncError::UnexpectedAction);
            }
        }

        loop {
            let packet = match peer.receive_packet() {
                Ok(packet) => packet,
                Err(error) => {
                    self.coordinator.forget_request(root, key);
                    return Err(error.into());
                }
            };

            for action in session.on_packet(packet) {
                match action {
                    HeaderSyncAction::Proof(proof) => {
                        let result = self.coordinator.ingest_proof(proof)?;
                        let mut verified =
                            verified_resource_value(root_name.to_owned(), name_hash, &result)?;
                        if let Some(proof_height) = proof_height {
                            verified = verified.with_anchor(result.root, proof_height);
                        }
                        self.sink
                            .insert_verified_resource_value(verified)
                            .map_err(|error| SyncError::ResourceSink(error.to_string()))?;
                        return Ok(result);
                    }
                    HeaderSyncAction::Send(packet) => {
                        if let Err(error) = peer.send_packet(&packet) {
                            self.coordinator.forget_request(root, key);
                            return Err(error.into());
                        }
                    }
                    HeaderSyncAction::Disconnect(reason) => {
                        self.coordinator.forget_request(root, key);
                        return Err(SyncError::P2p(P2pError::SessionDisconnected(reason)));
                    }
                    HeaderSyncAction::Ready | HeaderSyncAction::Headers(_) => {
                        self.coordinator.forget_request(root, key);
                        return Err(SyncError::UnexpectedAction);
                    }
                }
            }
        }
    }
}

fn record_chain_failure(
    peers: &mut PeerManager,
    address: SocketAddr,
    now: u64,
    error: &ChainError,
    malformed_ban_seconds: u64,
) {
    match error {
        ChainError::InvalidGenesisHeader
        | ChainError::InvalidDifficultyBits { .. }
        | ChainError::InvalidDifficultyWindow
        | ChainError::InvalidProofOfWork
        | ChainError::InvalidCheckpoint { .. }
        | ChainError::Pow(_) => peers.record_malformed(address, now, malformed_ban_seconds),
        ChainError::UnknownParent | ChainError::DuplicateHeader => peers.record_stale_tip(address),
        ChainError::MissingBestHeader | ChainError::Storage(_) => {
            peers.record_transient_failure(address)
        }
    }
}

fn persist_peer_manager(
    store: Option<&SqlitePeerStore>,
    peers: &PeerManager,
) -> Result<(), SyncError> {
    if let Some(store) = store {
        store.save_manager(peers)?;
    }
    Ok(())
}

fn verified_resource_value(
    root_name: String,
    name_hash: NameHash,
    result: &ProofValidationResult,
) -> Result<VerifiedResourceValue, SyncError> {
    match result.kind {
        ProofKind::Inclusion => {
            let value = result.value.clone().ok_or(SyncError::MissingProofValue)?;
            let resource_value = extract_name_state_resource_value(&root_name, &value)?;
            Ok(VerifiedResourceValue::inclusion(
                root_name,
                name_hash,
                resource_value,
            ))
        }
        ProofKind::NonInclusion => Ok(VerifiedResourceValue::non_inclusion(root_name, name_hash)),
    }
}

fn extract_name_state_resource_value(root_name: &str, value: &[u8]) -> Result<Vec<u8>, SyncError> {
    let name_len = usize::from(*value.first().ok_or(SyncError::MalformedNameStateValue)?);
    if name_len > MAX_HSD_NAME_STATE_NAME_BYTES {
        return Err(SyncError::MalformedNameStateValue);
    }

    let name_start = 1usize;
    let name_end = name_start
        .checked_add(name_len)
        .ok_or(SyncError::MalformedNameStateValue)?;
    let data_len_start = name_end;
    let data_len_end = data_len_start
        .checked_add(2)
        .ok_or(SyncError::MalformedNameStateValue)?;
    if value.len() < data_len_end {
        return Err(SyncError::MalformedNameStateValue);
    }
    if &value[name_start..name_end] != root_name.as_bytes() {
        return Err(SyncError::ProofMismatch);
    }

    let data_len = usize::from(u16::from_le_bytes([
        value[data_len_start],
        value[data_len_start + 1],
    ]));
    if data_len > MAX_HSD_NAME_STATE_DATA_BYTES {
        return Err(SyncError::MalformedNameStateValue);
    }

    let data_start = data_len_end;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(SyncError::MalformedNameStateValue)?;
    let min_end = data_end
        .checked_add(HSD_NAME_STATE_FIXED_TAIL_BYTES)
        .ok_or(SyncError::MalformedNameStateValue)?;
    if value.len() < min_end {
        return Err(SyncError::MalformedNameStateValue);
    }

    Ok(value[data_start..data_end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_chain::DifficultyPolicy;
    use hns_chain::MemoryHeaderStore;
    use hns_core::network;
    use hns_core::pow::verify_pow;
    use hns_p2p::{
        AddrPacket, HeadersPacket, NetAddress, Packet, PeerConnection, SERVICE_NETWORK,
        VersionPacket,
    };
    use hns_urkel::{FailClosedProofVerifier, ProofKind};
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[derive(Default)]
    struct MemoryResourceSink {
        values: RefCell<HashMap<(String, NameHash), VerifiedResourceValue>>,
    }

    impl MemoryResourceSink {
        fn get(&self, root_name: &str, name_hash: NameHash) -> Option<VerifiedResourceValue> {
            self.values
                .borrow()
                .get(&(root_name.to_owned(), name_hash))
                .cloned()
        }
    }

    impl VerifiedResourceValueSink for &MemoryResourceSink {
        type Error = std::convert::Infallible;

        fn insert_verified_resource_value(
            &self,
            value: VerifiedResourceValue,
        ) -> Result<(), Self::Error> {
            self.values
                .borrow_mut()
                .insert((value.root_name.clone(), value.name_hash), value);
            Ok(())
        }
    }

    fn permissive_runner_config() -> HeaderSyncRunnerConfig {
        HeaderSyncRunnerConfig {
            allow_unsafe_peer_endpoints: true,
            ..HeaderSyncRunnerConfig::default()
        }
    }

    #[test]
    fn empty_batch_keeps_best_tip() {
        let mut coordinator = seeded_coordinator();
        let best = coordinator.chain().best_header().unwrap();

        assert_eq!(
            coordinator.ingest_headers(Vec::new()).unwrap(),
            HeaderBatchResult { accepted: 0, best },
        );
    }

    #[test]
    fn duplicate_headers_are_successful_noops() {
        let mut coordinator = seeded_coordinator();
        let genesis = BlockHeader::mainnet_genesis();
        let best = coordinator.chain().best_header().unwrap();

        assert_eq!(
            coordinator.ingest_headers(vec![genesis]).unwrap(),
            HeaderBatchResult { accepted: 0, best },
        );
    }

    #[test]
    fn duplicate_headers_inside_batch_do_not_abort_progress() {
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let child = low_difficulty_child(&genesis);

        let result = coordinator
            .ingest_headers(vec![child.clone(), child])
            .unwrap();

        assert_eq!(result.accepted, 1);
        assert_eq!(result.best.unwrap().height, Height(1));
    }

    #[test]
    fn unexpected_action_is_rejected() {
        let mut coordinator = seeded_coordinator();

        assert_eq!(
            coordinator
                .ingest_action(HeaderSyncAction::Ready)
                .unwrap_err(),
            SyncError::UnexpectedAction,
        );
    }

    #[test]
    fn unknown_parent_batch_is_rejected() {
        let mut coordinator = seeded_coordinator();
        let mut orphan = BlockHeader::mainnet_genesis();
        orphan.nonce = 1;

        assert_eq!(
            coordinator
                .ingest_action(HeaderSyncAction::Headers(vec![orphan]))
                .unwrap_err(),
            SyncError::Chain(ChainError::UnknownParent),
        );
    }

    #[test]
    fn invalid_pow_batch_is_rejected() {
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let mut child = BlockHeader::mainnet_genesis();
        child.prev_block = genesis.hash;
        child.bits = 0x01010000;

        assert_eq!(
            coordinator.ingest_headers(vec![child]).unwrap_err(),
            SyncError::Chain(ChainError::InvalidProofOfWork),
        );
    }

    #[test]
    fn locator_starts_from_best_tip() {
        let coordinator = seeded_coordinator();
        let best = coordinator.chain().best_header().unwrap().unwrap();

        assert_eq!(coordinator.locator().unwrap(), vec![best.hash]);
    }

    #[test]
    fn header_sync_runner_requests_headers_and_persists_peer_state() {
        let path = temp_db_path("sync-peers");
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let child = low_difficulty_child(&genesis);
        let address: std::net::SocketAddr = "127.0.0.1:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::headers(Height(1), vec![child]),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                ..permissive_runner_config()
            },
        );

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let result = runner
                .sync_once_and_persist(&mut coordinator, &mut peers, &store, 500)
                .unwrap();

            assert_eq!(result.attempted, 1);
            assert_eq!(result.successful, 1);
            assert_eq!(result.accepted, 1);
            assert!(result.failures.is_empty());
            assert_eq!(result.best.unwrap().height, Height(1));
            store.flush().unwrap();
        }

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let persisted = store.load_peer(address).unwrap().unwrap();

            assert_eq!(persisted.last_height, Height(1));
            assert_eq!(persisted.last_height_observed_at, Some(500));
            assert_eq!(persisted.last_connected_at, Some(500));
            assert_eq!(persisted.successes, 1);
            assert_eq!(persisted.failures, 0);
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn strict_runner_filters_private_and_custom_port_peers_and_discovery() {
        let mut coordinator = seeded_coordinator();
        let primary: SocketAddr = "1.1.1.1:12038".parse().unwrap();
        let discovered: SocketAddr = "8.8.8.8:12038".parse().unwrap();
        let private: SocketAddr = "127.0.0.1:12038".parse().unwrap();
        let custom_port: SocketAddr = "9.9.9.9:22".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([private, custom_port, primary]);
        let connector = ScriptedHeaderConnector::new([(
            primary,
            ScriptedHeaderPeer::headers(Height(0), Vec::new()).with_addresses(vec![
                private,
                custom_port,
                discovered,
            ]),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 3,
                peer_discovery_target: 2,
                ..HeaderSyncRunnerConfig::default()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 1);
        assert_eq!(peers.get(primary).unwrap().successes, 1);
        assert!(peers.get(discovered).is_some());
        assert_eq!(peers.get(private).unwrap().successes, 0);
        assert_eq!(peers.get(custom_port).unwrap().successes, 0);
    }

    #[test]
    fn header_sync_runner_persists_discovery_before_header_download() {
        let path = temp_db_path("sync-peers-early");
        let mut coordinator = seeded_coordinator();
        let address: std::net::SocketAddr = "127.0.0.1:12044".parse().unwrap();
        let discovered: std::net::SocketAddr = "127.0.0.2:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let check_path = path.clone();
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::headers(Height(42), Vec::new())
                .with_addresses(vec![discovered])
                .with_request_headers_callback(move || {
                    let store = SqlitePeerStore::open(&check_path).unwrap();
                    let persisted = store.load_peer(address).unwrap().unwrap();
                    assert_eq!(persisted.last_height, Height(0));
                    assert_eq!(persisted.last_connected_at, Some(700));
                    assert_eq!(persisted.successes, 0);
                    assert!(store.load_peer(discovered).unwrap().is_some());
                    store.flush().unwrap();
                }),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                ..permissive_runner_config()
            },
        );

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let result = runner
                .sync_once_and_persist(&mut coordinator, &mut peers, &store, 700)
                .unwrap();

            assert_eq!(result.attempted, 1);
            assert_eq!(result.successful, 1);
            assert_eq!(result.accepted, 0);
            let persisted = store.load_peer(address).unwrap().unwrap();
            assert_eq!(persisted.last_height, Height(0));
            assert!(persisted.score >= hns_p2p::STALE_TIP_SCORE);
            store.flush().unwrap();
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn header_sync_runner_requests_multiple_header_batches_per_peer() {
        let path = temp_db_path("sync-progress-sequential");
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let headers = low_difficulty_chain(&genesis, MAX_HEADERS + 1);
        let address: std::net::SocketAddr = "127.0.0.1:12040".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::header_batches(
                Height((MAX_HEADERS + 1) as u32),
                [
                    headers[..MAX_HEADERS].to_vec(),
                    headers[MAX_HEADERS..].to_vec(),
                ],
            ),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                max_header_batches_per_peer: 2,
                ..permissive_runner_config()
            },
        );

        let mut progress = Vec::new();
        let result = {
            let store = SqlitePeerStore::open(&path).unwrap();
            let result = runner
                .sync_once_and_persist_with_progress(
                    &mut coordinator,
                    &mut peers,
                    &store,
                    1_000,
                    |snapshot| progress.push(snapshot),
                )
                .unwrap();
            store.flush().unwrap();
            result
        };

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 1);
        assert_eq!(result.accepted, MAX_HEADERS + 1);
        assert!(result.failures.is_empty());
        assert_eq!(
            result.best.unwrap().height,
            Height((MAX_HEADERS + 1) as u32)
        );
        assert_eq!(
            progress,
            vec![
                HeaderSyncProgress {
                    best_height: Some(Height(MAX_HEADERS as u32)),
                    accepted: MAX_HEADERS,
                },
                HeaderSyncProgress {
                    best_height: Some(Height((MAX_HEADERS + 1) as u32)),
                    accepted: MAX_HEADERS + 1,
                },
            ]
        );

        cleanup_db_path(&path);
    }

    #[test]
    fn header_sync_runner_stops_duplicate_only_full_batch() {
        let mut coordinator = seeded_coordinator();
        let genesis = BlockHeader::mainnet_genesis();
        let best = coordinator.chain().best_header().unwrap();
        let address: std::net::SocketAddr = "127.0.0.1:12041".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::headers(Height(0), vec![genesis; MAX_HEADERS]),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                max_header_batches_per_peer: 2,
                ..permissive_runner_config()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 1);
        assert_eq!(result.accepted, 0);
        assert!(result.failures.is_empty());
        assert_eq!(result.best, best);
    }

    #[test]
    fn header_sync_runner_skips_headers_when_peer_is_not_ahead() {
        let mut coordinator = seeded_coordinator();
        let best = coordinator.chain().best_header().unwrap();
        let address: std::net::SocketAddr = "127.0.0.1:12042".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::header_errors(Height(0), [P2pError::UnexpectedAction]),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                ..permissive_runner_config()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 1);
        assert_eq!(result.accepted, 0);
        assert!(result.failures.is_empty());
        assert_eq!(result.best, best);
        assert_eq!(peers.get(address).unwrap().successes, 1);
    }

    #[test]
    fn header_sync_runner_discovers_addresses_from_successful_peer() {
        let mut coordinator = seeded_coordinator();
        let address: std::net::SocketAddr = "127.0.0.1:12043".parse().unwrap();
        let discovered: std::net::SocketAddr = "127.0.0.2:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::headers(Height(0), Vec::new()).with_addresses(vec![discovered]),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                ..permissive_runner_config()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.successful, 1);
        assert!(peers.get(discovered).is_some());
    }

    #[test]
    fn header_sync_runner_queries_additional_peers_for_discovery() {
        let mut coordinator = seeded_coordinator();
        let primary: std::net::SocketAddr = "10.0.0.1:12038".parse().unwrap();
        let discovery_candidate: std::net::SocketAddr = "10.0.0.2:12038".parse().unwrap();
        let first_discovered: std::net::SocketAddr = "203.0.113.1:12038".parse().unwrap();
        let second_discovered: std::net::SocketAddr = "203.0.114.1:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([primary, discovery_candidate]);
        let connector = ScriptedHeaderConnector::new([
            (
                primary,
                ScriptedHeaderPeer::headers(Height(0), Vec::new())
                    .with_addresses(vec![first_discovered]),
            ),
            (
                discovery_candidate,
                ScriptedHeaderPeer::headers(Height(0), Vec::new())
                    .with_addresses(vec![second_discovered]),
            ),
        ]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                peer_discovery_target: 4,
                peer_discovery_query_peers: 1,
                ..permissive_runner_config()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 1);
        assert!(peers.get(first_discovered).is_some());
        assert!(peers.get(second_discovered).is_some());
        assert_eq!(peers.get(discovery_candidate).unwrap().successes, 1);
    }

    #[test]
    fn header_sync_runner_parallel_probe_records_liveness_without_promoting_heights() {
        let path = temp_db_path("parallel-probe");
        let discovered: std::net::SocketAddr = "127.0.0.3:12038".parse().unwrap();
        let (first, first_server) = spawn_probe_server(Height(42), vec![discovered]);
        let (second, second_server) = spawn_probe_server(Height(43), Vec::new());
        let mut peers = PeerManager::default();
        peers.seed([first, second]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            TcpHeaderPeerConnector,
            HeaderSyncRunnerConfig {
                parallel_peer_probes: 4,
                ..permissive_runner_config()
            },
        );

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let successful = runner
                .probe_peers_parallel_and_persist(&mut peers, &store, 900)
                .unwrap();

            assert_eq!(successful, 2);
            assert_eq!(peers.get(first).unwrap().last_height, Height(0));
            assert_eq!(peers.get(first).unwrap().last_height_observed_at, None);
            assert_eq!(peers.get(second).unwrap().last_height, Height(0));
            assert_eq!(peers.get(second).unwrap().last_height_observed_at, None);
            assert!(peers.get(discovered).is_some());
            let persisted = store.load_peer(first).unwrap().unwrap();
            assert_eq!(persisted.last_height, Height(0));
            assert_eq!(persisted.last_height_observed_at, None);
            assert_eq!(persisted.last_connected_at, Some(900));
            assert!(store.load_peer(discovered).unwrap().is_some());
            store.flush().unwrap();
        }

        first_server.join().unwrap();
        second_server.join().unwrap();
        cleanup_db_path(&path);
    }

    #[test]
    fn header_sync_runner_parallel_probe_refreshes_stale_full_peer_table() {
        let path = temp_db_path("parallel-probe-refresh");
        let (first, first_server) = spawn_probe_server(Height(42), Vec::new());
        let (second, second_server) = spawn_probe_server(Height(43), Vec::new());
        let mut peers = PeerManager::default();
        peers.record_success(first, Height(1), 100);
        peers.record_success(second, Height(1), 100);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            TcpHeaderPeerConnector,
            HeaderSyncRunnerConfig {
                parallel_peer_probes: 2,
                peer_discovery_target: 2,
                peer_height_refresh_interval: 60,
                ..permissive_runner_config()
            },
        );

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let successful = runner
                .probe_peers_parallel_and_persist(&mut peers, &store, 1_000)
                .unwrap();

            assert_eq!(successful, 2);
            assert_eq!(peers.get(first).unwrap().last_height, Height(0));
            assert_eq!(peers.get(first).unwrap().last_height_observed_at, None);
            assert_eq!(peers.get(second).unwrap().last_height, Height(0));
            assert_eq!(peers.get(second).unwrap().last_height_observed_at, None);
            let persisted = store.load_peer(second).unwrap().unwrap();
            assert_eq!(persisted.last_height, Height(0));
            assert_eq!(persisted.last_height_observed_at, None);
            assert_eq!(persisted.last_connected_at, Some(1_000));
            store.flush().unwrap();
        }

        first_server.join().unwrap();
        second_server.join().unwrap();
        cleanup_db_path(&path);
    }

    #[test]
    fn header_sync_runner_parallel_probe_skips_fresh_full_peer_table() {
        let path = temp_db_path("parallel-probe-fresh-skip");
        let first: std::net::SocketAddr = "127.0.0.2:12038".parse().unwrap();
        let second: std::net::SocketAddr = "127.0.0.3:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.record_success(first, Height(42), 950);
        peers.record_success(second, Height(43), 950);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            TcpHeaderPeerConnector,
            HeaderSyncRunnerConfig {
                parallel_peer_probes: 2,
                peer_discovery_target: 2,
                peer_height_refresh_interval: 60,
                ..permissive_runner_config()
            },
        );

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let successful = runner
                .probe_peers_parallel_and_persist(&mut peers, &store, 1_000)
                .unwrap();

            assert_eq!(successful, 0);
            assert_eq!(peers.get(second).unwrap().last_height, Height(43));
            store.flush().unwrap();
        }

        cleanup_db_path(&path);
    }

    #[test]
    fn post_sync_probe_corroborates_only_claims_at_or_below_validated_tip() {
        let path = temp_db_path("post-sync-corroboration");
        let (first, first_server) = spawn_probe_server(Height(12), Vec::new());
        let (second, second_server) = spawn_probe_server(Height(11), Vec::new());
        let (third, third_server) = spawn_probe_server(Height(12), Vec::new());
        let (liar, liar_server) = spawn_probe_server(Height(50_000), Vec::new());
        let mut peers = PeerManager::default();
        peers.seed([first, second, third, liar]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            TcpHeaderPeerConnector,
            HeaderSyncRunnerConfig {
                parallel_peer_probes: 4,
                timeout: Duration::from_secs(2),
                ..permissive_runner_config()
            },
        );

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let corroborated = runner
                .corroborate_peer_heights_at_tip_parallel_and_persist(
                    &mut peers,
                    &store,
                    1_000,
                    Height(12),
                )
                .unwrap();

            assert_eq!(corroborated, 3);
            assert_eq!(peers.get(first).unwrap().last_height, Height(12));
            assert_eq!(peers.get(second).unwrap().last_height, Height(11));
            assert_eq!(peers.get(third).unwrap().last_height, Height(12));
            assert_eq!(peers.get(liar).unwrap().last_height, Height(0));
            assert_eq!(peers.get(liar).unwrap().last_height_observed_at, None);
            let persisted_liar = store.load_peer(liar).unwrap().unwrap();
            assert_eq!(persisted_liar.last_height, Height(0));
            assert_eq!(persisted_liar.last_height_observed_at, None);
            assert_eq!(persisted_liar.last_connected_at, Some(1_000));
            store.flush().unwrap();
        }

        first_server.join().unwrap();
        second_server.join().unwrap();
        third_server.join().unwrap();
        liar_server.join().unwrap();
        cleanup_db_path(&path);
    }

    #[test]
    fn parallel_sync_uses_fresh_time_for_final_corroboration() {
        let path = temp_db_path("post-sync-fresh-time");
        let (first, first_server) = spawn_probe_server(Height(0), Vec::new());
        let (second, second_server) = spawn_probe_server(Height(0), Vec::new());
        let (third, third_server) = spawn_probe_server(Height(0), Vec::new());
        let mut coordinator = seeded_coordinator();
        let mut peers = PeerManager::default();
        peers.seed([first, second, third]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            TcpHeaderPeerConnector,
            HeaderSyncRunnerConfig {
                preferred_peers: 0,
                discover_peers: false,
                parallel_peer_probes: 3,
                timeout: Duration::from_secs(2),
                ..permissive_runner_config()
            },
        );

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let mut progress = Vec::new();
            runner
                .sync_once_parallel_and_persist_with_completion_time_and_progress(
                    &mut coordinator,
                    &mut peers,
                    &store,
                    1_000,
                    || 1_275,
                    |snapshot| progress.push(snapshot),
                )
                .unwrap();

            assert!(progress.is_empty());

            for address in [first, second, third] {
                assert_eq!(
                    peers.get(address).unwrap().last_height_observed_at,
                    Some(1_275)
                );
                assert_eq!(
                    store
                        .load_peer(address)
                        .unwrap()
                        .unwrap()
                        .last_height_observed_at,
                    Some(1_275)
                );
            }
            store.flush().unwrap();
        }

        first_server.join().unwrap();
        second_server.join().unwrap();
        third_server.join().unwrap();
        cleanup_db_path(&path);
    }

    #[test]
    fn header_sync_runner_races_header_batch_and_uses_fast_peer() {
        let path = temp_db_path("race-headers");
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let child = low_difficulty_child(&genesis);
        let (slow, slow_server) =
            spawn_header_server(Height(1), vec![child.clone()], Duration::from_millis(300));
        let (fast, fast_server) = spawn_header_server(Height(1), vec![child], Duration::ZERO);
        let mut peers = PeerManager::default();
        peers.seed([slow, fast]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            TcpHeaderPeerConnector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                max_header_batches_per_peer: 1,
                parallel_header_fetch_peers: 2,
                timeout: Duration::from_secs(2),
                ..permissive_runner_config()
            },
        );

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let mut progress = Vec::new();
            let result = runner
                .sync_once_racing_and_persist(
                    &mut coordinator,
                    &mut peers,
                    &store,
                    800,
                    HeaderCheckpointPrefetchResult {
                        attempted: 0,
                        successful: 0,
                        ranges: Vec::new(),
                        failures: Vec::new(),
                    },
                    &mut |snapshot| progress.push(snapshot),
                )
                .unwrap();

            assert_eq!(result.attempted, 1);
            assert_eq!(result.successful, 1);
            assert_eq!(result.accepted, 1);
            assert_eq!(result.best.unwrap().height, Height(1));
            assert_eq!(peers.get(fast).unwrap().successes, 1);
            assert_eq!(peers.get(slow).unwrap().successes, 0);
            assert_eq!(
                progress,
                vec![HeaderSyncProgress {
                    best_height: Some(Height(1)),
                    accepted: 1,
                }]
            );
            store.flush().unwrap();
        }

        fast_server.join().unwrap();
        slow_server.join().unwrap();
        cleanup_db_path(&path);
    }

    #[test]
    fn header_sync_runner_races_past_fast_empty_batch() {
        let path = temp_db_path("race-empty-headers");
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let child = low_difficulty_child(&genesis);
        let (empty, empty_server) = spawn_header_server(Height(1), Vec::new(), Duration::ZERO);
        let (useful, useful_server) =
            spawn_header_server(Height(1), vec![child], Duration::from_millis(100));
        let mut peers = PeerManager::default();
        peers.seed([empty, useful]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            TcpHeaderPeerConnector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                max_header_batches_per_peer: 1,
                parallel_header_fetch_peers: 2,
                timeout: Duration::from_secs(2),
                ..permissive_runner_config()
            },
        );

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let result = runner
                .sync_once_parallel_and_persist(&mut coordinator, &mut peers, &store, 800)
                .unwrap();

            assert_eq!(result.attempted, 1);
            assert_eq!(result.successful, 1);
            assert_eq!(result.accepted, 1);
            assert_eq!(result.best.unwrap().height, Height(1));
            assert_eq!(peers.get(empty).unwrap().successes, 1);
            assert_eq!(peers.get(empty).unwrap().last_height, Height(0));
            assert_eq!(peers.get(useful).unwrap().successes, 1);
            store.flush().unwrap();
        }

        useful_server.join().unwrap();
        empty_server.join().unwrap();
        cleanup_db_path(&path);
    }

    #[test]
    fn header_sync_runner_races_past_fast_stale_peer() {
        let path = temp_db_path("race-stale-peer");
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let child = low_difficulty_child(&genesis);
        let (stale, stale_server) = spawn_header_server(Height(0), Vec::new(), Duration::ZERO);
        let (useful, useful_server) =
            spawn_header_server(Height(1), vec![child], Duration::from_millis(100));
        let mut peers = PeerManager::default();
        peers.seed([stale, useful]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            TcpHeaderPeerConnector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                max_header_batches_per_peer: 1,
                parallel_header_fetch_peers: 2,
                timeout: Duration::from_secs(2),
                ..permissive_runner_config()
            },
        );

        {
            let store = SqlitePeerStore::open(&path).unwrap();
            let result = runner
                .sync_once_parallel_and_persist(&mut coordinator, &mut peers, &store, 800)
                .unwrap();

            assert_eq!(result.attempted, 1);
            assert_eq!(result.successful, 1);
            assert_eq!(result.accepted, 1);
            assert_eq!(result.best.unwrap().height, Height(1));
            assert_eq!(peers.get(stale).unwrap().successes, 1);
            assert_eq!(peers.get(useful).unwrap().successes, 1);
            store.flush().unwrap();
        }

        useful_server.join().unwrap();
        stale_server.join().unwrap();
        cleanup_db_path(&path);
    }

    #[test]
    fn checkpoint_prefetch_range_waits_for_parent_before_ingest() {
        let path = temp_db_path("checkpoint-prefetch-stage");
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let headers = low_difficulty_chain(&genesis, 4);
        let checkpoint = HeaderCheckpoint {
            height: Height(2),
            hash: headers[1].hash(),
        };
        let address: SocketAddr = "127.0.0.1:12045".parse().unwrap();
        let mut staged_ranges = vec![PrefetchedHeaderRange {
            address,
            checkpoint,
            headers: headers[2..].to_vec(),
        }];
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let mut result = HeaderSyncRunResult::empty();
        let mut progress = Vec::new();
        {
            let mut observe = |snapshot| progress.push(snapshot);
            let mut progress_reporter = HeaderSyncProgressReporter::new(&mut observe);

            {
                let store = SqlitePeerStore::open(&path).unwrap();
                let applied = apply_ready_checkpoint_ranges(
                    &mut coordinator,
                    &mut peers,
                    CheckpointRangeApplyContext {
                        store: &store,
                        now: 1_000,
                        malformed_ban_seconds: DEFAULT_MALFORMED_BAN_SECONDS,
                    },
                    &mut staged_ranges,
                    &mut result,
                    &mut progress_reporter,
                )
                .unwrap();

                assert!(!applied);
                assert_eq!(result.accepted, 0);
                assert_eq!(staged_ranges.len(), 1);
                assert_eq!(progress_reporter.accepted(), 0);
                store.flush().unwrap();
            }

            coordinator
                .ingest_headers(headers[..2].to_vec())
                .expect("prefix should attach");

            {
                let store = SqlitePeerStore::open(&path).unwrap();
                let applied = apply_ready_checkpoint_ranges(
                    &mut coordinator,
                    &mut peers,
                    CheckpointRangeApplyContext {
                        store: &store,
                        now: 1_000,
                        malformed_ban_seconds: DEFAULT_MALFORMED_BAN_SECONDS,
                    },
                    &mut staged_ranges,
                    &mut result,
                    &mut progress_reporter,
                )
                .unwrap();

                assert!(applied);
                assert_eq!(result.accepted, 2);
                assert_eq!(result.best.unwrap().height, Height(4));
                assert!(staged_ranges.is_empty());
                assert_eq!(progress_reporter.accepted(), 2);
                store.flush().unwrap();
            }
        }
        assert_eq!(
            progress,
            vec![HeaderSyncProgress {
                best_height: Some(Height(4)),
                accepted: 2,
            }]
        );

        cleanup_db_path(&path);
    }

    #[test]
    fn header_sync_runner_reports_peer_failure_stage() {
        let mut coordinator = seeded_coordinator();
        let address: std::net::SocketAddr = "127.0.0.1:12039".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            ScriptedHeaderConnector::new(std::iter::empty::<(
                std::net::SocketAddr,
                ScriptedHeaderPeer,
            )>()),
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                ..permissive_runner_config()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 0);
        assert_eq!(result.accepted, 0);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].address, address);
        assert_eq!(result.failures[0].stage, HeaderPeerFailureStage::Connect);
        assert!(result.failures[0].error.contains("connection"));
        assert_eq!(peers.get(address).unwrap().failures, 1);
    }

    #[test]
    fn header_sync_runner_bans_invalid_pow_peer_and_continues() {
        let mut coordinator = seeded_coordinator();
        let genesis = coordinator.chain().best_header().unwrap().unwrap();
        let invalid = invalid_pow_child(&genesis);
        let address: std::net::SocketAddr = "127.0.0.1:12038".parse().unwrap();
        let mut peers = PeerManager::default();
        peers.seed([address]);
        let connector = ScriptedHeaderConnector::new([(
            address,
            ScriptedHeaderPeer::headers(Height(1), vec![invalid]),
        )]);
        let runner = HeaderSyncRunner::with_config(
            network::mainnet(),
            connector,
            HeaderSyncRunnerConfig {
                preferred_peers: 1,
                malformed_ban_seconds: 60,
                ..permissive_runner_config()
            },
        );

        let result = runner
            .sync_once(&mut coordinator, &mut peers, 1_000)
            .unwrap();

        assert_eq!(result.attempted, 1);
        assert_eq!(result.successful, 0);
        assert_eq!(result.accepted, 0);
        assert_eq!(peers.get(address).unwrap().banned_until, Some(1_060));
        assert!(peers.get(address).unwrap().is_banned(1_001));
    }

    #[test]
    fn proof_coordinator_rejects_unrequested_proof() {
        let mut coordinator = ProofSyncCoordinator::new(AcceptingProofVerifier);

        assert_eq!(
            coordinator.ingest_proof(proof_packet(1, 2)).unwrap_err(),
            SyncError::UnexpectedProof,
        );
    }

    #[test]
    fn proof_coordinator_rejects_malformed_payload() {
        let mut coordinator = ProofSyncCoordinator::new(AcceptingProofVerifier);
        let root = hash(1);
        let key = hash(2);
        coordinator.track_request(root, key);

        assert_eq!(
            coordinator
                .ingest_proof(ProofPacket {
                    root,
                    key,
                    proof: vec![0],
                })
                .unwrap_err(),
            SyncError::Proof(ProofError::Malformed),
        );
    }

    #[test]
    fn proof_coordinator_fails_closed_without_verifier() {
        let mut coordinator = ProofSyncCoordinator::new(FailClosedProofVerifier);
        let packet = proof_packet(1, 2);
        coordinator.track_request(packet.root, packet.key);

        assert_eq!(
            coordinator.ingest_proof(packet).unwrap_err(),
            SyncError::Proof(ProofError::UnsupportedVerifier),
        );
    }

    #[test]
    fn proof_coordinator_accepts_verified_proof() {
        let mut coordinator = ProofSyncCoordinator::new(AcceptingProofVerifier);
        let packet = proof_packet(1, 2);
        coordinator.track_request(packet.root, packet.key);

        assert_eq!(
            coordinator.ingest_proof(packet.clone()).unwrap(),
            ProofValidationResult {
                root: packet.root,
                key: packet.key,
                kind: ProofKind::Inclusion,
                value: Some(proof_bytes(packet.root, packet.key)[6..].to_vec()),
            },
        );
        assert_eq!(coordinator.pending_len(), 0);
    }

    #[test]
    fn proof_scheduler_requests_verifies_and_stores_value() {
        let network = network::mainnet();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let root_name = "welcome";
        let root = hash(9);
        let name_hash = NameHash::from_name(root_name).unwrap();
        let key = name_hash.as_hash();
        let expected_value = vec![0, 4, 127, 0, 0, 1];
        let name_state_value = name_state_value(root_name, &expected_value);
        let proof_payload = proof_bytes_with_value(&name_state_value);
        let server_network = network.clone();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut peer = PeerConnection::new(stream, server_network);

            assert!(matches!(peer.receive_packet().unwrap(), Packet::Version(_),));
            peer.send_packet(&Packet::Version(VersionPacket::default()))
                .unwrap();
            assert_eq!(peer.receive_packet().unwrap(), Packet::Verack);
            peer.send_packet(&Packet::Verack).unwrap();

            match peer.receive_packet().unwrap() {
                Packet::GetProof(request) => {
                    assert_eq!(request.root, root);
                    assert_eq!(request.key, key);
                }
                other => panic!("unexpected packet: {other:?}"),
            }
            peer.send_packet(&Packet::Proof(ProofPacket {
                root,
                key,
                proof: proof_payload,
            }))
            .unwrap();
        });

        let store = MemoryResourceSink::default();
        let mut scheduler = ProofScheduler::new(AcceptingProofVerifier, &store);
        let mut peer = PeerConnection::connect(address, network, Duration::from_secs(2)).unwrap();
        let mut session = HeaderSyncSession::new(VersionPacket::default());
        peer.handshake(&mut session).unwrap();

        let result = scheduler
            .request_and_store_at_height(&mut peer, &mut session, root_name, root, Height(7))
            .unwrap();

        assert_eq!(result.root, root);
        assert_eq!(result.key, key);
        assert_eq!(result.kind, ProofKind::Inclusion);
        assert_eq!(result.value, Some(name_state_value));
        assert_eq!(scheduler.pending_len(), 0);
        let stored = store.get(root_name, name_hash).unwrap();
        assert_eq!(stored.value, Some(expected_value));
        assert_eq!(stored.anchor.unwrap().tree_root, root);
        assert_eq!(stored.anchor.unwrap().height, Height(7));

        server.join().unwrap();
    }

    #[test]
    fn proof_scheduler_fails_closed_for_invalid_name() {
        let store = MemoryResourceSink::default();
        let mut scheduler = ProofScheduler::new(AcceptingProofVerifier, &store);
        let network = network::mainnet();
        let mut session = HeaderSyncSession::new(VersionPacket::default());
        let mut peer = PeerConnection::new(VecTransport::default(), network);

        assert!(matches!(
            scheduler.request_and_store(&mut peer, &mut session, "bad.name", hash(1)),
            Err(SyncError::InvalidName(_)),
        ));
        assert_eq!(scheduler.pending_len(), 0);
    }

    fn seeded_coordinator() -> HeaderSyncCoordinator<MemoryHeaderStore> {
        let mut chain = HeaderChain::with_difficulty_policy(
            MemoryHeaderStore::default(),
            DifficultyPolicy::Permissive,
        );
        chain
            .insert_genesis(BlockHeader::mainnet_genesis())
            .unwrap();
        HeaderSyncCoordinator::new(chain)
    }

    fn low_difficulty_child(parent: &StoredHeader) -> BlockHeader {
        let mut child = BlockHeader::mainnet_genesis();
        child.prev_block = parent.hash;
        child.bits = 0x207f_ffff;
        for nonce in 0..10_000 {
            child.nonce = nonce;
            if verify_pow(child.hash(), child.bits).unwrap() {
                return child;
            }
        }
        panic!("could not find low-difficulty header nonce");
    }

    fn low_difficulty_chain(parent: &StoredHeader, count: usize) -> Vec<BlockHeader> {
        let mut headers = Vec::with_capacity(count);
        let mut parent_hash = parent.hash;

        for _ in 0..count {
            let mut child = BlockHeader::mainnet_genesis();
            child.prev_block = parent_hash;
            child.bits = 0x207f_ffff;
            for nonce in 0..10_000 {
                child.nonce = nonce;
                if verify_pow(child.hash(), child.bits).unwrap() {
                    parent_hash = child.hash();
                    headers.push(child);
                    break;
                }
            }
        }

        assert_eq!(headers.len(), count);
        headers
    }

    fn invalid_pow_child(parent: &StoredHeader) -> BlockHeader {
        let mut child = BlockHeader::mainnet_genesis();
        child.prev_block = parent.hash;
        child.bits = 0x0101_0000;
        child
    }

    fn proof_packet(root: u8, key: u8) -> ProofPacket {
        let root = hash(root);
        let key = hash(key);
        ProofPacket {
            root,
            key,
            proof: proof_bytes(root, key),
        }
    }

    fn proof_bytes(root: Hash, key: Hash) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&root.as_bytes()[..2]);
        value.extend_from_slice(&key.as_bytes()[..2]);
        proof_bytes_with_value(&value)
    }

    fn proof_bytes_with_value(value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_u16_le(&mut bytes, 3 << 14);
        write_u16_le(&mut bytes, 0);
        write_u16_le(&mut bytes, value.len() as u16);
        bytes.extend_from_slice(value);
        bytes
    }

    fn name_state_value(name: &str, data: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        value.push(name.len() as u8);
        value.extend(name.as_bytes());
        write_u16_le(&mut value, data.len() as u16);
        value.extend(data);
        value.extend(7_u32.to_le_bytes());
        value.extend(7_u32.to_le_bytes());
        value.extend(0_u16.to_le_bytes());
        value
    }

    fn write_u16_le(out: &mut Vec<u8>, value: u16) {
        out.extend(value.to_le_bytes());
    }

    fn hash(value: u8) -> Hash {
        Hash::new([value; 32])
    }

    fn temp_db_path(label: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hns-sync-{label}-{}-{now}.sqlite",
            std::process::id()
        ))
    }

    fn cleanup_db_path(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    fn spawn_probe_server(
        remote_height: Height,
        addresses: Vec<SocketAddr>,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let network = network::mainnet();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut peer = PeerConnection::new(stream, network);

            assert!(matches!(peer.receive_packet().unwrap(), Packet::Version(_),));
            peer.send_packet(&Packet::Version(VersionPacket {
                height: remote_height,
                ..VersionPacket::default()
            }))
            .unwrap();
            assert_eq!(peer.receive_packet().unwrap(), Packet::Verack);
            peer.send_packet(&Packet::Verack).unwrap();
            assert_eq!(peer.receive_packet().unwrap(), Packet::GetAddr);
            peer.send_packet(&Packet::Addr(AddrPacket {
                items: addresses
                    .into_iter()
                    .map(|address| NetAddress {
                        time: 1,
                        services: SERVICE_NETWORK,
                        address: address.ip(),
                        port: address.port(),
                    })
                    .collect(),
            }))
            .unwrap();
        });

        (address, server)
    }

    fn spawn_header_server(
        remote_height: Height,
        headers: Vec<BlockHeader>,
        response_delay: Duration,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let network = network::mainnet();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut peer = PeerConnection::new(stream, network);

            assert!(matches!(peer.receive_packet().unwrap(), Packet::Version(_),));
            peer.send_packet(&Packet::Version(VersionPacket {
                height: remote_height,
                ..VersionPacket::default()
            }))
            .unwrap();
            assert_eq!(peer.receive_packet().unwrap(), Packet::Verack);
            peer.send_packet(&Packet::Verack).unwrap();

            match peer.receive_packet().unwrap() {
                Packet::GetHeaders(request) => {
                    assert_eq!(request.locator, vec![BlockHeader::mainnet_genesis().hash()]);
                    assert_eq!(request.stop, Hash::ZERO);
                }
                other => panic!("unexpected packet: {other:?}"),
            }
            thread::sleep(response_delay);
            peer.send_packet(&Packet::Headers(HeadersPacket { items: headers }))
                .unwrap();
        });

        (address, server)
    }

    struct ScriptedHeaderConnector {
        peers: RefCell<HashMap<std::net::SocketAddr, ScriptedHeaderPeer>>,
    }

    impl ScriptedHeaderConnector {
        fn new<I>(peers: I) -> Self
        where
            I: IntoIterator<Item = (std::net::SocketAddr, ScriptedHeaderPeer)>,
        {
            Self {
                peers: RefCell::new(peers.into_iter().collect()),
            }
        }
    }

    impl HeaderPeerConnector for ScriptedHeaderConnector {
        type Peer = ScriptedHeaderPeer;

        fn connect(
            &self,
            address: std::net::SocketAddr,
            _network: &Network,
            _timeout: Duration,
        ) -> Result<Self::Peer, P2pError> {
            self.peers
                .borrow_mut()
                .remove(&address)
                .ok_or(P2pError::ConnectionClosed)
        }
    }

    struct ScriptedHeaderPeer {
        remote_height: Height,
        headers: VecDeque<Result<Vec<BlockHeader>, P2pError>>,
        addresses: Vec<SocketAddr>,
        on_request_headers: Option<Box<dyn FnMut()>>,
    }

    impl ScriptedHeaderPeer {
        fn headers(remote_height: Height, headers: Vec<BlockHeader>) -> Self {
            Self::header_batches(remote_height, [headers])
        }

        fn header_batches<I>(remote_height: Height, batches: I) -> Self
        where
            I: IntoIterator<Item = Vec<BlockHeader>>,
        {
            Self {
                remote_height,
                headers: batches.into_iter().map(Ok).collect(),
                addresses: Vec::new(),
                on_request_headers: None,
            }
        }

        fn header_errors<I>(remote_height: Height, errors: I) -> Self
        where
            I: IntoIterator<Item = P2pError>,
        {
            Self {
                remote_height,
                headers: errors.into_iter().map(Err).collect(),
                addresses: Vec::new(),
                on_request_headers: None,
            }
        }

        fn with_addresses(mut self, addresses: Vec<SocketAddr>) -> Self {
            self.addresses = addresses;
            self
        }

        fn with_request_headers_callback(mut self, callback: impl FnMut() + 'static) -> Self {
            self.on_request_headers = Some(Box::new(callback));
            self
        }
    }

    impl HeaderPeerClient for ScriptedHeaderPeer {
        fn handshake(
            &mut self,
            _session: &mut HeaderSyncSession,
        ) -> Result<VersionPacket, P2pError> {
            Ok(VersionPacket {
                height: self.remote_height,
                ..VersionPacket::default()
            })
        }

        fn request_headers(
            &mut self,
            _session: &mut HeaderSyncSession,
            _locator: Vec<Hash>,
            _stop: Hash,
        ) -> Result<Vec<BlockHeader>, P2pError> {
            if let Some(callback) = self.on_request_headers.as_mut() {
                callback();
            }
            self.headers.pop_front().unwrap_or_else(|| Ok(Vec::new()))
        }

        fn request_addresses(&mut self) -> Result<Vec<SocketAddr>, P2pError> {
            Ok(self.addresses.clone())
        }
    }

    struct AcceptingProofVerifier;

    impl ProofVerifier for AcceptingProofVerifier {
        fn verify(&self, proof: &ParsedProof, expected_root: Hash) -> Result<bool, ProofError> {
            Ok(proof.kind == ProofKind::Inclusion && proof.root == expected_root)
        }
    }

    #[derive(Default)]
    struct VecTransport {
        read: std::io::Cursor<Vec<u8>>,
        write: Vec<u8>,
    }

    impl std::io::Read for VecTransport {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(out)
        }
    }

    impl std::io::Write for VecTransport {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            self.write.extend(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
