//! Bounded standard Handshake P2P session for light clients.
//!
//! The state machine is runtime independent: socket adapters exchange
//! `hns-p2p-wire` frames and provide an explicit clock. Only standard HSD
//! version/verack, ping/pong, headers, name-proof, and wallet-filter traffic is
//! admitted here. Chain and wallet evidence remains authoritative only after
//! local verification. Experimental HIP sessions remain separate.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "HNS, P2P, HSD, and HIP are protocol names"
)]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

use hns_header_consensus::Header;
use hns_p2p_wire::{
    Frame, FrameDecoder, GetProofPacket, Inventory, LocatorPacket, NetAddress, NetworkMagic,
    Packet, PacketType, ProofPacket, RejectPacket, SERVICE_BLOOM, SERVICE_NETWORK, VersionPacket,
    WireError,
};
use hns_primitives::{BlockHash, NameHash, TreeRoot};
use hns_transaction::Transaction;
use thiserror::Error;

/// Default complete version/verack deadline.
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;
/// Default header/proof/ping response deadline.
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 15;
/// Default maximum peer wall-clock skew.
pub const DEFAULT_MAX_CLOCK_SKEW_SECONDS: u64 = 2 * 60 * 60;
/// Bounded stack read used by the standard stream adapter.
pub const PEER_READ_BUFFER_SIZE: usize = 8 * 1_024;
/// Maximum decoded frames retained between caller polls.
pub const MAX_PENDING_PEER_FRAMES: usize = 1_024;

/// Standard-peer session bounds and admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerConfig {
    /// Selected Handshake wire network.
    pub network: NetworkMagic,
    /// Required standard service bits.
    pub required_services: u64,
    /// Complete handshake deadline.
    pub handshake_timeout_seconds: u64,
    /// Per-request deadline.
    pub request_timeout_seconds: u64,
    /// Maximum version timestamp skew.
    pub max_clock_skew_seconds: u64,
}

impl PeerConfig {
    /// Secure defaults for one network.
    #[must_use]
    pub const fn for_network(network: NetworkMagic) -> Self {
        Self {
            network,
            required_services: SERVICE_NETWORK,
            handshake_timeout_seconds: DEFAULT_HANDSHAKE_TIMEOUT_SECONDS,
            request_timeout_seconds: DEFAULT_REQUEST_TIMEOUT_SECONDS,
            max_clock_skew_seconds: DEFAULT_MAX_CLOCK_SKEW_SECONDS,
        }
    }

    /// Secure defaults for a wallet peer that must support HSD bloom filters.
    #[must_use]
    pub const fn for_wallet_network(network: NetworkMagic) -> Self {
        Self {
            network,
            required_services: SERVICE_NETWORK | SERVICE_BLOOM,
            handshake_timeout_seconds: DEFAULT_HANDSHAKE_TIMEOUT_SECONDS,
            request_timeout_seconds: DEFAULT_REQUEST_TIMEOUT_SECONDS,
            max_clock_skew_seconds: DEFAULT_MAX_CLOCK_SKEW_SECONDS,
        }
    }

    fn validate(self) -> Result<Self, PeerError> {
        if self.required_services & SERVICE_NETWORK == 0
            || self.handshake_timeout_seconds == 0
            || self.handshake_timeout_seconds > 60
            || self.request_timeout_seconds == 0
            || self.request_timeout_seconds > 300
            || self.max_clock_skew_seconds > 24 * 60 * 60
        {
            return Err(PeerError::InvalidConfig);
        }
        Ok(self)
    }
}

/// Peer session phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerState {
    /// Local version sent; remote version required.
    AwaitingVersion,
    /// Remote version accepted and local verack sent.
    AwaitingVerack,
    /// Standard requests may be issued.
    Ready,
    /// Session is permanently closed.
    Closed,
}

/// Admitted remote version metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerMetadata {
    /// Negotiated HSD protocol version.
    pub version: u32,
    /// Advertised standard services.
    pub services: u64,
    /// Remote Unix timestamp.
    pub time: u64,
    /// Remote user agent.
    pub agent: String,
    /// Advertised best height.
    pub height: u32,
}

/// Standard wallet traffic admitted after version/verack.
///
/// Every variant is still untrusted peer input. The wallet coordinator must
/// correlate requested inventory and verify filtered blocks and transactions
/// against its locally validated header chain before changing wallet state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalletPeerEvent {
    /// Newly announced transaction or block inventory.
    Inventory(Vec<Inventory>),
    /// The peer requested data previously announced by this wallet.
    DataRequest(Vec<Inventory>),
    /// Requested inventory that the peer could not provide.
    NotFound(Vec<Inventory>),
    /// Untrusted transaction bytes decoded by the shared canonical codec.
    Transaction(Transaction),
    /// Raw HSD MerkleBlock payload awaiting local partial-tree verification.
    MerkleBlock(Vec<u8>),
    /// Remote minimum transaction fee rate.
    FeeFilter(i64),
}

/// Response-bearing request category.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestKind {
    /// Standard `getheaders`.
    Headers = 0,
    /// Standard `getproof`.
    Proof = 1,
    /// Standard ping.
    Ping = 2,
}

/// Requests that exceeded their explicit deadline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExpiredRequests {
    /// Header request expired.
    pub headers: bool,
    /// Name-proof request expired.
    pub proof: bool,
    /// Ping expired.
    pub ping: bool,
}

impl ExpiredRequests {
    /// Whether at least one request expired.
    #[must_use]
    pub const fn any(self) -> bool {
        self.headers || self.proof || self.ping
    }
}

/// Event emitted by one admitted inbound frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerEvent {
    /// Send this standard frame to the peer.
    Send(Frame),
    /// Version/verack completed.
    Ready(PeerMetadata),
    /// Correlated bounded header batch.
    Headers(Vec<Header>),
    /// Correlated exact-root/key Urkel proof.
    Proof(ProofPacket),
    /// Bounded standard peer addresses supplied for discovery.
    Addresses(Vec<NetAddress>),
    /// Matching pong arrived.
    Pong([u8; 8]),
    /// Peer rejected a request.
    Rejected(RejectPacket),
    /// Standard wallet traffic awaiting correlation and local verification.
    Wallet(WalletPeerEvent),
    /// One bounded unknown packet preserved for an explicitly opted-in
    /// experimental protocol. The standard session neither interprets nor
    /// authorizes this payload; its consumer owns registry negotiation,
    /// correlation, and all protocol-specific validation.
    Experimental {
        /// The unassigned standard packet type that carried `payload`.
        packet_type: u8,
        /// Bounded raw packet bytes, already framed for the selected network.
        payload: Vec<u8>,
    },
    /// Ordinary packet was safely outside the light-client flow.
    Ignored(PacketType),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pending {
    deadline: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingProof {
    root: TreeRoot,
    key: NameHash,
    deadline: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingPing {
    nonce: [u8; 8],
    deadline: u64,
}

/// One bounded standard HSD peer session.
#[derive(Clone, Debug)]
pub struct PeerSession {
    config: PeerConfig,
    state: PeerState,
    local_nonce: [u8; 8],
    handshake_deadline: u64,
    metadata: Option<PeerMetadata>,
    pending_headers: Option<Pending>,
    pending_proof: Option<PendingProof>,
    pending_ping: Option<PendingPing>,
}

/// One standard peer session bound to a blocking byte stream.
///
/// The stream may be a native [`TcpStream`] or a deterministic test/host
/// adapter. All bytes pass through the bounded shared frame decoder and the
/// same [`PeerSession`] correlation rules before being exposed as events.
#[derive(Debug)]
pub struct PeerConnection<T> {
    transport: T,
    session: PeerSession,
    decoder: FrameDecoder,
    pending: VecDeque<Frame>,
}

impl PeerSession {
    /// Start a session and return the local version frame.
    pub fn start(
        config: PeerConfig,
        local_version: &VersionPacket,
        now: u64,
    ) -> Result<(Self, Frame), PeerError> {
        let config = config.validate()?;
        if local_version.nonce == [0; 8]
            || local_version.version < hns_p2p_wire::MIN_PROTOCOL_VERSION
            || local_version.time.abs_diff(now) > config.max_clock_skew_seconds
        {
            return Err(PeerError::InvalidLocalVersion);
        }
        let handshake_deadline = now
            .checked_add(config.handshake_timeout_seconds)
            .ok_or(PeerError::TimeOverflow)?;
        let frame = Frame::from_packet(&Packet::Version(local_version.clone()))?;
        Ok((
            Self {
                config,
                state: PeerState::AwaitingVersion,
                local_nonce: local_version.nonce,
                handshake_deadline,
                metadata: None,
                pending_headers: None,
                pending_proof: None,
                pending_ping: None,
            },
            frame,
        ))
    }

    /// Selected wire network for the adapter's frame decoder.
    #[must_use]
    pub const fn network(&self) -> NetworkMagic {
        self.config.network
    }

    /// Current session phase.
    #[must_use]
    pub const fn state(&self) -> PeerState {
        self.state
    }

    /// Admitted remote metadata after version.
    #[must_use]
    pub const fn metadata(&self) -> Option<&PeerMetadata> {
        self.metadata.as_ref()
    }

    /// Close permanently and revoke all outstanding requests.
    pub fn close(&mut self) {
        self.state = PeerState::Closed;
        self.pending_headers = None;
        self.pending_proof = None;
        self.pending_ping = None;
    }

    /// Admit one strict frame from the selected-network decoder.
    pub fn handle_frame(&mut self, frame: &Frame, now: u64) -> Result<PeerEvent, PeerError> {
        if self.state == PeerState::Closed {
            return Err(PeerError::Closed);
        }
        if self.state != PeerState::Ready && now > self.handshake_deadline {
            self.close();
            return Err(PeerError::HandshakeTimeout);
        }
        let packet = frame.decode_packet()?;
        match self.state {
            PeerState::AwaitingVersion => self.handle_version(packet, now),
            PeerState::AwaitingVerack => {
                if packet != Packet::Verack {
                    return Err(PeerError::ExpectedVerack);
                }
                self.state = PeerState::Ready;
                Ok(PeerEvent::Ready(
                    self.metadata.clone().ok_or(PeerError::InternalInvariant)?,
                ))
            }
            PeerState::Ready => self.handle_ready(packet, now),
            PeerState::Closed => Err(PeerError::Closed),
        }
    }

    /// Build one bounded `getheaders`; only one may be outstanding.
    pub fn request_headers(
        &mut self,
        locator: Vec<BlockHash>,
        stop: BlockHash,
        now: u64,
    ) -> Result<Frame, PeerError> {
        self.require_ready()?;
        if locator.is_empty() {
            return Err(PeerError::EmptyLocator);
        }
        if self.pending_headers.is_some() {
            return Err(PeerError::DuplicateRequest(RequestKind::Headers));
        }
        let deadline = self.request_deadline(now)?;
        let frame = Frame::from_packet(&Packet::GetHeaders(LocatorPacket { locator, stop }))?;
        self.pending_headers = Some(Pending { deadline });
        Ok(frame)
    }

    /// Build one exact-root/key standard name-proof request.
    pub fn request_proof(
        &mut self,
        root: TreeRoot,
        key: NameHash,
        now: u64,
    ) -> Result<Frame, PeerError> {
        self.require_ready()?;
        if self.pending_proof.is_some() {
            return Err(PeerError::DuplicateRequest(RequestKind::Proof));
        }
        let deadline = self.request_deadline(now)?;
        let frame = Frame::from_packet(&Packet::GetProof(GetProofPacket { root, key }))?;
        self.pending_proof = Some(PendingProof {
            root,
            key,
            deadline,
        });
        Ok(frame)
    }

    /// Build one standard wallet packet after the peer has advertised bloom
    /// support and completed version/verack.
    ///
    /// This deliberately admits only the client side of HSD's BIP37 flow and
    /// direct transaction propagation. Callers should construct filter
    /// payloads with the strict wallet codec rather than passing arbitrary
    /// bytes from an external source.
    pub fn wallet_frame(&self, packet: &Packet) -> Result<Frame, PeerError> {
        self.require_ready()?;
        if self
            .metadata
            .as_ref()
            .is_none_or(|metadata| metadata.services & SERVICE_BLOOM == 0)
        {
            return Err(PeerError::MissingBloomService);
        }
        if !matches!(
            packet,
            Packet::Inv(_)
                | Packet::GetData(_)
                | Packet::Tx(_)
                | Packet::Mempool
                | Packet::FilterLoad(_)
                | Packet::FilterAdd(_)
                | Packet::FilterClear
        ) {
            return Err(PeerError::UnsupportedWalletPacket(packet.packet_type()));
        }
        Ok(Frame::from_packet(packet)?)
    }

    /// Build a standard peer-discovery request after version/verack.
    pub fn address_request(&self) -> Result<Frame, PeerError> {
        self.require_ready()?;
        Ok(Frame::from_packet(&Packet::GetAddr)?)
    }

    /// Build one ping; only one may be outstanding.
    pub fn ping(&mut self, nonce: [u8; 8], now: u64) -> Result<Frame, PeerError> {
        self.require_ready()?;
        if nonce == [0; 8] {
            return Err(PeerError::ZeroPingNonce);
        }
        if self.pending_ping.is_some() {
            return Err(PeerError::DuplicateRequest(RequestKind::Ping));
        }
        let deadline = self.request_deadline(now)?;
        let frame = Frame::from_packet(&Packet::Ping(nonce))?;
        self.pending_ping = Some(PendingPing { nonce, deadline });
        Ok(frame)
    }

    /// Expire all overdue work and return name-free timeout flags.
    pub fn expire(&mut self, now: u64) -> Result<ExpiredRequests, PeerError> {
        if self.state != PeerState::Ready {
            if self.state != PeerState::Closed && now > self.handshake_deadline {
                self.close();
                return Err(PeerError::HandshakeTimeout);
            }
            return Ok(ExpiredRequests::default());
        }
        let expired = ExpiredRequests {
            headers: self
                .pending_headers
                .is_some_and(|pending| now > pending.deadline),
            proof: self
                .pending_proof
                .is_some_and(|pending| now > pending.deadline),
            ping: self
                .pending_ping
                .is_some_and(|pending| now > pending.deadline),
        };
        if expired.headers {
            self.pending_headers = None;
        }
        if expired.proof {
            self.pending_proof = None;
        }
        if expired.ping {
            self.pending_ping = None;
        }
        Ok(expired)
    }

    fn handle_version(&mut self, packet: Packet, now: u64) -> Result<PeerEvent, PeerError> {
        let Packet::Version(version) = packet else {
            return Err(PeerError::ExpectedVersion);
        };
        if version.version < hns_p2p_wire::MIN_PROTOCOL_VERSION {
            return Err(PeerError::ObsoleteVersion);
        }
        if version.services & self.config.required_services != self.config.required_services {
            return Err(PeerError::MissingService);
        }
        if version.nonce == self.local_nonce {
            return Err(PeerError::SelfConnection);
        }
        if version.time.abs_diff(now) > self.config.max_clock_skew_seconds {
            return Err(PeerError::ClockSkew);
        }
        self.metadata = Some(PeerMetadata {
            version: version.version.min(hns_p2p_wire::PROTOCOL_VERSION),
            services: version.services,
            time: version.time,
            agent: version.agent,
            height: version.height,
        });
        self.state = PeerState::AwaitingVerack;
        Ok(PeerEvent::Send(Frame::from_packet(&Packet::Verack)?))
    }

    fn handle_ready(&mut self, packet: Packet, now: u64) -> Result<PeerEvent, PeerError> {
        match packet {
            Packet::Version(_) | Packet::Verack => Err(PeerError::DuplicateHandshake),
            Packet::Ping(nonce) => Ok(PeerEvent::Send(Frame::from_packet(&Packet::Pong(nonce))?)),
            Packet::Pong(nonce) => {
                let pending = self.pending_ping.ok_or(PeerError::UnsolicitedPong)?;
                if now > pending.deadline {
                    self.pending_ping = None;
                    return Err(PeerError::RequestTimeout(RequestKind::Ping));
                }
                if pending.nonce != nonce {
                    return Err(PeerError::WrongPong);
                }
                self.pending_ping = None;
                Ok(PeerEvent::Pong(nonce))
            }
            Packet::Headers(headers) => {
                let pending = self
                    .pending_headers
                    .take()
                    .ok_or(PeerError::UnsolicitedHeaders)?;
                if now > pending.deadline {
                    return Err(PeerError::RequestTimeout(RequestKind::Headers));
                }
                Ok(PeerEvent::Headers(headers))
            }
            Packet::Proof(proof) => {
                let pending = self
                    .pending_proof
                    .take()
                    .ok_or(PeerError::UnsolicitedProof)?;
                if now > pending.deadline {
                    return Err(PeerError::RequestTimeout(RequestKind::Proof));
                }
                if proof.root != pending.root || proof.key != pending.key {
                    return Err(PeerError::WrongProof);
                }
                Ok(PeerEvent::Proof(proof))
            }
            Packet::Addr(addresses) => Ok(PeerEvent::Addresses(addresses)),
            Packet::Reject(reject) => Ok(PeerEvent::Rejected(reject)),
            Packet::Inv(inventory) => Ok(PeerEvent::Wallet(WalletPeerEvent::Inventory(inventory))),
            Packet::GetData(inventory) => {
                Ok(PeerEvent::Wallet(WalletPeerEvent::DataRequest(inventory)))
            }
            Packet::NotFound(inventory) => {
                Ok(PeerEvent::Wallet(WalletPeerEvent::NotFound(inventory)))
            }
            Packet::Tx(transaction) => {
                Ok(PeerEvent::Wallet(WalletPeerEvent::Transaction(transaction)))
            }
            Packet::MerkleBlock(payload) => {
                Ok(PeerEvent::Wallet(WalletPeerEvent::MerkleBlock(payload)))
            }
            Packet::FeeFilter(rate) => Ok(PeerEvent::Wallet(WalletPeerEvent::FeeFilter(rate))),
            Packet::Unknown {
                packet_type,
                payload,
            } => Ok(PeerEvent::Experimental {
                packet_type,
                payload,
            }),
            packet => Ok(PeerEvent::Ignored(packet.packet_type())),
        }
    }

    fn require_ready(&self) -> Result<(), PeerError> {
        match self.state {
            PeerState::Ready => Ok(()),
            PeerState::Closed => Err(PeerError::Closed),
            PeerState::AwaitingVersion | PeerState::AwaitingVerack => Err(PeerError::NotReady),
        }
    }

    fn request_deadline(&self, now: u64) -> Result<u64, PeerError> {
        now.checked_add(self.config.request_timeout_seconds)
            .ok_or(PeerError::TimeOverflow)
    }
}

impl<T: Read + Write> PeerConnection<T> {
    /// Start a standard session and immediately write the local version frame.
    pub fn start(
        transport: T,
        config: PeerConfig,
        local_version: &VersionPacket,
        now: u64,
    ) -> Result<Self, PeerError> {
        let (session, version) = PeerSession::start(config, local_version, now)?;
        let decoder = FrameDecoder::new(session.network());
        let mut connection = Self {
            transport,
            session,
            decoder,
            pending: VecDeque::new(),
        };
        connection.send_frame(&version)?;
        Ok(connection)
    }

    /// Immutable admitted session state.
    #[must_use]
    pub const fn session(&self) -> &PeerSession {
        &self.session
    }

    /// Mutable admitted session state for explicit request construction.
    #[must_use]
    pub const fn session_mut(&mut self) -> &mut PeerSession {
        &mut self.session
    }

    /// Underlying host stream.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Mutable underlying host stream.
    #[must_use]
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consume the peer and return its host stream.
    pub fn into_inner(self) -> T {
        self.transport
    }

    /// Complete version/verack while sampling the caller's monotonic Unix
    /// clock before every admitted frame.
    pub fn complete_handshake(
        &mut self,
        mut now_unix: impl FnMut() -> u64,
    ) -> Result<PeerMetadata, PeerError> {
        if self.session.state() == PeerState::Ready {
            return self
                .session
                .metadata()
                .cloned()
                .ok_or(PeerError::InternalInvariant);
        }
        loop {
            match self.receive_event(now_unix())? {
                PeerEvent::Ready(metadata) => return Ok(metadata),
                PeerEvent::Ignored(_) | PeerEvent::Addresses(_) => {}
                PeerEvent::Send(_)
                | PeerEvent::Headers(_)
                | PeerEvent::Proof(_)
                | PeerEvent::Pong(_)
                | PeerEvent::Rejected(_)
                | PeerEvent::Wallet(_)
                | PeerEvent::Experimental { .. } => {
                    return Err(PeerError::UnexpectedHandshakeEvent);
                }
            }
        }
    }

    /// Write one already-admitted frame completely.
    pub fn send_frame(&mut self, frame: &Frame) -> Result<(), PeerError> {
        let encoded = frame.encode(self.session.network())?;
        self.transport
            .write_all(&encoded)
            .map_err(|error| peer_io_error(&error))?;
        self.transport
            .flush()
            .map_err(|error| peer_io_error(&error))
    }

    /// Send one same-locator header request and arm exact response correlation.
    pub fn request_headers(
        &mut self,
        locator: Vec<BlockHash>,
        stop: BlockHash,
        now: u64,
    ) -> Result<(), PeerError> {
        let frame = self.session.request_headers(locator, stop, now)?;
        self.send_frame(&frame)
    }

    /// Send one exact-root/key name proof request.
    pub fn request_proof(
        &mut self,
        root: TreeRoot,
        key: NameHash,
        now: u64,
    ) -> Result<(), PeerError> {
        let frame = self.session.request_proof(root, key, now)?;
        self.send_frame(&frame)
    }

    /// Send one admitted BIP37, inventory, mempool, or transaction packet.
    pub fn send_wallet_packet(&mut self, packet: &Packet) -> Result<(), PeerError> {
        let frame = self.session.wallet_frame(packet)?;
        self.send_frame(&frame)
    }

    /// Send one explicitly selected experimental packet after the standard
    /// handshake. This does not negotiate or authorize a subprotocol; callers
    /// must do both before treating any response as useful.
    pub fn send_experimental_packet(
        &mut self,
        packet_type: u8,
        payload: Vec<u8>,
    ) -> Result<(), PeerError> {
        self.session.require_ready()?;
        let frame = Frame::new(PacketType::Unknown(packet_type), payload)?;
        self.send_frame(&frame)
    }

    /// Request bounded standard peer addresses.
    pub fn request_addresses(&mut self) -> Result<(), PeerError> {
        let frame = self.session.address_request()?;
        self.send_frame(&frame)
    }

    /// Send one correlated liveness ping.
    pub fn ping(&mut self, nonce: [u8; 8], now: u64) -> Result<(), PeerError> {
        let frame = self.session.ping(nonce, now)?;
        self.send_frame(&frame)
    }

    /// Read and admit the next non-automatic peer event. Ping responses and
    /// the local verack are written internally before this method returns.
    pub fn receive_event(&mut self, now: u64) -> Result<PeerEvent, PeerError> {
        loop {
            let frame = self.receive_frame()?;
            match self.session.handle_frame(&frame, now)? {
                PeerEvent::Send(response) => self.send_frame(&response)?,
                event => return Ok(event),
            }
        }
    }

    /// Revoke requests and close the logical session without assuming that a
    /// host adapter has a transport-level shutdown primitive.
    pub fn close(&mut self) {
        self.session.close();
        self.pending.clear();
    }

    fn receive_frame(&mut self) -> Result<Frame, PeerError> {
        if let Some(frame) = self.pending.pop_front() {
            return Ok(frame);
        }
        let mut input = [0_u8; PEER_READ_BUFFER_SIZE];
        loop {
            let read = self
                .transport
                .read(&mut input)
                .map_err(|error| peer_io_error(&error))?;
            if read == 0 {
                return Err(PeerError::ConnectionClosed);
            }
            let bytes = input.get(..read).ok_or(PeerError::InternalInvariant)?;
            let frames = self.decoder.push(bytes)?;
            if self.pending.len().saturating_add(frames.len()) > MAX_PENDING_PEER_FRAMES {
                return Err(PeerError::FrameQueueLimit);
            }
            self.pending.extend(frames);
            if let Some(frame) = self.pending.pop_front() {
                return Ok(frame);
            }
        }
    }
}

impl PeerConnection<TcpStream> {
    /// Connect a native socket, install bounded I/O timeouts, and send the
    /// standard local version frame.
    pub fn connect(
        address: SocketAddr,
        config: PeerConfig,
        local_version: &VersionPacket,
        now: u64,
        connect_timeout: Duration,
    ) -> Result<Self, PeerError> {
        if connect_timeout.is_zero() || connect_timeout > Duration::from_secs(300) {
            return Err(PeerError::InvalidConnectTimeout);
        }
        let config = config.validate()?;
        let stream = TcpStream::connect_timeout(&address, connect_timeout)
            .map_err(|error| peer_io_error(&error))?;
        configure_native_stream(&stream, config)?;
        Self::start(stream, config, local_version, now)
    }

    /// Bind an already accepted native socket to a bounded standard HSD
    /// session and immediately advertise the local version frame.
    ///
    /// This is deliberately only the socket/session adapter. Callers own
    /// listener lifecycle, admission policy, and every protocol service above
    /// the standard version/verack exchange.
    pub fn accept(
        stream: TcpStream,
        config: PeerConfig,
        local_version: &VersionPacket,
        now: u64,
    ) -> Result<Self, PeerError> {
        let config = config.validate()?;
        configure_native_stream(&stream, config)?;
        Self::start(stream, config, local_version, now)
    }

    /// Close both directions of the native socket and revoke session state.
    pub fn shutdown(&mut self) -> Result<(), PeerError> {
        self.close();
        self.transport
            .shutdown(Shutdown::Both)
            .map_err(|error| peer_io_error(&error))
    }
}

fn configure_native_stream(stream: &TcpStream, config: PeerConfig) -> Result<(), PeerError> {
    let io_timeout = Duration::from_secs(
        config
            .handshake_timeout_seconds
            .max(config.request_timeout_seconds),
    );
    stream
        .set_read_timeout(Some(io_timeout))
        .map_err(|error| peer_io_error(&error))?;
    stream
        .set_write_timeout(Some(io_timeout))
        .map_err(|error| peer_io_error(&error))?;
    stream
        .set_nodelay(true)
        .map_err(|error| peer_io_error(&error))
}

/// Construct the standard version packet for a non-serving light wallet.
#[must_use]
pub fn light_wallet_version(
    remote: SocketAddr,
    nonce: [u8; 8],
    height: u32,
    now: u64,
) -> VersionPacket {
    VersionPacket {
        version: hns_p2p_wire::PROTOCOL_VERSION,
        services: 0,
        time: now,
        remote: NetAddress::from_socket_addr(remote, now, 0),
        nonce,
        agent: concat!("/hns-light-wallet:", env!("CARGO_PKG_VERSION"), "/").to_owned(),
        height,
        no_relay: false,
    }
}

fn peer_io_error(error: &std::io::Error) -> PeerError {
    PeerError::Io(error.kind())
}

/// Standard peer handshake, correlation, or deadline failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PeerError {
    /// Canonical shared wire codec failed.
    #[error("standard Handshake wire failure: {0}")]
    Wire(#[from] WireError),
    /// Host stream read, write, flush, or connection failed.
    #[error("standard Handshake peer I/O failed: {0:?}")]
    Io(std::io::ErrorKind),
    /// The host stream ended before the session completed.
    #[error("standard Handshake peer closed the connection")]
    ConnectionClosed,
    /// One host read decoded more queued frames than the bounded adapter admits.
    #[error("standard Handshake peer frame queue exceeded its bound")]
    FrameQueueLimit,
    /// Session configuration is zero, excessive, or omits NETWORK service.
    #[error("invalid light-peer configuration")]
    InvalidConfig,
    /// Native connection timeout is zero or exceeds the five-minute bound.
    #[error("invalid native peer connection timeout")]
    InvalidConnectTimeout,
    /// Local version has a zero nonce, obsolete version, or implausible timestamp.
    #[error("invalid local version packet")]
    InvalidLocalVersion,
    /// Clock/deadline arithmetic overflowed.
    #[error("peer deadline overflow")]
    TimeOverflow,
    /// Version/verack did not complete by its deadline.
    #[error("peer handshake timed out")]
    HandshakeTimeout,
    /// Version was required before this packet.
    #[error("expected remote version packet")]
    ExpectedVersion,
    /// Verack was required after remote version.
    #[error("expected remote verack packet")]
    ExpectedVerack,
    /// Remote protocol version is obsolete.
    #[error("remote Handshake protocol version is obsolete")]
    ObsoleteVersion,
    /// Remote omitted a required standard service.
    #[error("remote peer omitted a required service")]
    MissingService,
    /// Wallet traffic requires a peer that advertised standard bloom service.
    #[error("remote peer omitted the standard bloom-filter service")]
    MissingBloomService,
    /// Remote nonce identifies a self-connection.
    #[error("remote version nonce matches local nonce")]
    SelfConnection,
    /// Remote version timestamp exceeds configured skew.
    #[error("remote version timestamp exceeds clock-skew policy")]
    ClockSkew,
    /// Handshake packet repeated after readiness.
    #[error("duplicate version or verack")]
    DuplicateHandshake,
    /// Request was attempted before version/verack.
    #[error("peer session is not ready")]
    NotReady,
    /// Session has been closed.
    #[error("peer session is closed")]
    Closed,
    /// Block locator cannot be empty.
    #[error("header locator is empty")]
    EmptyLocator,
    /// A response-bearing request of this kind is already outstanding.
    #[error("duplicate outstanding {0:?} request")]
    DuplicateRequest(RequestKind),
    /// A response arrived after its exact request deadline.
    #[error("{0:?} response arrived after its request deadline")]
    RequestTimeout(RequestKind),
    /// Peer sent headers without an outstanding request.
    #[error("unsolicited headers packet")]
    UnsolicitedHeaders,
    /// Peer sent proof without an outstanding request.
    #[error("unsolicited proof packet")]
    UnsolicitedProof,
    /// Proof root or name key differs from the exact request.
    #[error("proof response does not match requested root and key")]
    WrongProof,
    /// Peer sent pong without an outstanding ping.
    #[error("unsolicited pong")]
    UnsolicitedPong,
    /// Pong nonce differs from the outstanding ping.
    #[error("pong nonce mismatch")]
    WrongPong,
    /// Zero ping nonce is not admitted.
    #[error("ping nonce must be nonzero")]
    ZeroPingNonce,
    /// Packet is not part of the admitted client-side wallet flow.
    #[error("unsupported outbound wallet packet: {0:?}")]
    UnsupportedWalletPacket(PacketType),
    /// Internal handshake metadata invariant failed.
    #[error("peer session internal invariant failed")]
    InternalInvariant,
    /// A response-bearing event appeared while version/verack was incomplete.
    #[error("unexpected event during standard peer handshake")]
    UnexpectedHandshakeEvent,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid local peer fixtures"
)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::thread;

    use hns_p2p_wire::{InventoryKind, NetAddress, Packet};

    use super::*;

    #[derive(Debug)]
    struct ScriptedIo {
        inbound: VecDeque<u8>,
        outbound: Vec<u8>,
        read_chunk: usize,
    }

    impl ScriptedIo {
        fn new(inbound: Vec<u8>, read_chunk: usize) -> Self {
            Self {
                inbound: inbound.into(),
                outbound: Vec::new(),
                read_chunk,
            }
        }
    }

    impl Read for ScriptedIo {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let length = output.len().min(self.read_chunk).min(self.inbound.len());
            for byte in output.iter_mut().take(length) {
                *byte = self.inbound.pop_front().unwrap();
            }
            Ok(length)
        }
    }

    impl Write for ScriptedIo {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            self.outbound.extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn version(nonce: [u8; 8], now: u64) -> VersionPacket {
        VersionPacket {
            version: hns_p2p_wire::PROTOCOL_VERSION,
            services: SERVICE_NETWORK,
            time: now,
            remote: NetAddress::from_socket_addr(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12_038),
                now,
                SERVICE_NETWORK,
            ),
            nonce,
            agent: "/hns-light-p2p:test/".to_owned(),
            height: 100,
            no_relay: true,
        }
    }

    fn ready(now: u64) -> PeerSession {
        let (mut session, local) = PeerSession::start(
            PeerConfig::for_network(NetworkMagic::Regtest),
            &version([1; 8], now),
            now,
        )
        .unwrap();
        assert!(matches!(local.decode_packet().unwrap(), Packet::Version(_)));
        let remote = Frame::from_packet(&Packet::Version(version([2; 8], now))).unwrap();
        assert!(matches!(
            session.handle_frame(&remote, now).unwrap(),
            PeerEvent::Send(_)
        ));
        let verack = Frame::from_packet(&Packet::Verack).unwrap();
        assert!(matches!(
            session.handle_frame(&verack, now).unwrap(),
            PeerEvent::Ready(_)
        ));
        session
    }

    fn ready_wallet(now: u64) -> PeerSession {
        let mut local_version = version([3; 8], now);
        local_version.services = 0;
        let (mut session, _) = PeerSession::start(
            PeerConfig::for_wallet_network(NetworkMagic::Regtest),
            &local_version,
            now,
        )
        .unwrap();
        let mut remote_version = version([4; 8], now);
        remote_version.services |= SERVICE_BLOOM;
        let remote = Frame::from_packet(&Packet::Version(remote_version)).unwrap();
        assert!(matches!(
            session.handle_frame(&remote, now).unwrap(),
            PeerEvent::Send(_)
        ));
        let verack = Frame::from_packet(&Packet::Verack).unwrap();
        assert!(matches!(
            session.handle_frame(&verack, now).unwrap(),
            PeerEvent::Ready(_)
        ));
        session
    }

    #[test]
    fn accepted_native_socket_completes_the_standard_handshake() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let now = 1_700_000_000;
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut connection = PeerConnection::accept(
                stream,
                PeerConfig::for_network(NetworkMagic::Regtest),
                &version([2; 8], now),
                now,
            )
            .unwrap();
            connection.complete_handshake(|| now).unwrap()
        });

        let mut client = PeerConnection::connect(
            address,
            PeerConfig::for_network(NetworkMagic::Regtest),
            &version([1; 8], now),
            now,
            Duration::from_secs(1),
        )
        .unwrap();
        let client_metadata = client.complete_handshake(|| now).unwrap();
        let server_metadata = server.join().unwrap();

        assert_eq!(client_metadata.services, SERVICE_NETWORK);
        assert_eq!(server_metadata.services, SERVICE_NETWORK);
    }

    #[test]
    fn completes_standard_handshake_and_rejects_invalid_versions() {
        let now = 1_700_000_000;
        let session = ready(now);
        assert_eq!(session.state(), PeerState::Ready);
        assert_eq!(session.metadata().unwrap().height, 100);

        let mut local_light_client = version([9; 8], now);
        local_light_client.services = 0;
        assert!(
            PeerSession::start(
                PeerConfig::for_network(NetworkMagic::Mainnet),
                &local_light_client,
                now
            )
            .is_ok()
        );

        let (mut self_peer, _) = PeerSession::start(
            PeerConfig::for_network(NetworkMagic::Mainnet),
            &version([3; 8], now),
            now,
        )
        .unwrap();
        let frame = Frame::from_packet(&Packet::Version(version([3; 8], now))).unwrap();
        assert!(matches!(
            self_peer.handle_frame(&frame, now),
            Err(PeerError::SelfConnection)
        ));

        let (mut missing_service, _) = PeerSession::start(
            PeerConfig::for_network(NetworkMagic::Mainnet),
            &version([4; 8], now),
            now,
        )
        .unwrap();
        let mut remote = version([5; 8], now);
        remote.services = 0;
        let frame = Frame::from_packet(&Packet::Version(remote)).unwrap();
        assert!(matches!(
            missing_service.handle_frame(&frame, now),
            Err(PeerError::MissingService)
        ));
    }

    #[test]
    fn correlates_one_header_request_and_expires_duplicates() {
        let now = 1_700_000_000;
        let mut session = ready(now);
        let request = session
            .request_headers(vec![BlockHash::new([1; 32])], BlockHash::default(), now)
            .unwrap();
        assert!(matches!(
            request.decode_packet().unwrap(),
            Packet::GetHeaders(_)
        ));
        assert!(matches!(
            session.request_headers(vec![BlockHash::new([1; 32])], BlockHash::default(), now,),
            Err(PeerError::DuplicateRequest(RequestKind::Headers))
        ));
        let headers = Frame::from_packet(&Packet::Headers(Vec::new())).unwrap();
        assert_eq!(
            session.handle_frame(&headers, now).unwrap(),
            PeerEvent::Headers(Vec::new())
        );
        assert!(matches!(
            session.handle_frame(&headers, now),
            Err(PeerError::UnsolicitedHeaders)
        ));

        session
            .request_headers(vec![BlockHash::new([2; 32])], BlockHash::default(), now)
            .unwrap();
        let expired = session
            .expire(now + DEFAULT_REQUEST_TIMEOUT_SECONDS + 1)
            .unwrap();
        assert!(expired.headers);
        assert!(matches!(
            session.handle_frame(&headers, now + DEFAULT_REQUEST_TIMEOUT_SECONDS + 1),
            Err(PeerError::UnsolicitedHeaders)
        ));

        session
            .request_headers(vec![BlockHash::new([3; 32])], BlockHash::default(), now)
            .unwrap();
        assert!(matches!(
            session.handle_frame(&headers, now + DEFAULT_REQUEST_TIMEOUT_SECONDS + 1),
            Err(PeerError::RequestTimeout(RequestKind::Headers))
        ));
        assert!(matches!(
            session.handle_frame(&headers, now + DEFAULT_REQUEST_TIMEOUT_SECONDS + 1),
            Err(PeerError::UnsolicitedHeaders)
        ));
    }

    #[test]
    fn proof_root_key_and_ping_nonce_are_exactly_correlated() {
        let now = 1_700_000_000;
        let mut session = ready(now);
        let root = TreeRoot::new([7; 32]);
        let key = NameHash::new([8; 32]);
        session.request_proof(root, key, now).unwrap();

        let mut payload = Vec::new();
        payload.extend_from_slice(root.as_bytes());
        payload.extend_from_slice(NameHash::new([9; 32]).as_bytes());
        payload.extend_from_slice(&[0, 0, 0, 0]);
        let wrong = Frame::new(PacketType::Proof, payload).unwrap();
        assert!(matches!(
            session.handle_frame(&wrong, now),
            Err(PeerError::WrongProof)
        ));

        session.request_proof(root, key, now).unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(root.as_bytes());
        payload.extend_from_slice(key.as_bytes());
        payload.extend_from_slice(&[0, 0, 0, 0]);
        let proof = Frame::new(PacketType::Proof, payload).unwrap();
        assert!(matches!(
            session.handle_frame(&proof, now).unwrap(),
            PeerEvent::Proof(_)
        ));

        let request_frame = session.ping([4; 8], now).unwrap();
        assert!(matches!(
            request_frame.decode_packet().unwrap(),
            Packet::Ping(_)
        ));
        let wrong_pong = Frame::from_packet(&Packet::Pong([5; 8])).unwrap();
        assert!(matches!(
            session.handle_frame(&wrong_pong, now),
            Err(PeerError::WrongPong)
        ));
        let response_frame = Frame::from_packet(&Packet::Pong([4; 8])).unwrap();
        assert_eq!(
            session.handle_frame(&response_frame, now).unwrap(),
            PeerEvent::Pong([4; 8])
        );
    }

    #[test]
    fn answers_ping_and_times_out_incomplete_handshake() {
        let now = 1_700_000_000;
        let mut session = ready(now);
        let inbound = Frame::from_packet(&Packet::Ping([6; 8])).unwrap();
        let outbound = match session.handle_frame(&inbound, now).unwrap() {
            PeerEvent::Send(frame) => Some(frame),
            _ => None,
        }
        .unwrap();
        assert_eq!(outbound.decode_packet().unwrap(), Packet::Pong([6; 8]));

        let (mut incomplete, _) = PeerSession::start(
            PeerConfig::for_network(NetworkMagic::Regtest),
            &version([1; 8], now),
            now,
        )
        .unwrap();
        assert!(matches!(
            incomplete.expire(now + DEFAULT_HANDSHAKE_TIMEOUT_SECONDS + 1),
            Err(PeerError::HandshakeTimeout)
        ));
        assert_eq!(incomplete.state(), PeerState::Closed);
    }

    #[test]
    fn admits_only_standard_wallet_flow_for_bloom_peers() {
        let now = 1_700_000_000;
        let mut session = ready_wallet(now);
        let filter = Packet::FilterLoad(vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            session
                .wallet_frame(&filter)
                .unwrap()
                .decode_packet()
                .unwrap(),
            filter
        );
        assert!(matches!(
            session.wallet_frame(&Packet::Ping([7; 8])),
            Err(PeerError::UnsupportedWalletPacket(PacketType::Ping))
        ));

        let inventory = vec![Inventory {
            kind: InventoryKind::FilteredBlock,
            hash: [9; 32],
        }];
        let announced = Frame::from_packet(&Packet::Inv(inventory.clone())).unwrap();
        assert_eq!(
            session.handle_frame(&announced, now).unwrap(),
            PeerEvent::Wallet(WalletPeerEvent::Inventory(inventory))
        );
        let merkle = Frame::from_packet(&Packet::MerkleBlock(vec![8; 64])).unwrap();
        assert_eq!(
            session.handle_frame(&merkle, now).unwrap(),
            PeerEvent::Wallet(WalletPeerEvent::MerkleBlock(vec![8; 64]))
        );

        let header_only = ready(now);
        assert!(matches!(
            header_only.wallet_frame(&Packet::FilterClear),
            Err(PeerError::MissingBloomService)
        ));
    }

    #[test]
    fn preserves_bounded_unknown_packets_only_after_standard_handshake() {
        let now = 1_700_000_000;
        let mut session = ready(now);
        let experimental = Frame::from_packet(&Packet::Unknown {
            packet_type: 0xf4,
            payload: vec![1, 2, 3],
        })
        .unwrap();
        assert_eq!(
            session.handle_frame(&experimental, now).unwrap(),
            PeerEvent::Experimental {
                packet_type: 0xf4,
                payload: vec![1, 2, 3],
            }
        );
    }

    #[test]
    fn experimental_send_requires_standard_handshake() {
        let now = 1_700_000_000;
        let (session, _) = PeerSession::start(
            PeerConfig::for_network(NetworkMagic::Regtest),
            &version([1; 8], now),
            now,
        )
        .unwrap();
        let mut connection = PeerConnection {
            transport: ScriptedIo::new(Vec::new(), 1),
            session,
            decoder: FrameDecoder::new(NetworkMagic::Regtest),
            pending: VecDeque::new(),
        };
        assert!(matches!(
            connection.send_experimental_packet(0xf4, vec![1]),
            Err(PeerError::NotReady)
        ));
    }

    #[test]
    fn fragmented_stream_adapter_drives_handshake_headers_discovery_and_wallet_frames() {
        let now = 1_700_000_000;
        let remote_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14_038);
        let mut remote_version = version([8; 8], now);
        remote_version.services |= SERVICE_BLOOM;
        let discovered = NetAddress::from_socket_addr(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 14_038),
            now,
            SERVICE_NETWORK | SERVICE_BLOOM,
        );
        let inbound_packets = [
            Packet::Version(remote_version),
            Packet::Verack,
            Packet::Headers(Vec::new()),
            Packet::Addr(vec![discovered.clone()]),
            Packet::Ping([9; 8]),
            Packet::FeeFilter(2_000),
        ];
        let mut inbound = Vec::new();
        for packet in &inbound_packets {
            inbound.extend(
                Frame::from_packet(packet)
                    .unwrap()
                    .encode(NetworkMagic::Regtest)
                    .unwrap(),
            );
        }
        let local_version = light_wallet_version(remote_address, [7; 8], 42, now);
        let mut connection = PeerConnection::start(
            ScriptedIo::new(inbound, 7),
            PeerConfig::for_wallet_network(NetworkMagic::Regtest),
            &local_version,
            now,
        )
        .unwrap();
        let metadata = connection.complete_handshake(|| now).unwrap();
        assert_eq!(metadata.height, 100);
        assert_eq!(connection.session().state(), PeerState::Ready);

        connection
            .request_headers(vec![BlockHash::new([1; 32])], BlockHash::default(), now)
            .unwrap();
        assert_eq!(
            connection.receive_event(now).unwrap(),
            PeerEvent::Headers(Vec::new())
        );
        connection.request_addresses().unwrap();
        assert_eq!(
            connection.receive_event(now).unwrap(),
            PeerEvent::Addresses(vec![discovered])
        );
        connection
            .send_wallet_packet(&Packet::FilterLoad(vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
            .unwrap();
        assert_eq!(
            connection.receive_event(now).unwrap(),
            PeerEvent::Wallet(WalletPeerEvent::FeeFilter(2_000))
        );

        let io = connection.into_inner();
        let mut decoder = FrameDecoder::new(NetworkMagic::Regtest);
        let packets = decoder
            .push(&io.outbound)
            .unwrap()
            .into_iter()
            .map(|frame| frame.decode_packet().unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(packets.first(), Some(Packet::Version(_))));
        assert_eq!(packets.get(1), Some(&Packet::Verack));
        assert!(matches!(packets.get(2), Some(Packet::GetHeaders(_))));
        assert_eq!(packets.get(3), Some(&Packet::GetAddr));
        assert!(matches!(packets.get(4), Some(Packet::FilterLoad(_))));
        assert_eq!(packets.get(5), Some(&Packet::Pong([9; 8])));
    }
}
