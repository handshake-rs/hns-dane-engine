use crate::{
    HeaderSyncSession, P2pError, Packet, PeerAddressGroup, PeerConnection, PeerManager,
    VersionPacket,
};
use hns_core::dns::{DnsMessage, RecordType};
use hns_core::network::Network;
use hns_core::validate_handshake_name;
use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[cfg(test)]
use hns_core::Height;

/// Temporary, private service bit for the DNS-relay experiment.
///
/// This is deliberately not presented as a permanent Handshake assignment.
pub const EXPERIMENTAL_DNS_RELAY_SERVICE: u64 = 0x4000_0000;
/// Temporary, private request packet number for the DNS-relay experiment.
pub const EXPERIMENTAL_GET_DNS_RELAY: u8 = 0xf0;
/// Temporary, private response packet number for the DNS-relay experiment.
pub const EXPERIMENTAL_DNS_RELAY: u8 = 0xf1;

pub const MAX_DNS_RELAY_QUERY_SIZE: usize = 4 * 1024;
pub const MAX_DNS_RELAY_RESPONSE_SIZE: usize = u16::MAX as usize;
pub const MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE: usize = 8 + 2 + MAX_DNS_RELAY_QUERY_SIZE;
pub const MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE: usize = 8 + 1 + 2 + MAX_DNS_RELAY_RESPONSE_SIZE;
pub const DEFAULT_DNS_RELAY_TIMEOUT: Duration = Duration::from_secs(3);
pub const DEFAULT_MAX_DNS_RELAY_CONNECTIONS: usize = 2;
pub const DEFAULT_DNS_RELAY_ALTERNATE_RETRIES: usize = 1;
pub const MAX_DNS_RELAY_HANDSHAKE_ATTEMPTS_PER_RESOLUTION: usize = 4;
pub const DEFAULT_DNS_RELAY_COOLDOWN_SECONDS: u64 = 30;
pub const DEFAULT_DNS_RELAY_MALFORMED_BAN_SECONDS: u64 = 10 * 60;

const MAX_ADVISORY_PACKETS_PER_EXCHANGE: usize = 32;
const MAX_PACKETS_PER_HANDSHAKE: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DnsRelayStatus {
    Ok = 0,
    Refused = 1,
    Unsupported = 2,
    Busy = 3,
    InvalidQuery = 4,
    ResolverUnavailable = 5,
    Timeout = 6,
    InternalError = 7,
}

impl TryFrom<u8> for DnsRelayStatus {
    type Error = P2pError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Refused),
            2 => Ok(Self::Unsupported),
            3 => Ok(Self::Busy),
            4 => Ok(Self::InvalidQuery),
            5 => Ok(Self::ResolverUnavailable),
            6 => Ok(Self::Timeout),
            7 => Ok(Self::InternalError),
            _ => Err(P2pError::InvalidDnsRelayStatus),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetDnsRelayPacket {
    pub request_id: u64,
    pub query: Vec<u8>,
}

impl GetDnsRelayPacket {
    pub fn new(request_id: u64, query: Vec<u8>) -> Result<Self, P2pError> {
        let packet = Self { request_id, query };
        packet.validate()?;
        Ok(packet)
    }

    pub fn encode(&self) -> Result<Vec<u8>, P2pError> {
        self.validate()?;
        let mut out = Vec::with_capacity(10 + self.query.len());
        out.extend(self.request_id.to_le_bytes());
        out.extend((self.query.len() as u16).to_le_bytes());
        out.extend(&self.query);
        Ok(out)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, P2pError> {
        if payload.len() < 10 {
            return Err(hns_core::bytes::ParseError::UnexpectedEof.into());
        }

        let request_id = u64::from_le_bytes(payload[..8].try_into().expect("checked request id"));
        if request_id == 0 {
            return Err(P2pError::InvalidDnsRelayRequestId);
        }
        let query_len =
            u16::from_le_bytes(payload[8..10].try_into().expect("checked query length")) as usize;
        if query_len > MAX_DNS_RELAY_QUERY_SIZE {
            return Err(P2pError::DnsRelayQueryTooLarge);
        }
        let expected = 10usize
            .checked_add(query_len)
            .ok_or(P2pError::DnsRelayQueryTooLarge)?;
        if payload.len() < expected {
            return Err(hns_core::bytes::ParseError::UnexpectedEof.into());
        }
        if payload.len() > expected {
            return Err(P2pError::TrailingBytes);
        }

        Self::new(request_id, payload[10..expected].to_vec())
    }

    fn validate(&self) -> Result<(), P2pError> {
        if self.request_id == 0 {
            return Err(P2pError::InvalidDnsRelayRequestId);
        }
        if self.query.is_empty() {
            return Err(P2pError::InvalidDnsRelayPacket("DNS-relay query is empty"));
        }
        if self.query.len() > MAX_DNS_RELAY_QUERY_SIZE {
            return Err(P2pError::DnsRelayQueryTooLarge);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRelayPacket {
    pub request_id: u64,
    pub status: DnsRelayStatus,
    pub response: Vec<u8>,
}

impl DnsRelayPacket {
    pub fn new(
        request_id: u64,
        status: DnsRelayStatus,
        response: Vec<u8>,
    ) -> Result<Self, P2pError> {
        let packet = Self {
            request_id,
            status,
            response,
        };
        packet.validate()?;
        Ok(packet)
    }

    pub fn encode(&self) -> Result<Vec<u8>, P2pError> {
        self.validate()?;
        let mut out = Vec::with_capacity(11 + self.response.len());
        out.extend(self.request_id.to_le_bytes());
        out.push(self.status as u8);
        out.extend((self.response.len() as u16).to_le_bytes());
        out.extend(&self.response);
        Ok(out)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, P2pError> {
        if payload.len() < 11 {
            return Err(hns_core::bytes::ParseError::UnexpectedEof.into());
        }

        let request_id = u64::from_le_bytes(payload[..8].try_into().expect("checked request id"));
        if request_id == 0 {
            return Err(P2pError::InvalidDnsRelayRequestId);
        }
        let status = DnsRelayStatus::try_from(payload[8])?;
        let response_len =
            u16::from_le_bytes(payload[9..11].try_into().expect("checked response length"))
                as usize;
        if response_len > MAX_DNS_RELAY_RESPONSE_SIZE {
            return Err(P2pError::DnsRelayResponseTooLarge);
        }
        let expected = 11usize
            .checked_add(response_len)
            .ok_or(P2pError::DnsRelayResponseTooLarge)?;
        if payload.len() < expected {
            return Err(hns_core::bytes::ParseError::UnexpectedEof.into());
        }
        if payload.len() > expected {
            return Err(P2pError::TrailingBytes);
        }

        Self::new(request_id, status, payload[11..expected].to_vec())
    }

    fn validate(&self) -> Result<(), P2pError> {
        if self.request_id == 0 {
            return Err(P2pError::InvalidDnsRelayRequestId);
        }
        if self.response.len() > MAX_DNS_RELAY_RESPONSE_SIZE {
            return Err(P2pError::DnsRelayResponseTooLarge);
        }
        match (self.status, self.response.is_empty()) {
            (DnsRelayStatus::Ok, true) => Err(P2pError::InvalidDnsRelayPacket(
                "OK DNS-relay response is empty",
            )),
            (DnsRelayStatus::Ok, false) | (_, true) => Ok(()),
            (_, false) => Err(P2pError::InvalidDnsRelayPacket(
                "error DNS-relay response has a DNS body",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsRelayPeerCapability {
    pub address: SocketAddr,
    pub services: u64,
    pub fully_handshaken: bool,
    pub cooldown_until: Option<u64>,
}

impl DnsRelayPeerCapability {
    pub fn is_eligible(self, now: u64) -> bool {
        self.fully_handshaken
            && self.services & EXPERIMENTAL_DNS_RELAY_SERVICE != 0
            && self.cooldown_until.is_none_or(|until| until <= now)
    }
}

impl PeerManager {
    /// Selects from capabilities observed on live, completed version handshakes.
    ///
    /// Capability observations intentionally do not become part of `PeerState` or its SQLite
    /// representation, so a previous session can never authorize a request on a new session.
    pub fn select_dns_relay(
        &self,
        capabilities: &[DnsRelayPeerCapability],
        preferred_count: usize,
        now: u64,
        proof_peer: Option<SocketAddr>,
    ) -> Vec<SocketAddr> {
        let mut eligible = capabilities
            .iter()
            .copied()
            .filter(|capability| capability.is_eligible(now))
            .filter_map(|capability| {
                self.get(capability.address)
                    .filter(|state| !state.is_banned(now))
                    .map(|state| (capability.address, state))
            })
            .collect::<Vec<_>>();
        eligible.sort_by(|(left_address, left), (right_address, right)| {
            (*left_address == proof_peer.unwrap_or(*left_address))
                .cmp(&(*right_address == proof_peer.unwrap_or(*right_address)))
                .then_with(|| left.score.cmp(&right.score))
                .then_with(|| right.last_height.cmp(&left.last_height))
                .then_with(|| left_address.cmp(right_address))
        });
        eligible.dedup_by_key(|(address, _)| *address);

        let mut selected = Vec::new();
        let mut groups = HashSet::new();
        for (address, _) in &eligible {
            if selected.len() >= preferred_count {
                return selected;
            }
            if groups.insert(PeerAddressGroup::from_socket_addr(*address)) {
                selected.push(*address);
            }
        }
        for (address, _) in eligible {
            if selected.len() >= preferred_count {
                break;
            }
            if !selected.contains(&address) {
                selected.push(address);
            }
        }
        selected
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum DnsRelayValidationError {
    #[error("DNS message exceeds the relay limit")]
    MessageTooLarge,
    #[error("malformed DNS message")]
    MalformedMessage,
    #[error("DNS relay requires a standard QUERY")]
    NotStandardQuery,
    #[error("DNS relay requires exactly one question")]
    InvalidQuestionCount,
    #[error("DNS relay requires an IN-class question")]
    InvalidQuestionClass,
    #[error("DNS relay query contains response sections")]
    QueryHasResponseSections,
    #[error("DNS relay query has invalid header flags")]
    InvalidQueryFlags,
    #[error("DNS relay question type is not supported")]
    UnsupportedQuestionType,
    #[error("DNS relay question has an invalid Handshake root")]
    InvalidHnsRoot,
    #[error("DNS relay requires exactly one EDNS OPT record")]
    InvalidEdns,
    #[error("DNS relay EDNS payload size is outside 512 through 4096 bytes")]
    InvalidEdnsSize,
    #[error("DNSSEC OK is not set")]
    DnssecOkRequired,
    #[error("EDNS Client Subnet is forbidden")]
    EdnsClientSubnetForbidden,
    #[error("recursive DNS flags are inconsistent")]
    InvalidRecursiveFlags,
    #[error("DNS response identifier does not match")]
    ResponseIdMismatch,
    #[error("DNS response question does not match")]
    ResponseQuestionMismatch,
}

/// Validates and normalizes a caller-created recursive DNS query.
///
/// RD and CD are set in the returned wire message. The caller's buffer is never modified. EDNS DO
/// must already be present because adding an OPT record while preserving arbitrary compression is
/// not safe as an in-place operation.
pub fn prepare_dns_relay_query(query: &[u8]) -> Result<Vec<u8>, DnsRelayValidationError> {
    validate_dns_relay_query(query, false)?;
    let mut prepared = query.to_vec();
    let flags = u16::from_be_bytes([prepared[2], prepared[3]]) | 0x0110;
    prepared[2..4].copy_from_slice(&flags.to_be_bytes());
    validate_dns_relay_query(&prepared, true)?;
    Ok(prepared)
}

pub fn validate_dns_relay_response(
    prepared_query: &[u8],
    response: &[u8],
) -> Result<(), DnsRelayValidationError> {
    let query = validate_dns_relay_query(prepared_query, true)?;
    if response.len() > MAX_DNS_RELAY_RESPONSE_SIZE {
        return Err(DnsRelayValidationError::MessageTooLarge);
    }
    let response =
        DnsMessage::parse(response).map_err(|_| DnsRelayValidationError::MalformedMessage)?;
    if !response.header.flags.is_response() || response.header.flags.opcode() != 0 {
        return Err(DnsRelayValidationError::NotStandardQuery);
    }
    if response.questions.len() != 1 {
        return Err(DnsRelayValidationError::InvalidQuestionCount);
    }
    let flags = response.header.flags.bits();
    // RD must be echoed and the selected backend must actually offer recursion. CD is commonly
    // echoed too (including by bns), but it is not required in replies by the DNS protocol.
    if flags & 0x0100 == 0 || flags & 0x0080 == 0 {
        return Err(DnsRelayValidationError::InvalidRecursiveFlags);
    }
    if response.header.id != query.header.id {
        return Err(DnsRelayValidationError::ResponseIdMismatch);
    }
    if response.questions[0] != query.questions[0] {
        return Err(DnsRelayValidationError::ResponseQuestionMismatch);
    }
    Ok(())
}

fn validate_dns_relay_query(
    query: &[u8],
    require_recursive_flags: bool,
) -> Result<DnsMessage, DnsRelayValidationError> {
    if query.len() > MAX_DNS_RELAY_QUERY_SIZE {
        return Err(DnsRelayValidationError::MessageTooLarge);
    }
    let query = DnsMessage::parse(query).map_err(|_| DnsRelayValidationError::MalformedMessage)?;
    if query.header.flags.is_response() || query.header.flags.opcode() != 0 {
        return Err(DnsRelayValidationError::NotStandardQuery);
    }
    if query.questions.len() != 1 {
        return Err(DnsRelayValidationError::InvalidQuestionCount);
    }
    let flags = query.header.flags.bits();
    if flags & 0x06c0 != 0 || flags & 0x000f != 0 {
        return Err(DnsRelayValidationError::InvalidQueryFlags);
    }
    if query.questions[0].class != 1 {
        return Err(DnsRelayValidationError::InvalidQuestionClass);
    }
    if !is_supported_dns_relay_type(query.questions[0].record_type.code()) {
        return Err(DnsRelayValidationError::UnsupportedQuestionType);
    }
    let root = query.questions[0]
        .name
        .labels()
        .last()
        .ok_or(DnsRelayValidationError::InvalidHnsRoot)?;
    validate_handshake_name(root).map_err(|_| DnsRelayValidationError::InvalidHnsRoot)?;
    if !query.answers.is_empty() || !query.authorities.is_empty() {
        return Err(DnsRelayValidationError::QueryHasResponseSections);
    }
    if require_recursive_flags && (flags & 0x0100 == 0 || flags & 0x0010 == 0) {
        return Err(DnsRelayValidationError::InvalidRecursiveFlags);
    }

    if query.additionals.len() != 1 {
        return Err(DnsRelayValidationError::InvalidEdns);
    }
    let opt = &query.additionals[0];
    if opt.record_type != RecordType::Unknown(41) || !opt.name.labels().is_empty() {
        return Err(DnsRelayValidationError::InvalidEdns);
    }
    if !(512..=MAX_DNS_RELAY_QUERY_SIZE as u16).contains(&opt.class) {
        return Err(DnsRelayValidationError::InvalidEdnsSize);
    }
    if opt.ttl & 0x8000 == 0 {
        return Err(DnsRelayValidationError::DnssecOkRequired);
    }
    if opt.ttl != 0x8000 {
        return Err(DnsRelayValidationError::InvalidEdns);
    }
    validate_edns_options(&opt.rdata)?;
    Ok(query)
}

fn is_supported_dns_relay_type(code: u16) -> bool {
    matches!(
        code,
        1 | 2 | 5 | 6 | 15 | 16 | 28 | 33 | 39 | 43 | 46 | 47 | 48 | 50 | 51 | 52 | 64 | 65 | 257
    )
}

fn validate_edns_options(mut options: &[u8]) -> Result<(), DnsRelayValidationError> {
    while !options.is_empty() {
        if options.len() < 4 {
            return Err(DnsRelayValidationError::InvalidEdns);
        }
        let code = u16::from_be_bytes([options[0], options[1]]);
        let length = u16::from_be_bytes([options[2], options[3]]) as usize;
        options = &options[4..];
        if options.len() < length {
            return Err(DnsRelayValidationError::InvalidEdns);
        }
        if code == 8 {
            return Err(DnsRelayValidationError::EdnsClientSubnetForbidden);
        }
        if code != 12 {
            return Err(DnsRelayValidationError::InvalidEdns);
        }
        options = &options[length..];
    }
    Ok(())
}

pub trait DnsRelayPeerConnection {
    fn handshake(
        &mut self,
        local_version: VersionPacket,
        deadline: Instant,
    ) -> Result<VersionPacket, P2pError>;
    fn send_packet(&mut self, packet: &Packet, deadline: Instant) -> Result<(), P2pError>;
    fn receive_packet(&mut self, deadline: Instant) -> Result<Packet, P2pError>;
    fn close(&mut self) {}
}

pub trait DnsRelayPeerConnector {
    type Connection: DnsRelayPeerConnection;

    fn connect(
        &mut self,
        address: SocketAddr,
        network: &Network,
        timeout: Duration,
    ) -> Result<Self::Connection, P2pError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpDnsRelayPeerConnector;

impl DnsRelayPeerConnector for TcpDnsRelayPeerConnector {
    type Connection = PeerConnection<TcpStream>;

    fn connect(
        &mut self,
        address: SocketAddr,
        network: &Network,
        timeout: Duration,
    ) -> Result<Self::Connection, P2pError> {
        PeerConnection::connect(address, network.clone(), timeout)
    }
}

impl DnsRelayPeerConnection for PeerConnection<TcpStream> {
    fn handshake(
        &mut self,
        local_version: VersionPacket,
        deadline: Instant,
    ) -> Result<VersionPacket, P2pError> {
        let mut session = HeaderSyncSession::new(local_version);
        relay_apply_handshake_action(self, session.start(), deadline)?;

        for _ in 0..MAX_PACKETS_PER_HANDSHAKE {
            let packet = DnsRelayPeerConnection::receive_packet(self, deadline)?;
            for action in session.on_packet(packet) {
                match action {
                    crate::HeaderSyncAction::Ready => {
                        return session
                            .remote_version()
                            .cloned()
                            .ok_or(P2pError::UnexpectedAction);
                    }
                    action => relay_apply_handshake_action(self, action, deadline)?,
                }
            }
        }

        Err(P2pError::HandshakePacketLimit)
    }

    fn send_packet(&mut self, packet: &Packet, deadline: Instant) -> Result<(), P2pError> {
        relay_send_packet_until(self, packet, deadline, |stream, timeout| {
            stream.set_write_timeout(Some(timeout))
        })
    }

    fn receive_packet(&mut self, deadline: Instant) -> Result<Packet, P2pError> {
        relay_receive_packet_until(self, deadline, |stream, timeout| {
            stream.set_read_timeout(Some(timeout))
        })
    }

    fn close(&mut self) {
        let _ = self.transport_mut().shutdown(Shutdown::Both);
    }
}

/// Performs one bounded relay-capability handshake and closes the probe connection.
///
/// This is used for user-supplied static endpoints. The returned version is an observation from
/// the live connection only; in particular, its chain height must not become a sync target.
pub fn probe_dns_relay_peer(
    address: SocketAddr,
    network: &Network,
    timeout: Duration,
) -> Result<VersionPacket, P2pError> {
    let mut connector = TcpDnsRelayPeerConnector;
    let mut connection = connector.connect(address, network, timeout)?;
    let result = DnsRelayPeerConnection::handshake(
        &mut connection,
        relay_requester_version(),
        deadline_after(timeout),
    );
    DnsRelayPeerConnection::close(&mut connection);
    result
}

fn relay_requester_version() -> VersionPacket {
    // Relay-only connections neither serve chain data nor accept relay requests. Advertising no
    // local services prevents a full node from reasonably treating this connection as a header or
    // proof source while still allowing us to require those services from the remote peer.
    VersionPacket {
        services: 0,
        remote: crate::NetAddress {
            services: 0,
            ..crate::NetAddress::default()
        },
        ..VersionPacket::default()
    }
}

fn relay_apply_handshake_action(
    connection: &mut PeerConnection<TcpStream>,
    action: crate::HeaderSyncAction,
    deadline: Instant,
) -> Result<(), P2pError> {
    match action {
        crate::HeaderSyncAction::Send(packet) => {
            DnsRelayPeerConnection::send_packet(connection, &packet, deadline)
        }
        crate::HeaderSyncAction::Disconnect(reason) => Err(P2pError::SessionDisconnected(reason)),
        crate::HeaderSyncAction::Ready
        | crate::HeaderSyncAction::Headers(_)
        | crate::HeaderSyncAction::Proof(_) => Err(P2pError::UnexpectedAction),
    }
}

fn relay_send_packet_until<T, F>(
    connection: &mut PeerConnection<T>,
    packet: &Packet,
    deadline: Instant,
    mut set_timeout: F,
) -> Result<(), P2pError>
where
    T: Read + Write,
    F: FnMut(&mut T, Duration) -> std::io::Result<()>,
{
    let frame = crate::encode_frame(connection.network(), packet)?;
    let mut written = 0usize;

    while written < frame.len() {
        let remaining = remaining_until(deadline)?;
        set_timeout(connection.transport_mut(), remaining)
            .map_err(|error| deadline_io_error(error, deadline))?;
        let size = connection
            .transport_mut()
            .write(&frame[written..])
            .map_err(|error| deadline_io_error(error, deadline))?;
        if size == 0 {
            return Err(P2pError::Io(ErrorKind::WriteZero));
        }
        written = written.saturating_add(size);
    }

    let remaining = remaining_until(deadline)?;
    set_timeout(connection.transport_mut(), remaining)
        .map_err(|error| deadline_io_error(error, deadline))?;
    connection
        .transport_mut()
        .flush()
        .map_err(|error| deadline_io_error(error, deadline))
}

fn relay_receive_packet_until<T, F>(
    connection: &mut PeerConnection<T>,
    deadline: Instant,
    mut set_timeout: F,
) -> Result<Packet, P2pError>
where
    T: Read + Write,
    F: FnMut(&mut T, Duration) -> std::io::Result<()>,
{
    remaining_until(deadline)?;
    if let Some(packet) = connection.pending.pop_front() {
        return Ok(packet);
    }

    let mut buffer = [0u8; 8192];
    loop {
        let remaining = remaining_until(deadline)?;
        set_timeout(connection.transport_mut(), remaining)
            .map_err(|error| deadline_io_error(error, deadline))?;
        let read = connection
            .transport_mut()
            .read(&mut buffer)
            .map_err(|error| deadline_io_error(error, deadline))?;
        if read == 0 {
            return Err(P2pError::ConnectionClosed);
        }

        let packets = connection.decoder.feed(&buffer[..read])?;
        connection.pending.extend(packets);
        if let Some(packet) = connection.pending.pop_front() {
            return Ok(packet);
        }
    }
}

fn deadline_after(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout).unwrap_or(now)
}

fn remaining_until(deadline: Instant) -> Result<Duration, P2pError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(P2pError::Io(ErrorKind::TimedOut))
}

fn deadline_io_error(error: std::io::Error, deadline: Instant) -> P2pError {
    if Instant::now() >= deadline
        || matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
    {
        P2pError::Io(ErrorKind::TimedOut)
    } else {
        P2pError::Io(error.kind())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRelayExchange {
    pub response: Vec<u8>,
    pub peer: SocketAddr,
    pub retries: usize,
}

#[derive(Debug, Error)]
pub enum DnsRelayClientError {
    #[error("invalid DNS relay query: {0}")]
    InvalidQuery(DnsRelayValidationError),
    #[error("no live peer advertised the experimental DNS-relay service")]
    NoCapablePeer,
    #[error("request-id randomness is unavailable")]
    RandomnessUnavailable,
    #[error("DNS-relay peer transport failed: {0}")]
    Transport(P2pError),
    #[error("DNS-relay peer returned status {0:?}")]
    Status(DnsRelayStatus),
    #[error("DNS-relay response failed validation: {0}")]
    InvalidResponse(DnsRelayValidationError),
    #[error("DNS-relay peer returned unsolicited request id {0}")]
    UnsolicitedResponse(u64),
    #[error("DNS-relay peer sent an unexpected packet")]
    UnexpectedPacket,
    #[error("DNS-relay peer sent too many unrelated packets")]
    AdvisoryPacketLimit,
}

struct LiveRelayConnection<T> {
    address: SocketAddr,
    services: u64,
    connection: T,
}

pub struct DnsRelayClient<C = TcpDnsRelayPeerConnector>
where
    C: DnsRelayPeerConnector,
{
    network: Network,
    peers: PeerManager,
    connector: C,
    connections: Vec<LiveRelayConnection<C::Connection>>,
    cooldowns: HashMap<SocketAddr, u64>,
    pending: HashSet<u64>,
    proof_peer: Option<SocketAddr>,
    timeout: Duration,
    max_connections: usize,
    alternate_retries: usize,
}

impl DnsRelayClient<TcpDnsRelayPeerConnector> {
    pub fn new(network: Network, peers: PeerManager) -> Self {
        Self::with_connector(network, peers, TcpDnsRelayPeerConnector)
    }
}

impl<C> DnsRelayClient<C>
where
    C: DnsRelayPeerConnector,
{
    pub fn with_connector(network: Network, peers: PeerManager, connector: C) -> Self {
        Self {
            network,
            peers,
            connector,
            connections: Vec::new(),
            cooldowns: HashMap::new(),
            pending: HashSet::new(),
            proof_peer: None,
            timeout: DEFAULT_DNS_RELAY_TIMEOUT,
            max_connections: DEFAULT_MAX_DNS_RELAY_CONNECTIONS,
            alternate_retries: DEFAULT_DNS_RELAY_ALTERNATE_RETRIES,
        }
    }

    pub fn set_proof_peer(&mut self, proof_peer: Option<SocketAddr>) {
        self.proof_peer = proof_peer;
    }

    pub fn peer_manager(&self) -> &PeerManager {
        &self.peers
    }

    pub fn peer_manager_mut(&mut self) -> &mut PeerManager {
        &mut self.peers
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn resolve(&mut self, query: &[u8]) -> Result<DnsRelayExchange, DnsRelayClientError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.resolve_at(query, now)
    }

    pub fn resolve_at(
        &mut self,
        query: &[u8],
        now: u64,
    ) -> Result<DnsRelayExchange, DnsRelayClientError> {
        let query = prepare_dns_relay_query(query).map_err(DnsRelayClientError::InvalidQuery)?;
        let mut attempted = HashSet::new();
        let mut last_error = None;
        let mut handshake_budget = MAX_DNS_RELAY_HANDSHAKE_ATTEMPTS_PER_RESOLUTION;

        for retry in 0..=self.alternate_retries {
            self.replenish_connections(now, &attempted, &mut handshake_budget);
            let Some((index, address)) = self.select_connection(now, &attempted) else {
                return Err(last_error.unwrap_or(DnsRelayClientError::NoCapablePeer));
            };
            attempted.insert(address);

            let request_id = self.allocate_request_id()?;
            self.pending.insert(request_id);
            let result = self.exchange(index, request_id, &query);
            self.pending.remove(&request_id);

            match result {
                Ok(response) => {
                    self.peers.record_transport_success(address, now);
                    return Ok(DnsRelayExchange {
                        response,
                        peer: address,
                        retries: retry,
                    });
                }
                Err(failure) => {
                    let retryable = failure.retryable;
                    match failure.peer_action {
                        AttemptPeerAction::Close => {
                            // The frame was consumed but cannot be interpreted by this protocol
                            // version. Drop correlation state without scoring or cooling down the
                            // peer solely for a potentially future status assignment.
                            self.remove_connection(index);
                        }
                        AttemptPeerAction::Malformed => {
                            self.peers.record_malformed(
                                address,
                                now,
                                DEFAULT_DNS_RELAY_MALFORMED_BAN_SECONDS,
                            );
                            self.cooldowns.insert(
                                address,
                                now.saturating_add(DEFAULT_DNS_RELAY_COOLDOWN_SECONDS),
                            );
                            self.remove_connection(index);
                        }
                        AttemptPeerAction::Transport => {
                            self.peers.record_transient_failure(address);
                            self.cooldowns.insert(
                                address,
                                now.saturating_add(DEFAULT_DNS_RELAY_COOLDOWN_SECONDS),
                            );
                            self.remove_connection(index);
                        }
                        AttemptPeerAction::Backoff => {
                            self.cooldowns.insert(
                                address,
                                now.saturating_add(DEFAULT_DNS_RELAY_COOLDOWN_SECONDS),
                            );
                        }
                        AttemptPeerAction::None => {}
                    }
                    last_error = Some(failure.error);
                    if !retryable {
                        break;
                    }
                }
            }
        }

        Err(last_error.unwrap_or(DnsRelayClientError::NoCapablePeer))
    }

    /// Report a response that failed local DNSSEC validation after transport checks passed.
    ///
    /// Feedback is accepted only for a currently live relay connection. The response is treated as
    /// untrusted/malformed peer data: the peer is strongly penalized, banned, cooled down, and its
    /// connection is dropped so the next resolution can select an alternate.
    pub fn report_dnssec_failure(&mut self, peer: SocketAddr, now: u64) -> bool {
        let Some(index) = self
            .connections
            .iter()
            .position(|connection| connection.address == peer)
        else {
            return false;
        };

        self.peers
            .record_malformed(peer, now, DEFAULT_DNS_RELAY_MALFORMED_BAN_SECONDS);
        self.cooldowns
            .insert(peer, now.saturating_add(DEFAULT_DNS_RELAY_COOLDOWN_SECONDS));
        self.remove_connection(index);
        true
    }

    pub fn shutdown(&mut self) {
        for mut live in self.connections.drain(..) {
            live.connection.close();
        }
        self.pending.clear();
    }

    fn replenish_connections(
        &mut self,
        now: u64,
        exclude: &HashSet<SocketAddr>,
        handshake_budget: &mut usize,
    ) {
        let mut index = 0;
        while index < self.connections.len() {
            let address = self.connections[index].address;
            let unavailable = self
                .peers
                .get(address)
                .is_some_and(|peer| peer.is_banned(now));
            if unavailable {
                self.remove_connection(index);
            } else {
                index += 1;
            }
        }

        if self.connections.len() >= self.max_connections {
            return;
        }

        let connected = self
            .connections
            .iter()
            .map(|connection| connection.address)
            .collect::<HashSet<_>>();
        let mut candidates = self.peers.select_outbound(self.peers.len(), now);
        if let Some(proof_peer) = self.proof_peer
            && let Some(index) = candidates.iter().position(|address| *address == proof_peer)
        {
            let proof_peer = candidates.remove(index);
            candidates.push(proof_peer);
        }

        for address in candidates {
            if self.connections.len() >= self.max_connections || *handshake_budget == 0 {
                break;
            }
            if connected.contains(&address)
                || exclude.contains(&address)
                || self
                    .cooldowns
                    .get(&address)
                    .is_some_and(|until| *until > now)
            {
                continue;
            }

            *handshake_budget = handshake_budget.saturating_sub(1);
            let deadline = deadline_after(self.timeout);
            let Ok(connect_timeout) = remaining_until(deadline) else {
                break;
            };
            let Ok(mut connection) =
                self.connector
                    .connect(address, &self.network, connect_timeout)
            else {
                self.peers.record_transient_failure(address);
                self.cooldowns.insert(
                    address,
                    now.saturating_add(DEFAULT_DNS_RELAY_COOLDOWN_SECONDS),
                );
                continue;
            };
            let local_version = relay_requester_version();
            match connection.handshake(local_version, deadline) {
                Ok(remote) => {
                    // Relay handshakes do not authenticate chain height. Keep
                    // sync target observations owned by the header-sync path.
                    self.peers.record_connection(address, now);
                    if remote.services & EXPERIMENTAL_DNS_RELAY_SERVICE == 0 {
                        connection.close();
                        self.cooldowns.insert(
                            address,
                            now.saturating_add(DEFAULT_DNS_RELAY_COOLDOWN_SECONDS),
                        );
                        continue;
                    }
                    self.connections.push(LiveRelayConnection {
                        address,
                        services: remote.services,
                        connection,
                    });
                }
                Err(_) => {
                    connection.close();
                    self.peers.record_transient_failure(address);
                    self.cooldowns.insert(
                        address,
                        now.saturating_add(DEFAULT_DNS_RELAY_COOLDOWN_SECONDS),
                    );
                }
            }
        }
    }

    fn select_connection(
        &self,
        now: u64,
        exclude: &HashSet<SocketAddr>,
    ) -> Option<(usize, SocketAddr)> {
        let capabilities = self
            .connections
            .iter()
            .map(|connection| DnsRelayPeerCapability {
                address: connection.address,
                services: connection.services,
                fully_handshaken: true,
                cooldown_until: self.cooldowns.get(&connection.address).copied(),
            })
            .collect::<Vec<_>>();
        let address = self
            .peers
            .select_dns_relay(&capabilities, self.connections.len(), now, self.proof_peer)
            .into_iter()
            .find(|address| !exclude.contains(address))?;
        self.connections
            .iter()
            .position(|connection| connection.address == address)
            .map(|index| (index, address))
    }

    fn exchange(
        &mut self,
        index: usize,
        request_id: u64,
        query: &[u8],
    ) -> Result<Vec<u8>, AttemptFailure> {
        let deadline = deadline_after(self.timeout);
        let request = GetDnsRelayPacket::new(request_id, query.to_vec())
            .map(Packet::GetDnsRelay)
            .map_err(AttemptFailure::transport)?;
        self.connections[index]
            .connection
            .send_packet(&request, deadline)
            .map_err(AttemptFailure::transport)?;

        for _ in 0..MAX_ADVISORY_PACKETS_PER_EXCHANGE {
            let packet = match self.connections[index].connection.receive_packet(deadline) {
                Ok(packet) => packet,
                Err(P2pError::InvalidDnsRelayStatus) => {
                    return Err(AttemptFailure::unknown_status());
                }
                Err(error) => return Err(AttemptFailure::transport(error)),
            };
            match packet {
                Packet::DnsRelay(response) => {
                    if response.request_id != request_id || !self.pending.contains(&request_id) {
                        return Err(AttemptFailure::malformed(
                            DnsRelayClientError::UnsolicitedResponse(response.request_id),
                        ));
                    }
                    if response.status != DnsRelayStatus::Ok {
                        return Err(AttemptFailure::status(response.status));
                    }
                    validate_dns_relay_response(query, &response.response).map_err(|error| {
                        AttemptFailure::malformed(DnsRelayClientError::InvalidResponse(error))
                    })?;
                    return Ok(response.response);
                }
                Packet::Ping(nonce) => self.connections[index]
                    .connection
                    .send_packet(&Packet::Pong(nonce), deadline)
                    .map_err(AttemptFailure::transport)?,
                Packet::GetAddr
                | Packet::Addr(_)
                | Packet::Pong(_)
                | Packet::SendHeaders
                | Packet::GetHeaders(_)
                | Packet::Headers(_)
                | Packet::GetProof(_)
                | Packet::Proof(_)
                | Packet::GetDnsRelay(_)
                | Packet::Unknown { .. }
                | Packet::Verack => {}
                Packet::Version(_) => {
                    return Err(AttemptFailure::malformed(
                        DnsRelayClientError::UnexpectedPacket,
                    ));
                }
            }
        }
        Err(AttemptFailure::transport(
            DnsRelayClientError::AdvisoryPacketLimit,
        ))
    }

    fn allocate_request_id(&self) -> Result<u64, DnsRelayClientError> {
        for _ in 0..16 {
            let mut bytes = [0u8; 8];
            getrandom::fill(&mut bytes).map_err(|_| DnsRelayClientError::RandomnessUnavailable)?;
            let request_id = u64::from_le_bytes(bytes);
            if request_id != 0 && !self.pending.contains(&request_id) {
                return Ok(request_id);
            }
        }
        Err(DnsRelayClientError::RandomnessUnavailable)
    }

    fn remove_connection(&mut self, index: usize) {
        let mut connection = self.connections.swap_remove(index);
        connection.connection.close();
    }
}

impl<C> Drop for DnsRelayClient<C>
where
    C: DnsRelayPeerConnector,
{
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct AttemptFailure {
    retryable: bool,
    peer_action: AttemptPeerAction,
    error: DnsRelayClientError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptPeerAction {
    None,
    Close,
    Backoff,
    Transport,
    Malformed,
}

impl AttemptFailure {
    fn unknown_status() -> Self {
        Self {
            retryable: true,
            peer_action: AttemptPeerAction::Close,
            error: DnsRelayClientError::Transport(P2pError::InvalidDnsRelayStatus),
        }
    }
    fn transport(error: impl Into<DnsRelayClientError>) -> Self {
        Self {
            retryable: true,
            peer_action: AttemptPeerAction::Transport,
            error: error.into(),
        }
    }

    fn malformed(error: DnsRelayClientError) -> Self {
        Self {
            retryable: true,
            peer_action: AttemptPeerAction::Malformed,
            error,
        }
    }

    fn status(status: DnsRelayStatus) -> Self {
        let (retryable, peer_action) = match status {
            DnsRelayStatus::InvalidQuery => (false, AttemptPeerAction::None),
            DnsRelayStatus::Refused => (true, AttemptPeerAction::None),
            DnsRelayStatus::Unsupported
            | DnsRelayStatus::Busy
            | DnsRelayStatus::ResolverUnavailable
            | DnsRelayStatus::Timeout
            | DnsRelayStatus::InternalError => (true, AttemptPeerAction::Backoff),
            DnsRelayStatus::Ok => unreachable!("OK is handled before status classification"),
        };

        Self {
            retryable,
            peer_action,
            error: DnsRelayClientError::Status(status),
        }
    }
}

impl From<P2pError> for DnsRelayClientError {
    fn from(error: P2pError) -> Self {
        Self::Transport(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_core::network;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};

    const FIXTURE_DIRECTORY: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/experimental-dns-relay"
    );

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{FIXTURE_DIRECTORY}/{name}");
        let encoded: String = std::fs::read_to_string(path)
            .unwrap()
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        hex::decode(encoded).unwrap()
    }

    fn address(octets: [u8; 4]) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), 12_038)
    }

    fn basic_query() -> Vec<u8> {
        GetDnsRelayPacket::decode(&fixture("request-basic.hex"))
            .unwrap()
            .query
    }

    #[test]
    fn request_fixtures_are_canonical_and_strict() {
        for name in [
            "request-basic.hex",
            "request-max.hex",
            "request-max-qname.hex",
        ] {
            let wire = fixture(name);
            let packet = GetDnsRelayPacket::decode(&wire).unwrap();
            assert_eq!(packet.encode().unwrap(), wire);
            assert_ne!(packet.request_id, 0);
        }

        let max_name = GetDnsRelayPacket::decode(&fixture("request-max-qname.hex"))
            .unwrap()
            .query;
        hns_core::dns::DnsMessage::parse(&max_name).unwrap();

        for name in [
            "malformed-length.hex",
            "trailing-bytes.hex",
            "oversized-request.hex",
        ] {
            assert!(GetDnsRelayPacket::decode(&fixture(name)).is_err(), "{name}");
        }
    }

    #[test]
    fn response_fixtures_are_canonical_and_strict() {
        for name in ["response-ok.hex", "response-error.hex", "response-max.hex"] {
            let wire = fixture(name);
            let packet = DnsRelayPacket::decode(&wire).unwrap();
            assert_eq!(packet.encode().unwrap(), wire);
        }

        for name in [
            "unknown-status.hex",
            "oversized-response.hex",
            "zero-request-id.hex",
        ] {
            assert!(DnsRelayPacket::decode(&fixture(name)).is_err(), "{name}");
        }
    }

    #[test]
    fn experimental_constants_and_service_bit_round_trip() {
        assert_eq!(EXPERIMENTAL_DNS_RELAY_SERVICE, 0x4000_0000);
        assert_eq!(EXPERIMENTAL_GET_DNS_RELAY, 0xf0);
        assert_eq!(EXPERIMENTAL_DNS_RELAY, 0xf1);

        let packet = Packet::Version(VersionPacket {
            services: crate::SERVICE_NETWORK | EXPERIMENTAL_DNS_RELAY_SERVICE,
            ..VersionPacket::default()
        });
        let payload = packet.encode_payload().unwrap();
        assert_eq!(
            Packet::decode_payload(crate::PacketType::Version as u8, &payload).unwrap(),
            packet
        );
    }

    #[test]
    fn unknown_packet_reencoding_preserves_private_type_byte() {
        let network = network::mainnet();
        let packet = Packet::decode_payload(0xee, &[1, 2, 3]).unwrap();
        assert_eq!(packet.raw_packet_type(), 0xee);
        let frame = crate::encode_frame(&network, &packet).unwrap();
        assert_eq!(frame[4], 0xee);
        assert_eq!(
            crate::decode_frame(&network, &frame).unwrap().unwrap().0,
            packet
        );
    }

    #[test]
    fn frame_header_rejects_relay_payload_limits_before_body_arrives() {
        let network = network::mainnet();
        for (packet_type, payload_len, expected) in [
            (
                EXPERIMENTAL_GET_DNS_RELAY,
                MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE + 1,
                P2pError::DnsRelayQueryTooLarge,
            ),
            (
                EXPERIMENTAL_DNS_RELAY,
                MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE + 1,
                P2pError::DnsRelayResponseTooLarge,
            ),
        ] {
            let mut header = Vec::new();
            crate::FrameHeader {
                magic: network.magic,
                packet_type,
                payload_len: payload_len as u32,
            }
            .encode(&mut header);
            assert_eq!(crate::decode_frame(&network, &header), Err(expected));
        }
    }

    #[test]
    fn query_preparation_sets_rd_and_cd_without_mutating_input() {
        let mut query = basic_query();
        query[2] &= !0x01;
        query[3] &= !0x10;
        let original = query.clone();
        let prepared = prepare_dns_relay_query(&query).unwrap();
        assert_eq!(query, original);
        assert_ne!(prepared[2] & 0x01, 0);
        assert_ne!(prepared[3] & 0x10, 0);
    }

    #[test]
    fn query_preparation_rejects_ecs_and_missing_do() {
        let mut no_do = basic_query();
        let ttl_offset = no_do.len() - 6;
        no_do[ttl_offset + 2] &= !0x80;
        assert_eq!(
            prepare_dns_relay_query(&no_do),
            Err(DnsRelayValidationError::DnssecOkRequired)
        );

        let mut ecs = basic_query();
        let rdlength = ecs.len() - 2;
        ecs[rdlength..].copy_from_slice(&[0, 4]);
        ecs.extend([0, 8, 0, 0]);
        assert_eq!(
            prepare_dns_relay_query(&ecs),
            Err(DnsRelayValidationError::EdnsClientSubnetForbidden)
        );
    }

    #[test]
    fn query_preparation_enforces_the_complete_relay_profile() {
        let mut response_flag = basic_query();
        response_flag[2] |= 0x04;
        assert_eq!(
            prepare_dns_relay_query(&response_flag),
            Err(DnsRelayValidationError::InvalidQueryFlags),
        );

        let mut unsupported_type = basic_query();
        unsupported_type[27..29].copy_from_slice(&255u16.to_be_bytes());
        assert_eq!(
            prepare_dns_relay_query(&unsupported_type),
            Err(DnsRelayValidationError::UnsupportedQuestionType),
        );

        let mut invalid_root = basic_query();
        invalid_root[17] = b'-';
        assert_eq!(
            prepare_dns_relay_query(&invalid_root),
            Err(DnsRelayValidationError::InvalidHnsRoot),
        );

        let mut small_edns = basic_query();
        let class_offset = small_edns.len() - 8;
        small_edns[class_offset..class_offset + 2].copy_from_slice(&511u16.to_be_bytes());
        assert_eq!(
            prepare_dns_relay_query(&small_edns),
            Err(DnsRelayValidationError::InvalidEdnsSize),
        );

        let mut future_edns = basic_query();
        let ttl_offset = future_edns.len() - 6;
        future_edns[ttl_offset + 1] = 1;
        assert_eq!(
            prepare_dns_relay_query(&future_edns),
            Err(DnsRelayValidationError::InvalidEdns),
        );

        let mut unknown_option = basic_query();
        let rdlength_offset = unknown_option.len() - 2;
        unknown_option[rdlength_offset..].copy_from_slice(&4u16.to_be_bytes());
        unknown_option.extend([0, 15, 0, 0]);
        assert_eq!(
            prepare_dns_relay_query(&unknown_option),
            Err(DnsRelayValidationError::InvalidEdns),
        );

        let mut padding = basic_query();
        let rdlength_offset = padding.len() - 2;
        padding[rdlength_offset..].copy_from_slice(&6u16.to_be_bytes());
        padding.extend([0, 12, 0, 2, 0, 0]);
        prepare_dns_relay_query(&padding).unwrap();
    }

    #[test]
    fn response_validation_checks_id_question_and_recursive_flags() {
        let query = basic_query();
        let response = DnsRelayPacket::decode(&fixture("response-ok.hex"))
            .unwrap()
            .response;
        validate_dns_relay_response(&query, &response).unwrap();

        let mut wrong_id = response.clone();
        wrong_id[1] ^= 1;
        assert_eq!(
            validate_dns_relay_response(&query, &wrong_id),
            Err(DnsRelayValidationError::ResponseIdMismatch)
        );
        let mut wrong_question = response.clone();
        wrong_question[28] = RecordType::Aaaa.code() as u8;
        assert_eq!(
            validate_dns_relay_response(&query, &wrong_question),
            Err(DnsRelayValidationError::ResponseQuestionMismatch)
        );
        let mut not_response = response.clone();
        not_response[2] &= !0x80;
        assert_eq!(
            validate_dns_relay_response(&query, &not_response),
            Err(DnsRelayValidationError::NotStandardQuery)
        );
        let mut wrong_opcode = response.clone();
        wrong_opcode[2] |= 0x08;
        assert_eq!(
            validate_dns_relay_response(&query, &wrong_opcode),
            Err(DnsRelayValidationError::NotStandardQuery)
        );
        let mut compression_loop = response.clone();
        compression_loop[12..14].copy_from_slice(&[0xc0, 0x0c]);
        assert_eq!(
            validate_dns_relay_response(&query, &compression_loop),
            Err(DnsRelayValidationError::MalformedMessage)
        );
        let mut no_cd = response.clone();
        no_cd[3] &= !0x10;
        validate_dns_relay_response(&query, &no_cd).unwrap();
        let mut no_ra = response;
        no_ra[3] &= !0x80;
        assert_eq!(
            validate_dns_relay_response(&query, &no_ra),
            Err(DnsRelayValidationError::InvalidRecursiveFlags)
        );
    }

    #[test]
    fn relay_selection_requires_live_capability_and_prefers_diversity() {
        let first = address([10, 1, 0, 1]);
        let same_group = address([10, 1, 0, 2]);
        let diverse = address([10, 2, 0, 1]);
        let incapable = address([10, 3, 0, 1]);
        let cooling = address([10, 4, 0, 1]);
        let banned = address([10, 5, 0, 1]);
        let mut peers = PeerManager::default();
        for peer in [first, same_group, diverse, incapable, cooling, banned] {
            peers.upsert(peer);
        }
        peers.record_success(first, Height(100), 1);
        peers.record_success(same_group, Height(99), 1);
        peers.record_success(diverse, Height(98), 1);
        peers.record_malformed(banned, 1, 100);

        let capable = |address, services, cooldown_until| DnsRelayPeerCapability {
            address,
            services,
            fully_handshaken: true,
            cooldown_until,
        };
        let selected = peers.select_dns_relay(
            &[
                capable(first, EXPERIMENTAL_DNS_RELAY_SERVICE, None),
                capable(same_group, EXPERIMENTAL_DNS_RELAY_SERVICE, None),
                capable(diverse, EXPERIMENTAL_DNS_RELAY_SERVICE, None),
                capable(incapable, 0, None),
                capable(cooling, EXPERIMENTAL_DNS_RELAY_SERVICE, Some(20)),
                capable(banned, EXPERIMENTAL_DNS_RELAY_SERVICE, None),
            ],
            2,
            10,
            None,
        );
        assert_eq!(selected, vec![first, diverse]);
    }

    #[test]
    fn relay_selection_prefers_non_proof_peer_but_falls_back() {
        let proof = address([10, 1, 0, 1]);
        let other = address([10, 2, 0, 1]);
        let mut peers = PeerManager::default();
        peers.upsert(proof);
        peers.upsert(other);
        let capabilities = [proof, other].map(|address| DnsRelayPeerCapability {
            address,
            services: EXPERIMENTAL_DNS_RELAY_SERVICE,
            fully_handshaken: true,
            cooldown_until: None,
        });
        assert_eq!(
            peers.select_dns_relay(&capabilities, 2, 1, Some(proof)),
            vec![other, proof]
        );
        assert_eq!(
            peers.select_dns_relay(&capabilities[..1], 1, 1, Some(proof)),
            vec![proof]
        );
    }

    struct FakeConnection {
        services: u64,
        response: FakeResponse,
        sent: Vec<Packet>,
        queued: VecDeque<Packet>,
        handshake_deadline: Option<Instant>,
        local_services: Option<u64>,
        exchange_deadlines: Vec<Instant>,
    }

    #[derive(Clone)]
    enum FakeResponse {
        Success(Vec<u8>),
        Duplicate(Vec<u8>),
        Advisory(Vec<u8>),
        Status(DnsRelayStatus),
        WrongId(Vec<u8>),
        UnknownStatus,
        Disconnect,
    }

    impl DnsRelayPeerConnection for FakeConnection {
        fn handshake(
            &mut self,
            local_version: VersionPacket,
            deadline: Instant,
        ) -> Result<VersionPacket, P2pError> {
            remaining_until(deadline)?;
            self.handshake_deadline = Some(deadline);
            self.local_services = Some(local_version.services);
            Ok(VersionPacket {
                services: self.services | crate::SERVICE_NETWORK,
                height: Height(10),
                ..VersionPacket::default()
            })
        }

        fn send_packet(&mut self, packet: &Packet, deadline: Instant) -> Result<(), P2pError> {
            remaining_until(deadline)?;
            self.exchange_deadlines.push(deadline);
            self.sent.push(packet.clone());
            if let Packet::GetDnsRelay(request) = packet {
                if matches!(self.response, FakeResponse::Disconnect) {
                    return Ok(());
                }
                if matches!(self.response, FakeResponse::UnknownStatus) {
                    return Ok(());
                }
                let response = match &self.response {
                    FakeResponse::Success(response)
                    | FakeResponse::Duplicate(response)
                    | FakeResponse::Advisory(response) => DnsRelayPacket::new(
                        request.request_id,
                        DnsRelayStatus::Ok,
                        response.clone(),
                    )
                    .unwrap(),
                    FakeResponse::Status(status) => {
                        DnsRelayPacket::new(request.request_id, *status, Vec::new()).unwrap()
                    }
                    FakeResponse::WrongId(response) => DnsRelayPacket::new(
                        request.request_id.wrapping_add(1),
                        DnsRelayStatus::Ok,
                        response.clone(),
                    )
                    .unwrap(),
                    FakeResponse::UnknownStatus | FakeResponse::Disconnect => {
                        unreachable!("handled before response creation")
                    }
                };
                if matches!(self.response, FakeResponse::Advisory(_)) {
                    self.queued.push_back(Packet::Ping([42; 8]));
                    self.queued.push_back(Packet::GetAddr);
                }
                self.queued.push_back(Packet::DnsRelay(response.clone()));
                if matches!(self.response, FakeResponse::Duplicate(_)) {
                    self.queued.push_back(Packet::DnsRelay(response));
                }
            }
            Ok(())
        }

        fn receive_packet(&mut self, deadline: Instant) -> Result<Packet, P2pError> {
            remaining_until(deadline)?;
            self.exchange_deadlines.push(deadline);
            if matches!(self.response, FakeResponse::UnknownStatus) {
                return Err(P2pError::InvalidDnsRelayStatus);
            }
            self.queued.pop_front().ok_or(P2pError::ConnectionClosed)
        }
    }

    struct FakeConnector {
        connections: HashMap<SocketAddr, VecDeque<FakeResponse>>,
        services: HashMap<SocketAddr, u64>,
        connects: HashMap<SocketAddr, usize>,
    }

    impl DnsRelayPeerConnector for FakeConnector {
        type Connection = FakeConnection;

        fn connect(
            &mut self,
            address: SocketAddr,
            _network: &Network,
            _timeout: Duration,
        ) -> Result<Self::Connection, P2pError> {
            *self.connects.entry(address).or_default() += 1;
            let response = self
                .connections
                .get_mut(&address)
                .and_then(VecDeque::pop_front)
                .ok_or(P2pError::ConnectionClosed)?;
            Ok(FakeConnection {
                services: self
                    .services
                    .get(&address)
                    .copied()
                    .unwrap_or(EXPERIMENTAL_DNS_RELAY_SERVICE),
                response,
                sent: Vec::new(),
                queued: VecDeque::new(),
                handshake_deadline: None,
                local_services: None,
                exchange_deadlines: Vec::new(),
            })
        }
    }

    struct SlowDripTransport {
        delay: Duration,
    }

    impl Read for SlowDripTransport {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.delay);
            if buffer.is_empty() {
                return Ok(0);
            }
            buffer[0] = 0;
            Ok(1)
        }
    }

    impl Write for SlowDripTransport {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn relay_frame_progress_cannot_reset_absolute_deadline() {
        assert_eq!(DEFAULT_DNS_RELAY_TIMEOUT, Duration::from_secs(3));
        let mut connection = PeerConnection::new(
            SlowDripTransport {
                delay: Duration::from_millis(15),
            },
            network::mainnet(),
        );
        let started = Instant::now();
        let result = relay_receive_packet_until(
            &mut connection,
            deadline_after(Duration::from_millis(40)),
            |_transport, _remaining| Ok(()),
        );

        assert!(matches!(result, Err(P2pError::Io(ErrorKind::TimedOut))));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "slow-drip reads must not extend the absolute frame deadline"
        );
    }

    #[test]
    fn relay_capability_probe_bounds_handshake_advisories() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut peer = PeerConnection::new(stream, network::regtest());
            assert!(matches!(peer.receive_packet().unwrap(), Packet::Version(_)));
            for nonce in 0..MAX_PACKETS_PER_HANDSHAKE {
                let nonce = (nonce as u64).to_le_bytes();
                peer.send_packet(&Packet::Ping(nonce)).unwrap();
                assert_eq!(peer.receive_packet().unwrap(), Packet::Pong(nonce));
            }
            assert!(peer.receive_packet().is_err());
        });

        assert_eq!(
            probe_dns_relay_peer(address, &network::regtest(), Duration::from_secs(1)),
            Err(P2pError::HandshakePacketLimit),
        );
        server.join().unwrap();
    }

    #[test]
    fn client_reuses_connections_and_cleans_pending_requests() {
        let peer = address([10, 1, 0, 1]);
        let response = DnsRelayPacket::decode(&fixture("response-ok.hex"))
            .unwrap()
            .response;
        let mut manager = PeerManager::default();
        manager.upsert(peer).last_height = Height(7);
        let connector = FakeConnector {
            connections: HashMap::from([(peer, VecDeque::from([FakeResponse::Success(response)]))]),
            services: HashMap::new(),
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);
        client.resolve_at(&basic_query(), 100).unwrap();
        client.resolve_at(&basic_query(), 101).unwrap();
        assert_eq!(client.connection_count(), 1);
        assert_eq!(client.pending_len(), 0);
        assert_eq!(
            client.peer_manager().get(peer).unwrap().last_height,
            Height(7)
        );
        assert_eq!(client.connections[0].connection.local_services, Some(0));
        assert_eq!(client.connector.connects[&peer], 1);
        assert_eq!(
            client.connections[0]
                .connection
                .sent
                .iter()
                .filter(|packet| matches!(packet, Packet::GetDnsRelay(_)))
                .count(),
            2
        );
    }

    #[test]
    fn client_retries_busy_peer_without_penalty_or_disconnect() {
        let busy = address([10, 1, 0, 1]);
        let good = address([10, 2, 0, 1]);
        let response = DnsRelayPacket::decode(&fixture("response-ok.hex"))
            .unwrap()
            .response;
        let mut manager = PeerManager::default();
        manager.upsert(busy);
        manager.upsert(good);
        let connector = FakeConnector {
            connections: HashMap::from([
                (
                    busy,
                    VecDeque::from([FakeResponse::Status(DnsRelayStatus::Busy)]),
                ),
                (good, VecDeque::from([FakeResponse::Success(response)])),
            ]),
            services: HashMap::new(),
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);
        let exchange = client.resolve_at(&basic_query(), 100).unwrap();
        assert_eq!(exchange.peer, good);
        assert_eq!(exchange.retries, 1);
        assert_eq!(client.pending_len(), 0);
        let state = client.peer_manager().get(busy).unwrap();
        assert_eq!(state.score, 0);
        assert_eq!(state.failures, 0);
        assert!(client.cooldowns[&busy] > 100);
        assert!(
            client
                .connections
                .iter()
                .any(|connection| connection.address == busy),
            "BUSY is a healthy application response and must not drop the transport"
        );
    }

    #[test]
    fn client_does_not_penalize_or_cool_down_invalid_query_status() {
        let peer = address([10, 1, 0, 1]);
        let mut manager = PeerManager::default();
        manager.upsert(peer);
        let connector = FakeConnector {
            connections: HashMap::from([(
                peer,
                VecDeque::from([FakeResponse::Status(DnsRelayStatus::InvalidQuery)]),
            )]),
            services: HashMap::new(),
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);

        assert!(matches!(
            client.resolve_at(&basic_query(), 100),
            Err(DnsRelayClientError::Status(DnsRelayStatus::InvalidQuery))
        ));
        let state = client.peer_manager().get(peer).unwrap();
        assert_eq!(state.score, 0);
        assert_eq!(state.failures, 0);
        assert!(!client.cooldowns.contains_key(&peer));
        assert_eq!(client.connection_count(), 1);
    }

    #[test]
    fn client_closes_unknown_status_without_penalty_or_cooldown() {
        let future = address([10, 1, 0, 1]);
        let good = address([10, 2, 0, 1]);
        let response = DnsRelayPacket::decode(&fixture("response-ok.hex"))
            .unwrap()
            .response;
        let mut manager = PeerManager::default();
        manager.upsert(future);
        manager.upsert(good);
        let connector = FakeConnector {
            connections: HashMap::from([
                (future, VecDeque::from([FakeResponse::UnknownStatus])),
                (good, VecDeque::from([FakeResponse::Success(response)])),
            ]),
            services: HashMap::new(),
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);

        let exchange = client.resolve_at(&basic_query(), 100).unwrap();
        assert_eq!(exchange.peer, good);
        assert_eq!(exchange.retries, 1);
        let state = client.peer_manager().get(future).unwrap();
        assert_eq!(state.score, 0);
        assert_eq!(state.failures, 0);
        assert!(!client.cooldowns.contains_key(&future));
        assert!(
            client
                .connections
                .iter()
                .all(|connection| connection.address != future),
        );
    }

    #[test]
    fn valid_statuses_have_reasoned_retry_and_peer_actions() {
        for status in [
            DnsRelayStatus::Unsupported,
            DnsRelayStatus::Busy,
            DnsRelayStatus::ResolverUnavailable,
            DnsRelayStatus::Timeout,
            DnsRelayStatus::InternalError,
        ] {
            let failure = AttemptFailure::status(status);
            assert!(failure.retryable, "{status:?}");
            assert_eq!(
                failure.peer_action,
                AttemptPeerAction::Backoff,
                "{status:?}"
            );
        }

        let refused = AttemptFailure::status(DnsRelayStatus::Refused);
        assert!(refused.retryable);
        assert_eq!(refused.peer_action, AttemptPeerAction::None);

        let invalid = AttemptFailure::status(DnsRelayStatus::InvalidQuery);
        assert!(!invalid.retryable);
        assert_eq!(invalid.peer_action, AttemptPeerAction::None);
    }

    #[test]
    fn advisory_packets_share_one_exchange_deadline() {
        let peer = address([10, 1, 0, 1]);
        let response = DnsRelayPacket::decode(&fixture("response-ok.hex"))
            .unwrap()
            .response;
        let mut manager = PeerManager::default();
        manager.upsert(peer);
        let connector = FakeConnector {
            connections: HashMap::from([(
                peer,
                VecDeque::from([FakeResponse::Advisory(response)]),
            )]),
            services: HashMap::new(),
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);

        client.resolve_at(&basic_query(), 100).unwrap();
        let connection = &client.connections[0].connection;
        assert!(connection.handshake_deadline.is_some());
        assert_eq!(connection.exchange_deadlines.len(), 5);
        let exchange_deadline = connection.exchange_deadlines[0];
        assert!(
            connection
                .exchange_deadlines
                .iter()
                .all(|deadline| *deadline == exchange_deadline),
            "advisory receives and Pong sends must not reset the exchange deadline"
        );
    }

    #[test]
    fn client_bans_unsolicited_response_and_shuts_down_cleanly() {
        let peer = address([10, 1, 0, 1]);
        let response = DnsRelayPacket::decode(&fixture("response-ok.hex"))
            .unwrap()
            .response;
        let mut manager = PeerManager::default();
        manager.upsert(peer);
        let connector = FakeConnector {
            connections: HashMap::from([(peer, VecDeque::from([FakeResponse::WrongId(response)]))]),
            services: HashMap::new(),
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);
        assert!(
            matches!(
                client.resolve_at(&basic_query(), 100),
                Err(DnsRelayClientError::UnsolicitedResponse(_))
            ),
            "wrong request ID must fail closed"
        );
        assert!(client.peer_manager().get(peer).unwrap().is_banned(101));
        assert_eq!(client.pending_len(), 0);
        client.shutdown();
        assert_eq!(client.connection_count(), 0);
    }

    #[test]
    fn dnssec_failure_feedback_bans_live_peer_and_selects_alternate() {
        let first = address([10, 1, 0, 1]);
        let alternate = address([10, 2, 0, 1]);
        let response = DnsRelayPacket::decode(&fixture("response-ok.hex"))
            .unwrap()
            .response;
        let mut manager = PeerManager::default();
        manager.upsert(first);
        manager.upsert(alternate);
        let connector = FakeConnector {
            connections: HashMap::from([
                (
                    first,
                    VecDeque::from([FakeResponse::Success(response.clone())]),
                ),
                (alternate, VecDeque::from([FakeResponse::Success(response)])),
            ]),
            services: HashMap::new(),
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);

        assert_eq!(client.resolve_at(&basic_query(), 100).unwrap().peer, first);
        assert!(client.report_dnssec_failure(first, 101));
        let first_state = client.peer_manager().get(first).unwrap();
        assert!(first_state.score >= crate::BAN_SCORE);
        assert!(first_state.is_banned(102));
        assert!(client.cooldowns[&first] > 101);
        assert!(
            client
                .connections
                .iter()
                .all(|connection| connection.address != first)
        );

        assert_eq!(
            client.resolve_at(&basic_query(), 102).unwrap().peer,
            alternate
        );
        let score = client.peer_manager().get(first).unwrap().score;
        assert!(!client.report_dnssec_failure(first, 103));
        assert_eq!(client.peer_manager().get(first).unwrap().score, score);
    }

    #[test]
    fn client_never_sends_relay_packet_to_legacy_peer() {
        let legacy = address([10, 1, 0, 1]);
        let capable = address([10, 2, 0, 1]);
        let response = DnsRelayPacket::decode(&fixture("response-ok.hex"))
            .unwrap()
            .response;
        let mut manager = PeerManager::default();
        manager.upsert(legacy);
        manager.upsert(capable);
        let connector = FakeConnector {
            connections: HashMap::from([
                (
                    legacy,
                    VecDeque::from([FakeResponse::Status(DnsRelayStatus::InternalError)]),
                ),
                (capable, VecDeque::from([FakeResponse::Success(response)])),
            ]),
            services: HashMap::from([(legacy, 0)]),
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);
        let exchange = client.resolve_at(&basic_query(), 100).unwrap();
        assert_eq!(exchange.peer, capable);
        assert_eq!(client.connection_count(), 1);
        assert_eq!(client.connections[0].address, capable);
    }

    #[test]
    fn client_bounds_handshake_attempts_when_all_peers_are_legacy() {
        let addresses = (1..=8)
            .map(|last| address([10, last, 0, 1]))
            .collect::<Vec<_>>();
        let mut manager = PeerManager::default();
        let mut connections = HashMap::new();
        let mut services = HashMap::new();
        for peer in &addresses {
            manager.upsert(*peer);
            connections.insert(
                *peer,
                VecDeque::from([FakeResponse::Status(DnsRelayStatus::InternalError)]),
            );
            services.insert(*peer, 0);
        }
        let connector = FakeConnector {
            connections,
            services,
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);
        assert!(matches!(
            client.resolve_at(&basic_query(), 100),
            Err(DnsRelayClientError::NoCapablePeer)
        ));
        assert_eq!(
            client.connector.connects.values().sum::<usize>(),
            MAX_DNS_RELAY_HANDSHAKE_ATTEMPTS_PER_RESOLUTION
        );
        assert_eq!(client.connection_count(), 0);
        assert_eq!(client.pending_len(), 0);
    }

    #[test]
    fn client_rejects_duplicate_completed_response_and_cleans_disconnects() {
        let duplicate_peer = address([10, 1, 0, 1]);
        let response = DnsRelayPacket::decode(&fixture("response-ok.hex"))
            .unwrap()
            .response;
        let mut manager = PeerManager::default();
        manager.upsert(duplicate_peer);
        let connector = FakeConnector {
            connections: HashMap::from([(
                duplicate_peer,
                VecDeque::from([FakeResponse::Duplicate(response)]),
            )]),
            services: HashMap::new(),
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);
        client.resolve_at(&basic_query(), 100).unwrap();
        assert!(matches!(
            client.resolve_at(&basic_query(), 101),
            Err(DnsRelayClientError::UnsolicitedResponse(_))
        ));
        assert_eq!(client.pending_len(), 0);
        assert_eq!(client.connection_count(), 0);

        let disconnected_peer = address([10, 2, 0, 1]);
        let mut manager = PeerManager::default();
        manager.upsert(disconnected_peer);
        let connector = FakeConnector {
            connections: HashMap::from([(
                disconnected_peer,
                VecDeque::from([FakeResponse::Disconnect]),
            )]),
            services: HashMap::new(),
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);
        assert!(matches!(
            client.resolve_at(&basic_query(), 200),
            Err(DnsRelayClientError::Transport(P2pError::ConnectionClosed))
        ));
        assert_eq!(client.pending_len(), 0);
        assert_eq!(client.connection_count(), 0);
    }

    #[test]
    fn client_attempts_no_more_than_one_alternate() {
        let first = address([10, 1, 0, 1]);
        let second = address([10, 2, 0, 1]);
        let third = address([10, 3, 0, 1]);
        let mut manager = PeerManager::default();
        for peer in [first, second, third] {
            manager.upsert(peer);
        }
        let connector = FakeConnector {
            connections: HashMap::from([
                (
                    first,
                    VecDeque::from([FakeResponse::Status(DnsRelayStatus::Busy)]),
                ),
                (
                    second,
                    VecDeque::from([FakeResponse::Status(DnsRelayStatus::Busy)]),
                ),
                (
                    third,
                    VecDeque::from([FakeResponse::Status(DnsRelayStatus::Busy)]),
                ),
            ]),
            services: HashMap::new(),
            connects: HashMap::new(),
        };
        let mut client = DnsRelayClient::with_connector(network::mainnet(), manager, connector);
        assert!(matches!(
            client.resolve_at(&basic_query(), 100),
            Err(DnsRelayClientError::Status(DnsRelayStatus::Busy))
        ));
        assert_eq!(client.pending_len(), 0);
        assert_eq!(
            client
                .connections
                .iter()
                .flat_map(|live| &live.connection.sent)
                .filter(|packet| matches!(packet, Packet::GetDnsRelay(_)))
                .count(),
            2,
            "only the primary and one alternate may receive a request"
        );
        assert_eq!(
            client.connector.connects.get(&third).copied().unwrap_or(0),
            0
        );
    }
}
