//! Engine-bound HNSR requester and opaque-relay lifecycle.
//!
//! The embedding adapter owns Brontide connections, packet I/O, scheduling,
//! and atomic rollback-resistant storage. This module owns the state machines,
//! exact authenticated-peer admission, policy binding, persistence envelope,
//! routing decisions, acknowledgements, and disconnect cleanup. It never
//! implements an endpoint, rendezvous directory, plaintext output, or socket.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use hns_hnsr_protocol::{
    HnsrActionId, HnsrPacket, HnsrPeerId, HnsrProtocolError, HnsrRequester,
    HnsrRequesterConfig, HnsrRequesterEvent, HnsrRequesterSnapshot, HnsrRoute,
    HnsrRuntimeError, HnsrRuntimeStatus, HnsrService, OpaqueRelayConfig, OpaqueRelayRuntime,
    OpaqueRelaySnapshot, QueuedHnsrRoute, RelayConfig, RelayService, RelayTicket,
};

use super::private_transport::{
    canonical_genesis_hash, crc32, experimental_network, network_magic, resolved_odoh_profile,
};
use super::{
    BrowserRuntime, Engine, EngineError, ExperimentalPeerState, ExperimentalWireProfile,
    NegotiatedRegistry, Network, P2pTransportError, PeerIdentity, PolicySnapshot,
    PrivateTransportAuthority, RuntimeStamp, WireProfile, resolution_transport_ready,
};

/// Engine HNSR status and persistence-envelope schema.
pub const HNSR_TRANSPORT_SCHEMA_VERSION: u16 = 1;
/// Hard bound for one wrapped requester or relay snapshot.
pub const MAX_HNSR_RUNTIME_SNAPSHOT_BYTES: usize = 4_096;

const HNSR_SNAPSHOT_MAGIC: &[u8; 8] = b"HNSRTE1\0";
const HNSR_SNAPSHOT_HEADER_BYTES: usize = 50;
const HNSR_SNAPSHOT_CHECKSUM_BYTES: usize = 4;
const MAX_HNSR_CONNECTION_LABEL_BYTES: usize = 96;

/// Engine-owned HNSR role. No provider role is implicit in another role.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HnsrTransportRole {
    /// Client/requester circuit role.
    Requester = 1,
    /// Ciphertext-only circuit relay plus its signed reservation plane.
    OpaqueRelay = 2,
}

/// Closed lifecycle state reported by an engine HNSR runtime.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HnsrTransportState {
    /// The role admits protocol work; adapter/path availability is separate.
    Enabled = 1,
    /// The role was independently disabled with a checked generation update.
    Disabled = 2,
    /// The binding was terminally revoked and cannot be re-enabled.
    Revoked = 3,
}

/// Immutable engine epoch and protocol profile bound to one HNSR runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsrTransportBinding {
    stamp: RuntimeStamp,
    network: Network,
    network_magic: u32,
    policy_generation: u64,
    policy_wire_profile: WireProfile,
    resolved_wire_profile: ExperimentalWireProfile,
    role: HnsrTransportRole,
    service_profile: u16,
    allow_private_address: bool,
}

impl HnsrTransportBinding {
    /// Browser process/session identity.
    #[must_use]
    pub const fn runtime_session(self) -> [u8; 16] {
        self.stamp.session()
    }

    /// Browser authority generation.
    #[must_use]
    pub const fn runtime_generation(self) -> u64 {
        self.stamp.generation()
    }

    /// Exact admitted authority event.
    #[must_use]
    pub const fn admission_event(self) -> u64 {
        self.stamp.event_sequence()
    }

    /// Persistent policy generation.
    #[must_use]
    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }

    /// Handshake network.
    #[must_use]
    pub const fn network(self) -> Network {
        self.network
    }

    /// Canonical network magic required by tickets and reservations.
    #[must_use]
    pub const fn network_magic(self) -> u32 {
        self.network_magic
    }

    /// Policy-level experimental assignment profile.
    #[must_use]
    pub const fn policy_wire_profile(self) -> WireProfile {
        self.policy_wire_profile
    }

    /// Concrete peer profile; always Denuo V1 for an admitted runtime.
    #[must_use]
    pub const fn resolved_wire_profile(self) -> ExperimentalWireProfile {
        self.resolved_wire_profile
    }

    /// Independent HNSR role.
    #[must_use]
    pub const fn role(self) -> HnsrTransportRole {
        self.role
    }

    /// Exact inner HNSR service profile carried by relay tickets.
    #[must_use]
    pub const fn service_profile(self) -> u16 {
        self.service_profile
    }

    /// Whether private relay/endpoint addresses are admitted.
    #[must_use]
    pub const fn allows_private_address(self) -> bool {
        self.allow_private_address
    }
}

/// Checksummed runtime snapshot and the caller-held floors it advances.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsrRuntimeExport {
    /// Independent role generation encoded in `bytes`.
    pub generation: u64,
    /// Greatest trusted Unix time encoded in `bytes`.
    pub trusted_time_high_water: u64,
    /// Checksummed engine envelope containing the checksummed canonical core snapshot.
    pub bytes: Vec<u8>,
}

/// Complete name-free HNSR status for platform readiness and diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsrTransportStatus {
    /// Status schema version.
    pub schema_version: u16,
    /// Exact engine/network/profile binding.
    pub binding: HnsrTransportBinding,
    /// Closed role lifecycle.
    pub state: HnsrTransportState,
    /// Terminal reason exactly when `state` is revoked.
    pub revocation_reason: Option<HnsrTransportRevocationReason>,
    /// Canonical core counters, bounds, generation, and time high-water.
    pub runtime: HnsrRuntimeStatus,
    /// Current confirmed reservation count; zero for requesters.
    pub confirmed_reservations: usize,
    /// Local requester state machine is enabled and current.
    pub requester_protocol_ready: bool,
    /// Local opaque relay and reservation state machines are enabled and current.
    pub opaque_relay_protocol_ready: bool,
    /// Live Brontide transport availability is adapter-owned and never inferred.
    pub transport_adapter_available: bool,
    /// Plaintext endpoint/output functionality is not implemented here.
    pub endpoint_provider_available: bool,
    /// Rendezvous directory functionality is not implemented here.
    pub rendezvous_provider_available: bool,
    /// Plaintext application data is never available to the opaque relay.
    pub plaintext_available: bool,
}

/// One exact authenticated outer connection admitted for HNSR routing.
///
/// The connection label, not an address or static key alone, is the core peer
/// identity. A reconnect must use a new label and repeat canonical admission.
#[derive(Debug)]
pub struct AuthenticatedHnsrPeer {
    binding: HnsrTransportBinding,
    connection_label: String,
    peer_id: HnsrPeerId,
    identity: PeerIdentity,
}

impl AuthenticatedHnsrPeer {
    /// Exact adapter connection label.
    #[must_use]
    pub fn connection_label(&self) -> &str {
        &self.connection_label
    }

    /// Brontide-authenticated static key on this exact connection.
    #[must_use]
    pub const fn identity(&self) -> PeerIdentity {
        self.identity
    }

    /// Opaque destination identity used in canonical returned routes.
    #[must_use]
    pub const fn peer_id(&self) -> &HnsrPeerId {
        &self.peer_id
    }
}

/// Current-authority validation seam shared by [`Engine`] and borrowed adapters.
pub trait HnsrTransportAuthorityContext: super::authority_sealed::Sealed {
    /// Validate one previously minted HNSR binding against current authority.
    fn validate_hnsr_transport_binding(
        &self,
        binding: HnsrTransportBinding,
    ) -> Result<(), HnsrTransportError>;
}

/// Engine-bound HNSR requester. Socket and storage ownership remain external.
#[derive(Debug)]
pub struct HnsrRequesterRuntime {
    binding: HnsrTransportBinding,
    requester: HnsrRequester,
    revocation_reason: Option<HnsrTransportRevocationReason>,
}

/// Engine-bound ciphertext-only HNSR relay and reservation plane.
pub struct HnsrOpaqueRelayRuntime {
    binding: HnsrTransportBinding,
    relay: OpaqueRelayRuntime,
    service: HnsrService,
    observed_peers: BTreeSet<String>,
    revocation_reason: Option<HnsrTransportRevocationReason>,
}

impl fmt::Debug for HnsrOpaqueRelayRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsrOpaqueRelayRuntime")
            .field("binding", &self.binding)
            .field("relay", &self.relay)
            .field("observed_peer_count", &self.observed_peers.len())
            .field("revocation_reason", &self.revocation_reason)
            .finish_non_exhaustive()
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HnsrTransportRevocationReason {
    /// Trusted platform code explicitly revoked this role.
    Explicit = 1,
    /// Browser session, generation, readiness, or invalidation changed.
    AuthorityChanged = 2,
    /// Policy generation, role enablement, or admitted profile changed.
    PolicyChanged = 3,
}

impl HnsrRequesterRuntime {
    /// Exact engine/network/profile epoch that admitted this requester.
    #[must_use]
    pub const fn binding(&self) -> HnsrTransportBinding {
        self.binding
    }

    /// Authenticate one exact relay connection against canonical Denuo V1.
    pub fn authenticate_relay<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        connection_label: String,
        identity: PeerIdentity,
        peer: ExperimentalPeerState,
        registry: NegotiatedRegistry,
    ) -> Result<AuthenticatedHnsrPeer, HnsrTransportError> {
        self.ensure_current(authority)?;
        authenticate_hnsr_peer(self.binding, connection_label, identity, peer, registry, true)
    }

    /// Begin one signed-ticket-bound open routed to the authenticated relay.
    #[allow(
        clippy::too_many_arguments,
        reason = "authority, authenticated peer, ticket, time, deadline, and flow credit are independent trust inputs"
    )]
    pub fn begin_open<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        relay: &AuthenticatedHnsrPeer,
        ticket: RelayTicket,
        now: u64,
        deadline: u64,
        initial_window: u32,
    ) -> Result<HnsrRoute, HnsrTransportError> {
        self.ensure_peer(authority, relay)?;
        self.requester
            .begin_open(
                relay.peer_id.clone(),
                relay.identity.as_bytes(),
                ticket,
                now,
                deadline,
                initial_window,
            )
            .map_err(HnsrTransportError::Runtime)
    }

    /// Admit one packet only from the exact relay connection owning the state.
    pub fn handle<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        relay: &AuthenticatedHnsrPeer,
        packet: &HnsrPacket,
        now: u64,
    ) -> Result<Option<HnsrRequesterEvent>, HnsrTransportError> {
        self.ensure_peer(authority, relay)?;
        self.requester
            .handle(&relay.peer_id, packet, now)
            .map_err(HnsrTransportError::Runtime)
    }

    /// Produce one exact outbound opaque DATA route.
    pub fn send_data<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        circuit_id: [u8; 8],
        bytes: Vec<u8>,
    ) -> Result<HnsrRoute, HnsrTransportError> {
        self.ensure_current(authority)?;
        self.requester
            .send_data(circuit_id, bytes)
            .map_err(HnsrTransportError::Runtime)
    }

    /// Consume one inbound frame and return its exact WINDOW route.
    pub fn take_data<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        circuit_id: [u8; 8],
    ) -> Result<(Vec<u8>, HnsrRoute), HnsrTransportError> {
        self.ensure_current(authority)?;
        self.requester
            .take_data(circuit_id)
            .map_err(HnsrTransportError::Runtime)
    }

    /// Close one active circuit locally and return its best-effort route.
    pub fn close<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        circuit_id: [u8; 8],
        reason: u16,
        detail: &str,
    ) -> Result<HnsrRoute, HnsrTransportError> {
        self.ensure_current(authority)?;
        self.requester
            .close(circuit_id, reason, detail)
            .map_err(HnsrTransportError::Runtime)
    }

    /// Cancel one pending open and return its exact relay route.
    pub fn cancel_open<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        context_id: [u8; 8],
        reason: u16,
        detail: &str,
    ) -> Result<HnsrRoute, HnsrTransportError> {
        self.ensure_current(authority)?;
        self.requester
            .cancel_open(context_id, reason, detail)
            .map_err(HnsrTransportError::Runtime)
    }

    /// Revoke all state owned by one disconnected authenticated relay.
    pub fn disconnect(&mut self, relay: &AuthenticatedHnsrPeer) -> usize {
        if relay.binding != self.binding {
            return 0;
        }
        self.requester.disconnect(&relay.peer_id)
    }

    /// Expire pending and active requester work against trusted time.
    pub fn expire<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        now: u64,
    ) -> Result<usize, HnsrTransportError> {
        self.ensure_current(authority)?;
        self.requester
            .expire(now)
            .map_err(HnsrTransportError::Runtime)
    }

    /// Independently replace requester enablement with generation matching.
    pub fn replace_enabled<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        expected_generation: u64,
        enabled: bool,
    ) -> Result<Vec<HnsrRoute>, HnsrTransportError> {
        self.ensure_current(authority)?;
        self.requester
            .replace_enabled(expected_generation, enabled)
            .map_err(HnsrTransportError::Runtime)
    }

    /// Export a checksummed, network/profile-bound restart snapshot.
    pub fn export<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        now: u64,
    ) -> Result<HnsrRuntimeExport, HnsrTransportError> {
        self.ensure_current(authority)?;
        self.requester
            .observe_time(now)
            .map_err(HnsrTransportError::Runtime)?;
        let status = self.requester.status();
        encode_runtime_export(
            self.binding,
            status,
            self.requester.snapshot().encode(),
        )
    }

    /// Read honest local readiness without claiming adapter availability.
    pub fn status<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
    ) -> Result<HnsrTransportStatus, HnsrTransportError> {
        self.observe_authority(authority)?;
        Ok(transport_status(
            self.binding,
            self.requester.status(),
            self.revocation_reason,
            0,
        ))
    }

    /// Terminally revoke requester authority and return best-effort closures.
    pub fn revoke(&mut self) -> Result<Vec<HnsrRoute>, HnsrTransportError> {
        self.revoke_for(HnsrTransportRevocationReason::Explicit)
    }

    fn ensure_peer<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        peer: &AuthenticatedHnsrPeer,
    ) -> Result<(), HnsrTransportError> {
        self.ensure_current(authority)?;
        if peer.binding != self.binding {
            return Err(HnsrTransportError::PeerBindingMismatch);
        }
        Ok(())
    }

    fn ensure_current<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
    ) -> Result<(), HnsrTransportError> {
        if self.revocation_reason.is_some() {
            return Err(HnsrTransportError::BindingRevoked);
        }
        if let Err(error) = authority.validate_hnsr_transport_binding(self.binding) {
            let reason = revocation_reason_for_error(&error);
            let _ = self.revoke_for(reason);
            return Err(error);
        }
        Ok(())
    }

    fn observe_authority<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
    ) -> Result<(), HnsrTransportError> {
        if self.revocation_reason.is_none() {
            if let Err(error) = authority.validate_hnsr_transport_binding(self.binding) {
                let _ = self.revoke_for(revocation_reason_for_error(&error));
            }
        }
        Ok(())
    }

    fn revoke_for(
        &mut self,
        reason: HnsrTransportRevocationReason,
    ) -> Result<Vec<HnsrRoute>, HnsrTransportError> {
        self.revocation_reason = Some(reason);
        let generation = self.requester.status().generation;
        self.requester
            .replace_enabled(generation, false)
            .map_err(HnsrTransportError::Runtime)
    }
}

impl HnsrOpaqueRelayRuntime {
    /// Exact engine/network/profile epoch that admitted this relay.
    #[must_use]
    pub const fn binding(&self) -> HnsrTransportBinding {
        self.binding
    }

    /// Public relay key whose private half remains inside the reservation service.
    #[must_use]
    pub fn relay_key(&self) -> [u8; 33] {
        self.service
            .relay()
            .map_or([0; 33], RelayService::relay_key)
    }

    /// Authenticate one exact requester/endpoint outer connection.
    pub fn authenticate_participant<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        connection_label: String,
        identity: PeerIdentity,
        peer: ExperimentalPeerState,
        registry: NegotiatedRegistry,
    ) -> Result<AuthenticatedHnsrPeer, HnsrTransportError> {
        self.ensure_current(authority)?;
        authenticate_hnsr_peer(self.binding, connection_label, identity, peer, registry, false)
    }

    /// Handle one reservation-plane packet; rendezvous opcodes fail closed.
    pub fn handle_reservation<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        source: &AuthenticatedHnsrPeer,
        packet: &HnsrPacket,
        now: u64,
    ) -> Result<Option<HnsrRoute>, HnsrTransportError> {
        self.ensure_peer(authority, source)?;
        self.relay
            .observe_time(now)
            .map_err(HnsrTransportError::Runtime)?;
        self.observed_peers.insert(source.connection_label.clone());
        self.service
            .handle(packet, &source.connection_label, now)
            .map(|response| {
                response.map(|packet| HnsrRoute {
                    destination: source.peer_id.clone(),
                    packet,
                })
            })
            .map_err(HnsrTransportError::Protocol)
    }

    /// Handle one opaque circuit packet and return exact queued routes.
    pub fn handle_circuit<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        source: &AuthenticatedHnsrPeer,
        packet: &HnsrPacket,
        now: u64,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrTransportError> {
        self.ensure_peer(authority, source)?;
        self.observed_peers.insert(source.connection_label.clone());
        let reservations = self
            .service
            .relay()
            .ok_or(HnsrTransportError::RelayServiceUnavailable)?;
        self.relay
            .handle(reservations, &source.peer_id, packet, now)
            .map_err(HnsrTransportError::Runtime)
    }

    /// Acknowledge one exact generation-bound adapter write.
    pub fn acknowledge<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        action_id: HnsrActionId,
        delivered: bool,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrTransportError> {
        self.ensure_current(authority)?;
        self.relay
            .acknowledge(action_id, delivered)
            .map_err(HnsrTransportError::Runtime)
    }

    /// Revoke reservations, pending work, circuits, and queued writes on disconnect.
    pub fn disconnect(&mut self, peer: &AuthenticatedHnsrPeer) -> Vec<QueuedHnsrRoute> {
        if peer.binding != self.binding {
            return Vec::new();
        }
        self.observed_peers.remove(&peer.connection_label);
        let reservation_ids = self
            .service
            .relay_mut()
            .map_or_else(Vec::new, |relay| relay.disconnect(&peer.connection_label));
        let mut routes = self.relay.disconnect(&peer.peer_id);
        for reservation_id in reservation_ids {
            routes.extend(self.relay.revoke_reservation(reservation_id));
        }
        routes
    }

    /// Prune reservation and circuit lifetimes against trusted time.
    pub fn expire<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        now: u64,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrTransportError> {
        self.ensure_current(authority)?;
        if let Some(relay) = self.service.relay_mut() {
            relay.prune(now);
        }
        self.relay.expire(now).map_err(HnsrTransportError::Runtime)
    }

    /// Independently replace opaque-relay enablement with generation matching.
    pub fn replace_enabled<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        expected_generation: u64,
        enabled: bool,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrTransportError> {
        self.ensure_current(authority)?;
        let routes = self
            .relay
            .replace_enabled(expected_generation, enabled)
            .map_err(HnsrTransportError::Runtime)?;
        if !enabled {
            self.clear_reservations();
        }
        Ok(routes)
    }

    /// Export a checksummed snapshot without private keys, peers, or live bytes.
    pub fn export<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        now: u64,
    ) -> Result<HnsrRuntimeExport, HnsrTransportError> {
        self.ensure_current(authority)?;
        self.relay
            .observe_time(now)
            .map_err(HnsrTransportError::Runtime)?;
        let status = self.relay.status();
        encode_runtime_export(self.binding, status, self.relay.snapshot().encode())
    }

    /// Read honest local readiness without claiming transport or plaintext access.
    pub fn status<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
    ) -> Result<HnsrTransportStatus, HnsrTransportError> {
        self.observe_authority(authority)?;
        let reservations = self.service.relay().map_or(0, RelayService::len);
        Ok(transport_status(
            self.binding,
            self.relay.status(),
            self.revocation_reason,
            reservations,
        ))
    }

    /// Terminally revoke relay authority and clear every reservation.
    pub fn revoke(&mut self) -> Result<Vec<QueuedHnsrRoute>, HnsrTransportError> {
        self.revoke_for(HnsrTransportRevocationReason::Explicit)
    }

    fn ensure_peer<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        peer: &AuthenticatedHnsrPeer,
    ) -> Result<(), HnsrTransportError> {
        self.ensure_current(authority)?;
        if peer.binding != self.binding {
            return Err(HnsrTransportError::PeerBindingMismatch);
        }
        Ok(())
    }

    fn ensure_current<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
    ) -> Result<(), HnsrTransportError> {
        if self.revocation_reason.is_some() {
            return Err(HnsrTransportError::BindingRevoked);
        }
        if let Err(error) = authority.validate_hnsr_transport_binding(self.binding) {
            let reason = revocation_reason_for_error(&error);
            let _ = self.revoke_for(reason);
            return Err(error);
        }
        Ok(())
    }

    fn observe_authority<C: HnsrTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
    ) -> Result<(), HnsrTransportError> {
        if self.revocation_reason.is_none() {
            if let Err(error) = authority.validate_hnsr_transport_binding(self.binding) {
                let _ = self.revoke_for(revocation_reason_for_error(&error));
            }
        }
        Ok(())
    }

    fn revoke_for(
        &mut self,
        reason: HnsrTransportRevocationReason,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrTransportError> {
        self.revocation_reason = Some(reason);
        let generation = self.relay.status().generation;
        let routes = self
            .relay
            .replace_enabled(generation, false)
            .map_err(HnsrTransportError::Runtime)?;
        self.clear_reservations();
        Ok(routes)
    }

    fn clear_reservations(&mut self) {
        let peers = std::mem::take(&mut self.observed_peers);
        for peer in peers {
            let reservations = self
                .service
                .relay_mut()
                .map_or_else(Vec::new, |relay| relay.disconnect(&peer));
            for reservation_id in reservations {
                let _ = self.relay.revoke_reservation(reservation_id);
            }
        }
    }
}

impl PrivateTransportAuthority<'_> {
    /// Start a profile-bound HNSR requester on the canonical browser runtime.
    pub fn start_hnsr_requester(
        &mut self,
        generation: u64,
        config: HnsrRequesterConfig,
        trusted_now: u64,
    ) -> Result<HnsrRequesterRuntime, HnsrTransportError> {
        let binding = mint_hnsr_transport_binding(
            self.runtime,
            self.network,
            self.policy,
            HnsrTransportRole::Requester,
            config.profile,
            config.allow_private_relay,
        )?;
        start_hnsr_requester(binding, generation, config, trusted_now)
    }

    /// Restore a requester under caller-held generation and time floors.
    #[allow(
        clippy::too_many_arguments,
        reason = "snapshot, two rollback floors, generation, and trusted time are independent persistence inputs"
    )]
    pub fn restore_hnsr_requester(
        &mut self,
        snapshot: &[u8],
        minimum_generation: u64,
        minimum_trusted_time_high_water: u64,
        trusted_now: u64,
    ) -> Result<HnsrRequesterRuntime, HnsrTransportError> {
        let decoded = decode_runtime_export(snapshot, HnsrTransportRole::Requester)?;
        let binding = mint_hnsr_transport_binding(
            self.runtime,
            self.network,
            self.policy,
            HnsrTransportRole::Requester,
            decoded.service_profile,
            decoded.allow_private_address,
        )?;
        restore_hnsr_requester(
            binding,
            decoded,
            minimum_generation,
            minimum_trusted_time_high_water,
            trusted_now,
        )
    }

    /// Start a single-profile opaque relay; endpoint and rendezvous stay absent.
    #[allow(
        clippy::too_many_arguments,
        reason = "generation, reservation configuration/key, circuit bounds, and time are independent trust inputs"
    )]
    pub fn start_hnsr_opaque_relay(
        &mut self,
        generation: u64,
        relay_config: RelayConfig,
        relay_private_key: [u8; 32],
        runtime_config: OpaqueRelayConfig,
        trusted_now: u64,
    ) -> Result<HnsrOpaqueRelayRuntime, HnsrTransportError> {
        let (profile, allow_private) = validate_relay_config(self.network, &relay_config)?;
        let binding = mint_hnsr_transport_binding(
            self.runtime,
            self.network,
            self.policy,
            HnsrTransportRole::OpaqueRelay,
            profile,
            allow_private,
        )?;
        start_hnsr_opaque_relay(
            binding,
            generation,
            relay_config,
            relay_private_key,
            runtime_config,
            trusted_now,
        )
    }

    /// Restore relay counters/settings with a fresh reservation key and no live state.
    #[allow(
        clippy::too_many_arguments,
        reason = "snapshot, rollback floors, fresh key/configuration, and time are independent persistence inputs"
    )]
    pub fn restore_hnsr_opaque_relay(
        &mut self,
        snapshot: &[u8],
        minimum_generation: u64,
        minimum_trusted_time_high_water: u64,
        relay_config: RelayConfig,
        relay_private_key: [u8; 32],
        trusted_now: u64,
    ) -> Result<HnsrOpaqueRelayRuntime, HnsrTransportError> {
        let decoded = decode_runtime_export(snapshot, HnsrTransportRole::OpaqueRelay)?;
        let (profile, allow_private) = validate_relay_config(self.network, &relay_config)?;
        if profile != decoded.service_profile || allow_private != decoded.allow_private_address {
            return Err(HnsrTransportError::SnapshotBindingMismatch);
        }
        let binding = mint_hnsr_transport_binding(
            self.runtime,
            self.network,
            self.policy,
            HnsrTransportRole::OpaqueRelay,
            profile,
            allow_private,
        )?;
        restore_hnsr_opaque_relay(
            binding,
            decoded,
            minimum_generation,
            minimum_trusted_time_high_water,
            relay_config,
            relay_private_key,
            trusted_now,
        )
    }
}

impl HnsrTransportAuthorityContext for PrivateTransportAuthority<'_> {
    fn validate_hnsr_transport_binding(
        &self,
        binding: HnsrTransportBinding,
    ) -> Result<(), HnsrTransportError> {
        validate_hnsr_transport_binding(self.runtime, self.network, self.policy, binding)
    }
}

impl Engine {
    /// Start a profile-bound HNSR requester through the engine convenience facade.
    pub fn start_hnsr_requester(
        &self,
        generation: u64,
        config: HnsrRequesterConfig,
        trusted_now: u64,
    ) -> Result<HnsrRequesterRuntime, HnsrTransportError> {
        let binding = self.mint_hnsr_transport_binding(
            HnsrTransportRole::Requester,
            config.profile,
            config.allow_private_relay,
        )?;
        start_hnsr_requester(binding, generation, config, trusted_now)
    }

    /// Restore requester settings/counters under caller-held rollback floors.
    pub fn restore_hnsr_requester(
        &self,
        snapshot: &[u8],
        minimum_generation: u64,
        minimum_trusted_time_high_water: u64,
        trusted_now: u64,
    ) -> Result<HnsrRequesterRuntime, HnsrTransportError> {
        let decoded = decode_runtime_export(snapshot, HnsrTransportRole::Requester)?;
        let binding = self.mint_hnsr_transport_binding(
            HnsrTransportRole::Requester,
            decoded.service_profile,
            decoded.allow_private_address,
        )?;
        restore_hnsr_requester(
            binding,
            decoded,
            minimum_generation,
            minimum_trusted_time_high_water,
            trusted_now,
        )
    }

    /// Start the ciphertext-only HNSR relay with rendezvous hard disabled.
    pub fn start_hnsr_opaque_relay(
        &self,
        generation: u64,
        relay_config: RelayConfig,
        relay_private_key: [u8; 32],
        runtime_config: OpaqueRelayConfig,
        trusted_now: u64,
    ) -> Result<HnsrOpaqueRelayRuntime, HnsrTransportError> {
        let snapshot = self.snapshot().map_err(HnsrTransportError::Engine)?;
        let (profile, allow_private) = validate_relay_config(snapshot.network, &relay_config)?;
        let binding = self.mint_hnsr_transport_binding(
            HnsrTransportRole::OpaqueRelay,
            profile,
            allow_private,
        )?;
        start_hnsr_opaque_relay(
            binding,
            generation,
            relay_config,
            relay_private_key,
            runtime_config,
            trusted_now,
        )
    }

    /// Restore relay settings/counters with a fresh key and no live authority.
    #[allow(
        clippy::too_many_arguments,
        reason = "snapshot, rollback floors, fresh key/configuration, and time are independent persistence inputs"
    )]
    pub fn restore_hnsr_opaque_relay(
        &self,
        snapshot: &[u8],
        minimum_generation: u64,
        minimum_trusted_time_high_water: u64,
        relay_config: RelayConfig,
        relay_private_key: [u8; 32],
        trusted_now: u64,
    ) -> Result<HnsrOpaqueRelayRuntime, HnsrTransportError> {
        let decoded = decode_runtime_export(snapshot, HnsrTransportRole::OpaqueRelay)?;
        let engine = self.snapshot().map_err(HnsrTransportError::Engine)?;
        let (profile, allow_private) = validate_relay_config(engine.network, &relay_config)?;
        if profile != decoded.service_profile || allow_private != decoded.allow_private_address {
            return Err(HnsrTransportError::SnapshotBindingMismatch);
        }
        let binding = self.mint_hnsr_transport_binding(
            HnsrTransportRole::OpaqueRelay,
            profile,
            allow_private,
        )?;
        restore_hnsr_opaque_relay(
            binding,
            decoded,
            minimum_generation,
            minimum_trusted_time_high_water,
            relay_config,
            relay_private_key,
            trusted_now,
        )
    }

    fn mint_hnsr_transport_binding(
        &self,
        role: HnsrTransportRole,
        service_profile: u16,
        allow_private_address: bool,
    ) -> Result<HnsrTransportBinding, HnsrTransportError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| HnsrTransportError::Engine(EngineError::LockPoisoned))?;
        let network = state.network;
        let policy = state.policy.snapshot();
        mint_hnsr_transport_binding(
            &mut state.runtime,
            network,
            policy,
            role,
            service_profile,
            allow_private_address,
        )
    }
}

impl HnsrTransportAuthorityContext for Engine {
    fn validate_hnsr_transport_binding(
        &self,
        binding: HnsrTransportBinding,
    ) -> Result<(), HnsrTransportError> {
        let state = self
            .state
            .read()
            .map_err(|_| HnsrTransportError::Engine(EngineError::LockPoisoned))?;
        validate_hnsr_transport_binding(
            &state.runtime,
            state.network,
            state.policy.snapshot(),
            binding,
        )
    }
}

fn start_hnsr_requester(
    binding: HnsrTransportBinding,
    generation: u64,
    mut config: HnsrRequesterConfig,
    trusted_now: u64,
) -> Result<HnsrRequesterRuntime, HnsrTransportError> {
    if config.network_magic != binding.network_magic
        || config.profile != binding.service_profile
        || config.allow_private_relay != binding.allow_private_address
    {
        return Err(HnsrTransportError::ConfigurationBindingMismatch);
    }
    config.network_magic = binding.network_magic;
    let requester = HnsrRequester::new(
        binding.runtime_session(),
        generation,
        config,
        trusted_now,
    )
    .map_err(HnsrTransportError::Runtime)?;
    Ok(HnsrRequesterRuntime {
        binding,
        requester,
        revocation_reason: None,
    })
}

fn restore_hnsr_requester(
    binding: HnsrTransportBinding,
    decoded: DecodedRuntimeExport,
    minimum_generation: u64,
    minimum_trusted_time_high_water: u64,
    trusted_now: u64,
) -> Result<HnsrRequesterRuntime, HnsrTransportError> {
    validate_restore_envelope(
        binding,
        &decoded,
        minimum_generation,
        minimum_trusted_time_high_water,
        trusted_now,
    )?;
    let snapshot = HnsrRequesterSnapshot::decode(&decoded.inner)
        .map_err(HnsrTransportError::Runtime)?;
    validate_requester_inner_binding(&decoded)?;
    let requester = HnsrRequester::restore(
        snapshot,
        binding.runtime_session(),
        minimum_generation,
        trusted_now,
    )
    .map_err(HnsrTransportError::Runtime)?;
    validate_restored_status(requester.status(), &decoded, trusted_now)?;
    Ok(HnsrRequesterRuntime {
        binding,
        requester,
        revocation_reason: None,
    })
}

fn start_hnsr_opaque_relay(
    binding: HnsrTransportBinding,
    generation: u64,
    relay_config: RelayConfig,
    relay_private_key: [u8; 32],
    runtime_config: OpaqueRelayConfig,
    trusted_now: u64,
) -> Result<HnsrOpaqueRelayRuntime, HnsrTransportError> {
    let relay_service =
        RelayService::new(relay_config, relay_private_key).map_err(HnsrTransportError::Protocol)?;
    let relay = OpaqueRelayRuntime::new(
        binding.runtime_session(),
        generation,
        runtime_config,
        trusted_now,
    )
    .map_err(HnsrTransportError::Runtime)?;
    Ok(HnsrOpaqueRelayRuntime {
        binding,
        relay,
        service: HnsrService::new(Some(relay_service), None),
        observed_peers: BTreeSet::new(),
        revocation_reason: None,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "binding, snapshot, rollback floors, fresh reservation configuration/key, and time are independent"
)]
fn restore_hnsr_opaque_relay(
    binding: HnsrTransportBinding,
    decoded: DecodedRuntimeExport,
    minimum_generation: u64,
    minimum_trusted_time_high_water: u64,
    relay_config: RelayConfig,
    relay_private_key: [u8; 32],
    trusted_now: u64,
) -> Result<HnsrOpaqueRelayRuntime, HnsrTransportError> {
    validate_restore_envelope(
        binding,
        &decoded,
        minimum_generation,
        minimum_trusted_time_high_water,
        trusted_now,
    )?;
    let snapshot =
        OpaqueRelaySnapshot::decode(&decoded.inner).map_err(HnsrTransportError::Runtime)?;
    validate_relay_inner_binding(&decoded)?;
    let relay = OpaqueRelayRuntime::restore(
        snapshot,
        binding.runtime_session(),
        minimum_generation,
        trusted_now,
    )
    .map_err(HnsrTransportError::Runtime)?;
    validate_restored_status(relay.status(), &decoded, trusted_now)?;
    let relay_service =
        RelayService::new(relay_config, relay_private_key).map_err(HnsrTransportError::Protocol)?;
    Ok(HnsrOpaqueRelayRuntime {
        binding,
        relay,
        service: HnsrService::new(Some(relay_service), None),
        observed_peers: BTreeSet::new(),
        revocation_reason: None,
    })
}

fn mint_hnsr_transport_binding(
    runtime: &mut BrowserRuntime,
    network: Network,
    policy: PolicySnapshot,
    role: HnsrTransportRole,
    service_profile: u16,
    allow_private_address: bool,
) -> Result<HnsrTransportBinding, HnsrTransportError> {
    validate_hnsr_policy(network, policy, role, service_profile, allow_private_address)?;
    if !resolution_transport_ready(runtime.authority_state()) {
        return Err(HnsrTransportError::AuthorityUnavailable);
    }
    let stamp = runtime
        .admit_event()
        .map_err(|error| HnsrTransportError::Engine(super::map_runtime_error(error)))?;
    Ok(HnsrTransportBinding {
        stamp,
        network,
        network_magic: network_magic(network),
        policy_generation: policy.generation(),
        policy_wire_profile: policy.config().wire_profile,
        resolved_wire_profile: resolved_odoh_profile(policy.config().wire_profile)
            .map_err(|_| HnsrTransportError::UnsupportedWireProfile)?,
        role,
        service_profile,
        allow_private_address,
    })
}

fn validate_hnsr_transport_binding(
    browser_runtime: &BrowserRuntime,
    network: Network,
    policy: PolicySnapshot,
    binding: HnsrTransportBinding,
) -> Result<(), HnsrTransportError> {
    validate_hnsr_policy(
        network,
        policy,
        binding.role,
        binding.service_profile,
        binding.allow_private_address,
    )?;
    let runtime = browser_runtime.snapshot();
    if network != binding.network || network_magic(network) != binding.network_magic {
        return Err(HnsrTransportError::NetworkChanged);
    }
    if runtime.session_bytes() != binding.stamp.session() {
        return Err(HnsrTransportError::RuntimeSessionChanged);
    }
    if runtime.generation() != binding.stamp.generation() {
        return Err(HnsrTransportError::RuntimeGenerationChanged);
    }
    if policy.generation() != binding.policy_generation {
        return Err(HnsrTransportError::PolicyGenerationChanged);
    }
    if policy.config().wire_profile != binding.policy_wire_profile
        || binding.resolved_wire_profile != ExperimentalWireProfile::DenuoV1
    {
        return Err(HnsrTransportError::UnsupportedWireProfile);
    }
    if !resolution_transport_ready(runtime.authority_state()) {
        return Err(HnsrTransportError::AuthorityUnavailable);
    }
    if !browser_runtime.admits(binding.stamp) {
        return Err(HnsrTransportError::AdmissionInvalidated);
    }
    Ok(())
}

fn validate_hnsr_policy(
    network: Network,
    policy: PolicySnapshot,
    role: HnsrTransportRole,
    service_profile: u16,
    allow_private_address: bool,
) -> Result<(), HnsrTransportError> {
    if service_profile == 0 {
        return Err(HnsrTransportError::InvalidServiceProfile);
    }
    if allow_private_address && !matches!(network, Network::Regtest | Network::Simnet) {
        return Err(HnsrTransportError::PrivateAddressForbidden);
    }
    let config = policy.config();
    if config.wire_profile == WireProfile::Official {
        return Err(HnsrTransportError::UnsupportedWireProfile);
    }
    if config.hnsr.endpoint_enabled() || config.hnsr.rendezvous_enabled() {
        return Err(HnsrTransportError::ForbiddenProviderRoles);
    }
    let enabled = match role {
        HnsrTransportRole::Requester => config.hnsr.requester_enabled(),
        HnsrTransportRole::OpaqueRelay => config.hnsr.relay_enabled(),
    };
    if !enabled {
        return Err(HnsrTransportError::RoleDisabled(role));
    }
    Ok(())
}

fn validate_relay_config(
    network: Network,
    config: &RelayConfig,
) -> Result<(u16, bool), HnsrTransportError> {
    if config.network_magic != network_magic(network) || config.supported_profiles.len() != 1 {
        return Err(HnsrTransportError::ConfigurationBindingMismatch);
    }
    let profile = config
        .supported_profiles
        .first()
        .copied()
        .ok_or(HnsrTransportError::InvalidServiceProfile)?;
    if profile == 0 {
        return Err(HnsrTransportError::InvalidServiceProfile);
    }
    if config.allow_private_address && !matches!(network, Network::Regtest | Network::Simnet) {
        return Err(HnsrTransportError::PrivateAddressForbidden);
    }
    Ok((profile, config.allow_private_address))
}

fn authenticate_hnsr_peer(
    binding: HnsrTransportBinding,
    connection_label: String,
    identity: PeerIdentity,
    peer: ExperimentalPeerState,
    registry: NegotiatedRegistry,
    require_relay_service: bool,
) -> Result<AuthenticatedHnsrPeer, HnsrTransportError> {
    if connection_label.is_empty()
        || connection_label.len() > MAX_HNSR_CONNECTION_LABEL_BYTES
        || !connection_label.is_ascii()
        || connection_label.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(HnsrTransportError::InvalidConnectionLabel);
    }
    let peer_id = HnsrPeerId::new(connection_label.as_bytes().to_vec())
        .map_err(HnsrTransportError::Runtime)?;
    let mut authenticated =
        super::AuthenticatedPeer::bind(identity, peer, registry).map_err(HnsrTransportError::Peer)?;
    let admission = if require_relay_service {
        authenticated.admit_canonical_hnsr_relay(
            experimental_network(binding.network),
            canonical_genesis_hash(binding.network),
            binding.resolved_wire_profile,
        )
    } else {
        authenticated.admit_canonical_hnsr_participant(
            experimental_network(binding.network),
            canonical_genesis_hash(binding.network),
            binding.resolved_wire_profile,
        )
    };
    admission.map_err(HnsrTransportError::Peer)?;
    Ok(AuthenticatedHnsrPeer {
        binding,
        connection_label,
        peer_id,
        identity,
    })
}

fn transport_status(
    binding: HnsrTransportBinding,
    runtime: HnsrRuntimeStatus,
    revocation_reason: Option<HnsrTransportRevocationReason>,
    confirmed_reservations: usize,
) -> HnsrTransportStatus {
    let state = if revocation_reason.is_some() {
        HnsrTransportState::Revoked
    } else if runtime.enabled {
        HnsrTransportState::Enabled
    } else {
        HnsrTransportState::Disabled
    };
    let ready = state == HnsrTransportState::Enabled;
    HnsrTransportStatus {
        schema_version: HNSR_TRANSPORT_SCHEMA_VERSION,
        binding,
        state,
        revocation_reason,
        runtime,
        confirmed_reservations,
        requester_protocol_ready: ready && binding.role == HnsrTransportRole::Requester,
        opaque_relay_protocol_ready: ready && binding.role == HnsrTransportRole::OpaqueRelay,
        transport_adapter_available: false,
        endpoint_provider_available: false,
        rendezvous_provider_available: false,
        plaintext_available: false,
    }
}

const fn revocation_reason_for_error(
    error: &HnsrTransportError,
) -> HnsrTransportRevocationReason {
    match error {
        HnsrTransportError::PolicyGenerationChanged
        | HnsrTransportError::UnsupportedWireProfile
        | HnsrTransportError::RoleDisabled(_)
        | HnsrTransportError::ForbiddenProviderRoles => {
            HnsrTransportRevocationReason::PolicyChanged
        }
        _ => HnsrTransportRevocationReason::AuthorityChanged,
    }
}

fn encode_runtime_export(
    binding: HnsrTransportBinding,
    status: HnsrRuntimeStatus,
    inner: Vec<u8>,
) -> Result<HnsrRuntimeExport, HnsrTransportError> {
    if status.generation == 0 || inner.is_empty() {
        return Err(HnsrTransportError::InvalidSnapshotGeneration);
    }
    let inner_length = u32::try_from(inner.len())
        .map_err(|_| HnsrTransportError::SnapshotTooLarge)?;
    let total = HNSR_SNAPSHOT_HEADER_BYTES
        .checked_add(inner.len())
        .and_then(|length| length.checked_add(HNSR_SNAPSHOT_CHECKSUM_BYTES))
        .ok_or(HnsrTransportError::SnapshotTooLarge)?;
    if total > MAX_HNSR_RUNTIME_SNAPSHOT_BYTES {
        return Err(HnsrTransportError::SnapshotTooLarge);
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(HNSR_SNAPSHOT_MAGIC);
    bytes.extend_from_slice(&HNSR_TRANSPORT_SCHEMA_VERSION.to_le_bytes());
    bytes.push(binding.role as u8);
    bytes.push(binding.network as u8);
    bytes.extend_from_slice(&binding.network_magic.to_le_bytes());
    bytes.push(binding.policy_wire_profile as u8);
    bytes.push(1);
    bytes.push(u8::from(binding.allow_private_address));
    bytes.push(0);
    bytes.extend_from_slice(&binding.service_profile.to_le_bytes());
    bytes.extend_from_slice(&binding.policy_generation.to_le_bytes());
    bytes.extend_from_slice(&status.generation.to_le_bytes());
    bytes.extend_from_slice(&status.trusted_time_high_water.to_le_bytes());
    bytes.extend_from_slice(&inner_length.to_le_bytes());
    bytes.extend_from_slice(&inner);
    let checksum = crc32(&bytes);
    bytes.extend_from_slice(&checksum.to_le_bytes());
    Ok(HnsrRuntimeExport {
        generation: status.generation,
        trusted_time_high_water: status.trusted_time_high_water,
        bytes,
    })
}

struct DecodedRuntimeExport {
    role: HnsrTransportRole,
    network: Network,
    network_magic: u32,
    policy_wire_profile: u8,
    resolved_wire_profile: u8,
    allow_private_address: bool,
    service_profile: u16,
    policy_generation: u64,
    generation: u64,
    trusted_time_high_water: u64,
    inner: Vec<u8>,
}

fn decode_runtime_export(
    input: &[u8],
    expected_role: HnsrTransportRole,
) -> Result<DecodedRuntimeExport, HnsrTransportError> {
    if input.len() < HNSR_SNAPSHOT_HEADER_BYTES + HNSR_SNAPSHOT_CHECKSUM_BYTES
        || input.len() > MAX_HNSR_RUNTIME_SNAPSHOT_BYTES
    {
        return Err(HnsrTransportError::InvalidSnapshot);
    }
    let payload_length = input
        .len()
        .checked_sub(HNSR_SNAPSHOT_CHECKSUM_BYTES)
        .ok_or(HnsrTransportError::InvalidSnapshot)?;
    let (payload, checksum) = input.split_at(payload_length);
    let expected_checksum = u32::from_le_bytes(
        checksum
            .try_into()
            .map_err(|_| HnsrTransportError::InvalidSnapshot)?,
    );
    if crc32(payload) != expected_checksum {
        return Err(HnsrTransportError::SnapshotChecksumMismatch);
    }
    let mut decoder = SnapshotDecoder::new(payload);
    if decoder.take(8)? != HNSR_SNAPSHOT_MAGIC {
        return Err(HnsrTransportError::InvalidSnapshot);
    }
    if decoder.u16()? != HNSR_TRANSPORT_SCHEMA_VERSION {
        return Err(HnsrTransportError::UnsupportedSnapshotSchema);
    }
    let role = match decoder.u8()? {
        1 => HnsrTransportRole::Requester,
        2 => HnsrTransportRole::OpaqueRelay,
        _ => return Err(HnsrTransportError::InvalidSnapshot),
    };
    if role != expected_role {
        return Err(HnsrTransportError::SnapshotBindingMismatch);
    }
    let network = match decoder.u8()? {
        0 => Network::Mainnet,
        1 => Network::Testnet,
        2 => Network::Regtest,
        3 => Network::Simnet,
        _ => return Err(HnsrTransportError::InvalidSnapshot),
    };
    let network_magic = decoder.u32()?;
    let policy_wire_profile = decoder.u8()?;
    let resolved_wire_profile = decoder.u8()?;
    let allow_private_address = match decoder.u8()? {
        0 => false,
        1 => true,
        _ => return Err(HnsrTransportError::InvalidSnapshot),
    };
    if decoder.u8()? != 0 {
        return Err(HnsrTransportError::InvalidSnapshot);
    }
    let service_profile = decoder.u16()?;
    let policy_generation = decoder.u64()?;
    let generation = decoder.u64()?;
    let trusted_time_high_water = decoder.u64()?;
    let inner_length = usize::try_from(decoder.u32()?)
        .map_err(|_| HnsrTransportError::InvalidSnapshot)?;
    if inner_length == 0 || decoder.remaining() != inner_length {
        return Err(HnsrTransportError::InvalidSnapshot);
    }
    let inner = decoder.take(inner_length)?.to_vec();
    decoder.finish()?;
    if service_profile == 0 || policy_generation == 0 || generation == 0 {
        return Err(HnsrTransportError::InvalidSnapshotGeneration);
    }
    Ok(DecodedRuntimeExport {
        role,
        network,
        network_magic,
        policy_wire_profile,
        resolved_wire_profile,
        allow_private_address,
        service_profile,
        policy_generation,
        generation,
        trusted_time_high_water,
        inner,
    })
}

fn validate_restore_envelope(
    binding: HnsrTransportBinding,
    decoded: &DecodedRuntimeExport,
    minimum_generation: u64,
    minimum_trusted_time_high_water: u64,
    trusted_now: u64,
) -> Result<(), HnsrTransportError> {
    if minimum_generation == 0
        || decoded.generation < minimum_generation
        || decoded.trusted_time_high_water < minimum_trusted_time_high_water
    {
        return Err(HnsrTransportError::SnapshotRollback);
    }
    if trusted_now < decoded.trusted_time_high_water
        || trusted_now < minimum_trusted_time_high_water
    {
        return Err(HnsrTransportError::TrustedClockRollback);
    }
    if decoded.role != binding.role
        || decoded.network != binding.network
        || decoded.network_magic != binding.network_magic
        || decoded.policy_wire_profile != binding.policy_wire_profile as u8
        || decoded.resolved_wire_profile != 1
        || decoded.allow_private_address != binding.allow_private_address
        || decoded.service_profile != binding.service_profile
        || decoded.policy_generation != binding.policy_generation
    {
        return Err(HnsrTransportError::SnapshotBindingMismatch);
    }
    Ok(())
}

fn validate_restored_status(
    status: HnsrRuntimeStatus,
    decoded: &DecodedRuntimeExport,
    trusted_now: u64,
) -> Result<(), HnsrTransportError> {
    let expected_generation = decoded
        .generation
        .checked_add(1)
        .ok_or(HnsrTransportError::GenerationExhausted)?;
    if status.generation != expected_generation || status.trusted_time_high_water != trusted_now {
        return Err(HnsrTransportError::SnapshotBindingMismatch);
    }
    Ok(())
}

fn validate_requester_inner_binding(
    decoded: &DecodedRuntimeExport,
) -> Result<(), HnsrTransportError> {
    if decoded.inner.get(..8) != Some(b"HNSRQR1\0".as_slice())
        || decoded.inner.get(8).copied() != Some(1)
        || decoded.inner.get(9..12) != Some([0_u8, 0, 0].as_slice())
    {
        return Err(HnsrTransportError::SnapshotBindingMismatch);
    }
    let generation = read_inner_u64(&decoded.inner, 28)?;
    let trusted_time = read_inner_u64(&decoded.inner, 37)?;
    let network_magic = read_inner_u32(&decoded.inner, 45)?;
    let service_profile = read_inner_u16(&decoded.inner, 49)?;
    let allow_private = match decoded.inner.get(51).copied() {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(HnsrTransportError::SnapshotBindingMismatch),
    };
    if generation != decoded.generation
        || trusted_time != decoded.trusted_time_high_water
        || network_magic != decoded.network_magic
        || service_profile != decoded.service_profile
        || allow_private != decoded.allow_private_address
    {
        return Err(HnsrTransportError::SnapshotBindingMismatch);
    }
    Ok(())
}

fn validate_relay_inner_binding(
    decoded: &DecodedRuntimeExport,
) -> Result<(), HnsrTransportError> {
    if decoded.inner.get(..8) != Some(b"HNSRRL1\0".as_slice())
        || decoded.inner.get(8).copied() != Some(1)
        || decoded.inner.get(9..12) != Some([0_u8, 0, 0].as_slice())
        || read_inner_u64(&decoded.inner, 28)? != decoded.generation
        || read_inner_u64(&decoded.inner, 37)? != decoded.trusted_time_high_water
    {
        return Err(HnsrTransportError::SnapshotBindingMismatch);
    }
    Ok(())
}

fn read_inner_u16(input: &[u8], offset: usize) -> Result<u16, HnsrTransportError> {
    Ok(u16::from_le_bytes(
        input
            .get(offset..offset + 2)
            .ok_or(HnsrTransportError::SnapshotBindingMismatch)?
            .try_into()
            .map_err(|_| HnsrTransportError::SnapshotBindingMismatch)?,
    ))
}

fn read_inner_u32(input: &[u8], offset: usize) -> Result<u32, HnsrTransportError> {
    Ok(u32::from_le_bytes(
        input
            .get(offset..offset + 4)
            .ok_or(HnsrTransportError::SnapshotBindingMismatch)?
            .try_into()
            .map_err(|_| HnsrTransportError::SnapshotBindingMismatch)?,
    ))
}

fn read_inner_u64(input: &[u8], offset: usize) -> Result<u64, HnsrTransportError> {
    Ok(u64::from_le_bytes(
        input
            .get(offset..offset + 8)
            .ok_or(HnsrTransportError::SnapshotBindingMismatch)?
            .try_into()
            .map_err(|_| HnsrTransportError::SnapshotBindingMismatch)?,
    ))
}

struct SnapshotDecoder<'input> {
    input: &'input [u8],
    position: usize,
}

impl<'input> SnapshotDecoder<'input> {
    const fn new(input: &'input [u8]) -> Self {
        Self { input, position: 0 }
    }

    const fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize) -> Result<&'input [u8], HnsrTransportError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(HnsrTransportError::InvalidSnapshot)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(HnsrTransportError::InvalidSnapshot)?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, HnsrTransportError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(HnsrTransportError::InvalidSnapshot)
    }

    fn u16(&mut self) -> Result<u16, HnsrTransportError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| HnsrTransportError::InvalidSnapshot)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, HnsrTransportError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| HnsrTransportError::InvalidSnapshot)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, HnsrTransportError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| HnsrTransportError::InvalidSnapshot)?,
        ))
    }

    fn finish(self) -> Result<(), HnsrTransportError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(HnsrTransportError::InvalidSnapshot)
        }
    }
}

/// Engine HNSR lifecycle, admission, persistence, or canonical protocol error.
#[derive(Debug)]
#[non_exhaustive]
pub enum HnsrTransportError {
    /// Engine facade failure.
    Engine(EngineError),
    /// Canonical HNSR state-machine failure.
    Runtime(HnsrRuntimeError),
    /// Canonical HNSR reservation/wire failure.
    Protocol(HnsrProtocolError),
    /// Canonical Brontide/Denuo peer admission failure.
    Peer(P2pTransportError),
    /// Browser authority is not ready for transport work.
    AuthorityUnavailable,
    /// Browser runtime session changed.
    RuntimeSessionChanged,
    /// Browser runtime generation changed.
    RuntimeGenerationChanged,
    /// Persistent policy generation changed.
    PolicyGenerationChanged,
    /// A security-invalidating event superseded the admission.
    AdmissionInvalidated,
    /// Handshake network changed.
    NetworkChanged,
    /// Current policy selects a noncanonical HNSR peer profile.
    UnsupportedWireProfile,
    /// The requested independent HNSR role is disabled.
    RoleDisabled(HnsrTransportRole),
    /// Endpoint or rendezvous policy was enabled on this hard-disabled surface.
    ForbiddenProviderRoles,
    /// The inner service profile is zero.
    InvalidServiceProfile,
    /// Private addressing is restricted to regtest and simnet.
    PrivateAddressForbidden,
    /// Runtime or relay configuration conflicts with the engine binding.
    ConfigurationBindingMismatch,
    /// The exact adapter connection label is empty, oversized, or noncanonical.
    InvalidConnectionLabel,
    /// An authenticated peer belongs to another role epoch.
    PeerBindingMismatch,
    /// The runtime was terminally revoked.
    BindingRevoked,
    /// Relay reservation state is unexpectedly absent.
    RelayServiceUnavailable,
    /// Snapshot framing is malformed or extended.
    InvalidSnapshot,
    /// Snapshot exceeds its hard bound.
    SnapshotTooLarge,
    /// Snapshot schema is unsupported.
    UnsupportedSnapshotSchema,
    /// Outer persistence checksum differs.
    SnapshotChecksumMismatch,
    /// Snapshot generation or policy generation is zero.
    InvalidSnapshotGeneration,
    /// Snapshot generation or trusted time is below the caller-held floor.
    SnapshotRollback,
    /// Snapshot belongs to another network, profile, policy, or role.
    SnapshotBindingMismatch,
    /// Trusted time moved below a persisted or caller-held high-water.
    TrustedClockRollback,
    /// A generation cannot advance without wrapping.
    GenerationExhausted,
}

impl fmt::Display for HnsrTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(error) => write!(formatter, "HNSR engine failed: {error}"),
            Self::Runtime(error) => write!(formatter, "HNSR runtime failed: {error}"),
            Self::Protocol(error) => write!(formatter, "HNSR protocol failed: {error}"),
            Self::Peer(error) => write!(formatter, "HNSR peer admission failed: {error}"),
            Self::AuthorityUnavailable => formatter.write_str("HNSR authority is unavailable"),
            Self::RuntimeSessionChanged => formatter.write_str("HNSR runtime session changed"),
            Self::RuntimeGenerationChanged => {
                formatter.write_str("HNSR runtime generation changed")
            }
            Self::PolicyGenerationChanged => {
                formatter.write_str("HNSR policy generation changed")
            }
            Self::AdmissionInvalidated => formatter.write_str("HNSR admission was invalidated"),
            Self::NetworkChanged => formatter.write_str("HNSR network changed"),
            Self::UnsupportedWireProfile => {
                formatter.write_str("unsupported HNSR wire profile")
            }
            Self::RoleDisabled(role) => write!(formatter, "HNSR role {role:?} is disabled"),
            Self::ForbiddenProviderRoles => {
                formatter.write_str("HNSR endpoint and rendezvous roles are hard disabled")
            }
            Self::InvalidServiceProfile => formatter.write_str("invalid HNSR service profile"),
            Self::PrivateAddressForbidden => {
                formatter.write_str("private HNSR addresses are forbidden on this network")
            }
            Self::ConfigurationBindingMismatch => {
                formatter.write_str("HNSR configuration does not match its engine binding")
            }
            Self::InvalidConnectionLabel => formatter.write_str("invalid HNSR connection label"),
            Self::PeerBindingMismatch => formatter.write_str("HNSR peer binding mismatch"),
            Self::BindingRevoked => formatter.write_str("HNSR binding was revoked"),
            Self::RelayServiceUnavailable => formatter.write_str("HNSR relay service unavailable"),
            Self::InvalidSnapshot => formatter.write_str("invalid HNSR engine snapshot"),
            Self::SnapshotTooLarge => formatter.write_str("HNSR snapshot exceeds its bound"),
            Self::UnsupportedSnapshotSchema => {
                formatter.write_str("unsupported HNSR snapshot schema")
            }
            Self::SnapshotChecksumMismatch => {
                formatter.write_str("HNSR snapshot checksum mismatch")
            }
            Self::InvalidSnapshotGeneration => {
                formatter.write_str("invalid HNSR snapshot generation")
            }
            Self::SnapshotRollback => formatter.write_str("HNSR snapshot rollback detected"),
            Self::SnapshotBindingMismatch => {
                formatter.write_str("HNSR snapshot binding mismatch")
            }
            Self::TrustedClockRollback => formatter.write_str("HNSR trusted clock rollback"),
            Self::GenerationExhausted => formatter.write_str("HNSR generation exhausted"),
        }
    }
}

impl Error for HnsrTransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Engine(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Peer(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests fail immediately on deterministic in-memory authority fixtures"
)]
mod tests {
    use super::*;

    #[test]
    fn outer_snapshot_rejects_checksum_and_floor_rollback() {
        let session = super::super::RuntimeSessionId::new([1; 16]).expect("session");
        let mut browser = BrowserRuntime::new(session);
        for state in [
            super::super::AuthorityState::LocalStateOpened,
            super::super::AuthorityState::HeaderSyncing,
            super::super::AuthorityState::HeaderCurrent,
            super::super::AuthorityState::ProofReady,
            super::super::AuthorityState::ResolutionTransportReady,
        ] {
            browser.transition(state).expect("valid transition");
        }
        let binding = mint_hnsr_transport_binding(
            &mut browser,
            Network::Regtest,
            PolicySnapshot::default(),
            HnsrTransportRole::Requester,
            1,
            true,
        )
        .expect("binding");
        let status = HnsrRuntimeStatus {
            generation: 7,
            enabled: true,
            pending_circuits: 0,
            active_circuits: 0,
            queued_bytes: 0,
            queued_actions: 0,
            trusted_time_high_water: 11,
            admitted_opens: 0,
            opened_circuits: 0,
            bytes_sent: 0,
            bytes_received: 0,
            revoked_work: 0,
        };
        let exported = encode_runtime_export(binding, status, vec![1]).expect("encodes");
        let decoded = decode_runtime_export(&exported.bytes, HnsrTransportRole::Requester)
            .expect("decodes");
        assert!(matches!(
            validate_restore_envelope(binding, &decoded, 8, 11, 11),
            Err(HnsrTransportError::SnapshotRollback)
        ));
        let mut corrupt = exported.bytes;
        corrupt[20] ^= 1;
        assert!(matches!(
            decode_runtime_export(&corrupt, HnsrTransportRole::Requester),
            Err(HnsrTransportError::SnapshotChecksumMismatch)
        ));
    }
}
