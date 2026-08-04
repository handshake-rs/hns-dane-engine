//! Generation-bound requester runtime for private Handshake transports.
//!
//! This module owns requester lifecycle and restart-safe public target
//! metadata. Platform code still owns Brontide sockets and supplies an
//! [`ExperimentalExchange`]. No proxy, target, DNS-output, endpoint, or
//! rendezvous provider is implemented here.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;

use hns_p2p_wire::NetworkMagic;
use hns_transport::CancellationToken;

use super::{
    Admission, AuthenticatedPeer, AuthorityState, DirectTargetLocator, Engine, EngineError,
    ExperimentalExchange, ExperimentalPeerState, NegotiatedRegistry, Network, OdohRequester,
    P2pTransportError, PeerIdentity, PolicyError, RequesterLimits, ResolutionTransport,
    RuntimeStamp, VerifiedOdohTarget, resolution_transport_ready,
};

/// Private-transport status and persistence schema.
pub const PRIVATE_TRANSPORT_SCHEMA_VERSION: u16 = 1;
/// Maximum distinct target locators retained by one requester runtime.
pub const MAX_CACHED_ODOH_TARGETS: usize = 16;
/// Maximum canonical signed target record admitted to persistence.
pub const MAX_PERSISTED_ODOH_TARGET_RECORD_BYTES: usize = 16_384;
/// Maximum encoded ODoH target-cache blob.
pub const MAX_ODOH_TARGET_CACHE_BLOB_BYTES: usize = 264_224;

const TARGET_CACHE_MAGIC: &[u8; 8] = b"HNSODC1\0";
const MAX_TARGET_LOCATOR_BYTES: usize = 64;

/// Lifecycle of the requester-only ODoH runtime.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OdohRequesterState {
    /// Runtime is current but lacks an authenticated proxy or current target.
    AwaitingPrerequisites = 0,
    /// An authenticated proxy and at least one current signed target exist.
    Ready = 1,
    /// Runtime was explicitly or implicitly revoked and cannot recover.
    Revoked = 2,
}

/// Closed reason why a requester runtime can no longer admit work.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateTransportRevocationReason {
    /// Trusted platform code explicitly revoked the runtime.
    Explicit = 1,
    /// Engine process/session identity changed.
    RuntimeSessionChanged = 2,
    /// Engine generation changed.
    RuntimeGenerationChanged = 3,
    /// Engine policy generation changed.
    PolicyGenerationChanged = 4,
    /// A degradation or revocation invalidated the admission stamp.
    AdmissionInvalidated = 5,
    /// Engine authority no longer admits transport work.
    AuthorityUnavailable = 6,
    /// ODoH requester policy no longer admits the path.
    PolicyDisabled = 7,
    /// Handshake network identity changed.
    NetworkChanged = 8,
}

/// Immutable engine epoch retained by a private requester runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateTransportBinding {
    stamp: RuntimeStamp,
    admission: Admission,
    network: Network,
    network_magic: u32,
}

impl PrivateTransportBinding {
    /// Runtime process/session bytes.
    #[must_use]
    pub const fn runtime_session(self) -> [u8; 16] {
        self.stamp.session()
    }

    /// Runtime generation at requester creation or restore.
    #[must_use]
    pub const fn runtime_generation(self) -> u64 {
        self.stamp.generation()
    }

    /// Admission event retained across unrelated later engine work.
    #[must_use]
    pub const fn admission_event(self) -> u64 {
        self.stamp.event_sequence()
    }

    /// Policy generation that admitted the requester.
    #[must_use]
    pub const fn policy_generation(self) -> u64 {
        self.admission.policy_generation
    }

    /// Handshake network selected by the engine.
    #[must_use]
    pub const fn network(self) -> Network {
        self.network
    }

    /// Canonical Handshake P2P magic for the selected network.
    #[must_use]
    pub const fn network_magic(self) -> u32 {
        self.network_magic
    }
}

/// Complete bounded requester status for native adapters and diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OdohRequesterStatus {
    /// Status schema version.
    pub schema_version: u16,
    /// Exact engine binding.
    pub binding: PrivateTransportBinding,
    /// Current lifecycle state.
    pub state: OdohRequesterState,
    /// Terminal reason when `state` is revoked.
    pub revocation_reason: Option<PrivateTransportRevocationReason>,
    /// Exact Brontide-authenticated proxy key, if bound.
    pub proxy_identity: Option<[u8; 33]>,
    /// Exact negotiated registry fingerprint, or zero before proxy binding.
    pub registry_fingerprint: [u8; 32],
    /// Exact negotiated registry version, or zero before proxy binding.
    pub registry_version: u16,
    /// Negotiated remote request concurrency, or zero before proxy binding.
    pub maximum_live_requests: u16,
    /// Number of locator anti-rollback slots retained.
    pub target_slots: u16,
    /// Number of unexpired signed targets currently selectable.
    pub current_targets: u16,
    /// Earliest current target expiry, or zero when none exist.
    pub earliest_target_expiry: u64,
    /// Local protocol prerequisites are ready; platform adapter availability is separate.
    pub requester_ready: bool,
    /// ODoH proxy provider availability; always false in this runtime.
    pub proxy_provider_available: bool,
    /// ODoH target provider availability; always false in this runtime.
    pub target_provider_available: bool,
}

#[derive(Debug)]
struct CachedOdohTarget {
    verified: VerifiedOdohTarget,
    configuration_index: u16,
    signed_record: Vec<u8>,
}

#[derive(Debug)]
struct TargetSlot {
    locator: DirectTargetLocator,
    highest_sequence: u64,
    current: Option<CachedOdohTarget>,
}

#[derive(Debug, Default)]
struct OdohTargetCache {
    slots: BTreeMap<Vec<u8>, TargetSlot>,
}

impl OdohTargetCache {
    fn install(
        &mut self,
        locator: DirectTargetLocator,
        signed_record: &[u8],
        configuration_index: usize,
        network_magic: u32,
        now: u64,
        allow_private: bool,
    ) -> Result<[u8; 32], PrivateTransportError> {
        if signed_record.is_empty()
            || signed_record.len() > MAX_PERSISTED_ODOH_TARGET_RECORD_BYTES
        {
            return Err(PrivateTransportError::InvalidTargetRecordLength);
        }
        let configuration_index = u16::try_from(configuration_index)
            .map_err(|_| PrivateTransportError::InvalidConfigurationIndex)?;
        let verified = VerifiedOdohTarget::decode(
            signed_record,
            &locator,
            network_magic,
            now,
            allow_private,
            usize::from(configuration_index),
        )
        .map_err(PrivateTransportError::Transport)?;
        let record_id = verified.record_id();
        let locator_key = locator.encode();
        if locator_key.is_empty() || locator_key.len() > MAX_TARGET_LOCATOR_BYTES {
            return Err(PrivateTransportError::InvalidTargetLocator);
        }
        if let Some(slot) = self.slots.get_mut(&locator_key) {
            if verified.sequence() < slot.highest_sequence {
                return Err(PrivateTransportError::TargetSequenceRollback);
            }
            if verified.sequence() == slot.highest_sequence {
                if slot.current.as_ref().is_some_and(|current| {
                    current.verified.record_id() == verified.record_id()
                        && current.configuration_index == configuration_index
                }) {
                    return Ok(record_id);
                }
                return Err(PrivateTransportError::TargetSequenceConflict);
            }
            slot.highest_sequence = verified.sequence();
            slot.current = Some(CachedOdohTarget {
                verified,
                configuration_index,
                signed_record: signed_record.to_vec(),
            });
        } else {
            if self.slots.len() == MAX_CACHED_ODOH_TARGETS {
                return Err(PrivateTransportError::TargetCacheFull);
            }
            let sequence = verified.sequence();
            self.slots.insert(
                locator_key,
                TargetSlot {
                    locator,
                    highest_sequence: sequence,
                    current: Some(CachedOdohTarget {
                        verified,
                        configuration_index,
                        signed_record: signed_record.to_vec(),
                    }),
                },
            );
        }
        Ok(record_id)
    }

    fn prune(&mut self, now: u64) {
        for slot in self.slots.values_mut() {
            if slot
                .current
                .as_ref()
                .is_some_and(|target| now >= target.verified.expires_at())
            {
                slot.current = None;
            }
        }
    }

    fn target(&self, record_id: [u8; 32]) -> Result<&VerifiedOdohTarget, PrivateTransportError> {
        self.slots
            .values()
            .filter_map(|slot| slot.current.as_ref())
            .find(|target| target.verified.record_id() == record_id)
            .map(|target| &target.verified)
            .ok_or(PrivateTransportError::TargetUnavailable)
    }

    fn current_count(&self) -> usize {
        self.slots
            .values()
            .filter(|slot| slot.current.is_some())
            .count()
    }

    fn earliest_expiry(&self) -> u64 {
        self.slots
            .values()
            .filter_map(|slot| slot.current.as_ref())
            .map(|target| target.verified.expires_at())
            .min()
            .unwrap_or(0)
    }

    fn encode(&self, network_magic: u32, allow_private: bool) -> Result<Vec<u8>, PrivateTransportError> {
        let count = u16::try_from(self.slots.len())
            .map_err(|_| PrivateTransportError::TargetCacheFull)?;
        let mut output = Vec::new();
        output.extend_from_slice(TARGET_CACHE_MAGIC);
        output.extend_from_slice(&PRIVATE_TRANSPORT_SCHEMA_VERSION.to_le_bytes());
        output.extend_from_slice(&network_magic.to_le_bytes());
        output.push(u8::from(allow_private));
        output.extend_from_slice(&count.to_le_bytes());
        for (locator_key, slot) in &self.slots {
            let locator = slot.locator.encode();
            if &locator != locator_key {
                return Err(PrivateTransportError::InvalidTargetLocator);
            }
            let locator_length = u16::try_from(locator.len())
                .map_err(|_| PrivateTransportError::InvalidTargetLocator)?;
            output.extend_from_slice(&locator_length.to_le_bytes());
            output.extend_from_slice(&locator);
            output.extend_from_slice(&slot.highest_sequence.to_le_bytes());
            if let Some(target) = &slot.current {
                let record_length = u16::try_from(target.signed_record.len())
                    .map_err(|_| PrivateTransportError::InvalidTargetRecordLength)?;
                output.push(1);
                output.extend_from_slice(&target.configuration_index.to_le_bytes());
                output.extend_from_slice(&target.verified.expires_at().to_le_bytes());
                output.extend_from_slice(&record_length.to_le_bytes());
                output.extend_from_slice(&target.signed_record);
            } else {
                output.push(0);
            }
        }
        if output.len().saturating_add(4) > MAX_ODOH_TARGET_CACHE_BLOB_BYTES {
            return Err(PrivateTransportError::TargetCacheBlobTooLarge);
        }
        let checksum = crc32(&output);
        output.extend_from_slice(&checksum.to_le_bytes());
        Ok(output)
    }

    fn decode(
        input: &[u8],
        expected_network_magic: u32,
        allow_private: bool,
        now: u64,
    ) -> Result<Self, PrivateTransportError> {
        if input.len() < 21 || input.len() > MAX_ODOH_TARGET_CACHE_BLOB_BYTES {
            return Err(PrivateTransportError::InvalidTargetCacheBlob);
        }
        let payload_length = input
            .len()
            .checked_sub(4)
            .ok_or(PrivateTransportError::InvalidTargetCacheBlob)?;
        let payload = input
            .get(..payload_length)
            .ok_or(PrivateTransportError::InvalidTargetCacheBlob)?;
        let checksum_bytes: [u8; 4] = input
            .get(payload_length..)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(PrivateTransportError::InvalidTargetCacheBlob)?;
        if crc32(payload) != u32::from_le_bytes(checksum_bytes) {
            return Err(PrivateTransportError::TargetCacheChecksumMismatch);
        }
        let mut decoder = CacheDecoder::new(payload);
        if decoder.take(8)? != TARGET_CACHE_MAGIC {
            return Err(PrivateTransportError::InvalidTargetCacheBlob);
        }
        if decoder.u16()? != PRIVATE_TRANSPORT_SCHEMA_VERSION {
            return Err(PrivateTransportError::UnsupportedTargetCacheSchema);
        }
        if decoder.u32()? != expected_network_magic {
            return Err(PrivateTransportError::TargetCacheNetworkMismatch);
        }
        if decoder.u8()? != u8::from(allow_private) {
            return Err(PrivateTransportError::TargetCacheAddressPolicyMismatch);
        }
        let count = usize::from(decoder.u16()?);
        if count > MAX_CACHED_ODOH_TARGETS {
            return Err(PrivateTransportError::TargetCacheFull);
        }
        let mut cache = Self::default();
        let mut previous_locator: Option<Vec<u8>> = None;
        for _ in 0..count {
            let locator_length = usize::from(decoder.u16()?);
            if locator_length == 0 || locator_length > MAX_TARGET_LOCATOR_BYTES {
                return Err(PrivateTransportError::InvalidTargetLocator);
            }
            let locator_key = decoder.take(locator_length)?.to_vec();
            if previous_locator
                .as_ref()
                .is_some_and(|previous| previous >= &locator_key)
            {
                return Err(PrivateTransportError::NonCanonicalTargetCache);
            }
            previous_locator = Some(locator_key.clone());
            let locator = DirectTargetLocator::decode(&locator_key, allow_private)
                .map_err(|_| PrivateTransportError::InvalidTargetLocator)?;
            let highest_sequence = decoder.u64()?;
            if highest_sequence == 0 {
                return Err(PrivateTransportError::InvalidTargetSequence);
            }
            let current = match decoder.u8()? {
                0 => None,
                1 => {
                    let configuration_index = decoder.u16()?;
                    let persisted_expiry = decoder.u64()?;
                    let record_length = usize::from(decoder.u16()?);
                    if record_length == 0 || record_length > MAX_PERSISTED_ODOH_TARGET_RECORD_BYTES {
                        return Err(PrivateTransportError::InvalidTargetRecordLength);
                    }
                    let signed_record = decoder.take(record_length)?.to_vec();
                    let verification_time = now.min(persisted_expiry.saturating_sub(1));
                    let verified = VerifiedOdohTarget::decode(
                        &signed_record,
                        &locator,
                        expected_network_magic,
                        verification_time,
                        allow_private,
                        usize::from(configuration_index),
                    )
                    .map_err(PrivateTransportError::Transport)?;
                    if persisted_expiry == 0
                        || verified.expires_at() != persisted_expiry
                        || verified.sequence() != highest_sequence
                    {
                        return Err(PrivateTransportError::TargetSequenceConflict);
                    }
                    (now < persisted_expiry).then_some(CachedOdohTarget {
                        verified,
                        configuration_index,
                        signed_record,
                    })
                }
                _ => return Err(PrivateTransportError::InvalidTargetCacheBlob),
            };
            cache.slots.insert(
                locator_key,
                TargetSlot {
                    locator,
                    highest_sequence,
                    current,
                },
            );
        }
        decoder.finish()?;
        Ok(cache)
    }
}

/// Non-cloneable, requester-only HIP-77 runtime bound to one engine epoch.
#[derive(Debug)]
pub struct OdohRequesterRuntime {
    binding: PrivateTransportBinding,
    requester: OdohRequester,
    proxy: Option<AuthenticatedPeer>,
    targets: OdohTargetCache,
    allow_private_targets: bool,
    revocation_reason: Option<PrivateTransportRevocationReason>,
}

impl OdohRequesterRuntime {
    /// Exact engine epoch that admitted this runtime.
    #[must_use]
    pub const fn binding(&self) -> PrivateTransportBinding {
        self.binding
    }

    /// Bind one exact established Brontide proxy and negotiated registry.
    pub fn bind_proxy(
        &mut self,
        engine: &Engine,
        identity: PeerIdentity,
        peer: ExperimentalPeerState,
        registry: NegotiatedRegistry,
    ) -> Result<(), PrivateTransportError> {
        self.ensure_current(engine)?;
        let proxy = AuthenticatedPeer::bind(identity, peer, registry)
            .map_err(PrivateTransportError::Transport)?;
        self.proxy = Some(proxy);
        Ok(())
    }

    /// Verify and cache one target-signed configuration record.
    pub fn install_target(
        &mut self,
        engine: &Engine,
        locator: DirectTargetLocator,
        signed_record: &[u8],
        configuration_index: usize,
        now: u64,
    ) -> Result<[u8; 32], PrivateTransportError> {
        self.ensure_current(engine)?;
        self.targets.prune(now);
        self.targets.install(
            locator,
            signed_record,
            configuration_index,
            self.binding.network_magic,
            now,
            self.allow_private_targets,
        )
    }

    /// Encode the canonical checksummed target-cache restart representation.
    ///
    /// Only public signed configuration material and per-locator sequence
    /// high-water marks are persisted. Proxy sessions, request IDs, HPKE query
    /// contexts, and in-flight work are never serialized.
    pub fn export_target_cache(&mut self, now: u64) -> Result<Vec<u8>, PrivateTransportError> {
        self.targets.prune(now);
        self.targets
            .encode(self.binding.network_magic, self.allow_private_targets)
    }

    /// Read status, terminally revoking this instance if its engine epoch ended.
    pub fn status(
        &mut self,
        engine: &Engine,
        now: u64,
    ) -> Result<OdohRequesterStatus, PrivateTransportError> {
        if self.revocation_reason.is_none() {
            if let Err(error) = engine.validate_private_transport_binding(self.binding) {
                self.revoke_for_error(&error);
                if matches!(error, PrivateTransportError::Engine(_)) {
                    return Err(error);
                }
            }
        }
        self.targets.prune(now);
        let (proxy_identity, registry_fingerprint, registry_version, maximum_live_requests) = self
            .proxy
            .as_ref()
            .map_or((None, [0; 32], 0, 0), |proxy| {
                (
                    Some(proxy.identity().as_bytes()),
                    proxy.registry_fingerprint(),
                    proxy.registry_version(),
                    proxy.maximum_live_requests(),
                )
            });
        let target_slots = u16::try_from(self.targets.slots.len()).unwrap_or(u16::MAX);
        let current_targets = u16::try_from(self.targets.current_count()).unwrap_or(u16::MAX);
        let ready = self.revocation_reason.is_none()
            && self.proxy.is_some()
            && current_targets != 0;
        Ok(OdohRequesterStatus {
            schema_version: PRIVATE_TRANSPORT_SCHEMA_VERSION,
            binding: self.binding,
            state: if self.revocation_reason.is_some() {
                OdohRequesterState::Revoked
            } else if ready {
                OdohRequesterState::Ready
            } else {
                OdohRequesterState::AwaitingPrerequisites
            },
            revocation_reason: self.revocation_reason,
            proxy_identity,
            registry_fingerprint,
            registry_version,
            maximum_live_requests,
            target_slots,
            current_targets,
            earliest_target_expiry: self.targets.earliest_expiry(),
            requester_ready: ready,
            proxy_provider_available: false,
            target_provider_available: false,
        })
    }

    /// Execute one exact generation-bound HIP-77 requester exchange.
    ///
    /// All canonical peer, registry, deadline, request correlation, and HPKE
    /// failures remain available through [`PrivateTransportError::Transport`].
    /// The engine binding is checked both before and after adapter I/O; stale
    /// bytes are never returned even if policy changes during the call.
    #[allow(clippy::too_many_arguments, reason = "adapter, target, query, cancellation, and clock are independent trust inputs")]
    pub fn exchange<A: ExperimentalExchange>(
        &mut self,
        engine: &Engine,
        adapter: &mut A,
        target_record_id: [u8; 32],
        query: &hns_dns_wire::Query,
        cancellation: &CancellationToken,
        now: u64,
        deadline: u64,
    ) -> Result<super::AdmittedDnsResponse, PrivateTransportError> {
        self.ensure_current(engine)?;
        self.targets.prune(now);
        let target = self.targets.target(target_record_id)?;
        let proxy = self
            .proxy
            .as_mut()
            .ok_or(PrivateTransportError::ProxyUnavailable)?;
        let result = self
            .requester
            .exchange(adapter, proxy, target, query, cancellation, now, deadline);
        if let Err(error) = engine.validate_private_transport_binding(self.binding) {
            self.revoke_for_error(&error);
            return Err(error);
        }
        result.map_err(PrivateTransportError::Transport)
    }

    /// Terminally revoke and erase all live proxy and target state.
    pub fn revoke(&mut self) {
        self.revocation_reason = Some(PrivateTransportRevocationReason::Explicit);
        self.proxy = None;
        self.targets = OdohTargetCache::default();
    }

    fn ensure_current(&mut self, engine: &Engine) -> Result<(), PrivateTransportError> {
        if let Some(reason) = self.revocation_reason {
            return Err(PrivateTransportError::BindingRevoked(reason));
        }
        if let Err(error) = engine.validate_private_transport_binding(self.binding) {
            self.revoke_for_error(&error);
            return Err(error);
        }
        Ok(())
    }

    fn revoke_for_error(&mut self, error: &PrivateTransportError) {
        let reason = match error {
            PrivateTransportError::RuntimeSessionChanged => {
                Some(PrivateTransportRevocationReason::RuntimeSessionChanged)
            }
            PrivateTransportError::RuntimeGenerationChanged => {
                Some(PrivateTransportRevocationReason::RuntimeGenerationChanged)
            }
            PrivateTransportError::PolicyGenerationChanged => {
                Some(PrivateTransportRevocationReason::PolicyGenerationChanged)
            }
            PrivateTransportError::AdmissionInvalidated => {
                Some(PrivateTransportRevocationReason::AdmissionInvalidated)
            }
            PrivateTransportError::AuthorityUnavailable => {
                Some(PrivateTransportRevocationReason::AuthorityUnavailable)
            }
            PrivateTransportError::Policy(PolicyError::TransportDisabled) => {
                Some(PrivateTransportRevocationReason::PolicyDisabled)
            }
            PrivateTransportError::NetworkChanged => {
                Some(PrivateTransportRevocationReason::NetworkChanged)
            }
            _ => None,
        };
        if let Some(reason) = reason {
            self.revocation_reason = Some(reason);
            self.proxy = None;
        }
    }
}

impl Engine {
    /// Start one requester-only ODoH runtime under a fresh engine admission.
    pub fn start_odoh_requester(
        &self,
        first_request_id: NonZeroU64,
        limits: RequesterLimits,
        allow_private_targets: bool,
    ) -> Result<OdohRequesterRuntime, PrivateTransportError> {
        let binding = self.mint_private_transport_binding(allow_private_targets)?;
        let requester = OdohRequester::new(first_request_id, limits)
            .map_err(PrivateTransportError::Transport)?;
        Ok(OdohRequesterRuntime {
            binding,
            requester,
            proxy: None,
            targets: OdohTargetCache::default(),
            allow_private_targets,
            revocation_reason: None,
        })
    }

    /// Restore signed ODoH target metadata under a fresh engine admission.
    ///
    /// A new unpredictable request-ID space and a newly authenticated proxy
    /// are mandatory after every process start; neither is accepted from the
    /// persistence blob.
    pub fn restore_odoh_requester(
        &self,
        first_request_id: NonZeroU64,
        limits: RequesterLimits,
        allow_private_targets: bool,
        target_cache: &[u8],
        now: u64,
    ) -> Result<OdohRequesterRuntime, PrivateTransportError> {
        let binding = self.mint_private_transport_binding(allow_private_targets)?;
        let requester = OdohRequester::new(first_request_id, limits)
            .map_err(PrivateTransportError::Transport)?;
        let targets = OdohTargetCache::decode(
            target_cache,
            binding.network_magic,
            allow_private_targets,
            now,
        )?;
        Ok(OdohRequesterRuntime {
            binding,
            requester,
            proxy: None,
            targets,
            allow_private_targets,
            revocation_reason: None,
        })
    }

    fn mint_private_transport_binding(
        &self,
        allow_private_targets: bool,
    ) -> Result<PrivateTransportBinding, PrivateTransportError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| PrivateTransportError::Engine(EngineError::LockPoisoned))?;
        if !resolution_transport_ready(state.runtime.authority_state()) {
            return Err(PrivateTransportError::AuthorityUnavailable);
        }
        if allow_private_targets && !matches!(state.network, Network::Regtest | Network::Simnet) {
            return Err(PrivateTransportError::PrivateTargetsForbidden);
        }
        let admission = state
            .policy
            .admit(ResolutionTransport::HandshakeP2pOdoh)
            .map_err(PrivateTransportError::Policy)?;
        let stamp = state
            .runtime
            .admit_event()
            .map_err(|error| PrivateTransportError::Engine(super::map_runtime_error(error)))?;
        Ok(PrivateTransportBinding {
            stamp,
            admission,
            network: state.network,
            network_magic: network_magic(state.network),
        })
    }

    fn validate_private_transport_binding(
        &self,
        binding: PrivateTransportBinding,
    ) -> Result<(), PrivateTransportError> {
        let state = self
            .state
            .read()
            .map_err(|_| PrivateTransportError::Engine(EngineError::LockPoisoned))?;
        let runtime = state.runtime.snapshot();
        if state.network != binding.network || network_magic(state.network) != binding.network_magic {
            return Err(PrivateTransportError::NetworkChanged);
        }
        if runtime.session_bytes() != binding.stamp.session() {
            return Err(PrivateTransportError::RuntimeSessionChanged);
        }
        if runtime.generation() != binding.stamp.generation() {
            return Err(PrivateTransportError::RuntimeGenerationChanged);
        }
        if state.policy.snapshot().generation() != binding.admission.policy_generation {
            return Err(PrivateTransportError::PolicyGenerationChanged);
        }
        if !resolution_transport_ready(runtime.authority_state()) {
            return Err(PrivateTransportError::AuthorityUnavailable);
        }
        if !state.runtime.admits(binding.stamp) {
            return Err(PrivateTransportError::AdmissionInvalidated);
        }
        state
            .policy
            .accept_completion(binding.admission)
            .map_err(PrivateTransportError::Policy)
    }
}

const fn network_magic(network: Network) -> u32 {
    match network {
        Network::Mainnet => NetworkMagic::Mainnet.as_u32(),
        Network::Testnet => NetworkMagic::Testnet.as_u32(),
        Network::Regtest => NetworkMagic::Regtest.as_u32(),
        Network::Simnet => NetworkMagic::Simnet.as_u32(),
    }
}

struct CacheDecoder<'input> {
    input: &'input [u8],
    position: usize,
}

impl<'input> CacheDecoder<'input> {
    const fn new(input: &'input [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'input [u8], PrivateTransportError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(PrivateTransportError::InvalidTargetCacheBlob)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(PrivateTransportError::InvalidTargetCacheBlob)?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, PrivateTransportError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(PrivateTransportError::InvalidTargetCacheBlob)
    }

    fn u16(&mut self) -> Result<u16, PrivateTransportError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| PrivateTransportError::InvalidTargetCacheBlob)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, PrivateTransportError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| PrivateTransportError::InvalidTargetCacheBlob)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, PrivateTransportError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| PrivateTransportError::InvalidTargetCacheBlob)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn finish(self) -> Result<(), PrivateTransportError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(PrivateTransportError::InvalidTargetCacheBlob)
        }
    }
}

fn crc32(input: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in input {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// ODoH requester lifecycle, persistence, or canonical transport failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum PrivateTransportError {
    /// Internal engine failure.
    Engine(EngineError),
    /// Canonical P2P/ODoH requester failure, preserved without flattening.
    Transport(P2pTransportError),
    /// Typed engine policy failure.
    Policy(PolicyError),
    /// This instance was already terminally revoked.
    BindingRevoked(PrivateTransportRevocationReason),
    /// Engine process/session changed.
    RuntimeSessionChanged,
    /// Engine runtime generation changed.
    RuntimeGenerationChanged,
    /// Engine policy generation changed.
    PolicyGenerationChanged,
    /// A security-invalidating transition superseded the admission stamp.
    AdmissionInvalidated,
    /// Authority state cannot admit transport work.
    AuthorityUnavailable,
    /// Handshake network identity changed.
    NetworkChanged,
    /// Private target addresses are restricted to regtest and simnet.
    PrivateTargetsForbidden,
    /// No authenticated proxy session is bound.
    ProxyUnavailable,
    /// Requested current target record is absent or expired.
    TargetUnavailable,
    /// Signed target record is empty or exceeds its hard bound.
    InvalidTargetRecordLength,
    /// Selected configuration index cannot be represented canonically.
    InvalidConfigurationIndex,
    /// Target locator encoding is empty, oversized, or noncanonical.
    InvalidTargetLocator,
    /// Target locator cache reached its hard capacity.
    TargetCacheFull,
    /// A target record sequence moved backwards.
    TargetSequenceRollback,
    /// Equal target sequence carried different signed data or selection.
    TargetSequenceConflict,
    /// Target anti-rollback high-water is zero.
    InvalidTargetSequence,
    /// Persistence blob length or framing is invalid.
    InvalidTargetCacheBlob,
    /// Persistence blob exceeds its hard bound.
    TargetCacheBlobTooLarge,
    /// Persistence checksum differs.
    TargetCacheChecksumMismatch,
    /// Persistence schema is not supported.
    UnsupportedTargetCacheSchema,
    /// Persistence belongs to another Handshake network.
    TargetCacheNetworkMismatch,
    /// Persistence was created under another private-address policy.
    TargetCacheAddressPolicyMismatch,
    /// Persistence entries are not strictly canonical and unique.
    NonCanonicalTargetCache,
}

impl fmt::Display for PrivateTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(error) => write!(formatter, "private transport engine failed: {error}"),
            Self::Transport(error) => write!(formatter, "private transport request failed: {error}"),
            Self::Policy(error) => write!(formatter, "private transport policy failed: {error}"),
            Self::BindingRevoked(reason) => write!(formatter, "private transport runtime was revoked: {reason:?}"),
            Self::RuntimeSessionChanged => formatter.write_str("private transport runtime session changed"),
            Self::RuntimeGenerationChanged => formatter.write_str("private transport runtime generation changed"),
            Self::PolicyGenerationChanged => formatter.write_str("private transport policy generation changed"),
            Self::AdmissionInvalidated => formatter.write_str("private transport admission was invalidated"),
            Self::AuthorityUnavailable => formatter.write_str("private transport authority is unavailable"),
            Self::NetworkChanged => formatter.write_str("private transport network changed"),
            Self::PrivateTargetsForbidden => formatter.write_str("private ODoH targets require regtest or simnet"),
            Self::ProxyUnavailable => formatter.write_str("authenticated ODoH proxy is unavailable"),
            Self::TargetUnavailable => formatter.write_str("current signed ODoH target is unavailable"),
            Self::InvalidTargetRecordLength => formatter.write_str("signed ODoH target record length is invalid"),
            Self::InvalidConfigurationIndex => formatter.write_str("ODoH configuration index is invalid"),
            Self::InvalidTargetLocator => formatter.write_str("ODoH target locator is invalid"),
            Self::TargetCacheFull => formatter.write_str("ODoH target cache is full"),
            Self::TargetSequenceRollback => formatter.write_str("ODoH target sequence rollback"),
            Self::TargetSequenceConflict => formatter.write_str("ODoH target sequence conflicts with cached state"),
            Self::InvalidTargetSequence => formatter.write_str("ODoH target sequence is invalid"),
            Self::InvalidTargetCacheBlob => formatter.write_str("ODoH target-cache blob is invalid"),
            Self::TargetCacheBlobTooLarge => formatter.write_str("ODoH target-cache blob exceeds its bound"),
            Self::TargetCacheChecksumMismatch => formatter.write_str("ODoH target-cache checksum mismatch"),
            Self::UnsupportedTargetCacheSchema => formatter.write_str("ODoH target-cache schema is unsupported"),
            Self::TargetCacheNetworkMismatch => formatter.write_str("ODoH target-cache network mismatch"),
            Self::TargetCacheAddressPolicyMismatch => formatter.write_str("ODoH target-cache address policy mismatch"),
            Self::NonCanonicalTargetCache => formatter.write_str("ODoH target-cache entries are noncanonical"),
        }
    }
}

impl Error for PrivateTransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Engine(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Policy(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid deterministic engine fixtures"
)]
mod tests {
    use super::*;
    use crate::{EngineConfig, PolicySnapshot, RuntimeSessionId};

    fn ready_engine(session: u8, network: Network) -> Engine {
        let engine = Engine::new(EngineConfig::new(
            RuntimeSessionId::new([session; 16]).unwrap(),
            network,
            PolicySnapshot::default(),
        ));
        for state in [
            AuthorityState::LocalStateOpened,
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
        ] {
            engine.advance_authority_state(state).unwrap();
        }
        engine
    }

    #[test]
    fn production_followup_odoh_binding_survives_unrelated_events_and_revokes_on_degrade() {
        let engine = ready_engine(41, Network::Regtest);
        let mut runtime = engine
            .start_odoh_requester(
                NonZeroU64::new(7).unwrap(),
                RequesterLimits::default(),
                true,
            )
            .unwrap();
        engine
            .advance_authority_state(AuthorityState::DnssecVerified)
            .unwrap();
        let status = runtime.status(&engine, 1_700_000_000).unwrap();
        assert_eq!(status.state, OdohRequesterState::AwaitingPrerequisites);
        assert_eq!(status.revocation_reason, None);
        assert!(!status.proxy_provider_available);
        assert!(!status.target_provider_available);

        engine
            .advance_authority_state(AuthorityState::Degraded)
            .unwrap();
        let status = runtime.status(&engine, 1_700_000_001).unwrap();
        assert_eq!(status.state, OdohRequesterState::Revoked);
        assert_eq!(
            status.revocation_reason,
            Some(PrivateTransportRevocationReason::AuthorityUnavailable)
        );
        assert!(matches!(
            runtime.ensure_current(&engine),
            Err(PrivateTransportError::BindingRevoked(
                PrivateTransportRevocationReason::AuthorityUnavailable
            ))
        ));
    }

    #[test]
    fn production_followup_odoh_cache_restart_blob_is_bounded_and_fail_closed() {
        let engine = ready_engine(42, Network::Regtest);
        let mut runtime = engine
            .start_odoh_requester(
                NonZeroU64::new(11).unwrap(),
                RequesterLimits::default(),
                true,
            )
            .unwrap();
        let encoded = runtime.export_target_cache(1_700_000_000).unwrap();
        assert!(encoded.len() <= MAX_ODOH_TARGET_CACHE_BLOB_BYTES);
        let mut restored = engine
            .restore_odoh_requester(
                NonZeroU64::new(12).unwrap(),
                RequesterLimits::default(),
                true,
                &encoded,
                1_700_000_000,
            )
            .unwrap();
        assert_ne!(
            restored.binding().admission_event(),
            runtime.binding().admission_event()
        );
        assert_eq!(
            restored.status(&engine, 1_700_000_000).unwrap().current_targets,
            0
        );

        let mut corrupted = encoded;
        if let Some(byte) = corrupted.get_mut(8) {
            *byte ^= 1;
        }
        assert!(matches!(
            engine.restore_odoh_requester(
                NonZeroU64::new(13).unwrap(),
                RequesterLimits::default(),
                true,
                &corrupted,
                1_700_000_000,
            ),
            Err(PrivateTransportError::TargetCacheChecksumMismatch)
        ));
    }

    #[test]
    fn production_followup_private_targets_are_never_permitted_on_public_networks() {
        let engine = ready_engine(43, Network::Mainnet);
        assert!(matches!(
            engine.start_odoh_requester(
                NonZeroU64::new(1).unwrap(),
                RequesterLimits::default(),
                true,
            ),
            Err(PrivateTransportError::PrivateTargetsForbidden)
        ));
    }
}
