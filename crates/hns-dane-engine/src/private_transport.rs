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

use hns_header_consensus::Network as ConsensusNetwork;
use hns_p2p_wire::NetworkMagic;
use hns_transport::CancellationToken;

use super::{
    AdapterFailure, Admission, AuthenticatedPeer, AuthorityState, BrowserRuntime,
    DirectTargetLocator, Engine, EngineError, ExperimentalExchange, ExperimentalNetwork,
    ExperimentalPeerState, ExperimentalRequest, ExperimentalResponse, NegotiatedRegistry, Network,
    OdohRequester, P2pTransportError, PeerIdentity, PolicyController, PolicyError, PolicySnapshot,
    RequesterLimits, ResolutionTransport, RuntimeStamp, VerifiedOdohTarget, WireProfile,
    resolution_transport_ready,
};

/// Private-transport requester status schema.
pub const PRIVATE_TRANSPORT_SCHEMA_VERSION: u16 = 4;
/// Maximum distinct target locators retained by one requester runtime.
pub const MAX_CACHED_ODOH_TARGETS: usize = 16;
/// Maximum canonical signed target record admitted to persistence.
pub const MAX_PERSISTED_ODOH_TARGET_RECORD_BYTES: usize = 16_384;
/// Maximum encoded ODoH target-cache blob.
pub const MAX_ODOH_TARGET_CACHE_BLOB_BYTES: usize = 264_224;

const TARGET_CACHE_MAGIC: &[u8; 8] = b"HNSODC1\0";
const ODOH_TARGET_CACHE_SCHEMA_VERSION: u16 = 3;
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
    policy_wire_profile: WireProfile,
}

/// Borrowed private-transport authority over the platform's one browser runtime.
///
/// Chromium and mobile adapters that already own [`BrowserRuntime`] use this
/// view instead of constructing a second [`Engine`]. The caller must supply
/// its current persisted policy snapshot every time it creates a view; using a
/// stale snapshot would violate the trusted platform boundary.
pub struct PrivateTransportAuthority<'runtime> {
    pub(crate) runtime: &'runtime mut BrowserRuntime,
    pub(crate) network: Network,
    pub(crate) policy: PolicySnapshot,
}

impl<'runtime> PrivateTransportAuthority<'runtime> {
    /// Borrow the platform's canonical runtime with its current network and policy.
    #[must_use]
    pub const fn new(
        runtime: &'runtime mut BrowserRuntime,
        network: Network,
        policy: PolicySnapshot,
    ) -> Self {
        Self {
            runtime,
            network,
            policy,
        }
    }

    /// Start a requester-only ODoH runtime without duplicating browser authority.
    pub fn start_odoh_requester(
        &mut self,
        first_request_id: NonZeroU64,
        limits: RequesterLimits,
        allow_private_targets: bool,
    ) -> Result<OdohRequesterRuntime, PrivateTransportError> {
        let binding = mint_private_transport_binding(
            self.runtime,
            self.network,
            self.policy,
            allow_private_targets,
        )?;
        start_odoh_requester(binding, first_request_id, limits, allow_private_targets)
    }

    /// Restore ODoH public target metadata under this canonical runtime.
    #[allow(
        clippy::too_many_arguments,
        reason = "request identity, limits, persistence guard, address policy, and time are independent trust inputs"
    )]
    pub fn restore_odoh_requester(
        &mut self,
        first_request_id: NonZeroU64,
        limits: RequesterLimits,
        allow_private_targets: bool,
        target_cache: &[u8],
        minimum_target_cache_generation: u64,
        now: u64,
    ) -> Result<OdohRequesterRuntime, PrivateTransportError> {
        let binding = mint_private_transport_binding(
            self.runtime,
            self.network,
            self.policy,
            allow_private_targets,
        )?;
        restore_odoh_requester(
            binding,
            first_request_id,
            limits,
            allow_private_targets,
            target_cache,
            minimum_target_cache_generation,
            now,
        )
    }
}

/// Current-authority validation seam shared by the engine facade and adapters.
pub trait PrivateTransportAuthorityContext: super::authority_sealed::Sealed {
    /// Validate one previously minted ODoH binding against current authority.
    fn validate_private_transport_binding(
        &self,
        binding: PrivateTransportBinding,
    ) -> Result<(), PrivateTransportError>;
}

impl super::authority_sealed::Sealed for PrivateTransportAuthority<'_> {}
impl super::authority_sealed::Sealed for Engine {}

impl PrivateTransportAuthorityContext for PrivateTransportAuthority<'_> {
    fn validate_private_transport_binding(
        &self,
        binding: PrivateTransportBinding,
    ) -> Result<(), PrivateTransportError> {
        validate_private_transport_binding(self.runtime, self.network, self.policy, binding)
    }
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

    /// Persisted policy profile from which a concrete Denuo V1 peer is resolved.
    #[must_use]
    pub const fn policy_wire_profile(self) -> WireProfile {
        self.policy_wire_profile
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
    /// Exact resolved peer profile, absent before proxy binding.
    pub resolved_wire_profile: Option<ExperimentalWireProfile>,
    /// Negotiated remote request concurrency, or zero before proxy binding.
    pub maximum_live_requests: u16,
    /// Number of locator anti-rollback slots retained.
    pub target_slots: u16,
    /// Number of unexpired signed targets currently selectable.
    pub current_targets: u16,
    /// Earliest current target expiry, or zero when none exist.
    pub earliest_target_expiry: u64,
    /// Greatest trusted caller/adapter time admitted by this runtime.
    pub trusted_time_high_water: u64,
    /// Monotonic durable target-cache generation.
    pub target_cache_generation: u64,
    /// Local protocol prerequisites are ready; platform adapter availability is separate.
    pub requester_ready: bool,
    /// ODoH proxy provider availability; always false in this runtime.
    pub proxy_provider_available: bool,
    /// ODoH target provider availability; always false in this runtime.
    pub target_provider_available: bool,
}

/// One exact target-cache snapshot and the caller-held anti-rollback floor it advances.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdohTargetCacheExport {
    /// Monotonic generation encoded in `bytes`.
    pub generation: u64,
    /// Checksummed canonical target-cache bytes.
    pub bytes: Vec<u8>,
}

/// Atomic result of one canonical GETCONFIG/CONFIG verification and install.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OdohTargetInstall {
    /// Target-signed record identity selected for future queries.
    pub record_id: [u8; 32],
    /// Durable cache generation after the atomic install.
    pub target_cache_generation: u64,
    /// Trusted adapter time after the complete CONFIG response was received.
    pub completed_at: u64,
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
    ) -> Result<([u8; 32], bool), PrivateTransportError> {
        if signed_record.is_empty() || signed_record.len() > MAX_PERSISTED_ODOH_TARGET_RECORD_BYTES
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
                    return Ok((record_id, false));
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
        Ok((record_id, true))
    }

    fn prune(&mut self, now: u64) -> bool {
        let mut changed = false;
        for slot in self.slots.values_mut() {
            if slot
                .current
                .as_ref()
                .is_some_and(|target| now >= target.verified.expires_at())
            {
                slot.current = None;
                changed = true;
            }
        }
        changed
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

    fn encode(
        &self,
        network_magic: u32,
        allow_private: bool,
        trusted_time_high_water: u64,
        generation: u64,
    ) -> Result<Vec<u8>, PrivateTransportError> {
        if generation == 0 {
            return Err(PrivateTransportError::InvalidTargetCacheGeneration);
        }
        let count =
            u16::try_from(self.slots.len()).map_err(|_| PrivateTransportError::TargetCacheFull)?;
        let mut output = Vec::new();
        output.extend_from_slice(TARGET_CACHE_MAGIC);
        output.extend_from_slice(&ODOH_TARGET_CACHE_SCHEMA_VERSION.to_le_bytes());
        output.extend_from_slice(&network_magic.to_le_bytes());
        output.push(u8::from(allow_private));
        output.extend_from_slice(&trusted_time_high_water.to_le_bytes());
        output.extend_from_slice(&generation.to_le_bytes());
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
    ) -> Result<(Self, u64, u64, bool), PrivateTransportError> {
        if input.len() < 37 || input.len() > MAX_ODOH_TARGET_CACHE_BLOB_BYTES {
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
        if decoder.u16()? != ODOH_TARGET_CACHE_SCHEMA_VERSION {
            return Err(PrivateTransportError::UnsupportedTargetCacheSchema);
        }
        if decoder.u32()? != expected_network_magic {
            return Err(PrivateTransportError::TargetCacheNetworkMismatch);
        }
        if decoder.u8()? != u8::from(allow_private) {
            return Err(PrivateTransportError::TargetCacheAddressPolicyMismatch);
        }
        let trusted_time_high_water = decoder.u64()?;
        if now < trusted_time_high_water {
            return Err(PrivateTransportError::TrustedClockRollback);
        }
        let generation = decoder.u64()?;
        if generation == 0 {
            return Err(PrivateTransportError::InvalidTargetCacheGeneration);
        }
        let count = usize::from(decoder.u16()?);
        if count > MAX_CACHED_ODOH_TARGETS {
            return Err(PrivateTransportError::TargetCacheFull);
        }
        let mut cache = Self::default();
        let mut pruned = false;
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
                    if record_length == 0 || record_length > MAX_PERSISTED_ODOH_TARGET_RECORD_BYTES
                    {
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
                    if now < persisted_expiry {
                        Some(CachedOdohTarget {
                            verified,
                            configuration_index,
                            signed_record,
                        })
                    } else {
                        pruned = true;
                        None
                    }
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
        Ok((cache, trusted_time_high_water, generation, pruned))
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
    trusted_time_high_water: u64,
    target_cache_generation: u64,
    revocation_reason: Option<PrivateTransportRevocationReason>,
}

struct CompletionTrackingExchange<'adapter, A> {
    adapter: &'adapter mut A,
    completed_at: Option<u64>,
}

impl<A: ExperimentalExchange> ExperimentalExchange for CompletionTrackingExchange<'_, A> {
    fn exchange(
        &mut self,
        request: ExperimentalRequest<'_>,
    ) -> Result<ExperimentalResponse, AdapterFailure> {
        let response = self.adapter.exchange(request)?;
        self.completed_at = Some(response.completed_at);
        Ok(response)
    }
}

impl OdohRequesterRuntime {
    /// Exact engine epoch that admitted this runtime.
    #[must_use]
    pub const fn binding(&self) -> PrivateTransportBinding {
        self.binding
    }

    /// Bind one exact established Brontide proxy and negotiated registry.
    pub fn bind_proxy<C: PrivateTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        identity: PeerIdentity,
        peer: ExperimentalPeerState,
        registry: NegotiatedRegistry,
    ) -> Result<(), PrivateTransportError> {
        self.ensure_current(authority)?;
        let mut proxy = AuthenticatedPeer::bind(identity, peer, registry)
            .map_err(PrivateTransportError::Transport)?;
        proxy
            .admit_canonical_odoh_proxy(
                experimental_network(self.binding.network),
                canonical_genesis_hash(self.binding.network),
                resolved_odoh_profile(self.binding.policy_wire_profile)?,
            )
            .map_err(PrivateTransportError::Transport)?;
        self.proxy = Some(proxy);
        Ok(())
    }

    /// Verify and cache one target-signed configuration record.
    pub fn install_target<C: PrivateTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        locator: DirectTargetLocator,
        signed_record: &[u8],
        configuration_index: usize,
        now: u64,
    ) -> Result<[u8; 32], PrivateTransportError> {
        self.ensure_current(authority)?;
        self.advance_trusted_time(now)?;
        self.prune_targets(now)?;
        if self.target_cache_generation == u64::MAX {
            return Err(PrivateTransportError::TargetCacheGenerationExhausted);
        }
        let (record_id, changed) = self.targets.install(
            locator,
            signed_record,
            configuration_index,
            self.binding.network_magic,
            now,
            self.allow_private_targets,
        )?;
        if changed {
            self.advance_target_cache_generation()?;
        }
        Ok(record_id)
    }

    /// Acquire and atomically install one signed target configuration.
    ///
    /// This is the canonical browser/mobile bootstrap seam: the adapter only
    /// exchanges bytes with the already authenticated proxy. The requester
    /// owns GETCONFIG/CONFIG framing, request correlation, proxy/target
    /// separation, target signature/network/locator verification, sequence
    /// anti-rollback, configuration selection, and durable generation update.
    #[allow(
        clippy::too_many_arguments,
        reason = "authority, adapter, locator, cache policy, selection, cancellation, and deadline are independent inputs"
    )]
    pub fn fetch_target_configuration<C, A>(
        &mut self,
        authority: &C,
        adapter: &mut A,
        locator: DirectTargetLocator,
        allow_cached: bool,
        configuration_index: usize,
        cancellation: &CancellationToken,
        now: u64,
        deadline: u64,
    ) -> Result<OdohTargetInstall, PrivateTransportError>
    where
        C: PrivateTransportAuthorityContext + ?Sized,
        A: ExperimentalExchange,
    {
        self.ensure_current(authority)?;
        self.advance_trusted_time(now)?;
        self.prune_targets(now)?;
        if self.target_cache_generation == u64::MAX {
            return Err(PrivateTransportError::TargetCacheGenerationExhausted);
        }
        let proxy = self
            .proxy
            .as_mut()
            .ok_or(PrivateTransportError::ProxyUnavailable)?;
        let fetched = self
            .requester
            .request_target_configuration(
                adapter,
                proxy,
                &locator,
                allow_cached,
                self.binding.network_magic,
                self.allow_private_targets,
                configuration_index,
                cancellation,
                now,
                deadline,
            )
            .map_err(PrivateTransportError::Transport)?;
        self.advance_trusted_time(fetched.completed_at)?;
        if let Err(error) = authority.validate_private_transport_binding(self.binding) {
            self.revoke_for_error(&error);
            return Err(error);
        }
        if self.target_cache_generation == u64::MAX {
            return Err(PrivateTransportError::TargetCacheGenerationExhausted);
        }
        let (record_id, changed) = self.targets.install(
            locator,
            &fetched.signed_record,
            configuration_index,
            self.binding.network_magic,
            fetched.completed_at,
            self.allow_private_targets,
        )?;
        if changed {
            self.advance_target_cache_generation()?;
        }
        Ok(OdohTargetInstall {
            record_id,
            target_cache_generation: self.target_cache_generation,
            completed_at: fetched.completed_at,
        })
    }

    /// Encode the canonical checksummed target-cache restart representation.
    ///
    /// Only public signed configuration material and per-locator sequence
    /// high-water marks are persisted. Proxy sessions, request IDs, HPKE query
    /// contexts, and in-flight work are never serialized.
    pub fn export_target_cache(
        &mut self,
        now: u64,
    ) -> Result<OdohTargetCacheExport, PrivateTransportError> {
        self.advance_trusted_time(now)?;
        self.prune_targets(now)?;
        let bytes = self.targets.encode(
            self.binding.network_magic,
            self.allow_private_targets,
            self.trusted_time_high_water,
            self.target_cache_generation,
        )?;
        Ok(OdohTargetCacheExport {
            generation: self.target_cache_generation,
            bytes,
        })
    }

    /// Read status, terminally revoking this instance if its engine epoch ended.
    pub fn status<C: PrivateTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
        now: u64,
    ) -> Result<OdohRequesterStatus, PrivateTransportError> {
        self.advance_trusted_time(now)?;
        if self.revocation_reason.is_none() {
            if let Err(error) = authority.validate_private_transport_binding(self.binding) {
                self.revoke_for_error(&error);
                if matches!(error, PrivateTransportError::Engine(_)) {
                    return Err(error);
                }
            }
        }
        self.prune_targets(now)?;
        let (
            proxy_identity,
            registry_fingerprint,
            registry_version,
            resolved_wire_profile,
            maximum_live_requests,
        ) = self
            .proxy
            .as_ref()
            .map_or((None, [0; 32], 0, None, 0), |proxy| {
                (
                    Some(proxy.identity().as_bytes()),
                    proxy.registry_fingerprint(),
                    proxy.registry_version(),
                    Some(proxy.wire_profile()),
                    proxy.maximum_live_requests(),
                )
            });
        let target_slots = u16::try_from(self.targets.slots.len()).unwrap_or(u16::MAX);
        let current_targets = u16::try_from(self.targets.current_count()).unwrap_or(u16::MAX);
        let ready =
            self.revocation_reason.is_none() && self.proxy.is_some() && current_targets != 0;
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
            resolved_wire_profile,
            maximum_live_requests,
            target_slots,
            current_targets,
            earliest_target_expiry: self.targets.earliest_expiry(),
            trusted_time_high_water: self.trusted_time_high_water,
            target_cache_generation: self.target_cache_generation,
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
    #[allow(
        clippy::too_many_arguments,
        reason = "adapter, target, query, cancellation, and clock are independent trust inputs"
    )]
    pub fn exchange<C, A>(
        &mut self,
        authority: &C,
        adapter: &mut A,
        target_record_id: [u8; 32],
        query: &hns_dns_wire::Query,
        cancellation: &CancellationToken,
        now: u64,
        deadline: u64,
    ) -> Result<super::AdmittedDnsResponse, PrivateTransportError>
    where
        C: PrivateTransportAuthorityContext + ?Sized,
        A: ExperimentalExchange,
    {
        self.ensure_current(authority)?;
        self.advance_trusted_time(now)?;
        self.prune_targets(now)?;
        let target = self.targets.target(target_record_id)?;
        let proxy = self
            .proxy
            .as_mut()
            .ok_or(PrivateTransportError::ProxyUnavailable)?;
        let mut tracking = CompletionTrackingExchange {
            adapter,
            completed_at: None,
        };
        let result = self.requester.exchange(
            &mut tracking,
            proxy,
            target,
            query,
            cancellation,
            now,
            deadline,
        );
        if let Some(completed_at) = tracking
            .completed_at
            .filter(|completed_at| *completed_at >= now && *completed_at <= deadline)
        {
            self.advance_trusted_time(completed_at)?;
        }
        if let Err(error) = authority.validate_private_transport_binding(self.binding) {
            self.revoke_for_error(&error);
            return Err(error);
        }
        result.map_err(PrivateTransportError::Transport)
    }

    /// Terminally revoke and erase all live proxy and target state.
    pub fn revoke(&mut self) -> Result<(), PrivateTransportError> {
        let generation_result = if self.targets.slots.is_empty() {
            Ok(())
        } else {
            self.advance_target_cache_generation()
        };
        self.revocation_reason = Some(PrivateTransportRevocationReason::Explicit);
        self.proxy = None;
        self.targets = OdohTargetCache::default();
        generation_result
    }

    fn ensure_current<C: PrivateTransportAuthorityContext + ?Sized>(
        &mut self,
        authority: &C,
    ) -> Result<(), PrivateTransportError> {
        if let Some(reason) = self.revocation_reason {
            return Err(PrivateTransportError::BindingRevoked(reason));
        }
        if let Err(error) = authority.validate_private_transport_binding(self.binding) {
            self.revoke_for_error(&error);
            return Err(error);
        }
        Ok(())
    }

    fn advance_trusted_time(&mut self, now: u64) -> Result<(), PrivateTransportError> {
        if now < self.trusted_time_high_water {
            return Err(PrivateTransportError::TrustedClockRollback);
        }
        if now > self.trusted_time_high_water {
            self.advance_target_cache_generation()?;
            self.trusted_time_high_water = now;
        }
        Ok(())
    }

    fn prune_targets(&mut self, now: u64) -> Result<(), PrivateTransportError> {
        if self.targets.slots.values().any(|slot| {
            slot.current
                .as_ref()
                .is_some_and(|target| now >= target.verified.expires_at())
        }) {
            self.advance_target_cache_generation()?;
            let _ = self.targets.prune(now);
        }
        Ok(())
    }

    fn advance_target_cache_generation(&mut self) -> Result<(), PrivateTransportError> {
        self.target_cache_generation = self
            .target_cache_generation
            .checked_add(1)
            .ok_or(PrivateTransportError::TargetCacheGenerationExhausted)?;
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
        start_odoh_requester(binding, first_request_id, limits, allow_private_targets)
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
        minimum_target_cache_generation: u64,
        now: u64,
    ) -> Result<OdohRequesterRuntime, PrivateTransportError> {
        let binding = self.mint_private_transport_binding(allow_private_targets)?;
        restore_odoh_requester(
            binding,
            first_request_id,
            limits,
            allow_private_targets,
            target_cache,
            minimum_target_cache_generation,
            now,
        )
    }

    fn mint_private_transport_binding(
        &self,
        allow_private_targets: bool,
    ) -> Result<PrivateTransportBinding, PrivateTransportError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| PrivateTransportError::Engine(EngineError::LockPoisoned))?;
        let network = state.network;
        let policy = state.policy.snapshot();
        mint_private_transport_binding(&mut state.runtime, network, policy, allow_private_targets)
    }

    fn validate_private_transport_binding(
        &self,
        binding: PrivateTransportBinding,
    ) -> Result<(), PrivateTransportError> {
        let state = self
            .state
            .read()
            .map_err(|_| PrivateTransportError::Engine(EngineError::LockPoisoned))?;
        validate_private_transport_binding(
            &state.runtime,
            state.network,
            state.policy.snapshot(),
            binding,
        )
    }
}

impl PrivateTransportAuthorityContext for Engine {
    fn validate_private_transport_binding(
        &self,
        binding: PrivateTransportBinding,
    ) -> Result<(), PrivateTransportError> {
        Engine::validate_private_transport_binding(self, binding)
    }
}

fn start_odoh_requester(
    binding: PrivateTransportBinding,
    first_request_id: NonZeroU64,
    limits: RequesterLimits,
    allow_private_targets: bool,
) -> Result<OdohRequesterRuntime, PrivateTransportError> {
    let requester =
        OdohRequester::new(first_request_id, limits).map_err(PrivateTransportError::Transport)?;
    Ok(OdohRequesterRuntime {
        binding,
        requester,
        proxy: None,
        targets: OdohTargetCache::default(),
        allow_private_targets,
        trusted_time_high_water: 0,
        target_cache_generation: 1,
        revocation_reason: None,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "request identity, limits, persistence guard, address policy, and time are independent trust inputs"
)]
fn restore_odoh_requester(
    binding: PrivateTransportBinding,
    first_request_id: NonZeroU64,
    limits: RequesterLimits,
    allow_private_targets: bool,
    target_cache: &[u8],
    minimum_target_cache_generation: u64,
    now: u64,
) -> Result<OdohRequesterRuntime, PrivateTransportError> {
    if minimum_target_cache_generation == 0 {
        return Err(PrivateTransportError::InvalidTargetCacheGeneration);
    }
    let requester =
        OdohRequester::new(first_request_id, limits).map_err(PrivateTransportError::Transport)?;
    let (targets, persisted_time_high_water, persisted_generation, pruned) =
        OdohTargetCache::decode(
            target_cache,
            binding.network_magic,
            allow_private_targets,
            now,
        )?;
    if persisted_generation < minimum_target_cache_generation {
        return Err(PrivateTransportError::TargetCacheGenerationRollback);
    }
    if now < persisted_time_high_water {
        return Err(PrivateTransportError::TrustedClockRollback);
    }
    let mut runtime = OdohRequesterRuntime {
        binding,
        requester,
        proxy: None,
        targets,
        allow_private_targets,
        trusted_time_high_water: persisted_time_high_water,
        target_cache_generation: persisted_generation,
        revocation_reason: None,
    };
    runtime.advance_trusted_time(now)?;
    if pruned {
        runtime.advance_target_cache_generation()?;
    }
    Ok(runtime)
}

fn mint_private_transport_binding(
    runtime: &mut BrowserRuntime,
    network: Network,
    policy: PolicySnapshot,
    allow_private_targets: bool,
) -> Result<PrivateTransportBinding, PrivateTransportError> {
    if !resolution_transport_ready(runtime.authority_state()) {
        return Err(PrivateTransportError::AuthorityUnavailable);
    }
    if allow_private_targets && !matches!(network, Network::Regtest | Network::Simnet) {
        return Err(PrivateTransportError::PrivateTargetsForbidden);
    }
    if policy.config().wire_profile == WireProfile::Official {
        return Err(PrivateTransportError::UnsupportedWireProfile);
    }
    let admission = PolicyController::new(policy)
        .admit(ResolutionTransport::HandshakeP2pOdoh)
        .map_err(PrivateTransportError::Policy)?;
    let stamp = runtime
        .admit_event()
        .map_err(|error| PrivateTransportError::Engine(super::map_runtime_error(error)))?;
    Ok(PrivateTransportBinding {
        stamp,
        admission,
        network,
        network_magic: network_magic(network),
        policy_wire_profile: policy.config().wire_profile,
    })
}

fn validate_private_transport_binding(
    browser_runtime: &BrowserRuntime,
    network: Network,
    policy: PolicySnapshot,
    binding: PrivateTransportBinding,
) -> Result<(), PrivateTransportError> {
    let runtime = browser_runtime.snapshot();
    if network != binding.network || network_magic(network) != binding.network_magic {
        return Err(PrivateTransportError::NetworkChanged);
    }
    if runtime.session_bytes() != binding.stamp.session() {
        return Err(PrivateTransportError::RuntimeSessionChanged);
    }
    if runtime.generation() != binding.stamp.generation() {
        return Err(PrivateTransportError::RuntimeGenerationChanged);
    }
    if policy.generation() != binding.admission.policy_generation {
        return Err(PrivateTransportError::PolicyGenerationChanged);
    }
    if !resolution_transport_ready(runtime.authority_state()) {
        return Err(PrivateTransportError::AuthorityUnavailable);
    }
    if !browser_runtime.admits(binding.stamp) {
        return Err(PrivateTransportError::AdmissionInvalidated);
    }
    PolicyController::new(policy)
        .accept_completion(binding.admission)
        .map_err(PrivateTransportError::Policy)
}

pub(crate) const fn network_magic(network: Network) -> u32 {
    match network {
        Network::Mainnet => NetworkMagic::Mainnet.as_u32(),
        Network::Testnet => NetworkMagic::Testnet.as_u32(),
        Network::Regtest => NetworkMagic::Regtest.as_u32(),
        Network::Simnet => NetworkMagic::Simnet.as_u32(),
    }
}

pub(crate) const fn experimental_network(network: Network) -> ExperimentalNetwork {
    match network {
        Network::Mainnet => ExperimentalNetwork::Mainnet,
        Network::Testnet => ExperimentalNetwork::Testnet,
        Network::Regtest => ExperimentalNetwork::Regtest,
        Network::Simnet => ExperimentalNetwork::Simnet,
    }
}

pub(crate) const fn resolved_odoh_profile(
    policy_profile: WireProfile,
) -> Result<ExperimentalWireProfile, PrivateTransportError> {
    match policy_profile {
        WireProfile::DenuoV1 | WireProfile::Auto => Ok(ExperimentalWireProfile::DenuoV1),
        WireProfile::Official => Err(PrivateTransportError::UnsupportedWireProfile),
    }
}

const fn consensus_network(network: Network) -> ConsensusNetwork {
    match network {
        Network::Mainnet => ConsensusNetwork::Mainnet,
        Network::Testnet => ConsensusNetwork::Testnet,
        Network::Regtest => ConsensusNetwork::Regtest,
        Network::Simnet => ConsensusNetwork::Simnet,
    }
}

pub(crate) const fn canonical_genesis_hash(network: Network) -> [u8; 32] {
    consensus_network(network)
        .parameters()
        .genesis_hash
        .into_bytes()
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

pub(crate) fn crc32(input: &[u8]) -> u32 {
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
    /// Current policy selects a registry profile this runtime cannot authenticate.
    UnsupportedWireProfile,
    /// Trusted caller or adapter time moved below the persisted high-water.
    TrustedClockRollback,
    /// Target-cache generation or caller-held floor is zero.
    InvalidTargetCacheGeneration,
    /// Persisted target-cache generation is below the caller-held floor.
    TargetCacheGenerationRollback,
    /// Target-cache generation cannot advance without wrapping.
    TargetCacheGenerationExhausted,
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
            Self::Transport(error) => {
                write!(formatter, "private transport request failed: {error}")
            }
            Self::Policy(error) => write!(formatter, "private transport policy failed: {error}"),
            Self::BindingRevoked(reason) => write!(
                formatter,
                "private transport runtime was revoked: {reason:?}"
            ),
            Self::RuntimeSessionChanged => {
                formatter.write_str("private transport runtime session changed")
            }
            Self::RuntimeGenerationChanged => {
                formatter.write_str("private transport runtime generation changed")
            }
            Self::PolicyGenerationChanged => {
                formatter.write_str("private transport policy generation changed")
            }
            Self::AdmissionInvalidated => {
                formatter.write_str("private transport admission was invalidated")
            }
            Self::AuthorityUnavailable => {
                formatter.write_str("private transport authority is unavailable")
            }
            Self::NetworkChanged => formatter.write_str("private transport network changed"),
            Self::PrivateTargetsForbidden => {
                formatter.write_str("private ODoH targets require regtest or simnet")
            }
            Self::UnsupportedWireProfile => {
                formatter.write_str("ODoH runtime cannot authenticate the selected wire profile")
            }
            Self::TrustedClockRollback => {
                formatter.write_str("ODoH runtime trusted clock moved backwards")
            }
            Self::InvalidTargetCacheGeneration => {
                formatter.write_str("ODoH target-cache generation is invalid")
            }
            Self::TargetCacheGenerationRollback => formatter
                .write_str("ODoH target-cache generation rolled back below the caller floor"),
            Self::TargetCacheGenerationExhausted => {
                formatter.write_str("ODoH target-cache generation is exhausted")
            }
            Self::ProxyUnavailable => {
                formatter.write_str("authenticated ODoH proxy is unavailable")
            }
            Self::TargetUnavailable => {
                formatter.write_str("current signed ODoH target is unavailable")
            }
            Self::InvalidTargetRecordLength => {
                formatter.write_str("signed ODoH target record length is invalid")
            }
            Self::InvalidConfigurationIndex => {
                formatter.write_str("ODoH configuration index is invalid")
            }
            Self::InvalidTargetLocator => formatter.write_str("ODoH target locator is invalid"),
            Self::TargetCacheFull => formatter.write_str("ODoH target cache is full"),
            Self::TargetSequenceRollback => formatter.write_str("ODoH target sequence rollback"),
            Self::TargetSequenceConflict => {
                formatter.write_str("ODoH target sequence conflicts with cached state")
            }
            Self::InvalidTargetSequence => formatter.write_str("ODoH target sequence is invalid"),
            Self::InvalidTargetCacheBlob => {
                formatter.write_str("ODoH target-cache blob is invalid")
            }
            Self::TargetCacheBlobTooLarge => {
                formatter.write_str("ODoH target-cache blob exceeds its bound")
            }
            Self::TargetCacheChecksumMismatch => {
                formatter.write_str("ODoH target-cache checksum mismatch")
            }
            Self::UnsupportedTargetCacheSchema => {
                formatter.write_str("ODoH target-cache schema is unsupported")
            }
            Self::TargetCacheNetworkMismatch => {
                formatter.write_str("ODoH target-cache network mismatch")
            }
            Self::TargetCacheAddressPolicyMismatch => {
                formatter.write_str("ODoH target-cache address policy mismatch")
            }
            Self::NonCanonicalTargetCache => {
                formatter.write_str("ODoH target-cache entries are noncanonical")
            }
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
    use crate::{
        DENUO_EXTENSION_SERVICE, EngineConfig, ExperimentalWireProfile, ODOH_SERVICE,
        PeerProtocolError, PolicyConfig, PolicySnapshot, RegistryHello, RuntimeSessionId,
        ServiceMask,
    };

    const SECP256K1_GENERATOR: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn ready_engine(session: u8, network: Network) -> Engine {
        ready_engine_with_profile(session, network, WireProfile::DenuoV1)
    }

    fn ready_engine_with_profile(
        session: u8,
        network: Network,
        wire_profile: WireProfile,
    ) -> Engine {
        let policy = PolicySnapshot::new(
            1,
            PolicyConfig {
                wire_profile,
                ..PolicyConfig::default()
            },
        )
        .unwrap();
        let engine = Engine::new(EngineConfig::new(
            RuntimeSessionId::new([session; 16]).unwrap(),
            network,
            policy,
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

    fn proxy_inputs(
        profile: ExperimentalWireProfile,
        network: ExperimentalNetwork,
        genesis_hash: [u8; 32],
        advertise_odoh: bool,
        advertise_denuo: bool,
        alternate_registry: bool,
    ) -> (ExperimentalPeerState, NegotiatedRegistry) {
        let hello =
            RegistryHello::denuo_v1(network, genesis_hash, Vec::new(), 100_000, 8, 0).unwrap();
        let mut registry = NegotiatedRegistry::negotiate(&hello, &hello).unwrap();
        if alternate_registry {
            registry.fingerprint = [0x44; 32].into();
        }
        let mut services = ServiceMask::default();
        if advertise_denuo {
            services = services.with(DENUO_EXTENSION_SERVICE);
        }
        if advertise_odoh {
            services = services.with(ODOH_SERVICE);
        }
        let peer = ExperimentalPeerState::new(
            profile,
            network,
            genesis_hash,
            registry.fingerprint,
            services,
        );
        (peer, registry)
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
        let exported = runtime.export_target_cache(1_700_000_000).unwrap();
        assert!(exported.bytes.len() <= MAX_ODOH_TARGET_CACHE_BLOB_BYTES);
        assert_eq!(exported.generation, 2);
        assert!(matches!(
            runtime.export_target_cache(1_699_999_999),
            Err(PrivateTransportError::TrustedClockRollback)
        ));
        assert!(matches!(
            engine.restore_odoh_requester(
                NonZeroU64::new(12).unwrap(),
                RequesterLimits::default(),
                true,
                &exported.bytes,
                exported.generation,
                1_699_999_999,
            ),
            Err(PrivateTransportError::TrustedClockRollback)
        ));
        let mut restored = engine
            .restore_odoh_requester(
                NonZeroU64::new(13).unwrap(),
                RequesterLimits::default(),
                true,
                &exported.bytes,
                exported.generation,
                1_700_000_000,
            )
            .unwrap();
        assert_ne!(
            restored.binding().admission_event(),
            runtime.binding().admission_event()
        );
        assert_eq!(
            restored
                .status(&engine, 1_700_000_000)
                .unwrap()
                .current_targets,
            0
        );
        assert!(matches!(
            restored.status(&engine, 1_699_999_999),
            Err(PrivateTransportError::TrustedClockRollback)
        ));

        let mut corrupted = exported.bytes;
        if let Some(byte) = corrupted.get_mut(8) {
            *byte ^= 1;
        }
        assert!(matches!(
            engine.restore_odoh_requester(
                NonZeroU64::new(14).unwrap(),
                RequesterLimits::default(),
                true,
                &corrupted,
                exported.generation,
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

    #[test]
    fn production_followup_odoh_cache_generation_rejects_older_sequence_snapshot() {
        let engine = ready_engine(47, Network::Regtest);
        let mut runtime = engine
            .start_odoh_requester(
                NonZeroU64::new(24).unwrap(),
                RequesterLimits::default(),
                true,
            )
            .unwrap();
        let locator = DirectTargetLocator::new(
            SECP256K1_GENERATOR,
            "127.0.0.1:14039".parse().unwrap(),
            true,
        )
        .unwrap();
        let locator_key = locator.encode();
        runtime.targets.slots.insert(
            locator_key.clone(),
            TargetSlot {
                locator,
                highest_sequence: 1,
                current: None,
            },
        );
        runtime.advance_target_cache_generation().unwrap();
        let older = runtime.export_target_cache(1_700_000_200).unwrap();

        runtime
            .targets
            .slots
            .get_mut(&locator_key)
            .unwrap()
            .highest_sequence = 2;
        runtime.advance_target_cache_generation().unwrap();
        let current = runtime.export_target_cache(1_700_000_200).unwrap();
        assert!(current.generation > older.generation);
        assert!(matches!(
            engine.restore_odoh_requester(
                NonZeroU64::new(25).unwrap(),
                RequesterLimits::default(),
                true,
                &older.bytes,
                current.generation,
                1_700_000_200,
            ),
            Err(PrivateTransportError::TargetCacheGenerationRollback)
        ));
        assert!(matches!(
            engine.restore_odoh_requester(
                NonZeroU64::new(26).unwrap(),
                RequesterLimits::default(),
                true,
                &current.bytes,
                0,
                1_700_000_200,
            ),
            Err(PrivateTransportError::InvalidTargetCacheGeneration)
        ));
        let restored = engine
            .restore_odoh_requester(
                NonZeroU64::new(27).unwrap(),
                RequesterLimits::default(),
                true,
                &current.bytes,
                current.generation,
                1_700_000_200,
            )
            .unwrap();
        assert_eq!(
            restored
                .targets
                .slots
                .get(&locator_key)
                .unwrap()
                .highest_sequence,
            2
        );
    }

    #[test]
    fn production_followup_engine_proxy_binding_requires_canonical_network_registry_and_service() {
        let engine = ready_engine(44, Network::Regtest);
        let mut runtime = engine
            .start_odoh_requester(
                NonZeroU64::new(21).unwrap(),
                RequesterLimits::default(),
                true,
            )
            .unwrap();
        let identity = PeerIdentity::new(SECP256K1_GENERATOR).unwrap();
        let regtest_genesis = canonical_genesis_hash(Network::Regtest);

        let (peer, registry) = proxy_inputs(
            ExperimentalWireProfile::DenuoV1,
            ExperimentalNetwork::Testnet,
            canonical_genesis_hash(Network::Testnet),
            true,
            true,
            false,
        );
        assert!(matches!(
            runtime.bind_proxy(&engine, identity, peer, registry),
            Err(PrivateTransportError::Transport(
                P2pTransportError::PeerAdmission(PeerProtocolError::WrongNetwork)
            ))
        ));

        let (peer, registry) = proxy_inputs(
            ExperimentalWireProfile::DenuoV1,
            ExperimentalNetwork::Regtest,
            [0x45; 32],
            true,
            true,
            false,
        );
        assert!(matches!(
            runtime.bind_proxy(&engine, identity, peer, registry),
            Err(PrivateTransportError::Transport(
                P2pTransportError::PeerAdmission(PeerProtocolError::WrongGenesis)
            ))
        ));

        let (peer, registry) = proxy_inputs(
            ExperimentalWireProfile::DenuoV1,
            ExperimentalNetwork::Regtest,
            regtest_genesis,
            true,
            true,
            true,
        );
        assert!(matches!(
            runtime.bind_proxy(&engine, identity, peer, registry),
            Err(PrivateTransportError::Transport(
                P2pTransportError::InvalidNegotiatedRegistry
            ))
        ));

        let (peer, registry) = proxy_inputs(
            ExperimentalWireProfile::DenuoV1,
            ExperimentalNetwork::Regtest,
            regtest_genesis,
            false,
            true,
            false,
        );
        assert!(matches!(
            runtime.bind_proxy(&engine, identity, peer, registry),
            Err(PrivateTransportError::Transport(
                P2pTransportError::PeerAdmission(PeerProtocolError::PacketWithoutService { .. })
            ))
        ));

        let (peer, registry) = proxy_inputs(
            ExperimentalWireProfile::DenuoV1,
            ExperimentalNetwork::Regtest,
            regtest_genesis,
            true,
            false,
            false,
        );
        assert!(matches!(
            runtime.bind_proxy(&engine, identity, peer, registry),
            Err(PrivateTransportError::Transport(
                P2pTransportError::PeerAdmission(
                    PeerProtocolError::AdvertisedServiceWithoutRegistry
                )
            ))
        ));

        for profile in [
            ExperimentalWireProfile::DenuoV2,
            ExperimentalWireProfile::LegacyDraftRegtest,
            ExperimentalWireProfile::Official(1),
            ExperimentalWireProfile::Auto,
        ] {
            let (peer, registry) = proxy_inputs(
                profile,
                ExperimentalNetwork::Regtest,
                regtest_genesis,
                true,
                true,
                false,
            );
            assert!(matches!(
                runtime.bind_proxy(&engine, identity, peer, registry),
                Err(PrivateTransportError::Transport(
                    P2pTransportError::UnexpectedWireProfile {
                        expected: ExperimentalWireProfile::DenuoV1,
                        actual,
                    }
                )) if actual == profile
            ));
        }

        let (peer, registry) = proxy_inputs(
            ExperimentalWireProfile::DenuoV1,
            ExperimentalNetwork::Regtest,
            regtest_genesis,
            true,
            true,
            false,
        );
        runtime
            .bind_proxy(&engine, identity, peer, registry)
            .unwrap();
        let status = runtime.status(&engine, 1_700_000_100).unwrap();
        assert_eq!(status.schema_version, 3);
        assert_eq!(status.proxy_identity, Some(SECP256K1_GENERATOR));
        assert_eq!(
            runtime.binding().policy_wire_profile(),
            WireProfile::DenuoV1
        );
        assert_eq!(
            status.resolved_wire_profile,
            Some(ExperimentalWireProfile::DenuoV1)
        );
        assert!(!status.requester_ready);
    }

    #[test]
    fn production_followup_odoh_policy_resolves_auto_and_rejects_official() {
        let official_engine =
            ready_engine_with_profile(45, Network::Regtest, WireProfile::Official);
        assert!(matches!(
            official_engine.start_odoh_requester(
                NonZeroU64::new(22).unwrap(),
                RequesterLimits::default(),
                true,
            ),
            Err(PrivateTransportError::UnsupportedWireProfile)
        ));

        let auto_engine = ready_engine_with_profile(46, Network::Regtest, WireProfile::Auto);
        let mut runtime = auto_engine
            .start_odoh_requester(
                NonZeroU64::new(23).unwrap(),
                RequesterLimits::default(),
                true,
            )
            .unwrap();
        let regtest_genesis = canonical_genesis_hash(Network::Regtest);
        let (peer, registry) = proxy_inputs(
            ExperimentalWireProfile::DenuoV1,
            ExperimentalNetwork::Regtest,
            regtest_genesis,
            true,
            true,
            false,
        );
        runtime
            .bind_proxy(
                &auto_engine,
                PeerIdentity::new(SECP256K1_GENERATOR).unwrap(),
                peer,
                registry,
            )
            .unwrap();
        assert_eq!(runtime.binding().policy_wire_profile(), WireProfile::Auto);
        assert_eq!(
            runtime
                .status(&auto_engine, 1_700_000_101)
                .unwrap()
                .resolved_wire_profile,
            Some(ExperimentalWireProfile::DenuoV1)
        );
    }
}
