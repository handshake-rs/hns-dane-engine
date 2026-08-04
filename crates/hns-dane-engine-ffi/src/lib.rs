//! Versioned C ABI for [`hns_dane_engine`].
//!
//! Every entry point catches Rust panics. Pointer validity, allocation
//! ownership, and buffer lengths remain explicit caller obligations documented
//! in `include/hns_dane_engine.h`.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "the C header is the normative error contract and uses protocol acronyms"
)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::str;
use std::sync::Arc;

use hns_dane::DaneLimits;
use hns_dane_engine::{
    AuthorityState, CompletionContext, Engine, EngineConfig, EngineError, LocalDanePrerequisites,
    ProviderAuthorityContext, ResolutionAttempt, RuntimeSessionId,
};
use hns_dns_wire::{Name, ParseLimits, Query, RecordType};
use hns_resolution_policy::{
    DnsRelayRequesterPolicy, EvidenceState, HnsrPolicy, Network, ObliviousDnsPolicy, PolicyConfig,
    PolicyError, PolicySnapshot, ProviderPolicy, ResolutionTransport, WireProfile,
};

/// C ABI version implemented by this library.
pub const ABI_VERSION: u32 = 1;
/// Policy ABI version that exposes recursive-HNS-DoH requester consent.
pub const POLICY_ABI_VERSION_V2: u32 = 2;
/// Provider-authority consumer ABI version.
pub const PROVIDER_AUTHORITY_ABI_VERSION_V1: u32 = 1;
/// All caller-supplied prerequisite bits required before local DANE matching.
pub const PREREQUISITES_ALL_VERIFIED: u32 = 0x33;
/// Maximum bytes in each fixed-size C transport identity.
pub const ABI_IDENTITY_CAPACITY: usize = 128;

const PROVIDER_DNS_RELAY: u16 = 1 << 0;
const PROVIDER_ODOH_PROXY: u16 = 1 << 1;
const PROVIDER_ODOH_TARGET: u16 = 1 << 2;
const PROVIDER_MARKET_GOSSIP: u16 = 1 << 3;
const PROVIDER_KNOWN: u16 =
    PROVIDER_DNS_RELAY | PROVIDER_ODOH_PROXY | PROVIDER_ODOH_TARGET | PROVIDER_MARKET_GOSSIP;

const EFFECT_STOP_DISABLED: u32 = 1 << 0;
const EFFECT_CANCEL_OR_DRAIN: u32 = 1 << 1;
const EFFECT_CLEAR_REQUESTER: u32 = 1 << 2;
const EFFECT_WITHDRAW_ADVERTISEMENTS: u32 = 1 << 3;
const EFFECT_WITHDRAW_HNSR: u32 = 1 << 4;
const EFFECT_REVOKE_TARGETS: u32 = 1 << 5;
const EFFECT_RENEGOTIATE: u32 = 1 << 6;
const EFFECT_UPDATE_STATUS: u32 = 1 << 7;

/// Opaque engine handle declaration.
#[repr(C)]
pub struct HnsDaneEngine {
    _private: [u8; 0],
}

/// Opaque admitted-attempt handle declaration.
#[repr(C)]
pub struct HnsDaneAttempt {
    _private: [u8; 0],
}

/// Opaque authorized provider-context handle declaration.
///
/// C callers cannot construct or import this handle. A trusted Rust authority
/// host must move an engine-issued [`ProviderAuthorityContext`] through
/// [`provider_authority_into_ffi`].
#[repr(C)]
pub struct HnsDaneProviderAuthority {
    _private: [u8; 0],
}

struct EngineHandle {
    engine: Engine,
}

struct AttemptHandle {
    attempt: ResolutionAttempt,
}

struct ProviderAuthorityHandle {
    engine: Arc<Engine>,
    authority: ProviderAuthorityContext,
}

/// C ABI status.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HnsDaneStatus {
    /// Success.
    Ok = 0,
    /// Required pointer was null.
    NullPointer = 1,
    /// ABI version or struct size is unsupported.
    AbiMismatch = 2,
    /// Input encoding or enum discriminant is invalid.
    InvalidArgument = 3,
    /// Output buffer is too small.
    BufferTooSmall = 4,
    /// Expected generation is stale.
    StaleGeneration = 5,
    /// Requested transport is disabled.
    TransportDisabled = 6,
    /// Browser authority state is not ready.
    AuthorityNotReady = 7,
    /// DNS packet is malformed or uncorrelated.
    DnsRejected = 8,
    /// Local validation evidence is incomplete.
    EvidenceRejected = 9,
    /// Internal engine state failed.
    Internal = 10,
    /// A Rust panic was contained at the ABI boundary.
    PanicContained = 255,
}

impl HnsDaneStatus {
    const fn code(self) -> i32 {
        self as i32
    }
}

/// Versioned C policy structure.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HnsDanePolicyV1 {
    /// Set to `sizeof(HnsDanePolicyV1)`.
    pub struct_size: u32,
    /// Set to [`ABI_VERSION`].
    pub abi_version: u32,
    /// Current policy generation on output; expected generation on input.
    pub generation: u64,
    /// [`DnsRelayRequesterPolicy`] discriminant.
    pub dns_relay_requester: u8,
    /// [`ObliviousDnsPolicy`] discriminant.
    pub oblivious_dns: u8,
    /// Independent [`HnsrPolicy`] role bits.
    pub hnsr: u8,
    /// [`WireProfile`] discriminant.
    pub wire_profile: u8,
    /// One when proof-authenticated authoritative DoH is enabled.
    pub authenticated_authoritative_doh: u8,
    /// One when bounded legacy regtest compatibility is enabled.
    pub allow_legacy_regtest_compatibility: u8,
    /// Explicit provider-role bitset.
    pub provider_flags: u16,
    /// Must be zero.
    pub reserved: [u8; 8],
}

/// Versioned C policy structure with recursive-HNS-DoH requester consent.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HnsDanePolicyV2 {
    /// Set to `sizeof(HnsDanePolicyV2)`.
    pub struct_size: u32,
    /// Set to [`POLICY_ABI_VERSION_V2`].
    pub abi_version: u32,
    /// Current policy generation on output; expected generation on input.
    pub generation: u64,
    /// [`DnsRelayRequesterPolicy`] discriminant.
    pub dns_relay_requester: u8,
    /// [`ObliviousDnsPolicy`] discriminant.
    pub oblivious_dns: u8,
    /// Independent [`HnsrPolicy`] role bits.
    pub hnsr: u8,
    /// [`WireProfile`] discriminant.
    pub wire_profile: u8,
    /// One when proof-authenticated authoritative DoH is enabled.
    pub authenticated_authoritative_doh: u8,
    /// One when bounded legacy regtest compatibility is enabled.
    pub allow_legacy_regtest_compatibility: u8,
    /// Explicit provider-role bitset.
    pub provider_flags: u16,
    /// One only after explicit recursive-HNS-DoH requester consent.
    pub user_configured_recursive_hns_doh: u8,
    /// Must be zero.
    pub reserved: [u8; 7],
}

/// Versioned transport identity context.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsDaneTransportContextV1 {
    /// Set to `sizeof(HnsDaneTransportContextV1)`.
    pub struct_size: u32,
    /// Set to [`ABI_VERSION`].
    pub abi_version: u32,
    /// Used bytes in `peer_identity`.
    pub peer_identity_len: u16,
    /// Used bytes in `proxy_identity`.
    pub proxy_identity_len: u16,
    /// Used bytes in `target_identity`.
    pub target_identity_len: u16,
    /// One only when ODoH downgraded to a direct relay attempt.
    pub direct_relay_fallback: u8,
    /// Must be zero.
    pub reserved: u8,
    /// UTF-8 relay or peer identity.
    pub peer_identity: [u8; ABI_IDENTITY_CAPACITY],
    /// UTF-8 ODoH proxy identity.
    pub proxy_identity: [u8; ABI_IDENTITY_CAPACITY],
    /// UTF-8 ODoH target identity.
    pub target_identity: [u8; ABI_IDENTITY_CAPACITY],
}

impl Default for HnsDaneTransportContextV1 {
    fn default() -> Self {
        Self {
            struct_size: u32::try_from(std::mem::size_of::<Self>()).unwrap_or(u32::MAX),
            abi_version: ABI_VERSION,
            peer_identity_len: 0,
            proxy_identity_len: 0,
            target_identity_len: 0,
            direct_relay_fallback: 0,
            reserved: 0,
            peer_identity: [0; ABI_IDENTITY_CAPACITY],
            proxy_identity: [0; ABI_IDENTITY_CAPACITY],
            target_identity: [0; ABI_IDENTITY_CAPACITY],
        }
    }
}

/// Versioned validated response summary.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HnsDaneResultV1 {
    /// Set to `sizeof(HnsDaneResultV1)`.
    pub struct_size: u32,
    /// Result schema version.
    pub schema_version: u16,
    /// [`ResolutionTransport`] discriminant.
    pub transport: u8,
    /// One if the remote packet asserted AD; never local evidence.
    pub untrusted_ad_claim: u8,
    /// Runtime generation that accepted the result.
    pub runtime_generation: u64,
    /// Policy generation that accepted the result.
    pub policy_generation: u64,
    /// Monotonic engine event sequence.
    pub event_sequence: u64,
    /// Parsed answer count.
    pub answer_count: u16,
    /// Index in the exact-owner TLSA RRset that matched.
    pub tlsa_record_index: u16,
    /// Matched TLSA certificate usage.
    pub tlsa_usage: u8,
    /// Matched TLSA selector.
    pub tlsa_selector: u8,
    /// Matched TLSA association matching type.
    pub tlsa_matching_type: u8,
    /// Reserved and zero.
    pub reserved: u8,
}

/// Immutable typed bindings carried by one authorized provider context.
///
/// This is an output-only projection. Its fields cannot be imported or used to
/// reconstruct authority; possession of the corresponding opaque handle and a
/// successful currentness check remain mandatory.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HnsDaneProviderAuthorityInfoV1 {
    /// Set to `sizeof(HnsDaneProviderAuthorityInfoV1)`.
    pub struct_size: u32,
    /// Set to [`PROVIDER_AUTHORITY_ABI_VERSION_V1`].
    pub abi_version: u32,
    /// [`hns_dane_engine::OriginScheme`] discriminant.
    pub origin_scheme: u8,
    /// [`hns_dane_engine::Namespace`] discriminant.
    pub selected_namespace: u8,
    /// [`hns_dane_engine::AuthenticatedContextStatus`] discriminant.
    pub authenticated_context: u8,
    /// [`hns_dane_engine::HnsNetwork`] discriminant.
    pub hns_network: u8,
    /// [`hns_dane_engine::TlsTrustPolicy`] discriminant.
    pub tls_policy: u8,
    /// Must be zero.
    pub reserved0: u8,
    /// Effective URL-origin port.
    pub origin_port: u16,
    /// Exact selected TCP service port.
    pub service_port: u16,
    /// Must be zero.
    pub reserved1: [u8; 6],
    /// Browser-authority process session.
    pub runtime_session: [u8; 16],
    /// Browser-authority runtime generation.
    pub runtime_generation: u64,
    /// Persistent trust-policy generation.
    pub policy_generation: u64,
    /// Exact authority event that stamped the context.
    pub event_sequence: u64,
    /// Complete namespace-decision identity.
    pub decision_fingerprint: [u8; 32],
    /// First time at which the context may be consumed.
    pub valid_from: u64,
    /// Exclusive context expiry.
    pub valid_until: u64,
    /// Must be zero.
    pub reserved: [u8; 8],
}

/// Move an authorized Rust context into a caller-owned opaque C handle.
///
/// This Rust-only handoff is deliberately the sole constructor. It retains
/// the exact live engine used for future currentness checks and accepts no
/// diagnostic decision or caller-provided permission fields. The returned
/// pointer must be destroyed exactly once with
/// [`hns_dane_engine_provider_v1_authority_destroy`] after concurrent borrows
/// have stopped, and must never be exposed to page JavaScript.
/// A retained engine that does not admit the context cannot make the handle
/// current; the projection never substitutes for this check. The handle keeps
/// its engine alive until destruction.
#[must_use = "the returned provider-authority handle is caller-owned"]
pub fn provider_authority_into_ffi(
    engine: Arc<Engine>,
    authority: ProviderAuthorityContext,
) -> *mut HnsDaneProviderAuthority {
    Box::into_raw(Box::new(ProviderAuthorityHandle { engine, authority }))
        .cast::<HnsDaneProviderAuthority>()
}

/// Return the ABI version without dereferencing caller memory.
#[unsafe(no_mangle)]
pub extern "C" fn hns_dane_engine_v1_abi_version() -> u32 {
    ABI_VERSION
}

/// Return the policy-v2 ABI version without dereferencing caller memory.
#[unsafe(no_mangle)]
pub extern "C" fn hns_dane_engine_v2_abi_version() -> u32 {
    POLICY_ABI_VERSION_V2
}

/// Return the provider-authority consumer ABI version without dereferencing caller memory.
#[unsafe(no_mangle)]
pub extern "C" fn hns_dane_engine_provider_v1_abi_version() -> u32 {
    PROVIDER_AUTHORITY_ABI_VERSION_V1
}

/// Create an engine.
///
/// `runtime_session` must contain a fresh, unpredictable, nonzero value for
/// this process start. The all-zero sentinel is rejected.
///
/// An empty policy blob selects secure defaults. A nonempty blob must be the
/// exact checksummed representation returned by the export function.
///
/// # Safety
///
/// `runtime_session` must reference 16 readable bytes. `policy_blob` must
/// reference `policy_blob_len` readable bytes when the length is nonzero.
/// `output` must be valid for one pointer write and becomes caller-owned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v1_create(
    runtime_session: *const u8,
    network: u8,
    policy_blob: *const u8,
    policy_blob_len: usize,
    output: *mut *mut HnsDaneEngine,
) -> i32 {
    ffi_guard(|| {
        if runtime_session.is_null() || output.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        let network = network_from_u8(network)?;
        // SAFETY: The caller contract requires 16 readable session bytes.
        let session_slice = unsafe { slice::from_raw_parts(runtime_session, 16) };
        let mut session = [0u8; 16];
        session.copy_from_slice(session_slice);
        let session = RuntimeSessionId::new(session).map_err(|_| HnsDaneStatus::InvalidArgument)?;
        let policy = if policy_blob_len == 0 {
            PolicySnapshot::default()
        } else {
            if policy_blob.is_null() {
                return Err(HnsDaneStatus::NullPointer);
            }
            // SAFETY: The caller contract requires policy_blob_len readable bytes.
            let blob = unsafe { slice::from_raw_parts(policy_blob, policy_blob_len) };
            PolicySnapshot::decode(blob).map_err(map_policy_error)?
        };
        let handle = Box::new(EngineHandle {
            engine: Engine::new(EngineConfig {
                runtime_session: session,
                network,
                policy,
            }),
        });
        // SAFETY: output is caller-provided writable storage and the allocation
        // is intentionally transferred to the matching destroy function.
        unsafe {
            output.write(Box::into_raw(handle).cast::<HnsDaneEngine>());
        }
        Ok(())
    })
}

/// Destroy an engine returned by the create function.
///
/// # Safety
///
/// `engine` must be null or a live pointer returned by this library, and must
/// be destroyed at most once with no concurrent calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v1_destroy(engine: *mut HnsDaneEngine) -> i32 {
    ffi_guard(|| {
        if engine.is_null() {
            return Ok(());
        }
        // SAFETY: Ownership is returned by the caller under the function contract.
        unsafe {
            drop(Box::from_raw(engine.cast::<EngineHandle>()));
        }
        Ok(())
    })
}

/// Destroy an admitted attempt.
///
/// # Safety
///
/// `attempt` must be null or a live pointer returned by the admit function,
/// and must be destroyed at most once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v1_attempt_destroy(attempt: *mut HnsDaneAttempt) -> i32 {
    ffi_guard(|| {
        if attempt.is_null() {
            return Ok(());
        }
        // SAFETY: Ownership is returned by the caller under the function contract.
        unsafe {
            drop(Box::from_raw(attempt.cast::<AttemptHandle>()));
        }
        Ok(())
    })
}

/// Destroy an opaque provider-authority handle.
///
/// # Safety
///
/// `authority` must be null or a live pointer returned by
/// [`provider_authority_into_ffi`], and must be destroyed at most once after
/// concurrent calls using it have stopped.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_provider_v1_authority_destroy(
    authority: *mut HnsDaneProviderAuthority,
) -> i32 {
    ffi_guard(|| {
        if authority.is_null() {
            return Ok(());
        }
        // SAFETY: Ownership is returned by the caller under the function contract.
        unsafe {
            drop(Box::from_raw(authority.cast::<ProviderAuthorityHandle>()));
        }
        Ok(())
    })
}

/// Read immutable typed bindings from an opaque provider authority.
///
/// The projection is diagnostic and cannot recreate or replace the handle.
///
/// # Safety
///
/// `authority` must be a live handle and `output` valid for one structure write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_provider_v1_authority_get_info(
    authority: *const HnsDaneProviderAuthority,
    output: *mut HnsDaneProviderAuthorityInfoV1,
) -> i32 {
    ffi_guard(|| {
        if output.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires a live provider-authority handle.
        let authority = unsafe { provider_authority_ref(authority)? };
        let info = provider_authority_info(&authority.authority)?;
        // SAFETY: output is required writable by the caller contract.
        unsafe {
            output.write(info);
        }
        Ok(())
    })
}

/// Copy the exact canonical logical-origin host from an opaque authority.
///
/// The host is returned as exact UTF-8 bytes without a trailing NUL. A sizing
/// call may pass a null `output` with zero `capacity`; `written` then receives
/// the required length and the function returns `BufferTooSmall`.
///
/// # Safety
///
/// `authority` must be a live handle. `written` must be writable. `output`
/// must reference `capacity` writable bytes when capacity is sufficient.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_provider_v1_authority_copy_host(
    authority: *const HnsDaneProviderAuthority,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_guard(|| {
        if written.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires a live provider-authority handle.
        let authority = unsafe { provider_authority_ref(authority)? };
        let host = authority.authority.logical_origin().host().as_bytes();
        // SAFETY: written is required writable by the caller contract.
        unsafe {
            written.write(host.len());
        }
        if capacity < host.len() {
            return Err(HnsDaneStatus::BufferTooSmall);
        }
        if output.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: capacity was checked and output must reference writable storage.
        unsafe {
            slice::from_raw_parts_mut(output, capacity)[..host.len()].copy_from_slice(host);
        }
        Ok(())
    })
}

/// Check an opaque authority against its retained engine and trusted time.
///
/// Expiry or any session, network, policy, runtime, or invalidation mismatch is
/// a normal successful query that writes zero to `current`.
/// `now_unix` must come from the trusted native lifecycle, never page input;
/// the platform is responsible for rejecting clock rollback.
///
/// # Safety
///
/// `authority` must be a live handle and `current` writable. No caller may
/// destroy the handle concurrently with this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_provider_v1_authority_is_current(
    authority: *const HnsDaneProviderAuthority,
    now_unix: u64,
    current: *mut u8,
) -> i32 {
    ffi_guard(|| {
        if current.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires a live authority handle.
        let authority = unsafe { provider_authority_ref(authority)? };
        let is_current = authority
            .engine
            .provider_authority_is_current(&authority.authority, now_unix)
            .map_err(map_engine_error)?;
        // SAFETY: current is required writable by the caller contract.
        unsafe {
            current.write(u8::from(is_current));
        }
        Ok(())
    })
}

/// Export the versioned persistent policy blob.
///
/// # Safety
///
/// `engine` must be a live handle. `written` must be writable. `output` must
/// reference `capacity` writable bytes when capacity is nonzero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v1_export_policy(
    engine: *const HnsDaneEngine,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    ffi_guard(|| {
        if written.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires a live engine handle.
        let engine = unsafe { engine_ref(engine)? };
        let blob = engine.engine.export_policy().map_err(map_engine_error)?;
        // SAFETY: written is required writable by the caller contract.
        unsafe {
            written.write(blob.len());
        }
        if capacity < blob.len() {
            return Err(HnsDaneStatus::BufferTooSmall);
        }
        if output.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: capacity was checked and output must reference writable storage.
        unsafe {
            slice::from_raw_parts_mut(output, capacity)[..blob.len()].copy_from_slice(&blob);
        }
        Ok(())
    })
}

/// Read the policy-V1 projection.
///
/// Returns [`HnsDaneStatus::AbiMismatch`] while recursive-HNS-DoH consent is
/// enabled because policy V1 cannot represent that permission.
///
/// # Safety
///
/// `engine` must be a live handle and `output` valid for one structure write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v1_get_policy(
    engine: *const HnsDaneEngine,
    output: *mut HnsDanePolicyV1,
) -> i32 {
    ffi_guard(|| {
        if output.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires a live engine handle.
        let engine = unsafe { engine_ref(engine)? };
        let snapshot = engine.engine.snapshot().map_err(map_engine_error)?.policy;
        if snapshot.config().user_configured_recursive_hns_doh {
            return Err(HnsDaneStatus::AbiMismatch);
        }
        let policy = policy_to_ffi_v1(snapshot);
        // SAFETY: output is required writable by the caller contract.
        unsafe {
            output.write(policy);
        }
        Ok(())
    })
}

/// Replace policy through the V1 fail-closed boundary.
///
/// A successful V1 update always disables recursive-HNS-DoH consent because
/// policy V1 cannot represent or retain that permission.
///
/// # Safety
///
/// `engine` must be a live handle; `policy`, `new_generation`, and `effects`
/// must be valid readable/writable pointers for their respective types.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v1_set_policy(
    engine: *const HnsDaneEngine,
    policy: *const HnsDanePolicyV1,
    new_generation: *mut u64,
    effects: *mut u32,
) -> i32 {
    ffi_guard(|| {
        if policy.is_null() || new_generation.is_null() || effects.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires a live engine handle.
        let engine = unsafe { engine_ref(engine)? };
        // SAFETY: policy is required readable by the caller contract.
        let policy = unsafe { policy.read() };
        let (expected_generation, config) = policy_from_ffi_v1(policy)?;
        let transition = engine
            .engine
            .update_policy(expected_generation, config)
            .map_err(map_engine_error)?;
        let effect_bits = effects_to_bits(transition.effects);
        // SAFETY: output pointers are required writable by the caller contract.
        unsafe {
            new_generation.write(transition.current.generation());
            effects.write(effect_bits);
        }
        Ok(())
    })
}

/// Read typed current policy, including recursive-HNS-DoH requester consent.
///
/// # Safety
///
/// `engine` must be a live handle and `output` valid for one structure write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v2_get_policy(
    engine: *const HnsDaneEngine,
    output: *mut HnsDanePolicyV2,
) -> i32 {
    ffi_guard(|| {
        if output.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires a live engine handle.
        let engine = unsafe { engine_ref(engine)? };
        let snapshot = engine.engine.snapshot().map_err(map_engine_error)?.policy;
        let policy = policy_to_ffi_v2(snapshot);
        // SAFETY: output is required writable by the caller contract.
        unsafe {
            output.write(policy);
        }
        Ok(())
    })
}

/// Replace typed policy, including recursive-HNS-DoH requester consent.
///
/// # Safety
///
/// `engine` must be a live handle; `policy`, `new_generation`, and `effects`
/// must be valid readable/writable pointers for their respective types.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v2_set_policy(
    engine: *const HnsDaneEngine,
    policy: *const HnsDanePolicyV2,
    new_generation: *mut u64,
    effects: *mut u32,
) -> i32 {
    ffi_guard(|| {
        if policy.is_null() || new_generation.is_null() || effects.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires a live engine handle.
        let engine = unsafe { engine_ref(engine)? };
        // SAFETY: policy is required readable by the caller contract.
        let policy = unsafe { policy.read() };
        let (expected_generation, config) = policy_from_ffi_v2(policy)?;
        let transition = engine
            .engine
            .update_policy(expected_generation, config)
            .map_err(map_engine_error)?;
        let effect_bits = effects_to_bits(transition.effects);
        // SAFETY: output pointers are required writable by the caller contract.
        unsafe {
            new_generation.write(transition.current.generation());
            effects.write(effect_bits);
        }
        Ok(())
    })
}

/// Advance the explicit authority state machine.
///
/// # Safety
///
/// `engine` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v1_advance_authority(
    engine: *const HnsDaneEngine,
    state: u8,
) -> i32 {
    ffi_guard(|| {
        // SAFETY: The caller contract requires a live engine handle.
        let engine = unsafe { engine_ref(engine)? };
        engine
            .engine
            .advance_authority_state(authority_state_from_u8(state)?)
            .map_err(map_engine_error)?;
        Ok(())
    })
}

/// Return the number of currently ordered transport candidates.
///
/// # Safety
///
/// `engine` must be live and `count` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v1_transport_count(
    engine: *const HnsDaneEngine,
    count: *mut usize,
) -> i32 {
    ffi_guard(|| {
        if count.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires a live engine handle.
        let engine = unsafe { engine_ref(engine)? };
        let length = engine
            .engine
            .transport_plan()
            .map_err(map_engine_error)?
            .as_slice()
            .len();
        // SAFETY: count is required writable by the caller contract.
        unsafe {
            count.write(length);
        }
        Ok(())
    })
}

/// Read one current transport candidate by index.
///
/// # Safety
///
/// `engine` must be live and `transport` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v1_transport_at(
    engine: *const HnsDaneEngine,
    index: usize,
    transport: *mut u8,
) -> i32 {
    ffi_guard(|| {
        if transport.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires a live engine handle.
        let engine = unsafe { engine_ref(engine)? };
        let plan = engine.engine.transport_plan().map_err(map_engine_error)?;
        let value = plan
            .as_slice()
            .get(index)
            .copied()
            .ok_or(HnsDaneStatus::InvalidArgument)?;
        // SAFETY: transport is required writable by the caller contract.
        unsafe {
            transport.write(value as u8);
        }
        Ok(())
    })
}

/// Admit one exact class-IN query on one transport.
///
/// # Safety
///
/// `engine` must be live. `name` must reference `name_len` readable UTF-8
/// bytes. `output` must be writable and becomes caller-owned on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v1_admit(
    engine: *const HnsDaneEngine,
    transport: u8,
    query_id: u16,
    name: *const u8,
    name_len: usize,
    record_type: u16,
    output: *mut *mut HnsDaneAttempt,
) -> i32 {
    ffi_guard(|| {
        if name.is_null() || output.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires a live engine handle.
        let engine = unsafe { engine_ref(engine)? };
        // SAFETY: name is required to reference name_len readable bytes.
        let name_bytes = unsafe { slice::from_raw_parts(name, name_len) };
        let name_text = str::from_utf8(name_bytes).map_err(|_| HnsDaneStatus::InvalidArgument)?;
        let query = Query::new(
            query_id,
            Name::from_ascii(name_text).map_err(|_| HnsDaneStatus::InvalidArgument)?,
            RecordType::from_code(record_type),
        )
        .map_err(|_| HnsDaneStatus::InvalidArgument)?;
        let attempt = engine
            .engine
            .admit_resolution(
                ResolutionTransport::try_from(transport).map_err(map_policy_error)?,
                query,
            )
            .map_err(map_engine_error)?;
        let attempt = Box::new(AttemptHandle { attempt });
        // SAFETY: output is writable and receives ownership of the allocation.
        unsafe {
            output.write(Box::into_raw(attempt).cast::<HnsDaneAttempt>());
        }
        Ok(())
    })
}

/// Parse, correlate, and locally match one TLSA response and certificate.
///
/// `prerequisite_mask` bits 0, 1, 4, and 5 represent HNS proof, DNSSEC, chain
/// currency, and SNI respectively. TLSA and DANE cannot be asserted by the
/// caller: they are derived from the correlated response and certificate.
/// `context` may be null only for a direct transport.
///
/// # Safety
///
/// `engine` and `attempt` must be live handles. `response` must reference
/// `response_len` readable bytes. `certificate_der` must reference
/// `certificate_der_len` readable bytes. `output` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hns_dane_engine_v1_validate_response(
    engine: *const HnsDaneEngine,
    attempt: *const HnsDaneAttempt,
    response: *const u8,
    response_len: usize,
    certificate_der: *const u8,
    certificate_der_len: usize,
    context: *const HnsDaneTransportContextV1,
    prerequisite_mask: u32,
    output: *mut HnsDaneResultV1,
) -> i32 {
    ffi_guard(|| {
        if response.is_null() || certificate_der.is_null() || output.is_null() {
            return Err(HnsDaneStatus::NullPointer);
        }
        // SAFETY: The caller contract requires live engine and attempt handles.
        let engine = unsafe { engine_ref(engine)? };
        // SAFETY: The caller contract requires a live admitted-attempt handle.
        let attempt = unsafe { attempt_ref(attempt)? };
        // SAFETY: response is required to reference response_len readable bytes.
        let bytes = unsafe { slice::from_raw_parts(response, response_len) };
        // SAFETY: certificate_der must reference certificate_der_len readable bytes.
        let certificate = unsafe { slice::from_raw_parts(certificate_der, certificate_der_len) };
        let parsed = engine
            .engine
            .parse_response(&attempt.attempt, bytes, ParseLimits::requester())
            .map_err(map_engine_error)?;
        let prerequisites = prerequisites_from_mask(prerequisite_mask)?;
        let context = if context.is_null() {
            CompletionContext::default()
        } else {
            // SAFETY: A nonnull context is required to reference one readable structure.
            context_from_ffi(unsafe { &*context })?
        };
        let answer_count =
            u16::try_from(parsed.message().answers.len()).map_err(|_| HnsDaneStatus::Internal)?;
        let completed = engine
            .engine
            .complete_resolution_with_local_dane(
                &attempt.attempt,
                &parsed,
                prerequisites,
                certificate,
                DaneLimits::default(),
                context,
            )
            .map_err(map_engine_error)?;
        let provenance = completed.provenance().clone();
        let dane_match = completed.dane_match();
        let record_index =
            u16::try_from(dane_match.record_index()).map_err(|_| HnsDaneStatus::Internal)?;
        let result = HnsDaneResultV1 {
            struct_size: size_u32::<HnsDaneResultV1>()?,
            schema_version: provenance.schema_version,
            transport: provenance.transport as u8,
            untrusted_ad_claim: u8::from(provenance.untrusted_ad_claim),
            runtime_generation: provenance.runtime_generation,
            policy_generation: provenance.policy_generation,
            event_sequence: provenance.event_sequence,
            answer_count,
            tlsa_record_index: record_index,
            tlsa_usage: dane_match.usage() as u8,
            tlsa_selector: dane_match.selector() as u8,
            tlsa_matching_type: dane_match.matching_type() as u8,
            reserved: 0,
        };
        // SAFETY: output is required writable by the caller contract.
        unsafe {
            output.write(result);
        }
        Ok(())
    })
}

fn ffi_guard(operation: impl FnOnce() -> Result<(), HnsDaneStatus>) -> i32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => HnsDaneStatus::Ok.code(),
        Ok(Err(status)) => status.code(),
        Err(_) => HnsDaneStatus::PanicContained.code(),
    }
}

unsafe fn engine_ref<'a>(engine: *const HnsDaneEngine) -> Result<&'a EngineHandle, HnsDaneStatus> {
    if engine.is_null() {
        return Err(HnsDaneStatus::NullPointer);
    }
    // SAFETY: The caller guarantees this is a live handle from create.
    Ok(unsafe { &*engine.cast::<EngineHandle>() })
}

unsafe fn attempt_ref<'a>(
    attempt: *const HnsDaneAttempt,
) -> Result<&'a AttemptHandle, HnsDaneStatus> {
    if attempt.is_null() {
        return Err(HnsDaneStatus::NullPointer);
    }
    // SAFETY: The caller guarantees this is a live handle from admit.
    Ok(unsafe { &*attempt.cast::<AttemptHandle>() })
}

unsafe fn provider_authority_ref<'a>(
    authority: *const HnsDaneProviderAuthority,
) -> Result<&'a ProviderAuthorityHandle, HnsDaneStatus> {
    if authority.is_null() {
        return Err(HnsDaneStatus::NullPointer);
    }
    // SAFETY: The caller guarantees this is a live handle from the Rust handoff.
    Ok(unsafe { &*authority.cast::<ProviderAuthorityHandle>() })
}

fn provider_authority_info(
    authority: &ProviderAuthorityContext,
) -> Result<HnsDaneProviderAuthorityInfoV1, HnsDaneStatus> {
    Ok(HnsDaneProviderAuthorityInfoV1 {
        struct_size: size_u32::<HnsDaneProviderAuthorityInfoV1>()?,
        abi_version: PROVIDER_AUTHORITY_ABI_VERSION_V1,
        origin_scheme: authority.logical_origin().scheme() as u8,
        selected_namespace: authority.selected_namespace() as u8,
        authenticated_context: authority.authenticated_context() as u8,
        hns_network: authority.hns_network() as u8,
        tls_policy: authority.tls_policy() as u8,
        reserved0: 0,
        origin_port: authority.logical_origin().port(),
        service_port: authority.service_port(),
        reserved1: [0; 6],
        runtime_session: authority.runtime_session(),
        runtime_generation: authority.runtime_generation(),
        policy_generation: authority.policy_generation(),
        event_sequence: authority.event_sequence(),
        decision_fingerprint: authority.decision_fingerprint(),
        valid_from: authority.valid_from(),
        valid_until: authority.valid_until(),
        reserved: [0; 8],
    })
}

fn network_from_u8(value: u8) -> Result<Network, HnsDaneStatus> {
    match value {
        0 => Ok(Network::Mainnet),
        1 => Ok(Network::Testnet),
        2 => Ok(Network::Regtest),
        3 => Ok(Network::Simnet),
        _ => Err(HnsDaneStatus::InvalidArgument),
    }
}

fn authority_state_from_u8(value: u8) -> Result<AuthorityState, HnsDaneStatus> {
    match value {
        0 => Ok(AuthorityState::Uninitialized),
        1 => Ok(AuthorityState::LocalStateOpened),
        2 => Ok(AuthorityState::HeaderSyncing),
        3 => Ok(AuthorityState::HeaderCurrent),
        4 => Ok(AuthorityState::ProofReady),
        5 => Ok(AuthorityState::ResolutionTransportReady),
        6 => Ok(AuthorityState::DnssecVerified),
        7 => Ok(AuthorityState::DaneOriginVerified),
        8 => Ok(AuthorityState::BrowserBridgeReady),
        9 => Ok(AuthorityState::Active),
        10 => Ok(AuthorityState::Degraded),
        11 => Ok(AuthorityState::Revoked),
        12 => Ok(AuthorityState::Stopped),
        _ => Err(HnsDaneStatus::InvalidArgument),
    }
}

fn policy_to_ffi_v1(snapshot: PolicySnapshot) -> HnsDanePolicyV1 {
    let config = snapshot.config();
    HnsDanePolicyV1 {
        struct_size: u32::try_from(std::mem::size_of::<HnsDanePolicyV1>()).unwrap_or(u32::MAX),
        abi_version: ABI_VERSION,
        generation: snapshot.generation(),
        dns_relay_requester: config.dns_relay_requester as u8,
        oblivious_dns: config.oblivious_dns as u8,
        hnsr: config.hnsr.bits(),
        wire_profile: config.wire_profile as u8,
        authenticated_authoritative_doh: u8::from(config.authenticated_authoritative_doh),
        allow_legacy_regtest_compatibility: u8::from(config.allow_legacy_regtest_compatibility),
        provider_flags: provider_flags(config.providers),
        reserved: [0; 8],
    }
}

fn policy_to_ffi_v2(snapshot: PolicySnapshot) -> HnsDanePolicyV2 {
    let config = snapshot.config();
    HnsDanePolicyV2 {
        struct_size: u32::try_from(std::mem::size_of::<HnsDanePolicyV2>()).unwrap_or(u32::MAX),
        abi_version: POLICY_ABI_VERSION_V2,
        generation: snapshot.generation(),
        dns_relay_requester: config.dns_relay_requester as u8,
        oblivious_dns: config.oblivious_dns as u8,
        hnsr: config.hnsr.bits(),
        wire_profile: config.wire_profile as u8,
        authenticated_authoritative_doh: u8::from(config.authenticated_authoritative_doh),
        allow_legacy_regtest_compatibility: u8::from(config.allow_legacy_regtest_compatibility),
        provider_flags: provider_flags(config.providers),
        user_configured_recursive_hns_doh: u8::from(config.user_configured_recursive_hns_doh),
        reserved: [0; 7],
    }
}

fn policy_from_ffi_v1(policy: HnsDanePolicyV1) -> Result<(u64, PolicyConfig), HnsDaneStatus> {
    if policy.struct_size != size_u32::<HnsDanePolicyV1>()?
        || policy.abi_version != ABI_VERSION
        || policy.reserved != [0; 8]
        || policy.provider_flags & !PROVIDER_KNOWN != 0
        || policy.authenticated_authoritative_doh > 1
        || policy.allow_legacy_regtest_compatibility > 1
    {
        return Err(HnsDaneStatus::AbiMismatch);
    }
    Ok((
        policy.generation,
        PolicyConfig {
            dns_relay_requester: DnsRelayRequesterPolicy::try_from(policy.dns_relay_requester)
                .map_err(map_policy_error)?,
            oblivious_dns: ObliviousDnsPolicy::try_from(policy.oblivious_dns)
                .map_err(map_policy_error)?,
            hnsr: HnsrPolicy::from_bits(policy.hnsr).map_err(map_policy_error)?,
            authenticated_authoritative_doh: policy.authenticated_authoritative_doh != 0,
            user_configured_recursive_hns_doh: false,
            providers: providers_from_flags(policy.provider_flags),
            wire_profile: WireProfile::try_from(policy.wire_profile).map_err(map_policy_error)?,
            allow_legacy_regtest_compatibility: policy.allow_legacy_regtest_compatibility != 0,
        },
    ))
}

fn policy_from_ffi_v2(policy: HnsDanePolicyV2) -> Result<(u64, PolicyConfig), HnsDaneStatus> {
    if policy.struct_size != size_u32::<HnsDanePolicyV2>()?
        || policy.abi_version != POLICY_ABI_VERSION_V2
        || policy.reserved != [0; 7]
        || policy.provider_flags & !PROVIDER_KNOWN != 0
        || policy.authenticated_authoritative_doh > 1
        || policy.allow_legacy_regtest_compatibility > 1
        || policy.user_configured_recursive_hns_doh > 1
    {
        return Err(HnsDaneStatus::AbiMismatch);
    }
    Ok((
        policy.generation,
        PolicyConfig {
            dns_relay_requester: DnsRelayRequesterPolicy::try_from(policy.dns_relay_requester)
                .map_err(map_policy_error)?,
            oblivious_dns: ObliviousDnsPolicy::try_from(policy.oblivious_dns)
                .map_err(map_policy_error)?,
            hnsr: HnsrPolicy::from_bits(policy.hnsr).map_err(map_policy_error)?,
            authenticated_authoritative_doh: policy.authenticated_authoritative_doh != 0,
            user_configured_recursive_hns_doh: policy.user_configured_recursive_hns_doh != 0,
            providers: providers_from_flags(policy.provider_flags),
            wire_profile: WireProfile::try_from(policy.wire_profile).map_err(map_policy_error)?,
            allow_legacy_regtest_compatibility: policy.allow_legacy_regtest_compatibility != 0,
        },
    ))
}

const fn provider_flags(providers: ProviderPolicy) -> u16 {
    (if providers.dns_relay {
        PROVIDER_DNS_RELAY
    } else {
        0
    }) | (if providers.odoh_proxy {
        PROVIDER_ODOH_PROXY
    } else {
        0
    }) | (if providers.odoh_target {
        PROVIDER_ODOH_TARGET
    } else {
        0
    }) | (if providers.market_gossip {
        PROVIDER_MARKET_GOSSIP
    } else {
        0
    })
}

const fn providers_from_flags(flags: u16) -> ProviderPolicy {
    ProviderPolicy {
        dns_relay: flags & PROVIDER_DNS_RELAY != 0,
        odoh_proxy: flags & PROVIDER_ODOH_PROXY != 0,
        odoh_target: flags & PROVIDER_ODOH_TARGET != 0,
        market_gossip: flags & PROVIDER_MARKET_GOSSIP != 0,
    }
}

fn effects_to_bits(effects: hns_resolution_policy::PolicyChangeEffects) -> u32 {
    (if effects.stop_admitting_disabled_work {
        EFFECT_STOP_DISABLED
    } else {
        0
    }) | (if effects.cancel_or_drain_inflight {
        EFFECT_CANCEL_OR_DRAIN
    } else {
        0
    }) | (if effects.clear_requester_selections {
        EFFECT_CLEAR_REQUESTER
    } else {
        0
    }) | (if effects.withdraw_advertisements {
        EFFECT_WITHDRAW_ADVERTISEMENTS
    } else {
        0
    }) | (if effects.withdraw_hnsr_routes {
        EFFECT_WITHDRAW_HNSR
    } else {
        0
    }) | (if effects.revoke_target_configurations {
        EFFECT_REVOKE_TARGETS
    } else {
        0
    }) | (if effects.renegotiate_peer_connections {
        EFFECT_RENEGOTIATE
    } else {
        0
    }) | (if effects.update_structured_status {
        EFFECT_UPDATE_STATUS
    } else {
        0
    })
}

const fn evidence_state(mask: u32, bit: u32) -> EvidenceState {
    if mask & bit != 0 {
        EvidenceState::Verified
    } else {
        EvidenceState::Unavailable
    }
}

fn prerequisites_from_mask(mask: u32) -> Result<LocalDanePrerequisites, HnsDaneStatus> {
    if mask & !PREREQUISITES_ALL_VERIFIED != 0 {
        return Err(HnsDaneStatus::InvalidArgument);
    }
    Ok(LocalDanePrerequisites {
        hns_proof: evidence_state(mask, 1 << 0),
        dnssec: evidence_state(mask, 1 << 1),
        chain_current: evidence_state(mask, 1 << 4),
        origin_sni: evidence_state(mask, 1 << 5),
    })
}

fn context_from_ffi(
    context: &HnsDaneTransportContextV1,
) -> Result<CompletionContext, HnsDaneStatus> {
    if context.struct_size != size_u32::<HnsDaneTransportContextV1>()?
        || context.abi_version != ABI_VERSION
        || context.reserved != 0
        || context.direct_relay_fallback > 1
    {
        return Err(HnsDaneStatus::AbiMismatch);
    }
    Ok(CompletionContext {
        chain_anchor: None,
        peer_identity: decode_identity(&context.peer_identity, context.peer_identity_len)?,
        proxy_identity: decode_identity(&context.proxy_identity, context.proxy_identity_len)?,
        target_identity: decode_identity(&context.target_identity, context.target_identity_len)?,
        direct_relay_fallback: context.direct_relay_fallback != 0,
    })
}

fn decode_identity(
    storage: &[u8; ABI_IDENTITY_CAPACITY],
    length: u16,
) -> Result<Option<String>, HnsDaneStatus> {
    let length = usize::from(length);
    if length > storage.len() {
        return Err(HnsDaneStatus::InvalidArgument);
    }
    if length == 0 {
        return Ok(None);
    }
    let text = str::from_utf8(
        storage
            .get(..length)
            .ok_or(HnsDaneStatus::InvalidArgument)?,
    )
    .map_err(|_| HnsDaneStatus::InvalidArgument)?;
    Ok(Some(text.to_owned()))
}

fn size_u32<T>() -> Result<u32, HnsDaneStatus> {
    u32::try_from(std::mem::size_of::<T>()).map_err(|_| HnsDaneStatus::Internal)
}

fn map_policy_error(error: PolicyError) -> HnsDaneStatus {
    match error {
        PolicyError::StaleGeneration => HnsDaneStatus::StaleGeneration,
        PolicyError::TransportDisabled => HnsDaneStatus::TransportDisabled,
        PolicyError::UnverifiedEvidence => HnsDaneStatus::EvidenceRejected,
        PolicyError::InvalidEncoding
        | PolicyError::UnsupportedSchema
        | PolicyError::ChecksumMismatch
        | PolicyError::ZeroGeneration
        | PolicyError::ConflictingPolicies => HnsDaneStatus::InvalidArgument,
        _ => HnsDaneStatus::Internal,
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err requires ownership while nested policy errors are moved without cloning"
)]
fn map_engine_error(error: EngineError) -> HnsDaneStatus {
    match error {
        EngineError::AuthorityNotReady | EngineError::InvalidAuthorityTransition => {
            HnsDaneStatus::AuthorityNotReady
        }
        EngineError::StaleRuntimeGeneration => HnsDaneStatus::StaleGeneration,
        EngineError::ResponseAttemptMismatch
        | EngineError::UnsuccessfulDnsResponse
        | EngineError::Wire(_) => HnsDaneStatus::DnsRejected,
        EngineError::Dane(_) => HnsDaneStatus::EvidenceRejected,
        EngineError::ExpectedTlsaQuery
        | EngineError::InvalidRuntimeSession
        | EngineError::MissingTransportIdentity
        | EngineError::InvalidTransportIdentity
        | EngineError::ProxyTargetNotSeparated
        | EngineError::InvalidCompletionContext => HnsDaneStatus::InvalidArgument,
        EngineError::Policy(error) => map_policy_error(error),
        _ => HnsDaneStatus::Internal,
    }
}

#[cfg(test)]
#[allow(
    clippy::borrow_as_ptr,
    clippy::too_many_lines,
    clippy::undocumented_unsafe_blocks,
    clippy::unwrap_used,
    reason = "tests pass stack addresses through complete audited ABI flows and fail immediately on invariants"
)]
mod tests {
    use super::*;
    use hns_dane_engine::{
        AuthenticatedContextStatus, HnsNetwork, IcannOriginAuthentication,
        IcannOriginAuthenticationRequest, Namespace, NamespaceDecision, OriginScheme,
        TlsTrustPolicy,
    };
    use hns_dns_wire::{Flags, Header, Message, Rdata, ResourceRecord, Tlsa};
    use hns_namespace_resolution::{
        AbsenceKind, ApplicationProtocol, CanonicalHost, EvidenceProvenance, Freshness,
        IcannChainState, OriginPlanInput, OriginQuery, ProtocolCapabilities, RootLookup,
        SelectionPolicy, ServiceBinding, ServiceBindingInput, ServiceTransport, ValidatedAbsence,
        ValidatedOriginPlan, decide_namespace,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::ptr;
    use std::sync::Arc;

    const PROVIDER_AUTHORITY_NOW: u64 = 1_700_000_000;

    fn decode_hex(input: &str) -> Vec<u8> {
        let compact: Vec<u8> = input
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        assert!(compact.len().is_multiple_of(2));
        compact
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                u8::try_from((high << 4) | low).unwrap()
            })
            .collect()
    }

    fn provider_authority_ffi_engine(session: [u8; 16]) -> Engine {
        let engine = Engine::new(EngineConfig {
            runtime_session: RuntimeSessionId::new(session).unwrap(),
            network: Network::Regtest,
            policy: PolicySnapshot::default(),
        });
        for state in [
            AuthorityState::LocalStateOpened,
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
            AuthorityState::DnssecVerified,
            AuthorityState::BrowserBridgeReady,
            AuthorityState::Active,
        ] {
            engine.advance_authority_state(state).unwrap();
        }
        engine
    }

    fn provider_authority_ffi_decision(host: &str) -> NamespaceDecision {
        let query = OriginQuery::new(
            CanonicalHost::parse(host).unwrap(),
            OriginScheme::Https,
            None,
            ProtocolCapabilities::all(),
        );
        let target = query.host().clone();
        let port = query.origin_port();
        let freshness =
            Freshness::new(PROVIDER_AUTHORITY_NOW - 10, PROVIDER_AUTHORITY_NOW + 100).unwrap();
        let service = ServiceBinding::new(ServiceBindingInput {
            priority: None,
            service_target: target.clone(),
            mandatory_keys: Vec::new(),
            advertised_alpn: Vec::new(),
            selected_protocol: ApplicationProtocol::Http11,
            effective_port: port,
            transport: ServiceTransport::Tcp,
            connection_hints: Vec::new(),
            ech_config: None,
            parameters: Vec::new(),
        })
        .unwrap();
        let icann = ValidatedOriginPlan::new(OriginPlanInput {
            namespace: Namespace::Icann,
            query: query.clone(),
            alias_path: Vec::new(),
            terminal_target: target.clone(),
            endpoint_alias_path: Vec::new(),
            endpoint_target: target,
            endpoints: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                port.get(),
            )],
            service,
            tls_policy: TlsTrustPolicy::WebPkiAuthenticatedAbsence,
            tlsa_records: Vec::new(),
            provenance: EvidenceProvenance::IcannDoh {
                chain_state: IcannChainState::Secure,
            },
            freshness,
        })
        .unwrap();
        let hns_absence = ValidatedAbsence::new(
            Namespace::Hns,
            query.clone(),
            AbsenceKind::HnsCurrentUrkelNonInclusion,
            EvidenceProvenance::Hns {
                network: HnsNetwork::Regtest,
                tree_root: [21; 32],
                height: 42,
            },
            freshness,
        )
        .unwrap();
        decide_namespace(
            &query,
            RootLookup::Absent(hns_absence),
            RootLookup::Present(icann),
            SelectionPolicy::default(),
            PROVIDER_AUTHORITY_NOW,
        )
        .unwrap()
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "the deterministic test principal implements the optional authenticator result"
    )]
    fn provider_authority_ffi_webpki(
        request: &IcannOriginAuthenticationRequest,
    ) -> Option<IcannOriginAuthentication> {
        Some(request.attest_webpki_verified())
    }

    fn provider_authority_ffi_context(
        engine: &Engine,
        decision: &NamespaceDecision,
    ) -> ProviderAuthorityContext {
        let context = engine
            .bind_icann_origin_context(
                decision,
                &provider_authority_ffi_webpki,
                PROVIDER_AUTHORITY_NOW,
            )
            .unwrap();
        engine
            .authorize_provider_injection(decision, &context, PROVIDER_AUTHORITY_NOW)
            .unwrap()
            .into_context()
            .unwrap()
    }

    #[test]
    fn provider_authority_ffi_projects_and_checks_authorized_handle() {
        assert_eq!(std::mem::size_of::<HnsDaneProviderAuthorityInfoV1>(), 120);
        assert_eq!(
            hns_dane_engine_provider_v1_abi_version(),
            PROVIDER_AUTHORITY_ABI_VERSION_V1
        );

        let engine = Arc::new(provider_authority_ffi_engine([41; 16]));
        let decision = provider_authority_ffi_decision("wallet.example");
        let authority = provider_authority_ffi_context(&engine, &decision);
        let authority = provider_authority_into_ffi(Arc::clone(&engine), authority);
        assert!(!authority.is_null());

        let mut info = HnsDaneProviderAuthorityInfoV1::default();
        // SAFETY: authority is live and info is writable local storage.
        assert_eq!(
            unsafe { hns_dane_engine_provider_v1_authority_get_info(authority, &mut info) },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(info.struct_size, 120);
        assert_eq!(info.abi_version, PROVIDER_AUTHORITY_ABI_VERSION_V1);
        assert_eq!(info.origin_scheme, OriginScheme::Https as u8);
        assert_eq!(info.selected_namespace, Namespace::Icann as u8);
        assert_eq!(
            info.authenticated_context,
            AuthenticatedContextStatus::IcannWebPkiAuthenticatedAbsence as u8
        );
        assert_eq!(info.hns_network, HnsNetwork::Regtest as u8);
        assert_eq!(
            info.tls_policy,
            TlsTrustPolicy::WebPkiAuthenticatedAbsence as u8
        );
        assert_eq!(info.origin_port, 443);
        assert_eq!(info.service_port, 443);
        assert_eq!(info.runtime_session, [41; 16]);
        assert_eq!(info.runtime_generation, 1);
        assert_eq!(info.policy_generation, 1);
        assert_ne!(info.event_sequence, 0);
        assert_ne!(info.decision_fingerprint, [0; 32]);
        assert_eq!(info.valid_from, PROVIDER_AUTHORITY_NOW);
        assert_eq!(info.valid_until, PROVIDER_AUTHORITY_NOW + 100);
        assert_eq!(info.reserved0, 0);
        assert_eq!(info.reserved1, [0; 6]);
        assert_eq!(info.reserved, [0; 8]);

        let mut required = 0usize;
        // SAFETY: authority is live and required is writable local storage.
        assert_eq!(
            unsafe {
                hns_dane_engine_provider_v1_authority_copy_host(
                    authority,
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            HnsDaneStatus::BufferTooSmall.code()
        );
        assert_eq!(required, b"wallet.example".len());
        let mut host = vec![0; required];
        // SAFETY: authority is live, host has the reported capacity, and required is writable.
        assert_eq!(
            unsafe {
                hns_dane_engine_provider_v1_authority_copy_host(
                    authority,
                    host.as_mut_ptr(),
                    host.len(),
                    &mut required,
                )
            },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(host.as_slice(), b"wallet.example");

        let mut current = 0;
        // SAFETY: authority is live and current is writable.
        assert_eq!(
            unsafe {
                hns_dane_engine_provider_v1_authority_is_current(
                    authority,
                    PROVIDER_AUTHORITY_NOW,
                    &mut current,
                )
            },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(current, 1);

        let unrelated_query = Query::new(
            0x4040,
            Name::from_ascii("_443._tcp.other.example").unwrap(),
            RecordType::Tlsa,
        )
        .unwrap();
        engine
            .admit_resolution(ResolutionTransport::DirectAuthoritativeTcp, unrelated_query)
            .unwrap();
        // SAFETY: authority remains live and current is writable.
        assert_eq!(
            unsafe {
                hns_dane_engine_provider_v1_authority_is_current(
                    authority,
                    PROVIDER_AUTHORITY_NOW,
                    &mut current,
                )
            },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(current, 1);

        let authority_engine = Arc::new(provider_authority_ffi_engine([42; 16]));
        let authority_decision = provider_authority_ffi_decision("mismatch.example");
        let mismatched_authority =
            provider_authority_ffi_context(&authority_engine, &authority_decision);
        let mismatched_engine = Arc::new(provider_authority_ffi_engine([43; 16]));
        let mismatched_engine_lifetime = Arc::downgrade(&mismatched_engine);
        let mismatched_authority =
            provider_authority_into_ffi(mismatched_engine, mismatched_authority);
        assert!(mismatched_engine_lifetime.upgrade().is_some());
        // SAFETY: mismatched_authority is live and current is writable.
        assert_eq!(
            unsafe {
                hns_dane_engine_provider_v1_authority_is_current(
                    mismatched_authority,
                    PROVIDER_AUTHORITY_NOW,
                    &mut current,
                )
            },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(current, 0);
        // SAFETY: mismatched_authority is its still-live caller-owned allocation.
        assert_eq!(
            unsafe { hns_dane_engine_provider_v1_authority_destroy(mismatched_authority) },
            HnsDaneStatus::Ok.code()
        );
        assert!(mismatched_engine_lifetime.upgrade().is_none());

        // SAFETY: authority is live and current is writable.
        assert_eq!(
            unsafe {
                hns_dane_engine_provider_v1_authority_is_current(
                    authority,
                    PROVIDER_AUTHORITY_NOW + 100,
                    &mut current,
                )
            },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(current, 0);

        engine
            .advance_authority_state(AuthorityState::Degraded)
            .unwrap();
        for state in [
            AuthorityState::HeaderSyncing,
            AuthorityState::HeaderCurrent,
            AuthorityState::ProofReady,
            AuthorityState::ResolutionTransportReady,
            AuthorityState::BrowserBridgeReady,
            AuthorityState::Active,
        ] {
            engine.advance_authority_state(state).unwrap();
        }
        // SAFETY: authority is live and current is writable.
        assert_eq!(
            unsafe {
                hns_dane_engine_provider_v1_authority_is_current(
                    authority,
                    PROVIDER_AUTHORITY_NOW,
                    &mut current,
                )
            },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(current, 0);

        // SAFETY: each pointer is its still-live caller-owned allocation.
        assert_eq!(
            unsafe { hns_dane_engine_provider_v1_authority_destroy(authority) },
            HnsDaneStatus::Ok.code()
        );
    }

    #[test]
    fn provider_authority_ffi_rejects_nulls_without_constructing_authority() {
        let mut info = HnsDaneProviderAuthorityInfoV1::default();
        let mut written = 0usize;
        let mut current = 0u8;
        // SAFETY: null inputs are explicitly admitted for fail-closed validation.
        assert_eq!(
            unsafe {
                hns_dane_engine_provider_v1_authority_get_info(ptr::null(), &mut info)
            },
            HnsDaneStatus::NullPointer.code()
        );
        // SAFETY: null inputs are explicitly admitted for fail-closed validation.
        assert_eq!(
            unsafe {
                hns_dane_engine_provider_v1_authority_copy_host(
                    ptr::null(),
                    ptr::null_mut(),
                    0,
                    &mut written,
                )
            },
            HnsDaneStatus::NullPointer.code()
        );
        // SAFETY: null inputs are explicitly admitted for fail-closed validation.
        assert_eq!(
            unsafe {
                hns_dane_engine_provider_v1_authority_is_current(
                    ptr::null(),
                    PROVIDER_AUTHORITY_NOW,
                    &mut current,
                )
            },
            HnsDaneStatus::NullPointer.code()
        );
        // SAFETY: destroying a null provider-authority handle is explicitly a no-op.
        assert_eq!(
            unsafe { hns_dane_engine_provider_v1_authority_destroy(ptr::null_mut()) },
            HnsDaneStatus::Ok.code()
        );
    }

    #[test]
    fn c_abi_rejects_zero_runtime_session() {
        let session = [0u8; 16];
        let mut engine = ptr::null_mut();
        // SAFETY: All pointers reference live local storage of the documented sizes.
        let status = unsafe {
            hns_dane_engine_v1_create(
                session.as_ptr(),
                Network::Mainnet as u8,
                ptr::null(),
                0,
                &mut engine,
            )
        };
        assert_eq!(status, HnsDaneStatus::InvalidArgument.code());
        assert!(engine.is_null());
    }

    #[test]
    fn c_abi_policy_round_trip_and_provider_default() {
        assert_eq!(std::mem::size_of::<HnsDanePolicyV1>(), 32);
        assert_eq!(std::mem::size_of::<HnsDanePolicyV2>(), 32);
        assert_eq!(std::mem::size_of::<HnsDaneTransportContextV1>(), 400);
        assert_eq!(std::mem::size_of::<HnsDaneResultV1>(), 40);
        assert_eq!(hns_dane_engine_v1_abi_version(), ABI_VERSION);
        assert_eq!(hns_dane_engine_v2_abi_version(), POLICY_ABI_VERSION_V2);

        let session = [9u8; 16];
        let mut engine = ptr::null_mut();
        // SAFETY: All pointers reference live local storage of the documented sizes.
        let status = unsafe {
            hns_dane_engine_v1_create(
                session.as_ptr(),
                Network::Mainnet as u8,
                ptr::null(),
                0,
                &mut engine,
            )
        };
        assert_eq!(status, HnsDaneStatus::Ok.code());
        assert!(!engine.is_null());

        let mut policy = HnsDanePolicyV1::default();
        // SAFETY: engine is live and policy is writable.
        assert_eq!(
            unsafe { hns_dane_engine_v1_get_policy(engine, &mut policy) },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(policy.hnsr, HnsrPolicy::client_relay_default().bits());
        assert_eq!(policy.provider_flags, PROVIDER_ODOH_PROXY);
        assert_eq!(policy.provider_flags & PROVIDER_ODOH_TARGET, 0);
        policy.dns_relay_requester = DnsRelayRequesterPolicy::Disabled as u8;
        let mut generation = 0;
        let mut effects = 0;
        // SAFETY: engine and all structure/output pointers are live.
        assert_eq!(
            unsafe {
                hns_dane_engine_v1_set_policy(engine, &policy, &mut generation, &mut effects)
            },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(generation, 2);
        assert_ne!(effects & EFFECT_CANCEL_OR_DRAIN, 0);

        let mut required = 0usize;
        // SAFETY: engine is live and required is writable.
        assert_eq!(
            unsafe { hns_dane_engine_v1_export_policy(engine, ptr::null_mut(), 0, &mut required,) },
            HnsDaneStatus::BufferTooSmall.code()
        );
        assert_eq!(required, 32);

        // SAFETY: engine is the live allocation returned by create.
        assert_eq!(
            unsafe { hns_dane_engine_v1_destroy(engine) },
            HnsDaneStatus::Ok.code()
        );
    }

    #[test]
    fn policy_v2_exposes_consent_and_v1_can_only_fail_closed() {
        let session = [8u8; 16];
        let mut engine = ptr::null_mut();
        // SAFETY: All pointers reference live local storage of documented sizes.
        assert_eq!(
            unsafe {
                hns_dane_engine_v1_create(
                    session.as_ptr(),
                    Network::Mainnet as u8,
                    ptr::null(),
                    0,
                    &mut engine,
                )
            },
            HnsDaneStatus::Ok.code()
        );

        let mut policy_v2 = HnsDanePolicyV2::default();
        // SAFETY: engine is live and policy_v2 is writable.
        assert_eq!(
            unsafe { hns_dane_engine_v2_get_policy(engine, &mut policy_v2) },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(policy_v2.user_configured_recursive_hns_doh, 0);
        policy_v2.user_configured_recursive_hns_doh = 1;
        let mut generation = 0;
        let mut effects = 0;
        // SAFETY: engine and all structure/output pointers are live.
        assert_eq!(
            unsafe {
                hns_dane_engine_v2_set_policy(engine, &policy_v2, &mut generation, &mut effects)
            },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(generation, 2);
        assert_ne!(effects & EFFECT_CLEAR_REQUESTER, 0);

        let mut count = 0;
        // SAFETY: engine is live and count is writable.
        assert_eq!(
            unsafe { hns_dane_engine_v1_transport_count(engine, &mut count) },
            HnsDaneStatus::Ok.code()
        );
        let mut terminal = u8::MAX;
        // SAFETY: engine is live and terminal is writable.
        assert_eq!(
            unsafe { hns_dane_engine_v1_transport_at(engine, count - 1, &mut terminal) },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(
            terminal,
            ResolutionTransport::UserConfiguredRecursiveHnsDoh as u8
        );
        for state in 2..=5 {
            // SAFETY: engine is live and each state is the next valid transition.
            assert_eq!(
                unsafe { hns_dane_engine_v1_advance_authority(engine, state) },
                HnsDaneStatus::Ok.code()
            );
        }
        let owner = b"_443._tcp.example";
        let mut attempt = ptr::null_mut();
        // SAFETY: engine and output are live; owner is readable.
        assert_eq!(
            unsafe {
                hns_dane_engine_v1_admit(
                    engine,
                    ResolutionTransport::LocalHnsProof as u8,
                    1,
                    owner.as_ptr(),
                    owner.len(),
                    RecordType::Tlsa.code(),
                    &mut attempt,
                )
            },
            HnsDaneStatus::TransportDisabled.code()
        );
        assert!(attempt.is_null());

        let mut policy_v1 = HnsDanePolicyV1::default();
        // SAFETY: engine is live and policy_v1 is writable.
        assert_eq!(
            unsafe { hns_dane_engine_v1_get_policy(engine, &mut policy_v1) },
            HnsDaneStatus::AbiMismatch.code()
        );

        let enabled = PolicyConfig {
            user_configured_recursive_hns_doh: true,
            ..PolicyConfig::default()
        };
        policy_v1 = policy_to_ffi_v1(PolicySnapshot::new(generation, enabled).unwrap());
        // SAFETY: engine and all structure/output pointers are live. Policy V1
        // deliberately decodes its unrepresentable consent field as disabled.
        assert_eq!(
            unsafe {
                hns_dane_engine_v1_set_policy(engine, &policy_v1, &mut generation, &mut effects)
            },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(generation, 3);

        // SAFETY: engine is live and policy_v2 is writable.
        assert_eq!(
            unsafe { hns_dane_engine_v2_get_policy(engine, &mut policy_v2) },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(policy_v2.user_configured_recursive_hns_doh, 0);

        // SAFETY: engine is the live allocation returned by create.
        assert_eq!(
            unsafe { hns_dane_engine_v1_destroy(engine) },
            HnsDaneStatus::Ok.code()
        );
    }

    #[test]
    fn c_transport_context_requires_distinct_utf8_identities() {
        let mut context = HnsDaneTransportContextV1::default();
        context.proxy_identity[..5].copy_from_slice(b"proxy");
        context.proxy_identity_len = 5;
        context.target_identity[..6].copy_from_slice(b"target");
        context.target_identity_len = 6;

        let decoded = context_from_ffi(&context).unwrap();
        assert_eq!(decoded.proxy_identity.as_deref(), Some("proxy"));
        assert_eq!(decoded.target_identity.as_deref(), Some("target"));
    }

    #[test]
    fn c_abi_derives_dane_match_and_rejects_caller_dane_bits() {
        let session = [3u8; 16];
        let mut engine = ptr::null_mut();
        // SAFETY: All pointers reference live local storage of documented sizes.
        assert_eq!(
            unsafe {
                hns_dane_engine_v1_create(
                    session.as_ptr(),
                    Network::Mainnet as u8,
                    ptr::null(),
                    0,
                    &mut engine,
                )
            },
            HnsDaneStatus::Ok.code()
        );
        for state in 1..=6 {
            // SAFETY: engine is live and each state is the next valid transition.
            assert_eq!(
                unsafe { hns_dane_engine_v1_advance_authority(engine, state) },
                HnsDaneStatus::Ok.code()
            );
        }

        let owner = b"_443._tcp.example";
        let mut attempt = ptr::null_mut();
        // SAFETY: engine and output are live; owner is readable.
        assert_eq!(
            unsafe {
                hns_dane_engine_v1_admit(
                    engine,
                    ResolutionTransport::DirectAuthoritativeTcp as u8,
                    0x2345,
                    owner.as_ptr(),
                    owner.len(),
                    RecordType::Tlsa.code(),
                    &mut attempt,
                )
            },
            HnsDaneStatus::Ok.code()
        );

        let certificate = decode_hex(include_str!(
            "../../../fixtures/dane/self-signed-cert.der.hex"
        ));
        let query = Query::new(
            0x2345,
            Name::from_ascii("_443._tcp.example").unwrap(),
            RecordType::Tlsa,
        )
        .unwrap();
        let response = Message {
            header: Header {
                id: query.id,
                flags: Flags::from_bits(0x8400),
                question_count: 1,
                answer_count: 1,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![query.question.clone()],
            answers: vec![ResourceRecord {
                name: query.question.name,
                record_type: RecordType::Tlsa,
                class: hns_dns_wire::CLASS_IN,
                ttl: 300,
                rdata: Rdata::Tlsa(Tlsa {
                    usage: 3,
                    selector: 0,
                    matching_type: 0,
                    association_data: certificate.clone(),
                }),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode(u16::MAX.into())
        .unwrap();
        let mut result = HnsDaneResultV1::default();

        // SAFETY: Every pointer references readable/writable local storage.
        assert_eq!(
            unsafe {
                hns_dane_engine_v1_validate_response(
                    engine,
                    attempt,
                    response.as_ptr(),
                    response.len(),
                    certificate.as_ptr(),
                    certificate.len(),
                    ptr::null(),
                    0x3f,
                    &mut result,
                )
            },
            HnsDaneStatus::InvalidArgument.code()
        );
        // SAFETY: Every pointer references readable/writable local storage.
        assert_eq!(
            unsafe {
                hns_dane_engine_v1_validate_response(
                    engine,
                    attempt,
                    response.as_ptr(),
                    response.len(),
                    certificate.as_ptr(),
                    certificate.len(),
                    ptr::null(),
                    PREREQUISITES_ALL_VERIFIED,
                    &mut result,
                )
            },
            HnsDaneStatus::Ok.code()
        );
        assert_eq!(result.tlsa_record_index, 0);
        assert_eq!(result.tlsa_usage, 3);
        assert_eq!(result.tlsa_selector, 0);
        assert_eq!(result.tlsa_matching_type, 0);

        // SAFETY: handles are the live allocations returned above.
        assert_eq!(
            unsafe { hns_dane_engine_v1_attempt_destroy(attempt) },
            HnsDaneStatus::Ok.code()
        );
        // SAFETY: handle is the live allocation returned above.
        assert_eq!(
            unsafe { hns_dane_engine_v1_destroy(engine) },
            HnsDaneStatus::Ok.code()
        );
    }
}
