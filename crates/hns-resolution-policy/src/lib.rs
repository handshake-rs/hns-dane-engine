//! Persistent, typed HNS resolution policy and evidence provenance.
//!
//! The transport plan deliberately has no operating-system or implicit
//! public-recursive candidate. Explicit user consent may add one configured
//! recursive HNS DoH transport as the terminal candidate. A policy mutation
//! increments the generation, and completion under a stale generation is
//! rejected even if a path is later re-enabled.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    reason = "protocol acronyms, shared PolicyError, and explicit effect fields are intentional"
)]

use std::fmt;

const PERSISTED_MAGIC: &[u8; 8] = b"HNSPOL1\0";
const PERSISTED_SCHEMA: u16 = 3;
const PERSISTED_SCHEMA_V2: u16 = 2;
const LEGACY_PERSISTED_SCHEMA: u16 = 1;
const PERSISTED_PAYLOAD_LEN: u16 = 16;
/// Exact encoded policy snapshot length.
pub const PERSISTED_POLICY_LEN: usize = 32;

/// P2P DNS Relay requester behavior.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsRelayRequesterPolicy {
    /// Permit relay only in the policy-selected fallback position.
    Auto = 0,
    /// Never select or transmit through a DNS relay.
    Disabled = 1,
    /// Require relay as the terminal fallback if direct authority fails.
    Required = 2,
}

impl TryFrom<u8> for DnsRelayRequesterPolicy {
    type Error = PolicyError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Auto),
            1 => Ok(Self::Disabled),
            2 => Ok(Self::Required),
            _ => Err(PolicyError::InvalidEncoding),
        }
    }
}

/// P2P Oblivious DNS requester behavior.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObliviousDnsPolicy {
    /// ODoH must be the only experimental fallback.
    Required = 0,
    /// Prefer ODoH and prohibit privacy downgrade to direct relay.
    Preferred = 1,
    /// Prefer ODoH and permit a final direct-relay fallback.
    DirectRelayAllowed = 2,
    /// Never select or transmit through ODoH.
    Disabled = 3,
}

impl TryFrom<u8> for ObliviousDnsPolicy {
    type Error = PolicyError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Required),
            1 => Ok(Self::Preferred),
            2 => Ok(Self::DirectRelayAllowed),
            3 => Ok(Self::Disabled),
            _ => Err(PolicyError::InvalidEncoding),
        }
    }
}

/// Independent HNSR participation roles.
///
/// Requester/client and opaque relay participation default on and remain
/// independently opt-out. Endpoint/output and rendezvous roles require
/// separate explicit enablement, so one role can never grant another
/// implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsrPolicy {
    bits: u8,
}

impl HnsrPolicy {
    const CLIENT: u8 = 1 << 0;
    const ENDPOINT: u8 = 1 << 1;
    const RELAY: u8 = 1 << 2;
    const RENDEZVOUS: u8 = 1 << 3;
    const KNOWN_BITS: u8 = Self::CLIENT | Self::ENDPOINT | Self::RELAY | Self::RENDEZVOUS;

    /// Disable every HNSR role.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { bits: 0 }
    }

    /// Default to opaque relay participation only.
    #[must_use]
    pub const fn relay_default() -> Self {
        Self { bits: Self::RELAY }
    }

    /// Default to requester/client and opaque relay participation.
    #[must_use]
    pub const fn client_relay_default() -> Self {
        Self::relay_default().with_requester(true)
    }

    /// Set requester/client participation independently.
    #[must_use]
    pub const fn with_requester(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, Self::CLIENT, enabled);
        self
    }

    /// Set endpoint/output-node participation independently.
    #[must_use]
    pub const fn with_endpoint(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, Self::ENDPOINT, enabled);
        self
    }

    /// Set opaque relay participation independently.
    #[must_use]
    pub const fn with_relay(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, Self::RELAY, enabled);
        self
    }

    /// Set rendezvous-directory participation independently.
    #[must_use]
    pub const fn with_rendezvous(mut self, enabled: bool) -> Self {
        self.bits = set_flag(self.bits, Self::RENDEZVOUS, enabled);
        self
    }

    /// Whether this mode permits requester activity.
    #[must_use]
    pub const fn requester_enabled(self) -> bool {
        self.bits & Self::CLIENT != 0
    }

    /// Whether endpoint/output-node activity is enabled.
    #[must_use]
    pub const fn endpoint_enabled(self) -> bool {
        self.bits & Self::ENDPOINT != 0
    }

    /// Whether opaque relay activity is enabled.
    #[must_use]
    pub const fn relay_enabled(self) -> bool {
        self.bits & Self::RELAY != 0
    }

    /// Whether rendezvous-directory activity is enabled.
    #[must_use]
    pub const fn rendezvous_enabled(self) -> bool {
        self.bits & Self::RENDEZVOUS != 0
    }

    /// Whether this mode advertises any provider capability.
    #[must_use]
    pub const fn provider_enabled(self) -> bool {
        self.provider_bits() != 0
    }

    /// Stable role bit representation for persistence and platform ABIs.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.bits
    }

    /// Decode independent role bits.
    pub const fn from_bits(bits: u8) -> Result<Self, PolicyError> {
        if bits & !Self::KNOWN_BITS != 0 {
            Err(PolicyError::InvalidEncoding)
        } else {
            Ok(Self { bits })
        }
    }

    const fn provider_bits(self) -> u8 {
        self.bits & (Self::ENDPOINT | Self::RELAY | Self::RENDEZVOUS)
    }
}

impl Default for HnsrPolicy {
    fn default() -> Self {
        Self::client_relay_default()
    }
}

const fn set_flag(bits: u8, flag: u8, enabled: bool) -> u8 {
    if enabled { bits | flag } else { bits & !flag }
}

const fn legacy_hnsr_policy(value: u8) -> Result<HnsrPolicy, PolicyError> {
    match value {
        0 => Ok(HnsrPolicy::disabled()),
        1 => Ok(HnsrPolicy::disabled().with_requester(true)),
        2 => Ok(HnsrPolicy::disabled().with_endpoint(true)),
        3 => Ok(HnsrPolicy::disabled().with_relay(true)),
        4 => Ok(HnsrPolicy::disabled().with_rendezvous(true)),
        5 => Ok(HnsrPolicy::disabled()
            .with_requester(true)
            .with_endpoint(true)),
        6 => Ok(HnsrPolicy::disabled()
            .with_requester(true)
            .with_endpoint(true)
            .with_relay(true)
            .with_rendezvous(true)),
        _ => Err(PolicyError::InvalidEncoding),
    }
}

/// Experimental assignment profile.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireProfile {
    /// Denuo Experimental V1, not an official Handshake assignment.
    DenuoV1 = 0,
    /// Future official assignment profile.
    Official = 1,
    /// Negotiate supported profiles without silent packet-number reuse.
    Auto = 2,
}

impl TryFrom<u8> for WireProfile {
    type Error = PolicyError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::DenuoV1),
            1 => Ok(Self::Official),
            2 => Ok(Self::Auto),
            _ => Err(PolicyError::InvalidEncoding),
        }
    }
}

/// Provider roles with opaque proxying default-on and output roles default-off.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderPolicy {
    /// Offer bounded P2P DNS relay capacity.
    pub dns_relay: bool,
    /// Offer P2P ODoH proxy capacity.
    pub odoh_proxy: bool,
    /// Offer P2P ODoH target capacity.
    pub odoh_target: bool,
    /// Advertise market gossip while the market service is active.
    pub market_gossip: bool,
}

impl Default for ProviderPolicy {
    fn default() -> Self {
        Self {
            dns_relay: false,
            odoh_proxy: true,
            odoh_target: false,
            market_gossip: false,
        }
    }
}

impl ProviderPolicy {
    const DNS_RELAY: u16 = 1 << 0;
    const ODOH_PROXY: u16 = 1 << 1;
    const ODOH_TARGET: u16 = 1 << 2;
    const MARKET_GOSSIP: u16 = 1 << 3;
    const KNOWN_BITS: u16 =
        Self::DNS_RELAY | Self::ODOH_PROXY | Self::ODOH_TARGET | Self::MARKET_GOSSIP;

    const fn bits(self) -> u16 {
        (if self.dns_relay { Self::DNS_RELAY } else { 0 })
            | (if self.odoh_proxy { Self::ODOH_PROXY } else { 0 })
            | (if self.odoh_target {
                Self::ODOH_TARGET
            } else {
                0
            })
            | (if self.market_gossip {
                Self::MARKET_GOSSIP
            } else {
                0
            })
    }

    fn from_bits(bits: u16) -> Result<Self, PolicyError> {
        if bits & !Self::KNOWN_BITS != 0 {
            return Err(PolicyError::InvalidEncoding);
        }
        Ok(Self {
            dns_relay: bits & Self::DNS_RELAY != 0,
            odoh_proxy: bits & Self::ODOH_PROXY != 0,
            odoh_target: bits & Self::ODOH_TARGET != 0,
            market_gossip: bits & Self::MARKET_GOSSIP != 0,
        })
    }
}

/// Complete runtime policy, without persistence metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyConfig {
    /// P2P DNS Relay requester policy.
    pub dns_relay_requester: DnsRelayRequesterPolicy,
    /// P2P ODoH requester policy.
    pub oblivious_dns: ObliviousDnsPolicy,
    /// Independent HNSR requester/provider roles.
    pub hnsr: HnsrPolicy,
    /// Permit proof-authenticated authoritative DoH after direct UDP/TCP.
    pub authenticated_authoritative_doh: bool,
    /// Permit an explicitly user-configured recursive HNS DoH terminal fallback.
    pub user_configured_recursive_hns_doh: bool,
    /// Independent provider controls.
    pub providers: ProviderPolicy,
    /// Experimental assignment profile.
    pub wire_profile: WireProfile,
    /// Permit specifically bounded legacy compatibility on regtest only.
    pub allow_legacy_regtest_compatibility: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            dns_relay_requester: DnsRelayRequesterPolicy::Auto,
            oblivious_dns: ObliviousDnsPolicy::DirectRelayAllowed,
            hnsr: HnsrPolicy::default(),
            authenticated_authoritative_doh: true,
            user_configured_recursive_hns_doh: false,
            providers: ProviderPolicy::default(),
            wire_profile: WireProfile::Auto,
            allow_legacy_regtest_compatibility: true,
        }
    }
}

impl PolicyConfig {
    /// Validate combinations whose individual typed controls conflict.
    pub const fn validate(self) -> Result<(), PolicyError> {
        if matches!(
            self.oblivious_dns,
            ObliviousDnsPolicy::Required | ObliviousDnsPolicy::Preferred
        ) && matches!(self.dns_relay_requester, DnsRelayRequesterPolicy::Required)
        {
            return Err(PolicyError::ConflictingPolicies);
        }
        Ok(())
    }
}

/// Persistent policy with a monotonic generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicySnapshot {
    generation: u64,
    config: PolicyConfig,
}

impl Default for PolicySnapshot {
    fn default() -> Self {
        Self {
            generation: 1,
            config: PolicyConfig::default(),
        }
    }
}

impl PolicySnapshot {
    /// Construct a checked snapshot.
    pub const fn new(generation: u64, config: PolicyConfig) -> Result<Self, PolicyError> {
        if generation == 0 {
            return Err(PolicyError::ZeroGeneration);
        }
        if config.validate().is_err() {
            return Err(PolicyError::ConflictingPolicies);
        }
        Ok(Self { generation, config })
    }

    /// Nonzero policy generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Typed policy.
    #[must_use]
    pub const fn config(self) -> PolicyConfig {
        self.config
    }

    /// Encode the versioned, checksummed persistence representation.
    #[must_use]
    pub fn encode(self) -> [u8; PERSISTED_POLICY_LEN] {
        let mut output = [0u8; PERSISTED_POLICY_LEN];
        output[..8].copy_from_slice(PERSISTED_MAGIC);
        output[8..10].copy_from_slice(&PERSISTED_SCHEMA.to_be_bytes());
        output[10..12].copy_from_slice(&PERSISTED_PAYLOAD_LEN.to_be_bytes());
        output[12..20].copy_from_slice(&self.generation.to_be_bytes());
        output[20] = self.config.dns_relay_requester as u8;
        output[21] = self.config.oblivious_dns as u8;
        output[22] = self.config.hnsr.bits();
        output[23] = self.config.wire_profile as u8;
        output[24..26].copy_from_slice(&self.config.providers.bits().to_be_bytes());
        let settings = u16::from(self.config.authenticated_authoritative_doh)
            | (u16::from(self.config.allow_legacy_regtest_compatibility) << 1)
            | (u16::from(self.config.user_configured_recursive_hns_doh) << 2);
        output[26..28].copy_from_slice(&settings.to_be_bytes());
        let checksum = crc32(&output[..28]);
        output[28..32].copy_from_slice(&checksum.to_be_bytes());
        output
    }

    /// Decode a versioned snapshot, rejecting unknown flags and corruption.
    pub fn decode(input: &[u8]) -> Result<Self, PolicyError> {
        if input.len() != PERSISTED_POLICY_LEN || input.get(..8) != Some(PERSISTED_MAGIC.as_slice())
        {
            return Err(PolicyError::InvalidEncoding);
        }
        let schema = read_u16(input, 8)?;
        if !matches!(
            schema,
            LEGACY_PERSISTED_SCHEMA | PERSISTED_SCHEMA_V2 | PERSISTED_SCHEMA
        ) || read_u16(input, 10)? != PERSISTED_PAYLOAD_LEN
        {
            return Err(PolicyError::UnsupportedSchema);
        }
        let expected_crc = read_u32(input, 28)?;
        if crc32(input.get(..28).ok_or(PolicyError::InvalidEncoding)?) != expected_crc {
            return Err(PolicyError::ChecksumMismatch);
        }
        let generation = read_u64(input, 12)?;
        if generation == 0 {
            return Err(PolicyError::ZeroGeneration);
        }
        let provider_bits = read_u16(input, 24)?;
        let settings = read_u16(input, 26)?;
        let known_settings = if schema == PERSISTED_SCHEMA {
            0b111
        } else {
            0b011
        };
        if settings & !known_settings != 0 {
            return Err(PolicyError::InvalidEncoding);
        }
        let hnsr = if schema == LEGACY_PERSISTED_SCHEMA {
            legacy_hnsr_policy(byte(input, 22)?)?
        } else {
            HnsrPolicy::from_bits(byte(input, 22)?)?
        };
        let config = PolicyConfig {
            dns_relay_requester: DnsRelayRequesterPolicy::try_from(byte(input, 20)?)?,
            oblivious_dns: ObliviousDnsPolicy::try_from(byte(input, 21)?)?,
            hnsr,
            wire_profile: WireProfile::try_from(byte(input, 23)?)?,
            providers: ProviderPolicy::from_bits(provider_bits)?,
            authenticated_authoritative_doh: settings & 1 != 0,
            user_configured_recursive_hns_doh: schema == PERSISTED_SCHEMA && settings & 4 != 0,
            allow_legacy_regtest_compatibility: settings & 2 != 0,
        };
        Self::new(generation, config)
    }
}

/// Actual DNS transport, separate from validation authority.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResolutionTransport {
    /// UDP to a proof-derived delegated authority.
    DirectAuthoritativeUdp = 0,
    /// TCP to a proof-derived delegated authority.
    DirectAuthoritativeTcp = 1,
    /// DoH endpoint authenticated from local HNS/DNSSEC evidence.
    AuthenticatedAuthoritativeDoh = 2,
    /// Denuo Experimental V1 ODoH intermediary path.
    HandshakeP2pOdoh = 3,
    /// Denuo Experimental V1 recursive relay path.
    HandshakeP2pDnsRelay = 4,
    /// No transport succeeded.
    Unavailable = 5,
    /// TLS-authenticated validating DoH for the ICANN namespace.
    ///
    /// This is status provenance for the separate ICANN path and is never a
    /// candidate in the fail-closed HNS [`TransportPlan`].
    ValidatingIcannDoh = 6,
    /// Explicitly user-configured recursive HNS DoH recovery transport.
    ///
    /// This is admitted only when the current policy binds affirmative user
    /// consent. It is always terminal in the fail-closed HNS [`TransportPlan`].
    UserConfiguredRecursiveHnsDoh = 7,
    /// Origin data obtained directly from a locally verified HNS name proof.
    ///
    /// This is status provenance for a proof-contained result and is never a
    /// network candidate in the fail-closed HNS [`TransportPlan`].
    LocalHnsProof = 8,
}

impl TryFrom<u8> for ResolutionTransport {
    type Error = PolicyError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::DirectAuthoritativeUdp),
            1 => Ok(Self::DirectAuthoritativeTcp),
            2 => Ok(Self::AuthenticatedAuthoritativeDoh),
            3 => Ok(Self::HandshakeP2pOdoh),
            4 => Ok(Self::HandshakeP2pDnsRelay),
            5 => Ok(Self::Unavailable),
            6 => Ok(Self::ValidatingIcannDoh),
            7 => Ok(Self::UserConfiguredRecursiveHnsDoh),
            8 => Ok(Self::LocalHnsProof),
            _ => Err(PolicyError::InvalidEncoding),
        }
    }
}

/// Ordered, fail-closed transport candidates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportPlan {
    transports: Vec<ResolutionTransport>,
}

impl TransportPlan {
    /// Construct the direct-authoritative-first plan for a policy.
    #[must_use]
    pub fn for_policy(config: PolicyConfig) -> Self {
        let mut transports = vec![
            ResolutionTransport::DirectAuthoritativeUdp,
            ResolutionTransport::DirectAuthoritativeTcp,
        ];
        if config.authenticated_authoritative_doh {
            transports.push(ResolutionTransport::AuthenticatedAuthoritativeDoh);
        }
        if config.oblivious_dns != ObliviousDnsPolicy::Disabled {
            transports.push(ResolutionTransport::HandshakeP2pOdoh);
        }
        let relay_allowed = match config.oblivious_dns {
            ObliviousDnsPolicy::Required | ObliviousDnsPolicy::Preferred => false,
            ObliviousDnsPolicy::DirectRelayAllowed | ObliviousDnsPolicy::Disabled => {
                config.dns_relay_requester != DnsRelayRequesterPolicy::Disabled
            }
        };
        if relay_allowed {
            transports.push(ResolutionTransport::HandshakeP2pDnsRelay);
        }
        if config.user_configured_recursive_hns_doh {
            transports.push(ResolutionTransport::UserConfiguredRecursiveHnsDoh);
        }
        Self { transports }
    }

    /// Ordered candidates. No OS or implicit public-recursive candidate is
    /// admitted here.
    #[must_use]
    pub fn as_slice(&self) -> &[ResolutionTransport] {
        &self.transports
    }

    /// Whether the plan admits a transport.
    #[must_use]
    pub fn contains(&self, transport: ResolutionTransport) -> bool {
        self.transports.contains(&transport)
    }
}

/// Generation-bound permission to start one transport attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admission {
    /// Policy generation at admission.
    pub policy_generation: u64,
    /// Admitted transport.
    pub transport: ResolutionTransport,
}

/// Required runtime actions after a policy mutation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyChangeEffects {
    /// Immediately stop admitting newly disabled work.
    pub stop_admitting_disabled_work: bool,
    /// Cancel or safely drain stale in-flight work.
    pub cancel_or_drain_inflight: bool,
    /// Clear cached requester path selections.
    pub clear_requester_selections: bool,
    /// Withdraw removed provider advertisements.
    pub withdraw_advertisements: bool,
    /// Withdraw removed HNSR routes.
    pub withdraw_hnsr_routes: bool,
    /// Revoke disabled ODoH target configurations.
    pub revoke_target_configurations: bool,
    /// Reconnect affected peers to renegotiate version service bits.
    pub renegotiate_peer_connections: bool,
    /// Publish updated structured status.
    pub update_structured_status: bool,
}

/// Result of replacing policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyTransition {
    /// Previous snapshot.
    pub previous: PolicySnapshot,
    /// Current snapshot.
    pub current: PolicySnapshot,
    /// Whether effective policy changed.
    pub changed: bool,
    /// Actions adapters must execute.
    pub effects: PolicyChangeEffects,
}

/// Deterministic policy controller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyController {
    current: PolicySnapshot,
}

impl PolicyController {
    /// Open from a checked persisted snapshot.
    #[must_use]
    pub const fn new(snapshot: PolicySnapshot) -> Self {
        Self { current: snapshot }
    }

    /// Current snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> PolicySnapshot {
        self.current
    }

    /// Ordered current transport plan.
    #[must_use]
    pub fn transport_plan(&self) -> TransportPlan {
        TransportPlan::for_policy(self.current.config)
    }

    /// Admit work only if the current policy contains its transport.
    pub fn admit(&self, transport: ResolutionTransport) -> Result<Admission, PolicyError> {
        if transport == ResolutionTransport::Unavailable
            || !self.transport_plan().contains(transport)
        {
            return Err(PolicyError::TransportDisabled);
        }
        Ok(Admission {
            policy_generation: self.current.generation,
            transport,
        })
    }

    /// Validate an in-flight completion against current generation and policy.
    pub fn accept_completion(&self, admission: Admission) -> Result<(), PolicyError> {
        if admission.policy_generation != self.current.generation {
            return Err(PolicyError::StaleGeneration);
        }
        if !self.transport_plan().contains(admission.transport) {
            return Err(PolicyError::TransportDisabled);
        }
        Ok(())
    }

    /// Replace policy using optimistic generation matching.
    pub fn replace(
        &mut self,
        expected_generation: u64,
        next_config: PolicyConfig,
    ) -> Result<PolicyTransition, PolicyError> {
        if expected_generation != self.current.generation {
            return Err(PolicyError::StaleGeneration);
        }
        next_config.validate()?;
        let previous = self.current;
        if previous.config == next_config {
            return Ok(PolicyTransition {
                previous,
                current: previous,
                changed: false,
                effects: PolicyChangeEffects::default(),
            });
        }
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or(PolicyError::GenerationExhausted)?;
        let current = PolicySnapshot {
            generation,
            config: next_config,
        };
        let effects = transition_effects(previous.config, next_config);
        self.current = current;
        Ok(PolicyTransition {
            previous,
            current,
            changed: true,
            effects,
        })
    }
}

fn transition_effects(previous: PolicyConfig, current: PolicyConfig) -> PolicyChangeEffects {
    let requester_changed = previous.dns_relay_requester != current.dns_relay_requester
        || previous.oblivious_dns != current.oblivious_dns
        || previous.authenticated_authoritative_doh != current.authenticated_authoritative_doh
        || previous.user_configured_recursive_hns_doh != current.user_configured_recursive_hns_doh
        || previous.hnsr.requester_enabled() != current.hnsr.requester_enabled();
    let hnsr_providers_changed = previous.hnsr.provider_bits() != current.hnsr.provider_bits();
    let providers_changed = previous.providers != current.providers || hnsr_providers_changed;
    let removed_provider = (previous.providers.bits() & !current.providers.bits()) != 0
        || (previous.hnsr.provider_bits() & !current.hnsr.provider_bits()) != 0;
    PolicyChangeEffects {
        stop_admitting_disabled_work: true,
        cancel_or_drain_inflight: true,
        clear_requester_selections: requester_changed,
        withdraw_advertisements: removed_provider,
        withdraw_hnsr_routes: (previous.hnsr.provider_bits() & !current.hnsr.provider_bits()) != 0,
        revoke_target_configurations: previous.providers.odoh_target
            && !current.providers.odoh_target,
        renegotiate_peer_connections: providers_changed
            || previous.wire_profile != current.wire_profile,
        update_structured_status: true,
    }
}

/// Explicit local evidence state for browser observability.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceState {
    /// Locally verified.
    Verified = 0,
    /// Locally checked and failed.
    Failed = 1,
    /// No acceptable evidence was available.
    Unavailable = 2,
    /// The required evidence form or algorithm is unsupported.
    Unsupported = 3,
    /// Validation has not been attempted.
    NotAttempted = 4,
    /// Previously valid evidence is no longer current.
    Stale = 5,
    /// Evidence was invalidated by a policy or runtime generation change.
    Revoked = 6,
}

/// Local validation evidence required for HNS HTTPS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationEvidence {
    /// Verified Handshake state and Urkel proof.
    pub hns_proof: EvidenceState,
    /// Locally verified DNSSEC chain.
    pub dnssec: EvidenceState,
    /// Exact supported TLSA result.
    pub tlsa: EvidenceState,
    /// Local DANE origin result.
    pub dane: EvidenceState,
    /// Chain currency sufficiency.
    pub chain_current: EvidenceState,
    /// Origin SNI match.
    pub origin_sni: EvidenceState,
}

impl ValidationEvidence {
    /// Initial state before any HNS HTTPS validation work.
    #[must_use]
    pub const fn not_attempted() -> Self {
        Self {
            hns_proof: EvidenceState::NotAttempted,
            dnssec: EvidenceState::NotAttempted,
            tlsa: EvidenceState::NotAttempted,
            dane: EvidenceState::NotAttempted,
            chain_current: EvidenceState::NotAttempted,
            origin_sni: EvidenceState::NotAttempted,
        }
    }

    /// State after a policy/runtime generation revokes prior work.
    #[must_use]
    pub const fn revoked() -> Self {
        Self {
            hns_proof: EvidenceState::Revoked,
            dnssec: EvidenceState::Revoked,
            tlsa: EvidenceState::Revoked,
            dane: EvidenceState::Revoked,
            chain_current: EvidenceState::Revoked,
            origin_sni: EvidenceState::Revoked,
        }
    }

    /// Whether all required local evidence is verified.
    #[must_use]
    pub const fn fully_verified(self) -> bool {
        matches!(self.hns_proof, EvidenceState::Verified)
            && matches!(self.dnssec, EvidenceState::Verified)
            && matches!(self.tlsa, EvidenceState::Verified)
            && matches!(self.dane, EvidenceState::Verified)
            && matches!(self.chain_current, EvidenceState::Verified)
            && matches!(self.origin_sni, EvidenceState::Verified)
    }
}

/// Handshake network.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    /// Main network.
    Mainnet = 0,
    /// Public test network.
    Testnet = 1,
    /// Local regression network.
    Regtest = 2,
    /// In-memory simulation network.
    Simnet = 3,
}

/// Locally authenticated chain anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainAnchor {
    /// Validated header height.
    pub height: u32,
    /// Validated name-tree root.
    pub tree_root: [u8; 32],
}

/// Structured resolution provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionProvenance {
    /// Status schema version.
    pub schema_version: u16,
    /// Caller-supplied runtime session identifier.
    pub runtime_session: [u8; 16],
    /// Runtime generation.
    pub runtime_generation: u64,
    /// Policy generation.
    pub policy_generation: u64,
    /// Monotonic event sequence.
    pub event_sequence: u64,
    /// Handshake network.
    pub network: Network,
    /// Locally validated chain anchor, if available.
    pub chain_anchor: Option<ChainAnchor>,
    /// Actual selected transport.
    pub transport: ResolutionTransport,
    /// Remote relay peer identity, if applicable.
    pub peer_identity: Option<String>,
    /// ODoH proxy identity, if applicable.
    pub proxy_identity: Option<String>,
    /// ODoH target identity, if applicable.
    pub target_identity: Option<String>,
    /// Whether privacy downgraded to direct relay.
    pub direct_relay_fallback: bool,
    /// Experimental assignment profile.
    pub registry_profile: WireProfile,
    /// Local validation evidence.
    pub evidence: ValidationEvidence,
    /// Whether a remote DNS response asserted AD.
    pub untrusted_ad_claim: bool,
}

impl ResolutionProvenance {
    /// Require all local HNS HTTPS evidence, independent of transport.
    pub const fn require_verified_hns_https(&self) -> Result<(), PolicyError> {
        if self.evidence.fully_verified() {
            Ok(())
        } else {
            Err(PolicyError::UnverifiedEvidence)
        }
    }
}

/// Policy, persistence, admission, or evidence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PolicyError {
    /// Persisted bytes are malformed or contain unknown bits.
    InvalidEncoding,
    /// Persisted schema is not supported.
    UnsupportedSchema,
    /// Persisted checksum does not match.
    ChecksumMismatch,
    /// Generations must start at one.
    ZeroGeneration,
    /// A generation comparison failed.
    StaleGeneration,
    /// No later generation can be represented.
    GenerationExhausted,
    /// The selected transport is disabled.
    TransportDisabled,
    /// Required local HNS/DNSSEC/TLSA/DANE evidence is not all verified.
    UnverifiedEvidence,
    /// Typed requester policies express mutually exclusive requirements.
    ConflictingPolicies,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid persisted policy encoding",
            Self::UnsupportedSchema => "unsupported persisted policy schema",
            Self::ChecksumMismatch => "persisted policy checksum mismatch",
            Self::ZeroGeneration => "policy generation must be nonzero",
            Self::StaleGeneration => "stale policy generation",
            Self::GenerationExhausted => "policy generation exhausted",
            Self::TransportDisabled => "transport is disabled by policy",
            Self::UnverifiedEvidence => "required local validation evidence is not verified",
            Self::ConflictingPolicies => "requester policy requirements conflict",
        })
    }
}

impl std::error::Error for PolicyError {}

fn crc32(input: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in input {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn byte(input: &[u8], offset: usize) -> Result<u8, PolicyError> {
    input
        .get(offset)
        .copied()
        .ok_or(PolicyError::InvalidEncoding)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, PolicyError> {
    let value: [u8; 2] = input
        .get(offset..offset + 2)
        .ok_or(PolicyError::InvalidEncoding)?
        .try_into()
        .map_err(|_| PolicyError::InvalidEncoding)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, PolicyError> {
    let value: [u8; 4] = input
        .get(offset..offset + 4)
        .ok_or(PolicyError::InvalidEncoding)?
        .try_into()
        .map_err(|_| PolicyError::InvalidEncoding)?;
    Ok(u32::from_be_bytes(value))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, PolicyError> {
    let value: [u8; 8] = input
        .get(offset..offset + 8)
        .ok_or(PolicyError::InvalidEncoding)?
        .try_into()
        .map_err(|_| PolicyError::InvalidEncoding)?;
    Ok(u64::from_be_bytes(value))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests intentionally fail immediately on invalid fixtures"
)]
mod tests {
    use super::*;

    #[test]
    fn transport_discriminants_are_stable_and_recursive_doh_requires_consent() {
        assert_eq!(ResolutionTransport::DirectAuthoritativeUdp as u8, 0);
        assert_eq!(ResolutionTransport::DirectAuthoritativeTcp as u8, 1);
        assert_eq!(ResolutionTransport::AuthenticatedAuthoritativeDoh as u8, 2);
        assert_eq!(ResolutionTransport::HandshakeP2pOdoh as u8, 3);
        assert_eq!(ResolutionTransport::HandshakeP2pDnsRelay as u8, 4);
        assert_eq!(ResolutionTransport::Unavailable as u8, 5);
        assert_eq!(ResolutionTransport::ValidatingIcannDoh as u8, 6);
        assert_eq!(ResolutionTransport::UserConfiguredRecursiveHnsDoh as u8, 7);
        assert_eq!(ResolutionTransport::LocalHnsProof as u8, 8);
        assert_eq!(
            ResolutionTransport::try_from(6).unwrap(),
            ResolutionTransport::ValidatingIcannDoh
        );
        assert_eq!(
            ResolutionTransport::try_from(7).unwrap(),
            ResolutionTransport::UserConfiguredRecursiveHnsDoh
        );
        assert_eq!(
            ResolutionTransport::try_from(8).unwrap(),
            ResolutionTransport::LocalHnsProof
        );
        assert!(
            !TransportPlan::for_policy(PolicyConfig::default())
                .contains(ResolutionTransport::ValidatingIcannDoh)
        );
        assert!(
            !TransportPlan::for_policy(PolicyConfig::default())
                .contains(ResolutionTransport::UserConfiguredRecursiveHnsDoh)
        );
        assert!(
            !TransportPlan::for_policy(PolicyConfig::default())
                .contains(ResolutionTransport::LocalHnsProof)
        );

        let config = PolicyConfig {
            user_configured_recursive_hns_doh: true,
            ..PolicyConfig::default()
        };
        let plan = TransportPlan::for_policy(config);
        assert_eq!(
            plan.as_slice().last(),
            Some(&ResolutionTransport::UserConfiguredRecursiveHnsDoh)
        );
        let controller = PolicyController::new(PolicySnapshot::new(1, config).unwrap());
        assert_eq!(
            controller.admit(ResolutionTransport::LocalHnsProof),
            Err(PolicyError::TransportDisabled)
        );
    }

    #[test]
    fn defaults_are_direct_first_with_client_relay_opt_out_and_output_opt_in() {
        let snapshot = PolicySnapshot::default();
        let plan = TransportPlan::for_policy(snapshot.config);

        assert_eq!(
            plan.as_slice(),
            &[
                ResolutionTransport::DirectAuthoritativeUdp,
                ResolutionTransport::DirectAuthoritativeTcp,
                ResolutionTransport::AuthenticatedAuthoritativeDoh,
                ResolutionTransport::HandshakeP2pOdoh,
                ResolutionTransport::HandshakeP2pDnsRelay,
            ]
        );
        assert!(!snapshot.config.providers.dns_relay);
        assert!(snapshot.config.providers.odoh_proxy);
        assert!(!snapshot.config.providers.odoh_target);
        assert!(snapshot.config.hnsr.relay_enabled());
        assert!(!snapshot.config.hnsr.endpoint_enabled());
        assert!(snapshot.config.hnsr.requester_enabled());
        assert!(!snapshot.config.hnsr.rendezvous_enabled());
        assert!(!snapshot.config.user_configured_recursive_hns_doh);
        assert_eq!(snapshot.config.wire_profile, WireProfile::Auto);
    }

    #[test]
    fn requester_opt_out_removes_every_hidden_path() {
        let config = PolicyConfig {
            dns_relay_requester: DnsRelayRequesterPolicy::Disabled,
            oblivious_dns: ObliviousDnsPolicy::Disabled,
            ..PolicyConfig::default()
        };
        let plan = TransportPlan::for_policy(config);

        assert!(!plan.contains(ResolutionTransport::HandshakeP2pOdoh));
        assert!(!plan.contains(ResolutionTransport::HandshakeP2pDnsRelay));
        assert_eq!(
            plan.as_slice(),
            &[
                ResolutionTransport::DirectAuthoritativeUdp,
                ResolutionTransport::DirectAuthoritativeTcp,
                ResolutionTransport::AuthenticatedAuthoritativeDoh,
            ]
        );
    }

    #[test]
    fn preferred_odoh_does_not_silently_downgrade_privacy() {
        let config = PolicyConfig {
            oblivious_dns: ObliviousDnsPolicy::Preferred,
            ..PolicyConfig::default()
        };
        let plan = TransportPlan::for_policy(config);

        assert!(plan.contains(ResolutionTransport::HandshakeP2pOdoh));
        assert!(!plan.contains(ResolutionTransport::HandshakeP2pDnsRelay));
    }

    #[test]
    fn conflicting_required_privacy_modes_are_rejected() {
        let config = PolicyConfig {
            dns_relay_requester: DnsRelayRequesterPolicy::Required,
            oblivious_dns: ObliviousDnsPolicy::Required,
            ..PolicyConfig::default()
        };
        assert_eq!(
            PolicySnapshot::new(1, config),
            Err(PolicyError::ConflictingPolicies)
        );

        let mut controller = PolicyController::new(PolicySnapshot::default());
        assert_eq!(
            controller.replace(1, config),
            Err(PolicyError::ConflictingPolicies)
        );
        assert_eq!(controller.snapshot(), PolicySnapshot::default());
    }

    #[test]
    fn snapshot_round_trips_and_detects_mutation() {
        let snapshot = PolicySnapshot::default();
        let encoded = snapshot.encode();
        assert_eq!(encoded.len(), PERSISTED_POLICY_LEN);
        assert_eq!(read_u16(&encoded, 8).unwrap(), PERSISTED_SCHEMA);
        assert_eq!(PolicySnapshot::decode(&encoded).unwrap(), snapshot);

        let mut mutated = encoded;
        mutated[21] ^= 1;
        assert_eq!(
            PolicySnapshot::decode(&mutated),
            Err(PolicyError::ChecksumMismatch)
        );

        let explicit_opt_out = PolicyConfig {
            dns_relay_requester: DnsRelayRequesterPolicy::Disabled,
            oblivious_dns: ObliviousDnsPolicy::Disabled,
            hnsr: HnsrPolicy::disabled(),
            providers: ProviderPolicy {
                dns_relay: false,
                odoh_proxy: false,
                odoh_target: false,
                market_gossip: false,
            },
            ..PolicyConfig::default()
        };
        let stored = PolicySnapshot::new(7, explicit_opt_out).unwrap().encode();
        assert_eq!(
            PolicySnapshot::decode(&stored).unwrap().config(),
            explicit_opt_out
        );
    }

    #[test]
    fn schema_three_round_trips_recursive_doh_consent_in_fixed_length() {
        let config = PolicyConfig {
            user_configured_recursive_hns_doh: true,
            ..PolicyConfig::default()
        };
        let snapshot = PolicySnapshot::new(9, config).unwrap();
        let encoded = snapshot.encode();

        assert_eq!(encoded.len(), 32);
        assert_eq!(read_u16(&encoded, 8).unwrap(), PERSISTED_SCHEMA);
        assert_eq!(read_u16(&encoded, 26).unwrap() & 4, 4);
        assert_eq!(PolicySnapshot::decode(&encoded).unwrap(), snapshot);
    }

    #[test]
    fn schema_two_migrates_without_granting_recursive_doh_consent() {
        let mut previous = PolicySnapshot::default().encode();
        previous[8..10].copy_from_slice(&PERSISTED_SCHEMA_V2.to_be_bytes());
        let checksum = crc32(&previous[..28]);
        previous[28..32].copy_from_slice(&checksum.to_be_bytes());

        let migrated = PolicySnapshot::decode(&previous).unwrap();

        assert!(!migrated.config().user_configured_recursive_hns_doh);
        assert_eq!(read_u16(&migrated.encode(), 8).unwrap(), PERSISTED_SCHEMA);

        let mut mislabeled = previous;
        let settings = read_u16(&mislabeled, 26).unwrap() | 4;
        mislabeled[26..28].copy_from_slice(&settings.to_be_bytes());
        let checksum = crc32(&mislabeled[..28]);
        mislabeled[28..32].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            PolicySnapshot::decode(&mislabeled),
            Err(PolicyError::InvalidEncoding)
        );
    }

    #[test]
    fn schema_one_roles_migrate_without_granting_new_consent() {
        let mut legacy = PolicySnapshot::default().encode();
        legacy[8..10].copy_from_slice(&LEGACY_PERSISTED_SCHEMA.to_be_bytes());
        legacy[22] = 0;
        legacy[24..26].copy_from_slice(&0u16.to_be_bytes());
        let checksum = crc32(&legacy[..28]);
        legacy[28..32].copy_from_slice(&checksum.to_be_bytes());

        let migrated = PolicySnapshot::decode(&legacy).unwrap();

        assert_eq!(migrated.generation(), 1);
        assert_eq!(migrated.config().hnsr, HnsrPolicy::disabled());
        assert!(!migrated.config().user_configured_recursive_hns_doh);
        assert_eq!(
            migrated.config().providers,
            ProviderPolicy {
                dns_relay: false,
                odoh_proxy: false,
                odoh_target: false,
                market_gossip: false,
            }
        );
        assert_eq!(read_u16(&migrated.encode(), 8).unwrap(), PERSISTED_SCHEMA);
    }

    #[test]
    fn schema_one_enum_values_are_not_reinterpreted_as_role_bits() {
        let mut legacy = PolicySnapshot::default().encode();
        legacy[8..10].copy_from_slice(&LEGACY_PERSISTED_SCHEMA.to_be_bytes());
        legacy[22] = 3;
        let checksum = crc32(&legacy[..28]);
        legacy[28..32].copy_from_slice(&checksum.to_be_bytes());

        let migrated = PolicySnapshot::decode(&legacy).unwrap().config().hnsr;

        assert!(migrated.relay_enabled());
        assert!(!migrated.requester_enabled());
        assert!(!migrated.endpoint_enabled());
        assert!(!migrated.rendezvous_enabled());

        let current = HnsrPolicy::from_bits(3).unwrap();
        assert!(current.requester_enabled());
        assert!(current.endpoint_enabled());
        assert!(!current.relay_enabled());
    }

    #[test]
    fn relay_and_output_node_consent_are_independent() {
        let client_relay = PolicyConfig::default();
        assert!(client_relay.hnsr.requester_enabled());
        assert!(client_relay.hnsr.relay_enabled());
        assert!(!client_relay.hnsr.endpoint_enabled());
        assert!(client_relay.providers.odoh_proxy);
        assert!(!client_relay.providers.odoh_target);

        let mut output_enabled = client_relay;
        output_enabled.hnsr = output_enabled.hnsr.with_endpoint(true);
        output_enabled.providers.odoh_target = true;
        assert!(output_enabled.hnsr.relay_enabled());
        assert!(output_enabled.hnsr.endpoint_enabled());

        output_enabled.hnsr = output_enabled.hnsr.with_relay(false);
        output_enabled.providers.odoh_proxy = false;
        assert!(!output_enabled.hnsr.relay_enabled());
        assert!(output_enabled.hnsr.endpoint_enabled());
        assert!(!output_enabled.providers.odoh_proxy);
        assert!(output_enabled.providers.odoh_target);
    }

    #[test]
    fn policy_change_revokes_stale_completions() {
        let mut controller = PolicyController::new(PolicySnapshot::default());
        let admission = controller
            .admit(ResolutionTransport::HandshakeP2pDnsRelay)
            .unwrap();
        let mut next = controller.snapshot().config;
        next.dns_relay_requester = DnsRelayRequesterPolicy::Disabled;
        let transition = controller.replace(1, next).unwrap();

        assert_eq!(transition.current.generation, 2);
        assert!(transition.effects.stop_admitting_disabled_work);
        assert!(transition.effects.cancel_or_drain_inflight);
        assert!(transition.effects.clear_requester_selections);
        assert_eq!(
            controller.accept_completion(admission),
            Err(PolicyError::StaleGeneration)
        );
        assert_eq!(
            controller.admit(ResolutionTransport::HandshakeP2pDnsRelay),
            Err(PolicyError::TransportDisabled)
        );
    }

    #[test]
    fn recursive_doh_opt_out_revokes_admission_and_stale_completion() {
        let enabled = PolicyConfig {
            user_configured_recursive_hns_doh: true,
            ..PolicyConfig::default()
        };
        let mut controller = PolicyController::new(PolicySnapshot::new(11, enabled).unwrap());
        let admission = controller
            .admit(ResolutionTransport::UserConfiguredRecursiveHnsDoh)
            .unwrap();
        let mut disabled = enabled;
        disabled.user_configured_recursive_hns_doh = false;

        let transition = controller.replace(11, disabled).unwrap();

        assert_eq!(transition.current.generation(), 12);
        assert!(transition.effects.stop_admitting_disabled_work);
        assert!(transition.effects.cancel_or_drain_inflight);
        assert!(transition.effects.clear_requester_selections);
        assert_eq!(
            controller.accept_completion(admission),
            Err(PolicyError::StaleGeneration)
        );
        assert_eq!(
            controller.admit(ResolutionTransport::UserConfiguredRecursiveHnsDoh),
            Err(PolicyError::TransportDisabled)
        );
    }

    #[test]
    fn provider_disable_requests_withdrawal_and_renegotiation() {
        let mut config = PolicyConfig::default();
        config.providers.dns_relay = true;
        config.providers.odoh_target = true;
        config.hnsr = HnsrPolicy::default()
            .with_requester(true)
            .with_endpoint(true)
            .with_rendezvous(true);
        let mut controller = PolicyController::new(PolicySnapshot::new(7, config).unwrap());
        let mut next = config;
        next.providers = ProviderPolicy {
            dns_relay: false,
            odoh_proxy: false,
            odoh_target: false,
            market_gossip: false,
        };
        next.hnsr = HnsrPolicy::disabled();
        let transition = controller.replace(7, next).unwrap();

        assert!(transition.effects.withdraw_advertisements);
        assert!(transition.effects.withdraw_hnsr_routes);
        assert!(transition.effects.revoke_target_configurations);
        assert!(transition.effects.renegotiate_peer_connections);
    }

    #[test]
    fn requester_change_does_not_mutate_provider_consent() {
        let mut config = PolicyConfig::default();
        config.hnsr = config.hnsr.with_requester(false);
        let mut controller = PolicyController::new(PolicySnapshot::new(4, config).unwrap());
        let mut next = config;
        next.hnsr = next.hnsr.with_requester(true);

        let transition = controller.replace(4, next).unwrap();

        assert!(transition.effects.clear_requester_selections);
        assert!(!transition.effects.withdraw_advertisements);
        assert!(!transition.effects.withdraw_hnsr_routes);
        assert!(!transition.effects.renegotiate_peer_connections);
        assert!(transition.current.config().hnsr.relay_enabled());
        assert!(transition.current.config().hnsr.requester_enabled());
    }

    #[test]
    fn identical_policy_does_not_churn_generation() {
        let mut controller = PolicyController::new(PolicySnapshot::default());
        let transition = controller.replace(1, PolicyConfig::default()).unwrap();

        assert!(!transition.changed);
        assert_eq!(transition.current.generation, 1);
        assert_eq!(transition.effects, PolicyChangeEffects::default());
    }

    #[test]
    fn transport_never_substitutes_for_local_evidence() {
        let provenance = ResolutionProvenance {
            schema_version: 1,
            runtime_session: [1; 16],
            runtime_generation: 1,
            policy_generation: 1,
            event_sequence: 1,
            network: Network::Mainnet,
            chain_anchor: None,
            transport: ResolutionTransport::HandshakeP2pOdoh,
            peer_identity: None,
            proxy_identity: Some("proxy".to_owned()),
            target_identity: Some("target".to_owned()),
            direct_relay_fallback: false,
            registry_profile: WireProfile::DenuoV1,
            evidence: ValidationEvidence {
                hns_proof: EvidenceState::Verified,
                dnssec: EvidenceState::Verified,
                tlsa: EvidenceState::Unavailable,
                dane: EvidenceState::Unavailable,
                chain_current: EvidenceState::Verified,
                origin_sni: EvidenceState::Verified,
            },
            untrusted_ad_claim: true,
        };

        assert_eq!(
            provenance.require_verified_hns_https(),
            Err(PolicyError::UnverifiedEvidence)
        );
    }
}
