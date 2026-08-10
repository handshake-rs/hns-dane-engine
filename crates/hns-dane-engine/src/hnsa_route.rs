//! Engine-bound verification for HNSA-authenticated named HNSR routes.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use hns_hnsr_protocol::{
    HNS_CHAT_V1, HNS_WEB_V1, HnsrProtocolError, HnsrRoute, MAX_RECORDS_PER_KEY, NamedRoutePolicy,
    NamedRouteRecordV2, NamedRouteTrust, named_route_key,
};
use hns_light_chain::{HnsAnchor, HnsResourceRecord, VerifiedHnsResource};
use hns_resolution_policy::Network;
use hns_service_authority::{
    AuthorityError, AuthorityRecord, ServiceIdentity, select_authority_record,
    select_endpoint_delegation, select_service_authorization,
};

use super::{
    AuthenticatedHnsrPeer, Engine, HnsrRequesterRuntime, HnsrTransportAuthorityContext,
    HnsrTransportBinding, HnsrTransportError, HnsrTransportRole, network_id,
};

/// Maximum logical endpoints retained for one authority/service epoch.
pub const MAX_HNSA_NAMED_ROUTE_ENDPOINTS: usize = 64;
/// Maximum canonical encoded size of one persistent named-route state.
pub const MAX_HNSA_NAMED_ROUTE_STATE_BYTES: usize = 7_519;

const HNSA_NAMED_ROUTE_STATE_MAGIC: &[u8; 4] = b"HNS1";
const HNSA_AUTHORITY_DIGEST_DOMAIN: &[u8] = b"HNS-DANE-HNSA-AUTHORITY-STATE-V1\0";
const HNSA_ROUTE_DIGEST_DOMAIN: &[u8] = b"HNS-DANE-HNSA-ROUTE-STATE-V1\0";
const HNSA_STATE_CHECKSUM_DOMAIN: &[u8] = b"HNS-DANE-HNSA-STATE-CHECKSUM-V1\0";
const HNSA_STATE_HEADER_SIZE: usize = 127;
const HNSA_ENDPOINT_STATE_SIZE: usize = 115;
const HNSA_STATE_CHECKSUM_SIZE: usize = 32;

/// Platform-held HNS-resource, application-policy, and trusted-time floors for
/// named-route verification.
///
/// The platform must advance `resource_generation` whenever its accepted HNS
/// name state changes, including a new anchor or reorganization, and must
/// advance `profile_policy_generation` whenever any profile rule changes.
/// Opaque selections are not serializable. The platform must durably advance
/// `trusted_time_high_water` before every selector call, including calls that
/// fail, and store it with the generation floors and encoded named-route state
/// in one authenticated rollback-resistant transaction. Encoded route input
/// must be fully reverified after restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsaNamedRouteContext {
    resource_generation: u64,
    profile_policy_generation: u64,
    trusted_time_high_water: u64,
    policy: NamedRoutePolicy,
}

impl HnsaNamedRouteContext {
    /// Construct checked external authority floors for a named profile.
    pub const fn new(
        resource_generation: u64,
        profile_policy_generation: u64,
        trusted_time_high_water: u64,
        policy: NamedRoutePolicy,
    ) -> Result<Self, HnsaRouteError> {
        if resource_generation == 0 || profile_policy_generation == 0 {
            return Err(HnsaRouteError::InvalidContextGeneration);
        }
        Ok(Self {
            resource_generation,
            profile_policy_generation,
            trusted_time_high_water,
            policy,
        })
    }

    /// Monotonic generation of the platform's latest accepted HNS resource.
    #[must_use]
    pub const fn resource_generation(self) -> u64 {
        self.resource_generation
    }

    /// Monotonic generation of the application-profile policy.
    #[must_use]
    pub const fn profile_policy_generation(self) -> u64 {
        self.profile_policy_generation
    }

    /// Caller-held trusted-time rollback floor.
    #[must_use]
    pub const fn trusted_time_high_water(self) -> u64 {
        self.trusted_time_high_water
    }

    /// Exact profile rules bound to this generation.
    #[must_use]
    pub const fn policy(self) -> NamedRoutePolicy {
        self.policy
    }
}

/// Caller-selected identity, external authority context, and trusted time for
/// one named-route candidate verification.
///
/// `expected_name` and `service_name` are application inputs. They are never
/// selected from the untrusted route record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsaNamedRouteRequest<'a> {
    /// Exact lowercase Handshake TLD label selected by the application.
    pub expected_name: &'a [u8],
    /// Exact canonical HNSA service name selected by the application.
    pub service_name: &'a str,
    /// Exact Web or Chat HNSR profile selected by the application.
    pub profile_id: u16,
    /// Platform-held resource, profile-policy, and trusted-time floors.
    pub context: HnsaNamedRouteContext,
    /// Trusted Unix time used for both chain currency and route expiry.
    pub trusted_now: u64,
}

impl<'a> HnsaNamedRouteRequest<'a> {
    /// Construct an exact named-route request.
    #[must_use]
    pub const fn new(
        expected_name: &'a [u8],
        service_name: &'a str,
        profile_id: u16,
        context: HnsaNamedRouteContext,
        trusted_now: u64,
    ) -> Self {
        Self {
            expected_name,
            service_name,
            profile_id,
            context,
            trusted_now,
        }
    }
}

/// Internal cryptographically verified candidate before conflict-safe
/// replacement selection.
struct VerifiedHnsaNamedRouteCandidate {
    binding: HnsrTransportBinding,
    context: HnsaNamedRouteContext,
    trusted_time_high_water: u64,
    anchor: HnsAnchor,
    name: Vec<u8>,
    authority_digest: [u8; 32],
    record: NamedRouteRecordV2,
}

impl VerifiedHnsaNamedRouteCandidate {
    /// Browser process/session identity that admitted this verification.
    #[must_use]
    pub const fn runtime_session(&self) -> [u8; 16] {
        self.binding.runtime_session()
    }

    /// Browser authority generation that admitted this verification.
    #[must_use]
    pub const fn runtime_generation(&self) -> u64 {
        self.binding.runtime_generation()
    }

    /// Exact engine event that admitted this verification.
    #[must_use]
    pub const fn admission_event(&self) -> u64 {
        self.binding.admission_event()
    }

    /// Persistent requester-policy generation that admitted this verification.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.binding.policy_generation()
    }

    /// Platform HNS-resource generation that supplied this candidate.
    #[must_use]
    pub const fn resource_generation(&self) -> u64 {
        self.context.resource_generation
    }

    /// Application-profile policy generation used for complete verification.
    #[must_use]
    pub const fn profile_policy_generation(&self) -> u64 {
        self.context.profile_policy_generation
    }

    /// Handshake network authenticated by both the engine and route chain.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.binding.network()
    }

    /// Exact lowercase Handshake name selected by the requester.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Canonical Handshake name hash signed into the service authorization.
    #[must_use]
    pub const fn name_hash(&self) -> [u8; 32] {
        self.record.authorization.name_hash
    }

    /// Exact canonical HNSA service name selected by the requester.
    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.record.authorization.service_name
    }

    /// Exact named HNSR application profile.
    #[must_use]
    pub const fn profile_id(&self) -> u16 {
        self.record.profile
    }

    /// Stable route key derived from the caller-selected service identity.
    #[must_use]
    pub const fn route_key(&self) -> [u8; 32] {
        self.record.route_key
    }

    /// Monotonic named-route replacement sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.record.sequence
    }

    /// First trusted Unix time at which both the chain anchor and route hold.
    #[must_use]
    pub const fn valid_from(&self) -> u64 {
        let anchor = self.anchor.validated_at().get();
        if anchor > self.record.issued_at {
            anchor
        } else {
            self.record.issued_at
        }
    }

    /// First trusted Unix time at which either the chain anchor or route expires.
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        let anchor = self.anchor.valid_until().get();
        if anchor < self.record.expires_at {
            anchor
        } else {
            self.record.expires_at
        }
    }

    /// Service-authorization serial used for bounded candidate selection.
    #[must_use]
    pub const fn authorization_serial(&self) -> u64 {
        self.record.authorization.serial
    }

    /// Endpoint-delegation sequence used for profile-scoped selection.
    #[must_use]
    pub const fn endpoint_sequence(&self) -> u64 {
        self.record.delegation.endpoint_sequence
    }

    /// Endpoint key that scopes the named-route replacement sequence.
    #[must_use]
    pub const fn endpoint_key(&self) -> [u8; 33] {
        self.record.delegation.endpoint_key
    }

    /// Whether another non-forgeable resource carries the exact same accepted
    /// name-tree anchor and name binding.
    #[must_use]
    pub fn is_bound_to_resource(&self, resource: &VerifiedHnsResource) -> bool {
        self.anchor == resource.anchor()
            && self.name == resource.name()
            && self.name_hash() == resource.name_hash().into_bytes()
    }
}

impl fmt::Debug for VerifiedHnsaNamedRouteCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedHnsaNamedRouteCandidate")
            .field("runtime_session", &self.runtime_session())
            .field("runtime_generation", &self.runtime_generation())
            .field("admission_event", &self.admission_event())
            .field("policy_generation", &self.policy_generation())
            .field("resource_generation", &self.resource_generation())
            .field(
                "profile_policy_generation",
                &self.profile_policy_generation(),
            )
            .field("trusted_time_high_water", &self.trusted_time_high_water)
            .field("network", &self.network())
            .field("anchor", &self.anchor)
            .field("profile_id", &self.profile_id())
            .field("sequence", &self.sequence())
            .field("valid_from", &self.valid_from())
            .field("valid_until", &self.valid_until())
            .field("relay_ticket_count", &self.record.tickets.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct HnsaSelectionCommitment {
    authority_digest: [u8; 32],
    route_key: [u8; 32],
    endpoint_key: [u8; 33],
    authorization_serial: u64,
    authorization_id: [u8; 32],
    endpoint_sequence: u64,
    delegation_id: [u8; 32],
    route_sequence: u64,
    route_digest: [u8; 32],
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HnsaSequenceStateStatus {
    Active = 1,
    Conflicted = 2,
    Exhausted = 3,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct HnsaAuthorizationState {
    serial: u64,
    id: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct HnsaDelegationState {
    sequence: u64,
    id: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct HnsaRouteState {
    sequence: u64,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct HnsaEndpointState {
    endpoint_key: [u8; 33],
    delegation: Option<HnsaDelegationState>,
    route: Option<HnsaRouteState>,
}

/// Bounded durable replacement state for one HNSA authority and service.
///
/// Selection advances this value as soon as a newer valid authorization or
/// delegation is observed, even when no usable route remains. Equal-sequence
/// conflicts and endpoint-history exhaustion are sticky until a verified new
/// `hsa1` authority root/epoch is observed under a greater resource generation.
/// The embedding platform must atomically persist every generation change in
/// authenticated rollback-resistant storage before opening any selected route.
pub struct HnsaNamedRouteState {
    generation: u64,
    resource_generation: u64,
    authority_digest: [u8; 32],
    route_key: [u8; 32],
    status: HnsaSequenceStateStatus,
    authorization: Option<HnsaAuthorizationState>,
    endpoints: Vec<HnsaEndpointState>,
}

impl HnsaNamedRouteState {
    /// Construct an unscoped initial state for first selection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generation: 0,
            resource_generation: 0,
            authority_digest: [0; 32],
            route_key: [0; 32],
            status: HnsaSequenceStateStatus::Active,
            authorization: None,
            endpoints: Vec::new(),
        }
    }

    /// Monotonic state generation; zero only before first scoped selection.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Platform HNS-resource generation bound to this state.
    #[must_use]
    pub const fn resource_generation(&self) -> u64 {
        self.resource_generation
    }

    /// Number of logical endpoint histories retained in this state.
    #[must_use]
    pub fn endpoint_history_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Whether selection and opening remain permitted for this authority epoch.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, HnsaSequenceStateStatus::Active)
    }

    /// Whether a signed equal-sequence conflict permanently blocked this scope.
    #[must_use]
    pub const fn is_conflicted(&self) -> bool {
        matches!(self.status, HnsaSequenceStateStatus::Conflicted)
    }

    /// Whether bounded endpoint history was exhausted for this scope.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        matches!(self.status, HnsaSequenceStateStatus::Exhausted)
    }

    /// Encode the scoped state as one bounded checksummed persistence blob.
    pub fn encode(&self) -> Result<Vec<u8>, HnsaRouteError> {
        if !self.is_scoped() || self.endpoints.len() > MAX_HNSA_NAMED_ROUTE_ENDPOINTS {
            return Err(HnsaRouteError::InvalidSequenceState);
        }
        let mut output = Vec::with_capacity(
            HNSA_STATE_HEADER_SIZE
                + self.endpoints.len() * HNSA_ENDPOINT_STATE_SIZE
                + HNSA_STATE_CHECKSUM_SIZE,
        );
        output.extend_from_slice(HNSA_NAMED_ROUTE_STATE_MAGIC);
        output.extend_from_slice(&self.generation.to_le_bytes());
        output.extend_from_slice(&self.resource_generation.to_le_bytes());
        output.push(self.status as u8);
        output.push(u8::from(self.authorization.is_some()));
        output.extend_from_slice(&self.authority_digest);
        output.extend_from_slice(&self.route_key);
        if let Some(authorization) = self.authorization {
            output.extend_from_slice(&authorization.serial.to_le_bytes());
            output.extend_from_slice(&authorization.id);
        } else {
            output.extend_from_slice(&[0; 8]);
            output.extend_from_slice(&[0; 32]);
        }
        output.push(
            u8::try_from(self.endpoints.len()).map_err(|_| HnsaRouteError::InvalidSequenceState)?,
        );
        for endpoint in &self.endpoints {
            output.extend_from_slice(&endpoint.endpoint_key);
            output.push(u8::from(endpoint.delegation.is_some()));
            if let Some(delegation) = endpoint.delegation {
                output.extend_from_slice(&delegation.sequence.to_le_bytes());
                output.extend_from_slice(&delegation.id);
            } else {
                output.extend_from_slice(&[0; 8]);
                output.extend_from_slice(&[0; 32]);
            }
            output.push(u8::from(endpoint.route.is_some()));
            if let Some(route) = endpoint.route {
                output.extend_from_slice(&route.sequence.to_le_bytes());
                output.extend_from_slice(&route.digest);
            } else {
                output.extend_from_slice(&[0; 8]);
                output.extend_from_slice(&[0; 32]);
            }
        }
        if output.len() != HNSA_STATE_HEADER_SIZE + self.endpoints.len() * HNSA_ENDPOINT_STATE_SIZE
        {
            return Err(HnsaRouteError::InvalidSequenceState);
        }
        let checksum = blake2b_256(HNSA_STATE_CHECKSUM_DOMAIN, &[&output]);
        output.extend_from_slice(&checksum);
        Ok(output)
    }

    /// Decode one canonical state from authenticated rollback-resistant storage.
    #[allow(
        clippy::too_many_lines,
        reason = "canonical state decoding validates the complete fixed-layout envelope in one pass"
    )]
    pub fn decode(input: &[u8]) -> Result<Self, HnsaRouteError> {
        let payload_size = input
            .len()
            .checked_sub(HNSA_STATE_CHECKSUM_SIZE)
            .ok_or(HnsaRouteError::InvalidSequenceState)?;
        if input.len() > MAX_HNSA_NAMED_ROUTE_STATE_BYTES || payload_size < HNSA_STATE_HEADER_SIZE {
            return Err(HnsaRouteError::InvalidSequenceState);
        }
        let payload = input
            .get(..payload_size)
            .ok_or(HnsaRouteError::InvalidSequenceState)?;
        let checksum: [u8; 32] = input
            .get(payload_size..)
            .ok_or(HnsaRouteError::InvalidSequenceState)?
            .try_into()
            .map_err(|_| HnsaRouteError::InvalidSequenceState)?;
        if blake2b_256(HNSA_STATE_CHECKSUM_DOMAIN, &[payload]) != checksum {
            return Err(HnsaRouteError::InvalidSequenceState);
        }

        let mut fields = payload;
        let magic = take_state_field::<4>(&mut fields)?;
        let generation = u64::from_le_bytes(take_state_field::<8>(&mut fields)?);
        let resource_generation = u64::from_le_bytes(take_state_field::<8>(&mut fields)?);
        let [status] = take_state_field::<1>(&mut fields)?;
        let status = match status {
            1 => HnsaSequenceStateStatus::Active,
            2 => HnsaSequenceStateStatus::Conflicted,
            3 => HnsaSequenceStateStatus::Exhausted,
            _ => return Err(HnsaRouteError::InvalidSequenceState),
        };
        let [authorization_present] = take_state_field::<1>(&mut fields)?;
        let authority_digest = take_state_field::<32>(&mut fields)?;
        let route_key = take_state_field::<32>(&mut fields)?;
        let authorization_serial = u64::from_le_bytes(take_state_field::<8>(&mut fields)?);
        let authorization_id = take_state_field::<32>(&mut fields)?;
        let authorization = match authorization_present {
            0 if authorization_serial == 0 && authorization_id == [0; 32] => None,
            1 if authorization_serial != 0 && authorization_id != [0; 32] => {
                Some(HnsaAuthorizationState {
                    serial: authorization_serial,
                    id: authorization_id,
                })
            }
            _ => return Err(HnsaRouteError::InvalidSequenceState),
        };
        let [endpoint_count] = take_state_field::<1>(&mut fields)?;
        let endpoint_count = usize::from(endpoint_count);
        if endpoint_count > MAX_HNSA_NAMED_ROUTE_ENDPOINTS {
            return Err(HnsaRouteError::InvalidSequenceState);
        }
        let mut endpoints = Vec::with_capacity(endpoint_count);
        let mut previous_key = None;
        for _ in 0..endpoint_count {
            let endpoint_key = take_state_field::<33>(&mut fields)?;
            if endpoint_key == [0; 33]
                || previous_key.is_some_and(|previous| endpoint_key <= previous)
            {
                return Err(HnsaRouteError::InvalidSequenceState);
            }
            previous_key = Some(endpoint_key);
            let [delegation_present] = take_state_field::<1>(&mut fields)?;
            let delegation_sequence = u64::from_le_bytes(take_state_field::<8>(&mut fields)?);
            let delegation_id = take_state_field::<32>(&mut fields)?;
            let delegation = match delegation_present {
                0 if delegation_sequence == 0 && delegation_id == [0; 32] => None,
                1 if delegation_sequence != 0 && delegation_id != [0; 32] => {
                    Some(HnsaDelegationState {
                        sequence: delegation_sequence,
                        id: delegation_id,
                    })
                }
                _ => return Err(HnsaRouteError::InvalidSequenceState),
            };
            let [route_present] = take_state_field::<1>(&mut fields)?;
            let route_sequence = u64::from_le_bytes(take_state_field::<8>(&mut fields)?);
            let route_digest = take_state_field::<32>(&mut fields)?;
            let route = match route_present {
                0 if route_sequence == 0 && route_digest == [0; 32] => None,
                1 if route_sequence != 0 && route_digest != [0; 32] => Some(HnsaRouteState {
                    sequence: route_sequence,
                    digest: route_digest,
                }),
                _ => return Err(HnsaRouteError::InvalidSequenceState),
            };
            endpoints.push(HnsaEndpointState {
                endpoint_key,
                delegation,
                route,
            });
        }
        if magic != *HNSA_NAMED_ROUTE_STATE_MAGIC
            || generation == 0
            || resource_generation == 0
            || authority_digest == [0; 32]
            || route_key == [0; 32]
            || !fields.is_empty()
            || (authorization.is_none() && !endpoints.is_empty())
        {
            return Err(HnsaRouteError::InvalidSequenceState);
        }
        Ok(Self {
            generation,
            resource_generation,
            authority_digest,
            route_key,
            status,
            authorization,
            endpoints,
        })
    }

    fn is_scoped(&self) -> bool {
        self.generation != 0
            && self.resource_generation != 0
            && self.authority_digest != [0; 32]
            && self.route_key != [0; 32]
    }

    fn bind_scope(
        &mut self,
        authority_digest: [u8; 32],
        route_key: [u8; 32],
        resource_generation: u64,
    ) -> Result<(), HnsaRouteError> {
        if !self.is_scoped() {
            self.generation = 1;
            self.resource_generation = resource_generation;
            self.authority_digest = authority_digest;
            self.route_key = route_key;
            self.status = HnsaSequenceStateStatus::Active;
            self.authorization = None;
            self.endpoints.clear();
            return Ok(());
        }
        if self.route_key != route_key {
            return Err(HnsaRouteError::SequenceStateScopeMismatch);
        }
        if resource_generation < self.resource_generation {
            return Err(HnsaRouteError::SequenceStateRollback);
        }
        if self.authority_digest != authority_digest {
            if resource_generation <= self.resource_generation {
                return Err(HnsaRouteError::SequenceStateRollback);
            }
            self.bump_generation()?;
            self.resource_generation = resource_generation;
            self.authority_digest = authority_digest;
            self.status = HnsaSequenceStateStatus::Active;
            self.authorization = None;
            self.endpoints.clear();
        } else if resource_generation > self.resource_generation {
            self.bump_generation()?;
            self.resource_generation = resource_generation;
        }
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), HnsaRouteError> {
        match self.status {
            HnsaSequenceStateStatus::Active => Ok(()),
            HnsaSequenceStateStatus::Conflicted => Err(HnsaRouteError::SequenceStateConflicted),
            HnsaSequenceStateStatus::Exhausted => Err(HnsaRouteError::SequenceStateExhausted),
        }
    }

    fn advance_authorization(&mut self, serial: u64, id: [u8; 32]) -> Result<(), HnsaRouteError> {
        match self.authorization {
            None => {
                self.bump_generation()?;
                self.authorization = Some(HnsaAuthorizationState { serial, id });
                Ok(())
            }
            Some(current) if serial < current.serial => Err(HnsaRouteError::SequenceRollback),
            Some(current) if serial == current.serial && id != current.id => {
                self.mark_conflicted()?;
                Err(HnsaRouteError::ConflictingSequenceState)
            }
            Some(current) if serial > current.serial => {
                self.bump_generation()?;
                self.authorization = Some(HnsaAuthorizationState { serial, id });
                for endpoint in &mut self.endpoints {
                    endpoint.delegation = None;
                }
                Ok(())
            }
            Some(_) => Ok(()),
        }
    }

    fn advance_delegation(
        &mut self,
        endpoint_key: [u8; 33],
        sequence: u64,
        id: [u8; 32],
    ) -> Result<(), HnsaRouteError> {
        match self
            .endpoints
            .binary_search_by_key(&endpoint_key, |endpoint| endpoint.endpoint_key)
        {
            Ok(position) => {
                let current = self
                    .endpoints
                    .get(position)
                    .ok_or(HnsaRouteError::InvalidSequenceState)?
                    .delegation;
                match current {
                    Some(current) if sequence < current.sequence => {
                        Err(HnsaRouteError::SequenceRollback)
                    }
                    Some(current) if sequence == current.sequence && id != current.id => {
                        self.mark_conflicted()?;
                        Err(HnsaRouteError::ConflictingSequenceState)
                    }
                    Some(current) if sequence == current.sequence && id == current.id => Ok(()),
                    _ => {
                        self.bump_generation()?;
                        self.endpoints
                            .get_mut(position)
                            .ok_or(HnsaRouteError::InvalidSequenceState)?
                            .delegation = Some(HnsaDelegationState { sequence, id });
                        Ok(())
                    }
                }
            }
            Err(position) => {
                if self.endpoints.len() >= MAX_HNSA_NAMED_ROUTE_ENDPOINTS {
                    self.mark_exhausted()?;
                    return Err(HnsaRouteError::SequenceStateExhausted);
                }
                self.bump_generation()?;
                self.endpoints.insert(
                    position,
                    HnsaEndpointState {
                        endpoint_key,
                        delegation: Some(HnsaDelegationState { sequence, id }),
                        route: None,
                    },
                );
                Ok(())
            }
        }
    }

    fn advance_route(
        &mut self,
        endpoint_key: [u8; 33],
        sequence: u64,
        digest: [u8; 32],
    ) -> Result<(), HnsaRouteError> {
        let position = self
            .endpoints
            .binary_search_by_key(&endpoint_key, |endpoint| endpoint.endpoint_key)
            .map_err(|_| HnsaRouteError::InvalidSequenceState)?;
        let current = self
            .endpoints
            .get(position)
            .ok_or(HnsaRouteError::InvalidSequenceState)?
            .route;
        match current {
            Some(current) if sequence < current.sequence => Err(HnsaRouteError::SequenceRollback),
            Some(current) if sequence == current.sequence && digest != current.digest => {
                self.mark_conflicted()?;
                Err(HnsaRouteError::ConflictingSequenceState)
            }
            Some(current) if sequence == current.sequence && digest == current.digest => Ok(()),
            _ => {
                self.bump_generation()?;
                self.endpoints
                    .get_mut(position)
                    .ok_or(HnsaRouteError::InvalidSequenceState)?
                    .route = Some(HnsaRouteState { sequence, digest });
                Ok(())
            }
        }
    }

    fn selection_is_current(&self, commitment: HnsaSelectionCommitment) -> bool {
        if !self.is_active()
            || self.authority_digest != commitment.authority_digest
            || self.route_key != commitment.route_key
            || self.authorization
                != Some(HnsaAuthorizationState {
                    serial: commitment.authorization_serial,
                    id: commitment.authorization_id,
                })
        {
            return false;
        }
        self.endpoints
            .binary_search_by_key(&commitment.endpoint_key, |endpoint| endpoint.endpoint_key)
            .ok()
            .and_then(|position| self.endpoints.get(position))
            .is_some_and(|endpoint| {
                endpoint.delegation
                    == Some(HnsaDelegationState {
                        sequence: commitment.endpoint_sequence,
                        id: commitment.delegation_id,
                    })
                    && endpoint.route
                        == Some(HnsaRouteState {
                            sequence: commitment.route_sequence,
                            digest: commitment.route_digest,
                        })
            })
    }

    fn mark_conflicted(&mut self) -> Result<(), HnsaRouteError> {
        if !matches!(self.status, HnsaSequenceStateStatus::Conflicted) {
            self.bump_generation()?;
            self.status = HnsaSequenceStateStatus::Conflicted;
        }
        Ok(())
    }

    fn mark_exhausted(&mut self) -> Result<(), HnsaRouteError> {
        if !matches!(self.status, HnsaSequenceStateStatus::Exhausted) {
            self.bump_generation()?;
            self.status = HnsaSequenceStateStatus::Exhausted;
        }
        Ok(())
    }

    fn bump_generation(&mut self) -> Result<(), HnsaRouteError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(HnsaRouteError::SequenceStateGenerationExhausted)?;
        Ok(())
    }
}

impl Default for HnsaNamedRouteState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HnsaNamedRouteState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsaNamedRouteState")
            .field("generation", &self.generation)
            .field("resource_generation", &self.resource_generation)
            .field("status", &self.status)
            .field(
                "authorization_serial",
                &self.authorization.map(|authorization| authorization.serial),
            )
            .field("endpoint_history_count", &self.endpoints.len())
            .finish_non_exhaustive()
    }
}

/// Non-authoritative connection metadata for one verified relay ticket.
///
/// These fields let the platform locate and Brontide-authenticate a relay.
/// They do not expose the signed ticket required to open a circuit.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HnsaRelayEndpoint {
    ticket_index: usize,
    transport: u8,
    host_type: u8,
    host: [u8; 16],
    port: u16,
    relay_key: [u8; 33],
    reservation_id: [u8; 16],
    valid_from: u64,
    valid_until: u64,
}

impl HnsaRelayEndpoint {
    /// Index consumed by [`Engine::begin_hnsa_named_route_open`].
    #[must_use]
    pub const fn ticket_index(self) -> usize {
        self.ticket_index
    }

    /// Canonical ticket transport discriminator.
    #[must_use]
    pub const fn transport(self) -> u8 {
        self.transport
    }

    /// Canonical ticket host discriminator.
    #[must_use]
    pub const fn host_type(self) -> u8 {
        self.host_type
    }

    /// Fixed-width ticket host bytes interpreted according to `host_type`.
    #[must_use]
    pub const fn host(self) -> [u8; 16] {
        self.host
    }

    /// Relay connection port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }

    /// Relay static key that the outer Brontide connection must authenticate.
    #[must_use]
    pub const fn relay_key(self) -> [u8; 33] {
        self.relay_key
    }

    /// Ticket reservation identifier used only for correlation/status.
    #[must_use]
    pub const fn reservation_id(self) -> [u8; 16] {
        self.reservation_id
    }

    /// First trusted time at which the selected route and ticket hold.
    #[must_use]
    pub const fn valid_from(self) -> u64 {
        self.valid_from
    }

    /// Exclusive earlier expiry of the selected route, anchor, or ticket.
    #[must_use]
    pub const fn valid_until(self) -> u64 {
        self.valid_until
    }
}

impl fmt::Debug for HnsaRelayEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsaRelayEndpoint")
            .field("ticket_index", &self.ticket_index)
            .field("transport", &self.transport)
            .field("host_type", &self.host_type)
            .field("port", &self.port)
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .finish_non_exhaustive()
    }
}

/// Conflict-safe latest named route for one HNSR logical endpoint.
///
/// Values are created only by the bounded batch selector. Raw route records
/// and tickets remain private; named circuit opening must pass this value back
/// to [`Engine::begin_hnsa_named_route_open`].
pub struct SelectedHnsaNamedRoute {
    candidate: VerifiedHnsaNamedRouteCandidate,
    commitment: HnsaSelectionCommitment,
}

impl SelectedHnsaNamedRoute {
    /// Exact lowercase HNS name selected by the request.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        self.candidate.name()
    }

    /// Exact HNSA service name selected by the request.
    #[must_use]
    pub fn service_name(&self) -> &str {
        self.candidate.service_name()
    }

    /// Exact named application profile.
    #[must_use]
    pub const fn profile_id(&self) -> u16 {
        self.candidate.profile_id()
    }

    /// Stable service-identity route key.
    #[must_use]
    pub const fn route_key(&self) -> [u8; 32] {
        self.candidate.route_key()
    }

    /// Logical endpoint key selected under replacement rules.
    #[must_use]
    pub const fn endpoint_key(&self) -> [u8; 33] {
        self.candidate.endpoint_key()
    }

    /// Greatest valid service-authorization serial in the bounded batch.
    #[must_use]
    pub const fn authorization_serial(&self) -> u64 {
        self.candidate.authorization_serial()
    }

    /// Greatest valid delegation sequence for this logical endpoint.
    #[must_use]
    pub const fn endpoint_sequence(&self) -> u64 {
        self.candidate.endpoint_sequence()
    }

    /// Greatest valid named-route sequence for this logical endpoint.
    #[must_use]
    pub const fn route_sequence(&self) -> u64 {
        self.candidate.sequence()
    }

    /// First trusted time at which the chain anchor and route hold.
    #[must_use]
    pub const fn valid_from(&self) -> u64 {
        self.candidate.valid_from()
    }

    /// Exclusive earlier expiry of the chain anchor and route.
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.candidate.valid_until()
    }

    /// Number of fully verified relay tickets kept private by this selection.
    #[must_use]
    pub fn relay_endpoint_count(&self) -> usize {
        self.candidate.record.tickets.len()
    }

    /// Non-authoritative connection metadata for one verified relay ticket.
    #[must_use]
    pub fn relay_endpoint(&self, index: usize) -> Option<HnsaRelayEndpoint> {
        let ticket = self.candidate.record.tickets.get(index)?;
        Some(HnsaRelayEndpoint {
            ticket_index: index,
            transport: ticket.transport,
            host_type: ticket.host_type,
            host: ticket.host,
            port: ticket.port,
            relay_key: ticket.relay_key,
            reservation_id: ticket.reservation_id,
            valid_from: self.valid_from().max(ticket.issued_at),
            valid_until: self.valid_until().min(ticket.expires_at),
        })
    }
}

impl fmt::Debug for SelectedHnsaNamedRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedHnsaNamedRoute")
            .field("network", &self.candidate.network())
            .field("profile_id", &self.profile_id())
            .field("authorization_serial", &self.authorization_serial())
            .field("endpoint_sequence", &self.endpoint_sequence())
            .field("route_sequence", &self.route_sequence())
            .field("valid_from", &self.valid_from())
            .field("valid_until", &self.valid_until())
            .field("relay_endpoint_count", &self.relay_endpoint_count())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Verify and conflict-safely select one latest HNSA route per logical
    /// endpoint from a complete bounded rendezvous response.
    ///
    /// Every supplied item counts toward the protocol bound before decoding.
    /// Invalid records are ignored, while equal-sequence authorization,
    /// delegation, or route conflicts fail the complete batch and permanently
    /// block the mutable sequence state. The caller must durably commit every
    /// state-generation change, including changes returned with an error.
    #[allow(
        clippy::too_many_lines,
        reason = "the three protocol replacement layers remain together so one bounded response cannot bypass a selection stage"
    )]
    pub fn verify_and_select_hnsa_named_routes<R: AsRef<[u8]>>(
        &self,
        resource: &VerifiedHnsResource,
        encoded_records: &[R],
        state: &mut HnsaNamedRouteState,
        request: HnsaNamedRouteRequest<'_>,
    ) -> Result<Vec<SelectedHnsaNamedRoute>, HnsaRouteError> {
        if encoded_records.is_empty() {
            return Err(HnsaRouteError::MissingRouteCandidate);
        }
        if encoded_records.len() > MAX_RECORDS_PER_KEY {
            return Err(HnsaRouteError::TooManyRouteCandidates {
                actual: encoded_records.len(),
                maximum: MAX_RECORDS_PER_KEY,
            });
        }
        if resource.name() != request.expected_name {
            return Err(HnsaRouteError::ExpectedNameMismatch);
        }
        if !is_canonical_service_name(request.service_name) {
            return Err(HnsaRouteError::InvalidServiceName);
        }
        if !matches!(request.profile_id, HNS_WEB_V1 | HNS_CHAT_V1) {
            return Err(HnsaRouteError::UnsupportedNamedProfile);
        }
        if request.trusted_now < request.context.trusted_time_high_water {
            return Err(HnsaRouteError::TrustedClockRollback);
        }
        ensure_anchor_current(resource.anchor(), request.trusted_now)?;

        let authority = authority_from_resource(resource)?;
        let authority_digest = authority_digest(&authority)?;
        let decoded = encoded_records
            .iter()
            .filter_map(|encoded| NamedRouteRecordV2::decode(encoded.as_ref()).ok())
            .collect::<Vec<_>>();
        let binding = self
            .mint_hnsr_transport_binding(
                HnsrTransportRole::Requester,
                request.profile_id,
                request.context.policy.allow_private_relays,
            )
            .map_err(HnsaRouteError::Transport)?;
        if network_id(binding.network()) != resource.anchor().network().id() {
            return Err(HnsaRouteError::HnsNetworkMismatch);
        }

        let identity = ServiceIdentity {
            network_magic: binding.network_magic(),
            name_hash: resource.name_hash().into_bytes(),
            service_name: request.service_name.to_owned(),
            profile_id: request.profile_id,
        };
        let route_key = named_route_key(&identity).map_err(HnsaRouteError::Protocol)?;
        state.bind_scope(
            authority_digest,
            route_key,
            request.context.resource_generation,
        )?;
        state.ensure_active()?;
        if decoded.is_empty() {
            return Err(HnsaRouteError::MissingRouteCandidate);
        }

        let authorization = match select_service_authorization(
            decoded.iter().map(|record| &record.authorization),
            &authority,
            &identity,
            resource.anchor().height().get(),
            request.context.policy.allowed_authorization_flags,
        ) {
            Ok(authorization) => authorization.clone(),
            Err(error @ AuthorityError::ConflictingSequence) => {
                state.mark_conflicted()?;
                return Err(HnsaRouteError::Authority(error));
            }
            Err(error) => return Err(HnsaRouteError::Authority(error)),
        };
        let authorization_id = authorization.id().map_err(HnsaRouteError::Authority)?;
        state.advance_authorization(authorization.serial, authorization_id)?;
        let trust = NamedRouteTrust {
            authority: &authority,
            identity: &identity,
            current_height: resource.anchor().height().get(),
            policy: request.context.policy,
        };
        let endpoint_keys = decoded
            .iter()
            .filter(|record| record.authorization == authorization)
            .map(|record| record.delegation.endpoint_key)
            .collect::<BTreeSet<_>>();
        let mut selected = Vec::with_capacity(endpoint_keys.len());

        for endpoint_key in endpoint_keys {
            let delegation = match select_endpoint_delegation(
                decoded
                    .iter()
                    .filter(|record| record.authorization == authorization)
                    .map(|record| &record.delegation),
                &authorization,
                request.trusted_now,
                request.context.policy.allowed_endpoint_capabilities,
                request.context.policy.expected_constraints_hash,
                |candidate| candidate.endpoint_key == endpoint_key,
            ) {
                Ok(delegation) => delegation.clone(),
                Err(AuthorityError::Missing) => continue,
                Err(error @ AuthorityError::ConflictingSequence) => {
                    state.mark_conflicted()?;
                    return Err(HnsaRouteError::Authority(error));
                }
                Err(error) => return Err(HnsaRouteError::Authority(error)),
            };
            let delegation_id = delegation.id().map_err(HnsaRouteError::Authority)?;
            state.advance_delegation(endpoint_key, delegation.endpoint_sequence, delegation_id)?;
            if delegation.capabilities & request.context.policy.required_endpoint_capabilities
                != request.context.policy.required_endpoint_capabilities
            {
                continue;
            }
            let mut latest: Option<&NamedRouteRecordV2> = None;
            for record in decoded.iter().filter(|record| {
                record.authorization == authorization && record.delegation == delegation
            }) {
                if record.verify(&trust, request.trusted_now).is_err() {
                    continue;
                }
                match latest {
                    None => latest = Some(record),
                    Some(current) if record.sequence > current.sequence => latest = Some(record),
                    Some(current) if record.sequence == current.sequence && record != current => {
                        state.mark_conflicted()?;
                        return Err(HnsaRouteError::ConflictingRouteSequence);
                    }
                    _ => {}
                }
            }
            let Some(record) = latest else {
                continue;
            };
            let candidate = VerifiedHnsaNamedRouteCandidate {
                binding,
                context: request.context,
                trusted_time_high_water: request.trusted_now,
                anchor: resource.anchor(),
                name: resource.name().to_vec(),
                authority_digest,
                record: record.clone(),
            };
            let commitment = commitment_from_candidate(&candidate)?;
            state.advance_route(
                endpoint_key,
                commitment.route_sequence,
                commitment.route_digest,
            )?;
            selected.push(SelectedHnsaNamedRoute {
                candidate,
                commitment,
            });
        }

        if selected.is_empty() {
            return Err(HnsaRouteError::MissingRouteCandidate);
        }

        HnsrTransportAuthorityContext::validate_hnsr_transport_binding(self, binding)
            .map_err(HnsaRouteError::Transport)?;
        Ok(selected)
    }

    /// Revalidate one selected route and atomically enter the HNSR requester
    /// open sink without exposing a detachable relay ticket.
    ///
    /// `current_state` must be the latest value durably committed by the
    /// platform before this call. The open deadline is capped by the enclosing
    /// route/anchor lifetime even when the relay ticket lives longer.
    #[allow(
        clippy::too_many_arguments,
        reason = "route, durable state, external authorities, requester/relay, ticket selection, clock, deadline, and credit are independent trust inputs"
    )]
    pub fn begin_hnsa_named_route_open(
        &self,
        selected: &mut SelectedHnsaNamedRoute,
        current_state: &HnsaNamedRouteState,
        current_resource: &VerifiedHnsResource,
        current_context: &HnsaNamedRouteContext,
        requester: &mut HnsrRequesterRuntime,
        relay: &AuthenticatedHnsrPeer,
        ticket_index: usize,
        trusted_now: u64,
        deadline: u64,
        initial_window: u32,
    ) -> Result<HnsrRoute, HnsaRouteError> {
        let selected_commitment = selected.commitment;
        let candidate = &mut selected.candidate;
        if candidate.context.resource_generation != current_context.resource_generation {
            return Err(HnsaRouteError::ResourceGenerationChanged);
        }
        if candidate.context.profile_policy_generation != current_context.profile_policy_generation
            || candidate.context.policy != current_context.policy
        {
            return Err(HnsaRouteError::ProfilePolicyChanged);
        }
        if !candidate.is_bound_to_resource(current_resource) {
            return Err(HnsaRouteError::ResourceBindingChanged);
        }
        if trusted_now < candidate.trusted_time_high_water
            || trusted_now < current_context.trusted_time_high_water
        {
            return Err(HnsaRouteError::TrustedClockRollback);
        }
        // Retain every trusted time observed under the exact current external
        // authorities, even when expiry or engine authority rejects the use.
        // A later recovery must not make an older clock value acceptable.
        candidate.trusted_time_high_water = trusted_now;
        if current_state.resource_generation != current_context.resource_generation
            || !current_state.selection_is_current(selected_commitment)
        {
            return Err(HnsaRouteError::SelectedRouteStateChanged);
        }
        if trusted_now < candidate.valid_from() || trusted_now >= candidate.valid_until() {
            return Err(HnsaRouteError::RouteNotCurrent);
        }
        if deadline >= candidate.valid_until() {
            return Err(HnsaRouteError::OpenDeadlineBeyondRoute);
        }
        if !compatible_requester_bindings(candidate.binding, requester.binding()) {
            return Err(HnsaRouteError::RequesterBindingMismatch);
        }
        let ticket = candidate
            .record
            .tickets
            .get(ticket_index)
            .ok_or(HnsaRouteError::TicketIndexOutOfRange)?
            .clone();
        self.begin_hnsr_open_with_authority_binding(
            candidate.binding,
            requester,
            relay,
            ticket,
            trusted_now,
            deadline,
            initial_window,
        )
        .map_err(HnsaRouteError::Transport)
    }
}

fn commitment_from_candidate(
    candidate: &VerifiedHnsaNamedRouteCandidate,
) -> Result<HnsaSelectionCommitment, HnsaRouteError> {
    let authorization_id = candidate
        .record
        .authorization
        .id()
        .map_err(HnsaRouteError::Authority)?;
    let delegation_id = candidate
        .record
        .delegation
        .id()
        .map_err(HnsaRouteError::Authority)?;
    let encoded = candidate
        .record
        .encode()
        .map_err(HnsaRouteError::Protocol)?;
    Ok(HnsaSelectionCommitment {
        authority_digest: candidate.authority_digest,
        route_key: candidate.route_key(),
        endpoint_key: candidate.endpoint_key(),
        authorization_serial: candidate.authorization_serial(),
        authorization_id,
        endpoint_sequence: candidate.endpoint_sequence(),
        delegation_id,
        route_sequence: candidate.sequence(),
        route_digest: blake2b_256(HNSA_ROUTE_DIGEST_DOMAIN, &[&encoded]),
    })
}

fn compatible_requester_bindings(
    candidate: HnsrTransportBinding,
    requester: HnsrTransportBinding,
) -> bool {
    candidate.runtime_session() == requester.runtime_session()
        && candidate.runtime_generation() == requester.runtime_generation()
        && candidate.policy_generation() == requester.policy_generation()
        && candidate.network() == requester.network()
        && candidate.network_magic() == requester.network_magic()
        && candidate.policy_wire_profile() == requester.policy_wire_profile()
        && candidate.resolved_wire_profile() == requester.resolved_wire_profile()
        && candidate.role() == HnsrTransportRole::Requester
        && requester.role() == HnsrTransportRole::Requester
        && candidate.service_profile() == requester.service_profile()
        && candidate.allows_private_address() == requester.allows_private_address()
}

fn authority_digest(authority: &AuthorityRecord) -> Result<[u8; 32], HnsaRouteError> {
    let encoded = authority.encode().map_err(HnsaRouteError::Authority)?;
    Ok(blake2b_256(
        HNSA_AUTHORITY_DIGEST_DOMAIN,
        &[encoded.as_bytes()],
    ))
}

fn take_state_field<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], HnsaRouteError> {
    let value = input
        .get(..N)
        .ok_or(HnsaRouteError::InvalidSequenceState)?
        .try_into()
        .map_err(|_| HnsaRouteError::InvalidSequenceState)?;
    *input = input.get(N..).ok_or(HnsaRouteError::InvalidSequenceState)?;
    Ok(value)
}

fn blake2b_256(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn is_canonical_service_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes.first() != Some(&b'-')
        && bytes.last() != Some(&b'-')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn authority_from_resource(
    resource: &VerifiedHnsResource,
) -> Result<hns_service_authority::AuthorityRecord, HnsaRouteError> {
    let mut candidates = Vec::new();
    for record in resource.resource().records() {
        let HnsResourceRecord::Txt(strings) = record else {
            continue;
        };
        if !strings.iter().any(|string| is_hsa1_candidate(string)) {
            continue;
        }
        if strings.len() != 1 {
            return Err(HnsaRouteError::NoncanonicalAuthorityTxt);
        }
        let string = strings
            .first()
            .ok_or(HnsaRouteError::NoncanonicalAuthorityTxt)?;
        candidates.push(
            std::str::from_utf8(string).map_err(|_| HnsaRouteError::NoncanonicalAuthorityTxt)?,
        );
    }
    select_authority_record(candidates).map_err(HnsaRouteError::Authority)
}

fn is_hsa1_candidate(value: &[u8]) -> bool {
    value == b"hsa1" || value.starts_with(b"hsa1 ")
}

fn ensure_anchor_current(anchor: HnsAnchor, trusted_now: u64) -> Result<(), HnsaRouteError> {
    if trusted_now < anchor.validated_at().get() || trusted_now >= anchor.valid_until().get() {
        return Err(HnsaRouteError::AnchorNotCurrent);
    }
    Ok(())
}

/// HNSA resource, named-route, or engine-binding verification failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum HnsaRouteError {
    /// A platform resource or profile-policy generation is zero.
    InvalidContextGeneration,
    /// The caller-supplied HNSA service name is not canonical.
    InvalidServiceName,
    /// The profile has no engine-defined logical-endpoint semantics.
    UnsupportedNamedProfile,
    /// No fully valid named-route candidate remained after bounded selection.
    MissingRouteCandidate,
    /// A rendezvous response exceeded the canonical per-key record bound.
    TooManyRouteCandidates {
        /// Supplied record count.
        actual: usize,
        /// Canonical maximum record count.
        maximum: usize,
    },
    /// The verified resource is not for the application-selected HNS name.
    ExpectedNameMismatch,
    /// The engine and verified HNS resource select different networks.
    HnsNetworkMismatch,
    /// The current-chain resource anchor is not valid at the trusted time.
    AnchorNotCurrent,
    /// A candidate `hsa1` TXT record is not one complete ASCII character-string.
    NoncanonicalAuthorityTxt,
    /// Fully valid routes conflict at one equal endpoint-scoped sequence.
    ConflictingRouteSequence,
    /// A persistent state blob is malformed, noncanonical, or corrupt.
    InvalidSequenceState,
    /// A persistent state belongs to another named service.
    SequenceStateScopeMismatch,
    /// Resource or authority state moved behind its durable generation.
    SequenceStateRollback,
    /// A signed equal-sequence conflict permanently blocked this authority epoch.
    SequenceStateConflicted,
    /// Bounded endpoint history was exhausted for this authority epoch.
    SequenceStateExhausted,
    /// Persistent sequence-state generation cannot advance without wrapping.
    SequenceStateGenerationExhausted,
    /// Equal accepted replacement sequences carry different object digests.
    ConflictingSequenceState,
    /// A selected signed object is older than the durable replacement state.
    SequenceRollback,
    /// The latest committed state no longer authorizes this opaque selection.
    SelectedRouteStateChanged,
    /// The platform supplied a newly accepted resource or chain anchor.
    ResourceBindingChanged,
    /// The platform advanced its accepted HNS-resource generation.
    ResourceGenerationChanged,
    /// The application profile generation or exact profile rules changed.
    ProfilePolicyChanged,
    /// Trusted time moved below the candidate or caller-held high-water mark.
    TrustedClockRollback,
    /// The route or its authenticated HNS anchor is outside its time interval.
    RouteNotCurrent,
    /// The requested OPEN deadline reaches or exceeds route/anchor expiry.
    OpenDeadlineBeyondRoute,
    /// The requester runtime is from another engine/profile security epoch.
    RequesterBindingMismatch,
    /// The selected relay endpoint index does not exist.
    TicketIndexOutOfRange,
    /// Canonical HNSA authority selection or signature failure.
    Authority(AuthorityError),
    /// Canonical HNSR route decoding or verification failure.
    Protocol(HnsrProtocolError),
    /// Engine HNSR requester policy or runtime binding failure.
    Transport(HnsrTransportError),
}

impl fmt::Display for HnsaRouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContextGeneration => {
                formatter.write_str("HNSA external authority generation is zero")
            }
            Self::InvalidServiceName => formatter.write_str("HNSA service name is not canonical"),
            Self::UnsupportedNamedProfile => {
                formatter.write_str("unsupported HNSA named-route profile")
            }
            Self::MissingRouteCandidate => {
                formatter.write_str("no valid HNSA named-route candidate was selected")
            }
            Self::TooManyRouteCandidates { actual, maximum } => write!(
                formatter,
                "too many HNSA named-route candidates: {actual} exceeds {maximum}"
            ),
            Self::ExpectedNameMismatch => {
                formatter.write_str("verified HNS resource does not match the expected name")
            }
            Self::HnsNetworkMismatch => {
                formatter.write_str("verified HNS resource belongs to another network")
            }
            Self::AnchorNotCurrent => {
                formatter.write_str("verified HNS resource anchor is not current")
            }
            Self::NoncanonicalAuthorityTxt => {
                formatter.write_str("HNSA authority TXT is not one canonical character-string")
            }
            Self::ConflictingRouteSequence => {
                formatter.write_str("conflicting HNSA routes have the same replacement sequence")
            }
            Self::InvalidSequenceState => {
                formatter.write_str("HNSA named-route sequence state is invalid")
            }
            Self::SequenceStateScopeMismatch => {
                formatter.write_str("HNSA named-route state has another service scope")
            }
            Self::SequenceStateRollback => {
                formatter.write_str("HNSA named-route state moved behind its durable generation")
            }
            Self::SequenceStateConflicted => {
                formatter.write_str("HNSA named-route state is blocked by signed equivocation")
            }
            Self::SequenceStateExhausted => {
                formatter.write_str("HNSA named-route endpoint history is exhausted")
            }
            Self::SequenceStateGenerationExhausted => {
                formatter.write_str("HNSA named-route state generation is exhausted")
            }
            Self::ConflictingSequenceState => {
                formatter.write_str("conflicting HNSA objects occupy an accepted sequence")
            }
            Self::SequenceRollback => {
                formatter.write_str("HNSA named-route replacement sequence moved backwards")
            }
            Self::SelectedRouteStateChanged => {
                formatter.write_str("HNSA selected route is not current in committed state")
            }
            Self::ResourceBindingChanged => {
                formatter.write_str("accepted HNS resource binding changed")
            }
            Self::ResourceGenerationChanged => {
                formatter.write_str("accepted HNS resource generation changed")
            }
            Self::ProfilePolicyChanged => {
                formatter.write_str("HNSA application profile policy changed")
            }
            Self::TrustedClockRollback => formatter.write_str("HNSA trusted clock moved backwards"),
            Self::RouteNotCurrent => formatter.write_str("HNSA named route is not current"),
            Self::OpenDeadlineBeyondRoute => {
                formatter.write_str("HNSA circuit deadline exceeds route authority")
            }
            Self::RequesterBindingMismatch => {
                formatter.write_str("HNSA route and HNSR requester bindings differ")
            }
            Self::TicketIndexOutOfRange => {
                formatter.write_str("HNSA relay endpoint index is out of range")
            }
            Self::Authority(error) => write!(formatter, "HNSA authority failed: {error}"),
            Self::Protocol(error) => write!(formatter, "HNSA named route failed: {error}"),
            Self::Transport(error) => write!(formatter, "HNSA engine binding failed: {error}"),
        }
    }
}

impl Error for HnsaRouteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests construct compact signed fixtures and fail immediately"
)]
mod tests {
    use hns_browser_testkit::verified_regtest_hns_resource;
    use hns_hnsr_protocol::{
        DEFAULT_WINDOW, HNS_WEB_V1, HNSR_RELAY_SERVICE, HnsrRequesterConfig, NamedRouteRecordV2,
        RelayTicket, named_route_key,
    };
    use hns_resolution_policy::{Network, PolicyConfig, PolicySnapshot};
    use hns_service_authority::{
        AuthorityError, AuthorityRecord, EndpointDelegationV1, ServiceAuthorizationV1,
        ServiceIdentity, public_key as authority_public_key,
    };

    use super::*;
    use crate::{
        AuthenticatedHnsrPeer, AuthorityState, DENUO_EXTENSION_SERVICE, EngineConfig,
        ExperimentalNetwork, ExperimentalPeerState, ExperimentalWireProfile, HnsrRequesterRuntime,
        PeerIdentity, RegistryHello, RuntimeSessionId, ServiceMask,
    };

    const NAME: &[u8] = b"alpha";
    const SERVICE: &str = "web";
    const MAGIC: u32 = 0xae38_95cf;

    fn ready_engine(network: Network, session: [u8; 16]) -> Engine {
        let engine = Engine::new(EngineConfig::new(
            RuntimeSessionId::new(session).unwrap(),
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

    fn policy() -> NamedRoutePolicy {
        NamedRoutePolicy {
            maximum_route_lifetime: 900,
            allowed_authorization_flags: 0,
            allowed_endpoint_capabilities: 1,
            required_endpoint_capabilities: 1,
            expected_constraints_hash: [0; 32],
            allow_private_relays: true,
        }
    }

    fn encode_txt_records(records: &[Vec<Vec<u8>>]) -> Vec<u8> {
        let mut resource = vec![0];
        for strings in records {
            resource.push(6);
            resource.push(u8::try_from(strings.len()).unwrap());
            for string in strings {
                resource.push(u8::try_from(string.len()).unwrap());
                resource.extend_from_slice(string);
            }
        }
        resource
    }

    fn authority() -> (AuthorityRecord, [u8; 32]) {
        let private_key = [11; 32];
        (
            AuthorityRecord {
                root_key: authority_public_key(&private_key).unwrap(),
                epoch: 3,
            },
            private_key,
        )
    }

    fn verified_resource(authority: &AuthorityRecord) -> (VerifiedHnsResource, u64) {
        let text = authority.encode().unwrap();
        let resource = encode_txt_records(&[vec![text.into_bytes()]]);
        let (verified, now) = verified_regtest_hns_resource(NAME, &resource).unwrap();
        (verified, u64::from(now))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "test fixtures vary each independent replacement sequence and signing key"
    )]
    fn signed_route_with(
        name_hash: [u8; 32],
        root_private_key: &[u8; 32],
        now: u64,
        service_name: &str,
        authorization_serial: u64,
        endpoint_private_key: [u8; 32],
        endpoint_sequence: u64,
        route_sequence: u64,
        relay_private_key: [u8; 32],
    ) -> Vec<u8> {
        let service_private_key = [12; 32];
        let identity = ServiceIdentity {
            network_magic: MAGIC,
            name_hash,
            service_name: service_name.to_owned(),
            profile_id: HNS_WEB_V1,
        };
        let mut authorization = ServiceAuthorizationV1 {
            network_magic: MAGIC,
            name_hash,
            authority_epoch: 3,
            service_name: service_name.to_owned(),
            profile_id: HNS_WEB_V1,
            service_key: authority_public_key(&service_private_key).unwrap(),
            flags: 0,
            serial: authorization_serial,
            valid_from_height: 1,
            valid_until_height: 100,
            max_endpoint_lifetime: 3_600,
            root_signature: Vec::new(),
        };
        authorization.sign(root_private_key).unwrap();
        let endpoint_key = authority_public_key(&endpoint_private_key).unwrap();
        let mut delegation = EndpointDelegationV1 {
            network_magic: MAGIC,
            authorization_id: authorization.id().unwrap(),
            endpoint_key,
            endpoint_sequence,
            issued_at: now,
            expires_at: now + 1_800,
            capabilities: 1,
            constraints_hash: [0; 32],
            service_signature: Vec::new(),
        };
        delegation.sign(&service_private_key).unwrap();
        let mut ticket = RelayTicket {
            network_magic: MAGIC,
            profile: HNS_WEB_V1,
            transport: 0,
            host_type: 1,
            host: [0; 16],
            port: 14_039,
            relay_key: hns_hnsr_protocol::public_key(&relay_private_key).unwrap(),
            endpoint_key,
            reservation_id: [16; 16],
            issued_at: now,
            expires_at: now + 1_800,
            max_active_circuits: 8,
            max_bytes_per_circuit: 1_048_576,
            max_total_bytes: 8_388_608,
            flags: 0,
            relay_signature: Vec::new(),
            endpoint_signature: Vec::new(),
        };
        ticket.sign_relay(&relay_private_key).unwrap();
        ticket.sign_endpoint(&endpoint_private_key).unwrap();
        let mut route = NamedRouteRecordV2 {
            route_key: named_route_key(&identity).unwrap(),
            profile: HNS_WEB_V1,
            sequence: route_sequence,
            issued_at: now,
            expires_at: now + 900,
            authorization,
            delegation,
            tickets: vec![ticket],
            endpoint_signature: Vec::new(),
        };
        route.sign(&endpoint_private_key).unwrap();
        route.encode().unwrap()
    }

    fn signed_route(
        name_hash: [u8; 32],
        root_private_key: &[u8; 32],
        now: u64,
        service_name: &str,
    ) -> Vec<u8> {
        signed_route_with(
            name_hash,
            root_private_key,
            now,
            service_name,
            1,
            [13; 32],
            1,
            1,
            [14; 32],
        )
    }

    fn context(
        resource_generation: u64,
        profile_policy_generation: u64,
        trusted_time_high_water: u64,
    ) -> HnsaNamedRouteContext {
        HnsaNamedRouteContext::new(
            resource_generation,
            profile_policy_generation,
            trusted_time_high_water,
            policy(),
        )
        .unwrap()
    }

    fn request(now: u64) -> HnsaNamedRouteRequest<'static> {
        HnsaNamedRouteRequest::new(NAME, SERVICE, HNS_WEB_V1, context(1, 1, now), now)
    }

    fn select_one(
        engine: &Engine,
        resource: &VerifiedHnsResource,
        route: &[u8],
        state: &mut HnsaNamedRouteState,
        now: u64,
    ) -> SelectedHnsaNamedRoute {
        engine
            .verify_and_select_hnsa_named_routes(resource, &[route.to_vec()], state, request(now))
            .unwrap()
            .pop()
            .unwrap()
    }

    fn resign_complete_chain(
        mut route: NamedRouteRecordV2,
        root_private_key: &[u8; 32],
        endpoint_private_key: &[u8; 32],
    ) -> Vec<u8> {
        route.authorization.sign(root_private_key).unwrap();
        route.delegation.authorization_id = route.authorization.id().unwrap();
        route.delegation.sign(&[12; 32]).unwrap();
        route.sign(endpoint_private_key).unwrap();
        route.encode().unwrap()
    }

    fn requester_and_relay(
        engine: &Engine,
        now: u64,
        relay_private_key: [u8; 32],
    ) -> (HnsrRequesterRuntime, AuthenticatedHnsrPeer) {
        let mut requester = engine
            .start_hnsr_requester(
                1,
                HnsrRequesterConfig {
                    network_magic: MAGIC,
                    profile: HNS_WEB_V1,
                    allow_private_relay: true,
                    maximum_circuits: 8,
                    maximum_queue_bytes: 65_536,
                    maximum_bytes_per_circuit: 1_048_576,
                },
                now,
            )
            .unwrap();
        let genesis = crate::private_transport::canonical_genesis_hash(Network::Regtest);
        let hello = RegistryHello::denuo_v1(
            ExperimentalNetwork::Regtest,
            genesis,
            Vec::new(),
            65_535,
            8,
            0,
        )
        .unwrap();
        let registry = crate::NegotiatedRegistry::negotiate(&hello, &hello).unwrap();
        let peer = ExperimentalPeerState::new(
            ExperimentalWireProfile::DenuoV1,
            ExperimentalNetwork::Regtest,
            genesis,
            registry.fingerprint,
            ServiceMask::new(DENUO_EXTENSION_SERVICE.value() | HNSR_RELAY_SERVICE),
        );
        let identity =
            PeerIdentity::new(hns_hnsr_protocol::public_key(&relay_private_key).unwrap()).unwrap();
        let relay = requester
            .authenticate_relay(engine, "relay-a".to_owned(), identity, peer, registry)
            .unwrap();
        (requester, relay)
    }

    #[test]
    fn selects_complete_chain_persists_state_and_opens_without_exposing_ticket() {
        let (authority, root_private_key) = authority();
        let (resource, now) = verified_resource(&authority);
        let route = signed_route(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
        );
        let engine = ready_engine(Network::Regtest, [31; 16]);
        let mut state = HnsaNamedRouteState::new();
        let mut selected = select_one(&engine, &resource, &route, &mut state, now);

        assert_eq!(selected.name(), NAME);
        assert_eq!(selected.service_name(), SERVICE);
        assert_eq!(selected.profile_id(), HNS_WEB_V1);
        assert_eq!(selected.authorization_serial(), 1);
        assert_eq!(selected.endpoint_sequence(), 1);
        assert_eq!(selected.route_sequence(), 1);
        assert_eq!(selected.relay_endpoint_count(), 1);
        let endpoint = selected.relay_endpoint(0).unwrap();
        assert_eq!(endpoint.port(), 14_039);
        assert_eq!(
            endpoint.relay_key(),
            authority_public_key(&[14; 32]).unwrap()
        );
        assert_eq!(endpoint.valid_until(), selected.valid_until());
        assert!(state.is_active());
        assert_eq!(state.endpoint_history_count(), 1);
        assert!(state.generation() > 0);
        let encoded_state = state.encode().unwrap();
        assert!(encoded_state.len() <= MAX_HNSA_NAMED_ROUTE_STATE_BYTES);
        let state = HnsaNamedRouteState::decode(&encoded_state).unwrap();
        assert_eq!(state.encode().unwrap(), encoded_state);
        let debug = format!("{selected:?}");
        assert!(!debug.contains("alpha"));
        assert!(!debug.contains("web"));
        let (mut requester, relay) = requester_and_relay(&engine, now, [14; 32]);
        let raw_ticket = NamedRouteRecordV2::decode(&route)
            .unwrap()
            .tickets
            .remove(0);
        assert!(matches!(
            requester.begin_open(&engine, &relay, raw_ticket, now, now + 10, DEFAULT_WINDOW,),
            Err(HnsrTransportError::NamedRouteAuthorityRequired)
        ));
        let current_context = context(1, 1, now);
        let open = engine
            .begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &resource,
                &current_context,
                &mut requester,
                &relay,
                endpoint.ticket_index(),
                now,
                now + 10,
                DEFAULT_WINDOW,
            )
            .unwrap();
        assert_eq!(&open.destination, relay.peer_id());
    }

    #[test]
    fn request_identity_and_candidate_bounds_fail_closed() {
        let (authority, root_private_key) = authority();
        let (resource, now) = verified_resource(&authority);
        let route = signed_route(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            "chat",
        );
        let engine = ready_engine(Network::Regtest, [32; 16]);
        let mut state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                std::slice::from_ref(&route),
                &mut state,
                request(now),
            ),
            Err(HnsaRouteError::Authority(AuthorityError::Missing))
        ));

        let mut wrong_name = request(now);
        wrong_name.expected_name = b"beta";
        let mut state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                std::slice::from_ref(&route),
                &mut state,
                wrong_name,
            ),
            Err(HnsaRouteError::ExpectedNameMismatch)
        ));

        let invalid_service =
            HnsaNamedRouteRequest::new(NAME, "hns.chat", HNS_WEB_V1, context(1, 1, now), now);
        let mut state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                std::slice::from_ref(&route),
                &mut state,
                invalid_service,
            ),
            Err(HnsaRouteError::InvalidServiceName)
        ));
        let unsupported =
            HnsaNamedRouteRequest::new(NAME, SERVICE, 0xff00, context(1, 1, now), now);
        let mut state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                std::slice::from_ref(&route),
                &mut state,
                unsupported,
            ),
            Err(HnsaRouteError::UnsupportedNamedProfile)
        ));
        let mut state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &vec![route; MAX_RECORDS_PER_KEY + 1],
                &mut state,
                request(now),
            ),
            Err(HnsaRouteError::TooManyRouteCandidates { .. })
        ));
        let mut state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &[vec![1]],
                &mut state,
                request(now),
            ),
            Err(HnsaRouteError::MissingRouteCandidate)
        ));
    }

    #[test]
    fn authority_txt_is_single_ascii_string_and_unambiguous() {
        let (authority, root_private_key) = authority();
        let (original, now) = verified_resource(&authority);
        let route = signed_route(
            original.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
        );
        let text = authority.encode().unwrap().into_bytes();

        let missing = encode_txt_records(&[vec![b"unrelated".to_vec()]]);
        let (missing, _) = verified_regtest_hns_resource(NAME, &missing).unwrap();
        let engine = ready_engine(Network::Regtest, [33; 16]);
        let mut state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &missing,
                std::slice::from_ref(&route),
                &mut state,
                request(now),
            ),
            Err(HnsaRouteError::Authority(AuthorityError::Missing))
        ));

        let split = encode_txt_records(&[vec![text.clone(), b"extra".to_vec()]]);
        let (split, _) = verified_regtest_hns_resource(NAME, &split).unwrap();
        let mut state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &split,
                std::slice::from_ref(&route),
                &mut state,
                request(now),
            ),
            Err(HnsaRouteError::NoncanonicalAuthorityTxt)
        ));

        let ambiguous = encode_txt_records(&[vec![text.clone()], vec![text]]);
        let (ambiguous, _) = verified_regtest_hns_resource(NAME, &ambiguous).unwrap();
        let mut state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &ambiguous,
                &[route],
                &mut state,
                request(now),
            ),
            Err(HnsaRouteError::Authority(AuthorityError::Ambiguous))
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one bounded batch regression covers conflicts at all three replacement layers"
    )]
    fn batch_selection_is_multilevel_bounded_and_conflict_safe() {
        let (authority, root_private_key) = authority();
        let (resource, now) = verified_resource(&authority);
        let first = signed_route(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
        );
        let second = signed_route_with(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
            1,
            [13; 32],
            1,
            2,
            [14; 32],
        );
        let concurrent_endpoint = signed_route_with(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
            1,
            [15; 32],
            1,
            1,
            [16; 32],
        );
        let engine = ready_engine(Network::Regtest, [34; 16]);
        let mut state = HnsaNamedRouteState::new();
        let selected = engine
            .verify_and_select_hnsa_named_routes(
                &resource,
                &[vec![1], first.clone(), second.clone(), concurrent_endpoint],
                &mut state,
                request(now),
            )
            .unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected
                .iter()
                .find(|route| route.endpoint_key() == authority_public_key(&[13; 32]).unwrap())
                .unwrap()
                .route_sequence(),
            2
        );

        let mut route_conflict = NamedRouteRecordV2::decode(&second).unwrap();
        route_conflict.expires_at -= 1;
        route_conflict.sign(&[13; 32]).unwrap();
        let route_conflict = route_conflict.encode().unwrap();
        let mut conflict_state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &[second.clone(), route_conflict],
                &mut conflict_state,
                request(now),
            ),
            Err(HnsaRouteError::ConflictingRouteSequence)
        ));
        assert!(conflict_state.is_conflicted());
        let conflict_state =
            HnsaNamedRouteState::decode(&conflict_state.encode().unwrap()).unwrap();
        assert!(conflict_state.is_conflicted());

        let mut authorization_conflict = NamedRouteRecordV2::decode(&first).unwrap();
        authorization_conflict.authorization.max_endpoint_lifetime -= 1;
        let authorization_conflict =
            resign_complete_chain(authorization_conflict, &root_private_key, &[13; 32]);
        let mut conflict_state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &[first.clone(), authorization_conflict],
                &mut conflict_state,
                request(now),
            ),
            Err(HnsaRouteError::Authority(
                AuthorityError::ConflictingSequence
            ))
        ));
        assert!(conflict_state.is_conflicted());

        let mut delegation_conflict = NamedRouteRecordV2::decode(&first).unwrap();
        delegation_conflict.delegation.expires_at -= 1;
        delegation_conflict.delegation.sign(&[12; 32]).unwrap();
        delegation_conflict.sign(&[13; 32]).unwrap();
        let delegation_conflict = delegation_conflict.encode().unwrap();
        let mut conflict_state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &[first, delegation_conflict],
                &mut conflict_state,
                request(now),
            ),
            Err(HnsaRouteError::Authority(
                AuthorityError::ConflictingSequence
            ))
        ));
        assert!(conflict_state.is_conflicted());
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                std::slice::from_ref(&second),
                &mut conflict_state,
                request(now),
            ),
            Err(HnsaRouteError::SequenceStateConflicted)
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one persistence regression covers rollback and unusable authorization and delegation advancement"
    )]
    fn persistent_state_rejects_rollback_and_advances_on_unusable_newer_layers() {
        let (authority, root_private_key) = authority();
        let (resource, now) = verified_resource(&authority);
        let first = signed_route(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
        );
        let second = signed_route_with(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
            1,
            [13; 32],
            1,
            2,
            [14; 32],
        );
        let engine = ready_engine(Network::Regtest, [35; 16]);
        let mut state = HnsaNamedRouteState::new();
        let mut selected = select_one(&engine, &resource, &second, &mut state, now);
        let encoded = state.encode().unwrap();
        assert_eq!(
            HnsaNamedRouteState::decode(&encoded)
                .unwrap()
                .encode()
                .unwrap(),
            encoded
        );
        let mut corrupt = encoded.clone();
        *corrupt.get_mut(20).unwrap() ^= 1;
        assert!(matches!(
            HnsaNamedRouteState::decode(&corrupt),
            Err(HnsaRouteError::InvalidSequenceState)
        ));
        let mut malformed = encoded.clone();
        *malformed.get_mut(21).unwrap() = 2;
        let payload_size = malformed.len() - HNSA_STATE_CHECKSUM_SIZE;
        let checksum = blake2b_256(
            HNSA_STATE_CHECKSUM_DOMAIN,
            &[malformed.get(..payload_size).unwrap()],
        );
        malformed
            .get_mut(payload_size..)
            .unwrap()
            .copy_from_slice(&checksum);
        assert!(matches!(
            HnsaNamedRouteState::decode(&malformed),
            Err(HnsaRouteError::InvalidSequenceState)
        ));

        let mut authorization_conflict = NamedRouteRecordV2::decode(&second).unwrap();
        authorization_conflict.authorization.max_endpoint_lifetime -= 1;
        let authorization_conflict =
            resign_complete_chain(authorization_conflict, &root_private_key, &[13; 32]);
        let mut conflict_state = HnsaNamedRouteState::decode(&encoded).unwrap();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &[authorization_conflict],
                &mut conflict_state,
                request(now),
            ),
            Err(HnsaRouteError::ConflictingSequenceState)
        ));
        assert!(conflict_state.is_conflicted());

        let mut delegation_conflict = NamedRouteRecordV2::decode(&second).unwrap();
        delegation_conflict.delegation.expires_at -= 1;
        delegation_conflict.delegation.sign(&[12; 32]).unwrap();
        delegation_conflict.sign(&[13; 32]).unwrap();
        let mut conflict_state = HnsaNamedRouteState::decode(&encoded).unwrap();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &[delegation_conflict.encode().unwrap()],
                &mut conflict_state,
                request(now),
            ),
            Err(HnsaRouteError::ConflictingSequenceState)
        ));
        assert!(conflict_state.is_conflicted());

        let mut route_conflict = NamedRouteRecordV2::decode(&second).unwrap();
        route_conflict.expires_at -= 1;
        route_conflict.sign(&[13; 32]).unwrap();
        let mut conflict_state = HnsaNamedRouteState::decode(&encoded).unwrap();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &[route_conflict.encode().unwrap()],
                &mut conflict_state,
                request(now),
            ),
            Err(HnsaRouteError::ConflictingSequenceState)
        ));
        assert!(conflict_state.is_conflicted());

        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &[first],
                &mut state,
                request(now),
            ),
            Err(HnsaRouteError::SequenceRollback)
        ));

        let generation = state.generation();
        let mut revoked = NamedRouteRecordV2::decode(&second).unwrap();
        revoked.sequence = 3;
        revoked.delegation.endpoint_sequence = 2;
        revoked.delegation.capabilities = 0;
        revoked.delegation.sign(&[12; 32]).unwrap();
        revoked.sign(&[13; 32]).unwrap();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &[second, revoked.encode().unwrap()],
                &mut state,
                request(now),
            ),
            Err(HnsaRouteError::MissingRouteCandidate)
        ));
        assert!(state.generation() > generation);
        let (mut requester, relay) = requester_and_relay(&engine, now, [14; 32]);
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &resource,
                &context(1, 1, now),
                &mut requester,
                &relay,
                0,
                now,
                now + 10,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::SelectedRouteStateChanged)
        ));

        let first = signed_route(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
        );
        let mut state = HnsaNamedRouteState::new();
        let mut old_endpoint = select_one(&engine, &resource, &first, &mut state, now);
        let mut newer_authorization = NamedRouteRecordV2::decode(&signed_route_with(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
            2,
            [15; 32],
            1,
            1,
            [16; 32],
        ))
        .unwrap();
        *newer_authorization.endpoint_signature.first_mut().unwrap() ^= 1;
        let generation = state.generation();
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &[newer_authorization.encode().unwrap()],
                &mut state,
                request(now),
            ),
            Err(HnsaRouteError::MissingRouteCandidate)
        ));
        assert!(state.generation() > generation);
        let (mut requester, relay) = requester_and_relay(&engine, now, [14; 32]);
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut old_endpoint,
                &state,
                &resource,
                &context(1, 1, now),
                &mut requester,
                &relay,
                0,
                now,
                now + 30,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::SelectedRouteStateChanged)
        ));
    }

    #[test]
    fn unrelated_endpoint_history_does_not_stale_current_selection() {
        let (authority, root_private_key) = authority();
        let (resource, now) = verified_resource(&authority);
        let endpoint_a = signed_route(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
        );
        let endpoint_b = signed_route_with(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
            1,
            [15; 32],
            1,
            1,
            [16; 32],
        );
        let engine = ready_engine(Network::Regtest, [39; 16]);
        let mut state = HnsaNamedRouteState::new();
        let mut selected_a = select_one(&engine, &resource, &endpoint_a, &mut state, now);
        let selected_b = engine
            .verify_and_select_hnsa_named_routes(&resource, &[endpoint_b], &mut state, request(now))
            .unwrap();
        assert_eq!(selected_b.len(), 1);
        assert_eq!(state.endpoint_history_count(), 2);

        let (mut requester, relay) = requester_and_relay(&engine, now, [14; 32]);
        engine
            .begin_hnsa_named_route_open(
                &mut selected_a,
                &state,
                &resource,
                &context(1, 1, now),
                &mut requester,
                &relay,
                0,
                now,
                now + 10,
                DEFAULT_WINDOW,
            )
            .unwrap();
    }

    #[test]
    fn endpoint_capacity_is_sticky_until_verified_authority_rotation() {
        let (authority, root_private_key) = authority();
        let (resource, now) = verified_resource(&authority);
        let route = signed_route(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
        );
        let engine = ready_engine(Network::Regtest, [40; 16]);
        let mut state = HnsaNamedRouteState::new();
        let _selected = select_one(&engine, &resource, &route, &mut state, now);
        for index in 0..(MAX_HNSA_NAMED_ROUTE_ENDPOINTS - 1) {
            let mut endpoint_key = [0_u8; 33];
            endpoint_key[0] = 2;
            endpoint_key[31..].copy_from_slice(&u16::try_from(index).unwrap().to_be_bytes());
            state
                .advance_delegation(endpoint_key, 1, [u8::try_from(index + 1).unwrap(); 32])
                .unwrap();
        }
        assert_eq!(
            state.endpoint_history_count(),
            MAX_HNSA_NAMED_ROUTE_ENDPOINTS
        );
        assert!(matches!(
            state.advance_delegation([3; 33], 1, [99; 32]),
            Err(HnsaRouteError::SequenceStateExhausted)
        ));
        assert!(state.is_exhausted());
        let encoded = state.encode().unwrap();
        assert_eq!(encoded.len(), MAX_HNSA_NAMED_ROUTE_STATE_BYTES);
        let mut state = HnsaNamedRouteState::decode(&encoded).unwrap();
        assert!(state.is_exhausted());
        let higher_authorization = signed_route_with(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
            2,
            [15; 32],
            1,
            1,
            [16; 32],
        );
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &resource,
                &[higher_authorization],
                &mut state,
                request(now),
            ),
            Err(HnsaRouteError::SequenceStateExhausted)
        ));

        let rotated_private_key = [21; 32];
        let rotated_authority = AuthorityRecord {
            root_key: authority_public_key(&rotated_private_key).unwrap(),
            epoch: 3,
        };
        let (rotated_resource, _) = verified_resource(&rotated_authority);
        let rotated_route = signed_route(
            rotated_resource.name_hash().into_bytes(),
            &rotated_private_key,
            now,
            SERVICE,
        );
        assert!(matches!(
            engine.verify_and_select_hnsa_named_routes(
                &rotated_resource,
                std::slice::from_ref(&rotated_route),
                &mut state,
                request(now),
            ),
            Err(HnsaRouteError::SequenceStateRollback)
        ));
        let rotated_request =
            HnsaNamedRouteRequest::new(NAME, SERVICE, HNS_WEB_V1, context(2, 1, now), now);
        let selected = engine
            .verify_and_select_hnsa_named_routes(
                &rotated_resource,
                &[rotated_route],
                &mut state,
                rotated_request,
            )
            .unwrap();
        assert_eq!(selected.len(), 1);
        assert!(state.is_active());
        assert_eq!(state.resource_generation(), 2);
        assert_eq!(state.endpoint_history_count(), 1);
    }

    #[test]
    fn state_mismatch_observes_time_before_a_lower_retry() {
        let (authority, root_private_key) = authority();
        let (resource, now) = verified_resource(&authority);
        let route = signed_route(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
        );
        let engine = ready_engine(Network::Regtest, [41; 16]);
        let mut state = HnsaNamedRouteState::new();
        let mut selected = select_one(&engine, &resource, &route, &mut state, now);
        let wrong_state = HnsaNamedRouteState::new();
        let (mut requester, relay) = requester_and_relay(&engine, now, [14; 32]);
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &wrong_state,
                &resource,
                &context(1, 1, now),
                &mut requester,
                &relay,
                0,
                now + 2,
                now + 30,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::SelectedRouteStateChanged)
        ));
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &resource,
                &context(1, 1, now),
                &mut requester,
                &relay,
                0,
                now + 1,
                now + 30,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::TrustedClockRollback)
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one lifecycle regression exercises every authority invalidation boundary against the same opaque selection"
    )]
    fn network_resource_policy_generation_and_clock_changes_fail_closed_at_open() {
        let (authority, root_private_key) = authority();
        let (resource, now) = verified_resource(&authority);
        let route = signed_route(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
        );

        let mainnet = ready_engine(Network::Mainnet, [34; 16]);
        let mut public_policy = policy();
        public_policy.allow_private_relays = false;
        let mut mainnet_state = HnsaNamedRouteState::new();
        assert!(matches!(
            mainnet.verify_and_select_hnsa_named_routes(
                &resource,
                std::slice::from_ref(&route),
                &mut mainnet_state,
                HnsaNamedRouteRequest::new(
                    NAME,
                    SERVICE,
                    HNS_WEB_V1,
                    HnsaNamedRouteContext::new(1, 1, now, public_policy).unwrap(),
                    now,
                ),
            ),
            Err(HnsaRouteError::HnsNetworkMismatch)
        ));

        let engine = ready_engine(Network::Regtest, [36; 16]);
        let mut state = HnsaNamedRouteState::new();
        let mut selected = select_one(&engine, &resource, &route, &mut state, now);
        let (mut requester, relay) = requester_and_relay(&engine, now, [14; 32]);
        let current_context = context(1, 1, now);

        let wrong_state = HnsaNamedRouteState::new();
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &wrong_state,
                &resource,
                &current_context,
                &mut requester,
                &relay,
                0,
                now,
                now + 30,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::SelectedRouteStateChanged)
        ));

        let mut changed_policy = policy();
        changed_policy.expected_constraints_hash = [1; 32];
        let changed_policy = HnsaNamedRouteContext::new(1, 1, now, changed_policy).unwrap();
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &resource,
                &changed_policy,
                &mut requester,
                &relay,
                0,
                now,
                now + 30,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::ProfilePolicyChanged)
        ));

        let advanced_resource = context(2, 1, now);
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &resource,
                &advanced_resource,
                &mut requester,
                &relay,
                0,
                now,
                now + 30,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::ResourceGenerationChanged)
        ));

        let replacement_text = authority.encode().unwrap();
        let replacement = encode_txt_records(&[
            vec![replacement_text.into_bytes()],
            vec![b"new resource commitment".to_vec()],
        ]);
        let (replacement, _) = verified_regtest_hns_resource(NAME, &replacement).unwrap();
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &replacement,
                &current_context,
                &mut requester,
                &relay,
                0,
                now,
                now + 30,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::ResourceBindingChanged)
        ));

        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &resource,
                &current_context,
                &mut requester,
                &relay,
                9,
                now,
                now + 30,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::TicketIndexOutOfRange)
        ));

        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &resource,
                &current_context,
                &mut requester,
                &relay,
                0,
                now,
                now + 900,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::OpenDeadlineBeyondRoute)
        ));
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &resource,
                &current_context,
                &mut requester,
                &relay,
                0,
                now + 900,
                now + 901,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::RouteNotCurrent)
        ));
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &resource,
                &current_context,
                &mut requester,
                &relay,
                0,
                now + 899,
                now + 900,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::TrustedClockRollback)
        ));
    }

    #[test]
    fn requester_epoch_cannot_be_substituted_or_rebound_after_policy_change() {
        assert!(matches!(
            HnsaNamedRouteContext::new(0, 1, 0, policy()),
            Err(HnsaRouteError::InvalidContextGeneration)
        ));
        assert!(matches!(
            HnsaNamedRouteContext::new(1, 0, 0, policy()),
            Err(HnsaRouteError::InvalidContextGeneration)
        ));

        let (authority, root_private_key) = authority();
        let (resource, now) = verified_resource(&authority);
        let route = signed_route(
            resource.name_hash().into_bytes(),
            &root_private_key,
            now,
            SERVICE,
        );
        let engine = ready_engine(Network::Regtest, [37; 16]);
        let mut state = HnsaNamedRouteState::new();
        let mut selected = select_one(&engine, &resource, &route, &mut state, now);
        let other = ready_engine(Network::Regtest, [38; 16]);
        let (mut other_requester, other_relay) = requester_and_relay(&other, now, [14; 32]);
        let current_context = context(1, 1, now);
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &resource,
                &current_context,
                &mut other_requester,
                &other_relay,
                0,
                now,
                now + 30,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::RequesterBindingMismatch)
        ));

        let (mut requester, relay) = requester_and_relay(&engine, now, [14; 32]);
        let snapshot = engine.snapshot().unwrap();
        let mut next_policy: PolicyConfig = snapshot.policy.config();
        next_policy.authenticated_authoritative_doh = !next_policy.authenticated_authoritative_doh;
        engine
            .update_policy(snapshot.policy.generation(), next_policy)
            .unwrap();
        assert!(matches!(
            engine.begin_hnsa_named_route_open(
                &mut selected,
                &state,
                &resource,
                &current_context,
                &mut requester,
                &relay,
                0,
                now,
                now + 30,
                DEFAULT_WINDOW,
            ),
            Err(HnsaRouteError::Transport(_))
        ));
    }
}
