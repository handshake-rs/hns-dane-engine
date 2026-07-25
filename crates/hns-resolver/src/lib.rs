//! Locally validated TLSA resolution with bounded, DNSSEC-verified CNAME chasing.
//!
//! This crate is transport-neutral. Callers fetch each exact query over a
//! policy-admitted transport, correlate the response, and feed it here.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "DNSSEC and TLSA protocol terminology is documented at crate level"
)]

use std::collections::HashSet;

use hns_dns_wire::{CLASS_IN, Ds, Message, Name, Query, Rdata, RecordType, ResourceRecord, Tlsa};
use hns_dnssec::{
    AuthenticatedDnskeys, DnssecError, DnssecLimits, VerifiedRrset, authenticate_dnskeys,
    verify_rrset_with_keys,
};
use hns_icann_dane::TlsaOwner;
use hns_light_chain::{HnsAnchor, VerifiedHnsResource};
use thiserror::Error;

/// TLSA service transport shared with automatic ICANN DANE discovery.
pub use hns_icann_dane::TlsaTransport as ServiceTransport;

/// HTTPS uses TCP TLSA service labels.
pub const HTTPS_PORT: u16 = 443;
/// Default maximum CNAME indirections.
pub const DEFAULT_MAX_CNAME_HOPS: usize = 16;
/// Default maximum TLSA alternatives.
pub const DEFAULT_MAX_TLSA_RECORDS: usize = 64;
/// HSD's default TTL for records projected from a name resource.
pub const HNS_RESOURCE_TTL: u32 = 21_600;

/// HNS resource, DS, DNSKEY, and signature evidence for one TLD authority.
///
/// Construction starts from a non-forgeable [`VerifiedHnsResource`]. This
/// keeps arbitrary caller-provided DS records out of the HNS browser path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsDnssecAuthority {
    evidence: HnsAuthorityEvidence,
    keys: AuthenticatedDnskeys,
}

impl HnsDnssecAuthority {
    /// Authenticate a TLD DNSKEY RRset from its current on-chain HNS resource.
    pub fn authenticate(
        resource: &VerifiedHnsResource,
        dnskeys: &[ResourceRecord],
        signatures: &[ResourceRecord],
        validation_time: u32,
        limits: DnssecLimits,
    ) -> Result<Self, ResolverError> {
        let anchor = resource.anchor();
        if anchor.validated_at().get() != u64::from(validation_time)
            || u64::from(validation_time) > anchor.valid_until().get()
        {
            return Err(ResolverError::AnchorTimeMismatch);
        }
        let zone = Name::from_labels(vec![resource.name().to_vec()])
            .map_err(|_| ResolverError::InvalidHnsZone)?;
        let trusted_ds = resource
            .resource()
            .delegation_signers()
            .map(|ds| ResourceRecord {
                name: zone.clone(),
                record_type: RecordType::Ds,
                class: CLASS_IN,
                ttl: HNS_RESOURCE_TTL,
                rdata: Rdata::Ds(Ds {
                    key_tag: ds.key_tag,
                    algorithm: ds.algorithm,
                    digest_type: ds.digest_type,
                    digest: ds.digest.clone(),
                }),
            })
            .collect::<Vec<_>>();
        if trusted_ds.is_empty() {
            return Err(ResolverError::MissingHnsDs);
        }
        let keys = authenticate_dnskeys(
            &zone,
            &trusted_ds,
            dnskeys,
            signatures,
            validation_time,
            limits,
        )?;
        Ok(Self {
            evidence: HnsAuthorityEvidence {
                anchor,
                zone,
                validation_time,
            },
            keys,
        })
    }

    /// Current Handshake chain anchor.
    #[must_use]
    pub const fn anchor(&self) -> HnsAnchor {
        self.evidence.anchor
    }

    /// Authenticated HNS TLD zone.
    #[must_use]
    pub const fn zone(&self) -> &Name {
        &self.evidence.zone
    }

    /// Shared local DNSSEC/currency validation time.
    #[must_use]
    pub const fn validation_time(&self) -> u32 {
        self.evidence.validation_time
    }
}

/// HNS authority lineage retained by a validated TLSA result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsAuthorityEvidence {
    anchor: HnsAnchor,
    zone: Name,
    validation_time: u32,
}

impl HnsAuthorityEvidence {
    /// Current Handshake header and name-tree anchor.
    #[must_use]
    pub const fn anchor(&self) -> HnsAnchor {
        self.anchor
    }

    /// On-chain DS-authenticated TLD zone.
    #[must_use]
    pub const fn zone(&self) -> &Name {
        &self.zone
    }

    /// Time used for chain currency and every DNSSEC signature check.
    #[must_use]
    pub const fn validation_time(&self) -> u32 {
        self.validation_time
    }
}

/// Bounded resolution policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolverLimits {
    /// Maximum followed CNAME records.
    pub max_cname_hops: usize,
    /// Maximum TLSA alternatives at the terminal owner.
    pub max_tlsa_records: usize,
    /// DNSSEC resource limits.
    pub dnssec: DnssecLimits,
}

impl Default for ResolverLimits {
    fn default() -> Self {
        Self {
            max_cname_hops: DEFAULT_MAX_CNAME_HOPS,
            max_tlsa_records: DEFAULT_MAX_TLSA_RECORDS,
            dnssec: DnssecLimits::default(),
        }
    }
}

/// One DNSSEC-verified CNAME edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCname {
    owner: Name,
    target: Name,
    rrset: VerifiedRrset,
}

impl VerifiedCname {
    /// Alias owner.
    #[must_use]
    pub const fn owner(&self) -> &Name {
        &self.owner
    }

    /// Canonical target.
    #[must_use]
    pub const fn target(&self) -> &Name {
        &self.target
    }

    /// Local DNSSEC signature evidence.
    #[must_use]
    pub const fn rrset(&self) -> &VerifiedRrset {
        &self.rrset
    }
}

/// Locally DNSSEC-validated TLSA result.
///
/// Fields are private so safe callers cannot manufacture browser trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedTlsa {
    requested_owner: Name,
    terminal_owner: Name,
    base_domain: Name,
    base_domain_ascii: String,
    records: Vec<Tlsa>,
    cname_chain: Vec<VerifiedCname>,
    rrset: VerifiedRrset,
    hns_authority: Option<HnsAuthorityEvidence>,
}

impl ValidatedTlsa {
    /// Original service-prefixed TLSA owner.
    #[must_use]
    pub const fn requested_owner(&self) -> &Name {
        &self.requested_owner
    }

    /// Owner that supplied the terminal TLSA RRset after CNAME expansion.
    #[must_use]
    pub const fn terminal_owner(&self) -> &Name {
        &self.terminal_owner
    }

    /// Original TLS service base domain.
    #[must_use]
    pub const fn base_domain(&self) -> &Name {
        &self.base_domain
    }

    /// Original TLS service base domain as an ASCII SNI host.
    #[must_use]
    pub fn base_domain_ascii(&self) -> &str {
        &self.base_domain_ascii
    }

    /// Terminal TLSA alternatives.
    #[must_use]
    pub fn records(&self) -> &[Tlsa] {
        &self.records
    }

    /// DNSSEC-verified CNAME path.
    #[must_use]
    pub fn cname_chain(&self) -> &[VerifiedCname] {
        &self.cname_chain
    }

    /// Terminal local DNSSEC evidence.
    #[must_use]
    pub const fn rrset(&self) -> &VerifiedRrset {
        &self.rrset
    }

    /// On-chain HNS authority lineage, if this used the HNS-only path.
    #[must_use]
    pub const fn hns_authority(&self) -> Option<&HnsAuthorityEvidence> {
        self.hns_authority.as_ref()
    }
}

/// Result of admitting one correlated DNS response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolutionStep {
    /// Fetch another class-IN TLSA query for this CNAME target.
    FollowCname(Name),
    /// Terminal local DNSSEC and TLSA evidence.
    Complete(Box<ValidatedTlsa>),
}

/// Mutable bounded CNAME/TLSA resolution.
#[derive(Clone, Debug)]
pub struct TlsaResolution {
    requested_owner: Name,
    current_owner: Name,
    base_domain: Name,
    base_domain_ascii: String,
    visited: HashSet<Name>,
    cname_chain: Vec<VerifiedCname>,
    completed: bool,
    limits: ResolverLimits,
    authority_binding: AuthorityBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AuthorityBinding {
    Unset,
    Generic,
    Hns(HnsAuthorityEvidence),
}

impl TlsaResolution {
    /// Begin a TLSA lookup for one explicit service.
    pub fn for_service(
        base_domain: Name,
        port: u16,
        transport: ServiceTransport,
        limits: ResolverLimits,
    ) -> Result<Self, ResolverError> {
        let base_domain_ascii = ascii_host(&base_domain)?;
        let service_owner = TlsaOwner::derive(&base_domain_ascii, port, transport)
            .map_err(|_| ResolverError::InvalidServiceName)?;
        let requested_owner = Name::from_ascii(service_owner.resolver_name())
            .map_err(|_| ResolverError::InvalidServiceName)?;
        let mut visited = HashSet::new();
        visited.insert(requested_owner.clone());
        Ok(Self {
            current_owner: requested_owner.clone(),
            requested_owner,
            base_domain,
            base_domain_ascii,
            visited,
            cname_chain: Vec::new(),
            completed: false,
            limits,
            authority_binding: AuthorityBinding::Unset,
        })
    }

    /// Begin the usual HTTPS-over-TCP lookup.
    pub fn for_https(base_domain: Name, limits: ResolverLimits) -> Result<Self, ResolverError> {
        Self::for_service(base_domain, HTTPS_PORT, ServiceTransport::Tcp, limits)
    }

    /// Current owner that must be queried for TLSA.
    #[must_use]
    pub const fn current_owner(&self) -> &Name {
        &self.current_owner
    }

    /// Build a current class-IN TLSA query.
    pub fn query(&self, id: u16) -> Result<Query, ResolverError> {
        Query::new(id, self.current_owner.clone(), RecordType::Tlsa).map_err(ResolverError::Wire)
    }

    /// Validate and consume one exactly correlated response.
    pub fn accept_response(
        &mut self,
        query: &Query,
        message: &Message,
        keysets: &[&AuthenticatedDnskeys],
        validation_time: u32,
    ) -> Result<ResolutionStep, ResolverError> {
        self.accept_response_inner(
            query,
            message,
            keysets,
            validation_time,
            AuthorityBinding::Generic,
        )
    }

    /// Validate a response using only an on-chain HNS DS-authenticated keyset.
    pub fn accept_hns_response(
        &mut self,
        query: &Query,
        message: &Message,
        authority: &HnsDnssecAuthority,
    ) -> Result<ResolutionStep, ResolverError> {
        if !is_suffix(&self.base_domain, authority.zone()) {
            return Err(ResolverError::HnsZoneMismatch);
        }
        self.accept_response_inner(
            query,
            message,
            &[&authority.keys],
            authority.validation_time(),
            AuthorityBinding::Hns(authority.evidence.clone()),
        )
    }

    fn accept_response_inner(
        &mut self,
        query: &Query,
        message: &Message,
        keysets: &[&AuthenticatedDnskeys],
        validation_time: u32,
        authority_binding: AuthorityBinding,
    ) -> Result<ResolutionStep, ResolverError> {
        if self.completed {
            return Err(ResolverError::AlreadyComplete);
        }
        if query.question.name != self.current_owner
            || query.question.record_type != RecordType::Tlsa
            || query.question.class != CLASS_IN
        {
            return Err(ResolverError::WrongQuery);
        }
        query.correlate(message)?;
        if message.header.flags.rcode() != 0 {
            return Err(ResolverError::UnsuccessfulResponse);
        }
        match &self.authority_binding {
            AuthorityBinding::Unset => self.authority_binding = authority_binding,
            existing if *existing == authority_binding => {}
            _ => return Err(ResolverError::AuthorityChanged),
        }

        loop {
            let tlsa_records = matching_records(message, &self.current_owner, RecordType::Tlsa);
            let cname_records = matching_records(message, &self.current_owner, RecordType::Cname);
            if !tlsa_records.is_empty() && !cname_records.is_empty() {
                return Err(ResolverError::CnameCoexistsWithData);
            }
            if !tlsa_records.is_empty() {
                if tlsa_records.len() > self.limits.max_tlsa_records {
                    return Err(ResolverError::Limit);
                }
                let signatures =
                    matching_signatures(message, &self.current_owner, RecordType::Tlsa);
                let verified = verify_with_any_keyset(
                    keysets,
                    &tlsa_records,
                    &signatures,
                    validation_time,
                    self.limits.dnssec,
                )?;
                let records = tlsa_records
                    .iter()
                    .map(|record| match &record.rdata {
                        Rdata::Tlsa(tlsa) => Ok(tlsa.clone()),
                        _ => Err(ResolverError::MalformedAnswer),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.completed = true;
                return Ok(ResolutionStep::Complete(Box::new(ValidatedTlsa {
                    requested_owner: self.requested_owner.clone(),
                    terminal_owner: self.current_owner.clone(),
                    base_domain: self.base_domain.clone(),
                    base_domain_ascii: self.base_domain_ascii.clone(),
                    records,
                    cname_chain: self.cname_chain.clone(),
                    rrset: verified,
                    hns_authority: match &self.authority_binding {
                        AuthorityBinding::Hns(evidence) => Some(evidence.clone()),
                        AuthorityBinding::Unset | AuthorityBinding::Generic => None,
                    },
                })));
            }
            if cname_records.len() != 1 {
                return Err(if cname_records.is_empty() {
                    ResolverError::MissingTlsa
                } else {
                    ResolverError::MalformedAnswer
                });
            }
            if self.cname_chain.len() >= self.limits.max_cname_hops {
                return Err(ResolverError::CnameLimit);
            }
            let signatures = matching_signatures(message, &self.current_owner, RecordType::Cname);
            let verified = verify_with_any_keyset(
                keysets,
                &cname_records,
                &signatures,
                validation_time,
                self.limits.dnssec,
            )?;
            let target = match &cname_records
                .first()
                .ok_or(ResolverError::MalformedAnswer)?
                .rdata
            {
                Rdata::Cname(target) => target.clone(),
                _ => return Err(ResolverError::MalformedAnswer),
            };
            if !self.visited.insert(target.clone()) {
                return Err(ResolverError::CnameLoop);
            }
            self.cname_chain.push(VerifiedCname {
                owner: self.current_owner.clone(),
                target: target.clone(),
                rrset: verified,
            });
            self.current_owner = target;

            if !has_owner_data(message, &self.current_owner) {
                return Ok(ResolutionStep::FollowCname(self.current_owner.clone()));
            }
        }
    }
}

/// Resolution validation failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ResolverError {
    /// DNS wire or response-correlation failure.
    #[error("DNS wire error: {0}")]
    Wire(#[from] hns_dns_wire::Error),
    /// Local DNSSEC failure.
    #[error("DNSSEC error: {0}")]
    Dnssec(#[from] DnssecError),
    /// Service-prefixed owner or ASCII SNI host is invalid.
    #[error("invalid TLS service name")]
    InvalidServiceName,
    /// Response does not correspond to the resolver's current query.
    #[error("response query does not match the current TLSA owner")]
    WrongQuery,
    /// DNS response code is not NOERROR.
    #[error("TLSA response was unsuccessful")]
    UnsuccessfulResponse,
    /// No TLSA or CNAME answer exists at the current owner.
    #[error("secure TLSA RRset is missing")]
    MissingTlsa,
    /// CNAME and other owner data coexist.
    #[error("CNAME coexists with TLSA data")]
    CnameCoexistsWithData,
    /// CNAME path repeated an owner.
    #[error("CNAME loop")]
    CnameLoop,
    /// CNAME path exceeded its bound.
    #[error("CNAME hop limit exceeded")]
    CnameLimit,
    /// An answer RRset is malformed or ambiguous.
    #[error("malformed TLSA or CNAME answer")]
    MalformedAnswer,
    /// A configured resource bound was exceeded.
    #[error("resolver resource bound exceeded")]
    Limit,
    /// Resolution already produced terminal evidence.
    #[error("TLSA resolution is already complete")]
    AlreadyComplete,
    /// A current HNS resource has no DNSSEC DS record.
    #[error("verified HNS resource has no DS record")]
    MissingHnsDs,
    /// The on-chain HNS label cannot form a DNS zone.
    #[error("verified HNS name is not a valid DNS zone")]
    InvalidHnsZone,
    /// DNSSEC validation time does not equal the chain-currency check time.
    #[error("DNSSEC time does not match current Handshake anchor time")]
    AnchorTimeMismatch,
    /// Requested origin is outside the HNS TLD authority.
    #[error("requested origin is outside the authenticated HNS zone")]
    HnsZoneMismatch,
    /// A multi-response resolution attempted to change its trust authority.
    #[error("resolution authority changed during CNAME processing")]
    AuthorityChanged,
}

fn matching_records(
    message: &Message,
    owner: &Name,
    record_type: RecordType,
) -> Vec<ResourceRecord> {
    message
        .answers
        .iter()
        .filter(|record| {
            record.name == *owner && record.record_type == record_type && record.class == CLASS_IN
        })
        .cloned()
        .collect()
}

fn matching_signatures(
    message: &Message,
    owner: &Name,
    record_type: RecordType,
) -> Vec<ResourceRecord> {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .filter(|record| {
            record.name == *owner
                && record.record_type == RecordType::Rrsig
                && record.class == CLASS_IN
                && matches!(
                    &record.rdata,
                    Rdata::Rrsig(signature) if signature.type_covered == record_type
                )
        })
        .cloned()
        .collect()
}

fn verify_with_any_keyset(
    keysets: &[&AuthenticatedDnskeys],
    records: &[ResourceRecord],
    signatures: &[ResourceRecord],
    validation_time: u32,
    limits: DnssecLimits,
) -> Result<VerifiedRrset, ResolverError> {
    let owner = records
        .first()
        .map(|record| &record.name)
        .ok_or(ResolverError::MalformedAnswer)?;
    let mut last_error = DnssecError::MissingKey;
    for keyset in keysets {
        if !is_suffix(owner, keyset.zone()) {
            continue;
        }
        match verify_rrset_with_keys(keyset, records, signatures, validation_time, limits) {
            Ok(verified) => return Ok(verified),
            Err(error) => last_error = error,
        }
    }
    Err(last_error.into())
}

fn has_owner_data(message: &Message, owner: &Name) -> bool {
    message
        .answers
        .iter()
        .any(|record| record.name == *owner && record.class == CLASS_IN)
}

fn ascii_host(name: &Name) -> Result<String, ResolverError> {
    if name.is_root() {
        return Err(ResolverError::InvalidServiceName);
    }
    let mut output = String::new();
    for (index, label) in name.labels().iter().enumerate() {
        if label.is_empty()
            || label.len() > 63
            || !label.first().is_some_and(u8::is_ascii_alphanumeric)
            || !label.last().is_some_and(u8::is_ascii_alphanumeric)
            || label
                .iter()
                .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'-')
        {
            return Err(ResolverError::InvalidServiceName);
        }
        if index != 0 {
            output.push('.');
        }
        for byte in label {
            output.push(char::from(*byte));
        }
    }
    Ok(output)
}

fn is_suffix(name: &Name, suffix: &Name) -> bool {
    name.labels()
        .get(name.labels().len().saturating_sub(suffix.labels().len())..)
        == Some(suffix.labels())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests intentionally fail immediately on invalid local cryptographic fixtures"
)]
mod tests {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    use hns_dns_wire::{Dnskey, Ds, Flags, Header, Question, Rrsig};
    use hns_dnssec::{ALGORITHM_RSASHA256, authenticate_dnskeys, dnskey_tag, rrsig_signed_data};
    use hns_header_consensus::{Header as ConsensusHeader, Network as ConsensusNetwork};
    use hns_light_chain::{ChainLimits, CurrencyPolicy, LightChain};
    use hns_primitives::{BlockTime, Chainwork, Height, TreeRoot};
    use openssl::hash::{MessageDigest, hash};
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;

    use super::*;

    fn name(value: &str) -> Name {
        Name::from_ascii(value).unwrap()
    }

    fn rsa_dnskey(rsa: &Rsa<Private>) -> Dnskey {
        let exponent = rsa.e().to_vec();
        let modulus = rsa.n().to_vec();
        let mut public_key = Vec::new();
        public_key.push(u8::try_from(exponent.len()).unwrap());
        public_key.extend_from_slice(&exponent);
        public_key.extend_from_slice(&modulus);
        Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: ALGORITHM_RSASHA256,
            public_key,
        }
    }

    fn encode_dnskey(key: &Dnskey) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&key.flags.to_be_bytes());
        output.push(key.protocol);
        output.push(key.algorithm);
        output.extend_from_slice(&key.public_key);
        output
    }

    fn sign_rrset(
        records: &[ResourceRecord],
        signer_name: Name,
        key: &Dnskey,
        key_pair: &PKey<Private>,
    ) -> ResourceRecord {
        sign_rrset_window(records, signer_name, key, key_pair, 1_000, 2_000)
    }

    fn sign_rrset_window(
        records: &[ResourceRecord],
        signer_name: Name,
        key: &Dnskey,
        key_pair: &PKey<Private>,
        inception: u32,
        expiration: u32,
    ) -> ResourceRecord {
        let first = records.first().unwrap();
        let mut signature = Rrsig {
            type_covered: first.record_type,
            algorithm: key.algorithm,
            labels: u8::try_from(first.name.labels().len()).unwrap(),
            original_ttl: first.ttl,
            expiration,
            inception,
            key_tag: dnskey_tag(key),
            signer: signer_name,
            signature: Vec::new(),
        };
        let signed = rrsig_signed_data(records, &signature, 1024 * 1024).unwrap();
        let mut crypto_signer = Signer::new(MessageDigest::sha256(), key_pair).unwrap();
        crypto_signer.update(&signed).unwrap();
        signature.signature = crypto_signer.sign_to_vec().unwrap();
        ResourceRecord {
            name: first.name.clone(),
            record_type: RecordType::Rrsig,
            class: CLASS_IN,
            ttl: first.ttl,
            rdata: Rdata::Rrsig(signature),
        }
    }

    fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).unwrap();
        for part in parts {
            hasher.update(part);
        }
        let mut output = [0_u8; 32];
        hasher.finalize_variable(&mut output).unwrap();
        output
    }

    fn verified_hns_resource(ds: &Ds) -> (VerifiedHnsResource, u32) {
        let genesis_time = ConsensusNetwork::Regtest.parameters().genesis_time;
        let validation_time = u32::try_from(genesis_time.get() + 100).unwrap();
        let mut resource = vec![0, 0];
        resource.extend_from_slice(&ds.key_tag.to_be_bytes());
        resource.extend_from_slice(&[ds.algorithm, ds.digest_type]);
        resource.push(u8::try_from(ds.digest.len()).unwrap());
        resource.extend_from_slice(&ds.digest);

        let mut state = Vec::new();
        state.push(5);
        state.extend_from_slice(b"alpha");
        state.extend_from_slice(&u16::try_from(resource.len()).unwrap().to_le_bytes());
        state.extend_from_slice(&resource);
        state.extend_from_slice(&1_u32.to_le_bytes());
        state.extend_from_slice(&1_u32.to_le_bytes());
        state.extend_from_slice(&0_u16.to_le_bytes());

        let key = hns_covenants::hash_name(b"alpha").unwrap();
        let value_hash = blake2b_256(&[&state]);
        let tree_root = TreeRoot::new(blake2b_256(&[&[0], key.as_bytes(), &value_hash]));
        let mut proof = Vec::new();
        proof.extend_from_slice(&0xc000_u16.to_le_bytes());
        proof.extend_from_slice(&0_u16.to_le_bytes());
        proof.extend_from_slice(&u16::try_from(state.len()).unwrap().to_le_bytes());
        proof.extend_from_slice(&state);

        let now = BlockTime::new(u64::from(validation_time));
        let mut chain =
            LightChain::from_genesis(ConsensusNetwork::Regtest, now, ChainLimits::default())
                .unwrap();
        let mut header = ConsensusHeader {
            time: BlockTime::new(genesis_time.get() + 1),
            previous_block: chain.tip().hash(),
            tree_root,
            bits: ConsensusNetwork::Regtest.parameters().pow.bits,
            ..ConsensusHeader::default()
        };
        while !header.verify_pow() {
            header.nonce = header.nonce.checked_add(1).unwrap();
        }
        chain.append(&header, now).unwrap();
        let current = chain
            .require_current(CurrencyPolicy {
                now,
                maximum_tip_age_seconds: 3_600,
                minimum_height: Height::new(1),
                minimum_chainwork: Chainwork::ZERO,
            })
            .unwrap();
        (
            current.verify_name_resource(b"alpha", &proof).unwrap(),
            validation_time,
        )
    }

    fn keyset() -> (AuthenticatedDnskeys, PKey<Private>, Dnskey) {
        let zone = name("example.");
        let rsa = Rsa::generate(1024).unwrap();
        let key = rsa_dnskey(&rsa);
        let key_pair = PKey::from_rsa(rsa).unwrap();
        let dnskeys = vec![ResourceRecord {
            name: zone.clone(),
            record_type: RecordType::Dnskey,
            class: CLASS_IN,
            ttl: 300,
            rdata: Rdata::Dnskey(key.clone()),
        }];
        let signatures = vec![sign_rrset(&dnskeys, zone.clone(), &key, &key_pair)];
        let mut digest_input = Vec::new();
        zone.encode(&mut digest_input).unwrap();
        digest_input.extend_from_slice(&encode_dnskey(&key));
        let ds = vec![ResourceRecord {
            name: zone.clone(),
            record_type: RecordType::Ds,
            class: CLASS_IN,
            ttl: 300,
            rdata: Rdata::Ds(Ds {
                key_tag: dnskey_tag(&key),
                algorithm: key.algorithm,
                digest_type: 2,
                digest: hash(MessageDigest::sha256(), &digest_input)
                    .unwrap()
                    .to_vec(),
            }),
        }];
        (
            authenticate_dnskeys(
                &zone,
                &ds,
                &dnskeys,
                &signatures,
                1_500,
                DnssecLimits::default(),
            )
            .unwrap(),
            key_pair,
            key,
        )
    }

    fn cname(owner: Name, target: Name) -> ResourceRecord {
        ResourceRecord {
            name: owner,
            record_type: RecordType::Cname,
            class: CLASS_IN,
            ttl: 300,
            rdata: Rdata::Cname(target),
        }
    }

    fn tlsa(owner: Name, association: u8) -> ResourceRecord {
        ResourceRecord {
            name: owner,
            record_type: RecordType::Tlsa,
            class: CLASS_IN,
            ttl: 300,
            rdata: Rdata::Tlsa(Tlsa {
                usage: 3,
                selector: 1,
                matching_type: 1,
                association_data: vec![association; 32],
            }),
        }
    }

    fn response(query: &Query, answers: Vec<ResourceRecord>) -> Message {
        Message {
            header: Header {
                id: query.id,
                flags: Flags::from_bits(0x8420),
                question_count: 1,
                answer_count: u16::try_from(answers.len()).unwrap(),
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![Question {
                name: query.question.name.clone(),
                record_type: query.question.record_type,
                class: query.question.class,
            }],
            answers,
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    #[test]
    fn validates_cname_and_terminal_tlsa_in_one_response() {
        let (keys, key_pair, key) = keyset();
        let mut resolution =
            TlsaResolution::for_https(name("service.example."), ResolverLimits::default()).unwrap();
        let query = resolution.query(7).unwrap();
        let target = name("tlsa.provider.example.");
        let cname_records = vec![cname(query.question.name.clone(), target.clone())];
        let tlsa_records = vec![tlsa(target.clone(), 9)];
        let message = response(
            &query,
            vec![
                cname_records.first().unwrap().clone(),
                sign_rrset(&cname_records, name("example."), &key, &key_pair),
                tlsa_records.first().unwrap().clone(),
                sign_rrset(&tlsa_records, name("example."), &key, &key_pair),
            ],
        );
        assert!(message.header.flags.authenticated_data_claim());
        let step = resolution
            .accept_response(&query, &message, &[&keys], 1_500)
            .unwrap();
        let validated = match step {
            ResolutionStep::Complete(validated) => Some(validated),
            ResolutionStep::FollowCname(_) => None,
        }
        .unwrap();
        assert_eq!(validated.base_domain_ascii(), "service.example");
        assert_eq!(validated.terminal_owner(), &target);
        assert_eq!(validated.cname_chain().len(), 1);
        assert_eq!(validated.records().len(), 1);
    }

    #[test]
    fn validates_cname_across_correlated_responses_and_rejects_loops() {
        let (keys, key_pair, key) = keyset();
        let mut resolution =
            TlsaResolution::for_https(name("service.example."), ResolverLimits::default()).unwrap();
        let first_query = resolution.query(10).unwrap();
        let target = name("tlsa.example.");
        let first_rrset = vec![cname(first_query.question.name.clone(), target.clone())];
        let first_message = response(
            &first_query,
            vec![
                first_rrset.first().unwrap().clone(),
                sign_rrset(&first_rrset, name("example."), &key, &key_pair),
            ],
        );
        assert_eq!(
            resolution
                .accept_response(&first_query, &first_message, &[&keys], 1_500)
                .unwrap(),
            ResolutionStep::FollowCname(target.clone())
        );

        let second_query = resolution.query(11).unwrap();
        let second_rrset = vec![tlsa(target.clone(), 4)];
        let second_message = response(
            &second_query,
            vec![
                second_rrset.first().unwrap().clone(),
                sign_rrset(&second_rrset, name("example."), &key, &key_pair),
            ],
        );
        assert!(matches!(
            resolution
                .accept_response(&second_query, &second_message, &[&keys], 1_500)
                .unwrap(),
            ResolutionStep::Complete(_)
        ));

        let mut looping =
            TlsaResolution::for_https(name("loop.example."), ResolverLimits::default()).unwrap();
        let loop_query = looping.query(12).unwrap();
        let alias = name("alias.example.");
        let first_loop = vec![cname(loop_query.question.name.clone(), alias.clone())];
        let first_loop_message = response(
            &loop_query,
            vec![
                first_loop.first().unwrap().clone(),
                sign_rrset(&first_loop, name("example."), &key, &key_pair),
            ],
        );
        looping
            .accept_response(&loop_query, &first_loop_message, &[&keys], 1_500)
            .unwrap();
        let alias_query = looping.query(13).unwrap();
        let second_loop = vec![cname(alias, name("_443._tcp.loop.example."))];
        let second_loop_message = response(
            &alias_query,
            vec![
                second_loop.first().unwrap().clone(),
                sign_rrset(&second_loop, name("example."), &key, &key_pair),
            ],
        );
        assert_eq!(
            looping.accept_response(&alias_query, &second_loop_message, &[&keys], 1_500),
            Err(ResolverError::CnameLoop)
        );
    }

    #[test]
    fn rejects_unsigned_or_mutated_tlsa_even_when_ad_is_set() {
        let (keys, key_pair, key) = keyset();
        let mut resolution =
            TlsaResolution::for_https(name("service.example."), ResolverLimits::default()).unwrap();
        let query = resolution.query(15).unwrap();
        let original = vec![tlsa(query.question.name.clone(), 1)];
        let signature = sign_rrset(&original, name("example."), &key, &key_pair);
        let mutated = tlsa(query.question.name.clone(), 2);
        let message = response(&query, vec![mutated, signature]);
        assert!(message.header.flags.authenticated_data_claim());
        assert!(matches!(
            resolution.accept_response(&query, &message, &[&keys], 1_500),
            Err(ResolverError::Dnssec(DnssecError::SignatureMismatch))
        ));
    }

    #[test]
    fn service_name_rejects_non_host_labels() {
        assert_eq!(
            TlsaResolution::for_https(name("_hidden.example."), ResolverLimits::default())
                .unwrap_err(),
            ResolverError::InvalidServiceName
        );
        assert!(
            TlsaResolution::for_https(
                Name::from_labels(vec![vec![0xff], b"example".to_vec()]).unwrap(),
                ResolverLimits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn binds_hns_header_resource_ds_dnskey_and_tlsa_evidence() {
        let zone = name("alpha.");
        let rsa = Rsa::generate(1024).unwrap();
        let key = rsa_dnskey(&rsa);
        let key_pair = PKey::from_rsa(rsa).unwrap();
        let dnskeys = vec![ResourceRecord {
            name: zone.clone(),
            record_type: RecordType::Dnskey,
            class: CLASS_IN,
            ttl: 300,
            rdata: Rdata::Dnskey(key.clone()),
        }];
        let mut digest_input = Vec::new();
        zone.encode(&mut digest_input).unwrap();
        digest_input.extend_from_slice(&encode_dnskey(&key));
        let ds = Ds {
            key_tag: dnskey_tag(&key),
            algorithm: key.algorithm,
            digest_type: 2,
            digest: hash(MessageDigest::sha256(), &digest_input)
                .unwrap()
                .to_vec(),
        };
        let (resource, validation_time) = verified_hns_resource(&ds);
        let dnskey_signatures = vec![sign_rrset_window(
            &dnskeys,
            zone.clone(),
            &key,
            &key_pair,
            validation_time - 10,
            validation_time + 10,
        )];
        let authority = HnsDnssecAuthority::authenticate(
            &resource,
            &dnskeys,
            &dnskey_signatures,
            validation_time,
            DnssecLimits::default(),
        )
        .unwrap();

        let mut resolution =
            TlsaResolution::for_https(name("www.alpha."), ResolverLimits::default()).unwrap();
        let query = resolution.query(31).unwrap();
        let tlsa_records = vec![tlsa(query.question.name.clone(), 0x44)];
        let message = response(
            &query,
            vec![
                tlsa_records.first().unwrap().clone(),
                sign_rrset_window(
                    &tlsa_records,
                    zone.clone(),
                    &key,
                    &key_pair,
                    validation_time - 10,
                    validation_time + 10,
                ),
            ],
        );
        let validated = match resolution
            .accept_hns_response(&query, &message, &authority)
            .unwrap()
        {
            ResolutionStep::Complete(validated) => Some(validated),
            ResolutionStep::FollowCname(_) => None,
        }
        .unwrap();
        let evidence = validated.hns_authority().unwrap();
        assert_eq!(evidence.zone(), &zone);
        assert_eq!(evidence.validation_time(), validation_time);
        assert_eq!(evidence.anchor(), resource.anchor());

        let mut outside =
            TlsaResolution::for_https(name("www.other."), ResolverLimits::default()).unwrap();
        let outside_query = outside.query(32).unwrap();
        assert_eq!(
            outside.accept_hns_response(&outside_query, &message, &authority),
            Err(ResolverError::HnsZoneMismatch)
        );
    }
}
