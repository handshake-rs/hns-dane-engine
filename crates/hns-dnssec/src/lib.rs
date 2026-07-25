//! Local, bounded DNSSEC RRset, delegation, and denial validation.
//!
//! This crate does not consult a recursive resolver and never trusts the DNS
//! AD bit. Callers provide parsed records and an explicit validation time.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "DNSSEC terminology and the public error type are documented at crate level"
)]

use std::cmp::Ordering;

use hns_dns_wire::{
    CLASS_IN, Dnskey, Ds, Name, Nsec, Nsec3, Rdata, RecordType, ResourceRecord, Rrsig,
};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{MessageDigest, hash};
use openssl::memcmp;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Verifier;
use thiserror::Error;

/// RSA/SHA-1.
pub const ALGORITHM_RSASHA1: u8 = 5;
/// RSA/SHA-1 with NSEC3.
pub const ALGORITHM_RSASHA1_NSEC3: u8 = 7;
/// RSA/SHA-256.
pub const ALGORITHM_RSASHA256: u8 = 8;
/// RSA/SHA-512.
pub const ALGORITHM_RSASHA512: u8 = 10;
/// ECDSA P-256/SHA-256.
pub const ALGORITHM_ECDSA_P256_SHA256: u8 = 13;
/// ECDSA P-384/SHA-384.
pub const ALGORITHM_ECDSA_P384_SHA384: u8 = 14;
/// Ed25519.
pub const ALGORITHM_ED25519: u8 = 15;
/// Ed448.
pub const ALGORITHM_ED448: u8 = 16;

/// Browser DNSSEC resource bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnssecLimits {
    /// Maximum records in one signed RRset.
    pub max_rrset_records: usize,
    /// Maximum signatures considered for one RRset.
    pub max_signatures: usize,
    /// Maximum candidate DNSKEY records.
    pub max_keys: usize,
    /// Maximum canonical signed bytes.
    pub max_signed_data_len: usize,
    /// Maximum NSEC3 iterations accepted.
    pub max_nsec3_iterations: u16,
    /// Maximum denial records considered.
    pub max_denial_records: usize,
}

impl Default for DnssecLimits {
    fn default() -> Self {
        Self {
            max_rrset_records: 1_024,
            max_signatures: 64,
            max_keys: 64,
            max_signed_data_len: 4 * 1024 * 1024,
            max_nsec3_iterations: 500,
            max_denial_records: 256,
        }
    }
}

/// A locally verified RRset signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRrset {
    /// Canonical RRset owner.
    owner: Name,
    /// Covered resource type.
    record_type: RecordType,
    /// DNSKEY tag.
    key_tag: u16,
    /// DNSSEC algorithm.
    algorithm: u8,
    /// Signature inception time.
    inception: u32,
    /// Signature expiration time.
    expiration: u32,
}

impl VerifiedRrset {
    /// Canonical RRset owner.
    #[must_use]
    pub const fn owner(&self) -> &Name {
        &self.owner
    }

    /// Covered resource type.
    #[must_use]
    pub const fn record_type(&self) -> RecordType {
        self.record_type
    }

    /// Authenticating DNSKEY tag.
    #[must_use]
    pub const fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Authenticating DNSSEC algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Signature inception time.
    #[must_use]
    pub const fn inception(&self) -> u32 {
        self.inception
    }

    /// Signature expiration time.
    #[must_use]
    pub const fn expiration(&self) -> u32 {
        self.expiration
    }
}

/// A DNSKEY RRset authenticated through a local DS chain.
///
/// Fields are private so safe callers cannot manufacture local DNSSEC
/// evidence. Use [`authenticate_dnskeys`] or [`authenticate_child_dnskeys`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedDnskeys {
    zone: Name,
    records: Vec<ResourceRecord>,
    delegation_key_tag: u16,
    delegation_algorithm: u8,
}

impl AuthenticatedDnskeys {
    /// Authenticated zone apex.
    #[must_use]
    pub const fn zone(&self) -> &Name {
        &self.zone
    }

    /// DS-authenticated key tag.
    #[must_use]
    pub const fn delegation_key_tag(&self) -> u16 {
        self.delegation_key_tag
    }

    /// DS-authenticated DNSSEC algorithm.
    #[must_use]
    pub const fn delegation_algorithm(&self) -> u8 {
        self.delegation_algorithm
    }
}

/// Borrowed data records plus their covering RRSIG records.
#[derive(Clone, Copy, Debug)]
pub struct SignedRrset<'a> {
    /// Data records.
    pub records: &'a [ResourceRecord],
    /// Covering RRSIG records.
    pub signatures: &'a [ResourceRecord],
}

/// Authenticated denial result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denial {
    /// The queried owner exists, but the requested type does not.
    NoData,
    /// The queried owner does not exist.
    NameError,
}

/// Local DNSSEC validation failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum DnssecError {
    /// No data records were supplied.
    #[error("DNSSEC RRset is empty")]
    EmptyRrset,
    /// A configured count or byte bound was exceeded.
    #[error("DNSSEC resource bound exceeded")]
    Limit,
    /// Records do not form one class-IN owner/type RRset.
    #[error("records do not form one class-IN RRset")]
    RrsetMismatch,
    /// No covering RRSIG exists.
    #[error("no covering RRSIG")]
    MissingSignature,
    /// No DNSKEY matches the signature.
    #[error("no matching DNSKEY")]
    MissingKey,
    /// The matching key is revoked or has an invalid DNSSEC protocol value.
    #[error("DNSKEY is revoked or malformed")]
    InvalidKey,
    /// The DNSSEC algorithm is unsupported.
    #[error("unsupported DNSSEC algorithm {0}")]
    UnsupportedAlgorithm(u8),
    /// The DS digest algorithm is unsupported.
    #[error("unsupported DS digest algorithm {0}")]
    UnsupportedDigest(u8),
    /// The signature is outside its inception/expiration window.
    #[error("RRSIG is outside its validity window")]
    SignatureTime,
    /// No candidate signature verified.
    #[error("DNSSEC signature mismatch")]
    SignatureMismatch,
    /// Typed RDATA cannot be canonically encoded for DNSSEC.
    #[error("unsupported or mismatched canonical RDATA")]
    UnsupportedRdata,
    /// No DS record authenticates the DNSKEY.
    #[error("DS digest mismatch")]
    DsMismatch,
    /// An NSEC or NSEC3 proof is malformed or does not prove the requested denial.
    #[error("authenticated denial proof mismatch")]
    DenialMismatch,
}

/// Verify one RRset against locally authenticated DNSKEY records.
pub fn verify_rrset(
    records: &[ResourceRecord],
    signatures: &[ResourceRecord],
    keys: &[ResourceRecord],
    validation_time: u32,
    limits: DnssecLimits,
) -> Result<VerifiedRrset, DnssecError> {
    if records.is_empty() {
        return Err(DnssecError::EmptyRrset);
    }
    if records.len() > limits.max_rrset_records
        || signatures.len() > limits.max_signatures
        || keys.len() > limits.max_keys
    {
        return Err(DnssecError::Limit);
    }
    let first = records.first().ok_or(DnssecError::EmptyRrset)?;
    if first.class != CLASS_IN
        || matches!(first.record_type, RecordType::Rrsig | RecordType::Opt)
        || records.iter().any(|record| {
            record.name != first.name
                || record.record_type != first.record_type
                || record.class != CLASS_IN
        })
    {
        return Err(DnssecError::RrsetMismatch);
    }

    let mut covering = 0usize;
    let mut saw_current = false;
    let mut saw_supported = false;
    let mut saw_key = false;
    let mut unsupported = None;
    for signature_record in signatures {
        let Some(signature) = rrsig_for(signature_record, &first.name, first.record_type) else {
            continue;
        };
        covering = covering.saturating_add(1);
        if !serial_in_window(validation_time, signature.inception, signature.expiration) {
            continue;
        }
        saw_current = true;
        if !supported_algorithm(signature.algorithm) {
            unsupported.get_or_insert(signature.algorithm);
            continue;
        }
        saw_supported = true;
        let signed = rrsig_signed_data(records, signature, limits.max_signed_data_len)?;
        for key_record in keys {
            let Some(key) = dnskey_for(key_record, &signature.signer) else {
                continue;
            };
            if key.protocol != 3 || key.flags & 0x0080 != 0 {
                continue;
            }
            if key.algorithm != signature.algorithm || dnskey_tag(key) != signature.key_tag {
                continue;
            }
            saw_key = true;
            if verify_signature(
                signature.algorithm,
                &key.public_key,
                &signed,
                &signature.signature,
            ) {
                return Ok(VerifiedRrset {
                    owner: first.name.clone(),
                    record_type: first.record_type,
                    key_tag: signature.key_tag,
                    algorithm: signature.algorithm,
                    inception: signature.inception,
                    expiration: signature.expiration,
                });
            }
        }
    }

    if covering == 0 {
        Err(DnssecError::MissingSignature)
    } else if !saw_current {
        Err(DnssecError::SignatureTime)
    } else if !saw_supported {
        Err(DnssecError::UnsupportedAlgorithm(
            unsupported.unwrap_or_default(),
        ))
    } else if !saw_key {
        Err(DnssecError::MissingKey)
    } else {
        Err(DnssecError::SignatureMismatch)
    }
}

/// Produce RFC 4034 canonical bytes covered by an RRSIG.
///
/// This is exposed for deterministic fixture generation and authoritative
/// tooling. Verification callers should normally use [`verify_rrset`].
pub fn rrsig_signed_data(
    records: &[ResourceRecord],
    signature: &Rrsig,
    maximum: usize,
) -> Result<Vec<u8>, DnssecError> {
    canonical_signed_data(records, signature, maximum)
}

/// Authenticate a zone DNSKEY RRset from already trusted DS records.
///
/// The caller must obtain `trusted_ds` from a locally verified parent RRset
/// or a locally verified Handshake name resource. For child delegations,
/// prefer [`authenticate_child_dnskeys`], which verifies that parent step.
pub fn authenticate_dnskeys(
    zone: &Name,
    trusted_ds: &[ResourceRecord],
    dnskeys: &[ResourceRecord],
    signatures: &[ResourceRecord],
    validation_time: u32,
    limits: DnssecLimits,
) -> Result<AuthenticatedDnskeys, DnssecError> {
    if dnskeys.is_empty() {
        return Err(DnssecError::EmptyRrset);
    }
    let mut saw_ds_match = false;
    for key_record in dnskeys {
        let Some(key) = dnskey_for(key_record, zone) else {
            continue;
        };
        if key.flags & 0x0100 == 0 || verify_ds(zone, key, trusted_ds).is_err() {
            continue;
        }
        saw_ds_match = true;
        let key_tag = dnskey_tag(key);
        let covering = signatures
            .iter()
            .filter(|record| {
                rrsig_for(record, zone, RecordType::Dnskey).is_some_and(|signature| {
                    signature.key_tag == key_tag && signature.algorithm == key.algorithm
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        if verify_rrset(dnskeys, &covering, dnskeys, validation_time, limits).is_ok() {
            return Ok(AuthenticatedDnskeys {
                zone: zone.clone(),
                records: dnskeys.to_vec(),
                delegation_key_tag: key_tag,
                delegation_algorithm: key.algorithm,
            });
        }
    }
    if saw_ds_match {
        Err(DnssecError::SignatureMismatch)
    } else {
        Err(DnssecError::DsMismatch)
    }
}

/// Verify an RRset with a DS-authenticated zone keyset.
pub fn verify_rrset_with_keys(
    keys: &AuthenticatedDnskeys,
    records: &[ResourceRecord],
    signatures: &[ResourceRecord],
    validation_time: u32,
    limits: DnssecLimits,
) -> Result<VerifiedRrset, DnssecError> {
    verify_rrset(records, signatures, &keys.records, validation_time, limits)
}

/// Authenticate a child delegation and its DNSKEY RRset from parent keys.
pub fn authenticate_child_dnskeys(
    parent: &AuthenticatedDnskeys,
    child_zone: &Name,
    child_ds: SignedRrset<'_>,
    child_dnskeys: SignedRrset<'_>,
    validation_time: u32,
    limits: DnssecLimits,
) -> Result<AuthenticatedDnskeys, DnssecError> {
    let verified = verify_rrset_with_keys(
        parent,
        child_ds.records,
        child_ds.signatures,
        validation_time,
        limits,
    )?;
    if verified.owner() != child_zone || verified.record_type() != RecordType::Ds {
        return Err(DnssecError::RrsetMismatch);
    }
    authenticate_dnskeys(
        child_zone,
        child_ds.records,
        child_dnskeys.records,
        child_dnskeys.signatures,
        validation_time,
        limits,
    )
}

/// Verify that at least one class-IN DS record authenticates a DNSKEY.
pub fn verify_ds(
    owner: &Name,
    key: &Dnskey,
    records: &[ResourceRecord],
) -> Result<(), DnssecError> {
    if key.protocol != 3 || key.flags & 0x0080 != 0 {
        return Err(DnssecError::InvalidKey);
    }
    let key_tag = dnskey_tag(key);
    let key_rdata = encode_dnskey(key);
    let mut digest_input = Vec::with_capacity(owner.wire_len().saturating_add(key_rdata.len()));
    owner
        .encode(&mut digest_input)
        .map_err(|_| DnssecError::UnsupportedRdata)?;
    digest_input.extend_from_slice(&key_rdata);

    let mut saw_candidate = false;
    let mut unsupported = None;
    for record in records {
        let Rdata::Ds(ds) = &record.rdata else {
            continue;
        };
        if record.name != *owner
            || record.class != CLASS_IN
            || record.record_type != RecordType::Ds
            || ds.key_tag != key_tag
            || ds.algorithm != key.algorithm
        {
            continue;
        }
        saw_candidate = true;
        let digest = match digest_ds(ds.digest_type, &digest_input) {
            Ok(digest) => digest,
            Err(DnssecError::UnsupportedDigest(value)) => {
                unsupported.get_or_insert(value);
                continue;
            }
            Err(error) => return Err(error),
        };
        if memcmp::eq(&digest, &ds.digest) {
            return Ok(());
        }
    }
    if saw_candidate && unsupported.is_some() {
        Err(DnssecError::UnsupportedDigest(
            unsupported.unwrap_or_default(),
        ))
    } else {
        Err(DnssecError::DsMismatch)
    }
}

/// Compute the RFC 4034 DNSKEY key tag.
#[must_use]
pub fn dnskey_tag(key: &Dnskey) -> u16 {
    let rdata = encode_dnskey(key);
    let mut accumulator = 0_u32;
    for (index, byte) in rdata.iter().copied().enumerate() {
        accumulator = accumulator.wrapping_add(if index & 1 == 0 {
            u32::from(byte) << 8
        } else {
            u32::from(byte)
        });
    }
    accumulator = accumulator.wrapping_add((accumulator >> 16) & 0xffff);
    (accumulator & 0xffff) as u16
}

/// Verify an already signature-authenticated NSEC proof.
pub fn verify_nsec_denial(
    qname: &Name,
    qtype: RecordType,
    records: &[ResourceRecord],
    response_is_name_error: bool,
    limits: DnssecLimits,
) -> Result<Denial, DnssecError> {
    if records.len() > limits.max_denial_records {
        return Err(DnssecError::Limit);
    }
    let nsecs = records.iter().filter_map(valid_nsec).collect::<Vec<_>>();
    for (record, nsec) in &nsecs {
        if record.name == *qname
            && !response_is_name_error
            && !bitmap_contains(&nsec.type_bitmaps, qtype.code())?
            && (qtype == RecordType::Cname
                || !bitmap_contains(&nsec.type_bitmaps, RecordType::Cname.code())?)
        {
            return Ok(Denial::NoData);
        }
    }
    if !response_is_name_error {
        return Err(DnssecError::DenialMismatch);
    }

    let closest_start = (1..=qname.labels().len())
        .find(|start| {
            ancestor(qname, *start)
                .is_some_and(|candidate| nsecs.iter().any(|(record, _)| record.name == candidate))
        })
        .ok_or(DnssecError::DenialMismatch)?;
    let next_closer =
        ancestor(qname, closest_start.saturating_sub(1)).ok_or(DnssecError::DenialMismatch)?;
    let closest = ancestor(qname, closest_start).ok_or(DnssecError::DenialMismatch)?;
    let wildcard = wildcard_of(&closest)?;
    if nsecs.iter().any(|(record, nsec)| {
        canonical_interval_contains(&record.name, &nsec.next_domain, &next_closer)
    }) && nsecs.iter().any(|(record, nsec)| {
        canonical_interval_contains(&record.name, &nsec.next_domain, &wildcard)
    }) {
        return Ok(Denial::NameError);
    }
    Err(DnssecError::DenialMismatch)
}

/// Compute the RFC 5155 SHA-1 NSEC3 hash with bounded iterations.
pub fn nsec3_hash(
    name: &Name,
    salt: &[u8],
    iterations: u16,
    limits: DnssecLimits,
) -> Result<[u8; 20], DnssecError> {
    if iterations > limits.max_nsec3_iterations || salt.len() > u8::MAX as usize {
        return Err(DnssecError::Limit);
    }
    let mut canonical_name = Vec::with_capacity(name.wire_len());
    name.encode(&mut canonical_name)
        .map_err(|_| DnssecError::UnsupportedRdata)?;
    let mut value = digest_sha1_many(&[&canonical_name, salt])?;
    for _ in 0..iterations {
        value = digest_sha1_many(&[&value, salt])?;
    }
    value
        .try_into()
        .map_err(|_| DnssecError::UnsupportedDigest(1))
}

/// Verify an already signature-authenticated NSEC3 no-data or name-error proof.
///
/// Owner labels must use the ordinary base32hex NSEC3 owner representation.
pub fn verify_nsec3_denial(
    zone: &Name,
    qname: &Name,
    qtype: RecordType,
    records: &[ResourceRecord],
    response_is_name_error: bool,
    limits: DnssecLimits,
) -> Result<Denial, DnssecError> {
    if records.len() > limits.max_denial_records {
        return Err(DnssecError::Limit);
    }
    if !is_suffix(qname, zone) {
        return Err(DnssecError::DenialMismatch);
    }
    let mut entries = Vec::new();
    for record in records {
        let Some(nsec3) = valid_nsec3_record(record) else {
            continue;
        };
        validate_nsec3(nsec3, limits)?;
        let Some(owner_hash) = nsec3_owner_hash(&record.name, zone) else {
            continue;
        };
        entries.push((owner_hash, nsec3));
    }
    let first = entries.first().ok_or(DnssecError::DenialMismatch)?.1;
    if entries.iter().any(|(_, record)| {
        record.hash_algorithm != first.hash_algorithm
            || record.iterations != first.iterations
            || record.salt != first.salt
    }) {
        return Err(DnssecError::DenialMismatch);
    }

    let query_hash = nsec3_hash(qname, &first.salt, first.iterations, limits)?;
    for (owner_hash, nsec3) in &entries {
        if *owner_hash == query_hash
            && !response_is_name_error
            && !bitmap_contains(&nsec3.type_bitmaps, qtype.code())?
            && (qtype == RecordType::Cname
                || !bitmap_contains(&nsec3.type_bitmaps, RecordType::Cname.code())?)
        {
            return Ok(Denial::NoData);
        }
    }
    if !response_is_name_error {
        return Err(DnssecError::DenialMismatch);
    }

    let maximum_start = qname.labels().len().saturating_sub(zone.labels().len());
    let closest_start = (1..=maximum_start)
        .find(|start| {
            ancestor(qname, *start).is_some_and(|candidate| {
                nsec3_hash(&candidate, &first.salt, first.iterations, limits)
                    .is_ok_and(|hash| entries.iter().any(|(owner_hash, _)| *owner_hash == hash))
            })
        })
        .ok_or(DnssecError::DenialMismatch)?;
    let next_closer =
        ancestor(qname, closest_start.saturating_sub(1)).ok_or(DnssecError::DenialMismatch)?;
    let closest = ancestor(qname, closest_start).ok_or(DnssecError::DenialMismatch)?;
    let wildcard = wildcard_of(&closest)?;
    let next_hash = nsec3_hash(&next_closer, &first.salt, first.iterations, limits)?;
    let wildcard_hash = nsec3_hash(&wildcard, &first.salt, first.iterations, limits)?;
    if entries.iter().any(|(owner, record)| {
        record.flags == 0 && hash_interval_contains(owner, &record.next_hashed_owner, &next_hash)
    }) && entries.iter().any(|(owner, record)| {
        record.flags == 0
            && hash_interval_contains(owner, &record.next_hashed_owner, &wildcard_hash)
    }) {
        return Ok(Denial::NameError);
    }
    Err(DnssecError::DenialMismatch)
}

fn valid_nsec(record: &ResourceRecord) -> Option<(&ResourceRecord, &Nsec)> {
    if record.class != CLASS_IN || record.record_type != RecordType::Nsec {
        return None;
    }
    let Rdata::Nsec(nsec) = &record.rdata else {
        return None;
    };
    Some((record, nsec))
}

fn valid_nsec3_record(record: &ResourceRecord) -> Option<&Nsec3> {
    if record.class != CLASS_IN || record.record_type != RecordType::Nsec3 {
        return None;
    }
    let Rdata::Nsec3(nsec3) = &record.rdata else {
        return None;
    };
    Some(nsec3)
}

fn ancestor(name: &Name, start: usize) -> Option<Name> {
    Name::from_labels(name.labels().get(start..)?.to_vec()).ok()
}

fn wildcard_of(name: &Name) -> Result<Name, DnssecError> {
    let mut labels = Vec::with_capacity(name.labels().len().saturating_add(1));
    labels.push(vec![b'*']);
    labels.extend_from_slice(name.labels());
    Name::from_labels(labels).map_err(|_| DnssecError::DenialMismatch)
}

fn is_suffix(name: &Name, suffix: &Name) -> bool {
    name.labels()
        .get(name.labels().len().saturating_sub(suffix.labels().len())..)
        == Some(suffix.labels())
}

fn rrsig_for<'a>(
    record: &'a ResourceRecord,
    owner: &Name,
    record_type: RecordType,
) -> Option<&'a Rrsig> {
    if record.name != *owner || record.class != CLASS_IN || record.record_type != RecordType::Rrsig
    {
        return None;
    }
    let Rdata::Rrsig(signature) = &record.rdata else {
        return None;
    };
    (signature.type_covered == record_type).then_some(signature)
}

fn dnskey_for<'a>(record: &'a ResourceRecord, owner: &Name) -> Option<&'a Dnskey> {
    if record.name != *owner || record.class != CLASS_IN || record.record_type != RecordType::Dnskey
    {
        return None;
    }
    let Rdata::Dnskey(key) = &record.rdata else {
        return None;
    };
    Some(key)
}

fn supported_algorithm(algorithm: u8) -> bool {
    matches!(
        algorithm,
        ALGORITHM_RSASHA1
            | ALGORITHM_RSASHA1_NSEC3
            | ALGORITHM_RSASHA256
            | ALGORITHM_RSASHA512
            | ALGORITHM_ECDSA_P256_SHA256
            | ALGORITHM_ECDSA_P384_SHA384
            | ALGORITHM_ED25519
            | ALGORITHM_ED448
    )
}

fn serial_in_window(now: u32, inception: u32, expiration: u32) -> bool {
    serial_le(inception, now) && serial_le(now, expiration)
}

fn serial_le(left: u32, right: u32) -> bool {
    left == right || right.wrapping_sub(left) < 0x8000_0000
}

fn canonical_signed_data(
    records: &[ResourceRecord],
    signature: &Rrsig,
    maximum: usize,
) -> Result<Vec<u8>, DnssecError> {
    let mut output = Vec::new();
    write_u16(&mut output, signature.type_covered.code());
    output.push(signature.algorithm);
    output.push(signature.labels);
    write_u32(&mut output, signature.original_ttl);
    write_u32(&mut output, signature.expiration);
    write_u32(&mut output, signature.inception);
    write_u16(&mut output, signature.key_tag);
    signature
        .signer
        .encode(&mut output)
        .map_err(|_| DnssecError::UnsupportedRdata)?;

    let mut canonical = records
        .iter()
        .map(|record| canonical_record(record, signature))
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort();
    for record in canonical {
        if output.len().saturating_add(record.len()) > maximum {
            return Err(DnssecError::Limit);
        }
        output.extend_from_slice(&record);
    }
    Ok(output)
}

fn canonical_record(record: &ResourceRecord, signature: &Rrsig) -> Result<Vec<u8>, DnssecError> {
    let mut output = canonical_owner(&record.name, usize::from(signature.labels))?;
    write_u16(&mut output, record.record_type.code());
    write_u16(&mut output, record.class);
    write_u32(&mut output, signature.original_ttl);
    let rdata = canonical_rdata(record)?;
    let length = u16::try_from(rdata.len()).map_err(|_| DnssecError::Limit)?;
    write_u16(&mut output, length);
    output.extend_from_slice(&rdata);
    Ok(output)
}

fn canonical_owner(owner: &Name, labels: usize) -> Result<Vec<u8>, DnssecError> {
    let owner_labels = owner.labels();
    if labels > owner_labels.len() {
        return Err(DnssecError::RrsetMismatch);
    }
    let mut output = Vec::with_capacity(owner.wire_len().saturating_add(2));
    if labels < owner_labels.len() {
        output.extend_from_slice(&[1, b'*']);
    }
    let start = owner_labels.len().saturating_sub(labels);
    for label in owner_labels
        .get(start..)
        .ok_or(DnssecError::RrsetMismatch)?
    {
        output.push(u8::try_from(label.len()).map_err(|_| DnssecError::UnsupportedRdata)?);
        output.extend_from_slice(label);
    }
    output.push(0);
    Ok(output)
}

fn canonical_rdata(record: &ResourceRecord) -> Result<Vec<u8>, DnssecError> {
    let mut output = Vec::new();
    match (&record.record_type, &record.rdata) {
        (RecordType::A, Rdata::A(address)) => output.extend_from_slice(&address.octets()),
        (RecordType::Aaaa, Rdata::Aaaa(address)) => output.extend_from_slice(&address.octets()),
        (RecordType::Ns, Rdata::Ns(name)) | (RecordType::Cname, Rdata::Cname(name)) => {
            encode_name(name, &mut output)?;
        }
        (RecordType::Soa, Rdata::Soa(soa)) => {
            encode_name(&soa.mname, &mut output)?;
            encode_name(&soa.rname, &mut output)?;
            write_u32(&mut output, soa.serial);
            write_u32(&mut output, soa.refresh);
            write_u32(&mut output, soa.retry);
            write_u32(&mut output, soa.expire);
            write_u32(&mut output, soa.minimum);
        }
        (RecordType::Mx, Rdata::Mx(mx)) => {
            write_u16(&mut output, mx.preference);
            encode_name(&mx.exchange, &mut output)?;
        }
        (RecordType::Txt, Rdata::Txt(strings)) => {
            for string in strings {
                output.push(u8::try_from(string.len()).map_err(|_| DnssecError::UnsupportedRdata)?);
                output.extend_from_slice(string);
            }
        }
        (RecordType::Srv, Rdata::Srv(srv)) => {
            write_u16(&mut output, srv.priority);
            write_u16(&mut output, srv.weight);
            write_u16(&mut output, srv.port);
            encode_name(&srv.target, &mut output)?;
        }
        (RecordType::Ds, Rdata::Ds(ds)) => output.extend_from_slice(&encode_ds(ds)),
        (RecordType::Dnskey, Rdata::Dnskey(key)) => output.extend_from_slice(&encode_dnskey(key)),
        (RecordType::Rrsig, Rdata::Rrsig(signature)) => {
            output.extend_from_slice(&encode_rrsig(signature)?);
        }
        (RecordType::Nsec, Rdata::Nsec(nsec)) => {
            encode_name(&nsec.next_domain, &mut output)?;
            output.extend_from_slice(&nsec.type_bitmaps);
        }
        (RecordType::Nsec3, Rdata::Nsec3(nsec3)) => {
            output.push(nsec3.hash_algorithm);
            output.push(nsec3.flags);
            write_u16(&mut output, nsec3.iterations);
            output.push(u8::try_from(nsec3.salt.len()).map_err(|_| DnssecError::UnsupportedRdata)?);
            output.extend_from_slice(&nsec3.salt);
            output.push(
                u8::try_from(nsec3.next_hashed_owner.len())
                    .map_err(|_| DnssecError::UnsupportedRdata)?,
            );
            output.extend_from_slice(&nsec3.next_hashed_owner);
            output.extend_from_slice(&nsec3.type_bitmaps);
        }
        (RecordType::Tlsa, Rdata::Tlsa(tlsa)) => {
            output.push(tlsa.usage);
            output.push(tlsa.selector);
            output.push(tlsa.matching_type);
            output.extend_from_slice(&tlsa.association_data);
        }
        (RecordType::Svcb | RecordType::Https | RecordType::Unknown(_), Rdata::Opaque(raw)) => {
            output.extend_from_slice(raw);
        }
        _ => return Err(DnssecError::UnsupportedRdata),
    }
    Ok(output)
}

fn encode_name(name: &Name, output: &mut Vec<u8>) -> Result<(), DnssecError> {
    name.encode(output)
        .map_err(|_| DnssecError::UnsupportedRdata)
}

fn encode_ds(ds: &Ds) -> Vec<u8> {
    let mut output = Vec::with_capacity(4usize.saturating_add(ds.digest.len()));
    write_u16(&mut output, ds.key_tag);
    output.push(ds.algorithm);
    output.push(ds.digest_type);
    output.extend_from_slice(&ds.digest);
    output
}

fn encode_dnskey(key: &Dnskey) -> Vec<u8> {
    let mut output = Vec::with_capacity(4usize.saturating_add(key.public_key.len()));
    write_u16(&mut output, key.flags);
    output.push(key.protocol);
    output.push(key.algorithm);
    output.extend_from_slice(&key.public_key);
    output
}

fn encode_rrsig(signature: &Rrsig) -> Result<Vec<u8>, DnssecError> {
    let mut output = Vec::new();
    write_u16(&mut output, signature.type_covered.code());
    output.push(signature.algorithm);
    output.push(signature.labels);
    write_u32(&mut output, signature.original_ttl);
    write_u32(&mut output, signature.expiration);
    write_u32(&mut output, signature.inception);
    write_u16(&mut output, signature.key_tag);
    encode_name(&signature.signer, &mut output)?;
    output.extend_from_slice(&signature.signature);
    Ok(output)
}

fn digest_ds(digest_type: u8, data: &[u8]) -> Result<Vec<u8>, DnssecError> {
    let digest = match digest_type {
        1 => MessageDigest::sha1(),
        2 => MessageDigest::sha256(),
        4 => MessageDigest::sha384(),
        value => return Err(DnssecError::UnsupportedDigest(value)),
    };
    hash(digest, data)
        .map(|digest| digest.to_vec())
        .map_err(|_| DnssecError::UnsupportedDigest(digest_type))
}

fn verify_signature(algorithm: u8, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    match algorithm {
        ALGORITHM_RSASHA1 | ALGORITHM_RSASHA1_NSEC3 => {
            verify_rsa(MessageDigest::sha1(), public_key, data, signature)
        }
        ALGORITHM_RSASHA256 => verify_rsa(MessageDigest::sha256(), public_key, data, signature),
        ALGORITHM_RSASHA512 => verify_rsa(MessageDigest::sha512(), public_key, data, signature),
        ALGORITHM_ECDSA_P256_SHA256 => verify_ecdsa(
            Nid::X9_62_PRIME256V1,
            32,
            MessageDigest::sha256(),
            public_key,
            data,
            signature,
        ),
        ALGORITHM_ECDSA_P384_SHA384 => verify_ecdsa(
            Nid::SECP384R1,
            48,
            MessageDigest::sha384(),
            public_key,
            data,
            signature,
        ),
        ALGORITHM_ED25519 => verify_ed(Id::ED25519, public_key, data, signature),
        ALGORITHM_ED448 => verify_ed(Id::ED448, public_key, data, signature),
        _ => false,
    }
}

fn verify_rsa(digest: MessageDigest, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let Some((exponent, modulus)) = rsa_components(public_key) else {
        return false;
    };
    let key = (|| {
        let exponent = BigNum::from_slice(exponent)?;
        let modulus = BigNum::from_slice(modulus)?;
        let rsa = Rsa::from_public_components(modulus, exponent)?;
        PKey::from_rsa(rsa)
    })();
    let Ok(key) = key else {
        return false;
    };
    verify_digest(digest, &key, data, signature, true)
}

fn rsa_components(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *raw.first()?;
    let (exponent_size, offset) = if first == 0 {
        let length = u16::from_be_bytes([*raw.get(1)?, *raw.get(2)?]);
        (usize::from(length), 3usize)
    } else {
        (usize::from(first), 1usize)
    };
    if exponent_size == 0 {
        return None;
    }
    let exponent_end = offset.checked_add(exponent_size)?;
    let exponent = raw.get(offset..exponent_end)?;
    let modulus = raw.get(exponent_end..)?;
    (!modulus.is_empty()).then_some((exponent, modulus))
}

fn verify_ecdsa(
    curve: Nid,
    coordinate_size: usize,
    digest: MessageDigest,
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> bool {
    if public_key.len() != coordinate_size.saturating_mul(2)
        || signature.len() != coordinate_size.saturating_mul(2)
    {
        return false;
    }
    let key = (|| {
        let group = EcGroup::from_curve_name(curve)?;
        let mut context = BigNumContext::new()?;
        let mut encoded = Vec::with_capacity(1usize.saturating_add(public_key.len()));
        encoded.push(4);
        encoded.extend_from_slice(public_key);
        let point = EcPoint::from_bytes(&group, &encoded, &mut context)?;
        let key = EcKey::from_public_key(&group, &point)?;
        PKey::from_ec_key(key)
    })();
    let Ok(key) = key else {
        return false;
    };
    let der = (|| {
        let r = BigNum::from_slice(signature.get(..coordinate_size).unwrap_or_default())?;
        let s = BigNum::from_slice(signature.get(coordinate_size..).unwrap_or_default())?;
        EcdsaSig::from_private_components(r, s)?.to_der()
    })();
    let Ok(der) = der else {
        return false;
    };
    verify_digest(digest, &key, data, &der, false)
}

fn verify_ed(id: Id, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = PKey::public_key_from_raw_bytes(public_key, id) else {
        return false;
    };
    let Ok(mut verifier) = Verifier::new_without_digest(&key) else {
        return false;
    };
    verifier.verify_oneshot(signature, data).unwrap_or(false)
}

fn verify_digest(
    digest: MessageDigest,
    key: &PKey<Public>,
    data: &[u8],
    signature: &[u8],
    rsa: bool,
) -> bool {
    let Ok(mut verifier) = Verifier::new(digest, key) else {
        return false;
    };
    if rsa && verifier.set_rsa_padding(Padding::PKCS1).is_err() {
        return false;
    }
    verifier
        .update(data)
        .and_then(|()| verifier.verify(signature))
        .unwrap_or(false)
}

fn validate_nsec3(record: &Nsec3, limits: DnssecLimits) -> Result<(), DnssecError> {
    if record.hash_algorithm != 1
        || record.flags & !1 != 0
        || record.iterations > limits.max_nsec3_iterations
        || record.salt.len() > u8::MAX as usize
        || record.next_hashed_owner.len() != 20
    {
        return Err(DnssecError::DenialMismatch);
    }
    Ok(())
}

fn nsec3_owner_hash(owner: &Name, zone: &Name) -> Option<[u8; 20]> {
    let owner_labels = owner.labels();
    let zone_labels = zone.labels();
    if owner_labels.len() != zone_labels.len().checked_add(1)?
        || owner_labels.get(1..)? != zone_labels
    {
        return None;
    }
    let decoded = decode_base32hex(owner_labels.first()?)?;
    decoded.try_into().ok()
}

fn decode_base32hex(input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len().saturating_mul(5) / 8);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in input {
        let value = match byte.to_ascii_uppercase() {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'V' => byte.to_ascii_uppercase() - b'A' + 10,
            _ => return None,
        };
        accumulator = (accumulator << 5) | u32::from(value);
        bits = bits.saturating_add(5);
        while bits >= 8 {
            bits -= 8;
            output.push(u8::try_from((accumulator >> bits) & 0xff).ok()?);
            accumulator &= (1_u32 << bits).saturating_sub(1);
        }
    }
    if bits != 0 && accumulator != 0 {
        return None;
    }
    Some(output)
}

fn bitmap_contains(bitmap: &[u8], record_type: u16) -> Result<bool, DnssecError> {
    let window = (record_type >> 8) as u8;
    let low = (record_type & 0xff) as usize;
    let mut cursor = 0usize;
    while cursor < bitmap.len() {
        let block_window = *bitmap.get(cursor).ok_or(DnssecError::DenialMismatch)?;
        let length = usize::from(
            *bitmap
                .get(cursor.saturating_add(1))
                .ok_or(DnssecError::DenialMismatch)?,
        );
        if length == 0 || length > 32 {
            return Err(DnssecError::DenialMismatch);
        }
        let start = cursor.saturating_add(2);
        let end = start.checked_add(length).ok_or(DnssecError::Limit)?;
        let block = bitmap.get(start..end).ok_or(DnssecError::DenialMismatch)?;
        if block_window == window {
            let byte_index = low / 8;
            return Ok(block
                .get(byte_index)
                .is_some_and(|byte| byte & (0x80 >> (low % 8)) != 0));
        }
        cursor = end;
    }
    Ok(false)
}

fn canonical_interval_contains(owner: &Name, next: &Name, candidate: &Name) -> bool {
    let owner_to_next = canonical_name_cmp(owner, next);
    let owner_to_candidate = canonical_name_cmp(owner, candidate);
    let candidate_to_next = canonical_name_cmp(candidate, next);
    if owner_to_next == Ordering::Less {
        owner_to_candidate == Ordering::Less && candidate_to_next == Ordering::Less
    } else {
        owner_to_candidate == Ordering::Less || candidate_to_next == Ordering::Less
    }
}

fn canonical_name_cmp(left: &Name, right: &Name) -> Ordering {
    let mut left_labels = left.labels().iter().rev();
    let mut right_labels = right.labels().iter().rev();
    loop {
        match (left_labels.next(), right_labels.next()) {
            (Some(left), Some(right)) => match left.cmp(right) {
                Ordering::Equal => {}
                ordering => return ordering,
            },
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

fn hash_interval_contains(owner: &[u8], next: &[u8], candidate: &[u8]) -> bool {
    if owner < next {
        owner < candidate && candidate < next
    } else {
        owner < candidate || candidate < next
    }
}

fn digest_sha1_many(parts: &[&[u8]]) -> Result<Vec<u8>, DnssecError> {
    let mut input = Vec::new();
    for part in parts {
        input
            .try_reserve(part.len())
            .map_err(|_| DnssecError::Limit)?;
        input.extend_from_slice(part);
    }
    hash(MessageDigest::sha1(), &input)
        .map(|digest| digest.to_vec())
        .map_err(|_| DnssecError::UnsupportedDigest(1))
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests intentionally fail immediately when local cryptographic fixtures are invalid"
)]
mod tests {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;

    use super::*;
    use hns_dns_wire::{Flags, Header, Message, Nsec, Question, Tlsa};

    fn name(value: &str) -> Name {
        Name::from_ascii(value).unwrap()
    }

    fn a_record(owner: &Name) -> ResourceRecord {
        ResourceRecord {
            name: owner.clone(),
            record_type: RecordType::A,
            class: CLASS_IN,
            ttl: 300,
            rdata: Rdata::A("192.0.2.1".parse().unwrap()),
        }
    }

    fn rsa_dnskey(rsa: &Rsa<openssl::pkey::Private>) -> Dnskey {
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

    fn sign_rrset(
        records: &[ResourceRecord],
        signer_name: Name,
        key: &Dnskey,
        key_pair: &PKey<openssl::pkey::Private>,
    ) -> ResourceRecord {
        let owner = records.first().unwrap().name.clone();
        let mut signature = Rrsig {
            type_covered: records.first().unwrap().record_type,
            algorithm: key.algorithm,
            labels: u8::try_from(owner.labels().len()).unwrap(),
            original_ttl: records.first().unwrap().ttl,
            expiration: 2_000,
            inception: 1_000,
            key_tag: dnskey_tag(key),
            signer: signer_name,
            signature: Vec::new(),
        };
        let signed = rrsig_signed_data(
            records,
            &signature,
            DnssecLimits::default().max_signed_data_len,
        )
        .unwrap();
        let mut crypto_signer = Signer::new(MessageDigest::sha256(), key_pair).unwrap();
        crypto_signer.update(&signed).unwrap();
        signature.signature = crypto_signer.sign_to_vec().unwrap();
        ResourceRecord {
            name: owner,
            record_type: RecordType::Rrsig,
            class: CLASS_IN,
            ttl: signature.original_ttl,
            rdata: Rdata::Rrsig(signature),
        }
    }

    fn signed_fixture() -> (
        Vec<ResourceRecord>,
        Vec<ResourceRecord>,
        Vec<ResourceRecord>,
    ) {
        let owner = name("www.example.");
        let signer_name = name("example.");
        let records = vec![a_record(&owner)];
        let rsa = Rsa::generate(1024).unwrap();
        let key = rsa_dnskey(&rsa);
        let key_pair = PKey::from_rsa(rsa).unwrap();
        let signatures = vec![sign_rrset(&records, signer_name.clone(), &key, &key_pair)];
        let keys = vec![ResourceRecord {
            name: signer_name,
            record_type: RecordType::Dnskey,
            class: CLASS_IN,
            ttl: 300,
            rdata: Rdata::Dnskey(key),
        }];
        (records, signatures, keys)
    }

    #[test]
    fn authenticated_keyset_verifies_terminal_rrsets() {
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
        let dnskey_signatures = vec![sign_rrset(&dnskeys, zone.clone(), &key, &key_pair)];
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
        let authenticated = authenticate_dnskeys(
            &zone,
            &ds,
            &dnskeys,
            &dnskey_signatures,
            1_500,
            DnssecLimits::default(),
        )
        .unwrap();
        assert_eq!(authenticated.zone(), &zone);
        assert_eq!(authenticated.delegation_key_tag(), dnskey_tag(&key));

        let records = vec![a_record(&name("www.example."))];
        let signatures = vec![sign_rrset(&records, zone, &key, &key_pair)];
        let verified = verify_rrset_with_keys(
            &authenticated,
            &records,
            &signatures,
            1_500,
            DnssecLimits::default(),
        )
        .unwrap();
        assert_eq!(verified.record_type(), RecordType::A);
        assert_eq!(verified.owner(), &name("www.example."));
    }

    #[test]
    fn validates_rrset_and_rejects_mutation_or_time_failure() {
        let (records, signatures, keys) = signed_fixture();
        let verified =
            verify_rrset(&records, &signatures, &keys, 1_500, DnssecLimits::default()).unwrap();
        assert_eq!(verified.owner(), &name("www.example."));
        assert_eq!(verified.record_type(), RecordType::A);

        let mut mutated = records.clone();
        let record = mutated.first_mut().unwrap();
        record.rdata = Rdata::A("192.0.2.2".parse().unwrap());
        assert!(matches!(
            verify_rrset(&mutated, &signatures, &keys, 1_500, DnssecLimits::default()),
            Err(DnssecError::SignatureMismatch)
        ));
        assert_eq!(
            verify_rrset(&records, &signatures, &keys, 999, DnssecLimits::default()),
            Err(DnssecError::SignatureTime)
        );
    }

    #[test]
    fn verifies_ds_and_rejects_wrong_digest() {
        let owner = name("example.");
        let rsa = Rsa::generate(1024).unwrap();
        let key = rsa_dnskey(&rsa);
        let mut input = Vec::new();
        owner.encode(&mut input).unwrap();
        input.extend_from_slice(&encode_dnskey(&key));
        let digest = hash(MessageDigest::sha256(), &input).unwrap().to_vec();
        let record = ResourceRecord {
            name: owner.clone(),
            record_type: RecordType::Ds,
            class: CLASS_IN,
            ttl: 300,
            rdata: Rdata::Ds(Ds {
                key_tag: dnskey_tag(&key),
                algorithm: key.algorithm,
                digest_type: 2,
                digest,
            }),
        };
        verify_ds(&owner, &key, std::slice::from_ref(&record)).unwrap();
        let mut wrong = record;
        let Rdata::Ds(ds) = &mut wrong.rdata else {
            unreachable!()
        };
        let first = ds.digest.first_mut().unwrap();
        *first ^= 1;
        assert_eq!(
            verify_ds(&owner, &key, &[wrong]),
            Err(DnssecError::DsMismatch)
        );
    }

    #[test]
    fn validates_nsec_nodata_and_wrapped_name_error() {
        let owner = name("present.example.");
        let nsec = ResourceRecord {
            name: owner.clone(),
            record_type: RecordType::Nsec,
            class: CLASS_IN,
            ttl: 300,
            rdata: Rdata::Nsec(Nsec {
                next_domain: name("zzz.example."),
                type_bitmaps: vec![0, 1, 0x40],
            }),
        };
        let closest_encloser = ResourceRecord {
            name: name("example."),
            record_type: RecordType::Nsec,
            class: CLASS_IN,
            ttl: 300,
            rdata: Rdata::Nsec(Nsec {
                next_domain: owner.clone(),
                type_bitmaps: vec![0, 1, 0x02],
            }),
        };
        assert_eq!(
            verify_nsec_denial(
                &owner,
                RecordType::Tlsa,
                std::slice::from_ref(&nsec),
                false,
                DnssecLimits::default()
            )
            .unwrap(),
            Denial::NoData
        );
        assert_eq!(
            verify_nsec_denial(
                &name("target.example."),
                RecordType::A,
                &[nsec, closest_encloser],
                true,
                DnssecLimits::default()
            )
            .unwrap(),
            Denial::NameError
        );
    }

    #[test]
    fn nsec3_hash_matches_rfc_5155_example() {
        assert_eq!(
            nsec3_hash(
                &name("example."),
                &[0xaa, 0xbb, 0xcc, 0xdd],
                12,
                DnssecLimits::default()
            )
            .unwrap(),
            [
                0x06, 0x53, 0x68, 0xab, 0xee, 0xd7, 0xec, 0x6e, 0x9f, 0xeb, 0xa9, 0x6b, 0x8c, 0x8b,
                0xc3, 0xe8, 0xb7, 0x91, 0xf7, 0x16,
            ]
        );
        assert_eq!(
            decode_base32hex(b"0p9mhaveqvm6t7vbl5lop2u3t2rp3tom")
                .unwrap()
                .as_slice(),
            [
                0x06, 0x53, 0x68, 0xab, 0xee, 0xd7, 0xec, 0x6e, 0x9f, 0xeb, 0xa9, 0x6b, 0x8c, 0x8b,
                0xc3, 0xe8, 0xb7, 0x91, 0xf7, 0x16,
            ]
        );
    }

    #[test]
    fn ad_bit_is_never_an_input_to_dnssec_verification() {
        let (records, signatures, keys) = signed_fixture();
        let message = Message {
            header: Header {
                id: 1,
                flags: Flags::from_bits(0x8020),
                question_count: 1,
                answer_count: u16::try_from(records.len() + signatures.len()).unwrap(),
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![Question {
                name: name("www.example."),
                record_type: RecordType::A,
                class: CLASS_IN,
            }],
            answers: records.iter().chain(&signatures).cloned().collect(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        assert!(message.header.flags.authenticated_data_claim());
        verify_rrset(&records, &signatures, &keys, 1_500, DnssecLimits::default()).unwrap();

        let tlsa = Tlsa {
            usage: 3,
            selector: 1,
            matching_type: 1,
            association_data: vec![0; 32],
        };
        assert_eq!(tlsa.association_data.len(), 32);
    }
}
