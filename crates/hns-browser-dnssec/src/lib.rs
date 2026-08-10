use hns_core::dns::{DnsName, RecordType, ResourceRecord, SvcbRecord};
use num_bigint::BigUint;
use num_traits::Zero;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use ring::signature::{
    ECDSA_P384_SHA384_FIXED, ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512,
    RsaPublicKeyComponents, UnparsedPublicKey,
};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};
use thiserror::Error;

pub const DNSSEC_PROTOCOL: u8 = 3;
pub const DNSKEY_ZONE_FLAG: u16 = 0x0100;
pub const DNSSEC_ALGORITHM_RSASHA1: u8 = 5;
pub const DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1: u8 = 7;
pub const DNSSEC_ALGORITHM_RSASHA256: u8 = 8;
pub const DNSSEC_ALGORITHM_RSASHA512: u8 = 10;
pub const DNSSEC_ALGORITHM_ECDSAP256SHA256: u8 = 13;
pub const DNSSEC_ALGORITHM_ECDSAP384SHA384: u8 = 14;
pub const DNSSEC_ALGORITHM_ED25519: u8 = 15;
pub const DS_DIGEST_SHA1: u8 = 1;
pub const DS_DIGEST_SHA256: u8 = 2;
pub const DS_DIGEST_SHA384: u8 = 4;
pub const NSEC3_HASH_SHA1: u8 = 1;
pub const NSEC3_OPT_OUT_FLAG: u8 = 0x01;
pub const NSEC3_MAX_ITERATIONS: u16 = 2_500;
const RSA_PKCS1_V1_5_MIN_PADDING_LEN: usize = 8;
const SHA1_DIGEST_INFO_PREFIX: [u8; 15] = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnssecTime(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnssecInput {
    pub rrsets: Vec<ResourceRecord>,
    pub now_unix: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedRrsetValidationInput<'a> {
    pub dnskey_owner: &'a DnsName,
    pub ds_rrset: &'a [ResourceRecord],
    pub dnskey_rrset: &'a [ResourceRecord],
    pub dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub rrset: &'a [ResourceRecord],
    pub rrsig_rrset: &'a [ResourceRecord],
    pub now: DnssecTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnssecChainLink<'a> {
    pub child_dnskey_owner: &'a DnsName,
    pub ds_rrset: &'a [ResourceRecord],
    pub ds_rrsig_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrset: &'a [ResourceRecord],
    pub child_dnskey_rrsig_rrset: &'a [ResourceRecord],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnssecChainValidationInput<'a> {
    pub initial_dnskey_owner: &'a DnsName,
    pub initial_ds_rrset: &'a [ResourceRecord],
    pub initial_dnskey_rrset: &'a [ResourceRecord],
    pub initial_dnskey_rrsig_rrset: &'a [ResourceRecord],
    pub delegation_links: &'a [DnssecChainLink<'a>],
    pub target_rrset: &'a [ResourceRecord],
    pub target_rrsig_rrset: &'a [ResourceRecord],
    pub now: DnssecTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsecNoDataValidationInput<'a> {
    pub signer_name: &'a DnsName,
    pub dnskey_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub query_type: RecordType,
    pub nsec_rrset: &'a [ResourceRecord],
    pub nsec_rrsig_rrset: &'a [ResourceRecord],
    pub now: DnssecTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsecNameRangeValidationInput<'a> {
    pub signer_name: &'a DnsName,
    pub dnskey_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub nsec_rrset: &'a [ResourceRecord],
    pub nsec_rrsig_rrset: &'a [ResourceRecord],
    pub now: DnssecTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsecNameErrorValidationInput<'a> {
    pub signer_name: &'a DnsName,
    pub dnskey_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub closest_encloser: &'a DnsName,
    pub covering_nsec_rrset: &'a [ResourceRecord],
    pub covering_nsec_rrsig_rrset: &'a [ResourceRecord],
    pub wildcard_nsec_rrset: &'a [ResourceRecord],
    pub wildcard_nsec_rrsig_rrset: &'a [ResourceRecord],
    pub now: DnssecTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nsec3NoDataValidationInput<'a> {
    pub signer_name: &'a DnsName,
    pub dnskey_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub query_type: RecordType,
    pub nsec3_rrset: &'a [ResourceRecord],
    pub nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub now: DnssecTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nsec3NameErrorValidationInput<'a> {
    pub signer_name: &'a DnsName,
    pub dnskey_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub closest_encloser: &'a DnsName,
    pub closest_encloser_nsec3_rrset: &'a [ResourceRecord],
    pub closest_encloser_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub next_closer_nsec3_rrset: &'a [ResourceRecord],
    pub next_closer_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub wildcard_nsec3_rrset: &'a [ResourceRecord],
    pub wildcard_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub now: DnssecTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nsec3DsNoDataValidationInput<'a> {
    pub signer_name: &'a DnsName,
    pub dnskey_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub matching_nsec3_rrset: &'a [ResourceRecord],
    pub matching_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub closest_encloser: &'a DnsName,
    pub closest_encloser_nsec3_rrset: &'a [ResourceRecord],
    pub closest_encloser_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub next_closer_nsec3_rrset: &'a [ResourceRecord],
    pub next_closer_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub now: DnssecTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nsec3WildcardNoDataValidationInput<'a> {
    pub signer_name: &'a DnsName,
    pub dnskey_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub closest_encloser: &'a DnsName,
    pub query_type: RecordType,
    pub closest_encloser_nsec3_rrset: &'a [ResourceRecord],
    pub closest_encloser_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub next_closer_nsec3_rrset: &'a [ResourceRecord],
    pub next_closer_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub wildcard_nsec3_rrset: &'a [ResourceRecord],
    pub wildcard_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub now: DnssecTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nsec3UnsignedReferralValidationInput<'a> {
    pub signer_name: &'a DnsName,
    pub dnskey_rrset: &'a [ResourceRecord],
    pub delegation_name: &'a DnsName,
    pub matching_nsec3_rrset: &'a [ResourceRecord],
    pub matching_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub closest_encloser: &'a DnsName,
    pub closest_encloser_nsec3_rrset: &'a [ResourceRecord],
    pub closest_encloser_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub next_closer_nsec3_rrset: &'a [ResourceRecord],
    pub next_closer_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub now: DnssecTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nsec3WildcardAnswerValidationInput<'a> {
    pub signer_name: &'a DnsName,
    pub dnskey_rrset: &'a [ResourceRecord],
    pub query_name: &'a DnsName,
    pub closest_encloser: &'a DnsName,
    pub next_closer_nsec3_rrset: &'a [ResourceRecord],
    pub next_closer_nsec3_rrsig_rrset: &'a [ResourceRecord],
    pub now: DnssecTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnskeyRecord {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
    rdata: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DsRecord {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RrsigRecord {
    pub type_covered: RecordType,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub signature_expiration: DnssecTime,
    pub signature_inception: DnssecTime,
    pub key_tag: u16,
    pub signer_name: DnsName,
    pub signature: Vec<u8>,
    signed_rdata: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NsecRecord {
    pub next_domain_name: DnsName,
    type_bit_maps: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nsec3Record {
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next_hashed_owner_name: Vec<u8>,
    type_bit_maps: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnssecStatus {
    Secure,
    InsecureDelegation,
    Bogus,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DnssecError {
    #[error("DNSSEC validation is not implemented")]
    UnsupportedValidator,
    #[error("DNSKEY record is malformed")]
    InvalidDnskey,
    #[error("DS record is malformed")]
    InvalidDs,
    #[error("DNSSEC digest type is unsupported")]
    UnsupportedDigest,
    #[error("DNSSEC owner name cannot be encoded canonically")]
    NameEncoding,
    #[error("RRSIG record is malformed")]
    InvalidRrsig,
    #[error("NSEC record is malformed")]
    InvalidNsec,
    #[error("NSEC3 record is malformed")]
    InvalidNsec3,
    #[error("RRset cannot be canonicalized")]
    InvalidRrset,
    #[error("RR type requires unsupported RDATA canonicalization")]
    UnsupportedCanonicalRdata,
    #[error("RRSIG is not valid at the requested time")]
    SignatureOutsideValidity,
    #[error("DNSSEC signature algorithm is unsupported")]
    UnsupportedAlgorithm,
    #[error("DNSSEC signature is malformed")]
    InvalidSignature,
}

pub trait DnssecValidator {
    fn validate(&self, input: &DnssecInput) -> Result<DnssecStatus, DnssecError>;
}

pub struct FailClosedDnssecValidator;

impl DnssecValidator for FailClosedDnssecValidator {
    fn validate(&self, _input: &DnssecInput) -> Result<DnssecStatus, DnssecError> {
        Err(DnssecError::UnsupportedValidator)
    }
}

impl DnskeyRecord {
    pub fn parse_rdata(rdata: &[u8]) -> Result<Self, DnssecError> {
        if rdata.len() < 4 {
            return Err(DnssecError::InvalidDnskey);
        }

        let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
        let protocol = rdata[2];
        if protocol != DNSSEC_PROTOCOL {
            return Err(DnssecError::InvalidDnskey);
        }

        Ok(Self {
            flags,
            protocol,
            algorithm: rdata[3],
            public_key: rdata[4..].to_vec(),
            rdata: rdata.to_vec(),
        })
    }

    pub fn from_record(record: &ResourceRecord) -> Result<Self, DnssecError> {
        if record.record_type != RecordType::Dnskey {
            return Err(DnssecError::InvalidDnskey);
        }
        Self::parse_rdata(&record.rdata)
    }

    pub fn rdata(&self) -> &[u8] {
        &self.rdata
    }

    pub fn key_tag(&self) -> u16 {
        key_tag(self.rdata())
    }
}

impl DsRecord {
    pub fn parse_rdata(rdata: &[u8]) -> Result<Self, DnssecError> {
        if rdata.len() < 5 {
            return Err(DnssecError::InvalidDs);
        }

        Ok(Self {
            key_tag: u16::from_be_bytes([rdata[0], rdata[1]]),
            algorithm: rdata[2],
            digest_type: rdata[3],
            digest: rdata[4..].to_vec(),
        })
    }

    pub fn from_record(record: &ResourceRecord) -> Result<Self, DnssecError> {
        if record.record_type != RecordType::Ds {
            return Err(DnssecError::InvalidDs);
        }
        Self::parse_rdata(&record.rdata)
    }
}

impl RrsigRecord {
    pub fn parse_rdata(rdata: &[u8]) -> Result<Self, DnssecError> {
        if rdata.len() < 19 {
            return Err(DnssecError::InvalidRrsig);
        }

        let type_covered = RecordType::from_code(u16::from_be_bytes([rdata[0], rdata[1]]));
        let algorithm = rdata[2];
        let labels = rdata[3];
        let original_ttl = u32::from_be_bytes([rdata[4], rdata[5], rdata[6], rdata[7]]);
        let signature_expiration =
            DnssecTime(u32::from_be_bytes([rdata[8], rdata[9], rdata[10], rdata[11]]) as u64);
        let signature_inception =
            DnssecTime(u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]) as u64);
        let key_tag = u16::from_be_bytes([rdata[16], rdata[17]]);
        let (signer_name, signer_end) =
            DnsName::parse_wire(rdata, 18).map_err(|_| DnssecError::InvalidRrsig)?;
        if signer_end >= rdata.len() {
            return Err(DnssecError::InvalidRrsig);
        }

        let mut signed_rdata = rdata[..18].to_vec();
        signer_name
            .encode_wire(&mut signed_rdata)
            .map_err(|_| DnssecError::NameEncoding)?;

        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature: rdata[signer_end..].to_vec(),
            signed_rdata,
        })
    }

    pub fn from_record(record: &ResourceRecord) -> Result<Self, DnssecError> {
        if record.record_type != RecordType::Rrsig {
            return Err(DnssecError::InvalidRrsig);
        }
        Self::parse_rdata(&record.rdata)
    }

    pub fn signed_rdata(&self) -> &[u8] {
        &self.signed_rdata
    }

    pub fn is_valid_at(&self, now: DnssecTime) -> bool {
        now.0 >= self.signature_inception.0 && now.0 <= self.signature_expiration.0
    }
}

impl NsecRecord {
    pub fn parse_rdata(rdata: &[u8]) -> Result<Self, DnssecError> {
        let (next_domain_name, cursor) =
            DnsName::parse_wire(rdata, 0).map_err(|_| DnssecError::InvalidNsec)?;
        if cursor >= rdata.len() {
            return Err(DnssecError::InvalidNsec);
        }
        validate_nsec_type_bit_maps(&rdata[cursor..])?;

        Ok(Self {
            next_domain_name,
            type_bit_maps: rdata[cursor..].to_vec(),
        })
    }

    pub fn from_record(record: &ResourceRecord) -> Result<Self, DnssecError> {
        if record.record_type != RecordType::Nsec {
            return Err(DnssecError::InvalidNsec);
        }
        Self::parse_rdata(&record.rdata)
    }

    pub fn has_type(&self, record_type: RecordType) -> Result<bool, DnssecError> {
        nsec_type_bit_maps_contain(&self.type_bit_maps, record_type)
    }
}

impl Nsec3Record {
    pub fn parse_rdata(rdata: &[u8]) -> Result<Self, DnssecError> {
        if rdata.len() < 6 {
            return Err(DnssecError::InvalidNsec3);
        }

        let hash_algorithm = rdata[0];
        let flags = rdata[1];
        let iterations = u16::from_be_bytes([rdata[2], rdata[3]]);
        let salt_len = rdata[4] as usize;
        let salt_start = 5usize;
        let salt_end = salt_start
            .checked_add(salt_len)
            .ok_or(DnssecError::InvalidNsec3)?;
        if salt_end >= rdata.len() {
            return Err(DnssecError::InvalidNsec3);
        }

        let hash_len = rdata[salt_end] as usize;
        if hash_len == 0 {
            return Err(DnssecError::InvalidNsec3);
        }
        let hash_start = salt_end + 1;
        let hash_end = hash_start
            .checked_add(hash_len)
            .ok_or(DnssecError::InvalidNsec3)?;
        if hash_end > rdata.len() {
            return Err(DnssecError::InvalidNsec3);
        }
        validate_nsec_type_bit_maps(&rdata[hash_end..]).map_err(|_| DnssecError::InvalidNsec3)?;

        Ok(Self {
            hash_algorithm,
            flags,
            iterations,
            salt: rdata[salt_start..salt_end].to_vec(),
            next_hashed_owner_name: rdata[hash_start..hash_end].to_vec(),
            type_bit_maps: rdata[hash_end..].to_vec(),
        })
    }

    pub fn from_record(record: &ResourceRecord) -> Result<Self, DnssecError> {
        if record.record_type != RecordType::Nsec3 {
            return Err(DnssecError::InvalidNsec3);
        }
        Self::parse_rdata(&record.rdata)
    }

    pub fn has_type(&self, record_type: RecordType) -> Result<bool, DnssecError> {
        nsec_type_bit_maps_contain(&self.type_bit_maps, record_type)
            .map_err(|_| DnssecError::InvalidNsec3)
    }

    pub fn is_opt_out(&self) -> bool {
        self.flags & NSEC3_OPT_OUT_FLAG != 0
    }

    fn is_usable(&self) -> bool {
        self.hash_algorithm == NSEC3_HASH_SHA1 && self.flags & !NSEC3_OPT_OUT_FLAG == 0
    }
}

pub fn key_tag(dnskey_rdata: &[u8]) -> u16 {
    let mut accumulator = 0u32;
    for (index, byte) in dnskey_rdata.iter().enumerate() {
        if index & 1 == 0 {
            accumulator += (*byte as u32) << 8;
        } else {
            accumulator += *byte as u32;
        }
    }
    accumulator += (accumulator >> 16) & 0xffff;
    (accumulator & 0xffff) as u16
}

pub fn ds_digest(
    owner: &DnsName,
    dnskey: &DnskeyRecord,
    digest_type: u8,
) -> Result<Vec<u8>, DnssecError> {
    let mut canonical = Vec::new();
    owner
        .encode_wire(&mut canonical)
        .map_err(|_| DnssecError::NameEncoding)?;
    canonical.extend(dnskey.rdata());

    match digest_type {
        DS_DIGEST_SHA1 => Ok(Sha1::digest(&canonical).to_vec()),
        DS_DIGEST_SHA256 => Ok(Sha256::digest(&canonical).to_vec()),
        DS_DIGEST_SHA384 => Ok(Sha384::digest(&canonical).to_vec()),
        _ => Err(DnssecError::UnsupportedDigest),
    }
}

pub fn verify_ds_digest(
    owner: &DnsName,
    dnskey: &DnskeyRecord,
    ds: &DsRecord,
) -> Result<bool, DnssecError> {
    if dnskey.flags & DNSKEY_ZONE_FLAG == 0 {
        return Ok(false);
    }
    if dnskey.algorithm != ds.algorithm || dnskey.key_tag() != ds.key_tag {
        return Ok(false);
    }

    Ok(ds_digest(owner, dnskey, ds.digest_type)? == ds.digest)
}

pub fn validate_delegation_link(
    owner: &DnsName,
    ds_rrset: &[ResourceRecord],
    dnskey_rrset: &[ResourceRecord],
) -> Result<DnssecStatus, DnssecError> {
    let ds_records = ds_rrset
        .iter()
        .filter(|record| record.record_type == RecordType::Ds)
        .map(DsRecord::from_record)
        .collect::<Result<Vec<_>, _>>()?;
    if ds_records.is_empty() {
        return Ok(DnssecStatus::InsecureDelegation);
    }

    let dnskeys = dnskey_rrset
        .iter()
        .filter(|record| record.record_type == RecordType::Dnskey)
        .map(DnskeyRecord::from_record)
        .collect::<Result<Vec<_>, _>>()?;

    for dnskey in &dnskeys {
        for ds in &ds_records {
            if verify_ds_digest(owner, dnskey, ds)? {
                return Ok(DnssecStatus::Secure);
            }
        }
    }

    Ok(DnssecStatus::Bogus)
}

pub fn validate_signed_rrset(
    input: SignedRrsetValidationInput<'_>,
) -> Result<DnssecStatus, DnssecError> {
    let delegation =
        validate_delegation_link(input.dnskey_owner, input.ds_rrset, input.dnskey_rrset)?;
    if delegation != DnssecStatus::Secure {
        return Ok(delegation);
    }

    let dnskey_status = validate_dnskey_rrset(
        input.dnskey_owner,
        input.dnskey_rrset,
        input.dnskey_rrsig_rrset,
        input.now,
    )?;
    if dnskey_status != DnssecStatus::Secure {
        return Ok(dnskey_status);
    }

    validate_rrset_signature(
        input.dnskey_owner,
        input.dnskey_rrset,
        input.rrset,
        input.rrsig_rrset,
        input.now,
    )
}

pub fn validate_dnssec_chain(
    input: DnssecChainValidationInput<'_>,
) -> Result<DnssecStatus, DnssecError> {
    let initial_delegation = validate_delegation_link(
        input.initial_dnskey_owner,
        input.initial_ds_rrset,
        input.initial_dnskey_rrset,
    )?;
    if initial_delegation != DnssecStatus::Secure {
        return Ok(initial_delegation);
    }

    let initial_dnskey_status = validate_dnskey_rrset(
        input.initial_dnskey_owner,
        input.initial_dnskey_rrset,
        input.initial_dnskey_rrsig_rrset,
        input.now,
    )?;
    if initial_dnskey_status != DnssecStatus::Secure {
        return Ok(initial_dnskey_status);
    }

    let mut current_dnskey_owner = input.initial_dnskey_owner;
    let mut current_dnskey_rrset = input.initial_dnskey_rrset;
    for link in input.delegation_links {
        let delegation = validate_delegation_link(
            link.child_dnskey_owner,
            link.ds_rrset,
            link.child_dnskey_rrset,
        )?;
        if delegation != DnssecStatus::Secure {
            return Ok(delegation);
        }

        let ds_status = validate_rrset_signature(
            current_dnskey_owner,
            current_dnskey_rrset,
            link.ds_rrset,
            link.ds_rrsig_rrset,
            input.now,
        )?;
        if ds_status != DnssecStatus::Secure {
            return Ok(ds_status);
        }

        let child_dnskey_status = validate_dnskey_rrset(
            link.child_dnskey_owner,
            link.child_dnskey_rrset,
            link.child_dnskey_rrsig_rrset,
            input.now,
        )?;
        if child_dnskey_status != DnssecStatus::Secure {
            return Ok(child_dnskey_status);
        }

        current_dnskey_owner = link.child_dnskey_owner;
        current_dnskey_rrset = link.child_dnskey_rrset;
    }

    validate_rrset_signature(
        current_dnskey_owner,
        current_dnskey_rrset,
        input.target_rrset,
        input.target_rrsig_rrset,
        input.now,
    )
}

pub fn validate_dnskey_rrset(
    dnskey_owner: &DnsName,
    dnskey_rrset: &[ResourceRecord],
    dnskey_rrsig_rrset: &[ResourceRecord],
    now: DnssecTime,
) -> Result<DnssecStatus, DnssecError> {
    validate_rrset_signature(
        dnskey_owner,
        dnskey_rrset,
        dnskey_rrset,
        dnskey_rrsig_rrset,
        now,
    )
}

pub fn validate_rrset_signature(
    dnskey_owner: &DnsName,
    dnskey_rrset: &[ResourceRecord],
    rrset: &[ResourceRecord],
    rrsig_rrset: &[ResourceRecord],
    now: DnssecTime,
) -> Result<DnssecStatus, DnssecError> {
    let first = rrset.first().ok_or(DnssecError::InvalidRrset)?;
    let rrset_owner = first.name.clone();
    let rrset_class = first.class;
    let record_type = first.record_type;
    let dnskeys = dnskey_rrset
        .iter()
        .filter(|record| record.record_type == RecordType::Dnskey)
        .map(DnskeyRecord::from_record)
        .collect::<Result<Vec<_>, _>>()?;
    let rrsigs = rrsig_rrset
        .iter()
        .filter(|record| {
            record.record_type == RecordType::Rrsig
                && record.name == rrset_owner
                && record.class == rrset_class
        })
        .map(RrsigRecord::from_record)
        .collect::<Result<Vec<_>, _>>()?;

    let mut deferred_error = None;
    for rrsig in rrsigs
        .iter()
        .filter(|rrsig| rrsig.type_covered == record_type && rrsig.signer_name == *dnskey_owner)
    {
        for dnskey in dnskeys.iter().filter(|dnskey| {
            dnskey.algorithm == rrsig.algorithm && dnskey.key_tag() == rrsig.key_tag
        }) {
            match verify_rrsig(rrset, rrsig, dnskey, now) {
                Ok(true) => return Ok(DnssecStatus::Secure),
                Ok(false) => {}
                Err(error) => {
                    deferred_error.get_or_insert(error);
                }
            }
        }
    }

    if let Some(error) = deferred_error {
        Err(error)
    } else {
        Ok(DnssecStatus::Bogus)
    }
}

pub fn validate_nsec_no_data(
    input: NsecNoDataValidationInput<'_>,
) -> Result<DnssecStatus, DnssecError> {
    let signature_status = validate_rrset_signature(
        input.signer_name,
        input.dnskey_rrset,
        input.nsec_rrset,
        input.nsec_rrsig_rrset,
        input.now,
    )?;
    if signature_status != DnssecStatus::Secure {
        return Ok(signature_status);
    }

    for record in input
        .nsec_rrset
        .iter()
        .filter(|record| record.record_type == RecordType::Nsec && record.name == *input.query_name)
    {
        let nsec = NsecRecord::from_record(record)?;
        if !nsec.has_type(input.query_type)? && !nsec.has_type(RecordType::Cname)? {
            return Ok(DnssecStatus::Secure);
        }
    }

    Ok(DnssecStatus::Bogus)
}

pub fn validate_nsec_name_range(
    input: NsecNameRangeValidationInput<'_>,
) -> Result<DnssecStatus, DnssecError> {
    let mut deferred_error = None;

    for record in input
        .nsec_rrset
        .iter()
        .filter(|record| record.record_type == RecordType::Nsec)
    {
        let nsec = NsecRecord::from_record(record)?;
        if nsec_covers_name(&record.name, &nsec.next_domain_name, input.query_name) {
            let owner_nsec_rrset = input
                .nsec_rrset
                .iter()
                .filter(|candidate| {
                    candidate.record_type == RecordType::Nsec
                        && candidate.name == record.name
                        && candidate.class == record.class
                })
                .cloned()
                .collect::<Vec<_>>();
            let owner_rrsig_rrset = input
                .nsec_rrsig_rrset
                .iter()
                .filter(|candidate| {
                    candidate.record_type == RecordType::Rrsig
                        && candidate.name == record.name
                        && candidate.class == record.class
                })
                .cloned()
                .collect::<Vec<_>>();

            match validate_rrset_signature(
                input.signer_name,
                input.dnskey_rrset,
                &owner_nsec_rrset,
                &owner_rrsig_rrset,
                input.now,
            ) {
                Ok(DnssecStatus::Secure) => return Ok(DnssecStatus::Secure),
                Ok(_) => {}
                Err(error) => {
                    deferred_error.get_or_insert(error);
                }
            }
        }
    }

    if let Some(error) = deferred_error {
        Err(error)
    } else {
        Ok(DnssecStatus::Bogus)
    }
}

pub fn validate_nsec_name_error(
    input: NsecNameErrorValidationInput<'_>,
) -> Result<DnssecStatus, DnssecError> {
    if !is_strict_subdomain(input.query_name, input.closest_encloser) {
        return Ok(DnssecStatus::Bogus);
    }
    if input.covering_nsec_rrset.is_empty() || input.wildcard_nsec_rrset.is_empty() {
        return Ok(DnssecStatus::Bogus);
    }

    let query_name_status = validate_nsec_name_range(NsecNameRangeValidationInput {
        signer_name: input.signer_name,
        dnskey_rrset: input.dnskey_rrset,
        query_name: input.query_name,
        nsec_rrset: input.covering_nsec_rrset,
        nsec_rrsig_rrset: input.covering_nsec_rrsig_rrset,
        now: input.now,
    })?;
    if query_name_status != DnssecStatus::Secure {
        return Ok(query_name_status);
    }

    let wildcard_name = wildcard_child(input.closest_encloser)?;
    let wildcard_status = validate_nsec_name_range(NsecNameRangeValidationInput {
        signer_name: input.signer_name,
        dnskey_rrset: input.dnskey_rrset,
        query_name: &wildcard_name,
        nsec_rrset: input.wildcard_nsec_rrset,
        nsec_rrsig_rrset: input.wildcard_nsec_rrsig_rrset,
        now: input.now,
    })?;
    if wildcard_status != DnssecStatus::Secure {
        return Ok(wildcard_status);
    }

    Ok(DnssecStatus::Secure)
}

pub fn validate_nsec3_no_data(
    input: Nsec3NoDataValidationInput<'_>,
) -> Result<DnssecStatus, DnssecError> {
    let signature_status = validate_nsec3_rrset_signature(
        input.signer_name,
        input.dnskey_rrset,
        input.nsec3_rrset,
        input.nsec3_rrsig_rrset,
        input.now,
    )?;
    if signature_status != DnssecStatus::Secure {
        return Ok(signature_status);
    }

    for proof in parse_nsec3_proofs(input.nsec3_rrset, input.signer_name)? {
        if nsec3_matches_name(&proof.nsec3, &proof.owner_hash, input.query_name)?
            && !proof.nsec3.has_type(input.query_type)?
            && !proof.nsec3.has_type(RecordType::Cname)?
        {
            return Ok(DnssecStatus::Secure);
        }
    }

    Ok(DnssecStatus::Bogus)
}

pub fn validate_nsec3_name_error(
    input: Nsec3NameErrorValidationInput<'_>,
) -> Result<DnssecStatus, DnssecError> {
    let closest_proof =
        match validate_nsec3_closest_encloser_proof(Nsec3ClosestEncloserProofInput {
            signer_name: input.signer_name,
            dnskey_rrset: input.dnskey_rrset,
            query_name: input.query_name,
            closest_encloser: input.closest_encloser,
            closest_encloser_nsec3_rrset: input.closest_encloser_nsec3_rrset,
            closest_encloser_nsec3_rrsig_rrset: input.closest_encloser_nsec3_rrsig_rrset,
            next_closer_nsec3_rrset: input.next_closer_nsec3_rrset,
            next_closer_nsec3_rrsig_rrset: input.next_closer_nsec3_rrsig_rrset,
            now: input.now,
        })? {
            Nsec3ProofValidation::Valid(proof) => *proof,
            Nsec3ProofValidation::Status(status) => return Ok(status),
        };
    if closest_proof.next_closer.nsec3.is_opt_out() {
        return Ok(DnssecStatus::InsecureDelegation);
    }

    let wildcard_name = wildcard_child(input.closest_encloser)?;
    let wildcard_status = validate_nsec3_rrset_signature(
        input.signer_name,
        input.dnskey_rrset,
        input.wildcard_nsec3_rrset,
        input.wildcard_nsec3_rrsig_rrset,
        input.now,
    )?;
    if wildcard_status != DnssecStatus::Secure {
        return Ok(wildcard_status);
    }
    let wildcard_proofs = parse_nsec3_proofs(input.wildcard_nsec3_rrset, input.signer_name)?;
    let Some(wildcard_proof) = find_nsec3_covering_proof(
        &wildcard_proofs,
        &wildcard_name,
        Some(&closest_proof.closest.nsec3),
    )?
    else {
        return Ok(DnssecStatus::Bogus);
    };
    if wildcard_proof.nsec3.is_opt_out() {
        return Ok(DnssecStatus::InsecureDelegation);
    }

    Ok(DnssecStatus::Secure)
}

pub fn validate_nsec3_ds_no_data(
    input: Nsec3DsNoDataValidationInput<'_>,
) -> Result<DnssecStatus, DnssecError> {
    if !input.matching_nsec3_rrset.is_empty() {
        let matching_status = validate_nsec3_rrset_signature(
            input.signer_name,
            input.dnskey_rrset,
            input.matching_nsec3_rrset,
            input.matching_nsec3_rrsig_rrset,
            input.now,
        )?;
        if matching_status != DnssecStatus::Secure {
            return Ok(matching_status);
        }
        let proofs = parse_nsec3_proofs(input.matching_nsec3_rrset, input.signer_name)?;
        let Some(proof) = find_nsec3_matching_proof(&proofs, input.query_name, None)? else {
            return Ok(DnssecStatus::Bogus);
        };
        if !proof.nsec3.has_type(RecordType::Ds)? && !proof.nsec3.has_type(RecordType::Cname)? {
            return Ok(DnssecStatus::Secure);
        }
        return Ok(DnssecStatus::Bogus);
    }

    let closest_proof =
        match validate_nsec3_closest_encloser_proof(Nsec3ClosestEncloserProofInput {
            signer_name: input.signer_name,
            dnskey_rrset: input.dnskey_rrset,
            query_name: input.query_name,
            closest_encloser: input.closest_encloser,
            closest_encloser_nsec3_rrset: input.closest_encloser_nsec3_rrset,
            closest_encloser_nsec3_rrsig_rrset: input.closest_encloser_nsec3_rrsig_rrset,
            next_closer_nsec3_rrset: input.next_closer_nsec3_rrset,
            next_closer_nsec3_rrsig_rrset: input.next_closer_nsec3_rrsig_rrset,
            now: input.now,
        })? {
            Nsec3ProofValidation::Valid(proof) => *proof,
            Nsec3ProofValidation::Status(status) => return Ok(status),
        };

    if closest_proof.next_closer.nsec3.is_opt_out() {
        Ok(DnssecStatus::InsecureDelegation)
    } else {
        Ok(DnssecStatus::Bogus)
    }
}

pub fn validate_nsec3_wildcard_no_data(
    input: Nsec3WildcardNoDataValidationInput<'_>,
) -> Result<DnssecStatus, DnssecError> {
    let closest_proof =
        match validate_nsec3_closest_encloser_proof(Nsec3ClosestEncloserProofInput {
            signer_name: input.signer_name,
            dnskey_rrset: input.dnskey_rrset,
            query_name: input.query_name,
            closest_encloser: input.closest_encloser,
            closest_encloser_nsec3_rrset: input.closest_encloser_nsec3_rrset,
            closest_encloser_nsec3_rrsig_rrset: input.closest_encloser_nsec3_rrsig_rrset,
            next_closer_nsec3_rrset: input.next_closer_nsec3_rrset,
            next_closer_nsec3_rrsig_rrset: input.next_closer_nsec3_rrsig_rrset,
            now: input.now,
        })? {
            Nsec3ProofValidation::Valid(proof) => *proof,
            Nsec3ProofValidation::Status(status) => return Ok(status),
        };
    if closest_proof.next_closer.nsec3.is_opt_out() {
        return Ok(DnssecStatus::InsecureDelegation);
    }

    let wildcard_name = wildcard_child(input.closest_encloser)?;
    let wildcard_status = validate_nsec3_rrset_signature(
        input.signer_name,
        input.dnskey_rrset,
        input.wildcard_nsec3_rrset,
        input.wildcard_nsec3_rrsig_rrset,
        input.now,
    )?;
    if wildcard_status != DnssecStatus::Secure {
        return Ok(wildcard_status);
    }
    let wildcard_proofs = parse_nsec3_proofs(input.wildcard_nsec3_rrset, input.signer_name)?;
    let Some(wildcard_proof) = find_nsec3_matching_proof(
        &wildcard_proofs,
        &wildcard_name,
        Some(&closest_proof.closest.nsec3),
    )?
    else {
        return Ok(DnssecStatus::Bogus);
    };
    if !wildcard_proof.nsec3.has_type(input.query_type)?
        && !wildcard_proof.nsec3.has_type(RecordType::Cname)?
    {
        return Ok(DnssecStatus::Secure);
    }

    Ok(DnssecStatus::Bogus)
}

pub fn validate_nsec3_unsigned_referral(
    input: Nsec3UnsignedReferralValidationInput<'_>,
) -> Result<DnssecStatus, DnssecError> {
    if !input.matching_nsec3_rrset.is_empty() {
        let matching_status = validate_nsec3_rrset_signature(
            input.signer_name,
            input.dnskey_rrset,
            input.matching_nsec3_rrset,
            input.matching_nsec3_rrsig_rrset,
            input.now,
        )?;
        if matching_status != DnssecStatus::Secure {
            return Ok(matching_status);
        }
        let proofs = parse_nsec3_proofs(input.matching_nsec3_rrset, input.signer_name)?;
        let Some(proof) = find_nsec3_matching_proof(&proofs, input.delegation_name, None)? else {
            return Ok(DnssecStatus::Bogus);
        };
        if proof.nsec3.has_type(RecordType::Ns)?
            && !proof.nsec3.has_type(RecordType::Ds)?
            && !proof.nsec3.has_type(RecordType::Soa)?
        {
            return Ok(DnssecStatus::InsecureDelegation);
        }
        return Ok(DnssecStatus::Bogus);
    }

    let closest_proof =
        match validate_nsec3_closest_encloser_proof(Nsec3ClosestEncloserProofInput {
            signer_name: input.signer_name,
            dnskey_rrset: input.dnskey_rrset,
            query_name: input.delegation_name,
            closest_encloser: input.closest_encloser,
            closest_encloser_nsec3_rrset: input.closest_encloser_nsec3_rrset,
            closest_encloser_nsec3_rrsig_rrset: input.closest_encloser_nsec3_rrsig_rrset,
            next_closer_nsec3_rrset: input.next_closer_nsec3_rrset,
            next_closer_nsec3_rrsig_rrset: input.next_closer_nsec3_rrsig_rrset,
            now: input.now,
        })? {
            Nsec3ProofValidation::Valid(proof) => *proof,
            Nsec3ProofValidation::Status(status) => return Ok(status),
        };

    if closest_proof.next_closer.nsec3.is_opt_out() {
        Ok(DnssecStatus::InsecureDelegation)
    } else {
        Ok(DnssecStatus::Bogus)
    }
}

pub fn validate_nsec3_wildcard_answer(
    input: Nsec3WildcardAnswerValidationInput<'_>,
) -> Result<DnssecStatus, DnssecError> {
    if !is_strict_subdomain(input.query_name, input.closest_encloser) {
        return Ok(DnssecStatus::Bogus);
    }
    let next_closer = next_closer_name(input.query_name, input.closest_encloser)?;
    let next_status = validate_nsec3_rrset_signature(
        input.signer_name,
        input.dnskey_rrset,
        input.next_closer_nsec3_rrset,
        input.next_closer_nsec3_rrsig_rrset,
        input.now,
    )?;
    if next_status != DnssecStatus::Secure {
        return Ok(next_status);
    }
    let next_proofs = parse_nsec3_proofs(input.next_closer_nsec3_rrset, input.signer_name)?;
    let Some(next_proof) = find_nsec3_covering_proof(&next_proofs, &next_closer, None)? else {
        return Ok(DnssecStatus::Bogus);
    };
    if next_proof.nsec3.is_opt_out() {
        return Ok(DnssecStatus::InsecureDelegation);
    }

    Ok(DnssecStatus::Secure)
}

pub fn nsec3_hash(
    name: &DnsName,
    hash_algorithm: u8,
    iterations: u16,
    salt: &[u8],
) -> Result<Vec<u8>, DnssecError> {
    if hash_algorithm != NSEC3_HASH_SHA1 {
        return Err(DnssecError::UnsupportedDigest);
    }
    if iterations > NSEC3_MAX_ITERATIONS {
        return Err(DnssecError::InvalidNsec3);
    }

    let mut canonical_name = Vec::new();
    name.encode_wire(&mut canonical_name)
        .map_err(|_| DnssecError::NameEncoding)?;

    let mut digest_input = Vec::with_capacity(canonical_name.len() + salt.len());
    digest_input.extend(&canonical_name);
    digest_input.extend(salt);
    let mut hash = Sha1::digest(&digest_input).to_vec();

    for _ in 0..iterations {
        let mut iteration_input = Vec::with_capacity(hash.len() + salt.len());
        iteration_input.extend(&hash);
        iteration_input.extend(salt);
        hash = Sha1::digest(&iteration_input).to_vec();
    }

    Ok(hash)
}

pub fn signed_data(
    rrset: &[ResourceRecord],
    rrsig: &RrsigRecord,
    now: DnssecTime,
) -> Result<Vec<u8>, DnssecError> {
    if !rrsig.is_valid_at(now) {
        return Err(DnssecError::SignatureOutsideValidity);
    }

    let mut canonical_records = canonical_rrset(rrset, rrsig)?;
    canonical_records.sort_by(|left, right| left.rdata.cmp(&right.rdata));
    for window in canonical_records.windows(2) {
        if window[0].rdata == window[1].rdata {
            return Err(DnssecError::InvalidRrset);
        }
    }

    let mut out = rrsig.signed_rdata().to_vec();
    for record in canonical_records {
        out.extend(record.wire);
    }
    Ok(out)
}

pub fn verify_rrsig(
    rrset: &[ResourceRecord],
    rrsig: &RrsigRecord,
    dnskey: &DnskeyRecord,
    now: DnssecTime,
) -> Result<bool, DnssecError> {
    if dnskey.flags & DNSKEY_ZONE_FLAG == 0 {
        return Ok(false);
    }
    if rrsig.algorithm != dnskey.algorithm || rrsig.key_tag != dnskey.key_tag() {
        return Ok(false);
    }

    match rrsig.algorithm {
        DNSSEC_ALGORITHM_RSASHA1 | DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1 => {
            verify_rsa(rrset, rrsig, dnskey, now, RsaHash::Sha1)
        }
        DNSSEC_ALGORITHM_RSASHA256 => verify_rsa(rrset, rrsig, dnskey, now, RsaHash::Sha256),
        DNSSEC_ALGORITHM_RSASHA512 => verify_rsa(rrset, rrsig, dnskey, now, RsaHash::Sha512),
        DNSSEC_ALGORITHM_ECDSAP256SHA256 => verify_ecdsa_p256_sha256(rrset, rrsig, dnskey, now),
        DNSSEC_ALGORITHM_ECDSAP384SHA384 => verify_ecdsa_p384_sha384(rrset, rrsig, dnskey, now),
        DNSSEC_ALGORITHM_ED25519 => verify_ed25519(rrset, rrsig, dnskey, now),
        _ => Err(DnssecError::UnsupportedAlgorithm),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RsaHash {
    Sha1,
    Sha256,
    Sha512,
}

fn verify_rsa(
    rrset: &[ResourceRecord],
    rrsig: &RrsigRecord,
    dnskey: &DnskeyRecord,
    now: DnssecTime,
    hash: RsaHash,
) -> Result<bool, DnssecError> {
    let (exponent, modulus) = parse_rsa_public_key(&dnskey.public_key)?;
    let data = signed_data(rrset, rrsig, now)?;
    let algorithm = match hash {
        RsaHash::Sha1 => {
            return Ok(verify_rsa_sha1_pkcs1_v15(
                &exponent,
                &modulus,
                &data,
                &rrsig.signature,
            ));
        }
        RsaHash::Sha256 => &RSA_PKCS1_2048_8192_SHA256,
        RsaHash::Sha512 => &RSA_PKCS1_2048_8192_SHA512,
    };
    let public_key = RsaPublicKeyComponents {
        n: &modulus,
        e: &exponent,
    };

    Ok(public_key
        .verify(algorithm, &data, &rrsig.signature)
        .is_ok())
}

fn verify_rsa_sha1_pkcs1_v15(
    exponent: &[u8],
    modulus: &[u8],
    data: &[u8],
    signature: &[u8],
) -> bool {
    if exponent.is_empty() || modulus.is_empty() || signature.len() != modulus.len() {
        return false;
    }
    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from_bytes_be(exponent);
    let s = BigUint::from_bytes_be(signature);
    if n.is_zero() || e.is_zero() || s >= n {
        return false;
    }
    let recovered = s.modpow(&e, &n);
    let mut encoded = vec![0u8; modulus.len()];
    let recovered_bytes = recovered.to_bytes_be();
    if recovered_bytes.len() > encoded.len() {
        return false;
    }
    let offset = encoded.len() - recovered_bytes.len();
    encoded[offset..].copy_from_slice(&recovered_bytes);

    let expected_suffix = rsa_sha1_digest_info(data);
    if encoded.len() < 3 + RSA_PKCS1_V1_5_MIN_PADDING_LEN + expected_suffix.len()
        || encoded[0] != 0
        || encoded[1] != 1
    {
        return false;
    }
    let separator = encoded.len() - expected_suffix.len() - 1;
    separator >= 2 + RSA_PKCS1_V1_5_MIN_PADDING_LEN
        && encoded[2..separator].iter().all(|byte| *byte == 0xff)
        && encoded[separator] == 0
        && encoded[(separator + 1)..] == expected_suffix[..]
}

fn rsa_sha1_digest_info(data: &[u8]) -> Vec<u8> {
    let digest = Sha1::digest(data);
    let mut output = Vec::with_capacity(SHA1_DIGEST_INFO_PREFIX.len() + digest.len());
    output.extend_from_slice(&SHA1_DIGEST_INFO_PREFIX);
    output.extend_from_slice(&digest);
    output
}

fn parse_rsa_public_key(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DnssecError> {
    let (exponent_len, cursor) = match public_key.first().copied() {
        Some(0) => {
            if public_key.len() < 3 {
                return Err(DnssecError::InvalidDnskey);
            }
            (
                u16::from_be_bytes([public_key[1], public_key[2]]) as usize,
                3usize,
            )
        }
        Some(length) => (length as usize, 1usize),
        None => return Err(DnssecError::InvalidDnskey),
    };
    if exponent_len == 0 {
        return Err(DnssecError::InvalidDnskey);
    }
    let exponent_end = cursor
        .checked_add(exponent_len)
        .ok_or(DnssecError::InvalidDnskey)?;
    if exponent_end >= public_key.len() {
        return Err(DnssecError::InvalidDnskey);
    }

    Ok((
        public_key[cursor..exponent_end].to_vec(),
        public_key[exponent_end..].to_vec(),
    ))
}

fn verify_ecdsa_p256_sha256(
    rrset: &[ResourceRecord],
    rrsig: &RrsigRecord,
    dnskey: &DnskeyRecord,
    now: DnssecTime,
) -> Result<bool, DnssecError> {
    if dnskey.public_key.len() != 64 {
        return Err(DnssecError::InvalidDnskey);
    }
    if rrsig.signature.len() != 64 {
        return Err(DnssecError::InvalidSignature);
    }

    let mut sec1_public_key = Vec::with_capacity(65);
    sec1_public_key.push(0x04);
    sec1_public_key.extend(&dnskey.public_key);
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&sec1_public_key).map_err(|_| DnssecError::InvalidDnskey)?;
    let signature =
        Signature::from_slice(&rrsig.signature).map_err(|_| DnssecError::InvalidSignature)?;
    let data = signed_data(rrset, rrsig, now)?;

    Ok(verifying_key.verify(&data, &signature).is_ok())
}

fn verify_ecdsa_p384_sha384(
    rrset: &[ResourceRecord],
    rrsig: &RrsigRecord,
    dnskey: &DnskeyRecord,
    now: DnssecTime,
) -> Result<bool, DnssecError> {
    if dnskey.public_key.len() != 96 {
        return Err(DnssecError::InvalidDnskey);
    }
    if rrsig.signature.len() != 96 {
        return Err(DnssecError::InvalidSignature);
    }

    let mut sec1_public_key = Vec::with_capacity(97);
    sec1_public_key.push(0x04);
    sec1_public_key.extend(&dnskey.public_key);
    let data = signed_data(rrset, rrsig, now)?;
    let public_key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, sec1_public_key);

    Ok(public_key.verify(&data, &rrsig.signature).is_ok())
}

fn verify_ed25519(
    rrset: &[ResourceRecord],
    rrsig: &RrsigRecord,
    dnskey: &DnskeyRecord,
    now: DnssecTime,
) -> Result<bool, DnssecError> {
    if dnskey.public_key.len() != 32 {
        return Err(DnssecError::InvalidDnskey);
    }
    if rrsig.signature.len() != 64 {
        return Err(DnssecError::InvalidSignature);
    }

    let data = signed_data(rrset, rrsig, now)?;
    let public_key = UnparsedPublicKey::new(&ED25519, &dnskey.public_key);
    Ok(public_key.verify(&data, &rrsig.signature).is_ok())
}

fn canonical_rrset(
    rrset: &[ResourceRecord],
    rrsig: &RrsigRecord,
) -> Result<Vec<CanonicalRecord>, DnssecError> {
    let first = rrset.first().ok_or(DnssecError::InvalidRrset)?;
    if first.record_type != rrsig.type_covered {
        return Err(DnssecError::InvalidRrset);
    }
    let owner = canonical_owner(&first.name, rrsig.labels)?;
    let class = first.class;

    rrset
        .iter()
        .map(|record| {
            if record.record_type != first.record_type
                || record.class != class
                || canonical_owner(&record.name, rrsig.labels)? != owner
            {
                return Err(DnssecError::InvalidRrset);
            }

            let rdata = canonical_rdata(record)?;
            let mut wire = owner.clone();
            write_u16_be(&mut wire, record.record_type.code());
            write_u16_be(&mut wire, record.class);
            write_u32_be(&mut wire, rrsig.original_ttl);
            if rdata.len() > u16::MAX as usize {
                return Err(DnssecError::InvalidRrset);
            }
            write_u16_be(&mut wire, rdata.len() as u16);
            wire.extend(&rdata);

            Ok(CanonicalRecord { rdata, wire })
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalRecord {
    rdata: Vec<u8>,
    wire: Vec<u8>,
}

fn canonical_owner(owner: &DnsName, labels: u8) -> Result<Vec<u8>, DnssecError> {
    let owner_labels = owner.labels();
    let labels = labels as usize;
    if labels > owner_labels.len() {
        return Err(DnssecError::InvalidRrset);
    }

    let mut out = Vec::new();
    if labels < owner_labels.len() {
        encode_label(&mut out, "*")?;
        for label in &owner_labels[owner_labels.len() - labels..] {
            encode_label(&mut out, label)?;
        }
    } else {
        for label in owner_labels {
            encode_label(&mut out, label)?;
        }
    }
    out.push(0);
    Ok(out)
}

fn encode_label(out: &mut Vec<u8>, label: &str) -> Result<(), DnssecError> {
    if label.len() > 63 {
        return Err(DnssecError::NameEncoding);
    }
    out.push(label.len() as u8);
    out.extend(label.as_bytes().iter().map(u8::to_ascii_lowercase));
    Ok(())
}

fn canonical_rdata(record: &ResourceRecord) -> Result<Vec<u8>, DnssecError> {
    match record.record_type {
        RecordType::A
        | RecordType::Aaaa
        | RecordType::Ds
        | RecordType::Dnskey
        | RecordType::Tlsa
        | RecordType::Txt
        | RecordType::Unknown(_) => Ok(record.rdata.clone()),
        RecordType::Ns | RecordType::Cname => canonical_single_name_rdata(record),
        RecordType::Soa => canonical_soa_rdata(record),
        RecordType::Srv => canonical_srv_rdata(record),
        RecordType::Nsec => canonical_nsec_rdata(record),
        RecordType::Nsec3 => canonical_nsec3_rdata(record),
        RecordType::Svcb | RecordType::Https => canonical_svcb_rdata(record),
        _ => Err(DnssecError::UnsupportedCanonicalRdata),
    }
}

fn canonical_single_name_rdata(record: &ResourceRecord) -> Result<Vec<u8>, DnssecError> {
    let (name, end) =
        DnsName::parse_wire(&record.rdata, 0).map_err(|_| DnssecError::InvalidRrset)?;
    if end != record.rdata.len() {
        return Err(DnssecError::InvalidRrset);
    }
    encode_canonical_name(&name)
}

fn canonical_soa_rdata(record: &ResourceRecord) -> Result<Vec<u8>, DnssecError> {
    let (mname, cursor) =
        DnsName::parse_wire(&record.rdata, 0).map_err(|_| DnssecError::InvalidRrset)?;
    let (rname, cursor) =
        DnsName::parse_wire(&record.rdata, cursor).map_err(|_| DnssecError::InvalidRrset)?;
    let timers = record
        .rdata
        .get(cursor..cursor.checked_add(20).ok_or(DnssecError::InvalidRrset)?)
        .ok_or(DnssecError::InvalidRrset)?;
    if cursor + 20 != record.rdata.len() {
        return Err(DnssecError::InvalidRrset);
    }

    let mut out = encode_canonical_name(&mname)?;
    out.extend(encode_canonical_name(&rname)?);
    out.extend(timers);
    Ok(out)
}

fn canonical_srv_rdata(record: &ResourceRecord) -> Result<Vec<u8>, DnssecError> {
    let fixed = record.rdata.get(..6).ok_or(DnssecError::InvalidRrset)?;
    let (target, end) =
        DnsName::parse_wire(&record.rdata, 6).map_err(|_| DnssecError::InvalidRrset)?;
    if end != record.rdata.len() {
        return Err(DnssecError::InvalidRrset);
    }

    let mut out = fixed.to_vec();
    out.extend(encode_canonical_name(&target)?);
    Ok(out)
}

fn encode_canonical_name(name: &DnsName) -> Result<Vec<u8>, DnssecError> {
    let mut out = Vec::new();
    name.encode_wire(&mut out)
        .map_err(|_| DnssecError::NameEncoding)?;
    Ok(out)
}

fn canonical_svcb_rdata(record: &ResourceRecord) -> Result<Vec<u8>, DnssecError> {
    let svcb = SvcbRecord::from_record(record).map_err(|_| DnssecError::InvalidRrset)?;
    let mut out = Vec::new();
    write_u16_be(&mut out, svcb.svc_priority);
    svcb.target_name
        .encode_wire(&mut out)
        .map_err(|_| DnssecError::NameEncoding)?;
    for param in svcb.params {
        write_u16_be(&mut out, param.key);
        write_u16_be(&mut out, param.value.len() as u16);
        out.extend(param.value);
    }
    Ok(out)
}

fn canonical_nsec_rdata(record: &ResourceRecord) -> Result<Vec<u8>, DnssecError> {
    let nsec = NsecRecord::from_record(record)?;
    let mut out = Vec::new();
    nsec.next_domain_name
        .encode_wire(&mut out)
        .map_err(|_| DnssecError::NameEncoding)?;
    out.extend(&nsec.type_bit_maps);
    Ok(out)
}

fn canonical_nsec3_rdata(record: &ResourceRecord) -> Result<Vec<u8>, DnssecError> {
    Nsec3Record::from_record(record)?;
    Ok(record.rdata.clone())
}

fn validate_nsec3_rrset_signature(
    signer_name: &DnsName,
    dnskey_rrset: &[ResourceRecord],
    nsec3_rrset: &[ResourceRecord],
    nsec3_rrsig_rrset: &[ResourceRecord],
    now: DnssecTime,
) -> Result<DnssecStatus, DnssecError> {
    if nsec3_rrset.is_empty() {
        return Ok(DnssecStatus::Bogus);
    }
    validate_rrset_signature(
        signer_name,
        dnskey_rrset,
        nsec3_rrset,
        nsec3_rrsig_rrset,
        now,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Nsec3ProofRecord {
    nsec3: Nsec3Record,
    owner_hash: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Nsec3ClosestEncloserProof {
    closest: Nsec3ProofRecord,
    next_closer: Nsec3ProofRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Nsec3ProofValidation {
    Valid(Box<Nsec3ClosestEncloserProof>),
    Status(DnssecStatus),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Nsec3ClosestEncloserProofInput<'a> {
    signer_name: &'a DnsName,
    dnskey_rrset: &'a [ResourceRecord],
    query_name: &'a DnsName,
    closest_encloser: &'a DnsName,
    closest_encloser_nsec3_rrset: &'a [ResourceRecord],
    closest_encloser_nsec3_rrsig_rrset: &'a [ResourceRecord],
    next_closer_nsec3_rrset: &'a [ResourceRecord],
    next_closer_nsec3_rrsig_rrset: &'a [ResourceRecord],
    now: DnssecTime,
}

fn validate_nsec3_closest_encloser_proof(
    input: Nsec3ClosestEncloserProofInput<'_>,
) -> Result<Nsec3ProofValidation, DnssecError> {
    if !is_strict_subdomain(input.query_name, input.closest_encloser) {
        return Ok(Nsec3ProofValidation::Status(DnssecStatus::Bogus));
    }

    let closest_status = validate_nsec3_rrset_signature(
        input.signer_name,
        input.dnskey_rrset,
        input.closest_encloser_nsec3_rrset,
        input.closest_encloser_nsec3_rrsig_rrset,
        input.now,
    )?;
    if closest_status != DnssecStatus::Secure {
        return Ok(Nsec3ProofValidation::Status(closest_status));
    }
    let closest_proofs = parse_nsec3_proofs(input.closest_encloser_nsec3_rrset, input.signer_name)?;
    let Some(closest) = find_nsec3_matching_proof(&closest_proofs, input.closest_encloser, None)?
    else {
        return Ok(Nsec3ProofValidation::Status(DnssecStatus::Bogus));
    };
    if !closest_nsec3_is_authoritative(&closest.nsec3)? {
        return Ok(Nsec3ProofValidation::Status(DnssecStatus::Bogus));
    }

    let next_closer_candidate = next_closer_name(input.query_name, input.closest_encloser)?;
    let next_status = validate_nsec3_rrset_signature(
        input.signer_name,
        input.dnskey_rrset,
        input.next_closer_nsec3_rrset,
        input.next_closer_nsec3_rrsig_rrset,
        input.now,
    )?;
    if next_status != DnssecStatus::Secure {
        return Ok(Nsec3ProofValidation::Status(next_status));
    }
    let next_proofs = parse_nsec3_proofs(input.next_closer_nsec3_rrset, input.signer_name)?;
    let Some(next_closer) =
        find_nsec3_covering_proof(&next_proofs, &next_closer_candidate, Some(&closest.nsec3))?
    else {
        return Ok(Nsec3ProofValidation::Status(DnssecStatus::Bogus));
    };

    Ok(Nsec3ProofValidation::Valid(Box::new(
        Nsec3ClosestEncloserProof {
            closest,
            next_closer,
        },
    )))
}

fn parse_nsec3_proofs(
    nsec3_rrset: &[ResourceRecord],
    zone_name: &DnsName,
) -> Result<Vec<Nsec3ProofRecord>, DnssecError> {
    let mut proofs = Vec::new();
    for record in nsec3_rrset
        .iter()
        .filter(|record| record.record_type == RecordType::Nsec3)
    {
        let nsec3 = Nsec3Record::from_record(record)?;
        if !nsec3.is_usable() {
            continue;
        }
        let owner_hash = nsec3_owner_hash(&record.name, zone_name)?;
        if owner_hash.len() != nsec3.next_hashed_owner_name.len() {
            continue;
        }
        proofs.push(Nsec3ProofRecord { nsec3, owner_hash });
    }
    Ok(proofs)
}

fn find_nsec3_matching_proof(
    proofs: &[Nsec3ProofRecord],
    name: &DnsName,
    expected: Option<&Nsec3Record>,
) -> Result<Option<Nsec3ProofRecord>, DnssecError> {
    for proof in proofs {
        if expected.is_some_and(|expected| !same_nsec3_params(expected, &proof.nsec3)) {
            continue;
        }
        if nsec3_matches_name(&proof.nsec3, &proof.owner_hash, name)? {
            return Ok(Some(proof.clone()));
        }
    }
    Ok(None)
}

fn find_nsec3_covering_proof(
    proofs: &[Nsec3ProofRecord],
    name: &DnsName,
    expected: Option<&Nsec3Record>,
) -> Result<Option<Nsec3ProofRecord>, DnssecError> {
    for proof in proofs {
        if expected.is_some_and(|expected| !same_nsec3_params(expected, &proof.nsec3)) {
            continue;
        }
        if nsec3_covers_name(&proof.nsec3, &proof.owner_hash, name)? {
            return Ok(Some(proof.clone()));
        }
    }
    Ok(None)
}

fn nsec3_matches_name(
    nsec3: &Nsec3Record,
    owner_hash: &[u8],
    name: &DnsName,
) -> Result<bool, DnssecError> {
    if !nsec3.is_usable() {
        return Ok(false);
    }
    let hash = nsec3_hash(name, nsec3.hash_algorithm, nsec3.iterations, &nsec3.salt)?;
    Ok(owner_hash == hash.as_slice())
}

fn nsec3_covers_name(
    nsec3: &Nsec3Record,
    owner_hash: &[u8],
    name: &DnsName,
) -> Result<bool, DnssecError> {
    if !nsec3.is_usable() {
        return Ok(false);
    }
    let hash = nsec3_hash(name, nsec3.hash_algorithm, nsec3.iterations, &nsec3.salt)?;
    Ok(nsec3_covers_hash(
        owner_hash,
        &nsec3.next_hashed_owner_name,
        &hash,
    ))
}

fn nsec3_covers_hash(owner_hash: &[u8], next_hash: &[u8], query_hash: &[u8]) -> bool {
    if query_hash == owner_hash
        || owner_hash.len() != next_hash.len()
        || owner_hash.len() != query_hash.len()
    {
        return false;
    }

    match owner_hash.cmp(next_hash) {
        std::cmp::Ordering::Less => owner_hash < query_hash && query_hash < next_hash,
        std::cmp::Ordering::Greater => owner_hash < query_hash || query_hash < next_hash,
        std::cmp::Ordering::Equal => true,
    }
}

fn nsec3_owner_hash(owner: &DnsName, zone_name: &DnsName) -> Result<Vec<u8>, DnssecError> {
    let owner_labels = owner.labels();
    let zone_labels = zone_name.labels();
    if owner_labels.len() != zone_labels.len() + 1 || &owner_labels[1..] != zone_labels {
        return Err(DnssecError::InvalidNsec3);
    }
    decode_base32hex_nopad(&owner_labels[0]).map_err(|_| DnssecError::InvalidNsec3)
}

fn same_nsec3_params(left: &Nsec3Record, right: &Nsec3Record) -> bool {
    left.hash_algorithm == right.hash_algorithm
        && left.iterations == right.iterations
        && left.salt == right.salt
}

fn closest_nsec3_is_authoritative(nsec3: &Nsec3Record) -> Result<bool, DnssecError> {
    if nsec3.has_type(RecordType::Unknown(39))? {
        return Ok(false);
    }
    if nsec3.has_type(RecordType::Ns)? && !nsec3.has_type(RecordType::Soa)? {
        return Ok(false);
    }
    Ok(true)
}

fn next_closer_name(
    query_name: &DnsName,
    closest_encloser: &DnsName,
) -> Result<DnsName, DnssecError> {
    if !is_strict_subdomain(query_name, closest_encloser) {
        return Err(DnssecError::NameEncoding);
    }
    let query_labels = query_name.labels();
    let closest_len = closest_encloser.labels().len();
    let start = query_labels
        .len()
        .checked_sub(closest_len + 1)
        .ok_or(DnssecError::NameEncoding)?;
    DnsName::from_ascii(&query_labels[start..].join(".")).map_err(|_| DnssecError::NameEncoding)
}

#[cfg(test)]
fn encode_base32hex_nopad(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in input {
        buffer = (buffer << 8) | (*byte as u32);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

fn decode_base32hex_nopad(input: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in input.bytes() {
        let value = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'v' => byte - b'a' + 10,
            b'A'..=b'V' => byte - b'A' + 10,
            _ => return Err(()),
        };
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && buffer & ((1u32 << bits) - 1) != 0 {
        return Err(());
    }
    Ok(out)
}

fn validate_nsec_type_bit_maps(type_bit_maps: &[u8]) -> Result<(), DnssecError> {
    let mut cursor = 0usize;
    let mut previous_window = None;
    while cursor < type_bit_maps.len() {
        if cursor + 2 > type_bit_maps.len() {
            return Err(DnssecError::InvalidNsec);
        }
        let window = type_bit_maps[cursor];
        let length = type_bit_maps[cursor + 1] as usize;
        cursor += 2;
        if length == 0 || length > 32 || cursor + length > type_bit_maps.len() {
            return Err(DnssecError::InvalidNsec);
        }
        if previous_window.is_some_and(|previous| window <= previous) {
            return Err(DnssecError::InvalidNsec);
        }
        previous_window = Some(window);
        cursor += length;
    }
    Ok(())
}

fn nsec_type_bit_maps_contain(
    type_bit_maps: &[u8],
    record_type: RecordType,
) -> Result<bool, DnssecError> {
    validate_nsec_type_bit_maps(type_bit_maps)?;
    let code = record_type.code();
    let target_window = (code >> 8) as u8;
    let target_bit = (code & 0x00ff) as usize;
    let mut cursor = 0usize;
    while cursor < type_bit_maps.len() {
        let window = type_bit_maps[cursor];
        let length = type_bit_maps[cursor + 1] as usize;
        cursor += 2;
        if window == target_window {
            let byte_index = target_bit / 8;
            if byte_index >= length {
                return Ok(false);
            }
            let mask = 1u8 << (7 - (target_bit % 8));
            return Ok(type_bit_maps[cursor + byte_index] & mask != 0);
        }
        cursor += length;
    }
    Ok(false)
}

fn nsec_covers_name(owner: &DnsName, next: &DnsName, query_name: &DnsName) -> bool {
    if query_name == owner {
        return false;
    }

    match canonical_name_cmp(owner, next) {
        std::cmp::Ordering::Less => {
            canonical_name_cmp(owner, query_name).is_lt()
                && canonical_name_cmp(query_name, next).is_lt()
        }
        std::cmp::Ordering::Greater => {
            canonical_name_cmp(owner, query_name).is_lt()
                || canonical_name_cmp(query_name, next).is_lt()
        }
        std::cmp::Ordering::Equal => true,
    }
}

fn wildcard_child(closest_encloser: &DnsName) -> Result<DnsName, DnssecError> {
    let name = if closest_encloser.labels().is_empty() {
        "*".to_owned()
    } else {
        format!("*.{closest_encloser}")
    };
    DnsName::from_ascii(&name).map_err(|_| DnssecError::NameEncoding)
}

fn is_strict_subdomain(name: &DnsName, parent: &DnsName) -> bool {
    let name_labels = name.labels();
    let parent_labels = parent.labels();
    name_labels.len() > parent_labels.len() && name_labels.ends_with(parent_labels)
}

fn canonical_name_cmp(left: &DnsName, right: &DnsName) -> std::cmp::Ordering {
    let mut left_labels = left.labels().iter().rev();
    let mut right_labels = right.labels().iter().rev();

    loop {
        match (left_labels.next(), right_labels.next()) {
            (Some(left_label), Some(right_label)) => {
                let ordering = left_label.as_bytes().cmp(right_label.as_bytes());
                if !ordering.is_eq() {
                    return ordering;
                }
            }
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

fn write_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend(value.to_be_bytes());
}

fn write_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend(value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    #[test]
    fn parses_dnskey_and_computes_key_tag() {
        let rdata = vec![0x01, 0x00, DNSSEC_PROTOCOL, 0x08, 0xab, 0xcd];
        let dnskey = DnskeyRecord::parse_rdata(&rdata).unwrap();

        assert_eq!(dnskey.flags, 0x0100);
        assert_eq!(dnskey.protocol, DNSSEC_PROTOCOL);
        assert_eq!(dnskey.algorithm, 0x08);
        assert_eq!(dnskey.public_key, vec![0xab, 0xcd]);
        assert_eq!(dnskey.key_tag(), 0xafd5);
    }

    #[test]
    fn rejects_dnskey_with_wrong_protocol() {
        assert_eq!(
            DnskeyRecord::parse_rdata(&[0x01, 0x00, 0x02, 0x08]).unwrap_err(),
            DnssecError::InvalidDnskey,
        );
    }

    #[test]
    fn verifies_sha1_ds_digest_for_compatibility_validation() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey = DnskeyRecord::parse_rdata(&[0x01, 0x00, DNSSEC_PROTOCOL, 0x08, 0xaa]).unwrap();
        let digest = ds_digest(&owner, &dnskey, DS_DIGEST_SHA1).unwrap();
        let ds = DsRecord {
            key_tag: dnskey.key_tag(),
            algorithm: dnskey.algorithm,
            digest_type: DS_DIGEST_SHA1,
            digest,
        };

        assert_eq!(ds.digest.len(), 20);
        assert!(verify_ds_digest(&owner, &dnskey, &ds).unwrap());
    }

    #[test]
    fn verifies_sha256_ds_digest() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey = DnskeyRecord::parse_rdata(&[0x01, 0x00, DNSSEC_PROTOCOL, 0x08, 0xaa]).unwrap();
        let digest = ds_digest(&owner, &dnskey, DS_DIGEST_SHA256).unwrap();
        let ds = DsRecord {
            key_tag: dnskey.key_tag(),
            algorithm: dnskey.algorithm,
            digest_type: DS_DIGEST_SHA256,
            digest,
        };

        assert!(verify_ds_digest(&owner, &dnskey, &ds).unwrap());
    }

    #[test]
    fn verifies_sha384_ds_digest() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey = DnskeyRecord::parse_rdata(&[0x01, 0x00, DNSSEC_PROTOCOL, 0x08, 0xaa]).unwrap();
        let digest = ds_digest(&owner, &dnskey, DS_DIGEST_SHA384).unwrap();
        let ds = DsRecord {
            key_tag: dnskey.key_tag(),
            algorithm: dnskey.algorithm,
            digest_type: DS_DIGEST_SHA384,
            digest,
        };

        assert_eq!(ds.digest.len(), 48);
        assert!(verify_ds_digest(&owner, &dnskey, &ds).unwrap());
    }

    #[test]
    fn dnskey_without_zone_flag_does_not_match_ds() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey = DnskeyRecord::parse_rdata(&[0x00, 0x00, DNSSEC_PROTOCOL, 0x08, 0xaa]).unwrap();
        let ds = DsRecord {
            key_tag: dnskey.key_tag(),
            algorithm: dnskey.algorithm,
            digest_type: DS_DIGEST_SHA256,
            digest: ds_digest(&owner, &dnskey, DS_DIGEST_SHA256).unwrap(),
        };

        assert!(!verify_ds_digest(&owner, &dnskey, &ds).unwrap());
    }

    #[test]
    fn mismatched_ds_digest_is_bogus() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey = DnskeyRecord::parse_rdata(&[0x01, 0x00, DNSSEC_PROTOCOL, 0x08, 0xaa]).unwrap();
        let ds = DsRecord {
            key_tag: dnskey.key_tag(),
            algorithm: dnskey.algorithm,
            digest_type: DS_DIGEST_SHA256,
            digest: vec![0; 32],
        };

        assert!(!verify_ds_digest(&owner, &dnskey, &ds).unwrap());
    }

    #[test]
    fn unsupported_ds_digest_fails_closed() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey = DnskeyRecord::parse_rdata(&[0x01, 0x00, DNSSEC_PROTOCOL, 0x08, 0xaa]).unwrap();
        let ds = DsRecord {
            key_tag: dnskey.key_tag(),
            algorithm: dnskey.algorithm,
            digest_type: 255,
            digest: vec![0; 32],
        };

        assert_eq!(
            verify_ds_digest(&owner, &dnskey, &ds).unwrap_err(),
            DnssecError::UnsupportedDigest,
        );
    }

    #[test]
    fn validates_matching_delegation_link() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey_rdata = vec![0x01, 0x00, DNSSEC_PROTOCOL, 0x08, 0xaa];
        let dnskey = DnskeyRecord::parse_rdata(&dnskey_rdata).unwrap();
        let mut ds_rdata = Vec::new();
        ds_rdata.extend(dnskey.key_tag().to_be_bytes());
        ds_rdata.push(dnskey.algorithm);
        ds_rdata.push(DS_DIGEST_SHA256);
        ds_rdata.extend(ds_digest(&owner, &dnskey, DS_DIGEST_SHA256).unwrap());

        assert_eq!(
            validate_delegation_link(
                &owner,
                &[record(owner.clone(), RecordType::Ds, ds_rdata)],
                &[record(owner.clone(), RecordType::Dnskey, dnskey_rdata)],
            )
            .unwrap(),
            DnssecStatus::Secure,
        );
    }

    #[test]
    fn missing_ds_rrset_is_insecure_delegation() {
        let owner = DnsName::from_ascii("example").unwrap();

        assert_eq!(
            validate_delegation_link(&owner, &[], &[]).unwrap(),
            DnssecStatus::InsecureDelegation,
        );
    }

    #[test]
    fn validates_signed_rrset_with_secure_delegation() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner.clone(), RecordType::A, vec![1, 1, 1, 1])];
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            owner.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let dnskey_rrsig_rrset = vec![signed_rrsig_record(
            &owner,
            &dnskey_rrset,
            &dnskey,
            &signing_key,
        )];
        let ds_rrset = vec![ds_record(&owner, &dnskey)];
        let rrsig_rrset = vec![signed_rrsig_record(&owner, &rrset, &dnskey, &signing_key)];

        assert_eq!(
            validate_signed_rrset(SignedRrsetValidationInput {
                dnskey_owner: &owner,
                ds_rrset: &ds_rrset,
                dnskey_rrset: &dnskey_rrset,
                dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                rrset: &rrset,
                rrsig_rrset: &rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Secure,
        );
    }

    #[test]
    fn signed_rrset_without_ds_is_insecure_delegation() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner.clone(), RecordType::A, vec![1, 1, 1, 1])];
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            owner.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let dnskey_rrsig_rrset = vec![signed_rrsig_record(
            &owner,
            &dnskey_rrset,
            &dnskey,
            &signing_key,
        )];
        let rrsig_rrset = vec![signed_rrsig_record(&owner, &rrset, &dnskey, &signing_key)];

        assert_eq!(
            validate_signed_rrset(SignedRrsetValidationInput {
                dnskey_owner: &owner,
                ds_rrset: &[],
                dnskey_rrset: &dnskey_rrset,
                dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                rrset: &rrset,
                rrsig_rrset: &rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::InsecureDelegation,
        );
    }

    #[test]
    fn tampered_signed_rrset_is_bogus() {
        let owner = DnsName::from_ascii("example").unwrap();
        let signed_rrset = vec![record(owner.clone(), RecordType::A, vec![1, 1, 1, 1])];
        let tampered_rrset = vec![record(owner.clone(), RecordType::A, vec![2, 2, 2, 2])];
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            owner.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let dnskey_rrsig_rrset = vec![signed_rrsig_record(
            &owner,
            &dnskey_rrset,
            &dnskey,
            &signing_key,
        )];
        let ds_rrset = vec![ds_record(&owner, &dnskey)];
        let rrsig_rrset = vec![signed_rrsig_record(
            &owner,
            &signed_rrset,
            &dnskey,
            &signing_key,
        )];

        assert_eq!(
            validate_signed_rrset(SignedRrsetValidationInput {
                dnskey_owner: &owner,
                ds_rrset: &ds_rrset,
                dnskey_rrset: &dnskey_rrset,
                dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
                rrset: &tampered_rrset,
                rrsig_rrset: &rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Bogus,
        );
    }

    #[test]
    fn signed_rrset_without_dnskey_signature_is_bogus() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner.clone(), RecordType::A, vec![1, 1, 1, 1])];
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            owner.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let ds_rrset = vec![ds_record(&owner, &dnskey)];
        let rrsig_rrset = vec![signed_rrsig_record(&owner, &rrset, &dnskey, &signing_key)];

        assert_eq!(
            validate_signed_rrset(SignedRrsetValidationInput {
                dnskey_owner: &owner,
                ds_rrset: &ds_rrset,
                dnskey_rrset: &dnskey_rrset,
                dnskey_rrsig_rrset: &[],
                rrset: &rrset,
                rrsig_rrset: &rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Bogus,
        );
    }

    #[test]
    fn validates_dnssec_chain_across_child_delegation() {
        let parent = DnsName::from_ascii("example").unwrap();
        let child = DnsName::from_ascii("sub.example").unwrap();
        let target = DnsName::from_ascii("www.sub.example").unwrap();
        let (parent_dnskey, parent_signing_key) = ecdsa_dnskey();
        let (child_dnskey, child_signing_key) = ecdsa_dnskey();
        let parent_dnskey_rrset = vec![record(
            parent.clone(),
            RecordType::Dnskey,
            parent_dnskey.rdata().to_vec(),
        )];
        let parent_dnskey_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &parent,
            &parent,
            &parent_dnskey_rrset,
            &parent_dnskey,
            &parent_signing_key,
        )];
        let child_dnskey_rrset = vec![record(
            child.clone(),
            RecordType::Dnskey,
            child_dnskey.rdata().to_vec(),
        )];
        let child_dnskey_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &child,
            &child,
            &child_dnskey_rrset,
            &child_dnskey,
            &child_signing_key,
        )];
        let child_ds_rrset = vec![ds_record(&child, &child_dnskey)];
        let child_ds_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &child,
            &parent,
            &child_ds_rrset,
            &parent_dnskey,
            &parent_signing_key,
        )];
        let target_rrset = vec![record(target.clone(), RecordType::A, vec![127, 0, 0, 1])];
        let target_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &target,
            &child,
            &target_rrset,
            &child_dnskey,
            &child_signing_key,
        )];
        let delegation_links = [DnssecChainLink {
            child_dnskey_owner: &child,
            ds_rrset: &child_ds_rrset,
            ds_rrsig_rrset: &child_ds_rrsig_rrset,
            child_dnskey_rrset: &child_dnskey_rrset,
            child_dnskey_rrsig_rrset: &child_dnskey_rrsig_rrset,
        }];

        assert_eq!(
            validate_dnssec_chain(DnssecChainValidationInput {
                initial_dnskey_owner: &parent,
                initial_ds_rrset: &[ds_record(&parent, &parent_dnskey)],
                initial_dnskey_rrset: &parent_dnskey_rrset,
                initial_dnskey_rrsig_rrset: &parent_dnskey_rrsig_rrset,
                delegation_links: &delegation_links,
                target_rrset: &target_rrset,
                target_rrsig_rrset: &target_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Secure,
        );

        let unsigned_links = [DnssecChainLink {
            child_dnskey_owner: &child,
            ds_rrset: &child_ds_rrset,
            ds_rrsig_rrset: &[],
            child_dnskey_rrset: &child_dnskey_rrset,
            child_dnskey_rrsig_rrset: &child_dnskey_rrsig_rrset,
        }];

        assert_eq!(
            validate_dnssec_chain(DnssecChainValidationInput {
                initial_dnskey_owner: &parent,
                initial_ds_rrset: &[ds_record(&parent, &parent_dnskey)],
                initial_dnskey_rrset: &parent_dnskey_rrset,
                initial_dnskey_rrsig_rrset: &parent_dnskey_rrsig_rrset,
                delegation_links: &unsigned_links,
                target_rrset: &target_rrset,
                target_rrsig_rrset: &target_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Bogus,
        );
    }

    #[test]
    fn parses_rrsig_rdata() {
        let rdata = rrsig_rdata(RecordType::A, 2, 300, b"sig");
        let rrsig = RrsigRecord::parse_rdata(&rdata).unwrap();

        assert_eq!(rrsig.type_covered, RecordType::A);
        assert_eq!(rrsig.algorithm, 8);
        assert_eq!(rrsig.labels, 2);
        assert_eq!(rrsig.original_ttl, 300);
        assert_eq!(rrsig.signature_expiration, DnssecTime(2_000));
        assert_eq!(rrsig.signature_inception, DnssecTime(1_000));
        assert_eq!(rrsig.key_tag, 0x1234);
        assert_eq!(rrsig.signer_name, DnsName::from_ascii("example").unwrap());
        assert_eq!(rrsig.signature, b"sig");
    }

    #[test]
    fn parses_nsec_type_bit_maps() {
        let next = DnsName::from_ascii("z.example").unwrap();
        let record = nsec_record(
            DnsName::from_ascii("example").unwrap(),
            &next,
            &[RecordType::A, RecordType::Rrsig, RecordType::Nsec],
        );
        let nsec = NsecRecord::from_record(&record).unwrap();

        assert_eq!(nsec.next_domain_name, next);
        assert!(nsec.has_type(RecordType::A).unwrap());
        assert!(nsec.has_type(RecordType::Rrsig).unwrap());
        assert!(nsec.has_type(RecordType::Nsec).unwrap());
        assert!(!nsec.has_type(RecordType::Aaaa).unwrap());
    }

    #[test]
    fn malformed_nsec_type_bitmap_fails_closed() {
        let mut rdata = Vec::new();
        DnsName::from_ascii("z.example")
            .unwrap()
            .encode_wire(&mut rdata)
            .unwrap();
        rdata.extend([0, 33, 0]);

        assert_eq!(
            NsecRecord::parse_rdata(&rdata).unwrap_err(),
            DnssecError::InvalidNsec,
        );
    }

    #[test]
    fn parses_nsec3_rdata_and_hashes_rfc5155_vector() {
        let zone = DnsName::from_ascii("example").unwrap();
        let salt = hex_bytes("aabbccdd");
        let owner_hash = nsec3_hash(&zone, NSEC3_HASH_SHA1, 12, &salt).unwrap();
        let next_hash = decode_base32hex_nopad("2t7b4g4vsa5smi47k61mv5bv1a22bojr").unwrap();
        let record = nsec3_record(
            &owner_hash,
            &zone,
            NSEC3_OPT_OUT_FLAG,
            12,
            &salt,
            &next_hash,
            &[
                RecordType::Unknown(15),
                RecordType::Dnskey,
                RecordType::Ns,
                RecordType::Soa,
                RecordType::Unknown(51),
                RecordType::Rrsig,
            ],
        );
        let nsec3 = Nsec3Record::from_record(&record).unwrap();

        assert_eq!(
            encode_base32hex_nopad(&owner_hash),
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
        );
        assert_eq!(nsec3.hash_algorithm, NSEC3_HASH_SHA1);
        assert!(nsec3.is_opt_out());
        assert_eq!(nsec3.iterations, 12);
        assert_eq!(nsec3.salt, salt);
        assert_eq!(nsec3.next_hashed_owner_name, next_hash);
        assert!(nsec3.has_type(RecordType::Soa).unwrap());
        assert!(!nsec3.has_type(RecordType::Aaaa).unwrap());
    }

    #[test]
    fn validates_nsec3_no_data_when_type_absent() {
        let zone = DnsName::from_ascii("example").unwrap();
        let query = DnsName::from_ascii("www.example").unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let query_hash = nsec3_hash(&query, NSEC3_HASH_SHA1, 0, &[]).unwrap();
        let nsec3_rrset = vec![nsec3_record(
            &query_hash,
            &zone,
            0,
            0,
            &[],
            &hash_after(&query_hash),
            &[RecordType::A, RecordType::Rrsig, RecordType::Nsec3],
        )];
        let nsec3_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &nsec3_rrset[0].name,
            &zone,
            &nsec3_rrset,
            &dnskey,
            &signing_key,
        )];

        assert_eq!(
            validate_nsec3_no_data(Nsec3NoDataValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &query,
                query_type: RecordType::Aaaa,
                nsec3_rrset: &nsec3_rrset,
                nsec3_rrsig_rrset: &nsec3_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Secure,
        );
        assert_eq!(
            validate_nsec3_no_data(Nsec3NoDataValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &query,
                query_type: RecordType::A,
                nsec3_rrset: &nsec3_rrset,
                nsec3_rrsig_rrset: &nsec3_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Bogus,
        );
    }

    #[test]
    fn validates_nsec3_name_error_with_wildcard_denial() {
        let zone = DnsName::from_ascii("example").unwrap();
        let query = DnsName::from_ascii("missing.example").unwrap();
        let wildcard = wildcard_child(&zone).unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let closest_hash = nsec3_hash(&zone, NSEC3_HASH_SHA1, 0, &[]).unwrap();
        let closest_nsec3_rrset = vec![nsec3_record(
            &closest_hash,
            &zone,
            0,
            0,
            &[],
            &hash_after(&closest_hash),
            &[
                RecordType::Soa,
                RecordType::Ns,
                RecordType::Dnskey,
                RecordType::Rrsig,
                RecordType::Nsec3,
            ],
        )];
        let closest_nsec3_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &closest_nsec3_rrset[0].name,
            &zone,
            &closest_nsec3_rrset,
            &dnskey,
            &signing_key,
        )];
        let next_closer_nsec3_rrset = vec![covering_nsec3_record_for_name(
            &zone,
            &query,
            0,
            &[RecordType::Rrsig],
        )];
        let next_closer_nsec3_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &next_closer_nsec3_rrset[0].name,
            &zone,
            &next_closer_nsec3_rrset,
            &dnskey,
            &signing_key,
        )];
        let wildcard_nsec3_rrset = vec![covering_nsec3_record_for_name(
            &zone,
            &wildcard,
            0,
            &[RecordType::Rrsig],
        )];
        let wildcard_nsec3_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &wildcard_nsec3_rrset[0].name,
            &zone,
            &wildcard_nsec3_rrset,
            &dnskey,
            &signing_key,
        )];

        assert_eq!(
            validate_nsec3_name_error(Nsec3NameErrorValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &query,
                closest_encloser: &zone,
                closest_encloser_nsec3_rrset: &closest_nsec3_rrset,
                closest_encloser_nsec3_rrsig_rrset: &closest_nsec3_rrsig_rrset,
                next_closer_nsec3_rrset: &next_closer_nsec3_rrset,
                next_closer_nsec3_rrsig_rrset: &next_closer_nsec3_rrsig_rrset,
                wildcard_nsec3_rrset: &wildcard_nsec3_rrset,
                wildcard_nsec3_rrsig_rrset: &wildcard_nsec3_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Secure,
        );
    }

    #[test]
    fn nsec3_name_error_opt_out_is_insecure() {
        let zone = DnsName::from_ascii("example").unwrap();
        let query = DnsName::from_ascii("missing.example").unwrap();
        let wildcard = wildcard_child(&zone).unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let closest_hash = nsec3_hash(&zone, NSEC3_HASH_SHA1, 0, &[]).unwrap();
        let closest_nsec3_rrset = vec![nsec3_record(
            &closest_hash,
            &zone,
            0,
            0,
            &[],
            &hash_after(&closest_hash),
            &[RecordType::Soa, RecordType::Rrsig, RecordType::Nsec3],
        )];
        let closest_nsec3_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &closest_nsec3_rrset[0].name,
            &zone,
            &closest_nsec3_rrset,
            &dnskey,
            &signing_key,
        )];
        let next_closer_nsec3_rrset = vec![covering_nsec3_record_for_name(
            &zone,
            &query,
            NSEC3_OPT_OUT_FLAG,
            &[RecordType::Rrsig],
        )];
        let next_closer_nsec3_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &next_closer_nsec3_rrset[0].name,
            &zone,
            &next_closer_nsec3_rrset,
            &dnskey,
            &signing_key,
        )];
        let wildcard_nsec3_rrset = vec![covering_nsec3_record_for_name(
            &zone,
            &wildcard,
            0,
            &[RecordType::Rrsig],
        )];
        let wildcard_nsec3_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &wildcard_nsec3_rrset[0].name,
            &zone,
            &wildcard_nsec3_rrset,
            &dnskey,
            &signing_key,
        )];

        assert_eq!(
            validate_nsec3_name_error(Nsec3NameErrorValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &query,
                closest_encloser: &zone,
                closest_encloser_nsec3_rrset: &closest_nsec3_rrset,
                closest_encloser_nsec3_rrsig_rrset: &closest_nsec3_rrsig_rrset,
                next_closer_nsec3_rrset: &next_closer_nsec3_rrset,
                next_closer_nsec3_rrsig_rrset: &next_closer_nsec3_rrsig_rrset,
                wildcard_nsec3_rrset: &wildcard_nsec3_rrset,
                wildcard_nsec3_rrsig_rrset: &wildcard_nsec3_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::InsecureDelegation,
        );
    }

    #[test]
    fn validates_nsec_no_data_when_type_absent() {
        let zone = DnsName::from_ascii("example").unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let nsec_rrset = vec![nsec_record(
            zone.clone(),
            &DnsName::from_ascii("z.example").unwrap(),
            &[RecordType::A, RecordType::Rrsig, RecordType::Nsec],
        )];
        let nsec_rrsig_rrset = vec![signed_rrsig_record(
            &zone,
            &nsec_rrset,
            &dnskey,
            &signing_key,
        )];

        assert_eq!(
            validate_nsec_no_data(NsecNoDataValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &zone,
                query_type: RecordType::Aaaa,
                nsec_rrset: &nsec_rrset,
                nsec_rrsig_rrset: &nsec_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Secure,
        );
    }

    #[test]
    fn rejects_nsec_no_data_when_type_or_cname_exists() {
        let zone = DnsName::from_ascii("example").unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let nsec_rrset = vec![nsec_record(
            zone.clone(),
            &DnsName::from_ascii("z.example").unwrap(),
            &[
                RecordType::A,
                RecordType::Cname,
                RecordType::Rrsig,
                RecordType::Nsec,
            ],
        )];
        let nsec_rrsig_rrset = vec![signed_rrsig_record(
            &zone,
            &nsec_rrset,
            &dnskey,
            &signing_key,
        )];

        assert_eq!(
            validate_nsec_no_data(NsecNoDataValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &zone,
                query_type: RecordType::A,
                nsec_rrset: &nsec_rrset,
                nsec_rrsig_rrset: &nsec_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Bogus,
        );
        assert_eq!(
            validate_nsec_no_data(NsecNoDataValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &zone,
                query_type: RecordType::Aaaa,
                nsec_rrset: &nsec_rrset,
                nsec_rrsig_rrset: &nsec_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Bogus,
        );
    }

    #[test]
    fn validates_nsec_name_range_absence() {
        let zone = DnsName::from_ascii("example").unwrap();
        let owner = DnsName::from_ascii("a.example").unwrap();
        let query = DnsName::from_ascii("m.example").unwrap();
        let outside = DnsName::from_ascii("zz.example").unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let nsec_rrset = vec![nsec_record(
            owner.clone(),
            &DnsName::from_ascii("z.example").unwrap(),
            &[RecordType::Rrsig, RecordType::Nsec],
        )];
        let nsec_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &owner,
            &zone,
            &nsec_rrset,
            &dnskey,
            &signing_key,
        )];

        assert_eq!(
            validate_nsec_name_range(NsecNameRangeValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &query,
                nsec_rrset: &nsec_rrset,
                nsec_rrsig_rrset: &nsec_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Secure,
        );
        assert_eq!(
            validate_nsec_name_range(NsecNameRangeValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &outside,
                nsec_rrset: &nsec_rrset,
                nsec_rrsig_rrset: &nsec_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Bogus,
        );
    }

    #[test]
    fn validates_nsec_name_error_with_wildcard_denial() {
        let zone = DnsName::from_ascii("example").unwrap();
        let query = DnsName::from_ascii("beta.example").unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let covering_owner = DnsName::from_ascii("alpha.example").unwrap();
        let covering_nsec_rrset = vec![nsec_record(
            covering_owner.clone(),
            &DnsName::from_ascii("delta.example").unwrap(),
            &[RecordType::Rrsig, RecordType::Nsec],
        )];
        let covering_nsec_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &covering_owner,
            &zone,
            &covering_nsec_rrset,
            &dnskey,
            &signing_key,
        )];
        let wildcard_covering_owner = DnsName::from_ascii("z.example").unwrap();
        let wildcard_nsec_rrset = vec![nsec_record(
            wildcard_covering_owner.clone(),
            &DnsName::from_ascii("a.example").unwrap(),
            &[RecordType::Rrsig, RecordType::Nsec],
        )];
        let wildcard_nsec_rrsig_rrset = vec![signed_rrsig_record_for_signer(
            &wildcard_covering_owner,
            &zone,
            &wildcard_nsec_rrset,
            &dnskey,
            &signing_key,
        )];

        assert_eq!(
            validate_nsec_name_error(NsecNameErrorValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &query,
                closest_encloser: &zone,
                covering_nsec_rrset: &covering_nsec_rrset,
                covering_nsec_rrsig_rrset: &covering_nsec_rrsig_rrset,
                wildcard_nsec_rrset: &wildcard_nsec_rrset,
                wildcard_nsec_rrsig_rrset: &wildcard_nsec_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Secure,
        );

        assert_eq!(
            validate_nsec_name_error(NsecNameErrorValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &query,
                closest_encloser: &zone,
                covering_nsec_rrset: &covering_nsec_rrset,
                covering_nsec_rrsig_rrset: &covering_nsec_rrsig_rrset,
                wildcard_nsec_rrset: &[],
                wildcard_nsec_rrsig_rrset: &[],
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Bogus,
        );
    }

    #[test]
    fn validates_nsec_name_error_with_multi_owner_proof_set() {
        let zone = DnsName::from_ascii("denuoweb").unwrap();
        let query = DnsName::from_ascii("_8443._tcp.denuoweb").unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];

        let query_covering_owner = DnsName::from_ascii("_443._tcp.denuoweb").unwrap();
        let query_covering_rrset = vec![nsec_record(
            query_covering_owner.clone(),
            &DnsName::from_ascii("ns1.denuoweb").unwrap(),
            &[RecordType::Rrsig, RecordType::Nsec],
        )];
        let query_covering_rrsig = signed_rrsig_record_for_signer(
            &query_covering_owner,
            &zone,
            &query_covering_rrset,
            &dnskey,
            &signing_key,
        );

        let wildcard_covering_rrset = vec![nsec_record(
            zone.clone(),
            &query_covering_owner,
            &[RecordType::Rrsig, RecordType::Nsec],
        )];
        let wildcard_covering_rrsig = signed_rrsig_record_for_signer(
            &zone,
            &zone,
            &wildcard_covering_rrset,
            &dnskey,
            &signing_key,
        );

        let nsec_rrset = vec![
            query_covering_rrset[0].clone(),
            wildcard_covering_rrset[0].clone(),
        ];
        let nsec_rrsig_rrset = vec![query_covering_rrsig, wildcard_covering_rrsig];

        assert_eq!(
            validate_nsec_name_error(NsecNameErrorValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &query,
                closest_encloser: &zone,
                covering_nsec_rrset: &nsec_rrset,
                covering_nsec_rrsig_rrset: &nsec_rrsig_rrset,
                wildcard_nsec_rrset: &nsec_rrset,
                wildcard_nsec_rrsig_rrset: &nsec_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Secure,
        );
    }

    #[test]
    fn rejects_nsec_name_error_when_closest_encloser_is_not_parent() {
        let zone = DnsName::from_ascii("example").unwrap();
        let query = DnsName::from_ascii("beta.example").unwrap();
        let unrelated = DnsName::from_ascii("other").unwrap();

        assert_eq!(
            validate_nsec_name_error(NsecNameErrorValidationInput {
                signer_name: &zone,
                dnskey_rrset: &[],
                query_name: &query,
                closest_encloser: &unrelated,
                covering_nsec_rrset: &[],
                covering_nsec_rrsig_rrset: &[],
                wildcard_nsec_rrset: &[],
                wildcard_nsec_rrsig_rrset: &[],
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Bogus,
        );
    }

    #[test]
    fn validates_nsec3_ds_no_data_exact_and_opt_out() {
        let zone = DnsName::from_ascii("example").unwrap();
        let child = DnsName::from_ascii("child.example").unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let child_hash = nsec3_hash(&child, NSEC3_HASH_SHA1, 0, &[]).unwrap();
        let matching_nsec3_rrset = vec![nsec3_record(
            &child_hash,
            &zone,
            0,
            0,
            &[],
            &hash_after(&child_hash),
            &[RecordType::Ns, RecordType::Rrsig, RecordType::Nsec3],
        )];
        let matching_nsec3_rrsig_rrset =
            signed_nsec3_rrsig_rrset(&zone, &matching_nsec3_rrset, &dnskey, &signing_key);

        assert_eq!(
            validate_nsec3_ds_no_data(Nsec3DsNoDataValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &child,
                matching_nsec3_rrset: &matching_nsec3_rrset,
                matching_nsec3_rrsig_rrset: &matching_nsec3_rrsig_rrset,
                closest_encloser: &zone,
                closest_encloser_nsec3_rrset: &[],
                closest_encloser_nsec3_rrsig_rrset: &[],
                next_closer_nsec3_rrset: &[],
                next_closer_nsec3_rrsig_rrset: &[],
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Secure,
        );

        let closest_hash = nsec3_hash(&zone, NSEC3_HASH_SHA1, 0, &[]).unwrap();
        let closest_nsec3_rrset = vec![nsec3_record(
            &closest_hash,
            &zone,
            0,
            0,
            &[],
            &hash_after(&closest_hash),
            &[RecordType::Soa, RecordType::Rrsig, RecordType::Nsec3],
        )];
        let closest_nsec3_rrsig_rrset =
            signed_nsec3_rrsig_rrset(&zone, &closest_nsec3_rrset, &dnskey, &signing_key);
        let next_closer_nsec3_rrset = vec![covering_nsec3_record_for_name(
            &zone,
            &child,
            NSEC3_OPT_OUT_FLAG,
            &[RecordType::Rrsig],
        )];
        let next_closer_nsec3_rrsig_rrset =
            signed_nsec3_rrsig_rrset(&zone, &next_closer_nsec3_rrset, &dnskey, &signing_key);

        assert_eq!(
            validate_nsec3_ds_no_data(Nsec3DsNoDataValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &child,
                matching_nsec3_rrset: &[],
                matching_nsec3_rrsig_rrset: &[],
                closest_encloser: &zone,
                closest_encloser_nsec3_rrset: &closest_nsec3_rrset,
                closest_encloser_nsec3_rrsig_rrset: &closest_nsec3_rrsig_rrset,
                next_closer_nsec3_rrset: &next_closer_nsec3_rrset,
                next_closer_nsec3_rrsig_rrset: &next_closer_nsec3_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::InsecureDelegation,
        );
    }

    #[test]
    fn validates_nsec3_wildcard_no_data() {
        let zone = DnsName::from_ascii("example").unwrap();
        let query = DnsName::from_ascii("missing.example").unwrap();
        let wildcard = wildcard_child(&zone).unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let closest_hash = nsec3_hash(&zone, NSEC3_HASH_SHA1, 0, &[]).unwrap();
        let closest_nsec3_rrset = vec![nsec3_record(
            &closest_hash,
            &zone,
            0,
            0,
            &[],
            &hash_after(&closest_hash),
            &[RecordType::Soa, RecordType::Rrsig, RecordType::Nsec3],
        )];
        let closest_nsec3_rrsig_rrset =
            signed_nsec3_rrsig_rrset(&zone, &closest_nsec3_rrset, &dnskey, &signing_key);
        let next_closer_nsec3_rrset = vec![covering_nsec3_record_for_name(
            &zone,
            &query,
            0,
            &[RecordType::Rrsig],
        )];
        let next_closer_nsec3_rrsig_rrset =
            signed_nsec3_rrsig_rrset(&zone, &next_closer_nsec3_rrset, &dnskey, &signing_key);
        let wildcard_hash = nsec3_hash(&wildcard, NSEC3_HASH_SHA1, 0, &[]).unwrap();
        let wildcard_nsec3_rrset = vec![nsec3_record(
            &wildcard_hash,
            &zone,
            0,
            0,
            &[],
            &hash_after(&wildcard_hash),
            &[
                RecordType::Unknown(15),
                RecordType::Rrsig,
                RecordType::Nsec3,
            ],
        )];
        let wildcard_nsec3_rrsig_rrset =
            signed_nsec3_rrsig_rrset(&zone, &wildcard_nsec3_rrset, &dnskey, &signing_key);

        assert_eq!(
            validate_nsec3_wildcard_no_data(Nsec3WildcardNoDataValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &query,
                closest_encloser: &zone,
                query_type: RecordType::A,
                closest_encloser_nsec3_rrset: &closest_nsec3_rrset,
                closest_encloser_nsec3_rrsig_rrset: &closest_nsec3_rrsig_rrset,
                next_closer_nsec3_rrset: &next_closer_nsec3_rrset,
                next_closer_nsec3_rrsig_rrset: &next_closer_nsec3_rrsig_rrset,
                wildcard_nsec3_rrset: &wildcard_nsec3_rrset,
                wildcard_nsec3_rrsig_rrset: &wildcard_nsec3_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Secure,
        );
        assert_eq!(
            validate_nsec3_wildcard_no_data(Nsec3WildcardNoDataValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &query,
                closest_encloser: &zone,
                query_type: RecordType::Unknown(15),
                closest_encloser_nsec3_rrset: &closest_nsec3_rrset,
                closest_encloser_nsec3_rrsig_rrset: &closest_nsec3_rrsig_rrset,
                next_closer_nsec3_rrset: &next_closer_nsec3_rrset,
                next_closer_nsec3_rrsig_rrset: &next_closer_nsec3_rrsig_rrset,
                wildcard_nsec3_rrset: &wildcard_nsec3_rrset,
                wildcard_nsec3_rrsig_rrset: &wildcard_nsec3_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Bogus,
        );
    }

    #[test]
    fn validates_nsec3_unsigned_referral() {
        let zone = DnsName::from_ascii("example").unwrap();
        let child = DnsName::from_ascii("child.example").unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let child_hash = nsec3_hash(&child, NSEC3_HASH_SHA1, 0, &[]).unwrap();
        let matching_nsec3_rrset = vec![nsec3_record(
            &child_hash,
            &zone,
            0,
            0,
            &[],
            &hash_after(&child_hash),
            &[RecordType::Ns, RecordType::Rrsig, RecordType::Nsec3],
        )];
        let matching_nsec3_rrsig_rrset =
            signed_nsec3_rrsig_rrset(&zone, &matching_nsec3_rrset, &dnskey, &signing_key);

        assert_eq!(
            validate_nsec3_unsigned_referral(Nsec3UnsignedReferralValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                delegation_name: &child,
                matching_nsec3_rrset: &matching_nsec3_rrset,
                matching_nsec3_rrsig_rrset: &matching_nsec3_rrsig_rrset,
                closest_encloser: &zone,
                closest_encloser_nsec3_rrset: &[],
                closest_encloser_nsec3_rrsig_rrset: &[],
                next_closer_nsec3_rrset: &[],
                next_closer_nsec3_rrsig_rrset: &[],
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::InsecureDelegation,
        );
    }

    #[test]
    fn validates_nsec3_wildcard_answer_cover() {
        let zone = DnsName::from_ascii("example").unwrap();
        let query = DnsName::from_ascii("missing.example").unwrap();
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dnskey_rrset = vec![record(
            zone.clone(),
            RecordType::Dnskey,
            dnskey.rdata().to_vec(),
        )];
        let next_closer_nsec3_rrset = vec![covering_nsec3_record_for_name(
            &zone,
            &query,
            0,
            &[RecordType::Rrsig],
        )];
        let next_closer_nsec3_rrsig_rrset =
            signed_nsec3_rrsig_rrset(&zone, &next_closer_nsec3_rrset, &dnskey, &signing_key);

        assert_eq!(
            validate_nsec3_wildcard_answer(Nsec3WildcardAnswerValidationInput {
                signer_name: &zone,
                dnskey_rrset: &dnskey_rrset,
                query_name: &query,
                closest_encloser: &zone,
                next_closer_nsec3_rrset: &next_closer_nsec3_rrset,
                next_closer_nsec3_rrsig_rrset: &next_closer_nsec3_rrsig_rrset,
                now: DnssecTime(1_500),
            })
            .unwrap(),
            DnssecStatus::Secure,
        );
    }

    #[test]
    fn rejects_nsec3_iteration_count_above_rfc5155_limit() {
        let zone = DnsName::from_ascii("example").unwrap();

        assert_eq!(
            nsec3_hash(&zone, NSEC3_HASH_SHA1, NSEC3_MAX_ITERATIONS + 1, &[]).unwrap_err(),
            DnssecError::InvalidNsec3,
        );
    }

    #[test]
    fn builds_canonical_signed_data_sorted_by_rdata() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata(RecordType::A, 1, 60, b"sig")).unwrap();
        let rrset = vec![
            record(owner.clone(), RecordType::A, vec![2, 2, 2, 2]),
            record(owner.clone(), RecordType::A, vec![1, 1, 1, 1]),
        ];

        let data = signed_data(&rrset, &rrsig, DnssecTime(1_500)).unwrap();
        let mut expected = rrsig.signed_rdata().to_vec();
        expected.extend(canonical_a_rr(&owner, 60, [1, 1, 1, 1]));
        expected.extend(canonical_a_rr(&owner, 60, [2, 2, 2, 2]));

        assert_eq!(data, expected);
    }

    #[test]
    fn canonicalizes_wildcard_owner_from_rrsig_labels() {
        let expanded_owner = DnsName::from_ascii("www.example").unwrap();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata(RecordType::A, 1, 60, b"sig")).unwrap();
        let rrset = vec![record(expanded_owner, RecordType::A, vec![1, 1, 1, 1])];

        let data = signed_data(&rrset, &rrsig, DnssecTime(1_500)).unwrap();
        let mut expected = rrsig.signed_rdata().to_vec();
        let mut owner_wire = Vec::new();
        owner_wire.push(1);
        owner_wire.extend(b"*");
        owner_wire.push(7);
        owner_wire.extend(b"example");
        owner_wire.push(0);
        expected.extend(owner_wire);
        write_u16_be(&mut expected, RecordType::A.code());
        write_u16_be(&mut expected, 1);
        write_u32_be(&mut expected, 60);
        write_u16_be(&mut expected, 4);
        expected.extend([1, 1, 1, 1]);

        assert_eq!(data, expected);
    }

    #[test]
    fn canonicalizes_svcb_target_name_rdata() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrsig =
            RrsigRecord::parse_rdata(&rrsig_rdata(RecordType::Https, 1, 60, b"sig")).unwrap();
        let rrset = vec![record(
            owner.clone(),
            RecordType::Https,
            raw_https_rdata_with_target(b"SvC", b"Example"),
        )];

        let data = signed_data(&rrset, &rrsig, DnssecTime(1_500)).unwrap();
        let mut canonical_rdata = Vec::new();
        write_u16_be(&mut canonical_rdata, 1);
        DnsName::from_ascii("svc.example")
            .unwrap()
            .encode_wire(&mut canonical_rdata)
            .unwrap();
        write_u16_be(&mut canonical_rdata, 3);
        write_u16_be(&mut canonical_rdata, 2);
        write_u16_be(&mut canonical_rdata, 443);
        let mut expected = rrsig.signed_rdata().to_vec();
        owner.encode_wire(&mut expected).unwrap();
        write_u16_be(&mut expected, RecordType::Https.code());
        write_u16_be(&mut expected, 1);
        write_u32_be(&mut expected, 60);
        write_u16_be(&mut expected, canonical_rdata.len() as u16);
        expected.extend(canonical_rdata);

        assert_eq!(data, expected);
    }

    #[test]
    fn canonicalizes_cname_rdata_name() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrsig =
            RrsigRecord::parse_rdata(&rrsig_rdata(RecordType::Cname, 1, 60, b"sig")).unwrap();
        let rrset = vec![record(
            owner.clone(),
            RecordType::Cname,
            raw_name(&[b"Target", b"Example"]),
        )];

        let data = signed_data(&rrset, &rrsig, DnssecTime(1_500)).unwrap();
        let mut canonical_rdata = Vec::new();
        DnsName::from_ascii("target.example")
            .unwrap()
            .encode_wire(&mut canonical_rdata)
            .unwrap();
        let mut expected = rrsig.signed_rdata().to_vec();
        owner.encode_wire(&mut expected).unwrap();
        write_u16_be(&mut expected, RecordType::Cname.code());
        write_u16_be(&mut expected, 1);
        write_u32_be(&mut expected, 60);
        write_u16_be(&mut expected, canonical_rdata.len() as u16);
        expected.extend(canonical_rdata);

        assert_eq!(data, expected);
    }

    #[test]
    fn canonicalizes_soa_and_srv_rdata_names() {
        let owner = DnsName::from_ascii("example").unwrap();
        let soa_rrsig =
            RrsigRecord::parse_rdata(&rrsig_rdata(RecordType::Soa, 1, 60, b"sig")).unwrap();
        let mut soa_rdata = raw_name(&[b"Ns1", b"Example"]);
        soa_rdata.extend(raw_name(&[b"HostMaster", b"Example"]));
        for value in [1u32, 2, 3, 4, 5] {
            write_u32_be(&mut soa_rdata, value);
        }

        let soa_data = signed_data(
            &[record(owner.clone(), RecordType::Soa, soa_rdata)],
            &soa_rrsig,
            DnssecTime(1_500),
        )
        .unwrap();
        assert!(
            soa_data
                .windows(b"ns1\x07example".len())
                .any(|window| window == b"ns1\x07example")
        );
        assert!(
            soa_data
                .windows(b"hostmaster\x07example".len())
                .any(|window| window == b"hostmaster\x07example")
        );

        let srv_rrsig =
            RrsigRecord::parse_rdata(&rrsig_rdata(RecordType::Srv, 1, 60, b"sig")).unwrap();
        let mut srv_rdata = Vec::new();
        write_u16_be(&mut srv_rdata, 10);
        write_u16_be(&mut srv_rdata, 20);
        write_u16_be(&mut srv_rdata, 443);
        srv_rdata.extend(raw_name(&[b"SVC", b"Example"]));

        let srv_data = signed_data(
            &[record(owner, RecordType::Srv, srv_rdata)],
            &srv_rrsig,
            DnssecTime(1_500),
        )
        .unwrap();
        assert!(
            srv_data
                .windows(b"svc\x07example".len())
                .any(|window| window == b"svc\x07example")
        );
    }

    #[test]
    fn rrsig_signed_data_canonicalizes_signer_name() {
        let rdata =
            rrsig_rdata_for_raw_signer(RecordType::A, 1, 60, 8, 0x1234, &[b"ExAmPlE"], b"sig");
        let rrsig = RrsigRecord::parse_rdata(&rdata).unwrap();
        let mut expected = rdata[..18].to_vec();
        DnsName::from_ascii("example")
            .unwrap()
            .encode_wire(&mut expected)
            .unwrap();

        assert_eq!(rrsig.signed_rdata(), expected);
        assert_eq!(rrsig.signer_name, DnsName::from_ascii("example").unwrap());
    }

    #[test]
    fn malformed_svcb_rdata_fails_closed() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrsig =
            RrsigRecord::parse_rdata(&rrsig_rdata(RecordType::Https, 1, 60, b"sig")).unwrap();
        let mut rdata = raw_https_rdata_with_target(b"svc", b"example");
        rdata.extend([0, 3, 0, 2, 0x01, 0xbb]);

        assert_eq!(
            signed_data(
                &[record(owner, RecordType::Https, rdata)],
                &rrsig,
                DnssecTime(1_500),
            )
            .unwrap_err(),
            DnssecError::InvalidRrset,
        );
    }

    #[test]
    fn rejects_duplicate_canonical_rrs() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata(RecordType::A, 1, 60, b"sig")).unwrap();
        let rrset = vec![
            record(owner.clone(), RecordType::A, vec![1, 1, 1, 1]),
            record(owner, RecordType::A, vec![1, 1, 1, 1]),
        ];

        assert_eq!(
            signed_data(&rrset, &rrsig, DnssecTime(1_500)).unwrap_err(),
            DnssecError::InvalidRrset,
        );
    }

    #[test]
    fn unsupported_canonical_rdata_fails_closed() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrsig =
            RrsigRecord::parse_rdata(&rrsig_rdata(RecordType::Rrsig, 1, 60, b"sig")).unwrap();

        assert_eq!(
            signed_data(
                &[record(owner, RecordType::Rrsig, vec![0])],
                &rrsig,
                DnssecTime(1_500),
            )
            .unwrap_err(),
            DnssecError::UnsupportedCanonicalRdata,
        );
    }

    #[test]
    fn expired_rrsig_fails_closed() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata(RecordType::A, 1, 60, b"sig")).unwrap();

        assert_eq!(
            signed_data(
                &[record(owner, RecordType::A, vec![1, 1, 1, 1])],
                &rrsig,
                DnssecTime(2_001),
            )
            .unwrap_err(),
            DnssecError::SignatureOutsideValidity,
        );
    }

    #[test]
    fn verifies_ecdsa_p256_sha256_rrsig() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner, RecordType::A, vec![1, 1, 1, 1])];
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dummy_rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ECDSAP256SHA256,
            dnskey.key_tag(),
            &[0; 64],
        ))
        .unwrap();
        let data = signed_data(&rrset, &dummy_rrsig, DnssecTime(1_500)).unwrap();
        let signature: Signature = signing_key.sign(&data);
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ECDSAP256SHA256,
            dnskey.key_tag(),
            &signature.to_bytes(),
        ))
        .unwrap();

        assert!(verify_rrsig(&rrset, &rrsig, &dnskey, DnssecTime(1_500)).unwrap());
    }

    #[test]
    fn rejects_tampered_ecdsa_rrsig() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner, RecordType::A, vec![1, 1, 1, 1])];
        let (dnskey, signing_key) = ecdsa_dnskey();
        let dummy_rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ECDSAP256SHA256,
            dnskey.key_tag(),
            &[0; 64],
        ))
        .unwrap();
        let data = signed_data(&rrset, &dummy_rrsig, DnssecTime(1_500)).unwrap();
        let signature: Signature = signing_key.sign(&data);
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ECDSAP256SHA256,
            dnskey.key_tag(),
            &signature.to_bytes(),
        ))
        .unwrap();
        let tampered_rrset = vec![record(
            DnsName::from_ascii("example").unwrap(),
            RecordType::A,
            vec![2, 2, 2, 2],
        )];

        assert!(!verify_rrsig(&tampered_rrset, &rrsig, &dnskey, DnssecTime(1_500)).unwrap());
    }

    #[test]
    fn verifies_ecdsa_p384_sha384_rrsig() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner, RecordType::A, vec![1, 1, 1, 1])];
        let (dnskey, signing_key) = ecdsa_p384_dnskey();
        let rng = SystemRandom::new();
        let dummy_rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ECDSAP384SHA384,
            dnskey.key_tag(),
            &[0; 96],
        ))
        .unwrap();
        let data = signed_data(&rrset, &dummy_rrsig, DnssecTime(1_500)).unwrap();
        let signature = signing_key.sign(&rng, &data).unwrap();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ECDSAP384SHA384,
            dnskey.key_tag(),
            signature.as_ref(),
        ))
        .unwrap();

        assert!(verify_rrsig(&rrset, &rrsig, &dnskey, DnssecTime(1_500)).unwrap());
    }

    #[test]
    fn rejects_tampered_ecdsa_p384_rrsig() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner, RecordType::A, vec![1, 1, 1, 1])];
        let (dnskey, signing_key) = ecdsa_p384_dnskey();
        let rng = SystemRandom::new();
        let dummy_rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ECDSAP384SHA384,
            dnskey.key_tag(),
            &[0; 96],
        ))
        .unwrap();
        let data = signed_data(&rrset, &dummy_rrsig, DnssecTime(1_500)).unwrap();
        let signature = signing_key.sign(&rng, &data).unwrap();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ECDSAP384SHA384,
            dnskey.key_tag(),
            signature.as_ref(),
        ))
        .unwrap();
        let tampered_rrset = vec![record(
            DnsName::from_ascii("example").unwrap(),
            RecordType::A,
            vec![2, 2, 2, 2],
        )];

        assert!(!verify_rrsig(&tampered_rrset, &rrsig, &dnskey, DnssecTime(1_500)).unwrap());
    }

    #[test]
    fn verifies_rsa_sha256_rrsig() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner, RecordType::A, vec![1, 1, 1, 1])];
        let dnskey = rsa_dnskey();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_RSASHA256,
            dnskey.key_tag(),
            &rsa_signature(),
        ))
        .unwrap();

        assert_eq!(dnskey.key_tag(), 39043);
        assert!(verify_rrsig(&rrset, &rrsig, &dnskey, DnssecTime(1_500)).unwrap());
    }

    #[test]
    fn verifies_rsa_sha512_rrsig() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner, RecordType::A, vec![1, 1, 1, 1])];
        let dnskey = rsa_sha512_dnskey();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_RSASHA512,
            dnskey.key_tag(),
            &rsa_sha512_signature(),
        ))
        .unwrap();

        assert_eq!(dnskey.key_tag(), 39045);
        assert!(verify_rrsig(&rrset, &rrsig, &dnskey, DnssecTime(1_500)).unwrap());
    }

    #[test]
    fn verifies_rsa_sha1_rrsig_compatibility_algorithms() {
        for (algorithm, expected_key_tag, signature) in [
            (DNSSEC_ALGORITHM_RSASHA1, 1216, rsa_sha1_signature()),
            (
                DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1,
                1218,
                rsa_sha1_nsec3_signature(),
            ),
        ] {
            let owner = DnsName::from_ascii("example").unwrap();
            let rrset = vec![record(owner, RecordType::A, vec![1, 1, 1, 1])];
            let dnskey = rsa_sha1_dnskey(algorithm);
            let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
                RecordType::A,
                1,
                60,
                algorithm,
                dnskey.key_tag(),
                &signature,
            ))
            .unwrap();

            assert_eq!(dnskey.key_tag(), expected_key_tag);
            assert!(verify_rrsig(&rrset, &rrsig, &dnskey, DnssecTime(1_500)).unwrap());
        }
    }

    #[test]
    fn rejects_short_rsa_sha1_signature_encoding() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner, RecordType::A, vec![1, 1, 1, 1])];
        let dnskey = rsa_sha1_dnskey(DNSSEC_ALGORITHM_RSASHA1);
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_RSASHA1,
            dnskey.key_tag(),
            &rsa_sha1_signature(),
        ))
        .unwrap();
        let data = signed_data(&rrset, &rrsig, DnssecTime(1_500)).unwrap();
        let (exponent, modulus) = parse_rsa_public_key(&dnskey.public_key).unwrap();
        let signature = rsa_sha1_signature();

        assert_eq!(signature.len(), modulus.len());
        assert!(!verify_rsa_sha1_pkcs1_v15(
            &exponent,
            &modulus,
            &data,
            &signature[1..],
        ));
    }

    #[test]
    fn verifies_ed25519_rrsig() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner, RecordType::A, vec![1, 1, 1, 1])];
        let (dnskey, signing_key) = ed25519_dnskey();
        let dummy_rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ED25519,
            dnskey.key_tag(),
            &[0; 64],
        ))
        .unwrap();
        let data = signed_data(&rrset, &dummy_rrsig, DnssecTime(1_500)).unwrap();
        let signature = signing_key.sign(&data);
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ED25519,
            dnskey.key_tag(),
            signature.as_ref(),
        ))
        .unwrap();

        assert!(verify_rrsig(&rrset, &rrsig, &dnskey, DnssecTime(1_500)).unwrap());
    }

    #[test]
    fn rejects_tampered_ed25519_rrsig() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner, RecordType::A, vec![1, 1, 1, 1])];
        let (dnskey, signing_key) = ed25519_dnskey();
        let dummy_rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ED25519,
            dnskey.key_tag(),
            &[0; 64],
        ))
        .unwrap();
        let data = signed_data(&rrset, &dummy_rrsig, DnssecTime(1_500)).unwrap();
        let signature = signing_key.sign(&data);
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ED25519,
            dnskey.key_tag(),
            signature.as_ref(),
        ))
        .unwrap();
        let tampered_rrset = vec![record(
            DnsName::from_ascii("example").unwrap(),
            RecordType::A,
            vec![2, 2, 2, 2],
        )];

        assert!(!verify_rrsig(&tampered_rrset, &rrsig, &dnskey, DnssecTime(1_500)).unwrap());
    }

    #[test]
    fn rejects_tampered_rsa_sha256_rrsig() {
        let owner = DnsName::from_ascii("example").unwrap();
        let rrset = vec![record(owner, RecordType::A, vec![2, 2, 2, 2])];
        let dnskey = rsa_dnskey();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_RSASHA256,
            dnskey.key_tag(),
            &rsa_signature(),
        ))
        .unwrap();

        assert!(!verify_rrsig(&rrset, &rrsig, &dnskey, DnssecTime(1_500)).unwrap());
    }

    #[test]
    fn malformed_rsa_public_key_fails_closed() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey = DnskeyRecord::parse_rdata(&[
            0x01,
            0x00,
            DNSSEC_PROTOCOL,
            DNSSEC_ALGORITHM_RSASHA256,
            0,
        ])
        .unwrap();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_RSASHA256,
            dnskey.key_tag(),
            &[0; 256],
        ))
        .unwrap();

        assert_eq!(
            verify_rrsig(
                &[record(owner, RecordType::A, vec![1, 1, 1, 1])],
                &rrsig,
                &dnskey,
                DnssecTime(1_500),
            )
            .unwrap_err(),
            DnssecError::InvalidDnskey,
        );
    }

    #[test]
    fn unsupported_rrsig_algorithm_fails_closed() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey = DnskeyRecord::parse_rdata(&[0x01, 0x00, DNSSEC_PROTOCOL, 253, 0xaa]).unwrap();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            253,
            dnskey.key_tag(),
            b"sig",
        ))
        .unwrap();

        assert_eq!(
            verify_rrsig(
                &[record(owner, RecordType::A, vec![1, 1, 1, 1])],
                &rrsig,
                &dnskey,
                DnssecTime(1_500),
            )
            .unwrap_err(),
            DnssecError::UnsupportedAlgorithm,
        );
    }

    #[test]
    fn malformed_ecdsa_public_key_fails_closed() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey = DnskeyRecord::parse_rdata(&[
            0x01,
            0x00,
            DNSSEC_PROTOCOL,
            DNSSEC_ALGORITHM_ECDSAP256SHA256,
            0xaa,
        ])
        .unwrap();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ECDSAP256SHA256,
            dnskey.key_tag(),
            &[0; 64],
        ))
        .unwrap();

        assert_eq!(
            verify_rrsig(
                &[record(owner, RecordType::A, vec![1, 1, 1, 1])],
                &rrsig,
                &dnskey,
                DnssecTime(1_500),
            )
            .unwrap_err(),
            DnssecError::InvalidDnskey,
        );
    }

    #[test]
    fn malformed_ecdsa_p384_public_key_fails_closed() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey = DnskeyRecord::parse_rdata(&[
            0x01,
            0x00,
            DNSSEC_PROTOCOL,
            DNSSEC_ALGORITHM_ECDSAP384SHA384,
            0xaa,
        ])
        .unwrap();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ECDSAP384SHA384,
            dnskey.key_tag(),
            &[0; 96],
        ))
        .unwrap();

        assert_eq!(
            verify_rrsig(
                &[record(owner, RecordType::A, vec![1, 1, 1, 1])],
                &rrsig,
                &dnskey,
                DnssecTime(1_500),
            )
            .unwrap_err(),
            DnssecError::InvalidDnskey,
        );
    }

    #[test]
    fn malformed_ed25519_public_key_fails_closed() {
        let owner = DnsName::from_ascii("example").unwrap();
        let dnskey = DnskeyRecord::parse_rdata(&[
            0x01,
            0x00,
            DNSSEC_PROTOCOL,
            DNSSEC_ALGORITHM_ED25519,
            0xaa,
        ])
        .unwrap();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ED25519,
            dnskey.key_tag(),
            &[0; 64],
        ))
        .unwrap();

        assert_eq!(
            verify_rrsig(
                &[record(owner, RecordType::A, vec![1, 1, 1, 1])],
                &rrsig,
                &dnskey,
                DnssecTime(1_500),
            )
            .unwrap_err(),
            DnssecError::InvalidDnskey,
        );
    }

    #[test]
    fn malformed_ed25519_signature_fails_closed() {
        let owner = DnsName::from_ascii("example").unwrap();
        let (dnskey, _) = ed25519_dnskey();
        let rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_key(
            RecordType::A,
            1,
            60,
            DNSSEC_ALGORITHM_ED25519,
            dnskey.key_tag(),
            &[0; 63],
        ))
        .unwrap();

        assert_eq!(
            verify_rrsig(
                &[record(owner, RecordType::A, vec![1, 1, 1, 1])],
                &rrsig,
                &dnskey,
                DnssecTime(1_500),
            )
            .unwrap_err(),
            DnssecError::InvalidSignature,
        );
    }

    fn record(name: DnsName, record_type: RecordType, rdata: Vec<u8>) -> ResourceRecord {
        ResourceRecord {
            name,
            record_type,
            class: 1,
            ttl: 300,
            rdata,
        }
    }

    fn rrsig_rdata(
        type_covered: RecordType,
        labels: u8,
        original_ttl: u32,
        signature: &[u8],
    ) -> Vec<u8> {
        rrsig_rdata_for_key(type_covered, labels, original_ttl, 8, 0x1234, signature)
    }

    fn rrsig_rdata_for_key(
        type_covered: RecordType,
        labels: u8,
        original_ttl: u32,
        algorithm: u8,
        key_tag: u16,
        signature: &[u8],
    ) -> Vec<u8> {
        rrsig_rdata_for_signer(
            type_covered,
            labels,
            original_ttl,
            algorithm,
            key_tag,
            &DnsName::from_ascii("example").unwrap(),
            signature,
        )
    }

    fn rrsig_rdata_for_signer(
        type_covered: RecordType,
        labels: u8,
        original_ttl: u32,
        algorithm: u8,
        key_tag: u16,
        signer: &DnsName,
        signature: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        write_u16_be(&mut out, type_covered.code());
        out.push(algorithm);
        out.push(labels);
        write_u32_be(&mut out, original_ttl);
        write_u32_be(&mut out, 2_000);
        write_u32_be(&mut out, 1_000);
        write_u16_be(&mut out, key_tag);
        signer.encode_wire(&mut out).unwrap();
        out.extend(signature);
        out
    }

    fn rrsig_rdata_for_raw_signer(
        type_covered: RecordType,
        labels: u8,
        original_ttl: u32,
        algorithm: u8,
        key_tag: u16,
        signer_labels: &[&[u8]],
        signature: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        write_u16_be(&mut out, type_covered.code());
        out.push(algorithm);
        out.push(labels);
        write_u32_be(&mut out, original_ttl);
        write_u32_be(&mut out, 2_000);
        write_u32_be(&mut out, 1_000);
        write_u16_be(&mut out, key_tag);
        out.extend(raw_name(signer_labels));
        out.extend(signature);
        out
    }

    fn ecdsa_dnskey() -> (DnskeyRecord, SigningKey) {
        let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_encoded_point(false);
        let public_key = public_key.as_bytes();
        let mut dnskey = vec![
            0x01,
            0x00,
            DNSSEC_PROTOCOL,
            DNSSEC_ALGORITHM_ECDSAP256SHA256,
        ];
        dnskey.extend(&public_key[1..]);

        (DnskeyRecord::parse_rdata(&dnskey).unwrap(), signing_key)
    }

    fn ecdsa_p384_dnskey() -> (DnskeyRecord, EcdsaKeyPair) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        let signing_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public_key = signing_key.public_key().as_ref();
        assert_eq!(public_key.len(), 97);
        let mut dnskey = vec![
            0x01,
            0x00,
            DNSSEC_PROTOCOL,
            DNSSEC_ALGORITHM_ECDSAP384SHA384,
        ];
        dnskey.extend(&public_key[1..]);

        (DnskeyRecord::parse_rdata(&dnskey).unwrap(), signing_key)
    }

    fn rsa_dnskey() -> DnskeyRecord {
        DnskeyRecord::parse_rdata(&hex_bytes(concat!(
            "0100030803010001",
            "b0599a2fe41c2ee03679ab72d1662bd29b2f1ced7835cc823ff131cd53",
            "b7f7ab69a09b8e8be73db533456ec8a1d713a4244aceaa46a39d4f",
            "ed1400887f65b1ada4c9ad7d8b286dcf6f6749cf50db0f16bf65f",
            "5f752ff22f6f2f8416ab894cce51cbe7287799b67e9b976b8f31a",
            "83093934931b421bf2ed90354cb1418ed246c026a8ab23f69ffc22e",
            "469f15d275709149179cce8323b2a4ff5c07fb89dbc697620fa0997",
            "7d303369990c786648bddb3ac968d9fb47b11ae3f1cfcbb689474",
            "83332d8dcd43859fc7eebf7167dca6ff46505d3c9d7eec04430df",
            "3e7526661fd9262d20a645028f526f64d581f2737e5b0abeee78",
            "846e9f43bb99c885e39cf850bd",
        )))
        .unwrap()
    }

    fn rsa_sha512_dnskey() -> DnskeyRecord {
        let mut rdata = rsa_dnskey().rdata().to_vec();
        rdata[3] = DNSSEC_ALGORITHM_RSASHA512;
        DnskeyRecord::parse_rdata(&rdata).unwrap()
    }

    fn rsa_sha1_dnskey(algorithm: u8) -> DnskeyRecord {
        let mut rdata = hex_bytes(concat!(
            "01000305030100019fa9046633278fe01665b57f60de58b90d4d1b6eca",
            "6964018fae5be101da5a0c251ad3e0d457ef9559b024a3589e2502",
            "bde952eb1fb3e7d1e4f0d3ac2c785727910a23212dd96739c82a8",
            "c7591f6ae2998a5373b67b4860ec174ac058178f5d4022f9f8b",
            "5926f7bd8fce15f9f5a38c6840bcb57f1e9c7468cf9e3e7fd",
            "16fcb62ece87223711bc163d084801ac7b314d6c0fc3e8aee817",
            "f173c1f70a3abdb5c410020138d489d378f5ad37b7d7b246154",
            "9b57b3d36bf14c01ede2494390e090e30e6e0557a8ab974aaee3",
            "be4de89835745bd268aaa911bdfee6959e027b3c98e11d9c582822",
            "d7f8506ee8ff964e7f267e20412aaf7c3845129a3f4f5081a57f8d",
        ));
        rdata[3] = algorithm;
        DnskeyRecord::parse_rdata(&rdata).unwrap()
    }

    fn ed25519_dnskey() -> (DnskeyRecord, Ed25519KeyPair) {
        let signing_key = Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap();
        let mut dnskey = vec![0x01, 0x00, DNSSEC_PROTOCOL, DNSSEC_ALGORITHM_ED25519];
        dnskey.extend(signing_key.public_key().as_ref());

        (DnskeyRecord::parse_rdata(&dnskey).unwrap(), signing_key)
    }

    fn rsa_signature() -> Vec<u8> {
        hex_bytes(concat!(
            "913215496bdc2b9079e4af8fb91ee2bc43c4dda6e389e84b7be9d8209ee75700",
            "c101261140ca9f87665f8cf80d0a4bec2295e10d4062b120927fc8be63838b",
            "3c68f4b4d043ed1a0fd8c4cfafe8396356e92c4c3f6d5aef1719278ad",
            "5bf91c7a0855a7e3fe3f87cfe2d18e2e7e53853f0fe891c82b716af",
            "9439baa71758c8d1bff6958e495391f01b2225bfa833f0f8445805d20d",
            "bf9acd3cad00c3e59a7bbde4f08579985079b1b8f2dfb9630017d93",
            "cdc268d43601a12d34dec45f9b20cf2dca942ccf263199b2556cc99a",
            "0462570e04c8a405f02e4327925d15ea6a8468d1e89fe27b2408660",
            "552ce215cb8594f590be149df382176f6ce731cf0b1a0d2228",
        ))
    }

    fn rsa_sha512_signature() -> Vec<u8> {
        hex_bytes(concat!(
            "4ffc91a19f7b4fc3621e313c118b8cdfff5d3b8b26d898e4b342e9bae31",
            "aa164859977750b48d725df8b91af601bb51993a0f208266c1d006e949",
            "db3b6c7d0e95c68b24b2a7d08de43bb5e89602d5801caa7d3422d",
            "c0c9afa3ee301850af2f38ae471deea2d9f42184ee0150abb5190e",
            "0f1a4b456fb8a69ce366bbeab2687c2b62558682ff8b15fa61429d",
            "ea693728ecc00d96e8f0bb772cbb1b794c53ff3a3258cf67383ca1",
            "b7f12c1b6e33c0ff08aee413c9b6cc707952b750802d8dcbca",
            "4d0728699f1c81d657254baa1f8c0d61e9b958e85770e456b2c",
            "a4c5fe725158c5b4a5bcc425214fd0c22816d9d00d8921bf9a25a",
            "174be5f14033ac1bffd1f1965d",
        ))
    }

    fn rsa_sha1_signature() -> Vec<u8> {
        hex_bytes(concat!(
            "2926c6807d182c15d9baf15baf1cf75809fdc4179f875b7577346c58",
            "92c87cfb6bc1f44419b17f69fcc5f0116c958ae51e04d21a251701",
            "a04cb2785e731054eb827276fb3467d73c9e90f56f1175d23d3b1",
            "760ae276e910ab8e6846978355e73c221ab553ef33186bf644d8",
            "bea6464f8460ac1b33390b3e196d1299d3ac91ac6023dcc515",
            "d01350a34e093e27b60a674072b07bef52550b4e238f1c6f",
            "3b5c3c42976b03e6244965a3ffc908930bec2d6d5efd34fa6",
            "ca3140bed093780e0259a652354cdc93e28dfbfc8c25afa6fe",
            "8c766983a13426d2f0809503e442d4876f29a16a4312d91bf",
            "5cbb2385c5c1150125230aa0148fa055c30bffcb0eeb82c16c6",
        ))
    }

    fn rsa_sha1_nsec3_signature() -> Vec<u8> {
        hex_bytes(concat!(
            "7ee9369ee6ec2931cdc380cb807bc04bdceae1b74f7676ebe35183af",
            "968ad2d6d9fb085856d67c13a93f72513c02119d9e49ca2cf0",
            "f44fb13ec8c8f5e5e2a2cb83807af67d90908fb3dcdf22ae",
            "69b70c276173b155eb6510fb792fe2a1d9af2791019c7d4bc",
            "aa24d14706b5c5e356bed653b24c8616e7319ea7800295d43",
            "9a8d64f2848fc8a04966a3f4a56cf9667ee75d78589db3",
            "788e89a1f8852f0c9daf720e71e8e8f0dcfb056dbb4d08",
            "47c99e0618b13cc97215ee1dac8b2989196749886ea007d",
            "40ca38e70de1b01f0e9304095e154aef9b1e4ceab6c3b1",
            "5378cb7fcedb88138da921976747c13453692930df15a9aa54",
            "ae3f7534ed94ca39daa5b0ecc",
        ))
    }

    fn hex_bytes(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| {
                let hex = std::str::from_utf8(chunk).unwrap();
                u8::from_str_radix(hex, 16).unwrap()
            })
            .collect()
    }

    fn ds_record(owner: &DnsName, dnskey: &DnskeyRecord) -> ResourceRecord {
        let mut ds_rdata = Vec::new();
        ds_rdata.extend(dnskey.key_tag().to_be_bytes());
        ds_rdata.push(dnskey.algorithm);
        ds_rdata.push(DS_DIGEST_SHA256);
        ds_rdata.extend(ds_digest(owner, dnskey, DS_DIGEST_SHA256).unwrap());
        record(owner.clone(), RecordType::Ds, ds_rdata)
    }

    fn nsec_record(owner: DnsName, next: &DnsName, types: &[RecordType]) -> ResourceRecord {
        let mut rdata = Vec::new();
        next.encode_wire(&mut rdata).unwrap();
        rdata.extend(type_bit_maps(types));
        record(owner, RecordType::Nsec, rdata)
    }

    fn nsec3_record(
        owner_hash: &[u8],
        zone: &DnsName,
        flags: u8,
        iterations: u16,
        salt: &[u8],
        next_hash: &[u8],
        types: &[RecordType],
    ) -> ResourceRecord {
        assert!(salt.len() <= u8::MAX as usize);
        assert!(next_hash.len() <= u8::MAX as usize);
        let mut rdata = Vec::new();
        rdata.push(NSEC3_HASH_SHA1);
        rdata.push(flags);
        write_u16_be(&mut rdata, iterations);
        rdata.push(salt.len() as u8);
        rdata.extend(salt);
        rdata.push(next_hash.len() as u8);
        rdata.extend(next_hash);
        rdata.extend(type_bit_maps(types));
        record(nsec3_owner_name(owner_hash, zone), RecordType::Nsec3, rdata)
    }

    fn covering_nsec3_record_for_name(
        zone: &DnsName,
        name: &DnsName,
        flags: u8,
        types: &[RecordType],
    ) -> ResourceRecord {
        let target_hash = nsec3_hash(name, NSEC3_HASH_SHA1, 0, &[]).unwrap();
        nsec3_record(
            &hash_before(&target_hash),
            zone,
            flags,
            0,
            &[],
            &hash_after(&target_hash),
            types,
        )
    }

    fn nsec3_owner_name(hash: &[u8], zone: &DnsName) -> DnsName {
        let label = encode_base32hex_nopad(hash);
        if zone.labels().is_empty() {
            DnsName::from_ascii(&label).unwrap()
        } else {
            DnsName::from_ascii(&format!("{label}.{zone}")).unwrap()
        }
    }

    fn type_bit_maps(types: &[RecordType]) -> Vec<u8> {
        if types.is_empty() {
            return Vec::new();
        }
        let mut bitmap = [0u8; 32];
        let mut max_byte = 0usize;
        for record_type in types {
            let code = record_type.code();
            assert!(code < 256);
            let bit = code as usize;
            let byte_index = bit / 8;
            let mask = 1u8 << (7 - (bit % 8));
            bitmap[byte_index] |= mask;
            max_byte = max_byte.max(byte_index);
        }
        let mut out = Vec::new();
        out.push(0);
        out.push((max_byte + 1) as u8);
        out.extend(&bitmap[..=max_byte]);
        out
    }

    fn hash_before(hash: &[u8]) -> Vec<u8> {
        let mut out = hash.to_vec();
        for index in (0..out.len()).rev() {
            if out[index] > 0 {
                out[index] -= 1;
                for trailing in &mut out[index + 1..] {
                    *trailing = 0xff;
                }
                return out;
            }
        }
        vec![0xff; out.len()]
    }

    fn hash_after(hash: &[u8]) -> Vec<u8> {
        let mut out = hash.to_vec();
        for index in (0..out.len()).rev() {
            if out[index] < 0xff {
                out[index] += 1;
                for trailing in &mut out[index + 1..] {
                    *trailing = 0;
                }
                return out;
            }
        }
        vec![0; out.len()]
    }

    fn signed_nsec3_rrsig_rrset(
        signer: &DnsName,
        rrset: &[ResourceRecord],
        dnskey: &DnskeyRecord,
        signing_key: &SigningKey,
    ) -> Vec<ResourceRecord> {
        vec![signed_rrsig_record_for_signer(
            &rrset[0].name,
            signer,
            rrset,
            dnskey,
            signing_key,
        )]
    }

    fn signed_rrsig_record(
        owner: &DnsName,
        rrset: &[ResourceRecord],
        dnskey: &DnskeyRecord,
        signing_key: &SigningKey,
    ) -> ResourceRecord {
        signed_rrsig_record_for_signer(owner, owner, rrset, dnskey, signing_key)
    }

    fn signed_rrsig_record_for_signer(
        owner: &DnsName,
        signer: &DnsName,
        rrset: &[ResourceRecord],
        dnskey: &DnskeyRecord,
        signing_key: &SigningKey,
    ) -> ResourceRecord {
        let dummy_rrsig = RrsigRecord::parse_rdata(&rrsig_rdata_for_signer(
            rrset[0].record_type,
            owner.labels().len() as u8,
            60,
            DNSSEC_ALGORITHM_ECDSAP256SHA256,
            dnskey.key_tag(),
            signer,
            &[0; 64],
        ))
        .unwrap();
        let data = signed_data(rrset, &dummy_rrsig, DnssecTime(1_500)).unwrap();
        let signature: Signature = signing_key.sign(&data);
        let rdata = rrsig_rdata_for_signer(
            rrset[0].record_type,
            owner.labels().len() as u8,
            60,
            DNSSEC_ALGORITHM_ECDSAP256SHA256,
            dnskey.key_tag(),
            signer,
            &signature.to_bytes(),
        );
        record(owner.clone(), RecordType::Rrsig, rdata)
    }

    fn canonical_a_rr(owner: &DnsName, ttl: u32, address: [u8; 4]) -> Vec<u8> {
        let mut out = Vec::new();
        owner.encode_wire(&mut out).unwrap();
        write_u16_be(&mut out, RecordType::A.code());
        write_u16_be(&mut out, 1);
        write_u32_be(&mut out, ttl);
        write_u16_be(&mut out, 4);
        out.extend(address);
        out
    }

    fn raw_https_rdata_with_target(first_label: &[u8], second_label: &[u8]) -> Vec<u8> {
        let mut rdata = Vec::new();
        write_u16_be(&mut rdata, 1);
        rdata.extend(raw_name(&[first_label, second_label]));
        write_u16_be(&mut rdata, 3);
        write_u16_be(&mut rdata, 2);
        write_u16_be(&mut rdata, 443);
        rdata
    }

    fn raw_name(labels: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend(*label);
        }
        out.push(0);
        out
    }
}
