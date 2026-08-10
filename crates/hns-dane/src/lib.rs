//! Local, fail-closed TLSA matching for HNS HTTPS certificates.
//!
//! This crate supports DANE-EE (usage 3), full-certificate and
//! `SubjectPublicKeyInfo` selectors, and exact/SHA-256/SHA-512 matching. It
//! does not contain a WebPKI or network fallback.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "protocol acronyms and the shared DaneError enum are documented at crate level"
)]

use std::fmt;

use hns_dns_wire::Tlsa;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509CheckFlags, X509VerifyFlags, X509VerifyParam};
use openssl::x509::{X509, X509StoreContext};
use sha2::{Digest, Sha256, Sha512};

/// Default maximum DER certificate size.
pub const DEFAULT_MAX_CERTIFICATE_LEN: usize = 256 * 1024;
/// Default maximum DER `SubjectPublicKeyInfo` size.
pub const DEFAULT_MAX_SPKI_LEN: usize = 64 * 1024;
/// Maximum TLSA association bytes representable by DNS RDATA after its prefix.
pub const MAX_TLSA_ASSOCIATION_LEN: usize = 65_532;

/// Bounded DANE verification inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaneLimits {
    /// Maximum leaf certificate DER bytes.
    pub max_certificate_len: usize,
    /// Maximum extracted SPKI DER bytes.
    pub max_spki_len: usize,
    /// Maximum number of alternative TLSA records.
    pub max_tlsa_records: usize,
    /// Maximum association bytes in one TLSA record.
    pub max_association_len: usize,
    /// Maximum certificates accepted from one TLS server.
    pub max_chain_certificates: usize,
}

impl Default for DaneLimits {
    fn default() -> Self {
        Self {
            max_certificate_len: DEFAULT_MAX_CERTIFICATE_LEN,
            max_spki_len: DEFAULT_MAX_SPKI_LEN,
            max_tlsa_records: 64,
            max_association_len: MAX_TLSA_ASSOCIATION_LEN,
            max_chain_certificates: 16,
        }
    }
}

/// Supported TLSA certificate usage.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateUsage {
    /// DANE trust anchor: a locally DNSSEC-authenticated record anchors a
    /// complete private PKIX path without consulting WebPKI.
    DaneTa = 2,
    /// DANE end entity: the locally DNSSEC-authenticated record pins the leaf.
    DaneEe = 3,
}

/// Supported TLSA selector.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selector {
    /// Entire leaf certificate DER.
    FullCertificate = 0,
    /// Entire DER `SubjectPublicKeyInfo` from the leaf certificate.
    SubjectPublicKeyInfo = 1,
}

/// Supported TLSA matching type.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchingType {
    /// Exact selected bytes.
    Exact = 0,
    /// SHA-256 of selected bytes.
    Sha256 = 1,
    /// SHA-512 of selected bytes.
    Sha512 = 2,
}

/// Successful local match details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaneMatch {
    record_index: usize,
    usage: CertificateUsage,
    selector: Selector,
    matching_type: MatchingType,
}

impl DaneMatch {
    /// Index into the caller's TLSA RRset.
    #[must_use]
    pub const fn record_index(self) -> usize {
        self.record_index
    }

    /// Matched certificate usage.
    #[must_use]
    pub const fn usage(self) -> CertificateUsage {
        self.usage
    }

    /// Matched selector.
    #[must_use]
    pub const fn selector(self) -> Selector {
        self.selector
    }

    /// Matched association algorithm.
    #[must_use]
    pub const fn matching_type(self) -> MatchingType {
        self.matching_type
    }
}

/// Local TLSA/DANE validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DaneError {
    /// No TLSA records were supplied.
    MissingTlsa,
    /// The RRset exceeds its configured record count.
    TooManyTlsaRecords,
    /// The leaf certificate is empty or exceeds its configured bound.
    CertificateLength,
    /// The certificate is not strict bounded DER with the expected X.509 shape.
    MalformedCertificate,
    /// The extracted SPKI exceeds its configured bound.
    SpkiLength,
    /// A TLSA usage is unsupported without another trust model.
    UnsupportedUsage(u8),
    /// A TLSA selector is unsupported.
    UnsupportedSelector(u8),
    /// A TLSA matching algorithm is unsupported.
    UnsupportedMatchingType(u8),
    /// Association data is empty, oversized, or has the wrong digest length.
    InvalidAssociationLength,
    /// Every record was valid but none matched the presented certificate.
    Mismatch,
    /// The supplied server certificate chain is empty or exceeds its bound.
    ChainLength,
    /// DANE-TA path, validity-time, or server-name validation failed.
    ChainValidation,
    /// The TLSA base domain is empty, contains NUL, or cannot be checked.
    InvalidServerName,
}

impl fmt::Display for DaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTlsa => formatter.write_str("TLSA RRset is empty"),
            Self::TooManyTlsaRecords => formatter.write_str("TLSA RRset exceeds configured limit"),
            Self::CertificateLength => {
                formatter.write_str("certificate DER is empty or exceeds configured limit")
            }
            Self::MalformedCertificate => formatter.write_str("certificate DER is malformed"),
            Self::SpkiLength => formatter.write_str("SPKI DER exceeds configured limit"),
            Self::UnsupportedUsage(value) => write!(formatter, "unsupported TLSA usage {value}"),
            Self::UnsupportedSelector(value) => {
                write!(formatter, "unsupported TLSA selector {value}")
            }
            Self::UnsupportedMatchingType(value) => {
                write!(formatter, "unsupported TLSA matching type {value}")
            }
            Self::InvalidAssociationLength => {
                formatter.write_str("invalid TLSA association-data length")
            }
            Self::Mismatch => formatter.write_str("TLSA records do not match certificate"),
            Self::ChainLength => formatter.write_str("certificate chain exceeds configured bounds"),
            Self::ChainValidation => {
                formatter.write_str("DANE-TA certificate path validation failed")
            }
            Self::InvalidServerName => formatter.write_str("invalid DANE TLSA base domain"),
        }
    }
}

impl std::error::Error for DaneError {}

/// Verify a leaf certificate against a strict DNSSEC-authenticated DANE-EE RRset.
///
/// All records are validated before matching. PKIX usages 0/1 are rejected
/// because this engine has no WebPKI trust path. DANE-TA usage 2 is rejected
/// until a local certificate-chain signature validator exists.
pub fn verify_dane_ee(
    certificate_der: &[u8],
    records: &[Tlsa],
    limits: DaneLimits,
) -> Result<DaneMatch, DaneError> {
    if certificate_der.is_empty() || certificate_der.len() > limits.max_certificate_len {
        return Err(DaneError::CertificateLength);
    }
    if records.is_empty() {
        return Err(DaneError::MissingTlsa);
    }
    if records.len() > limits.max_tlsa_records {
        return Err(DaneError::TooManyTlsaRecords);
    }

    let parsed_records = records
        .iter()
        .map(|record| parse_record(record, limits))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(record) = parsed_records
        .iter()
        .find(|record| record.usage != CertificateUsage::DaneEe)
    {
        return Err(DaneError::UnsupportedUsage(record.usage as u8));
    }
    let spki = extract_subject_public_key_info(certificate_der)?;
    if spki.len() > limits.max_spki_len {
        return Err(DaneError::SpkiLength);
    }

    let material = MatchMaterial::new(certificate_der, spki);
    for (record_index, record) in parsed_records.iter().enumerate() {
        if material.matches(*record) {
            return Ok(DaneMatch {
                record_index,
                usage: record.usage,
                selector: record.selector,
                matching_type: record.matching_type,
            });
        }
    }
    Err(DaneError::Mismatch)
}

/// Verify a TLS server certificate chain against DANE-EE or DANE-TA records.
///
/// DANE-EE matches only the leaf and, per RFC 7671, deliberately ignores
/// certificate names, validity dates, and public trust stores. DANE-TA builds
/// a private path rooted only in the matching TLSA trust anchor, validates at
/// `validation_unix_time`, and requires the TLSA base domain in the leaf.
/// WebPKI roots are never loaded.
pub fn verify_dane_chain(
    certificate_chain_der: &[&[u8]],
    tlsa_base_domain: &str,
    records: &[Tlsa],
    validation_unix_time: i64,
    limits: DaneLimits,
) -> Result<DaneMatch, DaneError> {
    validate_chain_inputs(certificate_chain_der, tlsa_base_domain, records, limits)?;

    let parsed_records = records
        .iter()
        .map(|record| parse_record(record, limits))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = certificate_chain_der
        .first()
        .copied()
        .ok_or(DaneError::ChainLength)?;
    let leaf_spki = extract_subject_public_key_info(leaf)?;
    if leaf_spki.len() > limits.max_spki_len {
        return Err(DaneError::SpkiLength);
    }
    let leaf_material = MatchMaterial::new(leaf, leaf_spki);
    for (record_index, record) in parsed_records.iter().copied().enumerate() {
        if record.usage == CertificateUsage::DaneEe && leaf_material.matches(record) {
            return Ok(DaneMatch {
                record_index,
                usage: record.usage,
                selector: record.selector,
                matching_type: record.matching_type,
            });
        }
    }

    let parsed_chain = certificate_chain_der
        .iter()
        .map(|certificate| X509::from_der(certificate).map_err(|_| DaneError::MalformedCertificate))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf_certificate = parsed_chain.first().ok_or(DaneError::ChainLength)?;
    let mut saw_ta_match = false;
    for (record_index, record) in parsed_records.iter().copied().enumerate() {
        if record.usage != CertificateUsage::DaneTa {
            continue;
        }
        let anchor_der = if record.selector == Selector::FullCertificate
            && record.matching_type == MatchingType::Exact
        {
            if !constant_time_eq(record.association_data, leaf)
                && certificate_chain_der
                    .iter()
                    .all(|certificate| !constant_time_eq(record.association_data, certificate))
            {
                // RFC 7671 permits a full-certificate DANE-TA association to
                // carry the trust anchor even when the server omits it.
                record.association_data
            } else {
                certificate_chain_der
                    .iter()
                    .copied()
                    .find(|certificate| constant_time_eq(record.association_data, certificate))
                    .ok_or(DaneError::Mismatch)?
            }
        } else {
            let mut matched = None;
            for certificate in certificate_chain_der {
                let spki = extract_subject_public_key_info(certificate)?;
                if spki.len() > limits.max_spki_len {
                    return Err(DaneError::SpkiLength);
                }
                if MatchMaterial::new(certificate, spki).matches(record) {
                    matched = Some(*certificate);
                    break;
                }
            }
            let Some(matched) = matched else {
                continue;
            };
            matched
        };
        let anchor = X509::from_der(anchor_der).map_err(|_| DaneError::MalformedCertificate)?;
        saw_ta_match = true;
        if validate_private_chain(
            leaf_certificate,
            &parsed_chain,
            &anchor,
            anchor_der,
            tlsa_base_domain,
            validation_unix_time,
            limits,
        ) {
            return Ok(DaneMatch {
                record_index,
                usage: record.usage,
                selector: record.selector,
                matching_type: record.matching_type,
            });
        }
    }
    if saw_ta_match {
        Err(DaneError::ChainValidation)
    } else {
        Err(DaneError::Mismatch)
    }
}

fn validate_chain_inputs(
    certificate_chain_der: &[&[u8]],
    tlsa_base_domain: &str,
    records: &[Tlsa],
    limits: DaneLimits,
) -> Result<(), DaneError> {
    if certificate_chain_der.is_empty()
        || certificate_chain_der.len() > limits.max_chain_certificates
    {
        return Err(DaneError::ChainLength);
    }
    if tlsa_base_domain.is_empty()
        || tlsa_base_domain.len() > 253
        || tlsa_base_domain.as_bytes().contains(&0)
    {
        return Err(DaneError::InvalidServerName);
    }
    if certificate_chain_der
        .iter()
        .any(|certificate| certificate.is_empty() || certificate.len() > limits.max_certificate_len)
    {
        return Err(DaneError::CertificateLength);
    }
    if records.is_empty() {
        return Err(DaneError::MissingTlsa);
    }
    if records.len() > limits.max_tlsa_records {
        return Err(DaneError::TooManyTlsaRecords);
    }
    Ok(())
}

/// Extract the exact DER `SubjectPublicKeyInfo` TLV from a leaf certificate.
pub fn extract_subject_public_key_info(certificate_der: &[u8]) -> Result<&[u8], DaneError> {
    let mut document = DerReader::new(certificate_der);
    let certificate = document.read_expected(TAG_SEQUENCE)?;
    if !document.is_empty() {
        return Err(DaneError::MalformedCertificate);
    }

    let mut certificate_fields = DerReader::new(certificate.value);
    let tbs = certificate_fields.read_expected(TAG_SEQUENCE)?;
    let outer_algorithm = certificate_fields.read_expected(TAG_SEQUENCE)?;
    validate_algorithm_identifier(outer_algorithm.value)?;
    validate_bit_string(certificate_fields.read_expected(TAG_BIT_STRING)?.value)?;
    if !certificate_fields.is_empty() {
        return Err(DaneError::MalformedCertificate);
    }

    let mut fields = DerReader::new(tbs.value);
    if fields.peek_tag() == Some(TAG_EXPLICIT_VERSION) {
        validate_version(fields.read_expected(TAG_EXPLICIT_VERSION)?.value)?;
    }
    validate_integer(fields.read_expected(TAG_INTEGER)?.value)?;
    let tbs_algorithm = fields.read_expected(TAG_SEQUENCE)?;
    validate_algorithm_identifier(tbs_algorithm.value)?;
    if !constant_time_eq(tbs_algorithm.full, outer_algorithm.full) {
        return Err(DaneError::MalformedCertificate);
    }
    validate_name(fields.read_expected(TAG_SEQUENCE)?.value)?;
    validate_validity(fields.read_expected(TAG_SEQUENCE)?.value)?;
    validate_name(fields.read_expected(TAG_SEQUENCE)?.value)?;

    let spki = fields.read_expected(TAG_SEQUENCE)?;
    validate_spki(spki.value)?;
    validate_tbs_tail(&mut fields)?;
    Ok(spki.full)
}

#[derive(Clone, Copy)]
struct ParsedRecord<'a> {
    usage: CertificateUsage,
    selector: Selector,
    matching_type: MatchingType,
    association_data: &'a [u8],
}

fn parse_record(record: &Tlsa, limits: DaneLimits) -> Result<ParsedRecord<'_>, DaneError> {
    let usage = match record.usage {
        2 => CertificateUsage::DaneTa,
        3 => CertificateUsage::DaneEe,
        value => return Err(DaneError::UnsupportedUsage(value)),
    };
    let selector = match record.selector {
        0 => Selector::FullCertificate,
        1 => Selector::SubjectPublicKeyInfo,
        value => return Err(DaneError::UnsupportedSelector(value)),
    };
    let matching_type = match record.matching_type {
        0 => MatchingType::Exact,
        1 => MatchingType::Sha256,
        2 => MatchingType::Sha512,
        value => return Err(DaneError::UnsupportedMatchingType(value)),
    };
    let length = record.association_data.len();
    if length == 0
        || length > limits.max_association_len
        || (matching_type == MatchingType::Sha256 && length != 32)
        || (matching_type == MatchingType::Sha512 && length != 64)
    {
        return Err(DaneError::InvalidAssociationLength);
    }
    Ok(ParsedRecord {
        usage,
        selector,
        matching_type,
        association_data: &record.association_data,
    })
}

struct MatchMaterial<'a> {
    certificate: &'a [u8],
    spki: &'a [u8],
    certificate_sha256: [u8; 32],
    certificate_sha512: [u8; 64],
    spki_sha256: [u8; 32],
    spki_sha512: [u8; 64],
}

impl<'a> MatchMaterial<'a> {
    fn new(certificate: &'a [u8], spki: &'a [u8]) -> Self {
        Self {
            certificate,
            spki,
            certificate_sha256: Sha256::digest(certificate).into(),
            certificate_sha512: Sha512::digest(certificate).into(),
            spki_sha256: Sha256::digest(spki).into(),
            spki_sha512: Sha512::digest(spki).into(),
        }
    }

    fn matches(&self, record: ParsedRecord<'_>) -> bool {
        let candidate = match (record.selector, record.matching_type) {
            (Selector::FullCertificate, MatchingType::Exact) => self.certificate,
            (Selector::FullCertificate, MatchingType::Sha256) => &self.certificate_sha256,
            (Selector::FullCertificate, MatchingType::Sha512) => &self.certificate_sha512,
            (Selector::SubjectPublicKeyInfo, MatchingType::Exact) => self.spki,
            (Selector::SubjectPublicKeyInfo, MatchingType::Sha256) => &self.spki_sha256,
            (Selector::SubjectPublicKeyInfo, MatchingType::Sha512) => &self.spki_sha512,
        };
        constant_time_eq(candidate, record.association_data)
    }
}

fn validate_private_chain(
    leaf: &X509,
    presented_chain: &[X509],
    anchor: &X509,
    anchor_der: &[u8],
    server_name: &str,
    validation_unix_time: i64,
    limits: DaneLimits,
) -> bool {
    let result = (|| {
        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(anchor.clone())?;
        let mut parameters = X509VerifyParam::new()?;
        parameters.set_flags(
            X509VerifyFlags::PARTIAL_CHAIN
                | X509VerifyFlags::TRUSTED_FIRST
                | X509VerifyFlags::X509_STRICT,
        )?;
        parameters.set_depth(
            i32::try_from(limits.max_chain_certificates)
                .map_err(|_| openssl::error::ErrorStack::get())?,
        );
        parameters.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
        parameters.set_host(server_name)?;
        parameters.set_time(validation_unix_time);
        store_builder.set_param(&parameters)?;
        let store = store_builder.build();

        let mut untrusted = Stack::new()?;
        for certificate in presented_chain.iter().skip(1) {
            let der = certificate.to_der()?;
            if !constant_time_eq(&der, anchor_der) {
                untrusted.push(certificate.clone())?;
            }
        }
        let mut context = X509StoreContext::new()?;
        context.init(
            &store,
            leaf,
            &untrusted,
            openssl::x509::X509StoreContextRef::verify_cert,
        )
    })();
    matches!(result, Ok(true))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_ISSUER_UNIQUE_ID: u8 = 0x81;
const TAG_SUBJECT_UNIQUE_ID: u8 = 0x82;
const TAG_EXTENSIONS: u8 = 0xa3;
const TAG_EXPLICIT_VERSION: u8 = 0xa0;

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    full: &'a [u8],
    value: &'a [u8],
}

struct DerReader<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> DerReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn is_empty(&self) -> bool {
        self.cursor == self.input.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.input.get(self.cursor).copied()
    }

    fn read_expected(&mut self, expected: u8) -> Result<Tlv<'a>, DaneError> {
        let value = self.read_tlv()?;
        if value.tag != expected {
            return Err(DaneError::MalformedCertificate);
        }
        Ok(value)
    }

    fn read_tlv(&mut self) -> Result<Tlv<'a>, DaneError> {
        let start = self.cursor;
        let tag = *self
            .input
            .get(self.cursor)
            .ok_or(DaneError::MalformedCertificate)?;
        if tag & 0x1f == 0x1f {
            return Err(DaneError::MalformedCertificate);
        }
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or(DaneError::MalformedCertificate)?;
        let first_length = *self
            .input
            .get(self.cursor)
            .ok_or(DaneError::MalformedCertificate)?;
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or(DaneError::MalformedCertificate)?;

        let length = if first_length & 0x80 == 0 {
            usize::from(first_length)
        } else {
            let octets = usize::from(first_length & 0x7f);
            if octets == 0 || octets > 4 {
                return Err(DaneError::MalformedCertificate);
            }
            let length_end = self
                .cursor
                .checked_add(octets)
                .ok_or(DaneError::MalformedCertificate)?;
            let encoded = self
                .input
                .get(self.cursor..length_end)
                .ok_or(DaneError::MalformedCertificate)?;
            if encoded.first() == Some(&0) {
                return Err(DaneError::MalformedCertificate);
            }
            self.cursor = length_end;
            let mut length = 0usize;
            for byte in encoded {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .ok_or(DaneError::MalformedCertificate)?;
            }
            if length < 128 {
                return Err(DaneError::MalformedCertificate);
            }
            length
        };

        let value_start = self.cursor;
        let end = value_start
            .checked_add(length)
            .ok_or(DaneError::MalformedCertificate)?;
        let value = self
            .input
            .get(value_start..end)
            .ok_or(DaneError::MalformedCertificate)?;
        let full = self
            .input
            .get(start..end)
            .ok_or(DaneError::MalformedCertificate)?;
        self.cursor = end;
        Ok(Tlv { tag, full, value })
    }
}

fn validate_version(input: &[u8]) -> Result<(), DaneError> {
    let mut reader = DerReader::new(input);
    let version = reader.read_expected(TAG_INTEGER)?;
    if !reader.is_empty()
        || version.value.len() != 1
        || version.value.first().is_none_or(|value| *value > 2)
    {
        return Err(DaneError::MalformedCertificate);
    }
    Ok(())
}

fn validate_integer(input: &[u8]) -> Result<(), DaneError> {
    if input.is_empty() {
        return Err(DaneError::MalformedCertificate);
    }
    if input.len() > 1 {
        let first = input
            .first()
            .copied()
            .ok_or(DaneError::MalformedCertificate)?;
        let second = input
            .get(1)
            .copied()
            .ok_or(DaneError::MalformedCertificate)?;
        if (first == 0 && second & 0x80 == 0) || (first == 0xff && second & 0x80 != 0) {
            return Err(DaneError::MalformedCertificate);
        }
    }
    Ok(())
}

fn validate_algorithm_identifier(input: &[u8]) -> Result<(), DaneError> {
    let mut reader = DerReader::new(input);
    let oid = reader.read_expected(TAG_OBJECT_IDENTIFIER)?;
    if oid.value.is_empty() {
        return Err(DaneError::MalformedCertificate);
    }
    if !reader.is_empty() {
        reader.read_tlv()?;
    }
    if !reader.is_empty() {
        return Err(DaneError::MalformedCertificate);
    }
    Ok(())
}

fn validate_bit_string(input: &[u8]) -> Result<(), DaneError> {
    let unused_bits = input
        .first()
        .copied()
        .ok_or(DaneError::MalformedCertificate)?;
    if unused_bits > 7 || input.len() < 2 {
        return Err(DaneError::MalformedCertificate);
    }
    if unused_bits != 0 {
        let last = input
            .last()
            .copied()
            .ok_or(DaneError::MalformedCertificate)?;
        let mask = (1u8 << unused_bits) - 1;
        if last & mask != 0 {
            return Err(DaneError::MalformedCertificate);
        }
    }
    Ok(())
}

fn validate_name(input: &[u8]) -> Result<(), DaneError> {
    let mut reader = DerReader::new(input);
    while !reader.is_empty() {
        reader.read_tlv()?;
    }
    Ok(())
}

fn validate_validity(input: &[u8]) -> Result<(), DaneError> {
    let mut reader = DerReader::new(input);
    for _ in 0..2 {
        let time = reader.read_tlv()?;
        if !matches!(time.tag, TAG_UTC_TIME | TAG_GENERALIZED_TIME) || time.value.is_empty() {
            return Err(DaneError::MalformedCertificate);
        }
    }
    if !reader.is_empty() {
        return Err(DaneError::MalformedCertificate);
    }
    Ok(())
}

fn validate_spki(input: &[u8]) -> Result<(), DaneError> {
    let mut reader = DerReader::new(input);
    validate_algorithm_identifier(reader.read_expected(TAG_SEQUENCE)?.value)?;
    validate_bit_string(reader.read_expected(TAG_BIT_STRING)?.value)?;
    if !reader.is_empty() {
        return Err(DaneError::MalformedCertificate);
    }
    Ok(())
}

fn validate_tbs_tail(reader: &mut DerReader<'_>) -> Result<(), DaneError> {
    let mut last_tag = 0u8;
    while !reader.is_empty() {
        let field = reader.read_tlv()?;
        if !matches!(
            field.tag,
            TAG_ISSUER_UNIQUE_ID | TAG_SUBJECT_UNIQUE_ID | TAG_EXTENSIONS
        ) || field.tag <= last_tag
        {
            return Err(DaneError::MalformedCertificate);
        }
        last_tag = field.tag;
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests intentionally fail immediately on malformed fixed fixtures"
)]
mod tests {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
        SubjectAlternativeName, SubjectKeyIdentifier,
    };
    use openssl::x509::{X509, X509NameBuilder};

    use super::*;

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

    fn serial(value: u32) -> openssl::asn1::Asn1Integer {
        BigNum::from_u32(value).unwrap().to_asn1_integer().unwrap()
    }

    fn certificate_chain() -> (Vec<u8>, Vec<u8>) {
        let root_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut root_name = X509NameBuilder::new().unwrap();
        root_name
            .append_entry_by_text("CN", "DANE Test Root")
            .unwrap();
        let root_name = root_name.build();
        let mut root_builder = X509::builder().unwrap();
        root_builder.set_version(2).unwrap();
        root_builder.set_serial_number(&serial(1)).unwrap();
        root_builder.set_subject_name(&root_name).unwrap();
        root_builder.set_issuer_name(&root_name).unwrap();
        root_builder.set_pubkey(&root_key).unwrap();
        root_builder
            .set_not_before(&Asn1Time::from_unix(1_600_000_000).unwrap())
            .unwrap();
        root_builder
            .set_not_after(&Asn1Time::from_unix(1_900_000_000).unwrap())
            .unwrap();
        root_builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        root_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let root_subject_key = SubjectKeyIdentifier::new()
            .build(&root_builder.x509v3_context(None, None))
            .unwrap();
        root_builder.append_extension(root_subject_key).unwrap();
        root_builder
            .sign(&root_key, MessageDigest::sha256())
            .unwrap();
        let root = root_builder.build();

        let leaf_key: PKey<Private> = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut leaf_name = X509NameBuilder::new().unwrap();
        leaf_name
            .append_entry_by_text("CN", "service.example")
            .unwrap();
        let leaf_name = leaf_name.build();
        let mut leaf_builder = X509::builder().unwrap();
        leaf_builder.set_version(2).unwrap();
        leaf_builder.set_serial_number(&serial(2)).unwrap();
        leaf_builder.set_subject_name(&leaf_name).unwrap();
        leaf_builder.set_issuer_name(root.subject_name()).unwrap();
        leaf_builder.set_pubkey(&leaf_key).unwrap();
        leaf_builder
            .set_not_before(&Asn1Time::from_unix(1_600_000_000).unwrap())
            .unwrap();
        leaf_builder
            .set_not_after(&Asn1Time::from_unix(1_900_000_000).unwrap())
            .unwrap();
        leaf_builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        leaf_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        leaf_builder
            .append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        let subject_alternative_name = SubjectAlternativeName::new()
            .dns("service.example")
            .build(&leaf_builder.x509v3_context(Some(&root), None))
            .unwrap();
        leaf_builder
            .append_extension(subject_alternative_name)
            .unwrap();
        let authority_key = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&leaf_builder.x509v3_context(Some(&root), None))
            .unwrap();
        leaf_builder.append_extension(authority_key).unwrap();
        let leaf_subject_key = SubjectKeyIdentifier::new()
            .build(&leaf_builder.x509v3_context(Some(&root), None))
            .unwrap();
        leaf_builder.append_extension(leaf_subject_key).unwrap();
        leaf_builder
            .sign(&root_key, MessageDigest::sha256())
            .unwrap();
        (
            leaf_builder.build().to_der().unwrap(),
            root.to_der().unwrap(),
        )
    }

    fn certificate() -> Vec<u8> {
        decode_hex(include_str!(
            "../fixtures/dane/self-signed-cert.der.hex"
        ))
    }

    fn expected_spki() -> Vec<u8> {
        decode_hex(include_str!(
            "../fixtures/dane/self-signed-spki.der.hex"
        ))
    }

    fn record(selector: Selector, matching_type: MatchingType, data: Vec<u8>) -> Tlsa {
        Tlsa {
            usage: CertificateUsage::DaneEe as u8,
            selector: selector as u8,
            matching_type: matching_type as u8,
            association_data: data,
        }
    }

    #[test]
    fn extracts_exact_spki_from_real_certificate_fixture() {
        let certificate = certificate();
        assert_eq!(
            extract_subject_public_key_info(&certificate).unwrap(),
            expected_spki()
        );
    }

    #[test]
    fn matches_full_certificate_exact_sha256_and_sha512() {
        let certificate = certificate();
        for (matching_type, association_data) in [
            (MatchingType::Exact, certificate.clone()),
            (MatchingType::Sha256, Sha256::digest(&certificate).to_vec()),
            (MatchingType::Sha512, Sha512::digest(&certificate).to_vec()),
        ] {
            let matched = verify_dane_ee(
                &certificate,
                &[record(
                    Selector::FullCertificate,
                    matching_type,
                    association_data,
                )],
                DaneLimits::default(),
            )
            .unwrap();
            assert_eq!(matched.selector(), Selector::FullCertificate);
            assert_eq!(matched.matching_type(), matching_type);
        }
    }

    #[test]
    fn matches_spki_exact_sha256_and_sha512() {
        let certificate = certificate();
        let spki = expected_spki();
        for (matching_type, association_data) in [
            (MatchingType::Exact, spki.clone()),
            (MatchingType::Sha256, Sha256::digest(&spki).to_vec()),
            (MatchingType::Sha512, Sha512::digest(&spki).to_vec()),
        ] {
            let matched = verify_dane_ee(
                &certificate,
                &[record(
                    Selector::SubjectPublicKeyInfo,
                    matching_type,
                    association_data,
                )],
                DaneLimits::default(),
            )
            .unwrap();
            assert_eq!(matched.selector(), Selector::SubjectPublicKeyInfo);
            assert_eq!(matched.matching_type(), matching_type);
        }
    }

    #[test]
    fn rejects_mismatch_and_mutated_certificate() {
        let certificate = certificate();
        let pin = Sha256::digest(&certificate).to_vec();
        let tlsa = record(Selector::FullCertificate, MatchingType::Sha256, pin);
        let mut mutated = certificate.clone();
        let last = mutated.len() - 1;
        mutated[last] ^= 1;

        assert_eq!(
            verify_dane_ee(&mutated, &[tlsa], DaneLimits::default()),
            Err(DaneError::Mismatch)
        );
    }

    #[test]
    fn dane_ta_builds_only_the_dnssec_selected_private_chain() {
        let (leaf, root) = certificate_chain();
        let exact_anchor = Tlsa {
            usage: 2,
            selector: 0,
            matching_type: 0,
            association_data: root.clone(),
        };
        let matched = verify_dane_chain(
            &[&leaf],
            "service.example",
            std::slice::from_ref(&exact_anchor),
            1_750_000_000,
            DaneLimits::default(),
        )
        .unwrap();
        assert_eq!(matched.usage(), CertificateUsage::DaneTa);
        assert_eq!(matched.selector(), Selector::FullCertificate);

        assert_eq!(
            verify_dane_chain(
                &[&leaf],
                "wrong.example",
                std::slice::from_ref(&exact_anchor),
                1_750_000_000,
                DaneLimits::default(),
            ),
            Err(DaneError::ChainValidation)
        );
        assert_eq!(
            verify_dane_chain(
                &[&leaf],
                "service.example",
                std::slice::from_ref(&exact_anchor),
                2_000_000_000,
                DaneLimits::default(),
            ),
            Err(DaneError::ChainValidation)
        );
    }

    #[test]
    fn dane_ta_digest_requires_the_anchor_in_the_server_chain() {
        let (leaf, root) = certificate_chain();
        let root_spki = extract_subject_public_key_info(&root).unwrap();
        let digest_anchor = Tlsa {
            usage: 2,
            selector: 1,
            matching_type: 1,
            association_data: Sha256::digest(root_spki).to_vec(),
        };
        let matched = verify_dane_chain(
            &[&leaf, &root],
            "service.example",
            std::slice::from_ref(&digest_anchor),
            1_750_000_000,
            DaneLimits::default(),
        )
        .unwrap();
        assert_eq!(matched.usage(), CertificateUsage::DaneTa);
        assert_eq!(matched.selector(), Selector::SubjectPublicKeyInfo);

        assert_eq!(
            verify_dane_chain(
                &[&leaf],
                "service.example",
                std::slice::from_ref(&digest_anchor),
                1_750_000_000,
                DaneLimits::default(),
            ),
            Err(DaneError::Mismatch)
        );
    }

    #[test]
    fn dane_ee_ignores_pkix_name_time_and_public_roots() {
        let (leaf, _) = certificate_chain();
        let leaf_record = Tlsa {
            usage: 3,
            selector: 0,
            matching_type: 0,
            association_data: leaf.clone(),
        };
        let matched = verify_dane_chain(
            &[&leaf],
            "unrelated.example",
            std::slice::from_ref(&leaf_record),
            i64::MAX,
            DaneLimits::default(),
        )
        .unwrap();
        assert_eq!(matched.usage(), CertificateUsage::DaneEe);

        let wrong_record = Tlsa {
            association_data: vec![0; leaf.len()],
            ..leaf_record
        };
        assert_eq!(
            verify_dane_chain(
                &[&leaf],
                "service.example",
                &[wrong_record],
                1_750_000_000,
                DaneLimits::default(),
            ),
            Err(DaneError::Mismatch)
        );
    }

    #[test]
    fn rejects_unsupported_or_malformed_tlsa_before_matching() {
        let certificate = certificate();
        let valid_digest = Sha256::digest(&certificate).to_vec();
        for (tlsa, expected) in [
            (
                Tlsa {
                    usage: 0,
                    selector: 0,
                    matching_type: 1,
                    association_data: valid_digest.clone(),
                },
                DaneError::UnsupportedUsage(0),
            ),
            (
                Tlsa {
                    usage: 3,
                    selector: 2,
                    matching_type: 1,
                    association_data: valid_digest.clone(),
                },
                DaneError::UnsupportedSelector(2),
            ),
            (
                Tlsa {
                    usage: 3,
                    selector: 0,
                    matching_type: 3,
                    association_data: valid_digest.clone(),
                },
                DaneError::UnsupportedMatchingType(3),
            ),
            (
                Tlsa {
                    usage: 3,
                    selector: 0,
                    matching_type: 1,
                    association_data: vec![0; 31],
                },
                DaneError::InvalidAssociationLength,
            ),
        ] {
            assert_eq!(
                verify_dane_ee(&certificate, &[tlsa], DaneLimits::default()),
                Err(expected)
            );
        }
    }

    #[test]
    fn enforces_certificate_record_and_association_bounds() {
        let certificate = certificate();
        assert_eq!(
            verify_dane_ee(&certificate, &[], DaneLimits::default()),
            Err(DaneError::MissingTlsa)
        );

        let record = record(
            Selector::FullCertificate,
            MatchingType::Exact,
            certificate.clone(),
        );
        let limits = DaneLimits {
            max_certificate_len: certificate.len() - 1,
            ..DaneLimits::default()
        };
        assert_eq!(
            verify_dane_ee(&certificate, std::slice::from_ref(&record), limits),
            Err(DaneError::CertificateLength)
        );

        let limits = DaneLimits {
            max_tlsa_records: 1,
            ..DaneLimits::default()
        };
        assert_eq!(
            verify_dane_ee(&certificate, &[record.clone(), record], limits),
            Err(DaneError::TooManyTlsaRecords)
        );
    }

    #[test]
    fn rejects_truncated_and_non_minimal_der_lengths() {
        let certificate = certificate();
        for malformed in [
            certificate[..certificate.len() - 1].to_vec(),
            vec![0x30, 0x81, 0x01, 0x00],
            vec![0x30, 0x80, 0x00, 0x00],
        ] {
            assert_eq!(
                extract_subject_public_key_info(&malformed),
                Err(DaneError::MalformedCertificate)
            );
        }
    }
}
