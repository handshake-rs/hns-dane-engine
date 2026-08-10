use hns_core::dns::{DnsName, RecordType, ResourceRecord};
use hns_core::resource::decode_handshake_resource_records;
use hns_core::{Hash, Height, NameHash};
use hns_dnssec::{DnssecStatus, DnssecTime, SignedRrsetValidationInput, validate_signed_rrset};
use hns_urkel::{ParsedProof, ProofKind};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

pub const EXPERIMENTAL_HIP17_URKEL_PROOF_OID: &str = "1.3.6.1.4.1.55555.17.1";
pub const EXPERIMENTAL_HIP17_DNSSEC_CHAIN_OID: &str = "1.3.6.1.4.1.55555.17.2";
pub const MAX_STATELESS_DANE_ROOTS: usize = 40;
pub const MAX_STATELESS_DANE_PROOFS: usize = 2;
pub const MAX_STATELESS_DANE_DNSSEC_CHAIN_BYTES: usize = 64 * 1024;
const MAX_HSD_NAME_STATE_NAME_BYTES: usize = 63;
const MAX_HSD_NAME_STATE_DATA_BYTES: usize = 512;
const HSD_NAME_STATE_FIXED_TAIL_BYTES: usize = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsaUsage {
    PkixTa,
    PkixEe,
    DaneTa,
    DaneEe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsaSelector {
    FullCertificate,
    SubjectPublicKeyInfo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsaMatching {
    Exact,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsaRecord {
    pub usage: TlsaUsage,
    pub selector: TlsaSelector,
    pub matching: TlsaMatching,
    pub association_data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainTrustMode {
    HnsStrict,
    IcannWebPki,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebPkiStatus {
    Valid,
    Invalid,
    NotEvaluated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaneValidationInput<'a> {
    pub mode: DomainTrustMode,
    pub dnssec_secure: bool,
    pub tlsa_records: &'a [TlsaRecord],
    pub cert_der: &'a [u8],
    pub spki_der: &'a [u8],
    pub webpki_status: WebPkiStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaneCertificateValidationInput<'a> {
    pub mode: DomainTrustMode,
    pub dnssec_secure: bool,
    pub tlsa_records: &'a [TlsaRecord],
    pub cert_der: &'a [u8],
    pub webpki_status: WebPkiStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaneCertificateChainValidationInput<'a> {
    pub mode: DomainTrustMode,
    pub dnssec_secure: bool,
    pub tlsa_records: &'a [TlsaRecord],
    pub end_entity_der: &'a [u8],
    pub intermediate_der: &'a [&'a [u8]],
    pub webpki_status: WebPkiStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StatelessDaneConfig {
    pub enabled: bool,
    pub accepted_tree_roots: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatelessDaneValidationInput<'a> {
    pub cert_der: &'a [u8],
    pub host: &'a str,
    pub port: u16,
    pub accepted_tree_roots: &'a [[u8; 32]],
    pub now_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatelessDaneEvidence {
    Missing,
    Tlsa {
        records: Vec<TlsaRecord>,
        proof_root: [u8; 32],
        proof_height: Option<Height>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaneDecision {
    NoTlsa,
    Matched(TlsaUsage),
    StatelessMatched(TlsaUsage),
    WebPkiFallback,
    Failed,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DaneError {
    #[error("TLSA record is too short")]
    ShortRecord,
    #[error("unsupported TLSA usage")]
    UnsupportedUsage,
    #[error("unsupported TLSA selector")]
    UnsupportedSelector,
    #[error("unsupported TLSA matching type")]
    UnsupportedMatching,
    #[error("TLSA records are present but not DNSSEC-secure")]
    InsecureTlsa,
    #[error("strict HNS mode requires DNSSEC-secure TLSA")]
    MissingRequiredTlsa,
    #[error("WebPKI validation failed")]
    WebPkiFailed,
    #[error("certificate DER is malformed")]
    MalformedCertificate,
    #[error("certificate subjectPublicKeyInfo is missing")]
    MissingSubjectPublicKeyInfo,
    #[error("stateless DANE certificate evidence is malformed")]
    MalformedCertificateEvidence,
    #[error("stateless DANE certificate evidence is unsupported")]
    UnsupportedCertificateEvidence,
    #[error("stateless DANE certificate evidence did not validate")]
    InvalidCertificateEvidence,
    #[error("stateless DANE certificate evidence does not contain a usable TLSA RRset")]
    MissingCertificateTlsa,
    #[error("stateless DANE certificate evidence DNSSEC chain is invalid")]
    InvalidCertificateDnssec,
}

impl TlsaRecord {
    pub fn parse_rdata(rdata: &[u8]) -> Result<Self, DaneError> {
        if rdata.len() < 3 {
            return Err(DaneError::ShortRecord);
        }

        Ok(Self {
            usage: match rdata[0] {
                0 => TlsaUsage::PkixTa,
                1 => TlsaUsage::PkixEe,
                2 => TlsaUsage::DaneTa,
                3 => TlsaUsage::DaneEe,
                _ => return Err(DaneError::UnsupportedUsage),
            },
            selector: match rdata[1] {
                0 => TlsaSelector::FullCertificate,
                1 => TlsaSelector::SubjectPublicKeyInfo,
                _ => return Err(DaneError::UnsupportedSelector),
            },
            matching: match rdata[2] {
                0 => TlsaMatching::Exact,
                1 => TlsaMatching::Sha256,
                2 => TlsaMatching::Sha512,
                _ => return Err(DaneError::UnsupportedMatching),
            },
            association_data: rdata[3..].to_vec(),
        })
    }

    pub fn matches_der(&self, cert_der: &[u8], spki_der: &[u8]) -> bool {
        let selected = match self.selector {
            TlsaSelector::FullCertificate => cert_der,
            TlsaSelector::SubjectPublicKeyInfo => spki_der,
        };

        match self.matching {
            TlsaMatching::Exact => selected == self.association_data.as_slice(),
            TlsaMatching::Sha256 => {
                Sha256::digest(selected).as_slice() == self.association_data.as_slice()
            }
            TlsaMatching::Sha512 => {
                Sha512::digest(selected).as_slice() == self.association_data.as_slice()
            }
        }
    }

    fn is_ee_usage(&self) -> bool {
        matches!(self.usage, TlsaUsage::PkixEe | TlsaUsage::DaneEe)
    }

    fn is_pkix_usage(&self) -> bool {
        matches!(self.usage, TlsaUsage::PkixTa | TlsaUsage::PkixEe)
    }
}

#[derive(Clone, Copy, Debug)]
struct CertificateChainInput<'a> {
    end_entity_der: &'a [u8],
    end_entity_spki_der: &'a [u8],
    intermediate_der: &'a [&'a [u8]],
}

pub fn evaluate_tlsa(records: &[TlsaRecord], cert_der: &[u8], spki_der: &[u8]) -> DaneDecision {
    if records.is_empty() {
        return DaneDecision::NoTlsa;
    }

    records
        .iter()
        .find(|record| record.matches_der(cert_der, spki_der))
        .map(|record| DaneDecision::Matched(record.usage))
        .unwrap_or(DaneDecision::Failed)
}

fn evaluate_tlsa_for_chain(
    records: &[TlsaRecord],
    chain: CertificateChainInput<'_>,
    webpki_status: WebPkiStatus,
) -> Result<DaneDecision, DaneError> {
    let mut pkix_match_rejected_by_webpki = false;

    for record in records {
        if !record_matches_chain(record, chain)? {
            continue;
        }
        if record.is_pkix_usage() && webpki_status != WebPkiStatus::Valid {
            pkix_match_rejected_by_webpki = true;
            continue;
        }
        return Ok(DaneDecision::Matched(record.usage));
    }

    if pkix_match_rejected_by_webpki {
        Err(DaneError::WebPkiFailed)
    } else {
        Ok(DaneDecision::Failed)
    }
}

fn record_matches_chain(
    record: &TlsaRecord,
    chain: CertificateChainInput<'_>,
) -> Result<bool, DaneError> {
    match record.usage {
        TlsaUsage::PkixEe | TlsaUsage::DaneEe => {
            Ok(record.matches_der(chain.end_entity_der, chain.end_entity_spki_der))
        }
        TlsaUsage::PkixTa | TlsaUsage::DaneTa => {
            for cert_der in chain.intermediate_der {
                if record_matches_certificate(record, cert_der)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn record_matches_certificate(record: &TlsaRecord, cert_der: &[u8]) -> Result<bool, DaneError> {
    match record.selector {
        TlsaSelector::FullCertificate => Ok(record.matches_der(cert_der, &[])),
        TlsaSelector::SubjectPublicKeyInfo => {
            let spki_der = extract_spki_der(cert_der)?;
            Ok(record.matches_der(cert_der, &spki_der))
        }
    }
}

fn evaluate_no_tlsa_policy(
    mode: DomainTrustMode,
    webpki_status: WebPkiStatus,
) -> Result<DaneDecision, DaneError> {
    match mode {
        DomainTrustMode::HnsStrict => Err(DaneError::MissingRequiredTlsa),
        DomainTrustMode::IcannWebPki => match webpki_status {
            WebPkiStatus::Valid => Ok(DaneDecision::WebPkiFallback),
            WebPkiStatus::Invalid => Err(DaneError::WebPkiFailed),
            WebPkiStatus::NotEvaluated => Ok(DaneDecision::NoTlsa),
        },
    }
}

pub fn evaluate_policy(input: DaneValidationInput<'_>) -> Result<DaneDecision, DaneError> {
    if !input.tlsa_records.is_empty() {
        if !input.dnssec_secure {
            return Err(DaneError::InsecureTlsa);
        }

        return evaluate_tlsa_for_chain(
            input.tlsa_records,
            CertificateChainInput {
                end_entity_der: input.cert_der,
                end_entity_spki_der: input.spki_der,
                intermediate_der: &[],
            },
            input.webpki_status,
        );
    }

    evaluate_no_tlsa_policy(input.mode, input.webpki_status)
}

pub fn evaluate_policy_with_certificate(
    input: DaneCertificateValidationInput<'_>,
) -> Result<DaneDecision, DaneError> {
    evaluate_policy_with_certificate_chain(DaneCertificateChainValidationInput {
        mode: input.mode,
        dnssec_secure: input.dnssec_secure,
        tlsa_records: input.tlsa_records,
        end_entity_der: input.cert_der,
        intermediate_der: &[],
        webpki_status: input.webpki_status,
    })
}

pub fn evaluate_policy_with_certificate_chain(
    input: DaneCertificateChainValidationInput<'_>,
) -> Result<DaneDecision, DaneError> {
    let spki_der =
        if input.tlsa_records.iter().any(|record| {
            record.selector == TlsaSelector::SubjectPublicKeyInfo && record.is_ee_usage()
        }) {
            extract_spki_der(input.end_entity_der)?
        } else {
            Vec::new()
        };

    if !input.tlsa_records.is_empty() {
        if !input.dnssec_secure {
            return Err(DaneError::InsecureTlsa);
        }

        return evaluate_tlsa_for_chain(
            input.tlsa_records,
            CertificateChainInput {
                end_entity_der: input.end_entity_der,
                end_entity_spki_der: &spki_der,
                intermediate_der: input.intermediate_der,
            },
            input.webpki_status,
        );
    }

    evaluate_no_tlsa_policy(input.mode, input.webpki_status)
}

pub fn extract_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, DaneError> {
    let mut cursor = 0;
    let certificate = read_der_element(cert_der, &mut cursor)?;
    if certificate.tag != TAG_SEQUENCE || cursor != cert_der.len() {
        return Err(DaneError::MalformedCertificate);
    }

    let mut certificate_cursor = certificate.value_start;
    let tbs_certificate = read_der_element(cert_der, &mut certificate_cursor)?;
    if tbs_certificate.tag != TAG_SEQUENCE || tbs_certificate.end > certificate.end {
        return Err(DaneError::MalformedCertificate);
    }

    let mut tbs_cursor = tbs_certificate.value_start;
    if peek_der_tag(cert_der, tbs_cursor, tbs_certificate.end)? == Some(TAG_EXPLICIT_VERSION) {
        skip_der_element(cert_der, &mut tbs_cursor, tbs_certificate.end)?;
    }

    for _ in 0..5 {
        skip_der_element(cert_der, &mut tbs_cursor, tbs_certificate.end)?;
    }

    if tbs_cursor >= tbs_certificate.end {
        return Err(DaneError::MissingSubjectPublicKeyInfo);
    }

    let spki = read_der_element_with_limit(cert_der, &mut tbs_cursor, tbs_certificate.end)?;
    if spki.tag != TAG_SEQUENCE {
        return Err(DaneError::MissingSubjectPublicKeyInfo);
    }

    Ok(cert_der[spki.start..spki.end].to_vec())
}

pub fn evaluate_stateless_dane_certificate(
    input: StatelessDaneValidationInput<'_>,
) -> Result<StatelessDaneEvidence, DaneError> {
    let proof_values = certificate_extension_values(
        cert_der_checked(input.cert_der)?,
        EXPERIMENTAL_HIP17_URKEL_PROOF_OID,
    )?;
    let chain_values =
        certificate_extension_values(input.cert_der, EXPERIMENTAL_HIP17_DNSSEC_CHAIN_OID)?;
    if proof_values.is_empty() && chain_values.is_empty() {
        return Ok(StatelessDaneEvidence::Missing);
    }
    if proof_values.len() != 1 || chain_values.len() != 1 {
        return Err(DaneError::MalformedCertificateEvidence);
    }
    if input.accepted_tree_roots.is_empty()
        || input.accepted_tree_roots.len() > MAX_STATELESS_DANE_ROOTS
    {
        return Err(DaneError::InvalidCertificateEvidence);
    }

    let host = normalize_host(input.host);
    let root_name = hns_root_label(&host).ok_or(DaneError::InvalidCertificateEvidence)?;
    let name_hash =
        NameHash::from_name(&root_name).map_err(|_| DaneError::InvalidCertificateEvidence)?;
    let owner =
        DnsName::from_ascii(&root_name).map_err(|_| DaneError::InvalidCertificateEvidence)?;
    let service_owner = DnsName::from_ascii(&service_name(input.port, "tcp", &host))
        .map_err(|_| DaneError::InvalidCertificateEvidence)?;

    let accepted_roots = input
        .accepted_tree_roots
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let proofs = parse_stateless_urkel_proofs(&proof_values[0])?;
    let records = parse_rfc9102_authentication_chain(&chain_values[0])?;
    let tlsa_rrset = records_for(&records, &service_owner, RecordType::Tlsa);
    if tlsa_rrset.is_empty() {
        return Err(DaneError::MissingCertificateTlsa);
    }

    for proof in proofs {
        if !accepted_roots.contains(proof.root.as_bytes()) {
            continue;
        }
        let parsed = ParsedProof::parse_for_key(&proof.proof, proof.root, name_hash)
            .map_err(|_| DaneError::MalformedCertificateEvidence)?;
        if parsed.kind != ProofKind::Inclusion
            || parsed.name_hash != name_hash
            || !parsed.proof.verify(proof.root, name_hash.as_hash())
        {
            continue;
        }
        let value = parsed
            .value()
            .ok_or(DaneError::InvalidCertificateEvidence)?;
        let resource_value = extract_name_state_resource_value(&root_name, value)?;
        let hns_records = decode_handshake_resource_records(&owner, &resource_value)
            .map_err(|_| DaneError::InvalidCertificateEvidence)?;
        let ds_rrset = records_for(&hns_records, &owner, RecordType::Ds);
        if ds_rrset.is_empty() {
            return Err(DaneError::UnsupportedCertificateEvidence);
        }

        validate_direct_dnssec_tlsa_chain(
            &owner,
            &service_owner,
            &ds_rrset,
            &records,
            &tlsa_rrset,
            input.now_unix,
        )?;
        let tlsa_records = tlsa_rrset
            .iter()
            .map(|record| TlsaRecord::parse_rdata(&record.rdata))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(StatelessDaneEvidence::Tlsa {
            records: tlsa_records,
            proof_root: *proof.root.as_bytes(),
            proof_height: None,
        });
    }

    Err(DaneError::InvalidCertificateEvidence)
}

fn validate_direct_dnssec_tlsa_chain(
    root_owner: &DnsName,
    service_owner: &DnsName,
    ds_rrset: &[ResourceRecord],
    dnssec_records: &[ResourceRecord],
    tlsa_rrset: &[ResourceRecord],
    now_unix: u64,
) -> Result<(), DaneError> {
    let dnskey_rrset = records_for(dnssec_records, root_owner, RecordType::Dnskey);
    let dnskey_rrsig_rrset = rrsig_records_for(dnssec_records, root_owner, RecordType::Dnskey);
    let tlsa_rrsig_rrset = rrsig_records_for(dnssec_records, service_owner, RecordType::Tlsa);
    if dnskey_rrset.is_empty() || dnskey_rrsig_rrset.is_empty() || tlsa_rrsig_rrset.is_empty() {
        return Err(DaneError::InvalidCertificateDnssec);
    }

    let status = validate_signed_rrset(SignedRrsetValidationInput {
        dnskey_owner: root_owner,
        ds_rrset,
        dnskey_rrset: &dnskey_rrset,
        dnskey_rrsig_rrset: &dnskey_rrsig_rrset,
        rrset: tlsa_rrset,
        rrsig_rrset: &tlsa_rrsig_rrset,
        now: DnssecTime(now_unix),
    })
    .map_err(|_| DaneError::InvalidCertificateDnssec)?;
    if status == DnssecStatus::Secure {
        Ok(())
    } else {
        Err(DaneError::InvalidCertificateDnssec)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StatelessUrkelProof {
    root: Hash,
    proof: Vec<u8>,
}

fn parse_stateless_urkel_proofs(input: &[u8]) -> Result<Vec<StatelessUrkelProof>, DaneError> {
    let mut cursor = RawCursor::new(input);
    let count = cursor.read_u8()? as usize;
    if count == 0 || count > MAX_STATELESS_DANE_PROOFS {
        return Err(DaneError::MalformedCertificateEvidence);
    }
    let mut proofs = Vec::with_capacity(count);
    for _ in 0..count {
        let root = Hash::from_slice(cursor.read_bytes(32)?)
            .map_err(|_| DaneError::MalformedCertificateEvidence)?;
        let proof_len = cursor.read_u16_be()? as usize;
        let proof = cursor.read_bytes(proof_len)?.to_vec();
        proofs.push(StatelessUrkelProof { root, proof });
    }
    if !cursor.is_finished() {
        return Err(DaneError::MalformedCertificateEvidence);
    }
    Ok(proofs)
}

fn parse_rfc9102_authentication_chain(input: &[u8]) -> Result<Vec<ResourceRecord>, DaneError> {
    if input.len() > MAX_STATELESS_DANE_DNSSEC_CHAIN_BYTES || input.len() < 3 {
        return Err(DaneError::MalformedCertificateEvidence);
    }
    let mut cursor = 2usize;
    let mut records = Vec::new();
    while cursor < input.len() {
        let (record, next) = ResourceRecord::parse(input, cursor)
            .map_err(|_| DaneError::MalformedCertificateEvidence)?;
        if next <= cursor {
            return Err(DaneError::MalformedCertificateEvidence);
        }
        records.push(record);
        cursor = next;
    }
    Ok(records)
}

fn certificate_extension_values(
    cert_der: &[u8],
    target_oid: &str,
) -> Result<Vec<Vec<u8>>, DaneError> {
    let mut cursor = 0;
    let certificate = read_der_element(cert_der, &mut cursor)?;
    if certificate.tag != TAG_SEQUENCE || cursor != cert_der.len() {
        return Err(DaneError::MalformedCertificate);
    }
    let mut certificate_cursor = certificate.value_start;
    let tbs_certificate = read_der_element(cert_der, &mut certificate_cursor)?;
    if tbs_certificate.tag != TAG_SEQUENCE || tbs_certificate.end > certificate.end {
        return Err(DaneError::MalformedCertificate);
    }

    let mut tbs_cursor = tbs_certificate.value_start;
    if peek_der_tag(cert_der, tbs_cursor, tbs_certificate.end)? == Some(TAG_EXPLICIT_VERSION) {
        skip_der_element(cert_der, &mut tbs_cursor, tbs_certificate.end)?;
    }
    for _ in 0..6 {
        skip_der_element(cert_der, &mut tbs_cursor, tbs_certificate.end)?;
    }
    while tbs_cursor < tbs_certificate.end {
        let tag = peek_der_tag(cert_der, tbs_cursor, tbs_certificate.end)?
            .ok_or(DaneError::MalformedCertificate)?;
        let element = read_der_element_with_limit(cert_der, &mut tbs_cursor, tbs_certificate.end)?;
        if tag == TAG_EXPLICIT_EXTENSIONS {
            return parse_extensions_element(cert_der, element, target_oid);
        }
    }
    Ok(Vec::new())
}

fn parse_extensions_element(
    cert_der: &[u8],
    wrapper: DerElement,
    target_oid: &str,
) -> Result<Vec<Vec<u8>>, DaneError> {
    let mut wrapper_cursor = wrapper.value_start;
    let extensions = read_der_element_with_limit(cert_der, &mut wrapper_cursor, wrapper.end)?;
    if extensions.tag != TAG_SEQUENCE || wrapper_cursor != wrapper.end {
        return Err(DaneError::MalformedCertificate);
    }
    let mut cursor = extensions.value_start;
    let mut values = Vec::new();
    while cursor < extensions.end {
        let extension = read_der_element_with_limit(cert_der, &mut cursor, extensions.end)?;
        if extension.tag != TAG_SEQUENCE {
            return Err(DaneError::MalformedCertificate);
        }
        let mut ext_cursor = extension.value_start;
        let oid = read_der_element_with_limit(cert_der, &mut ext_cursor, extension.end)?;
        if oid.tag != TAG_OBJECT_IDENTIFIER {
            return Err(DaneError::MalformedCertificate);
        }
        let oid_text = oid_to_string(&cert_der[oid.value_start..oid.end])?;
        if peek_der_tag(cert_der, ext_cursor, extension.end)? == Some(TAG_BOOLEAN) {
            skip_der_element(cert_der, &mut ext_cursor, extension.end)?;
        }
        let value = read_der_element_with_limit(cert_der, &mut ext_cursor, extension.end)?;
        if value.tag != TAG_OCTET_STRING || ext_cursor != extension.end {
            return Err(DaneError::MalformedCertificate);
        }
        if oid_text == target_oid {
            values.push(cert_der[value.value_start..value.end].to_vec());
        }
    }
    Ok(values)
}

fn oid_to_string(input: &[u8]) -> Result<String, DaneError> {
    let first = *input.first().ok_or(DaneError::MalformedCertificate)?;
    let mut parts = vec![(first / 40).to_string(), (first % 40).to_string()];
    let mut value = 0u32;
    let mut saw_byte = false;
    for byte in input.iter().skip(1) {
        saw_byte = true;
        value = value
            .checked_mul(128)
            .and_then(|value| value.checked_add(u32::from(byte & 0x7f)))
            .ok_or(DaneError::MalformedCertificate)?;
        if byte & 0x80 == 0 {
            parts.push(value.to_string());
            value = 0;
            saw_byte = false;
        }
    }
    if saw_byte {
        return Err(DaneError::MalformedCertificate);
    }
    Ok(parts.join("."))
}

fn extract_name_state_resource_value(root_name: &str, value: &[u8]) -> Result<Vec<u8>, DaneError> {
    let name_len = usize::from(
        *value
            .first()
            .ok_or(DaneError::MalformedCertificateEvidence)?,
    );
    if name_len > MAX_HSD_NAME_STATE_NAME_BYTES {
        return Err(DaneError::MalformedCertificateEvidence);
    }
    let name_start = 1usize;
    let name_end = name_start
        .checked_add(name_len)
        .ok_or(DaneError::MalformedCertificateEvidence)?;
    let data_len_start = name_end;
    let data_len_end = data_len_start
        .checked_add(2)
        .ok_or(DaneError::MalformedCertificateEvidence)?;
    if value.len() < data_len_end || &value[name_start..name_end] != root_name.as_bytes() {
        return Err(DaneError::InvalidCertificateEvidence);
    }
    let data_len = usize::from(u16::from_le_bytes([
        value[data_len_start],
        value[data_len_start + 1],
    ]));
    if data_len > MAX_HSD_NAME_STATE_DATA_BYTES {
        return Err(DaneError::MalformedCertificateEvidence);
    }
    let data_start = data_len_end;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(DaneError::MalformedCertificateEvidence)?;
    let min_end = data_end
        .checked_add(HSD_NAME_STATE_FIXED_TAIL_BYTES)
        .ok_or(DaneError::MalformedCertificateEvidence)?;
    if value.len() < min_end {
        return Err(DaneError::MalformedCertificateEvidence);
    }
    Ok(value[data_start..data_end].to_vec())
}

fn records_for(
    records: &[ResourceRecord],
    owner: &DnsName,
    record_type: RecordType,
) -> Vec<ResourceRecord> {
    records
        .iter()
        .filter(|record| record.name == *owner && record.record_type == record_type)
        .cloned()
        .collect()
}

fn rrsig_records_for(
    records: &[ResourceRecord],
    owner: &DnsName,
    covered: RecordType,
) -> Vec<ResourceRecord> {
    records
        .iter()
        .filter(|record| record.name == *owner && record.record_type == RecordType::Rrsig)
        .filter(|record| {
            hns_dnssec::RrsigRecord::from_record(record)
                .map(|rrsig| rrsig.type_covered == covered)
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn hns_root_label(host: &str) -> Option<String> {
    let root = host.split('.').rfind(|label| !label.is_empty())?;
    (!root.is_empty()).then(|| root.to_owned())
}

fn cert_der_checked(cert_der: &[u8]) -> Result<&[u8], DaneError> {
    let mut cursor = 0;
    let certificate = read_der_element(cert_der, &mut cursor)?;
    if certificate.tag == TAG_SEQUENCE && cursor == cert_der.len() {
        Ok(cert_der)
    } else {
        Err(DaneError::MalformedCertificate)
    }
}

pub fn service_name(port: u16, transport: &str, host: &str) -> String {
    format!(
        "_{}._{}.{}",
        port,
        transport.to_ascii_lowercase(),
        host.trim_end_matches('.')
    )
}

const TAG_SEQUENCE: u8 = 0x30;
const TAG_EXPLICIT_VERSION: u8 = 0xa0;
const TAG_BOOLEAN: u8 = 0x01;
const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_EXPLICIT_EXTENSIONS: u8 = 0xa3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DerElement {
    tag: u8,
    start: usize,
    value_start: usize,
    end: usize,
}

fn read_der_element(data: &[u8], cursor: &mut usize) -> Result<DerElement, DaneError> {
    read_der_element_with_limit(data, cursor, data.len())
}

fn read_der_element_with_limit(
    data: &[u8],
    cursor: &mut usize,
    limit: usize,
) -> Result<DerElement, DaneError> {
    let start = *cursor;
    if start.checked_add(2).is_none_or(|end| end > limit) {
        return Err(DaneError::MalformedCertificate);
    }

    let tag = data[start];
    *cursor = start + 1;
    let length = read_der_length(data, cursor, limit)?;
    let value_start = *cursor;
    let end = value_start
        .checked_add(length)
        .ok_or(DaneError::MalformedCertificate)?;
    if end > limit {
        return Err(DaneError::MalformedCertificate);
    }

    *cursor = end;
    Ok(DerElement {
        tag,
        start,
        value_start,
        end,
    })
}

fn read_der_length(data: &[u8], cursor: &mut usize, limit: usize) -> Result<usize, DaneError> {
    let first = *data.get(*cursor).ok_or(DaneError::MalformedCertificate)?;
    *cursor += 1;

    if first & 0x80 == 0 {
        return Ok(first as usize);
    }

    let length_octets = (first & 0x7f) as usize;
    if length_octets == 0 || length_octets > std::mem::size_of::<usize>() {
        return Err(DaneError::MalformedCertificate);
    }
    if cursor
        .checked_add(length_octets)
        .is_none_or(|end| end > limit)
    {
        return Err(DaneError::MalformedCertificate);
    }
    if data[*cursor] == 0 {
        return Err(DaneError::MalformedCertificate);
    }

    let mut length = 0usize;
    for _ in 0..length_octets {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(data[*cursor] as usize))
            .ok_or(DaneError::MalformedCertificate)?;
        *cursor += 1;
    }

    if length < 128 {
        return Err(DaneError::MalformedCertificate);
    }

    Ok(length)
}

fn skip_der_element(data: &[u8], cursor: &mut usize, limit: usize) -> Result<(), DaneError> {
    read_der_element_with_limit(data, cursor, limit).map(|_| ())
}

fn peek_der_tag(data: &[u8], cursor: usize, limit: usize) -> Result<Option<u8>, DaneError> {
    if cursor == limit {
        Ok(None)
    } else if cursor < limit {
        Ok(Some(data[cursor]))
    } else {
        Err(DaneError::MalformedCertificate)
    }
}

struct RawCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> RawCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, DaneError> {
        let byte = *self
            .data
            .get(self.offset)
            .ok_or(DaneError::MalformedCertificateEvidence)?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_u16_be(&mut self) -> Result<u16, DaneError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], DaneError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(DaneError::MalformedCertificateEvidence)?;
        let bytes = self
            .data
            .get(self.offset..end)
            .ok_or(DaneError::MalformedCertificateEvidence)?;
        self.offset = end;
        Ok(bytes)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tlsa_311() {
        let mut rdata = vec![3, 1, 1];
        rdata.extend([7u8; 32]);
        let record = TlsaRecord::parse_rdata(&rdata).unwrap();

        assert_eq!(record.usage, TlsaUsage::DaneEe);
        assert_eq!(record.selector, TlsaSelector::SubjectPublicKeyInfo);
        assert_eq!(record.matching, TlsaMatching::Sha256);
    }

    #[test]
    fn matches_sha256_spki() {
        let spki = b"spki";
        let mut rdata = vec![3, 1, 1];
        rdata.extend(Sha256::digest(spki));
        let record = TlsaRecord::parse_rdata(&rdata).unwrap();

        assert!(record.matches_der(b"cert", spki));
    }

    #[test]
    fn strict_hns_requires_tlsa() {
        let decision = evaluate_policy(DaneValidationInput {
            mode: DomainTrustMode::HnsStrict,
            dnssec_secure: true,
            tlsa_records: &[],
            cert_der: b"cert",
            spki_der: b"spki",
            webpki_status: WebPkiStatus::Valid,
        });

        assert_eq!(decision.unwrap_err(), DaneError::MissingRequiredTlsa);
    }

    #[test]
    fn insecure_tlsa_fails_closed() {
        let record = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Exact,
            association_data: b"spki".to_vec(),
        };
        let decision = evaluate_policy(DaneValidationInput {
            mode: DomainTrustMode::HnsStrict,
            dnssec_secure: false,
            tlsa_records: &[record],
            cert_der: b"cert",
            spki_der: b"spki",
            webpki_status: WebPkiStatus::Valid,
        });

        assert_eq!(decision.unwrap_err(), DaneError::InsecureTlsa);
    }

    #[test]
    fn icann_mode_allows_valid_webpki_without_tlsa() {
        let decision = evaluate_policy(DaneValidationInput {
            mode: DomainTrustMode::IcannWebPki,
            dnssec_secure: true,
            tlsa_records: &[],
            cert_der: b"cert",
            spki_der: b"spki",
            webpki_status: WebPkiStatus::Valid,
        })
        .unwrap();

        assert_eq!(decision, DaneDecision::WebPkiFallback);
    }

    #[test]
    fn extracts_subject_public_key_info_from_v3_certificate() {
        let spki = test_spki();
        let cert = test_certificate(true, &spki);

        assert_eq!(extract_spki_der(&cert).unwrap(), spki);
    }

    #[test]
    fn extracts_subject_public_key_info_from_v1_certificate() {
        let spki = test_spki();
        let cert = test_certificate(false, &spki);

        assert_eq!(extract_spki_der(&cert).unwrap(), spki);
    }

    #[test]
    fn extracts_long_form_subject_public_key_info() {
        let mut key_bits = vec![0x00];
        key_bits.extend([0x5a; 160]);
        let spki = der(
            0x30,
            &[algorithm_identifier(), der(0x03, &key_bits)].concat(),
        );
        let cert = test_certificate(true, &spki);

        assert_eq!(extract_spki_der(&cert).unwrap(), spki);
    }

    #[test]
    fn rejects_malformed_certificate_der() {
        assert_eq!(
            extract_spki_der(&[0x30, 0x03, 0x02, 0x01]).unwrap_err(),
            DaneError::MalformedCertificate,
        );
    }

    #[test]
    fn rejects_non_minimal_long_form_length() {
        assert_eq!(
            extract_spki_der(&[0x30, 0x81, 0x01, 0x00]).unwrap_err(),
            DaneError::MalformedCertificate,
        );
    }

    #[test]
    fn extracts_experimental_stateless_dane_certificate_extensions() {
        let cert = test_certificate_with_extensions(&[
            (EXPERIMENTAL_HIP17_URKEL_PROOF_OID, b"proofs".as_slice()),
            (EXPERIMENTAL_HIP17_DNSSEC_CHAIN_OID, b"chain".as_slice()),
        ]);

        assert_eq!(
            certificate_extension_values(&cert, EXPERIMENTAL_HIP17_URKEL_PROOF_OID).unwrap(),
            vec![b"proofs".to_vec()],
        );
        assert_eq!(
            certificate_extension_values(&cert, EXPERIMENTAL_HIP17_DNSSEC_CHAIN_OID).unwrap(),
            vec![b"chain".to_vec()],
        );
    }

    #[test]
    fn certificate_policy_helper_matches_spki_tlsa() {
        let spki = test_spki();
        let cert = test_certificate(true, &spki);
        let record = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Sha256,
            association_data: Sha256::digest(&spki).to_vec(),
        };

        let decision = evaluate_policy_with_certificate(DaneCertificateValidationInput {
            mode: DomainTrustMode::HnsStrict,
            dnssec_secure: true,
            tlsa_records: &[record],
            cert_der: &cert,
            webpki_status: WebPkiStatus::NotEvaluated,
        })
        .unwrap();

        assert_eq!(decision, DaneDecision::Matched(TlsaUsage::DaneEe));
    }

    #[test]
    fn certificate_chain_policy_matches_intermediate_dane_ta() {
        let leaf_spki = test_spki_with_key(&[0x00, 0x01, 0x02]);
        let intermediate_spki = test_spki_with_key(&[0x00, 0x09, 0x09]);
        let leaf_cert = test_certificate(true, &leaf_spki);
        let intermediate_cert = test_certificate(true, &intermediate_spki);
        let intermediates = vec![intermediate_cert.as_slice()];
        let record = TlsaRecord {
            usage: TlsaUsage::DaneTa,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Sha256,
            association_data: Sha256::digest(&intermediate_spki).to_vec(),
        };

        let decision =
            evaluate_policy_with_certificate_chain(DaneCertificateChainValidationInput {
                mode: DomainTrustMode::HnsStrict,
                dnssec_secure: true,
                tlsa_records: &[record],
                end_entity_der: &leaf_cert,
                intermediate_der: &intermediates,
                webpki_status: WebPkiStatus::NotEvaluated,
            })
            .unwrap();

        assert_eq!(decision, DaneDecision::Matched(TlsaUsage::DaneTa));
    }

    #[test]
    fn certificate_chain_policy_does_not_match_dane_ta_on_leaf_only() {
        let leaf_spki = test_spki();
        let leaf_cert = test_certificate(true, &leaf_spki);
        let record = TlsaRecord {
            usage: TlsaUsage::DaneTa,
            selector: TlsaSelector::FullCertificate,
            matching: TlsaMatching::Exact,
            association_data: leaf_cert.clone(),
        };

        let decision =
            evaluate_policy_with_certificate_chain(DaneCertificateChainValidationInput {
                mode: DomainTrustMode::HnsStrict,
                dnssec_secure: true,
                tlsa_records: &[record],
                end_entity_der: &leaf_cert,
                intermediate_der: &[],
                webpki_status: WebPkiStatus::NotEvaluated,
            })
            .unwrap();

        assert_eq!(decision, DaneDecision::Failed);
    }

    #[test]
    fn pkix_tlsa_usage_requires_valid_webpki() {
        let spki = test_spki();
        let cert = test_certificate(true, &spki);
        let record = TlsaRecord {
            usage: TlsaUsage::PkixEe,
            selector: TlsaSelector::FullCertificate,
            matching: TlsaMatching::Exact,
            association_data: cert.clone(),
        };

        let invalid_webpki =
            evaluate_policy_with_certificate_chain(DaneCertificateChainValidationInput {
                mode: DomainTrustMode::HnsStrict,
                dnssec_secure: true,
                tlsa_records: std::slice::from_ref(&record),
                end_entity_der: &cert,
                intermediate_der: &[],
                webpki_status: WebPkiStatus::Invalid,
            });
        let valid_webpki =
            evaluate_policy_with_certificate_chain(DaneCertificateChainValidationInput {
                mode: DomainTrustMode::HnsStrict,
                dnssec_secure: true,
                tlsa_records: &[record],
                end_entity_der: &cert,
                intermediate_der: &[],
                webpki_status: WebPkiStatus::Valid,
            })
            .unwrap();

        assert_eq!(invalid_webpki.unwrap_err(), DaneError::WebPkiFailed);
        assert_eq!(valid_webpki, DaneDecision::Matched(TlsaUsage::PkixEe));
    }

    #[test]
    fn certificate_chain_policy_covers_usage_selector_matching_matrix() {
        let leaf_spki = test_spki_with_key(&[0x00, 0x01, 0x02]);
        let intermediate_spki = test_spki_with_key(&[0x00, 0x09, 0x09]);
        let leaf_cert = test_certificate(true, &leaf_spki);
        let intermediate_cert = test_certificate(true, &intermediate_spki);
        let intermediates = vec![intermediate_cert.as_slice()];

        for usage in [
            TlsaUsage::PkixTa,
            TlsaUsage::PkixEe,
            TlsaUsage::DaneTa,
            TlsaUsage::DaneEe,
        ] {
            for selector in [
                TlsaSelector::FullCertificate,
                TlsaSelector::SubjectPublicKeyInfo,
            ] {
                for matching in [
                    TlsaMatching::Exact,
                    TlsaMatching::Sha256,
                    TlsaMatching::Sha512,
                ] {
                    let source = match (usage, selector) {
                        (TlsaUsage::PkixTa | TlsaUsage::DaneTa, TlsaSelector::FullCertificate) => {
                            intermediate_cert.as_slice()
                        }
                        (
                            TlsaUsage::PkixTa | TlsaUsage::DaneTa,
                            TlsaSelector::SubjectPublicKeyInfo,
                        ) => intermediate_spki.as_slice(),
                        (TlsaUsage::PkixEe | TlsaUsage::DaneEe, TlsaSelector::FullCertificate) => {
                            leaf_cert.as_slice()
                        }
                        (
                            TlsaUsage::PkixEe | TlsaUsage::DaneEe,
                            TlsaSelector::SubjectPublicKeyInfo,
                        ) => leaf_spki.as_slice(),
                    };
                    let record = TlsaRecord {
                        usage,
                        selector,
                        matching,
                        association_data: association_data(matching, source),
                    };

                    let decision = evaluate_policy_with_certificate_chain(
                        DaneCertificateChainValidationInput {
                            mode: DomainTrustMode::HnsStrict,
                            dnssec_secure: true,
                            tlsa_records: &[record],
                            end_entity_der: &leaf_cert,
                            intermediate_der: &intermediates,
                            webpki_status: WebPkiStatus::Valid,
                        },
                    )
                    .unwrap();

                    assert_eq!(decision, DaneDecision::Matched(usage));
                }
            }
        }
    }

    #[test]
    fn certificate_chain_policy_rejects_wrong_cert_or_spki_association() {
        let leaf_spki = test_spki_with_key(&[0x00, 0x01, 0x02]);
        let intermediate_spki = test_spki_with_key(&[0x00, 0x09, 0x09]);
        let leaf_cert = test_certificate(true, &leaf_spki);
        let intermediate_cert = test_certificate(true, &intermediate_spki);
        let intermediates = vec![intermediate_cert.as_slice()];
        let wrong_cert = test_certificate(true, &test_spki_with_key(&[0x00, 0xaa, 0xbb]));
        let records = [
            TlsaRecord {
                usage: TlsaUsage::DaneEe,
                selector: TlsaSelector::FullCertificate,
                matching: TlsaMatching::Exact,
                association_data: wrong_cert.clone(),
            },
            TlsaRecord {
                usage: TlsaUsage::DaneEe,
                selector: TlsaSelector::SubjectPublicKeyInfo,
                matching: TlsaMatching::Sha256,
                association_data: Sha256::digest(b"wrong-spki").to_vec(),
            },
            TlsaRecord {
                usage: TlsaUsage::DaneTa,
                selector: TlsaSelector::SubjectPublicKeyInfo,
                matching: TlsaMatching::Sha512,
                association_data: Sha512::digest(b"wrong-intermediate-spki").to_vec(),
            },
        ];

        for record in records {
            let decision =
                evaluate_policy_with_certificate_chain(DaneCertificateChainValidationInput {
                    mode: DomainTrustMode::HnsStrict,
                    dnssec_secure: true,
                    tlsa_records: &[record],
                    end_entity_der: &leaf_cert,
                    intermediate_der: &intermediates,
                    webpki_status: WebPkiStatus::NotEvaluated,
                })
                .unwrap();

            assert_eq!(decision, DaneDecision::Failed);
        }
    }

    fn test_certificate(include_version: bool, spki: &[u8]) -> Vec<u8> {
        test_certificate_with_extensions_and_spki(include_version, spki, &[])
    }

    fn test_certificate_with_extensions(values: &[(&str, &[u8])]) -> Vec<u8> {
        test_certificate_with_extensions_and_spki(true, &test_spki(), values)
    }

    fn test_certificate_with_extensions_and_spki(
        include_version: bool,
        spki: &[u8],
        extension_values: &[(&str, &[u8])],
    ) -> Vec<u8> {
        let mut tbs_fields = Vec::new();
        if include_version {
            tbs_fields.extend(der(0xa0, &der(0x02, &[0x02])));
        }
        tbs_fields.extend(der(0x02, &[0x01]));
        tbs_fields.extend(algorithm_identifier());
        tbs_fields.extend(der(0x30, &[]));
        tbs_fields.extend(der(
            0x30,
            &[der(0x17, b"260101000000Z"), der(0x17, b"270101000000Z")].concat(),
        ));
        tbs_fields.extend(der(0x30, &[]));
        tbs_fields.extend(spki);
        if include_version {
            let extensions = extension_values
                .iter()
                .flat_map(|(oid, value)| extension_der(oid, value))
                .collect::<Vec<_>>();
            tbs_fields.extend(der(0xa3, &der(0x30, &extensions)));
        }

        der(
            0x30,
            &[
                der(0x30, &tbs_fields),
                algorithm_identifier(),
                der(0x03, &[0x00, 0x00]),
            ]
            .concat(),
        )
    }

    fn test_spki() -> Vec<u8> {
        test_spki_with_key(&[0x00, 0x01, 0x02])
    }

    fn test_spki_with_key(key_bits: &[u8]) -> Vec<u8> {
        der(
            0x30,
            &[algorithm_identifier(), der(0x03, key_bits)].concat(),
        )
    }

    fn algorithm_identifier() -> Vec<u8> {
        der(
            0x30,
            &[der(0x06, &[0x2a, 0x86, 0x48]), der(0x05, &[])].concat(),
        )
    }

    fn extension_der(oid: &str, value: &[u8]) -> Vec<u8> {
        der(0x30, &[oid_der(oid), der(0x04, value)].concat())
    }

    fn oid_der(oid: &str) -> Vec<u8> {
        let arcs = oid
            .split('.')
            .map(|part| part.parse::<u32>().unwrap())
            .collect::<Vec<_>>();
        let mut value = vec![(arcs[0] * 40 + arcs[1]) as u8];
        for arc in arcs.iter().skip(2).copied() {
            let mut stack = vec![(arc & 0x7f) as u8];
            let mut next = arc >> 7;
            while next > 0 {
                stack.push(((next & 0x7f) as u8) | 0x80);
                next >>= 7;
            }
            value.extend(stack.iter().rev());
        }
        der(0x06, &value)
    }

    fn association_data(matching: TlsaMatching, source: &[u8]) -> Vec<u8> {
        match matching {
            TlsaMatching::Exact => source.to_vec(),
            TlsaMatching::Sha256 => Sha256::digest(source).to_vec(),
            TlsaMatching::Sha512 => Sha512::digest(source).to_vec(),
        }
    }

    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 128 {
            out.push(value.len() as u8);
        } else {
            let bytes = value.len().to_be_bytes();
            let first = bytes
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(bytes.len() - 1);
            out.push(0x80 | (bytes.len() - first) as u8);
            out.extend(&bytes[first..]);
        }
        out.extend(value);
        out
    }
}
