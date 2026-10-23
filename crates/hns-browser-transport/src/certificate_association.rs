//! TLSA trust-anchor decisions bound to a verified certificate path.

use hns_dane::{
    DaneCertificateValidationInput, DaneDecision, DaneError, TlsaMatching, TlsaPathVerifier,
    TlsaRecord, TlsaSelector, evaluate_policy_with_path_verifier,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime};
use std::collections::HashSet;
use webpki::{EndEntityCert, KeyUsage, VerifiedPath};
use x509_parser::parse_x509_certificate;
use x509_parser::time::ASN1Time;

const MAX_DANE_TA_CANDIDATES: usize = 64;

pub(crate) fn evaluate_verified_certificate_association(
    input: DaneCertificateValidationInput<'_>,
    intermediate_der: &[&[u8]],
    server_name: &ServerName<'_>,
    now: UnixTime,
    roots: &RootCertStore,
    supported_algs: &[&dyn SignatureVerificationAlgorithm],
) -> Result<DaneDecision, DaneError> {
    let verifier = RustlsPathVerifier {
        end_entity_der: CertificateDer::from(input.cert_der.to_vec()),
        intermediates: intermediate_der
            .iter()
            .map(|der| CertificateDer::from(der.to_vec()))
            .collect(),
        server_name: server_name.to_owned(),
        now,
        roots,
        supported_algs,
    };
    evaluate_policy_with_path_verifier(input, &verifier)
}

struct RustlsPathVerifier<'a, 'b> {
    end_entity_der: CertificateDer<'static>,
    intermediates: Vec<CertificateDer<'static>>,
    server_name: ServerName<'static>,
    now: UnixTime,
    roots: &'a RootCertStore,
    supported_algs: &'b [&'b dyn SignatureVerificationAlgorithm],
}

impl TlsaPathVerifier for RustlsPathVerifier<'_, '_> {
    fn matches_pkix_ta(&self, records: &[&TlsaRecord]) -> bool {
        verify_pkix_ta(
            records,
            &self.end_entity_der,
            &self.intermediates,
            &self.server_name,
            self.now,
            self.roots,
            self.supported_algs,
        )
    }

    fn matches_dane_ta(&self, records: &[&TlsaRecord]) -> bool {
        verify_dane_ta(
            records,
            &self.end_entity_der,
            &self.intermediates,
            &self.server_name,
            self.now,
            self.supported_algs,
        )
    }
}

fn verify_pkix_ta(
    records: &[&TlsaRecord],
    end_entity_der: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    now: UnixTime,
    roots: &RootCertStore,
    supported_algs: &[&dyn SignatureVerificationAlgorithm],
) -> bool {
    let Ok(end_entity) = EndEntityCert::try_from(end_entity_der) else {
        return false;
    };
    if end_entity
        .verify_is_valid_for_subject_name(server_name)
        .is_err()
    {
        return false;
    }

    let match_path = |path: &VerifiedPath<'_>| {
        if records
            .iter()
            .any(|record| path_matches_pkix_ta(record, path))
        {
            Ok(())
        } else {
            Err(webpki::Error::UnknownIssuer)
        }
    };
    end_entity
        .verify_for_usage(
            supported_algs,
            &roots.roots,
            intermediates,
            now,
            KeyUsage::server_auth(),
            None,
            Some(&match_path),
        )
        .is_ok()
}

fn path_matches_pkix_ta(record: &TlsaRecord, path: &VerifiedPath<'_>) -> bool {
    if path.intermediate_certificates().any(|cert| {
        let spki = cert.subject_public_key_info();
        record.matches_der(cert.der().as_ref(), spki.as_ref())
    }) {
        return true;
    }

    match record.selector {
        TlsaSelector::SubjectPublicKeyInfo => record.matches_der(
            &[],
            &wrap_der_sequence(path.anchor().subject_public_key_info.as_ref()),
        ),
        // RootCertStore discards the root certificate's full DER. A root
        // certificate association cannot be established from its reduced
        // TrustAnchor, even if the peer or TLSA record supplies a certificate
        // with the same subject and key. Full-certificate matches above are
        // limited to intermediates on the verified path.
        TlsaSelector::FullCertificate => false,
    }
}

fn wrap_der_sequence(contents: &[u8]) -> Vec<u8> {
    let mut der = Vec::with_capacity(contents.len() + 10);
    der.push(0x30);
    if contents.len() < 128 {
        der.push(u8::try_from(contents.len()).unwrap_or(0));
    } else {
        let length = contents.len().to_be_bytes();
        let nonzero = length
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(length.len() - 1);
        der.push(0x80 | u8::try_from(length.len() - nonzero).unwrap_or(0));
        der.extend_from_slice(&length[nonzero..]);
    }
    der.extend_from_slice(contents);
    der
}

fn verify_dane_ta(
    records: &[&TlsaRecord],
    end_entity_der: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    now: UnixTime,
    supported_algs: &[&dyn SignatureVerificationAlgorithm],
) -> bool {
    let Ok(end_entity) = EndEntityCert::try_from(end_entity_der) else {
        return false;
    };
    if end_entity
        .verify_is_valid_for_subject_name(server_name)
        .is_err()
    {
        return false;
    }

    // Include full-certificate Exact anchors supplied by DNS, even when the
    // server omits that certificate. Deduplicate before parsing or verifying.
    let mut seen = HashSet::new();
    let mut candidate_bytes = Vec::new();
    for candidate in intermediates
        .iter()
        .map(AsRef::as_ref)
        .chain(records.iter().filter_map(|record| {
            (record.selector == TlsaSelector::FullCertificate
                && record.matching == TlsaMatching::Exact)
                .then_some(record.association_data.as_slice())
        }))
    {
        if seen.insert(candidate) {
            candidate_bytes.push(candidate);
            if candidate_bytes.len() > MAX_DANE_TA_CANDIDATES {
                return false;
            }
        }
    }

    let candidate_der = candidate_bytes
        .into_iter()
        .filter_map(|candidate| {
            let spki = hns_dane::extract_spki_der(candidate).ok()?;
            if !records
                .iter()
                .any(|record| record.matches_der(candidate, &spki))
            {
                return None;
            }
            let path_len_limit = valid_dane_ta(candidate, now)?;
            Some((CertificateDer::from(candidate.to_vec()), path_len_limit))
        })
        .collect::<Vec<_>>();
    let mut anchors = Vec::new();
    let mut path_len_limits = Vec::new();
    for (certificate, limit) in &candidate_der {
        if let Ok(anchor) = webpki::anchor_from_trusted_cert(certificate) {
            anchors.push(anchor);
            path_len_limits.push(*limit);
        }
    }
    if anchors.is_empty() {
        return false;
    }

    let check_path = |path: &VerifiedPath<'_>| {
        let Some(index) = anchors
            .iter()
            .position(|anchor| std::ptr::eq(anchor, path.anchor()))
        else {
            return Err(webpki::Error::UnknownIssuer);
        };
        if path_len_limits[index]
            .is_some_and(|limit| path.intermediate_certificates().count() > limit)
        {
            return Err(webpki::Error::UnknownIssuer);
        }
        Ok(())
    };
    end_entity
        .verify_for_usage(
            supported_algs,
            &anchors,
            intermediates,
            now,
            KeyUsage::server_auth(),
            None,
            Some(&check_path),
        )
        .is_ok()
}

fn valid_dane_ta(candidate: &[u8], now: UnixTime) -> Option<Option<usize>> {
    let (remaining, cert) = parse_x509_certificate(candidate).ok()?;
    if !remaining.is_empty() {
        return None;
    }
    let now = ASN1Time::from_timestamp(i64::try_from(now.as_secs()).ok()?).ok()?;
    if !cert.validity().is_valid_at(now) {
        return None;
    }
    let constraints = cert.basic_constraints().ok()??;
    if !constraints.value.ca {
        return None;
    }
    if cert
        .key_usage()
        .ok()?
        .is_some_and(|usage| !usage.value.key_cert_sign())
    {
        return None;
    }
    Some(
        constraints
            .value
            .path_len_constraint
            .map(|limit| limit as usize),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_dane::{TlsaUsage, WebPkiStatus};
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    struct SignedChain {
        leaf: Vec<u8>,
        issuer: Vec<u8>,
    }

    fn signed_chain(host: &str) -> SignedChain {
        let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        signed_chain_with_issuer(host, issuer_params)
    }

    fn signed_chain_with_issuer(host: &str, issuer_params: CertificateParams) -> SignedChain {
        let issuer =
            CertifiedIssuer::self_signed(issuer_params, KeyPair::generate().unwrap()).unwrap();

        let mut leaf_params = CertificateParams::new(vec![host.to_owned()]).unwrap();
        leaf_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        leaf_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let leaf = leaf_params
            .signed_by(&KeyPair::generate().unwrap(), &issuer)
            .unwrap();
        SignedChain {
            leaf: leaf.der().to_vec(),
            issuer: issuer.der().to_vec(),
        }
    }

    fn record(usage: TlsaUsage, certificate: &[u8]) -> TlsaRecord {
        TlsaRecord {
            usage,
            selector: TlsaSelector::FullCertificate,
            matching: TlsaMatching::Exact,
            association_data: certificate.to_vec(),
        }
    }

    fn evaluate(
        records: &[TlsaRecord],
        leaf: &[u8],
        extras: &[&[u8]],
        roots: &RootCertStore,
        webpki_status: WebPkiStatus,
    ) -> Result<DaneDecision, DaneError> {
        let provider = rustls::crypto::ring::default_provider();
        let server_name = ServerName::try_from("example.com").unwrap();
        evaluate_verified_certificate_association(
            DaneCertificateValidationInput {
                mode: hns_dane::DomainTrustMode::HnsStrict,
                dnssec_secure: true,
                tlsa_records: records,
                cert_der: leaf,
                webpki_status,
            },
            extras,
            &server_name,
            UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
            roots,
            provider.signature_verification_algorithms.all,
        )
    }

    #[test]
    fn dane_ta_requires_a_signed_path_to_the_matched_ca() {
        let issued = signed_chain("example.com");
        let unrelated = signed_chain("example.com");
        let pinned = record(TlsaUsage::DaneTa, &unrelated.issuer);
        let roots = RootCertStore::empty();

        assert_eq!(
            evaluate(
                std::slice::from_ref(&pinned),
                &issued.leaf,
                &[&unrelated.issuer],
                &roots,
                WebPkiStatus::Invalid,
            )
            .unwrap(),
            DaneDecision::Failed
        );
        assert_eq!(
            evaluate(
                &[record(TlsaUsage::DaneTa, &issued.issuer)],
                &issued.leaf,
                &[&issued.issuer],
                &roots,
                WebPkiStatus::Invalid,
            )
            .unwrap(),
            DaneDecision::Matched(TlsaUsage::DaneTa)
        );
    }

    #[test]
    fn pkix_ta_requires_a_match_on_the_verified_path() {
        let issued = signed_chain("example.com");
        let unrelated = signed_chain("example.com");
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(issued.issuer.clone()))
            .unwrap();

        assert_eq!(
            evaluate(
                &[record(TlsaUsage::PkixTa, &unrelated.issuer)],
                &issued.leaf,
                &[&issued.issuer, &unrelated.issuer],
                &roots,
                WebPkiStatus::Valid,
            )
            .unwrap(),
            DaneDecision::Failed
        );

        let issuer_spki = hns_dane::extract_spki_der(&issued.issuer).unwrap();
        let root_record = TlsaRecord {
            usage: TlsaUsage::PkixTa,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching: TlsaMatching::Exact,
            association_data: issuer_spki,
        };
        assert_eq!(
            evaluate(
                &[root_record],
                &issued.leaf,
                &[],
                &roots,
                WebPkiStatus::Valid,
            )
            .unwrap(),
            DaneDecision::Matched(TlsaUsage::PkixTa)
        );

        // The root store cannot prove a full-certificate association when it
        // has discarded the root's DER, even if DNS supplies those bytes.
        assert_eq!(
            evaluate(
                &[record(TlsaUsage::PkixTa, &issued.issuer)],
                &issued.leaf,
                &[],
                &roots,
                WebPkiStatus::Valid,
            )
            .unwrap(),
            DaneDecision::Failed
        );
    }

    #[test]
    fn pkix_ta_reports_webpki_rejection() {
        let issued = signed_chain("example.com");
        assert_eq!(
            evaluate(
                &[record(TlsaUsage::PkixTa, &issued.issuer)],
                &issued.leaf,
                &[&issued.issuer],
                &RootCertStore::empty(),
                WebPkiStatus::Invalid,
            )
            .unwrap_err(),
            DaneError::WebPkiFailed
        );
    }

    #[test]
    fn dane_ta_considers_all_matched_anchors_regardless_of_record_order() {
        let issued = signed_chain("example.com");
        let unrelated = signed_chain("example.com");
        for records in [
            vec![
                record(TlsaUsage::DaneTa, &unrelated.issuer),
                record(TlsaUsage::DaneTa, &issued.issuer),
                record(TlsaUsage::DaneTa, &issued.issuer),
            ],
            vec![
                record(TlsaUsage::DaneTa, &issued.issuer),
                record(TlsaUsage::DaneTa, &unrelated.issuer),
            ],
        ] {
            assert_eq!(
                evaluate(
                    &records,
                    &issued.leaf,
                    &[&unrelated.issuer, &issued.issuer],
                    &RootCertStore::empty(),
                    WebPkiStatus::Invalid,
                )
                .unwrap(),
                DaneDecision::Matched(TlsaUsage::DaneTa)
            );
        }
    }

    #[test]
    fn dane_ta_enforces_selected_anchor_path_length() {
        let mut ta_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ta_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ta_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        let ta = CertifiedIssuer::self_signed(ta_params, KeyPair::generate().unwrap()).unwrap();

        let mut sub_ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        sub_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        sub_ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        let sub_ca =
            CertifiedIssuer::signed_by(sub_ca_params, KeyPair::generate().unwrap(), &ta).unwrap();
        let leaf = CertificateParams::new(vec!["example.com".to_owned()])
            .unwrap()
            .signed_by(&KeyPair::generate().unwrap(), &sub_ca)
            .unwrap();

        assert_eq!(
            evaluate(
                &[record(TlsaUsage::DaneTa, ta.der().as_ref())],
                leaf.der().as_ref(),
                &[sub_ca.der().as_ref(), ta.der().as_ref()],
                &RootCertStore::empty(),
                WebPkiStatus::Invalid,
            )
            .unwrap(),
            DaneDecision::Failed
        );
    }

    #[test]
    fn pkix_ta_full_certificate_must_not_match_a_different_root_with_the_same_key() {
        let key = KeyPair::generate().unwrap();
        let mut pinned_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        pinned_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        pinned_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        pinned_params.serial_number = Some(1u64.into());
        let pinned = pinned_params.self_signed(&key).unwrap();

        let mut trusted_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        trusted_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        trusted_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        trusted_params.serial_number = Some(2u64.into());
        let trusted = CertifiedIssuer::self_signed(trusted_params, key).unwrap();

        let leaf = CertificateParams::new(vec!["example.com".to_owned()])
            .unwrap()
            .signed_by(&KeyPair::generate().unwrap(), &trusted)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(trusted.der().clone()).unwrap();
        assert_ne!(pinned.der(), trusted.der());

        assert_eq!(
            evaluate(
                &[record(TlsaUsage::PkixTa, pinned.der().as_ref())],
                leaf.der().as_ref(),
                &[],
                &roots,
                WebPkiStatus::Valid,
            )
            .unwrap(),
            DaneDecision::Failed
        );
    }

    #[test]
    fn pkix_ta_full_certificate_matches_an_intermediate_on_the_verified_path() {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        let root =
            CertifiedIssuer::self_signed(ca_params.clone(), KeyPair::generate().unwrap()).unwrap();
        let intermediate =
            CertifiedIssuer::signed_by(ca_params, KeyPair::generate().unwrap(), &root).unwrap();
        let leaf = CertificateParams::new(vec!["example.com".to_owned()])
            .unwrap()
            .signed_by(&KeyPair::generate().unwrap(), &intermediate)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(root.der().clone()).unwrap();

        for association in [
            record(TlsaUsage::PkixTa, intermediate.der().as_ref()),
            TlsaRecord {
                usage: TlsaUsage::PkixTa,
                selector: TlsaSelector::FullCertificate,
                matching: TlsaMatching::Sha256,
                association_data: Sha256::digest(intermediate.der().as_ref()).to_vec(),
            },
        ] {
            assert_eq!(
                evaluate(
                    &[association],
                    leaf.der().as_ref(),
                    &[intermediate.der().as_ref()],
                    &roots,
                    WebPkiStatus::Valid,
                )
                .unwrap(),
                DaneDecision::Matched(TlsaUsage::PkixTa)
            );
        }
    }

    #[test]
    fn dane_ta_accepts_full_certificate_anchor_from_dns() {
        let issued = signed_chain("example.com");
        assert_eq!(
            evaluate(
                &[record(TlsaUsage::DaneTa, &issued.issuer)],
                &issued.leaf,
                &[],
                &RootCertStore::empty(),
                WebPkiStatus::Invalid,
            )
            .unwrap(),
            DaneDecision::Matched(TlsaUsage::DaneTa)
        );
    }

    #[test]
    fn dane_ta_rejects_wrong_leaf_name() {
        let issued = signed_chain("other.example");
        assert_eq!(
            evaluate(
                &[record(TlsaUsage::DaneTa, &issued.issuer)],
                &issued.leaf,
                &[&issued.issuer],
                &RootCertStore::empty(),
                WebPkiStatus::Invalid,
            )
            .unwrap(),
            DaneDecision::Failed
        );
    }

    #[test]
    fn dane_ee_uses_the_dnssec_tlsa_name_binding() {
        let issued = signed_chain("other.example");
        assert_eq!(
            evaluate(
                &[record(TlsaUsage::DaneEe, &issued.leaf)],
                &issued.leaf,
                &[],
                &RootCertStore::empty(),
                WebPkiStatus::Invalid,
            )
            .unwrap(),
            DaneDecision::Matched(TlsaUsage::DaneEe)
        );
    }

    #[test]
    fn dane_ta_rejects_expired_or_non_ca_anchor() {
        let mut expired_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        expired_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        expired_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        expired_params.not_before = rcgen::date_time_ymd(2010, 1, 1);
        expired_params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        let expired = signed_chain_with_issuer("example.com", expired_params);

        let mut non_ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        non_ca_params.is_ca = IsCa::NoCa;
        non_ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        let non_ca = signed_chain_with_issuer("example.com", non_ca_params);

        for chain in [expired, non_ca] {
            assert_eq!(
                evaluate(
                    &[record(TlsaUsage::DaneTa, &chain.issuer)],
                    &chain.leaf,
                    &[&chain.issuer],
                    &RootCertStore::empty(),
                    WebPkiStatus::Invalid,
                )
                .unwrap(),
                DaneDecision::Failed
            );
        }
    }

    #[test]
    fn mixed_rrset_still_allows_a_valid_dane_ee_leaf() {
        let issued = signed_chain("example.com");
        let unrelated = signed_chain("example.com");
        let records = [
            record(TlsaUsage::DaneTa, &unrelated.issuer),
            record(TlsaUsage::DaneEe, &issued.leaf),
        ];
        assert_eq!(
            evaluate(
                &records,
                &issued.leaf,
                &[&unrelated.issuer],
                &RootCertStore::empty(),
                WebPkiStatus::Invalid,
            )
            .unwrap(),
            DaneDecision::Matched(TlsaUsage::DaneEe)
        );
    }

    #[test]
    fn malformed_extra_certificate_cannot_block_a_later_dane_ee_match() {
        let issued = signed_chain("example.com");
        let malformed = b"malformed certificate";
        let records = [
            record(TlsaUsage::DaneTa, malformed),
            record(TlsaUsage::DaneEe, &issued.leaf),
        ];

        assert_eq!(
            evaluate(
                &records,
                &issued.leaf,
                &[malformed],
                &RootCertStore::empty(),
                WebPkiStatus::Invalid,
            )
            .unwrap(),
            DaneDecision::Matched(TlsaUsage::DaneEe)
        );
    }
}
