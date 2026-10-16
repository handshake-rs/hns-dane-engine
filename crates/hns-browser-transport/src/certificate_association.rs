//! TLSA trust-anchor decisions bound to a verified certificate path.

use hns_dane::{
    DaneCertificateChainValidationInput, DaneDecision, DaneError, TlsaMatching, TlsaRecord,
    TlsaSelector, TlsaUsage, WebPkiStatus, evaluate_policy_with_certificate_chain,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime};
use webpki::{EndEntityCert, KeyUsage, VerifiedPath};
use x509_parser::parse_x509_certificate;
use x509_parser::time::ASN1Time;

pub(crate) fn evaluate_verified_certificate_association(
    input: DaneCertificateChainValidationInput<'_>,
    server_name: &ServerName<'_>,
    now: UnixTime,
    roots: &RootCertStore,
    supported_algs: &[&dyn SignatureVerificationAlgorithm],
) -> Result<DaneDecision, DaneError> {
    if input.tlsa_records.is_empty() {
        return evaluate_policy_with_certificate_chain(input);
    }
    if !input.dnssec_secure {
        return Err(DaneError::InsecureTlsa);
    }
    if input
        .tlsa_records
        .iter()
        .all(|record| matches!(record.usage, TlsaUsage::PkixEe | TlsaUsage::DaneEe))
    {
        return evaluate_policy_with_certificate_chain(input);
    }

    let end_entity_der = CertificateDer::from(input.end_entity_der);
    let intermediates = input
        .intermediate_der
        .iter()
        .map(|der| CertificateDer::from(*der))
        .collect::<Vec<_>>();
    let mut pkix_ee_rejected_by_webpki = false;

    for record in input.tlsa_records {
        match record.usage {
            TlsaUsage::PkixEe | TlsaUsage::DaneEe => {
                let decision =
                    evaluate_policy_with_certificate_chain(DaneCertificateChainValidationInput {
                        tlsa_records: std::slice::from_ref(record),
                        ..input.clone()
                    });
                match decision {
                    Ok(DaneDecision::Matched(usage)) => return Ok(DaneDecision::Matched(usage)),
                    Err(DaneError::WebPkiFailed) => pkix_ee_rejected_by_webpki = true,
                    Err(error) => return Err(error),
                    _ => {}
                }
            }
            TlsaUsage::PkixTa => {
                if input.webpki_status == WebPkiStatus::Valid
                    && verify_pkix_ta(
                        record,
                        &end_entity_der,
                        &intermediates,
                        server_name,
                        now,
                        roots,
                        supported_algs,
                    )
                {
                    return Ok(DaneDecision::Matched(TlsaUsage::PkixTa));
                }
            }
            TlsaUsage::DaneTa => {
                if verify_dane_ta(
                    record,
                    &end_entity_der,
                    &intermediates,
                    server_name,
                    now,
                    supported_algs,
                ) {
                    return Ok(DaneDecision::Matched(TlsaUsage::DaneTa));
                }
            }
        }
    }

    if pkix_ee_rejected_by_webpki {
        Err(DaneError::WebPkiFailed)
    } else {
        Ok(DaneDecision::Failed)
    }
}

fn verify_pkix_ta(
    record: &TlsaRecord,
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
        if path_matches_pkix_ta(record, path) {
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
    record: &TlsaRecord,
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

    let dns_anchor = (record.selector == TlsaSelector::FullCertificate
        && record.matching == TlsaMatching::Exact)
        .then(|| CertificateDer::from(record.association_data.as_slice()));
    let candidates = intermediates.iter().chain(dns_anchor.iter());
    for candidate in candidates {
        let spki = match hns_dane::extract_spki_der(candidate.as_ref()) {
            Ok(spki) => spki,
            Err(_) => continue,
        };
        if !record.matches_der(candidate.as_ref(), &spki) {
            continue;
        }
        let Some(path_len_limit) = valid_dane_ta(candidate.as_ref(), now) else {
            continue;
        };
        let Ok(anchor) = webpki::anchor_from_trusted_cert(candidate) else {
            continue;
        };
        let untrusted = intermediates
            .iter()
            .filter(|cert| cert.as_ref() != candidate.as_ref())
            .cloned()
            .collect::<Vec<_>>();
        let path = end_entity.verify_for_usage(
            supported_algs,
            std::slice::from_ref(&anchor),
            &untrusted,
            now,
            KeyUsage::server_auth(),
            None,
            None,
        );
        if path.is_ok_and(|path| {
            path_len_limit.is_none_or(|limit| path.intermediate_certificates().count() <= limit)
        }) {
            return true;
        }
    }
    false
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
            DaneCertificateChainValidationInput {
                mode: hns_dane::DomainTrustMode::HnsStrict,
                dnssec_secure: true,
                tlsa_records: records,
                end_entity_der: leaf,
                intermediate_der: extras,
                webpki_status,
            },
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
}
