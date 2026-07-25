//! Reusable full-path fixtures for Handshake browser security tests.
//!
//! The primary fixture mines one valid regtest header, verifies its committed
//! Urkel name proof, authenticates an HNS DNSKEY RRset from the resulting DS,
//! and signs a TLSA response for an exact HTTPS origin. It exposes only public
//! protocol evidence, never the temporary DNSSEC private key.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "HNS, DNSSEC, TLSA, and Urkel are protocol names"
)]

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_dns_wire::{
    Dnskey, Ds, Flags, Header, Message, Name, Query, Rdata, RecordType, ResourceRecord, Rrsig, Tlsa,
};
use hns_dnssec::{ALGORITHM_RSASHA256, DnssecLimits, dnskey_tag, rrsig_signed_data};
use hns_header_consensus::{Header as ConsensusHeader, Network as ConsensusNetwork};
use hns_light_chain::{ChainLimits, CurrencyPolicy, LightChain, VerifiedHnsResource};
use hns_primitives::{BlockTime, Chainwork, Height, TreeRoot};
use hns_resolver::{
    HnsDnssecAuthority, ResolutionStep, ResolverLimits, TlsaResolution, ValidatedTlsa,
};
use openssl::error::ErrorStack;
use openssl::hash::{MessageDigest, hash};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use thiserror::Error;

/// HNS TLD and exact HTTPS SNI used by the strict-path fixture.
pub const STRICT_HNS_ORIGIN: &str = "alpha";
/// DNS query identifier used by the strict-path fixture.
pub const STRICT_QUERY_ID: u16 = 0x4242;
/// Runtime session used by consumers that need a stable test identity.
pub const STRICT_RUNTIME_SESSION: [u8; 16] = [7; 16];

/// A complete locally verifiable HNS-to-DANE regtest exchange.
#[derive(Clone, Debug)]
pub struct StrictRegtestDaneFixture {
    authority: HnsDnssecAuthority,
    resolution: TlsaResolution,
    query: Query,
    response: Vec<u8>,
    certificate: Vec<u8>,
    validation_time: u32,
}

impl StrictRegtestDaneFixture {
    /// Build a fresh authenticated fixture.
    pub fn new() -> Result<Self, TestkitError> {
        let certificate = fixture_certificate()?;
        let (authority, key_pair, key, validation_time) = authenticated_hns_authority()?;
        let resolution = TlsaResolution::for_https(
            Name::from_ascii(&format!("{STRICT_HNS_ORIGIN}."))?,
            ResolverLimits::default(),
        )?;
        let query = resolution.query(STRICT_QUERY_ID)?;
        let tlsa_records = vec![ResourceRecord {
            name: query.question.name.clone(),
            record_type: RecordType::Tlsa,
            class: hns_dns_wire::CLASS_IN,
            ttl: 300,
            rdata: Rdata::Tlsa(Tlsa {
                usage: 3,
                selector: 0,
                matching_type: 0,
                association_data: certificate.clone(),
            }),
        }];
        let tlsa_record = tlsa_records
            .first()
            .ok_or(TestkitError::FixtureInvariant("TLSA RRset is empty"))?
            .clone();
        let response = Message {
            header: Header {
                id: query.id,
                flags: Flags::from_bits(0x8420),
                question_count: 1,
                answer_count: 2,
                authority_count: 0,
                additional_count: 0,
            },
            questions: vec![query.question.clone()],
            answers: vec![
                tlsa_record,
                sign_rrset_window(
                    &tlsa_records,
                    Name::from_ascii(&format!("{STRICT_HNS_ORIGIN}."))?,
                    &key,
                    &key_pair,
                    validation_time
                        .checked_sub(10)
                        .ok_or(TestkitError::FixtureInvariant(
                            "validation time is too small",
                        ))?,
                    validation_time
                        .checked_add(10)
                        .ok_or(TestkitError::FixtureInvariant("validation time overflows"))?,
                )?,
            ],
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
        .encode(u16::MAX.into())?;
        Ok(Self {
            authority,
            resolution,
            query,
            response,
            certificate,
            validation_time,
        })
    }

    /// DNSSEC authority authenticated from the regtest HNS name proof.
    #[must_use]
    pub const fn authority(&self) -> &HnsDnssecAuthority {
        &self.authority
    }

    /// Exact TLSA query that the response answers.
    #[must_use]
    pub const fn query(&self) -> &Query {
        &self.query
    }

    /// Encoded signed TLSA response.
    #[must_use]
    pub fn response(&self) -> &[u8] {
        &self.response
    }

    /// DER certificate whose exact bytes are authorized by TLSA.
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// Shared chain, DNSSEC, and DANE validation time.
    #[must_use]
    pub const fn validation_time(&self) -> u32 {
        self.validation_time
    }

    /// Validate the fixture response through the HNS-only resolver path.
    pub fn validate_response(&self, message: &Message) -> Result<ValidatedTlsa, TestkitError> {
        let mut resolution = self.resolution.clone();
        match resolution.accept_hns_response(&self.query, message, &self.authority)? {
            ResolutionStep::Complete(validated) => Ok(*validated),
            ResolutionStep::FollowCname(_) => Err(TestkitError::FixtureInvariant(
                "strict TLSA fixture unexpectedly followed CNAME",
            )),
        }
    }
}

fn fixture_certificate() -> Result<Vec<u8>, TestkitError> {
    decode_hex(include_str!(
        "../../../fixtures/dane/self-signed-cert.der.hex"
    ))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, TestkitError> {
    let compact = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if !compact.len().is_multiple_of(2) {
        return Err(TestkitError::FixtureInvariant(
            "hex fixture has an odd number of digits",
        ));
    }
    compact
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(*pair.first().ok_or(TestkitError::FixtureInvariant(
                "hex pair is missing its high digit",
            ))?)?;
            let low = hex_nibble(*pair.get(1).ok_or(TestkitError::FixtureInvariant(
                "hex pair is missing its low digit",
            ))?)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, TestkitError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(TestkitError::FixtureInvariant(
            "hex fixture contains a non-hex digit",
        )),
    }
}

fn rsa_dnskey(rsa: &Rsa<Private>) -> Result<Dnskey, TestkitError> {
    let exponent = rsa.e().to_vec();
    let modulus = rsa.n().to_vec();
    let mut public_key = Vec::with_capacity(exponent.len() + modulus.len() + 3);
    if exponent.len() < 256 {
        public_key.push(
            u8::try_from(exponent.len())
                .map_err(|_| TestkitError::FixtureInvariant("RSA exponent length overflows"))?,
        );
    } else {
        public_key.push(0);
        public_key.extend_from_slice(
            &u16::try_from(exponent.len())
                .map_err(|_| TestkitError::FixtureInvariant("RSA exponent length overflows"))?
                .to_be_bytes(),
        );
    }
    public_key.extend_from_slice(&exponent);
    public_key.extend_from_slice(&modulus);
    Ok(Dnskey {
        flags: 257,
        protocol: 3,
        algorithm: ALGORITHM_RSASHA256,
        public_key,
    })
}

fn sign_rrset_window(
    records: &[ResourceRecord],
    signer_name: Name,
    key: &Dnskey,
    key_pair: &PKey<Private>,
    inception: u32,
    expiration: u32,
) -> Result<ResourceRecord, TestkitError> {
    let first = records
        .first()
        .ok_or(TestkitError::FixtureInvariant("cannot sign an empty RRset"))?;
    let mut signature = Rrsig {
        type_covered: first.record_type,
        algorithm: key.algorithm,
        labels: u8::try_from(first.name.labels().len())
            .map_err(|_| TestkitError::FixtureInvariant("DNS label count overflows"))?,
        original_ttl: first.ttl,
        expiration,
        inception,
        key_tag: dnskey_tag(key),
        signer: signer_name,
        signature: Vec::new(),
    };
    let signed = rrsig_signed_data(records, &signature, 1024 * 1024)?;
    let mut crypto_signer = Signer::new(MessageDigest::sha256(), key_pair)?;
    crypto_signer.update(&signed)?;
    signature.signature = crypto_signer.sign_to_vec()?;
    Ok(ResourceRecord {
        name: first.name.clone(),
        record_type: RecordType::Rrsig,
        class: hns_dns_wire::CLASS_IN,
        ttl: first.ttl,
        rdata: Rdata::Rrsig(signature),
    })
}

fn blake2b_256(parts: &[&[u8]]) -> Result<[u8; 32], TestkitError> {
    let mut hasher = Blake2bVar::new(32)
        .map_err(|_| TestkitError::FixtureInvariant("invalid BLAKE2b output length"))?;
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| TestkitError::FixtureInvariant("invalid BLAKE2b output buffer"))?;
    Ok(output)
}

fn verified_hns_resource(ds: &Ds) -> Result<(VerifiedHnsResource, u32), TestkitError> {
    let genesis_time = ConsensusNetwork::Regtest.parameters().genesis_time;
    let validation_time = u32::try_from(
        genesis_time
            .get()
            .checked_add(100)
            .ok_or(TestkitError::FixtureInvariant("validation time overflows"))?,
    )
    .map_err(|_| TestkitError::FixtureInvariant("validation time exceeds u32"))?;
    let mut resource = vec![0, 0];
    resource.extend_from_slice(&ds.key_tag.to_be_bytes());
    resource.extend_from_slice(&[ds.algorithm, ds.digest_type]);
    resource.push(
        u8::try_from(ds.digest.len())
            .map_err(|_| TestkitError::FixtureInvariant("DS digest length overflows"))?,
    );
    resource.extend_from_slice(&ds.digest);
    let mut state = Vec::new();
    state.push(
        u8::try_from(STRICT_HNS_ORIGIN.len())
            .map_err(|_| TestkitError::FixtureInvariant("HNS label length overflows"))?,
    );
    state.extend_from_slice(STRICT_HNS_ORIGIN.as_bytes());
    state.extend_from_slice(
        &u16::try_from(resource.len())
            .map_err(|_| TestkitError::FixtureInvariant("resource length overflows"))?
            .to_le_bytes(),
    );
    state.extend_from_slice(&resource);
    state.extend_from_slice(&1_u32.to_le_bytes());
    state.extend_from_slice(&1_u32.to_le_bytes());
    state.extend_from_slice(&0_u16.to_le_bytes());

    let key = hns_covenants::hash_name(STRICT_HNS_ORIGIN.as_bytes())?;
    let value_hash = blake2b_256(&[&state])?;
    let tree_root = TreeRoot::new(blake2b_256(&[&[0], key.as_bytes(), &value_hash])?);
    let mut proof = Vec::new();
    proof.extend_from_slice(&0xc000_u16.to_le_bytes());
    proof.extend_from_slice(&0_u16.to_le_bytes());
    proof.extend_from_slice(
        &u16::try_from(state.len())
            .map_err(|_| TestkitError::FixtureInvariant("name state length overflows"))?
            .to_le_bytes(),
    );
    proof.extend_from_slice(&state);

    let now = BlockTime::new(u64::from(validation_time));
    let mut chain =
        LightChain::from_genesis(ConsensusNetwork::Regtest, now, ChainLimits::default())?;
    let mut header = ConsensusHeader {
        time: BlockTime::new(
            genesis_time
                .get()
                .checked_add(1)
                .ok_or(TestkitError::FixtureInvariant("header time overflows"))?,
        ),
        previous_block: chain.tip().hash(),
        tree_root,
        bits: ConsensusNetwork::Regtest.parameters().pow.bits,
        ..ConsensusHeader::default()
    };
    while !header.verify_pow() {
        header.nonce = header
            .nonce
            .checked_add(1)
            .ok_or(TestkitError::ProofOfWorkSearchExhausted)?;
    }
    chain.append(&header, now)?;
    let current = chain.require_current(CurrencyPolicy {
        now,
        maximum_tip_age_seconds: 3_600,
        minimum_height: Height::new(1),
        minimum_chainwork: Chainwork::ZERO,
    })?;
    Ok((
        current.verify_name_resource(STRICT_HNS_ORIGIN.as_bytes(), &proof)?,
        validation_time,
    ))
}

fn authenticated_hns_authority()
-> Result<(HnsDnssecAuthority, PKey<Private>, Dnskey, u32), TestkitError> {
    let zone = Name::from_ascii(&format!("{STRICT_HNS_ORIGIN}."))?;
    let rsa = Rsa::generate(1024)?;
    let key = rsa_dnskey(&rsa)?;
    let key_pair = PKey::from_rsa(rsa)?;
    let dnskeys = vec![ResourceRecord {
        name: zone.clone(),
        record_type: RecordType::Dnskey,
        class: hns_dns_wire::CLASS_IN,
        ttl: 300,
        rdata: Rdata::Dnskey(key.clone()),
    }];
    let mut key_rdata = Vec::new();
    key_rdata.extend_from_slice(&key.flags.to_be_bytes());
    key_rdata.push(key.protocol);
    key_rdata.push(key.algorithm);
    key_rdata.extend_from_slice(&key.public_key);
    let mut digest_input = Vec::new();
    zone.encode(&mut digest_input)?;
    digest_input.extend_from_slice(&key_rdata);
    let ds = Ds {
        key_tag: dnskey_tag(&key),
        algorithm: key.algorithm,
        digest_type: 2,
        digest: hash(MessageDigest::sha256(), &digest_input)?.to_vec(),
    };
    let (resource, validation_time) = verified_hns_resource(&ds)?;
    let inception = validation_time
        .checked_sub(10)
        .ok_or(TestkitError::FixtureInvariant(
            "validation time is too small",
        ))?;
    let expiration = validation_time
        .checked_add(10)
        .ok_or(TestkitError::FixtureInvariant("validation time overflows"))?;
    let signatures = vec![sign_rrset_window(
        &dnskeys, zone, &key, &key_pair, inception, expiration,
    )?];
    Ok((
        HnsDnssecAuthority::authenticate(
            &resource,
            &dnskeys,
            &signatures,
            validation_time,
            DnssecLimits::default(),
        )?,
        key_pair,
        key,
        validation_time,
    ))
}

/// Failure to construct or validate a browser security fixture.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TestkitError {
    /// HNS covenant name or resource encoding failed.
    #[error("HNS covenant fixture error: {0}")]
    Covenant(#[from] hns_covenants::CovenantError),
    /// DNS wire encoding or decoding failed.
    #[error("DNS wire fixture error: {0}")]
    DnsWire(#[from] hns_dns_wire::Error),
    /// DNSSEC signing or verification failed.
    #[error("DNSSEC fixture error: {0}")]
    Dnssec(#[from] hns_dnssec::DnssecError),
    /// Regtest header, currency, or Urkel proof verification failed.
    #[error("light-chain fixture error: {0}")]
    LightChain(#[from] hns_light_chain::LightChainError),
    /// TLSA resolution failed.
    #[error("resolver fixture error: {0}")]
    Resolver(#[from] hns_resolver::ResolverError),
    /// OpenSSL key generation, hashing, or signing failed.
    #[error("OpenSSL fixture error: {0}")]
    OpenSsl(#[from] ErrorStack),
    /// An internal static fixture assumption was violated.
    #[error("fixture invariant failed: {0}")]
    FixtureInvariant(&'static str),
    /// Regtest proof-of-work nonce space was exhausted.
    #[error("regtest proof-of-work search exhausted")]
    ProofOfWorkSearchExhausted,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid cryptographic fixtures"
)]
mod tests {
    use super::*;

    #[test]
    fn fixture_validates_header_proof_dnssec_and_tlsa() {
        let fixture = StrictRegtestDaneFixture::new().unwrap();
        let response = Message::parse(fixture.response()).unwrap();
        let validated = fixture.validate_response(&response).unwrap();

        assert_eq!(validated.base_domain_ascii(), STRICT_HNS_ORIGIN);
        assert_eq!(validated.records().len(), 1);
        assert_eq!(fixture.authority().anchor().height(), Height::new(1));
        assert_eq!(
            fixture.authority().validation_time(),
            fixture.validation_time()
        );
    }
}
