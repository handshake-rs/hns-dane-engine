# HNS browser security policy

For an HNS HTTPS origin, success requires all of:

1. locally validated Handshake state and a verified current Urkel proof;
2. a DNS response correlated to the exact local query;
3. local DNSSEC validation;
4. an exact, supported TLSA match;
5. local DANE origin validation, including SNI; and
6. an admission token from the current runtime and policy generations.

Local matching accepts DANE-EE usage 3 and DANE-TA usage 2. It supports full-certificate selector 0
and SPKI selector 1 with exact, SHA-256, and SHA-512 matching types 0, 1, and 2. Every terminal
record is checked for supported fields and association length before any match is accepted.
Certificate DER, extracted SPKI, chain length, RRset count, association data, CNAME hops, DNSSEC
records, and signed bytes are bounded. Empty, unsupported, malformed, oversized, unsigned, expired,
or nonmatching inputs fail closed.

PKIX usages 0/1 are rejected because there is no WebPKI trust path. DANE-TA builds a private X.509
path rooted only in the DNSSEC-selected trust anchor, checks certificate signatures, validity at an
explicit time, strict server-name matching, and chain bounds. It never loads a platform or public
root store. In accordance with RFC 7671, DANE-EE treats the DNSSEC-signed TLSA binding—not leaf
certificate names or dates—as the peer identity and validity period. The engine nevertheless
requires the actual origin SNI to equal the original TLSA base domain, as required by browser
policy.

RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256, ECDSA P-384, Ed25519, and Ed448 DNSSEC
signatures are checked locally. DS SHA-1, SHA-256, and SHA-384 are supported. DNSKEY RRsets must be
signed by a DS-matched zone key before their other keys can validate terminal data. CNAME and TLSA
RRsets are verified independently, loops and ambiguous CNAME/data coexistence fail, and NSEC/NSEC3
denial uses bounded closest-encloser and wildcard proofs.

The HNS DS set is not caller data. The light-chain gate validates every contiguous header from the
selected network genesis using shared `hns-rs` consensus code, requires explicit height, chainwork,
and tip-age currency, verifies a canonical Urkel inclusion proof at that header's exact tree root,
and strictly decodes the committed name state and resource. A private resource token is consumed to
authenticate the TLD DNSKEY. The resolver carries that anchor through every CNAME/TLSA response.
The engine rejects a missing lineage, another Handshake network, a different DNSSEC/DANE validation
time, or a caller-provided provenance anchor that conflicts with the derived header.

The present chain gate accepts only a single contiguous extension from genesis. It does not yet
perform peer synchronization or competing-fork selection; production activation remains blocked
until `hns-light-sync` supplies and selects the best validated chain.

The DNS AD bit, Brontide, a relay, an ODoH proxy, and an ODoH target are never validation
authorities. Transport status is reported separately from evidence status.

The only HNS resolution candidates are direct delegated-authoritative UDP/TCP, explicitly
authenticated authoritative DoH, Denuo Experimental V1 P2P ODoH, and Denuo Experimental V1 P2P DNS
Relay. The policy model contains no operating-system or public-recursive fallback variant.

Policy updates increment generations, immediately reject new disabled work, reject stale
completions, clear requester selections, and report provider withdrawal/peer renegotiation effects.
Provider roles default off. HNSR requester and provider roles default off.

The persisted policy CRC detects accidental corruption only. Platform adapters must use their normal
integrity-protected settings or secure storage; the CRC is not a MAC or signature.
