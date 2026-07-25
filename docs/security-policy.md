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

The standard peer layer admits only bounded HSD version/verack sessions and correlates one
outstanding header, proof, and ping request at finite deadlines. Multi-peer synchronization
validates every response on an independent chain clone, requires configurable agreement on the
unique greatest-work same-base extension, and rejects equal-work ambiguity. A chain is reported
current only after every selected peer responds, every consensus-valid response returns an empty
extension, and no non-banned peer advertises a higher height. Consensus-invalid responders may be
excluded only under the configured agreement and ban policy. Socket dialing, peer discovery,
durable checkpoints, and download/reorganization from a fork before the current base are not yet
implemented; production adapters must not treat the in-memory same-base synchronizer as durable
fork recovery.

The DNS AD bit, Brontide, a relay, an ODoH proxy, and an ODoH target are never validation
authorities. Transport status is reported separately from evidence status.

Shared status uses explicit `verified`, `failed`, `unavailable`, `unsupported`, `not attempted`,
`stale`, and `revoked` evidence values. It never contains qnames, URLs, DNS payloads, certificates,
or secrets. Actual transport identities are bounded and checked against the selected transport;
ODoH proxy and target must be present and distinct. Provider readiness must agree with explicit
provider roles, and rate-limit counters cannot claim impossible capacity or saturation states.

Cache entries use a per-runtime secret-derived opaque key and are bound to network, runtime and
policy generations, and the exact Handshake chain height/tree root. Positive and authenticated
negative TTLs have separate finite maxima. Entry count, per-value size, total value bytes, and LRU
state are bounded; expired or generation-mismatched entries are removed before any value is
returned. Cache metrics contain no qnames or values.

Direct UDP/TCP destinations are derived only from current proof-authenticated HNS resources. Glue
must be in bailiwick; mainnet/testnet addresses must be globally routable and use port 53.
Nonstandard ports are accepted only for explicit regtest loopback fixtures. Every exchange
rechecks the anchor validity window and exact query TLD before socket I/O, uses finite timeouts and
message bounds, sends a non-recursive DNSSEC query, and parses/correlates the complete response.

The only HNS resolution candidates are direct delegated-authoritative UDP/TCP, explicitly
authenticated authoritative DoH, Denuo Experimental V1 P2P ODoH, and Denuo Experimental V1 P2P DNS
Relay. The policy model contains no operating-system or public-recursive fallback variant.

Policy updates increment generations, immediately reject new disabled work, reject stale
completions, clear requester selections, and report provider withdrawal/peer renegotiation effects.
Provider roles default off. HNSR requester and provider roles default off.

Every admitted operation is stamped with the caller-supplied per-start unique runtime session,
current runtime generation, and monotonic event sequence. Parsing and completion reject another
session, a revoked generation, or an event that was never admitted. Platform adapters must supply a
fresh unpredictable session on every engine start; a constant or reused session violates this
replay-isolation contract.

The persisted policy CRC detects accidental corruption only. Platform adapters must use their normal
integrity-protected settings or secure storage; the CRC is not a MAC or signature.
