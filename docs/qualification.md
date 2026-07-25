# Foundation qualification

Qualification is run with the repository's locked dependency graph and no network access:

```text
cargo test --workspace --all-features --locked --offline
  66 unit tests passed
  9 doc-test targets passed (0 doctests)

cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
  passed

cargo build --workspace --all-features --release --locked --offline
  passed

cc -std=c11 -Wall -Wextra -Werror -fsyntax-only tests/abi_header_smoke.c
  passed
```

Covered:

- hard 65,535-byte DNS message bound and configurable tighter limits;
- bounded questions, records, RDATA, labels, expanded names, and compression jumps;
- backward-only compression pointers with self/forward, out-of-bounds, and cycle defenses;
- strict single-question correlation across ID, opcode, name, type, class, and truncation;
- typed A, AAAA, NS, CNAME, SOA, MX, TXT, SRV, DS, DNSKEY, RRSIG, NSEC, NSEC3, TLSA, and OPT;
- DNSSEC bitmap and EDNS framing validation, including strict-query ECS rejection;
- the AD bit retained only as an untrusted claim;
- canonical shared `hns-rs` network genesis, 236-byte header, proof-of-work, median-time,
  difficulty-transition, and chainwork validation for contiguous light-chain extensions;
- transactional bounded header batches and retention of the exact 147-entry Handshake retarget
  context;
- explicit minimum-height, minimum-chainwork, maximum-tip-age, and future-tip currency rejection;
- strict HSD Urkel inclusion proofs at the exact validated header tree root;
- strict HSD `NameState` decoding, proof-key/name equality, state-height bounds, canonical compact
  integers, assigned-field enforcement, and the 512-byte resource limit;
- assigned DS, NS, GLUE4, GLUE6, SYNTH4, SYNTH6, and TXT resource parsing with bounded DNS-name
  decompression and unknown-tag, forward-pointer, and loop rejection;
- a private verified-HNS-resource token that is the only HNS Rust path into initial DS/DNSKEY
  authentication;
- RSA, ECDSA, Ed25519, and Ed448 DNSSEC RRset validation with RFC serial-time handling;
- DS-authenticated DNSKEY keysets, child-delegation chaining, SHA-1/SHA-256/SHA-384 DS matching,
  and DNSKEY revocation/protocol checks;
- NSEC and NSEC3 no-data/name-error validation, closest-encloser/wildcard proofs, bounded NSEC3
  iterations, and the RFC 5155 example vector;
- strict DANE-EE and DANE-TA usage validation with no PKIX usages, network, or WebPKI fallback;
- exact DER extraction of certificate SPKI plus full-certificate/SPKI selectors and
  exact/SHA-256/SHA-512 matching;
- private-root DANE-TA certificate signature, explicit-time, strict hostname, chain-completeness,
  and chain-bound validation, including the RFC 7671 full-certificate omitted-anchor case;
- bounded locally signed CNAME chasing across one or multiple correlated responses, loop and
  ambiguous-data rejection, exact terminal TLSA binding, and SNI mismatch rejection;
- positive real-certificate fixtures, negative mismatch/mutation cases, unsupported TLSA fields,
  malformed DER, wrong digest lengths, nonzero response codes, missing/wrong-owner TLSA, and input
  bounds;
- checksummed policy persistence, optimistic updates, generation revocation, requester opt-out,
  provider opt-in, and conflicting privacy-policy rejection;
- direct-authoritative-first planning with no representable OS/public-recursive fallback;
- engine-derived HNS proof, chain-currency, DNSSEC, TLSA, DANE, and SNI evidence; exact
  Handshake-network and validation-time binding; derived rather than caller-selected provenance
  anchors; and distinct ODoH proxy/target identity enforcement;
- shared status schema with runtime/policy generations, event sequence, network/chain anchor,
  complete policy, actual transport, bounded identities, registry fingerprint/profile/version,
  HNSR/provider roles and readiness, aggregate rate limits, stable degraded/revocation reasons, and
  bounded unsupported-evidence details;
- all required evidence states: verified, failed, unavailable, unsupported, not attempted, stale,
  and revoked, with verified-state clearing on engine degradation or policy revocation;
- explicit browser authority states;
- C layout assertions, ownership functions, policy exchange, transport planning, query admission,
  end-to-end local DANE matching, caller-DANE-bit rejection, response correlation, and panic
  containment; and
- positive pinned vectors plus mutation-derived negatives.

Not yet implemented:

- Handshake peer/header transport, fork download, best-chain selection, durable restart state, and
  checkpoint bootstrap (the current gate validates one contiguous genesis-anchored extension);
- subdelegation discovery and a complete live authoritative DNSSEC walk beyond the on-chain TLD
  DNSKEY path;
- origin TLS socket/SNI execution (the Rust API checks the adapter-reported exact SNI);
- UDP, TCP, authoritative DoH, P2P DNS Relay, ODoH, or HNSR network transports;
- filesystem/mobile preferences adapters and atomic durable writes;
- registry fingerprint negotiation and HSD draft-PR cross-language execution;
- platform bridges, loopback proxy, local CA, mobile ABI packaging, and Chromium native host;
- fuzz targets, HSD-generated live DNSSEC fixture generation, and performance benchmarks.

The strict Rust facade has a non-forgeable header/Urkel/resource/DS/DNSKEY/CNAME/TLSA path and
derives DANE-EE or DANE-TA evidence locally. The legacy C ABI still accepts prerequisite verdicts
until ABI v2 carries the full proof workflow. This repository therefore does not yet claim that the
complete browser engine or ecosystem is qualified.
