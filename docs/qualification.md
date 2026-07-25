# Foundation qualification

Verified with Rust 1.89.0 on 2026-07-25:

```text
cargo test --workspace
  55 unit tests passed
  7 doc-test targets passed (0 doctests)

cargo clippy --workspace --all-targets --all-features -- -D warnings
  passed

cargo build --workspace --release
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
- engine-derived TLSA/DANE evidence, prerequisite-local-evidence enforcement, and distinct ODoH
  proxy/target identity enforcement;
- explicit browser authority states;
- C layout assertions, ownership functions, policy exchange, transport planning, query admission,
  end-to-end local DANE matching, caller-DANE-bit rejection, response correlation, and panic
  containment; and
- positive pinned vectors plus mutation-derived negatives.

Not yet implemented:

- Handshake header synchronization and currency rules;
- Urkel/name-state proof verification;
- the verified-HNS-resource-to-initial-DS binding and complete live authoritative DNSSEC chain;
- origin TLS socket/SNI execution (the Rust API checks the adapter-reported exact SNI);
- UDP, TCP, authoritative DoH, P2P DNS Relay, ODoH, or HNSR network transports;
- filesystem/mobile preferences adapters and atomic durable writes;
- registry fingerprint negotiation and HSD draft-PR cross-language execution;
- platform bridges, loopback proxy, local CA, mobile ABI packaging, and Chromium native host;
- fuzz targets, HSD-generated live DNSSEC fixture generation, and performance benchmarks.

The Rust facade now has a non-forgeable local DNSSEC/CNAME/TLSA path and derives DANE-EE or DANE-TA
evidence locally. It still accepts Handshake proof and chain-currency verdicts until the light-chain
crates are integrated, and does not claim that the complete browser engine or ecosystem is
qualified.
