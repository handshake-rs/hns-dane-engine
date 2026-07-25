# Foundation qualification

Verified with Rust 1.89.0 on 2026-07-25:

```text
cargo test --workspace
  32 unit tests passed
  4 doc-test targets passed (0 doctests)

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
- checksummed policy persistence, optimistic updates, generation revocation, requester opt-out,
  provider opt-in, and conflicting privacy-policy rejection;
- direct-authoritative-first planning with no representable OS/public-recursive fallback;
- all-local-evidence requirement and distinct ODoH proxy/target identity enforcement;
- explicit browser authority states;
- C layout assertions, ownership functions, policy exchange, transport planning, query admission,
  response correlation, and panic containment; and
- positive pinned vectors plus mutation-derived negatives.

Not yet implemented:

- Handshake header synchronization and currency rules;
- Urkel/name-state proof verification;
- DNSSEC signature and denial cryptography;
- TLSA certificate/SPKI matching and origin TLS/SNI execution;
- UDP, TCP, authoritative DoH, P2P DNS Relay, ODoH, or HNSR network transports;
- filesystem/mobile preferences adapters and atomic durable writes;
- registry fingerprint negotiation and HSD draft-PR cross-language execution;
- platform bridges, loopback proxy, local CA, mobile ABI packaging, and Chromium native host;
- fuzz targets, HSD-generated live DNSSEC fixture generation, and performance benchmarks.

The facade therefore rejects or records validation decisions supplied by future verifier crates; it
does not claim the complete browser engine or ecosystem is integrated.

