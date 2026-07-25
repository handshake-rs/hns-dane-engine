# HNS DANE Engine

`hns-dane-engine` is a runtime-independent foundation for Handshake browser resolution. It provides:

- a strict, allocation-bounded DNS wire codec with compression-loop and bounds defenses;
- typed DNSSEC and TLSA resource records;
- local DNSSEC RRset, DS/DNSKEY-chain, NSEC, and NSEC3 validation;
- bounded, DNSSEC-verified CNAME chasing for TLSA;
- local DANE-EE and private-path DANE-TA validation for full certificates and SPKI using exact,
  SHA-256, or SHA-512 associations;
- persistent typed requester/provider policy with generation-safe revocation;
- resolution provenance that distinguishes transport from locally verified evidence; and
- a versioned Rust facade and C ABI suitable for Android, Apple, and native-host adapters.

The implemented transport order is direct delegated-authoritative UDP, direct
delegated-authoritative TCP, optional authenticated authoritative DoH, then policy-permitted
Handshake P2P ODoH and P2P DNS Relay. HNS resolution has no operating-system resolver, public
recursive resolver, public DoH, or WebPKI fallback.

P2P DNS Relay and P2P ODoH are described as **Denuo Experimental V1 — Not an official Handshake
protocol assignment**. Their transport cannot establish authenticity. The production Rust path
consumes DS-authenticated DNSKEY sets, locally validates CNAME and TLSA RRsets, checks the exact
origin SNI, and derives DANE evidence from the server certificate chain. Handshake proof and chain
currency are still supplied by the not-yet-integrated light-chain layer.

## Build

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --release
cc -std=c11 -Wall -Wextra -Werror -fsyntax-only tests/abi_header_smoke.c
```

The minimum supported compiler is Rust 1.89.0. See `docs/architecture.md`,
`docs/security-policy.md`, `docs/abi.md`, `docs/provenance.md`, and `docs/qualification.md` for
boundaries, pinned compatibility inputs, exact coverage, and remaining work.
