# HNS DANE Engine

`hns-dane-engine` is a runtime-independent foundation for Handshake browser resolution. It provides:

- a strict, allocation-bounded DNS wire codec with compression-loop and bounds defenses;
- typed DNSSEC and TLSA resource records;
- persistent typed requester/provider policy with generation-safe revocation;
- resolution provenance that distinguishes transport from locally verified evidence; and
- a versioned Rust facade and C ABI suitable for Android, Apple, and native-host adapters.

The implemented transport order is direct delegated-authoritative UDP, direct
delegated-authoritative TCP, optional authenticated authoritative DoH, then policy-permitted
Handshake P2P ODoH and P2P DNS Relay. HNS resolution has no operating-system resolver, public
recursive resolver, public DoH, or WebPKI fallback.

P2P DNS Relay and P2P ODoH are described as **Denuo Experimental V1 — Not an official Handshake
protocol assignment**. Their transport cannot establish authenticity: callers must supply locally
verified Handshake state, DNSSEC, exact TLSA, and DANE evidence.

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
