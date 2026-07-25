# HNS DANE Engine

`hns-dane-engine` is a runtime-independent foundation for Handshake browser resolution. It provides:

- a strict, allocation-bounded DNS wire codec with compression-loop and bounds defenses;
- a genesis-anchored Handshake light-chain consensus gate with median-time, difficulty, proof-of-work,
  chainwork, explicit currency, strict Urkel, `NameState`, and HNS resource validation;
- a bounded standard-HSD peer state machine and multi-peer header synchronizer with strict
  version/verack admission, correlated finite request deadlines, same-base greatest-chainwork
  selection, configurable peer agreement, and equal-work fork rejection;
- a bounded positive/negative cache with qname-free session keys, exact runtime/policy/chain
  generation binding, finite TTLs, byte/entry limits, and LRU eviction;
- proof-authorized direct authoritative DNS over connected UDP and length-delimited TCP, with
  finite timeouts, lifecycle cancellation, strict query/response correlation, current-anchor and
  exact-TLD binding, public-address enforcement, and regtest-only loopback fixture ports;
- typed DNSSEC and TLSA resource records;
- local DNSSEC RRset, DS/DNSKEY-chain, NSEC, and NSEC3 validation;
- bounded, DNSSEC-verified CNAME chasing for TLSA;
- local DANE-EE and private-path DANE-TA validation for full certificates and SPKI using exact,
  SHA-256, or SHA-512 associations;
- persistent typed requester/provider policy with generation-safe revocation;
- resolution provenance that distinguishes transport from locally verified evidence;
- a shared session-bound browser authority runtime whose generation/event stamps reject stale
  policy work, future events, and cross-session attempt replay;
- bounded shared mobile/Chromium status covering runtime and policy generations, actual transport,
  intermediary identities, registry identity, provider readiness, rate limits, explicit evidence
  states, and degraded/revocation reasons; and
- a versioned Rust facade and C ABI suitable for Android, Apple, and native-host adapters.

The policy transport order is direct delegated-authoritative UDP, direct
delegated-authoritative TCP, optional authenticated authoritative DoH, then policy-permitted
Handshake P2P ODoH and P2P DNS Relay. HNS resolution has no operating-system resolver, public
recursive resolver, public DoH, or WebPKI fallback. Network I/O is currently implemented only for
direct UDP/TCP; the other candidates remain unavailable rather than falling back.

P2P DNS Relay and P2P ODoH are described as **Denuo Experimental V1 — Not an official Handshake
protocol assignment**. Their transport cannot establish authenticity. The production Rust path
validates shared `hns-rs` headers from the selected network genesis, verifies the exact HSD Urkel
proof and committed `NameState`, derives the initial DS set from that private proof token,
authenticates the TLD DNSKEY RRset, locally validates CNAME and TLSA RRsets, checks the exact origin
SNI, and derives DANE evidence from the server certificate chain. The engine derives its provenance
anchor from that lineage; callers cannot substitute a separate chain anchor or evidence flag.

The standard peer and synchronization state machines are runtime independent. They validate
bounded same-base candidate extensions independently, select the unique greatest-work result, and
require a complete no-extension round with no higher advertised active peer before reporting
current: all selected peers must respond, every valid response must report no extension, and
consensus-invalid responders are excluded only under the configured agreement/ban policy. Socket
dialing, peer discovery, competing-fork download/reorganization, restart
snapshots, and checkpoint bootstrap remain adapter/storage work.

## Build

```sh
cargo test --workspace --all-features --locked --offline
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo build --workspace --all-features --release --locked --offline
cc -std=c11 -Wall -Wextra -Werror -fsyntax-only tests/abi_header_smoke.c
```

The minimum supported compiler is Rust 1.89.0. See `docs/architecture.md`,
`docs/security-policy.md`, `docs/abi.md`, `docs/provenance.md`, and `docs/qualification.md` for
boundaries, pinned compatibility inputs, exact coverage, and remaining work.
