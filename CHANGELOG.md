# Changelog

All notable changes to the `hns-dane-engine` workspace are documented in this
file. The public crates use a shared version and follow Semantic Versioning.

## hns-browser-observability 0.1.2 - 2026-08-09

This maintenance release adds one browser-product-neutral currentness
contract without changing the canonical browser status schema:

- model HSD name-tree commit intervals for mainnet, testnet, regtest, and
  simnet;
- account for the following-header publication rule at interval boundaries;
  and
- report whether a validated local chain already contains the name-tree root
  authoritative at an independently corroborated target height.

## hns-browser-observability 0.1.1 - 2026-08-09

This maintenance release updates only `hns-browser-observability` so existing
0.1.x consumers can adopt the shared effective-runtime-feature diagnostics
schema without pulling the broader, not-yet-released 0.2 workspace:

- distinguish compiled capability, effective configuration, active production
  wiring, and optional request observation;
- reject impossible feature-state combinations; and
- add typed diagnostics for resolver caching, connection pooling, TLS session
  resumption, and authenticated Alt-Svc HTTP/3 promotion.

## 0.1.0 - 2026-07-29

Initial public release of the runtime-independent Handshake browser security
engine:

- strict DNS wire parsing, local DNSSEC and DANE validation, bounded TLSA
  resolution, proof-authorized authoritative DNS transports, and typed
  transport policy;
- locally validated Handshake light-chain, standard P2P session, and multi-peer
  header synchronization foundations;
- fail-closed browser runtime, observability, cache, dual-root namespace,
  gateway, loopback-proxy, Rust facade, and versioned C ABI boundaries; and
- authenticated adapter boundaries for explicitly experimental HIP-76 DNS
  Relay and HIP-77 ODoH transport.

The reusable browser testkit remains a private development package and is not
published.
