# Changelog

All notable changes to the `hns-dane-engine` workspace are documented in this
file. The public crates use a shared version and follow Semantic Versioning.

## 0.1.0 - Unreleased

Prepared initial public release of the runtime-independent Handshake browser
security engine:

- strict DNS wire parsing, local DNSSEC and DANE validation, bounded TLSA
  resolution, proof-authorized authoritative DNS transports, and typed
  transport policy;
- locally validated Handshake light-chain, standard P2P session, and multi-peer
  header synchronization foundations;
- fail-closed browser runtime, observability, cache, dual-root namespace,
  gateway, loopback-proxy, Rust facade, and versioned C ABI boundaries; and
- authenticated adapter boundaries for explicitly experimental HIP-76 DNS
  Relay and HIP-77 ODoH transport.

The reusable browser testkit remains a private development package and will
not be published.
