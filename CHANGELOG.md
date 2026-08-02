# Changelog

All notable changes to the `hns-dane-engine` workspace are documented in this
file. The public crates use a shared version and follow Semantic Versioning.

## 0.2.0 - Unreleased

- Added Rust facade version 3's minimal, fail-closed wallet-provider injection
  authority: HTTPS-only logical origin, URL/service ports, selected namespace,
  private typed context, current runtime/policy/event stamps, complete
  namespace-decision fingerprint, validity bounds, and closed denial reasons.
- Bound strict HNS completions to the selected plan's canonical TLSA RRset,
  TCP service, network, proof anchor/provenance, and lifetime before they can
  authenticate a provider context.
- Replaced caller-selectable ICANN authentication verdicts with exact-request
  opaque tokens minted by an explicitly trusted embedding-browser principal.
- Kept wallet state, permissions, signing, marketplace behavior, and the
  provider authority out of the unchanged C ABI until opaque namespace and
  context handles can preserve the same trust boundary.
- Advanced the shared package line because `0.1.0` is already published; this
  source change does not publish packages or create a tag.

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
