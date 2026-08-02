# Changelog

All notable changes to the `hns-dane-engine` workspace are documented in this
file. The public crates use a shared version and follow Semantic Versioning.

## 0.2.0 - Unreleased

- Changed provider authority from latest-global-event semantics to private
  engine-issued admission stamps. Exact HNS completions, ICANN authentication,
  provider contexts, publications, and grants now survive unrelated admitted
  work but remain invalid after degradation, revocation, stop, policy/runtime
  replacement, or expiry; recovery cannot resurrect a pre-invalidation stamp.
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
- Added a consumable Rust provider-authority outcome that mints a private,
  non-cloneable, non-serializable context only after the complete injection
  decision succeeds. The context exposes typed origin, namespace, service,
  network, authentication, session/generation/event, policy-generation,
  decision, and lifetime bindings. Consuming revalidation returns a
  lifetime-narrowed replacement or a denial with no reusable context, without
  browser products duplicating trust policy.
- Added the source-only loopback provider publication boundary. Its bounded
  in-memory registry consumes that opaque context, binds every origin,
  namespace, network, TCP service, TLS/authentication, runtime, policy, event,
  decision, process, and listener field, retains the opaque engine authority,
  and applies generation-checked atomic publish/replace/revoke operations.
  Opaque short-lived grants must be revalidated after every registry mutation
  or security-invalidating engine transition. Pending CONNECT handles
  also carry a hard-bounded exclusive expiry; trusted-clock rollback is
  rejected and expired records are pruned before capacity checks. Each
  publish attempt reclaims expired or engine-invalid publications before
  duplicate/capacity checks; those records already lack authority and their
  removal does not advance the registry generation. No
  DNS wire, listener, origin-proxy, TLS, platform-provider, or
  product-availability claim is made.
- Ignored only the repository-root `/dist/` build-output directory; nested
  distribution metadata remains unaffected.
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
