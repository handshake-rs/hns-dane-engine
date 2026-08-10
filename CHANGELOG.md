# Changelog

All notable changes to the `hns-dane-engine` workspace are documented in this
file. The public crates use a shared version and follow Semantic Versioning.

## 0.2.0 - Unreleased

- Consolidated the private mobile/Chromium platform adapters around shared
  request wiring, validating ICANN DoH, origin transport, native loopback
  listener and HTTP/TLS handling, local CA and exact-host leaf management, and
  browser integration building blocks. Mobile and Chromium shells consume this
  source, but no installed-product or live-network qualification evidence has
  been recorded. Native Brontide and live Denuo registry/HIP-76/77/HNSR network
  adapters, HNSA route discovery and endpoint-authenticated inner-session
  integration, HNSR endpoint/rendezvous roles, pure-C authority minting, and
  provider release availability remain absent.
- Added engine-bound HNSA named-route selection and direct requester-open
  admission from non-forgeable current HNS resources. One bounded complete
  response is filtered and verified against the caller-selected name, service,
  reviewed HNS Web or Chat profile, exact single-character-string `hsa1` root,
  network, height/time, flags, capabilities, constraints, lifetimes,
  signatures, and current HNSR requester authority. The selector applies greatest service
  authorization, endpoint delegation, and per-endpoint route sequence with
  equal-sequence conflict rejection. One bounded, checksummed
  `HnsaNamedRouteState` retains the global authorization and as many as 64
  endpoint delegation/route histories in at most 7,519 bytes. Newer valid
  authorization or delegation observations advance state even when selection
  returns no route, while equal-sequence conflicts and capacity exhaustion are
  sticky until a verified changed `hsa1` authority appears under a greater
  resource generation. Opaque selections expose only redacted route/relay
  metadata. The named-route open sink requires the current durably committed
  state, rechecks the resource, policy, external generations, monotonic time,
  expiry, engine and requester epochs, caps the open to the route/anchor
  lifetime, and consumes an internal ticket by index. Raw requester open is
  node-profile-only; HNS Web and Chat opens require opaque HNSA selection.
  Complete directory discovery and response-completeness/quorum policy,
  authenticated rollback-resistant platform storage, relay liveness, and the
  endpoint-authenticated inner session remain outside this slice. Ten focused
  full-chain regtest tests passed; the full release gate was not run.
- Re-pinned the immutable eleven-package direct and fourteen-package locked
  `hns-rs` graph to canonical revision
  `b33b346780c8f6a9bb18a54390019486cdab0221`, which permits every nonzero HNSR
  circuit profile required by named browser services. The exact-source policy
  remains unchanged, and this repin does not qualify or release the 0.2 line.
- Added the canonical engine HNSR requester and ciphertext-only relay adapter
  over `hns-hnsr-protocol` 0.2.0. Both roles bind exact browser session/runtime
  and policy generations, network/genesis, concrete Denuo V1 registry/profile,
  inner service profile, authenticated outer connection IDs, trusted time, and
  independent role generation. The adapter owns ticket admission, bounded
  requester flow control, reservation/circuit routing, generation-bound write
  acknowledgements, disconnect cleanup, role replace/revoke, and checksummed
  restart envelopes with caller-held generation and trusted-time floors. It
  owns no socket or atomic store, never restores peers/circuits/queued writes,
  and exposes endpoint, rendezvous, plaintext, and transport-adapter readiness
  as false. Requester and opaque relay remain default-on policy roles; endpoint
  and rendezvous are hard rejected on this runtime surface. This source has not
  run its focused or full qualification gate.
- Added `PrivateTransportAuthority::new(&mut BrowserRuntime, Network,
  PolicySnapshot)` so platform shells can consume ODoH and HNSR without
  instantiating a second browser authority. Added canonical HIP-77
  GETCONFIG/CONFIG acquisition: the requester frames and correlates the
  exchange through a distinct authenticated proxy, verifies the target-signed
  locator/network/configuration, atomically installs it, and returns the new
  durable cache generation. Platform adapters only transport bounded bytes.
- Added the requester-only engine ODoH runtime. A fresh engine admission binds
  each non-cloneable requester to the exact process session, runtime and policy
  generations, invalidation watermark, network, unpredictable request-ID
  space, authenticated proxy, and negotiated registry. Its 16-locator signed
  target cache preserves per-locator sequence high-water marks in a bounded,
  checksummed, canonical schema-3 restart representation together with a
  nondecreasing trusted-time high-water and checked monotonic cache generation.
  Restore requires a caller-held generation floor and re-verifies target
  signatures, network, locator, configuration, sequence, lifetime, time
  monotonicity, and snapshot non-rollback.
  Proxy binding independently requires the engine-selected canonical network
  genesis, a policy-authorized concrete Denuo V1 wire profile retained from
  peer admission, the Denuo V1 registry fingerprint/version/negotiation, and
  both the Denuo-extension and ODoH service advertisements. Official,
  Denuo V2, legacy-draft, and unresolved automatic peer profiles are rejected.
  Requester status schema 4 exposes the resolved peer profile and target-cache
  generation. Responses predating request
  start are rejected. Exact
  peer, registry, deadline, correlation, and HPKE errors remain typed, and an
  engine change during adapter I/O discards the result. No ODoH proxy or target
  provider role is implemented or made available by this runtime. This source
  has not yet run its focused or full qualification gate.
- Enabled the new-policy HNSR requester/client default alongside the existing
  opaque HNSR relay, HIP-76/HIP-77 requester paths, and opaque ODoH proxy.
  Fresh policy now selects the bounded `Auto` wire profile so current Denuo
  draft assignments work while future exact official mappings can be
  negotiated without silently reusing packet numbers.
  Persisted requester and relay opt-outs remain exact, direct authority remains
  first, and recursive DNS, plaintext output, target, endpoint, and rendezvous
  roles remain explicit opt-ins.
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
- Added a separate provider-authority consumer ABI that retains only a context
  moved from an authorized Rust outcome. Native code can inspect its immutable
  origin, namespace, authentication, network, TLS, service, runtime, policy,
  decision, and lifetime bindings; copy the bounded exact host; check it
  against current engine state; and destroy it. There is no C mint, import,
  clone, serialization, wallet permission, signing, value, or marketplace
  operation. Pure-C namespace/authentication minting remains unavailable, and
  this ABI alone makes no product-availability claim.
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
