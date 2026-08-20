# Changelog

All notable changes to the `hns-dane-engine` workspace are documented in this
file. The public crates use a shared version and follow Semantic Versioning.

## 0.2.1 - Unreleased

- Migrated the complete engine protocol cohort from the dated `hns-rs` 0.2
  Git source to exact crates.io `=0.3.0` packages: thirteen direct workspace
  declarations and their sixteen-package locked closure now use registry
  checksums only. Added `hns-hrm`, `hns-service-authority`, and
  `hns-rollback-journal` as direct facade inputs without changing the existing
  `hsa1`-backed HNSA-v2 route semantics. The release
  gate pins all nineteen non-yanked upstream archives in
  `release/hns-rs-0.3.0-crates.sha256` and verifies their crates.io API and
  download checksums, clean VCS source
  `d0cde9ded6f8f93f96f16daafc094849c6d484bf`, and package paths before any
  engine upload. This dependency migration does not itself qualify or enable
  an installed product.
- Added a bounded synchronous native `HrmHnsaAuthorityBroker` for canonical
  HRM/HNSA service authority. It holds a subject-wide fenced lease while it
  restores and reconfirms authenticated aggregate state, advances trusted time
  durably before retrieval, validates and observes the current HRM/HNSA state,
  applies exact fenced CAS updates, and exposes the exact active service or
  withdrawal only through a lease-scoped callback with panic containment and a
  release-boundary check. Its public backend contract requires real
  cross-process fencing, an authenticated snapshot, a non-evictable initialized
  marker, an independently protected rollback floor, authenticated current HNS
  state and HRM retrieval, durable acknowledgement, and ambiguous-write
  reconciliation. No platform backend, bridge, or product release gate is
  enabled by this tranche.
- Added `HrmHnsaHnsrRequesterBroker`, a shared dual-fenced composition for
  canonical HRM/HNSA-backed HNSR route consumption. It acquires authority then
  the distinct whole-requester lease, uses one trusted operation time across
  both durable state machines, commits requester time before invoking complete
  raw-batch retrieval, performs canonical endpoint/route product reduction and
  exact requester CAS, and keeps the bound route and dependent callback inside
  both lease scopes with panic containment. Six deterministic tests cover
  ordering, complete-batch selection, pending-CAS retry, withdrawal, lease
  loss, missing initialized state, and dual release checks. No real platform
  backend, bridge, inner-session consumer, availability flag, publication, or
  release follows from this source tranche.
- Split the release runner's crates.io cadence between new crate names and new
  versions of existing names (605 seconds and 65 seconds respectively), with
  fail-closed registry classification. Resume verification now rebuilds through
  Cargo's registry-backed publish dry-run so dependency `Cargo.lock`
  source/checksum fields reproduce the uploaded archive byte-for-byte. This is
  release tooling only and does not publish or qualify the 0.2.1 engine source.
- Raised the default per-host loopback-proxy request budget from 80 to the
  unchanged global budget of 240 requests per 10 seconds for both mobile and
  Chromium, allowing same-origin code-split asset bursts without increasing
  aggregate proxy admission.
- Added an opt-in browser header-sync progress observer that reports cumulative
  accepted headers and the best validated height after each non-empty batch is
  accepted by the caller's chain store. Existing APIs retain their behavior,
  and the observer is explicitly diagnostic rather than readiness evidence.
- Added RFC 9848/9849 Encrypted ClientHello to the private mobile origin
  transport for HTTP/1.1, HTTP/2, HTTP/3, and secure WebSocket connections.
  Plan-bound HTTPS/SVCB ECH configuration is carried from the selected
  namespace plan into rustls, forces TLS 1.3, and fails closed if ECH is
  rejected; no plaintext or unbound retry is attempted.
- Added strict ECHConfigList framing and capability classification for service
  selection. ECH configuration now partitions verifier, TLS resumption, and
  HTTP/1.1 pool state, while ECH requests cannot be promoted from unaffiliated
  Alt-Svc state. The existing ring TLS provider remains in use; AWS-LC supplies
  only the HPKE suites rustls requires for ECH.
- This successor to the qualified 0.2.0 source requires fresh exact-commit CI,
  CodeQL, platform cross-build, installed-product, and live-network evidence.

## 0.2.0 - 2026-08-10

- Qualified the exact dated engine source at
  `2b23bd55d14d36fe60073606869d75b4796c54f7`: the complete locked CI gate
  passed in run `31400455158`, all configured CodeQL languages passed in run
  `31400453827`, and the separately dispatched credential-free publish
  preflight verified all 19 public crates in run `31401229842`. Those workflows
  performed no upload or tag operation, and their evidence applies only to
  that exact commit; any successor source requires a fresh exact-commit gate.
- Finalized every direct, locked, source-policy, publication, and current
  provenance reference on the dated `hns-rs` 0.2.0 release source
  `b24b66c382de53330ec21dd3137e056a2bea3e2d`. The manifest and lockfile retain
  one immutable source for the eleven direct and fourteen locked protocol
  packages, and execute mode verifies all 17 upstream release archives against
  that same clean source before any engine upload. The exact protocol source
  passed upstream CI run `31398600728`, CodeQL run `31398598588`, and the
  17-package release preflight in run `31399004538`; those upstream results do
  not replace the engine's own exact-commit gates.
- Recorded the immediately preceding publication-preparation source at engine
  commit `97cbeb2b4e83d603af757f903391c719b29bf429`, which pinned `hns-rs` commit
  `abf11ff3b16920c08f3c0b6d32d2e1af7cbe37b2`. It passed the complete locked CI
  gate in run `31397210853` and all configured CodeQL languages in run
  `31397207768`. Those exact-commit results are intermediate evidence and are
  not inherited by the separately committed dated source; the routine run also
  did not replace the manual 19-crate publish preflight.
- Hardened the 19-crate publication path with a machine-readable allowlist,
  source-package inventory and VCS checks, synchronized per-crate licenses and
  changelogs, exact upstream `hns-rs` archive verification, explicit
  version/date/clean-tree confirmation for uploads, checksum-and-VCS-verified
  resume behavior, and an exact-commit credential-free Actions workflow for
  real `cargo publish --dry-run` checks. Routine qualification uses the
  non-compiling archive-only path. The intermediate exact-source run exercised
  that routine path, and the dated `2b23bd5` candidate subsequently passed
  exact-head CI, CodeQL, and the separate all-19-crate preflight. Nothing here
  uploads or tags a release.
- Unified the private browser gateway, resolver, and transport adapters on the
  workspace's canonical `hns-icann-dane` and `hns-namespace-resolution` 0.2
  packages. This removes the duplicate published 0.1 identities from the
  lockfile so plans, decisions, and ICANN evidence have one Cargo type identity
  across the engine and adapters. The correction was covered by both the exact
  intermediate `97cbeb2` CI and CodeQL runs and the dated `2b23bd5` gate.
- Earlier exact feature source
  `84005f1df21a30ea9dda7fafb95f9488b8f5da4b` passed the complete locked
  `scripts/check.sh` gate in GitHub Actions run `31372280327`. The successful
  gate covered default Chromium and separate mobile feature configurations,
  the ODoH/HNSR/HNSA source and tests, strict Clippy, the release build, C
  header smoke, and every public-package publish dry-run present at that
  commit. It supplied no installed-product, live-network, provider-availability,
  wallet, value, or marketplace evidence and did not publish the 0.2 line.
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
  full-chain regtest tests passed, and the same source was later covered by the
  exact intermediate `97cbeb2` full qualification gate.
- Re-pinned the immutable eleven-package direct and fourteen-package locked
  `hns-rs` graph to canonical revision
  `b33b346780c8f6a9bb18a54390019486cdab0221`, which permits every nonzero HNSR
  circuit profile required by named browser services. The exact-source policy
  remains unchanged. This graph was covered by the exact `84005f1` source gate,
  which did not publish or release the 0.2 line.
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
  and rendezvous are hard rejected on this runtime surface. The HNSR source and
  tests were covered by the exact intermediate `97cbeb2` full qualification
  gate; no live adapter or installed-product qualification follows from that
  result.
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
  provider role is implemented or made available by this runtime. The ODoH
  source and tests were covered by the exact intermediate `97cbeb2` full
  qualification gate; no live adapter or provider role was qualified.
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

## hns-browser-observability 0.1.1 - 2026-08-09

This maintenance release updated only `hns-browser-observability` so existing
0.1.x consumers could adopt the shared effective-runtime-feature diagnostics
schema independently of the later 0.2 workspace line:

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
