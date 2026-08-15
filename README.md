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
- a policy-bound fail-closed transport gateway that selects candidates in typed order, permits
  fallback only for reachability/timeout/unsupported paths or valid UDP truncation, and derives
  intermediary identity and privacy-downgrade status from the actual attempt history;
- authenticated adapter-backed HIP-76 DNS Relay and HIP-77 ODoH requesters with negotiated
  experimental-peer admission, independent request IDs, signed target records, distinct
  proxy/target identities, local HPKE opening, finite bounds, cancellation, and exact DNS
  correlation;
- a requester-only ODoH engine lifecycle bound to one engine admission, authenticated proxy and
  negotiated registry, with pre/post-I/O generation checks, explicit readiness and revocation,
  and a bounded canonical restart representation for signed target records and sequence and
  trusted-time high-water marks; canonical network/genesis/registry admission, an exact
  policy-resolved Denuo V1 peer profile, both Denuo-extension and ODoH service advertisements,
  and response-time monotonicity are required, and it exposes no proxy or target provider
  implementation;
- engine-bound HNSR requester and ciphertext-only relay lifecycles with exact
  service-profile, authenticated-connection, generation, acknowledgement,
  disconnect, trusted-time, and rollback-floor handling, while endpoint,
  rendezvous, and plaintext roles remain unavailable;
- bounded, conflict-safe HNSA named-route selection from a non-forgeable
  current HNS resource: one canonical `hsa1` character-string, caller-selected
  name and service, the reviewed HNS Web or Chat profile, signed service
  authorization and endpoint delegation, route and relay tickets, current
  height/time, profile capabilities and constraints, and current engine
  requester authority are checked; one checksummed `HnsaNamedRouteState`
  retains the global authorization and per-endpoint delegation/route rollback
  state, and a named-route open sink revalidates every authority before using
  an internally held ticket;
- typed DNSSEC and TLSA resource records;
- local DNSSEC RRset, DS/DNSKEY-chain, NSEC, and NSEC3 validation;
- bounded, DNSSEC-verified CNAME chasing for TLSA;
- a shared automatic ICANN DANE contract that derives the TLSA owner from the
  canonical host, effective port, and transport; enforces secure TLSA
  presence; permits WebPKI only after authenticated absence or a proven
  insecure delegation; and keeps bogus/indeterminate DNSSEC fail-closed;
- a shared full-host dual-root namespace contract that independently validates
  complete HNS and ICANN connection/trust plans, reports HNS-only, ICANN-only,
  convergent, divergent, or neither, rejects either root's failure or stale
  evidence, and applies explicit pin, persistent binding, then ICANN first-use
  precedence without using an IANA suffix list as authority or silently
  switching away from an unavailable bound root;
- a Rust facade v3 wallet-provider injection authority that permits only exact
  HTTPS logical origins and atomically binds the selected namespace, URL and
  service ports, complete namespace-decision fingerprint (including the plan,
  TLSA, and provenance), network, runtime/policy/event generations, and
  evidence lifetime to either a strict HNS completion or an opaque token minted
  by the trusted ICANN TLS adapter; it returns a closed allow-or-deny report and
  mints a non-cloneable, non-serializable provider-authority context only on
  success, with engine-owned consuming and borrowed revalidation for native
  browser consumers; private admission stamps survive unrelated work but not a
  security-invalidating lifecycle/policy transition, and no wallet or
  marketplace logic is included;
- local DANE-EE and private-path DANE-TA validation for full certificates and SPKI using exact,
  SHA-256, or SHA-512 associations;
- persistent typed requester/provider policy with generation-safe revocation,
  including a default-off, explicitly user-configured recursive HNS DoH
  terminal transport;
- resolution provenance that distinguishes transport from locally verified evidence;
- a non-cloneable shared browser authority runtime with checked nonzero per-start session IDs,
  private atomic snapshots, and generation/event stamps that reject stale policy work, future
  events, cross-session replay, work observed while degraded, revoked, or stopped, and pre-failure
  stamps even after authority recovery; bridge
  startup can become active before navigation or after authenticated ICANN WebPKI fallback without
  claiming DANE;
- a bounded authenticated loopback-proxy admission/publication core with numeric-loopback binding,
  per-instance constant-time Basic capability checks, strict exact-origin `CONNECT` parsing,
  rollback-safe expiring pending admission, process/listener restart isolation, generation-checked
  atomic publish/replace/revoke operations that consume only the engine's opaque provider
  authority, retain that opaque authority for engine-owned currentness checks, reclaim expired or
  invalid publications before bounded admission, and issue short-lived exact-binding tunnel grants;
- bounded shared mobile/Chromium status schema v2 covering the complete runtime/authority tuple,
  policy generations, actual transport including validating ICANN DoH and
  proof-contained local HNS origin data, intermediary identities,
  experimental-P2P-only registry identity, policy-derived provider readiness, rate limits,
  explicit evidence states, authority-consistent degraded/revocation reasons, sanitized dual-root
  outcome/selection/fingerprint fields with classifier-valid reason combinations, and typed ICANN
  DANE/WebPKI/fail-closed action;
- a reusable browser testkit that constructs and verifies a mined regtest header, committed Urkel
  name proof, HNS DS/DNSKEY authority, signed TLSA response, and exact-certificate DANE path; and
- a versioned Rust facade and C ABI that define adapter-facing contracts for
  Android, Apple, and native hosts, subject to the platform linkage boundary
  below.

Runtime-independent describes the engine's state machines, authority checks,
and injected-I/O boundary; it does not mean that the complete public facade is
free of native-library requirements. The direct `hns-dane-engine` dependency
graph includes public `hns-dane` and, through `hns-resolver`, public
`hns-dnssec`; both cryptographic implementations link OpenSSL. An Android or
Apple host that links the full facade must provide or cross-build OpenSSL for
the exact target and qualify that complete target linkage. The repository's
current `mobile` CI configurations exercise only the private
`hns-browser-gateway`, `hns-browser-loopback-proxy`, and
`hns-browser-transport` adapter crates on the Ubuntu host target; they are not
Android/Apple cross-build evidence for the facade. Until that qualification
exists, a mobile shell should pin and consume the exact mobile-safe private
adapter contracts it integrates rather than treat `hns-dane-engine` as a
turnkey mobile library.

The policy transport order is direct delegated-authoritative UDP, direct
delegated-authoritative TCP, optional authenticated authoritative DoH,
policy-permitted Handshake P2P ODoH and P2P DNS Relay, then explicitly
user-configured recursive HNS DoH when its independent requester-consent bit is
enabled. The recursive transport is absent by default and always terminal.
HNS resolution has no operating-system resolver, implicit recursive resolver,
implicit DoH, or WebPKI fallback. Every DNS response remains subject to local
HNS proof, DNSSEC, TLSA, and DANE validation; a remote AD bit is never
authority. Direct UDP/TCP own their socket I/O here. HIP-76/77 own the complete
authenticated request/response boundary. The ODoH engine runtime now owns its
requester lifecycle and signed-target restart representation, but it still
consumes a platform-supplied established Brontide exchange. The shared
platform adapter source supplies neither a native Brontide transport nor a
live Denuo registry exchange. The local HNSA selector accepts no unauthenticated
directory input in place of a non-forgeable HNS resource, bounds the supplied
complete response before decoding, applies all three replacement/conflict
layers, and enters the HNSR open sink without exposing a raw ticket. For the
reviewed `HNS_WEB_V1` and `HNS_CHAT_V1` profiles, the exact endpoint key is the
logical endpoint; other named profiles are rejected until their replacement
semantics receive explicit code review. Raw `HnsrRequesterRuntime::begin_open`
admits only the node profile, so named profiles must use opaque HNSA selection.
Directory lookup, complete-response and quorum policy, rollback-resistant
platform storage, relay I/O, and the endpoint-authenticated inner session
remain platform work.
Authenticated authoritative DoH and live HIP-76/77 or HNSR network execution
therefore remain unavailable rather than silently falling back.

An HNS name proof may itself contain the verified origin data and require no
DNS network transport. Such a successful result uses the append-only
`LocalHnsProof` status provenance (transport discriminant 8); it is never
inserted into a transport plan or accepted by transport admission.

The ICANN browser path is separate from HNS authority. `hns-icann-dane`
consumes typed evidence from a TLS-authenticated validating ICANN DoH adapter.
It never treats a resolver error or bogus DNSSEC as “no TLSA,” and it ignores
unsigned TLSA bytes when an insecure delegation retains WebPKI.

`hns-namespace-resolution` is the browser-shell-independent authority
classifier. Adapters must resolve the complete scheme/host/port/protocol query
through HNS and ICANN independently and submit whole, single-root plans or
typed authenticated absence. Plans retain the origin CNAME/AliasMode path,
HTTPS/SVCB ServiceMode TargetName, its separate endpoint CNAME path, final
A/AAAA owner and endpoints, effective transport, TLS policy, and supported
TLSA data. Records from the two roots are never merged. HNS provenance is the
exact proof anchor from that lookup, never a later tip; cached evidence keeps
absolute observation/expiry bounds. A static IANA root-zone snapshot may
schedule lookups or seed a cache, but it cannot decide which namespace owns a
hostname. The decision fingerprint binds the complete query, exact policy,
selected root, and whole connection/trust plan so browser connection,
TLS-session, Alt-Svc, and site-data state can be partitioned across namespace
choices.

P2P DNS Relay and P2P ODoH are described as **Denuo Experimental V1 — Not an official Handshake
protocol assignment**. Their transport cannot establish authenticity. The production Rust path
validates shared `hns-rs` headers from the selected network genesis, verifies the exact HSD Urkel
proof and committed `NameState`, derives the initial DS set from that private proof token,
authenticates the TLD DNSKEY RRset, locally validates CNAME and TLSA RRsets, checks the exact origin
SNI, and derives DANE evidence from the server certificate chain. The engine derives its provenance
anchor from that lineage; callers cannot substitute a separate chain anchor or evidence flag. Only
that strict completion can authenticate an HNS namespace decision for a current, expiring provider
authority, and only consuming that authority can publish proxy admission. Legacy caller-verdict
completions cannot authorize a proxy tunnel.

The standard peer and synchronization state machines are runtime independent. They validate
bounded same-base candidate extensions independently, select the unique greatest-work result, and
require a complete no-extension round with no higher advertised active peer before reporting
current: all selected peers must respond, every valid response must report no extension, and
consensus-invalid responders are excluded only under the configured agreement/ban policy. Socket
dialing, peer discovery, competing-fork download/reorganization, restart
snapshots, and checkpoint bootstrap remain adapter/storage work.

The HIP-76/77 requester boundary is likewise runtime independent. An adapter can return a response
only with the static key authenticated by the exact Brontide session, under the request's finite
deadline and allocation bound. The engine atomically admits the gateway-selected bytes,
intermediary identities, actual transport, and downgrade state under the current runtime/policy;
callers cannot substitute a separate completion context. See `docs/p2p-dns-transports.md`.

`hns-loopback-proxy` is deliberately the shared admission/publication boundary, not a DNS, socket,
or TLS server. Its in-memory bounded registry consumes a `ProviderAuthorityContext`, atomically
publishes/replaces/revokes the exact origin under an expected generation, and loses every
publication on process or listener replacement. The private browser adapter packages now provide
shared mobile/Chromium request wiring and building blocks for validating ICANN DoH, origin
transport, a native loopback listener with HTTP/TLS handling, and per-install local CA and
exact-host leaf management. Platform hosts still own execution, secure persistence, and lifecycle,
and must not begin tunnel I/O until the core returns and immediately revalidates an exact-origin
`TunnelGrant`. Ordinary unrelated admissions do not revoke a retained publication, but
degradation, revocation, stop, policy/runtime invalidation, or expiry does.
Same-origin navigation or namespace-decision replacement must synchronously revoke or replace the
exact publication; the engine deliberately does not retain an unbounded per-origin navigation map.

The repository is a standalone Cargo checkout. Its thirteen direct `hns-rs`
packages use exact crates.io requirement `=0.3.0`; the lockfile binds their
sixteen-package closure to registry checksums independently read back from
release source `d0cde9ded6f8f93f96f16daafc094849c6d484bf`. No sibling
`hns-rs` checkout or Cargo Git source is required. `hns-hrm` and
`hns-rollback-journal` are direct facade dependencies reserved for a later
broker tranche; this migration leaves the existing `hsa1` HNSA-v2 path
unchanged. A checked-in manifest pins all nineteen upstream 0.3.0 archives,
including the three packages outside the engine's locked closure. A tested
repository policy rejects Git dependencies, non-exact protocol requirements,
unreviewed registry sources or checksums, dependency aliases, lockfile drift,
and path dependencies that escape this repository. See
`docs/supply-chain.md`.

## Build

```sh
cargo +1.89.0 fetch --locked
cargo +1.89.0 install cargo-deny --version 0.19.9 --locked
./scripts/check.sh
```

The minimum supported compiler is Rust 1.89.0. See `docs/architecture.md`,
`docs/security-policy.md`, `docs/abi.md`, `docs/provenance.md`,
`docs/supply-chain.md`, and `docs/qualification.md` for boundaries, pinned
compatibility inputs, exact coverage, and remaining work.

## Qualification status

The current 0.2.1 dependency source consumes the published, non-yanked
`hns-rs` 0.3.0 cohort from exact release-source commit
`d0cde9ded6f8f93f96f16daafc094849c6d484bf`. That upstream source passed CI
run `31863271873`, CodeQL run `31863271863`, and the 19-package release
preflight in run `31863520941`; all nineteen downloaded archives were
independently matched to their crates.io checksums and clean VCS source. The
engine migration is a successor source and must pass its own exact-commit CI,
CodeQL, and release preflight before publication.

Historically, the exact dated 0.2.0 source candidate at
`2b23bd55d14d36fe60073606869d75b4796c54f7` passed the complete locked
`scripts/check.sh` source gate in GitHub Actions
[`31400455158`](https://github.com/handshake-rs/hns-dane-engine/actions/runs/31400455158),
the Actions, C/C++, Python, and Rust CodeQL matrices in
[`31400453827`](https://github.com/handshake-rs/hns-dane-engine/actions/runs/31400453827),
and the separately dispatched credential-free publish preflight for all 19
public crates in
[`31401229842`](https://github.com/handshake-rs/hns-dane-engine/actions/runs/31401229842).
That historical source pinned protocol revision
`b24b66c382de53330ec21dd3137e056a2bea3e2d`, whose own exact CI, CodeQL, and
17-package preflight also passed. The qualification and preflight workflows
performed no upload or tag operation. Their evidence is commit-scoped; any
successor source must repeat the exact-commit gates before publication.

The immediately preceding publication-preparation source at
`97cbeb2b4e83d603af757f903391c719b29bf429` passed CI run
[`31397210853`](https://github.com/handshake-rs/hns-dane-engine/actions/runs/31397210853)
and CodeQL run
[`31397207768`](https://github.com/handshake-rs/hns-dane-engine/actions/runs/31397207768).
It is retained as historical evidence for the canonical 0.2 adapter type
identities and hardened archive validation; it used the earlier protocol pin
and did not run the separate 19-crate preflight. See the
[`release guide`](docs/releasing.md) for the exact publication procedure.

The provider-authority, loopback-publication, and shared platform-adapter Rust
source is a production-continuation boundary, not a qualified installed
product. Mobile and Chromium shells now consume the shared request, validating-DoH,
origin-transport, listener/HTTP/TLS, and local-CA building blocks, but that
source-level integration has no installed-product or live-network qualification
evidence and does not establish provider availability. The HNSA selector and
HNSR requester/opaque-relay cores are implemented, but exposing them to a
mobile shell still requires a reviewed mobile-safe authority boundary that
preserves the non-forgeable verified resource, the single runtime/requester
authority, authenticated rollback-resistant state and floors, and trusted-time
checks across the platform bridge. The source-only
provider-authority consumer ABI can retain and inspect a context moved from
trusted Rust, but cannot create one from C. Pure-C authority minting, a native
Brontide and live Denuo registry/HIP-76/77/HNSR platform network adapter,
complete HNSA route discovery and response-completeness/quorum policy, atomic
authenticated rollback-resistant storage of `HnsaNamedRouteState` with
platform resource/profile generations and trusted-time high-water marks,
endpoint-authenticated inner sessions, and HNSR endpoint/rendezvous roles
remain absent. No source qualification result establishes wallet-provider or
marketplace availability.
