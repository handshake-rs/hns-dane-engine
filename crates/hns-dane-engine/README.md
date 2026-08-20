# hns-dane-engine

Runtime-independent facade for fail-closed Handshake browser resolution and
DANE validation.

The engine coordinates session and policy generations, transport admission,
query correlation, locally verified evidence, certificate matching, and
structured provenance. Native adapters own platform I/O and persistence; they
cannot substitute transport assertions for local validation.

Runtime-independent describes those state and I/O contracts, not a
native-library-free dependency graph. This full facade depends on public
`hns-dane` and, through `hns-resolver`, public `hns-dnssec`; both link OpenSSL.
Android and Apple consumers must provide or cross-build OpenSSL for the exact
target and qualify the resulting complete facade linkage. Current repository
CI exercises `mobile` feature configurations only for the private
`hns-browser-gateway`, `hns-browser-loopback-proxy`, and
`hns-browser-transport` adapters on Ubuntu. It does not cross-build this facade
for Android or Apple. Until a full-facade target is qualified, mobile shells
should pin and consume the exact mobile-safe private adapter contracts they
actually integrate.

Chromium and mobile integrations that already own the canonical
`BrowserRuntime` use `PrivateTransportAuthority::new(&mut runtime, network,
policy)` to start, restore, and validate ODoH and HNSR roles without creating a
second authority clock. ODoH includes canonical GETCONFIG acquisition and a
generation-floored signed-target cache. HNSR includes the profile-bound
requester and ciphertext-only relay state machines, exact outer-connection
routing and acknowledgement, disconnect cleanup, and checksummed snapshots.
The platform still owns Brontide I/O and atomic authenticated storage. No
endpoint, rendezvous, plaintext output, or inferred live-adapter availability
is exposed by these runtime seams.

`HrmHnsaAuthorityBroker` is the synchronous native ordering core for canonical
HRM/HNSA service authority. For one subject-wide key it acquires a real fenced
lease, reads one trusted operation time, restores or reconfirms the complete
authenticated aggregate against an external revision floor, durably advances
time before starting current-name/HRM retrieval, applies the canonical
HRM/HNSA validator, commits every proposal with an exact fenced CAS, and binds
the exact committed active service or withdrawal to a callback that cannot
outlive the lease. The bounded broker retains pending in-memory state across
ordinary errors and caught consumer unwinds so a later invocation must
reconcile it rather than silently starting over.

The broker deliberately defines, but does not implement, the trusted platform
backend. A production backend must provide real cross-process exclusion,
monotonic fencing, authenticated snapshots, a non-evictable initialized marker,
an independently protected rollback floor, trusted time, authenticated current
Handshake state, exact HRM retrieval, atomic durable acknowledgement, and
outcome-ambiguous-write reconciliation. No such Android, Apple, or Chromium
backend or bridge is supplied by this tranche, so it does not enable a product
release gate.

The legacy `hsa1` HNSA selector and HNSR requester/opaque-relay cores described
here are also implemented, but no reviewed mobile-safe authority boundary
currently exposes either authority path across a platform bridge. Such a
boundary must preserve the non-forgeable HNS authority, the one
`BrowserRuntime` and requester authority, authenticated rollback-resistant
state and floors, and trusted-time checks; JNI, C, Swift, or UI code must not
reconstruct those authorities. This mobile integration boundary is remaining
platform work, not an absence of the Rust core capabilities.

`Engine::verify_and_select_hnsa_named_routes` accepts only a non-forgeable
`VerifiedHnsResource` and one complete response of at most 16 encoded records.
It requires the exact application-selected HNS name, canonical service name,
the reviewed `HNS_WEB_V1` or `HNS_CHAT_V1` profile,
capability/constraints policy, and trusted time; selects one canonical
single-string `hsa1` record; verifies the full HNSA authorization, delegation,
route, and relay-ticket chain; and applies conflict-safe greatest
authorization, delegation, and route sequences. For those reviewed profiles,
the exact endpoint key defines the logical endpoint; any future profile
requires explicit replacement-semantics review. The caller supplies one
`HnsaNamedRouteState`, a bounded checksummed blob that retains the global
authorization and up to 64 endpoint delegation/route histories in at most
7,519 bytes. Selection can advance its generation even when it returns an
error or no route. Every such change must be atomically committed in
authenticated rollback-resistant storage before an open, and selection,
storage, and open must be serialized per scope. Equal-sequence conflict and
capacity-exhaustion states remain sticky until a verified changed `hsa1`
authority appears with a greater resource generation. Each non-cloneable
selection is bound to the engine requester epoch and exact HNS/profile/time
context and exposes only non-authoritative relay metadata, never a raw ticket.
`Engine::begin_hnsa_named_route_open` requires the current durably committed
state, rechecks every external and engine authority, and begins the HNSR open
using an internally selected ticket. Raw `HnsrRequesterRuntime::begin_open` is
node-profile-only. The platform must advance
`HnsaNamedRouteContext::trusted_time_high_water` after every trusted time
observation, including failed selection. It still owns complete directory
discovery and response-completeness/quorum policy, authenticated
rollback-resistant storage, live Brontide/relay I/O, and the profile's
endpoint-authenticated inner session.

Rust facade version 3 also exposes the minimal browser-authority boundary for
wallet-provider injection. It permits HTTPS only and stamps the exact logical
origin and URL port, selected service port and namespace, complete
namespace-decision fingerprint, network, authentication path, runtime and
policy generations, authority event, and validity interval into a private
context, then returns a typed allow-or-deny result. Exact success can mint a
separate non-cloneable, non-serializable `ProviderAuthorityContext`; native
browser code reads its typed origin/namespace/service/network and generation
bindings and consumes/replaces it through engine revalidation instead of
reproducing trust policy. A borrowed check lets a trusted native publication
retain the opaque context. Its private admission stamp survives unrelated work
but not degradation, revocation, stop, policy/runtime invalidation, or expiry.
HNS requires a matching strict engine completion.
ICANN uses an exact-request opaque token minted by a trusted embedding-browser adapter; that
adapter is a security principal and must never accept page-controlled TLS
assertions. The engine does not contain wallet, permissions, signing, or
marketplace code. A separate consumer ABI can take ownership of an already
authorized Rust context for typed inspection, currentness checks, and
destruction, but exposes no C mint/import path. Pure-C authority construction
and platform wiring remain unavailable. Navigation and same-origin decision
replacement remain platform revoke-or-replace responsibilities; the engine
keeps no unbounded per-origin navigation map.

Published releases can be added with:

```bash
cargo add hns-dane-engine
```

See the repository's
[architecture](https://github.com/handshake-rs/hns-dane-engine/blob/main/docs/architecture.md)
and
[security policy](https://github.com/handshake-rs/hns-dane-engine/blob/main/docs/security-policy.md)
for integration boundaries. The minimum supported Rust version is 1.89. API
documentation for published releases is hosted on
[docs.rs](https://docs.rs/hns-dane-engine).

Licensed under either Apache-2.0 or MIT.
