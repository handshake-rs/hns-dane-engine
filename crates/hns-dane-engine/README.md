# hns-dane-engine

Runtime-independent facade for fail-closed Handshake browser resolution and
DANE validation.

The engine coordinates session and policy generations, transport admission,
query correlation, locally verified evidence, certificate matching, and
structured provenance. Native adapters own platform I/O and persistence; they
cannot substitute transport assertions for local validation.

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
