# Architecture

The current deterministic trust path is:

```text
hns-rs P2P/header crates ---> hns-light-p2p ---+
                                               +--> hns-light-sync ---+
hns-rs header/covenant/Urkel crates ---> hns-light-chain ------------+
                                                                      |
hns-icann-dane ------------------------------------------------------>+
hns-namespace-resolution -------------------------------------------->+
                                                                      |
hns-dns-wire ---> hns-dnssec --------------------------> hns-resolver --+
       |                                                               |
       +---------------------------------> hns-dane ------------------->+--> hns-dane-engine
                                                                        |          |
hns-resolution-policy ---> hns-gateway -------------------------------+          v
hns-browser-observability ---------------------------------------------+   hns-dane-engine-ffi
hns-browser-runtime ---------------------------------------------------+
hns-cache -------------------------------------------------------------+
hns-browser-chain - - - durable browser header-store consolidation - -+
hns-browser-dnssec ---> hns-browser-dane - strict adapter consolidation+
hns-browser-p2p - - - bounded browser peer/relay consolidation - - - -+
hns-browser-primitives - - temporary product-adapter consolidation - -+
hns-browser-resolver - - strict browser light-resolver consolidation -+
hns-browser-sync - - bounded browser header/proof synchronization - - -+
hns-browser-transport - mobile streaming / Chromium CONNECT adapters -+
hns-browser-gateway - - strict platform gateway adapters - - - - - - -+
hns-browser-loopback-proxy - authenticated platform proxy adapters - -+
hns-browser-urkel - - - - exact legacy proof adapter consolidation - -+
hns-transport ---------------------------------------------------------+
hns-p2p-transport -----------------------------------------------------+
                                                                                  |
                                                                                  v
                                                                         hns-loopback-proxy

hns-browser-testkit - - regtest header/Urkel/DS/DNSKEY/TLSA qualification - - - -+
```

`hns-dns-wire` parses and emits DNS without I/O. `hns-resolution-policy` owns typed persistent
policy, transport ordering, generation admission, revocation effects, and evidence provenance. Its
default-off `user_configured_recursive_hns_doh` requester bit adds transport 7 only as the terminal
candidate. Disabling it changes policy generation, clears requester selections, stops new
admission, and makes already admitted work stale.
`hns-light-chain` consumes the canonical `hns-rs` header, covenant, name-hash, and Urkel-proof
implementations. It validates a contiguous chain from network genesis, retains the exact
median-time/difficulty history, checks explicit height/work/tip-age currency, strictly decodes the
committed HSD `NameState` and resource, and emits a private resource token.
`hns-light-p2p` is a socket-independent standard-HSD session: it admits version/verack with
service, self-connection, clock, and handshake-deadline checks; permits one bounded outstanding
header, proof, and ping request; and correlates responses at their exact deadlines.
`hns-light-sync` sends the same exponential locator to a bounded peer set, validates each response
on a cloned `hns-light-chain`, selects a unique greatest-chainwork same-base extension, requires
configurable agreement, scores consensus-invalid responses, and rejects equal-work ambiguity.
`HeaderCurrent` additionally requires every selected peer to answer, every consensus-valid response
to report an empty extension, and no non-banned peer to advertise a higher height.
`hns-dnssec` validates RRsets, DS-authenticated DNSKEY chains, and NSEC/NSEC3 denial locally.
`hns-icann-dane` is the shared browser-shell-independent ICANN policy boundary. It derives the
absolute TLSA owner from the canonical origin host, effective port, and TCP/UDP/SCTP transport,
then reduces authenticated validating-DoH evidence to DANE enforcement, WebPKI after authenticated
absence, or WebPKI after a proven insecure delegation. Unauthenticated resolver channels,
validation bypass, bogus/indeterminate DNSSEC, and contradictory presence/denial evidence are
terminal errors.
`hns-namespace-resolution` is the shared full-host authority boundary for dual-root browsers. Each
adapter independently produces either a complete, internally coherent HNS plan, a complete ICANN
plan, typed authenticated absence, or typed failure. The classifier never consults an IANA suffix
list and never combines records across roots. It compares alias paths, endpoints, HTTPS/SVCB
selection and ServiceMode TargetName, a separate endpoint CNAME path and final A/AAAA owner,
effective port/transport, ordered ALPN, hints, ECH, TLS policy, and supported TLSA data; reports
the five explicit outcomes; and treats a failure or stale evidence from either root as
indeterminate. Service bindings retain the raw advertised ALPN list for equivalence and
fingerprinting. Following the RFC 9460 HTTPS defaults, HTTP/1.1 remains eligible unless
`no-default-alpn` is present; HTTP/2 and HTTP/3 still require explicit identifiers. Plan,
authenticated-absence, and failure evidence all bind the complete
scheme/host/port/protocol-capability query. HNS provenance carries the exact proof network,
tree root, and height; ICANN provenance carries the validated secure/insecure chain state.
Persisted evidence retains absolute observation and expiry rather than restarting a TTL on read.
When both roots differ, precedence is exact-origin user pin, then persistent successful binding,
then the ICANN first-use default (or a stricter require-selection mode). Both convergent plans are retained so
their joint freshness bound and evidence remain observable. Stable decision and cache
fingerprints bind the complete query, exact deciding policy, root selection, canonical HNS
network, resolver configuration, and authority/binding generations. Cache identity is derived
from the actual decision rather than parallel caller-supplied query or policy fields. These
identities partition downstream pool,
TLS-session, Alt-Svc, and site-data isolation. If a pinned or persistently bound root becomes
authentically absent while the other root remains present, the classifier rejects the implicit
switch; the platform must execute its explicit state-isolated namespace-switch workflow.
`hns-resolver` accepts the initial DS set only from that private HNS resource token, authenticates
the TLD DNSKEY, follows bounded DNSSEC-verified CNAMEs, and returns a non-forgeable terminal TLSA
result carrying the chain lineage. `hns-dane` performs DANE-EE matching and private-root DANE-TA
path validation.
`hns-dane-engine` binds that evidence to a current policy generation, exact terminal response,
origin SNI, certificate chain, Handshake network, common validation time, and structured provenance.
It derives the reported chain anchor from resolver evidence and rejects conflicting caller context.
Its strict completion fields are private. A completion carries its engine-issued admission stamp
and can mint a browser-bridge authorization while that stamp remains admitted in the current
security epoch, its chain anchor is still valid, and its exact normalized origin remains bound.
Unrelated completions do not overwrite that authority; the retained `last_provenance` is diagnostic
only. The older caller-prerequisite completion path cannot mint this capability.
The private `hns-browser-transport`, `hns-browser-gateway`, and
`hns-browser-loopback-proxy` packages keep the production browser I/O adapters
in this repository rather than allowing mobile and Chromium source forks to
drift. Each requires an explicit platform feature. The mobile contract retains
validated-head-before-body streaming and its process-owned ICANN network
boundary; the Chromium contract retains authenticated CONNECT disposition,
end-to-end WebPKI passthrough, local-CA identity generation, and typed gateway
failure evidence. These are integration backends around the same canonical
resolver and authority types, not additional DNS authorities.
The Rust facade's provider-injection boundary derives the logical URL origin
from the authoritative namespace query and permits HTTPS only. It binds a
private authenticated context to that origin, its URL and selected service
ports, the selected root, the complete decision fingerprint (and therefore the
plan, TLSA RRset, and provenance), network, runtime session/generation, policy
generation, authority event, and an absolute validity interval. Its second
atomic check returns an all-outcomes typed decision and fails closed for
cleartext or non-HTTPS schemes, unauthenticated, mismatched, stale,
wrong-network, degraded, revoked, stopped, or TLS-policy-inconsistent contexts.
The report is diagnostic rather than transferable authority. Exact success may
instead return a non-cloneable, non-serializable `ProviderAuthorityContext`
whose private fields retain the origin, selected namespace, effective TCP
service, network, TLS/authentication path, decision fingerprint, runtime
session/generation/event, policy generation, and validity interval. Native
browser code can move this context into its provider host and ask the engine to
revalidate it against a current namespace decision. Revalidation consumes the
old context and either returns a lifetime-narrowed replacement or a denial with
no reusable authority. A borrowed currentness check lets a trusted native
publication retain the same opaque context without copying authority logic.
Ordinary later admissions remain valid; the runtime invalidation floor rejects
pre-degradation/revocation/stop stamps even after recovery. An authorized/denied
enum keeps the denial path from being converted into a context and centralizes
the trust-policy matrix in this engine.
The trusted ICANN adapter receives the engine-derived exact request and may
mint only an opaque token for that request; the engine rejects a retained token
after any decision binding or security epoch changes while allowing unrelated
admissions during authentication. The adapter is an explicit
same-process security principal and must consult browser-local TLS state, never
page input. HNS is bound directly from the engine's strict completion only
when its TCP service, canonical TLSA RRset, network, proof height/tree root,
provenance, and lifetime match the selected decision. No wallet state,
permission database, signing, transaction, or marketplace behavior is owned
here. The context is a trusted native Rust boundary, not a wire token: it must
not be serialized or exposed to page JavaScript. Platform code still owns
wallet-session, permission-generation, and navigation-generation binding.
`hns-browser-runtime` is the single authority-state graph and monotonic runtime clock. Each
admitted operation carries a checked nonzero, caller-supplied runtime session, runtime generation,
and event sequence; another session, a revoked generation, a future event, or any stamp observed
while authority is degraded, revoked, or stopped is rejected before response parsing or
completion. Entering a failure state also advances an internal invalidation floor, so an older
stamp cannot become valid again after authority recovers. Callers must generate a fresh
unpredictable session for every process start. The
runtime is non-cloneable so one session cannot fork its event clock, and its snapshot fields are
private so status consumers receive one engine-issued tuple rather than independently forgeable
session/generation/event/state values. `ResolutionTransportReady -> BrowserBridgeReady` permits
pre-navigation bridge startup, while `DnssecVerified -> BrowserBridgeReady` permits ICANN WebPKI
after authenticated TLSA absence or a proven-insecure delegation; neither edge claims DANE.
`hns-gateway` consumes the exact persistent policy snapshot and issues one process-unique,
policy-selected attempt at a time. Only unreachable, timed-out, or unsupported candidates advance;
a valid UDP truncation advances to direct TCP. Malformed or unauthenticated transport results,
foreign/replayed attempt tokens, stale policy, invalid intermediary topology, and response-bound
violations terminate the plan. ODoH-to-relay downgrade status is derived from attempt history.
Configured recursive HNS DoH can appear only after every earlier policy-permitted candidate and
only under its explicit consent bit. It supplies DNS wire bytes, not validation authority, so the
same local proof, DNSSEC, TLSA, DANE, correlation, and response bounds still apply.
`hns-dane-engine` additionally owns a requester-only ODoH lifecycle. A fresh
runtime admission binds its independent request-ID space, authenticated proxy,
negotiated registry, and signed target cache to the exact runtime session,
runtime/policy generations, invalidation watermark, and Handshake network.
Proxy installation independently requires the canonical engine network and
genesis, the concrete Denuo V1 profile resolved by policy and retained from
peer admission, the Denuo V1 registry identity and negotiation protocol, and
both Denuo-extension and ODoH service advertisements. Official, Denuo V2,
legacy-draft, unresolved automatic, and caller-self-consistent alternate peer
states are insufficient.
Pre/post-adapter checks discard results if that epoch changes. The 16-locator
cache persists only signed public target records, configuration selections,
per-locator sequence high-water marks, a nondecreasing trusted-time high-water,
and a checked monotonic cache generation in a canonical checksummed schema-3
blob. Restore requires the caller-held minimum generation, re-verifies every
signed binding, and never restores proxy sessions, HPKE query contexts, or
in-flight work. Response completion must fall within request start
and deadline. Native storage must add atomic authenticated rollback protection.
No ODoH provider role is implemented by this lifecycle.
`hns-browser-observability` schema v2 validates the shared, name-free mobile/Chromium status
contract: the complete private-field runtime snapshot including authority state, policy and actual
transport, chain anchor, HNSR/provider state and policy-derived readiness, rate-limit saturation,
intermediary identities, all seven evidence states, and stable
degraded/revocation/unsupported reasons. Registry fingerprint and negotiated protocol are nonzero
exactly for experimental P2P transports. Direct, unavailable, validating ICANN
DoH, user-configured recursive HNS DoH, and proof-contained `LocalHnsProof`
status carry the zero sentinels and no intermediary identity. Sanitized
dual-root fields retain only outcome kind, selected namespace,
selection reason, a nonzero decision fingerprint, and name-free root-failure kinds—never the
hostname or plans. Root failures do not fabricate a five-way outcome or namespace selection. A typed ICANN
TLS action distinguishes enforced DANE, authenticated-absence WebPKI, proven-insecure WebPKI, and
fail-closed bogus/indeterminate evidence. DANE requires DNSSEC/TLSA/DANE verified; either permitted
WebPKI path requires a validated secure or proven-insecure DNSSEC disposition with TLSA unavailable
and DANE unattempted/unavailable;
every other failed, unavailable, unsupported, not-attempted, stale, or revoked trust tuple can be
reported only as fail closed. The exact DANE and permitted-WebPKI tuples cannot be relabeled as
failure. The action may be absent for an intentionally cleartext scheme only when DNSSEC is
validated and TLSA/DANE remain explicitly unattempted. `Neither` can report only unavailable
transport, and outcome/namespace/reason combinations must match the canonical classifier's exact
selection matrix. ICANN action/evidence is accepted when ICANN is selected or its root lookup
failed; the facade then requires that ICANN evidence, clears HNS chain/identity state, reports
`ValidatingIcannDoh`, and forces registry fingerprint/protocol to zero. Bogus and indeterminate
lookup failures carry their canonical DNSSEC disposition and fail closed without a namespace
selection. An ICANN failure is bound to validating-DoH provenance; an HNS-only failure is bound to
unavailable transport. Secondary-root trust details remain outside a successful selected-plan status.
Authority state and degraded/revocation reason combinations are checked inside the status
constructor. For bounded observability only, the engine retains the latest provenance and clears it
on degradation or revocation, a failed classification, or an authenticated `Neither` result. This
diagnostic slot is not completion or provider authority.
`hns-cache` provides a runtime-independent bounded LRU for positive and authenticated-negative
results. Its opaque keys include a runtime secret, network, runtime/policy generations, exact chain
height/tree root, qtype, and canonical wire name. Reads remove TTL-expired or generation-mismatched
entries before returning them; metrics contain only counts and byte totals.
`hns-browser-chain` is the unpublished durable adapter used while browser products migrate their
SQLite header state into `hns-light-chain`. It validates proof of work, difficulty transitions,
checkpoints, chainwork selection, reorg publication, and restart snapshots before exposing a
canonical tip; persisted or peer-claimed heights alone never authorize name state.
`hns-browser-dnssec` and `hns-browser-dane` centralize the products' strict legacy validation APIs
while callers migrate to the engine 0.2 validators. They fail closed on malformed or unauthenticated
DNSSEC material, require locally matched TLSA for HNS HTTPS, and intentionally expose no HNS-to-
WebPKI compatibility mode.
`hns-browser-p2p` is the unpublished socket/session adapter used while products migrate to
`hns-light-p2p` and `hns-p2p-transport`. It bounds framing, handshakes, requests, advisory traffic,
relay retries, discovery persistence, and peer penalties. Peer service flags and claimed heights
remain untrusted inputs until the local chain and proof verifiers accept their results.
`hns-browser-sync` is the unpublished orchestration adapter shared by the mobile and Chromium
products while their callers migrate to `hns-light-sync`. It races a bounded peer set under finite
deadlines, validates downloaded headers through the local chain, and stores name values only after
exact-root Urkel verification. Resource persistence is supplied through a narrow sink so sync does
not depend on or authorize either product's legacy resolver implementation.
`hns-browser-primitives` is an unpublished consolidation boundary for the mobile and Chromium
adapters while they move to the canonical `hns-rs` and engine 0.2 types. It owns the single shared
implementation of their legacy header, DNS-wire, resource, proof-of-work, and network-policy
types; product repositories must not carry private copies. New engine trust decisions must use the
canonical private tokens above rather than accepting these compatibility types as authority.
`hns-browser-resolver` is the unpublished light-client adapter for browser-specific proof-backed
resolution, direct authoritative DNS/DoH, interception detection, and persistent verified-resource
storage. It retains exact tree-root lineage and feeds complete HNS and ICANN plans into the shared
dual-root classifier. The full-node `hns-resolverd` remains the canonical daemon resolver and now
shares the same `hns-covenants` resource decoder; its RPC/server process boundary is intentionally
not embedded in mobile or Chromium.
`hns-browser-urkel` centralizes the products' exact-root legacy proof decoder and verifier while
their callers migrate to `hns-urkel-proof`. It remains an unpublished adapter and cannot establish
name authority without the separately authenticated current tree root supplied by the runtime.
`hns-transport` derives immutable direct-DNS endpoints only from a current private HNS resource
token. Mainnet/testnet accept globally routable in-bailiwick glue or synth addresses on port 53;
nonstandard loopback ports require an explicit regtest-fixture policy. Connected UDP and
length-delimited TCP use strict non-recursive DNSSEC queries, finite timeouts and message bounds,
cooperative lifecycle cancellation, exact response correlation, and request-time anchor/TLD
authorization.
`hns-p2p-transport` is the socket-independent HIP-76/HIP-77 requester boundary. It binds a
validated compressed key to established, registry-negotiated experimental peer state; allocates
independent nonzero request IDs; admits exact semantic packets; and requires an adapter to attest
the same Brontide identity on the response. HIP-76 response status, ID, DNS framing, and question
are checked locally. HIP-77 selects an immutable target from its signed current record, rejects a
proxy/target identity collision, seals the query locally, pads the outer client message, and opens
the target response locally. The gateway receives only locally parsed/correlated DNS or a
fail-closed failure class. The engine atomically converts a successful gateway selection into its
current-generation attempt, parsed response, and derived completion context.
`hns-loopback-proxy` is a platform-neutral admission and publication gate. It binds one
non-cloneable session to an exact numeric-loopback endpoint, browser runtime session/generation,
immutable HNS TLD scope, per-instance capability, fresh native-process session/generation, exact
listener generation, and request/registry/time bounds. Its private in-memory registry can publish
only by consuming an engine-issued `ProviderAuthorityContext`; no diagnostic decision or
caller-constructed field set can create an admission. The record retains that opaque context and
borrows the engine's currentness check instead of reconstructing its security semantics from copied
fields. Publish, same-origin replace, and exact-handle revoke are atomic `&mut` transitions requiring
the current registry generation. Capacity is finite,
publication lifetimes are capped, and a publish attempt classifies all records through the engine
before duplicate/capacity decisions. Expired or engine-invalid records are reclaimed without a
registry-generation advance because they can no longer authorize; current records change only on a
successful mutation. Every new process/listener session begins empty, so retained handles fail
closed after crash or restart.

The strict authenticated loopback `CONNECT` phase creates one bounded opaque pending token stamped
with its admission time and hard-bounded exclusive expiry. The session accepts only trusted
nondecreasing time and prunes expired records before testing capacity. Final admission consumes that
token, rejects expiry, and revalidates the exact published logical origin, namespace, HNS network,
TCP service, TLS/authentication path, runtime session/generation/event, policy generation, decision
fingerprint, validity interval, registry/publication generations, endpoint, and process/listener
lifecycle. The resulting exact-origin grant is opaque, non-cloneable, non-serializable, and
short-lived. A separate full-binding revalidation immediately before native I/O rejects any
intervening publish/replace/revoke, security-invalidating engine transition, expiry, clock rollback,
or restart. Unrelated admitted work does not revoke the opaque publication. Navigation and
same-origin decision replacement remain platform lifecycle events that must synchronously revoke or
replace the exact publication; the engine keeps no unbounded per-origin navigation registry.
`hns-browser-testkit` builds a reusable strict regtest lineage—mined header, Urkel/`NameState`
resource, DS-authenticated DNSKEY, signed TLSA, and certificate bytes—without retaining the
temporary DNSSEC signing key. Engine and proxy tests consume the same fixture.
`hns-dane-engine-ffi` contains the narrowly audited unsafe pointer boundary and versioned C ABI.
Its separate provider-authority consumer ABI receives an authorized Rust context only through an
ordinary Rust move, retains it behind a caller-owned opaque handle, exposes an immutable typed
projection plus bounded exact-host copy, retains the exact `Arc<Engine>` for currentness checks,
and destroys the context exactly once. A mismatched Rust-side engine pairing remains non-current,
and the handle keeps its engine alive until destruction. It has no C mint/import/clone/serialization
path and does not expose namespace classification or authentication fields as authority.
The private shared adapter packages implement mobile/Chromium request wiring and bounded building
blocks for validating ICANN DoH, origin transport, native loopback listener and HTTP/TLS handling,
local CA material, exact-host certificate issuance, and proxy byte forwarding. Installed platform
hosts still own execution, clocks, secure storage, threads, UI, and process/navigation lifecycle.
The publication core performs none of those operations.

The dependency boundary is deliberate: these crates do not depend on Tokio, JNI, Swift, Chromium,
SQLite, operating-system DNS, or a particular network stack. Callers can execute the deterministic
state machines under their native runtime.

The `hns-rs` edge is canonical and immutable rather than a workspace-layout
assumption. Ten direct packages inherit a single exact
`https://github.com/handshake-rs/hns-rs.git` revision from the root manifest;
Cargo resolves their four additional transitive packages from that same Git
checkout. All other path dependencies must remain inside this repository.
Consequently, the dependency direction is independently cloneable
`hns-rs -> hns-dane-engine -> platform shells`; the engine neither imports
MeshMine nor requires an adjacent source tree.

The shared private adapter layer now contains, and mobile/Chromium shells consume, source for
request-surface wiring, validating ICANN DoH, origin TLS transport, native loopback listener and
HTTP/TLS handling, local CA and exact-host leaf management, and browser platform bridges. This is
source composition only: it has no installed-product or live-network qualification evidence.
Still absent are P2P socket dialing or peer discovery, download/reorganization from a fork
predating the current tip, durable restart checkpoints, authenticated authoritative DoH, a native
Brontide and live Denuo registry/HIP-76/77/HNSR platform network adapter, HNSA engine integration,
HIP-76/77 provider roles, and HNSR endpoint/rendezvous roles. A native network adapter must connect
the implemented HIP-76/77 and HNSR requester/opaque-relay state machines to its established
Brontide runtime and authenticated rollback-resistant storage. Platform-owned `BrowserRuntime`
integrations use a borrowed `PrivateTransportAuthority` view rather than a second engine runtime.
Header sync currently selects only among bounded candidates extending the same validated base.
PKIX usages 0/1 intentionally have no WebPKI path. The legacy C resolution ABI still exposes the earlier
single-response DANE-EE entry point; the full header-to-Urkel-to-DNSSEC Rust path is pending ABI
v2/mobile integration. The provider-authority consumer ABI can carry a context
already minted by trusted Rust, but pure-C namespace decisions, authenticated
contexts, strict completions, and ICANN authenticator integration remain
unavailable. Raw caller-constructible allow fields are intentionally not
exported as a substitute. No installed product has qualification evidence establishing this
provider path, and release availability remains disabled.
