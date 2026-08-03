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
Adapters own DNS wire I/O, sockets, clocks, secure storage, threads, UI, platform lifecycle, local
CA material, exact-host certificate issuance, origin authentication execution, and proxy/TLS byte
forwarding. The publication core performs none of those operations.

The dependency boundary is deliberate: these crates do not depend on Tokio, JNI, Swift, Chromium,
SQLite, operating-system DNS, or a particular network stack. Callers can execute the deterministic
state machines under their native runtime.

The `hns-rs` edge is canonical and immutable rather than a workspace-layout
assumption. Nine direct packages inherit a single exact
`https://github.com/handshake-rs/hns-rs.git` revision from the root manifest;
Cargo resolves their two additional transitive packages from that same Git
checkout. All other path dependencies must remain inside this repository.
Consequently, the dependency direction is independently cloneable
`hns-rs -> hns-dane-engine -> platform shells`; the engine neither imports
MeshMine nor requires an adjacent source tree.

This foundation does not yet implement P2P socket dialing or peer discovery,
download/reorganization from a fork predating the current tip, durable restart checkpoints,
authenticated authoritative DoH, an HNSR requester, HIP-76/77 provider roles, origin TLS socket
execution, native loopback listener and tunnel I/O, local CA management, or platform bridges. A
native adapter must connect the HIP-76/77 requester boundary to its established Brontide runtime.
Header sync currently selects only among bounded candidates extending the same validated base.
PKIX usages 0/1 intentionally have no WebPKI path. The legacy C resolution ABI still exposes the earlier
single-response DANE-EE entry point; the full header-to-Urkel-to-DNSSEC Rust path is pending ABI
v2/mobile integration. The provider-authority consumer ABI can carry a context
already minted by trusted Rust, but pure-C namespace decisions, authenticated
contexts, strict completions, and ICANN authenticator integration remain
unavailable. Raw caller-constructible allow fields are intentionally not
exported as a substitute. No platform product enables this provider path yet.
