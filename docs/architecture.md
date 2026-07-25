# Architecture

The current deterministic trust path is:

```text
hns-rs P2P/header crates ---> hns-light-p2p ---+
                                               +--> hns-light-sync ---+
hns-rs header/covenant/Urkel crates ---> hns-light-chain ------------+
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
                                                                                  |
                                                                                  v
                                                                         hns-loopback-proxy

hns-browser-testkit - - regtest header/Urkel/DS/DNSKEY/TLSA qualification - - - -+
```

`hns-dns-wire` parses and emits DNS without I/O. `hns-resolution-policy` owns typed persistent
policy, transport ordering, generation admission, revocation effects, and evidence provenance.
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
`hns-resolver` accepts the initial DS set only from that private HNS resource token, authenticates
the TLD DNSKEY, follows bounded DNSSEC-verified CNAMEs, and returns a non-forgeable terminal TLSA
result carrying the chain lineage. `hns-dane` performs DANE-EE matching and private-root DANE-TA
path validation.
`hns-dane-engine` binds that evidence to a current policy generation, exact terminal response,
origin SNI, certificate chain, Handshake network, common validation time, and structured provenance.
It derives the reported chain anchor from resolver evidence and rejects conflicting caller context.
Its strict completion fields are private. A completion can mint a browser-bridge authorization only
while it is the engine's latest fully verified current-generation result, its chain anchor is still
valid, and its exact normalized origin remains bound. The older caller-prerequisite completion path
cannot mint this capability.
`hns-browser-runtime` is the single authority-state graph and monotonic runtime clock. Each
admitted operation carries the caller-supplied unique runtime session, runtime generation, and
event sequence; another session, a revoked generation, or a future event is rejected before
response parsing or completion.
`hns-gateway` consumes the exact persistent policy snapshot and issues one process-unique,
policy-selected attempt at a time. Only unreachable, timed-out, or unsupported candidates advance;
a valid UDP truncation advances to direct TCP. Malformed or unauthenticated transport results,
foreign/replayed attempt tokens, stale policy, invalid intermediary topology, and response-bound
violations terminate the plan. ODoH-to-relay downgrade status is derived from attempt history.
`hns-browser-observability` validates the shared, name-free mobile/Chromium status contract:
session/generations/event sequence, policy and actual transport, chain anchor, registry identity,
HNSR/provider state and readiness, rate-limit saturation, intermediary identities, all seven
evidence states, and stable degraded/revocation/unsupported reasons. The engine retains only the
last current-generation provenance and clears it on degradation or revocation.
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
`hns-loopback-proxy` is a platform-neutral two-phase proxy gate. It binds one non-cloneable session
to an exact numeric-loopback endpoint, runtime session/generation, immutable HNS TLD scope,
per-instance capability, origin port, and request bounds. Phase one admits one strictly parsed,
authenticated loopback `CONNECT` into a bounded opaque pending set. Phase two consumes that pending
token and a non-forgeable engine browser-bridge authorization to return an exact-host tunnel grant.
The non-cloneable grant carries the exact authorizing event and inclusive validity window. Wrong
instances, origins, generations, policies, events, or times fail closed.
`hns-browser-testkit` builds a reusable strict regtest lineage—mined header, Urkel/`NameState`
resource, DS-authenticated DNSKEY, signed TLSA, and certificate bytes—without retaining the
temporary DNSSEC signing key. Engine and proxy tests consume the same fixture.
`hns-dane-engine-ffi` contains the narrowly audited unsafe pointer boundary and versioned C ABI.
Adapters own sockets, clocks, secure storage, threads, UI, platform lifecycle, local CA material,
exact-host certificate issuance, and proxy/TLS byte forwarding.

The dependency boundary is deliberate: these crates do not depend on Tokio, JNI, Swift, Chromium,
SQLite, operating-system DNS, or a particular network stack. Callers can execute the deterministic
state machines under their native runtime.

This foundation does not yet implement P2P socket dialing or peer discovery, download/reorganization
from a fork predating the current tip, durable restart checkpoints, authenticated authoritative
DoH, P2P relay/ODoH/HNSR transports, origin TLS socket execution, native loopback listener and
tunnel I/O, local CA management, or platform bridges. Header sync currently selects only among
bounded candidates extending the same validated base. PKIX usages 0/1 intentionally have no WebPKI
path. The existing C ABI still exposes the earlier single-response DANE-EE entry point; the full
header-to-Urkel-to-DNSSEC Rust path is pending ABI v2/mobile integration.
