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
hns-resolution-policy -------------------------------------------------+          v
hns-browser-observability ---------------------------------------------+   hns-dane-engine-ffi
hns-cache -------------------------------------------------------------+
hns-transport ---------------------------------------------------------+
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
`hns-dane-engine-ffi` contains the narrowly audited unsafe pointer boundary and versioned C ABI.
Adapters own sockets, clocks, secure storage, threads, UI, and platform lifecycle.

The dependency boundary is deliberate: these crates do not depend on Tokio, JNI, Swift, Chromium,
SQLite, operating-system DNS, or a particular network stack. Callers can execute the deterministic
state machines under their native runtime.

This foundation does not yet implement socket dialing or peer discovery, download/reorganization
from a fork predating the current tip, durable restart checkpoints, authenticated authoritative
DoH, P2P relay/ODoH/HNSR transports, origin TLS socket execution, or platform bridges. Header sync
currently selects only among bounded candidates extending the same validated base. PKIX usages 0/1
intentionally have no WebPKI path. The existing C ABI still exposes the earlier single-response
DANE-EE entry point; the full header-to-Urkel-to-DNSSEC Rust path is pending ABI v2/mobile
integration.
