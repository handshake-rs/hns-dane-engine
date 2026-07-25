# Architecture

The workspace has three dependency layers:

```text
hns-dns-wire ----> hns-dane
       \                \
        \                v
         +--------> hns-dane-engine <---- hns-resolution-policy
                            |
                            v
                  hns-dane-engine-ffi
```

`hns-dns-wire` parses and emits DNS without I/O. `hns-resolution-policy` owns typed persistent
policy, transport ordering, generation admission, revocation effects, and evidence provenance.
`hns-dane` performs bounded local DANE-EE certificate/SPKI matching. `hns-dane-engine` extracts the
exact-owner TLSA RRset from a correlated response, derives non-caller-forgeable TLSA/DANE evidence,
and coordinates those crates behind a synchronous Rust API.
`hns-dane-engine-ffi` contains the narrowly audited unsafe pointer boundary and versioned C ABI.
Adapters own sockets, clocks, secure storage, threads, UI, and platform lifecycle.

The dependency boundary is deliberate: these crates do not depend on Tokio, JNI, Swift, Chromium,
SQLite, operating-system DNS, or a particular network stack. Callers can execute the deterministic
state machines under their native runtime.

This foundation does not yet implement header synchronization, Urkel proof verification, DNSSEC
cryptography, origin TLS/SNI execution, P2P transports, or platform bridges. It supports DANE-EE
usage 3 only; PKIX usages 0/1 have no WebPKI path, and DANE-TA usage 2 awaits local chain-signature
validation. The engine does not chase CNAMEs while selecting TLSA answers.
