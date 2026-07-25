# Architecture

The workspace has three dependency layers:

```text
hns-dns-wire          hns-resolution-policy
          \             /
             hns-dane-engine
                    |
          hns-dane-engine-ffi
```

`hns-dns-wire` parses and emits DNS without I/O. `hns-resolution-policy` owns typed persistent
policy, transport ordering, generation admission, revocation effects, and evidence provenance.
`hns-dane-engine` coordinates those crates behind a synchronous Rust API.
`hns-dane-engine-ffi` contains the narrowly audited unsafe pointer boundary and versioned C ABI.
Adapters own sockets, clocks, secure storage, threads, UI, and platform lifecycle.

The dependency boundary is deliberate: these crates do not depend on Tokio, JNI, Swift, Chromium,
SQLite, operating-system DNS, or a particular network stack. Callers can execute the deterministic
state machines under their native runtime.

This foundation does not yet implement header synchronization, Urkel proof verification, DNSSEC
cryptography, TLSA certificate matching, origin TLS, P2P transports, or platform bridges. Instead it
defines the fail-closed interface at which those independently verified results must be supplied.
