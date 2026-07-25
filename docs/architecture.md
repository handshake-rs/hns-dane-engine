# Architecture

The current deterministic trust path is:

```text
hns-dns-wire ---> hns-dnssec ---> hns-resolver --+
       |                                          |
       +--------------> hns-dane ---------------->+--> hns-dane-engine
                                                   |          |
hns-resolution-policy ----------------------------+          v
                                                   hns-dane-engine-ffi
```

`hns-dns-wire` parses and emits DNS without I/O. `hns-resolution-policy` owns typed persistent
policy, transport ordering, generation admission, revocation effects, and evidence provenance.
`hns-dnssec` validates RRsets, DS-authenticated DNSKEY chains, and NSEC/NSEC3 denial locally.
`hns-resolver` follows bounded DNSSEC-verified CNAMEs and returns a non-forgeable terminal TLSA
result. `hns-dane` performs DANE-EE matching and private-root DANE-TA path validation.
`hns-dane-engine` binds that evidence to a current policy generation, exact terminal response,
origin SNI, certificate chain, and structured provenance.
`hns-dane-engine-ffi` contains the narrowly audited unsafe pointer boundary and versioned C ABI.
Adapters own sockets, clocks, secure storage, threads, UI, and platform lifecycle.

The dependency boundary is deliberate: these crates do not depend on Tokio, JNI, Swift, Chromium,
SQLite, operating-system DNS, or a particular network stack. Callers can execute the deterministic
state machines under their native runtime.

This foundation does not yet implement Handshake header synchronization, Urkel proof verification,
the binding from a verified HNS resource into the first trusted DS token, origin TLS socket
execution, network transports, or platform bridges. PKIX usages 0/1 intentionally have no WebPKI
path. The existing C ABI still exposes the earlier single-response DANE-EE entry point; the
non-forgeable multi-response DNSSEC path is currently a Rust API pending ABI v2/mobile integration.
