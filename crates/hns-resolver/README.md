# hns-resolver

Locally DNSSEC-validated Handshake service and TLSA resolution.

The transport-neutral resolver authenticates a TLD DNSKEY RRset from an exact
verified HNS resource, follows bounded signed CNAME chains, and returns typed
TLSA evidence. Callers fetch each correlated query through a policy-admitted
transport.

```bash
cargo add hns-resolver
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-resolver).

Licensed under either Apache-2.0 or MIT.
