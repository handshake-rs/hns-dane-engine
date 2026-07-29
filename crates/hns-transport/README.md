# hns-transport

Proof-authorized authoritative Handshake DNS over UDP and TCP.

Endpoints are derived only from a locally verified HNS resource. Queries are
bounded, DNSSEC-enabled, non-recursive, correlated, and subject to finite
timeouts and cancellation. Mainnet and testnet admit only globally routable
committed glue on the standard DNS port.

Published releases can be added with:

```bash
cargo add hns-transport
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-transport).

Licensed under either Apache-2.0 or MIT.
