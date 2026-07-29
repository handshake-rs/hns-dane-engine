# hns-dane

Bounded, local TLSA certificate matching for Handshake origins.

The crate supports DANE-EE and private-path DANE-TA, full-certificate and SPKI
selectors, and exact, SHA-256, or SHA-512 associations. It contains no network,
operating-system resolver, or WebPKI fallback.

```bash
cargo add hns-dane
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-dane).

Licensed under either Apache-2.0 or MIT.
