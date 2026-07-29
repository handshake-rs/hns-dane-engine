# hns-dnssec

Bounded local DNSSEC validation for Handshake browser resolution.

The crate validates DNSKEY and DS chains, signed RRsets, NSEC, and NSEC3
evidence under explicit limits. Callers provide DNS messages; resolver or
transport assertions are never treated as validation authority.

```bash
cargo add hns-dnssec
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-dnssec).

Licensed under either Apache-2.0 or MIT.
