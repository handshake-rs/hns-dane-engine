# hns-dns-wire

Strict, runtime-independent DNS wire parsing for DNSSEC and DANE.

Parsing is allocation bounded and validates packet size, section counts,
labels, RDATA, and compression jumps. Forward, cyclic, and out-of-message
compression pointers are rejected, and the DNS AD bit remains an untrusted
wire claim.

Published releases can be added with:

```bash
cargo add hns-dns-wire
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-dns-wire).

Licensed under either Apache-2.0 or MIT.
