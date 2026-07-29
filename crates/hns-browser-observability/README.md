# hns-browser-observability

Bounded, shared security and transport status for Handshake browser products.

The status schema keeps transport provenance separate from cryptographic
evidence and omits query names, URLs, certificates, DNS payloads, and secrets.
It is designed for consistent mobile and Chromium adapter reporting.

```bash
cargo add hns-browser-observability
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-browser-observability).

Licensed under either Apache-2.0 or MIT.
