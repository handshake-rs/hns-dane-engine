# hns-browser-observability

Bounded, shared security and transport status for Handshake browser products.

The status schema keeps transport provenance separate from cryptographic
evidence and omits query names, URLs, certificates, DNS payloads, and secrets.
It is designed for consistent mobile and Chromium adapter reporting.

The effective-runtime-feature schema reports compiled capability, current
configuration, active production wiring, and optional request observation as
separate states. Its constructors reject claims such as an active but
unconfigured feature.

The shared name-tree currentness contract models HSD's interval commits and
the following-header publication rule. Mobile and Chromium adapters can use
it to distinguish a stale chain tip from a missing authoritative name-tree
root without duplicating network intervals or boundary arithmetic.

Published releases can be added with:

```bash
cargo add hns-browser-observability
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-browser-observability).

Licensed under either Apache-2.0 or MIT.
