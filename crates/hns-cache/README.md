# hns-cache

Bounded positive and negative cache primitives for Handshake browser
resolution.

Cache keys are session-secret-derived hashes rather than query names. Entries
are bound to the exact runtime generation, policy generation, and validated
Handshake chain anchor, with finite TTL and memory limits.

Published releases can be added with:

```bash
cargo add hns-cache
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-cache).

Licensed under either Apache-2.0 or MIT.
