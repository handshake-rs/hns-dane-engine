# hns-namespace-resolution

Fail-closed full-host namespace selection for dual-root browsers.

The crate compares independently validated, complete HNS and ICANN connection
plans without merging records between roots. Decisions bind the query, policy,
selected root, connection endpoints, and trust plan for browser state and
cache isolation.

Published releases can be added with:

```bash
cargo add hns-namespace-resolution
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-namespace-resolution).

Licensed under either Apache-2.0 or MIT.
