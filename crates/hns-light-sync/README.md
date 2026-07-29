# hns-light-sync

Bounded multi-peer Handshake light-header synchronization.

Each round validates peer responses independently, chooses a unique
greatest-chainwork result, requires configurable agreement, and rejects
equal-work divergent tips. Durable checkpoints and deep reorganization
recovery remain storage-adapter responsibilities.

Published releases can be added with:

```bash
cargo add hns-light-sync
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-light-sync).

Licensed under either Apache-2.0 or MIT.
