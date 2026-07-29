# hns-light-p2p

Bounded standard Handshake light-client peer state machine.

The crate handles version/verack admission, correlated finite requests,
standard packet validation, deadlines, and peer failure policy without owning
sockets, async executors, peer discovery, or persistence.

Published releases can be added with:

```bash
cargo add hns-light-p2p
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-light-p2p).

Licensed under either Apache-2.0 or MIT.
