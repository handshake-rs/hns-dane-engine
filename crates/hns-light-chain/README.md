# hns-light-chain

Locally validated Handshake header-chain and Urkel name-resource anchors.

The crate gates headers by network consensus, chainwork, difficulty, median
time, and currency policy, then verifies exact committed Urkel name proofs and
HNS resource data. Its bounded consensus window has an exact checkpoint codec
for a wallet-owned authenticated store; peer discovery, the full birthday-to-
tip scan archive, and competing-fork download remain adapter responsibilities.

Published releases can be added with:

```bash
cargo add hns-light-chain
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-light-chain).

Licensed under either Apache-2.0 or MIT.
