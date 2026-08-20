# hns-light-wallet

Runtime-independent Handshake light-wallet evidence primitives.

The crate builds HSD-compatible BIP37 bloom filters, requests filtered blocks
through standard Handshake P2P inventory, verifies HSD partial Merkle trees
against locally validated headers, and correlates every matched transaction
before exposing a completed wallet block.

It deliberately does not store a pruned block or name index. Header
persistence, socket ownership, peer discovery, key management, coin selection,
and transaction signing remain separate adapters around this small local trust
boundary.

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).

Licensed under either Apache-2.0 or MIT.
