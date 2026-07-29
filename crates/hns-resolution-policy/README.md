# hns-resolution-policy

Persistent, typed transport policy and evidence provenance for Handshake
browser resolution.

The policy contains no implicit operating-system or public-recursive resolver.
Every mutation advances a generation, so stale completions remain rejected
even if a path is later re-enabled. Recursive HNS DoH is default-off,
user-configured, and terminal.

```bash
cargo add hns-resolution-policy
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-resolution-policy).

Licensed under either Apache-2.0 or MIT.
