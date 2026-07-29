# hns-gateway

Fail-closed transport selection for Handshake browser resolution.

The gateway evaluates typed candidates in policy order and records the actual
attempt history, intermediary identities, and privacy downgrade state.
Fallback is limited to explicitly classified reachability, timeout,
unsupported, or valid UDP-truncation outcomes.

```bash
cargo add hns-gateway
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-gateway).

Licensed under either Apache-2.0 or MIT.
