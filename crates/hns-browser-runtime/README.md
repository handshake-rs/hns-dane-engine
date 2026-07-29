# hns-browser-runtime

Session-bound lifecycle and admission stamps for Handshake browser authority.

The runtime binds work to one engine session, monotonic policy generations,
authority state, and an event clock so stale or cross-session completions fail
closed. Platform adapters remain responsible for generating fresh session IDs.

```bash
cargo add hns-browser-runtime
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-browser-runtime).

Licensed under either Apache-2.0 or MIT.
