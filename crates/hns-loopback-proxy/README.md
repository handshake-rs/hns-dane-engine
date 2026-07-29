# hns-loopback-proxy

Authenticated exact-origin admission for a native browser loopback proxy.

The crate parses strict loopback `CONNECT` requests, validates a per-instance
capability in constant time, and requires current non-forgeable DANE completion
before issuing a tunnel grant. It is an admission core, not a socket or TLS
server.

```bash
cargo add hns-loopback-proxy
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-loopback-proxy).

Licensed under either Apache-2.0 or MIT.
