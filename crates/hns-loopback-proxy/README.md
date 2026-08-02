# hns-loopback-proxy

Authenticated exact-origin admission and publication for a native browser
loopback proxy.

The crate parses strict loopback `CONNECT` requests, validates a per-instance
capability in constant time, and consumes an opaque engine-authorized provider
context into a bounded, in-memory, generation-checked publication registry.
Atomic publish, replace, and revoke operations bind the exact provider and
process/listener lifecycle fields. Tunnel grants are opaque, non-cloneable,
short-lived, and explicitly revalidated against the current registry and
engine state. Pending CONNECT handles have hard-bounded exclusive expiries;
the session rejects trusted-clock rollback and prunes expired records before
enforcing capacity. A fully validated successful publish atomically reclaims
expired publications before insertion under the same generation advance;
failed mutations leave the registry unchanged.

This crate does not perform DNS wire I/O, open a listener or origin socket,
issue certificates, terminate TLS, forward bytes, or enable a wallet provider
in any browser product. Those adapters remain unavailable and disabled until
implemented and qualified.

Published releases can be added with:

```bash
cargo add hns-loopback-proxy
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-loopback-proxy).

Licensed under either Apache-2.0 or MIT.
