# hns-loopback-proxy

Authenticated exact-origin admission and publication for a native browser
loopback proxy.

The crate parses strict loopback `CONNECT` requests, validates a per-instance
capability in constant time, and consumes an opaque engine-authorized provider
context into a bounded, in-memory, generation-checked publication registry.
The registry retains that opaque context and borrows the engine's currentness
check, so unrelated admitted work does not revoke it while lifecycle/policy
invalidation and expiry still fail closed.
Atomic publish, replace, and revoke operations bind the exact provider and
process/listener lifecycle fields. Tunnel grants are opaque, non-cloneable,
short-lived, and explicitly revalidated against the current registry and
engine state. Pending CONNECT handles have hard-bounded exclusive expiries;
the session rejects trusted-clock rollback and prunes expired records before
enforcing capacity. Each publish attempt reclaims expired or engine-invalid
publications before duplicate/capacity checks without advancing the generation;
those records already cannot authorize a tunnel. Current records change only
on a successful mutation.

This crate does not perform DNS wire I/O, open a listener or origin socket,
issue certificates, terminate TLS, forward bytes, or by itself enable a wallet
provider. Private shared browser packages now implement those platform-adapter
building blocks and mobile/Chromium shells consume them, but there is no
installed-product qualification evidence and provider availability remains
disabled.

Published releases can be added with:

```bash
cargo add hns-loopback-proxy
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-loopback-proxy).

Licensed under either Apache-2.0 or MIT.
