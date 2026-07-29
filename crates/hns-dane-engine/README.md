# hns-dane-engine

Runtime-independent facade for fail-closed Handshake browser resolution and
DANE validation.

The engine coordinates session and policy generations, transport admission,
query correlation, locally verified evidence, certificate matching, and
structured provenance. Native adapters own platform I/O and persistence; they
cannot substitute transport assertions for local validation.

Published releases can be added with:

```bash
cargo add hns-dane-engine
```

See the repository's
[architecture](https://github.com/handshake-rs/hns-dane-engine/blob/main/docs/architecture.md)
and
[security policy](https://github.com/handshake-rs/hns-dane-engine/blob/main/docs/security-policy.md)
for integration boundaries. The minimum supported Rust version is 1.89. API
documentation for published releases is hosted on
[docs.rs](https://docs.rs/hns-dane-engine).

Licensed under either Apache-2.0 or MIT.
