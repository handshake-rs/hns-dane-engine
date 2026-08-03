# hns-dane-engine-ffi

Versioned C ABI for the runtime-independent Handshake DANE engine.

The crate builds as an `rlib`, `cdylib`, or `staticlib`. Entry points catch
Rust panics, while pointer validity, buffer lengths, and allocation ownership
remain explicit caller obligations. The public header is
[`include/hns_dane_engine.h`](include/hns_dane_engine.h).

The provider-authority consumer ABI accepts only an opaque context moved from
an engine-authorized Rust outcome. Native code can inspect its immutable typed
bindings, copy its bounded canonical host, check it against current engine
state, and destroy it. C cannot construct, import, clone, or serialize an
authority. Pure-C namespace/context minting and product provider wiring remain
unavailable. Each handle retains the exact live Rust engine used for
currentness checks until native destruction; a mismatched engine/context pair
cannot become authority through its output projection.

Published releases can be added with:

```bash
cargo add hns-dane-engine-ffi
```

See the repository's
[ABI documentation](https://github.com/handshake-rs/hns-dane-engine/blob/main/docs/abi.md)
for the complete integration contract. The minimum supported Rust version is
1.89. API documentation for published releases is hosted on
[docs.rs](https://docs.rs/hns-dane-engine-ffi).

Licensed under either Apache-2.0 or MIT.
