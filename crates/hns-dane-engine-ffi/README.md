# hns-dane-engine-ffi

Versioned C ABI for the runtime-independent Handshake DANE engine.

The crate builds as an `rlib`, `cdylib`, or `staticlib`. Entry points catch
Rust panics, while pointer validity, buffer lengths, and allocation ownership
remain explicit caller obligations. The public header is
[`include/hns_dane_engine.h`](include/hns_dane_engine.h).

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
