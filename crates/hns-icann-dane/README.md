# hns-icann-dane

Shared browser policy for automatic DANE discovery in the ICANN namespace.

The crate consumes typed evidence from a TLS-authenticated validating DoH
adapter. Resolver failures and bogus DNSSEC never become authenticated absence,
and WebPKI is retained only after a proven insecure delegation or
authenticated TLSA absence.

Published releases can be added with:

```bash
cargo add hns-icann-dane
```

This crate is part of
[`hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine).
The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-icann-dane).

Licensed under either Apache-2.0 or MIT.
