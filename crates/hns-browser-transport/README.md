# hns-browser-transport

Browser origin-transport adapters with explicit mobile and Chromium feature
contracts for HTTP, TLS, and authenticated DANE/WebPKI policy enforcement.

The mobile and Chromium adapters implement `hns-browser-dane`'s public
`TlsaPathVerifier` contract. Each connection checks PKIX-TA records on the
WebPKI-verified path and DANE-TA records against a signed path to a matched
trust anchor. DANE-TA candidates are deduplicated and validated together;
the selected anchor's path-length limit is checked on its verified path.

This crate is part of [hns-dane-engine](https://github.com/handshake-rs/hns-dane-engine).
It is licensed under the PolyForm Noncommercial License 1.0.0.
