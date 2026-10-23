# hns-browser-dane

Strict browser-adapter DANE validation for Handshake and ICANN resolution
plans. It evaluates TLSA certificate and SPKI associations and preserves
fail-closed HNS policy.

TLSA trust-anchor usages 0 (PKIX-TA) and 2 (DANE-TA) require a signed
certificate path. Use `evaluate_policy_with_path_verifier` with a trusted
`TlsaPathVerifier` implementation that validates the presented leaf against
the same server name, time, trust roots, and TLS session. The certificate-only
`evaluate_policy_with_certificate_chain` API returns
`DaneError::PathValidationRequired` when a trust-anchor record needs this
validation. Its `intermediate_der` field is deprecated because a peer-supplied
certificate list cannot establish a verified path.

The browser transport crate supplies the Rustls/WebPKI verifier for mobile and
Chromium. Other callers must implement the path-verifier trait using their own
trusted TLS backend. The policy API caps raw TLSA records at 256 and distinct
usable records at 64; duplicate records are evaluated once.

This crate is part of [hns-dane-engine](https://github.com/handshake-rs/hns-dane-engine).
It is licensed under the PolyForm Noncommercial License 1.0.0.
