# Changelog

## Unreleased

Use the public DANE path-verifier interface for mobile and Chromium policy
decisions. PKIX-TA records return `WebPkiFailed` when WebPKI rejects the
connection. DANE-TA candidates are deduplicated and checked in one path
verification call, with the selected anchor's path-length limit enforced.
Raise the minimum `rustls-webpki` and `webpki-roots` versions to 0.103.16 and
1.0.10 respectively, addressing the emSign distrust advisories in the
transport's TLS dependency graph.
Require Tokio 1.53.3 to avoid its `AsyncFd` I/O-safety advisory.

## 0.2.4 - 2026-10-16

**Security fix:** 0.2.2 could authorize a PKIX-TA or DANE-TA TLSA record by
matching a certificate in the unverified peer-supplied list. Mobile and
Chromium users should upgrade to 0.2.4, refresh application lockfiles, and
rebuild their applications. See the repository
[upgrade note](https://github.com/handshake-rs/hns-dane-engine/blob/main/release/dane-trust-anchor-security-2026-10-23.md).

Mobile and Chromium TLS now verify usage 0 associations against the actual PKIX path and usage 2 associations against a signed path to the pinned CA. Name, CA, key usage, validity, and path length checks apply to usage 2. A full-certificate root pin fails closed when the root store has discarded its DER; SPKI root pins and full-certificate intermediate pins are checked on the verified path.

DANE-TA applies certificate name, validity, CA, key usage, and path length
checks. DANE-EE retains the DNSSEC-authenticated TLSA name binding specified by
RFC 7671 section 5.1, including certificates whose internal names differ.

Certificate-embedded stateless DANE evidence now uses the request's exact TLSA
service transport. Public requests with an HTTP protocol and TLSA transport
mismatch are rejected before network or certificate processing.

The release source and selected versions are described in the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-dane-engine/blob/main/CHANGELOG.md).

## 0.2.2 - 2026-08-23

This browser adapter retains its PolyForm Noncommercial license. A source archive alone does not qualify a browser,
mobile adapter, live network path, wallet provider, or marketplace product.
