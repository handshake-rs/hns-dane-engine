# Changelog

## 0.2.4 - 2026-10-16

TLSA trust-anchor usages 0 and 2 now fail closed in the certificate-only policy API. Callers must use a transport verifier that checks a signed certificate path before accepting either usage.

TLSA parsing rejects empty Exact associations and incorrectly sized SHA-256 or
SHA-512 associations. RRset consumers discard unusable records while retaining
usable records. Public policy helpers derive SPKI bytes from certificate DER,
and stateless RFC 9102 authentication chains require an exact encoded length.

Stateless DANE verification now accepts an explicit TCP, UDP, or SCTP service
transport when deriving the authenticated TLSA owner. The original entry point
remains as a deprecated TCP-only compatibility wrapper.

The release source and selected versions are described in the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-dane-engine/blob/main/CHANGELOG.md).

## 0.2.2 - 2026-08-23

This browser adapter retains its PolyForm Noncommercial license. A source archive alone does not qualify a browser,
mobile adapter, live network path, wallet provider, or marketplace product.
