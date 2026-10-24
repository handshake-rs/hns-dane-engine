# Changelog

## 0.2.5 - 2026-10-23

Add the public `TlsaPathVerifier` interface and
`evaluate_policy_with_path_verifier` so trusted transports can evaluate TLSA
usages 0 and 2 using authenticated certificate paths. The certificate-only
policy returns `PathValidationRequired` for these usages when no end-entity
record matches; its ignored raw `intermediate_der` field is deprecated.
Bound raw TLSA records to 256 and distinct usable records to 64, with
deduplication before path verification.

## 0.2.4 - 2026-10-16

**Security fix:** 0.2.2 could accept a PKIX-TA or DANE-TA TLSA association
against an unverified, peer-supplied certificate. An attacker could present an
unrelated leaf plus a public pinned CA certificate. Upgrade to 0.2.4 and
refresh application lockfiles. See the repository
[upgrade note](https://github.com/handshake-rs/hns-dane-engine/blob/main/release/dane-trust-anchor-security-2026-10-23.md).

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
