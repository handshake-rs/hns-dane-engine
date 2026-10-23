# Browser DANE trust-anchor security upgrade

`hns-browser-dane` 0.2.2 and `hns-browser-transport` 0.2.2 could accept a
PKIX-TA (TLSA usage 0) or DANE-TA (TLSA usage 2) association against a
certificate supplied by the TLS peer that was not on a verified certificate
path from the leaf. In the DANE-TA case, an attacker could present an
unrelated leaf along with the public certificate named by a TLSA trust-anchor
record. In the PKIX-TA case, a WebPKI-valid leaf issued by another trusted CA
could be accepted if the peer also supplied the pinned CA certificate. This
could allow impersonation of an affected HTTPS origin.

| Crate | Affected release | Fixed release |
| --- | --- | --- |
| `hns-browser-dane` | 0.2.2 | 0.2.4 |
| `hns-browser-transport` | 0.2.2 | 0.2.4 |

The issue affects the mobile and Chromium browser transports using TLSA
usages 0 or 2. TLSA usages 1 (PKIX-EE) and 3 (DANE-EE) are not affected by
this certificate-path issue.

## Upgrade

Raise direct dependencies on both crates to at least 0.2.4. Refresh existing
`Cargo.lock` files so they select 0.2.4, then rebuild and redistribute
applications that contain the affected code. Updating only `Cargo.toml` does
not replace code already built into an application. Check transitive
dependencies, including browser gateway and resolver integrations, for locked
0.2.2 copies.

The 0.2.4 `hns-browser-dane` certificate-only policy API deliberately rejects
usages 0 and 2 because it cannot verify a certificate path from the inputs it
receives. Callers that need these usages must use the corrected browser
transport verifier, which checks the signed path and TLSA association
together. The mobile and Chromium transports in `hns-browser-transport` 0.2.4
verify usage 0 against the WebPKI-verified path and usage 2 against a signed
path to the matched trust anchor, including name, validity, CA, key usage,
and path length checks.
