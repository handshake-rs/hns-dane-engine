# Current package versions

Each public package keeps the version selected in its manifest. Release only
packages affected by a source or dependency change. Use [the release procedure](docs/releasing.md)
for validation.

| Package | Selected version |
| --- | --- |
| `hns-dns-wire` | `0.2.2` |
| `hns-browser-runtime` | `0.2.2` |
| `hns-icann-dane` | `0.2.2` |
| `hns-namespace-resolution` | `0.2.3` |
| `hns-resolution-policy` | `0.3.0` |
| `hns-light-chain` | `0.2.6` |
| `hns-light-wallet` | `0.2.6` |
| `hns-dane` | `0.2.2` |
| `hns-dnssec` | `0.2.3` |
| `hns-gateway` | `0.3.0` |
| `hns-cache` | `0.2.2` |
| `hns-light-p2p` | `0.2.6` |
| `hns-light-sync` | `0.2.6` |
| `hns-transport` | `0.2.3` |
| `hns-resolver` | `0.2.3` |
| `hns-browser-observability` | `0.3.0` |
| `hns-p2p-transport` | `0.3.1` |
| `hns-dane-engine` | `0.3.1` |
| `hns-dane-engine-ffi` | `0.2.2` |
| `hns-loopback-proxy` | `0.2.2` |
| `hns-browser-primitives` | `0.2.2` |
| `hns-browser-urkel` | `0.2.2` |
| `hns-browser-dnssec` | `0.2.3` |
| `hns-browser-dane` | `0.2.4` |
| `hns-browser-chain` | `0.2.6` |
| `hns-browser-p2p` | `0.2.6` |
| `hns-browser-resolver` | `0.2.7` |
| `hns-browser-transport` | `0.2.4` |
| `hns-browser-gateway` | `0.2.4` |
| `hns-browser-loopback-proxy` | `0.2.4` |
| `hns-browser-sync` | `0.2.2` |

## Unreleased browser DANE follow-up

The browser DANE policy now exposes a path-verifier interface for TLSA usages
0 and 2. The certificate-only API reports when a verified path is required,
and its ignored raw-intermediate field is deprecated. Mobile and Chromium
transports deduplicate and bound TLSA records, validate DANE-TA candidates in
one path-building pass, enforce the selected anchor's path-length limit, and
report WebPKI rejection for PKIX-TA records. These changes have not yet been
published as new crate versions.
The transport also raises its `rustls-webpki` and `webpki-roots` minimums to
0.103.16 and 1.0.10 to remove the newly distrusted emSign path from its TLS
dependency graph.
The lockfile also updates `ctutils` to 0.4.4 and `tokio` to 1.53.3 for
their newly disclosed security advisories.

## DNSSEC and DANE security updates - 2026-10-16

**Security notice for browser DANE users:** `hns-browser-dane` 0.2.2 and
`hns-browser-transport` 0.2.2 accepted TLSA trust-anchor usages 0 (PKIX-TA)
and 2 (DANE-TA) against certificates supplied by the peer without requiring
the matched certificate to belong to a verified path from the leaf. An attacker
able to intercept a connection could use a public pinned CA certificate to
impersonate a protected origin. These versions should not be used. Upgrade
both crates to 0.2.4, update application lockfiles, and rebuild affected
browser or mobile applications. See the
[upgrade note](release/dane-trust-anchor-security-2026-10-23.md) for the
affected paths and migration details.

`hns-transport` 0.2.3 raises its Handshake protocol dependency cohort to
0.5.0 so its public types remain compatible with `hns-light-chain` 0.2.6 in a
registry-only build. This closes the dependency-resolution failure exposed by
the staged security publication.

DNSKEY bootstrap now requires the DNSKEY RRset signature to verify with the
exact key authenticated by the parent DS digest. The complete DNSKEY RRset is
trusted only after that check, preserving normal KSK and ZSK operation while
rejecting added-key and same-tag substitution.

Mobile ICANN TLSA resolution now rejects a CNAME chain that ends without TLSA
data or retained authenticated denial evidence. Stateless certificate evidence
derives its TLSA owner from the selected TCP, UDP, or SCTP service transport;
HTTP/3 therefore verifies `_udp`, and direct transport callers cannot submit a
protocol and TLSA transport mismatch.

TLSA usages 0 and 2 are checked on authenticated certificate paths in both
mobile and Chromium transports. The workspace lockfile selects `rustls`
0.23.46 and `quinn-proto` 0.11.18 to clear the current advisory gate.
TLSA records with empty or incorrectly sized association data are unusable;
unsupported records are discarded without hiding usable records in the same
RRset. Stateless authentication chains enforce their encoded vector length,
and certificate-only policy helpers derive SPKI bytes from the certificate.
Usage 2 applies certificate name, validity, CA, key usage, and path length
checks. Usage 3 retains the DNSSEC TLSA name binding required by RFC 7671.

Strict engine bridge authorization now expires with the earliest retained
HNS currency, DS, DNSKEY, CNAME, TLSA TTL, or RRSIG deadline. Stale keysets and
zero-duration evidence cannot authorize a later browser connection.

## hns-browser-loopback-proxy 0.2.4 - 2026-10-12

Adds an explicit authenticated ICANN bootstrap proxy mode for browser shells
waiting on Handshake header authority. DNS-name requests use the caller's
bounded ICANN resolver and public-address dialer; HTTPS remains an opaque
CONNECT tunnel for browser-engine WebPKI. Single-label Handshake names are
rejected in this mode. The existing whole-browser dual-root mode is unchanged.

## 0.2.2 - 2026-08-23

Engine foundations and browser adapters provide bounded protocol parsing,
locally validated HNS/DNSSEC/TLSA/DANE, transport, cache, runtime, and FFI boundaries.
