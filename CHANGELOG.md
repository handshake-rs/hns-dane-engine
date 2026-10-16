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
| `hns-transport` | `0.2.2` |
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

## DNSSEC and DANE security updates - 2026-10-16

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
