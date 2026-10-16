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
| `hns-dnssec` | `0.2.2` |
| `hns-gateway` | `0.3.0` |
| `hns-cache` | `0.2.2` |
| `hns-light-p2p` | `0.2.6` |
| `hns-light-sync` | `0.2.6` |
| `hns-transport` | `0.2.2` |
| `hns-resolver` | `0.2.2` |
| `hns-browser-observability` | `0.3.0` |
| `hns-p2p-transport` | `0.3.1` |
| `hns-dane-engine` | `0.3.0` |
| `hns-dane-engine-ffi` | `0.2.2` |
| `hns-loopback-proxy` | `0.2.2` |
| `hns-browser-primitives` | `0.2.2` |
| `hns-browser-urkel` | `0.2.2` |
| `hns-browser-dnssec` | `0.2.2` |
| `hns-browser-dane` | `0.2.3` |
| `hns-browser-chain` | `0.2.6` |
| `hns-browser-p2p` | `0.2.6` |
| `hns-browser-resolver` | `0.2.6` |
| `hns-browser-transport` | `0.2.3` |
| `hns-browser-gateway` | `0.2.3` |
| `hns-browser-loopback-proxy` | `0.2.4` |
| `hns-browser-sync` | `0.2.2` |

## Browser TLSA verification 0.2.3 - 2026-10-16

`hns-browser-dane` now rejects trust-anchor usages in its certificate-only
policy API. `hns-browser-transport` verifies usage 0 on a WebPKI-validated path
and usage 2 on a signed path to the TLSA-pinned CA, with the required certificate
checks. Both mobile and Chromium use the same verifier. Regression tests cover
unrelated anchors, a different root certificate with the same key, signed
intermediates, omitted DNS-supplied anchors, and invalid names and CA constraints.
The workspace lockfile selects `rustls` 0.23.46 and `quinn-proto` 0.11.18 to
clear the current advisory gate.

## hns-browser-loopback-proxy 0.2.4 - 2026-10-12

Adds an explicit authenticated ICANN bootstrap proxy mode for browser shells
waiting on Handshake header authority. DNS-name requests use the caller's
bounded ICANN resolver and public-address dialer; HTTPS remains an opaque
CONNECT tunnel for browser-engine WebPKI. Single-label Handshake names are
rejected in this mode. The existing whole-browser dual-root mode is unchanged.

## 0.2.2 - 2026-08-23

Engine foundations and browser adapters provide bounded protocol parsing,
locally validated HNS/DNSSEC/TLSA/DANE, transport, cache, runtime, and FFI boundaries.
