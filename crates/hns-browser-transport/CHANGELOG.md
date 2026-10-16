# Changelog

## 0.2.3 - 2026-10-16

Mobile and Chromium TLS now verify usage 0 associations against the actual PKIX path and usage 2 associations against a signed path to the pinned CA. Name, CA, key usage, validity, and path length checks apply to usage 2. A full-certificate root pin fails closed when the root store has discarded its DER; SPKI root pins and full-certificate intermediate pins are checked on the verified path.

The release source and selected versions are described in the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-dane-engine/blob/main/CHANGELOG.md).

## 0.2.2 - 2026-08-23

This browser adapter retains its PolyForm Noncommercial license. A source archive alone does not qualify a browser,
mobile adapter, live network path, wallet provider, or marketplace product.
