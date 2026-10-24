# Changelog

## 0.2.5 - 2026-10-24

Migrate protocol and ECDSA dependencies to the patched crypto stack; preserve existing DNSSEC and transport behavior.

The selected source version is listed in the workspace
[`CHANGELOG.md`](../../CHANGELOG.md).

## 0.2.4 - 2026-10-16

Mobile ICANN TLSA resolution now rejects CNAME chains that end without terminal
TLSA records or retained authenticated denial evidence. This prevents an
incomplete alias answer from becoming authenticated TLSA absence.

Mobile and Chromium gateway paths discard unsupported or malformed TLSA
records while retaining usable records from the same authenticated RRset. An
RRset with no usable record remains a terminal DANE failure.

## 0.2.3 - 2026-08-23

Apply the selected stateless DANE plan to mobile and Chromium requests while
keeping authenticated TLSA records authoritative. This browser adapter retains
its PolyForm Noncommercial license. The
[0.2.3 source tag](https://github.com/handshake-rs/hns-dane-engine/tree/stateless-dane-v0.2.3/crates/hns-browser-gateway)
records the published source.

## 0.2.2 - 2026-08-23

This browser adapter retains its PolyForm Noncommercial license. A source archive alone does not qualify a browser,
mobile adapter, live network path, wallet provider, or marketplace product.
