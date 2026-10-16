# Changelog

The selected source version is listed in the workspace
[`CHANGELOG.md`](../../CHANGELOG.md).

## 0.2.4 - 2026-10-16

Mobile ICANN TLSA resolution now rejects CNAME chains that end without terminal
TLSA records or retained authenticated denial evidence. This prevents an
incomplete alias answer from becoming authenticated TLSA absence.

## 0.2.3 - 2026-08-23

Apply the selected stateless DANE plan to mobile and Chromium requests while
keeping authenticated TLSA records authoritative. This browser adapter retains
its PolyForm Noncommercial license. The
[0.2.3 source tag](https://github.com/handshake-rs/hns-dane-engine/tree/stateless-dane-v0.2.3/crates/hns-browser-gateway)
records the published source.

## 0.2.2 - 2026-08-23

This browser adapter retains its PolyForm Noncommercial license. A source archive alone does not qualify a browser,
mobile adapter, live network path, wallet provider, or marketplace product.
