# Changelog

This crate uses the shared `hns-dane-engine` workspace version. Its selected version is described in the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-dane-engine/blob/main/CHANGELOG.md).

## 0.2.3 - 2026-10-16

DNSKEY RRset bootstrap signatures are now verified only with DNSKEY records
whose full digests match trusted DS records. Initial and child delegation
chains reject unrelated keys added to an otherwise DS-matching keyset.

Positive RRsets now require an exact-owner signature. Wildcard-expanded
signatures fail closed until the resolver supplies authenticated wildcard
applicability proof.

## 0.2.2 - 2026-08-23

This browser adapter retains its PolyForm Noncommercial license. A source archive alone does not qualify a browser,
mobile adapter, live network path, wallet provider, or marketplace product.
