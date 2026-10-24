# Changelog

## 0.3.2 - 2026-10-24

Migrate published protocol and ECDSA dependencies to patched k256/p256 0.14 and crypto-bigint 0.7.7; preserve existing DNSSEC and transport behavior.

This crate uses the shared `hns-dane-engine` workspace version. Complete
release notes for every public crate are maintained in the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-dane-engine/blob/v0.3.0/CHANGELOG.md).

## 0.3.1 - 2026-08-30

Corrected the packaged gateway dependency edge so registry consumers resolve
only the Shakescape V1 policy type graph.
