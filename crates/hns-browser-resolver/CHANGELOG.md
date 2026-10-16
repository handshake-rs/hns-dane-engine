# Changelog

This crate uses the shared `hns-dane-engine` workspace version. Complete
release notes for every public crate are maintained in the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-dane-engine/blob/main/CHANGELOG.md).

## 0.2.7 - 2026-10-16

Raises the browser DNSSEC dependency floor to 0.2.3 and the browser DANE floor
to 0.2.4 so positive, denial, and child-delegation validation use the corrected
trust boundaries.

## 0.2.6 - 2026-09-28

Repins the coordinated mobile-wallet engine cohort to the coherent
`hns-rs 0.5.0` protocol release while retaining the existing public light-client
and browser-adapter behavior.
