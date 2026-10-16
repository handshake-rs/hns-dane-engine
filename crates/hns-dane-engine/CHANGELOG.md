# Changelog

This crate uses the shared `hns-dane-engine` workspace version. Complete
release notes for every public crate are maintained in the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-dane-engine/blob/v0.3.0/CHANGELOG.md).

## 0.3.1 - 2026-10-16

Browser bridge authorization now expires with the earliest locally verified
DNSSEC or HNS authority deadline that established its TLSA and DANE result.

## 0.3.0 - 2026-08-30

Re-exported and enforced the clean-break Shakescape V1 policy and P2P
transport boundary. See the canonical workspace changelog.
