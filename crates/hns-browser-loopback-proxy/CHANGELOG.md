# Changelog

This crate follows the compatible `hns-dane-engine` release line. Complete
release notes are maintained in the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-dane-engine/blob/loopback-proxy-v0.2.3/CHANGELOG.md).

## 0.2.3 - 2026-09-03

Raised the still-bounded defaults to 128 active clients, 2,048 aggregate
requests per 10 seconds, and 1,024 requests per host per 10 seconds so modern
page bursts and overlapping navigations do not spuriously fail CONNECT with an
HTTP 429. Added regression coverage for the larger per-origin and aggregate
boundaries.
