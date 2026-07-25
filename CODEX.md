# Repository operating rules

This repository contains the platform-neutral HNS browser security engine.

- Keep protocol parsing and policy crates independent of async executors, operating-system DNS,
  platform UI frameworks, and persistence databases.
- HNS resolution fails closed. Never add operating-system DNS, public recursive DNS, public DoH,
  WebPKI fallback, or arbitrary HTTP proxy resolution to the HNS path.
- DNS transport is provenance, never validation authority. The AD bit and relay assertions are
  untrusted inputs.
- Direct delegated-authoritative DNS is always attempted before experimental P2P fallback.
- Requester controls are persistent and generation checked. Provider roles are explicit opt-ins.
- Every wire parser must be bounded before allocation and covered by mutation-derived negatives.
- Keep the public C ABI versioned, panic-contained, and represented in `include/hns_dane_engine.h`.
- Use Rust 1.89, edition 2024, resolver 3, and `MIT OR Apache-2.0`.
- Run `cargo test --workspace`, strict Clippy, and a release build before committing.
- Do not push from this repository.

