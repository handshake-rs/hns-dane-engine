# Engine qualification

Qualify the exact source using the pinned toolchain and immutable protocol
sources in `Cargo.toml` and `Cargo.lock`. A current source check is required
before signing or publishing any selected package.

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --release --locked
python3 scripts/verify-release.py --toolchain 1.89.0
```

Validate bounded parser mutations, local chain and Urkel proofs, DNSSEC denial,
TLSA/DANE certificate matching, typed dual-root selection, transport provenance,
request generations, cancellation, cache persistence, and panic-contained ABI
behavior. HNS resolution fails closed without validated current evidence.

Platform consumers must separately qualify their signed products, browser proxy
integration, lifecycle handling, and device networking. Workspace test success
does not establish installed-device or live-network readiness.
