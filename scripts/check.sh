#!/usr/bin/env sh
set -eu

cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --release

