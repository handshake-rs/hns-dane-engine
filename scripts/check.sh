#!/usr/bin/env sh
set -eu

cargo fmt --all -- --check
cargo test --workspace --all-features --locked --offline
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo build --workspace --all-features --release --locked --offline
cc -std=c11 -Wall -Wextra -Werror -fsyntax-only tests/abi_header_smoke.c
