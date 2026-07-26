#!/usr/bin/env sh
set -eu

RUST_TOOLCHAIN="1.89.0"

python3 -m unittest -v tests/test_cargo_source_policy.py
python3 scripts/verify_cargo_source_policy.py
cargo +"$RUST_TOOLCHAIN" metadata --locked --offline --format-version 1 >/dev/null
cargo +"$RUST_TOOLCHAIN" deny --locked check --config deny.toml
cargo +"$RUST_TOOLCHAIN" fmt --all -- --check
cargo +"$RUST_TOOLCHAIN" test --workspace --all-targets --all-features --locked --offline
cargo +"$RUST_TOOLCHAIN" test --workspace --doc --all-features --locked --offline
cargo +"$RUST_TOOLCHAIN" test --workspace --all-features --locked --offline
cargo +"$RUST_TOOLCHAIN" test --workspace --locked --offline
cargo +"$RUST_TOOLCHAIN" clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo +"$RUST_TOOLCHAIN" build --workspace --all-features --release --locked --offline
cc -std=c11 -Wall -Wextra -Werror -fsyntax-only tests/abi_header_smoke.c
