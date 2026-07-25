#!/usr/bin/env sh
set -eu

cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --release
cc -std=c11 -Wall -Wextra -Werror -fsyntax-only tests/abi_header_smoke.c
