#!/usr/bin/env sh
set -eu

RUST_TOOLCHAIN="1.89.0"

python3 -m unittest -v tests/test_cargo_source_policy.py
python3 scripts/verify_cargo_source_policy.py
cargo +"$RUST_TOOLCHAIN" metadata --locked --offline --format-version 1 >/dev/null
cargo +"$RUST_TOOLCHAIN" deny --locked check --config deny.toml
cargo +"$RUST_TOOLCHAIN" fmt --all -- --check
cargo +"$RUST_TOOLCHAIN" test --workspace --all-targets --locked --offline
cargo +"$RUST_TOOLCHAIN" test --workspace --doc --locked --offline
cargo +"$RUST_TOOLCHAIN" clippy --workspace --all-targets --locked --offline -- -D warnings
cargo +"$RUST_TOOLCHAIN" build --workspace --release --locked --offline
for package in hns-browser-gateway hns-browser-loopback-proxy hns-browser-transport; do
    cargo +"$RUST_TOOLCHAIN" test --package "$package" --all-targets \
        --no-default-features --features mobile --locked --offline
    cargo +"$RUST_TOOLCHAIN" test --package "$package" --doc \
        --no-default-features --features mobile --locked --offline
    cargo +"$RUST_TOOLCHAIN" clippy --package "$package" --all-targets \
        --no-default-features --features mobile --locked --offline -- -D warnings
    cargo +"$RUST_TOOLCHAIN" build --package "$package" --release \
        --no-default-features --features mobile --locked --offline
done
cmp include/hns_dane_engine.h crates/hns-dane-engine-ffi/include/hns_dane_engine.h
cc -std=c11 -Wall -Wextra -Werror -fsyntax-only tests/abi_header_smoke.c
python3 scripts/verify-release.py --toolchain "$RUST_TOOLCHAIN"
./scripts/check-publish-arguments.sh
./scripts/publish.sh --archive-only
