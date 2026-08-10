#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

public_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    release/public-crates.txt)

for package in $public_crates
do
    case "$package" in
        hns-*) ;;
        *)
            echo "error: invalid public package name: $package" >&2
            exit 1
            ;;
    esac
    case "$package" in
        *[!a-z0-9-]*)
            echo "error: invalid public package name: $package" >&2
            exit 1
            ;;
    esac
    if [ ! -f "crates/$package/Cargo.toml" ]
    then
        echo "error: public package directory is missing: crates/$package" >&2
        exit 1
    fi
    cp -- LICENSE-APACHE "crates/$package/LICENSE-APACHE"
    cp -- LICENSE-MIT "crates/$package/LICENSE-MIT"
    cp -- release/CRATE-CHANGELOG.md "crates/$package/CHANGELOG.md"
done

mkdir -p \
    crates/hns-dns-wire/fixtures/dns \
    crates/hns-dane/fixtures/dane \
    crates/hns-dane-engine/fixtures/dane \
    crates/hns-dane-engine-ffi/fixtures/dane

for fixture in \
    basic-query.hex \
    compressed-a-response-ad.hex \
    mutation-compression-self-loop.hex \
    mutation-count-bomb.hex \
    mutation-pointer-out-of-bounds.hex \
    tlsa-response.hex
do
    cp -- "fixtures/dns/$fixture" "crates/hns-dns-wire/fixtures/dns/$fixture"
done

for package in hns-dane hns-dane-engine hns-dane-engine-ffi
do
    cp -- fixtures/dane/self-signed-cert.der.hex \
        "crates/$package/fixtures/dane/self-signed-cert.der.hex"
done
cp -- fixtures/dane/self-signed-spki.der.hex \
    crates/hns-dane/fixtures/dane/self-signed-spki.der.hex
