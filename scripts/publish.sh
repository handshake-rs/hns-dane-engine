#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

rust_toolchain=${RUST_TOOLCHAIN:-1.89.0}
publish_new_interval_seconds=${PUBLISH_NEW_INTERVAL_SECONDS-605}
publish_update_interval_seconds=${PUBLISH_UPDATE_INTERVAL_SECONDS-65}
mode=${1:---dry-run}
requested_package=${2:-}
confirmed_version=${3:-}
argument_count=$#
release_commit=$(git rev-parse HEAD)
release_tmp=
require_clean_archive_vcs=no
package_mode='publish-dry-run'
release_manifest=release/public-crates.txt
protocol_repository=https://github.com/handshake-rs/hns-rs.git
protocol_revision=73611a0d83778e157b35f28ca2197d068e83fc61
protocol_version=0.4.1
protocol_crates='hns-encoding hns-rollback-journal hns-hrm hns-primitives hns-covenants hns-dns-relay-protocol hns-header-consensus hns-service-authority hns-odoh-protocol hns-p2p-experimental hns-urkel-proof hns-transaction hns-chat-protocol hns-hnsr-protocol hns-script hns-mining hns-swap hns-marketplace-protocol hns-p2p-wire'
protocol_checksum_manifest=release/hns-rs-0.4.1-crates.sha256
prepublished_engine_version=0.2.2
prepublished_engine_revision=b7fdf8826c81b77650a0f740d1f05314b74969f9
prepublished_engine_manifest=release/prepublished-0.2.2-crates.txt
prepublished_engine_checksum_manifest=release/hns-dane-engine-0.2.2-crates.sha256
prepublished_adapter_version=0.2.2
prepublished_adapter_revision=3907e2a93eb7b10ee7deb1f179ce67824277c82a
prepublished_adapter_manifest=release/prepublished-browser-adapters-0.2.2-crates.txt
prepublished_adapter_checksum_manifest=release/hns-dane-engine-browser-adapters-0.2.2-crates.sha256
prepublished_patch_version=0.2.3
prepublished_patch_revision=142117058690220b066782d8ff0655cf0a2670b3
prepublished_patch_manifest=release/prepublished-stateless-dane-0.2.3-crates.txt
prepublished_patch_checksum_manifest=release/hns-dane-engine-stateless-dane-0.2.3-crates.sha256
prepublished_light_client_version=0.2.3
prepublished_light_client_revision=87d2346c13ade4987801e0f1367bd604fd77c9f0
prepublished_light_client_manifest=release/prepublished-light-client-0.2.3-crates.txt
prepublished_light_client_checksum_manifest=release/hns-dane-engine-light-client-0.2.3-crates.sha256
prepublished_policy_version=0.3.0
prepublished_policy_revision=2e06af3489bd40e0ef90b847101e4f6a7aeebe71
prepublished_policy_manifest=release/prepublished-policy-0.3.0-crates.txt
prepublished_policy_checksum_manifest=release/hns-dane-engine-policy-0.3.0-crates.sha256
prepublished_successor_revision=ee222208a7750dcb061c5c3cc16b8cf82d75033e
prepublished_successor_manifest=release/prepublished-shakescape-successor-crates.txt
prepublished_successor_checksum_manifest=release/hns-dane-engine-shakescape-successor-crates.sha256
prepublished_loopback_version=0.2.3
prepublished_loopback_revision=9aa1b1ef48cd3628fbd579f208a865255301eb03
prepublished_loopback_manifest=release/prepublished-loopback-proxy-0.2.3-crates.txt
prepublished_loopback_checksum_manifest=release/hns-dane-engine-loopback-proxy-0.2.3-crates.sha256

cleanup_release_tmp() {
    if [ -n "$release_tmp" ] && [ -d "$release_tmp" ]
    then
        rm -rf -- "$release_tmp"
    fi
}

trap cleanup_release_tmp EXIT HUP INT TERM

usage() {
    echo "usage: $0 [--archive-only [PUBLIC-PACKAGE]|--dry-run [PUBLIC-PACKAGE]|--execute --confirm-publish VERSION]" >&2
}

ensure_release_tmp() {
    if [ -z "$release_tmp" ]
    then
        release_tmp=$(mktemp -d "${TMPDIR:-/tmp}/hns-dane-engine-release.XXXXXX")
    fi
}

verify_release_source_unchanged() {
    current_commit=$(git rev-parse HEAD)
    if [ "$current_commit" != "$release_commit" ]
    then
        echo "error: release HEAD changed from $release_commit to $current_commit" >&2
        exit 1
    fi
    if [ -n "$(git status --porcelain --untracked-files=normal)" ]
    then
        echo "error: release worktree changed after validation" >&2
        exit 1
    fi
}

public_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    "$release_manifest")
prepublished_engine_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    "$prepublished_engine_manifest")
prepublished_adapter_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    "$prepublished_adapter_manifest")
prepublished_patch_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    "$prepublished_patch_manifest")
prepublished_light_client_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    "$prepublished_light_client_manifest")
prepublished_policy_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    "$prepublished_policy_manifest")
prepublished_successor_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    "$prepublished_successor_manifest")
prepublished_loopback_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    "$prepublished_loopback_manifest")

last_public_crate=
for package in $public_crates
do
    last_public_crate=$package
done

require_public_crate() {
    requested=$1
    for package in $public_crates
    do
        if [ "$package" = "$requested" ]
        then
            return
        fi
    done
    echo "error: $requested is not in the public package allowlist" >&2
    exit 2
}

is_prepublished_engine_package() {
    package=$1
    version=$2
    if [ "$version" != "$prepublished_engine_version" ]
    then
        return 1
    fi
    for prepublished_package in $prepublished_engine_crates
    do
        if [ "$package" = "$prepublished_package" ]
        then
            return 0
        fi
    done
    return 1
}

is_prepublished_adapter_package() {
    package=$1
    version=$2
    if [ "$version" != "$prepublished_adapter_version" ]
    then
        return 1
    fi
    for prepublished_package in $prepublished_adapter_crates
    do
        if [ "$package" = "$prepublished_package" ]
        then
            return 0
        fi
    done
    return 1
}

is_prepublished_patch_package() {
    package=$1
    version=$2
    if [ "$version" != "$prepublished_patch_version" ]
    then
        return 1
    fi
    for prepublished_package in $prepublished_patch_crates
    do
        if [ "$package" = "$prepublished_package" ]
        then
            return 0
        fi
    done
    return 1
}

is_prepublished_light_client_package() {
    package=$1
    version=$2
    if [ "$version" != "$prepublished_light_client_version" ]
    then
        return 1
    fi
    for prepublished_package in $prepublished_light_client_crates
    do
        if [ "$package" = "$prepublished_package" ]
        then
            return 0
        fi
    done
    return 1
}

is_prepublished_policy_package() {
    package=$1
    version=$2
    [ "$version" = "$prepublished_policy_version" ] || return 1
    [ "$package" = "hns-resolution-policy" ]
}

is_prepublished_successor_package() {
    package=$1
    version=$2
    case "$package:$version" in
        hns-gateway:0.3.0|hns-browser-observability:0.3.0|\
            hns-p2p-transport:0.3.1|hns-dane-engine:0.3.0)
            return 0
            ;;
        *) return 1 ;;
    esac
}

is_prepublished_loopback_package() {
    package=$1
    version=$2
    [ "$version" = "$prepublished_loopback_version" ] || return 1
    [ "$package" = "hns-browser-loopback-proxy" ]
}

is_prepublished_package() {
    is_prepublished_engine_package "$1" "$2" ||
        is_prepublished_adapter_package "$1" "$2" ||
        is_prepublished_patch_package "$1" "$2" ||
        is_prepublished_light_client_package "$1" "$2" ||
        is_prepublished_policy_package "$1" "$2" ||
        is_prepublished_successor_package "$1" "$2" ||
        is_prepublished_loopback_package "$1" "$2"
}

run_package_operation() {
    package=$1
    shift
    if [ "$package_mode" = "archive-only" ]
    then
        cargo +"$rust_toolchain" package \
            --locked \
            --no-verify \
            --allow-dirty \
            -p "$package" \
            "$@"
    else
        cargo +"$rust_toolchain" publish \
            --locked \
            --dry-run \
            --allow-dirty \
            -p "$package" \
            "$@"
    fi
}

package_with_local_dependencies() {
    package=$1
    case "$package" in
        hns-dns-wire|hns-browser-runtime|hns-icann-dane|\
            hns-namespace-resolution|hns-resolution-policy)
            run_package_operation "$package"
            ;;
        hns-light-chain)
            run_package_operation "$package"
            ;;
        hns-light-wallet)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-light-chain.path="crates/hns-light-chain"'
            ;;
        hns-light-p2p)
            run_package_operation "$package"
            ;;
        hns-dane|hns-dnssec|hns-cache)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-dns-wire.path="crates/hns-dns-wire"'
            ;;
        hns-gateway)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-resolution-policy.path="crates/hns-resolution-policy"'
            ;;
        hns-light-sync)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-light-chain.path="crates/hns-light-chain"'
            ;;
        hns-transport)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-dns-wire.path="crates/hns-dns-wire"' \
                --config 'patch.crates-io.hns-light-chain.path="crates/hns-light-chain"'
            ;;
        hns-resolver)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-dns-wire.path="crates/hns-dns-wire"' \
                --config 'patch.crates-io.hns-dnssec.path="crates/hns-dnssec"' \
                --config 'patch.crates-io.hns-icann-dane.path="crates/hns-icann-dane"' \
                --config 'patch.crates-io.hns-light-chain.path="crates/hns-light-chain"'
            ;;
        hns-browser-observability)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-browser-runtime.path="crates/hns-browser-runtime"' \
                --config 'patch.crates-io.hns-icann-dane.path="crates/hns-icann-dane"' \
                --config 'patch.crates-io.hns-namespace-resolution.path="crates/hns-namespace-resolution"' \
                --config 'patch.crates-io.hns-resolution-policy.path="crates/hns-resolution-policy"'
            ;;
        hns-p2p-transport)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-dns-wire.path="crates/hns-dns-wire"' \
                --config 'patch.crates-io.hns-gateway.path="crates/hns-gateway"' \
                --config 'patch.crates-io.hns-light-chain.path="crates/hns-light-chain"' \
                --config 'patch.crates-io.hns-resolution-policy.path="crates/hns-resolution-policy"' \
                --config 'patch.crates-io.hns-transport.path="crates/hns-transport"'
            ;;
        hns-dane-engine)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-browser-observability.path="crates/hns-browser-observability"' \
                --config 'patch.crates-io.hns-browser-runtime.path="crates/hns-browser-runtime"' \
                --config 'patch.crates-io.hns-dane.path="crates/hns-dane"' \
                --config 'patch.crates-io.hns-dns-wire.path="crates/hns-dns-wire"' \
                --config 'patch.crates-io.hns-dnssec.path="crates/hns-dnssec"' \
                --config 'patch.crates-io.hns-gateway.path="crates/hns-gateway"' \
                --config 'patch.crates-io.hns-icann-dane.path="crates/hns-icann-dane"' \
                --config 'patch.crates-io.hns-light-chain.path="crates/hns-light-chain"' \
                --config 'patch.crates-io.hns-namespace-resolution.path="crates/hns-namespace-resolution"' \
                --config 'patch.crates-io.hns-p2p-transport.path="crates/hns-p2p-transport"' \
                --config 'patch.crates-io.hns-resolution-policy.path="crates/hns-resolution-policy"' \
                --config 'patch.crates-io.hns-resolver.path="crates/hns-resolver"' \
                --config 'patch.crates-io.hns-transport.path="crates/hns-transport"'
            ;;
        hns-dane-engine-ffi|hns-loopback-proxy)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-browser-observability.path="crates/hns-browser-observability"' \
                --config 'patch.crates-io.hns-browser-runtime.path="crates/hns-browser-runtime"' \
                --config 'patch.crates-io.hns-dane.path="crates/hns-dane"' \
                --config 'patch.crates-io.hns-dane-engine.path="crates/hns-dane-engine"' \
                --config 'patch.crates-io.hns-dns-wire.path="crates/hns-dns-wire"' \
                --config 'patch.crates-io.hns-dnssec.path="crates/hns-dnssec"' \
                --config 'patch.crates-io.hns-gateway.path="crates/hns-gateway"' \
                --config 'patch.crates-io.hns-icann-dane.path="crates/hns-icann-dane"' \
                --config 'patch.crates-io.hns-light-chain.path="crates/hns-light-chain"' \
                --config 'patch.crates-io.hns-namespace-resolution.path="crates/hns-namespace-resolution"' \
                --config 'patch.crates-io.hns-p2p-transport.path="crates/hns-p2p-transport"' \
                --config 'patch.crates-io.hns-resolution-policy.path="crates/hns-resolution-policy"' \
                --config 'patch.crates-io.hns-resolver.path="crates/hns-resolver"' \
                --config 'patch.crates-io.hns-transport.path="crates/hns-transport"'
            ;;
        hns-browser-primitives)
            run_package_operation "$package"
            ;;
        hns-browser-urkel|hns-browser-dnssec|hns-browser-chain)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-browser-primitives.path="crates/hns-browser-primitives"'
            ;;
        hns-browser-dane)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-browser-primitives.path="crates/hns-browser-primitives"' \
                --config 'patch.crates-io.hns-browser-dnssec.path="crates/hns-browser-dnssec"' \
                --config 'patch.crates-io.hns-browser-urkel.path="crates/hns-browser-urkel"'
            ;;
        hns-browser-p2p)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-browser-primitives.path="crates/hns-browser-primitives"' \
                --config 'patch.crates-io.hns-browser-urkel.path="crates/hns-browser-urkel"'
            ;;
        hns-browser-resolver)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-browser-primitives.path="crates/hns-browser-primitives"' \
                --config 'patch.crates-io.hns-browser-dane.path="crates/hns-browser-dane"' \
                --config 'patch.crates-io.hns-browser-dnssec.path="crates/hns-browser-dnssec"'
            ;;
        hns-browser-transport)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-browser-dane.path="crates/hns-browser-dane"'
            ;;
        hns-browser-gateway)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-browser-primitives.path="crates/hns-browser-primitives"' \
                --config 'patch.crates-io.hns-browser-dane.path="crates/hns-browser-dane"' \
                --config 'patch.crates-io.hns-browser-resolver.path="crates/hns-browser-resolver"' \
                --config 'patch.crates-io.hns-browser-transport.path="crates/hns-browser-transport"' \
                --config 'patch.crates-io.hns-icann-dane.path="crates/hns-icann-dane"' \
                --config 'patch.crates-io.hns-namespace-resolution.path="crates/hns-namespace-resolution"'
            ;;
        hns-browser-loopback-proxy)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-browser-primitives.path="crates/hns-browser-primitives"' \
                --config 'patch.crates-io.hns-browser-dane.path="crates/hns-browser-dane"' \
                --config 'patch.crates-io.hns-browser-resolver.path="crates/hns-browser-resolver"'
            ;;
        hns-browser-sync)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-browser-chain.path="crates/hns-browser-chain"' \
                --config 'patch.crates-io.hns-browser-primitives.path="crates/hns-browser-primitives"' \
                --config 'patch.crates-io.hns-browser-p2p.path="crates/hns-browser-p2p"' \
                --config 'patch.crates-io.hns-browser-urkel.path="crates/hns-browser-urkel"'
            ;;
        *)
            echo "error: missing package dependency mapping for $package" >&2
            exit 1
            ;;
    esac
}

package_version() {
    package=$1
    package_id=$(cargo +"$rust_toolchain" pkgid -p "$package")
    version=${package_id##*@}
    if [ "$version" = "$package_id" ]
    then
        version=${package_id##*#}
    fi
    printf '%s\n' "$version"
}

package_target_dir() {
    cargo +"$rust_toolchain" metadata \
        --locked \
        --no-deps \
        --format-version 1 |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
}

verify_archive_entry() {
    package=$1
    archive=$2
    archive_root=$3
    relative_path=$4
    if ! tar -tf "$archive" | grep -Fqx "$archive_root/$relative_path"
    then
        echo "error: normalized $package package omits $relative_path" >&2
        exit 1
    fi
}

verify_archive_copy() {
    package=$1
    archive=$2
    archive_root=$3
    relative_path=$4
    repository_path=$5
    verify_archive_entry "$package" "$archive" "$archive_root" "$relative_path"
    if ! tar -xOf "$archive" "$archive_root/$relative_path" |
        cmp -s - "$repository_path"
    then
        echo "error: normalized $package $relative_path differs from $repository_path" >&2
        exit 1
    fi
}

verify_common_source_package() {
    package=$1
    version=$(package_version "$package")
    package_target=$(package_target_dir)
    archive="$package_target/package/$package-$version.crate"
    archive_root="$package-$version"

    if [ ! -f "$archive" ]
    then
        echo "error: Cargo did not create $archive" >&2
        exit 1
    fi

    for relative_path in .cargo_vcs_info.json Cargo.toml Cargo.toml.orig
    do
        verify_archive_entry "$package" "$archive" "$archive_root" "$relative_path"
    done
    for relative_path in CHANGELOG.md README.md
    do
        verify_archive_copy "$package" "$archive" "$archive_root" \
            "$relative_path" "crates/$package/$relative_path"
    done
    case "$package" in
        hns-browser-chain|hns-browser-dane|hns-browser-dnssec|\
        hns-browser-gateway|hns-browser-loopback-proxy|hns-browser-p2p|\
        hns-browser-primitives|hns-browser-resolver|hns-browser-sync|\
        hns-browser-transport|hns-browser-urkel)
            verify_archive_copy "$package" "$archive" "$archive_root" \
                LICENSE-POLYFORM-NONCOMMERCIAL \
                "crates/$package/LICENSE-POLYFORM-NONCOMMERCIAL"
            ;;
        *)
            for relative_path in LICENSE-APACHE LICENSE-MIT
            do
                verify_archive_copy "$package" "$archive" "$archive_root" \
                    "$relative_path" "crates/$package/$relative_path"
            done
            ;;
    esac

    normalized_manifest=$(tar -xOf "$archive" "$archive_root/Cargo.toml")
    # Normalized manifests may retain target paths under [lib], [[test]],
    # [[example]], and [[bench]]. Dependency source selectors must not survive.
    if printf '%s\n' "$normalized_manifest" |
        awk '
            /^[[:space:]]*\[/ {
                header = $0
                gsub(/[[:space:]]/, "", header)
                in_dependency_table = \
                    header ~ /^\[(dependencies|dev-dependencies|build-dependencies)(\.[^]]+)?\]$/ || \
                    header ~ /^\[target\..+\.(dependencies|dev-dependencies|build-dependencies)(\.[^]]+)?\]$/ || \
                    header ~ /^\[workspace\.(dependencies|dev-dependencies|build-dependencies)(\.[^]]+)?\]$/
                next
            }
            in_dependency_table && \
                /(^|[[:space:]{,])(path|git|branch|tag|rev)[[:space:]]*=/ {
                found = 1
                exit
            }
            END { exit found ? 0 : 1 }
        '
    then
        echo "error: normalized $package manifest retains a dependency source selector" >&2
        exit 1
    fi

    vcs_info=$(tar -xOf "$archive" "$archive_root/.cargo_vcs_info.json")
    compact_vcs_info=$(printf '%s' "$vcs_info" | tr -d '[:space:]')
    case "$compact_vcs_info" in
        *\"sha1\":\"$release_commit\"*) ;;
        *)
            echo "error: normalized $package package does not identify source commit $release_commit" >&2
            exit 1
            ;;
    esac
    if [ "$require_clean_archive_vcs" = "yes" ]
    then
        case "$compact_vcs_info" in
            *\"dirty\":true*)
                echo "error: normalized $package package records a dirty source tree" >&2
                exit 1
                ;;
        esac
    fi
}

verify_ffi_source_package() {
    package=hns-dane-engine-ffi
    version=$(package_version "$package")
    package_target=$(package_target_dir)
    archive="$package_target/package/$package-$version.crate"
    archive_root="$package-$version"
    verify_archive_copy "$package" "$archive" "$archive_root" \
        include/hns_dane_engine.h include/hns_dane_engine.h
}

verify_fixture_source_package() {
    package=$1
    version=$(package_version "$package")
    package_target=$(package_target_dir)
    archive="$package_target/package/$package-$version.crate"
    archive_root="$package-$version"

    case "$package" in
        hns-dns-wire)
            for fixture in \
                basic-query.hex \
                compressed-a-response-ad.hex \
                mutation-compression-self-loop.hex \
                mutation-count-bomb.hex \
                mutation-pointer-out-of-bounds.hex \
                tlsa-response.hex
            do
                relative_path="fixtures/dns/$fixture"
                verify_archive_copy "$package" "$archive" "$archive_root" \
                    "$relative_path" "crates/$package/$relative_path"
            done
            ;;
        hns-dane)
            for fixture in self-signed-cert.der.hex self-signed-spki.der.hex
            do
                relative_path="fixtures/dane/$fixture"
                verify_archive_copy "$package" "$archive" "$archive_root" \
                    "$relative_path" "crates/$package/$relative_path"
            done
            ;;
        hns-dane-engine|hns-dane-engine-ffi)
            relative_path=fixtures/dane/self-signed-cert.der.hex
            verify_archive_copy "$package" "$archive" "$archive_root" \
                "$relative_path" "crates/$package/$relative_path"
            ;;
    esac
}

verify_source_package() {
    package=$1
    verify_common_source_package "$package"
    verify_fixture_source_package "$package"
    case "$package" in
        hns-dane-engine-ffi) verify_ffi_source_package ;;
    esac
}

create_source_package() {
    package=$1
    cargo +"$rust_toolchain" package \
        --locked \
        --no-verify \
        -p "$package"
    verify_source_package "$package"
}

create_registry_source_package() {
    package=$1
    cargo +"$rust_toolchain" publish \
        --locked \
        --dry-run \
        -p "$package"
    verify_source_package "$package"
}

published_crate_status() {
    package=$1
    version=$2
    curl \
        --silent \
        --show-error \
        --user-agent "hns-dane-engine-release/$version (https://github.com/handshake-rs/hns-dane-engine)" \
        --output /dev/null \
        --write-out '%{http_code}' \
        "https://crates.io/api/v1/crates/$package"
}

published_package_status() {
    package=$1
    version=$2
    curl \
        --silent \
        --show-error \
        --user-agent "hns-dane-engine-release/$version (https://github.com/handshake-rs/hns-dane-engine)" \
        --output /dev/null \
        --write-out '%{http_code}' \
        "https://crates.io/api/v1/crates/$package/$version"
}

verify_prepublished_package() {
    package=$1
    version=$2
    if is_prepublished_engine_package "$package" "$version"
    then
        source_revision=$prepublished_engine_revision
        checksum_manifest=$prepublished_engine_checksum_manifest
    elif is_prepublished_adapter_package "$package" "$version"
    then
        source_revision=$prepublished_adapter_revision
        checksum_manifest=$prepublished_adapter_checksum_manifest
    elif is_prepublished_patch_package "$package" "$version"
    then
        source_revision=$prepublished_patch_revision
        checksum_manifest=$prepublished_patch_checksum_manifest
    elif is_prepublished_light_client_package "$package" "$version"
    then
        source_revision=$prepublished_light_client_revision
        checksum_manifest=$prepublished_light_client_checksum_manifest
    elif is_prepublished_policy_package "$package" "$version"
    then
        source_revision=$prepublished_policy_revision
        checksum_manifest=$prepublished_policy_checksum_manifest
    elif is_prepublished_successor_package "$package" "$version"
    then
        source_revision=$prepublished_successor_revision
        checksum_manifest=$prepublished_successor_checksum_manifest
    elif is_prepublished_loopback_package "$package" "$version"
    then
        source_revision=$prepublished_loopback_revision
        checksum_manifest=$prepublished_loopback_checksum_manifest
    else
        echo "error: $package $version is not a recorded immutable package" >&2
        exit 1
    fi

    expected_filename="$package-$version.crate"
    expected_checksum=$(awk \
        -v filename="$expected_filename" \
        '$2 == filename { print $1 }' \
        "$checksum_manifest")
    if [ -z "$expected_checksum" ]
    then
        echo "error: $checksum_manifest has no checksum for $expected_filename" >&2
        exit 1
    fi

    ensure_release_tmp
    status=$(published_package_status "$package" "$version")
    if [ "$status" != "200" ]
    then
        echo "error: recorded prepublished $package $version is unavailable (HTTP $status)" >&2
        exit 1
    fi

    metadata="$release_tmp/$package-$version.json"
    curl \
        --fail \
        --silent \
        --show-error \
        --user-agent "hns-dane-engine-release/$version (https://github.com/handshake-rs/hns-dane-engine)" \
        --output "$metadata" \
        "https://crates.io/api/v1/crates/$package/$version"
    api_checksum=$(python3 -c \
        'import json, sys; print(json.load(sys.stdin)["version"]["checksum"])' \
        <"$metadata")
    api_yanked=$(python3 -c \
        'import json, sys; print(str(json.load(sys.stdin)["version"]["yanked"]).lower())' \
        <"$metadata")
    if [ "$api_checksum" != "$expected_checksum" ]
    then
        echo "error: crates.io API checksum for immutable $package $version differs from $checksum_manifest" >&2
        exit 1
    fi
    if [ "$api_yanked" != "false" ]
    then
        echo "error: recorded prepublished $package $version is yanked" >&2
        exit 1
    fi

    archive="$release_tmp/$expected_filename"
    curl \
        --fail \
        --location \
        --silent \
        --show-error \
        --user-agent "hns-dane-engine-release/$version (https://github.com/handshake-rs/hns-dane-engine)" \
        --output "$archive" \
        "https://crates.io/api/v1/crates/$package/$version/download"
    archive_checksum=$(sha256sum "$archive" | awk '{print $1}')
    if [ "$archive_checksum" != "$expected_checksum" ]
    then
        echo "error: downloaded immutable $package $version differs from $checksum_manifest" >&2
        exit 1
    fi

    vcs_info=$(tar -xOf "$archive" "$package-$version/.cargo_vcs_info.json")
    compact_vcs_info=$(printf '%s' "$vcs_info" | tr -d '[:space:]')
    case "$compact_vcs_info" in
        *\"sha1\":\"$source_revision\"*) ;;
        *)
            echo "error: immutable $package $version does not identify source $source_revision" >&2
            exit 1
            ;;
    esac
    case "$compact_vcs_info" in
        *\"dirty\":true*)
            echo "error: immutable $package $version records a dirty source tree" >&2
            exit 1
            ;;
    esac
    prepublished_path=$(printf '%s' "$vcs_info" |
        python3 -c 'import json, sys; print(json.load(sys.stdin).get("path_in_vcs", ""))')
    if [ "$prepublished_path" != "crates/$package" ]
    then
        echo "error: immutable $package $version identifies path $prepublished_path, expected crates/$package" >&2
        exit 1
    fi
}

verify_prepublished_packages() {
    for package in $prepublished_engine_crates
    do
        verify_prepublished_package "$package" "$prepublished_engine_version"
    done
    echo "verified all recorded prepublished engine $prepublished_engine_version archives and checksums at source $prepublished_engine_revision"
    for package in $prepublished_adapter_crates
    do
        verify_prepublished_package "$package" "$prepublished_adapter_version"
    done
    echo "verified all recorded prepublished browser adapter $prepublished_adapter_version archives and checksums at source $prepublished_adapter_revision"
    for package in $prepublished_patch_crates
    do
        verify_prepublished_package "$package" "$prepublished_patch_version"
    done
    echo "verified all recorded prepublished stateless DANE $prepublished_patch_version archives and checksums at source $prepublished_patch_revision"
    for package in $prepublished_light_client_crates
    do
        verify_prepublished_package "$package" "$prepublished_light_client_version"
    done
    echo "verified all recorded prepublished light-client $prepublished_light_client_version archives and checksums at source $prepublished_light_client_revision"
    for package in $prepublished_policy_crates
    do
        verify_prepublished_package "$package" "$(package_version "$package")"
    done
    echo "verified the recorded prepublished policy archive at source $prepublished_policy_revision"
    for package in $prepublished_successor_crates
    do
        verify_prepublished_package "$package" "$(package_version "$package")"
    done
    echo "verified all recorded prepublished Shakescape successor archives at source $prepublished_successor_revision"
    for package in $prepublished_loopback_crates
    do
        verify_prepublished_package "$package" "$prepublished_loopback_version"
    done
    echo "verified the recorded prepublished loopback proxy archive at source $prepublished_loopback_revision"
}

verify_published_package() {
    package=$1
    version=$2
    package_target=$(package_target_dir)
    local_archive="$package_target/package/$package-$version.crate"

    if [ ! -f "$local_archive" ]
    then
        echo "error: Cargo did not create $local_archive" >&2
        exit 1
    fi
    verify_source_package "$package"

    ensure_release_tmp
    published_archive="$release_tmp/$package-$version.crate"
    curl \
        --fail \
        --location \
        --silent \
        --show-error \
        --user-agent "hns-dane-engine-release/$version (https://github.com/handshake-rs/hns-dane-engine)" \
        --output "$published_archive" \
        "https://crates.io/api/v1/crates/$package/$version/download"

    local_checksum=$(sha256sum "$local_archive" | awk '{print $1}')
    published_checksum=$(sha256sum "$published_archive" | awk '{print $1}')
    if [ "$local_checksum" != "$published_checksum" ]
    then
        echo "error: published $package $version differs from the current source package" >&2
        echo "error: local checksum $local_checksum; published checksum $published_checksum" >&2
        exit 1
    fi

    for archive in "$local_archive" "$published_archive"
    do
        vcs_info=$(tar -xOf "$archive" "$package-$version/.cargo_vcs_info.json")
        compact_vcs_info=$(printf '%s' "$vcs_info" | tr -d '[:space:]')
        case "$compact_vcs_info" in
            *\"sha1\":\"$release_commit\"*) ;;
            *)
                echo "error: $archive does not identify release commit $release_commit" >&2
                exit 1
                ;;
        esac
        case "$compact_vcs_info" in
            *\"dirty\":true*)
                echo "error: $archive records a dirty source tree" >&2
                exit 1
                ;;
        esac
    done
}

verify_protocol_packages_published() {
    ensure_release_tmp
    for package in $protocol_crates
    do
        protocol_revision=73611a0d83778e157b35f28ca2197d068e83fc61
        protocol_version=0.4.1
        protocol_checksum_manifest=release/hns-rs-0.4.1-crates.sha256
        protocol_filename="$package-$protocol_version.crate"
        protocol_expected_checksum=$(awk \
            -v filename="$protocol_filename" \
            '$2 == filename { print $1 }' \
            "$protocol_checksum_manifest")
        if [ -z "$protocol_expected_checksum" ]
        then
            echo "error: $protocol_checksum_manifest has no checksum for $protocol_filename" >&2
            exit 1
        fi

        status=$(published_package_status "$package" "$protocol_version")
        if [ "$status" != "200" ]
        then
            echo "error: required protocol package $package $protocol_version is not published (HTTP $status)" >&2
            exit 1
        fi

        protocol_metadata="$release_tmp/$package-$protocol_version.json"
        curl \
            --fail \
            --silent \
            --show-error \
            --user-agent "hns-dane-engine-release/$protocol_version (https://github.com/handshake-rs/hns-dane-engine)" \
            --output "$protocol_metadata" \
            "https://crates.io/api/v1/crates/$package/$protocol_version"
        protocol_api_checksum=$(python3 -c \
            'import json, sys; print(json.load(sys.stdin)["version"]["checksum"])' \
            <"$protocol_metadata")
        protocol_api_yanked=$(python3 -c \
            'import json, sys; print(str(json.load(sys.stdin)["version"]["yanked"]).lower())' \
            <"$protocol_metadata")
        if [ "$protocol_api_checksum" != "$protocol_expected_checksum" ]
        then
            echo "error: crates.io API checksum for $package $protocol_version differs from $protocol_checksum_manifest" >&2
            exit 1
        fi
        if [ "$protocol_api_yanked" != "false" ]
        then
            echo "error: required protocol package $package $protocol_version is yanked" >&2
            exit 1
        fi

        protocol_archive="$release_tmp/$protocol_filename"
        curl \
            --fail \
            --location \
            --silent \
            --show-error \
            --user-agent "hns-dane-engine-release/$protocol_version (https://github.com/handshake-rs/hns-dane-engine)" \
            --output "$protocol_archive" \
            "https://crates.io/api/v1/crates/$package/$protocol_version/download"
        protocol_download_checksum=$(sha256sum "$protocol_archive" | awk '{print $1}')
        if [ "$protocol_download_checksum" != "$protocol_expected_checksum" ]
        then
            echo "error: downloaded $package $protocol_version differs from $protocol_checksum_manifest" >&2
            exit 1
        fi
        protocol_vcs_sha=$(tar -xOf \
            "$protocol_archive" \
            "$package-$protocol_version/.cargo_vcs_info.json" |
            python3 -c 'import json, sys; print(json.load(sys.stdin)["git"]["sha1"])')
        if [ "$protocol_vcs_sha" != "$protocol_revision" ]
        then
            echo "error: required protocol package $package $protocol_version identifies source $protocol_vcs_sha, expected $protocol_revision" >&2
            exit 1
        fi
        protocol_vcs_dirty=$(tar -xOf \
            "$protocol_archive" \
            "$package-$protocol_version/.cargo_vcs_info.json" |
            python3 -c 'import json, sys; print(str(json.load(sys.stdin)["git"].get("dirty", False)).lower())')
        if [ "$protocol_vcs_dirty" = "true" ]
        then
            echo "error: required protocol package $package $protocol_version records a dirty source tree" >&2
            exit 1
        fi
        protocol_vcs_path=$(tar -xOf \
            "$protocol_archive" \
            "$package-$protocol_version/.cargo_vcs_info.json" |
            python3 -c 'import json, sys; print(json.load(sys.stdin).get("path_in_vcs", ""))')
        if [ "$protocol_vcs_path" != "crates/$package" ]
        then
            echo "error: required protocol package $package $protocol_version identifies path $protocol_vcs_path, expected crates/$package" >&2
            exit 1
        fi
    done
    echo "verified all 19 non-yanked coherent hns-rs archives"
}

verify_new_upload() {
    package=$1
    version=$2
    publish_interval_seconds=$3
    publish_kind=$4

    if [ "$package" != "$last_public_crate" ] &&
        [ "$publish_interval_seconds" != "0" ]
    then
        echo "waiting ${publish_interval_seconds}s for crates.io propagation and $publish_kind cooldown"
        sleep "$publish_interval_seconds"
    fi

    status=$(published_package_status "$package" "$version")
    case "$status" in
        200)
            verify_published_package "$package" "$version"
            echo "verified newly published $package $version against source $release_commit"
            ;;
        404)
            echo "error: published $package $version is not yet visible for exact verification" >&2
            echo "error: rerun the same execute command after crates.io propagation; resume verification will not republish it" >&2
            exit 1
            ;;
        *)
            echo "error: crates.io returned HTTP $status while verifying newly published $package $version" >&2
            exit 1
            ;;
    esac
}

case "$mode" in
    --archive-only)
        if [ "$argument_count" -gt 2 ]
        then
            usage
            exit 2
        fi
        package_mode='archive-only'
        python3 scripts/verify-release.py --toolchain "$rust_toolchain"
        if [ -n "$requested_package" ]
        then
            require_public_crate "$requested_package"
            version=$(package_version "$requested_package")
            if is_prepublished_package "$requested_package" "$version"
            then
                verify_prepublished_package "$requested_package" "$version"
            else
                package_with_local_dependencies "$requested_package"
                verify_source_package "$requested_package"
            fi
        else
            verify_prepublished_packages
            for package in $public_crates
            do
                version=$(package_version "$package")
                if is_prepublished_package "$package" "$version"
                then
                    continue
                fi
                package_with_local_dependencies "$package"
                verify_source_package "$package"
            done
        fi
        ;;
    --dry-run)
        if [ "$argument_count" -gt 2 ]
        then
            usage
            exit 2
        fi
        python3 scripts/verify-release.py --toolchain "$rust_toolchain"
        if [ -n "$requested_package" ]
        then
            require_public_crate "$requested_package"
            version=$(package_version "$requested_package")
            if is_prepublished_package "$requested_package" "$version"
            then
                verify_prepublished_package "$requested_package" "$version"
            else
                package_with_local_dependencies "$requested_package"
                verify_source_package "$requested_package"
            fi
        else
            verify_prepublished_packages
            for package in $public_crates
            do
                version=$(package_version "$package")
                if is_prepublished_package "$package" "$version"
                then
                    continue
                fi
                package_with_local_dependencies "$package"
                verify_source_package "$package"
            done
        fi
        ;;
    --execute)
        if [ "$argument_count" -ne 3 ] ||
            [ "$requested_package" != "--confirm-publish" ] ||
            [ -z "$confirmed_version" ]
        then
            echo "error: irreversible publication requires --confirm-publish VERSION" >&2
            exit 2
        fi
        case "$publish_new_interval_seconds" in
            *[!0-9]*|'')
                echo "error: PUBLISH_NEW_INTERVAL_SECONDS must be a non-negative integer" >&2
                exit 2
                ;;
        esac
        case "$publish_update_interval_seconds" in
            *[!0-9]*|'')
                echo "error: PUBLISH_UPDATE_INTERVAL_SECONDS must be a non-negative integer" >&2
                exit 2
                ;;
        esac
        python3 scripts/verify-release.py \
            --toolchain "$rust_toolchain" \
            --require-clean \
            --expected-version "$confirmed_version"
        require_clean_archive_vcs=yes
        verify_protocol_packages_published
        verify_prepublished_packages
        verify_release_source_unchanged

        cargo_home=${CARGO_HOME:-"$HOME/.cargo"}
        if [ -z "${CARGO_REGISTRY_TOKEN:-}" ] &&
            [ ! -f "$cargo_home/credentials.toml" ]
        then
            echo "error: no crates.io credential found; run cargo login" >&2
            exit 1
        fi

        for package in $public_crates
        do
            version=$(package_version "$package")
            if is_prepublished_package "$package" "$version"
            then
                echo "skipping $package $version: immutable prepublished archive already verified"
                continue
            fi
            verify_release_source_unchanged
            status=$(published_package_status "$package" "$version")
            verify_release_source_unchanged
            case "$status" in
                200)
                    # Reproduce the uploaded Cargo.lock through Cargo's
                    # registry-backed publish path. A local workspace package
                    # omits registry source/checksum fields and is not an exact
                    # resume artifact once its dependencies are published.
                    create_registry_source_package "$package"
                    verify_published_package "$package" "$version"
                    echo "skipping $package $version: already published and verified"
                    ;;
                404)
                    crate_status=$(published_crate_status "$package" "$version")
                    case "$crate_status" in
                        200)
                            publish_interval_seconds=$publish_update_interval_seconds
                            publish_kind=existing-crate-update
                            ;;
                        404)
                            publish_interval_seconds=$publish_new_interval_seconds
                            publish_kind=new-crate-name
                            ;;
                        *)
                            echo "error: crates.io returned HTTP $crate_status while classifying $package" >&2
                            exit 1
                            ;;
                    esac
                    # Construct and inspect the normalized archive before the
                    # irreversible upload. cargo publish then replaces it with
                    # the registry-backed archive used for exact verification.
                    create_source_package "$package"
                    verify_release_source_unchanged
                    cargo +"$rust_toolchain" publish --locked -p "$package"
                    verify_new_upload \
                        "$package" \
                        "$version" \
                        "$publish_interval_seconds" \
                        "$publish_kind"
                    ;;
                *)
                    echo "error: crates.io returned HTTP $status for $package $version" >&2
                    exit 1
                    ;;
            esac
        done
        ;;
    *)
        usage
        exit 2
        ;;
esac
