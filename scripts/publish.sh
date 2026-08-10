#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

rust_toolchain=${RUST_TOOLCHAIN:-1.89.0}
publish_interval_seconds=${PUBLISH_INTERVAL_SECONDS-605}
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
protocol_revision=b33b346780c8f6a9bb18a54390019486cdab0221
protocol_version=0.2.0
protocol_crates='hns-encoding hns-primitives hns-covenants hns-dns-relay-protocol hns-header-consensus hns-service-authority hns-odoh-protocol hns-p2p-experimental hns-urkel-proof hns-transaction hns-chat-protocol hns-hnsr-protocol hns-script hns-mining hns-swap hns-marketplace-protocol hns-p2p-wire'

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
            run_package_operation "$package" \
                --config "patch.crates-io.hns-covenants.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-covenants.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-encoding.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-encoding.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-header-consensus.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-header-consensus.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-urkel-proof.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-urkel-proof.rev=\"$protocol_revision\""
            ;;
        hns-light-p2p)
            run_package_operation "$package" \
                --config "patch.crates-io.hns-header-consensus.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-header-consensus.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-p2p-wire.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-p2p-wire.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\""
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
                --config 'patch.crates-io.hns-light-chain.path="crates/hns-light-chain"' \
                --config "patch.crates-io.hns-header-consensus.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-header-consensus.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-p2p-wire.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-p2p-wire.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\""
            ;;
        hns-transport)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-dns-wire.path="crates/hns-dns-wire"' \
                --config 'patch.crates-io.hns-light-chain.path="crates/hns-light-chain"' \
                --config "patch.crates-io.hns-covenants.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-covenants.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-header-consensus.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-header-consensus.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\""
            ;;
        hns-resolver)
            run_package_operation "$package" \
                --config 'patch.crates-io.hns-dns-wire.path="crates/hns-dns-wire"' \
                --config 'patch.crates-io.hns-dnssec.path="crates/hns-dnssec"' \
                --config 'patch.crates-io.hns-icann-dane.path="crates/hns-icann-dane"' \
                --config 'patch.crates-io.hns-light-chain.path="crates/hns-light-chain"' \
                --config "patch.crates-io.hns-covenants.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-covenants.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-header-consensus.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-header-consensus.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\""
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
                --config 'patch.crates-io.hns-transport.path="crates/hns-transport"' \
                --config "patch.crates-io.hns-dns-relay-protocol.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-dns-relay-protocol.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-odoh-protocol.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-odoh-protocol.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-p2p-experimental.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-p2p-experimental.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-primitives.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-primitives.rev=\"$protocol_revision\""
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
                --config 'patch.crates-io.hns-transport.path="crates/hns-transport"' \
                --config "patch.crates-io.hns-header-consensus.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-header-consensus.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-hnsr-protocol.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-hnsr-protocol.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-p2p-wire.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-p2p-wire.rev=\"$protocol_revision\"" \
                --config "patch.crates-io.hns-service-authority.git=\"$protocol_repository\"" \
                --config "patch.crates-io.hns-service-authority.rev=\"$protocol_revision\""
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
    for relative_path in CHANGELOG.md LICENSE-APACHE LICENSE-MIT README.md
    do
        verify_archive_copy "$package" "$archive" "$archive_root" \
            "$relative_path" "crates/$package/$relative_path"
    done

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
        status=$(published_package_status "$package" "$protocol_version")
        if [ "$status" != "200" ]
        then
            echo "error: required protocol package $package $protocol_version is not published (HTTP $status)" >&2
            exit 1
        fi

        protocol_archive="$release_tmp/$package-$protocol_version.crate"
        curl \
            --fail \
            --location \
            --silent \
            --show-error \
            --user-agent "hns-dane-engine-release/$protocol_version (https://github.com/handshake-rs/hns-dane-engine)" \
            --output "$protocol_archive" \
            "https://crates.io/api/v1/crates/$package/$protocol_version/download"
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
    done
    echo "verified all 17 hns-rs $protocol_version archives at source $protocol_revision"
}

verify_new_upload() {
    package=$1
    version=$2

    if [ "$package" != "$last_public_crate" ] &&
        [ "$publish_interval_seconds" != "0" ]
    then
        echo "waiting ${publish_interval_seconds}s for crates.io propagation and cooldown"
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
            package_with_local_dependencies "$requested_package"
            verify_source_package "$requested_package"
        else
            for package in $public_crates
            do
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
            package_with_local_dependencies "$requested_package"
            verify_source_package "$requested_package"
        else
            for package in $public_crates
            do
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
        case "$publish_interval_seconds" in
            *[!0-9]*|'')
                echo "error: PUBLISH_INTERVAL_SECONDS must be a non-negative integer" >&2
                exit 2
                ;;
        esac
        python3 scripts/verify-release.py \
            --toolchain "$rust_toolchain" \
            --require-clean \
            --expected-version "$confirmed_version"
        require_clean_archive_vcs=yes
        verify_protocol_packages_published
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
            verify_release_source_unchanged
            # Construct and inspect the normalized archive before either an
            # irreversible upload or an exact-checksum resume decision.
            create_source_package "$package"
            status=$(published_package_status "$package" "$version")
            verify_release_source_unchanged
            case "$status" in
                200)
                    verify_published_package "$package" "$version"
                    echo "skipping $package $version: already published and verified"
                    ;;
                404)
                    verify_release_source_unchanged
                    cargo +"$rust_toolchain" publish --locked -p "$package"
                    verify_new_upload "$package" "$version"
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
