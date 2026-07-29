#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

rust_toolchain=${RUST_TOOLCHAIN:-1.89.0}
publish_interval_seconds=${PUBLISH_INTERVAL_SECONDS:-605}
mode=${1:---dry-run}

public_crates="
hns-dns-wire
hns-browser-runtime
hns-icann-dane
hns-namespace-resolution
hns-resolution-policy
hns-light-chain
hns-dane
hns-dnssec
hns-gateway
hns-cache
hns-light-p2p
hns-light-sync
hns-transport
hns-resolver
hns-browser-observability
hns-p2p-transport
hns-dane-engine
hns-dane-engine-ffi
hns-loopback-proxy
"

hns_rs_git_url="https://github.com/handshake-rs/hns-rs.git"
hns_rs_revision="dde2da81f29df935f043978a6d517c1d60ceff31"

assert_private() {
    package=$1
    if cargo +"$rust_toolchain" publish \
        --dry-run \
        --no-verify \
        --allow-dirty \
        -p "$package" >/dev/null 2>&1
    then
        echo "error: private package $package passed the publish preflight" >&2
        exit 1
    fi
}

dry_run_package() {
    package=$1
    local_dependencies=$2
    hns_rs_dependencies=$3
    set -- cargo +"$rust_toolchain" publish \
        --locked \
        --dry-run \
        --allow-dirty \
        -p "$package"
    for dependency in $local_dependencies
    do
        set -- "$@" \
            --config "patch.crates-io.$dependency.path=\"crates/$dependency\""
    done
    for dependency in $hns_rs_dependencies
    do
        set -- "$@" \
            --config "patch.crates-io.$dependency.git=\"$hns_rs_git_url\"" \
            --config "patch.crates-io.$dependency.rev=\"$hns_rs_revision\""
    done
    "$@"
}

dry_run_with_local_dependencies() {
    package=$1
    case "$package" in
        hns-dns-wire|hns-browser-runtime|hns-icann-dane|\
            hns-namespace-resolution|hns-resolution-policy|\
            hns-light-chain|hns-light-p2p)
            dry_run_package "$package" "" ""
            ;;
        hns-dane|hns-dnssec|hns-cache)
            dry_run_package "$package" "hns-dns-wire" ""
            ;;
        hns-gateway)
            dry_run_package "$package" "hns-resolution-policy" ""
            ;;
        hns-light-sync)
            dry_run_package "$package" "hns-light-chain" \
                "hns-header-consensus hns-p2p-wire hns-primitives"
            ;;
        hns-transport)
            dry_run_package "$package" \
                "hns-dns-wire hns-light-chain" \
                "hns-covenants hns-header-consensus hns-primitives"
            ;;
        hns-resolver)
            dry_run_package "$package" \
                "hns-dns-wire hns-dnssec hns-icann-dane hns-light-chain" \
                "hns-covenants hns-header-consensus hns-primitives"
            ;;
        hns-browser-observability)
            dry_run_package "$package" \
                "hns-browser-runtime hns-icann-dane hns-namespace-resolution hns-resolution-policy" \
                ""
            ;;
        hns-p2p-transport)
            dry_run_package "$package" \
                "hns-dns-wire hns-gateway hns-light-chain hns-resolution-policy hns-transport" \
                "hns-dns-relay-protocol hns-odoh-protocol hns-p2p-experimental hns-primitives"
            ;;
        hns-dane-engine)
            dry_run_package "$package" \
                "hns-browser-observability hns-browser-runtime hns-dane hns-dns-wire hns-dnssec hns-gateway hns-icann-dane hns-light-chain hns-namespace-resolution hns-p2p-transport hns-resolution-policy hns-resolver hns-transport" \
                ""
            ;;
        hns-dane-engine-ffi|hns-loopback-proxy)
            dry_run_package "$package" \
                "hns-browser-observability hns-browser-runtime hns-dane hns-dane-engine hns-dns-wire hns-dnssec hns-gateway hns-icann-dane hns-light-chain hns-namespace-resolution hns-p2p-transport hns-resolution-policy hns-resolver hns-transport" \
                ""
            ;;
        *)
            echo "error: missing dry-run dependency mapping for $package" >&2
            exit 1
            ;;
    esac
}

assert_private hns-browser-testkit

case "$mode" in
    --dry-run)
        for package in $public_crates
        do
            dry_run_with_local_dependencies "$package"
        done
        ;;
    --execute)
        case "$publish_interval_seconds" in
            *[!0-9]*|'')
                echo "error: PUBLISH_INTERVAL_SECONDS must be an integer" >&2
                exit 2
                ;;
        esac

        if [ -n "$(git status --porcelain --untracked-files=normal)" ]
        then
            echo "error: refusing to publish from a dirty worktree" >&2
            exit 1
        fi

        cargo_home=${CARGO_HOME:-"$HOME/.cargo"}
        if [ -z "${CARGO_REGISTRY_TOKEN:-}" ] &&
            [ ! -f "$cargo_home/credentials.toml" ]
        then
            echo "error: no crates.io credential found; run cargo login" >&2
            exit 1
        fi

        for package in $public_crates
        do
            package_id=$(cargo +"$rust_toolchain" pkgid -p "$package")
            version=${package_id##*@}
            if [ "$version" = "$package_id" ]
            then
                version=${package_id##*#}
            fi

            status=$(curl \
                --silent \
                --show-error \
                --user-agent "hns-dane-engine-release/0.1 (https://github.com/handshake-rs/hns-dane-engine)" \
                --output /dev/null \
                --write-out '%{http_code}' \
                "https://crates.io/api/v1/crates/$package/$version")

            case "$status" in
                200)
                    echo "skipping $package $version: already published"
                    ;;
                404)
                    cargo +"$rust_toolchain" publish --locked -p "$package"
                    if [ "$package" != "hns-loopback-proxy" ] &&
                        [ "$publish_interval_seconds" -gt 0 ]
                    then
                        echo "waiting ${publish_interval_seconds}s for the crates.io cooldown"
                        sleep "$publish_interval_seconds"
                    fi
                    ;;
                *)
                    echo "error: crates.io returned HTTP $status for $package $version" >&2
                    exit 1
                    ;;
            esac
        done
        ;;
    *)
        echo "usage: $0 [--dry-run|--execute]" >&2
        exit 2
        ;;
esac
