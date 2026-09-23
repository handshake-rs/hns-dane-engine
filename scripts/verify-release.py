#!/usr/bin/env python3
"""Cheap, deterministic validation of the engine release graph and metadata."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tomllib
from datetime import date
from pathlib import Path

import verify_cargo_source_policy


REPOSITORY = "https://github.com/handshake-rs/hns-dane-engine"
PROTOCOL_REPOSITORY = "https://github.com/handshake-rs/hns-rs.git"
PROTOCOL_REVISION = "73611a0d83778e157b35f28ca2197d068e83fc61"
PROTOCOL_VERSION = "=0.4.1"
PROTOCOL_VERSION_OVERRIDES: dict[str, str] = {}
PROTOCOL_PUBLIC_PACKAGES = (
    "hns-encoding",
    "hns-rollback-journal",
    "hns-hrm",
    "hns-primitives",
    "hns-covenants",
    "hns-dns-relay-protocol",
    "hns-header-consensus",
    "hns-service-authority",
    "hns-odoh-protocol",
    "hns-p2p-experimental",
    "hns-urkel-proof",
    "hns-transaction",
    "hns-chat-protocol",
    "hns-hnsr-protocol",
    "hns-script",
    "hns-mining",
    "hns-swap",
    "hns-marketplace-protocol",
    "hns-p2p-wire",
)
PROTOCOL_DIRECT_PACKAGES = {
    "hns-covenants",
    "hns-dns-relay-protocol",
    "hns-encoding",
    "hns-header-consensus",
    "hns-hnsr-protocol",
    "hns-hrm",
    "hns-odoh-protocol",
    "hns-p2p-experimental",
    "hns-p2p-wire",
    "hns-primitives",
    "hns-rollback-journal",
    "hns-service-authority",
    "hns-urkel-proof",
}
PUBLIC_ADAPTER_PACKAGES = {
    "hns-browser-chain",
    "hns-browser-dane",
    "hns-browser-dnssec",
    "hns-browser-gateway",
    "hns-browser-loopback-proxy",
    "hns-browser-p2p",
    "hns-browser-primitives",
    "hns-browser-resolver",
    "hns-browser-sync",
    "hns-browser-transport",
    "hns-browser-urkel",
}
PREPUBLISHED_ENGINE_VERSION = "0.2.2"
PREPUBLISHED_ENGINE_REVISION = "b7fdf8826c81b77650a0f740d1f05314b74969f9"
PREPUBLISHED_ENGINE_MANIFEST = "release/prepublished-0.2.2-crates.txt"
PREPUBLISHED_ENGINE_CHECKSUM_MANIFEST = (
    "release/hns-dane-engine-0.2.2-crates.sha256"
)
PREPUBLISHED_ADAPTER_VERSION = "0.2.2"
PREPUBLISHED_ADAPTER_REVISION = "3907e2a93eb7b10ee7deb1f179ce67824277c82a"
PREPUBLISHED_ADAPTER_MANIFEST = "release/prepublished-browser-adapters-0.2.2-crates.txt"
PREPUBLISHED_ADAPTER_CHECKSUM_MANIFEST = (
    "release/hns-dane-engine-browser-adapters-0.2.2-crates.sha256"
)
PREPUBLISHED_PATCH_VERSION = "0.2.3"
PREPUBLISHED_PATCH_REVISION = "142117058690220b066782d8ff0655cf0a2670b3"
PREPUBLISHED_PATCH_MANIFEST = "release/prepublished-stateless-dane-0.2.3-crates.txt"
PREPUBLISHED_PATCH_CHECKSUM_MANIFEST = (
    "release/hns-dane-engine-stateless-dane-0.2.3-crates.sha256"
)
PREPUBLISHED_PATCH_PACKAGES = (
    "hns-namespace-resolution",
    "hns-browser-gateway",
)
PREPUBLISHED_LIGHT_CLIENT_VERSION = "0.2.3"
PREPUBLISHED_LIGHT_CLIENT_REVISION = "87d2346c13ade4987801e0f1367bd604fd77c9f0"
PREPUBLISHED_LIGHT_CLIENT_MANIFEST = "release/prepublished-light-client-0.2.3-crates.txt"
PREPUBLISHED_LIGHT_CLIENT_CHECKSUM_MANIFEST = (
    "release/hns-dane-engine-light-client-0.2.3-crates.sha256"
)
PREPUBLISHED_LIGHT_CLIENT_PACKAGES = (
    "hns-light-chain",
    "hns-light-wallet",
    "hns-light-p2p",
    "hns-light-sync",
)
PREPUBLISHED_POLICY_REVISION = "2e06af3489bd40e0ef90b847101e4f6a7aeebe71"
PREPUBLISHED_POLICY_MANIFEST = "release/prepublished-policy-0.3.0-crates.txt"
PREPUBLISHED_POLICY_CHECKSUM_MANIFEST = (
    "release/hns-dane-engine-policy-0.3.0-crates.sha256"
)
PREPUBLISHED_POLICY_PACKAGES = ("hns-resolution-policy",)
PREPUBLISHED_SUCCESSOR_REVISION = "ee222208a7750dcb061c5c3cc16b8cf82d75033e"
PREPUBLISHED_SUCCESSOR_MANIFEST = (
    "release/prepublished-shakescape-successor-crates.txt"
)
PREPUBLISHED_SUCCESSOR_CHECKSUM_MANIFEST = (
    "release/hns-dane-engine-shakescape-successor-crates.sha256"
)
PREPUBLISHED_SUCCESSOR_PACKAGES = (
    "hns-gateway",
    "hns-browser-observability",
    "hns-p2p-transport",
    "hns-dane-engine",
)
PREPUBLISHED_LOOPBACK_VERSION = "0.2.3"
PREPUBLISHED_LOOPBACK_REVISION = "9aa1b1ef48cd3628fbd579f208a865255301eb03"
PREPUBLISHED_LOOPBACK_MANIFEST = "release/prepublished-loopback-proxy-0.2.3-crates.txt"
PREPUBLISHED_LOOPBACK_CHECKSUM_MANIFEST = (
    "release/hns-dane-engine-loopback-proxy-0.2.3-crates.sha256"
)
PREPUBLISHED_LOOPBACK_PACKAGES = ("hns-browser-loopback-proxy",)
PATCH_RELEASE_VERSION = "0.2.4"
PATCH_RELEASE_MANIFEST = "release/mobile-network-0.2.4-crates.txt"
PATCH_RELEASE_PACKAGES = (
    "hns-light-p2p",
    "hns-browser-chain",
    "hns-browser-p2p",
    "hns-browser-resolver",
)
PATCH_RELEASE_TAG = "mobile-network-v0.2.4"
PATCH_RELEASE_VERSIONS = {
    package: PATCH_RELEASE_VERSION for package in PATCH_RELEASE_PACKAGES
}
SUCCESSOR_RELEASE_VERSION = "0.3.0"
SUCCESSOR_RELEASE_VERSIONS = {
    "hns-browser-observability": SUCCESSOR_RELEASE_VERSION,
    "hns-dane-engine": SUCCESSOR_RELEASE_VERSION,
    "hns-gateway": SUCCESSOR_RELEASE_VERSION,
    "hns-p2p-transport": "0.3.1",
    "hns-resolution-policy": SUCCESSOR_RELEASE_VERSION,
}
PRIVATE_PACKAGES = {"hns-browser-testkit"}
PACKAGE_FIXTURES = {
    "hns-dns-wire": (
        "dns/basic-query.hex",
        "dns/compressed-a-response-ad.hex",
        "dns/mutation-compression-self-loop.hex",
        "dns/mutation-count-bomb.hex",
        "dns/mutation-pointer-out-of-bounds.hex",
        "dns/tlsa-response.hex",
    ),
    "hns-dane": (
        "dane/self-signed-cert.der.hex",
        "dane/self-signed-spki.der.hex",
    ),
    "hns-dane-engine": ("dane/self-signed-cert.der.hex",),
    "hns-dane-engine-ffi": ("dane/self-signed-cert.der.hex",),
}


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def shell_function_body(script: str, name: str, successor: str) -> str:
    start = f"{name}() {{\n"
    end = f"\n}}\n\n{successor}() {{"
    if script.count(start) != 1:
        fail(f"scripts/publish.sh must define {name} exactly once")
    remainder = script.split(start, 1)[1]
    if remainder.count(end) != 1:
        fail(
            f"scripts/publish.sh must place {name} immediately before {successor}"
        )
    return remainder.split(end, 1)[0]


def cargo_metadata(repo: Path, toolchain: str) -> dict:
    result = subprocess.run(
        [
            "cargo",
            f"+{toolchain}",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        fail("Cargo metadata failed for the release workspace")
    return json.loads(result.stdout)


def release_order(repo: Path) -> list[str]:
    path = repo / "release/public-crates.txt"
    packages = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(packages) != 31:
        fail(f"{path.relative_to(repo)} must contain exactly 31 packages")
    if len(packages) != len(set(packages)):
        fail(f"{path.relative_to(repo)} contains a duplicate package")
    for package in packages:
        if re.fullmatch(r"hns-[a-z0-9-]+", package) is None:
            fail(f"invalid public package name {package!r}")
    return packages


def verify_prepublished_engine_inventory(repo: Path, order: list[str]) -> None:
    manifest = repo / PREPUBLISHED_ENGINE_MANIFEST
    packages = [
        line.strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    expected = [package for package in order if package not in PUBLIC_ADAPTER_PACKAGES]
    if packages != expected:
        fail(
            f"{PREPUBLISHED_ENGINE_MANIFEST} must list every non-adapter public "
            "package in release dependency order"
        )
    if len(packages) != 20 or len(packages) != len(set(packages)):
        fail(f"{PREPUBLISHED_ENGINE_MANIFEST} must contain exactly 20 unique packages")

    checksum_manifest = repo / PREPUBLISHED_ENGINE_CHECKSUM_MANIFEST
    checksums: dict[str, str] = {}
    for line in checksum_manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (hns-[a-z0-9-]+-0[.]2[.]2[.]crate)", line)
        if match is None:
            fail(
                f"invalid checksum entry in {PREPUBLISHED_ENGINE_CHECKSUM_MANIFEST}: "
                f"{line!r}"
            )
        checksum, filename = match.groups()
        if filename in checksums:
            fail(f"duplicate checksum entry for {filename}")
        checksums[filename] = checksum
    expected_filenames = {f"{package}-0.2.2.crate" for package in packages}
    if set(checksums) != expected_filenames:
        fail(
            f"{PREPUBLISHED_ENGINE_CHECKSUM_MANIFEST} must contain exactly the "
            "recorded prepublished package archives"
        )


def verify_prepublished_adapter_inventory(repo: Path, order: list[str]) -> None:
    manifest = repo / PREPUBLISHED_ADAPTER_MANIFEST
    packages = [
        line.strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    expected = [package for package in order if package in PUBLIC_ADAPTER_PACKAGES]
    if packages != expected:
        fail(
            f"{PREPUBLISHED_ADAPTER_MANIFEST} must list every adapter public "
            "package in release dependency order"
        )
    if len(packages) != 11 or len(packages) != len(set(packages)):
        fail(f"{PREPUBLISHED_ADAPTER_MANIFEST} must contain exactly 11 unique packages")

    checksum_manifest = repo / PREPUBLISHED_ADAPTER_CHECKSUM_MANIFEST
    checksums: dict[str, str] = {}
    for line in checksum_manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (hns-[a-z0-9-]+-0[.]2[.]2[.]crate)", line)
        if match is None:
            fail(
                f"invalid checksum entry in {PREPUBLISHED_ADAPTER_CHECKSUM_MANIFEST}: "
                f"{line!r}"
            )
        checksum, filename = match.groups()
        if filename in checksums:
            fail(f"duplicate checksum entry for {filename}")
        checksums[filename] = checksum
    expected_filenames = {f"{package}-0.2.2.crate" for package in packages}
    if set(checksums) != expected_filenames:
        fail(
            f"{PREPUBLISHED_ADAPTER_CHECKSUM_MANIFEST} must contain exactly "
            "the recorded prepublished adapter archives"
        )


def verify_prepublished_patch_inventory(repo: Path) -> None:
    manifest = repo / PREPUBLISHED_PATCH_MANIFEST
    packages = tuple(
        line.strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    if packages != PREPUBLISHED_PATCH_PACKAGES:
        fail(
            f"{PREPUBLISHED_PATCH_MANIFEST} must contain exactly "
            f"{list(PREPUBLISHED_PATCH_PACKAGES)}"
        )

    checksum_manifest = repo / PREPUBLISHED_PATCH_CHECKSUM_MANIFEST
    checksums: dict[str, str] = {}
    for line in checksum_manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(
            r"([0-9a-f]{64})  (hns-[a-z0-9-]+-0[.]2[.]3[.]crate)", line
        )
        if match is None:
            fail(
                f"invalid checksum entry in {PREPUBLISHED_PATCH_CHECKSUM_MANIFEST}: "
                f"{line!r}"
            )
        checksum, filename = match.groups()
        if filename in checksums:
            fail(f"duplicate checksum entry for {filename}")
        checksums[filename] = checksum
    expected_filenames = {
        f"{package}-{PREPUBLISHED_PATCH_VERSION}.crate" for package in packages
    }
    if set(checksums) != expected_filenames:
        fail(
            f"{PREPUBLISHED_PATCH_CHECKSUM_MANIFEST} must contain exactly "
            "the recorded prepublished patch archives"
        )


def verify_named_prepublished_inventory(
    repo: Path,
    manifest_path: str,
    checksum_path: str,
    expected_packages: tuple[str, ...],
    expected_versions: dict[str, str],
) -> None:
    packages = tuple(
        line.strip()
        for line in (repo / manifest_path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    if packages != expected_packages:
        fail(f"{manifest_path} must contain exactly {list(expected_packages)}")
    expected_filenames = {
        f"{package}-{expected_versions[package]}.crate" for package in packages
    }
    observed: set[str] = set()
    for line in (repo / checksum_path).read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(
            r"[0-9a-f]{64}  (hns-[a-z0-9-]+-[0-9]+[.][0-9]+[.][0-9]+[.]crate)",
            line,
        )
        if match is None:
            fail(f"invalid checksum entry in {checksum_path}: {line!r}")
        filename = match.group(1)
        if filename in observed:
            fail(f"duplicate checksum entry for {filename}")
        observed.add(filename)
    if observed != expected_filenames:
        fail(f"{checksum_path} must cover exactly {sorted(expected_filenames)}")


def patch_release_order(repo: Path) -> tuple[str, ...]:
    packages = tuple(
        line.strip()
        for line in (repo / PATCH_RELEASE_MANIFEST).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    if packages != PATCH_RELEASE_PACKAGES:
        fail(f"{PATCH_RELEASE_MANIFEST} must contain exactly {list(PATCH_RELEASE_PACKAGES)}")
    return packages


def verify_release_document(repo: Path, order: list[str], version: str) -> None:
    document = (repo / "docs/releasing.md").read_text(encoding="utf-8")
    documented = re.findall(r"^\d+\. `([^`]+)`$", document, flags=re.MULTILINE)
    if documented != order:
        fail("docs/releasing.md does not match release/public-crates.txt")

    execute_command = (
        f"./scripts/publish.sh --execute --confirm-publish {PATCH_RELEASE_VERSION}"
    )
    if execute_command not in document:
        fail("docs/releasing.md does not use the current version in its execute example")

    publish_script = (repo / "scripts/publish.sh").read_text(encoding="utf-8")
    interval_defaults = (
        (
            "publish_new_interval_seconds",
            "PUBLISH_NEW_INTERVAL_SECONDS",
            "new-name",
        ),
        (
            "publish_update_interval_seconds",
            "PUBLISH_UPDATE_INTERVAL_SECONDS",
            "existing-crate update",
        ),
    )
    for shell_name, environment_name, description in interval_defaults:
        interval_match = re.search(
            rf"^{shell_name}=\$\{{{environment_name}-(\d+)\}}$",
            publish_script,
            re.MULTILINE,
        )
        if interval_match is None:
            fail(
                f"scripts/publish.sh has no validated {description} "
                "publication interval default"
            )
        default_interval = interval_match.group(1)
        if re.search(
            rf"{re.escape(default_interval)}-second\s+{re.escape(description)}",
            document,
        ) is None:
            fail(f"docs/releasing.md omits the {description} interval default")
        if f"{environment_name}={default_interval}" not in document:
            fail(
                f"docs/releasing.md {description} cooldown example differs "
                "from the script default"
            )

    required_text = (
        "release/public-crates.txt",
        PREPUBLISHED_ENGINE_MANIFEST,
        PREPUBLISHED_ENGINE_CHECKSUM_MANIFEST,
        PREPUBLISHED_ENGINE_REVISION,
        PREPUBLISHED_ADAPTER_MANIFEST,
        PREPUBLISHED_ADAPTER_CHECKSUM_MANIFEST,
        PREPUBLISHED_ADAPTER_REVISION,
        PREPUBLISHED_PATCH_MANIFEST,
        PREPUBLISHED_PATCH_CHECKSUM_MANIFEST,
        PREPUBLISHED_PATCH_REVISION,
        PREPUBLISHED_LIGHT_CLIENT_MANIFEST,
        PREPUBLISHED_LIGHT_CLIENT_CHECKSUM_MANIFEST,
        PREPUBLISHED_LIGHT_CLIENT_REVISION,
        PREPUBLISHED_POLICY_MANIFEST,
        PREPUBLISHED_POLICY_CHECKSUM_MANIFEST,
        PREPUBLISHED_POLICY_REVISION,
        PREPUBLISHED_SUCCESSOR_MANIFEST,
        PREPUBLISHED_SUCCESSOR_CHECKSUM_MANIFEST,
        PREPUBLISHED_SUCCESSOR_REVISION,
        PATCH_RELEASE_MANIFEST,
        PATCH_RELEASE_VERSION,
        "./scripts/publish.sh --archive-only",
        ".github/workflows/release-preflight.yml",
        "expected_commit",
        PROTOCOL_REVISION,
        f"`={PROTOCOL_VERSION.removeprefix('=')}`",
        str(verify_cargo_source_policy.HNS_RS_CHECKSUM_MANIFEST),
    )
    for required in required_text:
        if required not in document:
            fail(f"docs/releasing.md omits {required!r}")

    self_expiring_claims = (
        "current source is the unpublished",
        "packages are unpublished",
        "No package has been published",
    )
    for claim in self_expiring_claims:
        if claim in document:
            fail(f"docs/releasing.md contains self-expiring claim {claim!r}")


def verify_release_workflow(repo: Path) -> None:
    check_script = (repo / "scripts/check.sh").read_text(encoding="utf-8")
    archive_command = "./scripts/publish.sh --dry-run"
    if check_script.count(archive_command) != 1:
        fail("scripts/check.sh must run normalized publish dry-run verification once")
    if check_script.count("./scripts/check-publish-arguments.sh") != 1:
        fail("scripts/check.sh must run publish argument guards once")

    workflow = (repo / ".github/workflows/release-preflight.yml").read_text(
        encoding="utf-8"
    )
    if not re.search(r"^on:\n  workflow_dispatch:\s*$", workflow, re.MULTILINE):
        fail("release preflight workflow must be manually dispatchable")
    for automatic_event in ("push", "pull_request", "schedule"):
        if re.search(rf"^  {automatic_event}:\s*", workflow, re.MULTILINE):
            fail(f"release preflight workflow must not run on {automatic_event}")
    if workflow.count("run: ./scripts/publish.sh --dry-run") != 1:
        fail("release preflight workflow must run one complete publish dry-run")
    if "--execute" in workflow:
        fail("release preflight workflow must never execute publication")
    required_exact_commit_fragments = (
        "expected_commit:",
        "required: true",
        "concurrency:",
        "group: release-preflight-${{ inputs.expected_commit }}",
        "ref: ${{ inputs.expected_commit }}",
        "EXPECTED_COMMIT: ${{ inputs.expected_commit }}",
        "^[0-9a-f]{40}$",
        'test "$(git rev-parse HEAD)" = "$EXPECTED_COMMIT"',
    )
    for fragment in required_exact_commit_fragments:
        if fragment not in workflow:
            fail(f"release preflight workflow omits exact-commit guard {fragment!r}")


def verify_publish_script_safety(repo: Path) -> None:
    script = (repo / "scripts/publish.sh").read_text(encoding="utf-8")
    required_fragments = (
        "--archive-only)",
        "verify_protocol_packages_published()",
        "verify_published_package()",
        "published_crate_status()",
        "create_registry_source_package()",
        "verify_fixture_source_package()",
        "verify_release_source_unchanged()",
        "require_clean_archive_vcs=yes",
        "--confirm-publish VERSION",
        "sha256sum",
        "protocol_checksum_manifest",
        "protocol_api_checksum",
        "protocol_vcs_path",
        '*\\"dirty\\":true*',
        'python3 -c \'import json, sys; print(json.load(sys.stdin)["git"]["sha1"])\'',
    )
    for fragment in required_fragments:
        if fragment not in script:
            fail(f"scripts/publish.sh omits execute safety fragment {fragment!r}")

    required_script_lines = {
        f"protocol_repository={PROTOCOL_REPOSITORY}",
        f"protocol_revision={PROTOCOL_REVISION}",
        f"protocol_version={PROTOCOL_VERSION.removeprefix('=')}",
        f"protocol_crates='{' '.join(PROTOCOL_PUBLIC_PACKAGES)}'",
        "protocol_checksum_manifest="
        f"{verify_cargo_source_policy.HNS_RS_CHECKSUM_MANIFEST}",
    }
    missing_lines = required_script_lines - set(script.splitlines())
    if missing_lines:
        fail(
            "scripts/publish.sh protocol source differs from the workspace: "
            f"missing={sorted(missing_lines)}"
        )

    protocol_verify = shell_function_body(
        script,
        "verify_protocol_packages_published",
        "verify_new_upload",
    )
    protocol_evidence = (
        (
            "checksum-manifest lookup",
            """        protocol_expected_checksum=$(awk \\
            -v filename="$protocol_filename" \\
            '$2 == filename { print $1 }' \\
            "$protocol_checksum_manifest")""",
        ),
        (
            "API checksum extraction",
            """        protocol_api_checksum=$(python3 -c \\
            'import json, sys; print(json.load(sys.stdin)["version"]["checksum"])' \\
            <"$protocol_metadata")""",
        ),
        (
            "API yanked extraction",
            """        protocol_api_yanked=$(python3 -c \\
            'import json, sys; print(str(json.load(sys.stdin)["version"]["yanked"]).lower())' \\
            <"$protocol_metadata")""",
        ),
        (
            "download checksum extraction",
            """        protocol_download_checksum=$(sha256sum "$protocol_archive" | awk '{print $1}')""",
        ),
        (
            "VCS SHA extraction",
            """        protocol_vcs_sha=$(tar -xOf \\
            "$protocol_archive" \\
            "$package-$protocol_version/.cargo_vcs_info.json" |
            python3 -c 'import json, sys; print(json.load(sys.stdin)["git"]["sha1"])')""",
        ),
        (
            "VCS dirty extraction",
            """        protocol_vcs_dirty=$(tar -xOf \\
            "$protocol_archive" \\
            "$package-$protocol_version/.cargo_vcs_info.json" |
            python3 -c 'import json, sys; print(str(json.load(sys.stdin)["git"].get("dirty", False)).lower())')""",
        ),
        (
            "VCS path extraction",
            """        protocol_vcs_path=$(tar -xOf \\
            "$protocol_archive" \\
            "$package-$protocol_version/.cargo_vcs_info.json" |
            python3 -c 'import json, sys; print(json.load(sys.stdin).get("path_in_vcs", ""))')""",
        ),
    )
    protocol_predicates = (
        (
            "API checksum predicate",
            """        if [ "$protocol_api_checksum" != "$protocol_expected_checksum" ]
        then
            echo "error: crates.io API checksum for $package $protocol_version differs from $protocol_checksum_manifest" >&2
            exit 1
        fi""",
        ),
        (
            "non-yanked predicate",
            """        if [ "$protocol_api_yanked" != "false" ]
        then
            echo "error: required protocol package $package $protocol_version is yanked" >&2
            exit 1
        fi""",
        ),
        (
            "download checksum predicate",
            """        if [ "$protocol_download_checksum" != "$protocol_expected_checksum" ]
        then
            echo "error: downloaded $package $protocol_version differs from $protocol_checksum_manifest" >&2
            exit 1
        fi""",
        ),
        (
            "VCS SHA predicate",
            """        if [ "$protocol_vcs_sha" != "$protocol_revision" ]
        then
            echo "error: required protocol package $package $protocol_version identifies source $protocol_vcs_sha, expected $protocol_revision" >&2
            exit 1
        fi""",
        ),
        (
            "clean-VCS predicate",
            """        if [ "$protocol_vcs_dirty" = "true" ]
        then
            echo "error: required protocol package $package $protocol_version records a dirty source tree" >&2
            exit 1
        fi""",
        ),
        (
            "VCS path predicate",
            """        if [ "$protocol_vcs_path" != "crates/$package" ]
        then
            echo "error: required protocol package $package $protocol_version identifies path $protocol_vcs_path, expected crates/$package" >&2
            exit 1
        fi""",
        ),
    )
    protocol_guards = (
        *protocol_evidence[:3],
        *protocol_predicates[:2],
        protocol_evidence[3],
        protocol_predicates[2],
        protocol_evidence[4],
        protocol_predicates[3],
        protocol_evidence[5],
        protocol_predicates[4],
        protocol_evidence[6],
        protocol_predicates[5],
    )
    protocol_guard_positions: list[int] = []
    for description, fragment in protocol_guards:
        if protocol_verify.count(fragment) != 1:
            fail(
                "scripts/publish.sh protocol "
                f"{description} must remain wired exactly once"
            )
        protocol_guard_positions.append(protocol_verify.index(fragment))
    if protocol_guard_positions != sorted(protocol_guard_positions):
        fail("scripts/publish.sh protocol evidence and predicates are out of order")

    try:
        execute = script.split("    --execute)", 1)[1]
        protocol_position = execute.index("verify_protocol_packages_published")
        resume_package_position = execute.index(
            'create_registry_source_package "$package"'
        )
        new_package_position = execute.index('create_source_package "$package"')
        upload_position = execute.index(
            'cargo +"$rust_toolchain" publish --locked -p "$package"'
        )
        resume_position = execute.index('verify_published_package "$package" "$version"')
    except (IndexError, ValueError) as error:
        fail(f"scripts/publish.sh execute path is incomplete: {error}")
    if not (
        protocol_position < resume_package_position < resume_position < upload_position
        and protocol_position < new_package_position < upload_position
    ):
        fail(
            "protocol and path-specific local archive checks must precede "
            "resume verification and execute upload"
        )
    if "--allow-dirty" in execute:
        fail("scripts/publish.sh execute path must never allow dirty packaging")
    required_prepublished_fragments = (
        f"prepublished_engine_version={PREPUBLISHED_ENGINE_VERSION}",
        f"prepublished_engine_revision={PREPUBLISHED_ENGINE_REVISION}",
        f"prepublished_engine_manifest={PREPUBLISHED_ENGINE_MANIFEST}",
        f"prepublished_engine_checksum_manifest={PREPUBLISHED_ENGINE_CHECKSUM_MANIFEST}",
        f"prepublished_adapter_version={PREPUBLISHED_ADAPTER_VERSION}",
        f"prepublished_adapter_revision={PREPUBLISHED_ADAPTER_REVISION}",
        f"prepublished_adapter_manifest={PREPUBLISHED_ADAPTER_MANIFEST}",
        f"prepublished_adapter_checksum_manifest={PREPUBLISHED_ADAPTER_CHECKSUM_MANIFEST}",
        f"prepublished_patch_version={PREPUBLISHED_PATCH_VERSION}",
        f"prepublished_patch_revision={PREPUBLISHED_PATCH_REVISION}",
        f"prepublished_patch_manifest={PREPUBLISHED_PATCH_MANIFEST}",
        f"prepublished_patch_checksum_manifest={PREPUBLISHED_PATCH_CHECKSUM_MANIFEST}",
        f"prepublished_light_client_version={PREPUBLISHED_LIGHT_CLIENT_VERSION}",
        f"prepublished_light_client_revision={PREPUBLISHED_LIGHT_CLIENT_REVISION}",
        f"prepublished_light_client_manifest={PREPUBLISHED_LIGHT_CLIENT_MANIFEST}",
        f"prepublished_light_client_checksum_manifest={PREPUBLISHED_LIGHT_CLIENT_CHECKSUM_MANIFEST}",
        f"prepublished_policy_revision={PREPUBLISHED_POLICY_REVISION}",
        f"prepublished_policy_manifest={PREPUBLISHED_POLICY_MANIFEST}",
        f"prepublished_policy_checksum_manifest={PREPUBLISHED_POLICY_CHECKSUM_MANIFEST}",
        f"prepublished_successor_revision={PREPUBLISHED_SUCCESSOR_REVISION}",
        f"prepublished_successor_manifest={PREPUBLISHED_SUCCESSOR_MANIFEST}",
        f"prepublished_successor_checksum_manifest={PREPUBLISHED_SUCCESSOR_CHECKSUM_MANIFEST}",
        f"prepublished_loopback_version={PREPUBLISHED_LOOPBACK_VERSION}",
        f"prepublished_loopback_revision={PREPUBLISHED_LOOPBACK_REVISION}",
        f"prepublished_loopback_manifest={PREPUBLISHED_LOOPBACK_MANIFEST}",
        f"prepublished_loopback_checksum_manifest={PREPUBLISHED_LOOPBACK_CHECKSUM_MANIFEST}",
        "verify_prepublished_packages",
        'is_prepublished_package "$package" "$version"',
        'is_prepublished_engine_package "$package" "$version"',
        'is_prepublished_adapter_package "$package" "$version"',
        'is_prepublished_patch_package "$package" "$version"',
        'is_prepublished_light_client_package "$package" "$version"',
        'is_prepublished_policy_package "$package" "$version"',
        'is_prepublished_successor_package "$package" "$version"',
        'is_prepublished_loopback_package "$package" "$version"',
        'echo "skipping $package $version: immutable prepublished archive already verified"',
        'if [ "$api_checksum" != "$expected_checksum" ]',
        'if [ "$archive_checksum" != "$expected_checksum" ]',
        '*\\"sha1\\":\\"$source_revision\\"*',
    )
    for fragment in required_prepublished_fragments:
        if fragment not in script:
            fail(
                "scripts/publish.sh omits prepublished-engine provenance guard "
                f"{fragment!r}"
            )
    prepublished_position = execute.index("verify_prepublished_packages")
    if not prepublished_position < upload_position:
        fail("prepublished engine archive verification must precede every upload")

    mapping = script.split("package_with_local_dependencies()", 1)[1].split(
        "package_version()", 1
    )[0]
    if 'git="$protocol_repository"' in mapping:
        fail("published hns-rs packages must not be replaced by Git during packaging")
    mapped_packages: set[str] = set()
    pending_label = ""
    for line in mapping.splitlines():
        stripped = line.strip()
        if pending_label:
            pending_label += stripped
        elif re.match(r"^hns-[a-z0-9-|]+(?:\\|\))$", stripped):
            pending_label = stripped
        else:
            continue
        if pending_label.endswith("\\"):
            pending_label = pending_label[:-1]
            continue
        if pending_label.endswith(")"):
            for name in pending_label[:-1].split("|"):
                mapped_packages.add(name.strip())
            pending_label = ""
    allowlist = set(release_order(repo))
    if mapped_packages != allowlist:
        fail(
            "package dependency mappings differ from the public allowlist: "
            f"mapped={sorted(mapped_packages)}, allowlist={sorted(allowlist)}"
        )

    try:
        gateway_mapping = mapping.split("hns-browser-gateway)", 1)[1].split(
            ";;", 1
        )[0]
    except IndexError:
        fail("scripts/publish.sh has no hns-browser-gateway package mapping")
    for package in ("hns-icann-dane", "hns-namespace-resolution"):
        required_patch = f'patch.crates-io.{package}.path="crates/{package}"'
        if required_patch not in gateway_mapping:
            fail(
                "hns-browser-gateway dry-run must patch the shared "
                f"{package} identity alongside unpublished browser adapters"
            )


def verify_protocol_source(repo: Path) -> None:
    if verify_cargo_source_policy.HNS_RS_REPOSITORY != PROTOCOL_REPOSITORY:
        fail("release and Cargo source-policy hns-rs repositories differ")
    if verify_cargo_source_policy.HNS_RS_REVISION != PROTOCOL_REVISION:
        fail("release and Cargo source-policy hns-rs revisions differ")
    if (
        verify_cargo_source_policy.HNS_RS_CRATES_IO_REQUIREMENT
        != PROTOCOL_VERSION
    ):
        fail("release and Cargo source-policy hns-rs versions differ")
    if verify_cargo_source_policy.HNS_RS_VERSION_OVERRIDES != {
        package: requirement.removeprefix("=")
        for package, requirement in PROTOCOL_VERSION_OVERRIDES.items()
    }:
        fail("release and Cargo source-policy hns-rs version overrides differ")
    if verify_cargo_source_policy.HNS_RS_REVISION_OVERRIDES:
        fail("release and Cargo source-policy hns-rs revision overrides differ")
    if (
        tuple(verify_cargo_source_policy.HNS_RS_PUBLIC_PACKAGES)
        != PROTOCOL_PUBLIC_PACKAGES
    ):
        fail("release and Cargo source-policy hns-rs package inventories differ")
    try:
        verify_cargo_source_policy.verify_repository(repo)
    except verify_cargo_source_policy.CargoSourcePolicyError as error:
        fail(f"Cargo source policy failed: {error}")

    manifest = tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
    dependencies = manifest["workspace"]["dependencies"]
    for package in sorted(PROTOCOL_DIRECT_PACKAGES):
        dependency = dependencies.get(package)
        expected_requirement = PROTOCOL_VERSION_OVERRIDES.get(
            package, PROTOCOL_VERSION
        )
        if not isinstance(dependency, dict):
            fail(f"workspace protocol dependency {package} is not an exact table")
        if dependency != {"version": expected_requirement}:
            fail(
                f"workspace protocol dependency {package} must use only exact "
                f"registry requirement {expected_requirement}"
            )

    lock = tomllib.loads((repo / "Cargo.lock").read_text(encoding="utf-8"))
    checksums = verify_cargo_source_policy.load_hns_rs_checksums(repo)
    observed_protocol_dependencies: set[str] = set()
    for package in lock["package"]:
        name = package["name"]
        if name not in verify_cargo_source_policy.LOCKED_HNS_RS_PACKAGES:
            continue
        observed_protocol_dependencies.add(name)
        expected_version = PROTOCOL_VERSION_OVERRIDES.get(
            name, PROTOCOL_VERSION
        ).removeprefix("=")
        if package.get("version") != expected_version:
            fail(f"Cargo.lock has the wrong version for protocol package {name}")
        if (
            package.get("source")
            != verify_cargo_source_policy.HNS_RS_REGISTRY_SOURCE
        ):
            fail(f"Cargo.lock has an unreviewed source for protocol package {name}")
        if package.get("checksum") != checksums[name]:
            fail(f"Cargo.lock has an unreviewed checksum for protocol package {name}")
    if (
        observed_protocol_dependencies
        != verify_cargo_source_policy.LOCKED_HNS_RS_PACKAGES
    ):
        fail(
            "Cargo.lock protocol closure differs from source policy: "
            f"observed={sorted(observed_protocol_dependencies)}, "
            f"expected={sorted(verify_cargo_source_policy.LOCKED_HNS_RS_PACKAGES)}"
        )


def expected_workspace_versions(
    package_names: set[str], workspace_version: str
) -> dict[str, str]:
    return {
        name: SUCCESSOR_RELEASE_VERSIONS.get(
            name,
            PATCH_RELEASE_VERSIONS.get(
                name,
                (
                    PREPUBLISHED_PATCH_VERSION
                    if name in PREPUBLISHED_PATCH_PACKAGES
                    else PREPUBLISHED_LOOPBACK_VERSION
                    if name in PREPUBLISHED_LOOPBACK_PACKAGES
                    else PREPUBLISHED_LIGHT_CLIENT_VERSION
                    if name in PREPUBLISHED_LIGHT_CLIENT_PACKAGES
                    else workspace_version
                ),
            ),
        )
        for name in package_names
    }


def verify_workspace(repo: Path, metadata: dict, order: list[str]) -> tuple[str, str]:
    root_manifest = tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
    workspace_package = root_manifest["workspace"]["package"]
    version = workspace_package["version"]
    expected_publish = ["crates-io"]

    packages = {package["name"]: package for package in metadata["packages"]}
    expected_versions = expected_workspace_versions(set(packages), version)
    expected_packages = set(order) | PRIVATE_PACKAGES
    if set(packages) != expected_packages:
        fail(
            "workspace package set differs from the release inventory: "
            f"workspace={sorted(packages)}, expected={sorted(expected_packages)}"
        )

    publishable = {
        package["name"]
        for package in metadata["packages"]
        if package.get("publish") != []
    }
    if publishable != set(order):
        fail(
            "publishable workspace packages differ from the release allowlist: "
            f"workspace={sorted(publishable)}, allowlist={sorted(order)}"
        )
    private = {
        package["name"]
        for package in metadata["packages"]
        if package.get("publish") == []
    }
    if private != PRIVATE_PACKAGES:
        fail(
            "private workspace packages differ from the expected set: "
            f"workspace={sorted(private)}, expected={sorted(PRIVATE_PACKAGES)}"
        )

    for package in metadata["packages"]:
        for dependency in package["dependencies"]:
            dependency_name = dependency["name"]
            if dependency_name not in packages:
                continue
            expected_path = Path(packages[dependency_name]["manifest_path"]).resolve().parent
            dependency_path = dependency.get("path")
            if dependency_path is None:
                fail(
                    f"workspace package {package['name']} resolves internal dependency "
                    f"{dependency_name} from an external source"
                )
            if Path(dependency_path).resolve() != expected_path:
                fail(
                    f"workspace package {package['name']} resolves internal dependency "
                    f"{dependency_name} from {dependency_path}, expected {expected_path}"
                )

    lock = tomllib.loads((repo / "Cargo.lock").read_text(encoding="utf-8"))
    for package in lock["package"]:
        if package["name"] not in packages:
            continue
        if package.get("source") is not None:
            fail(
                f"Cargo.lock retains external duplicate identity for workspace package "
                f"{package['name']} {package['version']}"
            )
        expected_version = expected_versions[package["name"]]
        if package["version"] != expected_version:
            fail(
                f"Cargo.lock workspace package {package['name']} has version "
                f"{package['version']}, expected {expected_version}"
            )

    changelog = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(
        rf"^## {re.escape(version)} - (Unreleased|unreleased|\d{{4}}-\d{{2}}-\d{{2}})$",
        changelog,
        re.MULTILINE,
    )
    if len(headings) != 1:
        fail(
            f"CHANGELOG.md must contain exactly one {version} unreleased or dated heading"
        )
    release_label = headings[0]
    if release_label.lower() != "unreleased":
        try:
            date.fromisoformat(release_label)
        except ValueError:
            fail(f"CHANGELOG.md has an invalid release date {release_label!r}")
    expected_heading = f"## {version} - {release_label}"

    template = (repo / "release/CRATE-CHANGELOG.md").read_bytes()
    adapter_template = (repo / "release/ADAPTER-CRATE-CHANGELOG.md").read_bytes()
    light_client_template = (
        repo / "release/LIGHT-CLIENT-0.2.3-CRATE-CHANGELOG.md"
    ).read_bytes()
    template_text = template.decode("utf-8")
    adapter_template_text = adapter_template.decode("utf-8")
    if expected_heading not in template_text:
        fail("release/CRATE-CHANGELOG.md does not match the workspace release heading")
    stable_changelog_url = (
        f"https://github.com/handshake-rs/hns-dane-engine/blob/v{version}/CHANGELOG.md"
    )
    if stable_changelog_url not in template_text:
        fail("release/CRATE-CHANGELOG.md does not link the immutable release tag")
    if expected_heading not in adapter_template_text:
        fail("release/ADAPTER-CRATE-CHANGELOG.md does not match the workspace release heading")
    adapter_changelog_url = (
        f"https://github.com/handshake-rs/hns-dane-engine/blob/browser-adapters-v{version}/CHANGELOG.md"
    )
    if adapter_changelog_url not in adapter_template_text:
        fail("release/ADAPTER-CRATE-CHANGELOG.md does not link the adapter source tag")

    positions = {package: index for index, package in enumerate(order)}
    for name in order:
        package = packages[name]
        package_root = Path(package["manifest_path"]).resolve().parent
        expected_root = (repo / "crates" / name).resolve()
        if package_root != expected_root:
            fail(f"{name} manifest is outside crates/{name}")
        expected_version = expected_versions[name]
        if package["version"] != expected_version:
            fail(f"{name} version {package['version']} differs from expected {expected_version}")
        if package.get("publish") != expected_publish:
            fail(f"{name} must publish only to crates-io")
        required_values = {
            "description": package.get("description"),
            "repository": package.get("repository"),
            "documentation": package.get("documentation"),
            "readme": package.get("readme"),
            "rust_version": package.get("rust_version"),
        }
        missing_values = [field for field, value in required_values.items() if not value]
        if missing_values:
            fail(f"{name} is missing crates.io metadata: {', '.join(missing_values)}")
        if name in PUBLIC_ADAPTER_PACKAGES:
            expected_license_file = (
                package_root / "LICENSE-POLYFORM-NONCOMMERCIAL"
            ).resolve()
            if package.get("license") is not None or (
                package_root / package.get("license_file", "")
            ).resolve() != expected_license_file:
                fail(f"{name} must retain the PolyForm Noncommercial license file")
        elif package.get("license") != workspace_package["license"]:
            fail(f"{name} license differs from [workspace.package]")
        if package["repository"] != REPOSITORY:
            fail(f"{name} repository is not {REPOSITORY}")
        if package["documentation"] != f"https://docs.rs/{name}":
            fail(f"{name} has a noncanonical docs.rs URL")
        if package["rust_version"] != workspace_package["rust-version"]:
            fail(f"{name} rust-version differs from [workspace.package]")
        if package["edition"] != workspace_package["edition"]:
            fail(f"{name} edition differs from [workspace.package]")
        if package.get("keywords") != workspace_package["keywords"]:
            fail(f"{name} keywords differ from [workspace.package]")
        if package.get("categories") != workspace_package["categories"]:
            fail(f"{name} categories differ from [workspace.package]")

        readme = package_root / package["readme"]
        if not readme.is_file() or not readme.read_text(encoding="utf-8").strip():
            fail(f"{name} readme is missing or empty")
        license_names = (
            ("LICENSE-POLYFORM-NONCOMMERCIAL",)
            if name in PUBLIC_ADAPTER_PACKAGES
            else ("LICENSE-APACHE", "LICENSE-MIT")
        )
        for license_name in license_names:
            package_license = (package_root / license_name).read_bytes()
            workspace_license = (repo / license_name).read_bytes()
            if package_license != workspace_license:
                fail(f"{name} {license_name} differs from the workspace license")
        expected_template = (
            adapter_template if name in PUBLIC_ADAPTER_PACKAGES else template
        )
        expected_template_name = (
            "release/ADAPTER-CRATE-CHANGELOG.md"
            if name in PUBLIC_ADAPTER_PACKAGES
            else "release/CRATE-CHANGELOG.md"
        )
        package_changelog = (package_root / "CHANGELOG.md").read_bytes()
        if name in PATCH_RELEASE_VERSIONS:
            package_changelog_text = package_changelog.decode("utf-8")
            patch_heading = (
                rf"^## {re.escape(expected_version)} - \d{{4}}-\d{{2}}-\d{{2}}$"
            )
            if re.search(patch_heading, package_changelog_text, re.MULTILINE) is None:
                fail(
                    f"{name} CHANGELOG.md lacks a dated {expected_version} patch heading"
                )
            patch_changelog_url = (
                "https://github.com/handshake-rs/hns-dane-engine/blob/"
                f"{PATCH_RELEASE_TAG}/CHANGELOG.md"
            )
            if patch_changelog_url not in package_changelog_text:
                fail(f"{name} CHANGELOG.md does not link the patch release tag")
        elif name in PREPUBLISHED_LIGHT_CLIENT_PACKAGES:
            if package_changelog != light_client_template:
                fail(
                    f"{name} CHANGELOG.md differs from "
                    "release/LIGHT-CLIENT-0.2.3-CRATE-CHANGELOG.md"
                )
        elif name in PREPUBLISHED_LOOPBACK_PACKAGES:
            package_changelog_text = package_changelog.decode("utf-8")
            loopback_heading = (
                rf"^## {re.escape(PREPUBLISHED_LOOPBACK_VERSION)} - "
                r"\d{4}-\d{2}-\d{2}$"
            )
            if re.search(loopback_heading, package_changelog_text, re.MULTILINE) is None:
                fail(
                    f"{name} CHANGELOG.md lacks the recorded "
                    f"{PREPUBLISHED_LOOPBACK_VERSION} release heading"
                )
            if "loopback-proxy-v0.2.3/CHANGELOG.md" not in package_changelog_text:
                fail(f"{name} CHANGELOG.md does not link its immutable release tag")
        elif name in SUCCESSOR_RELEASE_VERSIONS:
            package_changelog_text = package_changelog.decode("utf-8")
            successor_heading = rf"^## {re.escape(expected_version)} - \d{{4}}-\d{{2}}-\d{{2}}$"
            if re.search(successor_heading, package_changelog_text, re.MULTILINE) is None:
                fail(
                    f"{name} CHANGELOG.md lacks a dated {expected_version} release heading"
                )
            successor_changelog_url = (
                "https://github.com/handshake-rs/hns-dane-engine/blob/"
                f"v{SUCCESSOR_RELEASE_VERSION}/CHANGELOG.md"
            )
            if successor_changelog_url not in package_changelog_text:
                fail(
                    f"{name} CHANGELOG.md does not link the successor release tag"
                )
        elif package_changelog != expected_template:
            fail(f"{name} CHANGELOG.md differs from {expected_template_name}")

        for fixture in PACKAGE_FIXTURES.get(name, ()):
            canonical_fixture = repo / "fixtures" / fixture
            package_fixture = package_root / "fixtures" / fixture
            if not canonical_fixture.is_file():
                fail(f"canonical fixture fixtures/{fixture} is missing")
            if not package_fixture.is_file():
                fail(f"{name} package fixture fixtures/{fixture} is missing")
            if package_fixture.read_bytes() != canonical_fixture.read_bytes():
                fail(f"{name} package fixture fixtures/{fixture} is stale")

        for dependency in package["dependencies"]:
            dependency_name = dependency["name"]
            if dependency_name not in packages:
                continue
            if dependency_name in PRIVATE_PACKAGES:
                if dependency.get("kind") != "dev":
                    fail(f"public package {name} has a non-dev private dependency")
                continue
            expected_requirement = f"^{expected_versions[dependency_name]}"
            if dependency["req"] != expected_requirement:
                # Immutable previously published consumers retain their
                # original compatible lower bound. Rewriting those manifests
                # would create unpublishable local source that no longer
                # matches the recorded archive; Cargo's 0.2 caret range still
                # admits the targeted 0.2.4 dependency.
                compatible_immutable_consumer = (
                    name not in PATCH_RELEASE_VERSIONS
                    and dependency_name in PATCH_RELEASE_VERSIONS
                    and dependency["req"] in {"^0.2.2", "^0.2.3"}
                    and expected_requirement == "^0.2.4"
                )
                if not compatible_immutable_consumer:
                    fail(
                        f"{name} requires internal {dependency_name} at "
                        f"{dependency['req']}, expected {expected_requirement}"
                    )
            if positions[dependency_name] >= positions[name]:
                fail(f"{dependency_name} must precede dependent package {name}")

    return version, release_label


def verify_clean_source(repo: Path) -> None:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.stdout:
        fail("execution requires a clean worktree")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        fail("execution requires HEAD to resolve to one exact Git commit")
    subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=repo,
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--toolchain", default="1.89.0")
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--expected-version")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parent.parent
    order = release_order(repo)
    verify_prepublished_engine_inventory(repo, order)
    verify_prepublished_adapter_inventory(repo, order)
    verify_prepublished_patch_inventory(repo)
    verify_named_prepublished_inventory(
        repo,
        PREPUBLISHED_LIGHT_CLIENT_MANIFEST,
        PREPUBLISHED_LIGHT_CLIENT_CHECKSUM_MANIFEST,
        PREPUBLISHED_LIGHT_CLIENT_PACKAGES,
        {
            package: PREPUBLISHED_LIGHT_CLIENT_VERSION
            for package in PREPUBLISHED_LIGHT_CLIENT_PACKAGES
        },
    )
    verify_named_prepublished_inventory(
        repo,
        PREPUBLISHED_POLICY_MANIFEST,
        PREPUBLISHED_POLICY_CHECKSUM_MANIFEST,
        PREPUBLISHED_POLICY_PACKAGES,
        {"hns-resolution-policy": "0.3.0"},
    )
    verify_named_prepublished_inventory(
        repo,
        PREPUBLISHED_SUCCESSOR_MANIFEST,
        PREPUBLISHED_SUCCESSOR_CHECKSUM_MANIFEST,
        PREPUBLISHED_SUCCESSOR_PACKAGES,
        SUCCESSOR_RELEASE_VERSIONS,
    )
    verify_named_prepublished_inventory(
        repo,
        PREPUBLISHED_LOOPBACK_MANIFEST,
        PREPUBLISHED_LOOPBACK_CHECKSUM_MANIFEST,
        PREPUBLISHED_LOOPBACK_PACKAGES,
        {"hns-browser-loopback-proxy": PREPUBLISHED_LOOPBACK_VERSION},
    )
    patch_release_order(repo)
    version, release_label = verify_workspace(
        repo, cargo_metadata(repo, args.toolchain), order
    )
    verify_protocol_source(repo)
    verify_release_document(repo, order, version)
    verify_release_workflow(repo)
    verify_publish_script_safety(repo)
    if args.expected_version is not None and args.expected_version != PATCH_RELEASE_VERSION:
        fail(
            f"confirmed version {args.expected_version} differs from patch release "
            f"version {PATCH_RELEASE_VERSION}"
        )
    if args.require_clean:
        if release_label.lower() == "unreleased":
            fail("execution requires a dated release heading, not 'Unreleased'")
        verify_clean_source(repo)
    print(
        f"release metadata valid for {len(order)} public crates; "
        f"{len(PATCH_RELEASE_PACKAGES)} patch packages are at {PATCH_RELEASE_VERSION}"
    )


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, subprocess.SubprocessError, tomllib.TOMLDecodeError) as error:
        fail(str(error))
