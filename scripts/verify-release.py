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
PROTOCOL_REVISION = "b24b66c382de53330ec21dd3137e056a2bea3e2d"
PROTOCOL_VERSION = "=0.2.0"
PROTOCOL_PUBLIC_PACKAGES = (
    "hns-encoding",
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
    "hns-odoh-protocol",
    "hns-p2p-experimental",
    "hns-p2p-wire",
    "hns-primitives",
    "hns-service-authority",
    "hns-urkel-proof",
}
PRIVATE_PACKAGES = {
    "hns-browser-chain",
    "hns-browser-dane",
    "hns-browser-dnssec",
    "hns-browser-gateway",
    "hns-browser-loopback-proxy",
    "hns-browser-p2p",
    "hns-browser-primitives",
    "hns-browser-resolver",
    "hns-browser-sync",
    "hns-browser-testkit",
    "hns-browser-transport",
    "hns-browser-urkel",
}
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
    if len(packages) != 19:
        fail(f"{path.relative_to(repo)} must contain exactly 19 packages")
    if len(packages) != len(set(packages)):
        fail(f"{path.relative_to(repo)} contains a duplicate package")
    for package in packages:
        if re.fullmatch(r"hns-[a-z0-9-]+", package) is None:
            fail(f"invalid public package name {package!r}")
    return packages


def verify_release_document(repo: Path, order: list[str], version: str) -> None:
    document = (repo / "docs/releasing.md").read_text(encoding="utf-8")
    documented = re.findall(r"^\d+\. `([^`]+)`$", document, flags=re.MULTILINE)
    if documented != order:
        fail("docs/releasing.md does not match release/public-crates.txt")

    execute_command = f"./scripts/publish.sh --execute --confirm-publish {version}"
    if execute_command not in document:
        fail("docs/releasing.md does not use the current version in its execute example")

    publish_script = (repo / "scripts/publish.sh").read_text(encoding="utf-8")
    interval_match = re.search(
        r"^publish_interval_seconds=\$\{PUBLISH_INTERVAL_SECONDS-(\d+)\}$",
        publish_script,
        re.MULTILINE,
    )
    if interval_match is None:
        fail("scripts/publish.sh has no validated publication interval default")
    default_interval = interval_match.group(1)
    if f"{default_interval}-second" not in document:
        fail("docs/releasing.md omits the publication interval default")
    if f"PUBLISH_INTERVAL_SECONDS={default_interval}" not in document:
        fail("docs/releasing.md cooldown example differs from the script default")

    required_text = (
        "release/public-crates.txt",
        "./scripts/publish.sh --archive-only",
        ".github/workflows/release-preflight.yml",
        "expected_commit",
        PROTOCOL_REVISION,
        f"`hns-rs` `{PROTOCOL_VERSION.removeprefix('=')}`",
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
    archive_command = "./scripts/publish.sh --archive-only"
    if check_script.count(archive_command) != 1:
        fail("scripts/check.sh must run archive-only release verification once")
    if "./scripts/publish.sh --dry-run" in check_script:
        fail("scripts/check.sh must not run the expensive publish dry-run")
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
        "verify_fixture_source_package()",
        "verify_release_source_unchanged()",
        "require_clean_archive_vcs=yes",
        "--confirm-publish VERSION",
        "sha256sum",
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
    }
    missing_lines = required_script_lines - set(script.splitlines())
    if missing_lines:
        fail(
            "scripts/publish.sh protocol source differs from the workspace: "
            f"missing={sorted(missing_lines)}"
        )

    try:
        execute = script.split("    --execute)", 1)[1]
        protocol_position = execute.index("verify_protocol_packages_published")
        package_position = execute.index('create_source_package "$package"')
        upload_position = execute.index(
            'cargo +"$rust_toolchain" publish --locked -p "$package"'
        )
        resume_position = execute.index('verify_published_package "$package" "$version"')
    except (IndexError, ValueError) as error:
        fail(f"scripts/publish.sh execute path is incomplete: {error}")
    if not protocol_position < package_position < resume_position < upload_position:
        fail("protocol, local archive, and resume checks must precede execute upload")
    if "--allow-dirty" in execute:
        fail("scripts/publish.sh execute path must never allow dirty packaging")

    mapping = script.split("package_with_local_dependencies()", 1)[1].split(
        "package_version()", 1
    )[0]
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


def verify_protocol_source(repo: Path) -> None:
    if verify_cargo_source_policy.HNS_RS_GIT_URL != PROTOCOL_REPOSITORY:
        fail("release and Cargo source-policy hns-rs repositories differ")
    if verify_cargo_source_policy.HNS_RS_REVISION != PROTOCOL_REVISION:
        fail("release and Cargo source-policy hns-rs revisions differ")
    if verify_cargo_source_policy.HNS_RS_CRATES_IO_VERSION != PROTOCOL_VERSION.removeprefix("="):
        fail("release and Cargo source-policy hns-rs versions differ")
    try:
        verify_cargo_source_policy.verify_repository(repo)
    except verify_cargo_source_policy.CargoSourcePolicyError as error:
        fail(f"Cargo source policy failed: {error}")

    manifest = tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
    dependencies = manifest["workspace"]["dependencies"]
    for package in sorted(PROTOCOL_DIRECT_PACKAGES):
        dependency = dependencies.get(package)
        if not isinstance(dependency, dict):
            fail(f"workspace protocol dependency {package} is not an exact table")
        if dependency.get("version") != PROTOCOL_VERSION.removeprefix("="):
            fail(f"workspace protocol dependency {package} has the wrong version")
        if dependency.get("git") != PROTOCOL_REPOSITORY:
            fail(f"workspace protocol dependency {package} has the wrong repository")
        if dependency.get("rev") != PROTOCOL_REVISION:
            fail(f"workspace protocol dependency {package} has the wrong revision")
        for forbidden in ("branch", "tag"):
            if forbidden in dependency:
                fail(f"workspace protocol dependency {package} uses {forbidden}")

    lock = tomllib.loads((repo / "Cargo.lock").read_text(encoding="utf-8"))
    expected_lock_source = (
        f"git+{PROTOCOL_REPOSITORY}?rev={PROTOCOL_REVISION}#{PROTOCOL_REVISION}"
    )
    observed_protocol_dependencies: set[str] = set()
    for package in lock["package"]:
        name = package["name"]
        if name not in PROTOCOL_PUBLIC_PACKAGES:
            continue
        observed_protocol_dependencies.add(name)
        if package.get("source") != expected_lock_source:
            fail(f"Cargo.lock has an unreviewed source for protocol package {name}")
    if not PROTOCOL_DIRECT_PACKAGES.issubset(observed_protocol_dependencies):
        fail(
            "Cargo.lock omits direct protocol packages: "
            f"{sorted(PROTOCOL_DIRECT_PACKAGES - observed_protocol_dependencies)}"
        )


def verify_workspace(repo: Path, metadata: dict, order: list[str]) -> tuple[str, str]:
    root_manifest = tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
    workspace_package = root_manifest["workspace"]["package"]
    version = workspace_package["version"]
    expected_publish = ["crates-io"]

    packages = {package["name"]: package for package in metadata["packages"]}
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
        if package["version"] != version:
            fail(
                f"Cargo.lock workspace package {package['name']} has version "
                f"{package['version']}, expected {version}"
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
    template_text = template.decode("utf-8")
    if expected_heading not in template_text:
        fail("release/CRATE-CHANGELOG.md does not match the workspace release heading")
    stable_changelog_url = (
        f"https://github.com/handshake-rs/hns-dane-engine/blob/v{version}/CHANGELOG.md"
    )
    if stable_changelog_url not in template_text:
        fail("release/CRATE-CHANGELOG.md does not link the immutable release tag")

    positions = {package: index for index, package in enumerate(order)}
    for name in order:
        package = packages[name]
        package_root = Path(package["manifest_path"]).resolve().parent
        expected_root = (repo / "crates" / name).resolve()
        if package_root != expected_root:
            fail(f"{name} manifest is outside crates/{name}")
        if package["version"] != version:
            fail(f"{name} version {package['version']} differs from workspace {version}")
        if package.get("publish") != expected_publish:
            fail(f"{name} must publish only to crates-io")
        required_values = {
            "description": package.get("description"),
            "license": package.get("license"),
            "repository": package.get("repository"),
            "documentation": package.get("documentation"),
            "readme": package.get("readme"),
            "rust_version": package.get("rust_version"),
        }
        missing_values = [field for field, value in required_values.items() if not value]
        if missing_values:
            fail(f"{name} is missing crates.io metadata: {', '.join(missing_values)}")
        if package["license"] != workspace_package["license"]:
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
        for license_name in ("LICENSE-APACHE", "LICENSE-MIT"):
            package_license = (package_root / license_name).read_bytes()
            workspace_license = (repo / license_name).read_bytes()
            if package_license != workspace_license:
                fail(f"{name} {license_name} differs from the workspace license")
        if (package_root / "CHANGELOG.md").read_bytes() != template:
            fail(f"{name} CHANGELOG.md differs from release/CRATE-CHANGELOG.md")

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
            expected_requirement = f"^{version}"
            if dependency["req"] != expected_requirement:
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
    version, release_label = verify_workspace(
        repo, cargo_metadata(repo, args.toolchain), order
    )
    verify_protocol_source(repo)
    verify_release_document(repo, order, version)
    verify_release_workflow(repo)
    verify_publish_script_safety(repo)
    if args.expected_version is not None and args.expected_version != version:
        fail(
            f"confirmed version {args.expected_version} differs from workspace version {version}"
        )
    if args.require_clean:
        if release_label.lower() == "unreleased":
            fail("execution requires a dated release heading, not 'Unreleased'")
        verify_clean_source(repo)
    print(f"release metadata valid for {len(order)} public crates at version {version}")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, subprocess.SubprocessError, tomllib.TOMLDecodeError) as error:
        fail(str(error))
