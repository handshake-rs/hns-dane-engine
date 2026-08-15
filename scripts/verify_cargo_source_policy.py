#!/usr/bin/env python3
"""Enforce the standalone engine's narrow, immutable Cargo source policy."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator, Mapping
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
ROOT_MANIFEST = Path("Cargo.toml")
LOCKFILE = Path("Cargo.lock")
HNS_RS_REPOSITORY = "https://github.com/handshake-rs/hns-rs.git"
HNS_RS_REVISION = "d0cde9ded6f8f93f96f16daafc094849c6d484bf"
HNS_RS_CRATES_IO_VERSION = "0.3.0"
HNS_RS_CRATES_IO_REQUIREMENT = f"={HNS_RS_CRATES_IO_VERSION}"
HNS_RS_REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
HNS_RS_CHECKSUM_MANIFEST = Path(
    f"release/hns-rs-{HNS_RS_CRATES_IO_VERSION}-crates.sha256"
)

HNS_RS_PUBLIC_PACKAGES = (
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

DIRECT_HNS_RS_PACKAGES = frozenset(
    {
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
)
LOCKED_HNS_RS_PACKAGES = DIRECT_HNS_RS_PACKAGES | {
    "hns-chat-protocol",
    "hns-mining",
    "hns-transaction",
}

EXPECTED_CONSUMERS = {
    Path("crates/hns-browser-testkit/Cargo.toml"): frozenset(
        {
            ("dependencies", "hns-covenants"),
            ("dependencies", "hns-header-consensus"),
            ("dependencies", "hns-primitives"),
        }
    ),
    Path("crates/hns-dane-engine/Cargo.toml"): frozenset(
        {
            ("dependencies", "hns-header-consensus"),
            ("dependencies", "hns-hnsr-protocol"),
            ("dependencies", "hns-hrm"),
            ("dependencies", "hns-p2p-wire"),
            ("dependencies", "hns-rollback-journal"),
            ("dependencies", "hns-service-authority"),
        }
    ),
    Path("crates/hns-light-chain/Cargo.toml"): frozenset(
        {
            ("dependencies", "hns-covenants"),
            ("dependencies", "hns-encoding"),
            ("dependencies", "hns-header-consensus"),
            ("dependencies", "hns-primitives"),
            ("dependencies", "hns-urkel-proof"),
        }
    ),
    Path("crates/hns-light-p2p/Cargo.toml"): frozenset(
        {
            ("dependencies", "hns-header-consensus"),
            ("dependencies", "hns-p2p-wire"),
            ("dependencies", "hns-primitives"),
        }
    ),
    Path("crates/hns-light-sync/Cargo.toml"): frozenset(
        {
            ("dependencies", "hns-header-consensus"),
            ("dependencies", "hns-p2p-wire"),
            ("dependencies", "hns-primitives"),
        }
    ),
    Path("crates/hns-p2p-transport/Cargo.toml"): frozenset(
        {
            ("dependencies", "hns-dns-relay-protocol"),
            ("dependencies", "hns-odoh-protocol"),
            ("dependencies", "hns-p2p-experimental"),
            ("dev-dependencies", "hns-primitives"),
        }
    ),
    Path("crates/hns-resolver/Cargo.toml"): frozenset(
        {
            ("dev-dependencies", "hns-covenants"),
            ("dev-dependencies", "hns-header-consensus"),
            ("dev-dependencies", "hns-primitives"),
        }
    ),
    Path("crates/hns-transport/Cargo.toml"): frozenset(
        {
            ("dependencies", "hns-covenants"),
            ("dependencies", "hns-header-consensus"),
            ("dependencies", "hns-primitives"),
        }
    ),
}


class CargoSourcePolicyError(RuntimeError):
    """A manifest or lockfile violates the reviewed Cargo source boundary."""


def tracked_cargo_manifests(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "**/Cargo.toml", "Cargo.toml"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return sorted(
        Path(raw.decode())
        for raw in result.stdout.split(b"\0")
        if raw and Path(raw.decode()).name == "Cargo.toml"
    )


def nested_specs(
    value: Any, path: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], Mapping[str, Any]]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = (*path, str(key))
            if isinstance(child, Mapping):
                yield child_path, child
            yield from nested_specs(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from nested_specs(child, (*path, str(index)))


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def load_hns_rs_checksums(root: Path) -> dict[str, str]:
    path = root / HNS_RS_CHECKSUM_MANIFEST
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(lines) != len(HNS_RS_PUBLIC_PACKAGES):
        raise CargoSourcePolicyError(
            f"{HNS_RS_CHECKSUM_MANIFEST}: expected "
            f"{len(HNS_RS_PUBLIC_PACKAGES)} archive hashes, found {len(lines)}"
        )

    checksums: dict[str, str] = {}
    for package, line in zip(HNS_RS_PUBLIC_PACKAGES, lines, strict=True):
        fields = line.split()
        expected_filename = f"{package}-{HNS_RS_CRATES_IO_VERSION}.crate"
        if (
            len(fields) != 2
            or re.fullmatch(r"[0-9a-f]{64}", fields[0]) is None
            or fields[1] != expected_filename
        ):
            raise CargoSourcePolicyError(
                f"{HNS_RS_CHECKSUM_MANIFEST}: expected '<sha256>  "
                f"{expected_filename}'"
            )
        checksums[package] = fields[0]
    return checksums


def validate_manifests(root: Path, manifests: list[Path]) -> None:
    root = root.resolve()
    root_declarations: dict[str, int] = {
        package: 0 for package in DIRECT_HNS_RS_PACKAGES
    }
    actual_consumers: dict[Path, set[tuple[str, str]]] = defaultdict(set)

    for relative_path in manifests:
        document = load_toml(root / relative_path)
        for location, specification in nested_specs(document):
            dependency = location[-1]
            rendered_location = ".".join(location)

            path_value = specification.get("path")
            if isinstance(path_value, str):
                dependency_path = (
                    (root / relative_path).parent / path_value
                ).resolve()
                try:
                    dependency_path.relative_to(root)
                except ValueError as error:
                    raise CargoSourcePolicyError(
                        f"{relative_path}:{rendered_location}: path dependency "
                        f"escapes the engine repository: {path_value!r}"
                    ) from error

            if dependency not in DIRECT_HNS_RS_PACKAGES:
                if "git" in specification:
                    raise CargoSourcePolicyError(
                        f"{relative_path}:{rendered_location}: Cargo Git "
                        f"dependency {dependency!r} is not allowed"
                    )
                package_override = specification.get("package")
                if (
                    isinstance(package_override, str)
                    and package_override in DIRECT_HNS_RS_PACKAGES
                ):
                    raise CargoSourcePolicyError(
                        f"{relative_path}:{rendered_location}: hns-rs dependency "
                        "renaming is not allowed"
                    )
                continue

            root_location = ("workspace", "dependencies", dependency)
            if relative_path == ROOT_MANIFEST and location == root_location:
                if specification != {"version": HNS_RS_CRATES_IO_REQUIREMENT}:
                    raise CargoSourcePolicyError(
                        f"{relative_path}:{rendered_location}: expected "
                        f"exact crates.io requirement "
                        f"{HNS_RS_CRATES_IO_REQUIREMENT!r} with no source override"
                    )
                root_declarations[dependency] += 1
                continue

            if (
                len(location) != 2
                or location[0]
                not in {"dependencies", "dev-dependencies", "build-dependencies"}
                or specification != {"workspace": True}
            ):
                raise CargoSourcePolicyError(
                    f"{relative_path}:{rendered_location}: canonical hns-rs "
                    "dependencies must inherit the reviewed workspace source"
                )
            actual_consumers[relative_path].add(
                (location[0], dependency)
            )

    for dependency, count in sorted(root_declarations.items()):
        if count != 1:
            raise CargoSourcePolicyError(
                f"{ROOT_MANIFEST}: expected exactly one pinned declaration "
                f"for {dependency}, found {count}"
            )

    for manifest, expected in EXPECTED_CONSUMERS.items():
        actual = frozenset(actual_consumers.pop(manifest, set()))
        if actual != expected:
            raise CargoSourcePolicyError(
                f"{manifest}: reviewed hns-rs consumer set differs: "
                f"expected {sorted(expected)!r}, found {sorted(actual)!r}"
            )
    if actual_consumers:
        manifest, declarations = sorted(actual_consumers.items())[0]
        raise CargoSourcePolicyError(
            f"{manifest}: unexpected hns-rs consumers: "
            f"{sorted(declarations)!r}"
        )


def validate_lockfile(root: Path) -> None:
    document = load_toml(root / LOCKFILE)
    checksums = load_hns_rs_checksums(root)
    counts: dict[str, int] = {
        package: 0 for package in LOCKED_HNS_RS_PACKAGES
    }

    for package in document.get("package", []):
        source = package.get("source")
        name = package.get("name", "<unknown>")
        if isinstance(source, str) and source.startswith("git+"):
            raise CargoSourcePolicyError(
                f"{LOCKFILE}: locked Cargo Git package {name!r} is not allowed"
            )
        if name not in HNS_RS_PUBLIC_PACKAGES:
            continue
        if name not in LOCKED_HNS_RS_PACKAGES:
            raise CargoSourcePolicyError(
                f"{LOCKFILE}: unexpected hns-rs package {name!r} entered the closure"
            )
        if package.get("version") != HNS_RS_CRATES_IO_VERSION:
            raise CargoSourcePolicyError(
                f"{LOCKFILE}: {name} must lock to version "
                f"{HNS_RS_CRATES_IO_VERSION}, found {package.get('version')!r}"
            )
        if source != HNS_RS_REGISTRY_SOURCE:
            raise CargoSourcePolicyError(
                f"{LOCKFILE}: {name} must use {HNS_RS_REGISTRY_SOURCE!r}, "
                f"found {source!r}"
            )
        if package.get("checksum") != checksums[name]:
            raise CargoSourcePolicyError(
                f"{LOCKFILE}: {name} checksum differs from "
                f"{HNS_RS_CHECKSUM_MANIFEST}"
            )
        counts[name] += 1

    for package, count in sorted(counts.items()):
        if count != 1:
            raise CargoSourcePolicyError(
                f"{LOCKFILE}: expected exactly one locked {package} package, "
                f"found {count}"
            )


def verify_repository(
    root: Path = ROOT, manifests: list[Path] | None = None
) -> None:
    validate_manifests(
        root,
        tracked_cargo_manifests(root) if manifests is None else manifests,
    )
    validate_lockfile(root)


def main() -> int:
    try:
        verify_repository()
    except (
        CargoSourcePolicyError,
        OSError,
        subprocess.CalledProcessError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"Cargo source policy failed: {error}", file=sys.stderr)
        return 1
    print(
        "Cargo source policy permits only the reviewed exact hns-rs "
        f"{HNS_RS_CRATES_IO_REQUIREMENT} registry closure and repository-local "
        f"path dependencies; {len(HNS_RS_PUBLIC_PACKAGES)} archive hashes bind "
        f"source {HNS_RS_REVISION}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
