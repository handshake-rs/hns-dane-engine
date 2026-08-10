#!/usr/bin/env python3
"""Enforce the standalone engine's narrow, immutable Cargo source policy."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator, Mapping
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
ROOT_MANIFEST = Path("Cargo.toml")
LOCKFILE = Path("Cargo.lock")
HNS_RS_GIT_URL = "https://github.com/handshake-rs/hns-rs.git"
HNS_RS_REVISION = "b33b346780c8f6a9bb18a54390019486cdab0221"
HNS_RS_CRATES_IO_VERSION = "0.2.0"
HNS_RS_LOCK_SOURCE = (
    f"git+{HNS_RS_GIT_URL}?rev={HNS_RS_REVISION}#{HNS_RS_REVISION}"
)

DIRECT_HNS_RS_PACKAGES = frozenset(
    {
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
            ("dependencies", "hns-p2p-wire"),
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
                continue

            root_location = ("workspace", "dependencies", dependency)
            if relative_path == ROOT_MANIFEST and location == root_location:
                if specification.get("git") != HNS_RS_GIT_URL:
                    raise CargoSourcePolicyError(
                        f"{relative_path}:{rendered_location}: expected "
                        f"canonical Git URL {HNS_RS_GIT_URL!r}"
                    )
                if specification.get("rev") != HNS_RS_REVISION:
                    raise CargoSourcePolicyError(
                        f"{relative_path}:{rendered_location}: expected exact "
                        f"Git revision {HNS_RS_REVISION}"
                    )
                if specification.get("version") != HNS_RS_CRATES_IO_VERSION:
                    raise CargoSourcePolicyError(
                        f"{relative_path}:{rendered_location}: expected "
                        f"crates.io version {HNS_RS_CRATES_IO_VERSION!r}"
                    )
                if "branch" in specification or "tag" in specification:
                    raise CargoSourcePolicyError(
                        f"{relative_path}:{rendered_location}: branch and tag "
                        "selectors are not allowed"
                    )
                package_override = specification.get("package")
                if package_override not in (None, dependency):
                    raise CargoSourcePolicyError(
                        f"{relative_path}:{rendered_location}: dependency "
                        "renaming is not allowed"
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
    counts: dict[str, int] = {
        package: 0 for package in LOCKED_HNS_RS_PACKAGES
    }

    for package in document.get("package", []):
        source = package.get("source")
        if not isinstance(source, str) or not source.startswith("git+"):
            continue
        name = package.get("name", "<unknown>")
        if name not in LOCKED_HNS_RS_PACKAGES:
            raise CargoSourcePolicyError(
                f"{LOCKFILE}: locked Cargo Git package {name!r} is not allowed"
            )
        if source != HNS_RS_LOCK_SOURCE:
            raise CargoSourcePolicyError(
                f"{LOCKFILE}: {name} must lock to "
                f"{HNS_RS_LOCK_SOURCE!r}, found {source!r}"
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
        "Cargo source policy permits only the reviewed hns-rs closure at "
        f"{HNS_RS_REVISION} and repository-local path dependencies."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
