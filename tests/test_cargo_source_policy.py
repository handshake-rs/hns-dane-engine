#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from verify_cargo_source_policy import (  # noqa: E402
    CargoSourcePolicyError,
    DIRECT_HNS_RS_PACKAGES,
    EXPECTED_CONSUMERS,
    HNS_RS_CHECKSUM_MANIFEST,
    HNS_RS_CRATES_IO_REQUIREMENT,
    HNS_RS_CRATES_IO_VERSION,
    HNS_RS_PUBLIC_PACKAGES,
    HNS_RS_REGISTRY_SOURCE,
    HNS_RS_REPOSITORY,
    HNS_RS_REVISION,
    LOCKED_HNS_RS_PACKAGES,
    load_hns_rs_checksums,
    verify_repository,
)


class CargoSourcePolicyTests(unittest.TestCase):
    def create_fixture(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, list[Path]]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "engine"
        root.mkdir()

        dependencies = "\n".join(
            f'{package} = {{ version = "{HNS_RS_CRATES_IO_REQUIREMENT}" }}'
            for package in sorted(DIRECT_HNS_RS_PACKAGES)
        )
        (root / "Cargo.toml").write_text(
            f"[workspace]\nmembers = []\n\n"
            f"[workspace.dependencies]\n{dependencies}\n",
            encoding="utf-8",
        )

        manifests = [Path("Cargo.toml")]
        for relative_path, declarations in EXPECTED_CONSUMERS.items():
            manifest = root / relative_path
            manifest.parent.mkdir(parents=True, exist_ok=True)
            sections: dict[str, list[str]] = {}
            for section, package in sorted(declarations):
                sections.setdefault(section, []).append(
                    f"{package}.workspace = true"
                )
            text = "\n\n".join(
                f"[{section}]\n" + "\n".join(lines)
                for section, lines in sorted(sections.items())
            )
            manifest.write_text(f"{text}\n", encoding="utf-8")
            manifests.append(relative_path)

        checksum_manifest = root / HNS_RS_CHECKSUM_MANIFEST
        checksum_manifest.parent.mkdir(parents=True, exist_ok=True)
        checksum_manifest.write_bytes((ROOT / HNS_RS_CHECKSUM_MANIFEST).read_bytes())
        checksums = load_hns_rs_checksums(root)
        locked_packages = "\n".join(
            "[[package]]\n"
            f'name = "{package}"\n'
            f'version = "{HNS_RS_CRATES_IO_VERSION}"\n'
            f'source = "{HNS_RS_REGISTRY_SOURCE}"\n'
            f'checksum = "{checksums[package]}"\n'
            for package in sorted(LOCKED_HNS_RS_PACKAGES)
        )
        (root / "Cargo.lock").write_text(
            f"version = 4\n\n{locked_packages}",
            encoding="utf-8",
        )
        return temporary, root, manifests

    def verify_fixture(self, root: Path, manifests: list[Path]) -> None:
        verify_repository(root, manifests)

    def test_reviewed_package_sets_are_explicit(self) -> None:
        self.assertEqual(len(HNS_RS_PUBLIC_PACKAGES), 19)
        self.assertEqual(len(DIRECT_HNS_RS_PACKAGES), 13)
        self.assertEqual(len(LOCKED_HNS_RS_PACKAGES), 16)
        self.assertEqual(
            LOCKED_HNS_RS_PACKAGES - DIRECT_HNS_RS_PACKAGES,
            {
                "hns-chat-protocol",
                "hns-mining",
                "hns-transaction",
            },
        )
        self.assertEqual(
            set(HNS_RS_PUBLIC_PACKAGES) - LOCKED_HNS_RS_PACKAGES,
            {
                "hns-marketplace-protocol",
                "hns-script",
                "hns-swap",
            },
        )
        self.assertEqual(len(load_hns_rs_checksums(ROOT)), 19)
        self.assertEqual(
            HNS_RS_REPOSITORY,
            "https://github.com/handshake-rs/hns-rs.git",
        )
        self.assertEqual(
            HNS_RS_REVISION,
            "d0cde9ded6f8f93f96f16daafc094849c6d484bf",
        )

    def test_accepts_exact_registry_source_boundary(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            self.verify_fixture(root, manifests)

    def test_rejects_compatible_but_not_exact_requirement(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            manifest = root / "Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    HNS_RS_CRATES_IO_REQUIREMENT,
                    HNS_RS_CRATES_IO_VERSION,
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "expected exact crates.io requirement"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_manifest_git_override(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            manifest = root / "Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    f'hns-covenants = {{ version = "{HNS_RS_CRATES_IO_REQUIREMENT}" }}',
                    f'hns-covenants = {{ version = "{HNS_RS_CRATES_IO_REQUIREMENT}", '
                    f'git = "{HNS_RS_REPOSITORY}" }}',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "with no source override"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_branch_selector(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            manifest = root / "Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    f'hns-covenants = {{ version = "{HNS_RS_CRATES_IO_REQUIREMENT}" }}',
                    f'hns-covenants = {{ version = "{HNS_RS_CRATES_IO_REQUIREMENT}", '
                    'branch = "main" }',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "with no source override"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_dependency_alias(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            manifest = root / "Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    "hns-covenants = {",
                    'covenant-alias = { package = "hns-covenants",',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "renaming is not allowed"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_direct_consumer_source_declaration(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            relative_path = Path("crates/hns-light-chain/Cargo.toml")
            manifest = root / relative_path
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    "hns-covenants.workspace = true",
                    f'hns-covenants = {{ version = "{HNS_RS_CRATES_IO_REQUIREMENT}" }}',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CargoSourcePolicyError, "must inherit"):
                self.verify_fixture(root, manifests)

    def test_rejects_unreviewed_consumer(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            extra = Path("crates/unreviewed/Cargo.toml")
            manifest = root / extra
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                "[dependencies]\nhns-primitives.workspace = true\n",
                encoding="utf-8",
            )
            manifests.append(extra)
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "unexpected hns-rs consumers"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_path_dependency_outside_repository(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            extra = Path("crates/local/Cargo.toml")
            manifest = root / extra
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                '[dependencies]\nexternal = { path = "../../../escape" }\n',
                encoding="utf-8",
            )
            manifests.append(extra)
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "escapes the engine repository"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_wrong_locked_version(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            lockfile = root / "Cargo.lock"
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8").replace(
                    f'version = "{HNS_RS_CRATES_IO_VERSION}"',
                    'version = "9.9.9"',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CargoSourcePolicyError, "must lock to version"):
                self.verify_fixture(root, manifests)

    def test_rejects_wrong_locked_registry(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            lockfile = root / "Cargo.lock"
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8").replace(
                    HNS_RS_REGISTRY_SOURCE,
                    "registry+https://example.invalid/index",
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CargoSourcePolicyError, "must use"):
                self.verify_fixture(root, manifests)

    def test_rejects_wrong_locked_checksum(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            lockfile = root / "Cargo.lock"
            checksum = next(iter(load_hns_rs_checksums(root).values()))
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8").replace(
                    checksum,
                    "0" * 64,
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CargoSourcePolicyError, "checksum differs"):
                self.verify_fixture(root, manifests)

    def test_rejects_missing_transitive_package(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            lockfile = root / "Cargo.lock"
            checksums = load_hns_rs_checksums(root)
            marker = (
                "[[package]]\n"
                'name = "hns-mining"\n'
                f'version = "{HNS_RS_CRATES_IO_VERSION}"\n'
                f'source = "{HNS_RS_REGISTRY_SOURCE}"\n'
                f'checksum = "{checksums["hns-mining"]}"\n'
            )
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8").replace(marker, ""),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError,
                "expected exactly one locked hns-mining",
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_unexpected_protocol_package(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            lockfile = root / "Cargo.lock"
            checksums = load_hns_rs_checksums(root)
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8")
                + "\n[[package]]\n"
                + 'name = "hns-script"\n'
                + f'version = "{HNS_RS_CRATES_IO_VERSION}"\n'
                + f'source = "{HNS_RS_REGISTRY_SOURCE}"\n'
                + f'checksum = "{checksums["hns-script"]}"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "unexpected hns-rs package"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_unreviewed_git_package(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            lockfile = root / "Cargo.lock"
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8")
                + "\n[[package]]\n"
                + 'name = "unreviewed"\n'
                + 'version = "1.0.0"\n'
                + 'source = "git+https://example.invalid/repository#'
                + "0" * 40
                + '"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "locked Cargo Git package"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_incomplete_archive_hash_manifest(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            checksum_manifest = root / HNS_RS_CHECKSUM_MANIFEST
            lines = checksum_manifest.read_text(encoding="utf-8").splitlines()
            checksum_manifest.write_text(
                "\n".join(lines[:-1]) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "expected 19 archive hashes"
            ):
                self.verify_fixture(root, manifests)


if __name__ == "__main__":
    unittest.main()
