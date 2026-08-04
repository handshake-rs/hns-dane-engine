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
    HNS_RS_CRATES_IO_VERSION,
    HNS_RS_GIT_URL,
    HNS_RS_LOCK_SOURCE,
    HNS_RS_REVISION,
    LOCKED_HNS_RS_PACKAGES,
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
            f'{package} = {{ version = "{HNS_RS_CRATES_IO_VERSION}", '
            f'git = "{HNS_RS_GIT_URL}", '
            f'rev = "{HNS_RS_REVISION}" }}'
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

        locked_packages = "\n".join(
            "[[package]]\n"
            f'name = "{package}"\n'
            f'version = "{HNS_RS_CRATES_IO_VERSION}"\n'
            f'source = "{HNS_RS_LOCK_SOURCE}"\n'
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
        self.assertEqual(len(DIRECT_HNS_RS_PACKAGES), 9)
        self.assertEqual(
            LOCKED_HNS_RS_PACKAGES - DIRECT_HNS_RS_PACKAGES,
            {"hns-mining", "hns-transaction"},
        )

    def test_accepts_exact_standalone_source_boundary(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            self.verify_fixture(root, manifests)

    def test_rejects_unpinned_manifest_dependency(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            manifest = root / "Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    f', rev = "{HNS_RS_REVISION}"', "", 1
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "expected exact Git revision"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_missing_crates_io_version(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            manifest = root / "Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    f'version = "{HNS_RS_CRATES_IO_VERSION}", ', "", 1
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "expected crates.io version"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_branch_selector(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            manifest = root / "Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    f'rev = "{HNS_RS_REVISION}"',
                    f'rev = "{HNS_RS_REVISION}", branch = "main"',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "branch and tag selectors"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_noncanonical_manifest_url(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            manifest = root / "Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    HNS_RS_GIT_URL,
                    "https://example.invalid/hns-rs.git",
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "expected canonical Git URL"
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
                CargoSourcePolicyError, "Cargo Git dependency"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_direct_consumer_git_declaration(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            relative_path = Path(
                "crates/hns-light-chain/Cargo.toml"
            )
            manifest = root / relative_path
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    "hns-covenants.workspace = true",
                    f'hns-covenants = {{ git = "{HNS_RS_GIT_URL}", '
                    f'rev = "{HNS_RS_REVISION}" }}',
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "must inherit"
            ):
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

    def test_rejects_wrong_locked_revision(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            lockfile = root / "Cargo.lock"
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8").replace(
                    HNS_RS_REVISION, "0" * 40, 1
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "must lock to"
            ):
                self.verify_fixture(root, manifests)

    def test_rejects_missing_transitive_package(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            lockfile = root / "Cargo.lock"
            marker = (
                "[[package]]\n"
                'name = "hns-mining"\n'
                f'version = "{HNS_RS_CRATES_IO_VERSION}"\n'
                f'source = "{HNS_RS_LOCK_SOURCE}"\n'
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

    def test_rejects_unreviewed_git_package(self) -> None:
        temporary, root, manifests = self.create_fixture()
        with temporary:
            lockfile = root / "Cargo.lock"
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8")
                + "\n[[package]]\n"
                + 'name = "hns-unreviewed"\n'
                + f'version = "{HNS_RS_CRATES_IO_VERSION}"\n'
                + f'source = "{HNS_RS_LOCK_SOURCE}"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "is not allowed"
            ):
                self.verify_fixture(root, manifests)


if __name__ == "__main__":
    unittest.main()
