#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "verify_release", ROOT / "scripts/verify-release.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load scripts/verify-release.py")
verify_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_release)


class ReleaseValidatorMutationTests(unittest.TestCase):
    def test_targeted_and_successor_versions_override_workspace_versions(self) -> None:
        versions = verify_release.expected_workspace_versions(
            {
                "hns-browser-chain",
                "hns-browser-gateway",
                "hns-dane-engine",
                "hns-gateway",
                "hns-namespace-resolution",
                "hns-p2p-transport",
            },
            "0.2.2",
        )

        self.assertEqual(versions["hns-browser-chain"], "0.2.6")
        self.assertEqual(versions["hns-browser-gateway"], "0.2.3")
        self.assertEqual(versions["hns-namespace-resolution"], "0.2.3")
        self.assertEqual(versions["hns-dane-engine"], "0.3.0")
        self.assertEqual(versions["hns-gateway"], "0.3.0")
        self.assertEqual(versions["hns-p2p-transport"], "0.3.1")

    def create_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "engine"
        (root / "scripts").mkdir(parents=True)
        (root / "release").mkdir()
        (root / "scripts/publish.sh").write_bytes(
            (ROOT / "scripts/publish.sh").read_bytes()
        )
        (root / "release/public-crates.txt").write_bytes(
            (ROOT / "release/public-crates.txt").read_bytes()
        )
        (root / verify_release.PREPUBLISHED_ENGINE_MANIFEST).write_bytes(
            (ROOT / verify_release.PREPUBLISHED_ENGINE_MANIFEST).read_bytes()
        )
        (root / verify_release.PREPUBLISHED_ENGINE_CHECKSUM_MANIFEST).write_bytes(
            (ROOT / verify_release.PREPUBLISHED_ENGINE_CHECKSUM_MANIFEST).read_bytes()
        )
        (root / verify_release.PREPUBLISHED_ADAPTER_MANIFEST).write_bytes(
            (ROOT / verify_release.PREPUBLISHED_ADAPTER_MANIFEST).read_bytes()
        )
        (root / verify_release.PREPUBLISHED_ADAPTER_CHECKSUM_MANIFEST).write_bytes(
            (ROOT / verify_release.PREPUBLISHED_ADAPTER_CHECKSUM_MANIFEST).read_bytes()
        )
        return temporary, root

    def assert_predicate_mutation_rejected(
        self, original: str, description: str
    ) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            script_path = root / "scripts/publish.sh"
            script = script_path.read_text(encoding="utf-8")
            self.assertEqual(script.count(original), 1)
            script_path.write_text(
                script.replace(original, "        if false", 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SystemExit, description):
                verify_release.verify_publish_script_safety(root)

    def test_accepts_reviewed_protocol_execute_guards(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            verify_release.verify_publish_script_safety(root)

    def test_rejects_bypassed_api_checksum_predicate(self) -> None:
        self.assert_predicate_mutation_rejected(
            '        if [ "$protocol_api_checksum" != "$protocol_expected_checksum" ]',
            "API checksum predicate",
        )

    def test_rejects_bypassed_non_yanked_predicate(self) -> None:
        self.assert_predicate_mutation_rejected(
            '        if [ "$protocol_api_yanked" != "false" ]',
            "non-yanked predicate",
        )

    def test_rejects_bypassed_download_checksum_predicate(self) -> None:
        self.assert_predicate_mutation_rejected(
            '        if [ "$protocol_download_checksum" != "$protocol_expected_checksum" ]',
            "download checksum predicate",
        )

    def test_rejects_bypassed_vcs_sha_predicate(self) -> None:
        self.assert_predicate_mutation_rejected(
            '        if [ "$protocol_vcs_sha" != "$protocol_revision" ]',
            "VCS SHA predicate",
        )

    def test_rejects_bypassed_clean_vcs_predicate(self) -> None:
        self.assert_predicate_mutation_rejected(
            '        if [ "$protocol_vcs_dirty" = "true" ]',
            "clean-VCS predicate",
        )

    def test_rejects_bypassed_vcs_path_predicate(self) -> None:
        self.assert_predicate_mutation_rejected(
            '        if [ "$protocol_vcs_path" != "crates/$package" ]',
            "VCS path predicate",
        )

    def test_rejects_bypassed_prepublished_archive_checksum_predicate(self) -> None:
        self.assert_predicate_mutation_rejected(
            '    if [ "$archive_checksum" != "$expected_checksum" ]',
            "prepublished-engine provenance guard",
        )

    def test_rejects_incomplete_prepublished_checksum_inventory(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            checksum_path = root / verify_release.PREPUBLISHED_ENGINE_CHECKSUM_MANIFEST
            entries = checksum_path.read_text(encoding="utf-8").splitlines()
            checksum_path.write_text("\n".join(entries[:-1]) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "must contain exactly"):
                verify_release.verify_prepublished_engine_inventory(
                    root, verify_release.release_order(root)
                )

    def test_rejects_incomplete_adapter_checksum_inventory(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            checksum_path = root / verify_release.PREPUBLISHED_ADAPTER_CHECKSUM_MANIFEST
            entries = checksum_path.read_text(encoding="utf-8").splitlines()
            checksum_path.write_text("\n".join(entries[:-1]) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "must contain exactly"):
                verify_release.verify_prepublished_adapter_inventory(
                    root, verify_release.release_order(root)
                )

    def test_rejects_gateway_dry_run_with_mixed_shared_type_sources(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            script_path = root / "scripts/publish.sh"
            script = script_path.read_text(encoding="utf-8")
            gateway_prefix, gateway_remainder = script.split(
                "hns-browser-gateway)", 1
            )
            gateway_mapping, gateway_suffix = gateway_remainder.split(";;", 1)
            broken_gateway_mapping = gateway_mapping.replace(
                "patch.crates-io.hns-namespace-resolution.path",
                "patch.crates-io.hns-namespace-resolution-missing.path",
                1,
            )
            self.assertNotEqual(gateway_mapping, broken_gateway_mapping)
            script_path.write_text(
                gateway_prefix
                + "hns-browser-gateway)"
                + broken_gateway_mapping
                + ";;"
                + gateway_suffix,
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                SystemExit, "hns-browser-gateway dry-run must patch"
            ):
                verify_release.verify_publish_script_safety(root)


if __name__ == "__main__":
    unittest.main()
