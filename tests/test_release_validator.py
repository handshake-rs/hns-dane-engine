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


if __name__ == "__main__":
    unittest.main()
