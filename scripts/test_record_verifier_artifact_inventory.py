from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from record_verifier_artifact_inventory import OUTPUT_NAME, build_inventory, main

TAG = "v0.2.0"
COMMIT = "a" * 40
WHEELS = (
    "manylinux_2_17_x86_64",
    "manylinux_2_28_aarch64",
    "macosx_11_0_x86_64",
    "macosx_11_0_arm64",
    "win_amd64",
)


class VerifierArtifactInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.assets = Path(self.temporary.name)
        for platform in WHEELS:
            (
                self.assets / f"marty_verification_py-0.2.0-cp311-cp311-{platform}.whl"
            ).write_bytes(platform.encode("ascii"))
        (self.assets / "marty_verification_py-0.2.0.tar.gz").write_bytes(b"sdist")

    def test_inventory_is_deterministic_and_digest_bound(self) -> None:
        first = build_inventory(self.assets, TAG, COMMIT)
        self.assertEqual(first, build_inventory(self.assets, TAG, COMMIT))
        self.assertEqual(first["qualification"], "unqualified-artifact-inventory")
        self.assertEqual(len(first["artifacts"]), 6)
        records = first["artifacts"]
        self.assertTrue(all(len(record["sha256"]) == 64 for record in records))
        self.assertEqual(
            {record["platform"] for record in records if record["kind"] == "wheel"},
            {
                "linux-x86_64",
                "linux-aarch64",
                "macos-x86_64",
                "macos-arm64",
                "windows-x86_64",
            },
        )

    def test_missing_wheel_or_sdist_fails(self) -> None:
        next(self.assets.glob("*.whl")).unlink()
        with self.assertRaisesRegex(ValueError, "five verifier wheels"):
            build_inventory(self.assets, TAG, COMMIT)

    def test_wrong_version_fails(self) -> None:
        wheel = next(self.assets.glob("*.whl"))
        wheel.rename(wheel.with_name(wheel.name.replace("0.2.0", "0.2.1")))
        with self.assertRaisesRegex(ValueError, "version"):
            build_inventory(self.assets, TAG, COMMIT)

    def test_python_312_only_and_pure_python_wheels_fail(self) -> None:
        for replacement in ("cp312-cp312", "py3-none"):
            with self.subTest(replacement=replacement):
                wheel = next(self.assets.glob("*win_amd64.whl"))
                invalid = wheel.with_name(
                    wheel.name.replace("cp311-cp311", replacement)
                )
                wheel.rename(invalid)
                with self.assertRaisesRegex(ValueError, "Python ABI"):
                    build_inventory(self.assets, TAG, COMMIT)
                invalid.rename(wheel)

    def test_duplicate_platform_fails_even_with_five_wheels(self) -> None:
        wheel = next(self.assets.glob("*win_amd64.whl"))
        wheel.rename(
            wheel.with_name(wheel.name.replace("win_amd64", "manylinux_2_28_x86_64"))
        )
        with self.assertRaisesRegex(ValueError, "platform matrix"):
            build_inventory(self.assets, TAG, COMMIT)

    def test_empty_artifact_fails(self) -> None:
        next(self.assets.glob("*.whl")).write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "empty"):
            build_inventory(self.assets, TAG, COMMIT)

    def test_bad_tag_and_commit_fail(self) -> None:
        with self.assertRaisesRegex(ValueError, "tag"):
            build_inventory(self.assets, "nightly", COMMIT)
        with self.assertRaisesRegex(ValueError, "commit"):
            build_inventory(self.assets, TAG, "short")

    def test_release_inventories_before_signing(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "release.yml"
        ).read_text(encoding="utf-8")
        flattened = workflow.index("Release artifact tree still contains nested files")
        inventoried = workflow.index(
            "python scripts/record_verifier_artifact_inventory.py"
        )
        signed = workflow.index("cosign sign-blob --yes")
        self.assertLess(flattened, inventoried)
        self.assertLess(inventoried, signed)

    def test_release_import_checks_native_macos_x86_wheel(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "release.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "matrix.os == 'macos-latest' && matrix.target == 'x86_64' && 'macos-15-intel'",
            workflow,
        )
        self.assertIn("runner.arch == 'X64' && matrix.target == 'x86_64'", workflow)

    def test_cli_writes_inventory_once(self) -> None:
        arguments = [
            "record_verifier_artifact_inventory.py",
            "--assets",
            str(self.assets),
            "--tag",
            TAG,
            "--commit",
            COMMIT,
        ]
        with patch("sys.argv", arguments):
            self.assertEqual(main(), 0)
            inventory = json.loads(
                (self.assets / OUTPUT_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual(inventory["commit"], COMMIT)
            with (
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                main()


if __name__ == "__main__":
    unittest.main()
