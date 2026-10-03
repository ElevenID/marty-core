from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

from ci_affected_packages import affected_packages, git_changed_paths


class AffectedPackagesTests(unittest.TestCase):
    def metadata(self, root: pathlib.Path) -> dict[str, object]:
        return {
            "workspace_members": ["crypto-id", "protocol-id", "app-id"],
            "packages": [
                {
                    "id": "crypto-id",
                    "name": "crypto",
                    "manifest_path": str(root / "crates" / "crypto" / "Cargo.toml"),
                    "dependencies": [],
                },
                {
                    "id": "protocol-id",
                    "name": "protocol",
                    "manifest_path": str(root / "crates" / "protocol" / "Cargo.toml"),
                    "dependencies": [{"name": "crypto"}],
                },
                {
                    "id": "app-id",
                    "name": "app",
                    "manifest_path": str(root / "app" / "Cargo.toml"),
                    "dependencies": [{"name": "protocol"}],
                },
            ],
        }

    def test_root_lockfile_invalidates_the_workspace(self) -> None:
        self.assertEqual((True, []), affected_packages(["Cargo.lock"], {}))

    def test_includes_reverse_workspace_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with mock.patch.object(pathlib.Path, "cwd", return_value=root):
                result = affected_packages(
                    ["crates/crypto/src/lib.rs"], self.metadata(root)
                )
        self.assertEqual((False, ["app", "crypto", "protocol"]), result)

    def test_unowned_inputs_require_the_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with mock.patch.object(pathlib.Path, "cwd", return_value=root):
                for path in (
                    "README.md", "scripts/build-native.sh", ".github/workflows/ci.yml",
                    "removed-package/src/lib.rs", "shared/fixtures/vector.json",
                ):
                    with self.subTest(path=path):
                        self.assertEqual(
                            (True, []), affected_packages([path], self.metadata(root))
                        )

    def test_package_inputs_include_fixtures_native_code_and_embedded_docs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with mock.patch.object(pathlib.Path, "cwd", return_value=root):
                for path in (
                    "crates/crypto/tests/fixtures/vector.json",
                    "crates/crypto/native/verify.cc",
                    "crates/crypto/contracts/behavior.md",
                    "crates/crypto/build.rs",
                    "crates/crypto/tests/fixtures/cert.der",
                ):
                    with self.subTest(path=path):
                        self.assertEqual(
                            (False, ["app", "crypto", "protocol"]),
                            affected_packages([path], self.metadata(root)),
                        )

    def test_nested_package_selects_its_owner_and_all_dependency_kinds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            metadata = self.metadata(root)
            metadata["packages"][1]["dependencies"][0].update(
                {"kind": "dev", "rename": "aliased_crypto"}
            )
            metadata["packages"][2]["dependencies"][0]["kind"] = "build"
            metadata["packages"].append({
                "id": "root-id", "name": "root-package",
                "manifest_path": str(root / "Cargo.toml"), "dependencies": [],
            })
            metadata["workspace_members"].append("root-id")
            with mock.patch.object(pathlib.Path, "cwd", return_value=root):
                self.assertEqual(
                    (False, ["app", "crypto", "protocol"]),
                    affected_packages(["crates/crypto/fixture.json"], metadata),
                )

    def test_empty_change_is_distinct_from_missing_package_metadata(self) -> None:
        self.assertEqual((False, []), affected_packages([], {}))
        self.assertEqual((True, []), affected_packages(["crate/src/lib.rs"], {}))

    def test_git_diff_preserves_deleted_and_both_sides_of_renamed_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)

            def git(*args: str) -> str:
                return subprocess.check_output(
                    ["git", "-c", "commit.gpgsign=false", "-c", "user.name=Selector Test",
                     "-c", "user.email=selector@example.invalid", *args],
                    cwd=root, text=True, encoding="utf-8", stderr=subprocess.PIPE,
                ).strip()

            git("init")
            for path in ("crates/crypto/deleted.json", "crates/crypto/renamed ü.json"):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("synthetic fixture\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-m", "base")
            base = git("rev-parse", "HEAD")
            (root / "crates/crypto/deleted.json").unlink()
            (root / "app").mkdir()
            (root / "crates/crypto/renamed ü.json").rename(root / "app/renamed ü.json")
            git("add", "-A")
            git("commit", "-m", "delete and move fixtures")
            real_run = subprocess.run

            def run_in_repo(*args, **kwargs):
                return real_run(*args, cwd=root, **kwargs)

            with mock.patch("ci_affected_packages.subprocess.run", side_effect=run_in_repo):
                changed = git_changed_paths(base, "HEAD")
            self.assertEqual(
                {"crates/crypto/deleted.json", "crates/crypto/renamed ü.json",
                 "app/renamed ü.json"}, set(changed),
            )
            with mock.patch.object(pathlib.Path, "cwd", return_value=root):
                self.assertEqual(
                    (False, ["app", "crypto", "protocol"]),
                    affected_packages(changed, self.metadata(root)),
                )


if __name__ == "__main__":
    unittest.main()
