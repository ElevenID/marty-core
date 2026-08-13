from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

from ci_affected_packages import affected_packages


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

    def test_ignores_non_rust_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with mock.patch.object(pathlib.Path, "cwd", return_value=root):
                result = affected_packages(["README.md"], self.metadata(root))
        self.assertEqual((False, []), result)


if __name__ == "__main__":
    unittest.main()
