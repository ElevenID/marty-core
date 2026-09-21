from __future__ import annotations

import importlib.machinery
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import check_python_wheel_import


class PythonWheelImportTests(unittest.TestCase):
    def test_imports_each_expected_native_extension(self) -> None:
        suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
        for package, module_name in check_python_wheel_import.EXTENSION_MODULES.items():
            with (
                self.subTest(package=package),
                patch.object(
                    check_python_wheel_import.importlib,
                    "import_module",
                    return_value=SimpleNamespace(
                        __file__=f"/wheel/{module_name}{suffix}"
                    ),
                ) as import_module,
            ):
                path = check_python_wheel_import.import_native_extension(package)
                import_module.assert_called_once_with(module_name)
                self.assertEqual(path, Path(f"/wheel/{module_name}{suffix}").resolve())

    def test_rejects_python_only_module(self) -> None:
        with patch.object(
            check_python_wheel_import.importlib,
            "import_module",
            return_value=SimpleNamespace(__file__="/wheel/marty_rs/_marty_rs.py"),
        ):
            with self.assertRaisesRegex(RuntimeError, "non-native module"):
                check_python_wheel_import.import_native_extension("marty-bindings")

    def test_rejects_unknown_package(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown wheel package"):
            check_python_wheel_import.import_native_extension("unknown")


if __name__ == "__main__":
    unittest.main()
