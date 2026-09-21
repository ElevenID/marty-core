from __future__ import annotations

import importlib.machinery
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import check_python_wheel_import


class PythonWheelImportTests(unittest.TestCase):
    def test_extension_names_match_packaged_maturin_layouts(self) -> None:
        self.assertEqual(
            check_python_wheel_import.EXTENSION_MODULES,
            {
                "marty-bindings": "marty_rs._marty_rs",
                "marty-biometrics": "marty_biometrics._marty_biometrics",
                "marty-iso18013": "marty_iso18013.marty_iso18013",
                "marty-verification": "marty_verification_py._marty_verification",
            },
        )

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

    def test_aggregate_public_api_requires_remote_signing_and_rejects_private_keys(
        self,
    ) -> None:
        public = SimpleNamespace(
            **{
                name: object()
                for name in check_python_wheel_import.AGGREGATE_REQUIRED_APIS
            }
        )
        with patch.object(
            check_python_wheel_import.importlib,
            "import_module",
            return_value=public,
        ):
            check_python_wheel_import.verify_public_api("marty-bindings")

        public.didcomm_decrypt = object()
        with patch.object(
            check_python_wheel_import.importlib,
            "import_module",
            return_value=public,
        ):
            with self.assertRaisesRegex(RuntimeError, "forbidden private-key APIs"):
                check_python_wheel_import.verify_public_api("marty-bindings")

    def test_biometrics_public_loader_and_mock_adapter_use_packaged_extension(
        self,
    ) -> None:
        suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
        native = SimpleNamespace(__file__=f"/wheel/marty_biometrics/native{suffix}")
        public = SimpleNamespace(__version__="0.2.0", get_rust_bindings=lambda: native)
        verifier = object()
        adapter = SimpleNamespace(
            RustFaceVerifier=SimpleNamespace(mock=lambda: verifier)
        )

        def import_module(name: str):
            return {
                "marty_biometrics": public,
                "marty_biometrics._marty_biometrics": native,
                "marty_biometrics.adapters.rust": adapter,
            }[name]

        with (
            patch.object(
                check_python_wheel_import.importlib,
                "import_module",
                side_effect=import_module,
            ),
            patch.object(
                check_python_wheel_import.metadata,
                "version",
                return_value="0.2.0",
            ),
        ):
            check_python_wheel_import.verify_public_api("marty-biometrics")

    def test_verification_public_api_is_versioned_and_kms_only(self) -> None:
        public = SimpleNamespace(
            __version__="0.2.0",
            open_badge_ob2_verify=object(),
            open_badge_ob3_verify=object(),
        )
        with (
            patch.object(
                check_python_wheel_import.importlib,
                "import_module",
                return_value=public,
            ),
            patch.object(
                check_python_wheel_import.metadata,
                "version",
                return_value="0.2.0",
            ),
        ):
            check_python_wheel_import.verify_public_api("marty-verification")

        public.open_badge_ob2_issue = object()
        with (
            patch.object(
                check_python_wheel_import.importlib,
                "import_module",
                return_value=public,
            ),
            patch.object(
                check_python_wheel_import.metadata,
                "version",
                return_value="0.2.0",
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "local issuance APIs"):
                check_python_wheel_import.verify_public_api("marty-verification")

    def test_iso_public_api_version_matches_distribution_metadata(self) -> None:
        public = SimpleNamespace(
            __version__="0.2.0",
            MdlRequest=object(),
            MdlResponse=object(),
            Session=object(),
        )
        with (
            patch.object(
                check_python_wheel_import.importlib,
                "import_module",
                return_value=public,
            ),
            patch.object(
                check_python_wheel_import.metadata,
                "version",
                return_value="0.2.0",
            ),
        ):
            check_python_wheel_import.verify_public_api("marty-iso18013")

        public.__version__ = "0.1.0"
        with (
            patch.object(
                check_python_wheel_import.importlib,
                "import_module",
                return_value=public,
            ),
            patch.object(
                check_python_wheel_import.metadata,
                "version",
                return_value="0.2.0",
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "does not match wheel metadata"):
                check_python_wheel_import.verify_public_api("marty-iso18013")


if __name__ == "__main__":
    unittest.main()
