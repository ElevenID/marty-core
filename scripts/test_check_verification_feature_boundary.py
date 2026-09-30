import unittest
from unittest.mock import patch

from check_verification_feature_boundary import ROOT, check_repository, load_toml


class VerificationFeatureBoundaryTests(unittest.TestCase):
    def test_repository_feature_boundary(self) -> None:
        check_repository()

    def test_inherited_crypto_dependencies_remain_default_free(self) -> None:
        for dependency in ("ecdsa-core", "k256", "ssi-jwk"):
            with self.subTest(dependency=dependency):
                def mutated_manifest(path):
                    manifest = load_toml(path)
                    if path == ROOT / "Cargo.toml":
                        manifest["workspace"]["dependencies"][dependency][
                            "default-features"
                        ] = True
                    return manifest

                with patch(
                    "check_verification_feature_boundary.load_toml",
                    side_effect=mutated_manifest,
                ):
                    with self.assertRaises(ValueError):
                        check_repository()

    def test_ecdsa_primitive_cannot_restore_signing_or_be_required(self) -> None:
        for field, value in (("features", ["signing"]), ("optional", False)):
            with self.subTest(field=field):
                def mutated_manifest(path):
                    manifest = load_toml(path)
                    if path == ROOT / "marty-crypto" / "Cargo.toml":
                        manifest["dependencies"]["ecdsa-core"][field] = value
                    return manifest

                with patch(
                    "check_verification_feature_boundary.load_toml",
                    side_effect=mutated_manifest,
                ):
                    with self.assertRaises(ValueError):
                        check_repository()

    def test_oid4vci_ecdsa_primitive_cannot_restore_signing(self) -> None:
        def mutated_manifest(path):
            manifest = load_toml(path)
            if path == ROOT / "marty-oid4vci" / "Cargo.toml":
                manifest["dependencies"]["ecdsa-core"]["features"].append("signing")
            return manifest

        with patch(
            "check_verification_feature_boundary.load_toml",
            side_effect=mutated_manifest,
        ):
            with self.assertRaises(ValueError):
                check_repository()


if __name__ == "__main__":
    unittest.main()
