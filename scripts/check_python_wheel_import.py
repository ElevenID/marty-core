#!/usr/bin/env python3
"""Import a built Marty wheel's native extension and reject Python-only shells."""

from __future__ import annotations

import argparse
import importlib
import importlib.machinery
from importlib import metadata
from pathlib import Path


EXTENSION_MODULES = {
    "marty-bindings": "marty_rs._marty_rs",
    "marty-biometrics": "marty_biometrics._marty_biometrics",
    "marty-iso18013": "marty_iso18013.marty_iso18013",
    "marty-verification": "marty_verification_py._marty_verification",
}

DISTRIBUTIONS = {
    "marty-bindings": "marty-rs",
    "marty-biometrics": "marty-biometrics",
    "marty-iso18013": "marty-iso18013",
    "marty-verification": "marty-verification-py",
}

AGGREGATE_REQUIRED_APIS = frozenset(
    {
        "oid4vci_prepare_sd_jwt",
        "oid4vci_assemble_sd_jwt",
        "oid4vci_prepare_jwt_vc",
        "oid4vci_assemble_jwt_vc",
        "oid4vci_prepare_mdoc",
        "oid4vci_prepare_mdoc_batch",
        "oid4vci_assemble_mdoc",
        "oid4vci_prepare_open_badge_v3_jwt_vc",
    }
)
AGGREGATE_FORBIDDEN_APIS = frozenset(
    {
        "generate_p256_key",
        "generate_p256_jwk",
        "generate_p256_did_jwk",
        "generate_p384_key",
        "generate_ed25519_key",
        "generate_did_key",
        "sign_p256",
        "sign_p384",
        "sign_ed25519",
        "create_verifiable_credential",
        "oid4vci_sign_credential",
        "oid4vci_create_proof_jwt",
        "oid4vci_prepare_credential",
        "oid4vci_assemble_credential",
        "vds_nc_sign_profile",
        "didcomm_encrypt_authcrypt",
        "didcomm_decrypt",
        "didcomm_decrypt_authcrypt",
        "HaipResponseDecryptionSession",
        "haip_generate_response_encryption_key",
        "haip_decrypt_response",
        "aes_256_cbc_encrypt",
        "aes_256_cbc_decrypt",
        "hmac_sha256",
    }
)


def import_native_extension(package: str) -> Path:
    """Import the package's native module and return its extension path."""
    try:
        module_name = EXTENSION_MODULES[package]
    except KeyError as error:
        choices = ", ".join(sorted(EXTENSION_MODULES))
        raise ValueError(
            f"unknown wheel package {package!r}; expected one of {choices}"
        ) from error

    module = importlib.import_module(module_name)
    location = getattr(module, "__file__", None)
    if not isinstance(location, str) or not location:
        raise RuntimeError(f"{module_name} did not expose an extension module path")
    if not any(
        location.endswith(suffix) for suffix in importlib.machinery.EXTENSION_SUFFIXES
    ):
        raise RuntimeError(f"{module_name} resolved to non-native module {location}")
    return Path(location).resolve()


def _require_attributes(module: object, names: frozenset[str], label: str) -> None:
    missing = sorted(name for name in names if not hasattr(module, name))
    if missing:
        raise RuntimeError(f"{label} is missing public APIs: {', '.join(missing)}")


def _require_distribution_version(module: object, package: str) -> None:
    distribution = DISTRIBUTIONS[package]
    expected = metadata.version(distribution)
    actual = getattr(module, "__version__", None)
    if actual != expected:
        raise RuntimeError(
            f"{distribution} public version {actual!r} does not match wheel metadata "
            f"{expected!r}"
        )


def verify_public_api(package: str) -> None:
    """Exercise the installed wheel through its supported consumer boundary."""
    if package == "marty-bindings":
        public = importlib.import_module("marty_rs")
        _require_attributes(public, AGGREGATE_REQUIRED_APIS, "marty_rs")
        present = sorted(
            name for name in AGGREGATE_FORBIDDEN_APIS if hasattr(public, name)
        )
        if present:
            raise RuntimeError(
                "marty_rs KMS-only wheel exposes forbidden private-key APIs: "
                + ", ".join(present)
            )
        return

    if package == "marty-biometrics":
        public = importlib.import_module("marty_biometrics")
        _require_distribution_version(public, package)
        native = public.get_rust_bindings()
        native_path = Path(native.__file__).resolve()
        if native_path != import_native_extension(package):
            raise RuntimeError(
                "marty_biometrics public loader resolved a different extension"
            )
        adapter = importlib.import_module("marty_biometrics.adapters.rust")
        verifier = adapter.RustFaceVerifier.mock()
        if verifier is None:
            raise RuntimeError("RustFaceVerifier.mock() did not return a verifier")
        return

    if package == "marty-verification":
        public = importlib.import_module("marty_verification_py")
        _require_distribution_version(public, package)
        _require_attributes(
            public,
            frozenset({"open_badge_ob2_verify", "open_badge_ob3_verify"}),
            "marty_verification_py",
        )
        forbidden = sorted(
            name
            for name in ("open_badge_ob2_issue", "open_badge_ob3_issue")
            if hasattr(public, name)
        )
        if forbidden:
            raise RuntimeError(
                "marty_verification_py KMS-only wheel exposes local issuance APIs: "
                + ", ".join(forbidden)
            )
        return

    if package == "marty-iso18013":
        public = importlib.import_module("marty_iso18013")
        _require_distribution_version(public, package)
        _require_attributes(
            public,
            frozenset({"MdlRequest", "MdlResponse", "Session"}),
            "marty_iso18013",
        )
        return

    raise ValueError(f"unknown wheel package {package!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", choices=sorted(EXTENSION_MODULES))
    args = parser.parse_args()
    location = import_native_extension(args.package)
    verify_public_api(args.package)
    print(f"wheel-import: {args.package} loaded {location} and public API")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
