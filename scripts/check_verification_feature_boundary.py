#!/usr/bin/env python3
"""Validate the verifier/authority Cargo feature boundary."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REMOVED_CRYPTO_FEATURES = {
    "default",
    "full",
    "bbs",
    "cert-builder",
    "crl-builder",
    "ecdsa",
    "ecdsa-local-signing",
    "eddsa",
    "eddsa-local-signing",
    "keygen",
    "pkcs12",
    "private-key-codec",
    "rsa",
    "rsa-local-signing",
    "serialization",
    "sod-builder",
}


def load_toml(path: Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def check_repository(root: Path = ROOT) -> None:
    workspace = load_toml(root / "Cargo.toml")
    crypto = load_toml(root / "marty-crypto" / "Cargo.toml")
    verification = load_toml(root / "marty-verification" / "Cargo.toml")
    oid4vci = load_toml(root / "marty-oid4vci" / "Cargo.toml")
    iso18013 = load_toml(root / "marty-iso18013" / "Cargo.toml")
    didcomm = load_toml(root / "marty-didcomm" / "Cargo.toml")
    bindings = load_toml(root / "marty-bindings" / "Cargo.toml")
    test_support = load_toml(root / "marty-crypto-test-support" / "Cargo.toml")
    verification_python = load_toml(root / "marty-verification" / "pyproject.toml")

    workspace_dependencies = workspace["workspace"]["dependencies"]
    for curve in ("p256", "p384", "p521"):
        dependency = workspace_dependencies[curve]
        require(
            dependency.get("default-features") is False
            and not dependency.get("features", []),
            f"workspace {curve} must be capability-neutral; members select curve features",
        )
    require(
        workspace_dependencies["x509-cert"].get("default-features") is False
        and "builder" not in workspace_dependencies["x509-cert"].get("features", []),
        "workspace X.509 dependencies must not globally enable certificate builders",
    )
    require(
        "encryption" not in workspace_dependencies["pkcs8"].get("features", []),
        "workspace PKCS#8 dependencies must not globally enable private-key encryption",
    )
    require(
        "pkcs5" not in workspace_dependencies
        and "pkcs5" not in crypto["dependencies"],
        "unused PKCS#5/PBES2 must not compile in public-key builds",
    )
    require(
        "builder" not in workspace_dependencies["cms"].get("features", []),
        "workspace CMS dependencies must not globally enable signed-data builders",
    )
    require(
        workspace_dependencies["ed25519-dalek"].get("default-features") is False
        and not (
            {"pem", "pkcs8", "rand_core"}
            & set(workspace_dependencies["ed25519-dalek"].get("features", []))
        ),
        "workspace Ed25519 dependencies must not globally enable key codecs or generation",
    )

    crypto_features = crypto["features"]
    require(
        crypto_features["default"] == [],
        "marty-crypto defaults must not select local private-key capabilities",
    )
    require(
        set(crypto_features["crl"]) == {"x509", "dep:pem-rfc7468"},
        "CRL parsing must not enable builders",
    )
    require(
        set(crypto_features["ocsp"]) == {"x509", "dep:x509-ocsp"},
        "OCSP verification must not enable builders",
    )
    require(crypto_features["kms-only"] == [], "the KMS marker must enable no primitives")
    require(
        "ecdsa-core/verifying" in crypto_features["ecdsa-verification"]
        and "ecdsa-core/signing" not in crypto_features["ecdsa-verification"]
        and not (
            {"p256/ecdsa", "p384/ecdsa", "p521/ecdsa"}
            & set(crypto_features["ecdsa-verification"])
        ),
        "ECDSA verification must use verification-only primitives",
    )
    require(
        not (REMOVED_CRYPTO_FEATURES - {"default"}) & set(crypto_features),
        "marty-crypto must not expose production-selectable private-key features",
    )
    require(
        workspace_dependencies["rsa"].get("default-features") is False
        and "pem" not in workspace_dependencies["rsa"].get("features", []),
        "workspace RSA verification must not enable private-key PEM support",
    )
    require(
        crypto["dependencies"]["ecdsa-core"].get("default-features") is False
        and crypto["dependencies"]["ecdsa-core"].get("optional") is True,
        "the direct ECDSA primitive dependency must be optional and default-free",
    )

    verification_features = verification["features"]
    require(
        set(verification_features["kms-only"])
        == {"marty-crypto/kms-only", "marty-oid4vci/kms-only"},
        "verification KMS enforcement must propagate to cryptographic dependencies",
    )
    require(
        not {"authority-issuance", "cert-builder", "local-key-operations"}
        & set(verification_features),
        "marty-verification must not expose local-key or authority-builder features",
    )
    require(
        "ephemeral-session-keys" not in verification_features["default"],
        "default verification must not create protocol session keys",
    )
    for curve in ("p256", "p384", "p521"):
        require(
            verification["dependencies"][curve].get("features") == ["ecdsa-core"],
            f"marty-verification {curve} must select signature types without signing",
        )
    require(
        {"marty-crypto/kdf", "p256/ecdh", "p384/ecdh"}
        <= set(verification_features["ephemeral-session-keys"]),
        "session KDF and curve ECDH must require the explicit ephemeral-session-keys capability",
    )
    verification_crypto = verification["dependencies"]["marty-crypto"]
    require(
        verification_crypto.get("default-features") is False,
        "marty-verification must disable marty-crypto defaults",
    )
    require(
        not (set(verification_crypto["features"]) & REMOVED_CRYPTO_FEATURES),
        "marty-verification normal dependencies must exclude authority-only crypto features",
    )
    require(
        "kdf" not in verification_crypto["features"],
        "passive marty-verification builds must not compile key derivation",
    )

    oid4vci_crypto = oid4vci["dependencies"]["marty-crypto"]
    require(
        oid4vci_crypto.get("default-features") is False
        and set(oid4vci_crypto["features"])
        == {"ecdsa-verification", "eddsa-verification"},
        "marty-oid4vci must not transitively restore marty-crypto defaults",
    )
    require(
        oid4vci["features"]["kms-only"] == ["marty-crypto/kms-only"],
        "marty-oid4vci must propagate KMS enforcement",
    )
    require(
        oid4vci["dependencies"]["p256"].get("features") == ["arithmetic"]
        and oid4vci["dependencies"]["p384"].get("features") == ["arithmetic"],
        "marty-oid4vci base roles must not directly enable signing or ECDH",
    )
    require(
        {"p256/ecdsa-core", "p384/ecdsa-core"}
        <= set(oid4vci["features"]["issuer"]),
        "remote-signature issuer assembly must select signature codecs without signing",
    )
    require(
        oid4vci["dependencies"]["k256"].get("default-features") is False
        and set(oid4vci["dependencies"]["k256"].get("features", []))
        == {"arithmetic", "ecdsa-core", "sha256"},
        "secp256k1 proof verification must omit combined signing support",
    )
    require(
        "ssi-crypto" not in oid4vci["dependencies"]
        and not oid4vci["dependencies"]["ssi-jwk"].get("features", []),
        "SSI signing and key-generation algorithms must be absent from production dependencies",
    )
    require(
        "local-key-operations" not in oid4vci["features"],
        "OID4VCI local issuer keys must not be a downstream-selectable capability",
    )
    require(
        oid4vci["dependencies"]["jsonwebtoken"].get("default-features") is False
        and not oid4vci["dependencies"]["jsonwebtoken"].get("features", []),
        "jsonwebtoken crypto providers must be role-selected rather than globally enabled",
    )
    require(
        "jsonwebtoken/rust_crypto" not in oid4vci["features"]["issuer"]
        and "jsonwebtoken/rust_crypto" in oid4vci["features"]["verifier"]
        and "holder-key-operations" not in oid4vci["features"]
        and "verifier" in oid4vci["features"]["wallet"],
        "JWT crypto must be absent from issuer planning and available to opaque-signer wallets only through verification",
    )

    bindings_crypto = bindings["dependencies"]["marty-crypto"]
    require(
        bindings_crypto.get("default-features") is False,
        "released bindings must disable marty-crypto defaults",
    )
    require(
        not (set(bindings_crypto["features"]) & REMOVED_CRYPTO_FEATURES),
        "released bindings must exclude authority-only crypto features",
    )
    require(
        "symmetric" not in bindings_crypto["features"]
        and "marty-crypto/symmetric"
        in bindings["features"]["ephemeral-session-keys"],
        "aggregate bindings must compile symmetric secret APIs only on explicit request",
    )
    require(
        bindings["dependencies"]["marty-verification"].get("default-features") is False,
        "released bindings must select verification capabilities explicitly",
    )
    require(
        set(bindings["features"]["kms-only"])
        == {
            "marty-crypto/kms-only",
            "marty-didcomm/kms-only",
            "marty-oid4vci/kms-only",
            "marty-verification/kms-only",
        },
        "released bindings must propagate KMS enforcement",
    )
    require(
        bindings["dependencies"]["marty-didcomm"].get("default-features") is False
        and not {
            "encrypted-envelope",
            "local-key-operations",
        }
        & set(bindings["dependencies"]["marty-didcomm"].get("features", []))
        and "didcomm-local-keys" not in bindings["features"],
        "released bindings must not expose caller-private-key DIDComm APIs",
    )
    require(
        didcomm["features"]["kms-only"] == []
        and didcomm["features"]["encrypted-envelope"]
        == ["dep:affinidi-messaging-didcomm"]
        and didcomm["features"]["local-key-operations"]
        == ["encrypted-envelope"]
        and didcomm["dependencies"]["affinidi-messaging-didcomm"].get("optional")
        is True
        and didcomm["dependencies"]["affinidi-messaging-didcomm"].get(
            "default-features"
        )
        is False
        and "local-key-operations" not in didcomm["features"]["default"]
        and "encrypted-envelope" not in didcomm["features"]["default"],
        "DIDComm software envelopes must be explicit and absent from the KMS marker",
    )
    require(
        bindings["features"]["didcomm-encrypted-envelope"]
        == ["marty-didcomm/encrypted-envelope"]
        and "didcomm-encrypted-envelope" not in bindings["features"]["default"],
        "bindings must keep DIDComm envelopes out of the default artifact",
    )
    require(
        "local-key-operations" not in bindings["features"],
        "released bindings must not offer a feature that restores private-key APIs",
    )
    require(
        didcomm["dependencies"]["p256"].get("features") == ["arithmetic"],
        "DIDComm public-key resolution must not directly enable signing or ECDH",
    )

    iso18013_crypto = iso18013["dependencies"]["marty-crypto"]
    require(
        iso18013_crypto.get("default-features") is False
        and iso18013_crypto.get("optional") is True
        and not iso18013_crypto.get("features", []),
        "passive ISO 18013 verification must not compile session cryptography",
    )
    require(
        set(iso18013["features"]["session-protocol"])
        >= {
            "verifier",
            "dep:marty-crypto",
            "marty-crypto/ecdh",
            "marty-crypto/kdf",
            "marty-crypto/symmetric",
        },
        "ISO 18013 session cryptography must require an explicit capability",
    )
    require(
        iso18013["features"]["default"] == ["session-protocol"],
        "the historical ISO 18013 API must remain available in default builds",
    )
    require(
        bindings["dependencies"]["marty-iso18013"].get("default-features") is False
        and bindings["dependencies"]["marty-iso18013"].get("features") == ["verifier"],
        "aggregate KMS bindings must use passive ISO 18013 verification only",
    )

    wheel_features = set(verification_python["tool"]["maturin"]["features"])
    require(
        not ({"authority-issuance", "cert-builder"} & wheel_features),
        "the released verification wheel must exclude authority and certificate builders",
    )
    require(
        verification_python["tool"]["maturin"].get("no-default-features") is True
        and "kms-only" in wheel_features,
        "the released verification wheel must use an explicit KMS-only feature set",
    )

    bindings_wheel = load_toml(root / "marty-bindings" / "pyproject.toml")
    bindings_wheel_config = bindings_wheel["tool"]["maturin"]
    require(
        bindings_wheel_config.get("no-default-features") is True
        and "kms-only" in bindings_wheel_config["features"],
        "the released aggregate wheel must use an explicit KMS-only feature set",
    )

    bindings_source = (root / "marty-bindings" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    require(
        'feature = "local-key-operations"' not in bindings_source
        and 'feature = "didcomm-local-keys"' not in bindings_source,
        "binding source must not contain production-selectable private-key API gates",
    )
    for raw_secret_api in (
        "aes_256_cbc_encrypt",
        "aes_256_cbc_decrypt",
        "hmac_sha256",
    ):
        require(
            f"fn {raw_secret_api}" not in bindings_source,
            f"aggregate Python bindings must not expose raw {raw_secret_api}",
        )

    verification_bindings_source = (
        root / "marty-verification" / "src" / "bindings" / "crypto.rs"
    ).read_text(encoding="utf-8")
    for raw_secret_api in (
        "hkdf_sha256",
        "hkdf_sha384",
        "pbkdf2_sha256",
        "generate_random_bytes",
        "aes_gcm_encrypt",
        "aes_gcm_decrypt",
        "tdes_cbc_encrypt",
        "tdes_cbc_decrypt",
    ):
        require(
            f"fn {raw_secret_api}" not in verification_bindings_source,
            f"verification Python bindings must not expose raw {raw_secret_api}",
        )

    ci_source = (root / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    didcomm_boundary_condition = (
        "contains(steps.affected.outputs.packages, 'marty-didcomm')"
    )
    require(
        didcomm_boundary_condition in ci_source,
        "DIDComm-only PRs must run the full encrypted-envelope/local-key agent suite",
    )
    ephemeral_binding_test = "ephemeral_session_module_exports_only_opaque_session_crypto"
    require(
        ephemeral_binding_test in ci_source
        and f"fn {ephemeral_binding_test}" in bindings_source
        and "ephemeral_session_module_does_not_restore_credential_keys" not in ci_source,
        "CI must execute a currently defined opaque-session Python binding boundary test",
    )

    lib_source = (root / "marty-verification" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    require(
        "pub mod issuance;" not in lib_source,
        "marty-verification must not expose authority issuance",
    )

    crypto_source = (root / "marty-crypto" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    require(
        not any(f'feature = "{feature}"' in crypto_source for feature in REMOVED_CRYPTO_FEATURES),
        "marty-crypto source must not retain Cargo gates for removed private-key features",
    )
    require(
        test_support["package"].get("publish") is False
        and "marty-crypto-test-support" not in bindings["dependencies"]
        and "marty-crypto-test-support" in bindings["dev-dependencies"],
        "local signing fixtures must remain publish-disabled and dev-only",
    )

    def normal_or_build_dependency(table: object) -> bool:
        if not isinstance(table, dict):
            return False
        for key, value in table.items():
            if key in {"dependencies", "build-dependencies"} and isinstance(value, dict):
                if "marty-crypto-test-support" in value:
                    return True
            if key != "dev-dependencies" and normal_or_build_dependency(value):
                return True
        return False

    shipping_edges = [
        str(manifest.relative_to(root))
        for manifest in root.rglob("Cargo.toml")
        if normal_or_build_dependency(load_toml(manifest))
    ]
    require(
        not shipping_edges,
        "marty-crypto-test-support must have no normal/build dependency edges; found: "
        + ", ".join(shipping_edges),
    )


def main() -> int:
    try:
        check_repository()
    except (KeyError, StopIteration, ValueError) as error:
        print(f"verification feature boundary failed: {error}", file=sys.stderr)
        return 1
    print("verification feature boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
