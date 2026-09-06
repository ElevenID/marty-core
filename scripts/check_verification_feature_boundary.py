#!/usr/bin/env python3
"""Validate the verifier/authority Cargo feature boundary."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_CRYPTO_FEATURES = {
    "default",
    "full",
    "cert-builder",
    "crl-builder",
    "keygen",
    "sod-builder",
}
FORBIDDEN_KMS_CRYPTO_FEATURES = FORBIDDEN_CRYPTO_FEATURES | {
    "bbs",
    "ecdsa-local-signing",
    "eddsa-local-signing",
    "pkcs12",
    "private-key-codec",
    "rsa-local-signing",
    "serialization",
}
KMS_GUARDED_CRYPTO_FEATURES = {
    "bbs",
    "cert-builder",
    "crl-builder",
    "ecdsa-local-signing",
    "eddsa-local-signing",
    "keygen",
    "pkcs12",
    "private-key-codec",
    "rsa-local-signing",
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
        crypto_features["crl-builder"] == ["crl", "cert-builder"],
        "CRL construction must remain an explicit builder feature",
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
        {"ecdsa-core/signing", "p256/ecdsa", "p384/ecdsa", "p521/ecdsa"}
        <= set(crypto_features["ecdsa-local-signing"]),
        "ECDSA signing primitives must require the local-signing capability",
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
        "authority-issuance" not in verification_features["default"],
        "default verification must exclude authority issuance",
    )
    require(
        "ephemeral-session-keys" not in verification_features["default"],
        "default verification must not create protocol session keys",
    )
    require(
        set(verification_features["authority-issuance"])
        == {
            "csca",
            "marty-crypto/sod-builder",
            "cms/builder",
            "x509-cert/builder",
        },
        "authority issuance must explicitly select CSCA verification and SOD construction",
    )

    for curve in ("p256", "p384", "p521"):
        require(
            verification["dependencies"][curve].get("features") == ["ecdsa-core"],
            f"marty-verification {curve} must select signature types without signing",
        )
    require(
        {"p256/ecdh", "p384/ecdh"}
        <= set(verification_features["ephemeral-session-keys"]),
        "curve ECDH must require the explicit ephemeral-session-keys capability",
    )
    require(
        "authority-issuance" in verification_features["full"],
        "the explicitly feature-complete matrix must continue to exercise authority issuance",
    )

    require(
        "python" not in verification["features"]["local-key-operations"],
        "native and browser local-key operations must not select Python bindings",
    )
    verification_crypto = verification["dependencies"]["marty-crypto"]
    require(
        verification_crypto.get("default-features") is False,
        "marty-verification must disable marty-crypto defaults",
    )
    require(
        not (set(verification_crypto["features"]) & FORBIDDEN_CRYPTO_FEATURES),
        "marty-verification normal dependencies must exclude authority-only crypto features",
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
        and "jsonwebtoken/rust_crypto"
        in oid4vci["features"]["holder-key-operations"],
        "JWT crypto must be absent from issuer planning and explicit for verification/holders",
    )

    bindings_crypto = bindings["dependencies"]["marty-crypto"]
    require(
        bindings_crypto.get("default-features") is False,
        "released bindings must disable marty-crypto defaults",
    )
    require(
        not (set(bindings_crypto["features"]) & FORBIDDEN_CRYPTO_FEATURES),
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

    lib_source = (root / "marty-verification" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    require(
        re.search(
            r'#\[cfg\(feature = "authority-issuance"\)\]\s*pub mod issuance;',
            lib_source,
        )
        is not None,
        "the public issuance module must be gated by authority-issuance",
    )
    require(
        re.search(r'#\[cfg\(feature = "csca"\)\]\s*pub mod issuance;', lib_source)
        is None,
        "ordinary CSCA verification must not expose authority issuance",
    )

    crypto_source = (root / "marty-crypto" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    for forbidden_feature in KMS_GUARDED_CRYPTO_FEATURES:
        require(
            f'feature = "{forbidden_feature}"' in crypto_source,
            f"marty-crypto KMS guard must reject {forbidden_feature}",
        )

    benches = verification.get("bench", [])
    kernel_bench = next(bench for bench in benches if bench["name"] == "verification_kernels")
    require(
        kernel_bench.get("required-features") == ["authority-issuance"],
        "the authority-dependent benchmark must select the authority feature",
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
