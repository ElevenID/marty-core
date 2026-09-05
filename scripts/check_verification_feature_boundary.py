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
    crypto = load_toml(root / "marty-crypto" / "Cargo.toml")
    verification = load_toml(root / "marty-verification" / "Cargo.toml")
    oid4vci = load_toml(root / "marty-oid4vci" / "Cargo.toml")
    iso18013 = load_toml(root / "marty-iso18013" / "Cargo.toml")
    bindings = load_toml(root / "marty-bindings" / "Cargo.toml")
    verification_python = load_toml(root / "marty-verification" / "pyproject.toml")

    crypto_features = crypto["features"]
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
        set(verification_features["authority-issuance"])
        == {"csca", "marty-crypto/sod-builder"},
        "authority issuance must explicitly select CSCA verification and SOD construction",
    )
    require(
        "authority-issuance" in verification_features["full"],
        "the explicitly feature-complete matrix must continue to exercise authority issuance",
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
        and oid4vci_crypto["features"] == ["ecdsa-verification"],
        "marty-oid4vci must not transitively restore marty-crypto defaults",
    )
    require(
        oid4vci["features"]["kms-only"] == ["marty-crypto/kms-only"],
        "marty-oid4vci must propagate KMS enforcement",
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
            "marty-oid4vci/kms-only",
            "marty-verification/kms-only",
        },
        "released bindings must propagate KMS enforcement",
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
