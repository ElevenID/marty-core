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
    require(crypto_features["crl"] == ["x509"], "CRL parsing must not enable builders")
    require(
        crypto_features["crl-builder"] == ["crl", "cert-builder"],
        "CRL construction must remain an explicit builder feature",
    )
    require(crypto_features["ocsp"] == ["x509"], "OCSP verification must not enable builders")

    verification_features = verification["features"]
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
        and oid4vci_crypto["features"] == ["ecdsa"],
        "marty-oid4vci must not transitively restore marty-crypto defaults",
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

    iso18013_crypto = iso18013["dependencies"]["marty-crypto"]
    require(
        iso18013_crypto.get("default-features") is False
        and set(iso18013_crypto["features"]) == {"ecdh", "kdf", "symmetric"},
        "ISO 18013 bindings must not transitively restore marty-crypto defaults",
    )

    wheel_features = set(verification_python["tool"]["maturin"]["features"])
    require(
        not ({"authority-issuance", "cert-builder"} & wheel_features),
        "the released verification wheel must exclude authority and certificate builders",
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
