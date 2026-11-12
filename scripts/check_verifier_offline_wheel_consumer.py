#!/usr/bin/env python3
"""Exercise an installed verifier wheel with bundled, locally resolved fixtures.

Python-audited socket operations are denied. This is not an OS-level network
sandbox or a complete verifier product/dependency-closure qualification.
"""

from __future__ import annotations

import copy
import argparse
import importlib
import importlib.machinery
import json
from collections.abc import Callable
from pathlib import Path

FIXTURES = (
    Path(__file__).resolve().parents[1]
    / "marty-verification/tests/fixtures/open_badges"
)
OTHER_ED25519_PUBLIC_KEY = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
# Evaluate after the bundled public proof's creation time, without altering
# its signed bytes or coupling the probe to the current wall clock.
OB3_EVALUATION_TIME = "2026-11-12T00:00:00Z"


def deny_network(event: str, _args: tuple[object, ...]) -> None:
    if event.startswith("socket."):
        raise RuntimeError(
            f"offline verifier probe attempted network operation: {event}"
        )


def verify_fixture(
    verify: Callable[[str], str], fixture_name: str, fixtures_dir: Path = FIXTURES
) -> None:
    request = json.loads((fixtures_dir / fixture_name).read_text(encoding="utf-8"))
    result = json.loads(verify(json.dumps(request)))
    if result.get("valid") is not True:
        raise RuntimeError(
            f"{fixture_name}: valid signed fixture was rejected: {result}"
        )

    # Probe one signed-payload edit. This is not a comprehensive
    # payload-binding or trust-store authentication test.
    wrong_key = copy.deepcopy(request)
    request["credential"]["credentialSubject"]["achievement"]["name"] = "Tampered"
    negative = json.loads(verify(json.dumps(request)))
    if negative.get("valid") is not False:
        raise RuntimeError(f"{fixture_name}: negative fixture was accepted: {negative}")

    # Mismatched but well-formed caller-supplied key material must not verify
    # the fixture's signature. This does not authenticate a trust store.
    issuer_key_id = wrong_key["credential"]["proof"]["verificationMethod"]
    key = wrong_key["document_store"][issuer_key_id]["publicKeyJwk"]
    if (
        key.get("kty") != "OKP"
        or key.get("crv") != "Ed25519"
        or key.get("x") == OTHER_ED25519_PUBLIC_KEY
    ):
        raise RuntimeError(f"{fixture_name}: expected a distinct Ed25519 fixture key")
    key["x"] = OTHER_ED25519_PUBLIC_KEY
    wrong_key_result = json.loads(verify(json.dumps(wrong_key)))
    if wrong_key_result.get("valid") is not False:
        raise RuntimeError(
            f"{fixture_name}: mismatched issuer key was accepted: {wrong_key_result}"
        )


def reject_retired_fixture(
    verify: Callable[[str], str], fixtures_dir: Path = FIXTURES
) -> None:
    """An old signed assertion must never acquire an OB3 verification route."""
    legacy = json.loads((fixtures_dir / "ob2_verify_request.json").read_text(encoding="utf-8"))
    request = {"credential": legacy["assertion"], "document_store": legacy.get("document_store", {})}
    try:
        verify(json.dumps(request))
    except ValueError as error:
        if "Open Badges 2 is retired" not in str(error):
            raise RuntimeError("retired OB2 fixture gave an unexpected error") from error
    else:
        raise RuntimeError("retired OB2 fixture reached an active verifier")


def verify_ob3_at_caller_time(
    verify_at: Callable[[str, str], str], fixtures_dir: Path = FIXTURES
) -> None:
    """Smoke-test the installed API; Rust owns signed time-boundary coverage."""
    request = json.loads(
        (fixtures_dir / "ob3_verify_request.json").read_text(encoding="utf-8")
    )
    result = json.loads(verify_at(json.dumps(request), OB3_EVALUATION_TIME))
    if result.get("valid") is not True:
        raise RuntimeError(f"OB3 caller-time fixture was rejected: {result}")
    try:
        verify_at(json.dumps(request), "2026-01-01T00:00:00")
    except ValueError as error:
        if "evaluation_time must be RFC 3339 with an explicit offset" not in str(error):
            raise RuntimeError("OB3 caller-time API gave an unexpected error") from error
    else:
        raise RuntimeError("OB3 caller-time API accepted a timezone-free timestamp")


def require_installed_native(
    public_path: Path, native_path: Path, environment: Path
) -> None:
    root = environment.resolve()
    if not public_path.resolve().is_relative_to(
        root
    ) or not native_path.resolve().is_relative_to(root):
        raise RuntimeError(
            "verifier package or native extension resolved outside the consumer venv"
        )
    if not any(
        str(native_path).endswith(suffix)
        for suffix in importlib.machinery.EXTENSION_SUFFIXES
    ):
        raise RuntimeError("verifier native extension is missing")


def main() -> int:
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures-dir", required=True, type=Path)
    args = parser.parse_args()
    if sys.prefix == sys.base_prefix:
        raise RuntimeError("verifier consumer must run inside a virtual environment")
    sys.addaudithook(deny_network)
    # Import only after installing the Python socket guard, so import-time
    # Python socket use is covered too. This is not a native-code sandbox.
    import marty_verification_py as verifier

    native = importlib.import_module("marty_verification_py._marty_verification")
    require_installed_native(
        Path(verifier.__file__), Path(native.__file__), Path(sys.prefix)
    )

    for module in (verifier, native):
        if hasattr(module, "open_badge_ob2_verify") or hasattr(module, "open_badge_ob2_issue"):
            raise RuntimeError("verifier wheel exposes a retired OB2 API")
    reject_retired_fixture(verifier.open_badge_ob3_verify, args.fixtures_dir)
    verify_fixture(
        verifier.open_badge_ob3_verify, "ob3_verify_request.json", args.fixtures_dir
    )
    verify_ob3_at_caller_time(verifier.open_badge_ob3_verify_at, args.fixtures_dir)
    print(
        "verifier-offline-wheel-consumer: OB3 positive, tamper, wrong-key, caller-time, and retired OB2 rejection fixtures passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
