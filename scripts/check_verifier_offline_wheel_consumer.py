#!/usr/bin/env python3
"""Exercise an installed verifier wheel with bundled, locally resolved fixtures.

Python-audited socket operations are denied. This is not an OS-level network
sandbox or a complete verifier product/dependency-closure qualification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable


FIXTURES = Path(__file__).resolve().parents[1] / "marty-verification/tests/fixtures/open_badges"


def deny_network(event: str, _args: tuple[object, ...]) -> None:
    if event.startswith("socket."):
        raise RuntimeError(f"offline verifier probe attempted network operation: {event}")


def verify_fixture(verify: Callable[[str], str], fixture_name: str) -> None:
    request = json.loads((FIXTURES / fixture_name).read_text(encoding="utf-8"))
    result = json.loads(verify(json.dumps(request)))
    if result.get("valid") is not True:
        raise RuntimeError(f"{fixture_name}: valid signed fixture was rejected: {result}")

    # Probe one signed-payload edit per format. This is not a comprehensive
    # payload-binding or trust-store authentication test.
    if fixture_name.startswith("ob2"):
        request["assertion"]["id"] = "urn:uuid:tampered"
    else:
        request["credential"]["credentialSubject"]["achievement"]["name"] = "Tampered"
    negative = json.loads(verify(json.dumps(request)))
    if negative.get("valid") is not False:
        raise RuntimeError(f"{fixture_name}: negative fixture was accepted: {negative}")


def main() -> int:
    import sys

    sys.addaudithook(deny_network)
    # Import only after installing the Python socket guard, so import-time
    # Python socket use is covered too. This is not a native-code sandbox.
    import marty_verification_py as verifier

    verify_fixture(verifier.open_badge_ob2_verify, "ob2_verify_request.json")
    verify_fixture(verifier.open_badge_ob3_verify, "ob3_verify_request.json")
    print("verifier-offline-wheel-consumer: OB2/OB3 positive and negative fixtures passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
