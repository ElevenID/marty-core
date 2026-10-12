import json
from pathlib import Path

import marty_verification
import pytest


def public_p256_jwk():
    vectors = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "tests/fixtures/public_key_jwk_vectors.json"
        ).read_text(encoding="utf-8")
    )
    return next(
        vector["expected_jwk"]
        for vector in vectors["vectors"]
        if vector["name"] == "p_256"
    )


def test_p256_public_jwk_and_pem_round_trip_in_native_backend():
    public_jwk = public_p256_jwk()

    public_pem = marty_verification.p256_public_jwk_to_pem(json.dumps(public_jwk))
    round_tripped = json.loads(marty_verification.public_key_pem_to_jwk(public_pem))

    assert round_tripped["kty"] == "EC"
    assert round_tripped["crv"] == "P-256"
    assert round_tripped["x"] == public_jwk["x"]
    assert round_tripped["y"] == public_jwk["y"]
    assert "d" not in round_tripped


def test_p256_public_jwk_to_pem_rejects_private_material():
    synthetic_private_jwk = {**public_p256_jwk(), "d": "synthetic-rejected-value"}

    with pytest.raises(ValueError, match="private key material"):
        marty_verification.p256_public_jwk_to_pem(json.dumps(synthetic_private_jwk))
