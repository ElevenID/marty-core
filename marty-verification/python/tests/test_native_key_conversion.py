import json

import marty_verification
import pytest


def test_p256_public_jwk_and_pem_round_trip_in_native_backend():
    private_jwk = marty_verification.jwk_generate("p256")
    public_jwk = json.loads(private_jwk.to_public().to_json())

    public_pem = marty_verification.p256_public_jwk_to_pem(
        json.dumps(public_jwk)
    )
    round_tripped = json.loads(
        marty_verification.public_key_pem_to_jwk(public_pem)
    )

    assert round_tripped["kty"] == "EC"
    assert round_tripped["crv"] == "P-256"
    assert round_tripped["x"] == public_jwk["x"]
    assert round_tripped["y"] == public_jwk["y"]
    assert "d" not in round_tripped


def test_p256_public_jwk_to_pem_rejects_private_material():
    private_jwk = marty_verification.jwk_generate("p256").to_json()

    with pytest.raises(ValueError, match="private key material"):
        marty_verification.p256_public_jwk_to_pem(private_jwk)
