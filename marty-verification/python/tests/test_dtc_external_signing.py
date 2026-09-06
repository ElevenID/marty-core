import base64
import json

import marty_verification
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


_SIGNING_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiNW7Kf1E+H1DeG4s
2D38+6hJbAnf4fy5s6RJFuMAcMWhRANCAAQsKlSJSUKItZlFvKAJnjZob3Q6r98t
fYIH6foa373wsHSHktdpDZmb7fe0E3MFc3TvrWlCg/nPMlQNMU41xr4M
-----END PRIVATE KEY-----"""

_SIGNER_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELCpUiUlCiLWZRbygCZ42aG90Oq/f
LX2CB+n6Gt+98LB0h5LXaQ2Zm+33tBNzBXN0761pQoP5zzJUDTFONca+DA==
-----END PUBLIC KEY-----"""


def _create_request() -> str:
    return json.dumps(
        {
            "passport_number": "P1234567",
            "issuing_authority": "USA",
            "issue_date": "2024-01-01",
            "expiry_date": "2030-01-01",
            "personal_details": {
                "first_name": "JOHN",
                "last_name": "DOE",
                "date_of_birth": "1990-01-01",
                "gender": "M",
                "nationality": "USA",
                "portrait": "cG9ydHJhaXQ=",
                "signature": "c2lnbmF0dXJl",
            },
            "data_groups": [{"dg_number": 1, "data": "ZGcx", "data_type": "MRZ"}],
            "dtc_type": 4,
            "type1_profile": {
                "mrz_line1": "P<USADOE<<JOHN<<<<<<<<<<<<<<<<<<<<<<<",
                "mrz_line2": "1234567890USA8504031M3504027<<<<<<<6",
                "sod_hash": "",
                "issuing_state": "USA",
                "passive_auth_ok": True,
            },
        }
    )


def _external_signature(signing_input_base64: str) -> str:
    private_key = serialization.load_pem_private_key(_SIGNING_KEY_PEM, password=None)
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    signature = private_key.sign(
        base64.b64decode(signing_input_base64), ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode("ascii")


def test_python_bindings_share_the_canonical_external_signing_payload():
    created = json.loads(marty_verification.dtc_create(_create_request()))
    prepared = json.loads(marty_verification.dtc_prepare_signing(json.dumps(created)))

    assembled = json.loads(
        marty_verification.dtc_assemble_signature(
            json.dumps(
                {
                    "dtc": prepared["dtc"],
                    "signature_base64": _external_signature(
                        prepared["signing_input_base64"]
                    ),
                    "signer_id": "python-binding-test",
                    "signer_public_key_pem": _SIGNER_PUBLIC_PEM,
                    "signature_date": "2026-08-11T00:00:00Z",
                }
            )
        )
    )

    assert assembled["is_signed"] is True
    assert assembled["signature_info"]["is_valid"] is True
    assert assembled["signature_info"]["signer_id"] == "python-binding-test"
    assert prepared["signature_encoding"] == "DER_BASE64"


def test_python_binding_rejects_tampered_external_signer_output():
    created = json.loads(marty_verification.dtc_create(_create_request()))
    prepared = json.loads(marty_verification.dtc_prepare_signing(json.dumps(created)))
    signature = _external_signature(prepared["signing_input_base64"])
    prepared["dtc"]["passport_number"] = "TAMPERED"

    with pytest.raises(ValueError, match="signature"):
        marty_verification.dtc_assemble_signature(
            json.dumps(
                {
                    "dtc": prepared["dtc"],
                    "signature_base64": signature,
                    "signer_id": "python-binding-test",
                    "signer_public_key_pem": _SIGNER_PUBLIC_PEM,
                }
            )
        )
