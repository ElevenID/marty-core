import base64
import hashlib
import json

import marty_verification
import pytest


_SIGNER_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELCpUiUlCiLWZRbygCZ42aG90Oq/f
LX2CB+n6Gt+98LB0h5LXaQ2Zm+33tBNzBXN0761pQoP5zzJUDTFONca+DA==
-----END PUBLIC KEY-----"""
_SIGNING_INPUT_SHA256 = "e5d3bfae43c5c48ea95c2ab66717896c74a75c5ff90b726477e3347c8062567c"
_SIGNATURE_BASE64 = (
    "MEUCIQCet0x3VTEB1NZUBc1YWA0wZIdh9hF06KuoBd0nkGXFoQIgfg9T81Suu23zA/WQLQCdRAUV/TRj1oh0mo4VjgMkVTk="
)


def _create_request() -> str:
    return json.dumps(
        {
            "dtc_id": "dtc-python-binding-public-vector",
            "passport_number": "P1234567",
            "issuing_authority": "USA",
            "issue_date": "2024-01-01",
            "expiry_date": "2030-01-01",
            "creation_date": "2026-08-11T00:00:00Z",
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


def _prepared_with_public_signature() -> dict:
    created = json.loads(marty_verification.dtc_create(_create_request()))
    prepared = json.loads(marty_verification.dtc_prepare_signing(json.dumps(created)))
    signing_input = base64.b64decode(prepared["signing_input_base64"], validate=True)
    assert hashlib.sha256(signing_input).hexdigest() == _SIGNING_INPUT_SHA256
    return prepared


def test_python_bindings_share_the_canonical_external_signing_payload():
    prepared = _prepared_with_public_signature()

    assembled = json.loads(
        marty_verification.dtc_assemble_signature(
            json.dumps(
                {
                    "dtc": prepared["dtc"],
                    "signature_base64": _SIGNATURE_BASE64,
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
    prepared = _prepared_with_public_signature()
    prepared["dtc"]["passport_number"] = "TAMPERED"

    with pytest.raises(ValueError, match="signature"):
        marty_verification.dtc_assemble_signature(
            json.dumps(
                {
                    "dtc": prepared["dtc"],
                    "signature_base64": _SIGNATURE_BASE64,
                    "signer_id": "python-binding-test",
                    "signer_public_key_pem": _SIGNER_PUBLIC_PEM,
                }
            )
        )
