import json

import marty_verification
import pytest


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


def _p256_pem_pair() -> tuple[str, str]:
    private_raw, public_raw = marty_verification.ecdsa_p256_generate()
    private_der = marty_verification.raw_private_key_to_pkcs8(private_raw, "P256")
    public_der = marty_verification.raw_public_key_to_spki(public_raw, "P256")
    return (
        marty_verification.save_private_key_pem(private_der),
        marty_verification.save_public_key_pem(public_der),
    )


def test_python_bindings_share_the_canonical_external_signing_payload():
    private_pem, public_pem = _p256_pem_pair()
    created = json.loads(marty_verification.dtc_create(_create_request()))
    prepared = json.loads(marty_verification.dtc_prepare_signing(json.dumps(created)))

    local_signing_envelope = dict(prepared["dtc"])
    local_signing_envelope["signing_key_pem"] = private_pem
    local_signing_envelope["signer_id"] = "python-binding-test"
    locally_signed = json.loads(
        marty_verification.dtc_sign(json.dumps(local_signing_envelope))
    )

    assembled = json.loads(
        marty_verification.dtc_assemble_signature(
            json.dumps(
                {
                    "dtc": prepared["dtc"],
                    "signature_base64": locally_signed["signature_info"]["signature"],
                    "signer_id": "python-binding-test",
                    "signer_public_key_pem": public_pem,
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
    private_pem, public_pem = _p256_pem_pair()
    created = json.loads(marty_verification.dtc_create(_create_request()))
    prepared = json.loads(marty_verification.dtc_prepare_signing(json.dumps(created)))
    local_signing_envelope = dict(prepared["dtc"])
    local_signing_envelope["signing_key_pem"] = private_pem
    local_signing_envelope["signer_id"] = "python-binding-test"
    locally_signed = json.loads(
        marty_verification.dtc_sign(json.dumps(local_signing_envelope))
    )
    prepared["dtc"]["passport_number"] = "TAMPERED"

    with pytest.raises(ValueError, match="signature"):
        marty_verification.dtc_assemble_signature(
            json.dumps(
                {
                    "dtc": prepared["dtc"],
                    "signature_base64": locally_signed["signature_info"]["signature"],
                    "signer_id": "python-binding-test",
                    "signer_public_key_pem": public_pem,
                }
            )
        )
