import base64
import json
from pathlib import Path

import marty_verification


FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "emrtd_verification_vectors.json"
)


def _decode(value):
    return base64.b64decode(value, validate=True)


def test_python_binding_matches_shared_emrtd_golden_vector():
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["schema_version"] == 1
    sod = _decode(fixture["sod_der_base64"])
    dsc = _decode(fixture["dsc_der_base64"])
    csca = _decode(fixture["csca_der_base64"])
    dg1 = _decode(fixture["data_groups"]["1"])
    dg2 = _decode(fixture["data_groups"]["2"])

    parsed = marty_verification.parse_sod(sod)
    assert len(parsed["data_group_hashes"]) == 2
    assert marty_verification.verify_sod_signature(sod) is True
    assert marty_verification.verify_sod_data_group_hash(sod, 1, dg1) is True
    assert marty_verification.verify_sod_data_group_hash(sod, 2, dg2) is True

    registry = marty_verification.CscaRegistry()
    registry.add_country_csca(
        "TST", marty_verification.certificate_der_to_pem(csca)
    )
    result = marty_verification.verify_emrtd(
        sod, {1: dg1, 2: dg2}, registry, country_hint="TST"
    )
    assert result["verified"] is True
    assert result["dsc_chain_status"] == "valid"
    assert result["sod_signature_status"] == "valid"
    assert result["dg_hash_status"] == "valid"
    assert result["revocation_status"] == "unchecked"
    assert result["error_codes"] == []
    assert result["trust_anchor_subject"]
    assert len(result["certificate_chain"]) == 2

    altered_dg1 = bytes([dg1[0] ^ 1]) + dg1[1:]
    assert marty_verification.verify_sod_data_group_hash(sod, 1, altered_dg1) is False
    altered_result = marty_verification.verify_emrtd(
        sod, {1: altered_dg1, 2: dg2}, registry, country_hint="TST"
    )
    assert altered_result["verified"] is False
    assert altered_result["dg_hash_status"] == "invalid"
    assert "EMRTD_DG_HASH_INVALID" in altered_result["error_codes"]

    untrusted_result = marty_verification.verify_emrtd(
        sod,
        {1: dg1, 2: dg2},
        marty_verification.CscaRegistry(),
        country_hint="TST",
    )
    assert untrusted_result["verified"] is False
    assert untrusted_result["dsc_chain_status"] == "invalid"
    assert "EMRTD_CHAIN_INVALID" in untrusted_result["error_codes"]

    altered_sod = sod[:-1] + bytes([sod[-1] ^ 1])
    try:
        signature_valid = marty_verification.verify_sod_signature(altered_sod)
    except ValueError:
        signature_valid = False
    assert signature_valid is False

    validator = marty_verification.ChainValidator()
    validator.add_trust_anchor_der(csca)
    chain = [
        marty_verification.certificate_der_to_pem(dsc),
        marty_verification.certificate_der_to_pem(csca),
    ]
    assert validator.validate_chain(chain).valid is True
    assert validator.validate_with_config(
        chain, marty_verification.ValidationConfig()
    ).valid is True
    assert marty_verification.ChainValidator().validate_chain(chain).valid is False
