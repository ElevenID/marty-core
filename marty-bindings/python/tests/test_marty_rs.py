"""Tests for _marty_rs Python bindings.

These tests exercise the PyO3 FFI surface. They require the native extension
to be built first:

    cd marty-core/marty-bindings
    maturin develop --release

The extension deliberately omits long-term issuer/holder private-key import,
generation, signing, and DIDComm key decryption functions. Explicit short-lived
protocol-session capabilities remain separate. Issuers use the format-specific
prepare -> remote sign -> assemble APIs.

Or for venv-based development:

    pip install -e ".[dev]"
"""

import json
import hashlib
import base64

import pytest

# All tests are skipped if the native extension hasn't been built yet.
_marty_rs = pytest.importorskip("marty_rs._marty_rs", reason="native extension not built")

def test_canonical_top_level_import_exposes_native_bindings():
    import _marty_rs as canonical
    import marty_rs

    assert canonical.TokenStatusList is _marty_rs.TokenStatusList
    assert canonical.oid4vci_prepare_jwt_vc is _marty_rs.oid4vci_prepare_jwt_vc
    assert canonical.oid4vci_assemble_jwt_vc is _marty_rs.oid4vci_assemble_jwt_vc
    assert (
        canonical.oid4vci_verify_detached_signature
        is _marty_rs.oid4vci_verify_detached_signature
    )
    assert (
        canonical.oid4vci_normalize_ecdsa_signature
        is _marty_rs.oid4vci_normalize_ecdsa_signature
    )
    assert canonical.oidc_validate_id_token is _marty_rs.oidc_validate_id_token
    assert canonical.OidcValidationError is _marty_rs.OidcValidationError
    assert issubclass(marty_rs.NativeBackendUnavailable, RuntimeError)


def test_native_backend_diagnostics_are_explicit_and_versioned():
    diagnostics = json.loads(_marty_rs.native_backend_diagnostics())

    assert diagnostics["available"] is True
    assert diagnostics["backend"] == "_marty_rs"
    assert diagnostics["version"]
    assert "oidc_id_token_validation" in diagnostics["capabilities"]
    assert "credential_presentation_metadata" in diagnostics["capabilities"]


def test_private_key_operations_are_not_packaged():
    private_key_operations = {
        "generate_p256_key",
        "generate_p256_jwk",
        "generate_p256_did_jwk",
        "generate_p384_key",
        "generate_ed25519_key",
        "generate_did_key",
        "sign_p256",
        "sign_p384",
        "sign_ed25519",
        "create_verifiable_credential",
        "oid4vci_sign_credential",
        "oid4vci_create_proof_jwt",
        "oid4vci_prepare_credential",
        "oid4vci_assemble_credential",
        "vds_nc_sign_profile",
        "didcomm_encrypt_authcrypt",
        "didcomm_decrypt",
        "didcomm_decrypt_authcrypt",
    }
    assert not (private_key_operations & set(dir(_marty_rs)))
    assert hasattr(_marty_rs, "oid4vci_prepare_jwt_vc")
    assert hasattr(_marty_rs, "oid4vci_assemble_jwt_vc")


@pytest.mark.parametrize(
    ("operation", "public_key", "message", "signature"),
    [
        (
            _marty_rs.verify_p256,
            bytes.fromhex(
                "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
                "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
            ),
            b"sample",
            bytes.fromhex(
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
            ),
        ),
        (
            _marty_rs.verify_p384,
            bytes.fromhex(
                "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385"
                "502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8"
                "f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
            ),
            b"sample",
            bytes.fromhex(
                "306502301f30a1b9119f64fcf6d04fbd2892e71926675a40e8ceaee3ff3ebba581"
                "58db477f6a7e7d79b4b692bbe815a168cb0701023100e1669b9c87c57e033d22cb"
                "8b2628dc15dcb9762b48269b9bfb5d000af1d01db1f7916b539abceea6880b74c"
                "058610b25"
            ),
        ),
        (
            _marty_rs.verify_ed25519,
            bytes.fromhex(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            ),
            b"",
            bytes.fromhex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
        ),
    ],
)
def test_public_verification_fixed_vectors(operation, public_key, message, signature):
    assert operation(public_key, message, signature) is True
    assert operation(public_key, b"tampered", signature) is False


def test_open_badge_presentation_metadata_matches_canonical_rust_issuer_profile():
    metadata = json.loads(
        _marty_rs.credential_profile_presentation_metadata(
            "open_badge", "jwt_vc_json", ""
        )
    )

    assert metadata == {
        "format": "jwt_vc_json",
        "meta": {
            "type_values": [["VerifiableCredential", "OpenBadgeCredential"]]
        },
    }


def test_unknown_credential_presentation_profile_fails_closed():
    with pytest.raises(RuntimeError, match="Unsupported credential presentation profile"):
        _marty_rs.credential_profile_presentation_metadata(
            "unknown-profile", "jwt_vc_json", ""
        )


def test_oidc_validation_exposes_typed_fail_closed_errors():
    with pytest.raises(_marty_rs.OidcValidationError, match="OIDC.MALFORMED_TOKEN"):
        _marty_rs.oidc_validate_id_token(
            json.dumps(
                {
                    "compact_jwt": "not-a-jwt",
                    "jwks": {"keys": []},
                    "expected_issuer": "https://issuer.example",
                    "expected_audience": "marty-ui",
                }
            )
        )


class TestStatusLists:
    """Status-list bindings follow their standards and fail closed."""

    def test_ietf_golden_vector_and_roundtrip(self):
        values = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]
        status_list = _marty_rs.TokenStatusList(len(values), 1)
        for index, value in enumerate(values):
            status_list.set(index, value)

        assert bytes(status_list.to_bytes()) == bytes.fromhex("b9a3")
        assert bytes(status_list.compress()) == bytes.fromhex("78dadbb918000217015d")
        restored = _marty_rs.TokenStatusList.from_base64url(
            status_list.to_base64url(), len(values), 1
        )
        assert [restored.get(index) for index in range(len(values))] == values

    def test_w3c_multibase_roundtrip(self):
        status_list = _marty_rs.BitstringStatusList(131_072)
        status_list.revoke(0)
        status_list.revoke(131_071)

        encoded = status_list.to_base64url()
        assert encoded.startswith("u")
        restored = _marty_rs.BitstringStatusList.from_base64url(encoded, 131_072)
        assert restored.is_revoked(0)
        assert restored.is_revoked(131_071)
        assert restored.count_revoked() == 2

    def test_persisted_raw_bytes_roundtrip(self):
        token = _marty_rs.TokenStatusList.from_bytes(b"\x00\x07", 2, 8)
        token.set(0, 3)
        assert bytes(token.to_bytes()) == b"\x03\x07"

        bitstring = _marty_rs.BitstringStatusList.from_bytes(b"\x80", 8)
        assert bitstring.is_revoked(0)
        bitstring.reinstate(0)
        assert bytes(bitstring.to_bytes()) == b"\x00"

    def test_malformed_payloads_are_rejected(self):
        with pytest.raises(ValueError):
            _marty_rs.TokenStatusList.from_compressed(b"not-zlib", 100, 8)
        with pytest.raises(ValueError, match="multibase"):
            _marty_rs.BitstringStatusList.from_base64url("not-multibase", 131_072)


class TestMdocPresentationVerification:
    """The production wheel exposes fail-closed ISO presentation bindings."""

    def test_mdoc_verifier_surface_is_packaged(self):
        assert hasattr(_marty_rs, "parse_device_response")
        assert hasattr(_marty_rs, "verify_mdoc_cbor")
        assert hasattr(_marty_rs, "verify_mdoc_issuer")
        assert hasattr(_marty_rs, "verify_mdoc_presentation")

    def test_malformed_mdoc_issuer_verification_fails_closed(self):
        result = _marty_rs.verify_mdoc_issuer(b"\xff", [])
        assert result.signature_valid is False
        assert result.issuer_trusted is False
        assert result.document_evidence == []
        assert result.revocation_checked is False
        assert result.not_revoked is None
        assert result.error

    def test_malformed_mdoc_presentation_fails_closed(self):
        result = _marty_rs.verify_mdoc_presentation(
            b"\xff",
            bytes([0x83, 0xF6, 0xF6, 0x82, 0x71]),
            [],
        )
        assert result.issuer_signature_valid is False
        assert result.issuer_trusted is False
        assert result.device_authentication_valid is False
        assert result.document_evidence == []
        assert result.revocation_checked is False
        assert result.not_revoked is None
        assert result.error


# =========================================================================
# OID4VCI Protocol
# =========================================================================


class TestOID4VCI:
    """Tests for the OID4VCI protocol binding functions."""

    ISSUER_URL = "https://issuer.example.com"

    def test_create_credential_offer(self):
        offer_json = _marty_rs.oid4vci_create_credential_offer(
            self.ISSUER_URL,
            ["VerifiableId"],
            "pre-auth-123",
            False,
        )
        offer = json.loads(offer_json)
        assert offer["credential_issuer"] == self.ISSUER_URL
        assert "VerifiableId" in offer["credential_configuration_ids"]

    def test_create_credential_offer_without_preauth(self):
        offer_json = _marty_rs.oid4vci_create_credential_offer(
            self.ISSUER_URL,
            ["mDL"],
        )
        offer = json.loads(offer_json)
        assert "credential_configuration_ids" in offer

    def test_create_token_response(self):
        resp_json = _marty_rs.oid4vci_create_token_response("code-abc", 1800)
        resp = json.loads(resp_json)
        assert resp["token_type"] == "Bearer"
        assert "access_token" in resp
        assert "nonce" not in resp

    def test_pkce_s256_valid(self):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert _marty_rs.oid4vci_verify_pkce_s256(verifier, challenge) is True

    def test_pkce_s256_invalid(self):
        assert _marty_rs.oid4vci_verify_pkce_s256("wrong", "wrong") is False

# =========================================================================
# OID4VP Verification
# =========================================================================


class TestOID4VP:
    """Tests for VP token verification."""

    def test_verify_vp_token_invalid_jwt(self):
        """An invalid JWT should return valid=false with errors."""
        result_json = _marty_rs.oid4vp_verify_vp_token(
            "not.a.jwt", "nonce-123", "verifier-1"
        )
        result = json.loads(result_json)
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_verify_presentation_structure_is_scoped_low_level_evidence(self):
        definition = {
            "id": "definition-1",
            "input_descriptors": [
                {
                    "id": "credential-1",
                    "format": {"jwt_vc_json": {}},
                    "constraints": {},
                }
            ],
        }
        submission = {
            "id": "submission-1",
            "definition_id": "definition-1",
            "descriptor_map": [
                {
                    "id": "credential-1",
                    "format": "jwt_vc_json",
                    "path": "$",
                }
            ],
        }

        result = json.loads(
            _marty_rs.verify_presentation_structure(
                "verifier-1",
                "https://verifier.example/response",
                json.dumps(definition),
                json.dumps(submission),
            )
        )

        assert result["valid"] is False
        assert result["decision_ready"] is False
        assert result["check_valid"] is True
        assert result["scope"] == "presentation_structure"
        assert result["evidence"]["presentation_structure"] == "passed"

    def test_verify_presentation_structure_rejects_definition_mismatch(self):
        definition = {
            "id": "definition-1",
            "input_descriptors": [{"id": "credential-1", "constraints": {}}],
        }
        submission = {
            "id": "submission-1",
            "definition_id": "different-definition",
            "descriptor_map": [
                {
                    "id": "credential-1",
                    "format": "jwt_vc_json",
                    "path": "$",
                }
            ],
        }

        result = json.loads(
            _marty_rs.verify_presentation_structure(
                "verifier-1",
                "https://verifier.example/response",
                json.dumps(definition),
                json.dumps(submission),
            )
        )

        assert result["valid"] is False
        assert result["check_valid"] is False
        assert result["scope"] == "presentation_structure"
        assert result["errors"]
