"""Tests for _marty_rs Python bindings.

These tests exercise the PyO3 FFI surface. They require the native extension
to be built first:

    cd marty-core/marty-bindings
    maturin develop --release

Or for venv-based development:

    pip install -e ".[dev]"
"""

import json
import hashlib
import base64

import pytest

# All tests are skipped if the native extension hasn't been built yet.
_marty_rs = pytest.importorskip("marty_rs._marty_rs", reason="native extension not built")


# =========================================================================
# Key generation
# =========================================================================


class TestKeyGeneration:
    """Tests for key pair generation functions."""

    def test_generate_p256_returns_two_byte_strings(self):
        secret, public = _marty_rs.generate_p256_key()
        assert isinstance(secret, bytes)
        assert isinstance(public, bytes)

    def test_generate_p256_key_lengths(self):
        secret, public = _marty_rs.generate_p256_key()
        assert len(secret) == 32, "P-256 secret key must be 32 bytes"
        assert len(public) == 65, "P-256 uncompressed public key must be 65 bytes"

    def test_generate_p256_unique_keys(self):
        """Each call must produce a distinct key pair."""
        s1, _ = _marty_rs.generate_p256_key()
        s2, _ = _marty_rs.generate_p256_key()
        assert s1 != s2

    def test_generate_p384_key_lengths(self):
        secret, public = _marty_rs.generate_p384_key()
        assert len(secret) == 48, "P-384 secret key must be 48 bytes"
        assert len(public) == 97, "P-384 uncompressed public key must be 97 bytes"

    def test_generate_ed25519_key_lengths(self):
        secret, public = _marty_rs.generate_ed25519_key()
        assert len(secret) == 32
        assert len(public) == 32


# =========================================================================
# Signing and verification — round-trip
# =========================================================================


class TestSignAndVerify:
    """Sign-then-verify round-trip tests for each algorithm."""

    MESSAGE = b"The quick brown fox jumps over the lazy dog"

    # -- P-256 ----------------------------------------------------------------

    def test_p256_sign_verify_roundtrip(self):
        secret, public = _marty_rs.generate_p256_key()
        signature = _marty_rs.sign_p256(secret, self.MESSAGE)
        assert isinstance(signature, bytes)
        assert _marty_rs.verify_p256(public, self.MESSAGE, signature) is True

    def test_p256_wrong_message_fails(self):
        secret, public = _marty_rs.generate_p256_key()
        sig = _marty_rs.sign_p256(secret, self.MESSAGE)
        assert _marty_rs.verify_p256(public, b"tampered", sig) is False

    def test_p256_wrong_key_fails(self):
        secret, _ = _marty_rs.generate_p256_key()
        _, other_public = _marty_rs.generate_p256_key()
        sig = _marty_rs.sign_p256(secret, self.MESSAGE)
        assert _marty_rs.verify_p256(other_public, self.MESSAGE, sig) is False

    # -- P-384 ----------------------------------------------------------------

    def test_p384_sign_verify_roundtrip(self):
        secret, public = _marty_rs.generate_p384_key()
        sig = _marty_rs.sign_p384(secret, self.MESSAGE)
        assert _marty_rs.verify_p384(public, self.MESSAGE, sig) is True

    def test_p384_wrong_message_fails(self):
        secret, public = _marty_rs.generate_p384_key()
        sig = _marty_rs.sign_p384(secret, self.MESSAGE)
        assert _marty_rs.verify_p384(public, b"tampered", sig) is False

    # -- Ed25519 --------------------------------------------------------------

    def test_ed25519_sign_verify_roundtrip(self):
        secret, public = _marty_rs.generate_ed25519_key()
        sig = _marty_rs.sign_ed25519(secret, self.MESSAGE)
        assert isinstance(sig, bytes)
        assert len(sig) == 64, "Ed25519 signature must be 64 bytes"
        assert _marty_rs.verify_ed25519(public, self.MESSAGE, sig) is True

    def test_ed25519_wrong_message_fails(self):
        secret, public = _marty_rs.generate_ed25519_key()
        sig = _marty_rs.sign_ed25519(secret, self.MESSAGE)
        assert _marty_rs.verify_ed25519(public, b"tampered", sig) is False


# =========================================================================
# Error handling
# =========================================================================


class TestErrorHandling:
    """Verify that invalid inputs produce proper Python exceptions."""

    def test_sign_p256_bad_key_raises(self):
        with pytest.raises(RuntimeError):
            _marty_rs.sign_p256(b"too-short", b"msg")

    def test_sign_ed25519_bad_key_raises(self):
        with pytest.raises(RuntimeError):
            _marty_rs.sign_ed25519(b"x" * 16, b"msg")

    def test_create_vc_bad_json_raises_value_error(self):
        secret, _ = _marty_rs.generate_p256_key()
        with pytest.raises(ValueError, match="Invalid JSON"):
            _marty_rs.create_verifiable_credential("not json", secret, "key-1")


# =========================================================================
# Verifiable Credentials
# =========================================================================


class TestVerifiableCredentials:
    """Test the simplified create_verifiable_credential binding."""

    def test_create_vc_returns_valid_json(self):
        secret, _ = _marty_rs.generate_p256_key()
        cred = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "credentialSubject": {"name": "Alice"},
        }
        result = _marty_rs.create_verifiable_credential(
            json.dumps(cred), secret, "did:example:issuer#key-1"
        )
        vc = json.loads(result)
        assert "proof" in vc
        assert vc["proof"]["type"] == "EcdsaSecp256r1Signature2019"
        assert vc["proof"]["verificationMethod"] == "did:example:issuer#key-1"
        assert vc["proof"]["proofPurpose"] == "assertionMethod"
        assert "jws" in vc["proof"]


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
        assert "nonce" in resp

    def test_pkce_s256_valid(self):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert _marty_rs.oid4vci_verify_pkce_s256(verifier, challenge) is True

    def test_pkce_s256_invalid(self):
        assert _marty_rs.oid4vci_verify_pkce_s256("wrong", "wrong") is False

    def test_proof_jwt_roundtrip(self):
        """Create and verify a proof JWT."""
        jwt = _marty_rs.oid4vci_create_proof_jwt(self.ISSUER_URL, "nonce-xyz")
        assert jwt.count(".") == 2, "JWT must have 3 parts"

        holder_did, nonce = _marty_rs.oid4vci_verify_proof_jwt(
            jwt, "nonce-xyz", self.ISSUER_URL
        )
        assert holder_did.startswith("did:key:")
        assert nonce == "nonce-xyz"

    def test_proof_jwt_bad_nonce_fails(self):
        jwt = _marty_rs.oid4vci_create_proof_jwt(self.ISSUER_URL, "nonce-a")
        with pytest.raises(RuntimeError, match="[Nn]once"):
            _marty_rs.oid4vci_verify_proof_jwt(jwt, "nonce-b", None)


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
