//! Python bindings for Marty Core cryptographic operations.
//!
//! This crate provides Python bindings for essential cryptographic functions
//! from marty-crypto and marty-verification, focused on credential issuance and verification.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Convert marty_crypto errors to Python exceptions
fn to_pyerr(err: impl std::fmt::Display) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(err.to_string())
}

// ============================================================================
// Key Generation
// ============================================================================

/// Generate a P-256 ECDSA key pair for signing credentials.
///
/// Returns:
///     Tuple of (private_key, public_key) as bytes.
///     Private key is 32 bytes, public key is 65 bytes (uncompressed).
///
/// Example:
///     >>> secret, public = generate_p256_key()
#[pyfunction]
fn generate_p256_key<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ecdsa::generate_p256_keypair().map_err(to_pyerr)?;
    Ok((PyBytes::new_bound(py, &secret), PyBytes::new_bound(py, &public)))
}

/// Generate a P-384 ECDSA key pair for signing credentials.
///
/// Returns:
///     Tuple of (private_key, public_key) as bytes.
///     Private key is 48 bytes, public key is 97 bytes (uncompressed).
#[pyfunction]
fn generate_p384_key<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ecdsa::generate_p384_keypair().map_err(to_pyerr)?;
    Ok((PyBytes::new_bound(py, &secret), PyBytes::new_bound(py, &public)))
}

/// Generate an Ed25519 key pair for signing credentials.
///
/// Returns:
///     Tuple of (private_key, public_key) as bytes.
///     Both keys are 32 bytes.
#[pyfunction]
fn generate_ed25519_key<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ed25519::generate_keypair();
    Ok((PyBytes::new_bound(py, &secret), PyBytes::new_bound(py, &public)))
}

// ============================================================================
// Signing
// ============================================================================

/// Sign a message with ECDSA P-256 SHA-256 (ES256).
///
/// Args:
///     secret_key: 32-byte private key
///     message: Message to sign
///
/// Returns:
///     DER-encoded signature
///
/// Example:
///     >>> secret, _ = generate_p256_key()
///     >>> signature = sign_p256(secret, b"Hello, World!")
#[pyfunction]
fn sign_p256<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::ecdsa::sign_p256_sha256(secret_key, message).map_err(to_pyerr)?;
    Ok(PyBytes::new_bound(py, &signature))
}

/// Sign a message with ECDSA P-384 SHA-384 (ES384).
///
/// Args:
///     secret_key: 48-byte private key
///     message: Message to sign
///
/// Returns:
///     DER-encoded signature
#[pyfunction]
fn sign_p384<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::ecdsa::sign_p384_sha384(secret_key, message).map_err(to_pyerr)?;
    Ok(PyBytes::new_bound(py, &signature))
}

/// Sign a message with Ed25519.
///
/// Args:
///     secret_key: 32-byte private key
///     message: Message to sign
///
/// Returns:
///     64-byte signature
#[pyfunction]
fn sign_ed25519<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::ed25519::sign(secret_key, message).map_err(to_pyerr)?;
    Ok(PyBytes::new_bound(py, &signature))
}

// ============================================================================
// Verification
// ============================================================================

/// Verify an ECDSA P-256 SHA-256 signature.
///
/// Args:
///     public_key: DER-encoded public key or raw SEC1 format
///     message: Original message
///     signature: DER-encoded signature
///
/// Returns:
///     True if signature is valid, False otherwise
#[pyfunction]
fn verify_p256(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    marty_crypto::ecdsa::verify_p256_sha256(public_key, message, signature).map_err(to_pyerr)
}

/// Verify an ECDSA P-384 SHA-384 signature.
///
/// Args:
///     public_key: DER-encoded public key or raw SEC1 format
///     message: Original message
///     signature: DER-encoded signature
///
/// Returns:
///     True if signature is valid, False otherwise
#[pyfunction]
fn verify_p384(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    marty_crypto::ecdsa::verify_p384_sha384(public_key, message, signature).map_err(to_pyerr)
}

/// Verify an Ed25519 signature.
///
/// Args:
///     public_key: 32-byte public key
///     message: Original message
///     signature: 64-byte signature
///
/// Returns:
///     True if signature is valid, False otherwise
#[pyfunction]
fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    Ok(marty_crypto::ed25519::verify_bool(public_key, message, signature))
}

// ============================================================================
// Verifiable Credentials (Simplified)
// ============================================================================

/// Create a simple signed verifiable credential.
///
/// Args:
///     credential_json: JSON string of the credential (without proof)
///     secret_key: 32-byte P-256 private key
///     key_id: Key identifier (e.g., "did:example:123#key-1")
///
/// Returns:
///     JSON string of the credential with embedded proof
///
/// Note: This is a simplified implementation. For production, use full
///       VC-JWT or VC-LD proofs with proper DID resolution.
#[pyfunction]
fn create_verifiable_credential(
    credential_json: &str,
    secret_key: &[u8],
    key_id: &str,
) -> PyResult<String> {
    use serde_json::{json, Value};
    
    // Parse the credential
    let mut credential: Value = serde_json::from_str(credential_json)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid JSON: {}", e)))?;
    
    // Sign the credential (simplified - just sign the JSON bytes)
    let message = credential_json.as_bytes();
    let signature = marty_crypto::ecdsa::sign_p256_sha256(secret_key, message)
        .map_err(to_pyerr)?;
    
    // Encode signature as base64url
    let signature_b64 = base64_url_encode(&signature);
    
    // Add proof to credential
    credential["proof"] = json!({
        "type": "EcdsaSecp256r1Signature2019",
        "created": chrono::Utc::now().to_rfc3339(),
        "verificationMethod": key_id,
        "proofPurpose": "assertionMethod",
        "jws": signature_b64
    });
    
    serde_json::to_string_pretty(&credential)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("JSON serialization failed: {e}")))
}

/// Helper function to encode bytes as base64url (no padding)
fn base64_url_encode(data: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

// ============================================================================
// OID4VCI Protocol Functions
//
// These thin wrappers delegate entirely to the marty-oid4vci crate so Python
// never re-implements protocol logic.  All functions take/return JSON strings
// for easy interop across the FFI boundary.
// ============================================================================

/// Build a minimal IssuerConfig for stateless engine methods that don't
/// reference config fields (authorization response, token exchange, etc.).
fn _dummy_engine() -> marty_oid4vci::IssuanceEngine {
    use marty_oid4vci::types::*;
    let config = IssuerConfig {
        credential_issuer_url: String::new(),
        issuer_name: String::new(),
        credential_types: vec![],
        issuer_key: IssuerKey {
            issuer_id: String::new(),
            jwk_json: String::new(),
            algorithm: SigningAlgorithm::EdDSA,
        },
        token_endpoint: None,
        credential_endpoint: None,
        authorization_endpoint: None,
        deferred_credential_endpoint: None,
        binding_methods: vec![],
        proof_signing_alg_values: vec![],
    };
    marty_oid4vci::IssuanceEngine::new(config)
}

/// Create a credential offer as a JSON string.
///
/// Args:
///     issuer_url: Credential issuer base URL
///     credential_types: List of credential configuration IDs
///     pre_authorized_code: Optional pre-authorized code (omit for auth code flow)
///     user_pin_required: Whether a PIN/tx_code is required
///
/// Returns:
///     JSON-serialized CredentialOffer
#[pyfunction]
#[pyo3(signature = (issuer_url, credential_types, pre_authorized_code=None, user_pin_required=false))]
fn oid4vci_create_credential_offer(
    issuer_url: &str,
    credential_types: Vec<String>,
    pre_authorized_code: Option<String>,
    user_pin_required: bool,
) -> PyResult<String> {
    marty_oid4vci::issuer::create_credential_offer(
        issuer_url,
        &credential_types,
        pre_authorized_code.as_deref(),
        user_pin_required,
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        format!("Offer creation error: {e}"),
    ))
}

/// Create a token response for a pre-authorized code exchange.
///
/// Generates a fresh access_token + c_nonce without performing DB lookups.
/// The caller is responsible for validating the pre-auth code, checking
/// expiry, and persisting the returned token/nonce.
///
/// Args:
///     pre_authorized_code: The pre-authorized code being exchanged
///     token_lifetime_secs: Token validity in seconds (e.g. 1800)
///
/// Returns:
///     JSON-serialized TokenResponse
#[pyfunction]
fn oid4vci_create_token_response(
    pre_authorized_code: &str,
    token_lifetime_secs: u64,
) -> PyResult<String> {
    let engine = _dummy_engine();
    let resp = engine
        .create_token_response(pre_authorized_code, token_lifetime_secs)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Token response error: {e}"),
        ))?;
    Ok(serde_json::to_string(&resp).map_err(to_pyerr)?)
}

/// Create an OID4VCI authorization response from an authorization request.
///
/// Validates the request (response_type, PKCE params) and generates a fresh
/// authorization code + session via the Rust engine.
///
/// Args:
///     request_json: JSON-serialized AuthorizationRequest
///     session_lifetime_secs: Session validity in seconds (e.g. 600)
///
/// Returns:
///     Tuple of (authorization_response_json, authorization_session_json)
#[pyfunction]
fn oid4vci_create_authorization_response(
    request_json: &str,
    session_lifetime_secs: u64,
) -> PyResult<(String, String)> {
    use marty_oid4vci::types::AuthorizationRequest;

    let request: AuthorizationRequest = serde_json::from_str(request_json)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Invalid AuthorizationRequest JSON: {e}"),
        ))?;

    let engine = _dummy_engine();
    let (response, session) = engine
        .create_authorization_response(&request, session_lifetime_secs)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Authorization error: {e}"),
        ))?;

    let resp_json = serde_json::to_string(&response).map_err(to_pyerr)?;
    let sess_json = serde_json::to_string(&session).map_err(to_pyerr)?;
    Ok((resp_json, sess_json))
}

/// Exchange an authorization code for a token response.
///
/// Validates grant_type, redirect_uri match, and PKCE code_verifier (S256)
/// via the Rust engine.
///
/// Args:
///     request_json: JSON-serialized AuthorizationCodeTokenRequest
///     session_json: JSON-serialized AuthorizationSession (from DB)
///     token_lifetime_secs: Token validity in seconds (e.g. 1800)
///
/// Returns:
///     JSON-serialized TokenResponse
#[pyfunction]
fn oid4vci_exchange_auth_code_for_token(
    request_json: &str,
    session_json: &str,
    token_lifetime_secs: u64,
) -> PyResult<String> {
    use marty_oid4vci::types::{AuthorizationCodeTokenRequest, AuthorizationSession};

    let request: AuthorizationCodeTokenRequest = serde_json::from_str(request_json)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Invalid AuthorizationCodeTokenRequest JSON: {e}"),
        ))?;
    let session: AuthorizationSession = serde_json::from_str(session_json)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Invalid AuthorizationSession JSON: {e}"),
        ))?;

    let engine = _dummy_engine();
    let token_response = engine
        .create_token_response_for_auth_code(&request, &session, token_lifetime_secs)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Token exchange error: {e}"),
        ))?;

    Ok(serde_json::to_string(&token_response).map_err(to_pyerr)?)
}

/// Verify a PKCE S256 code_verifier against a code_challenge.
///
/// Returns:
///     True if verification passes
#[pyfunction]
fn oid4vci_verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> bool {
    marty_oid4vci::verify_pkce_s256(code_verifier, code_challenge)
}

/// Create a spec-correct OID4VCI proof-of-possession JWT (OID4VCI §8.2).
///
/// Generates an ephemeral Ed25519 key pair, derives a `did:key` from it, and
/// returns a compact JWT signed with that key.  Suitable for wallet clients
/// and integration tests that need a real, verifiable proof of possession.
///
/// Args:
///     aud: Credential issuer URL (audience), e.g. "http://localhost:8005/org/<org_id>"
///     c_nonce: The c_nonce value from the token response
///
/// Returns:
///     Compact JWT string (`header.payload.signature`)
///
/// Raises:
///     `RuntimeError` on key generation or signing failure
#[pyfunction]
fn oid4vci_create_proof_jwt(aud: &str, c_nonce: &str) -> PyResult<String> {
    marty_oid4vci::proof::create_proof_jwt(aud, c_nonce)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Proof JWT creation failed: {e}")))
}

/// Verify an OID4VCI proof-of-possession JWT.
///
/// Performs full OID4VCI §8.2 verification:
/// - JWT structure and `typ` header
/// - Cryptographic signature (Ed25519 or P-256)
/// - `did:key` resolution from `kid` — no network I/O required
/// - `nonce` claim matches `expected_c_nonce` when provided
/// - `aud` matches `issuer_url` when non-empty
/// - `iat` present and not older than 5 minutes; `exp` not elapsed
///
/// Args:
///     proof_jwt: Compact JWT from the credential request `proof.jwt`
///     expected_c_nonce: c_nonce the wallet should have bound into the proof
///     issuer_url: Expected `aud` — omit or pass `""` to skip the aud check
///
/// Returns:
///     `(holder_did, nonce)` tuple on success
///
/// Raises:
///     `RuntimeError` on any verification failure
#[pyfunction]
#[pyo3(signature = (proof_jwt, expected_c_nonce=None, issuer_url=None))]
fn oid4vci_verify_proof_jwt(
    proof_jwt: &str,
    expected_c_nonce: Option<&str>,
    issuer_url: Option<&str>,
) -> PyResult<(String, Option<String>)> {
    let url = issuer_url.unwrap_or("");
    let verified = marty_oid4vci::proof::verify_jwt_proof(proof_jwt, url, expected_c_nonce, 300)
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Proof JWT verification failed: {e}"
            ))
        })?;
    Ok((verified.holder_id, verified.nonce))
}

/// Create an OID4VCI format-aware verifiable credential via the Rust signing engine.
///
/// Supports all credential formats: jwt_vc_json, vc+sd-jwt, mso_mdoc, zk_mdoc.
/// Delegates entirely to marty-oid4vci — no protocol logic lives in Python.
///
/// Args:
///     issuer_id: Issuer DID (e.g. "did:key:z6Mk...")
///     jwk_json: Issuer signing key as a JWK JSON string (OKP/Ed25519 or EC/P-256)
///     subject_id: Optional holder DID
///     credential_type: Credential type string
///     claims_json: JSON object of credential subject claims
///     expiration_seconds: Optional validity in seconds
///     format: Credential wire format ("jwt_vc_json", "vc+sd-jwt", "mso_mdoc", "zk_mdoc")
///     selective_disclosure_claims: Claims to make selectively disclosable (SD-JWT only)
///     zk_predicate_claims: Claims eligible for ZK predicate proofs (zk_mdoc only)
///     credential_payload_format: SD-JWT payload structure ("ietf_sd_jwt" or "w3c_vcdm_v2_sd_jwt")
///     w3c_context: Additional @context URIs for W3C VCDM v2 payloads
///     w3c_types: Additional type values for W3C VCDM v2 payloads
///
/// Returns:
///     (credential_string, credential_id)
#[pyfunction]
#[pyo3(signature = (issuer_id, jwk_json, subject_id, credential_type, claims_json, expiration_seconds=None, format="jwt_vc_json", selective_disclosure_claims=vec![], zk_predicate_claims=vec![], credential_payload_format="w3c_vcdm_v2_sd_jwt", w3c_context=vec![], w3c_types=vec![]))]
fn oid4vci_sign_credential(
    issuer_id: &str,
    jwk_json: &str,
    subject_id: Option<&str>,
    credential_type: &str,
    claims_json: &str,
    expiration_seconds: Option<i64>,
    format: &str,
    selective_disclosure_claims: Vec<String>,
    zk_predicate_claims: Vec<String>,
    credential_payload_format: &str,
    w3c_context: Vec<String>,
    w3c_types: Vec<String>,
) -> PyResult<(String, String)> {
    use marty_oid4vci::types::{CredentialClaims, CredentialFormat, CredentialPayloadFormat, IssuerKey, SignedCredential};
    use marty_oid4vci::formats;

    let claims: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_str(claims_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid claims JSON: {e}"))
        })?;

    let algorithm = marty_oid4vci::issuer::detect_algorithm(jwk_json)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Key error: {e}")))?
;
    let issuer_key = IssuerKey {
        issuer_id: issuer_id.to_string(),
        jwk_json: jwk_json.to_string(),
        algorithm,
    };

    let zk_predicate_bindings = normalize_zk_predicate_claims(&claims, zk_predicate_claims);

    let cred_claims = CredentialClaims {
        subject_id: subject_id.map(String::from),
        credential_type: credential_type.to_string(),
        claims,
        expiration_seconds,
        selective_disclosure_claims,
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: zk_predicate_bindings,
        credential_payload_format: CredentialPayloadFormat::from_str_loose(credential_payload_format),
        w3c_context,
        w3c_types,
    };

    let cred_format = CredentialFormat::from_str_loose(format)
        .unwrap_or(CredentialFormat::JwtVcJson);

    let signed = formats::sign_credential(&cred_format, &issuer_key, &cred_claims)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Signing error: {e}")))?
;
    let credential_str = match &signed {
        SignedCredential::JwtVcJson { jwt, .. } => jwt.clone(),
        SignedCredential::SdJwt { compact, .. } => compact.clone(),
        SignedCredential::MsoMdoc { issuer_signed_b64, .. } => issuer_signed_b64.clone(),
        SignedCredential::ZkMdoc { issuer_signed_b64, .. } => issuer_signed_b64.clone(),
    };

    Ok((credential_str, signed.credential_id().to_string()))
}

/// Prepare a credential for external signing (BYOK).
///
/// Returns a tuple of (signing_input_base64, credential_id, format_hint).
/// The caller signs `signing_input` externally and passes the result to
/// `oid4vci_assemble_credential()`.
#[pyfunction]
#[pyo3(signature = (issuer_id, algorithm, subject_id, credential_type, claims_json, expiration_seconds=None, format="jwt_vc_json", selective_disclosure_claims=vec![], credential_payload_format="w3c_vcdm_v2_sd_jwt", w3c_context=vec![], w3c_types=vec![]))]
fn oid4vci_prepare_credential(
    issuer_id: &str,
    algorithm: &str,
    subject_id: Option<&str>,
    credential_type: &str,
    claims_json: &str,
    expiration_seconds: Option<i64>,
    format: &str,
    selective_disclosure_claims: Vec<String>,
    credential_payload_format: &str,
    w3c_context: Vec<String>,
    w3c_types: Vec<String>,
) -> PyResult<(String, String, String)> {
    use marty_oid4vci::types::{CredentialClaims, CredentialFormat, CredentialPayloadFormat, SigningAlgorithm};
    use marty_oid4vci::signer::CredentialSigner;

    let claims: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_str(claims_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid claims JSON: {e}"))
        })?;

    let signing_algorithm = match algorithm {
        "ES256" => SigningAlgorithm::ES256,
        "EdDSA" => SigningAlgorithm::EdDSA,
        "ES256K" => SigningAlgorithm::ES256K,
        "ES384" => SigningAlgorithm::ES384,
        "RS256" => SigningAlgorithm::RS256,
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Unknown algorithm: {algorithm}")
        )),
    };

    // Create a stub signer that provides metadata but cannot sign
    // (signing will happen externally)
    #[derive(Debug)]
    struct MetadataSigner {
        issuer_id: String,
        algorithm: SigningAlgorithm,
    }
    impl CredentialSigner for MetadataSigner {
        fn sign(&self, _message: &[u8]) -> marty_oid4vci::Oid4vciResult<Vec<u8>> {
            unreachable!("MetadataSigner.sign() should not be called during prepare")
        }
        fn algorithm(&self) -> SigningAlgorithm { self.algorithm }
        fn issuer_id(&self) -> &str { &self.issuer_id }
        fn kid_url(&self) -> String {
            if let Some(key_part) = self.issuer_id.strip_prefix("did:key:") {
                format!("{}#{}", self.issuer_id, key_part)
            } else {
                self.issuer_id.clone()
            }
        }
    }

    let signer = MetadataSigner {
        issuer_id: issuer_id.to_string(),
        algorithm: signing_algorithm,
    };

    let cred_claims = CredentialClaims {
        subject_id: subject_id.map(String::from),
        credential_type: credential_type.to_string(),
        claims,
        expiration_seconds,
        selective_disclosure_claims,
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        credential_payload_format: CredentialPayloadFormat::from_str_loose(credential_payload_format),
        w3c_context,
        w3c_types,
    };

    let cred_format = CredentialFormat::from_str_loose(format)
        .unwrap_or(CredentialFormat::JwtVcJson);

    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    match cred_format {
        CredentialFormat::JwtVcJson => {
            let prepared = marty_oid4vci::formats::jwt_vc::prepare_jwt_vc(&signer, &cred_claims)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e}")))?;
            // signing_input is already a string (header_b64.payload_b64)
            Ok((prepared.signing_input, prepared.credential_id, "jwt_vc_json".to_string()))
        }
        CredentialFormat::MsoMdoc => {
            let prepared = marty_oid4vci::formats::mdoc::prepare_mdoc(&signer, &cred_claims)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e}")))?;
            // tbs_data is raw bytes — base64url encode for transport
            let tbs_b64 = b64.encode(&prepared.tbs_data);
            Ok((tbs_b64, prepared.credential_id, "mso_mdoc".to_string()))
        }
        _ => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Format '{}' does not support prepare/assemble yet", format)
        )),
    }
}

/// Assemble a signed credential from prepared data and an external signature.
///
/// Takes the signing_input (from prepare), signature bytes (base64url), and
/// format/credential_id. Returns (credential_str, credential_id).
#[pyfunction]
#[pyo3(signature = (signing_input, signature_b64, credential_id, format))]
fn oid4vci_assemble_credential(
    signing_input: &str,
    signature_b64: &str,
    credential_id: &str,
    format: &str,
) -> PyResult<(String, String)> {
    use marty_oid4vci::types::SignedCredential;
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let signature = b64.decode(signature_b64).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid signature base64: {e}"))
    })?;

    match format {
        "jwt_vc_json" => {
            let prepared = marty_oid4vci::formats::jwt_vc::PreparedJwtVc {
                signing_input: signing_input.to_string(),
                credential_id: credential_id.to_string(),
            };
            let signed = marty_oid4vci::formats::jwt_vc::assemble_jwt_vc(prepared, &signature);
            match signed {
                SignedCredential::JwtVcJson { jwt, credential_id } => {
                    Ok((jwt, credential_id))
                }
                _ => unreachable!(),
            }
        }
        _ => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Format '{}' assemble not yet supported via FFI", format)
        )),
    }
}

/// Normalize legacy Python input (`List[str]`) into typed ZK predicate bindings.
fn normalize_zk_predicate_claims(
    claims: &std::collections::HashMap<String, serde_json::Value>,
    raw: Vec<String>,
) -> Vec<marty_oid4vci::types::ZkPredicateBinding> {
    if raw.is_empty() {
        return vec![];
    }

    let mut json_bindings: Vec<marty_oid4vci::types::ZkPredicateBinding> = Vec::new();
    let mut all_json_bindings = true;
    for item in &raw {
        match serde_json::from_str::<marty_oid4vci::types::ZkPredicateBinding>(item) {
            Ok(binding) if !binding.claim_name.is_empty() && !binding.supported_predicates.is_empty() => {
                json_bindings.push(binding);
            }
            _ => {
                all_json_bindings = false;
                break;
            }
        }
    }
    if all_json_bindings {
        return json_bindings;
    }

    let mut claim_names: Vec<String> = Vec::new();
    let mut predicates: Vec<String> = Vec::new();
    for item in &raw {
        if claims.contains_key(item) {
            claim_names.push(item.clone());
        } else {
            predicates.push(item.clone());
        }
    }

    if !claim_names.is_empty() {
        let fallback_predicates = if predicates.is_empty() {
            claim_names.clone()
        } else {
            predicates.clone()
        };

        return claim_names
            .into_iter()
            .map(|claim_name| marty_oid4vci::types::ZkPredicateBinding::multi(claim_name, fallback_predicates.clone()))
            .collect();
    }

    if !predicates.is_empty() {
        if claims.contains_key("birth_date") {
            return vec![marty_oid4vci::types::ZkPredicateBinding::multi("birth_date", predicates)];
        }
        if let Some(first_claim_name) = claims.keys().next() {
            return vec![marty_oid4vci::types::ZkPredicateBinding::multi(first_claim_name.clone(), predicates)];
        }
    }

    raw.into_iter()
        .map(|name| marty_oid4vci::types::ZkPredicateBinding::single(name.clone(), name))
        .collect()
}

// ============================================================================
// OID4VP Verification
// ============================================================================

/// Verify an OID4VP VP JWT token.
///
/// Validates the JWT signature (when the holder public key is embedded in the
/// token via `jwk` header, `cnf.jwk`, or `sub_jwk`), the nonce, the audience,
/// and the expiry.
///
/// Args:
///     vp_token: The compact-serialised VP JWT (or SD-JWT presentation).
///     expected_nonce: The nonce from the authorization request.
///     verifier_id: The verifier's client_id / audience value.
///
/// Returns:
///     JSON object `{ "valid": bool, "errors": [str] }`.
#[pyfunction]
fn oid4vp_verify_vp_token(
    vp_token: &str,
    expected_nonce: &str,
    verifier_id: &str,
) -> PyResult<String> {
    use marty_oid4vci::verifier::VerificationEngine;
    // Pass verifier_id as both verifier_id and response_uri — the engine uses
    // verifier_id as the expected `aud` claim value.
    let engine = VerificationEngine::new(verifier_id, verifier_id);
    let result = engine.verify_vp_token(vp_token, expected_nonce);
    serde_json::to_string(&result)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Serialization error: {e}")))
}

// ============================================================================
// Symmetric Crypto (AES-CBC, HMAC, SHA-256) — EAC secure messaging support
// ============================================================================

/// AES-256-CBC encrypt with PKCS7 padding.
#[pyfunction]
fn aes_256_cbc_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let ct = marty_crypto::symmetric::aes_256_cbc_encrypt(key, iv, plaintext)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &ct))
}

/// AES-256-CBC decrypt with PKCS7 padding.
#[pyfunction]
fn aes_256_cbc_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let pt = marty_crypto::symmetric::aes_256_cbc_decrypt(key, iv, ciphertext)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &pt))
}

/// HMAC-SHA256.
#[pyfunction]
fn hmac_sha256<'py>(
    py: Python<'py>,
    key: &[u8],
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let mac = marty_crypto::symmetric::hmac_sha256(key, data)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &mac))
}

/// SHA-256 hash.
#[pyfunction]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let digest = marty_crypto::hashing::hash_sha256(data);
    Ok(PyBytes::new_bound(py, &digest))
}

// ============================================================================
// DIDComm v2
// ============================================================================

/// Resolve a DID to its DID Document (JSON string).
///
/// Supports did:key, did:web, did:peer, did:jwk.
/// Does NOT support ledger-based methods (did:ion, did:ethr, did:sov).
///
/// Args:
///     did: The DID to resolve
///     universal_resolver_url: Optional URL to a Universal Resolver for unsupported methods
///
/// Returns:
///     JSON string of the DID Document
#[pyfunction]
#[pyo3(signature = (did, universal_resolver_url=None))]
fn didcomm_resolve_did(did: &str, universal_resolver_url: Option<&str>) -> PyResult<String> {
    let rt = tokio::runtime::Runtime::new().map_err(to_pyerr)?;
    let resolver = match universal_resolver_url {
        Some(url) => marty_didcomm::DidResolver::with_universal_resolver(url),
        None => marty_didcomm::DidResolver::new(),
    };
    let doc = rt.block_on(resolver.resolve(did)).map_err(to_pyerr)?;
    serde_json::to_string(&doc).map_err(to_pyerr)
}

/// Extract the DIDComm service endpoint URI from a DID Document JSON.
///
/// Args:
///     did_document_json: JSON string of the DID Document
///
/// Returns:
///     The service endpoint URI string, or empty string if none found
#[pyfunction]
fn didcomm_extract_endpoint(did_document_json: &str) -> PyResult<String> {
    let doc: marty_didcomm::DidDocument =
        serde_json::from_str(did_document_json).map_err(to_pyerr)?;
    Ok(doc.didcomm_endpoint().unwrap_or("").to_string())
}

/// Pack a signed credential into a DIDComm v2 plaintext message.
///
/// Creates an issue-credential/3.0 message with the credential as an attachment.
/// The caller is responsible for delivering this to the holder's endpoint.
///
/// Args:
///     credential: The signed credential string (SD-JWT, JWT, or base64 mDoc)
///     format: Credential format (e.g. "vc+sd-jwt", "mso_mdoc", "jwt_vc_json")
///     issuer_did: The issuer's DID
///     holder_did: The holder/recipient DID
///     thread_id: Optional thread ID for correlation
///     credential_id: Optional credential identifier
///
/// Returns:
///     JSON string of the DIDComm plaintext message
#[pyfunction]
#[pyo3(signature = (credential, format, issuer_did, holder_did, thread_id=None, credential_id=None))]
fn didcomm_pack_credential(
    credential: &str,
    format: &str,
    issuer_did: &str,
    holder_did: &str,
    thread_id: Option<&str>,
    credential_id: Option<&str>,
) -> PyResult<String> {
    marty_didcomm::pack_credential_for_holder(
        credential,
        format,
        issuer_did,
        holder_did,
        thread_id,
        credential_id,
    )
    .map_err(to_pyerr)
}

/// Unpack a DIDComm v2 plaintext message and return its JSON representation.
///
/// Args:
///     message_json: The DIDComm plaintext message JSON string
///
/// Returns:
///     Parsed message as JSON string (validated structure)
#[pyfunction]
fn didcomm_unpack_message(message_json: &str) -> PyResult<String> {
    let msg = marty_didcomm::unpack_didcomm_message(message_json).map_err(to_pyerr)?;
    serde_json::to_string(&msg).map_err(to_pyerr)
}

/// Encrypt a DIDComm v2 plaintext message for a recipient using ECDH-ES+A256KW + A256GCM.
///
/// Args:
///     plaintext_json: The DIDComm plaintext message (JSON string)
///     recipient_did_document_json: The recipient's DID Document (JSON string)
///
/// Returns:
///     JWE JSON Serialization (General) string
#[pyfunction]
fn didcomm_encrypt(plaintext_json: &str, recipient_did_document_json: &str) -> PyResult<String> {
    let did_doc: marty_didcomm::DidDocument =
        serde_json::from_str(recipient_did_document_json).map_err(to_pyerr)?;
    marty_didcomm::encrypt_for_recipient(plaintext_json, &did_doc).map_err(to_pyerr)
}

/// Decrypt a DIDComm v2 JWE (anoncrypt) message using the recipient's X25519 private key.
///
/// Args:
///     jwe_json: JWE JSON Serialization string
///     recipient_x25519_private_key: 32-byte X25519 private key
///
/// Returns:
///     Decrypted plaintext (JSON string)
#[pyfunction]
fn didcomm_decrypt(jwe_json: &str, recipient_x25519_private_key: &[u8]) -> PyResult<String> {
    if recipient_x25519_private_key.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "X25519 private key must be exactly 32 bytes",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(recipient_x25519_private_key);
    marty_didcomm::decrypt_jwe(jwe_json, &key).map_err(to_pyerr)
}

// ============================================================================
// Module Definition
// ============================================================================

/// Python module for Marty cryptographic operations.
///
/// This module provides essential cryptographic functions for credential
/// issuance and verification:
///
/// - Key generation: generate_p256_key, generate_p384_key, generate_ed25519_key
/// - Signing: sign_p256, sign_p384, sign_ed25519
/// - Verification: verify_p256, verify_p384, verify_ed25519
/// - Credentials: create_verifiable_credential
///
/// Example:
///     >>> import _marty_rs
///     >>> secret, public = _marty_rs.generate_p256_key()
///     >>> signature = _marty_rs.sign_p256(secret, b"Hello!")
///     >>> _marty_rs.verify_p256(public, b"Hello!", signature)
///     True
#[pymodule]
fn _marty_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Key Generation
    m.add_function(wrap_pyfunction!(generate_p256_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_p384_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_ed25519_key, m)?)?;
    
    // Signing
    m.add_function(wrap_pyfunction!(sign_p256, m)?)?;
    m.add_function(wrap_pyfunction!(sign_p384, m)?)?;
    m.add_function(wrap_pyfunction!(sign_ed25519, m)?)?;
    
    // Verification
    m.add_function(wrap_pyfunction!(verify_p256, m)?)?;
    m.add_function(wrap_pyfunction!(verify_p384, m)?)?;
    m.add_function(wrap_pyfunction!(verify_ed25519, m)?)?;
    
    // Verifiable Credentials
    m.add_function(wrap_pyfunction!(create_verifiable_credential, m)?)?;
    
    // OID4VCI Protocol
    m.add_function(wrap_pyfunction!(oid4vci_create_credential_offer, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_create_token_response, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_create_authorization_response, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_exchange_auth_code_for_token, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_verify_pkce_s256, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_create_proof_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_verify_proof_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_sign_credential, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_prepare_credential, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_assemble_credential, m)?)?;

    // OID4VP Protocol
    m.add_function(wrap_pyfunction!(oid4vp_verify_vp_token, m)?)?;

    // Symmetric Crypto (EAC secure messaging)
    m.add_function(wrap_pyfunction!(aes_256_cbc_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_256_cbc_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(sha256, m)?)?;

    // DIDComm v2
    m.add_function(wrap_pyfunction!(didcomm_resolve_did, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_extract_endpoint, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_pack_credential, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_unpack_message, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_decrypt, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // Helper function tests (pure Rust — no Python interpreter needed)
    // ====================================================================

    #[test]
    fn test_base64_url_encode_empty() {
        assert_eq!(base64_url_encode(&[]), "");
    }

    #[test]
    fn test_base64_url_encode_known_vector() {
        // RFC 4648 test vector
        let encoded = base64_url_encode(b"Hello, World!");
        assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ");
        // Verify no padding characters
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_base64_url_encode_binary() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = base64_url_encode(&data);
        // URL-safe: no '+' or '/'
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    // ====================================================================
    // Credential offer creation (delegates to marty-oid4vci, no PyO3)
    // ====================================================================

    #[test]
    fn test_credential_offer_single_type() {
        let json_str = marty_oid4vci::issuer::create_credential_offer(
            "https://issuer.example.com",
            &["VerifiableId".to_string()],
            Some("pre-auth-123"),
            false,
        )
        .expect("offer creation should succeed");
        let offer: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(
            offer["credential_issuer"],
            "https://issuer.example.com"
        );
        assert!(offer["credential_configuration_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "VerifiableId"));
    }

    #[test]
    fn test_credential_offer_multiple_types() {
        let json_str = marty_oid4vci::issuer::create_credential_offer(
            "https://issuer.example.com",
            &["VerifiableId".to_string(), "mDL".to_string()],
            None,
            false,
        )
        .expect("offer should succeed without pre-auth code");
        let offer: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let ids = offer["credential_configuration_ids"].as_array().unwrap();
        assert_eq!(ids.len(), 2);
    }

    // ====================================================================
    // Token response (via engine, no PyO3)
    // ====================================================================

    #[test]
    fn test_token_response_structure() {
        let engine = _dummy_engine();
        let resp = engine
            .create_token_response("pre-auth-abc", 1800)
            .expect("token response should succeed");
        let json_str = serde_json::to_string(&resp).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert!(val.get("access_token").is_some(), "must contain access_token");
        assert!(val.get("nonce").is_some(), "must contain nonce");
        assert_eq!(val["token_type"], "Bearer");
    }

    // ====================================================================
    // PKCE S256 verification (pure Rust)
    // ====================================================================

    #[test]
    fn test_pkce_s256_valid() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let hash = marty_crypto::hashing::hash_sha256(verifier.as_bytes());
        let challenge = base64_url_encode(&hash);

        assert!(
            marty_oid4vci::verify_pkce_s256(verifier, &challenge),
            "valid PKCE pair must verify"
        );
    }

    #[test]
    fn test_pkce_s256_invalid() {
        assert!(
            !marty_oid4vci::verify_pkce_s256("wrong-verifier", "wrong-challenge"),
            "mismatched PKCE pair must fail"
        );
    }

    // ====================================================================
    // Proof JWT round-trip (pure Rust)
    // ====================================================================

    #[test]
    fn test_proof_jwt_create_and_verify() {
        let aud = "https://issuer.example.com";
        let c_nonce = "test-nonce-12345";

        let jwt = marty_oid4vci::proof::create_proof_jwt(aud, c_nonce)
            .expect("proof JWT creation should succeed");

        // JWT should have 3 dot-separated parts
        assert_eq!(jwt.split('.').count(), 3, "JWT must have header.payload.signature");

        // Verify it round-trips
        let verified = marty_oid4vci::proof::verify_jwt_proof(&jwt, aud, Some(c_nonce), 300)
            .expect("proof JWT verification should succeed");

        assert!(
            verified.holder_id.starts_with("did:key:"),
            "holder_did should be a did:key, got: {}",
            verified.holder_id
        );
        assert_eq!(verified.nonce.as_deref(), Some(c_nonce));
    }

    #[test]
    fn test_proof_jwt_wrong_nonce_fails() {
        let jwt = marty_oid4vci::proof::create_proof_jwt("https://issuer.example.com", "nonce-a")
            .expect("creation should succeed");

        let result = marty_oid4vci::proof::verify_jwt_proof(&jwt, "", Some("nonce-b"), 300);
        assert!(result.is_err(), "wrong nonce must fail verification");
    }

    // ====================================================================
    // normalize_zk_predicate_claims (pure Rust helper)
    // ====================================================================

    #[test]
    fn test_normalize_zk_empty_input() {
        let claims = std::collections::HashMap::new();
        let result = normalize_zk_predicate_claims(&claims, vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_normalize_zk_claim_names_input() {
        let mut claims = std::collections::HashMap::new();
        claims.insert("birth_date".to_string(), serde_json::json!("1990-01-01"));
        claims.insert("name".to_string(), serde_json::json!("Alice"));

        let result = normalize_zk_predicate_claims(
            &claims,
            vec!["birth_date".to_string()],
        );
        assert!(!result.is_empty());
        assert_eq!(result[0].claim_name, "birth_date");
    }

    #[test]
    fn test_normalize_zk_predicate_strings_with_birth_date() {
        let mut claims = std::collections::HashMap::new();
        claims.insert("birth_date".to_string(), serde_json::json!("1990-01-01"));

        // Input that looks like predicates, not claim names
        let result = normalize_zk_predicate_claims(
            &claims,
            vec!["age_over_18".to_string()],
        );
        assert!(!result.is_empty());
        assert_eq!(result[0].claim_name, "birth_date");
        assert!(result[0].supported_predicates.contains(&"age_over_18".to_string()));
    }
}

