//! Python bindings for Marty Core cryptographic operations.
//!
//! This crate provides Python bindings for essential cryptographic functions
//! from marty-crypto and marty-verification, focused on credential issuance and verification.

// PyO3 0.22's `#[pyfunction]` expansion emits same-type PyErr conversions that
// Rust 1.97 flags even though they are outside the handwritten function bodies.
#![allow(clippy::useless_conversion)]

mod device_auth;
mod flow;
mod haip;
mod mdoc;
mod oid4vp_identity;
mod remote_credential;
mod siop;
mod status_list;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

pyo3::create_exception!(
    _marty_rs,
    OidcValidationError,
    pyo3::exceptions::PyValueError
);
pyo3::create_exception!(
    _marty_rs,
    PolicyEvaluationError,
    pyo3::exceptions::PyValueError
);
pyo3::create_exception!(
    _marty_rs,
    VdsNcOperationError,
    pyo3::exceptions::PyValueError
);

/// Convert marty_crypto errors to Python exceptions
fn to_pyerr(err: impl std::fmt::Display) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(err.to_string())
}

fn verification_build_decision_result_impl(input_json: &str) -> Result<String, String> {
    let input: marty_verification::verification::VerificationDecisionResultInput =
        serde_json::from_str(input_json)
            .map_err(|error| format!("invalid canonical verification input: {error}"))?;
    let result = marty_verification::verification::build_verification_decision_result(input)
        .map_err(|error| error.to_string())?;
    serde_json::to_string(&result)
        .map_err(|error| format!("canonical verification result serialization failed: {error}"))
}

/// Build the canonical verification decision result from caller-supplied facts.
///
/// The input intentionally has no decision, validity, reducer, or summary fields.
/// Unknown fields are rejected rather than ignored. The returned JSON is produced
/// by the sole Rust reducer and canonical result builder.
#[pyfunction]
fn verification_build_decision_result(input_json: &str) -> PyResult<String> {
    verification_build_decision_result_impl(input_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Resolve and validate the tenant-bound OID4VCI key-attestation policy.
#[pyfunction]
fn key_attestation_policy(request_json: &str) -> PyResult<String> {
    marty_verification::key_attestation::policy_from_issuer_context_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Select ordinary or key-attestation-bound OID4VCI proof verification.
#[pyfunction]
fn key_attestation_route_proof(request_json: &str) -> PyResult<String> {
    marty_verification::key_attestation::route_proof_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Verify the key-attestation JWT, certificate chain, signature, and claims.
#[pyfunction]
fn key_attestation_validate(request_json: &str) -> PyResult<String> {
    marty_verification::key_attestation::validate_attestation_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Validate and normalize a Token Status List reference before network access.
#[pyfunction]
fn key_attestation_validate_status_reference(request_json: &str) -> PyResult<String> {
    marty_verification::key_attestation::validate_status_reference_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Verify a signed Token Status List and return the referenced status value.
#[pyfunction]
fn key_attestation_validate_status_token(request_json: &str) -> PyResult<u8> {
    marty_verification::key_attestation::validate_status_token_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Return the language-neutral behavioral vectors consumed by wrapper tests.
#[pyfunction]
fn key_attestation_behavior_fixture() -> &'static str {
    include_str!("../../marty-verification/tests/fixtures/key_attestation_behavior.json")
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
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Generate a P-256 private JWK and its public-only JWK.
#[pyfunction]
fn generate_p256_jwk() -> PyResult<(String, String)> {
    marty_oid4vci::issuer::generate_p256_jwk_pair().map_err(to_pyerr)
}

/// Generate a did:jwk identifier and P-256 private signing JWK.
#[pyfunction]
fn generate_p256_did_jwk() -> PyResult<(String, String)> {
    marty_oid4vci::issuer::generate_p256_did_jwk().map_err(to_pyerr)
}

/// Derive a self-describing `did:jwk` or `did:key` from a P-256 public JWK.
#[pyfunction]
fn derive_p256_did_identifier(public_jwk_json: &str, method: &str) -> PyResult<String> {
    marty_didcomm::derive_p256_did_identifier(public_jwk_json, method).map_err(to_pyerr)
}

/// Generate a P-384 ECDSA key pair for signing credentials.
///
/// Returns:
///     Tuple of (private_key, public_key) as bytes.
///     Private key is 48 bytes, public key is 97 bytes (uncompressed).
#[pyfunction]
fn generate_p384_key<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ecdsa::generate_p384_keypair().map_err(to_pyerr)?;
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Generate an Ed25519 key pair for signing credentials.
///
/// Returns:
///     Tuple of (private_key, public_key) as bytes.
///     Both keys are 32 bytes.
#[pyfunction]
fn generate_ed25519_key<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ed25519::generate_keypair();
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Generate an Ed25519 `did:key` and its private JWK.
///
/// This preserves the established credential binding contract while keeping
/// key generation and DID derivation in the canonical Rust extension.
#[pyfunction]
fn generate_did_key() -> PyResult<(String, String)> {
    use base64::Engine;

    let (secret, public) = marty_crypto::ed25519::generate_keypair();
    let mut multicodec = Vec::with_capacity(34);
    multicodec.extend_from_slice(&[0xed, 0x01]);
    multicodec.extend_from_slice(&public);
    let did = format!("did:key:z{}", bs58::encode(multicodec).into_string());
    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": encoder.encode(public),
        "d": encoder.encode(secret),
    });
    Ok((did, serde_json::to_string(&jwk).map_err(to_pyerr)?))
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
    Ok(PyBytes::new(py, &signature))
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
    Ok(PyBytes::new(py, &signature))
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
    Ok(PyBytes::new(py, &signature))
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
    Ok(marty_crypto::ed25519::verify_bool(
        public_key, message, signature,
    ))
}

/// Verify a W3C VCDM v2 JSON-LD Data Integrity credential or presentation.
///
/// The request and response are JSON strings so the cryptographic boundary is
/// stable across Rust and Python releases. Verification uses Marty's embedded
/// contexts and offline did:key resolution.
#[pyfunction]
fn verify_vcdm_data_integrity(request_json: &str) -> String {
    marty_verification::vcdm::verify_vcdm_data_integrity_json(request_json)
}

/// Verify a compact W3C VCDM v2 VC-JWT with public issuer-profile DID material.
///
/// The JSON request accepts `token` and an optional `issuer_public_jwk`. The
/// JWK must be public; signing and private-key custody remain behind the issuer
/// profile rather than crossing the Python/Rust verification boundary.
#[pyfunction]
fn verify_vcdm_jwt(request_json: &str) -> String {
    marty_verification::vcdm::verify_vcdm_jwt_json(request_json)
}

/// Verify an Open Badges 3.0 credential carried as a compact VCDM v2 VC-JWT.
///
/// This composes issuer-signature verification and the canonical Open Badge
/// profile validator in Rust. Invalid signatures never expose badge claims.
#[pyfunction]
fn verify_open_badge_v3_jwt(request_json: &str) -> String {
    marty_verification::vcdm::verify_open_badge_v3_jwt_json(request_json)
}

/// Prepare the exact canonical bytes for an issuer-profile-backed
/// `eddsa-rdfc-2022` credential signature.
#[pyfunction]
fn prepare_vcdm_data_integrity_credential(request_json: &str) -> PyResult<String> {
    marty_verification::vcdm::prepare_vcdm_data_integrity_credential_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Insert a remote issuer-profile signature and verify the completed
/// `eddsa-rdfc-2022` credential before returning it.
#[pyfunction]
fn complete_vcdm_data_integrity_credential(request_json: &str) -> PyResult<String> {
    marty_verification::vcdm::complete_vcdm_data_integrity_credential_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Validate an unsigned VCDM v2 credential at the production issuance
/// boundary. Validation failures are stable machine-readable error codes.
#[pyfunction]
fn validate_vcdm_issuance_document(request_json: &str) -> PyResult<()> {
    marty_verification::vcdm::validate_vcdm_issuance_document_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Validate caller-fetched related-resource bytes against the credential's
/// SRI and multibase digests in Rust.
#[pyfunction]
fn validate_vcdm_related_resource_digests(request_json: &str) -> PyResult<()> {
    marty_verification::vcdm::validate_vcdm_related_resource_digests_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn governance_canonical_digest(value_json: &str) -> PyResult<String> {
    marty_verification::governance::canonical_digest_json(value_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn governance_validate(raw: &str) -> PyResult<()> {
    marty_verification::governance::validate_governance_json(raw)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn governance_authorize(request_json: &str) -> PyResult<String> {
    marty_verification::governance::authorize_governance_json(request_json)
        .map_err(pyo3::exceptions::PyPermissionError::new_err)
}

#[pyfunction]
fn governance_from_snapshot(request_json: &str) -> PyResult<String> {
    marty_verification::governance::governance_from_snapshot_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn governance_resume(request_json: &str) -> PyResult<String> {
    marty_verification::governance::resume_governance_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn governance_require_purpose(request_json: &str) -> PyResult<()> {
    marty_verification::governance::require_governance_purpose_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn governance_validate_request(request_json: &str) -> PyResult<()> {
    marty_verification::governance::validate_governance_request_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Evaluate normalized application evidence using the canonical Rust policy kernel.
#[pyfunction]
fn evaluate_application_evidence_policy(request_json: &str) -> PyResult<String> {
    marty_verification::evidence_policy::evaluate_application_evidence_policy_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Select the newest immutable revision for each logical evidence key.
#[pyfunction]
fn current_evidence_heads(request_json: &str) -> PyResult<String> {
    marty_verification::evidence_policy::current_evidence_heads_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn evidence_reconciliation_plan(request_json: &str) -> PyResult<String> {
    marty_verification::evidence_reconciliation::reconciliation_plan_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

#[pyfunction]
fn evidence_reconciliation_stale_reasons(request_json: &str) -> PyResult<String> {
    marty_verification::evidence_reconciliation::stale_receipt_reasons_json(request_json)
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

/// Return one canonical language-neutral behavior fixture for adapter tests.
#[pyfunction]
fn verification_behavior_fixture(name: &str) -> PyResult<String> {
    let fixture = match name {
        "evidence_policy" => marty_verification::evidence_policy::behavior_fixture_json(),
        "evidence_reconciliation" => {
            marty_verification::evidence_reconciliation::behavior_fixture_json()
        }
        "governance" => marty_verification::governance::behavior_fixture_json(),
        "vcdm_issuance" => marty_verification::vcdm::issuance_behavior_fixture_json(),
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "unknown verification behavior fixture",
            ));
        }
    };
    Ok(fixture.to_string())
}

/// Helper function to encode bytes as base64url (no padding)
#[cfg(test)]
fn base64_url_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(data)
}

// ============================================================================
// Canvas LTI / Sandbox Hardening
// ============================================================================

#[pyfunction]
#[pyo3(signature = (base_url, allow_private_networks=false, allow_http_localhost=false))]
fn canvas_normalize_base_url(
    base_url: &str,
    allow_private_networks: bool,
    allow_http_localhost: bool,
) -> PyResult<String> {
    marty_oid4vci::lti::normalize_canvas_base_url(
        base_url,
        allow_private_networks,
        allow_http_localhost,
    )
    .map_err(to_pyerr)
}

#[pyfunction]
#[pyo3(signature = (base_url, timeout_seconds=5, allow_private_networks=false, allow_http_localhost=false))]
fn canvas_probe_lti_platform(
    base_url: &str,
    timeout_seconds: u64,
    allow_private_networks: bool,
    allow_http_localhost: bool,
) -> PyResult<String> {
    let rt = tokio::runtime::Runtime::new().map_err(to_pyerr)?;
    let probe = rt
        .block_on(marty_oid4vci::lti::probe_canvas_lti_platform(
            base_url,
            timeout_seconds,
            allow_private_networks,
            allow_http_localhost,
        ))
        .map_err(to_pyerr)?;
    serde_json::to_string(&probe).map_err(to_pyerr)
}

#[pyfunction]
#[pyo3(signature = (id_token, expected_issuer, expected_client_id, expected_deployment_id, jwks_json, expected_nonce=None, leeway_seconds=120))]
fn lti_verify_launch_jwt(
    id_token: &str,
    expected_issuer: &str,
    expected_client_id: &str,
    expected_deployment_id: &str,
    jwks_json: &str,
    expected_nonce: Option<&str>,
    leeway_seconds: u64,
) -> PyResult<String> {
    let verified = marty_oid4vci::lti::verify_lti_launch_jwt(
        id_token,
        expected_issuer,
        expected_client_id,
        expected_deployment_id,
        jwks_json,
        expected_nonce,
        leeway_seconds,
    )
    .map_err(to_pyerr)?;
    serde_json::to_string(&verified).map_err(to_pyerr)
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
    .map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Offer creation error: {e}"))
    })
}

/// Backward-compatible alias for the canonical OID4VCI offer builder.
#[pyfunction]
#[pyo3(signature = (issuer_url, credential_types, pre_authorized_code=None, user_pin_required=false))]
fn create_credential_offer(
    issuer_url: &str,
    credential_types: Vec<String>,
    pre_authorized_code: Option<String>,
    user_pin_required: bool,
) -> PyResult<String> {
    oid4vci_create_credential_offer(
        issuer_url,
        credential_types,
        pre_authorized_code,
        user_pin_required,
    )
}

/// Build the legacy offer URI shape through the Rust protocol implementation.
#[pyfunction]
fn generate_offer_uri(issuer_url: &str, offer_id: &str, format: &str) -> String {
    marty_oid4vci::issuer::generate_offer_uri(issuer_url, offer_id, format)
}

/// Backward-compatible metadata entry point using canonical Rust types.
#[pyfunction]
fn generate_issuer_metadata(
    issuer_url: &str,
    issuer_name: &str,
    credential_types_json: &str,
) -> PyResult<String> {
    let credential_types: Vec<marty_oid4vci::types::CredentialTypeConfig> =
        serde_json::from_str(credential_types_json).map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid credential type configuration JSON: {error}"
            ))
        })?;
    marty_oid4vci::metadata::generate_issuer_metadata(issuer_url, issuer_name, &credential_types)
        .map_err(to_pyerr)
}

/// Create a token response for a pre-authorized code exchange.
///
/// Generates a fresh access token without performing DB lookups.
/// The caller is responsible for validating the pre-auth code, checking
/// expiry, and persisting the returned token.
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
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Token response error: {e}"))
        })?;
    serde_json::to_string(&resp).map_err(to_pyerr)
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

    let request: AuthorizationRequest = serde_json::from_str(request_json).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Invalid AuthorizationRequest JSON: {e}"
        ))
    })?;

    let engine = _dummy_engine();
    let (response, session) = engine
        .create_authorization_response(&request, session_lifetime_secs)
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Authorization error: {e}"))
        })?;

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

    let request: AuthorizationCodeTokenRequest =
        serde_json::from_str(request_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid AuthorizationCodeTokenRequest JSON: {e}"
            ))
        })?;
    let session: AuthorizationSession = serde_json::from_str(session_json).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Invalid AuthorizationSession JSON: {e}"
        ))
    })?;

    let engine = _dummy_engine();
    let token_response = engine
        .create_token_response_for_auth_code(&request, &session, token_lifetime_secs)
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Token exchange error: {e}"))
        })?;

    serde_json::to_string(&token_response).map_err(to_pyerr)
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
    marty_oid4vci::proof::create_proof_jwt(aud, c_nonce).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Proof JWT creation failed: {e}"))
    })
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
///     `(holder_did, nonce, holder_public_jwk_json)` tuple on success
///
/// Raises:
///     `RuntimeError` on any verification failure
#[pyfunction]
#[pyo3(signature = (proof_jwt, expected_c_nonce=None, issuer_url=None))]
fn oid4vci_verify_proof_jwt(
    proof_jwt: &str,
    expected_c_nonce: Option<&str>,
    issuer_url: Option<&str>,
) -> PyResult<(String, Option<String>, Option<String>)> {
    let url = issuer_url.unwrap_or("");
    let verified = marty_oid4vci::proof::verify_jwt_proof(proof_jwt, url, expected_c_nonce, 300)
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Proof JWT verification failed: {e}"
            ))
        })?;
    let holder_jwk_json = verified
        .holder_jwk
        .map(|jwk| serde_json::to_string(&jwk))
        .transpose()
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Holder JWK serialization failed: {e}"
            ))
        })?;
    Ok((verified.holder_id, verified.nonce, holder_jwk_json))
}

/// Verify an OID4VCI proof bound to an issuer-validated key attestation.
///
/// `validated_key_attestation_jwt` must be the exact compact JWT that the
/// tenant-bound issuer policy already validated. The Rust protocol layer then
/// requires the proof's `key_attestation` header to match that token
/// byte-for-byte, confirms the proof header's `jwk` or standards-defined `kid`
/// identifies a key in the token's `attested_keys`, and verifies the proof
/// signature with that key. No separately supplied key list can drift from the
/// validated token.
///
/// Certificate-chain, status, assurance, and organization/profile policy
/// checks intentionally remain at the product boundary that owns those
/// tenant-scoped records. This binding does not accept trust decisions or
/// private custody selectors.
#[pyfunction]
#[pyo3(signature = (
    proof_jwt,
    validated_key_attestation_jwt,
    expected_c_nonce=None,
    issuer_url=None,
))]
fn oid4vci_verify_key_attestation_bound_proof_jwt(
    proof_jwt: &str,
    validated_key_attestation_jwt: &str,
    expected_c_nonce: Option<&str>,
    issuer_url: Option<&str>,
) -> PyResult<(String, Option<String>, String)> {
    let verified = marty_oid4vci::proof::verify_key_attestation_bound_jwt_proof(
        proof_jwt,
        issuer_url.unwrap_or(""),
        expected_c_nonce,
        300,
        validated_key_attestation_jwt,
    )
    .map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Key-attestation-bound proof JWT verification failed: {e}"
        ))
    })?;
    let holder_jwk = verified.holder_jwk.ok_or_else(|| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "Verified key-attestation-bound proof did not return its selected public key",
        )
    })?;
    let holder_jwk_json = serde_json::to_string(&holder_jwk).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Holder JWK serialization failed: {e}"
        ))
    })?;
    Ok((verified.holder_id, verified.nonce, holder_jwk_json))
}

/// Verify a compact JWT with one explicitly selected public JWK.
///
/// This binding performs JOSE parsing, duplicate-member rejection, algorithm
/// binding, public-key validation, and cryptographic signature verification.
/// Protocol-specific claim policy remains with the Python orchestration layer.
#[pyfunction]
fn oid4vci_verify_compact_jwt(
    compact_jwt: &str,
    public_jwk_json: &str,
    expected_algorithm: &str,
) -> PyResult<(String, String)> {
    let verified = marty_oid4vci::jose::verify_compact_jwt_with_public_jwk(
        compact_jwt,
        public_jwk_json,
        expected_algorithm,
    )
    .map_err(|error| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Compact JWT verification failed: {error}"
        ))
    })?;
    let header = serde_json::to_string(&verified.header).map_err(to_pyerr)?;
    let claims = serde_json::to_string(&verified.claims).map_err(to_pyerr)?;
    Ok((header, claims))
}

/// Validate an OpenID Connect ID token against a provider JWKS.
///
/// The Rust validator selects the key by ``kid`` and enforces signature,
/// algorithm allowlist, issuer, audience/authorized-party, nonce, expiry,
/// issuance/not-before time, and ``at_hash`` when present. It returns claims
/// only after every applicable check succeeds.
#[pyfunction]
fn oidc_validate_id_token(request_json: &str) -> PyResult<String> {
    let claims = marty_oid4vci::oidc::validate_id_token_request(request_json)
        .map_err(|error| PyErr::new::<OidcValidationError, _>(error.to_string()))?;
    serde_json::to_string(&claims).map_err(to_pyerr)
}

fn evaluate_presentation_policy_impl(request_json: &str) -> Result<String, String> {
    let request: marty_verification::policy::PolicyEvaluationRequest =
        serde_json::from_str(request_json)
            .map_err(|error| format!("invalid presentation policy request: {error}"))?;
    let evaluator = marty_verification::policy::PolicyEvaluator::new(request.policy);
    let result = evaluator.evaluate(&request.input);
    serde_json::to_string(&result)
        .map_err(|error| format!("presentation policy result serialization failed: {error}"))
}

fn evaluate_service_presentation_policy_impl(request_json: &str) -> Result<String, String> {
    if request_json.len() > 1_000_000 {
        return Err("service presentation policy request exceeds 1000000 bytes".to_string());
    }
    let request: marty_verification::policy::ServicePolicyEvaluationRequest =
        serde_json::from_str(request_json)
            .map_err(|error| format!("invalid service presentation policy request: {error}"))?;
    let result = marty_verification::policy::evaluate_service_policy(request)
        .map_err(|error| error.to_string())?;
    serde_json::to_string(&result).map_err(|error| {
        format!("service presentation policy result serialization failed: {error}")
    })
}

/// Evaluate verified presentation facts with the canonical Rust policy engine.
#[pyfunction]
fn evaluate_presentation_policy(request_json: &str) -> PyResult<String> {
    evaluate_presentation_policy_impl(request_json).map_err(PyErr::new::<PolicyEvaluationError, _>)
}

/// Evaluate the complete presentation-policy service contract in Rust.
#[pyfunction]
fn evaluate_service_presentation_policy(request_json: &str) -> PyResult<String> {
    evaluate_service_presentation_policy_impl(request_json)
        .map_err(PyErr::new::<PolicyEvaluationError, _>)
}

/// Normalize a presentation credential format using the canonical Rust aliases.
#[pyfunction]
fn normalize_presentation_credential_format(value: &str) -> String {
    marty_verification::policy::canonical_credential_format(value)
}

/// Return explicit native backend and capability diagnostics for readiness.
#[pyfunction]
fn native_backend_diagnostics() -> PyResult<String> {
    serde_json::to_string(&serde_json::json!({
        "available": true,
        "backend": "_marty_rs",
        "version": env!("CARGO_PKG_VERSION"),
        "build_revision": option_env!("MARTY_BUILD_REVISION").unwrap_or("unknown"),
        "capabilities": [
            "oidc_id_token_validation",
            "presentation_policy_evaluation",
            "presentation_policy_service_evaluation",
            "oid4vci",
            "oid4vp",
            "document_verification",
            "credential_format_detection",
            "credential_presentation_metadata",
            "oid4vp_request_builder",
            "oid4vp_x509_identity",
            "siop_jwk_id_token_verification",
            "device_authentication",
            "flow_state_machine",
            "haip_response_encryption",
            "did_resolution",
            "did_identifier_derivation",
            "openid4vp_mdoc_handover",
            "vds_nc_profile",
            "trust_registry_sync",
            "status_list"
        ]
    }))
    .map_err(to_pyerr)
}

#[pyfunction]
#[pyo3(signature = (framework=None))]
fn trust_registry_catalog_json(framework: Option<&str>) -> PyResult<String> {
    marty_verification::trust_sync::registry_catalog_json(framework).map_err(to_pyerr)
}

#[pyfunction]
fn trust_registry_behavior_fixture_json() -> &'static str {
    marty_verification::trust_sync::behavior_fixture_json()
}

#[pyfunction]
#[pyo3(signature = (registry_type, now_rfc3339, requested_formats_json=None, sync_interval_hours=None))]
fn trust_registry_import_decision_json(
    registry_type: &str,
    now_rfc3339: &str,
    requested_formats_json: Option<&str>,
    sync_interval_hours: Option<u16>,
) -> PyResult<String> {
    marty_verification::trust_sync::import_decision_json(
        registry_type,
        requested_formats_json,
        sync_interval_hours,
        now_rfc3339,
    )
    .map_err(to_pyerr)
}

#[pyfunction]
#[pyo3(signature = (since=None))]
fn trust_registry_public_sync_query_json(since: Option<&str>) -> PyResult<String> {
    marty_verification::trust_sync::public_sync_query_json(since).map_err(to_pyerr)
}

#[pyfunction]
fn trust_registry_public_sync_metadata_json(
    current_sequence: u64,
    generated_at_rfc3339: &str,
) -> PyResult<String> {
    marty_verification::trust_sync::public_sync_metadata_json(
        current_sequence,
        generated_at_rfc3339,
    )
    .map_err(to_pyerr)
}

#[pyfunction]
#[pyo3(signature = (refresh_interval_hours, now_rfc3339, last_synchronized_at_rfc3339=None))]
fn trust_registry_sync_is_due_json(
    refresh_interval_hours: u16,
    now_rfc3339: &str,
    last_synchronized_at_rfc3339: Option<&str>,
) -> PyResult<String> {
    marty_verification::trust_sync::sync_is_due_json(
        last_synchronized_at_rfc3339,
        refresh_interval_hours,
        now_rfc3339,
    )
    .map_err(to_pyerr)
}

#[pyfunction]
fn trust_registry_validate_url(url: &str) -> PyResult<String> {
    marty_verification::trust_sync::validate_registry_url(url).map_err(to_pyerr)
}

#[pyfunction]
fn trust_registry_destination_decision_json(
    url: &str,
    addresses_json: &str,
    private_host_allowlist: &str,
) -> PyResult<String> {
    marty_verification::trust_sync::destination_decision_json(
        url,
        addresses_json,
        private_host_allowlist,
    )
    .map_err(to_pyerr)
}

#[pyfunction]
fn trust_registry_private_host_allowlist_json(configured: &str) -> PyResult<String> {
    marty_verification::trust_sync::private_host_allowlist_json(configured).map_err(to_pyerr)
}

#[pyfunction]
#[pyo3(signature = (url, token=None, address=None))]
fn trust_registry_request_plan_json(
    url: &str,
    token: Option<&str>,
    address: Option<&str>,
) -> PyResult<String> {
    marty_verification::trust_sync::request_plan_json(url, token, address).map_err(to_pyerr)
}

#[pyfunction]
fn trust_registry_validate_feed_json(feed_json: &str) -> PyResult<String> {
    marty_verification::trust_sync::validate_feed_json(feed_json).map_err(to_pyerr)
}

#[pyfunction]
fn trust_registry_validate_state_json(state_json: &str) -> PyResult<String> {
    marty_verification::trust_sync::validate_state_json(state_json).map_err(to_pyerr)
}

#[pyfunction]
fn trust_registry_evaluate_pages_json(
    previous_state_json: &str,
    pages_json: &str,
    now_rfc3339: &str,
) -> PyResult<String> {
    marty_verification::trust_sync::evaluate_pages_json(
        previous_state_json,
        pages_json,
        now_rfc3339,
    )
    .map_err(to_pyerr)
}

#[pyfunction]
fn trust_registry_revalidate_state_json(state_json: &str, now_rfc3339: &str) -> PyResult<String> {
    marty_verification::trust_sync::revalidate_state_json(state_json, now_rfc3339).map_err(to_pyerr)
}

/// Verify a detached provider/KMS signature using a public JWK.
#[pyfunction]
fn oid4vci_verify_detached_signature(
    message: &[u8],
    signature: &[u8],
    public_jwk_json: &str,
    expected_algorithm: &str,
) -> PyResult<bool> {
    marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
        message,
        signature,
        public_jwk_json,
        expected_algorithm,
    )
    .map_err(|error| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Detached signature verification failed: {error}"
        ))
    })
}

/// Normalize a DER or raw ECDSA signature to fixed-width P1363/JOSE bytes.
#[pyfunction]
fn oid4vci_normalize_ecdsa_signature(
    signature: &[u8],
    expected_algorithm: &str,
) -> PyResult<Vec<u8>> {
    marty_oid4vci::jose::normalize_ecdsa_signature(signature, expected_algorithm).map_err(to_pyerr)
}

/// Verify an SD-JWT VC presentation using Marty Core's RFC 9449 engine.
///
/// The issuer JWK must contain public material only. When both expected
/// bindings are supplied, the Key Binding JWT is required to match the
/// supplied audience and nonce. The returned JSON is the verified credential
/// payload with disclosed claims reconstructed.
///
/// This is intentionally a direct binding to ``marty-oid4vci`` rather than a
/// Python-side verifier: public services must use the same Rust verification
/// implementation as the protocol conformance tests.
#[pyfunction]
#[pyo3(signature = (sd_jwt_compact, issuer_jwk_json, expected_aud=None, expected_nonce=None))]
fn verify_sd_jwt(
    sd_jwt_compact: &str,
    issuer_jwk_json: &str,
    expected_aud: Option<String>,
    expected_nonce: Option<String>,
) -> PyResult<String> {
    let verified = marty_oid4vci::formats::sd_jwt::verify_sd_jwt(
        sd_jwt_compact,
        issuer_jwk_json,
        expected_aud,
        expected_nonce,
    )
    .map_err(|error| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "SD-JWT verification failed: {error}"
        ))
    })?;
    serde_json::to_string(&verified).map_err(to_pyerr)
}

/// Select issuer-bound SD-JWT disclosures for an unbound presentation.
///
/// A nonce or audience requires a holder-key-aware OID4VP flow and therefore
/// fails closed at this compatibility boundary.
#[pyfunction]
#[pyo3(signature = (sd_jwt_compact, disclosed_fields, nonce=None, audience=None))]
fn sd_jwt_create_presentation(
    sd_jwt_compact: &str,
    disclosed_fields: Vec<String>,
    nonce: Option<&str>,
    audience: Option<&str>,
) -> PyResult<String> {
    if nonce.is_some() || audience.is_some() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "SD-JWT nonce or audience binding requires a holder-key-aware OID4VP flow",
        ));
    }
    marty_oid4vci::formats::sd_jwt::create_sd_jwt_presentation(sd_jwt_compact, &disclosed_fields)
        .map_err(to_pyerr)
}

/// Create an OID4VCI format-aware verifiable credential via the Rust signing engine.
///
/// Supports all credential formats: jwt_vc_json, vc+sd-jwt, mso_mdoc, zk_mdoc, vds_nc.
/// Delegates entirely to marty-oid4vci — no protocol logic lives in Python.
///
/// Args:
///     issuer_id: Issuer DID (e.g. "did:key:z6Mk...")
///     jwk_json: Issuer signing key as a JWK JSON string (OKP/Ed25519 or EC/P-256)
///     subject_id: Optional holder DID
///     credential_type: Credential type string
///     claims_json: JSON object of credential subject claims
///     expiration_seconds: Optional validity in seconds
///     format: Credential wire format ("jwt_vc_json", "vc+sd-jwt", "mso_mdoc", "zk_mdoc", "vds_nc")
///     selective_disclosure_claims: Claims to make selectively disclosable (SD-JWT only)
///     zk_predicate_claims: Claims eligible for ZK predicate proofs (zk_mdoc only)
///     credential_payload_format: SD-JWT payload structure ("ietf_sd_jwt" or "w3c_vcdm_v2_sd_jwt")
///     w3c_context: Additional @context URIs for W3C VCDM v2 payloads
///     w3c_types: Additional type values for W3C VCDM v2 payloads
///
/// Returns:
///     (credential_string, credential_id)
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (issuer_id, jwk_json, subject_id, credential_type, claims_json, expiration_seconds=None, format="jwt_vc_json", selective_disclosure_claims=vec![], zk_predicate_claims=vec![], credential_payload_format="w3c_vcdm_v2_sd_jwt", w3c_context=vec![], w3c_types=vec![], mdoc_namespace=None, mdoc_doctype=None))]
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
    mdoc_namespace: Option<String>,
    mdoc_doctype: Option<String>,
) -> PyResult<(String, String)> {
    use marty_oid4vci::formats;
    use marty_oid4vci::types::{
        CredentialClaims, CredentialFormat, CredentialPayloadFormat, IssuerKey, SignedCredential,
    };

    let claims: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_str(claims_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid claims JSON: {e}"))
        })?;

    let algorithm = marty_oid4vci::issuer::detect_algorithm(jwk_json).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Key error: {e}"))
    })?;
    let issuer_key = IssuerKey {
        issuer_id: issuer_id.to_string(),
        jwk_json: jwk_json.to_string(),
        algorithm,
    };

    let zk_predicate_bindings = normalize_zk_predicate_claims(&claims, zk_predicate_claims);

    let payload_format = match credential_payload_format {
        "ietf_sd_jwt" | "ietf" | "flat" => CredentialPayloadFormat::IetfSdJwt,
        "w3c_vcdm_v2_sd_jwt" => CredentialPayloadFormat::W3cVcdmV2SdJwt,
        "w3c_vcdm_v2_jwt_vc" => CredentialPayloadFormat::W3cVcdmV2JwtVc,
        unsupported => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unsupported credential payload format: {unsupported}"
            )))
        }
    };

    let cred_claims = CredentialClaims {
        subject_id: subject_id.map(String::from),
        credential_type: credential_type.to_string(),
        claims,
        expiration_seconds,
        selective_disclosure_claims,
        mdoc_namespace,
        mdoc_doctype,
        zk_predicate_claims: zk_predicate_bindings,
        credential_payload_format: payload_format,
        w3c_context,
        w3c_types,
    };

    let cred_format = CredentialFormat::from_str_loose(format).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("Unsupported credential format: {format}"))
    })?;

    let signed =
        formats::sign_credential(&cred_format, &issuer_key, &cred_claims).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Signing error: {e}"))
        })?;
    let credential_str = match &signed {
        SignedCredential::JwtVcJson { jwt, .. } => jwt.clone(),
        SignedCredential::SdJwt { compact, .. } => compact.clone(),
        SignedCredential::MsoMdoc {
            issuer_signed_b64, ..
        } => issuer_signed_b64.clone(),
        SignedCredential::ZkMdoc {
            issuer_signed_b64, ..
        } => issuer_signed_b64.clone(),
        SignedCredential::VdsNc { barcode_data, .. } => barcode_data.clone(),
    };

    Ok((credential_str, signed.credential_id().to_string()))
}

/// Backward-compatible name for the standards-aware OID4VCI issuance kernel.
///
/// The former ad-hoc JSON proof helper was removed; every supported format now
/// passes through the same Rust credential engine.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (issuer_did, issuer_jwk_json, subject_id, credential_type, claims_json, expiration_seconds=None, format="jwt_vc_json", selective_disclosure_claims=vec![], mdoc_namespace=None, mdoc_doctype=None, zk_predicate_claims=vec![], credential_payload_format="w3c_vcdm_v2_sd_jwt", w3c_context=vec![], w3c_types=vec![]))]
fn create_verifiable_credential(
    issuer_did: &str,
    issuer_jwk_json: &str,
    subject_id: Option<&str>,
    credential_type: &str,
    claims_json: &str,
    expiration_seconds: Option<i64>,
    format: &str,
    selective_disclosure_claims: Vec<String>,
    mdoc_namespace: Option<String>,
    mdoc_doctype: Option<String>,
    zk_predicate_claims: Vec<String>,
    credential_payload_format: &str,
    w3c_context: Vec<String>,
    w3c_types: Vec<String>,
) -> PyResult<(String, String)> {
    oid4vci_sign_credential(
        issuer_did,
        issuer_jwk_json,
        subject_id,
        credential_type,
        claims_json,
        expiration_seconds,
        format,
        selective_disclosure_claims,
        zk_predicate_claims,
        credential_payload_format,
        w3c_context,
        w3c_types,
        mdoc_namespace,
        mdoc_doctype,
    )
}

/// Prepare a credential for external signing (BYOK).
///
/// Returns a tuple of (signing_input_base64, credential_id, format_hint).
/// The caller signs `signing_input` externally and passes the result to
/// `oid4vci_assemble_credential()`.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
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
    use marty_oid4vci::signer::CredentialSigner;
    use marty_oid4vci::types::{
        CredentialClaims, CredentialFormat, CredentialPayloadFormat, SigningAlgorithm,
    };

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
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Unknown algorithm: {algorithm}"
            )))
        }
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
            Err(marty_oid4vci::Oid4vciError::SigningError(
                "metadata-only credential signer cannot sign".to_string(),
            ))
        }
        fn algorithm(&self) -> SigningAlgorithm {
            self.algorithm
        }
        fn issuer_id(&self) -> &str {
            &self.issuer_id
        }
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
        credential_payload_format: CredentialPayloadFormat::from_str_loose(
            credential_payload_format,
        ),
        w3c_context,
        w3c_types,
    };

    let cred_format =
        CredentialFormat::from_str_loose(format).unwrap_or(CredentialFormat::JwtVcJson);

    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    match cred_format {
        CredentialFormat::JwtVcJson => {
            let prepared = marty_oid4vci::formats::jwt_vc::prepare_jwt_vc(&signer, &cred_claims)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e}")))?;
            // signing_input is already a string (header_b64.payload_b64)
            Ok((
                prepared.signing_input,
                prepared.credential_id,
                "jwt_vc_json".to_string(),
            ))
        }
        CredentialFormat::MsoMdoc => {
            let prepared = marty_oid4vci::formats::mdoc::prepare_mdoc(&signer, &cred_claims)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e}")))?;
            // tbs_data is raw bytes — base64url encode for transport
            let tbs_b64 = b64.encode(&prepared.tbs_data);
            Ok((tbs_b64, prepared.credential_id, "mso_mdoc".to_string()))
        }
        CredentialFormat::VdsNc => {
            let prepared = marty_oid4vci::formats::vds_nc::prepare_vds_nc(&signer, &cred_claims)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e}")))?;
            Ok((
                prepared.signing_input,
                prepared.credential_id,
                "vds_nc".to_string(),
            ))
        }
        _ => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Format '{}' does not support prepare/assemble yet",
            format
        ))),
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
    use base64::Engine;
    use marty_oid4vci::types::SignedCredential;
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
                SignedCredential::JwtVcJson { jwt, credential_id } => Ok((jwt, credential_id)),
                _ => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "JWT-VC assembler returned an unexpected credential format",
                )),
            }
        }
        "vds_nc" => {
            let prepared = marty_oid4vci::formats::vds_nc::PreparedVdsNc::from_signing_input(
                signing_input.to_string(),
                credential_id.to_string(),
            )
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e}")))?;
            let signed = marty_oid4vci::formats::vds_nc::assemble_vds_nc(prepared, &signature);
            match signed {
                SignedCredential::VdsNc {
                    barcode_data,
                    credential_id,
                } => Ok((barcode_data, credential_id)),
                _ => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "VDS-NC assembler returned an unexpected credential format",
                )),
            }
        }
        _ => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Format '{}' assemble not yet supported via FFI",
            format
        ))),
    }
}

/// Opaque mDoc preparation state retained inside the native extension between
/// issuer-profile signing and final COSE assembly. The protected header,
/// MSO and issuer-signed items must never be reconstructed from a lossy
/// Python representation after the profile signs the exact TBS bytes as its DID.
#[pyclass]
struct PreparedMdocForRemoteSigning {
    inner: Option<marty_oid4vci::formats::mdoc::PreparedMdoc>,
}

#[pymethods]
impl PreparedMdocForRemoteSigning {
    #[getter]
    fn tbs_data(&self) -> PyResult<Vec<u8>> {
        self.inner
            .as_ref()
            .map(|prepared| prepared.tbs_data.clone())
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "mDoc preparation has already been assembled",
                )
            })
    }

    #[getter]
    fn credential_id(&self) -> PyResult<String> {
        self.inner
            .as_ref()
            .map(|prepared| prepared.credential_id.clone())
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "mDoc preparation has already been assembled",
                )
            })
    }
}

/// Prepare an ISO 18013-5 mDoc for issuer-profile signing.
///
/// This keeps the complete prepared state in Rust and returns only the COSE
/// Sig_structure bytes that the issuer profile must sign as its DID. The caller
/// must pass the raw IEEE P1363 ECDSA signature to
/// ``oid4vci_assemble_mdoc``.
#[pyfunction]
// Python keeps these protocol fields explicit so an issuer cannot smuggle
// holder key binding or issuer identity through an opaque options object.
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    issuer_id,
    algorithm,
    credential_type,
    namespace,
    claims_json,
    expiration_seconds=None,
    credential_id=None,
    holder_jwk_json=None
))]
fn oid4vci_prepare_mdoc(
    issuer_id: &str,
    algorithm: &str,
    credential_type: &str,
    namespace: &str,
    claims_json: &str,
    expiration_seconds: Option<i64>,
    credential_id: Option<&str>,
    holder_jwk_json: Option<&str>,
) -> PyResult<PreparedMdocForRemoteSigning> {
    let claims = serde_json::from_str(claims_json).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid claims JSON: {e}"))
    })?;
    let holder_public_jwk = holder_jwk_json
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid holder public JWK JSON: {e}"
            ))
        })?;
    let prepared = marty_oid4vci::remote_credential::prepare_remote_mdoc(
        marty_oid4vci::remote_credential::RemoteMdocRequest {
            issuer_id: issuer_id.to_owned(),
            algorithm: algorithm.to_owned(),
            credential_type: credential_type.to_owned(),
            namespace: namespace.to_owned(),
            claims,
            expiration_seconds,
            credential_id: credential_id.map(str::to_owned),
            holder_jwk: holder_public_jwk,
        },
    )
    .map_err(remote_credential::remote_pyerr)?;
    Ok(PreparedMdocForRemoteSigning {
        inner: Some(prepared),
    })
}

/// Assemble one mDoc credential after its issuer-profile signature is available.
#[pyfunction]
fn oid4vci_assemble_mdoc(
    prepared: &mut PreparedMdocForRemoteSigning,
    signature: Vec<u8>,
) -> PyResult<(String, String)> {
    use marty_oid4vci::types::SignedCredential;
    let prepared = prepared.inner.take().ok_or_else(|| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "mDoc preparation may only be assembled once",
        )
    })?;
    match marty_oid4vci::formats::mdoc::assemble_mdoc(prepared, &signature).map_err(to_pyerr)? {
        SignedCredential::MsoMdoc {
            issuer_signed_b64,
            credential_id,
        } => Ok((issuer_signed_b64, credential_id)),
        _ => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "mDoc assembler returned an unexpected credential format",
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
            Ok(binding)
                if !binding.claim_name.is_empty() && !binding.supported_predicates.is_empty() =>
            {
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
            .map(|claim_name| {
                marty_oid4vci::types::ZkPredicateBinding::multi(
                    claim_name,
                    fallback_predicates.clone(),
                )
            })
            .collect();
    }

    if !predicates.is_empty() {
        if claims.contains_key("birth_date") {
            return vec![marty_oid4vci::types::ZkPredicateBinding::multi(
                "birth_date",
                predicates,
            )];
        }
        if let Some(first_claim_name) = claims.keys().next() {
            return vec![marty_oid4vci::types::ZkPredicateBinding::multi(
                first_claim_name.clone(),
                predicates,
            )];
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
/// Validates the JWT signature (when a presentation public key is embedded in the
/// token via `jwk` header, `cnf.jwk`, or `sub_jwk`), the nonce, the audience,
/// and the expiry.
///
/// This is a low-level presentation-proof check, not credential verification.
/// A passing proof is reported as `check_valid: true` with scoped `evidence`;
/// `valid` and `decision_ready` remain false until a higher-level verifier has
/// authenticated every embedded credential and established holder binding,
/// issuer trust, validity, and status.
///
/// Args:
///     vp_token: The compact-serialised VP JWT (or SD-JWT presentation).
///     expected_nonce: The nonce from the authorization request.
///     verifier_id: The verifier's client_id / audience value.
///
/// Returns:
///     JSON object with `valid`, `check_valid`, `decision_ready`, `scope`,
///     `evidence`, `descriptor_results`, and `errors` fields.
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
    serde_json::to_string(&result).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Serialization error: {e}"))
    })
}

/// Validate an OID4VP presentation submission against its definition.
///
/// This is a low-level structural check. A successful result reports
/// `check_valid: true` and `scope: "presentation_structure"`; `valid` and
/// `decision_ready` remain false because this operation does not authenticate
/// the presentation proof or any embedded credential.
#[pyfunction]
fn verify_presentation_structure(
    verifier_id: &str,
    response_uri: &str,
    definition_json: &str,
    submission_json: &str,
) -> PyResult<String> {
    use marty_oid4vci::verifier::{
        PresentationDefinition, PresentationSubmission, VerificationEngine,
    };

    let definition: PresentationDefinition =
        serde_json::from_str(definition_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid presentation definition: {e}"
            ))
        })?;
    let submission: PresentationSubmission =
        serde_json::from_str(submission_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid presentation submission: {e}"
            ))
        })?;

    let engine = VerificationEngine::new(verifier_id, response_uri);
    let result = engine.verify_presentation_structure(&definition, &submission);
    serde_json::to_string(&result).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Serialization error: {e}"))
    })
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
    Ok(PyBytes::new(py, &ct))
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
    Ok(PyBytes::new(py, &pt))
}

/// HMAC-SHA256.
#[pyfunction]
fn hmac_sha256<'py>(py: Python<'py>, key: &[u8], data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let mac = marty_crypto::symmetric::hmac_sha256(key, data)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(PyBytes::new(py, &mac))
}

/// SHA-256 hash.
#[pyfunction]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let digest = marty_crypto::hashing::hash_sha256(data);
    Ok(PyBytes::new(py, &digest))
}

// ============================================================================
// DIDComm v2
// ============================================================================

/// Resolve a DID to its DID Document (JSON string).
///
/// Resolves did:key, did:peer, and did:jwk locally. did:web and unsupported
/// methods require a deployment-managed Universal Resolver URL.
/// Does NOT support ledger-based methods (did:ion, did:ethr, did:sov).
///
/// Args:
///     did: The DID to resolve
///     universal_resolver_url: Optional deployment-managed Universal Resolver base URL
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

/// Resolve a DID with native egress policy and integrity provenance.
///
/// `did_web_internal_base_urls` are deployment-owned HTTP(S) bases that serve
/// standard did:web document paths and are tried in order. Public HTTPS
/// resolution is enabled only for exact `did_web_allowed_hosts`. The JSON
/// result contains `document`, `source`, `retrieved_at`, and `content_sha256`.
#[pyfunction]
#[pyo3(signature = (did, *, universal_resolver_url=None, did_web_internal_base_urls=None, did_web_allowed_hosts=None))]
fn didcomm_resolve_did_with_metadata(
    did: &str,
    universal_resolver_url: Option<&str>,
    did_web_internal_base_urls: Option<Vec<String>>,
    did_web_allowed_hosts: Option<Vec<String>>,
) -> PyResult<String> {
    let rt = tokio::runtime::Runtime::new().map_err(to_pyerr)?;
    let resolver = match universal_resolver_url {
        Some(url) => marty_didcomm::DidResolver::with_universal_resolver(url),
        None => marty_didcomm::DidResolver::new(),
    };
    let resolver = match did_web_internal_base_urls {
        Some(urls) => resolver.with_did_web_internal_base_urls(urls),
        None => resolver,
    };
    let resolver = match did_web_allowed_hosts {
        Some(hosts) => resolver.allow_did_web_hosts(hosts),
        None => resolver,
    };
    let result = rt
        .block_on(resolver.resolve_with_metadata(did))
        .map_err(to_pyerr)?;
    serde_json::to_string(&result).map_err(to_pyerr)
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

/// Encrypt a DIDComm Messaging 2.1 plaintext message for one recipient.
///
/// The public credential-delivery profile uses X25519 anonymous encryption
/// with `ECDH-ES+A256KW` key wrapping and the required `A256CBC-HS512`
/// content-encryption algorithm.
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

/// Encrypt a DIDComm Messaging 2.1 plaintext message with sender authentication.
///
/// The sender private key must match an X25519 method authorized by the sender
/// DID document's `keyAgreement` relationship. The plaintext `from` and `to`
/// values must identify the supplied sender and recipient documents.
#[pyfunction]
fn didcomm_encrypt_authcrypt(
    plaintext_json: &str,
    sender_did_document_json: &str,
    sender_x25519_private_key: &[u8],
    recipient_did_document_json: &str,
) -> PyResult<String> {
    if sender_x25519_private_key.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "X25519 private key must be exactly 32 bytes",
        ));
    }
    let sender_doc: marty_didcomm::DidDocument =
        serde_json::from_str(sender_did_document_json).map_err(to_pyerr)?;
    let recipient_doc: marty_didcomm::DidDocument =
        serde_json::from_str(recipient_did_document_json).map_err(to_pyerr)?;
    let mut sender_key = [0u8; 32];
    sender_key.copy_from_slice(sender_x25519_private_key);
    marty_didcomm::encrypt_for_recipient_authenticated(
        plaintext_json,
        &sender_doc,
        &sender_key,
        &recipient_doc,
    )
    .map_err(to_pyerr)
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

/// Decrypt a one-recipient DIDComm authcrypt envelope and authenticate its sender.
///
/// Returns JSON containing `plaintext`, `sender_kid`, and `recipient_kid`.
/// Anoncrypt, legacy ECDH-1PU derivation, unauthorized methods, key/document
/// mismatch, and plaintext party substitution are rejected.
#[pyfunction]
fn didcomm_decrypt_authcrypt(
    jwe_json: &str,
    recipient_x25519_private_key: &[u8],
    recipient_did_document_json: &str,
    sender_did_document_json: &str,
) -> PyResult<String> {
    if recipient_x25519_private_key.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "X25519 private key must be exactly 32 bytes",
        ));
    }
    let recipient_doc: marty_didcomm::DidDocument =
        serde_json::from_str(recipient_did_document_json).map_err(to_pyerr)?;
    let sender_doc: marty_didcomm::DidDocument =
        serde_json::from_str(sender_did_document_json).map_err(to_pyerr)?;
    let mut recipient_key = [0u8; 32];
    recipient_key.copy_from_slice(recipient_x25519_private_key);
    let result = marty_didcomm::decrypt_authenticated_jwe(
        jwe_json,
        &recipient_key,
        &recipient_doc,
        &sender_doc,
    )
    .map_err(to_pyerr)?;
    serde_json::to_string(&result).map_err(to_pyerr)
}

// ============================================================================
// VDS-NC Verification
// ============================================================================

/// Verify a VDS-NC barcode string against an issuer JWK.
///
/// Parses the tilde-separated `header~payload_json~signature_b64` barcode,
/// validates the header structure, and verifies the ECDSA/EdDSA signature
/// using the supplied issuer public key JWK.
///
/// Supported algorithms: ES256 (P-256/SHA-256), ES384 (P-384/SHA-384),
/// EdDSA (Ed25519).  The algorithm is taken from the JWK `alg` field; if
/// absent it is inferred from the key type/curve.
///
/// Args:
///     barcode: Full VDS-NC tilde-separated barcode string.
///     issuer_jwk_json: Issuer public key as a JSON Web Key string.
///
/// Returns:
///     A dict with keys:
///       - ``verified`` (bool): overall verification result
///       - ``country`` (str | None): 3-letter country code from header
///       - ``header`` (str | None): full header segment
///       - ``payload`` (dict | None): parsed payload object
///       - ``signature_status`` (str): "Valid", "Invalid", or "Unknown"
///       - ``errors`` (list[str]): list of error descriptions; empty if verified
///
/// Raises:
///     ``RuntimeError`` if the JWK JSON cannot be parsed.
#[pyfunction]
fn vds_nc_verify(barcode: &str, issuer_jwk_json: &str) -> PyResult<Py<PyAny>> {
    pyo3::Python::attach(|py| {
        let result = marty_verification::verify_vds_nc_jwk_json(barcode, issuer_jwk_json)
            .map_err(to_pyerr)?;

        let sig_status = match result.signature_status {
            marty_verification::SignatureVerificationStatus::Valid => "Valid",
            marty_verification::SignatureVerificationStatus::Invalid => "Invalid",
            marty_verification::SignatureVerificationStatus::Unknown => "Unknown",
        };

        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("verified", result.verified)?;
        dict.set_item("country", result.country)?;
        dict.set_item("header", result.header)?;
        dict.set_item(
            "payload",
            result
                .payload
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_default(),
        )?;
        dict.set_item("signature_status", sig_status)?;
        dict.set_item("errors", result.errors)?;
        Ok(dict.into())
    })
}

fn vds_nc_error(error: impl std::fmt::Display) -> PyErr {
    PyErr::new::<VdsNcOperationError, _>(error.to_string())
}

/// Inspect canonical signer metadata without asserting authenticity.
#[pyfunction]
fn vds_nc_inspect(barcode: &str) -> PyResult<String> {
    let parsed = marty_verification::inspect_vds_nc(barcode).map_err(vds_nc_error)?;
    serde_json::to_string(&parsed).map_err(vds_nc_error)
}

/// Verify canonical profile, signature, printed fields, and temporal policy.
#[pyfunction]
#[pyo3(signature = (barcode, public_key_pem, evaluation_date, printed_values_json=None))]
fn vds_nc_verify_profile(
    barcode: &str,
    public_key_pem: &str,
    evaluation_date: &str,
    printed_values_json: Option<&str>,
) -> PyResult<String> {
    let evaluation_date = chrono::NaiveDate::parse_from_str(evaluation_date, "%Y-%m-%d")
        .map_err(|_| vds_nc_error("VDS_NC.INVALID_DATE: evaluation_date must use YYYY-MM-DD"))?;
    let printed_values = printed_values_json
        .map(serde_json::from_str::<serde_json::Value>)
        .transpose()
        .map_err(|error| vds_nc_error(format!("VDS_NC.INVALID_PRINTED_FIELDS: {error}")))?;
    if printed_values
        .as_ref()
        .is_some_and(|value| !value.is_object())
    {
        return Err(vds_nc_error(
            "VDS_NC.INVALID_PRINTED_FIELDS: expected a JSON object",
        ));
    }
    let result = marty_verification::verify_vds_nc_profile_pem(
        barcode,
        public_key_pem,
        printed_values.as_ref(),
        evaluation_date,
    )
    .map_err(vds_nc_error)?;
    serde_json::to_string(&result).map_err(vds_nc_error)
}

/// Validate canonical profile, printed fields, and temporal policy without
/// treating the result as an authenticity decision.
#[pyfunction]
#[pyo3(signature = (barcode, evaluation_date, printed_values_json=None))]
fn vds_nc_validate_profile(
    barcode: &str,
    evaluation_date: &str,
    printed_values_json: Option<&str>,
) -> PyResult<String> {
    use marty_oid4vci::formats::vds_nc_profile::{
        recommended_error_correction, select_barcode_format, validate_fields, validate_temporal,
        VdsNcDocumentType,
    };

    let evaluation_date = chrono::NaiveDate::parse_from_str(evaluation_date, "%Y-%m-%d")
        .map_err(|_| vds_nc_error("VDS_NC.INVALID_DATE: evaluation_date must use YYYY-MM-DD"))?;
    let printed_values = printed_values_json
        .map(serde_json::from_str::<serde_json::Value>)
        .transpose()
        .map_err(|error| vds_nc_error(format!("VDS_NC.INVALID_PRINTED_FIELDS: {error}")))?;
    if printed_values
        .as_ref()
        .is_some_and(|value| !value.is_object())
    {
        return Err(vds_nc_error(
            "VDS_NC.INVALID_PRINTED_FIELDS: expected a JSON object",
        ));
    }
    let parsed = marty_verification::inspect_vds_nc(barcode).map_err(vds_nc_error)?;
    let field_errors = validate_fields(&parsed.payload, printed_values.as_ref());
    let temporal_errors = validate_temporal(&parsed.payload, evaluation_date);
    let document_type =
        VdsNcDocumentType::parse(&parsed.metadata.document_type).map_err(vds_nc_error)?;
    let correction = recommended_error_correction(document_type);
    let format = select_barcode_format(barcode.len(), correction, None).map_err(vds_nc_error)?;
    let mut errors = field_errors.clone();
    errors.extend(temporal_errors.iter().cloned());
    serde_json::to_string(&serde_json::json!({
        "canonicalization_ok": true,
        "field_consistency_valid": field_errors.is_empty(),
        "temporal_validity_ok": temporal_errors.is_empty(),
        "document_type": document_type.as_str(),
        "issuing_country": parsed.country,
        "signer_id": parsed.metadata.issuer_id,
        "certificate_reference": parsed.metadata.certificate_reference,
        "algorithm": parsed.metadata.algorithm,
        "payload": parsed.payload,
        "barcode_format": format.as_str(),
        "error_correction": correction.as_str(),
        "field_errors": field_errors,
        "temporal_errors": temporal_errors,
        "errors": errors,
        "warnings": if printed_values.is_none() {
            vec!["No printed values provided for field comparison"]
        } else {
            Vec::<&str>::new()
        },
    }))
    .map_err(vds_nc_error)
}

/// Create and sign a canonical VDS-NC profile with a PEM private key.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn vds_nc_sign_profile(
    private_key_pem: &str,
    signer_id: &str,
    certificate_reference: &str,
    document_type: &str,
    issuing_country: &str,
    document_data_json: &str,
    algorithm: &str,
) -> PyResult<String> {
    use marty_oid4vci::types::{CredentialClaims, SignedCredential};

    let private_key_der =
        marty_crypto::serialization::load_private_key_pem(private_key_pem).map_err(vds_nc_error)?;
    let key_type = marty_crypto::serialization::detect_private_key_type(&private_key_der)
        .map_err(vds_nc_error)?;
    let expected_key_type = match algorithm {
        "ES256" => "EC_P256",
        "ES384" => "EC_P384",
        "EdDSA" => "Ed25519",
        "PS256" | "PS384" | "PS512" => "RSA",
        other => {
            return Err(vds_nc_error(format!(
                "unsupported VDS-NC algorithm: {other}"
            )))
        }
    };
    if key_type != expected_key_type {
        return Err(vds_nc_error(format!(
            "VDS_NC.KEY_ALGORITHM_MISMATCH: {key_type} key cannot sign with {algorithm}"
        )));
    }
    let mut claims: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_str(document_data_json).map_err(|error| {
            vds_nc_error(format!(
                "VDS_NC.INVALID_PROFILE: invalid document JSON: {error}"
            ))
        })?;
    claims.insert(
        "docType".to_owned(),
        serde_json::Value::String(document_type.to_owned()),
    );
    claims.insert(
        "issuingCountry".to_owned(),
        serde_json::Value::String(issuing_country.to_owned()),
    );
    claims.insert(
        "signerId".to_owned(),
        serde_json::Value::String(signer_id.to_owned()),
    );
    claims.insert(
        "certificateReference".to_owned(),
        serde_json::Value::String(certificate_reference.to_owned()),
    );
    let credential_claims = CredentialClaims {
        subject_id: None,
        credential_type: document_type.to_owned(),
        claims,
        expiration_seconds: None,
        selective_disclosure_claims: vec![],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        credential_payload_format: Default::default(),
        w3c_context: vec![],
        w3c_types: vec![],
    };
    let prepared = marty_oid4vci::formats::vds_nc::prepare_vds_nc_profile(
        signer_id,
        certificate_reference,
        algorithm,
        &credential_claims,
    )
    .map_err(vds_nc_error)?;
    let message = prepared.signing_input.as_bytes();
    let signature = match algorithm {
        "ES256" | "ES384" | "EdDSA" => {
            let (raw_private_key, _) =
                marty_crypto::serialization::pkcs8_to_raw_private_key(&private_key_der)
                    .map_err(vds_nc_error)?;
            match algorithm {
                "ES256" => marty_crypto::ecdsa::sign_p256_sha256(&raw_private_key, message),
                "ES384" => marty_crypto::ecdsa::sign_p384_sha384(&raw_private_key, message),
                "EdDSA" => marty_crypto::ed25519::sign(&raw_private_key, message),
                _ => unreachable!(),
            }
        }
        "PS256" => marty_crypto::rsa::sign_pss_sha256(&private_key_der, message),
        "PS384" => marty_crypto::rsa::sign_pss_sha384(&private_key_der, message),
        "PS512" => marty_crypto::rsa::sign_pss_sha512(&private_key_der, message),
        _ => unreachable!(),
    }
    .map_err(vds_nc_error)?;
    let signed = marty_oid4vci::formats::vds_nc::assemble_vds_nc_raw(prepared, &signature);
    let (barcode_data, credential_id) = match signed {
        SignedCredential::VdsNc {
            barcode_data,
            credential_id,
        } => (barcode_data, credential_id),
        _ => return Err(vds_nc_error("VDS-NC signer returned an unexpected format")),
    };
    let parsed = marty_verification::inspect_vds_nc(&barcode_data).map_err(vds_nc_error)?;
    let document_type = marty_oid4vci::formats::vds_nc_profile::VdsNcDocumentType::parse(
        &parsed.metadata.document_type,
    )
    .map_err(vds_nc_error)?;
    let correction =
        marty_oid4vci::formats::vds_nc_profile::recommended_error_correction(document_type);
    let format = marty_oid4vci::formats::vds_nc_profile::select_barcode_format(
        barcode_data.len(),
        correction,
        None,
    )
    .map_err(vds_nc_error)?;
    serde_json::to_string(&serde_json::json!({
        "barcode_data": barcode_data,
        "credential_id": credential_id,
        "payload": parsed.payload,
        "metadata": parsed.metadata,
        "barcode_format": format.as_str(),
        "error_correction": correction.as_str(),
    }))
    .map_err(vds_nc_error)
}

/// Canonicalize one VDS-NC document profile in Rust.
#[pyfunction]
fn vds_nc_canonicalize(document_type: &str, document_data_json: &str) -> PyResult<String> {
    let document_type =
        marty_oid4vci::formats::vds_nc_profile::VdsNcDocumentType::parse(document_type)
            .map_err(vds_nc_error)?;
    let document: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(document_data_json).map_err(vds_nc_error)?;
    let canonical =
        marty_oid4vci::formats::vds_nc_profile::canonicalize_document(document_type, &document)
            .map_err(vds_nc_error)?;
    serde_json::to_string(&canonical).map_err(vds_nc_error)
}

/// Return the retained profile's barcode policy decision.
#[pyfunction]
#[pyo3(signature = (document_type, payload_size, preferred_format=None))]
fn vds_nc_barcode_policy(
    document_type: &str,
    payload_size: usize,
    preferred_format: Option<&str>,
) -> PyResult<(String, String)> {
    use marty_oid4vci::formats::vds_nc_profile::{
        recommended_error_correction, select_barcode_format, VdsNcBarcodeFormat, VdsNcDocumentType,
    };
    let document_type = VdsNcDocumentType::parse(document_type).map_err(vds_nc_error)?;
    let correction = recommended_error_correction(document_type);
    let preferred = preferred_format
        .map(|value| match value {
            "QR" => Ok(VdsNcBarcodeFormat::Qr),
            "AZTEC" => Ok(VdsNcBarcodeFormat::Aztec),
            "DM" => Ok(VdsNcBarcodeFormat::DataMatrix),
            other => Err(vds_nc_error(format!(
                "unsupported VDS-NC barcode format: {other}"
            ))),
        })
        .transpose()?;
    let format =
        select_barcode_format(payload_size, correction, preferred).map_err(vds_nc_error)?;
    Ok((format.as_str().to_owned(), correction.as_str().to_owned()))
}

/// Select a barcode format with an explicit native error-correction level.
#[pyfunction]
#[pyo3(signature = (encoded_size, error_correction, preferred_format=None))]
fn vds_nc_select_barcode_format(
    encoded_size: usize,
    error_correction: &str,
    preferred_format: Option<&str>,
) -> PyResult<String> {
    use marty_oid4vci::formats::vds_nc_profile::{
        select_barcode_format, VdsNcBarcodeFormat, VdsNcErrorCorrection,
    };
    let correction = match error_correction {
        "L" => VdsNcErrorCorrection::Low,
        "M" => VdsNcErrorCorrection::Medium,
        "Q" => VdsNcErrorCorrection::Quartile,
        "H" => VdsNcErrorCorrection::High,
        other => {
            return Err(vds_nc_error(format!(
                "unsupported VDS-NC error correction level: {other}"
            )))
        }
    };
    let preferred = preferred_format
        .map(|value| match value {
            "QR" => Ok(VdsNcBarcodeFormat::Qr),
            "AZTEC" => Ok(VdsNcBarcodeFormat::Aztec),
            "DM" => Ok(VdsNcBarcodeFormat::DataMatrix),
            other => Err(vds_nc_error(format!(
                "unsupported VDS-NC barcode format: {other}"
            ))),
        })
        .transpose()?;
    select_barcode_format(encoded_size, correction, preferred)
        .map(|format| format.as_str().to_owned())
        .map_err(vds_nc_error)
}

/// Select the canonical credential verifier for a JSON or compact token.
///
/// This operation performs routing only. The selected verifier remains
/// responsible for proof, trust, status, and policy validation.
#[pyfunction]
fn detect_credential_format(input: &str) -> String {
    marty_verification::credential_format::detect_credential_format(input)
        .as_str()
        .to_string()
}

/// Resolve application profile aliases to the canonical Rust-issued OID4VP
/// format and DCQL metadata.
#[pyfunction]
fn credential_profile_presentation_metadata(
    profile: &str,
    credential_format: &str,
    type_identifier: &str,
) -> PyResult<String> {
    let metadata = marty_oid4vci::formats::credential_profile_presentation_metadata(
        profile,
        credential_format,
        type_identifier,
    )
    .map_err(to_pyerr)?;
    serde_json::to_string(&metadata).map_err(to_pyerr)
}

fn build_oid4vp_presentation_request_impl(request_json: &str) -> Result<String, String> {
    if request_json.len() > 1_000_000 {
        return Err("OID4VP presentation request input exceeds 1000000 bytes".into());
    }
    let request: marty_oid4vci::presentation_request::PresentationRequestBuildInput =
        serde_json::from_str(request_json)
            .map_err(|error| format!("invalid OID4VP presentation request input: {error}"))?;
    let result = marty_oid4vci::presentation_request::build_presentation_request(request)
        .map_err(|error| error.to_string())?;
    serde_json::to_string(&result)
        .map_err(|error| format!("OID4VP presentation request serialization failed: {error}"))
}

/// Build equivalent Presentation Exchange and DCQL credential queries in Rust.
#[pyfunction]
fn build_oid4vp_presentation_request(request_json: &str) -> PyResult<String> {
    build_oid4vp_presentation_request_impl(request_json)
        .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
}

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
/// Register the canonical Marty credential/protocol Python surface.
///
/// Downstream extension crates use this entry point to extend ``_marty_rs``
/// without copying bindings or publishing a second, incompatible module.
pub fn register_marty_bindings(m: &Bound<'_, PyModule>) -> PyResult<()> {
    flow::register_flow_bindings(m)?;
    oid4vp_identity::register(m)?;
    siop::register(m)?;
    m.add(
        "OidcValidationError",
        m.py().get_type::<OidcValidationError>(),
    )?;
    m.add(
        "PolicyEvaluationError",
        m.py().get_type::<PolicyEvaluationError>(),
    )?;
    m.add(
        "VdsNcOperationError",
        m.py().get_type::<VdsNcOperationError>(),
    )?;
    remote_credential::register(m)?;
    status_list::register_status_list_bindings(m)?;
    haip::register(m)?;

    // Key Generation
    m.add_function(wrap_pyfunction!(generate_p256_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_p256_jwk, m)?)?;
    m.add_function(wrap_pyfunction!(generate_p256_did_jwk, m)?)?;
    m.add_function(wrap_pyfunction!(derive_p256_did_identifier, m)?)?;
    m.add_function(wrap_pyfunction!(generate_p384_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_ed25519_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_did_key, m)?)?;

    // Signing
    m.add_function(wrap_pyfunction!(sign_p256, m)?)?;
    m.add_function(wrap_pyfunction!(sign_p384, m)?)?;
    m.add_function(wrap_pyfunction!(sign_ed25519, m)?)?;

    // Verification
    m.add_function(wrap_pyfunction!(detect_credential_format, m)?)?;
    m.add_function(wrap_pyfunction!(
        credential_profile_presentation_metadata,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(build_oid4vp_presentation_request, m)?)?;
    m.add_function(wrap_pyfunction!(verify_p256, m)?)?;
    m.add_function(wrap_pyfunction!(verify_p384, m)?)?;
    m.add_function(wrap_pyfunction!(verify_ed25519, m)?)?;
    m.add_function(wrap_pyfunction!(verify_vcdm_data_integrity, m)?)?;
    m.add_function(wrap_pyfunction!(verify_vcdm_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(verify_open_badge_v3_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(verification_build_decision_result, m)?)?;
    m.add_function(wrap_pyfunction!(key_attestation_policy, m)?)?;
    m.add_function(wrap_pyfunction!(key_attestation_route_proof, m)?)?;
    m.add_function(wrap_pyfunction!(key_attestation_validate, m)?)?;
    m.add_function(wrap_pyfunction!(
        key_attestation_validate_status_reference,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(key_attestation_validate_status_token, m)?)?;
    m.add_function(wrap_pyfunction!(key_attestation_behavior_fixture, m)?)?;
    m.add_function(wrap_pyfunction!(prepare_vcdm_data_integrity_credential, m)?)?;
    m.add_function(wrap_pyfunction!(
        complete_vcdm_data_integrity_credential,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(validate_vcdm_issuance_document, m)?)?;
    m.add_function(wrap_pyfunction!(validate_vcdm_related_resource_digests, m)?)?;
    m.add_function(wrap_pyfunction!(governance_canonical_digest, m)?)?;
    m.add_function(wrap_pyfunction!(governance_validate, m)?)?;
    m.add_function(wrap_pyfunction!(governance_authorize, m)?)?;
    m.add_function(wrap_pyfunction!(governance_from_snapshot, m)?)?;
    m.add_function(wrap_pyfunction!(governance_resume, m)?)?;
    m.add_function(wrap_pyfunction!(governance_require_purpose, m)?)?;
    m.add_function(wrap_pyfunction!(governance_validate_request, m)?)?;
    m.add_function(wrap_pyfunction!(evaluate_application_evidence_policy, m)?)?;
    m.add_function(wrap_pyfunction!(current_evidence_heads, m)?)?;
    m.add_function(wrap_pyfunction!(evidence_reconciliation_plan, m)?)?;
    m.add_function(wrap_pyfunction!(evidence_reconciliation_stale_reasons, m)?)?;
    m.add_function(wrap_pyfunction!(verification_behavior_fixture, m)?)?;
    m.add_function(wrap_pyfunction!(vds_nc_verify, m)?)?;
    m.add_function(wrap_pyfunction!(vds_nc_inspect, m)?)?;
    m.add_function(wrap_pyfunction!(vds_nc_verify_profile, m)?)?;
    m.add_function(wrap_pyfunction!(vds_nc_validate_profile, m)?)?;
    m.add_function(wrap_pyfunction!(vds_nc_sign_profile, m)?)?;
    m.add_function(wrap_pyfunction!(vds_nc_canonicalize, m)?)?;
    m.add_function(wrap_pyfunction!(vds_nc_barcode_policy, m)?)?;
    m.add_function(wrap_pyfunction!(vds_nc_select_barcode_format, m)?)?;
    m.add_class::<mdoc::MdocDocumentVerificationEvidence>()?;
    m.add_class::<mdoc::MdocIssuerVerificationResult>()?;
    m.add_class::<mdoc::MdocPresentationVerificationResult>()?;
    m.add_function(wrap_pyfunction!(mdoc::parse_device_response, m)?)?;
    m.add_function(wrap_pyfunction!(mdoc::verify_mdoc_cbor, m)?)?;
    m.add_function(wrap_pyfunction!(mdoc::verify_mdoc_issuer, m)?)?;
    m.add_function(wrap_pyfunction!(mdoc::verify_mdoc_presentation, m)?)?;
    m.add_function(wrap_pyfunction!(
        mdoc::build_openid4vp_mdoc_session_transcript,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        mdoc::openid4vp_response_key_thumbprint,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(mdoc::openid4vp_mdoc_binding_digests, m)?)?;

    // Verifiable Credentials
    m.add_function(wrap_pyfunction!(create_verifiable_credential, m)?)?;

    // Canvas LTI / Sandbox Hardening
    m.add_function(wrap_pyfunction!(canvas_normalize_base_url, m)?)?;
    m.add_function(wrap_pyfunction!(canvas_probe_lti_platform, m)?)?;
    m.add_function(wrap_pyfunction!(lti_verify_launch_jwt, m)?)?;

    // OID4VCI Protocol
    m.add_function(wrap_pyfunction!(oid4vci_create_credential_offer, m)?)?;
    m.add_function(wrap_pyfunction!(create_credential_offer, m)?)?;
    m.add_function(wrap_pyfunction!(generate_offer_uri, m)?)?;
    m.add_function(wrap_pyfunction!(generate_issuer_metadata, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_create_token_response, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_create_authorization_response, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_exchange_auth_code_for_token, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_verify_pkce_s256, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_create_proof_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_verify_proof_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_verify_compact_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(oidc_validate_id_token, m)?)?;
    m.add_function(wrap_pyfunction!(evaluate_presentation_policy, m)?)?;
    m.add_function(wrap_pyfunction!(evaluate_service_presentation_policy, m)?)?;
    m.add_function(wrap_pyfunction!(
        normalize_presentation_credential_format,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(native_backend_diagnostics, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_catalog_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_behavior_fixture_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_import_decision_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_public_sync_query_json, m)?)?;
    m.add_function(wrap_pyfunction!(
        trust_registry_public_sync_metadata_json,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(trust_registry_sync_is_due_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_validate_url, m)?)?;
    m.add_function(wrap_pyfunction!(
        trust_registry_destination_decision_json,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        trust_registry_private_host_allowlist_json,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(trust_registry_request_plan_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_validate_feed_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_validate_state_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_evaluate_pages_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_revalidate_state_json, m)?)?;
    device_auth::register_device_auth_bindings(m)?;
    m.add_function(wrap_pyfunction!(oid4vci_verify_detached_signature, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_normalize_ecdsa_signature, m)?)?;
    m.add_function(wrap_pyfunction!(
        oid4vci_verify_key_attestation_bound_proof_jwt,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(verify_sd_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(sd_jwt_create_presentation, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_sign_credential, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_prepare_credential, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_assemble_credential, m)?)?;
    m.add_class::<PreparedMdocForRemoteSigning>()?;
    m.add_function(wrap_pyfunction!(oid4vci_prepare_mdoc, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_assemble_mdoc, m)?)?;

    // OID4VP Protocol
    m.add_function(wrap_pyfunction!(oid4vp_verify_vp_token, m)?)?;
    m.add_function(wrap_pyfunction!(verify_presentation_structure, m)?)?;

    // Symmetric Crypto (EAC secure messaging)
    m.add_function(wrap_pyfunction!(aes_256_cbc_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_256_cbc_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(sha256, m)?)?;

    // DIDComm v2
    m.add_function(wrap_pyfunction!(didcomm_resolve_did, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_resolve_did_with_metadata, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_extract_endpoint, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_pack_credential, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_unpack_message, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_encrypt_authcrypt, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(didcomm_decrypt_authcrypt, m)?)?;
    Ok(())
}

#[cfg(feature = "extension-module")]
#[pymodule]
fn _marty_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    register_marty_bindings(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_verification_input() -> serde_json::Value {
        serde_json::json!({
            "verification_id": "verification-123",
            "context": {
                "mode": "ONLINE",
                "verifier_id": "verifier:example",
                "organization_id": "123e4567-e89b-42d3-a456-426614174000",
                "transaction_id": "transaction-example-001",
                "audience": "https://verifier.example"
            },
            "processing_status": "COMPLETED",
            "evaluated_at": "2026-08-08T23:30:00Z",
            "input_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "evidence_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "policy": {
                "id": "policy.example",
                "version": "1.0.0",
                "content_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            },
            "trust_profile": {
                "id": "trust.example",
                "version": "1.0.0",
                "content_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
            },
            "components": [{
                "component_id": "marty-verification",
                "version": "0.1.35",
                "artifact_digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
                "adapter_id": "oid4vp",
                "adapter_version": "1.0.0"
            }],
            "checks": [{
                "check_id": "credential.proof",
                "category": "CREDENTIAL_PROOF",
                "required": true,
                "outcome": "PASSED",
                "code": "CREDENTIAL_SIGNATURE_VALID",
                "component_id": "marty-verification",
                "evaluated_at": "2026-08-08T23:30:00Z",
                "evidence_refs": [
                    "urn:marty:evidence:123e4567-e89b-42d3-a456-426614174000"
                ]
            }]
        })
    }

    #[test]
    fn canonical_verification_binding_derives_the_result() {
        let input = canonical_verification_input().to_string();
        let output = verification_build_decision_result_impl(&input).expect("canonical result");
        let result: serde_json::Value = serde_json::from_str(&output).expect("result JSON");

        assert_eq!(result["decision"], "PASS");
        assert_eq!(result["decision_code"], "ALL_REQUIRED_CHECKS_PASSED");
        assert_eq!(result["valid"], true);
        assert_eq!(
            result["reducer"]["reducer_id"],
            "mip.required-check-reducer"
        );
        assert_eq!(result["reducer"]["version"], "1.0.0");
    }

    #[test]
    fn canonical_verification_binding_rejects_derived_and_unknown_fields() {
        for (path, value) in [
            ("schema_version", serde_json::json!("1.0.0")),
            ("decision", serde_json::json!("PASS")),
            (
                "decision_code",
                serde_json::json!("ALL_REQUIRED_CHECKS_PASSED"),
            ),
            ("valid", serde_json::json!(true)),
            (
                "reducer",
                serde_json::json!({"reducer_id": "caller", "version": "9"}),
            ),
            ("category_summaries", serde_json::json!([])),
        ] {
            let mut input = canonical_verification_input();
            input
                .as_object_mut()
                .expect("input object")
                .insert(path.to_owned(), value);
            let error = verification_build_decision_result_impl(&input.to_string())
                .expect_err("caller-derived field must fail");
            assert!(error.contains("unknown field"), "unexpected error: {error}");
        }

        for pointer in [
            "/context",
            "/policy",
            "/trust_profile",
            "/components/0",
            "/checks/0",
        ] {
            let mut nested = canonical_verification_input();
            nested
                .pointer_mut(pointer)
                .and_then(serde_json::Value::as_object_mut)
                .expect("nested input object")
                .insert("caller_field".to_owned(), serde_json::json!("caller text"));
            let error = verification_build_decision_result_impl(&nested.to_string())
                .expect_err("unknown nested field must fail");
            assert!(error.contains("unknown field"), "unexpected error: {error}");
        }
    }

    #[test]
    fn canonical_verification_binding_rejects_semantic_evidence_references() {
        let mut input = canonical_verification_input();
        input["checks"][0]["evidence_refs"] =
            serde_json::json!(["urn:marty:evidence:customer-123"]);
        let error = verification_build_decision_result_impl(&input.to_string())
            .expect_err("semantic evidence reference must fail");
        assert!(error.contains("opaque canonical Marty evidence UUID URN"));
    }

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

        assert_eq!(offer["credential_issuer"], "https://issuer.example.com");
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

        assert!(
            val.get("access_token").is_some(),
            "must contain access_token"
        );
        assert!(
            val.get("nonce").is_none(),
            "OID4VCI Final token responses must not contain a proof nonce"
        );
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
        assert_eq!(
            jwt.split('.').count(),
            3,
            "JWT must have header.payload.signature"
        );

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

    #[test]
    fn test_sd_jwt_binding_verifies_and_returns_reconstructed_claims() {
        use marty_oid4vci::formats::sd_jwt::sign_sd_jwt;
        use marty_oid4vci::types::{
            CredentialClaims, CredentialPayloadFormat, IssuerKey, SignedCredential,
            SigningAlgorithm,
        };

        let issuer_jwk = r#"{
            "kty":"OKP",
            "crv":"Ed25519",
            "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
        }"#;
        let issuer_public_jwk = r#"{
            "kty":"OKP",
            "crv":"Ed25519",
            "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }"#;
        let issuer = IssuerKey {
            issuer_id: "https://issuer.example.test".to_string(),
            jwk_json: issuer_jwk.to_string(),
            algorithm: SigningAlgorithm::EdDSA,
        };
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".to_string()),
            credential_type: "IdentityCredential".to_string(),
            claims: [("given_name".to_string(), serde_json::json!("Alice"))]
                .into_iter()
                .collect(),
            expiration_seconds: Some(3600),
            selective_disclosure_claims: vec!["given_name".to_string()],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: Vec::new(),
            credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
            w3c_context: Vec::new(),
            w3c_types: Vec::new(),
        };
        let compact = match sign_sd_jwt(&issuer, &claims).expect("SD-JWT issuance") {
            SignedCredential::SdJwt { compact, .. } => compact,
            _ => panic!("expected SD-JWT credential"),
        };

        let verified = verify_sd_jwt(&compact, issuer_public_jwk, None, None)
            .expect("binding must verify a valid SD-JWT");
        let payload: serde_json::Value = serde_json::from_str(&verified).expect("verified JSON");
        assert_eq!(payload["given_name"], "Alice");
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

        let result = normalize_zk_predicate_claims(&claims, vec!["birth_date".to_string()]);
        assert!(!result.is_empty());
        assert_eq!(result[0].claim_name, "birth_date");
    }

    #[test]
    fn test_normalize_zk_predicate_strings_with_birth_date() {
        let mut claims = std::collections::HashMap::new();
        claims.insert("birth_date".to_string(), serde_json::json!("1990-01-01"));

        // Input that looks like predicates, not claim names
        let result = normalize_zk_predicate_claims(&claims, vec!["age_over_18".to_string()]);
        assert!(!result.is_empty());
        assert_eq!(result[0].claim_name, "birth_date");
        assert!(result[0]
            .supported_predicates
            .contains(&"age_over_18".to_string()));
    }

    fn presentation_policy_request() -> serde_json::Value {
        serde_json::json!({
            "policy": {
                "id": "policy-1",
                "name": "Employee access",
                "description": null,
                "purpose": "Authorize access",
                "accepted_credential_types": ["EmployeeCredential"],
                "required_claims": [{
                    "claim_name": "employee_id",
                    "credential_type": "EmployeeCredential",
                    "accept_predicate": false,
                    "required_value": null
                }],
                "holder_binding": "session_nonce",
                "trust_profile_id": "workforce",
                "allowed_issuers": ["did:example:issuer"],
                "freshness_requirements": {
                    "max_credential_age_seconds": 3600,
                    "max_proof_age_seconds": 300,
                    "require_live_revocation_check": true
                },
                "prefer_predicates": true,
                "single_presentation": true,
                "derived_attribute_preferences": {},
                "credential_ranking_strategy": "freshest_first",
                "credential_ranking_weights": {},
                "metadata": {},
                "version": 1
            },
            "input": {
                "credential_types": ["EmployeeCredential"],
                "claims": {"employee_id": "E-123"},
                "issuer_id": "did:example:issuer",
                "trust_profile_verified": true,
                "issued_at_epoch_seconds": 900,
                "proof_epoch_seconds": 990,
                "evaluation_time_epoch_seconds": 1000,
                "holder_binding_verified": true,
                "revocation_checked": true,
                "not_revoked": true,
                "presentation_count": 1
            }
        })
    }

    #[test]
    fn presentation_policy_binding_returns_normalized_result() {
        let output = evaluate_presentation_policy_impl(&presentation_policy_request().to_string())
            .expect("valid policy request");
        let result: serde_json::Value = serde_json::from_str(&output).expect("result JSON");

        assert_eq!(result["is_satisfied"], true);
        assert_eq!(result["errors"], serde_json::json!([]));
        assert_eq!(
            result["minimum_disclosure_set"],
            serde_json::json!(["employee_id"])
        );
        assert_eq!(result["component_statuses"].as_array().unwrap().len(), 8);
    }

    #[test]
    fn presentation_policy_binding_rejects_unknown_fields() {
        let mut request = presentation_policy_request();
        request["input"]["unexpected"] = serde_json::json!(true);

        let error = evaluate_presentation_policy_impl(&request.to_string())
            .expect_err("unknown fields must fail closed");
        assert!(error.contains("unknown field"));
    }

    fn service_policy_request() -> serde_json::Value {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/vectors/presentation_policy_service.json"
        ))
        .expect("valid service policy golden vector");
        fixture["request"].clone()
    }

    #[test]
    fn service_policy_binding_returns_service_compatible_decision() {
        let output =
            evaluate_service_presentation_policy_impl(&service_policy_request().to_string())
                .expect("valid service policy request");
        let result: serde_json::Value = serde_json::from_str(&output).expect("result JSON");

        assert_eq!(result["result"], "passed");
        assert_eq!(result["decision"], "allow");
        assert_eq!(result["verified_claims"]["email"], "member@example.com");
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/vectors/presentation_policy_service.json"
        ))
        .expect("valid service policy golden vector");
        assert_eq!(
            result["required_total"],
            fixture["expected"]["required_total"]
        );
        assert_eq!(
            result["required_satisfied"],
            fixture["expected"]["required_satisfied"]
        );
        assert_eq!(result["errors"], serde_json::json!([]));
    }

    #[test]
    fn service_policy_binding_accepts_explicit_presentation_only_obligation() {
        let mut request = service_policy_request();
        request["policy"]["credential_requirements"] = serde_json::json!([]);
        request["policy"]["freshness"] = serde_json::Value::Null;
        request["policy"]["presentation_proof_required"] = serde_json::json!(true);
        request["credentials"] = serde_json::json!([]);
        request["presentation_verified"] = serde_json::json!(true);

        let output = evaluate_service_presentation_policy_impl(&request.to_string())
            .expect("valid presentation-only policy request");
        let result: serde_json::Value = serde_json::from_str(&output).expect("result JSON");

        assert_eq!(result["result"], "passed");
        assert_eq!(result["decision"], "allow");
        assert_eq!(result["required_total"], 1);
        assert_eq!(result["required_satisfied"], 1);
        assert_eq!(result["credential_results"], serde_json::json!([]));
        assert_eq!(result["verified_claims"], serde_json::json!({}));
    }

    #[test]
    fn service_policy_binding_rejects_unknown_constraints() {
        let mut request = service_policy_request();
        request["policy"]["credential_requirements"][0]["requested_claims"][0]["constraints"][0]
            ["constraint_type"] = serde_json::json!("unknown");

        let error = evaluate_service_presentation_policy_impl(&request.to_string())
            .expect_err("unknown constraints must fail closed");
        assert!(error.contains("unknown variant"));
    }

    #[test]
    fn presentation_format_normalization_uses_service_aliases() {
        assert_eq!(
            normalize_presentation_credential_format("w3c_vcdm_v2_sd_jwt"),
            "SD_JWT_VC"
        );
        assert_eq!(
            normalize_presentation_credential_format("JSON_LD"),
            "W3C_VCDM_V2_DI"
        );
    }

    #[test]
    fn native_diagnostics_advertise_migrated_capabilities() {
        let diagnostics: serde_json::Value =
            serde_json::from_str(&native_backend_diagnostics().expect("native diagnostics"))
                .expect("diagnostics JSON");
        let capabilities = diagnostics["capabilities"]
            .as_array()
            .expect("capability array");
        assert!(capabilities
            .iter()
            .any(|capability| capability == "did_resolution"));
        assert!(capabilities
            .iter()
            .any(|capability| capability == "did_identifier_derivation"));
        assert!(capabilities
            .iter()
            .any(|capability| capability == "openid4vp_mdoc_handover"));
        assert!(capabilities
            .iter()
            .any(|capability| capability == "haip_response_encryption"));
        assert!(capabilities
            .iter()
            .any(|capability| capability == "oid4vp_x509_identity"));
        assert!(capabilities
            .iter()
            .any(|capability| capability == "siop_jwk_id_token_verification"));
    }

    #[test]
    fn did_identifier_binding_derives_supported_methods_and_fails_closed() {
        let public_jwk = r#"{"alg":"ES256","crv":"P-256","kid":"key-1","kty":"EC","use":"sig","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}"#;
        assert!(derive_p256_did_identifier(public_jwk, "did:jwk")
            .unwrap()
            .starts_with("did:jwk:"));
        assert!(derive_p256_did_identifier(public_jwk, "did:key")
            .unwrap()
            .starts_with("did:key:z"));
        assert!(derive_p256_did_identifier(public_jwk, "did:web").is_err());
    }

    #[test]
    fn oid4vp_request_builder_binding_returns_both_query_shapes() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/vectors/oid4vp_request_builder.json"
        ))
        .expect("valid shared fixture");
        let vector = &fixture["valid"][0];

        let output = build_oid4vp_presentation_request_impl(&vector["request"].to_string())
            .expect("valid OID4VP builder input");
        let result: serde_json::Value = serde_json::from_str(&output).expect("result JSON");

        assert_eq!(result, vector["expected"]);
    }

    #[test]
    fn oid4vp_request_builder_binding_fails_closed() {
        let error = build_oid4vp_presentation_request_impl(
            r#"{"id":"pd-1","wallet_formats":["dc+sd-jwt"],"requirements":[]}"#,
        )
        .expect_err("empty requirements must fail");
        assert!(error.contains("at least one credential requirement"));
    }

    #[test]
    fn vds_nc_profile_binding_signs_and_verifies_in_rust() {
        let (private_key, public_key) = marty_crypto::ecdsa::generate_p256_keypair().unwrap();
        let private_der =
            marty_crypto::serialization::raw_private_key_to_pkcs8(&private_key, "EC_P256").unwrap();
        let public_der =
            marty_crypto::serialization::raw_public_key_to_spki(&public_key, "EC_P256").unwrap();
        let private_pem = marty_crypto::serialization::save_private_key_pem(&private_der).unwrap();
        let public_pem = marty_crypto::serialization::save_public_key_pem(&public_der).unwrap();
        let document = serde_json::json!({
            "documentNumber": "X123456",
            "surname": "Example",
            "givenNames": "Ada",
            "dateOfBirth": "19900102",
            "nationality": "AUS",
            "gender": "F",
            "dateOfIssue": "20260101",
            "dateOfExpiry": "20300101"
        });
        let signed: serde_json::Value = serde_json::from_str(
            &vds_nc_sign_profile(
                &private_pem,
                "TESTSGN",
                "TESTCERT001",
                "CMC",
                "AUS",
                &document.to_string(),
                "ES256",
            )
            .unwrap(),
        )
        .unwrap();
        let verified: serde_json::Value = serde_json::from_str(
            &vds_nc_verify_profile(
                signed["barcode_data"].as_str().unwrap(),
                &public_pem,
                "2027-01-01",
                Some(r#"{"surname":"example"}"#),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verified["is_valid"], true);
        assert_eq!(verified["signature_valid"], true);
        assert_eq!(verified["field_consistency_valid"], true);
        assert_eq!(verified["signer_id"], "TESTSGN");

        let policy: serde_json::Value = serde_json::from_str(
            &vds_nc_validate_profile(
                signed["barcode_data"].as_str().unwrap(),
                "2031-01-01",
                Some(r#"{"surname":"changed"}"#),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(policy["canonicalization_ok"], true);
        assert_eq!(policy["field_consistency_valid"], false);
        assert_eq!(policy["temporal_validity_ok"], false);
        assert!(policy["field_errors"].as_array().unwrap()[0]
            .as_str()
            .unwrap()
            .contains("FIELD_MISMATCH"));

        let (rsa_private_der, rsa_public_der) =
            marty_crypto::rsa::generate_rsa_keypair(2048).unwrap();
        let rsa_private_pem =
            marty_crypto::serialization::save_private_key_pem(&rsa_private_der).unwrap();
        let rsa_public_pem =
            marty_crypto::serialization::save_public_key_pem(&rsa_public_der).unwrap();
        let rsa_signed: serde_json::Value = serde_json::from_str(
            &vds_nc_sign_profile(
                &rsa_private_pem,
                "TESTSGN",
                "TESTRSA001",
                "CMC",
                "AUS",
                &document.to_string(),
                "PS256",
            )
            .unwrap(),
        )
        .unwrap();
        let rsa_verified: serde_json::Value = serde_json::from_str(
            &vds_nc_verify_profile(
                rsa_signed["barcode_data"].as_str().unwrap(),
                &rsa_public_pem,
                "2027-01-01",
                None,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(rsa_verified["is_valid"], true);
        assert_eq!(rsa_verified["algorithm"], "PS256");

        assert_eq!(
            vds_nc_select_barcode_format(2_000, "L", Some("QR")).unwrap(),
            "QR"
        );
        assert_eq!(
            vds_nc_select_barcode_format(2_000, "H", Some("QR")).unwrap(),
            "DM"
        );
    }
}
