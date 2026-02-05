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
    
    Ok(serde_json::to_string_pretty(&credential).unwrap())
}

/// Helper function to encode bytes as base64url (no padding)
fn base64_url_encode(data: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
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
    
    Ok(())
}

