//! Python adapters for crypto.

use super::to_pyerr;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::types::PyDict;

// ============================================================================
// Certificate Bindings
// ============================================================================

/// Load a certificate from PEM format, return DER bytes.
#[pyfunction]
pub(super) fn load_certificate_pem<'py>(
    py: Python<'py>,
    pem_data: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let der = marty_crypto::certificate::load_certificate_pem(pem_data).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &der))
}

/// Validate a certificate DER encoding.
#[pyfunction]
pub(super) fn load_certificate_der<'py>(
    py: Python<'py>,
    der_data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let _cert = marty_crypto::certificate::load_certificate_der(der_data).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, der_data))
}

/// Get certificate info as a dictionary.
#[pyfunction]
pub(super) fn get_certificate_info<'py>(
    py: Python<'py>,
    der_data: &[u8],
) -> PyResult<Bound<'py, PyDict>> {
    let info = marty_crypto::certificate::get_certificate_info(der_data).map_err(to_pyerr)?;

    let dict = PyDict::new(py);
    dict.set_item("subject", &info.subject)?;
    dict.set_item("issuer", &info.issuer)?;
    dict.set_item("serial_number", &info.serial_number)?;
    dict.set_item("not_before", &info.not_before)?;
    dict.set_item("not_after", &info.not_after)?;
    dict.set_item("is_ca", info.is_ca)?;
    dict.set_item("key_usage", info.key_usage)?;
    dict.set_item("subject_alt_names", info.subject_alt_names)?;
    dict.set_item("signature_algorithm", &info.signature_algorithm)?;
    dict.set_item("subject_key_identifier", &info.subject_key_identifier)?;
    dict.set_item("authority_key_identifier", &info.authority_key_identifier)?;
    dict.set_item("fingerprint_sha1", &info.fingerprint_sha1)?;
    dict.set_item("fingerprint_sha256", &info.fingerprint_sha256)?;
    Ok(dict)
}

/// Convert certificate PEM to DER.
#[pyfunction]
pub(super) fn certificate_pem_to_der<'py>(
    py: Python<'py>,
    pem_data: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let der = marty_crypto::certificate::pem_to_der(pem_data).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &der))
}

/// Convert certificate DER to PEM.
#[pyfunction]
pub(super) fn certificate_der_to_pem(der_data: &[u8]) -> PyResult<String> {
    marty_crypto::certificate::der_to_pem(der_data).map_err(to_pyerr)
}

/// Get certificate public key in SPKI DER format.
#[pyfunction]
pub(super) fn get_certificate_public_key<'py>(
    py: Python<'py>,
    der_data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let pubkey =
        marty_crypto::certificate::get_certificate_public_key(der_data).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &pubkey))
}

/// Check if a certificate is expired.
#[pyfunction]
pub(super) fn is_certificate_expired(der_data: &[u8]) -> PyResult<bool> {
    marty_crypto::certificate::is_certificate_expired(der_data).map_err(to_pyerr)
}

/// Check if a certificate is not yet valid.
#[pyfunction]
pub(super) fn is_certificate_not_yet_valid(der_data: &[u8]) -> PyResult<bool> {
    marty_crypto::certificate::is_certificate_not_yet_valid(der_data).map_err(to_pyerr)
}

/// Verify that a certificate was signed by another certificate.
#[pyfunction]
pub(super) fn verify_certificate_signature(cert_der: &[u8], issuer_der: &[u8]) -> PyResult<bool> {
    marty_crypto::certificate::verify_certificate_signature(cert_der, issuer_der).map_err(to_pyerr)
}

// ============================================================================
// Key Serialization Bindings
// ============================================================================

/// Load a public key from PEM format (SPKI), return DER.
#[pyfunction]
pub(super) fn load_public_key_pem<'py>(
    py: Python<'py>,
    pem_data: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let der = marty_crypto::serialization::load_public_key_pem(pem_data).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &der))
}

/// Validate/load a public key from DER format.
#[pyfunction]
pub(super) fn load_public_key_der<'py>(
    py: Python<'py>,
    der_data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let der = marty_crypto::serialization::load_public_key_der(der_data).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &der))
}

/// Save a public key to PEM format (SPKI).
#[pyfunction]
pub(super) fn save_public_key_pem(public_key_der: &[u8]) -> PyResult<String> {
    marty_crypto::serialization::save_public_key_pem(public_key_der).map_err(to_pyerr)
}

/// Convert a supported SubjectPublicKeyInfo PEM public key to a public JWK.
#[pyfunction]
pub(super) fn public_key_pem_to_jwk(public_key_pem: &str) -> PyResult<String> {
    crate::jwk::public_key_pem_to_jwk(public_key_pem)
        .and_then(|jwk| jwk.to_json())
        .map_err(to_pyerr)
}

/// Convert a supported SubjectPublicKeyInfo DER public key to a public JWK.
#[pyfunction]
pub(super) fn public_key_der_to_jwk(public_key_der: &[u8]) -> PyResult<String> {
    crate::jwk::public_key_der_to_jwk(public_key_der)
        .and_then(|jwk| jwk.to_json())
        .map_err(to_pyerr)
}

/// Extract a public JWK from a PEM X.509 certificate.
#[pyfunction]
pub(super) fn certificate_pem_to_jwk(certificate_pem: &str) -> PyResult<String> {
    crate::jwk::certificate_pem_to_jwk(certificate_pem)
        .and_then(|jwk| jwk.to_json())
        .map_err(to_pyerr)
}

/// Extract a public JWK from a DER X.509 certificate.
#[pyfunction]
pub(super) fn certificate_der_to_jwk(certificate_der: &[u8]) -> PyResult<String> {
    crate::jwk::certificate_der_to_jwk(certificate_der)
        .and_then(|jwk| jwk.to_json())
        .map_err(to_pyerr)
}

/// Convert a public P-256 JWK to SubjectPublicKeyInfo PEM.
#[pyfunction]
pub(super) fn p256_public_jwk_to_pem(public_jwk_json: &str) -> PyResult<String> {
    use pyo3::exceptions::PyValueError;

    let jwk = crate::jwk::Jwk::from_json(public_jwk_json).map_err(to_pyerr)?;
    if jwk.is_private() {
        return Err(PyValueError::new_err(
            "public_jwk must not contain private key material",
        ));
    }
    if jwk.kty != "EC" || jwk.crv.as_deref() != Some("P-256") {
        return Err(PyValueError::new_err("public_jwk must be an EC P-256 key"));
    }

    let x = crate::jwk::base64url_decode(
        jwk.x
            .as_deref()
            .ok_or_else(|| PyValueError::new_err("public_jwk is missing x"))?,
    )
    .map_err(to_pyerr)?;
    let y = crate::jwk::base64url_decode(
        jwk.y
            .as_deref()
            .ok_or_else(|| PyValueError::new_err("public_jwk is missing y"))?,
    )
    .map_err(to_pyerr)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(PyValueError::new_err(
            "P-256 JWK coordinates must each be 32 bytes",
        ));
    }

    let mut raw_public_key = Vec::with_capacity(65);
    raw_public_key.push(0x04);
    raw_public_key.extend_from_slice(&x);
    raw_public_key.extend_from_slice(&y);
    let spki = marty_crypto::serialization::raw_public_key_to_spki(&raw_public_key, "EC_P256")
        .map_err(to_pyerr)?;
    marty_crypto::serialization::save_public_key_pem(&spki).map_err(to_pyerr)
}

/// Detect the type of a public key.
#[pyfunction]
pub(super) fn detect_public_key_type(der_data: &[u8]) -> PyResult<String> {
    marty_crypto::serialization::detect_public_key_type(der_data).map_err(to_pyerr)
}

/// Get the key size in bits.
#[pyfunction]
pub(super) fn get_key_size(public_key_der: &[u8]) -> PyResult<usize> {
    marty_crypto::serialization::get_key_size(public_key_der).map_err(to_pyerr)
}

/// Convert raw public key bytes to SPKI DER format.
#[pyfunction]
pub(super) fn raw_public_key_to_spki<'py>(
    py: Python<'py>,
    raw_key: &[u8],
    key_type: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let der =
        marty_crypto::serialization::raw_public_key_to_spki(raw_key, key_type).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &der))
}

/// Extract raw public key bytes from SPKI DER format.
#[pyfunction]
pub(super) fn spki_to_raw_public_key<'py>(
    py: Python<'py>,
    spki_der: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, String)> {
    let (raw, key_type) =
        marty_crypto::serialization::spki_to_raw_public_key(spki_der).map_err(to_pyerr)?;
    Ok((PyBytes::new(py, &raw), key_type))
}

// ============================================================================
// Ed25519 Bindings
// ============================================================================

/// Verify an Ed25519 signature.
#[pyfunction]
pub(super) fn ed25519_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    Ok(marty_crypto::ed25519::verify_bool(
        public_key, message, signature,
    ))
}

// ============================================================================
// ECDH Bindings
// ============================================================================

// ============================================================================
// ECDSA Signing Bindings
// ============================================================================

/// Verify an ECDSA P-256 SHA-256 signature.
#[pyfunction]
pub(super) fn ecdsa_p256_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::ecdsa::verify_p256_sha256(public_key, message, signature).map_err(to_pyerr)
}

/// Verify an ECDSA P-384 SHA-384 signature.
#[pyfunction]
pub(super) fn ecdsa_p384_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::ecdsa::verify_p384_sha384(public_key, message, signature).map_err(to_pyerr)
}

/// Verify an ECDSA P-521 SHA-512 signature.
#[pyfunction]
pub(super) fn ecdsa_p521_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::ecdsa::verify_p521_sha512(public_key, message, signature).map_err(to_pyerr)
}

// ============================================================================
// RSA Signing Bindings
// ============================================================================

/// Verify an RSA PKCS#1 v1.5 SHA-256 signature.
#[pyfunction]
pub(super) fn rsa_pkcs1_sha256_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pkcs1_sha256(public_key_der, message, signature).map_err(to_pyerr)
}

/// Verify an RSA PKCS#1 v1.5 SHA-384 signature.
#[pyfunction]
pub(super) fn rsa_pkcs1_sha384_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pkcs1_sha384(public_key_der, message, signature).map_err(to_pyerr)
}

/// Verify an RSA PKCS#1 v1.5 SHA-512 signature.
#[pyfunction]
pub(super) fn rsa_pkcs1_sha512_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pkcs1_sha512(public_key_der, message, signature).map_err(to_pyerr)
}

/// Verify an RSA-PSS SHA-256 signature.
#[pyfunction]
pub(super) fn rsa_pss_sha256_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pss_sha256(public_key_der, message, signature).map_err(to_pyerr)
}

/// Verify an RSA-PSS SHA-384 signature.
#[pyfunction]
pub(super) fn rsa_pss_sha384_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pss_sha384(public_key_der, message, signature).map_err(to_pyerr)
}

/// Verify an RSA-PSS SHA-512 signature.
#[pyfunction]
pub(super) fn rsa_pss_sha512_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pss_sha512(public_key_der, message, signature).map_err(to_pyerr)
}

// ============================================================================
// Ed448 Bindings
// ============================================================================

/// Verify an Ed448 signature.
///
/// Args:
///     public_key: 57-byte public key
///     message: Message that was signed
///     signature: 114-byte signature
///
/// Returns:
///     True if signature is valid
#[pyfunction]
pub(super) fn ed448_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    marty_crypto::ed448::ed448_verify(public_key, message, signature).map_err(to_pyerr)
}

// ============================================================================
// PKCS#12 Bindings
// ============================================================================

// ============================================================================
// ISO 9796-2 Bindings
// ============================================================================

/// Verify an ISO 9796-2 signature.
///
/// Args:
///     public_key_der: DER-encoded RSA public key
///     message: Message that was signed
///     signature: Signature to verify
///     scheme: Scheme number (1, 2, or 3)
///     hash_alg: Hash algorithm ("sha1", "sha256", "sha384", "sha512")
///
/// Returns:
///     True if signature is valid
#[pyfunction]
#[pyo3(signature = (public_key_der, message, signature, scheme=2, hash_alg="sha256"))]
pub(super) fn iso9796_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
    scheme: u8,
    hash_alg: &str,
) -> PyResult<bool> {
    use marty_crypto::iso9796::{Iso9796HashAlgorithm, Iso9796Scheme};

    let scheme = match scheme {
        1 => Iso9796Scheme::Scheme1,
        2 => Iso9796Scheme::Scheme2,
        3 => Iso9796Scheme::Scheme3,
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Scheme must be 1, 2, or 3",
            ))
        }
    };

    let hash_alg = match hash_alg.to_lowercase().as_str() {
        "sha1" => Iso9796HashAlgorithm::Sha1,
        "sha224" => Iso9796HashAlgorithm::Sha224,
        "sha256" => Iso9796HashAlgorithm::Sha256,
        "sha384" => Iso9796HashAlgorithm::Sha384,
        "sha512" => Iso9796HashAlgorithm::Sha512,
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Hash algorithm must be sha1, sha224, sha256, sha384, or sha512",
            ))
        }
    };

    marty_crypto::iso9796::iso9796_verify(public_key_der, message, signature, scheme, hash_alg)
        .map_err(to_pyerr)
}

/// Recover message from an ISO 9796-2 signature.
///
/// Args:
///     public_key_der: DER-encoded RSA public key
///     signature: Signature to recover from
///     scheme: Scheme number (1, 2, or 3)
///     hash_alg: Hash algorithm (optional, required for scheme 2/3)
///
/// Returns:
///     Recovered message portion
#[pyfunction]
#[pyo3(signature = (public_key_der, signature, scheme=2, hash_alg=None))]
pub(super) fn iso9796_recover<'py>(
    py: Python<'py>,
    public_key_der: &[u8],
    signature: &[u8],
    scheme: u8,
    hash_alg: Option<&str>,
) -> PyResult<Bound<'py, PyBytes>> {
    use marty_crypto::iso9796::{Iso9796HashAlgorithm, Iso9796Scheme};

    let scheme = match scheme {
        1 => Iso9796Scheme::Scheme1,
        2 => Iso9796Scheme::Scheme2,
        3 => Iso9796Scheme::Scheme3,
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Scheme must be 1, 2, or 3",
            ))
        }
    };

    let hash_alg = hash_alg
        .map(|h| match h.to_lowercase().as_str() {
            "sha1" => Ok(Iso9796HashAlgorithm::Sha1),
            "sha224" => Ok(Iso9796HashAlgorithm::Sha224),
            "sha256" => Ok(Iso9796HashAlgorithm::Sha256),
            "sha384" => Ok(Iso9796HashAlgorithm::Sha384),
            "sha512" => Ok(Iso9796HashAlgorithm::Sha512),
            _ => Err(pyo3::exceptions::PyValueError::new_err(
                "Hash algorithm must be sha1, sha224, sha256, sha384, or sha512",
            )),
        })
        .transpose()?;

    let recovered =
        marty_crypto::iso9796::iso9796_recover_message(public_key_der, signature, scheme, hash_alg)
            .map_err(to_pyerr)?;

    Ok(PyBytes::new(py, &recovered))
}

#[cfg(feature = "csca")]
pub(super) fn parse_iso9796_hash_algorithm(
    hash_algorithm: &str,
) -> PyResult<marty_crypto::iso9796::Iso9796HashAlgorithm> {
    use marty_crypto::iso9796::Iso9796HashAlgorithm;
    match hash_algorithm
        .to_ascii_lowercase()
        .replace('-', "")
        .as_str()
    {
        "sha1" => Ok(Iso9796HashAlgorithm::Sha1),
        "sha224" => Ok(Iso9796HashAlgorithm::Sha224),
        "sha256" => Ok(Iso9796HashAlgorithm::Sha256),
        "sha384" => Ok(Iso9796HashAlgorithm::Sha384),
        "sha512" => Ok(Iso9796HashAlgorithm::Sha512),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Unsupported Active Authentication hash algorithm: {hash_algorithm}"
        ))),
    }
}
