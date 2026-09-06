//! Python adapters for crypto.

use super::*;

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

/// Load a private key from PEM format, return PKCS#8 DER.
#[pyfunction]
pub(super) fn load_private_key_pem<'py>(
    py: Python<'py>,
    pem_data: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let der = marty_crypto::serialization::load_private_key_pem(pem_data).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &der))
}

/// Validate/load a private key from DER format.
#[pyfunction]
pub(super) fn load_private_key_der<'py>(
    py: Python<'py>,
    der_data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let der = marty_crypto::serialization::load_private_key_der(der_data).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &der))
}

/// Save a private key to PEM format (PKCS#8).
#[pyfunction]
pub(super) fn save_private_key_pem(private_key_der: &[u8]) -> PyResult<String> {
    marty_crypto::serialization::save_private_key_pem(private_key_der).map_err(to_pyerr)
}

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

/// Extract public key from private key (PKCS#8 DER).
#[pyfunction]
pub(super) fn extract_public_key<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let pubkey =
        marty_crypto::serialization::extract_public_key(private_key_der).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &pubkey))
}

/// Detect the type of a private key.
#[pyfunction]
pub(super) fn detect_private_key_type(der_data: &[u8]) -> PyResult<String> {
    marty_crypto::serialization::detect_private_key_type(der_data).map_err(to_pyerr)
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

/// Convert raw EC private key bytes to PKCS#8 DER format.
#[pyfunction]
pub(super) fn raw_private_key_to_pkcs8<'py>(
    py: Python<'py>,
    raw_key: &[u8],
    key_type: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let der = marty_crypto::serialization::raw_private_key_to_pkcs8(raw_key, key_type)
        .map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &der))
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

/// Extract raw private key bytes from PKCS#8 DER format.
#[pyfunction]
pub(super) fn pkcs8_to_raw_private_key<'py>(
    py: Python<'py>,
    pkcs8_der: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, String)> {
    let (raw, key_type) =
        marty_crypto::serialization::pkcs8_to_raw_private_key(pkcs8_der).map_err(to_pyerr)?;
    Ok((PyBytes::new(py, &raw), key_type))
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

/// Derive a key using HKDF-SHA256.
#[pyfunction]
pub(super) fn hkdf_sha256<'py>(
    py: Python<'py>,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let result = marty_crypto::kdf::hkdf_sha256(ikm, salt, info, length).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &result))
}

/// Derive a key using HKDF-SHA384.
#[pyfunction]
pub(super) fn hkdf_sha384<'py>(
    py: Python<'py>,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let result = marty_crypto::kdf::hkdf_sha384(ikm, salt, info, length).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &result))
}

/// Derive a key using PBKDF2-SHA256.
#[pyfunction]
pub(super) fn pbkdf2_sha256<'py>(
    py: Python<'py>,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let result = marty_crypto::kdf::pbkdf2_sha256(password, salt, iterations, key_length);
    Ok(PyBytes::new(py, &result))
}

/// Encrypt data using AES-GCM.
#[pyfunction]
pub(super) fn aes_gcm_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = match key.len() {
        16 => marty_crypto::symmetric::aes_128_gcm_encrypt(key, nonce, plaintext, aad),
        32 => marty_crypto::symmetric::aes_256_gcm_encrypt(key, nonce, plaintext, aad),
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Key must be 16 bytes (AES-128) or 32 bytes (AES-256)",
            ))
        }
    }
    .map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &result))
}

/// Decrypt data using AES-GCM.
#[pyfunction]
pub(super) fn aes_gcm_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = match key.len() {
        16 => marty_crypto::symmetric::aes_128_gcm_decrypt(key, nonce, ciphertext, aad),
        32 => marty_crypto::symmetric::aes_256_gcm_decrypt(key, nonce, ciphertext, aad),
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Key must be 16 bytes (AES-128) or 32 bytes (AES-256)",
            ))
        }
    }
    .map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &result))
}

/// Encrypt data using 3DES-CBC.
#[pyfunction]
pub(super) fn tdes_cbc_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result =
        marty_crypto::des::tdes_cbc_encrypt_padded(key, iv, plaintext).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &result))
}

/// Decrypt data using 3DES-CBC.
#[pyfunction]
pub(super) fn tdes_cbc_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result =
        marty_crypto::des::tdes_cbc_decrypt_padded(key, iv, ciphertext).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &result))
}

/// Generate an Ed25519 key pair.
#[pyfunction]
pub(super) fn ed25519_generate<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ed25519::generate_keypair();
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Sign a message with Ed25519.
#[pyfunction]
pub(super) fn ed25519_sign<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::ed25519::sign(secret_key, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

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

/// Generate an X25519 key pair.
#[pyfunction]
pub(super) fn x25519_generate<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ecdh::x25519_generate_keypair();
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Perform X25519 key agreement.
#[pyfunction]
pub(super) fn x25519_agree<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    peer_public: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let keypair =
        marty_crypto::ecdh::X25519KeyPair::from_secret_key(secret_key).map_err(to_pyerr)?;
    let shared = keypair.agree(peer_public).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &shared))
}

/// Generate a P-256 key pair.
#[pyfunction]
pub(super) fn p256_generate<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ecdh::p256_generate_keypair();
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Perform P-256 ECDH key agreement.
#[pyfunction]
pub(super) fn p256_agree<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    peer_public: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = marty_crypto::ecdh::p256_agree(secret_key, peer_public).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &result))
}

/// Generate a P-256 ECDSA key pair for signing.
#[pyfunction]
pub(super) fn ecdsa_p256_generate<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ecdsa::generate_p256_keypair().map_err(to_pyerr)?;
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Generate a P-384 ECDSA key pair for signing.
#[pyfunction]
pub(super) fn ecdsa_p384_generate<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ecdsa::generate_p384_keypair().map_err(to_pyerr)?;
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Sign a message with ECDSA P-256 SHA-256 (ES256).
#[pyfunction]
pub(super) fn ecdsa_p256_sign<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::ecdsa::sign_p256_sha256(secret_key, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with ECDSA P-384 SHA-384 (ES384).
#[pyfunction]
pub(super) fn ecdsa_p384_sign<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::ecdsa::sign_p384_sha384(secret_key, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

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

/// Generate a P-521 ECDSA key pair for signing.
#[pyfunction]
pub(super) fn ecdsa_p521_generate<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ecdsa::generate_p521_keypair().map_err(to_pyerr)?;
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Sign a message with ECDSA P-521 SHA-512 (ES512).
#[pyfunction]
pub(super) fn ecdsa_p521_sign<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::ecdsa::sign_p521_sha512(secret_key, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
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

/// Generate an RSA key pair (2048 bits by default).
#[pyfunction]
#[pyo3(signature = (bits = 2048))]
pub(super) fn rsa_generate<'py>(
    py: Python<'py>,
    bits: usize,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (private_der, public_der) =
        marty_crypto::rsa::generate_rsa_keypair(bits).map_err(to_pyerr)?;
    Ok((
        PyBytes::new(py, &private_der),
        PyBytes::new(py, &public_der),
    ))
}

/// Sign a message with RSA PKCS#1 v1.5 SHA-256 (RS256).
#[pyfunction]
pub(super) fn rsa_pkcs1_sha256_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::rsa::sign_pkcs1_sha256(private_key_der, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with RSA PKCS#1 v1.5 SHA-384 (RS384).
#[pyfunction]
pub(super) fn rsa_pkcs1_sha384_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::rsa::sign_pkcs1_sha384(private_key_der, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with RSA PKCS#1 v1.5 SHA-512 (RS512).
#[pyfunction]
pub(super) fn rsa_pkcs1_sha512_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::rsa::sign_pkcs1_sha512(private_key_der, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with RSA-PSS SHA-256 (PS256).
#[pyfunction]
pub(super) fn rsa_pss_sha256_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::rsa::sign_pss_sha256(private_key_der, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with RSA-PSS SHA-384 (PS384).
#[pyfunction]
pub(super) fn rsa_pss_sha384_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::rsa::sign_pss_sha384(private_key_der, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with RSA-PSS SHA-512 (PS512).
#[pyfunction]
pub(super) fn rsa_pss_sha512_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::rsa::sign_pss_sha512(private_key_der, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

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

/// Generate random bytes.
#[pyfunction]
pub(super) fn generate_random_bytes<'py>(py: Python<'py>, length: usize) -> Bound<'py, PyBytes> {
    let bytes = marty_crypto::keygen::generate_random_bytes(length);
    PyBytes::new(py, &bytes)
}

/// Generate a cryptographic key.
#[pyfunction]
pub(super) fn generate_key<'py>(
    py: Python<'py>,
    key_type: &str,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    use marty_crypto::keygen::{generate_keypair, KeyType};

    let kt = match key_type.to_lowercase().as_str() {
        "ed25519" => KeyType::Ed25519,
        "x25519" => KeyType::X25519,
        "p256" | "ecdsa_p256" | "ec_p256" => KeyType::EcdsaP256,
        "p384" | "ecdsa_p384" | "ec_p384" => KeyType::EcdsaP384,
        "rsa2048" => KeyType::Rsa2048,
        "rsa3072" => KeyType::Rsa3072,
        "rsa4096" => KeyType::Rsa4096,
        "aes128" => KeyType::Aes128,
        "aes256" => KeyType::Aes256,
        "hmac256" | "hmac_sha256" => KeyType::HmacSha256,
        "hmac384" | "hmac_sha384" => KeyType::HmacSha384,
        "hmac512" | "hmac_sha512" => KeyType::HmacSha512,
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown key type: {}",
                key_type
            )))
        }
    };

    let key = generate_keypair(kt).map_err(to_pyerr)?;
    Ok((
        PyBytes::new(py, &key.private_key),
        PyBytes::new(py, &key.public_key),
    ))
}

/// Generate an Ed448 key pair.
///
/// Returns:
///     Tuple of (private_key_bytes, public_key_bytes)
#[pyfunction]
pub(super) fn ed448_generate<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (private_key, public_key) = marty_crypto::ed448::ed448_generate().map_err(to_pyerr)?;
    Ok((
        PyBytes::new(py, &private_key),
        PyBytes::new(py, &public_key),
    ))
}

/// Sign a message using Ed448.
///
/// Args:
///     private_key: 57-byte private key
///     message: Message to sign
///
/// Returns:
///     114-byte signature
#[pyfunction]
pub(super) fn ed448_sign<'py>(
    py: Python<'py>,
    private_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::ed448::ed448_sign(private_key, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

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

/// Parsed PKCS#12 data.
#[pyclass(name = "Pkcs12Data", from_py_object)]
#[derive(Clone)]
pub struct PyPkcs12Data {
    #[pyo3(get)]
    pub private_key_algorithm: String,
    #[pyo3(get)]
    pub certificate_subject: Option<String>,
    #[pyo3(get)]
    pub friendly_name: Option<String>,
    #[pyo3(get)]
    pub chain_length: usize,
    private_key_der: Vec<u8>,
    certificate_der: Vec<u8>,
    certificate_chain: Vec<Vec<u8>>,
}

#[pymethods]
impl PyPkcs12Data {
    /// Get the private key in DER format.
    fn private_key_der<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.private_key_der)
    }

    /// Get the private key in PEM format.
    fn private_key_pem(&self) -> PyResult<String> {
        pem_rfc7468::encode_string(
            "PRIVATE KEY",
            pem_rfc7468::LineEnding::LF,
            &self.private_key_der,
        )
        .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to encode PEM: {}", e))
        })
    }

    /// Get the certificate in DER format.
    fn certificate_der<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.certificate_der)
    }

    /// Get the certificate in PEM format.
    fn certificate_pem(&self) -> PyResult<String> {
        pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            &self.certificate_der,
        )
        .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to encode PEM: {}", e))
        })
    }

    /// Get the certificate chain in PEM format.
    fn chain_pem(&self) -> PyResult<Vec<String>> {
        let mut result = vec![self.certificate_pem()?];
        for cert in &self.certificate_chain {
            let pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, cert)
                .map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Failed to encode PEM: {}", e))
                })?;
            result.push(pem);
        }
        Ok(result)
    }

    fn __repr__(&self) -> String {
        format!(
            "Pkcs12Data(algorithm={}, subject={:?}, chain_length={})",
            self.private_key_algorithm, self.certificate_subject, self.chain_length
        )
    }
}

/// Parse a PKCS#12 (PFX) file.
///
/// Args:
///     data: Raw PKCS#12 file bytes
///     password: Password to decrypt the file
///
/// Returns:
///     Pkcs12Data with private key, certificate, and chain
#[pyfunction]
pub(super) fn pkcs12_parse(data: &[u8], password: &str) -> PyResult<PyPkcs12Data> {
    let parsed = marty_crypto::pkcs12::parse_pkcs12(data, password).map_err(to_pyerr)?;

    Ok(PyPkcs12Data {
        private_key_algorithm: parsed.private_key_algorithm.to_string(),
        certificate_subject: parsed.certificate_subject,
        friendly_name: parsed.friendly_name,
        chain_length: parsed.certificate_chain.len() + 1,
        private_key_der: parsed.private_key_der,
        certificate_der: parsed.certificate_der,
        certificate_chain: parsed.certificate_chain,
    })
}

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

/// Create a Scheme 1 signature for passport-chip simulators and tests.
#[pyfunction]
pub(super) fn iso9796_scheme1_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::iso9796::iso9796_scheme1_sign(private_key_der, message).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

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
