//! ECDSA signature verification for P-256, P-384, and P-521 curves.

use p256::ecdsa::Signature as P256Signature;
use p384::ecdsa::Signature as P384Signature;
use p521::ecdsa::Signature as P521Signature;

use crate::{CryptoError, CryptoResult};

#[cfg(not(test))]
/// Marker documenting the verifier-only ECDSA API boundary.
///
/// Local signing and key generation do not exist in this build:
///
/// ```compile_fail
/// let _ = marty_crypto::ecdsa::generate_p256_keypair();
/// ```
pub struct VerificationOnly;

// ============================================================================
// ECDSA Verification
// ============================================================================

/// Verify ECDSA P-256 signature with SHA-256 (ES256).
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo
/// * `message` - The message that was signed
/// * `signature` - The signature bytes (DER or raw format)
///
/// # Returns
///
/// `Ok(true)` if valid, `Ok(false)` if invalid signature.
pub fn verify_p256_sha256(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key = match p256::PublicKey::from_sec1_bytes(public_key_der) {
        Ok(public_key) => public_key,
        Err(_) => {
            let point =
                extract_named_curve_point(public_key_der, const_oid::db::rfc5912::SECP_256_R_1)?;
            p256::PublicKey::from_sec1_bytes(&point).map_err(|e| {
                CryptoError::invalid_signature_with_context(
                    "ECDSA P-256",
                    format!("Invalid public key: {e}"),
                )
            })?
        }
    };

    // Try DER-encoded signature first, then raw format
    let sig = P256Signature::from_der(signature)
        .or_else(|_| P256Signature::from_slice(signature))
        .map_err(|e| {
            CryptoError::invalid_signature_with_context(
                "ECDSA P-256",
                format!("Invalid signature format: {}", e),
            )
        })?;

    use sha2::Digest;
    let digest = sha2::Sha256::digest(message);
    let z = ecdsa_core::hazmat::bits2field::<p256::NistP256>(&digest)
        .map_err(|_| CryptoError::invalid_signature("ECDSA P-256 digest"))?;
    let public_point = p256::ProjectivePoint::from(*public_key.as_affine());
    match ecdsa_core::hazmat::verify_prehashed::<p256::NistP256>(&public_point, &z, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify ECDSA P-384 signature with SHA-384 (ES384).
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo
/// * `message` - The message that was signed
/// * `signature` - The signature bytes (DER or raw format)
///
/// # Returns
///
/// `Ok(true)` if valid, `Ok(false)` if invalid signature.
pub fn verify_p384_sha384(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key = match p384::PublicKey::from_sec1_bytes(public_key_der) {
        Ok(public_key) => public_key,
        Err(_) => {
            let point =
                extract_named_curve_point(public_key_der, const_oid::db::rfc5912::SECP_384_R_1)?;
            p384::PublicKey::from_sec1_bytes(&point).map_err(|e| {
                CryptoError::invalid_signature_with_context(
                    "ECDSA P-384",
                    format!("Invalid public key: {e}"),
                )
            })?
        }
    };

    // Try DER-encoded signature first, then raw format
    let sig = P384Signature::from_der(signature)
        .or_else(|_| P384Signature::from_slice(signature))
        .map_err(|e| {
            CryptoError::invalid_signature_with_context(
                "ECDSA P-384",
                format!("Invalid signature format: {}", e),
            )
        })?;

    use sha2::Digest;
    let digest = sha2::Sha384::digest(message);
    let z = ecdsa_core::hazmat::bits2field::<p384::NistP384>(&digest)
        .map_err(|_| CryptoError::invalid_signature("ECDSA P-384 digest"))?;
    let public_point = p384::ProjectivePoint::from(*public_key.as_affine());
    match ecdsa_core::hazmat::verify_prehashed::<p384::NistP384>(&public_point, &z, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify ECDSA P-521 signature with SHA-512 (ES512).
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo
/// * `message` - The message that was signed
/// * `signature` - The signature bytes (DER or raw format)
///
/// # Returns
///
/// `Ok(true)` if valid, `Ok(false)` if invalid signature.
pub fn verify_p521_sha512(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key = match p521::PublicKey::from_sec1_bytes(public_key_der) {
        Ok(public_key) => public_key,
        Err(_) => {
            let point =
                extract_named_curve_point(public_key_der, const_oid::db::rfc5912::SECP_521_R_1)?;
            p521::PublicKey::from_sec1_bytes(&point).map_err(|e| {
                CryptoError::invalid_signature_with_context(
                    "ECDSA P-521",
                    format!("Invalid public key: {e}"),
                )
            })?
        }
    };

    // Try DER-encoded signature first, then raw format
    let sig = P521Signature::from_der(signature)
        .or_else(|_| P521Signature::from_slice(signature))
        .map_err(|e| {
            CryptoError::invalid_signature_with_context(
                "ECDSA P-521",
                format!("Invalid signature format: {}", e),
            )
        })?;

    use sha2::Digest;
    let digest = sha2::Sha512::digest(message);
    let z = ecdsa_core::hazmat::bits2field::<p521::NistP521>(&digest)
        .map_err(|_| CryptoError::invalid_signature("ECDSA P-521 digest"))?;
    let public_point = p521::ProjectivePoint::from(*public_key.as_affine());
    match ecdsa_core::hazmat::verify_prehashed::<p521::NistP521>(&public_point, &z, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Extract a named-curve EC public point from SubjectPublicKeyInfo.
///
/// The algorithm identifier and named-curve parameters are validated before
/// the public BIT STRING is returned. The caller remains responsible for
/// interpreting the point using the declared curve.
pub fn extract_ec_point_from_spki(spki_der: &[u8]) -> CryptoResult<Vec<u8>> {
    use der::Decode;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse SPKI: {}", e)))?;
    if spki.algorithm.oid != const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
        return Err(CryptoError::invalid_signature(
            "SPKI algorithm is not id-ecPublicKey",
        ));
    }
    spki.algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| CryptoError::invalid_signature("EC named-curve parameters are missing"))?
        .decode_as::<const_oid::ObjectIdentifier>()
        .map_err(|_| CryptoError::invalid_signature("EC named-curve parameters are invalid"))?;
    if spki.subject_public_key.unused_bits() != 0 {
        return Err(CryptoError::invalid_signature(
            "EC public key BIT STRING has unused bits",
        ));
    }

    Ok(spki.subject_public_key.raw_bytes().to_vec())
}

fn extract_named_curve_point(
    spki_der: &[u8],
    expected_curve: const_oid::ObjectIdentifier,
) -> CryptoResult<Vec<u8>> {
    use der::Decode;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse SPKI: {e}")))?;
    if spki.algorithm.oid != const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
        return Err(CryptoError::invalid_signature(
            "ECDSA public key algorithm is not id-ecPublicKey",
        ));
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| CryptoError::invalid_signature("ECDSA named-curve parameters are missing"))?
        .decode_as::<const_oid::ObjectIdentifier>()
        .map_err(|_| CryptoError::invalid_signature("ECDSA named-curve parameters are invalid"))?;
    if curve != expected_curve {
        return Err(CryptoError::invalid_signature(
            "ECDSA public key uses an unexpected named curve",
        ));
    }
    if spki.subject_public_key.unused_bits() != 0 {
        return Err(CryptoError::invalid_signature(
            "ECDSA public key BIT STRING has unused bits",
        ));
    }
    Ok(spki.subject_public_key.raw_bytes().to_vec())
}

/// Normalize an ES256, ES384, or ES512 signature to fixed-width IEEE P1363/JOSE form.
///
/// Provider APIs commonly return ASN.1 DER while JWS and COSE use `r || s`.
/// Already-normalized signatures are accepted only at the exact curve width;
/// malformed DER and unsupported algorithms fail closed.
pub fn normalize_signature(signature: &[u8], algorithm: &str) -> CryptoResult<Vec<u8>> {
    match algorithm {
        "ES256" if signature.len() == 64 => Ok(signature.to_vec()),
        "ES256" => p256::ecdsa::Signature::from_der(signature)
            .map(|value| value.to_bytes().to_vec())
            .map_err(|error| {
                CryptoError::invalid_signature(format!("Invalid ES256 signature encoding: {error}"))
            }),
        "ES384" if signature.len() == 96 => Ok(signature.to_vec()),
        "ES384" => p384::ecdsa::Signature::from_der(signature)
            .map(|value| value.to_bytes().to_vec())
            .map_err(|error| {
                CryptoError::invalid_signature(format!("Invalid ES384 signature encoding: {error}"))
            }),
        "ES512" if signature.len() == 132 => Ok(signature.to_vec()),
        "ES512" => p521::ecdsa::Signature::from_der(signature)
            .map(|value| value.to_bytes().to_vec())
            .map_err(|error| {
                CryptoError::invalid_signature(format!("Invalid ES512 signature encoding: {error}"))
            }),
        _ => Err(CryptoError::unsupported_algorithm(format!(
            "Unsupported ECDSA signature algorithm: {algorithm}"
        ))),
    }
}
