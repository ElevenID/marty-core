//! Ed25519 signature verification.
//!
//! This module verifies Ed25519 signatures using the ed25519-dalek crate.
//! Ed25519 is used in:
//! - DID document verification (did:key, did:web)
//! - SD-JWT verification
//! - Verifiable Credentials (EdDSA)
//!
//! # Security Properties
//!
//! - 128-bit security level
//! - Deterministic signatures (no random nonce needed)
//! - Fast verification (~15,000 ops/sec)
//! - Small signatures (64 bytes) and keys (32 bytes)

use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

use crate::{CryptoError, CryptoResult};

#[cfg(not(test))]
/// Marker documenting the verifier-only EdDSA API boundary.
///
/// Secret-key import and local signing do not exist in this build:
///
/// ```compile_fail
/// let _ = marty_crypto::ed25519::Ed25519KeyPair::generate();
/// ```
pub struct VerificationOnly;

// ============================================================================
// Key Types
// ============================================================================

/// Ed25519 public key for verification only.
#[derive(Clone)]
pub struct Ed25519VerifyingKey {
    key: VerifyingKey,
}

impl Ed25519VerifyingKey {
    /// Create from raw 32-byte public key.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(CryptoError::internal(format!(
                "Ed25519 public key must be {} bytes",
                PUBLIC_KEY_LENGTH
            )));
        }

        let bytes_array: [u8; PUBLIC_KEY_LENGTH] = bytes
            .try_into()
            .map_err(|_| CryptoError::internal("Invalid public key length".to_string()))?;

        let key = VerifyingKey::from_bytes(&bytes_array)
            .map_err(|e| CryptoError::internal(format!("Invalid Ed25519 public key: {}", e)))?;

        Ok(Self { key })
    }

    /// Get the raw public key bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.key.to_bytes()
    }

    /// Verify a signature.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CryptoResult<()> {
        if signature.len() != SIGNATURE_LENGTH {
            return Err(CryptoError::internal(format!(
                "Ed25519 signature must be {} bytes",
                SIGNATURE_LENGTH
            )));
        }

        let sig_bytes: [u8; SIGNATURE_LENGTH] = signature
            .try_into()
            .map_err(|_| CryptoError::internal("Invalid signature length".to_string()))?;

        let signature = Signature::from_bytes(&sig_bytes);

        self.key.verify_strict(message, &signature).map_err(|e| {
            CryptoError::internal(format!("Ed25519 signature verification failed: {}", e))
        })
    }

    /// Verify a signature, returning a boolean instead of Result.
    pub fn verify_strict(&self, message: &[u8], signature: &[u8]) -> bool {
        self.verify(message, signature).is_ok()
    }
}

// ============================================================================
// Standalone Functions
// ============================================================================

/// Verify an Ed25519 signature.
///
/// # Arguments
///
/// * `public_key` - 32-byte public key
/// * `message` - Original message
/// * `signature` - 64-byte signature
///
/// # Returns
///
/// Ok(()) if signature is valid.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<()> {
    let verifying_key = Ed25519VerifyingKey::from_bytes(public_key)?;
    verifying_key.verify(message, signature)
}

/// Verify an Ed25519 signature, returning a boolean.
pub fn verify_bool(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify(public_key, message, signature).is_ok()
}

/// Verify an Ed25519 signature using a SPKI-encoded public key.
///
/// This function accepts DER-encoded SubjectPublicKeyInfo format public keys,
/// which is the standard format used in X.509 certificates.
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo or raw 32-byte public key
/// * `message` - Original message
/// * `signature` - 64-byte signature
///
/// # Returns
///
/// `Ok(true)` if signature is valid, `Ok(false)` if invalid.
pub fn verify_ed25519_spki(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let verifying_key = if public_key_der.len() == PUBLIC_KEY_LENGTH {
        // Raw 32-byte public key
        let bytes_array: [u8; PUBLIC_KEY_LENGTH] = public_key_der
            .try_into()
            .map_err(|_| CryptoError::internal("Invalid public key length".to_string()))?;
        VerifyingKey::from_bytes(&bytes_array)
            .map_err(|e| CryptoError::internal(format!("Invalid Ed25519 public key: {}", e)))?
    } else {
        use der::Decode;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;

        let spki = SubjectPublicKeyInfoOwned::from_der(public_key_der)
            .map_err(|e| CryptoError::internal(format!("Invalid Ed25519 SPKI public key: {e}")))?;
        verifying_key_from_spki(&spki)?
    };

    if signature.len() != SIGNATURE_LENGTH {
        return Err(CryptoError::internal(format!(
            "Ed25519 signature must be {} bytes, got {}",
            SIGNATURE_LENGTH,
            signature.len()
        )));
    }

    let sig_bytes: [u8; SIGNATURE_LENGTH] = signature
        .try_into()
        .map_err(|_| CryptoError::internal("Invalid signature length".to_string()))?;

    let sig = Signature::from_bytes(&sig_bytes);

    match verifying_key.verify_strict(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn verifying_key_from_spki(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> CryptoResult<VerifyingKey> {
    if spki.algorithm.oid != const_oid::db::rfc8410::ID_ED_25519
        || spki.algorithm.parameters.is_some()
    {
        return Err(CryptoError::internal(
            "Invalid Ed25519 SPKI algorithm identifier".to_string(),
        ));
    }
    if spki.subject_public_key.unused_bits() != 0 {
        return Err(CryptoError::internal(
            "Invalid Ed25519 SPKI public key bit string".to_string(),
        ));
    }
    let bytes: [u8; PUBLIC_KEY_LENGTH] = spki
        .subject_public_key
        .raw_bytes()
        .try_into()
        .map_err(|_| CryptoError::internal("Invalid Ed25519 public key length".to_string()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| CryptoError::internal(format!("Invalid Ed25519 public key: {e}")))
}

// ============================================================================
// PEM/DER Support
// ============================================================================

/// Parse a PEM-encoded Ed25519 public key.
pub fn parse_public_key_pem(pem: &str) -> CryptoResult<Ed25519VerifyingKey> {
    use der::DecodePem;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let spki = SubjectPublicKeyInfoOwned::from_pem(pem)
        .map_err(|e| CryptoError::internal(format!("Invalid Ed25519 public-key PEM: {e}")))?;
    Ok(Ed25519VerifyingKey {
        key: verifying_key_from_spki(&spki)?,
    })
}

/// Parse a DER-encoded Ed25519 public key (SubjectPublicKeyInfo format).
pub fn parse_public_key_der(der: &[u8]) -> CryptoResult<Ed25519VerifyingKey> {
    use der::Decode;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let spki = SubjectPublicKeyInfoOwned::from_der(der)
        .map_err(|e| CryptoError::internal(format!("Invalid Ed25519 public-key DER: {e}")))?;
    Ok(Ed25519VerifyingKey {
        key: verifying_key_from_spki(&spki)?,
    })
}
