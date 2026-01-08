//! Ed448 (Edwards curve over 448-bit field) signing operations.
//!
//! This module provides Ed448 key generation, signing, and verification
//! for eMRTD Active Authentication and other protocols requiring Ed448.
//!
//! Ed448 provides 224-bit security (vs 128-bit for Ed25519) and is used
//! in newer ePassports with higher security requirements.
//!
//! # Example
//!
//! ```ignore
//! use marty_verification::crypto::ed448::{ed448_generate, ed448_sign, ed448_verify};
//!
//! // Generate a key pair
//! let (private_key, public_key) = ed448_generate()?;
//!
//! // Sign a message
//! let message = b"Hello, World!";
//! let signature = ed448_sign(&private_key, message)?;
//!
//! // Verify the signature
//! assert!(ed448_verify(&public_key, message, &signature)?);
//! ```

use ed448_goldilocks_plus::rand_core::OsRng;
use ed448_goldilocks_plus::{
    Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};

use crate::{CryptoError, CryptoResult};

/// Ed448 private key size in bytes (57 bytes).
pub const ED448_PRIVATE_KEY_SIZE: usize = SECRET_KEY_LENGTH;

/// Ed448 public key size in bytes (57 bytes).
pub const ED448_PUBLIC_KEY_SIZE: usize = PUBLIC_KEY_LENGTH;

/// Ed448 signature size in bytes (114 bytes).
pub const ED448_SIGNATURE_SIZE: usize = SIGNATURE_LENGTH;

/// Generate a new Ed448 key pair.
///
/// # Returns
/// A tuple of (private_key, public_key) as byte vectors.
pub fn ed448_generate() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    Ok((
        signing_key.to_bytes().to_vec(),
        verifying_key.to_bytes().to_vec(),
    ))
}

/// Sign a message using Ed448 (pure EdDSA, no prehashing).
///
/// # Arguments
/// * `private_key` - 57-byte private key seed
/// * `message` - Message to sign
///
/// # Returns
/// 114-byte signature
pub fn ed448_sign(private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    if private_key.len() != ED448_PRIVATE_KEY_SIZE {
        return Err(CryptoError::crypto_error(format!(
            "Invalid Ed448 private key size: expected {}, got {}",
            ED448_PRIVATE_KEY_SIZE,
            private_key.len()
        )));
    }

    // Convert bytes to SigningKey
    let signing_key = SigningKey::try_from(private_key)
        .map_err(|e| CryptoError::crypto_error(format!("Invalid private key: {}", e)))?;

    // Sign without context (pure Ed448)
    let signature = signing_key.sign_raw(message);

    Ok(signature.to_bytes().to_vec())
}

/// Sign a message using Ed448 with a context string.
///
/// This implements RFC 8032 Ed448 signing with an optional context.
///
/// # Arguments
/// * `private_key` - 57-byte private key seed
/// * `message` - Message to sign  
/// * `context` - Context string (max 255 bytes)
///
/// # Returns
/// 114-byte signature
pub fn ed448_sign_with_context(
    private_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> CryptoResult<Vec<u8>> {
    if private_key.len() != ED448_PRIVATE_KEY_SIZE {
        return Err(CryptoError::crypto_error(format!(
            "Invalid Ed448 private key size: expected {}, got {}",
            ED448_PRIVATE_KEY_SIZE,
            private_key.len()
        )));
    }

    if context.len() > 255 {
        return Err(CryptoError::crypto_error(
            "Ed448 context must be at most 255 bytes",
        ));
    }

    // Convert bytes to SigningKey
    let signing_key = SigningKey::try_from(private_key)
        .map_err(|e| CryptoError::crypto_error(format!("Invalid private key: {}", e)))?;

    // Sign with context
    let signature = signing_key
        .sign_ctx(context, message)
        .map_err(|e| CryptoError::crypto_error(format!("Signing failed: {:?}", e)))?;

    Ok(signature.to_bytes().to_vec())
}

/// Verify an Ed448 signature.
///
/// # Arguments
/// * `public_key` - 57-byte public key
/// * `message` - Message that was signed
/// * `signature` - 114-byte signature
///
/// # Returns
/// `true` if signature is valid
pub fn ed448_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    if public_key.len() != ED448_PUBLIC_KEY_SIZE {
        return Err(CryptoError::crypto_error(format!(
            "Invalid Ed448 public key size: expected {}, got {}",
            ED448_PUBLIC_KEY_SIZE,
            public_key.len()
        )));
    }

    if signature.len() != ED448_SIGNATURE_SIZE {
        return Err(CryptoError::crypto_error(format!(
            "Invalid Ed448 signature size: expected {}, got {}",
            ED448_SIGNATURE_SIZE,
            signature.len()
        )));
    }

    // Convert slice to array for VerifyingKey::from_bytes
    let pk_array: [u8; 57] = public_key
        .try_into()
        .map_err(|_| CryptoError::crypto_error("Invalid public key length"))?;

    // Parse public key using from_bytes (not TryFrom)
    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(vk) => vk,
        Err(_) => return Ok(false), // Invalid public key format
    };

    // Convert signature slice to array
    let sig_array: [u8; 114] = signature
        .try_into()
        .map_err(|_| CryptoError::crypto_error("Invalid signature length"))?;

    // Parse signature using from_bytes (returns Result)
    let sig = match Signature::from_bytes(&sig_array) {
        Ok(s) => s,
        Err(_) => return Ok(false), // Invalid signature format
    };

    // Verify using verify_raw (no context)
    Ok(verifying_key.verify_raw(&sig, message).is_ok())
}

/// Verify an Ed448 signature with a context string.
///
/// # Arguments
/// * `public_key` - 57-byte public key
/// * `message` - Message that was signed
/// * `signature` - 114-byte signature
/// * `context` - Context string used during signing
///
/// # Returns
/// `true` if signature is valid
pub fn ed448_verify_with_context(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> CryptoResult<bool> {
    if public_key.len() != ED448_PUBLIC_KEY_SIZE {
        return Err(CryptoError::crypto_error(format!(
            "Invalid Ed448 public key size: expected {}, got {}",
            ED448_PUBLIC_KEY_SIZE,
            public_key.len()
        )));
    }

    if signature.len() != ED448_SIGNATURE_SIZE {
        return Err(CryptoError::crypto_error(format!(
            "Invalid Ed448 signature size: expected {}, got {}",
            ED448_SIGNATURE_SIZE,
            signature.len()
        )));
    }

    if context.len() > 255 {
        return Err(CryptoError::crypto_error(
            "Ed448 context must be at most 255 bytes",
        ));
    }

    // Convert slice to array for VerifyingKey::from_bytes
    let pk_array: [u8; 57] = public_key
        .try_into()
        .map_err(|_| CryptoError::crypto_error("Invalid public key length"))?;

    // Parse public key using from_bytes
    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(vk) => vk,
        Err(_) => return Ok(false), // Invalid public key format
    };

    // Convert signature slice to array
    let sig_array: [u8; 114] = signature
        .try_into()
        .map_err(|_| CryptoError::crypto_error("Invalid signature length"))?;

    // Parse signature using from_bytes (returns Result)
    let sig = match Signature::from_bytes(&sig_array) {
        Ok(s) => s,
        Err(_) => return Ok(false), // Invalid signature format
    };

    // Verify with context using verify_ctx(self, sig, ctx, message)
    Ok(verifying_key.verify_ctx(&sig, context, message).is_ok())
}

/// Verify an Ed448 signature using a SPKI-encoded public key.
///
/// This function accepts DER-encoded SubjectPublicKeyInfo format public keys,
/// which is the standard format used in X.509 certificates.
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo or raw 57-byte public key
/// * `message` - Original message
/// * `signature` - 114-byte signature
///
/// # Returns
///
/// `Ok(true)` if signature is valid, `Ok(false)` if invalid.
pub fn verify_ed448_spki(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    // Extract the public key from SPKI or use raw bytes
    let pk_bytes = if public_key_der.len() == ED448_PUBLIC_KEY_SIZE {
        // Raw 57-byte public key
        public_key_der
    } else if public_key_der.len() >= ED448_PUBLIC_KEY_SIZE + 12 {
        // SPKI format: the key is typically the last 57 bytes
        // SPKI structure for Ed448:
        // SEQUENCE {
        //   SEQUENCE { OID 1.3.101.113 }
        //   BIT STRING { 57 bytes }
        // }
        &public_key_der[public_key_der.len() - ED448_PUBLIC_KEY_SIZE..]
    } else {
        return Err(CryptoError::crypto_error(format!(
            "Invalid Ed448 public key size: expected {} or SPKI format, got {}",
            ED448_PUBLIC_KEY_SIZE,
            public_key_der.len()
        )));
    };

    if signature.len() != ED448_SIGNATURE_SIZE {
        return Err(CryptoError::crypto_error(format!(
            "Invalid Ed448 signature size: expected {}, got {}",
            ED448_SIGNATURE_SIZE,
            signature.len()
        )));
    }

    // Convert slice to array for VerifyingKey::from_bytes
    let pk_array: [u8; 57] = pk_bytes
        .try_into()
        .map_err(|_| CryptoError::crypto_error("Invalid public key length"))?;

    // Parse public key using from_bytes
    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(vk) => vk,
        Err(_) => return Ok(false), // Invalid public key format
    };

    // Convert signature slice to array
    let sig_array: [u8; 114] = signature
        .try_into()
        .map_err(|_| CryptoError::crypto_error("Invalid signature length"))?;

    // Parse signature using from_bytes (returns Result)
    let sig = match Signature::from_bytes(&sig_array) {
        Ok(s) => s,
        Err(_) => return Ok(false), // Invalid signature format
    };

    // Verify using verify_raw (no context) - pure Ed448
    Ok(verifying_key.verify_raw(&sig, message).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed448_roundtrip() {
        let (private_key, public_key) = ed448_generate().unwrap();

        assert_eq!(private_key.len(), ED448_PRIVATE_KEY_SIZE);
        assert_eq!(public_key.len(), ED448_PUBLIC_KEY_SIZE);

        let message = b"Test message for Ed448 signature";
        let signature = ed448_sign(&private_key, message).unwrap();

        assert_eq!(signature.len(), ED448_SIGNATURE_SIZE);
        assert!(ed448_verify(&public_key, message, &signature).unwrap());
    }

    #[test]
    fn test_ed448_wrong_message() {
        let (private_key, public_key) = ed448_generate().unwrap();

        let message = b"Original message";
        let signature = ed448_sign(&private_key, message).unwrap();

        let wrong_message = b"Wrong message";
        assert!(!ed448_verify(&public_key, wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_ed448_with_context() {
        let (private_key, public_key) = ed448_generate().unwrap();

        let message = b"Test message";
        let context = b"test-context";

        let signature = ed448_sign_with_context(&private_key, message, context).unwrap();

        // Correct context verifies
        assert!(ed448_verify_with_context(&public_key, message, &signature, context).unwrap());

        // Wrong context fails
        assert!(!ed448_verify_with_context(&public_key, message, &signature, b"wrong").unwrap());

        // No context fails (different signature scheme)
        assert!(!ed448_verify(&public_key, message, &signature).unwrap());
    }

    #[test]
    fn test_ed448_invalid_sizes() {
        let result = ed448_sign(&[0u8; 32], b"message");
        assert!(result.is_err());

        let (_, public_key) = ed448_generate().unwrap();
        let result = ed448_verify(&public_key, b"message", &[0u8; 64]);
        assert!(result.is_err());
    }
}
