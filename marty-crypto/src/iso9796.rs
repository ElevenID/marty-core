//! ISO 9796-2 Digital Signature Scheme with Message Recovery.
//!
//! This module implements ISO 9796-2 signature verification, which is used
//! in eMRTD Active Authentication. ISO 9796-2 is an RSA-based signature scheme
//! that allows partial or full message recovery from the signature.
//!
//! # Schemes Supported
//!
//! - Scheme 1: Full message recovery (legacy)
//! - Scheme 2: Partial message recovery with hash (commonly used)
//! - Scheme 3: Partial message recovery with randomization
//!
//! # Example
//!
//! ```ignore
//! use marty_verification::crypto::iso9796::{iso9796_verify, Iso9796Scheme};
//!
//! // Verify an ISO 9796-2 signature
//! let is_valid = iso9796_verify(
//!     &public_key_der,
//!     &message,
//!     &signature,
//!     Iso9796Scheme::Scheme2,
//!     HashAlgorithm::Sha256,
//! )?;
//! ```

use rsa::{traits::PublicKeyParts, BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use spki::DecodePublicKey;

use crate::{CryptoError, CryptoResult};

// ============================================================================
// Types
// ============================================================================

/// ISO 9796-2 signature scheme variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Iso9796Scheme {
    /// Scheme 1: Message recovery only (no hash, legacy)
    Scheme1,
    /// Scheme 2: Partial message recovery with hash (common for Active Auth)
    Scheme2,
    /// Scheme 3: Scheme 2 with randomization
    Scheme3,
}

/// Hash algorithms for ISO 9796-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Iso9796HashAlgorithm {
    /// SHA-1 (legacy, but still used in older eMRTDs)
    Sha1,
    /// SHA-224
    Sha224,
    /// SHA-256 (recommended)
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl Iso9796HashAlgorithm {
    /// Get the trailer byte for this hash algorithm per ISO 9796-2.
    fn trailer(&self) -> u8 {
        match self {
            Self::Sha1 => 0x33,
            Self::Sha224 => 0x38,
            Self::Sha256 => 0x34,
            Self::Sha384 => 0x36,
            Self::Sha512 => 0x35,
        }
    }

    /// Get the hash output size in bytes.
    fn hash_size(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Hash data using this algorithm.
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha224 => Sha224::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

// ============================================================================
// Verification Functions
// ============================================================================

/// Verify an ISO 9796-2 signature.
///
/// # Arguments
/// * `public_key_der` - DER-encoded RSA public key (SPKI format)
/// * `message` - The message or recoverable portion (depending on scheme)
/// * `signature` - The ISO 9796-2 signature
/// * `scheme` - The signature scheme (Scheme1, Scheme2, or Scheme3)
/// * `hash_alg` - Hash algorithm used
///
/// # Returns
/// `true` if signature is valid
pub fn iso9796_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
    scheme: Iso9796Scheme,
    hash_alg: Iso9796HashAlgorithm,
) -> CryptoResult<bool> {
    // Parse the RSA public key
    let public_key = RsaPublicKey::from_public_key_der(public_key_der)
        .map_err(|e| CryptoError::crypto_error(format!("Failed to parse RSA public key: {}", e)))?;

    match scheme {
        Iso9796Scheme::Scheme1 => iso9796_scheme1_verify(&public_key, message, signature),
        Iso9796Scheme::Scheme2 => iso9796_scheme2_verify(&public_key, message, signature, hash_alg),
        Iso9796Scheme::Scheme3 => iso9796_scheme3_verify(&public_key, message, signature, hash_alg),
    }
}

/// Verify ISO 9796-2 Scheme 1 signature (full message recovery).
fn iso9796_scheme1_verify(
    public_key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let k = public_key.n().bits().div_ceil(8);

    if signature.len() != k {
        return Ok(false);
    }

    // Convert signature to integer and perform RSA verification (s^e mod n)
    let s = BigUint::from_bytes_be(signature);
    let em = s.modpow(public_key.e(), public_key.n());
    let em_bytes = em.to_bytes_be();

    // Pad to key size
    let mut padded_em = vec![0u8; k - em_bytes.len()];
    padded_em.extend_from_slice(&em_bytes);

    // Check format: 0x6A || M || 0xBC
    if padded_em[0] != 0x6A || padded_em[padded_em.len() - 1] != 0xBC {
        return Ok(false);
    }

    // Extract recovered message
    let recovered = &padded_em[1..padded_em.len() - 1];

    // Compare with provided message
    Ok(recovered == message)
}

/// Verify ISO 9796-2 Scheme 2 signature (partial message recovery with hash).
fn iso9796_scheme2_verify(
    public_key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
    hash_alg: Iso9796HashAlgorithm,
) -> CryptoResult<bool> {
    let k = public_key.n().bits().div_ceil(8);
    let hash_len = hash_alg.hash_size();

    if signature.len() != k {
        return Ok(false);
    }

    // Convert signature to integer and perform RSA verification
    let s = BigUint::from_bytes_be(signature);
    let em = s.modpow(public_key.e(), public_key.n());
    let em_bytes = em.to_bytes_be();

    // Pad to key size
    let mut padded_em = vec![0u8; k - em_bytes.len()];
    padded_em.extend_from_slice(&em_bytes);

    // ISO 9796-2 Scheme 2 format:
    // For implicit trailer: 0x4B || padding || 0x00 || M1 || H || 0xCC
    // For explicit trailer: 0x6A || padding || 0x00 || M1 || H || trailer (2 bytes)

    let last_byte = padded_em[padded_em.len() - 1];
    let (header_byte, trailer_len, _uses_implicit) = if last_byte == 0xBC {
        // Implicit trailer
        (0x4B, 1, true)
    } else if last_byte == hash_alg.trailer() {
        // Explicit trailer with single byte
        (0x6A, 1, false)
    } else {
        // Check for two-byte trailer (0x00 || trailer)
        if padded_em.len() >= 2 && padded_em[padded_em.len() - 2] == 0x00 {
            (0x6A, 2, false)
        } else {
            return Ok(false);
        }
    };

    // Check header
    if padded_em[0] != header_byte {
        return Ok(false);
    }

    // Extract hash from the encoded message
    let hash_start = padded_em.len() - trailer_len - hash_len;
    if hash_start < 2 {
        return Ok(false);
    }

    let embedded_hash = &padded_em[hash_start..padded_em.len() - trailer_len];

    // Find where M1 (recoverable message part) starts
    // Format is: header || padding || 0x00 || M1 || hash || trailer
    let mut m1_start = 1;
    while m1_start < hash_start && padded_em[m1_start] == 0xBB {
        m1_start += 1;
    }

    // Check for 0x00 separator or 0x01/0x0A depending on recovery
    if m1_start >= hash_start {
        return Ok(false);
    }

    // The separator can be 0x00, 0x01, or 0x0A
    let separator = padded_em[m1_start];
    if separator != 0x00 && separator != 0x01 && separator != 0x0A {
        return Ok(false);
    }
    m1_start += 1;

    // Extract M1 (recoverable message part)
    let m1 = &padded_em[m1_start..hash_start];

    // For Active Authentication, M1 contains the challenge
    // and the message parameter contains the full message (M = M1 || M2)
    // If M1 is a prefix of message, M2 = message[M1.len()..]

    // Compute hash based on whether this is partial or full recovery
    let computed_hash = if message.len() >= m1.len() && &message[..m1.len()] == m1 {
        // Full message was provided, M2 is the remainder
        hash_alg.hash(message)
    } else if !m1.is_empty() {
        // M1 is the complete recoverable part, message is M2
        let mut full_message = m1.to_vec();
        full_message.extend_from_slice(message);
        hash_alg.hash(&full_message)
    } else {
        // No recoverable part, hash just the message
        hash_alg.hash(message)
    };

    Ok(embedded_hash == computed_hash.as_slice())
}

/// Verify ISO 9796-2 Scheme 3 signature (with randomization).
fn iso9796_scheme3_verify(
    public_key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
    hash_alg: Iso9796HashAlgorithm,
) -> CryptoResult<bool> {
    // Scheme 3 is similar to Scheme 2 but includes randomization
    // The verification process is the same, just the encoding includes random salt
    iso9796_scheme2_verify(public_key, message, signature, hash_alg)
}

/// Recover the message from an ISO 9796-2 signature.
///
/// For Scheme 1, this recovers the full message.
/// For Scheme 2/3, this recovers the recoverable part (M1).
///
/// # Arguments
/// * `public_key_der` - DER-encoded RSA public key
/// * `signature` - The ISO 9796-2 signature
/// * `scheme` - The signature scheme
/// * `hash_alg` - Hash algorithm (for Scheme 2/3)
///
/// # Returns
/// The recovered message portion, or error if signature format is invalid.
pub fn iso9796_recover_message(
    public_key_der: &[u8],
    signature: &[u8],
    scheme: Iso9796Scheme,
    hash_alg: Option<Iso9796HashAlgorithm>,
) -> CryptoResult<Vec<u8>> {
    let public_key = RsaPublicKey::from_public_key_der(public_key_der)
        .map_err(|e| CryptoError::crypto_error(format!("Failed to parse RSA public key: {}", e)))?;

    let k = public_key.n().bits().div_ceil(8);

    if signature.len() != k {
        return Err(CryptoError::crypto_error("Invalid signature length"));
    }

    // Decrypt signature
    let s = BigUint::from_bytes_be(signature);
    let em = s.modpow(public_key.e(), public_key.n());
    let em_bytes = em.to_bytes_be();

    // Pad to key size
    let mut padded_em = vec![0u8; k - em_bytes.len()];
    padded_em.extend_from_slice(&em_bytes);

    match scheme {
        Iso9796Scheme::Scheme1 => {
            // Format: 0x6A || M || 0xBC
            if padded_em[0] != 0x6A || padded_em[padded_em.len() - 1] != 0xBC {
                return Err(CryptoError::crypto_error(
                    "Invalid Scheme 1 signature format",
                ));
            }
            Ok(padded_em[1..padded_em.len() - 1].to_vec())
        }
        Iso9796Scheme::Scheme2 | Iso9796Scheme::Scheme3 => {
            let hash_alg = hash_alg.ok_or_else(|| {
                CryptoError::crypto_error("Hash algorithm required for Scheme 2/3")
            })?;

            let hash_len = hash_alg.hash_size();

            // Determine trailer length
            let last_byte = padded_em[padded_em.len() - 1];
            let trailer_len = if last_byte == 0xBC {
                1
            } else if padded_em.len() >= 2 && padded_em[padded_em.len() - 2] == 0x00 {
                2
            } else {
                1
            };

            let hash_start = padded_em.len() - trailer_len - hash_len;

            // Find M1 start
            let mut m1_start = 1;
            while m1_start < hash_start && padded_em[m1_start] == 0xBB {
                m1_start += 1;
            }

            // Skip separator
            if m1_start < hash_start {
                m1_start += 1;
            }

            Ok(padded_em[m1_start..hash_start].to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_properties() {
        assert_eq!(Iso9796HashAlgorithm::Sha1.hash_size(), 20);
        assert_eq!(Iso9796HashAlgorithm::Sha256.hash_size(), 32);
        assert_eq!(Iso9796HashAlgorithm::Sha512.hash_size(), 64);

        assert_eq!(Iso9796HashAlgorithm::Sha1.trailer(), 0x33);
        assert_eq!(Iso9796HashAlgorithm::Sha256.trailer(), 0x34);
    }

    #[test]
    fn test_hash_algorithm_hash() {
        let data = b"test data";

        let sha1_hash = Iso9796HashAlgorithm::Sha1.hash(data);
        assert_eq!(sha1_hash.len(), 20);

        let sha256_hash = Iso9796HashAlgorithm::Sha256.hash(data);
        assert_eq!(sha256_hash.len(), 32);
    }

    // Note: Full verification tests require test vectors from ISO 9796-2
    // or generated test signatures
}
