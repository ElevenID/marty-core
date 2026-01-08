//! Key derivation functions (HKDF, PBKDF2).

use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha384, Sha512};

use super::HashAlgorithm;
use crate::{CryptoError, CryptoResult};

// ============================================================================
// HKDF (RFC 5869)
// ============================================================================

/// Derive keys using HKDF with SHA-256.
///
/// HKDF is used in ISO 18013-5 for session key derivation.
///
/// # Arguments
///
/// * `ikm` - Input keying material
/// * `salt` - Optional salt (can be empty)
/// * `info` - Context/application-specific info
/// * `length` - Desired output length in bytes
///
/// # Returns
///
/// Derived key material.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);

    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm).map_err(|_| {
        CryptoError::internal("HKDF expansion failed: output length too long".to_string())
    })?;

    Ok(okm)
}

/// Derive keys using HKDF with SHA-384.
pub fn hkdf_sha384(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hkdf = Hkdf::<Sha384>::new(salt, ikm);

    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm).map_err(|_| {
        CryptoError::internal("HKDF expansion failed: output length too long".to_string())
    })?;

    Ok(okm)
}

/// Derive keys using HKDF with SHA-512.
pub fn hkdf_sha512(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hkdf = Hkdf::<Sha512>::new(salt, ikm);

    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm).map_err(|_| {
        CryptoError::internal("HKDF expansion failed: output length too long".to_string())
    })?;

    Ok(okm)
}

/// Derive keys using HKDF with specified algorithm.
pub fn hkdf(
    algorithm: HashAlgorithm,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> CryptoResult<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Sha256 => hkdf_sha256(ikm, salt, info, length),
        HashAlgorithm::Sha384 => hkdf_sha384(ikm, salt, info, length),
        HashAlgorithm::Sha512 => hkdf_sha512(ikm, salt, info, length),
        HashAlgorithm::Sha1 => Err(CryptoError::internal(
            "SHA-1 is not supported for HKDF".to_string(),
        )),
    }
}

// ============================================================================
// PBKDF2 (RFC 2898)
// ============================================================================

/// Derive keys using PBKDF2 with SHA-256.
///
/// PBKDF2 is used for password-based key derivation.
///
/// # Arguments
///
/// * `password` - The password bytes
/// * `salt` - Salt for the derivation
/// * `iterations` - Number of iterations (higher = slower but more secure)
/// * `length` - Desired output length in bytes
///
/// # Returns
///
/// Derived key material.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
    let mut output = vec![0u8; length];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);
    output
}

/// Derive keys using PBKDF2 with SHA-512.
pub fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
    let mut output = vec![0u8; length];
    pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut output);
    output
}

// ============================================================================
// ISO 18013-5 Session Key Derivation
// ============================================================================

/// Derive mDL session keys per ISO 18013-5.
///
/// Uses HKDF-SHA256 with specific info strings for reader/device keys.
///
/// # Arguments
///
/// * `shared_secret` - ECDH shared secret (Z)
/// * `session_transcript` - Session transcript bytes
///
/// # Returns
///
/// Tuple of (device_key, reader_key), each 32 bytes.
pub fn derive_mdl_session_keys(
    shared_secret: &[u8],
    session_transcript: &[u8],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    // Salt is session transcript hash
    let salt = super::hashing::hash_sha256(session_transcript);

    // Derive device key
    let device_key = hkdf_sha256(shared_secret, &salt, b"SKDevice", 32)?;

    // Derive reader key
    let reader_key = hkdf_sha256(shared_secret, &salt, b"SKReader", 32)?;

    Ok((device_key, reader_key))
}

// ============================================================================
// BAC Key Derivation (ICAO 9303)
// ============================================================================

/// Derive BAC session keys from MRZ information.
///
/// Per ICAO 9303 Part 11, derives K_ENC and K_MAC from MRZ data.
///
/// # Arguments
///
/// * `mrz_info` - Concatenated: document_number + date_of_birth + date_of_expiry
///   (with check digits)
///
/// # Returns
///
/// Tuple of (k_enc, k_mac), each 16 bytes for 3DES.
pub fn derive_bac_keys(mrz_info: &str) -> (Vec<u8>, Vec<u8>) {
    use sha1::Digest;

    // Hash the MRZ information
    let mut hasher = sha1::Sha1::new();
    hasher.update(mrz_info.as_bytes());
    let h = hasher.finalize();

    // K_seed is first 16 bytes
    let k_seed = &h[..16];

    // Derive K_ENC (counter = 1)
    let k_enc = derive_3des_key(k_seed, &[0, 0, 0, 1]);

    // Derive K_MAC (counter = 2)
    let k_mac = derive_3des_key(k_seed, &[0, 0, 0, 2]);

    (k_enc, k_mac)
}

/// Derive a 3DES key from seed and counter.
fn derive_3des_key(k_seed: &[u8], counter: &[u8]) -> Vec<u8> {
    use sha1::Digest;

    let mut hasher = sha1::Sha1::new();
    hasher.update(k_seed);
    hasher.update(counter);
    let h = hasher.finalize();

    // Adjust parity bits for 3DES (take first 16 bytes)
    let mut key = h[..16].to_vec();
    adjust_parity(&mut key);
    key
}

/// Adjust parity bits for DES keys.
fn adjust_parity(key: &mut [u8]) {
    for byte in key.iter_mut() {
        let parity = (*byte).count_ones() % 2;
        if parity == 0 {
            *byte ^= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256_basic() {
        // RFC 5869 Test Case 1
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let result = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(result.len(), 42);
    }

    #[test]
    fn test_pbkdf2_sha256_basic() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 1000;

        let result = pbkdf2_sha256(password, salt, iterations, 32);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_mdl_session_keys() {
        let shared_secret = [0x42; 32];
        let transcript = b"session transcript data";

        let (device_key, reader_key) = derive_mdl_session_keys(&shared_secret, transcript).unwrap();

        assert_eq!(device_key.len(), 32);
        assert_eq!(reader_key.len(), 32);
        assert_ne!(device_key, reader_key);
    }

    #[test]
    fn test_bac_key_derivation() {
        // Test MRZ info (document number + check + DOB + check + expiry + check)
        let mrz_info = "L898902C36907231M6908061";

        let (k_enc, k_mac) = derive_bac_keys(mrz_info);

        assert_eq!(k_enc.len(), 16);
        assert_eq!(k_mac.len(), 16);
        assert_ne!(k_enc, k_mac);
    }
}
