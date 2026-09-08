//! Key derivation functions (HKDF, PBKDF2).

#[cfg(not(target_family = "wasm"))]
use aws_lc_rs::{hkdf as aws_hkdf, pbkdf2 as aws_pbkdf2};
use zeroize::{Zeroize, Zeroizing};

use super::HashAlgorithm;
use crate::{CryptoError, CryptoResult};

/// Derived secret bytes with redacted diagnostics and automatic erasure.
pub struct SecretBytes {
    bytes: Vec<u8>,
    #[cfg(all(test, not(target_family = "wasm")))]
    cleanup_observer: Option<SecretBytesCleanupObserver>,
}

#[cfg(all(test, not(target_family = "wasm")))]
#[derive(Clone, Default)]
struct SecretBytesCleanupObserver(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

#[cfg(all(test, not(target_family = "wasm")))]
impl SecretBytesCleanupObserver {
    fn snapshots(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
}

impl SecretBytes {
    fn from_zeroizing(mut bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            bytes: std::mem::take(&mut *bytes),
            #[cfg(all(test, not(target_family = "wasm")))]
            cleanup_observer: None,
        }
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    fn with_cleanup_observer(mut self, observer: SecretBytesCleanupObserver) -> Self {
        self.cleanup_observer = Some(observer);
        self
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            #[cfg(all(test, not(target_family = "wasm")))]
            cleanup_observer: None,
        }
    }
}

impl std::ops::Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.bytes.resize(self.bytes.capacity(), 0);
        self.bytes.fill(0);
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(all(test, not(target_family = "wasm")))]
        if let Some(observer) = &self.cleanup_observer {
            observer.0.lock().unwrap().push(self.bytes.clone());
        }
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for SecretBytes {}

impl PartialEq<Vec<u8>> for SecretBytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const LENGTH: usize> PartialEq<[u8; LENGTH]> for SecretBytes {
    fn eq(&self, other: &[u8; LENGTH]) -> bool {
        self.as_slice() == other
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

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
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> CryptoResult<SecretBytes> {
    hkdf_impl(HkdfAlgorithm::Sha256, ikm, salt, info, length)
}

/// Derive keys using HKDF with SHA-384.
pub fn hkdf_sha384(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> CryptoResult<SecretBytes> {
    hkdf_impl(HkdfAlgorithm::Sha384, ikm, salt, info, length)
}

/// Derive keys using HKDF with SHA-512.
pub fn hkdf_sha512(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> CryptoResult<SecretBytes> {
    hkdf_impl(HkdfAlgorithm::Sha512, ikm, salt, info, length)
}

#[derive(Clone, Copy)]
enum HkdfAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[cfg(not(target_family = "wasm"))]
#[derive(Clone, Copy)]
struct HkdfOutputLength(usize);

#[cfg(not(target_family = "wasm"))]
impl aws_hkdf::KeyType for HkdfOutputLength {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(not(target_family = "wasm"))]
fn hkdf_impl(
    algorithm: HkdfAlgorithm,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> CryptoResult<SecretBytes> {
    let algorithm = match algorithm {
        HkdfAlgorithm::Sha256 => aws_hkdf::HKDF_SHA256,
        HkdfAlgorithm::Sha384 => aws_hkdf::HKDF_SHA384,
        HkdfAlgorithm::Sha512 => aws_hkdf::HKDF_SHA512,
    };
    let salt = if salt.is_empty() {
        aws_hkdf::Salt::none(algorithm)
    } else {
        aws_hkdf::Salt::new(algorithm, salt)
    };
    let prk = salt.extract(ikm);
    let info_parts = [info];
    let okm = prk
        .expand(&info_parts, HkdfOutputLength(length))
        .map_err(|_| {
            CryptoError::internal("HKDF expansion failed: output length too long".to_string())
        })?;
    let mut output = Zeroizing::new(vec![0u8; length]);
    okm.fill(&mut output).map_err(|_| {
        CryptoError::internal("HKDF expansion failed: output length too long".to_string())
    })?;
    Ok(SecretBytes::from_zeroizing(output))
}

#[cfg(target_family = "wasm")]
fn hkdf_impl(
    algorithm: HkdfAlgorithm,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> CryptoResult<SecretBytes> {
    let mut output = Zeroizing::new(vec![0u8; length]);
    let algorithm = match algorithm {
        HkdfAlgorithm::Sha256 => crate::secret_hash::SecureHashAlgorithm::Sha256,
        HkdfAlgorithm::Sha384 => crate::secret_hash::SecureHashAlgorithm::Sha384,
        HkdfAlgorithm::Sha512 => crate::secret_hash::SecureHashAlgorithm::Sha512,
    };
    crate::secret_hash::hkdf(algorithm, ikm, salt, info, &mut output, || Ok(())).map_err(|_| {
        CryptoError::internal("HKDF expansion failed: output length too long".to_string())
    })?;
    Ok(SecretBytes::from_zeroizing(output))
}

/// Derive keys using HKDF with specified algorithm.
#[allow(deprecated)]
pub fn hkdf(
    algorithm: HashAlgorithm,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> CryptoResult<SecretBytes> {
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
// Concat KDF (NIST SP 800-56A / RFC 7518 section 4.6.2)
// ============================================================================

/// Derive key material with the SHA-256 Concat KDF used by JOSE ECDH-ES.
///
/// `party_u_info` and `party_v_info` are the decoded agreement-party values.
/// This function constructs the length-prefixed OtherInfo structure required
/// by RFC 7518 rather than accepting an ambiguous pre-encoded buffer.
pub fn concat_kdf_sha256(
    shared_secret: &[u8],
    algorithm_id: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
    key_data_len: usize,
) -> CryptoResult<SecretBytes> {
    if shared_secret.is_empty() {
        return Err(CryptoError::internal(
            "Concat KDF shared secret must not be empty".to_string(),
        ));
    }
    if key_data_len == 0 {
        return Err(CryptoError::internal(
            "Concat KDF output length must be positive".to_string(),
        ));
    }

    let key_data_bits = key_data_len
        .checked_mul(8)
        .ok_or_else(|| CryptoError::internal("Concat KDF output length overflow".to_string()))?;
    let key_data_bits = u32::try_from(key_data_bits).map_err(|_| {
        CryptoError::internal("Concat KDF output length exceeds RFC 7518 limits".to_string())
    })?;

    let mut other_info = Vec::new();
    append_length_prefixed(&mut other_info, algorithm_id)?;
    append_length_prefixed(&mut other_info, party_u_info)?;
    append_length_prefixed(&mut other_info, party_v_info)?;
    other_info.extend_from_slice(&key_data_bits.to_be_bytes());

    let repetitions = key_data_len.div_ceil(32);
    let repetitions = u32::try_from(repetitions)
        .map_err(|_| CryptoError::internal("Concat KDF repetition count overflow".to_string()))?;
    let mut derived = Zeroizing::new(Vec::with_capacity(key_data_len));
    for counter in 1..=repetitions {
        #[cfg(not(target_family = "wasm"))]
        {
            let mut digest = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
            digest.update(&counter.to_be_bytes());
            digest.update(shared_secret);
            digest.update(&other_info);
            derived.extend_from_slice(digest.finish().as_ref());
        }
        #[cfg(target_family = "wasm")]
        {
            let digest =
                crate::secret_hash::sha256(&[&counter.to_be_bytes(), shared_secret, &other_info]);
            derived.extend_from_slice(&*digest);
        }
    }
    derived.truncate(key_data_len);
    Ok(SecretBytes::from_zeroizing(derived))
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) -> CryptoResult<()> {
    let length = u32::try_from(value.len()).map_err(|_| {
        CryptoError::internal("Concat KDF field exceeds RFC 7518 limits".to_string())
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
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
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> SecretBytes {
    assert!(iterations != 0, "PBKDF2 iterations must be nonzero");
    let mut output = Zeroizing::new(vec![0u8; length]);
    #[cfg(not(target_family = "wasm"))]
    aws_pbkdf2::derive(
        aws_pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(iterations).expect("iterations were validated"),
        salt,
        password,
        &mut output,
    );
    #[cfg(target_family = "wasm")]
    crate::secret_hash::pbkdf2(
        crate::secret_hash::SecureHashAlgorithm::Sha256,
        password,
        salt,
        iterations,
        &mut output,
    );
    SecretBytes::from_zeroizing(output)
}

/// Derive keys using PBKDF2 with SHA-512.
pub fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> SecretBytes {
    assert!(iterations != 0, "PBKDF2 iterations must be nonzero");
    let mut output = Zeroizing::new(vec![0u8; length]);
    #[cfg(not(target_family = "wasm"))]
    aws_pbkdf2::derive(
        aws_pbkdf2::PBKDF2_HMAC_SHA512,
        std::num::NonZeroU32::new(iterations).expect("iterations were validated"),
        salt,
        password,
        &mut output,
    );
    #[cfg(target_family = "wasm")]
    crate::secret_hash::pbkdf2(
        crate::secret_hash::SecureHashAlgorithm::Sha512,
        password,
        salt,
        iterations,
        &mut output,
    );
    SecretBytes::from_zeroizing(output)
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
) -> CryptoResult<(SecretBytes, SecretBytes)> {
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
fn adjust_parity(key: &mut [u8]) {
    for byte in key.iter_mut() {
        let parity = (*byte).count_ones() % 2;
        if parity == 0 {
            *byte ^= 1;
        }
    }
}

#[cfg(not(test))]
/// Named BAC key-export helpers are excluded from production builds; use the
/// opaque BAC handshake/session API in `marty-verification`.
///
/// ```compile_fail
/// let _ = marty_crypto::kdf::derive_bac_keys("MRZ data");
/// ```
pub struct NoProtocolKeyExportApis;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_family = "wasm"))]
    use crate::secret_buffer::{SensitiveBuffer, SensitiveBufferCleanupObserver};

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn derived_keys_and_hkdf_error_scratch_wipe_on_drop_and_unwind() {
        let secret_observer = SecretBytesCleanupObserver::default();
        let derived = hkdf_sha256(b"secret input", b"salt", b"info", 32)
            .unwrap()
            .with_cleanup_observer(secret_observer.clone());
        assert_eq!(format!("{derived:?}"), "SecretBytes([REDACTED])");
        drop(derived);
        let secret_snapshots = secret_observer.snapshots();
        assert_eq!(secret_snapshots.len(), 1);
        assert_eq!(secret_snapshots[0].len(), 32);
        assert!(secret_snapshots[0].iter().all(|byte| *byte == 0));

        let salt = aws_hkdf::Salt::new(aws_hkdf::HKDF_SHA256, b"salt");
        let prk = salt.extract(b"secret input");
        let info = [b"info".as_slice()];
        let okm = prk.expand(&info, HkdfOutputLength(32)).unwrap();
        let error_observer = SensitiveBufferCleanupObserver::default();
        {
            let mut wrong_length =
                SensitiveBuffer::copied_from_with_observer(&[0xa5; 31], 0, error_observer.clone());
            assert!(okm.fill(&mut wrong_length.bytes).is_err());
        }
        let snapshots = error_observer.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].len(), 31);
        assert!(snapshots[0].iter().all(|byte| *byte == 0));

        let unwind_observer = SensitiveBufferCleanupObserver::default();
        let unwind = std::panic::catch_unwind({
            let observer = unwind_observer.clone();
            move || {
                let salt = aws_hkdf::Salt::new(aws_hkdf::HKDF_SHA256, b"salt");
                let _prk = salt.extract(b"second secret input");
                let mut output =
                    SensitiveBuffer::copied_from_with_observer(&[0x5a; 32], 0, observer);
                output.bytes[0] ^= 0xff;
                panic!("injected HKDF unwind after extract")
            }
        });
        assert!(unwind.is_err());
        let snapshots = unwind_observer.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].len(), 32);
        assert!(snapshots[0].iter().all(|byte| *byte == 0));
    }

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
    fn concat_kdf_matches_rfc7518_appendix_c() {
        let shared_secret = [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let derived = concat_kdf_sha256(&shared_secret, b"A128GCM", b"Alice", b"Bob", 16)
            .expect("RFC 7518 Concat KDF vector");
        assert_eq!(
            derived,
            [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]
        );
    }

    #[test]
    fn test_pbkdf2_sha256_basic() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 1000;

        let result = pbkdf2_sha256(password, salt, iterations, 32);
        assert_eq!(result.len(), 32);

        assert_eq!(
            hex::encode(pbkdf2_sha256(b"password", b"salt", 1, 32).as_slice()),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
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
