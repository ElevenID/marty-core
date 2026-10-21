//! Triple DES (3DES) encryption for BAC and PACE protocols.
//!
//! This module provides 3DES-CBC encryption and decryption as required by
//! ICAO 9303 (eMRTD) Basic Access Control (BAC) and Password Authenticated
//! Connection Establishment (PACE) protocols.
//!
//! # Security Note
//!
//! 3DES is considered legacy and should only be used for eMRTD compatibility.
//! For new applications, prefer AES-256-GCM.

use cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use des::TdesEde3;
use zeroize::{Zeroize, Zeroizing};

use crate::secret_buffer::SensitiveBuffer;
#[cfg(test)]
use crate::secret_buffer::SensitiveBufferCleanupObserver;
use crate::{CryptoError, CryptoResult};

type TdesEncryptor = cbc::Encryptor<TdesEde3>;
type TdesDecryptor = cbc::Decryptor<TdesEde3>;

struct ExpandedTdesKey {
    bytes: [u8; 24],
    #[cfg(test)]
    cleanup_observer: Option<ExpandedTdesKeyCleanupObserver>,
}

#[cfg(test)]
#[derive(Clone, Default)]
struct ExpandedTdesKeyCleanupObserver(std::sync::Arc<std::sync::Mutex<Vec<[u8; 24]>>>);

impl ExpandedTdesKey {
    fn repeated(component: &[u8]) -> Self {
        debug_assert_eq!(component.len(), 8);
        let mut bytes = [0u8; 24];
        for part in bytes.chunks_exact_mut(8) {
            part.copy_from_slice(component);
        }
        Self {
            bytes,
            #[cfg(test)]
            cleanup_observer: None,
        }
    }

    #[cfg(test)]
    fn with_cleanup_observer(mut self, observer: ExpandedTdesKeyCleanupObserver) -> Self {
        self.cleanup_observer = Some(observer);
        self
    }
}

impl AsRef<[u8]> for ExpandedTdesKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ExpandedTdesKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.cleanup_observer {
            observer.0.lock().unwrap().push(self.bytes);
        }
    }
}

// ============================================================================
// 3DES-CBC Encryption
// ============================================================================

/// Encrypt data using 3DES-CBC with no padding.
///
/// This is the standard mode used in BAC/PACE for secure messaging.
/// The input must be a multiple of 8 bytes (DES block size).
///
/// # Arguments
///
/// * `key` - 24-byte (192-bit) 3DES key (K1 || K2 || K3)
/// * `iv` - 8-byte initialization vector
/// * `plaintext` - Data to encrypt (must be multiple of 8 bytes)
///
/// # Returns
///
/// Ciphertext of the same length as plaintext.
///
/// # Example
///
/// ```ignore
/// use marty_verification::crypto::des::tdes_cbc_encrypt;
///
/// let key = [0u8; 24];  // 24-byte key
/// let iv = [0u8; 8];    // 8-byte IV
/// let plaintext = [0u8; 16];  // 16 bytes (2 blocks)
///
/// let ciphertext = tdes_cbc_encrypt(&key, &iv, &plaintext)?;
/// assert_eq!(ciphertext.len(), 16);
/// ```
pub fn tdes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    validate_tdes_params(key, iv, plaintext)?;

    let encryptor = TdesEncryptor::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("3DES key/IV error: {}", e)))?;

    // Clone plaintext since we need to encrypt in place
    let mut buffer = SensitiveBuffer::copied_from(plaintext, 0);

    // For no-padding mode, input must already be block-aligned
    let ciphertext = encryptor
        .encrypt_padded_mut::<NoPadding>(&mut buffer.bytes, plaintext.len())
        .map_err(|e| CryptoError::internal(format!("3DES-CBC encryption failed: {}", e)))?
        .len();

    buffer.bytes.truncate(ciphertext);
    Ok(buffer.into_vec())
}

/// Decrypt data using 3DES-CBC with no padding.
///
/// # Arguments
///
/// * `key` - 24-byte (192-bit) 3DES key (K1 || K2 || K3)
/// * `iv` - 8-byte initialization vector
/// * `ciphertext` - Data to decrypt (must be multiple of 8 bytes)
///
/// # Returns
///
/// Decrypted plaintext.
pub fn tdes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    validate_tdes_params(key, iv, ciphertext)?;

    let decryptor = TdesDecryptor::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("3DES key/IV error: {}", e)))?;

    let mut buffer = SensitiveBuffer::copied_from(ciphertext, 0);

    let plaintext = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buffer.bytes)
        .map_err(|e| CryptoError::internal(format!("3DES-CBC decryption failed: {}", e)))?
        .len();

    buffer.bytes.truncate(plaintext);
    Ok(buffer.into_vec())
}

// ============================================================================
// PKCS#7 Padded Variants (for general use)
// ============================================================================

/// Encrypt data using 3DES-CBC with PKCS#7 padding.
///
/// This variant automatically pads the plaintext to a multiple of 8 bytes.
///
/// # Arguments
///
/// * `key` - 24-byte (192-bit) 3DES key
/// * `iv` - 8-byte initialization vector
/// * `plaintext` - Data to encrypt (any length)
///
/// # Returns
///
/// Ciphertext (padded to multiple of 8 bytes).
pub fn tdes_cbc_encrypt_padded(key: &[u8], iv: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 24 {
        return Err(CryptoError::internal(
            "3DES requires 24-byte (192-bit) key".to_string(),
        ));
    }
    if iv.len() != 8 {
        return Err(CryptoError::internal(
            "3DES-CBC requires 8-byte IV".to_string(),
        ));
    }

    let encryptor = TdesEncryptor::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("3DES key/IV error: {}", e)))?;

    // Allocate buffer with space for padding (up to one block)
    let mut buffer = SensitiveBuffer::copied_from(plaintext, 8);
    buffer.bytes.resize(plaintext.len() + 8, 0);

    let ciphertext = encryptor
        .encrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buffer.bytes, plaintext.len())
        .map_err(|e| CryptoError::internal(format!("3DES-CBC encryption failed: {}", e)))?
        .len();

    buffer.bytes.truncate(ciphertext);
    Ok(buffer.into_vec())
}

/// Decrypt data using 3DES-CBC with PKCS#7 padding.
///
/// # Arguments
///
/// * `key` - 24-byte (192-bit) 3DES key
/// * `iv` - 8-byte initialization vector
/// * `ciphertext` - Data to decrypt (must be multiple of 8 bytes)
///
/// # Returns
///
/// Decrypted plaintext with padding removed.
pub fn tdes_cbc_decrypt_padded(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 24 {
        return Err(CryptoError::internal(
            "3DES requires 24-byte (192-bit) key".to_string(),
        ));
    }
    if iv.len() != 8 {
        return Err(CryptoError::internal(
            "3DES-CBC requires 8-byte IV".to_string(),
        ));
    }
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(8) {
        return Err(CryptoError::internal(
            "3DES-CBC ciphertext must be a non-empty multiple of 8 bytes".to_string(),
        ));
    }

    let decryptor = TdesDecryptor::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("3DES key/IV error: {}", e)))?;

    let mut buffer = SensitiveBuffer::copied_from(ciphertext, 0);

    let plaintext = decryptor
        .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buffer.bytes)
        .map_err(|e| CryptoError::internal(format!("3DES-CBC decryption failed: {}", e)))?
        .len();

    buffer.bytes.truncate(plaintext);
    Ok(buffer.into_vec())
}

// ============================================================================
// BAC/PACE Specific Functions
// ============================================================================

/// Compute retail MAC (ISO 9797-1 Algorithm 3) for BAC secure messaging.
///
/// This is the MAC algorithm used in eMRTD secure messaging:
/// 1. Pad message to 8-byte boundary
/// 2. CBC-encrypt with K1 (first 8 bytes of key), zero IV
/// 3. Decrypt last block with K2 (second 8 bytes)
/// 4. Encrypt with K1 again
///
/// # Arguments
///
/// * `key` - 16-byte MAC key (K1 || K2)
/// * `data` - Data to authenticate
///
/// # Returns
///
/// 8-byte MAC value.
pub fn retail_mac(key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::internal(
            "Retail MAC requires 16-byte key".to_string(),
        ));
    }

    // Split key into K1 and K2
    let k1 = &key[..8];
    let k2 = &key[8..16];

    // Pad data to 8-byte boundary (ISO/IEC 7816-4 padding: 0x80 then zeros)
    let mut padded = Zeroizing::new(data.to_vec());
    padded.push(0x80);
    while !padded.len().is_multiple_of(8) {
        padded.push(0x00);
    }

    // Process all blocks with single DES using K1
    let mut y = Zeroizing::new(vec![0u8; 8]); // IV = zero
    for chunk in padded.chunks(8) {
        // XOR with previous result
        for (i, &byte) in chunk.iter().enumerate() {
            y[i] ^= byte;
        }
        // Encrypt with K1 (using 3DES with K1||K1||K1)
        let expanded_key = ExpandedTdesKey::repeated(k1);
        y = Zeroizing::new(tdes_cbc_encrypt(expanded_key.as_ref(), &[0u8; 8], &y)?);
    }

    // Decrypt last block with K2
    let expanded_k2 = ExpandedTdesKey::repeated(k2);
    let y = Zeroizing::new(tdes_cbc_decrypt(expanded_k2.as_ref(), &[0u8; 8], &y)?);

    // Encrypt again with K1
    let expanded_k1 = ExpandedTdesKey::repeated(k1);
    let mac = tdes_cbc_encrypt(expanded_k1.as_ref(), &[0u8; 8], &y)?;

    Ok(mac)
}

/// Adjust DES key parity bits.
///
/// Sets the least significant bit of each byte to make odd parity.
/// This is required for DES keys derived from other sources.
pub fn adjust_parity(key: &mut [u8]) {
    for byte in key.iter_mut() {
        let parity = byte.count_ones() % 2;
        if parity == 0 {
            *byte ^= 0x01;
        }
    }
}

// ============================================================================
// Validation Helpers
// ============================================================================

fn validate_tdes_params(key: &[u8], iv: &[u8], data: &[u8]) -> CryptoResult<()> {
    if key.len() != 24 {
        return Err(CryptoError::internal(
            "3DES requires 24-byte (192-bit) key".to_string(),
        ));
    }
    if iv.len() != 8 {
        return Err(CryptoError::internal(
            "3DES-CBC requires 8-byte IV".to_string(),
        ));
    }
    if data.is_empty() || !data.len().is_multiple_of(8) {
        return Err(CryptoError::internal(
            "3DES-CBC data must be a non-empty multiple of 8 bytes".to_string(),
        ));
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_observed_buffer_wiped(observer: &SensitiveBufferCleanupObserver) {
        let snapshots = observer.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert!(!snapshots[0].is_empty());
        assert!(snapshots[0].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn tdes_cbc_matches_known_answer() {
        let key = hex::decode("0123456789abcdeffedcba987654321089abcdef01234567").unwrap();
        let iv = hex::decode("1234567890abcdef").unwrap();
        assert_eq!(
            hex::encode(tdes_cbc_encrypt(&key, &iv, b"Now is t").unwrap()),
            "204011f986e35647"
        );
    }

    #[test]
    fn tdes_buffers_wipe_on_invalid_padding_and_unwind() {
        let key = [0x13u8; 24];
        let iv = [0x21u8; 8];
        let mut ciphertext = tdes_cbc_encrypt_padded(&key, &iv, b"recognizable text").unwrap();
        *ciphertext.last_mut().unwrap() ^= 0xff;

        let failure_observer = SensitiveBufferCleanupObserver::default();
        {
            let decryptor = TdesDecryptor::new_from_slices(&key, &iv).unwrap();
            let mut buffer = SensitiveBuffer::copied_from_with_observer(
                &ciphertext,
                0,
                failure_observer.clone(),
            );
            assert!(decryptor
                .decrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buffer.bytes)
                .is_err());
        }
        assert_observed_buffer_wiped(&failure_observer);

        let unwind_observer = SensitiveBufferCleanupObserver::default();
        let unwind = std::panic::catch_unwind({
            let observer = unwind_observer.clone();
            move || {
                let mut buffer = SensitiveBuffer::copied_from_with_observer(
                    b"sensitive 3DES scratch",
                    8,
                    observer,
                );
                buffer.bytes[0] ^= 0xff;
                panic!("injected 3DES scratch unwind")
            }
        });
        assert!(unwind.is_err());
        assert_observed_buffer_wiped(&unwind_observer);
    }

    #[test]
    fn retail_mac_expanded_key_copies_wipe_on_drop_and_unwind() {
        let drop_observer = ExpandedTdesKeyCleanupObserver::default();
        let expanded =
            ExpandedTdesKey::repeated(b"12345678").with_cleanup_observer(drop_observer.clone());
        assert_eq!(expanded.as_ref(), b"123456781234567812345678");
        drop(expanded);
        let snapshots = drop_observer.0.lock().unwrap().clone();
        assert_eq!(snapshots, vec![[0; 24]]);

        let unwind_observer = ExpandedTdesKeyCleanupObserver::default();
        let unwind = std::panic::catch_unwind({
            let observer = unwind_observer.clone();
            move || {
                let _expanded =
                    ExpandedTdesKey::repeated(b"ABCDEFGH").with_cleanup_observer(observer);
                panic!("injected expanded-3DES-key unwind")
            }
        });
        assert!(unwind.is_err());
        let snapshots = unwind_observer.0.lock().unwrap().clone();
        assert_eq!(snapshots, vec![[0; 24]]);
    }

    #[test]
    fn test_tdes_cbc_roundtrip() {
        let key = [0x01u8; 24];
        let iv = [0x00u8; 8];
        let plaintext = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x21, 0x21]; // "Hello!!!"

        let ciphertext = tdes_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());

        let decrypted = tdes_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tdes_cbc_padded_roundtrip() {
        let key = [0x01u8; 24];
        let iv = [0x00u8; 8];
        let plaintext = b"Hello, World!"; // Not a multiple of 8

        let ciphertext = tdes_cbc_encrypt_padded(&key, &iv, plaintext).unwrap();
        assert_eq!(ciphertext.len(), 16); // Padded to 2 blocks

        let decrypted = tdes_cbc_decrypt_padded(&key, &iv, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0x01u8; 16]; // Wrong length
        let iv = [0x00u8; 8];
        let plaintext = [0x00u8; 8];

        let result = tdes_cbc_encrypt(&key, &iv, &plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_iv_length() {
        let key = [0x01u8; 24];
        let iv = [0x00u8; 16]; // Wrong length
        let plaintext = [0x00u8; 8];

        let result = tdes_cbc_encrypt(&key, &iv, &plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_unaligned_data() {
        let key = [0x01u8; 24];
        let iv = [0x00u8; 8];
        let plaintext = [0x00u8; 7]; // Not a multiple of 8

        let result = tdes_cbc_encrypt(&key, &iv, &plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_adjust_parity() {
        let mut key = [0x00u8; 8];
        adjust_parity(&mut key);

        // All bytes should now have odd parity
        for byte in key.iter() {
            assert_eq!(byte.count_ones() % 2, 1);
        }
    }

    #[test]
    fn test_retail_mac_basic() {
        let key = [0x01u8; 16];
        let data = b"Test message";

        let mac = retail_mac(&key, data).unwrap();
        assert_eq!(mac.len(), 8);

        // Same input should produce same MAC
        let mac2 = retail_mac(&key, data).unwrap();
        assert_eq!(mac, mac2);
    }
}
