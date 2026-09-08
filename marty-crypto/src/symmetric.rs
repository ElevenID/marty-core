//! Symmetric encryption (AES-GCM, AES-CBC).

// Suppress deprecated warning from aes-gcm crate using older generic-array version
#![allow(deprecated)]

use aes::{Aes128, Aes256};
use aes_gcm::{
    aead::{consts::U12, AeadCore, AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce as GcmNonce,
};
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::secret_buffer::SensitiveBuffer;
#[cfg(test)]
use crate::secret_buffer::SensitiveBufferCleanupObserver;
use crate::{CryptoError, CryptoResult};

fn aes_gcm_encrypt<C>(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>>
where
    C: AeadCore<NonceSize = U12> + AeadInPlace + KeyInit,
{
    let cipher = C::new_from_slice(key)
        .map_err(|error| CryptoError::internal(format!("AES key error: {error}")))?;
    let mut output = SensitiveBuffer::copied_from(plaintext, 16);
    cipher
        .encrypt_in_place(GcmNonce::from_slice(nonce), aad, &mut output.bytes)
        .map_err(|error| CryptoError::internal(format!("AES-GCM encryption failed: {error}")))?;
    Ok(output.into_vec())
}

fn aes_gcm_decrypt<C>(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>>
where
    C: AeadCore<NonceSize = U12> + AeadInPlace + KeyInit,
{
    let cipher = C::new_from_slice(key)
        .map_err(|error| CryptoError::internal(format!("AES key error: {error}")))?;
    let mut output = SensitiveBuffer::copied_from(ciphertext, 0);
    cipher
        .decrypt_in_place(GcmNonce::from_slice(nonce), aad, &mut output.bytes)
        .map_err(|_| {
            CryptoError::internal("AES-GCM decryption failed: authentication failed".to_string())
        })?;
    Ok(output.into_vec())
}

// ============================================================================
// AES-GCM (Authenticated Encryption)
// ============================================================================

/// Encrypt data using AES-128-GCM.
///
/// # Arguments
///
/// * `key` - 16-byte encryption key
/// * `nonce` - 12-byte nonce (must be unique per encryption)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (optional)
///
/// # Returns
///
/// Ciphertext with authentication tag appended.
pub fn aes_128_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::internal(
            "AES-128-GCM requires 16-byte key".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(CryptoError::internal(
            "AES-GCM requires 12-byte nonce".to_string(),
        ));
    }

    aes_gcm_encrypt::<Aes128Gcm>(key, nonce, plaintext, aad)
}

/// Decrypt data using AES-128-GCM.
///
/// # Arguments
///
/// * `key` - 16-byte encryption key
/// * `nonce` - 12-byte nonce
/// * `ciphertext` - Data to decrypt (includes auth tag)
/// * `aad` - Additional authenticated data (must match encryption)
///
/// # Returns
///
/// Decrypted plaintext.
pub fn aes_128_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::internal(
            "AES-128-GCM requires 16-byte key".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(CryptoError::internal(
            "AES-GCM requires 12-byte nonce".to_string(),
        ));
    }

    aes_gcm_decrypt::<Aes128Gcm>(key, nonce, ciphertext, aad)
}

/// Encrypt data using AES-256-GCM.
pub fn aes_256_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::internal(
            "AES-256-GCM requires 32-byte key".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(CryptoError::internal(
            "AES-GCM requires 12-byte nonce".to_string(),
        ));
    }

    aes_gcm_encrypt::<Aes256Gcm>(key, nonce, plaintext, aad)
}

/// Decrypt data using AES-256-GCM.
pub fn aes_256_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::internal(
            "AES-256-GCM requires 32-byte key".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(CryptoError::internal(
            "AES-GCM requires 12-byte nonce".to_string(),
        ));
    }

    aes_gcm_decrypt::<Aes256Gcm>(key, nonce, ciphertext, aad)
}

// ============================================================================
// AES-CBC (Used in BAC/PACE)
// ============================================================================

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

/// Encrypt data using AES-128-CBC with PKCS7 padding.
///
/// # Arguments
///
/// * `key` - 16-byte encryption key
/// * `iv` - 16-byte initialization vector
/// * `plaintext` - Data to encrypt
///
/// # Returns
///
/// Padded ciphertext.
pub fn aes_128_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::internal(
            "AES-128-CBC requires 16-byte key".to_string(),
        ));
    }
    if iv.len() != 16 {
        return Err(CryptoError::internal(
            "AES-CBC requires 16-byte IV".to_string(),
        ));
    }

    let cipher = Aes128CbcEnc::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("AES key/IV error: {}", e)))?;

    // Calculate padded length
    let padding_len = 16 - (plaintext.len() % 16);
    let mut buffer = SensitiveBuffer::copied_from(plaintext, padding_len);
    buffer.bytes.resize(plaintext.len() + padding_len, 0);

    let ciphertext_len = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer.bytes, plaintext.len())
        .map_err(|e| CryptoError::internal(format!("AES-CBC encryption failed: {}", e)))?
        .len();

    buffer.bytes.truncate(ciphertext_len);
    Ok(buffer.into_vec())
}

/// Decrypt data using AES-128-CBC with PKCS7 padding.
///
/// # Arguments
///
/// * `key` - 16-byte encryption key
/// * `iv` - 16-byte initialization vector
/// * `ciphertext` - Data to decrypt
///
/// # Returns
///
/// Unpadded plaintext.
pub fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::internal(
            "AES-128-CBC requires 16-byte key".to_string(),
        ));
    }
    if iv.len() != 16 {
        return Err(CryptoError::internal(
            "AES-CBC requires 16-byte IV".to_string(),
        ));
    }
    if !ciphertext.len().is_multiple_of(16) {
        return Err(CryptoError::internal(
            "AES-CBC ciphertext must be multiple of 16 bytes".to_string(),
        ));
    }

    let cipher = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("AES key/IV error: {}", e)))?;

    let mut buffer = SensitiveBuffer::copied_from(ciphertext, 0);
    let plaintext_len = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer.bytes)
        .map_err(|_| {
            CryptoError::internal("AES-CBC decryption failed: invalid padding".to_string())
        })?
        .len();

    buffer.bytes.truncate(plaintext_len);
    Ok(buffer.into_vec())
}

/// Encrypt data using AES-128-CBC without padding (for BAC).
///
/// Caller must ensure plaintext is already padded to 16-byte boundary.
pub fn aes_128_cbc_encrypt_nopad(key: &[u8], iv: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::internal(
            "AES-128-CBC requires 16-byte key".to_string(),
        ));
    }
    if iv.len() != 16 {
        return Err(CryptoError::internal(
            "AES-CBC requires 16-byte IV".to_string(),
        ));
    }
    if !plaintext.len().is_multiple_of(16) {
        return Err(CryptoError::internal(
            "Plaintext must be multiple of 16 bytes for no-padding mode".to_string(),
        ));
    }

    let cipher = Aes128CbcEnc::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("AES key/IV error: {}", e)))?;

    let mut buffer = SensitiveBuffer::copied_from(plaintext, 0);
    cipher
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer.bytes, plaintext.len())
        .map_err(|e| CryptoError::internal(format!("AES-CBC encryption failed: {}", e)))?;

    Ok(buffer.into_vec())
}

/// Decrypt data using AES-128-CBC without padding (for BAC).
pub fn aes_128_cbc_decrypt_nopad(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::internal(
            "AES-128-CBC requires 16-byte key".to_string(),
        ));
    }
    if iv.len() != 16 {
        return Err(CryptoError::internal(
            "AES-CBC requires 16-byte IV".to_string(),
        ));
    }
    if !ciphertext.len().is_multiple_of(16) {
        return Err(CryptoError::internal(
            "Ciphertext must be multiple of 16 bytes".to_string(),
        ));
    }

    let cipher = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("AES key/IV error: {}", e)))?;

    let mut buffer = SensitiveBuffer::copied_from(ciphertext, 0);
    cipher
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer.bytes)
        .map_err(|_| CryptoError::internal("AES-CBC decryption failed".to_string()))?;

    Ok(buffer.into_vec())
}

// ============================================================================
// AES-256-CBC (Used in EAC secure messaging)
// ============================================================================

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Encrypt data using AES-256-CBC with PKCS7 padding.
pub fn aes_256_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::internal(
            "AES-256-CBC requires 32-byte key".to_string(),
        ));
    }
    if iv.len() != 16 {
        return Err(CryptoError::internal(
            "AES-CBC requires 16-byte IV".to_string(),
        ));
    }

    let cipher = Aes256CbcEnc::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("AES key/IV error: {}", e)))?;

    let padding_len = 16 - (plaintext.len() % 16);
    let mut buffer = SensitiveBuffer::copied_from(plaintext, padding_len);
    buffer.bytes.resize(plaintext.len() + padding_len, 0);

    let ciphertext_len = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer.bytes, plaintext.len())
        .map_err(|e| CryptoError::internal(format!("AES-256-CBC encryption failed: {}", e)))?
        .len();

    buffer.bytes.truncate(ciphertext_len);
    Ok(buffer.into_vec())
}

/// Decrypt data using AES-256-CBC with PKCS7 padding.
pub fn aes_256_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::internal(
            "AES-256-CBC requires 32-byte key".to_string(),
        ));
    }
    if iv.len() != 16 {
        return Err(CryptoError::internal(
            "AES-CBC requires 16-byte IV".to_string(),
        ));
    }
    if !ciphertext.len().is_multiple_of(16) {
        return Err(CryptoError::internal(
            "AES-CBC ciphertext must be multiple of 16 bytes".to_string(),
        ));
    }

    let cipher = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("AES key/IV error: {}", e)))?;

    let mut buffer = SensitiveBuffer::copied_from(ciphertext, 0);
    let plaintext_len = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer.bytes)
        .map_err(|_| {
            CryptoError::internal("AES-256-CBC decryption failed: invalid padding".to_string())
        })?
        .len();

    buffer.bytes.truncate(plaintext_len);
    Ok(buffer.into_vec())
}

// ============================================================================
// CMAC (for Secure Messaging)
// ============================================================================

/// Compute AES-128 CMAC.
///
/// Used in secure messaging for message authentication.
pub fn aes_128_cmac(key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 16 {
        return Err(CryptoError::internal(
            "AES-128 CMAC requires 16-byte key".to_string(),
        ));
    }

    #[cfg(not(target_family = "wasm"))]
    {
        let key = aws_lc_rs::cmac::Key::new(aws_lc_rs::cmac::AES_128, key)
            .map_err(|_| CryptoError::internal("CMAC key error".to_string()))?;
        aws_lc_rs::cmac::sign(&key, data)
            .map(|tag| tag.as_ref().to_vec())
            .map_err(|_| CryptoError::internal("CMAC calculation failed".to_string()))
    }
    #[cfg(target_family = "wasm")]
    {
        use cmac::{Cmac, Mac};
        let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key)
            .map_err(|e| CryptoError::internal(format!("CMAC key error: {}", e)))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

// ============================================================================
// HMAC-SHA256 (for EAC secure messaging MAC)
// ============================================================================

/// Compute HMAC-SHA256.
///
/// Used in EAC secure messaging for message authentication.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    #[cfg(not(target_family = "wasm"))]
    {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
        Ok(aws_lc_rs::hmac::sign(&key, data).as_ref().to_vec())
    }
    #[cfg(target_family = "wasm")]
    {
        Ok(crate::secret_hash::hmac_sha256(key, &[data]).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_observed_buffers_wiped(observer: &SensitiveBufferCleanupObserver, count: usize) {
        let snapshots = observer.snapshots();
        assert_eq!(snapshots.len(), count);
        assert!(snapshots.iter().all(|snapshot| !snapshot.is_empty()));
        assert!(snapshots
            .iter()
            .flatten()
            .all(|observed_byte| *observed_byte == 0));
    }

    #[test]
    fn sensitive_buffers_wipe_on_authentication_failure_and_unwind() {
        let key = [0x42; 16];
        let nonce = [0x01; 12];
        let plaintext = b"recognizable plaintext";
        let mut ciphertext = aes_128_gcm_encrypt(&key, &nonce, plaintext, b"aad").unwrap();
        ciphertext[0] ^= 1;

        let failure_observer = SensitiveBufferCleanupObserver::default();
        {
            let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
            let mut output = SensitiveBuffer::copied_from_with_observer(
                &ciphertext,
                0,
                failure_observer.clone(),
            );
            assert!(cipher
                .decrypt_in_place(GcmNonce::from_slice(&nonce), b"aad", &mut output.bytes)
                .is_err());
        }
        assert_observed_buffers_wiped(&failure_observer, 1);

        let unwind_observer = SensitiveBufferCleanupObserver::default();
        let unwind = std::panic::catch_unwind({
            let observer = unwind_observer.clone();
            move || {
                let mut output = SensitiveBuffer::copied_from_with_observer(
                    b"second recognizable plaintext",
                    16,
                    observer,
                );
                output.bytes[0] ^= 0xff;
                panic!("injected symmetric-buffer unwind")
            }
        });
        assert!(unwind.is_err());
        assert_observed_buffers_wiped(&unwind_observer, 1);
    }

    #[test]
    fn test_aes_128_gcm_roundtrip() {
        let key = [0x42; 16];
        let nonce = [0x01; 12];
        let plaintext = b"Hello, mDL world!";
        let aad = b"";

        let ciphertext = aes_128_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = aes_128_gcm_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_256_gcm_roundtrip() {
        let key = [0x42; 32];
        let nonce = [0x01; 12];
        let plaintext = b"Hello, mDL world!";
        let aad = b"";

        let ciphertext = aes_256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = aes_256_gcm_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_128_gcm_with_aad() {
        let key = [0x42; 16];
        let nonce = [0x01; 12];
        let plaintext = b"Sensitive data";
        let aad = b"header";

        let ciphertext = aes_128_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Should succeed with correct AAD
        let decrypted = aes_128_gcm_decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);

        // Should fail with wrong AAD
        let result = aes_128_gcm_decrypt(&key, &nonce, &ciphertext, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_128_cbc_roundtrip() {
        let key = [0x42; 16];
        let iv = [0x00; 16];
        let plaintext = b"Hello, eMRTD world!";

        let ciphertext = aes_128_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_128_cbc_nopad_roundtrip() {
        let key = [0x42; 16];
        let iv = [0x00; 16];
        // Must be exact multiple of 16 bytes
        let plaintext = b"Exactly16bytes!!";

        let ciphertext = aes_128_cbc_encrypt_nopad(&key, &iv, plaintext).unwrap();
        let decrypted = aes_128_cbc_decrypt_nopad(&key, &iv, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_128_cmac() {
        let key = [0x42; 16];
        let data = b"data to authenticate";

        let mac = aes_128_cmac(&key, data).unwrap();
        assert_eq!(mac.len(), 16);

        // Verify same input produces same output
        let mac2 = aes_128_cmac(&key, data).unwrap();
        assert_eq!(mac, mac2);
    }

    #[test]
    fn mac_backends_match_published_known_answers() {
        let cmac_key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        assert_eq!(
            hex::encode(aes_128_cmac(&cmac_key, b"").unwrap()),
            "bb1d6929e95937287fa37d129b756746"
        );
        assert_eq!(
            hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There").unwrap()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
