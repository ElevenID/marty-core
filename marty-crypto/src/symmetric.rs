//! Symmetric encryption (AES-GCM, AES-CBC).

// Suppress deprecated warning from aes-gcm crate using older generic-array version
#![allow(deprecated)]

use aes::Aes128;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce as GcmNonce,
};
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::{CryptoError, CryptoResult};

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

    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::internal(format!("AES key error: {}", e)))?;

    let nonce = GcmNonce::from_slice(nonce);

    // For AAD support, we'd need to use encrypt_in_place_detached
    // For simplicity, this ignores AAD in the basic case
    let ciphertext = if aad.is_empty() {
        cipher.encrypt(nonce, plaintext)
    } else {
        cipher.encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
    };

    ciphertext.map_err(|e| CryptoError::internal(format!("AES-GCM encryption failed: {}", e)))
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

    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::internal(format!("AES key error: {}", e)))?;

    let nonce = GcmNonce::from_slice(nonce);

    let plaintext = if aad.is_empty() {
        cipher.decrypt(nonce, ciphertext)
    } else {
        cipher.decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
    };

    plaintext.map_err(|_| {
        CryptoError::internal("AES-GCM decryption failed: authentication failed".to_string())
    })
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

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::internal(format!("AES key error: {}", e)))?;

    let nonce = GcmNonce::from_slice(nonce);

    let ciphertext = if aad.is_empty() {
        cipher.encrypt(nonce, plaintext)
    } else {
        cipher.encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
    };

    ciphertext.map_err(|e| CryptoError::internal(format!("AES-GCM encryption failed: {}", e)))
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

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::internal(format!("AES key error: {}", e)))?;

    let nonce = GcmNonce::from_slice(nonce);

    let plaintext = if aad.is_empty() {
        cipher.decrypt(nonce, ciphertext)
    } else {
        cipher.decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
    };

    plaintext.map_err(|_| {
        CryptoError::internal("AES-GCM decryption failed: authentication failed".to_string())
    })
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
    let mut buffer = vec![0u8; plaintext.len() + padding_len];
    buffer[..plaintext.len()].copy_from_slice(plaintext);

    let ciphertext = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|e| CryptoError::internal(format!("AES-CBC encryption failed: {}", e)))?;

    Ok(ciphertext.to_vec())
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
pub fn aes_128_cbc_decrypt(
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
    if ciphertext.len() % 16 != 0 {
        return Err(CryptoError::internal(
            "AES-CBC ciphertext must be multiple of 16 bytes".to_string(),
        ));
    }

    let cipher = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("AES key/IV error: {}", e)))?;

    let mut buffer = ciphertext.to_vec();
    let plaintext = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| {
            CryptoError::internal("AES-CBC decryption failed: invalid padding".to_string())
        })?;

    Ok(plaintext.to_vec())
}

/// Encrypt data using AES-128-CBC without padding (for BAC).
///
/// Caller must ensure plaintext is already padded to 16-byte boundary.
pub fn aes_128_cbc_encrypt_nopad(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
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
    if plaintext.len() % 16 != 0 {
        return Err(CryptoError::internal(
            "Plaintext must be multiple of 16 bytes for no-padding mode".to_string(),
        ));
    }

    let cipher = Aes128CbcEnc::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("AES key/IV error: {}", e)))?;

    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer, plaintext.len())
        .map_err(|e| CryptoError::internal(format!("AES-CBC encryption failed: {}", e)))?;

    Ok(buffer)
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
    if ciphertext.len() % 16 != 0 {
        return Err(CryptoError::internal(
            "Ciphertext must be multiple of 16 bytes".to_string(),
        ));
    }

    let cipher = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|e| CryptoError::internal(format!("AES key/IV error: {}", e)))?;

    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buffer)
        .map_err(|_| CryptoError::internal("AES-CBC decryption failed".to_string()))?;

    Ok(buffer)
}

// ============================================================================
// CMAC (for Secure Messaging)
// ============================================================================

/// Compute AES-128 CMAC.
///
/// Used in secure messaging for message authentication.
pub fn aes_128_cmac(key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    use cmac::{Cmac, Mac};

    if key.len() != 16 {
        return Err(CryptoError::internal(
            "AES-128 CMAC requires 16-byte key".to_string(),
        ));
    }

    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key)
        .map_err(|e| CryptoError::internal(format!("CMAC key error: {}", e)))?;

    mac.update(data);
    let result = mac.finalize();

    Ok(result.into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
