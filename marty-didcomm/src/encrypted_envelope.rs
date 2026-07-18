//! DIDComm v2 encrypted envelope (anoncrypt) using ECDH-ES+A256KW + A256GCM.
//!
//! Implements **anonymous encryption** (anoncrypt): the sender is anonymous to
//! the recipient. The recipient's X25519 public key (from their DID Document's
//! `keyAgreement`) is used for key agreement.
//!
//! ## JWE Structure
//!
//! Following DIDComm v2 §4.1 and RFC 7516:
//!
//! ```text
//! {
//!   "protected": base64url({"alg":"ECDH-ES+A256KW","enc":"A256GCM","typ":"application/didcomm-encrypted+json"}),
//!   "recipients": [{"header": {"kid": "<key-id>"}, "encrypted_key": "<base64url>"}],
//!   "iv": "<base64url>",
//!   "ciphertext": "<base64url>",
//!   "tag": "<base64url>"
//! }
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::error::{DidcommError, DidcommResult};
use crate::types::DidDocument;

/// JWE protected header for DIDComm v2 anoncrypt.
const PROTECTED_HEADER: &str =
    r#"{"alg":"ECDH-ES+A256KW","enc":"A256GCM","typ":"application/didcomm-encrypted+json"}"#;

/// Encrypt a DIDComm v2 plaintext message using the recipient's DID Document.
///
/// Performs X25519 ECDH key agreement with the recipient's key agreement key,
/// derives a 256-bit AES key via Concat KDF (NIST SP 800-56A), wraps a
/// random CEK with AES-256-KW, and encrypts the plaintext with AES-256-GCM.
///
/// Returns the JWE JSON Serialization (General) string.
pub fn encrypt_for_recipient(
    plaintext: &str,
    recipient_did_doc: &DidDocument,
) -> DidcommResult<String> {
    // Extract recipient's X25519 public key
    let recipient_key_bytes = recipient_did_doc.x25519_key_agreement().ok_or_else(|| {
        DidcommError::NoKeyAgreementKey {
            did: recipient_did_doc.id.clone(),
        }
    })?;

    let key_id = recipient_did_doc
        .x25519_key_id()
        .unwrap_or_else(|| format!("{}#key-1", recipient_did_doc.id));

    if recipient_key_bytes.len() != 32 {
        return Err(DidcommError::Crypto(format!(
            "Expected 32-byte X25519 key, got {}",
            recipient_key_bytes.len()
        )));
    }

    let mut recipient_key_arr = [0u8; 32];
    recipient_key_arr.copy_from_slice(&recipient_key_bytes);
    let recipient_pub = PublicKey::from(recipient_key_arr);

    // Generate ephemeral X25519 keypair for ECDH
    let mut rng = rand::thread_rng();
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret);

    // Perform X25519 ECDH
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);

    // Derive wrapping key via Concat KDF (SP 800-56A, single pass)
    let kek = concat_kdf_sha256(shared_secret.as_bytes(), b"ECDH-ES+A256KW", 32);

    // Generate random CEK (Content Encryption Key) for AES-256-GCM
    let mut cek = [0u8; 32];
    rng.fill_bytes(&mut cek);

    // Wrap CEK with the KEK using AES-256-KW (RFC 3394)
    let wrapped_cek = aes_key_wrap(&kek, &cek)?;

    // Encrypt plaintext with AES-256-GCM using the CEK
    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);

    let cipher =
        Aes256Gcm::new_from_slice(&cek).map_err(|e| DidcommError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&iv);

    // AAD = the protected header base64url-encoded
    let protected_b64 = URL_SAFE_NO_PAD.encode(PROTECTED_HEADER.as_bytes());
    let ciphertext_with_tag = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext.as_bytes(),
                aad: protected_b64.as_bytes(),
            },
        )
        .map_err(|e| DidcommError::Crypto(format!("AES-GCM encrypt failed: {e}")))?;

    // AES-GCM appends the 16-byte tag to the ciphertext
    let (ct, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);

    // Build JWE JSON Serialization (General)
    let epk_b64 = URL_SAFE_NO_PAD.encode(ephemeral_pub.as_bytes());

    let jwe = serde_json::json!({
        "protected": protected_b64,
        "recipients": [{
            "header": {
                "kid": key_id,
                "epk": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": epk_b64
                }
            },
            "encrypted_key": URL_SAFE_NO_PAD.encode(&wrapped_cek)
        }],
        "iv": URL_SAFE_NO_PAD.encode(iv),
        "ciphertext": URL_SAFE_NO_PAD.encode(ct),
        "tag": URL_SAFE_NO_PAD.encode(tag)
    });

    serde_json::to_string(&jwe).map_err(|e| DidcommError::PackError(e.to_string()))
}

/// Decrypt a DIDComm v2 JWE (anoncrypt) using the recipient's X25519 private key.
///
/// # Arguments
///
/// * `jwe_json` — JWE JSON Serialization string
/// * `recipient_private_key` — The recipient's 32-byte X25519 private key
pub fn decrypt_jwe(jwe_json: &str, recipient_private_key: &[u8; 32]) -> DidcommResult<String> {
    let jwe: serde_json::Value =
        serde_json::from_str(jwe_json).map_err(|e| DidcommError::UnpackError(e.to_string()))?;

    let protected_b64 = jwe["protected"]
        .as_str()
        .ok_or_else(|| DidcommError::UnpackError("missing protected header".into()))?;

    let recipients = jwe["recipients"]
        .as_array()
        .ok_or_else(|| DidcommError::UnpackError("missing recipients".into()))?;

    if recipients.is_empty() {
        return Err(DidcommError::UnpackError("no recipients".into()));
    }

    // Extract ephemeral public key from first recipient
    let recip = &recipients[0];
    let epk_x = recip["header"]["epk"]["x"]
        .as_str()
        .ok_or_else(|| DidcommError::UnpackError("missing epk.x".into()))?;
    let epk_bytes = URL_SAFE_NO_PAD
        .decode(epk_x)
        .map_err(|e| DidcommError::UnpackError(format!("epk decode: {e}")))?;

    if epk_bytes.len() != 32 {
        return Err(DidcommError::UnpackError(format!(
            "expected 32-byte epk, got {}",
            epk_bytes.len()
        )));
    }

    let mut epk_arr = [0u8; 32];
    epk_arr.copy_from_slice(&epk_bytes);
    let epk = PublicKey::from(epk_arr);

    // Perform ECDH with the recipient's static private key
    let static_secret = x25519_dalek::StaticSecret::from(*recipient_private_key);
    let shared_secret = static_secret.diffie_hellman(&epk);

    // Derive KEK via Concat KDF
    let kek = concat_kdf_sha256(shared_secret.as_bytes(), b"ECDH-ES+A256KW", 32);

    // Unwrap CEK
    let wrapped_cek_b64 = recip["encrypted_key"]
        .as_str()
        .ok_or_else(|| DidcommError::UnpackError("missing encrypted_key".into()))?;
    let wrapped_cek = URL_SAFE_NO_PAD
        .decode(wrapped_cek_b64)
        .map_err(|e| DidcommError::UnpackError(format!("encrypted_key decode: {e}")))?;
    let cek = aes_key_unwrap(&kek, &wrapped_cek)?;

    // Decrypt ciphertext
    let iv_b64 = jwe["iv"]
        .as_str()
        .ok_or_else(|| DidcommError::UnpackError("missing iv".into()))?;
    let ct_b64 = jwe["ciphertext"]
        .as_str()
        .ok_or_else(|| DidcommError::UnpackError("missing ciphertext".into()))?;
    let tag_b64 = jwe["tag"]
        .as_str()
        .ok_or_else(|| DidcommError::UnpackError("missing tag".into()))?;

    let iv = URL_SAFE_NO_PAD
        .decode(iv_b64)
        .map_err(|e| DidcommError::UnpackError(format!("iv decode: {e}")))?;
    let ct = URL_SAFE_NO_PAD
        .decode(ct_b64)
        .map_err(|e| DidcommError::UnpackError(format!("ct decode: {e}")))?;
    let tag = URL_SAFE_NO_PAD
        .decode(tag_b64)
        .map_err(|e| DidcommError::UnpackError(format!("tag decode: {e}")))?;

    // Reassemble ciphertext + tag for AES-GCM
    let mut ct_with_tag = ct;
    ct_with_tag.extend_from_slice(&tag);

    let cipher =
        Aes256Gcm::new_from_slice(&cek).map_err(|e| DidcommError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&iv);

    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &ct_with_tag,
                aad: protected_b64.as_bytes(),
            },
        )
        .map_err(|e| DidcommError::Crypto(format!("AES-GCM decrypt failed: {e}")))?;

    String::from_utf8(plaintext).map_err(|e| DidcommError::UnpackError(e.to_string()))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Concat KDF (NIST SP 800-56A, single-pass SHA-256) for ECDH-ES key derivation.
///
/// ```text
/// DK = SHA-256(0x00000001 || Z || OtherInfo)
/// OtherInfo = AlgorithmID_len || AlgorithmID || PartyUInfo_len(0) || PartyVInfo_len(0) || SuppPubInfo
/// ```
fn concat_kdf_sha256(shared_secret: &[u8], algorithm_id: &[u8], key_len_bytes: usize) -> Vec<u8> {
    let key_len_bits = (key_len_bytes * 8) as u32;
    let alg_id_len = (algorithm_id.len() as u32).to_be_bytes();

    let mut hasher = Sha256::new();
    hasher.update(1u32.to_be_bytes()); // round = 1
    hasher.update(shared_secret);
    // OtherInfo per JWA §4.6.2
    hasher.update(alg_id_len);
    hasher.update(algorithm_id);
    hasher.update(0u32.to_be_bytes()); // PartyUInfo (empty)
    hasher.update(0u32.to_be_bytes()); // PartyVInfo (empty)
    hasher.update(key_len_bits.to_be_bytes()); // SuppPubInfo = keydatalen
    let hash = hasher.finalize();

    hash[..key_len_bytes].to_vec()
}

/// AES Key Wrap (RFC 3394) — wraps a 256-bit key with a 256-bit KEK.
fn aes_key_wrap(kek: &[u8], plaintext: &[u8]) -> DidcommResult<Vec<u8>> {
    use aes::cipher::KeyInit as AesKeyInit;
    use aes::Aes256;

    if !plaintext.len().is_multiple_of(8) || plaintext.is_empty() {
        return Err(DidcommError::Crypto(
            "AES Key Wrap: plaintext must be a non-empty multiple of 8 bytes".into(),
        ));
    }

    let n = plaintext.len() / 8;
    let mut a = 0xA6A6A6A6A6A6A6A6u64;
    let mut r: Vec<[u8; 8]> = plaintext
        .chunks(8)
        .map(|c| {
            let mut block = [0u8; 8];
            block.copy_from_slice(c);
            block
        })
        .collect();

    let cipher = Aes256::new_from_slice(kek)
        .map_err(|e| DidcommError::Crypto(format!("AES key init: {e}")))?;

    for j in 0..6u64 {
        for (i, r_block) in r.iter_mut().enumerate() {
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a.to_be_bytes());
            block[8..].copy_from_slice(r_block);

            let b = aes::Block::from(block);
            let encrypted = cipher.encrypt_with_backend_b(b);
            let encrypted_bytes: [u8; 16] = encrypted.into();

            let t = (n as u64) * j + (i as u64) + 1;
            a = u64::from_be_bytes(encrypted_bytes[..8].try_into().unwrap()) ^ t;
            r_block.copy_from_slice(&encrypted_bytes[8..]);
        }
    }

    let mut result = Vec::with_capacity(8 + plaintext.len());
    result.extend_from_slice(&a.to_be_bytes());
    for block in &r {
        result.extend_from_slice(block);
    }
    Ok(result)
}

/// AES Key Unwrap (RFC 3394) — unwraps a key using a 256-bit KEK.
fn aes_key_unwrap(kek: &[u8], ciphertext: &[u8]) -> DidcommResult<Vec<u8>> {
    use aes::cipher::KeyInit as AesKeyInit;
    use aes::Aes256;

    if !ciphertext.len().is_multiple_of(8) || ciphertext.len() < 24 {
        return Err(DidcommError::Crypto(
            "AES Key Unwrap: ciphertext must be >= 24 bytes and a multiple of 8".into(),
        ));
    }

    let n = (ciphertext.len() / 8) - 1;
    let mut a = u64::from_be_bytes(ciphertext[..8].try_into().unwrap());
    let mut r: Vec<[u8; 8]> = ciphertext[8..]
        .chunks(8)
        .map(|c| {
            let mut block = [0u8; 8];
            block.copy_from_slice(c);
            block
        })
        .collect();

    let cipher = Aes256::new_from_slice(kek)
        .map_err(|e| DidcommError::Crypto(format!("AES key init: {e}")))?;

    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            let t = (n as u64) * j + (i as u64) + 1;
            let a_xored = a ^ t;

            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a_xored.to_be_bytes());
            block[8..].copy_from_slice(&r[i]);

            let b = aes::Block::from(block);
            let decrypted = cipher.decrypt_with_backend_b(b);
            let decrypted_bytes: [u8; 16] = decrypted.into();

            a = u64::from_be_bytes(decrypted_bytes[..8].try_into().unwrap());
            r[i].copy_from_slice(&decrypted_bytes[8..]);
        }
    }

    // Verify integrity check value
    if a != 0xA6A6A6A6A6A6A6A6 {
        return Err(DidcommError::Crypto(
            "AES Key Unwrap: integrity check failed".into(),
        ));
    }

    let mut result = Vec::with_capacity(n * 8);
    for block in &r {
        result.extend_from_slice(block);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Extension trait for AES block cipher — needed for encrypt/decrypt of single blocks
// ---------------------------------------------------------------------------

trait BlockEncryptExt {
    fn encrypt_with_backend_b(&self, block: aes::Block) -> aes::Block;
}

trait BlockDecryptExt {
    fn decrypt_with_backend_b(&self, block: aes::Block) -> aes::Block;
}

impl BlockEncryptExt for aes::Aes256 {
    fn encrypt_with_backend_b(&self, mut block: aes::Block) -> aes::Block {
        use aes::cipher::BlockEncrypt;
        self.encrypt_block(&mut block);
        block
    }
}

impl BlockDecryptExt for aes::Aes256 {
    fn decrypt_with_backend_b(&self, mut block: aes::Block) -> aes::Block {
        use aes::cipher::BlockDecrypt;
        self.decrypt_block(&mut block);
        block
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_key_wrap_unwrap_roundtrip() {
        let kek = [0x42u8; 32];
        let plaintext = [0x01u8; 32]; // 256-bit key to wrap

        let wrapped = aes_key_wrap(&kek, &plaintext).unwrap();
        assert_eq!(wrapped.len(), 40); // 32 + 8 overhead

        let unwrapped = aes_key_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, plaintext);
    }

    #[test]
    fn test_aes_key_unwrap_tampered() {
        let kek = [0x42u8; 32];
        let plaintext = [0x01u8; 32];
        let mut wrapped = aes_key_wrap(&kek, &plaintext).unwrap();
        wrapped[0] ^= 0xFF; // tamper
        assert!(aes_key_unwrap(&kek, &wrapped).is_err());
    }

    #[test]
    fn test_concat_kdf() {
        let shared = [0xABu8; 32];
        let key = concat_kdf_sha256(&shared, b"ECDH-ES+A256KW", 32);
        assert_eq!(key.len(), 32);
        // Deterministic — same input always produces same output
        let key2 = concat_kdf_sha256(&shared, b"ECDH-ES+A256KW", 32);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Build a minimal DID Document with X25519 key agreement
        let recipient_private = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let recipient_public = PublicKey::from(&recipient_private);

        let did_doc = DidDocument {
            id: "did:key:test-recipient".into(),
            context: serde_json::json!("https://www.w3.org/ns/did/v1"),
            authentication: vec![],
            key_agreement: vec![],
            verification_method: vec![crate::types::VerificationMethod {
                id: "did:key:test-recipient#key-1".into(),
                r#type: "X25519KeyAgreementKey2020".into(),
                controller: "did:key:test-recipient".into(),
                public_key_jwk: Some(crate::types::Jwk {
                    kty: "OKP".into(),
                    crv: Some("X25519".into()),
                    x: Some(URL_SAFE_NO_PAD.encode(recipient_public.as_bytes())),
                    y: None,
                    d: None,
                    kid: None,
                }),
                public_key_multibase: None,
                public_key_base58: None,
            }],
            service: vec![],
        };

        let plaintext = r#"{"id":"msg-1","type":"https://didcomm.org/issue-credential/3.0/issue-credential","body":{}}"#;

        // Encrypt
        let jwe_json = encrypt_for_recipient(plaintext, &did_doc).unwrap();

        // Verify it's valid JSON
        let jwe: serde_json::Value = serde_json::from_str(&jwe_json).unwrap();
        assert!(jwe["protected"].is_string());
        assert!(jwe["recipients"].is_array());
        assert!(jwe["iv"].is_string());
        assert!(jwe["ciphertext"].is_string());
        assert!(jwe["tag"].is_string());

        // Decrypt
        let private_bytes: [u8; 32] = recipient_private.to_bytes();
        let decrypted = decrypt_jwe(&jwe_json, &private_bytes).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let recipient_private = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let recipient_public = PublicKey::from(&recipient_private);

        let did_doc = DidDocument {
            id: "did:key:test".into(),
            context: serde_json::json!("https://www.w3.org/ns/did/v1"),
            authentication: vec![],
            key_agreement: vec![],
            verification_method: vec![crate::types::VerificationMethod {
                id: "did:key:test#key-1".into(),
                r#type: "X25519KeyAgreementKey2020".into(),
                controller: "did:key:test".into(),
                public_key_jwk: Some(crate::types::Jwk {
                    kty: "OKP".into(),
                    crv: Some("X25519".into()),
                    x: Some(URL_SAFE_NO_PAD.encode(recipient_public.as_bytes())),
                    y: None,
                    d: None,
                    kid: None,
                }),
                public_key_multibase: None,
                public_key_base58: None,
            }],
            service: vec![],
        };

        let jwe = encrypt_for_recipient("secret message", &did_doc).unwrap();

        // Try decrypting with a different key
        let wrong_key = [0x99u8; 32];
        assert!(decrypt_jwe(&jwe, &wrong_key).is_err());
    }
}
