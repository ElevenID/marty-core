//! BBS+ signature operations.
//!
//! This module provides BBS+ signing, verification, and selective disclosure
//! proof generation using the `zkryptium` crate (IETF draft-irtf-cfrg-bbs-signatures).
//!
//! BBS+ signatures enable:
//! - **Unlinkable selective disclosure**: Reveal a subset of signed messages
//!   without leaking information about hidden messages.
//! - **Proof of knowledge**: Holder proves knowledge of a valid signature
//!   without revealing the signature itself.
//! - **Multi-message signing**: A single signature covers N messages.
//!
//! # Supported Ciphersuites
//!
//! - `BLS12-381-SHA-256` — Standard SHA-256 based expansion
//! - `BLS12-381-SHAKE-256` — SHAKE-256 based expansion (recommended by IETF)
//!
//! # Security Properties
//!
//! - 128-bit security level (BLS12-381 curve)
//! - Signature: 80 bytes, public key: 96 bytes, proof: variable
//! - CRS-free (no trusted setup required)

use crate::{CryptoError, CryptoResult};
use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};
use zkryptium::schemes::generics::{PoKSignature, Signature};

/// BBS+ ciphersuite selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BbsCiphersuite {
    /// BLS12-381 with SHA-256 message expansion.
    Bls12381Sha256,
    /// BLS12-381 with SHAKE-256 message expansion (IETF recommended).
    Bls12381Shake256,
}

impl BbsCiphersuite {
    /// JOSE algorithm identifier.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Bls12381Sha256 => "BBS_BLS12381_SHA256",
            Self::Bls12381Shake256 => "BBS_BLS12381_SHAKE256",
        }
    }

    /// Parse from algorithm name string.
    pub fn from_algorithm_name(name: &str) -> CryptoResult<Self> {
        match name {
            "BBS_BLS12381_SHA256" | "bbs_bls12381_sha256" => Ok(Self::Bls12381Sha256),
            "BBS_BLS12381_SHAKE256" | "bbs_bls12381_shake256" => Ok(Self::Bls12381Shake256),
            _ => Err(CryptoError::unsupported_algorithm(format!(
                "Unknown BBS+ ciphersuite: {}",
                name
            ))),
        }
    }
}

// ============================================================================
// Key Types
// ============================================================================

/// BBS+ key pair for multi-message signing and selective disclosure.
#[derive(Clone)]
pub struct BbsKeyPair {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
    ciphersuite: BbsCiphersuite,
}

impl BbsKeyPair {
    /// Generate a new BBS+ key pair.
    pub fn generate(ciphersuite: BbsCiphersuite) -> CryptoResult<Self> {
        match ciphersuite {
            BbsCiphersuite::Bls12381Sha256 => {
                let kp = KeyPair::<BbsBls12381Sha256>::random()
                    .map_err(|e| CryptoError::internal(format!("BBS+ keygen failed: {:?}", e)))?;
                Ok(Self {
                    secret_key: kp.private_key().to_bytes().to_vec(),
                    public_key: kp.public_key().to_bytes().to_vec(),
                    ciphersuite,
                })
            }
            BbsCiphersuite::Bls12381Shake256 => {
                let kp = KeyPair::<BbsBls12381Shake256>::random()
                    .map_err(|e| CryptoError::internal(format!("BBS+ keygen failed: {:?}", e)))?;
                Ok(Self {
                    secret_key: kp.private_key().to_bytes().to_vec(),
                    public_key: kp.public_key().to_bytes().to_vec(),
                    ciphersuite,
                })
            }
        }
    }

    /// Reconstruct a key pair from raw bytes.
    pub fn from_bytes(
        secret_key: &[u8],
        public_key: &[u8],
        ciphersuite: BbsCiphersuite,
    ) -> CryptoResult<Self> {
        if public_key.len() != 96 {
            return Err(CryptoError::internal(
                "BBS+ public key must be 96 bytes (BLS12-381 G2)".to_string(),
            ));
        }
        Ok(Self {
            secret_key: secret_key.to_vec(),
            public_key: public_key.to_vec(),
            ciphersuite,
        })
    }

    /// Get the secret key bytes.
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    /// Get the public key bytes (96 bytes, BLS12-381 G2 compressed).
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the ciphersuite this key pair uses.
    pub fn ciphersuite(&self) -> BbsCiphersuite {
        self.ciphersuite
    }

    /// Sign a list of messages, producing a single BBS+ signature.
    ///
    /// Each message is an arbitrary byte vector. The signature covers all
    /// messages jointly — selective disclosure happens at proof generation time.
    pub fn sign(&self, messages: &[Vec<u8>], header: &[u8]) -> CryptoResult<Vec<u8>> {
        bbs_sign(
            &self.secret_key,
            &self.public_key,
            messages,
            header,
            self.ciphersuite,
        )
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> BbsVerifyingKey {
        BbsVerifyingKey {
            public_key: self.public_key.clone(),
            ciphersuite: self.ciphersuite,
        }
    }
}

/// BBS+ public key for verification only.
#[derive(Clone)]
pub struct BbsVerifyingKey {
    public_key: Vec<u8>,
    ciphersuite: BbsCiphersuite,
}

impl BbsVerifyingKey {
    /// Create from raw 96-byte public key.
    pub fn from_bytes(bytes: &[u8], ciphersuite: BbsCiphersuite) -> CryptoResult<Self> {
        if bytes.len() != 96 {
            return Err(CryptoError::internal(
                "BBS+ public key must be 96 bytes".to_string(),
            ));
        }
        Ok(Self {
            public_key: bytes.to_vec(),
            ciphersuite,
        })
    }

    /// Verify a BBS+ signature over multiple messages.
    pub fn verify(
        &self,
        messages: &[Vec<u8>],
        header: &[u8],
        signature: &[u8],
    ) -> CryptoResult<()> {
        bbs_verify(
            &self.public_key,
            messages,
            header,
            signature,
            self.ciphersuite,
        )
    }

    /// Verify a selective disclosure proof.
    pub fn verify_proof(
        &self,
        proof: &[u8],
        disclosed_messages: &[Vec<u8>],
        disclosed_indices: &[usize],
        header: &[u8],
        presentation_header: &[u8],
    ) -> CryptoResult<()> {
        bbs_verify_proof(
            &self.public_key,
            proof,
            disclosed_messages,
            disclosed_indices,
            header,
            presentation_header,
            self.ciphersuite,
        )
    }

    /// Get the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.public_key
    }
}

// ============================================================================
// Standalone Functions
// ============================================================================

fn parse_sk(bytes: &[u8]) -> CryptoResult<BBSplusSecretKey> {
    BBSplusSecretKey::from_bytes(bytes)
        .map_err(|e| CryptoError::internal(format!("Invalid BBS+ secret key: {:?}", e)))
}

fn parse_pk(bytes: &[u8]) -> CryptoResult<BBSplusPublicKey> {
    BBSplusPublicKey::from_bytes(bytes)
        .map_err(|e| CryptoError::internal(format!("Invalid BBS+ public key: {:?}", e)))
}

/// Sign multiple messages with BBS+.
pub fn bbs_sign(
    secret_key: &[u8],
    public_key: &[u8],
    messages: &[Vec<u8>],
    header: &[u8],
    ciphersuite: BbsCiphersuite,
) -> CryptoResult<Vec<u8>> {
    let sk = parse_sk(secret_key)?;
    let pk = parse_pk(public_key)?;

    match ciphersuite {
        BbsCiphersuite::Bls12381Sha256 => {
            let sig = Signature::<BbsBls12381Sha256>::sign(Some(messages), &sk, &pk, Some(header))
                .map_err(|e| CryptoError::internal(format!("BBS+ sign failed: {:?}", e)))?;
            Ok(sig.to_bytes().to_vec())
        }
        BbsCiphersuite::Bls12381Shake256 => {
            let sig =
                Signature::<BbsBls12381Shake256>::sign(Some(messages), &sk, &pk, Some(header))
                    .map_err(|e| CryptoError::internal(format!("BBS+ sign failed: {:?}", e)))?;
            Ok(sig.to_bytes().to_vec())
        }
    }
}

/// Verify a BBS+ signature over multiple messages.
pub fn bbs_verify(
    public_key: &[u8],
    messages: &[Vec<u8>],
    header: &[u8],
    signature: &[u8],
    ciphersuite: BbsCiphersuite,
) -> CryptoResult<()> {
    let pk = parse_pk(public_key)?;
    let sig_bytes: &[u8; 80] = signature
        .try_into()
        .map_err(|_| CryptoError::internal("BBS+ signature must be 80 bytes".to_string()))?;

    match ciphersuite {
        BbsCiphersuite::Bls12381Sha256 => {
            let sig = Signature::<BbsBls12381Sha256>::from_bytes(sig_bytes)
                .map_err(|e| CryptoError::internal(format!("Invalid BBS+ signature: {:?}", e)))?;
            sig.verify(&pk, Some(messages), Some(header))
                .map_err(|e| CryptoError::internal(format!("BBS+ verify failed: {:?}", e)))
        }
        BbsCiphersuite::Bls12381Shake256 => {
            let sig = Signature::<BbsBls12381Shake256>::from_bytes(sig_bytes)
                .map_err(|e| CryptoError::internal(format!("Invalid BBS+ signature: {:?}", e)))?;
            sig.verify(&pk, Some(messages), Some(header))
                .map_err(|e| CryptoError::internal(format!("BBS+ verify failed: {:?}", e)))
        }
    }
}

/// Generate a selective disclosure proof from a BBS+ signature.
///
/// # Arguments
/// - `public_key`: Issuer's BBS+ public key bytes.
/// - `signature`: The original BBS+ signature bytes (80 bytes).
/// - `messages`: All signed messages (in original order).
/// - `disclosed_indices`: Indices of messages to disclose (0-based).
/// - `header`: The header used during signing.
/// - `presentation_header`: Fresh context binding (e.g., nonce from verifier).
pub fn bbs_create_proof(
    public_key: &[u8],
    signature: &[u8],
    messages: &[Vec<u8>],
    disclosed_indices: &[usize],
    header: &[u8],
    presentation_header: &[u8],
    ciphersuite: BbsCiphersuite,
) -> CryptoResult<Vec<u8>> {
    let pk = parse_pk(public_key)?;
    let total = messages.len();
    for &idx in disclosed_indices {
        if idx >= total {
            return Err(CryptoError::internal(format!(
                "Disclosed index {} out of range (total messages: {})",
                idx, total
            )));
        }
    }

    match ciphersuite {
        BbsCiphersuite::Bls12381Sha256 => {
            let proof = PoKSignature::<BbsBls12381Sha256>::proof_gen(
                &pk,
                signature,
                Some(header),
                Some(presentation_header),
                Some(messages),
                Some(disclosed_indices),
            )
            .map_err(|e| CryptoError::internal(format!("BBS+ proof generation failed: {:?}", e)))?;
            Ok(proof.to_bytes())
        }
        BbsCiphersuite::Bls12381Shake256 => {
            let proof = PoKSignature::<BbsBls12381Shake256>::proof_gen(
                &pk,
                signature,
                Some(header),
                Some(presentation_header),
                Some(messages),
                Some(disclosed_indices),
            )
            .map_err(|e| CryptoError::internal(format!("BBS+ proof generation failed: {:?}", e)))?;
            Ok(proof.to_bytes())
        }
    }
}

/// Verify a BBS+ selective disclosure proof.
pub fn bbs_verify_proof(
    public_key: &[u8],
    proof: &[u8],
    disclosed_messages: &[Vec<u8>],
    disclosed_indices: &[usize],
    header: &[u8],
    presentation_header: &[u8],
    ciphersuite: BbsCiphersuite,
) -> CryptoResult<()> {
    let pk = parse_pk(public_key)?;

    match ciphersuite {
        BbsCiphersuite::Bls12381Sha256 => {
            let pok = PoKSignature::<BbsBls12381Sha256>::from_bytes(proof)
                .map_err(|e| CryptoError::internal(format!("Invalid BBS+ proof: {:?}", e)))?;
            pok.proof_verify(
                &pk,
                Some(disclosed_messages),
                Some(disclosed_indices),
                Some(header),
                Some(presentation_header),
            )
            .map_err(|e| CryptoError::internal(format!("BBS+ proof verification failed: {:?}", e)))
        }
        BbsCiphersuite::Bls12381Shake256 => {
            let pok = PoKSignature::<BbsBls12381Shake256>::from_bytes(proof)
                .map_err(|e| CryptoError::internal(format!("Invalid BBS+ proof: {:?}", e)))?;
            pok.proof_verify(
                &pk,
                Some(disclosed_messages),
                Some(disclosed_indices),
                Some(header),
                Some(presentation_header),
            )
            .map_err(|e| CryptoError::internal(format!("BBS+ proof verification failed: {:?}", e)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sha256() {
        let kp = BbsKeyPair::generate(BbsCiphersuite::Bls12381Sha256).unwrap();
        assert_eq!(kp.public_key().len(), 96);
        assert!(!kp.secret_key().is_empty());
    }

    #[test]
    fn test_keygen_shake256() {
        let kp = BbsKeyPair::generate(BbsCiphersuite::Bls12381Shake256).unwrap();
        assert_eq!(kp.public_key().len(), 96);
    }

    #[test]
    fn test_sign_verify_roundtrip_sha256() {
        let kp = BbsKeyPair::generate(BbsCiphersuite::Bls12381Sha256).unwrap();
        let messages: Vec<Vec<u8>> =
            vec![b"claim1".to_vec(), b"claim2".to_vec(), b"claim3".to_vec()];
        let header = b"test-header";

        let sig = kp.sign(&messages, header).unwrap();
        assert_eq!(sig.len(), 80);
        let vk = kp.verifying_key();
        vk.verify(&messages, header, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_roundtrip_shake256() {
        let kp = BbsKeyPair::generate(BbsCiphersuite::Bls12381Shake256).unwrap();
        let messages: Vec<Vec<u8>> = vec![
            b"name:Alice".to_vec(),
            b"age:30".to_vec(),
            b"country:US".to_vec(),
        ];
        let header = b"credential-header";

        let sig = kp.sign(&messages, header).unwrap();
        kp.verifying_key().verify(&messages, header, &sig).unwrap();
    }

    #[test]
    fn test_selective_disclosure_proof_sha256() {
        let kp = BbsKeyPair::generate(BbsCiphersuite::Bls12381Sha256).unwrap();
        let messages: Vec<Vec<u8>> = vec![
            b"name:Alice".to_vec(),
            b"age:30".to_vec(),
            b"country:US".to_vec(),
        ];
        let header = b"test-header";
        let presentation_header = b"verifier-nonce-12345";

        // Sign all messages
        let sig = kp.sign(&messages, header).unwrap();

        // Create proof disclosing only message at index 1 (age)
        let proof = bbs_create_proof(
            kp.public_key(),
            &sig,
            &messages,
            &[1],
            header,
            presentation_header,
            BbsCiphersuite::Bls12381Sha256,
        )
        .unwrap();

        // Verify the proof with only the disclosed message
        let disclosed_msgs = vec![b"age:30".to_vec()];
        kp.verifying_key()
            .verify_proof(&proof, &disclosed_msgs, &[1], header, presentation_header)
            .unwrap();
    }

    #[test]
    fn test_selective_disclosure_proof_shake256() {
        let kp = BbsKeyPair::generate(BbsCiphersuite::Bls12381Shake256).unwrap();
        let messages: Vec<Vec<u8>> = vec![
            b"given_name:Bob".to_vec(),
            b"family_name:Smith".to_vec(),
            b"dob:1990-01-15".to_vec(),
            b"country:DE".to_vec(),
        ];
        let header = b"eudi-pid-header";
        let presentation_header = b"siopv2-nonce-xyz";

        let sig = kp.sign(&messages, header).unwrap();

        // Disclose given_name (0) and country (3), hide family_name and dob
        let proof = bbs_create_proof(
            kp.public_key(),
            &sig,
            &messages,
            &[0, 3],
            header,
            presentation_header,
            BbsCiphersuite::Bls12381Shake256,
        )
        .unwrap();

        let disclosed_msgs = vec![b"given_name:Bob".to_vec(), b"country:DE".to_vec()];
        kp.verifying_key()
            .verify_proof(
                &proof,
                &disclosed_msgs,
                &[0, 3],
                header,
                presentation_header,
            )
            .unwrap();
    }

    #[test]
    fn test_tampered_message_fails() {
        let kp = BbsKeyPair::generate(BbsCiphersuite::Bls12381Sha256).unwrap();
        let messages: Vec<Vec<u8>> = vec![b"claim1".to_vec(), b"claim2".to_vec()];
        let header = b"h";

        let sig = kp.sign(&messages, header).unwrap();

        // Tamper with a message
        let tampered: Vec<Vec<u8>> = vec![b"claim1".to_vec(), b"TAMPERED".to_vec()];
        let result = kp.verifying_key().verify(&tampered, header, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_disclosed_message_fails_proof() {
        let kp = BbsKeyPair::generate(BbsCiphersuite::Bls12381Shake256).unwrap();
        let messages: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let header = b"h";
        let ph = b"nonce";

        let sig = kp.sign(&messages, header).unwrap();
        let proof = bbs_create_proof(
            kp.public_key(),
            &sig,
            &messages,
            &[0],
            header,
            ph,
            BbsCiphersuite::Bls12381Shake256,
        )
        .unwrap();

        // Try to verify with wrong disclosed message
        let wrong_disclosed = vec![b"WRONG".to_vec()];
        let result = kp
            .verifying_key()
            .verify_proof(&proof, &wrong_disclosed, &[0], header, ph);
        assert!(result.is_err());
    }
}
