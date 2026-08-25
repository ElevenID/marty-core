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

    fn decode_hex(value: &str) -> Vec<u8> {
        hex::decode(value).expect("test vector must contain valid hex")
    }

    fn assert_known_signature_vector(
        ciphersuite: BbsCiphersuite,
        public_key: &str,
        signature: &str,
    ) {
        // These are the valid single-message vectors shipped by zkryptium in
        // both 0.4.1 and 0.6.2. Keeping them here prevents a dependency-only
        // update from silently breaking verification of existing signatures.
        let key = BbsVerifyingKey::from_bytes(&decode_hex(public_key), ciphersuite).unwrap();
        let messages = vec![decode_hex(
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
        )];
        let header = decode_hex("11223344556677889900aabbccddeeff");

        key.verify(&messages, &header, &decode_hex(signature))
            .unwrap();
    }

    #[test]
    fn test_known_signature_vector_sha256() {
        assert_known_signature_vector(
            BbsCiphersuite::Bls12381Sha256,
            "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
            "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0",
        );
    }

    #[test]
    fn test_known_signature_vector_shake256() {
        assert_known_signature_vector(
            BbsCiphersuite::Bls12381Shake256,
            "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
            "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb71c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0b97a12025a283d78b7136bb9825d04ef",
        );
    }

    fn assert_known_proof_vector(ciphersuite: BbsCiphersuite, public_key: &str, proof: &str) {
        let key = BbsVerifyingKey::from_bytes(&decode_hex(public_key), ciphersuite).unwrap();
        let disclosed_messages = vec![decode_hex(
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
        )];
        let header = decode_hex("11223344556677889900aabbccddeeff");
        let presentation_header =
            decode_hex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

        key.verify_proof(
            &decode_hex(proof),
            &disclosed_messages,
            &[0],
            &header,
            &presentation_header,
        )
        .unwrap();
    }

    #[test]
    fn test_known_proof_vector_sha256() {
        assert_known_proof_vector(
            BbsCiphersuite::Bls12381Sha256,
            "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
            "94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418",
        );
    }

    #[test]
    fn test_known_proof_vector_shake256() {
        assert_known_proof_vector(
            BbsCiphersuite::Bls12381Shake256,
            "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
            "89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c737fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceedb023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775ab32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d6791940ccbd75e719537f7ace6ee817298d",
        );
    }

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
