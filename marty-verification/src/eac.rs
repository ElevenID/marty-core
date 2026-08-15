//! Native kernels used by the eMRTD Extended Access Control adapter.
//!
//! Transport and certificate acquisition remain application concerns. Key
//! generation, terminal signatures, certificate-signature checks, chip key
//! agreement, session-key derivation, and protected-message processing live
//! here so callers cannot substitute placeholder cryptography.

use serde::{Deserialize, Serialize};

use crate::error::{VerificationError, VerificationResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EacAlgorithm {
    EcdhP256Sha256,
    EcdhP384Sha384,
    EcdhBrainpoolP256r1Sha256,
    Rsa2048Sha256,
    Rsa3072Sha256,
}

impl EacAlgorithm {
    pub fn parse(value: &str) -> VerificationResult<Self> {
        match value {
            "ecdh_p256_sha256" => Ok(Self::EcdhP256Sha256),
            "ecdh_p384_sha384" => Ok(Self::EcdhP384Sha384),
            "ecdh_brainpool_p256r1_sha256" => Ok(Self::EcdhBrainpoolP256r1Sha256),
            "rsa_2048_sha256" => Ok(Self::Rsa2048Sha256),
            "rsa_3072_sha256" => Ok(Self::Rsa3072Sha256),
            _ => Err(VerificationError::internal(format!(
                "Unsupported EAC algorithm: {value}"
            ))),
        }
    }

    fn uses_sha384(self) -> bool {
        self == Self::EcdhP384Sha384
    }
}

/// Generate an ephemeral key pair as `(private scalar, SEC1 public point)`.
pub fn generate_ephemeral_keypair(
    algorithm: EacAlgorithm,
) -> VerificationResult<(Vec<u8>, Vec<u8>)> {
    match algorithm {
        EacAlgorithm::EcdhP256Sha256 => Ok(marty_crypto::ecdh::p256_generate_keypair()),
        EacAlgorithm::EcdhP384Sha384 => Ok(marty_crypto::ecdh::p384_generate_keypair()),
        EacAlgorithm::EcdhBrainpoolP256r1Sha256 => Err(VerificationError::internal(
            "Brainpool P-256 EAC is unavailable in the native backend",
        )),
        EacAlgorithm::Rsa2048Sha256 | EacAlgorithm::Rsa3072Sha256 => {
            Err(VerificationError::internal(
                "RSA key agreement is not defined for EAC Chip Authentication",
            ))
        }
    }
}

/// Perform actual ECDH with a generated private scalar and chip public point.
pub fn agree(
    algorithm: EacAlgorithm,
    private_key: &[u8],
    peer_public_key: &[u8],
) -> VerificationResult<Vec<u8>> {
    let peer = normalize_ec_point(peer_public_key)?;
    match algorithm {
        EacAlgorithm::EcdhP256Sha256 => {
            marty_crypto::ecdh::p256_agree(private_key, &peer).map_err(Into::into)
        }
        EacAlgorithm::EcdhP384Sha384 => {
            marty_crypto::ecdh::p384_agree(private_key, &peer).map_err(Into::into)
        }
        EacAlgorithm::EcdhBrainpoolP256r1Sha256 => Err(VerificationError::internal(
            "Brainpool P-256 EAC is unavailable in the native backend",
        )),
        EacAlgorithm::Rsa2048Sha256 | EacAlgorithm::Rsa3072Sha256 => {
            Err(VerificationError::internal(
                "RSA key agreement is not defined for EAC Chip Authentication",
            ))
        }
    }
}

fn normalize_ec_point(point: &[u8]) -> VerificationResult<Vec<u8>> {
    match point.len() {
        64 | 96 => {
            let mut encoded = Vec::with_capacity(point.len() + 1);
            encoded.push(0x04);
            encoded.extend_from_slice(point);
            Ok(encoded)
        }
        33 | 49 | 65 | 97 if matches!(point[0], 0x02..=0x04) => Ok(point.to_vec()),
        _ => Err(VerificationError::internal(
            "Invalid EAC elliptic-curve public point",
        )),
    }
}

/// Serialize the generated EC private scalar as PKCS#8 for compatibility APIs.
pub fn encode_private_key(
    algorithm: EacAlgorithm,
    private_key: &[u8],
) -> VerificationResult<Vec<u8>> {
    use elliptic_curve::pkcs8::EncodePrivateKey;
    match algorithm {
        EacAlgorithm::EcdhP256Sha256 => p256::SecretKey::from_slice(private_key)
            .map_err(|error| VerificationError::internal(format!("Invalid P-256 key: {error}")))?
            .to_pkcs8_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|error| {
                VerificationError::internal(format!("P-256 key encoding failed: {error}"))
            }),
        EacAlgorithm::EcdhP384Sha384 => p384::SecretKey::from_slice(private_key)
            .map_err(|error| VerificationError::internal(format!("Invalid P-384 key: {error}")))?
            .to_pkcs8_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|error| {
                VerificationError::internal(format!("P-384 key encoding failed: {error}"))
            }),
        _ => Err(VerificationError::internal(
            "No EAC private-key encoding is available for this algorithm",
        )),
    }
}

/// Sign the chip challenge with a PKCS#8 terminal private key.
pub fn sign_terminal_challenge(
    algorithm: EacAlgorithm,
    private_key_der: &[u8],
    challenge: &[u8],
) -> VerificationResult<Vec<u8>> {
    use elliptic_curve::pkcs8::DecodePrivateKey;
    if challenge.is_empty() {
        return Err(VerificationError::internal(
            "EAC terminal challenge must not be empty",
        ));
    }
    match algorithm {
        EacAlgorithm::EcdhP256Sha256 => {
            let key = p256::SecretKey::from_pkcs8_der(private_key_der).map_err(|error| {
                VerificationError::internal(format!("Invalid P-256 terminal key: {error}"))
            })?;
            marty_crypto::ecdsa::sign_p256_sha256(key.to_bytes().as_slice(), challenge)
                .map_err(Into::into)
        }
        EacAlgorithm::EcdhP384Sha384 => {
            let key = p384::SecretKey::from_pkcs8_der(private_key_der).map_err(|error| {
                VerificationError::internal(format!("Invalid P-384 terminal key: {error}"))
            })?;
            marty_crypto::ecdsa::sign_p384_sha384(key.to_bytes().as_slice(), challenge)
                .map_err(Into::into)
        }
        EacAlgorithm::Rsa2048Sha256 | EacAlgorithm::Rsa3072Sha256 => {
            marty_crypto::rsa::sign_pss_sha256(private_key_der, challenge).map_err(Into::into)
        }
        EacAlgorithm::EcdhBrainpoolP256r1Sha256 => Err(VerificationError::internal(
            "Brainpool P-256 EAC is unavailable in the native backend",
        )),
    }
}

/// Verify a subject certificate body with its signer's public key.
pub fn verify_certificate_signature(
    algorithm: EacAlgorithm,
    signer_public_key_der: &[u8],
    certificate_body: &[u8],
    signature: &[u8],
) -> VerificationResult<bool> {
    if certificate_body.is_empty() || signature.is_empty() {
        return Ok(false);
    }
    match algorithm {
        EacAlgorithm::EcdhP256Sha256 => marty_crypto::ecdsa::verify_p256_sha256(
            signer_public_key_der,
            certificate_body,
            signature,
        )
        .map_err(Into::into),
        EacAlgorithm::EcdhP384Sha384 => marty_crypto::ecdsa::verify_p384_sha384(
            signer_public_key_der,
            certificate_body,
            signature,
        )
        .map_err(Into::into),
        EacAlgorithm::Rsa2048Sha256 | EacAlgorithm::Rsa3072Sha256 => {
            marty_crypto::rsa::verify_pss_sha256(signer_public_key_der, certificate_body, signature)
                .map_err(Into::into)
        }
        EacAlgorithm::EcdhBrainpoolP256r1Sha256 => Err(VerificationError::internal(
            "Brainpool P-256 EAC is unavailable in the native backend",
        )),
    }
}

pub fn certificate_fingerprint(data: &[u8]) -> String {
    let digest = marty_crypto::hashing::hash_sha256(data);
    format!("{}...", hex::encode(&digest[..8]))
}

/// Deterministically serialize the compatibility certificate metadata.
///
/// This does not claim to construct a CVC. Callers transmitting a real CVC
/// must provide its original raw bytes.
pub fn serialize_certificate_metadata(
    holder: &str,
    authority: &str,
    authorization: u32,
    effective: &str,
    expiration: &str,
) -> VerificationResult<Vec<u8>> {
    #[derive(Serialize)]
    struct Metadata<'a> {
        holder: &'a str,
        authority: &'a str,
        authorization: u32,
        effective: &'a str,
        expiration: &'a str,
    }
    serde_json::to_vec(&Metadata {
        holder,
        authority,
        authorization,
        effective,
        expiration,
    })
    .map_err(|error| VerificationError::internal(format!("EAC metadata encoding failed: {error}")))
}

pub fn calculate_mac(key: &[u8], data: &[u8]) -> VerificationResult<Vec<u8>> {
    marty_crypto::symmetric::hmac_sha256(key, data).map_err(Into::into)
}

/// Stateful encrypted-message compatibility channel used by EAC callers.
pub struct EacSecureMessaging {
    mac_key: [u8; 32],
    encryption_key: [u8; 32],
    send_sequence_counter: u32,
    receive_sequence_counter: u32,
}

impl EacSecureMessaging {
    pub fn new(shared_secret: &[u8], algorithm: EacAlgorithm) -> VerificationResult<Self> {
        if shared_secret.is_empty() {
            return Err(VerificationError::internal(
                "EAC shared secret must not be empty",
            ));
        }
        // These labels are public HKDF domain separators, not secret or
        // randomized salts. Keeping them distinct prevents key reuse between
        // authentication and encryption.
        let derive = |domain_separator: &[u8], info: &[u8]| {
            if algorithm.uses_sha384() {
                marty_crypto::kdf::hkdf_sha384(shared_secret, domain_separator, info, 32)
            } else {
                marty_crypto::kdf::hkdf_sha256(shared_secret, domain_separator, info, 32)
            }
        };
        let mac_key: [u8; 32] = derive(b"EAC_MAC_KEY", b"MAC_DERIVATION")?
            .try_into()
            .expect("HKDF requested 32 bytes");
        let encryption_key: [u8; 32] = derive(b"EAC_ENC_KEY", b"ENC_DERIVATION")?
            .try_into()
            .expect("HKDF requested 32 bytes");
        Ok(Self {
            mac_key,
            encryption_key,
            send_sequence_counter: 0,
            receive_sequence_counter: 0,
        })
    }

    pub fn keys(&self) -> (&[u8; 32], &[u8; 32]) {
        (&self.mac_key, &self.encryption_key)
    }

    pub fn counters(&self) -> (u32, u32) {
        (self.send_sequence_counter, self.receive_sequence_counter)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> VerificationResult<Vec<u8>> {
        let iv: [u8; 16] = rand::random();
        self.encrypt_with_iv(plaintext, &iv)
    }

    pub fn encrypt_with_iv(&mut self, plaintext: &[u8], iv: &[u8]) -> VerificationResult<Vec<u8>> {
        let iv: [u8; 16] = iv
            .try_into()
            .map_err(|_| VerificationError::internal("EAC secure-messaging IV must be 16 bytes"))?;
        self.send_sequence_counter = self
            .send_sequence_counter
            .checked_add(1)
            .ok_or_else(|| VerificationError::internal("EAC send sequence counter exhausted"))?;
        let ciphertext =
            marty_crypto::symmetric::aes_256_cbc_encrypt(&self.encryption_key, &iv, plaintext)?;
        let mac_input = mac_input(self.send_sequence_counter, &iv, &ciphertext);
        let mac = marty_crypto::symmetric::hmac_sha256(&self.mac_key, &mac_input)?;
        let mut output = Vec::with_capacity(16 + ciphertext.len() + mac.len());
        output.extend_from_slice(&iv);
        output.extend_from_slice(&ciphertext);
        output.extend_from_slice(&mac);
        Ok(output)
    }

    pub fn decrypt(&mut self, protected: &[u8]) -> VerificationResult<Vec<u8>> {
        if protected.len() < 64 || !(protected.len() - 48).is_multiple_of(16) {
            return Err(VerificationError::internal(
                "Invalid EAC protected-message length",
            ));
        }
        let (iv, remainder) = protected.split_at(16);
        let (ciphertext, received_mac) = remainder.split_at(remainder.len() - 32);
        let next_counter = self
            .receive_sequence_counter
            .checked_add(1)
            .ok_or_else(|| VerificationError::internal("EAC receive sequence counter exhausted"))?;
        let mac_input = mac_input(next_counter, iv, ciphertext);
        let expected = marty_crypto::symmetric::hmac_sha256(&self.mac_key, &mac_input)?;
        if !constant_time_eq(&expected, received_mac) {
            return Err(VerificationError::internal(
                "EAC protected-message MAC verification failed",
            ));
        }
        let plaintext =
            marty_crypto::symmetric::aes_256_cbc_decrypt(&self.encryption_key, iv, ciphertext)?;
        self.receive_sequence_counter = next_counter;
        Ok(plaintext)
    }
}

fn mac_input(counter: u32, iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(4 + iv.len() + ciphertext.len());
    input.extend_from_slice(&counter.to_be_bytes());
    input.extend_from_slice(iv);
    input.extend_from_slice(ciphertext);
    input
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_crypto::ecdsa::verify_p256_sha256;

    #[test]
    fn p256_key_agreement_is_symmetric_and_rejects_bad_points() {
        let (left_private, left_public) =
            generate_ephemeral_keypair(EacAlgorithm::EcdhP256Sha256).unwrap();
        let (right_private, right_public) =
            generate_ephemeral_keypair(EacAlgorithm::EcdhP256Sha256).unwrap();
        assert_eq!(
            agree(EacAlgorithm::EcdhP256Sha256, &left_private, &right_public).unwrap(),
            agree(EacAlgorithm::EcdhP256Sha256, &right_private, &left_public).unwrap()
        );
        assert!(agree(EacAlgorithm::EcdhP256Sha256, &left_private, b"fake").is_err());
    }

    #[test]
    fn secure_messaging_round_trip_authenticates_iv_and_ciphertext() {
        let mut channel =
            EacSecureMessaging::new(b"shared secret", EacAlgorithm::EcdhP256Sha256).unwrap();
        let protected = channel
            .encrypt_with_iv(b"passport biometric APDU", &[0x11; 16])
            .unwrap();
        assert_eq!(
            channel.decrypt(&protected).unwrap(),
            b"passport biometric APDU"
        );

        let mut tampered_iv = protected.clone();
        tampered_iv[0] ^= 1;
        assert!(channel.decrypt(&tampered_iv).is_err());
        let mut tampered_ciphertext = protected;
        tampered_ciphertext[20] ^= 1;
        assert!(channel.decrypt(&tampered_ciphertext).is_err());
    }

    #[test]
    fn terminal_challenge_signing_uses_the_native_key() {
        let (private_key, public_key) = marty_crypto::ecdsa::generate_p256_keypair().unwrap();
        let private_der = encode_private_key(EacAlgorithm::EcdhP256Sha256, &private_key).unwrap();
        let challenge = b"chip-issued-terminal-authentication-challenge";
        let signature =
            sign_terminal_challenge(EacAlgorithm::EcdhP256Sha256, &private_der, challenge).unwrap();
        assert!(verify_p256_sha256(&public_key, challenge, &signature).unwrap());
        assert!(!verify_p256_sha256(&public_key, b"wrong", &signature).unwrap());
    }
}
