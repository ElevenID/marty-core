//! Local private-key fixtures for Marty tests.
//!
//! This crate is deliberately `publish = false` and must only appear in
//! `dev-dependencies`. Shipping crates expose remote-signing inputs instead.

pub mod ecdsa {
    use marty_crypto::{CryptoError, CryptoResult};
    use p256::ecdsa::signature::Signer;
    use rand::rngs::OsRng;

    pub fn generate_p256_keypair() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        Ok((
            key.to_bytes().to_vec(),
            key.verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        ))
    }

    pub fn sign_p256_sha256(private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        let key = p256::ecdsa::SigningKey::from_slice(private_key)
            .map_err(|error| CryptoError::internal(format!("Invalid P-256 key: {error}")))?;
        let signature: p256::ecdsa::Signature = key.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    pub fn sign_p384_sha384(private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        let key = p384::ecdsa::SigningKey::from_slice(private_key)
            .map_err(|error| CryptoError::internal(format!("Invalid P-384 key: {error}")))?;
        let signature: p384::ecdsa::Signature = key.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

pub mod ed25519 {
    use ed25519_dalek::{Signer, SigningKey};
    use marty_crypto::{CryptoError, CryptoResult};

    pub fn sign(secret_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        let bytes: [u8; 32] = secret_key.try_into().map_err(|_| {
            CryptoError::internal("Ed25519 private key must be 32 bytes".to_string())
        })?;
        Ok(SigningKey::from_bytes(&bytes)
            .sign(message)
            .to_bytes()
            .to_vec())
    }
}

pub mod rsa {
    use marty_crypto::{CryptoError, CryptoResult};
    use rand::rngs::OsRng;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::{RsaPrivateKey, RsaPublicKey};

    pub fn generate_rsa_keypair(bits: usize) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        if bits < 2048 {
            return Err(CryptoError::internal(
                "RSA key size must be at least 2048 bits".to_string(),
            ));
        }
        let private = RsaPrivateKey::new(&mut OsRng, bits).map_err(|error| {
            CryptoError::internal(format!("RSA key generation failed: {error}"))
        })?;
        let public = RsaPublicKey::from(&private);
        Ok((
            private
                .to_pkcs8_der()
                .map_err(|error| CryptoError::internal(error.to_string()))?
                .as_bytes()
                .to_vec(),
            public
                .to_public_key_der()
                .map_err(|error| CryptoError::internal(error.to_string()))?
                .as_bytes()
                .to_vec(),
        ))
    }

    macro_rules! pss_signer {
        ($name:ident, $digest:ty) => {
            pub fn $name(private_key_der: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
                use rsa::pkcs8::DecodePrivateKey;
                let key = RsaPrivateKey::from_pkcs8_der(private_key_der)
                    .map_err(|error| CryptoError::internal(format!("Invalid RSA key: {error}")))?;
                let signature = rsa::pss::BlindedSigningKey::<$digest>::new(key)
                    .sign_with_rng(&mut OsRng, message);
                Ok(signature.to_vec())
            }
        };
    }

    pss_signer!(sign_pss_sha256, sha2::Sha256);
    pss_signer!(sign_pss_sha384, sha2::Sha384);
    pss_signer!(sign_pss_sha512, sha2::Sha512);

    pub fn sign_iso9796_scheme1(private_key_der: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        use rsa::{BigUint, RsaPrivateKey};

        let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
            .map_err(|error| CryptoError::crypto_error(format!("Invalid RSA key: {error}")))?;
        let key_size = private_key.n().bits().div_ceil(8);
        if message.len() + 3 > key_size {
            return Err(CryptoError::crypto_error(
                "Message too large for ISO 9796 Scheme 1 key",
            ));
        }
        let mut encoded = Vec::with_capacity(key_size);
        encoded.push(0x6A);
        encoded.extend(std::iter::repeat_n(0xBB, key_size - message.len() - 3));
        encoded.push(0x00);
        encoded.extend_from_slice(message);
        encoded.push(0xBC);
        let signature = BigUint::from_bytes_be(&encoded).modpow(private_key.d(), private_key.n());
        let bytes = signature.to_bytes_be();
        let mut result = vec![0u8; key_size - bytes.len()];
        result.extend_from_slice(&bytes);
        Ok(result)
    }
}

pub mod serialization {
    use der::Decode;
    use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
    use marty_crypto::{CryptoError, CryptoResult};

    pub fn load_private_key_pem(pem: &str) -> CryptoResult<Vec<u8>> {
        let (label, bytes) = pem_rfc7468::decode_vec(pem.as_bytes())
            .map_err(|error| CryptoError::internal(format!("Invalid private-key PEM: {error}")))?;
        if label != "PRIVATE KEY" {
            return Err(CryptoError::internal(format!(
                "Expected PRIVATE KEY PEM, found {label}"
            )));
        }
        Ok(bytes)
    }

    pub fn save_private_key_pem(der: &[u8]) -> CryptoResult<String> {
        pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, der)
            .map_err(|error| CryptoError::internal(error.to_string()))
    }

    pub fn detect_private_key_type(der: &[u8]) -> CryptoResult<String> {
        let info = pkcs8::PrivateKeyInfo::from_der(der)
            .map_err(|error| CryptoError::internal(format!("Invalid PKCS#8 key: {error}")))?;
        match info.algorithm.oid.to_string().as_str() {
            "1.2.840.10045.2.1" => {
                if p256::SecretKey::from_pkcs8_der(der).is_ok() {
                    Ok("EC_P256".to_string())
                } else if p384::SecretKey::from_pkcs8_der(der).is_ok() {
                    Ok("EC_P384".to_string())
                } else {
                    Err(CryptoError::internal(
                        "Unsupported EC private key".to_string(),
                    ))
                }
            }
            "1.3.101.112" => Ok("Ed25519".to_string()),
            "1.2.840.113549.1.1.1" => Ok("RSA".to_string()),
            oid => Err(CryptoError::internal(format!(
                "Unsupported private-key algorithm {oid}"
            ))),
        }
    }

    pub fn pkcs8_to_raw_private_key(der: &[u8]) -> CryptoResult<(Vec<u8>, String)> {
        match detect_private_key_type(der)?.as_str() {
            "EC_P256" => Ok((
                p256::SecretKey::from_pkcs8_der(der)
                    .map_err(|error| CryptoError::internal(error.to_string()))?
                    .to_bytes()
                    .to_vec(),
                "EC_P256".to_string(),
            )),
            "EC_P384" => Ok((
                p384::SecretKey::from_pkcs8_der(der)
                    .map_err(|error| CryptoError::internal(error.to_string()))?
                    .to_bytes()
                    .to_vec(),
                "EC_P384".to_string(),
            )),
            "Ed25519" => Ok((
                ed25519_dalek::SigningKey::from_pkcs8_der(der)
                    .map_err(|error| CryptoError::internal(error.to_string()))?
                    .to_bytes()
                    .to_vec(),
                "Ed25519".to_string(),
            )),
            kind => Err(CryptoError::internal(format!(
                "Raw conversion is unsupported for {kind}"
            ))),
        }
    }

    pub fn raw_private_key_to_pkcs8(raw: &[u8], key_type: &str) -> CryptoResult<Vec<u8>> {
        match key_type {
            "EC_P256" => p256::SecretKey::from_slice(raw)
                .map_err(|error| CryptoError::internal(error.to_string()))?
                .to_pkcs8_der()
                .map(|document| document.as_bytes().to_vec())
                .map_err(|error| CryptoError::internal(error.to_string())),
            "EC_P384" => p384::SecretKey::from_slice(raw)
                .map_err(|error| CryptoError::internal(error.to_string()))?
                .to_pkcs8_der()
                .map(|document| document.as_bytes().to_vec())
                .map_err(|error| CryptoError::internal(error.to_string())),
            "Ed25519" => {
                let bytes: [u8; 32] = raw.try_into().map_err(|_| {
                    CryptoError::internal("Ed25519 private key must be 32 bytes".to_string())
                })?;
                ed25519_dalek::SigningKey::from_bytes(&bytes)
                    .to_pkcs8_der()
                    .map(|document| document.as_bytes().to_vec())
                    .map_err(|error| CryptoError::internal(error.to_string()))
            }
            kind => Err(CryptoError::internal(format!(
                "Unsupported raw private-key type {kind}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn p256_fixture_round_trips_through_pkcs8() {
        let (private, _) = crate::ecdsa::generate_p256_keypair().unwrap();
        let signature = crate::ecdsa::sign_p256_sha256(&private, b"fixture").unwrap();
        assert!(!signature.is_empty());

        let der = crate::serialization::raw_private_key_to_pkcs8(&private, "EC_P256").unwrap();
        assert_eq!(
            crate::serialization::detect_private_key_type(&der).unwrap(),
            "EC_P256"
        );
        let pem = crate::serialization::save_private_key_pem(&der).unwrap();
        assert_eq!(
            crate::serialization::load_private_key_pem(&pem).unwrap(),
            der
        );
    }

    #[test]
    fn rsa_fixture_enforces_minimum_and_signs() {
        assert!(crate::rsa::generate_rsa_keypair(1024).is_err());
        let (private, _) = crate::rsa::generate_rsa_keypair(2048).unwrap();
        assert!(!crate::rsa::sign_pss_sha256(&private, b"fixture")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn ed25519_fixture_signing_is_deterministic() {
        let key = [7u8; 32];
        assert_eq!(
            crate::ed25519::sign(&key, b"fixture").unwrap(),
            crate::ed25519::sign(&key, b"fixture").unwrap()
        );
    }
}
