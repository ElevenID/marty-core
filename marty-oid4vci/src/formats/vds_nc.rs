//! VDS-NC credential format (`vds_nc`).
//!
//! This module provides a signer-agnostic VDS-NC construction path. Production
//! callers delegate through the `CredentialSigner` trait to an external KMS/HSM;
//! local JWK signing is fixture-only under `cfg(test)`.

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::signer::{
    validate_remote_signature, validate_rsa_signature_encoding,
    validate_signer_public_jwk_for_algorithm, CredentialSigner,
};
#[cfg(test)]
use crate::types::IssuerKey;
use crate::types::{CredentialClaims, SignedCredential};

use base64::Engine;

/// Intermediate state between VDS-NC preparation and signature assembly.
pub struct PreparedVdsNc {
    /// The exact bytes (as UTF-8 text) that must be signed.
    signing_input: String,
    /// Stable issuance-side credential identifier.
    credential_id: String,
    /// Protected profile algorithm that the remote signer must use.
    algorithm: String,
    /// Public-only key that must verify the remote output.
    issuer_public_jwk: String,
}

impl std::fmt::Debug for PreparedVdsNc {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedVdsNc([redacted])")
    }
}

impl PreparedVdsNc {
    /// Reconstruct a prepared envelope from a `header~payload_json` signing input.
    #[cfg(test)]
    pub fn from_signing_input(
        signing_input: String,
        credential_id: String,
        issuer_public_jwk: String,
    ) -> Oid4vciResult<Self> {
        let (_header, payload_json) =
            super::vds_nc_profile::validate_signing_input(&signing_input)?;
        let payload: serde_json::Value = serde_json::from_str(&payload_json)?;
        let algorithm = payload
            .get("_vds")
            .and_then(|metadata| metadata.get("algorithm"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Oid4vciError::SigningError(
                    "VDS-NC signing input is missing its protected algorithm".into(),
                )
            })?
            .to_owned();

        Ok(Self {
            signing_input,
            credential_id,
            algorithm,
            issuer_public_jwk,
        })
    }

    /// Protected profile algorithm that the remote signer must use.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn signing_payload(&self) -> &[u8] {
        self.signing_input.as_bytes()
    }

    pub fn signing_input(&self) -> &str {
        &self.signing_input
    }

    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    /// Validate and normalize remote output without consuming prepared state.
    pub fn validate_signature(&self, signature: &[u8]) -> Oid4vciResult<Vec<u8>> {
        let normalized = normalize_signature_bytes(&self.algorithm, signature)?;
        let verified = crate::jose::verify_detached_signature_with_public_jwk(
            self.signing_payload(),
            &normalized,
            &self.issuer_public_jwk,
            &self.algorithm,
        )?;
        if !verified {
            return Err(Oid4vciError::SigningError(
                "remote VDS-NC signature does not verify with the configured issuer public key"
                    .into(),
            ));
        }
        Ok(normalized)
    }
}

#[cfg(feature = "issuer")]
/// Marker documenting that KMS issuer builds cannot reconstruct prepared VDS state.
///
/// ```compile_fail
/// let _ = marty_oid4vci::formats::vds_nc::PreparedVdsNc::from_signing_input;
/// ```
pub struct NoPreparedVdsNcReconstruction;

/// Sign a VDS-NC credential using a local issuer key.
#[cfg(test)]
pub fn sign_vds_nc(
    issuer_key: &IssuerKey,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    sign_vds_nc_with_signer(issuer_key, claims)
}

/// Sign a VDS-NC credential using any [`CredentialSigner`].
///
/// The output is a compact tilde-separated envelope:
/// `header~payload_json~signature_b64`.
pub fn sign_vds_nc_with_signer(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    let prepared = prepare_vds_nc(signer, claims)?;
    let signature = signer.sign(prepared.signing_payload())?;
    assemble_vds_nc(prepared, &signature)
}

/// Prepare a VDS-NC credential for external signing.
pub fn prepare_vds_nc(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<PreparedVdsNc> {
    let algorithm = signer.algorithm();
    let mut prepared = prepare_vds_nc_profile_envelope(
        signer.issuer_id(),
        &signer.kid_url(),
        algorithm.as_str(),
        claims,
    )?;
    prepared.issuer_public_jwk = validate_signer_public_jwk_for_algorithm(signer, algorithm)?;
    Ok(prepared)
}

/// Prepare a canonical VDS-NC profile using explicit signed metadata.
///
/// This path allows bindings with profile-specific algorithms to share the
/// same envelope construction without expanding the general credential signer
/// algorithm surface.
pub fn prepare_vds_nc_profile(
    issuer_id: &str,
    key_id: &str,
    algorithm: &str,
    issuer_public_jwk: &str,
    claims: &CredentialClaims,
) -> Oid4vciResult<PreparedVdsNc> {
    let mut prepared = prepare_vds_nc_profile_envelope(issuer_id, key_id, algorithm, claims)?;
    if issuer_public_jwk.len() > crate::jose::MAX_PUBLIC_JWK_BYTES {
        return Err(Oid4vciError::KeyError(
            "Issuer public JWK exceeds its size limit".into(),
        ));
    }
    let public_jwk =
        crate::jose::parse_unique_object(issuer_public_jwk.as_bytes(), "issuer public JWK")?;
    crate::jose::validate_public_jwk(&public_jwk, algorithm)?;
    prepared.issuer_public_jwk = issuer_public_jwk.to_owned();
    Ok(prepared)
}

fn prepare_vds_nc_profile_envelope(
    issuer_id: &str,
    key_id: &str,
    algorithm: &str,
    claims: &CredentialClaims,
) -> Oid4vciResult<PreparedVdsNc> {
    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let (payload_json, _document_type, issuing_country) =
        super::vds_nc_profile::build_profile_payload(
            &claims.claims,
            &claims.credential_type,
            issuer_id,
            key_id,
            algorithm,
        )?;
    let header = format!("DC03{issuing_country}");
    let signing_input = format!("{}~{}", header, payload_json);

    Ok(PreparedVdsNc {
        signing_input,
        credential_id,
        algorithm: algorithm.to_owned(),
        issuer_public_jwk: String::new(),
    })
}

/// Assemble a VDS-NC credential from a signature already encoded in the
/// profile algorithm's canonical raw form.
pub fn assemble_vds_nc_raw(
    prepared: PreparedVdsNc,
    signature: &[u8],
) -> Oid4vciResult<SignedCredential> {
    let normalized = prepared.validate_signature(signature)?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(normalized);
    let barcode_data = format!("{}~{}", prepared.signing_input, signature_b64);
    Ok(SignedCredential::VdsNc {
        barcode_data,
        credential_id: prepared.credential_id,
    })
}

/// Assemble a VDS-NC credential from prepared data and signature bytes.
///
/// `signature` may be either a raw fixed-length ECDSA signature (r || s,
/// 64 bytes for P-256 / 96 bytes for P-384) **or** a DER-encoded ECDSA
/// signature as returned by external KMS providers (OpenBao, AWS, Azure,
/// GCP).  This function normalises DER → raw before base64-encoding the
/// barcode segment so that verifiers receive a consistent format.
///
/// Ed25519 signatures are 64 bytes and are never DER-encoded; they are
/// passed through unchanged.
pub fn assemble_vds_nc(
    prepared: PreparedVdsNc,
    signature: &[u8],
) -> Oid4vciResult<SignedCredential> {
    let normalized = prepared.validate_signature(signature)?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&normalized);
    let barcode_data = format!("{}~{}", prepared.signing_input, signature_b64);

    Ok(SignedCredential::VdsNc {
        barcode_data,
        credential_id: prepared.credential_id,
    })
}

/// Reject malformed remote output and normalize ECDSA DER to raw `r || s`.
fn normalize_signature_bytes(algorithm: &str, signature: &[u8]) -> Oid4vciResult<Vec<u8>> {
    let invalid = || {
        Oid4vciError::SigningError(format!(
            "invalid {algorithm} remote signature encoding: got {} bytes",
            signature.len()
        ))
    };

    match algorithm {
        "ES256" => p256::ecdsa::Signature::from_slice(signature)
            .or_else(|_| p256::ecdsa::Signature::from_der(signature))
            .map(|value| value.to_bytes().to_vec())
            .map_err(|_| invalid()),
        "ES384" => p384::ecdsa::Signature::from_slice(signature)
            .or_else(|_| p384::ecdsa::Signature::from_der(signature))
            .map(|value| value.to_bytes().to_vec())
            .map_err(|_| invalid()),
        "EdDSA" => {
            validate_remote_signature(crate::types::SigningAlgorithm::EdDSA, signature)?;
            Ok(signature.to_vec())
        }
        "PS256" | "PS384" | "PS512" if validate_rsa_signature_encoding(signature) => {
            Ok(signature.to_vec())
        }
        "PS256" | "PS384" | "PS512" => Err(invalid()),
        _ => Err(Oid4vciError::SigningError(format!(
            "unsupported VDS-NC signature algorithm '{algorithm}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::CredentialSigner;
    use crate::types::SigningAlgorithm;

    struct TestSigner {
        signing_key: p256::ecdsa::SigningKey,
    }

    impl TestSigner {
        fn new() -> Self {
            Self {
                signing_key: p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap(),
            }
        }
    }

    impl std::fmt::Debug for TestSigner {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("TestSigner([redacted])")
        }
    }

    impl CredentialSigner for TestSigner {
        fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
            use p256::ecdsa::signature::Signer as _;
            let signature: p256::ecdsa::Signature = self.signing_key.sign(message);
            Ok(signature.to_bytes().to_vec())
        }

        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::ES256
        }

        fn issuer_id(&self) -> &str {
            "did:example:vdsnc-issuer"
        }

        fn kid_url(&self) -> String {
            "did:example:vdsnc-issuer#key-1".to_string()
        }

        fn public_jwk(&self) -> Oid4vciResult<String> {
            Ok(crate::signer::test_es256_public_jwk_for_key(
                &self.signing_key,
            ))
        }
    }

    fn cmc_claims(country: &str) -> CredentialClaims {
        let claims_map = serde_json::from_value(serde_json::json!({
            "docType": "CMC",
            "issuingCountry": country,
            "documentNumber": "X123456",
            "surname": "EXAMPLE",
            "givenNames": "ADA",
            "dateOfBirth": "19900102",
            "nationality": "AUS",
            "gender": "F",
            "dateOfIssue": "20260101",
            "dateOfExpiry": "20300101"
        }))
        .unwrap();
        CredentialClaims {
            subject_id: None,
            credential_type: "CMC".to_string(),
            claims: claims_map,
            expiration_seconds: None,
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        }
    }

    #[test]
    fn signs_vds_nc_with_signer() {
        let signer = TestSigner::new();

        let claims = cmc_claims("AUS");

        let signed = sign_vds_nc_with_signer(&signer, &claims).unwrap();
        match signed {
            SignedCredential::VdsNc { barcode_data, .. } => {
                assert!(barcode_data.starts_with("DC03AUS~"));
                assert_eq!(barcode_data.split('~').count(), 3);
            }
            _ => panic!("Expected SignedCredential::VdsNc"),
        }
    }

    #[test]
    fn prepare_and_assemble_vds_nc_round_trip() {
        let signer = TestSigner::new();

        let claims = cmc_claims("USA");

        let prepared = prepare_vds_nc(&signer, &claims).unwrap();
        assert!(prepared.signing_input.starts_with("DC03USA~"));

        let signature = signer.sign(prepared.signing_payload()).unwrap();
        let assembled = assemble_vds_nc(prepared, &signature).unwrap();
        match assembled {
            SignedCredential::VdsNc { barcode_data, .. } => {
                assert_eq!(barcode_data.split('~').count(), 3);
            }
            _ => panic!("Expected SignedCredential::VdsNc"),
        }
    }

    #[test]
    fn prepared_vds_diagnostics_redact_signing_payload() {
        let signing_key = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let prepared = make_prepared(
            "AUS",
            "ES256",
            crate::signer::test_es256_public_jwk_for_key(&signing_key),
        );
        let diagnostic = format!("{prepared:?}");
        assert_eq!(diagnostic, "PreparedVdsNc([redacted])");
        assert!(!diagnostic.contains("CMC"));
    }

    #[test]
    fn rejects_invalid_country() {
        let signer = TestSigner::new();

        let claims = cmc_claims("US");

        let err = sign_vds_nc_with_signer(&signer, &claims).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("issuingCountry"));
    }

    // =========================================================================
    // KMS provider signature encoding matrix (VDSNC-RUST-011)
    //
    // Verifies that DER-encoded ECDSA signatures produced by external KMS
    // providers (OpenBao/HashiCorp Vault, AWS KMS, Azure Key Vault, GCP KMS)
    // are correctly normalized to raw (r || s) format during assembly.
    // =========================================================================

    fn make_prepared(country: &str, algorithm: &str, issuer_public_jwk: String) -> PreparedVdsNc {
        let header = format!("DC03{}", country);
        let payload_json = r#"{"typ":"CMC"}"#.to_string();
        let signing_input = format!("{}~{}", header, payload_json);
        PreparedVdsNc {
            signing_input,
            credential_id: "urn:uuid:test".to_string(),
            algorithm: algorithm.to_string(),
            issuer_public_jwk,
        }
    }

    fn p384_public_jwk(signing_key: &p384::ecdsa::SigningKey) -> String {
        let point = signing_key.verifying_key().to_encoded_point(false);
        serde_json::json!({
            "alg": "ES384",
            "crv": "P-384",
            "kty": "EC",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
        .to_string()
    }

    fn ed25519_public_jwk(signing_key: &ed25519_dalek::SigningKey) -> String {
        serde_json::json!({
            "alg": "EdDSA",
            "crv": "Ed25519",
            "kty": "OKP",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signing_key.verifying_key().to_bytes()),
        })
        .to_string()
    }

    fn barcode_signature_bytes(barcode_data: &str) -> Vec<u8> {
        let sig_b64 = barcode_data.split('~').nth(2).expect("segment 3");
        base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .expect("base64 decode")
    }

    /// Mock KMS: returns a DER-encoded P-256 ECDSA signature.
    #[test]
    fn kms_p256_der_signature_is_normalized_to_raw() {
        use p256::ecdsa::{signature::Signer as _, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let prepared = make_prepared(
            "AUS",
            "ES256",
            crate::signer::test_es256_public_jwk_for_key(&signing_key),
        );
        let sig_der: p256::ecdsa::DerSignature =
            signing_key.sign(prepared.signing_input.as_bytes());

        let assembled = assemble_vds_nc(prepared, sig_der.as_bytes()).unwrap();
        let sig_bytes = match assembled {
            SignedCredential::VdsNc {
                ref barcode_data, ..
            } => barcode_signature_bytes(barcode_data),
            _ => panic!("expected VdsNc"),
        };

        // Normalized signature must be exactly 64 bytes (P-256 raw: r || s)
        assert_eq!(
            sig_bytes.len(),
            64,
            "P-256 raw signature must be 64 bytes, got {}",
            sig_bytes.len()
        );
        let expected = p256::ecdsa::Signature::from_der(sig_der.as_bytes())
            .expect("valid P-256 DER signature")
            .to_bytes();
        assert_eq!(sig_bytes, expected.as_slice());
    }

    /// Mock KMS: returns a raw P-256 signature (already in r || s format).
    #[test]
    fn kms_p256_raw_signature_passes_through_unchanged() {
        use p256::ecdsa::{signature::Signer as _, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let prepared = make_prepared(
            "GBR",
            "ES256",
            crate::signer::test_es256_public_jwk_for_key(&signing_key),
        );
        let sig: p256::ecdsa::Signature = signing_key.sign(prepared.signing_input.as_bytes());
        let raw_bytes = sig.to_bytes().to_vec();

        let assembled = assemble_vds_nc(prepared, &raw_bytes).unwrap();
        let sig_bytes = match assembled {
            SignedCredential::VdsNc {
                ref barcode_data, ..
            } => barcode_signature_bytes(barcode_data),
            _ => panic!("expected VdsNc"),
        };

        assert_eq!(sig_bytes, raw_bytes);
    }

    /// Mock KMS: returns a DER-encoded P-384 ECDSA signature.
    #[test]
    fn kms_p384_der_signature_is_normalized_to_raw() {
        use p384::ecdsa::{signature::Signer as _, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let prepared = make_prepared("DEU", "ES384", p384_public_jwk(&signing_key));
        let sig_der: p384::ecdsa::DerSignature =
            signing_key.sign(prepared.signing_input.as_bytes());

        let assembled = assemble_vds_nc(prepared, sig_der.as_bytes()).unwrap();
        let sig_bytes = match assembled {
            SignedCredential::VdsNc {
                ref barcode_data, ..
            } => barcode_signature_bytes(barcode_data),
            _ => panic!("expected VdsNc"),
        };

        // Normalized P-384 signature must be exactly 96 bytes (r || s)
        assert_eq!(
            sig_bytes.len(),
            96,
            "P-384 raw signature must be 96 bytes, got {}",
            sig_bytes.len()
        );
        let expected = p384::ecdsa::Signature::from_der(sig_der.as_bytes())
            .expect("valid P-384 DER signature")
            .to_bytes();
        assert_eq!(sig_bytes, expected.as_slice());
    }

    /// Ed25519 signatures are 64 bytes and never DER-encoded; pass through unchanged.
    #[test]
    fn ed25519_signature_passes_through_unchanged() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let prepared = make_prepared("FRA", "EdDSA", ed25519_public_jwk(&signing_key));
        let raw_ed25519_sig = signing_key
            .sign(prepared.signing_input.as_bytes())
            .to_bytes();
        let assembled = assemble_vds_nc(prepared, &raw_ed25519_sig).unwrap();
        let sig_bytes = match assembled {
            SignedCredential::VdsNc {
                ref barcode_data, ..
            } => barcode_signature_bytes(barcode_data),
            _ => panic!("expected VdsNc"),
        };
        assert_eq!(sig_bytes, raw_ed25519_sig);
    }

    #[test]
    fn malformed_signature_is_rejected_and_valid_signature_assembles() {
        use p256::ecdsa::{signature::Signer as _, SigningKey};
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let prepared = make_prepared(
            "AUS",
            "ES256",
            crate::signer::test_es256_public_jwk_for_key(&signing_key),
        );
        assert!(assemble_vds_nc(prepared, &[0u8; 64]).is_err());

        let prepared = make_prepared(
            "AUS",
            "ES256",
            crate::signer::test_es256_public_jwk_for_key(&signing_key),
        );
        let valid: p256::ecdsa::Signature = signing_key.sign(prepared.signing_payload());
        assert!(assemble_vds_nc(prepared, valid.to_bytes().as_slice()).is_ok());
    }

    #[test]
    fn assembly_rejects_signature_for_wrong_payload_and_wrong_key() {
        use p256::ecdsa::{signature::Signer as _, SigningKey};

        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let wrong_key = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
        let prepared = make_prepared(
            "AUS",
            "ES256",
            crate::signer::test_es256_public_jwk_for_key(&signing_key),
        );
        let signature: p256::ecdsa::Signature = signing_key.sign(prepared.signing_payload());

        let mut wrong_payload = make_prepared(
            "AUS",
            "ES256",
            crate::signer::test_es256_public_jwk_for_key(&signing_key),
        );
        wrong_payload.signing_input.push(' ');
        assert!(assemble_vds_nc(wrong_payload, signature.to_bytes().as_slice()).is_err());

        let wrong_key_prepared = make_prepared(
            "AUS",
            "ES256",
            crate::signer::test_es256_public_jwk_for_key(&wrong_key),
        );
        assert!(assemble_vds_nc(wrong_key_prepared, signature.to_bytes().as_slice()).is_err());
    }

    #[test]
    fn rsa_signature_width_is_bounded_to_supported_moduli() {
        assert!(normalize_signature_bytes("PS256", &[1; 255]).is_err());
        assert_eq!(
            normalize_signature_bytes("PS256", &[1; 256]).unwrap().len(),
            256
        );
        assert_eq!(
            normalize_signature_bytes("PS512", &[1; 1024])
                .unwrap()
                .len(),
            1024
        );
        assert!(normalize_signature_bytes("PS384", &[1; 1025]).is_err());
    }
}
