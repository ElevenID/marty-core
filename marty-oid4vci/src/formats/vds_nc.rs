//! VDS-NC credential format (`vds_nc`).
//!
//! This module provides a signer-agnostic VDS-NC construction path that works
//! with local JWK signing (`IssuerKey`) and external/KMS-backed signing via
//! the `CredentialSigner` trait.

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::signer::{validate_remote_signature, CredentialSigner};
#[cfg(any(test, feature = "local-key-operations"))]
use crate::types::IssuerKey;
use crate::types::{CredentialClaims, SignedCredential};

use base64::Engine;

/// Intermediate state between VDS-NC preparation and signature assembly.
#[derive(Debug, Clone)]
pub struct PreparedVdsNc {
    /// The exact bytes (as UTF-8 text) that must be signed.
    signing_input: String,
    /// Stable issuance-side credential identifier.
    credential_id: String,
    /// Protected profile algorithm that the remote signer must use.
    algorithm: String,
}

impl PreparedVdsNc {
    /// Reconstruct a prepared envelope from a `header~payload_json` signing input.
    pub fn from_signing_input(signing_input: String, credential_id: String) -> Oid4vciResult<Self> {
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
        normalize_signature_bytes(&self.algorithm, signature)
    }
}

/// Sign a VDS-NC credential using a local issuer key.
#[cfg(any(test, feature = "local-key-operations"))]
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
    assemble_vds_nc(&prepared, &signature)
}

/// Prepare a VDS-NC credential for external signing.
pub fn prepare_vds_nc(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<PreparedVdsNc> {
    prepare_vds_nc_profile(
        signer.issuer_id(),
        &signer.kid_url(),
        signer.algorithm().as_str(),
        claims,
    )
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
    })
}

/// Assemble a VDS-NC credential from a signature already encoded in the
/// profile algorithm's canonical raw form.
pub fn assemble_vds_nc_raw(
    prepared: &PreparedVdsNc,
    signature: &[u8],
) -> Oid4vciResult<SignedCredential> {
    let normalized = prepared.validate_signature(signature)?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(normalized);
    let barcode_data = format!("{}~{}", prepared.signing_input, signature_b64);
    Ok(SignedCredential::VdsNc {
        barcode_data,
        credential_id: prepared.credential_id.clone(),
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
    prepared: &PreparedVdsNc,
    signature: &[u8],
) -> Oid4vciResult<SignedCredential> {
    let normalized = prepared.validate_signature(signature)?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&normalized);
    let barcode_data = format!("{}~{}", prepared.signing_input, signature_b64);

    Ok(SignedCredential::VdsNc {
        barcode_data,
        credential_id: prepared.credential_id.clone(),
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
        "PS256" | "PS384" | "PS512"
            if signature.len() >= 256 && signature.iter().any(|byte| *byte != 0) =>
        {
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

    #[derive(Debug)]
    struct TestSigner;

    impl CredentialSigner for TestSigner {
        fn sign(&self, _message: &[u8]) -> Oid4vciResult<Vec<u8>> {
            let mut signature = vec![0u8; 64];
            signature[31] = 1;
            signature[63] = 1;
            Ok(signature)
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
        let signer = TestSigner;

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
        let signer = TestSigner;

        let claims = cmc_claims("USA");

        let prepared = prepare_vds_nc(&signer, &claims).unwrap();
        assert!(prepared.signing_input.starts_with("DC03USA~"));

        let mut signature = [0u8; 64];
        signature[31] = 1;
        signature[63] = 1;
        let assembled = assemble_vds_nc(&prepared, &signature).unwrap();
        match assembled {
            SignedCredential::VdsNc { barcode_data, .. } => {
                assert_eq!(barcode_data.split('~').count(), 3);
            }
            _ => panic!("Expected SignedCredential::VdsNc"),
        }
    }

    #[test]
    fn rejects_invalid_country() {
        let signer = TestSigner;

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

    fn make_prepared(country: &str, algorithm: &str) -> PreparedVdsNc {
        let header = format!("DC03{}", country);
        let payload_json = r#"{"typ":"CMC"}"#.to_string();
        let signing_input = format!("{}~{}", header, payload_json);
        PreparedVdsNc {
            signing_input,
            credential_id: "urn:uuid:test".to_string(),
            algorithm: algorithm.to_string(),
        }
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
        let prepared = make_prepared("AUS", "ES256");
        let sig_der: p256::ecdsa::DerSignature =
            signing_key.sign(prepared.signing_input.as_bytes());

        let assembled = assemble_vds_nc(&prepared, sig_der.as_bytes()).unwrap();
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
        let prepared = make_prepared("GBR", "ES256");
        let sig: p256::ecdsa::Signature = signing_key.sign(prepared.signing_input.as_bytes());
        let raw_bytes = sig.to_bytes().to_vec();

        let assembled = assemble_vds_nc(&prepared, &raw_bytes).unwrap();
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
        let prepared = make_prepared("DEU", "ES384");
        let sig_der: p384::ecdsa::DerSignature =
            signing_key.sign(prepared.signing_input.as_bytes());

        let assembled = assemble_vds_nc(&prepared, sig_der.as_bytes()).unwrap();
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
        let prepared = make_prepared("FRA", "EdDSA");
        let raw_ed25519_sig = SigningKey::from_bytes(&[7u8; 32])
            .sign(prepared.signing_input.as_bytes())
            .to_bytes();
        let assembled = assemble_vds_nc(&prepared, &raw_ed25519_sig).unwrap();
        let sig_bytes = match assembled {
            SignedCredential::VdsNc {
                ref barcode_data, ..
            } => barcode_signature_bytes(barcode_data),
            _ => panic!("expected VdsNc"),
        };
        assert_eq!(sig_bytes, raw_ed25519_sig);
    }

    #[test]
    fn malformed_signature_does_not_consume_prepared_state() {
        let prepared = make_prepared("AUS", "ES256");
        assert!(assemble_vds_nc(&prepared, &[0u8; 64]).is_err());

        let mut valid = [0u8; 64];
        valid[31] = 1;
        valid[63] = 1;
        assert!(assemble_vds_nc(&prepared, &valid).is_ok());
    }
}
