//! W3C VC-JWT credential format (`jwt_vc_json`).
//!
//! Constructs and signs W3C Verifiable Credentials as JWTs per the
//! W3C VC Data Model 1.1 + JWT encoding (default), or VCDM v2 when
//! `credential_payload_format = W3cVcdmV2JwtVc`.
//!
//! VCDM v1  — `https://www.w3.org/2018/credentials/v1`, `issuanceDate`, `expirationDate`
//! VCDM v2  — `https://www.w3.org/ns/credentials/v2`,  `validFrom`,    `validUntil`

use base64::Engine;
use ssi::crypto::AlgorithmInstance;
use ssi::jwk::{Params, JWK};
use std::collections::HashMap;

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::types::{CredentialClaims, CredentialPayloadFormat, IssuerKey, SignedCredential};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Sign a W3C VC-JWT credential.
///
/// Branches on `claims.credential_payload_format`:
/// - `W3cVcdmV2JwtVc` → VCDM v2 (`validFrom`/`validUntil`, v2 `@context`)
/// - any other value  → VCDM v1 (`issuanceDate`/`expirationDate`, v1 `@context`)
pub fn sign_jwt_vc(issuer_key: &IssuerKey, claims: &CredentialClaims) -> Oid4vciResult<SignedCredential> {
    let jwk: JWK = serde_json::from_str(&issuer_key.jwk_json)
        .map_err(|e| Oid4vciError::KeyError(format!("Invalid issuer JWK: {}", e)))?;

    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();

    // Build the W3C VC payload
    let mut credential_subject: HashMap<String, serde_json::Value> = claims.claims.clone();
    if let Some(ref subject_id) = claims.subject_id {
        credential_subject.insert("id".to_string(), serde_json::json!(subject_id));
    }

    let use_vcdm_v2 = claims.credential_payload_format == CredentialPayloadFormat::W3cVcdmV2JwtVc;

    let mut vc_types = vec!["VerifiableCredential".to_string()];
    if !claims.credential_type.is_empty() {
        vc_types.push(claims.credential_type.clone());
    }
    vc_types.extend(claims.w3c_types.iter().cloned());

    let vc = if use_vcdm_v2 {
        // ── VCDM v2 ──────────────────────────────────────────────────────────
        let valid_from = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let mut context = vec!["https://www.w3.org/ns/credentials/v2".to_string()];
        context.extend(claims.w3c_context.iter().cloned());

        let mut v = serde_json::json!({
            "@context": context,
            "id": credential_id,
            "type": vc_types,
            "issuer": issuer_key.issuer_id,
            "validFrom": valid_from,
            "credentialSubject": credential_subject,
        });
        if let Some(exp_secs) = claims.expiration_seconds {
            let valid_until = (now + chrono::Duration::seconds(exp_secs))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            v["validUntil"] = serde_json::json!(valid_until);
        }
        v
    } else {
        // ── VCDM v1 (default) ────────────────────────────────────────────────
        let issuance_date = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let mut v = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": credential_id,
            "type": vc_types,
            "issuer": issuer_key.issuer_id,
            "issuanceDate": issuance_date,
            "credentialSubject": credential_subject,
        });
        if let Some(exp_secs) = claims.expiration_seconds {
            let expiration_date = (now + chrono::Duration::seconds(exp_secs))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            v["expirationDate"] = serde_json::json!(expiration_date);
        }
        v
    };

    // Build the JWT registered claims
    let mut payload = serde_json::json!({
        "iss": issuer_key.issuer_id,
        "iat": now.timestamp(),
        "jti": credential_id,
        "vc": vc,
    });

    if let Some(ref subject_id) = claims.subject_id {
        payload["sub"] = serde_json::json!(subject_id);
    }

    if let Some(exp_secs) = claims.expiration_seconds {
        payload["exp"] = serde_json::json!(now.timestamp() + exp_secs);
    }

    // Build and sign the JWT
    let alg_str = issuer_key.algorithm.as_str();
    let header = serde_json::json!({
        "alg": alg_str,
        "typ": "vc+jwt",
        "kid": issuer_key.kid_url()
    });

    let jwt = encode_and_sign_jwt(&jwk, &header, &payload)?;

    Ok(SignedCredential::JwtVcJson {
        jwt,
        credential_id,
    })
}

/// Encode header and payload as base64url, sign, and produce a compact JWT.
pub(crate) fn encode_and_sign_jwt(
    jwk: &JWK,
    header: &serde_json::Value,
    payload: &serde_json::Value,
) -> Oid4vciResult<String> {
    let header_str = serde_json::to_string(header)
        .map_err(|e| Oid4vciError::SigningError(format!("Header serialization failed: {}", e)))?;
    let payload_str = serde_json::to_string(payload)
        .map_err(|e| Oid4vciError::SigningError(format!("Payload serialization failed: {}", e)))?;

    let header_b64 = B64.encode(header_str.as_bytes());
    let payload_b64 = B64.encode(payload_str.as_bytes());

    let message = format!("{}.{}", header_b64, payload_b64);
    let signature = sign_with_jwk(jwk, message.as_bytes())?;
    let signature_b64 = B64.encode(&signature);

    Ok(format!("{}.{}", message, signature_b64))
}

/// Sign a message with a JWK using the appropriate algorithm.
fn sign_with_jwk(jwk: &JWK, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
    let secret_key = extract_secret_key(jwk)?;
    let alg_instance = get_algorithm_instance(jwk)?;

    let signature = secret_key
        .sign(alg_instance, message)
        .map_err(|e| Oid4vciError::SigningError(format!("Signing failed: {:?}", e)))?;

    Ok(signature)
}

/// Extract a SecretKey from a JWK for signing.
fn extract_secret_key(jwk: &JWK) -> Oid4vciResult<ssi::crypto::SecretKey> {
    match &jwk.params {
        Params::OKP(params) => {
            let d = params
                .private_key
                .as_ref()
                .ok_or_else(|| Oid4vciError::KeyError("Missing private key (d) in OKP JWK".into()))?;
            ssi::crypto::SecretKey::new_ed25519(&d.0)
                .map_err(|e| Oid4vciError::KeyError(format!("Invalid Ed25519 key: {:?}", e)))
        }
        Params::EC(params) => {
            let d = params
                .ecc_private_key
                .as_ref()
                .ok_or_else(|| Oid4vciError::KeyError("Missing private key (d) in EC JWK".into()))?;
            match params.curve.as_deref() {
                Some("P-256") => ssi::crypto::SecretKey::new_p256(&d.0)
                    .map_err(|e| Oid4vciError::KeyError(format!("Invalid P-256 key: {:?}", e))),
                Some("secp256k1") => ssi::crypto::SecretKey::new_secp256k1(&d.0)
                    .map_err(|e| Oid4vciError::KeyError(format!("Invalid secp256k1 key: {:?}", e))),
                curve => Err(Oid4vciError::KeyError(format!(
                    "Unsupported EC curve: {:?}",
                    curve
                ))),
            }
        }
        _ => Err(Oid4vciError::KeyError(
            "Unsupported key type for signing (need OKP or EC)".into(),
        )),
    }
}

/// Get the AlgorithmInstance for a JWK.
fn get_algorithm_instance(jwk: &JWK) -> Oid4vciResult<AlgorithmInstance> {
    match &jwk.params {
        Params::OKP(_) => Ok(AlgorithmInstance::EdDSA),
        Params::EC(ec) => match ec.curve.as_deref() {
            Some("P-256") => Ok(AlgorithmInstance::ES256),
            Some("secp256k1") => Ok(AlgorithmInstance::ES256K),
            curve => Err(Oid4vciError::KeyError(format!(
                "Unsupported EC curve: {:?}",
                curve
            ))),
        },
        _ => Err(Oid4vciError::KeyError(
            "Unsupported key type for algorithm selection".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SigningAlgorithm;

    fn test_ed25519_key() -> IssuerKey {
        let jwk = JWK::generate_ed25519().unwrap();
        let jwk_json = serde_json::to_string(&jwk).unwrap();

        // Use did:jwk for simplicity (avoids bs58 dependency)
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(jwk_json.as_bytes());
        let did = format!("did:jwk:{}", encoded);

        IssuerKey {
            issuer_id: did,
            jwk_json,
            algorithm: SigningAlgorithm::EdDSA,
        }
    }

    fn test_p256_key() -> IssuerKey {
        let jwk = JWK::generate_p256();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(jwk_json.as_bytes());
        let did = format!("did:jwk:{}", encoded);

        IssuerKey {
            issuer_id: did,
            jwk_json,
            algorithm: SigningAlgorithm::ES256,
        }
    }

    #[test]
    fn test_sign_jwt_vc_ed25519() {
        let key = test_ed25519_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder123".into()),
            credential_type: "UniversityDegree".into(),
            claims: [
                ("degree".into(), serde_json::json!("Bachelor of Science")),
                ("gpa".into(), serde_json::json!(3.8)),
            ]
            .into(),
            expiration_seconds: Some(3600),
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let result = sign_jwt_vc(&key, &claims).unwrap();
        match result {
            SignedCredential::JwtVcJson { jwt, credential_id } => {
                assert!(jwt.split('.').count() == 3, "JWT should have 3 parts");
                assert!(credential_id.starts_with("urn:uuid:"));

                // Decode and verify payload structure
                let parts: Vec<&str> = jwt.split('.').collect();
                let payload_bytes = B64.decode(parts[1]).unwrap();
                let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
                assert_eq!(payload["vc"]["type"][1], "UniversityDegree");
                assert_eq!(payload["sub"], "did:example:holder123");
                assert!(payload["exp"].is_number());
            }
            _ => panic!("Expected JwtVcJson"),
        }
    }

    #[test]
    fn test_sign_jwt_vc_p256() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: None,
            credential_type: "DriverLicense".into(),
            claims: [("name".into(), serde_json::json!("Alice"))].into(),
            expiration_seconds: None,
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let result = sign_jwt_vc(&key, &claims).unwrap();
        match result {
            SignedCredential::JwtVcJson { jwt, .. } => {
                assert!(jwt.split('.').count() == 3);

                // Decode header and verify algorithm
                let parts: Vec<&str> = jwt.split('.').collect();
                let header_bytes = B64.decode(parts[0]).unwrap();
                let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
                assert_eq!(header["alg"], "ES256");
            }
            _ => panic!("Expected JwtVcJson"),
        }
    }
}
