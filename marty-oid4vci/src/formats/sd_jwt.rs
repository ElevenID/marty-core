//! IETF SD-JWT credential format (`vc+sd-jwt`).
//!
//! Constructs SD-JWT Verifiable Credentials with selective disclosure
//! per IETF draft-ietf-oauth-sd-jwt-vc and SD-JWT (RFC 9449).
//!
//! Supports two payload structures selected via `CredentialPayloadFormat`:
//!
//! - `IetfSdJwt`: flat claims with `vct`/`iss` at top level.
//!   SD JSONPath selectors: `$.claim_name`
//! - `W3cVcdmV2SdJwt` (default): W3C VCDM v2 envelope with
//!   `@context`/`type`/`issuer`/`validFrom`/`credentialSubject`.
//!   SD JSONPath selectors: `$.credentialSubject.claim_name`

use sd_jwt_rs::issuer::ClaimsForSelectiveDisclosureStrategy;
use sd_jwt_rs::{SDJWTIssuer, SDJWTSerializationFormat};
use ssi::jwk::{Params, JWK};
use p256::pkcs8::EncodePrivateKey;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::types::{CredentialClaims, CredentialPayloadFormat, IssuerKey, SignedCredential};

/// Sign an SD-JWT verifiable credential.
///
/// Claims listed in `selective_disclosure_claims` will be made selectively
/// disclosable. All other claims are included directly in the JWT payload.
pub fn sign_sd_jwt(
    issuer_key: &IssuerKey,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    let jwk: JWK = serde_json::from_str(&issuer_key.jwk_json)
        .map_err(|e| Oid4vciError::KeyError(format!("Invalid issuer JWK: {}", e)))?;

    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();

    let vct = if claims.credential_type.is_empty() {
        "VerifiableCredential".to_string()
    } else {
        claims.credential_type.clone()
    };

    // Build the JWT payload and SD JSONPath selectors based on the payload format.
    let (payload, sd_path_prefix) = match &claims.credential_payload_format {
        CredentialPayloadFormat::IetfSdJwt => {
            // ── IETF flat SD-JWT VC ──────────────────────────────────────────
            // Top-level claims: vct, iss, iat, jti, sub, exp, plus all credential claims.
            // Selective disclosure JSONPath: `$.claim_name`
            let mut p = serde_json::json!({
                "iss": issuer_key.issuer_id,
                "iat": now.timestamp(),
                "jti": credential_id,
                "vct": vct,
            });
            if let Some(ref subject_id) = claims.subject_id {
                p["sub"] = serde_json::json!(subject_id);
            }
            if let Some(exp_secs) = claims.expiration_seconds {
                p["exp"] = serde_json::json!(now.timestamp() + exp_secs);
            }
            if let Some(obj) = p.as_object_mut() {
                for (key, value) in &claims.claims {
                    obj.insert(key.clone(), value.clone());
                }
            }
            (p, "$.")
        }

        CredentialPayloadFormat::W3cVcdmV2SdJwt => {
            // ── W3C VCDM v2 SD-JWT ──────────────────────────────────────────
            // Claims are nested under `credentialSubject`.
            // Selective disclosure JSONPath: `$.credentialSubject.claim_name`
            let mut credential_subject = serde_json::json!({});
            if let Some(ref subject_id) = claims.subject_id {
                credential_subject["id"] = serde_json::json!(subject_id);
            }
            if let Some(obj) = credential_subject.as_object_mut() {
                for (key, value) in &claims.claims {
                    obj.insert(key.clone(), value.clone());
                }
            }

            let valid_from = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

            let mut context = vec!["https://www.w3.org/ns/credentials/v2".to_string()];
            context.extend(claims.w3c_context.iter().cloned());

            let mut types = vec!["VerifiableCredential".to_string()];
            types.extend(claims.w3c_types.iter().cloned());

            let mut p = serde_json::json!({
                "iss": issuer_key.issuer_id,
                "iat": now.timestamp(),
                "jti": credential_id,
                "vct": vct,
                "@context": context,
                "type": types,
                "issuer": issuer_key.issuer_id,
                "validFrom": valid_from,
                "credentialSubject": credential_subject,
            });
            if let Some(ref subject_id) = claims.subject_id {
                p["sub"] = serde_json::json!(subject_id);
            }
            if let Some(exp_secs) = claims.expiration_seconds {
                let exp_ts = now.timestamp() + exp_secs;
                p["exp"] = serde_json::json!(exp_ts);
                let valid_until = chrono::DateTime::from_timestamp(exp_ts, 0)
                    .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .unwrap_or_default();
                p["validUntil"] = serde_json::json!(valid_until);
            }
            (p, "$.credentialSubject.")
        }

        CredentialPayloadFormat::W3cVcdmV2JwtVc => {
            return Err(Oid4vciError::UnsupportedFormat(
                "credential_payload_format 'w3c_vcdm_v2_jwt_vc' is only valid for jwt_vc_json, \
                 not for SD-JWT credentials"
                    .to_string(),
            ));
        }
    };

    // Get the signing algorithm and key material for sd-jwt-rs
    let (alg_str, encoding_key) = get_sd_jwt_signing_params(&jwk, issuer_key)?;
    let encoding_key_resign = encoding_key.clone();

    let mut issuer = SDJWTIssuer::new(encoding_key, Some(alg_str.clone()));

    let sd_jwt = if claims.selective_disclosure_claims.is_empty() {
        issuer.issue_sd_jwt(
            payload,
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
    } else {
        // Build JSONPath-style selectors using the format-appropriate prefix.
        // IETF flat: `$.claim_name`  |  W3C VCDM v2: `$.credentialSubject.claim_name`
        let paths: Vec<String> = claims
            .selective_disclosure_claims
            .iter()
            .map(|s| format!("{}{}", sd_path_prefix, s))
            .collect();
        let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();

        issuer.issue_sd_jwt(
            payload,
            ClaimsForSelectiveDisclosureStrategy::Custom(path_refs),
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
    }
    .map_err(|e| Oid4vciError::SdJwtError(format!("SD-JWT issuance failed: {:?}", e)))?;

    // Re-sign the SD-JWT JWS with a proper header that includes `kid`
    // sd-jwt-rs 0.7 doesn't support extra_header_parameters (unimplemented!)
    let sd_jwt = inject_kid_header(
        &sd_jwt,
        &issuer_key.kid_url(),
        &alg_str,
        &encoding_key_resign,
    )?;

    Ok(SignedCredential::SdJwt {
        compact: sd_jwt,
        credential_id,
    })
}

/// Re-sign the SD-JWT's JWS part with a new header that includes `kid`.
///
/// `sd-jwt-rs` 0.7 does not support `extra_header_parameters` (unimplemented!).
/// We work around this by extracting the signed payload from the generated
/// SD-JWT, then re-signing it with `jsonwebtoken` using a header that includes
/// the issuer DID as `kid`.
///
/// SD-JWT compact format: `<JWS>~[disclosure~...]`
/// JWS: `<base64url-header>.<base64url-payload>.<signature>`
fn inject_kid_header(
    sd_jwt: &str,
    kid: &str,
    alg_str: &str,
    encoding_key: &jsonwebtoken::EncodingKey,
) -> Oid4vciResult<String> {
    // Split off the JWS (first segment before any `~`)
    let (jws, disclosures_suffix) = match sd_jwt.split_once('~') {
        Some((jws, rest)) => (jws, format!("~{}", rest)),
        None => (sd_jwt, String::new()),
    };

    // Split JWS into header.payload.signature
    let parts: Vec<&str> = jws.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(Oid4vciError::SdJwtError(
            format!("Malformed SD-JWT JWS (expected 3 parts, got {})", parts.len())
        ));
    }

    // Decode the existing payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| Oid4vciError::SdJwtError(format!("Base64 decode error: {}", e)))?;
    let payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Oid4vciError::SdJwtError(format!("Payload JSON parse error: {}", e)))?;

    // Build a new header with kid and vc+sd-jwt typ
    let alg = match alg_str {
        "EdDSA" => jsonwebtoken::Algorithm::EdDSA,
        "ES256" => jsonwebtoken::Algorithm::ES256,
        "ES384" => jsonwebtoken::Algorithm::ES384,
        other => return Err(Oid4vciError::SdJwtError(
            format!("Unsupported algorithm for SD-JWT re-sign: {}", other)
        )),
    };
    let mut header = jsonwebtoken::Header::new(alg);
    header.kid = Some(kid.to_string());
    header.typ = Some("dc+sd-jwt".to_string());

    // Re-sign the same payload with the new header
    let new_jws = jsonwebtoken::encode(&header, &payload_json, encoding_key)
        .map_err(|e| Oid4vciError::SdJwtError(format!("Re-sign failed: {}", e)))?;

    Ok(format!("{}{}", new_jws, disclosures_suffix))
}

/// Build a PKCS#8 v2 DER-encoded Ed25519 private key for use with `ring`/`jsonwebtoken`.
///
/// `ring::signature::Ed25519KeyPair::from_pkcs8` requires PKCS#8 v2 format which
/// includes both the 32-byte private seed and the 32-byte public key.
fn ed25519_to_pkcs8_v2_der(private_seed: &[u8], public_key: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 (id-EdDSA / Ed25519) }
    let alg_id = b"\x30\x05\x06\x03\x2b\x65\x70";
    // Private key: OCTET STRING { OCTET STRING { seed } }
    let mut priv_part = vec![0x04u8, 0x22, 0x04, 0x20];
    priv_part.extend_from_slice(private_seed);
    // Public key: [1] EXPLICIT { BIT STRING { 0x00 || pubkey } }
    let mut pub_part = vec![0xa1u8, 0x23, 0x03, 0x21, 0x00];
    pub_part.extend_from_slice(public_key);
    // PKCS#8 v2 version = 1
    let version = b"\x02\x01\x01";

    let inner_len = version.len() + alg_id.len() + priv_part.len() + pub_part.len();
    let mut der = Vec::with_capacity(2 + inner_len);
    der.push(0x30u8);
    der.push(inner_len as u8);
    der.extend_from_slice(version);
    der.extend_from_slice(alg_id);
    der.extend_from_slice(&priv_part);
    der.extend_from_slice(&pub_part);
    der
}

/// Get the signing algorithm string and the JWK-derived EncodingKey for sd-jwt-rs.
fn get_sd_jwt_signing_params(
    jwk: &JWK,
    issuer_key: &IssuerKey,
) -> Oid4vciResult<(String, jsonwebtoken::EncodingKey)> {
    let alg_str = issuer_key.algorithm.as_str().to_string();

    let encoding_key = match &jwk.params {
        Params::OKP(params) => {
            let d = params
                .private_key
                .as_ref()
                .ok_or_else(|| Oid4vciError::KeyError("Missing Ed25519 private key".into()))?;

            // Build PKCS#8 v2 DER — ring needs both private seed and public key
            let pkcs8_der = ed25519_to_pkcs8_v2_der(&d.0, &params.public_key.0);
            jsonwebtoken::EncodingKey::from_ed_der(&pkcs8_der)
        }
        Params::EC(params) => {
            let d = params
                .ecc_private_key
                .as_ref()
                .ok_or_else(|| Oid4vciError::KeyError("Missing EC private key".into()))?;

            // For EC keys, convert to PKCS#8 DER or use the raw key
            // The jsonwebtoken crate expects PEM or DER format
            // We'll serialize the JWK to JSON and use from_jwk
            let _jwk_json = serde_json::to_string(jwk)
                .map_err(|e| Oid4vciError::KeyError(format!("JWK serialize error: {}", e)))?;
            
            // jsonwebtoken doesn't directly support JWK — build a minimal EC PEM
            // For P-256: use the `p256` crate to convert
            match params.curve.as_deref() {
                Some("P-256") => {
                    let secret =
                        p256::SecretKey::from_slice(&d.0).map_err(|e| {
                            Oid4vciError::KeyError(format!("Invalid P-256 key: {}", e))
                        })?;
                    let pkcs8_der = secret.to_pkcs8_der().map_err(|e| {
                        Oid4vciError::KeyError(format!("P-256 PKCS#8 encoding failed: {}", e))
                    })?;
                    Ok(jsonwebtoken::EncodingKey::from_ec_der(
                        pkcs8_der.as_bytes(),
                    ))
                }
                Some(curve) => Err(Oid4vciError::KeyError(format!(
                    "SD-JWT signing not supported for curve: {}",
                    curve
                ))),
                None => Err(Oid4vciError::KeyError("Missing curve in EC JWK".into())),
            }?
        }
        _ => {
            return Err(Oid4vciError::KeyError(
                "Unsupported key type for SD-JWT signing".into(),
            ));
        }
    };

    Ok((alg_str, encoding_key))
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SigningAlgorithm;
    use base64::Engine;

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn test_p256_key() -> IssuerKey {
        let jwk = JWK::generate_p256();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let encoded = B64.encode(jwk_json.as_bytes());
        let did = format!("did:jwk:{}", encoded);

        IssuerKey {
            issuer_id: did,
            jwk_json,
            algorithm: SigningAlgorithm::ES256,
        }
    }

    #[test]
    fn test_sign_sd_jwt_no_disclosures() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "IdentityCredential".into(),
            claims: [("name".into(), serde_json::json!("Alice"))].into(),
            expiration_seconds: Some(3600),
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let result = sign_sd_jwt(&key, &claims).unwrap();
        match result {
            SignedCredential::SdJwt { compact, credential_id } => {
                // SD-JWT should end with ~ (compact format)
                assert!(compact.contains('.'), "Should contain JWT dots");
                assert!(credential_id.starts_with("urn:uuid:"));
            }
            _ => panic!("Expected SdJwt"),
        }
    }

    #[test]
    fn test_sign_sd_jwt_with_disclosures() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "IdentityCredential".into(),
            claims: [
                ("name".into(), serde_json::json!("Alice")),
                ("age".into(), serde_json::json!(30)),
                ("email".into(), serde_json::json!("alice@example.com")),
            ]
            .into(),
            expiration_seconds: Some(3600),
            selective_disclosure_claims: vec!["name".into(), "email".into()],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let result = sign_sd_jwt(&key, &claims).unwrap();
        match result {
            SignedCredential::SdJwt { compact, .. } => {
                // With selective disclosures, the compact form should contain ~ separators
                let parts: Vec<&str> = compact.split('~').collect();
                // First part is the JWT, remaining are disclosures
                assert!(
                    parts.len() >= 2,
                    "SD-JWT with disclosures should have ~ separators, got: {}",
                    compact
                );
            }
            _ => panic!("Expected SdJwt"),
        }
    }
}
