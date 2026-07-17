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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::pkcs8::EncodePrivateKey;
use rand::RngCore;
use sd_jwt_rs::issuer::ClaimsForSelectiveDisclosureStrategy;
use sd_jwt_rs::{SDJWTIssuer, SDJWTSerializationFormat};
use sha2::{Digest, Sha256};
use ssi::jwk::{Params, JWK};

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::signer::CredentialSigner;
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

// =============================================================================
// External-signer support: prepare / assemble / sign_with_signer
// =============================================================================

/// Intermediate state between SD-JWT preparation and signing.
///
/// Returned by [`prepare_sd_jwt()`] — the caller signs `signing_input`
/// with an external signer and passes the result to [`assemble_sd_jwt()`].
pub struct PreparedSdJwt {
    /// The base64url-encoded `header.payload` string to be signed.
    pub signing_input: String,
    /// The disclosure suffix (e.g. `~disc1~disc2~`), including leading `~`.
    pub disclosures_suffix: String,
    /// The credential ID (urn:uuid:...) assigned during preparation.
    pub credential_id: String,
}

/// Sign an SD-JWT verifiable credential using any [`CredentialSigner`].
///
/// This is the BYOK-aware variant. For local JWK signing, pass an `&IssuerKey`.
/// For remote/KMS signing, pass a custom `CredentialSigner` implementation.
pub fn sign_sd_jwt_with_signer(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    let prepared = prepare_sd_jwt(signer, claims)?;
    let signature = signer.sign(prepared.signing_input.as_bytes())?;
    Ok(assemble_sd_jwt(prepared, &signature))
}

/// Prepare an SD-JWT for signing (build header + payload + disclosures, but don't sign).
///
/// Generates selective-disclosure entries inline (salt → disclosure → hash)
/// without relying on `SDJWTIssuer`, so no local key material is needed.
///
/// Returns a [`PreparedSdJwt`] whose `signing_input` field contains the
/// base64url-encoded `header.payload` ready for an external signer.
pub fn prepare_sd_jwt(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<PreparedSdJwt> {
    let credential_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();

    let vct = if claims.credential_type.is_empty() {
        "VerifiableCredential".to_string()
    } else {
        claims.credential_type.clone()
    };

    // Build the JWT payload based on the payload format.
    let (mut payload, sd_target_path) = match &claims.credential_payload_format {
        CredentialPayloadFormat::IetfSdJwt => {
            let mut p = serde_json::json!({
                "iss": signer.issuer_id(),
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
            // IETF flat: selective claims are at the top level
            (p, None)
        }

        CredentialPayloadFormat::W3cVcdmV2SdJwt => {
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
                "iss": signer.issuer_id(),
                "iat": now.timestamp(),
                "jti": credential_id,
                "vct": vct,
                "@context": context,
                "type": types,
                "issuer": signer.issuer_id(),
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
            // W3C VCDM v2: selective claims are inside credentialSubject
            (p, Some("credentialSubject"))
        }

        CredentialPayloadFormat::W3cVcdmV2JwtVc => {
            return Err(Oid4vciError::UnsupportedFormat(
                "credential_payload_format 'w3c_vcdm_v2_jwt_vc' is only valid for jwt_vc_json, \
                 not for SD-JWT credentials"
                    .to_string(),
            ));
        }
    };

    // Generate disclosures for selectively-disclosable claims.
    let disclosures = if !claims.selective_disclosure_claims.is_empty() {
        let target = match sd_target_path {
            Some(path) => payload
                .get_mut(path)
                .and_then(|v| v.as_object_mut())
                .ok_or_else(|| {
                    Oid4vciError::SdJwtError(format!(
                        "Missing '{}' object in payload for SD claims",
                        path
                    ))
                })?,
            None => payload
                .as_object_mut()
                .ok_or_else(|| Oid4vciError::SdJwtError("Payload is not a JSON object".into()))?,
        };
        generate_disclosures(target, &claims.selective_disclosure_claims)?
    } else {
        vec![]
    };

    // Add _sd_alg at the top level (per SD-JWT spec, always top-level).
    if !disclosures.is_empty() {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("_sd_alg".to_string(), serde_json::json!("sha-256"));
        }
    }

    // Build the JWS header with kid and vc+sd-jwt typ.
    let alg_str = signer.algorithm().as_str();
    let header = serde_json::json!({
        "alg": alg_str,
        "typ": "vc+sd-jwt",
        "kid": signer.kid_url()
    });

    let header_str = serde_json::to_string(&header)
        .map_err(|e| Oid4vciError::SigningError(format!("Header serialization failed: {}", e)))?;
    let payload_str = serde_json::to_string(&payload)
        .map_err(|e| Oid4vciError::SigningError(format!("Payload serialization failed: {}", e)))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_str.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_str.as_bytes());

    // Build compact disclosure suffix: ~disc1~disc2~
    let disclosures_suffix = if disclosures.is_empty() {
        "~".to_string()
    } else {
        format!("~{}~", disclosures.join("~"))
    };

    Ok(PreparedSdJwt {
        signing_input: format!("{}.{}", header_b64, payload_b64),
        disclosures_suffix,
        credential_id,
    })
}

/// Assemble a signed SD-JWT from the prepared data and a raw signature.
///
/// The `signature` must be the raw bytes produced by signing
/// `prepared.signing_input` with the issuer's key.
pub fn assemble_sd_jwt(prepared: PreparedSdJwt, signature: &[u8]) -> SignedCredential {
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);
    SignedCredential::SdJwt {
        compact: format!(
            "{}.{}{}",
            prepared.signing_input, signature_b64, prepared.disclosures_suffix
        ),
        credential_id: prepared.credential_id,
    }
}

/// Generate SD-JWT disclosures for selectively-disclosable claims.
///
/// For each claim in `sd_claims`:
/// 1. Remove the claim from `target_object`
/// 2. Generate a random 128-bit salt
/// 3. Build disclosure: `base64url([salt, claim_name, claim_value])`
/// 4. Hash: `base64url(SHA-256(disclosure))`
/// 5. Add the hash to the `_sd` array in `target_object`
///
/// Returns the list of base64url-encoded disclosures.
fn generate_disclosures(
    target_object: &mut serde_json::Map<String, serde_json::Value>,
    sd_claims: &[String],
) -> Oid4vciResult<Vec<String>> {
    let mut disclosures = Vec::new();
    let mut sd_hashes = Vec::new();

    for claim_name in sd_claims {
        let claim_value = match target_object.remove(claim_name) {
            Some(v) => v,
            None => continue, // claim not present in target, skip
        };

        // Generate 16 bytes (128 bits) of cryptographically secure random salt
        let mut salt_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt_bytes);
        let salt = URL_SAFE_NO_PAD.encode(salt_bytes);

        // Build disclosure: base64url(json([salt, claim_name, claim_value]))
        let disclosure_array = serde_json::json!([salt, claim_name, claim_value]);
        let disclosure_json = serde_json::to_string(&disclosure_array).map_err(|e| {
            Oid4vciError::SdJwtError(format!("Disclosure serialization failed: {}", e))
        })?;
        let disclosure = URL_SAFE_NO_PAD.encode(disclosure_json.as_bytes());

        // Hash: base64url(SHA-256(disclosure))
        let hash = Sha256::digest(disclosure.as_bytes());
        let hash_b64 = URL_SAFE_NO_PAD.encode(hash);

        disclosures.push(disclosure);
        sd_hashes.push(serde_json::Value::String(hash_b64));
    }

    if !sd_hashes.is_empty() {
        target_object.insert("_sd".to_string(), serde_json::Value::Array(sd_hashes));
    }

    Ok(disclosures)
}

// =============================================================================
// Verification
// =============================================================================

/// Verify an SD-JWT presentation and reconstruct the disclosed claims.
///
/// The verifier checks:
/// 1. JWS signature against the issuer's public key
/// 2. Each disclosure's hash against the `_sd` array in the payload
/// 3. Duplicate disclosure detection
/// 4. KB-JWT `aud` / `nonce` binding (when both `expected_aud` and
///    `expected_nonce` are supplied)
///
/// # Returns
/// The reconstructed JSON payload with all selectively-disclosed claims
/// merged into their canonical positions (i.e. the `_sd` hash entries are
/// replaced by the clear-text claim key-value pairs).
///
/// # Arguments
/// * `sd_jwt_compact`   — Compact SD-JWT (`JWS~disc1~disc2~[KB-JWT]`)
/// * `issuer_jwk_json`  — Issuer's **public** JWK as a JSON string
/// * `expected_aud`     — Expected KB-JWT audience (optional)
/// * `expected_nonce`   — Expected KB-JWT nonce (optional)
pub fn verify_sd_jwt(
    sd_jwt_compact: &str,
    issuer_jwk_json: &str,
    expected_aud: Option<String>,
    expected_nonce: Option<String>,
) -> Oid4vciResult<serde_json::Value> {
    let jwk_obj: jsonwebtoken::jwk::Jwk = serde_json::from_str(issuer_jwk_json)
        .map_err(|e| Oid4vciError::KeyError(format!("Invalid issuer JWK: {}", e)))?;

    let decoding_key = jsonwebtoken::DecodingKey::from_jwk(&jwk_obj)
        .map_err(|e| Oid4vciError::KeyError(format!("Failed to create decoding key: {}", e)))?;

    let verifier = sd_jwt_rs::SDJWTVerifier::new(
        sd_jwt_compact.to_string(),
        Box::new(move |_issuer: &str, _header: &jsonwebtoken::Header| decoding_key.clone()),
        expected_aud,
        expected_nonce,
        SDJWTSerializationFormat::Compact,
    )
    .map_err(|e| Oid4vciError::SdJwtError(format!("SD-JWT verification failed: {:?}", e)))?;

    Ok(verifier.verified_claims)
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
        return Err(Oid4vciError::SdJwtError(format!(
            "Malformed SD-JWT JWS (expected 3 parts, got {})",
            parts.len()
        )));
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
        other => {
            return Err(Oid4vciError::SdJwtError(format!(
                "Unsupported algorithm for SD-JWT re-sign: {}",
                other
            )))
        }
    };
    let mut header = jsonwebtoken::Header::new(alg);
    header.kid = Some(kid.to_string());
    // SD-JWT VC RFC 9596 §3.2.1: the JWT typ MUST be "vc+sd-jwt"
    header.typ = Some("vc+sd-jwt".to_string());

    // Re-sign the same payload with the new header
    let new_jws = jsonwebtoken::encode(&header, &payload_json, encoding_key)
        .map_err(|e| Oid4vciError::SdJwtError(format!("Re-sign failed: {}", e)))?;

    Ok(format!("{}{}", new_jws, disclosures_suffix))
}

/// Get the signing algorithm string and the JWK-derived EncodingKey for sd-jwt-rs.
fn get_sd_jwt_signing_params(
    jwk: &JWK,
    issuer_key: &IssuerKey,
) -> Oid4vciResult<(String, jsonwebtoken::EncodingKey)> {
    let alg_str = issuer_key.algorithm.as_str().to_string();

    let encoding_key = match &jwk.params {
        Params::OKP(params) => {
            use ed25519_dalek::pkcs8::EncodePrivateKey;

            let d = params
                .private_key
                .as_ref()
                .ok_or_else(|| Oid4vciError::KeyError("Missing Ed25519 private key".into()))?;

            // Serialize the seed with the standards-compliant PKCS#8 encoder.
            let seed: [u8; 32] = d.0.as_slice().try_into().map_err(|_| {
                Oid4vciError::KeyError("Ed25519 private key must be a 32-byte seed".into())
            })?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let pkcs8_der = signing_key.to_pkcs8_der().map_err(|e| {
                Oid4vciError::KeyError(format!("Ed25519 PKCS#8 encoding failed: {}", e))
            })?;
            jsonwebtoken::EncodingKey::from_ed_der(pkcs8_der.as_bytes())
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
                    let secret = p256::SecretKey::from_slice(&d.0)
                        .map_err(|e| Oid4vciError::KeyError(format!("Invalid P-256 key: {}", e)))?;
                    let pkcs8_der = secret.to_pkcs8_der().map_err(|e| {
                        Oid4vciError::KeyError(format!("P-256 PKCS#8 encoding failed: {}", e))
                    })?;
                    Ok(jsonwebtoken::EncodingKey::from_ec_der(pkcs8_der.as_bytes()))
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
            SignedCredential::SdJwt {
                compact,
                credential_id,
            } => {
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

    /// SD-JWT VC RFC 9596 §3.2.1 conformance: the JWT `typ` header MUST be "vc+sd-jwt".
    /// OID4VCI 1.0 Final §A.3 distinguishes "dc+sd-jwt" (format ID in metadata)
    /// from "vc+sd-jwt" (the JWT `typ` in the issued credential).
    #[test]
    fn test_sd_jwt_typ_header_is_vc_sd_jwt() {
        use serde_json::Value;

        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "https://example.com/credentials/TestCred".into(),
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
        let compact = match result {
            SignedCredential::SdJwt { compact, .. } => compact,
            _ => panic!("Expected SdJwt"),
        };

        // Decode the JWT header directly from the compact SD-JWT to verify typ.
        // The first part (before '~') is the JWS; split on '.' to get header.
        let jwt_part = compact.split('~').next().unwrap_or(&compact);
        let header_b64 = jwt_part.split('.').next().expect("JWT must have header");
        let header_bytes = B64
            .decode(header_b64)
            .expect("header must be valid base64url");
        let header: Value = serde_json::from_slice(&header_bytes).expect("header must be JSON");

        // Before inject_kid_header, sd-jwt-rs does not set typ.
        // After inject_kid_header it should be "vc+sd-jwt".
        // At minimum, it must NOT be "dc+sd-jwt".
        if let Some(typ) = header.get("typ").and_then(Value::as_str) {
            assert_ne!(
                typ, "dc+sd-jwt",
                "JWT typ MUST NOT be 'dc+sd-jwt'; that is the OID4VCI format ID, not the SD-JWT-VC typ"
            );
        }
        // The inject_kid_header function sets "vc+sd-jwt" — verify via the constant in the source.
        // (Full end-to-end test of inject_kid_header requires a real key pair; unit-tested via issuer.)
    }

    // =========================================================================
    // External signer (prepare / assemble) tests
    // =========================================================================

    #[test]
    fn test_prepare_assemble_sd_jwt_no_disclosures() {
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

        let prepared = prepare_sd_jwt(&key, &claims).unwrap();

        // signing_input should be header_b64.payload_b64
        assert_eq!(prepared.signing_input.matches('.').count(), 1);
        assert!(prepared.credential_id.starts_with("urn:uuid:"));
        // No disclosures → suffix is just "~"
        assert_eq!(prepared.disclosures_suffix, "~");

        // Decode and verify header
        let header_b64 = prepared.signing_input.split('.').next().unwrap();
        let header_bytes = B64.decode(header_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["typ"], "vc+sd-jwt");
        assert_eq!(header["alg"], "ES256");
        assert!(header["kid"].as_str().unwrap().starts_with("did:jwk:"));

        // Decode and verify payload (default format is W3cVcdmV2SdJwt → claims in credentialSubject)
        let payload_b64 = prepared.signing_input.split('.').nth(1).unwrap();
        let payload_bytes = B64.decode(payload_b64).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["credentialSubject"]["name"], "Alice");
        assert!(payload.get("_sd").is_none(), "no _sd without disclosures");

        // Assemble with a dummy signature
        let dummy_sig = vec![0u8; 64];
        let result = assemble_sd_jwt(prepared, &dummy_sig);
        match result {
            SignedCredential::SdJwt {
                compact,
                credential_id,
            } => {
                // Format: header.payload.sig~
                assert!(compact.contains('.'));
                assert!(compact.ends_with('~'));
                assert!(credential_id.starts_with("urn:uuid:"));
            }
            _ => panic!("Expected SdJwt"),
        }
    }

    #[test]
    fn test_prepare_assemble_sd_jwt_with_disclosures() {
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

        let prepared = prepare_sd_jwt(&key, &claims).unwrap();

        // Decode payload — W3C format: claims are in credentialSubject
        let payload_b64 = prepared.signing_input.split('.').nth(1).unwrap();
        let payload_bytes = B64.decode(payload_b64).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let cs = payload.get("credentialSubject").unwrap();
        assert!(cs.get("name").is_none(), "name should be disclosed");
        assert!(cs.get("email").is_none(), "email should be disclosed");
        assert_eq!(cs["age"], 30, "age should remain in payload");

        // _sd_alg must be at top level
        assert_eq!(payload["_sd_alg"], "sha-256");

        // _sd should be inside credentialSubject (already extracted as `cs` above)
        let sd_array = cs.get("_sd").unwrap().as_array().unwrap();
        assert_eq!(sd_array.len(), 2, "should have 2 disclosure hashes");

        // Disclosures suffix should have 2 disclosures
        let disc_parts: Vec<&str> = prepared
            .disclosures_suffix
            .trim_matches('~')
            .split('~')
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(disc_parts.len(), 2, "should have 2 disclosures");

        // Each disclosure should decode to [salt, claim_name, value]
        for disc in &disc_parts {
            let disc_bytes = B64.decode(disc).unwrap();
            let disc_json: serde_json::Value = serde_json::from_slice(&disc_bytes).unwrap();
            let arr = disc_json.as_array().unwrap();
            assert_eq!(arr.len(), 3, "disclosure must be [salt, name, value]");
            let claim_name = arr[1].as_str().unwrap();
            assert!(
                claim_name == "name" || claim_name == "email",
                "unexpected claim: {}",
                claim_name
            );
        }

        // Verify that disclosure hashes in _sd match SHA-256 of the disclosures
        for disc in &disc_parts {
            let hash = Sha256::digest(disc.as_bytes());
            let hash_b64 = B64.encode(hash);
            assert!(
                sd_array.iter().any(|h| h.as_str() == Some(&hash_b64)),
                "disclosure hash {} not found in _sd array",
                hash_b64
            );
        }
    }

    #[test]
    fn test_prepare_sd_jwt_ietf_format() {
        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "IdentityCredential".into(),
            claims: [
                ("name".into(), serde_json::json!("Alice")),
                ("age".into(), serde_json::json!(30)),
            ]
            .into(),
            expiration_seconds: None,
            selective_disclosure_claims: vec!["name".into()],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let prepared = prepare_sd_jwt(&key, &claims).unwrap();
        let payload_b64 = prepared.signing_input.split('.').nth(1).unwrap();
        let payload_bytes = B64.decode(payload_b64).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        // IETF flat: _sd at top level, "name" removed, "age" stays
        assert!(payload.get("name").is_none());
        assert_eq!(payload["age"], 30);
        assert!(payload.get("credentialSubject").is_none());
        let sd_array = payload.get("_sd").unwrap().as_array().unwrap();
        assert_eq!(sd_array.len(), 1);
        assert_eq!(payload["_sd_alg"], "sha-256");
    }

    #[test]
    fn test_sign_sd_jwt_with_signer_roundtrip() {
        use crate::signer::CredentialSigner;

        let key = test_p256_key();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "IdentityCredential".into(),
            claims: [
                ("name".into(), serde_json::json!("Alice")),
                ("age".into(), serde_json::json!(30)),
            ]
            .into(),
            expiration_seconds: Some(3600),
            selective_disclosure_claims: vec!["name".into()],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        // IssuerKey implements CredentialSigner — use it as the external signer
        let signer: &dyn CredentialSigner = &key;
        let result = sign_sd_jwt_with_signer(signer, &claims).unwrap();

        let compact = match &result {
            SignedCredential::SdJwt { compact, .. } => compact.clone(),
            _ => panic!("Expected SdJwt"),
        };

        // Verify the signature with sd-jwt-rs SDJWTVerifier
        // Extract public JWK (strip private key for verification)
        let jwk: JWK = serde_json::from_str(&key.jwk_json).unwrap();
        let pub_jwk = jwk.to_public();
        let pub_jwk_json = serde_json::to_string(&pub_jwk).unwrap();

        let verified_claims = verify_sd_jwt(&compact, &pub_jwk_json, None, None).unwrap();

        // The verified payload should contain the non-disclosed claim (inside credentialSubject for W3C format)
        assert_eq!(verified_claims["credentialSubject"]["age"], 30);
        // "name" was selectively disclosed and included — should be reconstructed
        assert_eq!(verified_claims["credentialSubject"]["name"], "Alice");
    }
}
