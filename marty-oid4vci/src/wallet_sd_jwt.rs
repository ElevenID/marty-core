//! Verified SD-JWT presentation boundary for the wallet engine.

use base64::Engine as _;

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::types::SigningAlgorithm;

/// Issuer verification material returned by an SD-JWT key resolver.
///
/// The identity metadata is carried alongside the public JWK so the wallet can
/// fail closed if a resolver returns a key for a different issuer, key ID, or
/// JOSE algorithm than the credential's unverified key-selection context.
#[derive(Clone)]
pub struct ResolvedSdJwtIssuerKey {
    issuer: String,
    key_id: Option<String>,
    algorithm: SigningAlgorithm,
    public_jwk_json: String,
}

impl std::fmt::Debug for ResolvedSdJwtIssuerKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResolvedSdJwtIssuerKey([redacted])")
    }
}

impl ResolvedSdJwtIssuerKey {
    /// Construct resolved public verification material.
    pub fn new(
        issuer: impl Into<String>,
        key_id: Option<String>,
        algorithm: SigningAlgorithm,
        public_jwk_json: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            key_id,
            algorithm,
            public_jwk_json: public_jwk_json.into(),
        }
    }

    /// Issuer identifier to which the resolver bound this key.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Verification-method identifier to which the resolver bound this key.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// JOSE algorithm to which the resolver bound this key.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// Public-only JWK JSON used for issuer-signature verification.
    pub fn public_jwk_json(&self) -> &str {
        &self.public_jwk_json
    }
}

/// Resolve an issuer verification key from an unverified SD-JWT VC
/// key-selection context.
///
/// Implementations may consult a DID document, trusted issuer profile, or a
/// prevalidated local key set. Network and trust-policy decisions remain with
/// the caller; the wallet independently checks the returned binding metadata.
/// The `issuer`, `key_id`, and `algorithm` inputs are unverified key-selection
/// hints. A resolver must apply its own allowlist and SSRF policy and must not
/// treat those inputs as authenticated. After resolution,
/// [`WalletEngine::create_verified_sd_jwt_presentation`](crate::wallet::WalletEngine::create_verified_sd_jwt_presentation)
/// verifies the JWS before using its signed claims or the holder key.
pub trait SdJwtIssuerKeyResolver {
    fn resolve(
        &self,
        issuer: &str,
        key_id: Option<&str>,
        algorithm: SigningAlgorithm,
    ) -> Oid4vciResult<ResolvedSdJwtIssuerKey>;
}

struct SdJwtIssuerContext {
    issuer: String,
    key_id: Option<String>,
    algorithm: SigningAlgorithm,
    jose_algorithm: jsonwebtoken::Algorithm,
    payload: serde_json::Value,
}

/// Verify issuer and holder bindings before performing any KB-JWT signing.
pub(crate) fn create_verified_presentation(
    credential: &str,
    claims_to_disclose: &[String],
    nonce: &str,
    audience: &str,
    holder_jwk_json: &str,
    issuer_key_resolver: &dyn SdJwtIssuerKeyResolver,
) -> Oid4vciResult<String> {
    use sd_jwt_rs::{SDJWTHolder, SDJWTSerializationFormat};

    if nonce.trim().is_empty() {
        return Err(Oid4vciError::InvalidRequest(
            "SD-JWT presentation nonce must not be empty".into(),
        ));
    }
    if audience.trim().is_empty() {
        return Err(Oid4vciError::InvalidRequest(
            "SD-JWT presentation audience must not be empty".into(),
        ));
    }

    let issuer_context = parse_sd_jwt_issuer_context(credential)?;
    let resolved_key = issuer_key_resolver.resolve(
        &issuer_context.issuer,
        issuer_context.key_id.as_deref(),
        issuer_context.algorithm,
    )?;
    validate_resolved_sd_jwt_issuer_key(&issuer_context, &resolved_key)?;
    let decoding_key = sd_jwt_issuer_decoding_key(&issuer_context, &resolved_key)?;

    let expected_issuer = issuer_context.issuer.clone();
    let expected_key_id = issuer_context.key_id.clone();
    let expected_algorithm = issuer_context.jose_algorithm;
    let mut holder = SDJWTHolder::new(
        credential.to_string(),
        SDJWTSerializationFormat::Compact,
        Box::new(move |issuer, header| {
            if issuer == expected_issuer
                && header.kid.as_deref() == expected_key_id.as_deref()
                && header.alg == expected_algorithm
            {
                decoding_key.clone()
            } else {
                // The dependency's resolver callback cannot return an error.
                // An impossible second-context mismatch therefore receives a
                // key that deterministically fails signature verification.
                jsonwebtoken::DecodingKey::from_secret(&[])
            }
        }),
    )
    .map_err(|_| Oid4vciError::InvalidRequest("SD-JWT issuer verification failed".into()))?;

    let (encoding_key, holder_public_key) = verified_p256_holder_key(holder_jwk_json)?;
    validate_sd_jwt_holder_binding(&issuer_context.payload, &holder_public_key)?;

    let disclosures = claims_to_disclose
        .iter()
        .map(|claim| (claim.clone(), serde_json::Value::Bool(true)))
        .collect();
    holder
        .create_presentation(
            disclosures,
            Some(nonce.to_string()),
            Some(audience.to_string()),
            Some(encoding_key),
            Some("ES256".to_string()),
        )
        .map_err(|_| {
            Oid4vciError::SigningError("Verified SD-JWT presentation creation failed".into())
        })
}

fn parse_sd_jwt_issuer_context(credential: &str) -> Oid4vciResult<SdJwtIssuerContext> {
    let issuer_jws = credential
        .split('~')
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| {
            Oid4vciError::InvalidRequest("SD-JWT is missing its issuer-signed JWT".into())
        })?;
    let (header, payload) =
        crate::jose::decode_unverified_compact_jwt(issuer_jws).map_err(|_| {
            Oid4vciError::InvalidRequest(
                "Issuer-signed SD-JWT must be a unique-member compact JWS".into(),
            )
        })?;
    if header.get("crit").is_some() || header.get("b64").is_some() {
        return Err(Oid4vciError::InvalidRequest(
            "Issuer-signed SD-JWT uses unsupported critical JOSE parameters".into(),
        ));
    }
    match header.get("typ").and_then(serde_json::Value::as_str) {
        Some("vc+sd-jwt" | "dc+sd-jwt") => {}
        _ => {
            return Err(Oid4vciError::InvalidRequest(
                "Issuer-signed SD-JWT has a missing or unsupported protected `typ`".into(),
            ));
        }
    }
    let algorithm_name = header
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Oid4vciError::InvalidRequest(
                "Issuer-signed SD-JWT protected header is missing string `alg`".into(),
            )
        })?;
    let (algorithm, jose_algorithm) = supported_sd_jwt_issuer_algorithm(algorithm_name)?;
    let key_id = match header.get("kid") {
        None => None,
        Some(serde_json::Value::String(key_id)) if !key_id.is_empty() => Some(key_id.clone()),
        Some(_) => {
            return Err(Oid4vciError::InvalidRequest(
                "Issuer-signed SD-JWT protected `kid` must be a non-empty string".into(),
            ));
        }
    };
    let issuer = payload
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .filter(|issuer| !issuer.is_empty())
        .ok_or_else(|| {
            Oid4vciError::InvalidRequest("Issuer-signed SD-JWT is missing `iss`".into())
        })?;
    payload
        .get("vct")
        .and_then(serde_json::Value::as_str)
        .filter(|credential_type| !credential_type.trim().is_empty())
        .ok_or_else(|| {
            Oid4vciError::InvalidRequest(
                "Issuer-signed SD-JWT is missing non-empty string `vct`".into(),
            )
        })?;

    Ok(SdJwtIssuerContext {
        issuer: issuer.to_string(),
        key_id,
        algorithm,
        jose_algorithm,
        payload,
    })
}

fn supported_sd_jwt_issuer_algorithm(
    name: &str,
) -> Oid4vciResult<(SigningAlgorithm, jsonwebtoken::Algorithm)> {
    match name {
        "ES256" => Ok((SigningAlgorithm::ES256, jsonwebtoken::Algorithm::ES256)),
        "ES384" => Ok((SigningAlgorithm::ES384, jsonwebtoken::Algorithm::ES384)),
        "EdDSA" => Ok((SigningAlgorithm::EdDSA, jsonwebtoken::Algorithm::EdDSA)),
        "RS256" => Ok((SigningAlgorithm::RS256, jsonwebtoken::Algorithm::RS256)),
        _ => Err(Oid4vciError::InvalidRequest(format!(
            "Unsupported SD-JWT issuer algorithm: {name}"
        ))),
    }
}

fn validate_resolved_sd_jwt_issuer_key(
    context: &SdJwtIssuerContext,
    resolved: &ResolvedSdJwtIssuerKey,
) -> Oid4vciResult<()> {
    if resolved.issuer != context.issuer {
        return Err(Oid4vciError::KeyError(
            "Resolved SD-JWT key is bound to a different issuer".into(),
        ));
    }
    if resolved.key_id != context.key_id {
        return Err(Oid4vciError::KeyError(
            "Resolved SD-JWT key ID does not exactly match the protected `kid`".into(),
        ));
    }
    if resolved.algorithm != context.algorithm {
        return Err(Oid4vciError::KeyError(
            "Resolved SD-JWT key algorithm does not exactly match the protected `alg`".into(),
        ));
    }
    Ok(())
}

fn sd_jwt_issuer_decoding_key(
    context: &SdJwtIssuerContext,
    resolved: &ResolvedSdJwtIssuerKey,
) -> Oid4vciResult<jsonwebtoken::DecodingKey> {
    let public_jwk =
        crate::jose::parse_unique_object(resolved.public_jwk_json.as_bytes(), "issuer public JWK")
            .map_err(|_| Oid4vciError::KeyError("Invalid issuer public JWK".into()))?;
    let public_jwk_object = public_jwk
        .as_object()
        .ok_or_else(|| Oid4vciError::KeyError("Issuer public JWK must be a JSON object".into()))?;
    let parsed_jwk = crate::jose::validate_public_jwk(&public_jwk, context.algorithm.as_str())?;
    if let Some(jwk_key_id) = public_jwk_object.get("kid") {
        let jwk_key_id = jwk_key_id
            .as_str()
            .filter(|key_id| !key_id.is_empty())
            .ok_or_else(|| {
                Oid4vciError::KeyError(
                    "Issuer public JWK `kid` must be a non-empty string when present".into(),
                )
            })?;
        if Some(jwk_key_id) != context.key_id.as_deref() {
            return Err(Oid4vciError::KeyError(
                "Issuer public JWK `kid` does not match the protected `kid`".into(),
            ));
        }
    }

    let key_type = public_jwk_object
        .get("kty")
        .and_then(serde_json::Value::as_str);
    let curve = public_jwk_object
        .get("crv")
        .and_then(serde_json::Value::as_str);
    let key_family_matches = match context.algorithm {
        SigningAlgorithm::ES256 => key_type == Some("EC") && curve == Some("P-256"),
        SigningAlgorithm::ES384 => key_type == Some("EC") && curve == Some("P-384"),
        SigningAlgorithm::EdDSA => key_type == Some("OKP") && curve == Some("Ed25519"),
        SigningAlgorithm::RS256 => key_type == Some("RSA"),
        SigningAlgorithm::ES256K => false,
    };
    if !key_family_matches {
        return Err(Oid4vciError::KeyError(
            "Issuer public JWK type or curve is incompatible with the protected `alg`".into(),
        ));
    }

    jsonwebtoken::DecodingKey::from_jwk(&parsed_jwk).map_err(|error| {
        Oid4vciError::KeyError(format!("Failed to create issuer decoding key: {error}"))
    })
}

fn decode_p256_jwk_coordinate(value: &serde_json::Value, name: &str) -> Oid4vciResult<Vec<u8>> {
    let encoded = value
        .as_str()
        .ok_or_else(|| Oid4vciError::KeyError(format!("P-256 JWK is missing string `{name}`")))?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| {
            Oid4vciError::KeyError(format!("P-256 JWK `{name}` decode failed: {error}"))
        })?;
    if decoded.len() != 32 {
        return Err(Oid4vciError::KeyError(format!(
            "P-256 JWK `{name}` must encode exactly 32 bytes"
        )));
    }
    Ok(decoded)
}

fn verified_p256_holder_key(jwk_json: &str) -> Oid4vciResult<(jsonwebtoken::EncodingKey, Vec<u8>)> {
    use p256::pkcs8::EncodePrivateKey as _;

    let signing_key = crate::holder_key::p256_signing_key_from_private_jwk(jwk_json)?;
    let public_key = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let der = signing_key
        .to_pkcs8_der()
        .map_err(|error| Oid4vciError::KeyError(format!("PKCS#8 DER encoding failed: {error}")))?;
    Ok((
        jsonwebtoken::EncodingKey::from_ec_der(der.as_bytes()),
        public_key,
    ))
}

fn validate_sd_jwt_holder_binding(
    issuer_payload: &serde_json::Value,
    holder_public_key: &[u8],
) -> Oid4vciResult<()> {
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;

    let cnf_jwk = issuer_payload
        .get("cnf")
        .and_then(serde_json::Value::as_object)
        .and_then(|cnf| cnf.get("jwk"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            Oid4vciError::InvalidRequest(
                "Verified SD-JWT is missing an object-valued `cnf.jwk`".into(),
            )
        })?;
    crate::jose::validate_public_jwk(
        &serde_json::Value::Object(cnf_jwk.clone()),
        SigningAlgorithm::ES256.as_str(),
    )?;
    if cnf_jwk.get("kty").and_then(serde_json::Value::as_str) != Some("EC")
        || cnf_jwk.get("crv").and_then(serde_json::Value::as_str) != Some("P-256")
    {
        return Err(Oid4vciError::KeyError(
            "Verified SD-JWT `cnf.jwk` must be an EC P-256 public key".into(),
        ));
    }
    let x = decode_p256_jwk_coordinate(cnf_jwk.get("x").unwrap_or(&serde_json::Value::Null), "x")?;
    let y = decode_p256_jwk_coordinate(cnf_jwk.get("y").unwrap_or(&serde_json::Value::Null), "y")?;
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let bound_public_key = p256::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|error| Oid4vciError::KeyError(format!("Invalid `cnf.jwk` point: {error}")))?;
    if bound_public_key.to_encoded_point(false).as_bytes() != holder_public_key {
        return Err(Oid4vciError::KeyError(
            "Holder private key does not match the verified SD-JWT `cnf.jwk`".into(),
        ));
    }
    Ok(())
}
