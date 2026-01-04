use serde::Deserialize;
use serde_json::{json, Value};

use marty_crypto::serialization::{load_public_key_pem, spki_to_raw_public_key};
use crate::error::{codes as error_codes, VerificationError, VerificationResult};
use crate::jwk::{base64url_encode, jws_sign, jws_verify, Jwk, JwsHeader};

use super::contexts::ob2_context_uri;
use super::types::{DocumentStore, OpenBadgesIssueResult, OpenBadgesVerificationResult};

const DEFAULT_HASH_ALG: &str = "sha256";

#[derive(Debug, Deserialize)]
struct IssueOb2Request {
    assertion: Value,
    #[serde(default)]
    recipient: Option<Ob2RecipientInput>,
    #[serde(default)]
    signing: Option<Ob2SigningOptions>,
}

#[derive(Debug, Deserialize)]
struct VerifyOb2Request {
    assertion: Value,
    #[serde(default)]
    document_store: Option<DocumentStore>,
    #[serde(default)]
    recipient_identity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Ob2RecipientInput {
    identity: String,
    #[serde(rename = "type")]
    identity_type: Option<String>,
    #[serde(default)]
    hashed: Option<bool>,
    #[serde(default)]
    salt: Option<String>,
    #[serde(default)]
    hash_alg: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Ob2SigningOptions {
    jwk: Value,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    creator: Option<String>,
    #[serde(default)]
    verification_type: Option<String>,
}

pub fn issue_ob2_json(request_json: &str) -> VerificationResult<String> {
    let req: IssueOb2Request = serde_json::from_str(request_json)
        .map_err(|e| VerificationError::open_badges(format!("Invalid OB2 issue request: {}", e)))?;

    let mut assertion = req.assertion;
    let mut warnings = Vec::new();

    if let Some(recipient) = req.recipient {
        let recipient_value = build_recipient(recipient, &mut warnings)?;
        set_value(&mut assertion, "recipient", recipient_value);
    }

    if let Some(signing) = req.signing {
        let signature = sign_assertion(&assertion, &signing, &mut warnings)?;
        set_value(&mut assertion, "signature", Value::String(signature));

        let verification = build_verification(&signing, &mut warnings);
        if !verification.is_null() {
            set_value(&mut assertion, "verification", verification);
        }
    }

    let result = OpenBadgesIssueResult {
        issued: true,
        version: "2.0".to_string(),
        credential: assertion,
        warnings,
    };

    serde_json::to_string(&result)
        .map_err(|e| VerificationError::open_badges(format!("Failed to serialize OB2 issue result: {}", e)))
}

pub fn verify_ob2_json(request_json: &str) -> VerificationResult<String> {
    let req: VerifyOb2Request = serde_json::from_str(request_json)
        .map_err(|e| VerificationError::open_badges(format!("Invalid OB2 verify request: {}", e)))?;

    let assertion = req.assertion;
    let store = req.document_store.unwrap_or_default();

    let mut errors = Vec::new();
    let mut error_codes_out = Vec::new();
    let mut warnings = Vec::new();

    if !has_context(&assertion, ob2_context_uri()) {
        push_error(
            &mut errors,
            &mut error_codes_out,
            error_codes::OPEN_BADGES_CONTEXT_MISSING,
            "Missing Open Badges v2 context",
        );
    }

    if !type_contains(&assertion, "Assertion") {
        push_error(
            &mut errors,
            &mut error_codes_out,
            error_codes::OPEN_BADGES_INVALID,
            "Assertion type missing",
        );
    }

    let badge = resolve_reference(
        assertion.get("badge"),
        &store,
        "badge",
        &mut errors,
        &mut error_codes_out,
    );
    let issuer = badge
        .as_ref()
        .and_then(|b| resolve_reference(b.get("issuer"), &store, "issuer", &mut errors, &mut error_codes_out));

    if let Some(recipient_identity) = req.recipient_identity.as_ref() {
        if let Some(recipient) = assertion.get("recipient").and_then(|v| v.as_object()) {
            if let Err(err) = verify_recipient_hash(recipient, recipient_identity) {
                errors.push(err.to_string());
                error_codes_out.push(err.code().to_string());
            }
        }
    }

    if should_verify_signature(&assertion) {
        match verify_signature(&assertion, &store) {
            Ok(warn) => {
                if let Some(w) = warn {
                    warnings.push(w);
                }
            }
            Err(err) => {
                errors.push(err.to_string());
                error_codes_out.push(err.code().to_string());
            }
        }
    } else if assertion.get("signature").is_some() {
        match verify_signature(&assertion, &store) {
            Ok(warn) => {
                if let Some(w) = warn {
                    warnings.push(w);
                }
            }
            Err(err) => {
                errors.push(err.to_string());
                error_codes_out.push(err.code().to_string());
            }
        }
    } else {
        warnings.push("Hosted assertion not cryptographically verified".to_string());
    }

    let normalized = normalize_ob2(&assertion, badge.as_ref(), issuer.as_ref());

    let result = OpenBadgesVerificationResult {
        valid: errors.is_empty(),
        version: "2.0".to_string(),
        errors,
        error_codes: error_codes_out,
        warnings,
        normalized: Some(normalized),
    };

    serde_json::to_string(&result)
        .map_err(|e| VerificationError::open_badges(format!("Failed to serialize OB2 verify result: {}", e)))
}

fn build_recipient(input: Ob2RecipientInput, warnings: &mut Vec<String>) -> VerificationResult<Value> {
    let hashed = input.hashed.unwrap_or(false);
    let hash_alg = input
        .hash_alg
        .unwrap_or_else(|| DEFAULT_HASH_ALG.to_string());

    let mut recipient = serde_json::Map::new();
    recipient.insert("type".to_string(), Value::String(input.identity_type.unwrap_or_else(|| "email".to_string())));

    if hashed {
        let salt = input.salt.unwrap_or_else(|| {
            warnings.push("Recipient hashed without salt; using empty salt".to_string());
            "".to_string()
        });
        let hashed_value = hash_identity(&hash_alg, &salt, &input.identity)?;
        recipient.insert("hashed".to_string(), Value::Bool(true));
        recipient.insert("salt".to_string(), Value::String(salt));
        recipient.insert("identity".to_string(), Value::String(hashed_value));
    } else {
        recipient.insert("identity".to_string(), Value::String(input.identity));
    }

    recipient.insert("hash".to_string(), Value::String(hash_alg));

    Ok(Value::Object(recipient))
}

fn sign_assertion(
    assertion: &Value,
    signing: &Ob2SigningOptions,
    warnings: &mut Vec<String>,
) -> VerificationResult<String> {
    let jwk_json = serde_json::to_string(&signing.jwk).map_err(|e| {
        VerificationError::open_badges(format!("Invalid signing JWK: {}", e))
    })?;
    let jwk = Jwk::from_json(&jwk_json)
        .map_err(|e| VerificationError::open_badges(format!("Invalid signing JWK: {}", e)))?;

    let alg = signing
        .alg
        .clone()
        .or_else(|| jwk.alg.clone())
        .unwrap_or_else(|| default_alg_for_jwk(&jwk));

    let mut header = JwsHeader::new(&alg);
    if let Some(kid) = signing.kid.clone().or_else(|| jwk.kid.clone()) {
        header.kid = Some(kid);
    }

    let mut payload = assertion.clone();
    if let Value::Object(ref mut obj) = payload {
        obj.remove("signature");
    }

    let payload_bytes = serde_json::to_vec(&payload).map_err(|e| {
        VerificationError::open_badges(format!("Failed to serialize assertion for signing: {}", e))
    })?;

    let signature = jws_sign(&header, &payload_bytes, &jwk)
        .map_err(|e| VerificationError::open_badges(format!("OB2 signing failed: {}", e)))?;

    if signing.creator.is_none() {
        warnings.push("Signed assertion missing verification.creator".to_string());
    }

    Ok(signature)
}

fn build_verification(signing: &Ob2SigningOptions, warnings: &mut Vec<String>) -> Value {
    let mut verification = serde_json::Map::new();
    let verification_type = signing
        .verification_type
        .clone()
        .unwrap_or_else(|| "signed".to_string());
    verification.insert("type".to_string(), Value::String(verification_type));

    if let Some(creator) = signing.creator.clone().or_else(|| signing.kid.clone()) {
        verification.insert("creator".to_string(), Value::String(creator));
    } else {
        warnings.push("verification.creator missing for signed assertion".to_string());
    }

    Value::Object(verification)
}

fn verify_signature(assertion: &Value, store: &DocumentStore) -> VerificationResult<Option<String>> {
    let signature = assertion
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerificationError::open_badges_signature_invalid(
                "Signed assertion missing signature".to_string(),
            )
        })?;

    let creator = assertion
        .get("verification")
        .and_then(|v| v.get("creator"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VerificationError::open_badges_signature_invalid(
                "Signed assertion missing verification.creator".to_string(),
            )
        })?;

    let key_value = store
        .get(creator)
        .ok_or_else(|| {
            VerificationError::open_badges_document_missing(format!(
                "verification.creator not found in document_store: {}",
                creator
            ))
        })?;

    let jwk = extract_public_jwk(key_value)?;

    let (_, payload_bytes) = jws_verify(signature, &jwk)
        .map_err(|e| {
            VerificationError::open_badges_signature_invalid(format!(
                "JWS verification failed: {}",
                e
            ))
        })?;

    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| {
            VerificationError::open_badges(format!("Signed payload is not JSON: {}", e))
        })?;

    let mut expected = assertion.clone();
    if let Value::Object(ref mut obj) = expected {
        obj.remove("signature");
    }

    if payload != expected {
        Ok(Some("Signed payload does not match assertion body".to_string()))
    } else {
        Ok(None)
    }
}

fn extract_public_jwk(value: &Value) -> VerificationResult<Jwk> {
    if let Some(jwk_value) = value.get("publicKeyJwk") {
        let jwk_json = serde_json::to_string(jwk_value)
            .map_err(|e| {
                VerificationError::open_badges(format!("Invalid publicKeyJwk: {}", e))
            })?;
        return Jwk::from_json(&jwk_json);
    }

    if let Some(pem) = value.get("publicKeyPem").and_then(|v| v.as_str()) {
        return jwk_from_pem(pem);
    }

    if let Some(public_key) = value.get("publicKey") {
        if let Some(pem) = public_key.as_str() {
            return jwk_from_pem(pem);
        }
        let jwk_json = serde_json::to_string(public_key)
            .map_err(|e| VerificationError::open_badges(format!("Invalid publicKey: {}", e)))?;
        return Jwk::from_json(&jwk_json);
    }

    Err(VerificationError::open_badges_unsupported(
        "Unsupported verification key format".to_string(),
    ))
}

fn jwk_from_pem(pem: &str) -> VerificationResult<Jwk> {
    let spki = load_public_key_pem(pem)?;
    jwk_from_spki(&spki)
}

fn jwk_from_spki(spki: &[u8]) -> VerificationResult<Jwk> {
    let (raw, key_type) = spki_to_raw_public_key(spki)?;

    match key_type.as_str() {
        "EC_P256" => jwk_from_ec("P-256", &raw),
        "EC_P384" => jwk_from_ec("P-384", &raw),
        "EC_P521" => jwk_from_ec("P-521", &raw),
        "Ed25519" => {
            Ok(Jwk {
                kty: "OKP".to_string(),
                crv: Some("Ed25519".to_string()),
                x: Some(base64url_encode(&raw)),
                ..Jwk::default()
            })
        }
        "RSA" => jwk_from_rsa(&raw),
        _ => Err(VerificationError::open_badges_unsupported(format!(
            "Unsupported public key type: {}",
            key_type
        ))),
    }
}

fn jwk_from_ec(curve: &str, raw: &[u8]) -> VerificationResult<Jwk> {
    let (x, y) = match curve {
        "P-256" => {
            let point = p256::EncodedPoint::from_bytes(raw)
                .map_err(|e| VerificationError::open_badges(format!("Invalid P-256 key: {}", e)))?;
            let x = point
                .x()
                .ok_or_else(|| VerificationError::open_badges("Missing P-256 x".to_string()))?;
            let y = point
                .y()
                .ok_or_else(|| VerificationError::open_badges("Missing P-256 y".to_string()))?;
            (x.to_vec(), y.to_vec())
        }
        "P-384" => {
            let point = p384::EncodedPoint::from_bytes(raw)
                .map_err(|e| VerificationError::open_badges(format!("Invalid P-384 key: {}", e)))?;
            let x = point
                .x()
                .ok_or_else(|| VerificationError::open_badges("Missing P-384 x".to_string()))?;
            let y = point
                .y()
                .ok_or_else(|| VerificationError::open_badges("Missing P-384 y".to_string()))?;
            (x.to_vec(), y.to_vec())
        }
        "P-521" => {
            let point = p521::EncodedPoint::from_bytes(raw)
                .map_err(|e| VerificationError::open_badges(format!("Invalid P-521 key: {}", e)))?;
            let x = point
                .x()
                .ok_or_else(|| VerificationError::open_badges("Missing P-521 x".to_string()))?;
            let y = point
                .y()
                .ok_or_else(|| VerificationError::open_badges("Missing P-521 y".to_string()))?;
            (x.to_vec(), y.to_vec())
        }
        _ => {
            return Err(VerificationError::open_badges_unsupported(format!(
                "Unsupported EC curve: {}",
                curve
            )))
        }
    };

    Ok(Jwk {
        kty: "EC".to_string(),
        crv: Some(curve.to_string()),
        x: Some(base64url_encode(&x)),
        y: Some(base64url_encode(&y)),
        ..Jwk::default()
    })
}

fn jwk_from_rsa(raw: &[u8]) -> VerificationResult<Jwk> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::traits::PublicKeyParts;

    let key = rsa::RsaPublicKey::from_pkcs1_der(raw)
        .map_err(|e| VerificationError::open_badges(format!("Invalid RSA public key: {}", e)))?;

    let n = key.n().to_bytes_be();
    let e = key.e().to_bytes_be();

    Ok(Jwk {
        kty: "RSA".to_string(),
        n: Some(base64url_encode(&n)),
        e: Some(base64url_encode(&e)),
        ..Jwk::default()
    })
}

fn verify_recipient_hash(
    recipient: &serde_json::Map<String, Value>,
    identity: &str,
) -> VerificationResult<()> {
    let hashed = recipient.get("hashed").and_then(|v| v.as_bool()).unwrap_or(false);
    if !hashed {
        return Ok(());
    }

    let salt = recipient
        .get("salt")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let hash_alg = recipient
        .get("hash")
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_HASH_ALG);
    let expected = hash_identity(hash_alg, salt, identity)?;

    let actual = recipient
        .get("identity")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if expected != actual {
        Err(VerificationError::open_badges(
            "Recipient hash does not match provided identity".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn hash_identity(hash_alg: &str, salt: &str, identity: &str) -> VerificationResult<String> {
    let input = format!("{}{}", salt, identity);

    let digest = match hash_alg.to_lowercase().as_str() {
        "sha1" => {
            use sha1::Digest;
            let mut hasher = sha1::Sha1::new();
            hasher.update(input.as_bytes());
            hasher.finalize().to_vec()
        }
        "sha256" => {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(input.as_bytes());
            hasher.finalize().to_vec()
        }
        "sha512" => {
            use sha2::Digest;
            let mut hasher = sha2::Sha512::new();
            hasher.update(input.as_bytes());
            hasher.finalize().to_vec()
        }
        _ => {
            return Err(VerificationError::open_badges_unsupported(format!(
                "Unsupported hash algorithm: {}",
                hash_alg
            )))
        }
    };

    Ok(hex::encode(digest))
}

fn has_context(value: &Value, context_uri: &str) -> bool {
    match value.get("@context") {
        Some(Value::String(ctx)) => ctx == context_uri,
        Some(Value::Array(contexts)) => contexts
            .iter()
            .any(|ctx| ctx.as_str().map(|s| s == context_uri).unwrap_or(false)),
        _ => false,
    }
}

fn type_contains(value: &Value, type_name: &str) -> bool {
    match value.get("type") {
        Some(Value::String(t)) => t == type_name,
        Some(Value::Array(types)) => types
            .iter()
            .any(|t| t.as_str().map(|s| s == type_name).unwrap_or(false)),
        _ => false,
    }
}

fn push_error(
    errors: &mut Vec<String>,
    error_codes_out: &mut Vec<String>,
    code: &'static str,
    message: impl Into<String>,
) {
    errors.push(message.into());
    error_codes_out.push(code.to_string());
}

fn resolve_reference(
    value: Option<&Value>,
    store: &DocumentStore,
    field: &str,
    errors: &mut Vec<String>,
    error_codes_out: &mut Vec<String>,
) -> Option<Value> {
    match value {
        Some(Value::String(id)) => match store.get(id) {
            Some(doc) => Some(doc.clone()),
            None => {
                push_error(
                    errors,
                    error_codes_out,
                    error_codes::OPEN_BADGES_DOCUMENT_MISSING,
                    format!("{} reference not found in document_store: {}", field, id),
                );
                None
            }
        },
        Some(Value::Object(_)) => value.cloned(),
        Some(_) => {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_INVALID,
                format!("{} must be an object or string reference", field),
            );
            None
        }
        None => {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_INVALID,
                format!("{} missing from assertion", field),
            );
            None
        }
    }
}

fn should_verify_signature(assertion: &Value) -> bool {
    let verification_type = assertion
        .get("verification")
        .and_then(|v| v.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    matches!(verification_type.to_lowercase().as_str(), "signed" | "signedbadge")
}

fn normalize_ob2(assertion: &Value, badge: Option<&Value>, issuer: Option<&Value>) -> Value {
    json!({
        "assertion_id": assertion.get("id").cloned().unwrap_or(Value::Null),
        "badge_id": badge.and_then(|b| b.get("id")).cloned().unwrap_or(Value::Null),
        "issuer_id": issuer.and_then(|i| i.get("id")).cloned().unwrap_or(Value::Null),
        "recipient": assertion.get("recipient").cloned().unwrap_or(Value::Null),
    })
}

fn set_value(target: &mut Value, key: &str, value: Value) {
    if let Value::Object(ref mut map) = target {
        map.insert(key.to_string(), value);
    }
}

fn default_alg_for_jwk(jwk: &Jwk) -> String {
    match jwk.key_type() {
        crate::jwk::KeyType::EcP256 => "ES256".to_string(),
        crate::jwk::KeyType::EcP384 => "ES384".to_string(),
        crate::jwk::KeyType::EcP521 => "ES512".to_string(),
        crate::jwk::KeyType::Ed25519 => "EdDSA".to_string(),
        crate::jwk::KeyType::Rsa => "RS256".to_string(),
        _ => "ES256".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_hash_round_trip() {
        let recipient = Ob2RecipientInput {
            identity: "user@example.org".to_string(),
            identity_type: Some("email".to_string()),
            hashed: Some(true),
            salt: Some("salt".to_string()),
            hash_alg: Some("sha256".to_string()),
        };
        let mut warnings = Vec::new();
        let built = build_recipient(recipient, &mut warnings).unwrap();
        let obj = built.as_object().unwrap();
        let result = verify_recipient_hash(obj, "user@example.org");
        assert!(result.is_ok(), "expected hash verification to succeed");
    }
}
