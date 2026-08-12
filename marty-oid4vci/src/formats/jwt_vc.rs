//! W3C VC-JWT credential format (`jwt_vc_json`).
//!
//! Constructs and signs W3C Verifiable Credentials as JWTs per the
//! W3C VC Data Model 1.1 + JWT encoding (default), or VCDM v2 when
//! `credential_payload_format = W3cVcdmV2JwtVc`.
//!
//! VCDM v1  — `https://www.w3.org/2018/credentials/v1`, `issuanceDate`, `expirationDate`
//! VCDM v2  — `https://www.w3.org/ns/credentials/v2`,  `validFrom`,    `validUntil`

use base64::Engine;
use ssi_jwk::JWK;
use std::collections::HashMap;

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::signer::CredentialSigner;
use crate::types::{CredentialClaims, CredentialPayloadFormat, IssuerKey, SignedCredential};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
/// Canonical 1EdTech Open Badges 3.0 JSON-LD context.
pub const OPEN_BADGES_V3_CONTEXT: &str = "https://purl.imsglobal.org/spec/ob/v3p0/context.json";
/// Canonical W3C credential type for an Open Badges 3.0 credential.
pub const OPEN_BADGES_V3_CREDENTIAL_TYPE: &str = "OpenBadgeCredential";

/// Sign a W3C VC-JWT credential.
///
/// Branches on `claims.credential_payload_format`:
/// - `W3cVcdmV2JwtVc` → VCDM v2 (`validFrom`/`validUntil`, v2 `@context`)
/// - any other value  → VCDM v1 (`issuanceDate`/`expirationDate`, v1 `@context`)
pub fn sign_jwt_vc(
    issuer_key: &IssuerKey,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
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

    Ok(SignedCredential::JwtVcJson { jwt, credential_id })
}

/// Sign a W3C VC-JWT credential using any [`CredentialSigner`].
///
/// This is the BYOK-aware variant. For local JWK signing, pass an `&IssuerKey`.
/// For remote/KMS signing, pass a custom `CredentialSigner` implementation.
pub fn sign_jwt_vc_with_signer(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    let prepared = prepare_jwt_vc(signer, claims)?;
    let signature = signer.sign(prepared.signing_input.as_bytes())?;
    Ok(assemble_jwt_vc(prepared, &signature))
}

/// Intermediate state between JWT-VC preparation and signing.
///
/// Returned by [`prepare_jwt_vc()`] — the caller signs `signing_input`
/// and passes the result to [`assemble_jwt_vc()`].
pub struct PreparedJwtVc {
    /// The base64url-encoded `header.payload` string to be signed.
    pub signing_input: String,
    /// The credential ID (urn:uuid:...) assigned during preparation.
    pub credential_id: String,
}

/// Optional protocol fields used by external issuer profiles.
#[derive(Debug, Clone)]
pub struct JwtVcPreparationOptions {
    /// Preserve a service-assigned credential identifier when supplied.
    pub credential_id: Option<String>,
    /// Use this complete VCDM credential subject instead of deriving one from
    /// the flat claims map.
    pub credential_subject: Option<serde_json::Value>,
    /// Optional VCDM credential status object.
    pub credential_status: Option<serde_json::Value>,
    /// Bind the JWT `sub` claim to `CredentialClaims::subject_id`.
    pub include_subject_claim: bool,
    /// Include the credential identifier inside the VCDM object.
    pub include_vc_id: bool,
    /// Include `nbf` at the issuance instant.
    pub include_nbf: bool,
}

impl Default for JwtVcPreparationOptions {
    fn default() -> Self {
        Self {
            credential_id: None,
            credential_subject: None,
            credential_status: None,
            include_subject_claim: true,
            include_vc_id: true,
            include_nbf: false,
        }
    }
}

/// Apply the canonical Open Badges 3.0 JWT-VC profile before preparation.
///
/// This keeps the credential shape in the Rust protocol owner while allowing
/// callers to retain their application-level configuration identifiers. Flat
/// application claims are preserved on the `AchievementSubject`; only the
/// legacy `achievement_name` and `achievement_description` aliases are moved
/// into the required OB3 `achievement` object.
pub fn apply_open_badge_v3_profile(
    claims: &mut CredentialClaims,
    options: &mut JwtVcPreparationOptions,
    achievement_id: &str,
) -> Oid4vciResult<()> {
    url::Url::parse(achievement_id).map_err(|error| {
        Oid4vciError::InvalidRequest(format!(
            "Open Badges achievement_id must be an absolute URI: {error}"
        ))
    })?;

    let mut subject = options.credential_subject.take().unwrap_or_else(|| {
        serde_json::Value::Object(std::mem::take(&mut claims.claims).into_iter().collect())
    });
    let subject_object = subject.as_object_mut().ok_or_else(|| {
        Oid4vciError::InvalidRequest("Open Badges credentialSubject must be one JSON object".into())
    })?;

    if let Some(holder_id) = claims.subject_id.as_deref() {
        match subject_object.get("id").and_then(serde_json::Value::as_str) {
            Some(existing) if existing != holder_id => {
                return Err(Oid4vciError::InvalidRequest(
                    "Open Badges credentialSubject id does not match the holder".into(),
                ));
            }
            Some(_) => {}
            None if subject_object.contains_key("id") => {
                return Err(Oid4vciError::InvalidRequest(
                    "Open Badges credentialSubject id must be a string".into(),
                ));
            }
            None => {
                subject_object.insert("id".into(), serde_json::json!(holder_id));
            }
        }
    }
    ensure_required_type(subject_object, "AchievementSubject", "credentialSubject")?;

    let legacy_name = take_optional_non_empty_string(subject_object, "achievement_name")?;
    let legacy_description =
        take_optional_non_empty_string(subject_object, "achievement_description")?;
    let legacy_criteria = subject_object.remove("achievement_criteria");
    let achievement = subject_object
        .entry("achievement")
        .or_insert_with(|| serde_json::json!({}));
    let achievement_object = achievement.as_object_mut().ok_or_else(|| {
        Oid4vciError::InvalidRequest("Open Badges achievement must be an object".into())
    })?;

    match achievement_object
        .get("id")
        .and_then(serde_json::Value::as_str)
    {
        Some(existing) if existing != achievement_id => {
            return Err(Oid4vciError::InvalidRequest(
                "Open Badges achievement id conflicts with the selected template".into(),
            ));
        }
        Some(_) => {}
        None if achievement_object.contains_key("id") => {
            return Err(Oid4vciError::InvalidRequest(
                "Open Badges achievement id must be a string".into(),
            ));
        }
        None => {
            achievement_object.insert("id".into(), serde_json::json!(achievement_id));
        }
    }
    ensure_required_type(achievement_object, "Achievement", "achievement")?;
    merge_required_string(achievement_object, "name", legacy_name)?;
    merge_required_string(achievement_object, "description", legacy_description)?;
    if let Some(criteria) = legacy_criteria {
        if achievement_object
            .insert("criteria".into(), criteria)
            .is_some()
        {
            return Err(Oid4vciError::InvalidRequest(
                "Open Badges achievement criteria were supplied twice".into(),
            ));
        }
    }

    claims.credential_type = OPEN_BADGES_V3_CREDENTIAL_TYPE.into();
    claims
        .w3c_types
        .retain(|value| !matches!(value.as_str(), "open_badge" | "open_badge_v3"));
    if !claims
        .w3c_context
        .iter()
        .any(|value| value == OPEN_BADGES_V3_CONTEXT)
    {
        claims.w3c_context.push(OPEN_BADGES_V3_CONTEXT.into());
    }
    claims.claims.clear();
    options.credential_subject = Some(subject);
    Ok(())
}

/// Validate the canonical Open Badges 3.0 shape used by Marty's VC-JWT profile.
///
/// Cryptographic verification is intentionally outside this function. Callers
/// must invoke it only for a credential recovered from an authenticated JWT or
/// Data Integrity proof. Keeping the shape rules beside the issuer-side
/// profile builder prevents issuance and verification from drifting apart.
pub fn validate_open_badge_v3_profile(credential: &serde_json::Value) -> Oid4vciResult<()> {
    let credential = credential.as_object().ok_or_else(|| {
        Oid4vciError::InvalidRequest("Open Badges credential must be one JSON object".into())
    })?;

    require_string_array_member(
        credential.get("@context"),
        "https://www.w3.org/ns/credentials/v2",
        "credential @context",
    )?;
    require_string_array_member(
        credential.get("@context"),
        OPEN_BADGES_V3_CONTEXT,
        "credential @context",
    )?;
    require_string_array_member(
        credential.get("type"),
        "VerifiableCredential",
        "credential type",
    )?;
    require_string_array_member(
        credential.get("type"),
        OPEN_BADGES_V3_CREDENTIAL_TYPE,
        "credential type",
    )?;

    let subject = credential
        .get("credentialSubject")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            Oid4vciError::InvalidRequest(
                "Open Badges credentialSubject must be one JSON object".into(),
            )
        })?;
    require_string_array_member(
        subject.get("type"),
        "AchievementSubject",
        "credentialSubject type",
    )?;
    require_non_empty_string(subject.get("id"), "credentialSubject id")?;

    let achievement = subject
        .get("achievement")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            Oid4vciError::InvalidRequest("Open Badges achievement must be an object".into())
        })?;
    require_string_array_member(achievement.get("type"), "Achievement", "achievement type")?;
    let achievement_id = require_non_empty_string(achievement.get("id"), "achievement id")?;
    url::Url::parse(achievement_id).map_err(|error| {
        Oid4vciError::InvalidRequest(format!(
            "Open Badges achievement id must be an absolute URI: {error}"
        ))
    })?;
    require_non_empty_string(achievement.get("name"), "achievement name")?;
    require_non_empty_string(achievement.get("description"), "achievement description")?;
    Ok(())
}

fn require_non_empty_string<'a>(
    value: Option<&'a serde_json::Value>,
    label: &str,
) -> Oid4vciResult<&'a str> {
    value
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Oid4vciError::InvalidRequest(format!("Open Badges {label} must be a non-empty string"))
        })
}

fn require_string_array_member(
    value: Option<&serde_json::Value>,
    required: &str,
    label: &str,
) -> Oid4vciResult<()> {
    let values = match value {
        Some(serde_json::Value::String(value)) => vec![value.as_str()],
        Some(serde_json::Value::Array(values))
            if values.iter().all(serde_json::Value::is_string) =>
        {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect()
        }
        _ => {
            return Err(Oid4vciError::InvalidRequest(format!(
                "Open Badges {label} must be a string or array of strings"
            )))
        }
    };
    if values.contains(&required) {
        Ok(())
    } else {
        Err(Oid4vciError::InvalidRequest(format!(
            "Open Badges {label} must include {required}"
        )))
    }
}

fn take_optional_non_empty_string(
    object: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Oid4vciResult<Option<String>> {
    let Some(value) = object.remove(field) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    value.map(|value| Some(value.to_string())).ok_or_else(|| {
        Oid4vciError::InvalidRequest(format!("Open Badges {field} must be a non-empty string"))
    })
}

fn merge_required_string(
    object: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
    legacy_value: Option<String>,
) -> Oid4vciResult<()> {
    let existing = object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let (Some(existing), Some(legacy)) = (existing, legacy_value.as_deref()) {
        if existing != legacy {
            return Err(Oid4vciError::InvalidRequest(format!(
                "Open Badges achievement {field} conflicts with its legacy claim"
            )));
        }
    }
    if existing.is_none() {
        let value = legacy_value.ok_or_else(|| {
            Oid4vciError::InvalidRequest(format!("Open Badges achievement {field} is required"))
        })?;
        object.insert(field.into(), serde_json::json!(value));
    }
    Ok(())
}

fn ensure_required_type(
    object: &mut serde_json::Map<String, serde_json::Value>,
    required: &str,
    label: &str,
) -> Oid4vciResult<()> {
    match object.get_mut("type") {
        None => {
            object.insert("type".into(), serde_json::json!([required]));
        }
        Some(serde_json::Value::String(value)) if value == required => {}
        Some(serde_json::Value::String(value)) => {
            let existing = std::mem::take(value);
            object.insert("type".into(), serde_json::json!([existing, required]));
        }
        Some(serde_json::Value::Array(values)) => {
            if !values.iter().all(serde_json::Value::is_string) {
                return Err(Oid4vciError::InvalidRequest(format!(
                    "Open Badges {label} type must contain only strings"
                )));
            }
            if !values.iter().any(|value| value.as_str() == Some(required)) {
                values.push(serde_json::json!(required));
            }
        }
        Some(_) => {
            return Err(Oid4vciError::InvalidRequest(format!(
                "Open Badges {label} type must be a string or array"
            )));
        }
    }
    Ok(())
}

/// Prepare a JWT-VC for signing (build header + payload, but don't sign).
///
/// Returns a [`PreparedJwtVc`] whose `signing_input` field contains the
/// base64url-encoded `header.payload` ready for an external signer.
pub fn prepare_jwt_vc(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<PreparedJwtVc> {
    prepare_jwt_vc_with_options(signer, claims, JwtVcPreparationOptions::default())
}

/// Prepare a JWT-VC with explicit remote-issuer protocol fields.
pub fn prepare_jwt_vc_with_options(
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
    options: JwtVcPreparationOptions,
) -> Oid4vciResult<PreparedJwtVc> {
    let credential_id = options
        .credential_id
        .clone()
        .unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4()));
    let now = chrono::Utc::now();

    let credential_subject = if let Some(ref explicit) = options.credential_subject {
        explicit.clone()
    } else {
        let mut derived: HashMap<String, serde_json::Value> = claims.claims.clone();
        if let Some(ref subject_id) = claims.subject_id {
            derived.insert("id".to_string(), serde_json::json!(subject_id));
        }
        serde_json::to_value(derived).map_err(|error| {
            Oid4vciError::SigningError(format!("Credential subject serialization failed: {error}"))
        })?
    };

    let use_vcdm_v2 = claims.credential_payload_format == CredentialPayloadFormat::W3cVcdmV2JwtVc;

    let mut vc_types = vec!["VerifiableCredential".to_string()];
    if !claims.credential_type.is_empty() {
        vc_types.push(claims.credential_type.clone());
    }
    vc_types.extend(claims.w3c_types.iter().cloned());

    let vc = if use_vcdm_v2 {
        let valid_from = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut context = vec!["https://www.w3.org/ns/credentials/v2".to_string()];
        context.extend(claims.w3c_context.iter().cloned());
        let mut v = serde_json::json!({
            "@context": context,
            "type": vc_types,
            "issuer": signer.issuer_id(),
            "validFrom": valid_from,
            "credentialSubject": credential_subject,
        });
        if options.include_vc_id {
            v["id"] = serde_json::json!(credential_id);
        }
        if let Some(exp_secs) = claims.expiration_seconds {
            let valid_until = (now + chrono::Duration::seconds(exp_secs))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            v["validUntil"] = serde_json::json!(valid_until);
        }
        v
    } else {
        let issuance_date = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut v = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": vc_types,
            "issuer": signer.issuer_id(),
            "issuanceDate": issuance_date,
            "credentialSubject": credential_subject,
        });
        if options.include_vc_id {
            v["id"] = serde_json::json!(credential_id);
        }
        if let Some(exp_secs) = claims.expiration_seconds {
            let expiration_date = (now + chrono::Duration::seconds(exp_secs))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            v["expirationDate"] = serde_json::json!(expiration_date);
        }
        v
    };
    let mut vc = vc;
    if let Some(ref credential_status) = options.credential_status {
        vc["credentialStatus"] = credential_status.clone();
    }

    let mut payload = serde_json::json!({
        "iss": signer.issuer_id(),
        "iat": now.timestamp(),
        "jti": credential_id,
        "vc": vc,
    });
    if options.include_subject_claim {
        if let Some(ref subject_id) = claims.subject_id {
            payload["sub"] = serde_json::json!(subject_id);
        }
    }
    if options.include_nbf {
        payload["nbf"] = serde_json::json!(now.timestamp());
    }
    if let Some(exp_secs) = claims.expiration_seconds {
        payload["exp"] = serde_json::json!(now.timestamp() + exp_secs);
    }

    let alg_str = signer.algorithm().as_str();
    let header = serde_json::json!({
        "alg": alg_str,
        "typ": "vc+jwt",
        "kid": signer.kid_url()
    });

    let header_str = serde_json::to_string(&header)
        .map_err(|e| Oid4vciError::SigningError(format!("Header serialization failed: {}", e)))?;
    let payload_str = serde_json::to_string(&payload)
        .map_err(|e| Oid4vciError::SigningError(format!("Payload serialization failed: {}", e)))?;

    let header_b64 = B64.encode(header_str.as_bytes());
    let payload_b64 = B64.encode(payload_str.as_bytes());

    Ok(PreparedJwtVc {
        signing_input: format!("{}.{}", header_b64, payload_b64),
        credential_id,
    })
}

/// Assemble a signed JWT-VC from the prepared data and a raw signature.
///
/// The `signature` must be the raw bytes produced by signing
/// `prepared.signing_input` with the issuer's key.
pub fn assemble_jwt_vc(prepared: PreparedJwtVc, signature: &[u8]) -> SignedCredential {
    let signature_b64 = B64.encode(signature);
    SignedCredential::JwtVcJson {
        jwt: format!("{}.{}", prepared.signing_input, signature_b64),
        credential_id: prepared.credential_id,
    }
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
    let signature = crate::signer::sign_with_jwk(jwk, message.as_bytes())?;
    let signature_b64 = B64.encode(&signature);

    Ok(format!("{}.{}", message, signature_b64))
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

    #[test]
    fn open_badge_v3_profile_builds_canonical_achievement_subject() {
        let key = test_p256_key();
        let mut claims = CredentialClaims {
            subject_id: Some("did:key:holder".into()),
            credential_type: "open_badge".into(),
            claims: [
                (
                    "achievement_name".into(),
                    serde_json::json!("Marty Verified Member Badge"),
                ),
                (
                    "achievement_description".into(),
                    serde_json::json!("Membership verified by Marty"),
                ),
                ("email".into(), serde_json::json!("holder@example.test")),
                ("member_id".into(), serde_json::json!("member-1")),
            ]
            .into(),
            expiration_seconds: Some(3600),
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: CredentialPayloadFormat::W3cVcdmV2JwtVc,
            w3c_context: vec![],
            w3c_types: vec![],
        };
        let mut options = JwtVcPreparationOptions::default();
        apply_open_badge_v3_profile(
            &mut claims,
            &mut options,
            "https://issuer.example/credentials/marty-verified-member-badge",
        )
        .unwrap();

        let prepared = prepare_jwt_vc_with_options(&key, &claims, options).unwrap();
        let payload_segment = prepared.signing_input.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64.decode(payload_segment).unwrap()).unwrap();
        let vc = &payload["vc"];

        assert_eq!(
            vc["type"],
            serde_json::json!(["VerifiableCredential", "OpenBadgeCredential"])
        );
        assert_eq!(
            vc["@context"],
            serde_json::json!([
                "https://www.w3.org/ns/credentials/v2",
                OPEN_BADGES_V3_CONTEXT
            ])
        );
        assert_eq!(vc["credentialSubject"]["id"], "did:key:holder");
        assert_eq!(
            vc["credentialSubject"]["type"],
            serde_json::json!(["AchievementSubject"])
        );
        assert_eq!(
            vc["credentialSubject"]["achievement"]["type"],
            serde_json::json!(["Achievement"])
        );
        assert_eq!(
            vc["credentialSubject"]["achievement"]["name"],
            "Marty Verified Member Badge"
        );
        assert_eq!(
            vc["credentialSubject"]["achievement"]["description"],
            "Membership verified by Marty"
        );
        assert_eq!(
            vc["credentialSubject"]["achievement"]["id"],
            "https://issuer.example/credentials/marty-verified-member-badge"
        );
        assert_eq!(vc["credentialSubject"]["email"], "holder@example.test");
        assert_eq!(vc["credentialSubject"]["member_id"], "member-1");
        assert!(vc["credentialSubject"].get("achievement_name").is_none());
    }

    #[test]
    fn open_badge_v3_profile_rejects_missing_or_conflicting_achievement_data() {
        let mut claims = CredentialClaims {
            subject_id: Some("did:key:holder".into()),
            credential_type: "open_badge".into(),
            claims: [("achievement_name".into(), serde_json::json!("Badge"))].into(),
            expiration_seconds: None,
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: CredentialPayloadFormat::W3cVcdmV2JwtVc,
            w3c_context: vec![],
            w3c_types: vec![],
        };
        let mut options = JwtVcPreparationOptions::default();
        let error = apply_open_badge_v3_profile(
            &mut claims,
            &mut options,
            "https://issuer.example/achievement",
        )
        .unwrap_err();
        assert!(error.to_string().contains("description is required"));

        let mut claims = CredentialClaims {
            subject_id: Some("did:key:holder".into()),
            credential_type: "open_badge".into(),
            claims: HashMap::new(),
            expiration_seconds: None,
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: CredentialPayloadFormat::W3cVcdmV2JwtVc,
            w3c_context: vec![],
            w3c_types: vec![],
        };
        let mut options = JwtVcPreparationOptions {
            credential_subject: Some(serde_json::json!({
                "id": "did:key:other-holder",
                "achievement": {
                    "id": "https://issuer.example/achievement",
                    "type": "Achievement",
                    "name": "Badge",
                    "description": "Description"
                }
            })),
            ..Default::default()
        };
        let error = apply_open_badge_v3_profile(
            &mut claims,
            &mut options,
            "https://issuer.example/achievement",
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match the holder"));
    }

    #[test]
    fn open_badge_v3_profile_accepts_non_hierarchical_absolute_uris() {
        let mut claims = CredentialClaims {
            subject_id: Some("did:key:holder".into()),
            credential_type: "open_badge".into(),
            claims: [
                ("achievement_name".into(), serde_json::json!("Badge")),
                (
                    "achievement_description".into(),
                    serde_json::json!("Description"),
                ),
            ]
            .into(),
            expiration_seconds: None,
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: CredentialPayloadFormat::W3cVcdmV2JwtVc,
            w3c_context: vec![],
            w3c_types: vec![],
        };
        let mut options = JwtVcPreparationOptions::default();

        apply_open_badge_v3_profile(
            &mut claims,
            &mut options,
            "did:web:issuer.example:achievements:member",
        )
        .unwrap();

        assert_eq!(
            options.credential_subject.unwrap()["achievement"]["id"],
            "did:web:issuer.example:achievements:member"
        );
    }

    #[test]
    fn validates_canonical_open_badge_v3_profile_and_rejects_missing_semantics() {
        let credential = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                OPEN_BADGES_V3_CONTEXT
            ],
            "id": "urn:uuid:5cd704e2-9034-470a-b31e-e02d2f766d91",
            "type": ["VerifiableCredential", OPEN_BADGES_V3_CREDENTIAL_TYPE],
            "issuer": "did:web:issuer.example",
            "credentialSubject": {
                "id": "did:key:zHolder",
                "type": ["AchievementSubject"],
                "email": "holder@example.test",
                "achievement": {
                    "id": "https://issuer.example/achievements/member",
                    "type": ["Achievement"],
                    "name": "Verified Member",
                    "description": "Membership achievement"
                }
            }
        });
        validate_open_badge_v3_profile(&credential).unwrap();

        for pointer in [
            "/credentialSubject/id",
            "/credentialSubject/achievement/name",
            "/credentialSubject/achievement/description",
        ] {
            let mut malformed = credential.clone();
            *malformed.pointer_mut(pointer).unwrap() = serde_json::Value::Null;
            assert!(
                validate_open_badge_v3_profile(&malformed).is_err(),
                "{pointer}"
            );
        }

        let mut relative_achievement = credential;
        relative_achievement["credentialSubject"]["achievement"]["id"] =
            serde_json::json!("achievements/member");
        assert!(validate_open_badge_v3_profile(&relative_achievement).is_err());
    }
}
