//! Verify the production Open Badge VC-JWT profile with an independently
//! admitted issuer key. No network resolver or local signing belongs here.
use crate::jwt_vc_profile::{contains_type, selected_credential, validate_profile_header};
use crate::types::SigningAlgorithm;
use crate::{JwtVcProfileBinding, JwtVcSecuringProfile};
use crate::{Oid4vciError, Oid4vciResult, SdJwtIssuerKeyResolver};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Bounded evidence for exactly the authenticated compact JWT. This is Marty's
/// profile validation, not an Open Badges certification or an issuer trust grant.
#[derive(Clone, Debug, Serialize)]
pub struct VerifiedOpenBadgeJwt {
    kind: &'static str,
    credential_sha256: String,
    credential_id: String,
    issuer: String,
    verification_method_id: Option<String>,
    algorithm: String,
    achievement_id: String,
    evaluated_at: i64,
    expires_at: i64,
    issuer_signature_verified: bool,
    profile_validated: bool,
}

fn invalid() -> Oid4vciError {
    Oid4vciError::InvalidRequest("Open Badge JWT identity or validity binding failed".into())
}
fn text<'a>(value: &'a serde_json::Value, name: &str) -> Oid4vciResult<&'a str> {
    value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty() && s.trim() == *s && s.len() <= 2048)
        .ok_or_else(invalid)
}

/// The header and issuer are untrusted key-selection hints until the resolver
/// returns the exact issuer/kid/algorithm tuple and JOSE verifies the signature.
/// Claim time checks use the caller's explicit UTC epoch seconds.
/// Exact issuer-authenticated claims under an explicitly selected securing
/// profile. This does not establish issuer trust/authorization, status,
/// schema certification, holder possession or a relying-party decision.
pub struct AuthenticatedJwtVc {
    binding: JwtVcProfileBinding,
    credential_sha256: String,
    subject_id: String,
    credential_id: String,
    issuer: String,
    key_id: Option<String>,
    algorithm: String,
    evaluated_at: i64,
    signature_issued_at: i64,
    expires_at: i64,
    credential_valid_from: Option<chrono::DateTime<chrono::Utc>>,
    credential_valid_until: Option<chrono::DateTime<chrono::Utc>>,
    credential_dates_verified: bool,
    claims: serde_json::Value,
    vc: serde_json::Value,
}

impl AuthenticatedJwtVc {
    pub const fn binding(&self) -> JwtVcProfileBinding {
        self.binding
    }
    pub fn credential(&self) -> &serde_json::Value {
        &self.vc
    }
    pub fn claims(&self) -> &serde_json::Value {
        &self.claims
    }
    pub fn credential_sha256(&self) -> &str {
        &self.credential_sha256
    }
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
    pub fn verification_method_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
    pub const fn evaluated_at(&self) -> i64 {
        self.evaluated_at
    }
    pub const fn signature_issued_at(&self) -> i64 {
        self.signature_issued_at
    }
    pub const fn signature_expires_at(&self) -> i64 {
        self.expires_at
    }
    pub const fn credential_valid_from(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.credential_valid_from
    }
    pub const fn credential_valid_until(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.credential_valid_until
    }
    pub const fn credential_dates_verified(&self) -> bool {
        self.credential_dates_verified
    }

    fn open_badge(self) -> Oid4vciResult<VerifiedOpenBadgeJwt> {
        crate::formats::jwt_vc::validate_open_badge_v3_profile(&self.vc)?;
        let achievement = self
            .vc
            .get("credentialSubject")
            .and_then(|s| s.get("achievement"))
            .ok_or_else(invalid)?;
        let achievement_id = text(achievement, "id")?.to_owned();
        Ok(VerifiedOpenBadgeJwt {
            kind: "CORE_VERIFIED_OPEN_BADGE_V3_JWT_V1",
            credential_sha256: self.credential_sha256,
            credential_id: self.credential_id,
            issuer: self.issuer,
            verification_method_id: self.key_id,
            algorithm: self.algorithm,
            achievement_id,
            evaluated_at: self.evaluated_at,
            expires_at: self.expires_at,
            issuer_signature_verified: true,
            profile_validated: true,
        })
    }
}

impl std::fmt::Debug for AuthenticatedJwtVc {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedJwtVc")
            .field("binding", &self.binding)
            .field("credential_sha256", &self.credential_sha256)
            .field("contents", &"[redacted]")
            .finish()
    }
}

pub fn verify_open_badge_jwt(
    compact_jwt: &str,
    resolver: &dyn SdJwtIssuerKeyResolver,
    evaluated_at: i64,
) -> Oid4vciResult<VerifiedOpenBadgeJwt> {
    verify_jwt_vc(compact_jwt, resolver, evaluated_at)?.open_badge()
}

fn verify_jwt_vc(
    compact_jwt: &str,
    resolver: &dyn SdJwtIssuerKeyResolver,
    evaluated_at: i64,
) -> Oid4vciResult<AuthenticatedJwtVc> {
    verify_jwt_vc_internal(compact_jwt, resolver, evaluated_at, None)
}

/// Authenticate one exact selected profile. No shape detection or fallback is
/// permitted. Both JWT time and credential validity use `evaluated_at`.
pub fn verify_jwt_vc_with_profile(
    compact_jwt: &str,
    resolver: &dyn SdJwtIssuerKeyResolver,
    evaluated_at: i64,
    expected_profile: JwtVcSecuringProfile,
) -> Oid4vciResult<AuthenticatedJwtVc> {
    verify_jwt_vc_internal(compact_jwt, resolver, evaluated_at, Some(expected_profile))
}

/// Additionally require the bounded OB3 content profile after authenticating
/// the selected securing profile. This is not OB3 JWT proof certification.
pub fn verify_open_badge_jwt_with_profile(
    compact_jwt: &str,
    resolver: &dyn SdJwtIssuerKeyResolver,
    evaluated_at: i64,
    expected_profile: JwtVcSecuringProfile,
) -> Oid4vciResult<AuthenticatedJwtVc> {
    let verified =
        verify_jwt_vc_with_profile(compact_jwt, resolver, evaluated_at, expected_profile)?;
    crate::formats::jwt_vc::validate_open_badge_v3_profile(verified.credential())?;
    Ok(verified)
}

fn verify_jwt_vc_internal(
    compact_jwt: &str,
    resolver: &dyn SdJwtIssuerKeyResolver,
    evaluated_at: i64,
    expected_profile: Option<JwtVcSecuringProfile>,
) -> Oid4vciResult<AuthenticatedJwtVc> {
    let future_limit = evaluated_at
        .checked_add(30)
        .filter(|_| evaluated_at > 0)
        .ok_or_else(invalid)?;
    let (header, hints) = crate::jose::decode_unverified_compact_jwt(compact_jwt)?;
    if let Some(profile) = expected_profile {
        validate_profile_header(profile, &header, false)?;
        selected_credential(profile, &hints)?;
    }
    // Embedded material is never an alternative to the governed key resolver.
    if ["jwk", "jku", "x5c", "x5u"]
        .iter()
        .any(|k| header.get(k).is_some())
    {
        return Err(invalid());
    }
    let issuer = text(&hints, "iss")?;
    let kid = match header.get("kid") {
        None => None,
        Some(_) => Some(text(&header, "kid")?),
    };
    let algorithm = match text(&header, "alg")? {
        "ES256" => SigningAlgorithm::ES256,
        "ES384" => SigningAlgorithm::ES384,
        "EdDSA" => SigningAlgorithm::EdDSA,
        "RS256" => SigningAlgorithm::RS256,
        _ => return Err(invalid()),
    };
    let key = resolver.resolve(issuer, kid, algorithm)?;
    if key.issuer() != issuer || key.key_id() != kid || key.algorithm() != algorithm {
        return Err(invalid());
    }
    let verified = crate::jose::verify_compact_jwt_with_public_jwk(
        compact_jwt,
        key.public_jwk_json(),
        algorithm.as_str(),
    )?;
    let claims = &verified.claims;
    if text(claims, "iss")? != issuer {
        return Err(invalid());
    }
    if let Some(profile) = expected_profile {
        let checked = crate::jwt_vc_profile::validate_unsigned_jwt_vc_profile_claims(
            claims,
            evaluated_at,
            profile,
        )?;
        return Ok(AuthenticatedJwtVc {
            binding: JwtVcProfileBinding::new(profile),
            credential_sha256: format!("{:x}", Sha256::digest(compact_jwt.as_bytes())),
            subject_id: checked.subject_id.into(),
            credential_id: checked.credential_id.into(),
            issuer: checked.issuer.into(),
            key_id: kid.map(str::to_owned),
            algorithm: algorithm.as_str().into(),
            evaluated_at,
            signature_issued_at: checked.signature_issued_at,
            expires_at: checked.signature_expires_at,
            credential_valid_from: checked.credential_valid_from,
            credential_valid_until: checked.credential_valid_until,
            credential_dates_verified: true,
            claims: claims.clone(),
            vc: checked.credential.clone(),
        });
    }
    let issued = claims
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(invalid)?;
    let expires = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(invalid)?;
    if issued < 0 || issued > future_limit || expires <= evaluated_at || expires <= issued {
        return Err(invalid());
    }
    if let Some(value) = claims.get("nbf") {
        let not_before = value.as_i64().ok_or_else(invalid)?;
        if not_before < 0 || not_before > evaluated_at {
            return Err(invalid());
        }
    }
    let vc = claims.get("vc").ok_or_else(invalid)?;
    let has_credential_type = vc
        .get("type")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|kinds| {
            kinds
                .iter()
                .any(|kind| kind.as_str() == Some("VerifiableCredential"))
        });
    if !has_credential_type {
        return Err(invalid());
    }
    if vc
        .get("type")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|types| {
            types
                .iter()
                .any(|kind| kind.as_str() == Some("OpenBadgeCredential"))
        })
    {
        crate::formats::jwt_vc::validate_open_badge_v3_profile(vc)?;
    }
    let credential_id = text(claims, "jti")?;
    if text(vc, "id")? != credential_id {
        return Err(invalid());
    }
    let vc_issuer = vc.get("issuer").ok_or_else(invalid)?;
    let vc_issuer = vc_issuer
        .as_str()
        .or_else(|| vc_issuer.get("id").and_then(serde_json::Value::as_str))
        .ok_or_else(invalid)?;
    if vc_issuer != issuer {
        return Err(invalid());
    }
    let subject = vc.get("credentialSubject").ok_or_else(invalid)?;
    if let Some(value) = claims.get("sub") {
        if value.as_str() != Some(text(subject, "id")?) {
            return Err(invalid());
        }
    }
    Ok(AuthenticatedJwtVc {
        binding: JwtVcProfileBinding::new(JwtVcSecuringProfile::MartyNestedVc2JwtV1),
        credential_sha256: format!("{:x}", Sha256::digest(compact_jwt.as_bytes())),
        subject_id: text(subject, "id")?.into(),
        credential_id: credential_id.into(),
        issuer: issuer.into(),
        key_id: kid.map(str::to_owned),
        algorithm: algorithm.as_str().into(),
        evaluated_at,
        signature_issued_at: issued,
        expires_at: expires,
        credential_valid_from: None,
        credential_valid_until: None,
        credential_dates_verified: false,
        claims: claims.clone(),
        vc: vc.clone(),
    })
}

/// A verified VP proof plus one authenticated OpenBadge credential and an
/// exact self-certifying holder-key binding. Issuer trust and authorization
/// remain the relying party's separate governed policy decision.
#[derive(Clone, Serialize)]
pub struct VerifiedOpenBadgePresentation {
    credential: VerifiedOpenBadgeJwt,
    holder_binding_verified: bool,
    nonce_bound: bool,
    audience_bound: bool,
    #[serde(skip)]
    credential_jwt: String,
}

impl std::fmt::Debug for VerifiedOpenBadgePresentation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedOpenBadgePresentation")
            .field("credential", &self.credential)
            .field("holder_binding_verified", &self.holder_binding_verified)
            .field("nonce_bound", &self.nonce_bound)
            .field("audience_bound", &self.audience_bound)
            .field("credential_jwt", &"[redacted]")
            .finish()
    }
}

fn holder_key_binding(subject: &str, public: &serde_json::Value) -> Oid4vciResult<()> {
    let (_, resolved) = crate::proof::resolve_self_certifying_holder_key(subject)?;
    let resolved = resolved.ok_or_else(invalid)?;
    let supplied: ssi_jwk::JWK = serde_json::from_value(public.clone()).map_err(|_| invalid())?;
    if resolved.thumbprint().map_err(|_| invalid())?
        != supplied.thumbprint().map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    Ok(())
}

/// Authenticate one governed VC-JWT and prepare a short-lived,
/// nonce/audience-bound presentation for the existing opaque holder signer.
/// The issuer-signed subject must resolve to this holder public key; an
/// arbitrary bearer credential cannot be wrapped by a different holder.
#[cfg(feature = "wallet")]
pub fn prepare_verified_jwt_vc_presentation(
    compact_jwt: &str,
    resolver: &dyn SdJwtIssuerKeyResolver,
    nonce: &str,
    audience: &str,
    holder_public_jwk_json: &str,
) -> Oid4vciResult<crate::wallet::PreparedHolderProof> {
    use base64::Engine;
    use serde_json::json;
    if nonce.is_empty()
        || nonce.len() > 512
        || !nonce
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
        || audience.is_empty()
        || audience.len() > 2048
        || audience.chars().any(char::is_control)
        || holder_public_jwk_json.len() > crate::jose::MAX_PUBLIC_JWK_BYTES
    {
        return Err(invalid());
    }
    let now = chrono::Utc::now().timestamp();
    let verified = verify_jwt_vc(compact_jwt, resolver, now)?;
    if verified
        .vc
        .get("type")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|types| {
            types
                .iter()
                .any(|t| t.as_str() == Some("OpenBadgeCredential"))
        })
    {
        crate::formats::jwt_vc::validate_open_badge_v3_profile(&verified.vc)?;
    }
    let public =
        crate::jose::parse_unique_object(holder_public_jwk_json.as_bytes(), "holder public JWK")?;
    let algorithm = match (public["kty"].as_str(), public["crv"].as_str()) {
        (Some("EC"), Some("P-256")) => SigningAlgorithm::ES256,
        (Some("OKP"), Some("Ed25519")) => SigningAlgorithm::EdDSA,
        _ => return Err(invalid()),
    };
    crate::jose::validate_public_jwk(&public, algorithm.as_str())?;
    holder_key_binding(&verified.subject_id, &public)?;
    let header = json!({"alg":algorithm.as_str(),"typ":"JWT","jwk":public});
    let claims = json!({"iss":verified.subject_id,"sub":verified.subject_id,"aud":audience,"nonce":nonce,
        "iat":now,"nbf":now,"exp":verified.expires_at.min(now.checked_add(120).ok_or_else(invalid)?),
        "jti":format!("urn:uuid:{}",uuid::Uuid::new_v4()),
        "vp":{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiablePresentation"],
            "holder":verified.subject_id,"verifiableCredential":[compact_jwt]}});
    let claims_bytes = serde_json::to_vec(&claims).map_err(|_| invalid())?;
    if claims_bytes.len() > crate::jose::MAX_JWT_CLAIMS_BYTES {
        return Err(invalid());
    }
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    crate::wallet::PreparedHolderProof::from_signing_input(
        format!(
            "{}.{}",
            b64.encode(serde_json::to_vec(&header).map_err(|_| invalid())?),
            b64.encode(claims_bytes)
        ),
        holder_public_jwk_json.into(),
        algorithm,
    )
}

/// Verify the complete signed VP, exact transaction, independently admitted
/// issuer signature/profile, and credential-subject-to-holder key binding.
/// This composition does not grant issuer trust or an authenticated session.
/// An authenticated issuer credential bound to an authenticated transaction
/// and its self-certifying holder. Trust/authorization remain external policy.
pub struct VerifiedJwtVcPresentation {
    credential: AuthenticatedJwtVc,
    credential_jwt: String,
}
impl VerifiedJwtVcPresentation {
    /// The exact independently authenticated inner credential, for an existing
    /// credential-domain verifier; never serialize this bearer into reports.
    pub fn credential_jwt(&self) -> &str {
        &self.credential_jwt
    }
}
impl VerifiedOpenBadgePresentation {
    /// Exact authenticated inner credential; not a public diagnostic value.
    pub fn credential_jwt(&self) -> &str {
        &self.credential_jwt
    }
}
fn inner_credential(claims: &serde_json::Value) -> Oid4vciResult<&str> {
    let vp = claims.get("vp").ok_or_else(invalid)?;
    let credentials = vp
        .get("verifiableCredential")
        .and_then(serde_json::Value::as_array)
        .filter(|v| v.len() == 1)
        .ok_or_else(invalid)?;
    credentials[0].as_str().ok_or_else(invalid)
}
/// Bounded untrusted issuer-key selection hint only. The caller must use a
/// governed resolver, then verify the complete VP before consuming the VC.
pub fn presented_jwt_vc(vp_token: &str) -> Oid4vciResult<String> {
    let (_, claims) = crate::jose::decode_unverified_compact_jwt(vp_token)?;
    Ok(inner_credential(&claims)?.to_owned())
}
/// Verify one exact OpenBadge credential, its holder and transaction proof.
/// Does not grant issuer trust, lifecycle status or an authenticated session.
pub fn verify_open_badge_presentation(
    vp_token: &str,
    resolver: &dyn SdJwtIssuerKeyResolver,
    nonce: &str,
    audience: &str,
) -> Oid4vciResult<VerifiedOpenBadgePresentation> {
    let proof = verify_jwt_vc_presentation(vp_token, resolver, nonce, audience)?;
    Ok(VerifiedOpenBadgePresentation {
        credential: proof.credential.open_badge()?,
        credential_jwt: proof.credential_jwt,
        holder_binding_verified: true,
        nonce_bound: true,
        audience_bound: true,
    })
}

pub fn verify_jwt_vc_presentation(
    vp_token: &str,
    resolver: &dyn SdJwtIssuerKeyResolver,
    nonce: &str,
    audience: &str,
) -> Oid4vciResult<VerifiedJwtVcPresentation> {
    let engine = crate::verifier::VerificationEngine::new(audience, "");
    let outer = engine
        .verify_authenticated_vp_proof(vp_token, nonce)
        .map_err(|_| invalid())?;
    let claims = outer.claims();
    let now = chrono::Utc::now().timestamp();
    let issued = claims
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(invalid)?;
    let expires = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(invalid)?;
    if issued <= 0
        || issued > now.saturating_add(30)
        || now.saturating_sub(issued) > 120
        || expires <= now
        || expires > issued.saturating_add(120)
    {
        return Err(invalid());
    }

    let vp = claims.get("vp").ok_or_else(invalid)?;
    let has_type = vp
        .get("type")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|v| {
            v.iter()
                .any(|s| s.as_str() == Some("VerifiablePresentation"))
        });
    let credentials = vp
        .get("verifiableCredential")
        .and_then(serde_json::Value::as_array)
        .filter(|v| v.len() == 1)
        .ok_or_else(invalid)?;
    if !has_type {
        return Err(invalid());
    }
    let raw = credentials[0].as_str().ok_or_else(invalid)?;
    let credential = verify_jwt_vc(raw, resolver, chrono::Utc::now().timestamp())?;
    if text(claims, "iss")? != credential.subject_id
        || text(claims, "sub")? != credential.subject_id
        || text(vp, "holder")? != credential.subject_id
    {
        return Err(invalid());
    }
    holder_key_binding(&credential.subject_id, outer.signer_public_jwk())?;
    Ok(VerifiedJwtVcPresentation {
        credential,
        credential_jwt: raw.into(),
    })
}

/// A holder presentation awaiting the existing opaque signer. Negotiation is
/// retained alongside the bytes; preparation does not grant an RP decision.
#[cfg(feature = "wallet")]
#[derive(Debug)]
pub struct PreparedProfiledJwtVcPresentation {
    prepared: crate::wallet::PreparedHolderProof,
    binding: JwtVcProfileBinding,
}

#[cfg(feature = "wallet")]
impl PreparedProfiledJwtVcPresentation {
    pub const fn binding(&self) -> JwtVcProfileBinding {
        self.binding
    }
    pub fn signing_input(&self) -> &[u8] {
        self.prepared.signing_input()
    }
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.prepared.algorithm()
    }
    pub fn complete(self, signature: &[u8]) -> Oid4vciResult<SignedProfiledJwtVcPresentation> {
        Ok(SignedProfiledJwtVcPresentation {
            vp_token: self.prepared.complete(signature)?,
            binding: self.binding,
        })
    }
}

#[cfg(feature = "wallet")]
pub struct SignedProfiledJwtVcPresentation {
    vp_token: String,
    binding: JwtVcProfileBinding,
}

#[cfg(feature = "wallet")]
impl SignedProfiledJwtVcPresentation {
    pub const fn binding(&self) -> JwtVcProfileBinding {
        self.binding
    }
    pub fn vp_token(&self) -> &str {
        &self.vp_token
    }
}

#[cfg(feature = "wallet")]
impl std::fmt::Debug for SignedProfiledJwtVcPresentation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedProfiledJwtVcPresentation")
            .field("binding", &self.binding)
            .field("contents", &"[redacted]")
            .finish()
    }
}

/// Prepare a presentation only for the explicitly selected credential profile.
/// The direct profile embeds exact credential bytes in a VC2 envelope; it never
/// nests a legacy `vc`/`vp` claim or rewrites the issuer's signed artifact.
#[cfg(feature = "wallet")]
pub fn prepare_verified_jwt_vc_presentation_with_profile(
    compact_jwt: &str,
    resolver: &dyn SdJwtIssuerKeyResolver,
    nonce: &str,
    audience: &str,
    holder_public_jwk_json: &str,
    evaluated_at: i64,
    expected_profile: JwtVcSecuringProfile,
) -> Oid4vciResult<PreparedProfiledJwtVcPresentation> {
    use base64::Engine;
    use serde_json::json;
    if nonce.is_empty()
        || nonce.len() > 512
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
        || audience.is_empty()
        || audience.len() > 2048
        || audience.chars().any(char::is_control)
        || holder_public_jwk_json.len() > crate::jose::MAX_PUBLIC_JWK_BYTES
    {
        return Err(invalid());
    }
    let credential =
        verify_jwt_vc_with_profile(compact_jwt, resolver, evaluated_at, expected_profile)?;
    let public =
        crate::jose::parse_unique_object(holder_public_jwk_json.as_bytes(), "holder public JWK")?;
    let algorithm = match (public["kty"].as_str(), public["crv"].as_str()) {
        (Some("EC"), Some("P-256")) => SigningAlgorithm::ES256,
        (Some("OKP"), Some("Ed25519")) => SigningAlgorithm::EdDSA,
        _ => return Err(invalid()),
    };
    crate::jose::validate_public_jwk(&public, algorithm.as_str())?;
    holder_key_binding(&credential.subject_id, &public)?;
    let expires_at = credential
        .expires_at
        .min(evaluated_at.checked_add(120).ok_or_else(invalid)?)
        .min(
            credential
                .credential_valid_until
                .map_or(i64::MAX, |until| until.timestamp()),
        );
    if expires_at <= evaluated_at {
        return Err(invalid());
    }
    let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let mut presentation = json!({
        "@context": [crate::jwt_vc_profile::VC2_CONTEXT],
        "type": ["VerifiablePresentation"],
        "holder": credential.subject_id,
    });
    let mut claims = json!({
        "iss": credential.subject_id, "sub": credential.subject_id,
        "aud": audience, "nonce": nonce, "iat": evaluated_at,
        "exp": expires_at, "jti": id,
    });
    let header = match expected_profile {
        JwtVcSecuringProfile::MartyNestedVc2JwtV1 => {
            presentation["verifiableCredential"] = json!([compact_jwt]);
            claims["nbf"] = json!(evaluated_at);
            claims["vp"] = presentation;
            json!({"alg": algorithm.as_str(), "typ": "JWT", "jwk": public})
        }
        JwtVcSecuringProfile::W3cVc2Jose2026V1 => {
            presentation["id"] = json!(id);
            presentation["verifiableCredential"] = json!([{
                "@context": [crate::jwt_vc_profile::VC2_CONTEXT],
                "type": ["EnvelopedVerifiableCredential"],
                "id": format!("data:application/vc+jwt,{compact_jwt}"),
            }]);
            claims
                .as_object_mut()
                .ok_or_else(invalid)?
                .extend(presentation.as_object().ok_or_else(invalid)?.clone());
            json!({"alg": algorithm.as_str(), "typ": "vp+jwt", "cty": "vp", "jwk": public})
        }
    };
    let claims = serde_json::to_vec(&claims).map_err(|_| invalid())?;
    if claims.len() > crate::jose::MAX_JWT_CLAIMS_BYTES {
        return Err(invalid());
    }
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let prepared = crate::wallet::PreparedHolderProof::from_signing_input(
        format!(
            "{}.{}",
            b64.encode(serde_json::to_vec(&header).map_err(|_| invalid())?),
            b64.encode(claims)
        ),
        holder_public_jwk_json.into(),
        algorithm,
    )?;
    Ok(PreparedProfiledJwtVcPresentation {
        prepared,
        binding: credential.binding,
    })
}

fn selected_presentation(
    claims: &serde_json::Value,
    expected_profile: JwtVcSecuringProfile,
) -> Oid4vciResult<&serde_json::Value> {
    let presentation = match expected_profile {
        JwtVcSecuringProfile::MartyNestedVc2JwtV1 => {
            if ["vc", "@context", "type", "holder", "verifiableCredential"]
                .iter()
                .any(|name| claims.get(*name).is_some())
            {
                return Err(invalid());
            }
            claims
                .get("vp")
                .filter(|value| value.is_object())
                .ok_or_else(invalid)?
        }
        JwtVcSecuringProfile::W3cVc2Jose2026V1 => {
            if ["vc", "vp", "nbf", "_sd", "_sd_alg", "vct"]
                .iter()
                .any(|name| claims.get(*name).is_some())
                || text(claims, "id")? != text(claims, "jti")?
            {
                return Err(invalid());
            }
            crate::jwt_vc_profile::validate_direct_identifier(text(claims, "id")?)?;
            claims
        }
    };
    if presentation
        .get("@context")
        .and_then(serde_json::Value::as_array)
        .and_then(|contexts| contexts.first())
        .and_then(serde_json::Value::as_str)
        != Some(crate::jwt_vc_profile::VC2_CONTEXT)
        || !contains_type(presentation, "VerifiablePresentation")
        || contains_type(presentation, "VerifiableCredential")
    {
        return Err(invalid());
    }
    Ok(presentation)
}

fn inner_credential_with_profile(
    claims: &serde_json::Value,
    expected_profile: JwtVcSecuringProfile,
) -> Oid4vciResult<&str> {
    let presentation = selected_presentation(claims, expected_profile)?;
    let credentials = presentation
        .get("verifiableCredential")
        .and_then(serde_json::Value::as_array)
        .filter(|values| values.len() == 1)
        .ok_or_else(invalid)?;
    match expected_profile {
        JwtVcSecuringProfile::MartyNestedVc2JwtV1 => credentials[0].as_str().ok_or_else(invalid),
        JwtVcSecuringProfile::W3cVc2Jose2026V1 => {
            let envelope = credentials[0].as_object().ok_or_else(invalid)?;
            if envelope
                .keys()
                .any(|name| !matches!(name.as_str(), "@context" | "type" | "id"))
                || envelope.get("@context")
                    != Some(&serde_json::json!([crate::jwt_vc_profile::VC2_CONTEXT]))
                || !(envelope.get("type")
                    == Some(&serde_json::json!(["EnvelopedVerifiableCredential"]))
                    || envelope.get("type")
                        == Some(&serde_json::json!("EnvelopedVerifiableCredential")))
            {
                return Err(invalid());
            }
            envelope
                .get("id")
                .and_then(serde_json::Value::as_str)
                .and_then(|id| id.strip_prefix("data:application/vc+jwt,"))
                .filter(|token| !token.is_empty())
                .ok_or_else(invalid)
        }
    }
}

/// Untrusted key-selection hint for one explicit profile. A successful parse
/// is never issuer, holder, trust or policy evidence.
pub fn presented_jwt_vc_with_profile(
    vp_token: &str,
    expected_profile: JwtVcSecuringProfile,
) -> Oid4vciResult<String> {
    let (header, claims) = crate::jose::decode_unverified_compact_jwt(vp_token)?;
    validate_profile_header(expected_profile, &header, true)?;
    Ok(inner_credential_with_profile(&claims, expected_profile)?.to_owned())
}

/// Verified issuer credential and transaction-bound holder proof. Issuer trust,
/// credential status and the relying party's acceptance policy remain separate.
pub struct VerifiedProfiledJwtVcPresentation {
    credential: AuthenticatedJwtVc,
    credential_jwt: String,
    proof_issued_at: i64,
}

impl VerifiedProfiledJwtVcPresentation {
    pub fn credential(&self) -> &AuthenticatedJwtVc {
        &self.credential
    }
    pub fn credential_jwt(&self) -> &str {
        &self.credential_jwt
    }
    pub const fn proof_issued_at(&self) -> i64 {
        self.proof_issued_at
    }
    pub fn binding(&self) -> JwtVcProfileBinding {
        self.credential.binding()
    }
}

impl std::fmt::Debug for VerifiedProfiledJwtVcPresentation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedProfiledJwtVcPresentation")
            .field("binding", &self.binding())
            .field("contents", &"[redacted]")
            .finish()
    }
}

/// Authenticate a profile-bound VP and its exact credential at one instant.
/// A direct envelope cannot contain a historical nested credential, and neither
/// a bare credential nor a different profile can satisfy this presentation API.
pub fn verify_jwt_vc_presentation_with_profile(
    vp_token: &str,
    resolver: &dyn SdJwtIssuerKeyResolver,
    nonce: &str,
    audience: &str,
    evaluated_at: i64,
    expected_profile: JwtVcSecuringProfile,
) -> Oid4vciResult<VerifiedProfiledJwtVcPresentation> {
    let (header, hints) = crate::jose::decode_unverified_compact_jwt(vp_token)?;
    validate_profile_header(expected_profile, &header, true)?;
    inner_credential_with_profile(&hints, expected_profile)?;
    let engine = crate::verifier::VerificationEngine::new(audience, "");
    let outer = engine
        .verify_authenticated_vp_proof_at(vp_token, nonce, evaluated_at)
        .map_err(|_| invalid())?;
    let claims = outer.claims();
    let issued = claims
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(invalid)?;
    let expires = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(invalid)?;
    if issued <= 0
        || issued > evaluated_at.saturating_add(30)
        || evaluated_at.saturating_sub(issued) > 120
        || expires <= evaluated_at
        || expires <= issued
        || expires > issued.saturating_add(120)
    {
        return Err(invalid());
    }
    if claims.get("nbf").is_some_and(|value| {
        value.as_i64().is_none_or(|not_before| {
            not_before < 0 || not_before > evaluated_at || not_before >= expires
        })
    }) {
        return Err(invalid());
    }
    let presentation = selected_presentation(claims, expected_profile)?;
    let raw = inner_credential_with_profile(claims, expected_profile)?;
    let credential = verify_jwt_vc_with_profile(raw, resolver, evaluated_at, expected_profile)?;
    if text(claims, "iss")? != credential.subject_id
        || text(claims, "sub")? != credential.subject_id
        || text(presentation, "holder")? != credential.subject_id
    {
        return Err(invalid());
    }
    holder_key_binding(&credential.subject_id, outer.signer_public_jwk())?;
    Ok(VerifiedProfiledJwtVcPresentation {
        credential,
        credential_jwt: raw.into(),
        proof_issued_at: issued,
    })
}

pub fn verify_open_badge_presentation_with_profile(
    vp_token: &str,
    resolver: &dyn SdJwtIssuerKeyResolver,
    nonce: &str,
    audience: &str,
    evaluated_at: i64,
    expected_profile: JwtVcSecuringProfile,
) -> Oid4vciResult<VerifiedProfiledJwtVcPresentation> {
    let proof = verify_jwt_vc_presentation_with_profile(
        vp_token,
        resolver,
        nonce,
        audience,
        evaluated_at,
        expected_profile,
    )?;
    crate::formats::jwt_vc::validate_open_badge_v3_profile(proof.credential().credential())?;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ResolvedSdJwtIssuerKey, TrustedSdJwtIssuerKeys};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde_json::{json, Value};
    const NOW: i64 = 1_700_000_000;
    const ISSUER: &str = "did:web:issuer.example";
    const KID: &str = "did:web:issuer.example#key-1";
    fn claims() -> Value {
        json!({"iss":ISSUER,"iat":NOW-60,"exp":NOW+3600,"sub":"did:example:holder","jti":"urn:uuid:badge",
        "vc":{"@context":["https://www.w3.org/ns/credentials/v2",crate::formats::jwt_vc::OPEN_BADGES_V3_CONTEXT],
        "type":["VerifiableCredential","OpenBadgeCredential"],"id":"urn:uuid:badge","issuer":ISSUER,
        "credentialSubject":{"id":"did:example:holder","type":["AchievementSubject"],"achievement":{"id":"https://issuer.example/member","type":["Achievement"],"name":"Member","description":"Governed membership","criteria":{"narrative":"Complete membership verification"}}}}})
    }
    struct NeverResolve;
    impl SdJwtIssuerKeyResolver for NeverResolve {
        fn resolve(
            &self,
            _: &str,
            _: Option<&str>,
            _: SigningAlgorithm,
        ) -> Oid4vciResult<ResolvedSdJwtIssuerKey> {
            panic!("Malformed or embedded-key credential must not resolve");
        }
    }
    fn unsigned(header: Value, claims: Value) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
            URL_SAFE_NO_PAD.encode([0u8; 64])
        )
    }
    #[test]
    fn rejects_malformed_or_embedded_key_without_resolution() {
        assert!(verify_open_badge_jwt("not-a-jwt", &NeverResolve, NOW).is_err());
        assert!(verify_open_badge_jwt(
            &unsigned(json!({"alg":"HS256"}), claims()),
            &NeverResolve,
            NOW
        )
        .is_err());
        assert!(verify_open_badge_jwt(
            &unsigned(json!({"alg":"ES256","jwk":{"kty":"EC"}}), claims()),
            &NeverResolve,
            NOW
        )
        .is_err());
    }
    #[test]
    fn rejects_foreign_issuer_kid_or_algorithm_before_jose() {
        struct ForeignResolver(&'static str, &'static str, SigningAlgorithm);
        impl SdJwtIssuerKeyResolver for ForeignResolver {
            fn resolve(
                &self,
                _: &str,
                _: Option<&str>,
                _: SigningAlgorithm,
            ) -> Oid4vciResult<ResolvedSdJwtIssuerKey> {
                // Invalid public material is never reached: exact metadata
                // binding must reject each independent resolver mismatch first.
                Ok(ResolvedSdJwtIssuerKey::new(
                    self.0,
                    Some(self.1.into()),
                    self.2,
                    "{}",
                ))
            }
        }
        for resolver in [
            ForeignResolver("did:web:foreign.example", KID, SigningAlgorithm::ES256),
            ForeignResolver(
                ISSUER,
                "did:web:issuer.example#foreign",
                SigningAlgorithm::ES256,
            ),
            ForeignResolver(ISSUER, KID, SigningAlgorithm::ES384),
        ] {
            let error = verify_open_badge_jwt(
                &unsigned(json!({"alg":"ES256","kid":KID}), claims()),
                &resolver,
                NOW,
            )
            .unwrap_err();
            assert!(
                matches!(error, Oid4vciError::InvalidRequest(ref message) if message == "Open Badge JWT identity or validity binding failed")
            );
        }
    }

    #[cfg(feature = "wallet")]
    fn fresh_nonce() -> String {
        // Same CSPRNG primitive as the production OID4VCI nonce endpoint.
        uuid::Uuid::new_v4().to_string()
    }

    #[test]
    #[cfg(feature = "wallet")]
    fn refuses_missing_transaction_before_resolving_or_signing() {
        let nonce = fresh_nonce();
        let mut empty = nonce.clone();
        empty.clear();
        let invalid = format!("{nonce} ");
        for (nonce, audience) in [
            (empty.as_str(), "https://verifier.example"),
            (nonce.as_str(), ""),
            (invalid.as_str(), "https://verifier.example"),
        ] {
            assert!(prepare_verified_jwt_vc_presentation(
                &unsigned(json!({"alg":"ES256","kid":KID}), claims()),
                &NeverResolve,
                nonce,
                audience,
                "{}"
            )
            .is_err());
        }
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    #[cfg(feature = "wallet")]
    fn remote_holder_vp_binds_exact_badge_nonce_audience_and_subject_key() {
        let fixture = crate::openbao_transit::DisposableOpenBao::from_marked_env();
        let holder = fixture.create_es256();
        let holder_id = format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(holder.public_jwk()));
        let now = chrono::Utc::now().timestamp();
        let mut credential_claims = claims();
        credential_claims["iat"] = json!(now - 1);
        credential_claims["exp"] = json!(now + 3600);
        credential_claims["sub"] = json!(holder_id);
        credential_claims["vc"]["credentialSubject"]["id"] = json!(holder_id);
        let (token, keys) = signed(credential_claims);
        let transaction_nonce = fresh_nonce();
        let nonce = transaction_nonce.as_str();
        let audience = "https://verifier.example";
        let prepared = prepare_verified_jwt_vc_presentation(
            &token,
            &keys,
            nonce,
            audience,
            holder.public_jwk(),
        )
        .unwrap();
        let signature = holder.sign(prepared.signing_input()).unwrap();
        let vp = prepared.complete(&signature).unwrap();
        let proof = verify_open_badge_presentation(&vp, &keys, nonce, audience).unwrap();
        assert!(proof.holder_binding_verified && proof.nonce_bound && proof.audience_bound);
        let serialized = serde_json::to_string(&proof).unwrap();
        assert!(!serialized.contains(&token));
        assert!(!serialized.contains("verifiableCredential"));
        assert_eq!(
            proof.credential.credential_sha256,
            format!("{:x}", Sha256::digest(token.as_bytes()))
        );
        let mismatched_nonce = fresh_nonce();
        assert_ne!(nonce, mismatched_nonce);
        assert!(verify_open_badge_presentation(&vp, &keys, &mismatched_nonce, audience).is_err());
        assert!(
            verify_open_badge_presentation(&vp, &keys, nonce, "https://foreign.example").is_err()
        );
        let other = fixture.create_es256();
        assert!(prepare_verified_jwt_vc_presentation(
            &token,
            &keys,
            nonce,
            audience,
            other.public_jwk()
        )
        .is_err());
        let prepared = prepare_verified_jwt_vc_presentation(
            &token,
            &keys,
            nonce,
            audience,
            holder.public_jwk(),
        )
        .unwrap();
        assert!(prepared.complete(&[0; 64]).is_err());
        // A genuine holder signature cannot authenticate a changed issuer JWT.
        let (header, mut outer) = crate::jose::decode_unverified_compact_jwt(&vp).unwrap();
        let parts: Vec<_> = token.split('.').collect();
        outer["vp"]["verifiableCredential"][0] = json!(format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            URL_SAFE_NO_PAD.encode([0u8; 64])
        ));
        let changed = crate::jose::sign_test_compact_es256(&holder, &header, &outer);
        assert!(verify_open_badge_presentation(&changed, &keys, nonce, audience).is_err());
        outer["vp"]["verifiableCredential"] = json!([token, token]);
        let multiple = crate::jose::sign_test_compact_es256(&holder, &header, &outer);
        assert!(verify_open_badge_presentation(&multiple, &keys, nonce, audience).is_err());
        // Issuer-valid input whose nested VP would exceed the same shared
        // JOSE claim bound is refused before asking the holder KMS to sign.
        let (_, mut large_claims) = crate::jose::decode_unverified_compact_jwt(&token).unwrap();
        large_claims["padding"] = json!("x".repeat(52 * 1024));
        let (large, large_keys) = signed(large_claims);
        assert!(prepare_verified_jwt_vc_presentation(
            &large,
            &large_keys,
            nonce,
            audience,
            holder.public_jwk()
        )
        .is_err());
    }

    #[test]
    fn presentation_receipt_serialization_and_debug_redact_bearer() {
        let bearer = "private-credential-header.private-credential-payload.private-signature";
        let credential = AuthenticatedJwtVc {
            binding: JwtVcProfileBinding::new(JwtVcSecuringProfile::MartyNestedVc2JwtV1),
            credential_sha256: format!("{:x}", Sha256::digest(bearer.as_bytes())),
            subject_id: "did:example:holder".into(),
            credential_id: "urn:example:badge".into(),
            issuer: ISSUER.into(),
            key_id: Some(KID.into()),
            algorithm: "ES256".into(),
            evaluated_at: NOW,
            signature_issued_at: NOW - 60,
            expires_at: NOW + 3600,
            credential_valid_from: None,
            credential_valid_until: None,
            credential_dates_verified: false,
            claims: claims(),
            vc: claims()["vc"].clone(),
        }
        .open_badge()
        .unwrap();
        let proof = VerifiedOpenBadgePresentation {
            credential,
            holder_binding_verified: true,
            nonce_bound: true,
            audience_bound: true,
            credential_jwt: bearer.into(),
        };
        let serialized = serde_json::to_string(&proof).unwrap();
        let diagnostic = format!("{proof:?}");
        assert!(!serialized.contains(bearer));
        assert!(!serialized.contains("credential_jwt"));
        assert!(!diagnostic.contains(bearer));
        assert!(diagnostic.contains("[redacted]"));
        assert_eq!(proof.credential_jwt(), bearer);
    }

    #[test]
    fn issuer_selection_hint_is_bounded_and_selects_exactly_one_credential() {
        let one = unsigned(
            json!({"alg":"ES256"}),
            json!({"vp":{"verifiableCredential":["inner"]}}),
        );
        assert_eq!(presented_jwt_vc(&one).unwrap(), "inner");
        for values in [json!([]), json!(["a", "b"]), json!([null])] {
            let token = unsigned(
                json!({"alg":"ES256"}),
                json!({"vp":{"verifiableCredential":values}}),
            );
            assert!(presented_jwt_vc(&token).is_err());
        }
        assert!(presented_jwt_vc(&"x".repeat(crate::jose::MAX_COMPACT_JWT_BYTES + 1)).is_err());
    }

    fn signed(claims: Value) -> (String, TrustedSdJwtIssuerKeys) {
        let signer = crate::openbao_transit::DisposableOpenBao::from_marked_env().create_es256();
        let token = crate::jose::sign_test_compact_es256(
            &signer,
            &json!({"alg":"ES256","kid":KID,"typ":"JWT"}),
            &claims,
        );
        let keys = TrustedSdJwtIssuerKeys::new(vec![ResolvedSdJwtIssuerKey::new(
            ISSUER,
            Some(KID.into()),
            SigningAlgorithm::ES256,
            signer.public_jwk(),
        )])
        .unwrap();
        (token, keys)
    }

    fn profile_date(timestamp: i64) -> String {
        chrono::DateTime::from_timestamp(timestamp, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    fn direct_claims() -> Value {
        let historical = claims();
        let mut direct = historical["vc"].clone();
        for name in ["iss", "sub", "jti", "iat", "exp"] {
            direct[name] = historical[name].clone();
        }
        direct["validFrom"] = json!(profile_date(NOW - 3600));
        direct["validUntil"] = json!(profile_date(NOW + 86_400));
        direct
    }

    fn direct_header() -> Value {
        json!({"alg":"ES256", "kid":KID, "typ":"vc+jwt", "cty":"vc"})
    }

    #[test]
    fn explicit_profile_rejects_downgrade_and_mixed_claims_before_resolution() {
        let direct = JwtVcSecuringProfile::W3cVc2Jose2026V1;
        let historical = JwtVcSecuringProfile::MartyNestedVc2JwtV1;
        assert!(verify_jwt_vc_with_profile(
            &unsigned(direct_header(), direct_claims()),
            &NeverResolve,
            NOW,
            historical,
        )
        .is_err());
        assert!(verify_jwt_vc_with_profile(
            &unsigned(json!({"alg":"ES256", "typ":"JWT"}), claims()),
            &NeverResolve,
            NOW,
            direct,
        )
        .is_err());
        for name in ["vc", "vp", "nbf", "_sd", "_sd_alg", "vct"] {
            let mut mixed = direct_claims();
            mixed[name] = json!(null);
            assert!(
                verify_jwt_vc_with_profile(
                    &unsigned(direct_header(), mixed),
                    &NeverResolve,
                    NOW,
                    direct,
                )
                .is_err(),
                "mixed field {name}"
            );
        }
        for field in ["typ", "cty", "crit", "b64"] {
            let mut header = direct_header();
            header[field] = json!(null);
            assert!(
                verify_jwt_vc_with_profile(
                    &unsigned(header, direct_claims()),
                    &NeverResolve,
                    NOW,
                    direct,
                )
                .is_err(),
                "invalid header {field}"
            );
        }
        for context in [
            json!(null),
            json!(["https://www.w3.org/2018/credentials/v1"]),
            json!([
                "https://example.org/context",
                crate::jwt_vc_profile::VC2_CONTEXT
            ]),
        ] {
            let mut legacy = claims();
            legacy["vc"]["@context"] = context;
            assert!(verify_jwt_vc_with_profile(
                &unsigned(json!({"alg":"ES256", "typ":"JWT"}), legacy),
                &NeverResolve,
                NOW,
                historical,
            )
            .is_err());
        }
        for name in ["vc", "vp", "issuanceDate", "expirationDate"] {
            let mut mixed = claims();
            mixed["vc"][name] = json!(null);
            assert!(verify_jwt_vc_with_profile(
                &unsigned(json!({"alg":"ES256", "typ":"JWT"}), mixed),
                &NeverResolve,
                NOW,
                historical,
            )
            .is_err());
        }
    }

    #[test]
    fn direct_profile_rejects_invalid_raw_identifiers_before_resolution() {
        let profile = JwtVcSecuringProfile::W3cVc2Jose2026V1;
        let invalid_ids = [
            "did:exam\nple:holder",
            "https://issuer.example/a\tb",
            "urn:credential:has space",
            "urn:credential:control\u{7f}",
            "https://issuer.example/a\\b",
            "https://issuer.example/a\"b",
            "urn:credential:<bad>",
            "urn:credential:%zz",
            "urn:credential:trailing%",
            "urn:credential:short%2",
            "urn:credential:[bad]",
            "urn:credential:caf\u{e9}",
            "https://first@second@issuer.example/credential",
        ];
        for bad in invalid_ids {
            for field in ["id", "issuer", "credentialSubject"] {
                let mut claims = direct_claims();
                match field {
                    "id" => {
                        claims["id"] = json!(bad);
                        claims["jti"] = json!(bad);
                    }
                    "issuer" => {
                        claims["issuer"] = json!({"id":bad});
                        claims["iss"] = json!(bad);
                    }
                    _ => {
                        claims["credentialSubject"]["id"] = json!(bad);
                        claims["sub"] = json!(bad);
                    }
                }
                assert!(
                    verify_jwt_vc_with_profile(
                        &unsigned(direct_header(), claims),
                        &NeverResolve,
                        NOW,
                        profile,
                    )
                    .is_err(),
                    "invalid raw {field}: {bad:?}"
                );
            }
        }
        let credential = unsigned(direct_header(), direct_claims());
        for id in [
            "urn:example:presentation",
            "did:example:Presentation",
            "https://Issuer.Example/CaseSensitive",
            "https://issuer.example/a%20b",
            "urn:credential:escaped%3Cvalue%3E",
            "https://[2001:db8::1]/credential",
        ] {
            let mut valid = direct_claims();
            valid["id"] = json!(id);
            valid["jti"] = json!(id);
            valid["issuer"] = json!({"id": id});
            valid["iss"] = json!(id);
            valid["credentialSubject"]["id"] = json!(id);
            valid["sub"] = json!(id);
            let (_, admitted) = crate::jwt_vc_profile::decode_unverified_jwt_vc(
                &unsigned(direct_header(), valid.clone()),
                profile,
            )
            .unwrap();
            assert_eq!(admitted, valid, "raw identifier spelling must be retained");
            let claims = json!({
                "@context":[crate::jwt_vc_profile::VC2_CONTEXT],
                "type":["VerifiablePresentation"], "id":id, "jti":id,
                "verifiableCredential":[{
                    "@context":[crate::jwt_vc_profile::VC2_CONTEXT],
                    "type":["EnvelopedVerifiableCredential"],
                    "id":format!("data:application/vc+jwt,{credential}"),
                }],
            });
            let header = json!({"alg":"ES256","typ":"vp+jwt","cty":"vp"});
            assert_eq!(
                presented_jwt_vc_with_profile(&unsigned(header.clone(), claims.clone()), profile)
                    .unwrap(),
                credential
            );
            for bad in invalid_ids {
                let mut changed = claims.clone();
                changed["id"] = json!(bad);
                changed["jti"] = json!(bad);
                assert!(
                    presented_jwt_vc_with_profile(&unsigned(header.clone(), changed), profile,)
                        .is_err(),
                    "invalid raw presentation identifier: {bad:?}"
                );
            }
        }
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn remote_direct_profile_authenticates_exact_claims_and_independent_validity() {
        let signer = crate::openbao_transit::DisposableOpenBao::from_marked_env().create_es256();
        let keys = TrustedSdJwtIssuerKeys::new(vec![ResolvedSdJwtIssuerKey::new(
            ISSUER,
            Some(KID.into()),
            SigningAlgorithm::ES256,
            signer.public_jwk(),
        )])
        .unwrap();
        let sign = |header: &Value, payload: &Value| {
            crate::jose::sign_test_compact_es256(&signer, header, payload)
        };
        let profile = JwtVcSecuringProfile::W3cVc2Jose2026V1;
        let original = direct_claims();
        let token = sign(&direct_header(), &original);
        let proof = verify_open_badge_jwt_with_profile(&token, &keys, NOW, profile).unwrap();
        assert_eq!(proof.claims(), &original);
        assert_eq!(proof.credential(), &original);
        assert_eq!(proof.binding(), JwtVcProfileBinding::new(profile));
        assert_eq!(proof.signature_expires_at(), NOW + 3600);
        assert_eq!(
            proof.credential_valid_until().unwrap().timestamp(),
            NOW + 86_400
        );
        assert_eq!(proof.evaluated_at(), NOW);
        assert!(proof.credential_dates_verified());
        assert_eq!(
            proof.credential_sha256(),
            format!("{:x}", Sha256::digest(token.as_bytes()))
        );
        assert!(!format!("{proof:?}").contains(&token));
        assert!(verify_open_badge_jwt(&token, &keys, NOW).is_err());
        assert!(verify_jwt_vc_with_profile(
            &token,
            &keys,
            NOW,
            JwtVcSecuringProfile::MartyNestedVc2JwtV1
        )
        .is_err());

        // Every negative is freshly signed by the same remote issuer. A
        // signature-valid JWT cannot override VC validity or an alias conflict.
        for (name, value) in [
            ("validUntil", json!(profile_date(NOW))),
            ("validFrom", json!(profile_date(NOW + 1))),
            ("validFrom", json!(17)),
            ("issuer", json!("did:web:foreign.example")),
            ("id", json!("urn:uuid:other")),
            ("sub", json!("did:example:other")),
            ("nbf", json!(NOW - 60)),
            ("vc", json!({})),
            ("vp", json!({})),
            ("exp", json!(NOW)),
            ("iat", json!(NOW + 31)),
        ] {
            let mut changed = original.clone();
            changed[name] = value;
            let rejected = sign(&direct_header(), &changed);
            assert!(
                verify_jwt_vc_with_profile(&rejected, &keys, NOW, profile).is_err(),
                "signed {name} conflict"
            );
        }
        let mut missing_date = original.clone();
        missing_date.as_object_mut().unwrap().remove("validFrom");
        assert!(verify_jwt_vc_with_profile(
            &sign(&direct_header(), &missing_date),
            &keys,
            NOW,
            profile
        )
        .is_err());
        let mut incomplete_badge = original.clone();
        incomplete_badge["credentialSubject"]["achievement"]
            .as_object_mut()
            .unwrap()
            .remove("criteria");
        assert!(verify_open_badge_jwt_with_profile(
            &sign(&direct_header(), &incomplete_badge),
            &keys,
            NOW,
            profile
        )
        .is_err());
        let mut retired = original.clone();
        retired["type"]
            .as_array_mut()
            .unwrap()
            .push(json!("Assertion"));
        assert!(
            verify_jwt_vc_with_profile(&sign(&direct_header(), &retired), &keys, NOW, profile)
                .is_err()
        );
        for (name, value) in [
            ("typ", json!("JWT")),
            ("cty", json!("vp")),
            ("crit", json!(["future"])),
            ("b64", json!(false)),
            ("alg", json!("none")),
            ("alg", json!("ES384")),
        ] {
            let mut header = direct_header();
            header[name] = value;
            assert!(
                verify_jwt_vc_with_profile(&sign(&header, &original), &keys, NOW, profile).is_err(),
                "signed header {name}"
            );
        }
        let mut parts: Vec<_> = token.split('.').map(str::to_owned).collect();
        parts[2] = URL_SAFE_NO_PAD.encode([0u8; 64]);
        assert!(verify_jwt_vc_with_profile(&parts.join("."), &keys, NOW, profile).is_err());

        let historical = sign(&json!({"alg":"ES256", "kid":KID, "typ":"JWT"}), &claims());
        verify_jwt_vc_with_profile(
            &historical,
            &keys,
            NOW,
            JwtVcSecuringProfile::MartyNestedVc2JwtV1,
        )
        .unwrap();
        assert!(verify_jwt_vc_with_profile(&historical, &keys, NOW, profile).is_err());
    }

    #[test]
    #[cfg(all(feature = "issuer", feature = "sd_jwt", feature = "mso_mdoc"))]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn remote_direct_preparation_completion_and_authentication_share_one_profile() {
        use crate::remote_credential::{prepare_remote_jwt_vc_with_profile, RemoteJwtVcRequest};
        use crate::{JwtVcPreparationProfile, JwtVcProfileTiming};
        let issuer = crate::openbao_transit::DisposableOpenBao::from_marked_env().create_es256();
        let credential = direct_claims();
        let request = RemoteJwtVcRequest {
            issuer_id: ISSUER.into(),
            verification_method_id: KID.into(),
            algorithm: "ES256".into(),
            issuer_public_jwk: issuer.public_jwk().into(),
            subject_id: Some("did:example:holder".into()),
            credential_type: "OpenBadgeCredential".into(),
            claims: std::collections::HashMap::new(),
            expiration_seconds: None,
            credential_id: Some("urn:uuid:00000000-0000-0000-0000-000000000421".into()),
            credential_subject: Some(credential["credentialSubject"].clone()),
            credential_profile: Some("open_badge_v3".into()),
            achievement_id: Some(
                credential["credentialSubject"]["achievement"]["id"]
                    .as_str()
                    .unwrap()
                    .into(),
            ),
        };
        let timing = JwtVcProfileTiming::new(
            NOW - 60,
            NOW + 3600,
            chrono::DateTime::from_timestamp(NOW - 3600, 0).unwrap(),
            Some(chrono::DateTime::from_timestamp(NOW + 86_400, 0).unwrap()),
        )
        .unwrap();
        let prepared = prepare_remote_jwt_vc_with_profile(
            request,
            JwtVcPreparationProfile::DirectVc2Jose(timing),
        )
        .unwrap();
        let expected_binding = prepared.binding();
        let signature = issuer.sign(prepared.signing_input().as_bytes()).unwrap();
        let signed = prepared.complete(&signature).unwrap();
        assert_eq!(signed.binding(), expected_binding);
        let keys = TrustedSdJwtIssuerKeys::new(vec![ResolvedSdJwtIssuerKey::new(
            ISSUER,
            Some(KID.into()),
            SigningAlgorithm::ES256,
            issuer.public_jwk(),
        )])
        .unwrap();
        let proof = verify_open_badge_jwt_with_profile(
            signed.credential(),
            &keys,
            NOW,
            expected_binding.securing_profile(),
        )
        .unwrap();
        assert_eq!(proof.binding(), expected_binding);
        assert_eq!(proof.credential_id(), signed.credential_id());
        assert_eq!(
            proof.credential()["credentialSubject"],
            credential["credentialSubject"]
        );
        assert_eq!(
            proof.credential_valid_until().unwrap().timestamp(),
            NOW + 86_400
        );
        assert_eq!(proof.signature_expires_at(), NOW + 3600);
        assert!(!format!("{signed:?}").contains(signed.credential()));
    }

    #[test]
    #[cfg(feature = "wallet")]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn remote_direct_presentation_binds_exact_envelope_profile_and_one_clock() {
        let fixture = crate::openbao_transit::DisposableOpenBao::from_marked_env();
        let issuer = fixture.create_es256();
        let holder = fixture.create_es256();
        let holder_id = format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(holder.public_jwk()));
        let mut credential = direct_claims();
        credential["sub"] = json!(holder_id);
        credential["credentialSubject"]["id"] = json!(holder_id);
        let token = crate::jose::sign_test_compact_es256(&issuer, &direct_header(), &credential);
        let keys = TrustedSdJwtIssuerKeys::new(vec![ResolvedSdJwtIssuerKey::new(
            ISSUER,
            Some(KID.into()),
            SigningAlgorithm::ES256,
            issuer.public_jwk(),
        )])
        .unwrap();
        let profile = JwtVcSecuringProfile::W3cVc2Jose2026V1;
        let nonce = fresh_nonce();
        let audience = "https://verifier.example";
        let prepared = prepare_verified_jwt_vc_presentation_with_profile(
            &token,
            &keys,
            &nonce,
            audience,
            holder.public_jwk(),
            NOW,
            profile,
        )
        .unwrap();
        assert_eq!(prepared.binding(), JwtVcProfileBinding::new(profile));
        let signature = holder.sign(prepared.signing_input()).unwrap();
        let vp = prepared.complete(&signature).unwrap();
        let proof = verify_open_badge_presentation_with_profile(
            vp.vp_token(),
            &keys,
            &nonce,
            audience,
            NOW,
            profile,
        )
        .unwrap();
        assert_eq!(proof.credential_jwt(), token);
        assert_eq!(proof.proof_issued_at(), NOW);
        assert_eq!(proof.credential().evaluated_at(), NOW);
        assert_eq!(proof.binding(), vp.binding());
        assert!(!format!("{proof:?}").contains(&token));
        assert_eq!(
            presented_jwt_vc_with_profile(vp.vp_token(), profile).unwrap(),
            token
        );
        let (header, outer) = crate::jose::decode_unverified_compact_jwt(vp.vp_token()).unwrap();
        assert_eq!(header["typ"], "vp+jwt");
        assert_eq!(header["cty"], "vp");
        assert!(outer.get("vp").is_none());
        assert!(outer.get("vc").is_none());
        assert!(outer.get("nbf").is_none());
        assert_eq!(outer["id"], outer["jti"]);
        assert_eq!(
            outer["verifiableCredential"][0]["id"],
            format!("data:application/vc+jwt,{token}")
        );
        for (name, value) in [
            ("nonce", json!(fresh_nonce())),
            ("aud", json!("https://foreign.example")),
            ("iss", json!("did:example:other")),
            ("sub", json!("did:example:other")),
            ("holder", json!("did:example:other")),
            ("id", json!("urn:uuid:other")),
            ("iat", json!(NOW - 121)),
            ("exp", json!(NOW)),
            ("exp", json!(NOW + 121)),
            ("vp", json!({})),
            ("verifiableCredential", json!([token])),
            (
                "verifiableCredential",
                json!([
                    outer["verifiableCredential"][0],
                    outer["verifiableCredential"][0]
                ]),
            ),
        ] {
            let mut changed = outer.clone();
            changed[name] = value;
            let rejected = crate::jose::sign_test_compact_es256(&holder, &header, &changed);
            assert!(
                verify_jwt_vc_presentation_with_profile(
                    &rejected, &keys, &nonce, audience, NOW, profile
                )
                .is_err(),
                "holder-signed {name} conflict"
            );
        }
        let mut nested = claims();
        nested["sub"] = json!(holder_id);
        nested["vc"]["credentialSubject"]["id"] = json!(holder_id);
        let old = crate::jose::sign_test_compact_es256(
            &issuer,
            &json!({"alg":"ES256", "kid":KID, "typ":"JWT"}),
            &nested,
        );
        let historical = JwtVcSecuringProfile::MartyNestedVc2JwtV1;
        let prepared = prepare_verified_jwt_vc_presentation_with_profile(
            &old,
            &keys,
            &nonce,
            audience,
            holder.public_jwk(),
            NOW,
            historical,
        )
        .unwrap();
        let signature = holder.sign(prepared.signing_input()).unwrap();
        let historical_vp = prepared.complete(&signature).unwrap();
        verify_jwt_vc_presentation_with_profile(
            historical_vp.vp_token(),
            &keys,
            &nonce,
            audience,
            NOW,
            historical,
        )
        .unwrap();
        let (historical_header, historical_claims) =
            crate::jose::decode_unverified_compact_jwt(historical_vp.vp_token()).unwrap();
        for not_before in [json!(NOW + 1), json!(-1), json!("invalid")] {
            let mut changed = historical_claims.clone();
            changed["nbf"] = not_before;
            let rejected =
                crate::jose::sign_test_compact_es256(&holder, &historical_header, &changed);
            assert!(verify_jwt_vc_presentation_with_profile(
                &rejected, &keys, &nonce, audience, NOW, historical,
            )
            .is_err());
        }
        let mut cross_profile = outer.clone();
        cross_profile["verifiableCredential"][0]["id"] =
            json!(format!("data:application/vc+jwt,{old}"));
        let cross = crate::jose::sign_test_compact_es256(&holder, &header, &cross_profile);
        assert!(verify_jwt_vc_presentation_with_profile(
            &cross, &keys, &nonce, audience, NOW, profile
        )
        .is_err());
        let mut wrong_media = outer.clone();
        wrong_media["verifiableCredential"][0]["id"] =
            json!(format!("data:application/jwt,{token}"));
        let rejected = crate::jose::sign_test_compact_es256(&holder, &header, &wrong_media);
        assert!(verify_jwt_vc_presentation_with_profile(
            &rejected, &keys, &nonce, audience, NOW, profile
        )
        .is_err());
        assert!(verify_jwt_vc_presentation_with_profile(
            vp.vp_token(),
            &keys,
            &nonce,
            audience,
            NOW,
            JwtVcSecuringProfile::MartyNestedVc2JwtV1
        )
        .is_err());
        assert!(prepare_verified_jwt_vc_presentation_with_profile(
            &token,
            &keys,
            &nonce,
            audience,
            issuer.public_jwk(),
            NOW,
            profile,
        )
        .is_err());
        let prepared = prepare_verified_jwt_vc_presentation_with_profile(
            &token,
            &keys,
            &nonce,
            audience,
            holder.public_jwk(),
            NOW,
            profile,
        )
        .unwrap();
        assert!(prepared.complete(&[0u8; 64]).is_err());
    }
    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn verified_profile_binds_exact_signed_credential_hash() {
        let (token, keys) = signed(claims());
        let proof = verify_open_badge_jwt(&token, &keys, NOW).unwrap();
        assert_eq!(
            proof.credential_sha256,
            format!("{:x}", Sha256::digest(token.as_bytes()))
        );
        assert_eq!(proof.achievement_id, "https://issuer.example/member");
        assert!(proof.profile_validated && proof.issuer_signature_verified);
    }
    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn rejects_changed_signature_and_foreign_issuer() {
        let (token, keys) = signed(claims());
        let mut parts: Vec<_> = token.split('.').map(str::to_owned).collect();
        parts[2] = URL_SAFE_NO_PAD.encode([0u8; 64]);
        assert!(verify_open_badge_jwt(&parts.join("."), &keys, NOW).is_err());
        let mut foreign = claims();
        foreign["iss"] = json!("did:web:foreign.example");
        let (token, keys) = signed(foreign);
        assert!(verify_open_badge_jwt(&token, &keys, NOW).is_err());
    }
    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn authenticated_badge_cannot_reintroduce_retired_ob2_types() {
        for legacy in ["Assertion", "OpenBadgeV2", "open_badge_v2"] {
            let mut retired = claims();
            retired["vc"]["type"]
                .as_array_mut()
                .unwrap()
                .push(json!(legacy));
            let (token, keys) = signed(retired);
            assert!(verify_open_badge_jwt(&token, &keys, NOW).is_err());
        }
    }
    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn rejects_signed_non_badge_profile_and_expired_credential() {
        let mut no_badge = claims();
        no_badge["vc"]["credentialSubject"]
            .as_object_mut()
            .unwrap()
            .remove("achievement");
        let (token, keys) = signed(no_badge);
        assert!(verify_open_badge_jwt(&token, &keys, NOW).is_err());
        let mut expired = claims();
        expired["exp"] = json!(NOW - 1);
        let (token, keys) = signed(expired);
        assert!(verify_open_badge_jwt(&token, &keys, NOW).is_err());
    }
}
