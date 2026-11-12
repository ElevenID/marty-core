//! Verify the production Open Badge VC-JWT profile with an independently
//! admitted issuer key. No network resolver or local signing belongs here.
use crate::types::SigningAlgorithm;
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
struct AuthenticatedJwtVc {
    credential_sha256: String,
    subject_id: String,
    credential_id: String,
    issuer: String,
    key_id: Option<String>,
    algorithm: String,
    evaluated_at: i64,
    expires_at: i64,
    vc: serde_json::Value,
}

impl AuthenticatedJwtVc {
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
    let future_limit = evaluated_at
        .checked_add(30)
        .filter(|_| evaluated_at > 0)
        .ok_or_else(invalid)?;
    let (header, hints) = crate::jose::decode_unverified_compact_jwt(compact_jwt)?;
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
    if !vc
        .get("type")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|kinds| {
            kinds
                .iter()
                .any(|kind| kind.as_str() == Some("VerifiableCredential"))
        })
    {
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
        credential_sha256: format!("{:x}", Sha256::digest(compact_jwt.as_bytes())),
        subject_id: text(subject, "id")?.into(),
        credential_id: credential_id.into(),
        issuer: issuer.into(),
        key_id: kid.map(str::to_owned),
        algorithm: algorithm.as_str().into(),
        evaluated_at,
        expires_at: expires,
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
            credential_sha256: format!("{:x}", Sha256::digest(bearer.as_bytes())),
            subject_id: "did:example:holder".into(),
            credential_id: "urn:example:badge".into(),
            issuer: ISSUER.into(),
            key_id: Some(KID.into()),
            algorithm: "ES256".into(),
            evaluated_at: NOW,
            expires_at: NOW + 3600,
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
