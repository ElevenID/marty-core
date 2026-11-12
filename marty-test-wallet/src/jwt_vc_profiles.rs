//! Explicit wallet adoption of Core's versioned JWT profiles.
//! Historical receipt and presentation stay on their existing entrypoints.

use marty_oid4vci::{
    metadata::admit_profiled_jwt_vc_configuration,
    presentation_request::{build_profiled_jwt_vc_query, profiled_jwt_vc_query_binding},
    wallet::DcqlCredentialQuery,
    JwtVcProfileBinding, JwtVcSecuringProfile, PreparedProfiledJwtVcPresentation,
    SdJwtIssuerKeyResolver,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, String>;

/// Absence preserves the old request. An explicitly present null/unknown value
/// is not an instruction to retry using the historical path.
pub fn optional_profile<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<JwtVcSecuringProfile>, D::Error>
where
    D: Deserializer<'de>,
{
    JwtVcSecuringProfile::deserialize(deserializer).map(Some)
}

pub fn select_configuration(
    offered: &[String],
    requested: Option<&str>,
    expected_profile: Option<JwtVcSecuringProfile>,
) -> Result<String> {
    if expected_profile.is_some() && requested.is_none() {
        return Err("Profiled receipt requires an explicit offered configuration ID".into());
    }
    let selected = requested
        .or_else(|| offered.first().map(String::as_str))
        .ok_or("Credential offer contains no configuration")?;
    if requested.is_some() && offered.iter().filter(|id| id.as_str() == selected).count() != 1 {
        return Err("Selected credential configuration is not uniquely offered".into());
    }
    Ok(selected.to_owned())
}

pub fn receipt_binding(
    expected_profile: Option<JwtVcSecuringProfile>,
    configuration_id: &str,
    configuration: &Value,
) -> Result<Option<JwtVcProfileBinding>> {
    if let Some(expected) = expected_profile {
        let binding = admit_profiled_jwt_vc_configuration(configuration_id, configuration)
            .map_err(|_| "Credential configuration has an invalid securing profile")?;
        if binding.securing_profile() != expected {
            return Err(
                "Credential configuration differs from the selected securing profile".into(),
            );
        }
        return Ok(Some(binding));
    }
    if configuration.get("marty_securing_profile").is_some()
        || configuration.get("format").and_then(Value::as_str) == Some("application/vc+jwt")
        || configuration_id.ends_with("#vc2-jose-2026-v1")
    {
        return Err("Versioned JWT receipt requires an explicit securing profile selection".into());
    }
    Ok(None)
}

/// The stored binding is negotiation state, not a trust/status decision. Its
/// public facts are created only after Core authenticated the exact credential.
#[derive(Clone, Debug, Serialize)]
pub struct ProfiledJwtEvidence {
    binding: JwtVcProfileBinding,
    credential_sha256: String,
    evaluated_at: i64,
    issuer_signature_verified: bool,
    open_badge_content_validated: bool,
    trust: &'static str,
    status: &'static str,
    holder_binding: &'static str,
}

impl ProfiledJwtEvidence {
    pub fn binding(&self) -> JwtVcProfileBinding {
        self.binding
    }
}

pub struct AuthenticatedReceipt {
    pub evidence: ProfiledJwtEvidence,
    pub vct: Option<String>,
    pub achievement_id: Option<String>,
    pub credential_types: Vec<String>,
    pub claim_names: Vec<String>,
}

pub fn authenticate_receipt(
    raw: &str,
    binding: JwtVcProfileBinding,
    resolver: &dyn SdJwtIssuerKeyResolver,
    evaluated_at: i64,
) -> Result<AuthenticatedReceipt> {
    let authenticated = marty_oid4vci::verify_jwt_vc_with_profile(
        raw,
        resolver,
        evaluated_at,
        binding.securing_profile(),
    )
    .map_err(|_| "Issued credential failed the selected JWT securing profile")?;
    let document = authenticated.credential();
    let credential_types = match document.get("type") {
        Some(Value::Array(types)) => types
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        Some(Value::String(kind)) => vec![kind.clone()],
        _ => return Err("Authenticated credential has no types".into()),
    };
    let open_badge = credential_types
        .iter()
        .any(|kind| kind == "OpenBadgeCredential");
    if open_badge {
        marty_oid4vci::formats::jwt_vc::validate_open_badge_v3_profile(document)
            .map_err(|_| "Authenticated credential failed Open Badge content validation")?;
    }
    let subject = document
        .get("credentialSubject")
        .and_then(Value::as_object)
        .ok_or("Authenticated credential has no object subject")?;
    let mut claim_names = subject.keys().cloned().collect::<Vec<_>>();
    claim_names.sort();
    let vct = authenticated
        .claims()
        .get("vct")
        .or_else(|| document.pointer("/credentialSchema/id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let achievement_id = document
        .pointer("/credentialSubject/achievement/id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(AuthenticatedReceipt {
        evidence: ProfiledJwtEvidence {
            binding: authenticated.binding(),
            credential_sha256: authenticated.credential_sha256().to_owned(),
            evaluated_at: authenticated.evaluated_at(),
            issuer_signature_verified: true,
            open_badge_content_validated: open_badge,
            trust: "not_checked",
            status: "not_checked",
            holder_binding: "not_checked",
        },
        vct,
        achievement_id,
        credential_types,
        claim_names,
    })
}

pub fn query_binding(query: &DcqlCredentialQuery) -> Result<Option<JwtVcProfileBinding>> {
    let marked = query
        .meta
        .as_ref()
        .is_some_and(|meta| meta.get("marty_securing_profile").is_some());
    if !marked {
        if query.format == "application/vc+jwt" {
            return Err("Versioned JWT query omitted its securing profile".into());
        }
        return Ok(None);
    }
    if !query.claims.is_empty() {
        return Err("Profiled JWT queries support credential type selection only".into());
    }
    let raw = serde_json::to_value(query).map_err(|_| "Invalid profiled credential query")?;
    let binding = profiled_jwt_vc_query_binding(&raw)
        .map_err(|_| "Credential query has an invalid securing profile")?;
    let meta = query
        .meta
        .as_ref()
        .and_then(Value::as_object)
        .ok_or("Invalid profiled query metadata")?;
    if meta.len() != 2 || !meta.contains_key("type_values") {
        return Err("Unsupported profiled query metadata".into());
    }
    let types: Vec<Vec<String>> = serde_json::from_value(meta["type_values"].clone())
        .map_err(|_| "Invalid profiled credential type selection")?;
    // Reuse the same bounded canonical producer's type/identifier admission.
    // This wallet always prepares a cryptographic holder proof.
    build_profiled_jwt_vc_query(&query.id, binding, types, true)
        .map_err(|_| "Invalid profiled credential type selection")?;
    Ok(Some(binding))
}

pub fn matches_query(
    stored: &ProfiledJwtEvidence,
    credential_types: &[String],
    query: &DcqlCredentialQuery,
) -> bool {
    let Ok(Some(requested)) = query_binding(query) else {
        return false;
    };
    if requested != stored.binding() {
        return false;
    }
    query
        .meta
        .as_ref()
        .and_then(|meta| meta.get("type_values"))
        .and_then(Value::as_array)
        .is_some_and(|sets| {
            sets.iter().any(|set| {
                set.as_array().is_some_and(|types| {
                    types.iter().all(|kind| {
                        kind.as_str().is_some_and(|kind| {
                            credential_types.iter().any(|stored| stored == kind)
                        })
                    })
                })
            })
        })
}

pub struct PresentationContext<'a> {
    pub resolver: &'a dyn SdJwtIssuerKeyResolver,
    pub nonce: &'a str,
    pub audience: &'a str,
    pub holder_public_jwk: &'a str,
    pub evaluated_at: i64,
}

pub fn prepare_presentation(
    raw: &str,
    stored: &ProfiledJwtEvidence,
    query: &DcqlCredentialQuery,
    context: PresentationContext<'_>,
) -> Result<PreparedProfiledJwtVcPresentation> {
    if query_binding(query)? != Some(stored.binding())
        || stored.credential_sha256 != format!("{:x}", Sha256::digest(raw.as_bytes()))
    {
        return Err("Stored credential and requested securing profile differ".into());
    }
    marty_oid4vci::prepare_verified_jwt_vc_presentation_with_profile(
        raw,
        context.resolver,
        context.nonce,
        context.audience,
        context.holder_public_jwk,
        context.evaluated_at,
        stored.binding().securing_profile(),
    )
    .map_err(|_| "Credential could not prepare the selected profile's holder proof".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_oid4vci::JwtVcSecuringProfile::{
        MartyNestedVc2JwtV1 as Historical, W3cVc2Jose2026V1 as Direct,
    };
    use serde_json::json;

    fn metadata(profile: JwtVcSecuringProfile) -> Value {
        json!({
            "format": profile.credential_format(),
            "marty_securing_profile": profile.as_str(),
            "credential_definition": {"type": ["VerifiableCredential", "OpenBadgeCredential"]}
        })
    }

    fn query(profile: JwtVcSecuringProfile) -> DcqlCredentialQuery {
        serde_json::from_value(
            build_profiled_jwt_vc_query(
                "badge",
                JwtVcProfileBinding::new(profile),
                vec![vec![
                    "VerifiableCredential".into(),
                    "OpenBadgeCredential".into(),
                ]],
                true,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn receipt_request_requires_explicit_known_profile_and_offered_configuration() {
        let legacy: crate::ReceiveRequest =
            serde_json::from_value(json!({"offer_uri":"offer"})).unwrap();
        assert!(legacy.expected_securing_profile.is_none());
        assert!(legacy.credential_configuration_id.is_none());
        for profile in [
            json!(null),
            json!("unknown"),
            json!("vc+jwt"),
            json!("W3cVc2Jose2026V1"),
        ] {
            assert!(serde_json::from_value::<crate::ReceiveRequest>(json!({
                "offer_uri":"offer", "expected_securing_profile":profile,
                "credential_configuration_id":"badge#vc2-jose-2026-v1"
            }))
            .is_err());
        }
        let offered = vec!["historical".into(), "badge#vc2-jose-2026-v1".into()];
        assert_eq!(
            select_configuration(&offered, None, None).unwrap(),
            "historical"
        );
        assert!(select_configuration(&offered, None, Some(Direct)).is_err());
        assert!(select_configuration(&offered, Some("absent"), Some(Direct)).is_err());
        assert_eq!(
            select_configuration(&offered, Some(&offered[1]), Some(Direct)).unwrap(),
            offered[1]
        );
        assert!(select_configuration(
            &[offered[1].clone(), offered[1].clone()],
            Some(&offered[1]),
            Some(Direct)
        )
        .is_err());
    }

    #[test]
    fn receipt_profile_is_exact_and_marked_metadata_never_falls_back() {
        for profile in [Historical, Direct] {
            let id = profile.configuration_id("badge").unwrap();
            let metadata = metadata(profile);
            assert_eq!(
                receipt_binding(Some(profile), &id, &metadata).unwrap(),
                Some(JwtVcProfileBinding::new(profile))
            );
            assert!(receipt_binding(None, &id, &metadata).is_err());
            let other = if profile == Direct {
                Historical
            } else {
                Direct
            };
            assert!(receipt_binding(Some(other), &id, &metadata).is_err());
            for marker in [json!(null), json!("unknown"), json!(other.as_str())] {
                let mut changed = metadata.clone();
                changed["marty_securing_profile"] = marker;
                assert!(receipt_binding(Some(profile), &id, &changed).is_err());
                assert!(receipt_binding(None, &id, &changed).is_err());
            }
        }
        let mut direct = metadata(Direct);
        assert!(receipt_binding(Some(Direct), "badge", &direct).is_err());
        direct
            .as_object_mut()
            .unwrap()
            .remove("marty_securing_profile");
        assert!(receipt_binding(Some(Direct), "badge#vc2-jose-2026-v1", &direct).is_err());
        assert!(receipt_binding(None, "badge", &direct).is_err());
        let legacy = json!({"format":"jwt_vc_json"});
        assert_eq!(receipt_binding(None, "badge", &legacy).unwrap(), None);
        assert!(receipt_binding(None, "badge#vc2-jose-2026-v1", &legacy).is_err());
    }

    #[test]
    fn profiled_dcql_requires_exact_binding_and_supported_type_metadata() {
        for profile in [Historical, Direct] {
            let original = query(profile);
            assert_eq!(
                query_binding(&original).unwrap(),
                Some(JwtVcProfileBinding::new(profile))
            );
            let mut with_claims = serde_json::to_value(&original).unwrap();
            with_claims["claims"] =
                json!([{"id":"achievement", "path":["credentialSubject", "achievement"]}]);
            let with_claims: DcqlCredentialQuery = serde_json::from_value(with_claims).unwrap();
            assert!(query_binding(&with_claims).is_err());
            for bad in [json!(null), json!("unknown"), json!("jwt_vc_json")] {
                let mut changed = original.clone();
                changed.meta.as_mut().unwrap()["marty_securing_profile"] = bad;
                assert!(query_binding(&changed).is_err());
            }
            for types in [
                json!([]),
                json!([[]]),
                json!(["OpenBadgeCredential"]),
                json!([[null]]),
                json!([[""]]),
            ] {
                let mut changed = original.clone();
                changed.meta.as_mut().unwrap()["type_values"] = types;
                assert!(query_binding(&changed).is_err());
            }
            let mut changed = original.clone();
            changed.meta.as_mut().unwrap()["vct_values"] = json!(["unexpected"]);
            assert!(query_binding(&changed).is_err());
            changed = original;
            changed.format = if profile == Direct {
                "jwt_vc_json"
            } else {
                "application/vc+jwt"
            }
            .into();
            assert!(query_binding(&changed).is_err());
        }
        let mut direct = query(Direct);
        direct
            .meta
            .as_mut()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("marty_securing_profile");
        assert!(query_binding(&direct).is_err());
        let mut historical = query(Historical);
        historical
            .meta
            .as_mut()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("marty_securing_profile");
        assert_eq!(query_binding(&historical).unwrap(), None);
    }

    #[test]
    fn stored_profile_and_legacy_query_boundaries_remain_separate() {
        // This record exercises selection only; it is not issuer evidence.
        let evidence = ProfiledJwtEvidence {
            binding: JwtVcProfileBinding::new(Direct),
            credential_sha256: "selection-test".into(),
            evaluated_at: 1,
            issuer_signature_verified: false,
            open_badge_content_validated: false,
            trust: "not_checked",
            status: "not_checked",
            holder_binding: "not_checked",
        };
        let mut stored = crate::StoredCredential {
            id: "selection".into(),
            credential_configuration_id: "badge#vc2-jose-2026-v1".into(),
            format: marty_oid4vci::types::CredentialFormat::JwtVcJson,
            raw: "not-a-real-credential".into(),
            vct: None,
            achievement_id: None,
            credential_types: vec!["VerifiableCredential".into(), "OpenBadgeCredential".into()],
            claim_names: vec![],
            received_at: "2026-01-01T00:00:00Z".into(),
            open_badge_evidence: None,
            profiled_jwt: Some(evidence),
        };
        let direct = query(Direct);
        assert!(crate::credential_matches_query(
            &stored,
            &direct,
            &stored.format
        ));
        let mut with_claims = serde_json::to_value(&direct).unwrap();
        with_claims["claims"] =
            json!([{"id":"achievement", "path":["credentialSubject", "achievement"]}]);
        let with_claims = serde_json::from_value(with_claims).unwrap();
        assert!(!crate::credential_matches_query(
            &stored,
            &with_claims,
            &stored.format
        ));
        assert!(!crate::credential_matches_query(
            &stored,
            &query(Historical),
            &stored.format
        ));
        let mut unmarked = query(Historical);
        unmarked
            .meta
            .as_mut()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("marty_securing_profile");
        assert!(!crate::credential_matches_query(
            &stored,
            &unmarked,
            &stored.format
        ));
        let mut wrong_types = direct.clone();
        wrong_types.meta.as_mut().unwrap()["type_values"] = json!([["EmployeeCredential"]]);
        assert!(!crate::credential_matches_query(
            &stored,
            &wrong_types,
            &stored.format
        ));
        stored.profiled_jwt = None;
        assert!(!crate::credential_matches_query(
            &stored,
            &direct,
            &stored.format
        ));
        assert!(!crate::credential_matches_query(
            &stored,
            &query(Historical),
            &stored.format
        ));
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn remote_profiled_receipt_and_presentation_retain_binding_and_exact_jwt() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use marty_crypto_test_support::openbao_transit::DisposableOpenBao;
        use marty_oid4vci::{
            remote_credential::{prepare_remote_jwt_vc_with_profile, RemoteJwtVcRequest},
            types::{CredentialFormat, SigningAlgorithm},
            JwtVcPreparationProfile, JwtVcProfileTiming, ResolvedSdJwtIssuerKey,
            TrustedSdJwtIssuerKeys,
        };
        let fixture = DisposableOpenBao::from_marked_env();
        let issuer = fixture.create_es256();
        let holder = fixture.create_es256();
        let wrong_holder = fixture.create_es256();
        let issuer_id = "did:web:issuer.example";
        let kid = issuer.key_id(issuer_id);
        let holder_id = format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(holder.public_jwk()));
        let keys = TrustedSdJwtIssuerKeys::new(vec![ResolvedSdJwtIssuerKey::new(
            issuer_id,
            Some(kid.clone()),
            SigningAlgorithm::ES256,
            issuer.public_jwk(),
        )])
        .unwrap();
        let now = chrono::Utc::now().timestamp();
        for profile in [Historical, Direct] {
            let timing = JwtVcProfileTiming::new(
                now - 60,
                now + 600,
                chrono::DateTime::from_timestamp(now - 3600, 0).unwrap(),
                Some(chrono::DateTime::from_timestamp(now + 7200, 0).unwrap()),
            )
            .unwrap();
            let request = RemoteJwtVcRequest {
                issuer_id: issuer_id.into(),
                verification_method_id: kid.clone(),
                algorithm: "ES256".into(),
                issuer_public_jwk: issuer.public_jwk().into(),
                subject_id: Some(holder_id.clone()),
                credential_type: "OpenBadgeCredential".into(),
                claims: std::collections::HashMap::from([
                    ("achievement_name".into(), json!("Profile adoption test")),
                    (
                        "achievement_description".into(),
                        json!("Public test content"),
                    ),
                    (
                        "achievement_criteria".into(),
                        json!({"narrative":"Complete the public test"}),
                    ),
                ]),
                expiration_seconds: (profile == Historical).then_some(3600),
                credential_id: Some("urn:uuid:00000000-0000-0000-0000-000000000421".into()),
                credential_subject: None,
                credential_profile: Some("open_badge_v3".into()),
                achievement_id: Some("https://issuer.example/achievements/profile-test".into()),
            };
            let preparation = if profile == Direct {
                JwtVcPreparationProfile::DirectVc2Jose(timing)
            } else {
                JwtVcPreparationProfile::HistoricalNested
            };
            let prepared = prepare_remote_jwt_vc_with_profile(request, preparation).unwrap();
            let signature = issuer
                .sign_es256(prepared.signing_input().as_bytes())
                .unwrap();
            let issued = prepared.complete(&signature).unwrap();
            let raw = issued.credential();
            let authenticated = authenticate_receipt(raw, issued.binding(), &keys, now).unwrap();
            assert_eq!(
                authenticated.credential_types,
                ["VerifiableCredential", "OpenBadgeCredential"]
            );
            assert_eq!(
                authenticated.achievement_id.as_deref(),
                Some("https://issuer.example/achievements/profile-test")
            );
            assert!(authenticated
                .claim_names
                .iter()
                .any(|claim| claim == "achievement"));
            let stored = crate::StoredCredential {
                id: "authenticated".into(),
                credential_configuration_id: profile.configuration_id("badge").unwrap(),
                format: CredentialFormat::JwtVcJson,
                raw: raw.into(),
                vct: authenticated.vct,
                achievement_id: authenticated.achievement_id,
                credential_types: authenticated.credential_types,
                claim_names: authenticated.claim_names,
                received_at: "2026-01-01T00:00:00Z".into(),
                open_badge_evidence: None,
                profiled_jwt: Some(authenticated.evidence),
            };
            assert_eq!(stored.raw, raw);
            let summary = serde_json::to_value(crate::CredentialSummary::from(&stored)).unwrap();
            assert_eq!(summary["format"], profile.credential_format());
            assert_eq!(
                summary["profiled_jwt_evidence"]["binding"]["securing_profile"],
                profile.as_str()
            );
            assert_eq!(
                summary["profiled_jwt_evidence"]["credential_sha256"],
                format!("{:x}", Sha256::digest(raw.as_bytes()))
            );
            assert_eq!(summary["profiled_jwt_evidence"]["evaluated_at"], now);
            for field in ["trust", "status", "holder_binding"] {
                assert_eq!(summary["profiled_jwt_evidence"][field], "not_checked");
            }
            assert!(!summary.to_string().contains(raw));
            assert!(summary.get("raw").is_none());
            let selected = query(profile);
            let nonce = uuid::Uuid::new_v4().to_string();
            let context = || PresentationContext {
                resolver: &keys,
                nonce: &nonce,
                audience: "https://verifier.example",
                holder_public_jwk: holder.public_jwk(),
                evaluated_at: now,
            };
            let evidence = stored.profiled_jwt.as_ref().unwrap();
            let prepared =
                prepare_presentation(&stored.raw, evidence, &selected, context()).unwrap();
            let holder_signature = holder.sign_es256(prepared.signing_input()).unwrap();
            let signed = prepared.complete(&holder_signature).unwrap();
            let verified = marty_oid4vci::verify_open_badge_presentation_with_profile(
                signed.vp_token(),
                &keys,
                &nonce,
                "https://verifier.example",
                now,
                profile,
            )
            .unwrap();
            assert_eq!(verified.credential_jwt(), raw);
            assert_eq!(verified.credential().evaluated_at(), now);
            let other = if profile == Direct {
                Historical
            } else {
                Direct
            };
            assert!(
                authenticate_receipt(raw, JwtVcProfileBinding::new(other), &keys, now).is_err()
            );
            assert!(prepare_presentation(raw, evidence, &query(other), context()).is_err());
            let mut with_claims = serde_json::to_value(&selected).unwrap();
            with_claims["claims"] =
                json!([{"id":"achievement", "path":["credentialSubject", "achievement"]}]);
            let with_claims = serde_json::from_value(with_claims).unwrap();
            assert!(prepare_presentation(raw, evidence, &with_claims, context()).is_err());
            let mut expired = context();
            expired.evaluated_at = now + 10_000;
            assert!(prepare_presentation(raw, evidence, &selected, expired).is_err());
            let mut wrong = context();
            wrong.holder_public_jwk = wrong_holder.public_jwk();
            assert!(prepare_presentation(raw, evidence, &selected, wrong).is_err());
            let mut pieces: Vec<_> = raw.split('.').map(str::to_owned).collect();
            pieces[2] = URL_SAFE_NO_PAD.encode([0u8; 64]);
            let tampered = pieces.join(".");
            assert!(authenticate_receipt(&tampered, issued.binding(), &keys, now).is_err());
            assert!(prepare_presentation(&tampered, evidence, &selected, context()).is_err());
        }
    }
}
