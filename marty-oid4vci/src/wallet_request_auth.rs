//! Authentication of an explicitly pre-registered OID4VP verifier.
//!
//! Authority must come from the caller's fresh governed verifier relationship,
//! never from issuer trust, the request's embedded keys, or its retrieval URL.
//! This initial profile deliberately does not implement DID, certificate,
//! federation, attestation, encrypted-response or transaction-data semantics.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{jose, Oid4vciError, Oid4vciResult, ParsedPresentationRequest, WalletEngine};

/// Fresh, public-only authority supplied by the verifier governance owner.
/// All response URIs are exact registrations, without wildcard matching.
#[derive(Clone)]
pub struct RegisteredVerifierAuthority {
    pub authority_id: String,
    pub revision: String,
    pub client_id: String,
    pub request_key_id: String,
    pub public_jwk_json: String,
    pub response_uris: Vec<String>,
    pub valid_from: i64,
    pub valid_until: i64,
}

/// Fresh governed DID authority. Snapshot freshness and signing-key validity
/// are separate boundaries. Response URIs remain exact registrations.
#[derive(Clone)]
pub struct GovernedDidVerifierAuthority {
    pub authority_id: String,
    pub revision: String,
    pub client_id: String,
    pub request_key_id: String,
    pub public_jwk_json: String,
    pub response_uris: Vec<String>,
    pub valid_from: i64,
    pub valid_until: i64,
    pub observed_at: i64,
    pub expires_at: i64,
}

impl GovernedDidVerifierAuthority {
    fn key_authority(&self) -> RegisteredVerifierAuthority {
        RegisteredVerifierAuthority {
            authority_id: self.authority_id.clone(),
            revision: self.revision.clone(),
            client_id: self.client_id.clone(),
            request_key_id: self.request_key_id.clone(),
            public_jwk_json: self.public_jwk_json.clone(),
            response_uris: self.response_uris.clone(),
            valid_from: self.valid_from,
            valid_until: self.valid_until,
        }
    }

    fn validate(&self, now: i64) -> Oid4vciResult<&str> {
        validate_authority(&self.key_authority(), now)?;
        let did = self
            .client_id
            .strip_prefix("decentralized_identifier:")
            .ok_or_else(invalid)?;
        if !text(did)
            || !did.starts_with("did:")
            || self.observed_at > now
            || self.expires_at <= now
            || self.expires_at <= self.observed_at
            || self.expires_at > self.observed_at.saturating_add(60)
            || self.expires_at > self.valid_until
        {
            return Err(invalid());
        }
        Ok(did)
    }
}

struct SdJwtSelectionPolicy {
    vct_values: Option<Vec<String>>,
    issuer_algorithms: Vec<String>,
    holder_algorithms: Vec<String>,
}

/// Signature-authenticated request with its original signed bytes retained.
/// Construction and mutation are private to the authentication boundary.
pub struct AuthenticatedPresentationRequest {
    request: ParsedPresentationRequest,
    compact_jws: String,
    authority_id: String,
    authority_revision: String,
    expires_at: i64,
    authority_snapshot_expires_at: Option<i64>,
    selection_policy: Option<SdJwtSelectionPolicy>,
}

impl AuthenticatedPresentationRequest {
    pub fn request(&self) -> &ParsedPresentationRequest {
        &self.request
    }

    /// Bind consent to these exact bytes, not a lossy projection of JWT claims.
    pub fn compact_jws(&self) -> &str {
        &self.compact_jws
    }

    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub fn authority_revision(&self) -> &str {
        &self.authority_revision
    }

    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Bind consent to original signed bytes and the exact authority revision.
    pub fn consent_binding_digest(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"marty.wallet/request-consent/v1");
        for value in [
            &self.authority_id,
            &self.authority_revision,
            &self.compact_jws,
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        format!("{:x}", digest.finalize())
    }

    fn require_current(&self) -> Oid4vciResult<()> {
        let now = chrono::Utc::now().timestamp();
        if self.expires_at <= now
            || self
                .authority_snapshot_expires_at
                .is_some_and(|until| until <= now)
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Verify credential/holder bindings and signed type/algorithm constraints
    /// before displaying a selectable credential. No private key is accepted.
    pub fn verify_sd_jwt_for_consent(
        &self,
        credential: &str,
        holder_public_jwk_json: &str,
        issuer_keys: &dyn crate::SdJwtIssuerKeyResolver,
    ) -> Oid4vciResult<crate::VerifiedSdJwtCredential> {
        self.require_current()?;
        let verified = crate::wallet_sd_jwt::verify_received_credential(
            credential,
            holder_public_jwk_json,
            issuer_keys,
        )?;
        if let Some(policy) = &self.selection_policy {
            let jwt = credential.split('~').next().ok_or_else(invalid)?;
            let header = jose::decode_unverified_compact_jwt_header(jwt)?;
            let algorithm = header
                .get("alg")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            if verified.format != "dc+sd-jwt"
                || !policy
                    .issuer_algorithms
                    .iter()
                    .any(|allowed| allowed == algorithm)
                || !policy
                    .holder_algorithms
                    .iter()
                    .any(|allowed| allowed == "ES256")
                || policy
                    .vct_values
                    .as_ref()
                    .is_some_and(|types| !types.contains(&verified.credential_type))
            {
                return Err(invalid());
            }
        }
        self.require_current()?;
        Ok(verified)
    }

    /// Prepare only approved request claims, with this authenticated nonce and
    /// full client identifier as audience. Callers must freshly authenticate the
    /// original signed request with current governance again before preparation.
    pub fn prepare_sd_jwt_presentation(
        &self,
        credential: &str,
        selected_claims: &[String],
        holder_public_jwk_json: &str,
        issuer_keys: &dyn crate::SdJwtIssuerKeyResolver,
    ) -> Oid4vciResult<crate::PreparedSdJwtPresentation> {
        self.verify_sd_jwt_for_consent(credential, holder_public_jwk_json, issuer_keys)?;
        let query = self.request.dcql_query.as_ref().ok_or_else(invalid)?;
        let [credential_query] = query.credentials.as_slice() else {
            return Err(invalid());
        };
        let mut selected = std::collections::HashSet::new();
        if selected_claims.len() != credential_query.claims.len()
            || selected_claims.iter().any(|name| {
                !selected.insert(name)
                    || !credential_query
                        .claims
                        .iter()
                        .any(|claim| claim.path.as_slice() == [name.as_str()])
            })
        {
            return Err(invalid());
        }
        let prepared = crate::wallet_sd_jwt::prepare_verified_presentation(
            credential,
            selected_claims,
            &self.request.nonce,
            &self.request.client_id,
            holder_public_jwk_json,
            issuer_keys,
        )?;
        self.require_current()?;
        Ok(prepared)
    }
}

fn invalid() -> Oid4vciError {
    Oid4vciError::InvalidRequest("Unsupported or unauthenticated verifier request".into())
}

fn text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn recipient(value: &str) -> bool {
    text(value)
        && url::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        })
}

fn plain_sd_jwt_query(value: &Value) -> bool {
    let Some(query) = value.as_object().filter(|object| object.len() == 1) else {
        return false;
    };
    let Some(credentials) = query
        .get("credentials")
        .and_then(Value::as_array)
        .filter(|items| items.len() == 1)
    else {
        return false;
    };
    let Some(credential) = credentials[0].as_object() else {
        return false;
    };
    if credential.keys().any(|key| {
        ![
            "id",
            "format",
            "claims",
            "require_cryptographic_holder_binding",
        ]
        .contains(&key.as_str())
    }) || credential
        .get("id")
        .and_then(Value::as_str)
        .is_none_or(|id| !text(id))
        || credential.get("format").and_then(Value::as_str) != Some("dc+sd-jwt")
        || credential
            .get("require_cryptographic_holder_binding")
            .is_some_and(|value| value.as_bool() != Some(true))
    {
        return false;
    }
    let Some(claims) = credential
        .get("claims")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty() && items.len() <= 64)
    else {
        return false;
    };
    let mut names = std::collections::HashSet::new();
    let mut ids = std::collections::HashSet::new();
    claims.iter().all(|claim| {
        let Some(claim) = claim.as_object() else {
            return false;
        };
        if claim
            .keys()
            .any(|key| !["id", "path"].contains(&key.as_str()))
            || claim
                .get("id")
                .is_some_and(|value| value.as_str().is_none_or(|id| !text(id) || !ids.insert(id)))
        {
            return false;
        }
        let Some(path) = claim
            .get("path")
            .and_then(Value::as_array)
            .filter(|items| items.len() == 1)
        else {
            return false;
        };
        path[0].as_str().is_some_and(|name| {
            !name.is_empty()
                && name.len() <= 256
                && name.as_bytes()[0].is_ascii_alphabetic()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                && names.insert(name)
        })
    })
}

/// Refuse stale or unsupported authority before any request network fetch.
pub(crate) fn validate_registered_authority(
    authority: &RegisteredVerifierAuthority,
    now: i64,
) -> Oid4vciResult<()> {
    validate_authority(authority, now)?;
    if authority.client_id.contains(':') {
        return Err(invalid());
    }
    Ok(())
}

fn validate_authority(authority: &RegisteredVerifierAuthority, now: i64) -> Oid4vciResult<()> {
    if !text(&authority.authority_id)
        || !text(&authority.revision)
        || !text(&authority.client_id)
        || !text(&authority.request_key_id)
        || authority.response_uris.is_empty()
        || authority.response_uris.len() > 32
        || !authority.response_uris.iter().all(|uri| recipient(uri))
        || authority.valid_from > now
        || authority.valid_until <= now
        || authority.valid_until <= authority.valid_from
    {
        return Err(invalid());
    }
    Ok(())
}

/// Authenticate a bounded compact ES256 JWS before deriving consent fields.
///
/// Supports only OID4VP Final's pre-registered client profile, direct_post and
/// flat SD-JWT DCQL. Unknown authorization semantics fail closed before typed
/// parsing can discard them. Obtain fresh authority again at preparation;
/// this value is neither a persistent trust grant nor signing authorization.
pub fn authenticate_registered_presentation_request(
    compact_jws: &str,
    authority: &RegisteredVerifierAuthority,
    now: i64,
) -> Oid4vciResult<AuthenticatedPresentationRequest> {
    validate_registered_authority(authority, now)?;
    authenticate_signed_profile(compact_jws, authority, now, None)
}

fn authenticate_signed_profile(
    compact_jws: &str,
    authority: &RegisteredVerifierAuthority,
    now: i64,
    authority_snapshot_expires_at: Option<i64>,
) -> Oid4vciResult<AuthenticatedPresentationRequest> {
    let verified =
        jose::verify_compact_jwt_with_public_jwk(compact_jws, &authority.public_jwk_json, "ES256")?;
    let header = verified.header.as_object().ok_or_else(invalid)?;
    if header.len() != 3
        || header.get("typ").and_then(Value::as_str) != Some("oauth-authz-req+jwt")
        || header.get("kid").and_then(Value::as_str) != Some(authority.request_key_id.as_str())
    {
        return Err(invalid());
    }
    let claims = verified.claims.as_object().ok_or_else(invalid)?;
    if claims.keys().any(|key| {
        if key == "client_metadata" && authority_snapshot_expires_at.is_some() {
            return false;
        }
        ![
            "iss",
            "aud",
            "iat",
            "exp",
            "nbf",
            "client_id",
            "response_type",
            "response_mode",
            "response_uri",
            "nonce",
            "state",
            "dcql_query",
        ]
        .contains(&key.as_str())
    }) {
        return Err(invalid());
    }
    let string = |name: &str| claims.get(name).and_then(Value::as_str).ok_or_else(invalid);
    let issued = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(invalid)?;
    let expires = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(invalid)?;
    if string("client_id")? != authority.client_id
        || string("iss")? != authority.client_id
        || string("aud")? != "https://self-issued.me/v2"
        || string("response_type")? != "vp_token"
        || string("response_mode")? != "direct_post"
        || !text(string("nonce")?)
        || !text(string("state")?)
        || !authority
            .response_uris
            .iter()
            .any(|uri| uri == string("response_uri").unwrap_or(""))
        || issued > now.saturating_add(30)
        || issued < authority.valid_from
        || expires <= now
        || expires <= issued
        || expires > issued.saturating_add(900)
        || expires > authority.valid_until
        || claims
            .get("nbf")
            .is_some_and(|value| value.as_i64().is_none_or(|time| time > now))
    {
        return Err(invalid());
    }
    let selection_policy = if authority_snapshot_expires_at.is_some() {
        Some(did_selection_policy(&verified.claims)?)
    } else {
        if claims
            .get("dcql_query")
            .is_none_or(|query| !plain_sd_jwt_query(query))
        {
            return Err(invalid());
        }
        None
    };
    let request = WalletEngine::parsed_request_from_value(verified.claims)?;
    Ok(AuthenticatedPresentationRequest {
        request,
        compact_jws: compact_jws.to_owned(),
        authority_id: authority.authority_id.clone(),
        authority_revision: authority.revision.clone(),
        expires_at: expires,
        authority_snapshot_expires_at,
        selection_policy,
    })
}

fn did_selection_policy(claims: &Value) -> Oid4vciResult<SdJwtSelectionPolicy> {
    let query = claims.get("dcql_query").ok_or_else(invalid)?;
    let mut flat = query.clone();
    let credential = flat
        .get_mut("credentials")
        .and_then(Value::as_array_mut)
        .filter(|items| items.len() == 1)
        .and_then(|items| items[0].as_object_mut())
        .ok_or_else(invalid)?;
    let vct_values = credential
        .remove("meta")
        .map(|meta| {
            let object = meta
                .as_object()
                .filter(|object| object.len() == 1)
                .ok_or_else(invalid)?;
            text_values(object.get("vct_values").ok_or_else(invalid)?, 32)
        })
        .transpose()?;
    if !plain_sd_jwt_query(&flat) {
        return Err(invalid());
    }
    let metadata = claims
        .get("client_metadata")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    if metadata
        .keys()
        .any(|name| !["client_name", "logo_uri", "vp_formats_supported"].contains(&name.as_str()))
        || metadata
            .get("client_name")
            .is_some_and(|value| value.as_str().is_none_or(|name| !text(name)))
        || metadata
            .get("logo_uri")
            .is_some_and(|value| value.as_str().is_none_or(|uri| !recipient(uri)))
    {
        return Err(invalid());
    }
    let formats = metadata
        .get("vp_formats_supported")
        .and_then(Value::as_object)
        .filter(|formats| !formats.is_empty() && formats.len() <= 16)
        .ok_or_else(invalid)?;
    let format = formats
        .get("dc+sd-jwt")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    if format.len() != 2
        || format
            .keys()
            .any(|name| !["sd-jwt_alg_values", "kb-jwt_alg_values"].contains(&name.as_str()))
    {
        return Err(invalid());
    }
    let issuer_algorithms = text_values(format.get("sd-jwt_alg_values").ok_or_else(invalid)?, 8)?;
    let holder_algorithms = text_values(format.get("kb-jwt_alg_values").ok_or_else(invalid)?, 8)?;
    if issuer_algorithms
        .iter()
        .chain(&holder_algorithms)
        .any(|algorithm| !["ES256", "ES384", "EdDSA", "RS256"].contains(&algorithm.as_str()))
        || !holder_algorithms
            .iter()
            .any(|algorithm| algorithm == "ES256")
    {
        return Err(invalid());
    }
    Ok(SdJwtSelectionPolicy {
        vct_values,
        issuer_algorithms,
        holder_algorithms,
    })
}

fn text_values(value: &Value, maximum: usize) -> Oid4vciResult<Vec<String>> {
    let values = value
        .as_array()
        .filter(|values| !values.is_empty() && values.len() <= maximum)
        .ok_or_else(invalid)?;
    let mut seen = std::collections::HashSet::new();
    values
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .filter(|value| text(value) && seen.insert(*value))
                .ok_or_else(invalid)?;
            Ok(value.to_owned())
        })
        .collect()
}

impl WalletEngine {
    /// Retrieve a signed request through the bounded public HTTPS transport,
    /// then resolve its governed DID method and authenticate its full semantics.
    pub async fn authenticate_governed_did_presentation_request(
        &self,
        input: &str,
        authority: &GovernedDidVerifierAuthority,
    ) -> Oid4vciResult<AuthenticatedPresentationRequest> {
        authority.validate(chrono::Utc::now().timestamp())?;
        let endpoint = crate::wallet::registered_request_endpoint(input, &authority.client_id)?;
        let (body, content_type) = self.fetch_request_object_body(&endpoint).await?;
        let media = content_type.split(';').next().unwrap_or("").trim();
        if !["application/oauth-authz-req+jwt", "application/jwt"]
            .iter()
            .any(|expected| media.eq_ignore_ascii_case(expected))
        {
            return Err(invalid());
        }
        self.reauthenticate_governed_did_signed_request(&body, authority)
            .await
    }

    /// Reauthenticate the original approved JWS with fresh governance, rather
    /// than fetching a replacement request that might change during consent.
    pub async fn reauthenticate_governed_did_signed_request(
        &self,
        compact_jws: &str,
        authority: &GovernedDidVerifierAuthority,
    ) -> Oid4vciResult<AuthenticatedPresentationRequest> {
        let did = authority.validate(chrono::Utc::now().timestamp())?;
        self.verify_governed_did_key_binding(
            did,
            &authority.request_key_id,
            &authority.public_jwk_json,
        )
        .await?;
        let now = chrono::Utc::now().timestamp();
        authority.validate(now)?;
        authenticate_signed_profile(
            compact_jws,
            &authority.key_authority(),
            now,
            Some(authority.expires_at),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn did_claims(client_id: &str, now: i64) -> Value {
        json!({"iss":client_id,"client_id":client_id,"aud":"https://self-issued.me/v2",
            "iat":now,"exp":now+300,"response_type":"vp_token","response_mode":"direct_post",
            "response_uri":"https://verifier.example/response/session-1","nonce":"challenge-1","state":"session-1",
            "dcql_query":{"credentials":[{"id":"identity","format":"dc+sd-jwt",
                "meta":{"vct_values":["Identity"]},"claims":[{"path":["age"]}]}]},
            "client_metadata":{"client_name":"Fixture verifier","logo_uri":"https://verifier.example/logo.svg",
                "vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]},
                    "mso_mdoc":{"alg_values_supported":["ES256"]}}}})
    }

    #[test]
    fn did_query_and_metadata_constraints_are_retained_or_rejected() {
        let claims = did_claims(
            "decentralized_identifier:did:web:verifier.example",
            2_000_000_000,
        );
        let policy = did_selection_policy(&claims).unwrap();
        assert_eq!(policy.vct_values, Some(vec!["Identity".to_owned()]));
        assert_eq!(policy.issuer_algorithms, ["ES256"]);
        for (pointer, replacement) in [
            (
                "/dcql_query/credentials/0/meta",
                json!({"vct_values":["Identity"],"other":true}),
            ),
            ("/dcql_query/credentials/0/meta/vct_values", json!([])),
            (
                "/dcql_query/credentials/0/meta/vct_values",
                json!(["Identity", "Identity"]),
            ),
            (
                "/dcql_query/credentials/0/claims",
                json!([{"path":["age"],"values":[21]}]),
            ),
            (
                "/client_metadata/vp_formats_supported/dc+sd-jwt/kb-jwt_alg_values",
                json!(["EdDSA"]),
            ),
            (
                "/client_metadata/vp_formats_supported/dc+sd-jwt/sd-jwt_alg_values",
                json!(["unknown"]),
            ),
            (
                "/client_metadata/logo_uri",
                json!("http://verifier.example/logo.svg"),
            ),
        ] {
            let mut changed = claims.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(did_selection_policy(&changed).is_err(), "{pointer}");
        }
        let mut changed = claims;
        changed["client_metadata"]["jwks"] = json!({"keys":[]});
        assert!(did_selection_policy(&changed).is_err());
    }

    #[test]
    fn did_snapshot_freshness_is_separate_from_key_validity() {
        let now = 2_000_000_000;
        let mut authority = GovernedDidVerifierAuthority {
            authority_id: "profile/source".into(),
            revision: "revision-1".into(),
            client_id: "decentralized_identifier:did:web:verifier.example".into(),
            request_key_id: "did:web:verifier.example#request-1".into(),
            public_jwk_json: "{}".into(),
            response_uris: vec!["https://verifier.example/response/session-1".into()],
            valid_from: now - 60,
            valid_until: now + 600,
            observed_at: now,
            expires_at: now + 60,
        };
        assert!(authority.validate(now).is_ok());
        assert!(validate_registered_authority(&authority.key_authority(), now).is_err());
        assert!(authority.validate(now + 60).is_err());
        authority.expires_at = now + 61;
        assert!(authority.validate(now).is_err());
        authority.expires_at = now + 60;
        authority.observed_at = now + 1;
        assert!(authority.validate(now).is_err());
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signers"]
    fn remote_did_request_authentication_enforces_vct_algorithms_and_frozen_approval() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let backend = crate::openbao_transit::DisposableOpenBao::from_marked_env();
        let verifier = backend.create_es256();
        let issuer = backend.create_es256();
        let holder = backend.create_es256();
        let public_only = |key: &str| {
            let mut jwk: Value = serde_json::from_str(key).unwrap();
            jwk.as_object_mut().unwrap().remove("kid");
            jwk
        };
        let verifier_jwk = public_only(verifier.public_jwk());
        let issuer_jwk = public_only(issuer.public_jwk());
        let holder_jwk = public_only(holder.public_jwk());
        let did = format!(
            "did:jwk:{}",
            URL_SAFE_NO_PAD.encode(verifier_jwk.to_string())
        );
        let now = chrono::Utc::now().timestamp();
        let authority = GovernedDidVerifierAuthority {
            authority_id: "profile/source".into(),
            revision: "revision-1".into(),
            client_id: format!("decentralized_identifier:{did}"),
            request_key_id: format!("{did}#0"),
            public_jwk_json: verifier_jwk.to_string(),
            response_uris: vec!["https://verifier.example/response/session-1".into()],
            valid_from: now - 60,
            valid_until: now + 600,
            observed_at: now,
            expires_at: now + 60,
        };
        let claims = did_claims(&authority.client_id, now);
        let header =
            json!({"alg":"ES256","typ":"oauth-authz-req+jwt","kid":authority.request_key_id});
        let signed = jose::sign_test_compact_es256(&verifier, &header, &claims);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let engine = WalletEngine::new();
        let authenticated = runtime
            .block_on(engine.reauthenticate_governed_did_signed_request(&signed, &authority))
            .unwrap();
        assert_eq!(authenticated.compact_jws(), signed);
        assert_eq!(
            authenticated
                .request()
                .dcql_query
                .as_ref()
                .unwrap()
                .credentials[0]
                .meta,
            Some(json!({"vct_values":["Identity"]}))
        );

        let disclosure = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!([uuid::Uuid::new_v4().to_string(), "age", 21])).unwrap(),
        );
        let disclosure_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()));
        let issuer_claims = json!({"iss":"https://issuer.example","vct":"Identity","iat":now,"exp":now+600,
            "_sd_alg":"sha-256","_sd":[disclosure_hash],"cnf":{"jwk":holder_jwk}});
        let issuer_jwt = jose::sign_test_compact_es256(
            &issuer,
            &json!({"alg":"ES256","typ":"dc+sd-jwt","kid":"issuer-key-1"}),
            &issuer_claims,
        );
        let credential = format!("{issuer_jwt}~{disclosure}~");
        let keys = crate::TrustedSdJwtIssuerKeys::new(vec![crate::ResolvedSdJwtIssuerKey::new(
            "https://issuer.example",
            Some("issuer-key-1".into()),
            crate::types::SigningAlgorithm::ES256,
            issuer_jwk.to_string(),
        )])
        .unwrap();
        let verified = authenticated
            .verify_sd_jwt_for_consent(&credential, &holder_jwk.to_string(), &keys)
            .unwrap();
        assert_eq!(verified.credential_type, "Identity");
        assert!(authenticated
            .prepare_sd_jwt_presentation(
                &credential,
                &["unrequested".into()],
                &holder_jwk.to_string(),
                &keys
            )
            .is_err());
        assert!(authenticated
            .prepare_sd_jwt_presentation(&credential, &[], &holder_jwk.to_string(), &keys)
            .is_err());
        let mut two_required = claims.clone();
        two_required["dcql_query"]["credentials"][0]["claims"] =
            json!([{"path":["age"]},{"path":["family_name"]}]);
        let two_required = jose::sign_test_compact_es256(&verifier, &header, &two_required);
        let two_required = runtime
            .block_on(engine.reauthenticate_governed_did_signed_request(&two_required, &authority))
            .unwrap();
        assert!(two_required
            .prepare_sd_jwt_presentation(
                &credential,
                &["age".into()],
                &holder_jwk.to_string(),
                &keys
            )
            .is_err());
        let prepared = authenticated
            .prepare_sd_jwt_presentation(
                &credential,
                &["age".into()],
                &holder_jwk.to_string(),
                &keys,
            )
            .unwrap();
        let signature = holder.sign(prepared.signing_input()).unwrap();
        let presentation = prepared.complete(&signature).unwrap();
        let proof = presentation.rsplit('~').next().unwrap();
        let proof =
            jose::verify_compact_jwt_with_public_jwk(proof, &holder_jwk.to_string(), "ES256")
                .unwrap();
        assert_eq!(proof.claims["nonce"], "challenge-1");
        assert_eq!(proof.claims["aud"], authority.client_id);

        for (pointer, replacement) in [
            (
                "/dcql_query/credentials/0/meta/vct_values",
                json!(["OtherCredential"]),
            ),
            (
                "/client_metadata/vp_formats_supported/dc+sd-jwt/sd-jwt_alg_values",
                json!(["EdDSA"]),
            ),
        ] {
            let mut changed = claims.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            let changed = jose::sign_test_compact_es256(&verifier, &header, &changed);
            let request = runtime
                .block_on(engine.reauthenticate_governed_did_signed_request(&changed, &authority))
                .unwrap();
            assert!(
                request
                    .verify_sd_jwt_for_consent(&credential, &holder_jwk.to_string(), &keys)
                    .is_err(),
                "{pointer}"
            );
        }
        for field in ["transaction_data", "client_id_scheme"] {
            let mut changed = claims.clone();
            changed[field] = json!("unsupported");
            let changed = jose::sign_test_compact_es256(&verifier, &header, &changed);
            assert!(runtime
                .block_on(engine.reauthenticate_governed_did_signed_request(&changed, &authority))
                .is_err());
        }
        let mut revision = authority.clone();
        revision.revision = "revision-2".into();
        let fresh = runtime
            .block_on(engine.reauthenticate_governed_did_signed_request(&signed, &revision))
            .unwrap();
        assert_ne!(
            authenticated.consent_binding_digest(),
            fresh.consent_binding_digest()
        );
        let mut destination = authority.clone();
        destination.response_uris = vec!["https://other.example/response".into()];
        assert!(runtime
            .block_on(engine.reauthenticate_governed_did_signed_request(&signed, &destination))
            .is_err());
        let mut expired = authority;
        expired.expires_at = now - 1;
        assert!(runtime
            .block_on(engine.reauthenticate_governed_did_signed_request(&signed, &expired))
            .is_err());
    }

    #[test]
    fn refuses_lossy_or_unsupported_query_semantics() {
        let query = json!({"credentials":[{"id":"identity","format":"dc+sd-jwt","claims":[{"path":["age"]}]}]});
        assert!(plain_sd_jwt_query(&query));
        for (field, value) in [
            ("meta", json!({"vct_values":["Identity"]})),
            ("require_cryptographic_holder_binding", json!(false)),
            ("claim_sets", json!([["age"]])),
        ] {
            let mut changed = query.clone();
            changed["credentials"][0][field] = value;
            assert!(!plain_sd_jwt_query(&changed), "accepted {field}");
        }
        for claim in [
            json!({"path":["age"],"values":[18]}),
            json!({"path":["address","city"]}),
            json!({"path":[null]}),
        ] {
            let mut changed = query.clone();
            changed["credentials"][0]["claims"] = json!([claim]);
            assert!(!plain_sd_jwt_query(&changed));
        }
        let mut duplicate = query.clone();
        duplicate["credentials"][0]["claims"] = json!([{"path":["age"]},{"path":["age"]}]);
        assert!(!plain_sd_jwt_query(&duplicate));
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn remote_registered_request_authentication_binds_identity_recipient_time_and_semantics() {
        let signer = crate::openbao_transit::DisposableOpenBao::from_marked_env().create_es256();
        let now = 2_000_000_000;
        let authority = RegisteredVerifierAuthority {
            authority_id: "governed-verifier-1".into(),
            revision: "revision-7".into(),
            client_id: "registered-verifier".into(),
            request_key_id: "request-key-1".into(),
            public_jwk_json: signer.public_jwk().into(),
            response_uris: vec!["https://verifier.example/response/session-1".into()],
            valid_from: now - 60,
            valid_until: now + 600,
        };
        let header = json!({"alg":"ES256","typ":"oauth-authz-req+jwt","kid":"request-key-1"});
        let claims = json!({"iss":authority.client_id,"client_id":authority.client_id,
            "aud":"https://self-issued.me/v2","iat":now,"exp":now+300,
            "response_type":"vp_token","response_mode":"direct_post",
            "response_uri":authority.response_uris[0],"nonce":"challenge-1","state":"session-1",
            "dcql_query":{"credentials":[{"id":"identity","format":"dc+sd-jwt","claims":[{"path":["age"]}]}]}});
        let sign =
            |header: &Value, claims: &Value| jose::sign_test_compact_es256(&signer, header, claims);
        let token = sign(&header, &claims);
        let authenticated =
            authenticate_registered_presentation_request(&token, &authority, now).unwrap();
        assert_eq!(authenticated.compact_jws(), token);
        assert_eq!(
            authenticated.request().response_uri,
            authority.response_uris[0]
        );
        assert_eq!(authenticated.authority_revision(), "revision-7");
        assert_eq!(authenticated.expires_at(), now + 300);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for finish in [now, now + 301, now + 601] {
            let mut calls = 0;
            let result = runtime.block_on(
                crate::wallet::authenticate_registered_request_with_transport(
                    "https://verifier.example/request",
                    &authority,
                    || {
                        calls += 1;
                        if calls == 1 {
                            now
                        } else {
                            finish
                        }
                    },
                    |endpoint| {
                        assert_eq!(endpoint, "https://verifier.example/request");
                        let body = token.clone();
                        async move {
                            Ok((
                                body,
                                "Application/OAuth-Authz-Req+JWT; charset=utf-8".into(),
                            ))
                        }
                    },
                ),
            );
            assert_eq!(calls, 2);
            assert_eq!(
                result.is_ok(),
                finish == now,
                "fetch completion time {finish}"
            );
        }
        for (field, value) in [
            ("client_id", json!("attacker")),
            ("iss", json!("attacker")),
            ("aud", json!("https://attacker.example")),
            ("response_uri", json!("https://attacker.example")),
            ("exp", json!(now)),
            ("iat", json!(now + 31)),
            ("nbf", json!(now + 1)),
            ("response_mode", json!("direct_post.jwt")),
            ("transaction_data", json!(["opaque"])),
            ("client_id_scheme", json!("pre-registered")),
            ("client_metadata", json!({})),
        ] {
            let mut changed = claims.clone();
            changed[field] = value;
            assert!(
                authenticate_registered_presentation_request(
                    &sign(&header, &changed),
                    &authority,
                    now
                )
                .is_err(),
                "accepted {field}"
            );
        }
        for (field, value) in [
            ("kid", json!("attacker")),
            ("typ", json!("JWT")),
            ("jwk", json!({})),
            ("crit", json!([])),
        ] {
            let mut changed = header.clone();
            changed[field] = value;
            assert!(
                authenticate_registered_presentation_request(
                    &sign(&changed, &claims),
                    &authority,
                    now
                )
                .is_err(),
                "accepted header {field}"
            );
        }
        let mut stale = authority.clone();
        stale.valid_until = now;
        assert!(authenticate_registered_presentation_request(&token, &stale, now).is_err());
        assert!(
            authenticate_registered_presentation_request(&token, &authority, now + 301).is_err()
        );
        assert!(
            authenticate_registered_presentation_request(&token, &authority, now + 601).is_err()
        );
        let other = crate::openbao_transit::DisposableOpenBao::from_marked_env().create_es256();
        let mut wrong_key = authority.clone();
        wrong_key.public_jwk_json = other.public_jwk().into();
        assert!(authenticate_registered_presentation_request(&token, &wrong_key, now).is_err());
        for query in [
            json!({"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{"vct_values":["Identity"]},"claims":[{"path":["age"]}]}]}),
            json!({"credentials":[{"id":"identity","format":"dc+sd-jwt","claims":[{"path":["age"],"values":[18]}]}]}),
        ] {
            let mut changed = claims.clone();
            changed["dcql_query"] = query;
            assert!(authenticate_registered_presentation_request(
                &sign(&header, &changed),
                &authority,
                now
            )
            .is_err());
        }
        let mut wrong = authority.clone();
        wrong.response_uris = vec!["https://verifier.example/response/other".into()];
        assert!(authenticate_registered_presentation_request(&token, &wrong, now).is_err());
        let mut tampered = token.into_bytes();
        let last = tampered.len() - 5;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert!(authenticate_registered_presentation_request(
            std::str::from_utf8(&tampered).unwrap(),
            &authority,
            now
        )
        .is_err());
    }
}
