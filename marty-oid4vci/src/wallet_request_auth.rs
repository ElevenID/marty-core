//! Authentication of an explicitly pre-registered OID4VP verifier.
//!
//! Authority must come from the caller's fresh governed verifier relationship,
//! never from issuer trust, the request's embedded keys, or its retrieval URL.
//! This initial profile deliberately does not implement DID, certificate,
//! federation, attestation, encrypted-response or transaction-data semantics.

use serde_json::Value;

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

/// Signature-authenticated request with its original signed bytes retained.
/// Construction and mutation are private to the authentication boundary.
pub struct AuthenticatedPresentationRequest {
    request: ParsedPresentationRequest,
    compact_jws: String,
    authority_id: String,
    authority_revision: String,
    expires_at: i64,
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
    if !text(&authority.authority_id)
        || !text(&authority.revision)
        || !text(&authority.client_id)
        || authority.client_id.contains(':')
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
        || claims
            .get("dcql_query")
            .is_none_or(|query| !plain_sd_jwt_query(query))
    {
        return Err(invalid());
    }
    let request = WalletEngine::parsed_request_from_value(verified.claims)?;
    Ok(AuthenticatedPresentationRequest {
        request,
        compact_jws: compact_jws.to_owned(),
        authority_id: authority.authority_id.clone(),
        authority_revision: authority.revision.clone(),
        expires_at: expires,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
