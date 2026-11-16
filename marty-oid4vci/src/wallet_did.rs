//! DID-method key binding for governed OID4VP verifier identities.
//! Resolution proves neither governance permission nor request authenticity.

use serde_json::Value;

use crate::{jose, Oid4vciError, Oid4vciResult, WalletEngine};

const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

fn invalid() -> Oid4vciError {
    Oid4vciError::InvalidRequest("Unsupported or mismatched verifier DID key".into())
}

fn text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn validate_identifier(did: &str, kid: &str) -> Oid4vciResult<()> {
    if !text(did)
        || did.contains(['#', '?', '/', '\\'])
        || !text(kid)
        || kid
            .strip_prefix(did)
            .and_then(|value| value.strip_prefix('#'))
            .is_none_or(|fragment| fragment.is_empty() || fragment.contains(['#', '?', '/', '\\']))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Map the supported ASCII did:web profile without letting URL normalization
/// reinterpret separators, credentials, encoded traversal or an IP address.
fn did_web_url(did: &str) -> Oid4vciResult<String> {
    let identifier = did.strip_prefix("did:web:").ok_or_else(invalid)?;
    let mut parts = identifier.split(':');
    let host = parts
        .next()
        .ok_or_else(invalid)?
        .replace("%3A", ":")
        .replace("%3a", ":");
    if host.is_empty()
        || !host.is_ascii()
        || host
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b".-:".contains(&byte))
    {
        return Err(invalid());
    }
    let mut url = url::Url::parse(&format!("https://{host}/")).map_err(|_| invalid())?;
    if !matches!(url.host(), Some(url::Host::Domain(_)))
        || url.port() == Some(0)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid());
    }
    let paths = parts.collect::<Vec<_>>();
    if paths.iter().any(|part| {
        part.is_empty()
            || matches!(*part, "." | "..")
            || part
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !b"._-".contains(&byte))
    }) {
        return Err(invalid());
    }
    {
        let mut segments = url.path_segments_mut().map_err(|_| invalid())?;
        segments.clear();
        if paths.is_empty() {
            segments.push(".well-known");
        } else {
            for part in paths {
                segments.push(part);
            }
        }
        segments.push("did.json");
    }
    Ok(url.into())
}

fn public_es256(value: &Value, kid: &str) -> Oid4vciResult<()> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object
        .get("kid")
        .is_some_and(|value| value.as_str() != Some(kid))
    {
        return Err(invalid());
    }
    jose::validate_public_signing_jwk_json(&value.to_string(), "ES256").map_err(|_| invalid())
}

fn same_key(resolved: &Value, expected: &Value, kid: &str) -> Oid4vciResult<()> {
    public_es256(resolved, kid)?;
    public_es256(expected, kid)?;
    if ["kty", "crv", "x", "y"]
        .iter()
        .any(|field| resolved.get(field) != expected.get(field))
    {
        return Err(invalid());
    }
    Ok(())
}

fn document_key(body: &[u8], did: &str, kid: &str) -> Oid4vciResult<Value> {
    if body.len() > MAX_DOCUMENT_BYTES {
        return Err(invalid());
    }
    let document =
        jose::parse_unique_object(body, "verifier DID document").map_err(|_| invalid())?;
    // This resolver consumes the DID JSON representation. JSON-LD context
    // processing must not be approximated by ignoring aliases or redefinitions.
    if document.get("id").and_then(Value::as_str) != Some(did) || document.get("@context").is_some()
    {
        return Err(invalid());
    }
    let methods = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .filter(|methods| !methods.is_empty() && methods.len() <= 32)
        .ok_or_else(invalid)?;
    let mut ids = std::collections::HashSet::new();
    let mut selected = None;
    for method in methods {
        let id = method
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| text(id))
            .ok_or_else(invalid)?;
        if !ids.insert(id) {
            return Err(invalid());
        }
        if let Some(jwk) = method.get("publicKeyJwk") {
            // Even unused verification methods must not introduce private keys.
            marty_crypto::public_jwk::PublicJwk::from_json(&jwk.to_string())
                .map_err(|_| invalid())?;
        }
        if id == kid {
            let object = method.as_object().ok_or_else(invalid)?;
            if object
                .keys()
                .any(|key| !["id", "controller", "type", "publicKeyJwk"].contains(&key.as_str()))
                || method.get("controller").and_then(Value::as_str) != Some(did)
                || method.get("type").and_then(Value::as_str) != Some("JsonWebKey2020")
            {
                return Err(invalid());
            }
            selected = method.get("publicKeyJwk").cloned();
        }
    }
    for relationship in [
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ] {
        let Some(value) = document.get(relationship) else {
            if relationship == "authentication" {
                return Err(invalid());
            }
            continue;
        };
        let references = value
            .as_array()
            .filter(|values| values.len() <= 32)
            .ok_or_else(invalid)?;
        let mut seen = std::collections::HashSet::new();
        for reference in references {
            let reference = reference.as_str().ok_or_else(invalid)?;
            // This profile has one definition per method in verificationMethod.
            // Inline definitions must not shadow it in any relationship.
            if !ids.contains(reference) || !seen.insert(reference) {
                return Err(invalid());
            }
        }
        if relationship == "authentication" && !seen.contains(kid) {
            return Err(invalid());
        }
    }
    selected.ok_or_else(invalid)
}

impl WalletEngine {
    /// Prove that an externally governed ES256 verifier key is the selected
    /// authentication verification method of its DID. Uses did:web JSON over
    /// pinned public HTTPS, or locally resolves did:jwk / did:key. No key is
    /// trusted merely because it appears in a request or DID document. Callers
    /// still need fresh verifier governance and signed-request authentication.
    pub async fn verify_governed_did_key_binding(
        &self,
        did: &str,
        request_key_id: &str,
        governed_public_jwk_json: &str,
    ) -> Oid4vciResult<()> {
        validate_identifier(did, request_key_id)?;
        if governed_public_jwk_json.len() > jose::MAX_PUBLIC_JWK_BYTES {
            return Err(invalid());
        }
        let expected =
            jose::parse_unique_object(governed_public_jwk_json.as_bytes(), "governed verifier key")
                .map_err(|_| invalid())?;
        public_es256(&expected, request_key_id)?;
        let resolved = if did.starts_with("did:web:") {
            let endpoint = did_web_url(did)?;
            let (client, endpoint) = crate::network::public_request_client(&endpoint).await?;
            let response = client
                .get(endpoint)
                .header("accept", "application/did+json, application/json")
                .send()
                .await
                .map_err(|_| invalid())?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(invalid());
            }
            let media = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            if !["application/did+json", "application/json"]
                .iter()
                .any(|expected| media.eq_ignore_ascii_case(expected))
            {
                return Err(invalid());
            }
            let body =
                crate::wallet::bounded_response_body(response, "Verifier DID", MAX_DOCUMENT_BYTES)
                    .await?;
            document_key(&body, did, request_key_id)?
        } else if did.starts_with("did:jwk:") || did.starts_with("did:key:z") {
            let fragment = if did.starts_with("did:jwk:") {
                "0"
            } else {
                did.strip_prefix("did:key:").ok_or_else(invalid)?
            };
            if request_key_id != format!("{did}#{fragment}") {
                return Err(invalid());
            }
            let (resolved_did, key) =
                crate::proof::resolve_self_certifying_holder_key(request_key_id)?;
            if resolved_did != did {
                return Err(invalid());
            }
            serde_json::to_value(key.ok_or_else(invalid)?).map_err(|_| invalid())?
        } else {
            return Err(invalid());
        };
        same_key(&resolved, &expected, request_key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde_json::json;

    fn public() -> Value {
        json!({"kty":"EC","crv":"P-256",
            "x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"})
    }

    #[test]
    fn web_mapping_is_method_bound_without_url_reinterpretation() {
        for (did, url) in [
            (
                "did:web:example.com",
                "https://example.com/.well-known/did.json",
            ),
            (
                "did:web:example.com:oid4vp",
                "https://example.com/oid4vp/did.json",
            ),
            (
                "did:web:example.com%3A8443:org:verifier",
                "https://example.com:8443/org/verifier/did.json",
            ),
        ] {
            assert_eq!(did_web_url(did).unwrap(), url);
        }
        for did in [
            "did:web:127.0.0.1",
            "did:web:2130706433",
            "did:web:example.com:..",
            "did:web:example.com:%2e%2e",
            "did:web:example.com%2fadmin",
            "did:web:example.com:one/two",
            "did:web:user@example.com",
            "did:web:example.com:abc?query",
            "did:web:example.com:",
            "did:web:example.com%3A0",
        ] {
            assert!(did_web_url(did).is_err(), "{did}");
        }
    }

    #[test]
    fn document_key_requires_exact_subject_method_controller_and_authentication() {
        let did = "did:web:example.com:oid4vp";
        let kid = format!("{did}#request-1");
        let document = json!({"id":did, "verificationMethod":[{"id":kid,"type":"JsonWebKey2020","controller":did,"publicKeyJwk":public()}],"authentication":[kid]});
        assert_eq!(
            document_key(&serde_json::to_vec(&document).unwrap(), did, &kid).unwrap(),
            public()
        );
        for (pointer, replacement) in [
            ("/id", json!("did:web:other.example")),
            (
                "/verificationMethod/0/controller",
                json!("did:web:other.example"),
            ),
            ("/authentication", json!([])),
            ("/verificationMethod/0/type", json!("UnsupportedKey")),
        ] {
            let mut changed = document.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(document_key(&serde_json::to_vec(&changed).unwrap(), did, &kid).is_err());
        }
        let mut duplicate = document.clone();
        duplicate["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(document["verificationMethod"][0].clone());
        assert!(document_key(&serde_json::to_vec(&duplicate).unwrap(), did, &kid).is_err());
        let duplicate_json = document.to_string().replacen("{", "{\"id\":\"other\",", 1);
        assert!(document_key(duplicate_json.as_bytes(), did, &kid).is_err());
        for relationship in [
            "authentication",
            "assertionMethod",
            "keyAgreement",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            let mut conflicting = document.clone();
            let mut alternate = document["verificationMethod"][0].clone();
            alternate["publicKeyJwk"]["x"] = json!("different-key");
            conflicting[relationship] = json!([kid, alternate]);
            assert!(document_key(&serde_json::to_vec(&conflicting).unwrap(), did, &kid).is_err());
            conflicting[relationship] = json!([kid, kid]);
            assert!(document_key(&serde_json::to_vec(&conflicting).unwrap(), did, &kid).is_err());
        }
        let mut context = document;
        context["@context"] = json!({"id":"https://attacker.example/redefined"});
        assert!(document_key(&serde_json::to_vec(&context).unwrap(), did, &kid).is_err());
    }

    #[tokio::test]
    async fn self_certifying_keys_are_method_resolved_and_compared_to_governance() {
        let jwk = public();
        let did = format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(jwk.to_string()));
        let engine = WalletEngine::new();
        engine
            .verify_governed_did_key_binding(&did, &format!("{did}#0"), &jwk.to_string())
            .await
            .unwrap();
        assert!(engine
            .verify_governed_did_key_binding(&did, &format!("{did}#other"), &jwk.to_string())
            .await
            .is_err());
        let mut wrong = jwk.clone();
        wrong["x"] = json!("invalid");
        assert!(engine
            .verify_governed_did_key_binding(&did, &format!("{did}#0"), &wrong.to_string())
            .await
            .is_err());
        let mut private = jwk.clone();
        private["d"] = json!("forbidden");
        assert!(engine
            .verify_governed_did_key_binding(&did, &format!("{did}#0"), &private.to_string())
            .await
            .is_err());
        let mut multicodec = vec![0x80, 0x24, 0x03];
        multicodec.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap());
        let fingerprint = format!("z{}", crate::proof::base58btc_encode(&multicodec));
        let did = format!("did:key:{fingerprint}");
        engine
            .verify_governed_did_key_binding(
                &did,
                &format!("{did}#{fingerprint}"),
                &jwk.to_string(),
            )
            .await
            .unwrap();
        assert!(engine
            .verify_governed_did_key_binding(&did, &format!("{did}#other"), &jwk.to_string())
            .await
            .is_err());
    }
}
