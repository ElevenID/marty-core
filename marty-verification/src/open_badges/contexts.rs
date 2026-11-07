use std::collections::HashMap;

use ssi_json_ld::ContextLoader;

use crate::error::{VerificationError, VerificationResult};

const CONTEXT_OPENBADGES_V3: &str = "https://purl.imsglobal.org/spec/ob/v3p0/context.json";
const CONTEXT_OPENBADGES_V3_303: &str =
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json";
const CONTEXT_OPENBADGES_V3_ALIAS: &str = "https://w3id.org/openbadges/v3";
const CONTEXT_VC_V1: &str = "https://www.w3.org/2018/credentials/v1";
const CONTEXT_VC_V2: &str = "https://www.w3.org/ns/credentials/v2";
const CONTEXT_VC_EXAMPLES_V2: &str = "https://www.w3.org/ns/credentials/examples/v2";
const CONTEXT_BITSTRING_STATUS_V1: &str = "https://www.w3.org/ns/credentials/status/v1";
const CONTEXT_DATA_INTEGRITY_V2: &str = "https://w3id.org/security/data-integrity/v2";
const CONTEXT_SECURITY_V1: &str = "https://w3id.org/security/v1";
const CONTEXT_SECURITY_V2: &str = "https://w3id.org/security/v2";
const CONTEXT_SECURITY_ED25519_2020: &str = "https://w3id.org/security/suites/ed25519-2020/v1";
const CONTEXT_SECURITY_JWS_2020: &str = "https://w3id.org/security/suites/jws-2020/v1";

const CONTEXT_FILE_OPENBADGES_V3: &str = include_str!("contexts/openbadges-v3.jsonld");
const CONTEXT_FILE_VC_V1: &str = include_str!("contexts/credentials-v1.jsonld");
const CONTEXT_FILE_VC_V2: &str = include_str!("contexts/credentials-v2.jsonld");
const CONTEXT_FILE_VC_EXAMPLES_V2: &str =
    r#"{"@context":{"@vocab":"https://www.w3.org/ns/credentials/examples#"}}"#;
const CONTEXT_FILE_BITSTRING_STATUS_V1: &str = include_str!("contexts/bitstring-status-v1.jsonld");
const CONTEXT_FILE_DATA_INTEGRITY_V2: &str =
    include_str!("contexts/security-data-integrity-v2.jsonld");
const CONTEXT_FILE_SECURITY_V1: &str = include_str!("contexts/security-v1.jsonld");
const CONTEXT_FILE_SECURITY_V2: &str = include_str!("contexts/security-v2.jsonld");
const CONTEXT_FILE_SECURITY_ED25519_2020: &str =
    include_str!("contexts/security-ed25519-2020.jsonld");
const CONTEXT_FILE_SECURITY_JWS_2020: &str = include_str!("contexts/security-jws-2020.jsonld");

pub fn open_badges_context_loader() -> VerificationResult<ContextLoader> {
    let mut context_map = HashMap::new();

    context_map.insert(
        CONTEXT_OPENBADGES_V3.to_string(),
        CONTEXT_FILE_OPENBADGES_V3.to_string(),
    );
    context_map.insert(
        CONTEXT_OPENBADGES_V3_303.to_string(),
        CONTEXT_FILE_OPENBADGES_V3.to_string(),
    );
    context_map.insert(
        CONTEXT_OPENBADGES_V3_ALIAS.to_string(),
        CONTEXT_FILE_OPENBADGES_V3.to_string(),
    );
    context_map.insert(CONTEXT_VC_V1.to_string(), CONTEXT_FILE_VC_V1.to_string());
    context_map.insert(CONTEXT_VC_V2.to_string(), CONTEXT_FILE_VC_V2.to_string());
    context_map.insert(
        CONTEXT_VC_EXAMPLES_V2.to_string(),
        CONTEXT_FILE_VC_EXAMPLES_V2.to_string(),
    );
    context_map.insert(
        CONTEXT_BITSTRING_STATUS_V1.to_string(),
        CONTEXT_FILE_BITSTRING_STATUS_V1.to_string(),
    );
    context_map.insert(
        CONTEXT_DATA_INTEGRITY_V2.to_string(),
        CONTEXT_FILE_DATA_INTEGRITY_V2.to_string(),
    );
    context_map.insert(
        CONTEXT_SECURITY_V1.to_string(),
        CONTEXT_FILE_SECURITY_V1.to_string(),
    );
    context_map.insert(
        CONTEXT_SECURITY_V2.to_string(),
        CONTEXT_FILE_SECURITY_V2.to_string(),
    );
    context_map.insert(
        CONTEXT_SECURITY_ED25519_2020.to_string(),
        CONTEXT_FILE_SECURITY_ED25519_2020.to_string(),
    );
    context_map.insert(
        CONTEXT_SECURITY_JWS_2020.to_string(),
        CONTEXT_FILE_SECURITY_JWS_2020.to_string(),
    );

    // Use only pinned contexts so OB3+VC v2 compatibility tweaks take effect.
    ContextLoader::empty()
        .with_context_map_from(context_map)
        .map_err(|e| {
            VerificationError::open_badges(format!("Failed to build context loader: {}", e))
        })
}

pub fn ob3_context_uri() -> &'static str {
    CONTEXT_OPENBADGES_V3
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    #[test]
    fn vendored_vcdm_v2_context_preserves_protected_term_boundaries() {
        let context: Value = serde_json::from_str(CONTEXT_FILE_VC_V2).unwrap();

        assert_eq!(context["@context"]["@protected"], true);
        assert_eq!(
            context["@context"]["VerifiableCredential"]["@context"]["@protected"],
            true
        );
    }

    #[test]
    fn vendored_bitstring_status_context_matches_w3c_recommendation_digest() {
        assert_eq!(
            hex::encode(Sha256::digest(CONTEXT_FILE_BITSTRING_STATUS_V1.as_bytes())),
            "fda5add353231e6a6884a46b12e6c75464281900cb348284d9c360f62381d9f7"
        );
    }

    // Independent expected N-Quads were generated with PyLD 3.3.0 URDNA2015,
    // using this repository's vendored credentials-v2.jsonld (no network loader).
    // Its SHA-256 is e2fdd92278c972bec624dfffd9a89558d92556a9b8fd246a6a8daed1c98de46e.
    // The consumer API below still selects only eddsa-rdfc-2022 and uses a public
    // JWK; it captures preparation bytes without a private key or signing service.
    const CANONICALIZATION_CREDENTIAL: &str =
        include_str!("../../tests/fixtures/ssi_canonicalization_consumer.json");
    const CANONICALIZATION_NQUADS: &str =
        include_str!("../../tests/fixtures/ssi_canonicalization_consumer.nq");

    async fn consumer_signing_input(credential: Value) -> Result<Vec<u8>, String> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let request = serde_json::json!({
            "credential": credential,
            "issuer_did": "did:web:issuer.example",
            "verification_method_id": "did:web:issuer.example#assertion",
            "public_jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": marty_crypto_test_support::ED25519_PUBLIC_JWK_X,
            }
        });
        let prepared =
            crate::vcdm::prepare_vcdm_data_integrity_credential_json_async(&request.to_string())
                .await?;
        let prepared: Value = serde_json::from_str(&prepared).unwrap();
        assert_eq!(prepared["algorithm"], "EdDSA");
        assert_eq!(
            prepared["credential"]["proof"]["cryptosuite"],
            "eddsa-rdfc-2022"
        );
        let bytes = URL_SAFE_NO_PAD
            .decode(prepared["signing_input_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(bytes.len(), 64);
        Ok(bytes)
    }

    fn canonicalization_credential() -> Value {
        serde_json::from_str(CANONICALIZATION_CREDENTIAL).unwrap()
    }

    #[tokio::test]
    async fn canonicalization_consumer_matches_independent_nquads_digest() {
        let expected = Sha256::digest(CANONICALIZATION_NQUADS.as_bytes());
        assert_eq!(
            hex::encode(expected),
            "b7bb66a5d1397d71e6df0de3aacb3864ef166483ea64c9a360f65b259aae37b2"
        );
        let prepared = consumer_signing_input(canonicalization_credential())
            .await
            .unwrap();
        // EdDSA-RDFC's signing input is proof-config hash || credential hash.
        // Checking the independent credential digest also covers graph names,
        // datatype IRIs, JSON lexical form, and symmetric blank-node labels.
        assert_eq!(&prepared[32..], expected.as_slice());
    }

    #[tokio::test]
    async fn canonicalization_consumer_is_invariant_to_blank_labels_and_json_key_order() {
        let original = consumer_signing_input(canonicalization_credential())
            .await
            .unwrap();
        let mut equivalent = canonicalization_credential();
        let subject = &mut equivalent["credentialSubject"];
        subject["node"][0]["@id"] = serde_json::json!("_:renamed-z");
        subject["node"][1]["@id"] = serde_json::json!("_:renamed-a");
        subject["node"].as_array_mut().unwrap().reverse();
        // JSON object member order is not part of an RDF JSON literal's meaning.
        for pointer in ["/payload", "/@graph/0/payload", "/@included/0/payload"] {
            *subject.pointer_mut(pointer).unwrap() =
                serde_json::from_str(r#"{"a":{"a":null,"z":2},"z":1}"#).unwrap();
        }
        assert_ne!(
            canonicalization_credential()["credentialSubject"]["payload"].to_string(),
            equivalent["credentialSubject"]["payload"].to_string()
        );
        let reordered = consumer_signing_input(equivalent).await.unwrap();
        assert_eq!(&original[32..], &reordered[32..]);
    }

    #[tokio::test]
    async fn canonicalization_consumer_binds_nested_json_datatypes_and_custom_literals() {
        let original = consumer_signing_input(canonicalization_credential())
            .await
            .unwrap();
        for (pointer, replacement) in [
            (
                "/credentialSubject/@graph/0/payload/z",
                serde_json::json!(3),
            ),
            (
                "/credentialSubject/@included/0/payload/z",
                serde_json::json!(3),
            ),
            (
                "/@context/1/custom/@type",
                serde_json::json!("urn:example:OtherDatatype"),
            ),
            (
                "/credentialSubject/@graph/0/custom",
                serde_json::json!(r#"{"a":2,"z":1}"#),
            ),
        ] {
            let mut changed = canonicalization_credential();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            let prepared = consumer_signing_input(changed).await.unwrap();
            assert_ne!(&original[32..], &prepared[32..], "{pointer}");
        }
    }

    #[tokio::test]
    async fn canonicalization_consumer_rejects_unknown_contexts_and_lossy_terms() {
        let original = canonicalization_credential();
        let mut unknown_context = original.clone();
        unknown_context["@context"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!(
                "https://untrusted.example/context.jsonld"
            ));
        let mut undefined_term = original.clone();
        undefined_term["credentialSubject"]["undefinedTerm"] =
            serde_json::json!("must not disappear");
        let mut malformed_type = original.clone();
        malformed_type["@context"][1]["custom"]["@type"] = serde_json::json!(7);
        let mut protected_term = original.clone();
        protected_term["@context"][1]["name"] = serde_json::json!("urn:example:substitutedName");
        let mut undefined_type = original;
        undefined_type["credentialSubject"]["type"] = serde_json::json!("UndefinedCredentialType");

        for (name, credential) in [
            ("unknown context", unknown_context),
            ("undefined term", undefined_term),
            ("malformed type", malformed_type),
            ("protected term", protected_term),
            ("undefined type", undefined_type),
        ] {
            assert!(
                consumer_signing_input(credential).await.is_err(),
                "{name} must not produce remote-signing input"
            );
        }
    }
}
