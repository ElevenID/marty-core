use marty_didcomm::types::{DidDocument, Jwk, VerificationMethod};

const PRIVATE_MEMBERS: &[&str] = &["d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const PRIVATE_METHOD_MEMBERS: &[&str] = &[
    "privateKeyJwk",
    "privateKeyPem",
    "privateKeyBase58",
    "privateKeyMultibase",
    "privateKeyHex",
];

#[test]
fn all_relationships_reject_private_inline_jwks_at_ingestion() {
    for relationship in ["authentication", "assertionMethod", "keyAgreement"] {
        for member in PRIVATE_MEMBERS {
            let mut jwk = serde_json::json!({"kty":"EC", "crv":"P-256", "x":"x", "y":"y"});
            jwk.as_object_mut()
                .unwrap()
                .insert((*member).into(), serde_json::json!("secret-sentinel"));
            let document = serde_json::json!({
                "id":"did:example:holder",
                (relationship): [{
                    "id":"#key-1",
                    "type":"JsonWebKey2020",
                    "controller":"did:example:holder",
                    "publicKeyJwk": jwk
                }]
            });
            let error = serde_json::from_value::<DidDocument>(document).unwrap_err();
            assert!(error.to_string().contains("private JWK member"));
            assert!(!format!("{error:?}").contains("secret-sentinel"));
        }
    }
}

#[test]
fn relationship_setters_accept_references_and_reject_private_inline_methods() {
    let mut document = DidDocument::new("did:example:holder");
    let references = vec![serde_json::json!("#key-1")];
    document.set_authentication(references.clone()).unwrap();
    document.set_assertion_methods(references.clone()).unwrap();
    document.set_key_agreements(references).unwrap();
    assert_eq!(document.authentication(), [serde_json::json!("#key-1")]);
    assert_eq!(document.assertion_methods(), [serde_json::json!("#key-1")]);
    assert_eq!(document.key_agreements(), [serde_json::json!("#key-1")]);

    let private = vec![serde_json::json!({
        "id":"#key-1",
        "type":"JsonWebKey2020",
        "controller":"did:example:holder",
        "publicKeyJwk":{"kty":"oct", "k":"secret-sentinel"}
    })];
    assert!(document.set_authentication(private.clone()).is_err());
    assert!(document.set_assertion_methods(private.clone()).is_err());
    assert!(document.set_key_agreements(private).is_err());
    assert!(!format!("{document:?}").contains("secret-sentinel"));
}

#[test]
fn verification_methods_reject_private_key_extensions_without_echoing_values() {
    for member in PRIVATE_METHOD_MEMBERS {
        let private_value = if *member == "privateKeyJwk" {
            serde_json::json!({"kty":"EC", "d":"secret-sentinel"})
        } else {
            serde_json::json!("secret-sentinel")
        };
        let mut method = serde_json::json!({
            "id":"did:example:holder#key-1",
            "type":"JsonWebKey2020",
            "controller":"did:example:holder"
        });
        method
            .as_object_mut()
            .unwrap()
            .insert((*member).into(), private_value.clone());

        let error = serde_json::from_value::<VerificationMethod>(method.clone()).unwrap_err();
        assert!(error.to_string().contains("private key member"));
        assert!(!format!("{error:?}").contains("secret-sentinel"));

        for relationship in ["authentication", "assertionMethod", "keyAgreement"] {
            let document = serde_json::json!({
                "id":"did:example:holder",
                (relationship): [method.clone()]
            });
            let error = serde_json::from_value::<DidDocument>(document).unwrap_err();
            assert!(error.to_string().contains("private key member"));
            assert!(!format!("{error:?}").contains("secret-sentinel"));
        }

        let mut extensions = serde_json::Map::new();
        extensions.insert((*member).into(), private_value);
        assert!(
            VerificationMethod::new("#key-1", "JsonWebKey2020", "did:example:holder")
                .with_additional_properties(extensions)
                .is_err()
        );
    }
}

#[test]
fn did_documents_reject_private_key_extensions_at_parse_and_builder_boundaries() {
    for member in PRIVATE_METHOD_MEMBERS {
        let private_value = if *member == "privateKeyJwk" {
            serde_json::json!({"kty":"EC", "d":"secret-sentinel"})
        } else {
            serde_json::json!("secret-sentinel")
        };
        let mut value = serde_json::json!({"id":"did:example:holder"});
        value
            .as_object_mut()
            .unwrap()
            .insert((*member).into(), private_value.clone());
        let error = serde_json::from_value::<DidDocument>(value).unwrap_err();
        assert!(error.to_string().contains("private key member"));
        assert!(!format!("{error:?}").contains("secret-sentinel"));

        let mut extensions = serde_json::Map::new();
        extensions.insert((*member).into(), private_value);
        assert!(DidDocument::new("did:example:holder")
            .with_additional_properties(extensions)
            .is_err());
    }
}

#[test]
fn did_verification_methods_reject_private_jwk_members() {
    for member in ["d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let json = format!(
            r#"{{"id":"did:example:holder#key","type":"JsonWebKey2020","controller":"did:example:holder","publicKeyJwk":{{"kty":"OKP","crv":"X25519","x":"public","{member}":"secret"}}}}"#
        );
        assert!(
            serde_json::from_str::<VerificationMethod>(&json).is_err(),
            "DID JWK accepted private member {member}"
        );
    }
}

#[test]
fn did_verification_methods_preserve_safe_public_extensions() {
    let method: VerificationMethod = serde_json::from_str(
        r#"{"id":"did:example:holder#key","type":"JsonWebKey2020","controller":"did:example:holder","publicKeyJwk":{"kty":"RSA","n":"modulus","e":"AQAB","use":"sig"}}"#,
    )
    .unwrap();
    let jwk = method.public_key_jwk.as_ref().unwrap();
    assert_eq!(jwk.additional_properties()["n"], "modulus");
    let serialized = serde_json::to_string(&method).unwrap();
    let debug = format!("{method:?}");
    assert!(!serialized.contains("secret"));
    assert!(!debug.contains("secret"));
}

#[test]
fn public_constructor_rejects_private_extensions() {
    let jwk = Jwk::new_public(
        "OKP",
        Some("X25519".into()),
        Some("public".into()),
        None,
        None,
    );
    let mut extensions = serde_json::Map::new();
    extensions.insert("d".into(), serde_json::json!("secret"));
    assert!(jwk.with_additional_properties(extensions).is_err());

    let jwk = Jwk::new_public(
        "OKP",
        Some("X25519".into()),
        Some("public".into()),
        None,
        None,
    );
    let mut extensions = serde_json::Map::new();
    extensions.insert("x".into(), serde_json::json!("substitution"));
    assert!(jwk.with_additional_properties(extensions).is_err());
}

#[test]
fn outer_safe_constructors_support_typed_serialization() {
    let mut method = VerificationMethod::new(
        "did:example:holder#key",
        "JsonWebKey2020",
        "did:example:holder",
    );
    method.public_key_jwk = Some(Jwk::new_public(
        "OKP",
        Some("X25519".into()),
        Some("public".into()),
        None,
        None,
    ));
    let mut document = DidDocument::new("did:example:holder");
    document.verification_method.push(method);

    let serialized = serde_json::to_value(document).unwrap();
    assert_eq!(
        serialized["verificationMethod"][0]["publicKeyJwk"]["x"],
        "public"
    );
}
