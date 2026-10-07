//! Open Badges verifier conformance over public, previously signed vectors.
//! No credential private key is generated, imported, or stored by this suite.

use marty_verification::open_badges::{ob3_context_uri, verify_ob2_json, verify_ob3_json};
use serde_json::{json, Value};

fn vector(name: &str) -> Value {
    let source = match name {
        "ob3" => include_str!("vectors/open_badges_ob3_public.json"),
        "ob3_image" => include_str!("vectors/open_badges_ob3_image_public.json"),
        "ob3_expired" => include_str!("vectors/open_badges_ob3_expired_public.json"),
        "ob2" => include_str!("vectors/open_badges_ob2_public.json"),
        _ => panic!("unknown Open Badges vector"),
    };
    let value: Value = serde_json::from_str(source).unwrap();
    let public = &value["public_jwk"];
    for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        assert!(public.get(member).is_none(), "vector contains {member}");
    }
    value
}

fn ob3_verification_request(source: &Value, public_jwk: Value) -> Value {
    let did = source["did"].as_str().unwrap();
    let controller = did.split('#').next().unwrap();
    let mut document_store = serde_json::Map::new();
    document_store.insert(
        did.into(),
        json!({
            "id": did,
            "type": "JsonWebKey2020",
            "controller": controller,
            "publicKeyJwk": public_jwk
        }),
    );
    json!({
        "credential": source["credential"],
        "document_store": document_store
    })
}

fn assert_valid(label: &str, result_json: &str) {
    let result: Value = serde_json::from_str(result_json).unwrap();
    assert_eq!(result["valid"], true, "{label}: {result}");
}

fn assert_invalid(label: &str, result_json: &str) {
    let result: Value = serde_json::from_str(result_json).unwrap();
    assert_eq!(result["valid"], false, "{label}: {result}");
}

#[test]
fn signed_ob3_vector_preserves_required_structure_and_verifies() {
    let source = vector("ob3");
    let credential = &source["credential"];
    let contexts = credential["@context"].as_array().unwrap();
    assert!(contexts.contains(&json!("https://www.w3.org/ns/credentials/v2")));
    assert!(contexts.contains(&json!(ob3_context_uri())));
    let types = credential["type"].as_array().unwrap();
    assert!(types.contains(&json!("VerifiableCredential")));
    assert!(types.contains(&json!("OpenBadgeCredential")));
    assert_eq!(credential["issuer"], source["did"]);
    assert!(credential["proof"].is_object());

    let subject = &credential["credentialSubject"];
    assert_eq!(subject["type"], "AchievementSubject");
    let achievement = &subject["achievement"];
    assert_eq!(achievement["type"], "Achievement");
    for name in ["id", "type", "name", "description"] {
        assert!(achievement[name].is_string(), "missing Achievement.{name}");
    }
    assert!(!achievement["name"].as_str().unwrap().is_empty());
    assert!(!achievement["criteria"]["narrative"]
        .as_str()
        .unwrap()
        .is_empty());

    let request = ob3_verification_request(&source, source["public_jwk"].clone());
    let result = verify_ob3_json(&request.to_string()).unwrap();
    assert_valid("OB3 signed public vector", &result);
}

#[test]
fn ob3_rejects_substituted_public_key() {
    let source = vector("ob3");
    let wrong_public = json!({
        "kty":"OKP", "crv":"Ed25519",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    });
    assert_ne!(wrong_public, source["public_jwk"]);
    let request = ob3_verification_request(&source, wrong_public);
    let result = verify_ob3_json(&request.to_string()).unwrap();
    assert_invalid("OB3 wrong public key", &result);
}

#[test]
fn ob3_image_survives_signed_verification() {
    let source = vector("ob3_image");
    assert_eq!(
        source["credential"]["credentialSubject"]["achievement"]["image"]["id"],
        "https://example.com/badge.png"
    );
    let request = ob3_verification_request(&source, source["public_jwk"].clone());
    let result = verify_ob3_json(&request.to_string()).unwrap();
    assert_valid("OB3 image", &result);
}

#[test]
fn ob3_expired_signed_credential_is_rejected() {
    let source = vector("ob3_expired");
    assert_eq!(source["credential"]["validUntil"], "2000-01-01T00:00:00Z");
    let request = ob3_verification_request(&source, source["public_jwk"].clone());
    let result = verify_ob3_json(&request.to_string()).unwrap();
    assert_invalid("OB3 expired", &result);
}

fn ob2_verification_request(source: &Value, recipient_identity: &str) -> Value {
    json!({
        "assertion": source["credential"],
        "document_store": {
            "urn:uuid:badge-2": {
                "id": "urn:uuid:badge-2", "issuer": "did:example:ob2-issuer"
            },
            "did:example:ob2-issuer": {
                "id": "did:example:ob2-issuer"
            },
            "did:example:ob2-issuer#key-1": {
                "publicKeyJwk": source["public_jwk"]
            }
        },
        "recipient_identity": recipient_identity
    })
}

#[test]
fn ob2_hashed_recipient_verifies_without_plaintext_identity() {
    let source = vector("ob2");
    let credential = &source["credential"];
    assert!(!credential.to_string().contains("conformance@example.org"));
    assert!(credential["signature"].is_string());
    let request = ob2_verification_request(&source, "conformance@example.org");
    let result = verify_ob2_json(&request.to_string()).unwrap();
    assert_valid("OB2 hashed recipient", &result);
}

#[test]
fn ob2_wrong_recipient_identity_is_rejected() {
    let source = vector("ob2");
    let request = ob2_verification_request(&source, "wrong@example.org");
    let result = verify_ob2_json(&request.to_string()).unwrap();
    assert_invalid("OB2 wrong recipient", &result);
}
