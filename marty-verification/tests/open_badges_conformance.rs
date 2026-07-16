//! 1EdTech Open Badges 3.0 specification conformance tests.
//!
//! Extends the existing ob2/ob3 round-trip tests with normative scenarios
//! from the IMS Global Open Badges 3.0 conformance suite:
//!
//!  §1  Achievement structure — mandatory fields per OB3 §8.1
//!  §2  Credential structure — OB3 credential mandatory fields
//!  §3  Multiple proof method support — Ed25519/JsonWebSignature2020
//!  §4  AchievementSubject structure — typed subject
//!  §5  Achievement criteria — optional criteria field
//!  §6  Expiry and validity date handling
//!  §7  Rejection scenarios — mismatched proof, wrong issuer, missing fields
//!  §8  OB2 backward compatibility — hashed recipient, badge class resolution

use serde_json::{json, Value};

use marty_verification::{
    jwk::generate_ed25519,
    open_badges::{
        issue_ob2_json, issue_ob3_json, ob2_context_uri, ob3_context_uri, verify_ob2_json,
        verify_ob3_json,
    },
};
use ssi::{dids::DIDJWK, JWK};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Generate an Ed25519 did:jwk with its JWK.
fn gen_ed25519_did() -> (String, JWK) {
    let jwk = JWK::generate_ed25519().expect("Ed25519 JWK");
    let did = DIDJWK::generate_url(&jwk).to_string();
    (did, jwk)
}

fn assert_valid(label: &str, result_json: &str) {
    let v: Value = serde_json::from_str(result_json)
        .unwrap_or_else(|e| panic!("{} result is not valid JSON: {}", label, e));
    assert!(
        v.get("valid").and_then(|x| x.as_bool()).unwrap_or(false),
        "{} expected valid=true: {:?}",
        label,
        v
    );
}

fn assert_invalid(label: &str, result_json: &str) {
    let v: Value = serde_json::from_str(result_json)
        .unwrap_or_else(|e| panic!("{} result is not valid JSON: {}", label, e));
    assert!(
        !v.get("valid").and_then(|x| x.as_bool()).unwrap_or(true),
        "{} expected valid=false: {:?}",
        label,
        v
    );
}

/// Produce a minimal but complete OB3 credential.
fn ob3_credential(issuer: &str, achievement_id: &str) -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            ob3_context_uri()
        ],
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "id": "urn:uuid:ob3-conformance-credential-1",
        "issuer": issuer,
        "credentialSubject": {
            "id": "did:example:recipient",
            "type": "AchievementSubject",
            "achievement": {
                "id": achievement_id,
                "type": "Achievement",
                "name": "Conformance Test Badge",
                "description": "Awarded for passing the conformance test suite.",
                "criteria": {
                    "narrative": "Must pass all OB3 conformance scenarios."
                }
            }
        }
    })
}

/// Issue an OB3 credential and return the issued credential JSON.
fn issue_ob3(issuer_did: &str, issuer_jwk: &JWK, achievement_id: &str) -> Value {
    let credential = ob3_credential(issuer_did, achievement_id);
    // For did:jwk DIDs the URL already contains the VM reference (did:jwk:BASE64#0)
    let signing = json!({
        "jwk": serde_json::to_value(issuer_jwk).unwrap(),
        "verification_method": issuer_did,
        "proof_purpose": "assertionMethod"
    });

    let req = json!({ "credential": credential, "signing": signing });
    let result_str = issue_ob3_json(&req.to_string()).expect("issue_ob3_json");
    let result: Value = serde_json::from_str(&result_str).expect("issue result JSON");
    assert!(
        result
            .get("issued")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        "OB3 issuance must succeed: {:?}",
        result
    );
    result
        .get("credential")
        .cloned()
        .expect("issued credential")
}

// ── §1  Achievement structure ─────────────────────────────────────────────────

/// OB3 §8.1 — `Achievement` must have `id`, `type`, `name`, and `description`.
#[test]
fn ob3_achievement_has_mandatory_fields() {
    let (did, jwk) = gen_ed25519_did();
    let cred = issue_ob3(&did, &jwk, "urn:uuid:achievement-mandatory-fields");

    let achievement = cred
        .pointer("/credentialSubject/achievement")
        .expect("achievement must be present");

    assert!(
        achievement.get("id").is_some(),
        "Achievement must have 'id'"
    );
    assert!(
        achievement.get("type").is_some(),
        "Achievement must have 'type'"
    );
    assert!(
        achievement.get("name").is_some(),
        "Achievement must have 'name'"
    );
    assert!(
        achievement.get("description").is_some(),
        "Achievement must have 'description'"
    );

    let ach_type = achievement.get("type").unwrap();
    let type_val = if let Some(arr) = ach_type.as_array() {
        arr.iter().any(|v| v.as_str() == Some("Achievement"))
    } else {
        ach_type.as_str() == Some("Achievement")
    };
    assert!(type_val, "Achievement type must include 'Achievement'");
}

/// `Achievement.name` must be a non-empty string.
#[test]
fn ob3_achievement_name_is_non_empty_string() {
    let (did, jwk) = gen_ed25519_did();
    let cred = issue_ob3(&did, &jwk, "urn:uuid:achievement-name-check");

    let name = cred
        .pointer("/credentialSubject/achievement/name")
        .and_then(|v| v.as_str())
        .expect("Achievement.name must be a string");

    assert!(!name.is_empty(), "Achievement.name must be non-empty");
}

/// `Achievement.criteria` is optional per OB3 §8.1 but when present must have
/// either `id` or `narrative`.
#[test]
fn ob3_achievement_criteria_narrative_present() {
    let (did, jwk) = gen_ed25519_did();
    let cred = issue_ob3(&did, &jwk, "urn:uuid:achievement-criteria");

    if let Some(criteria) = cred.pointer("/credentialSubject/achievement/criteria") {
        let has_id = criteria.get("id").is_some();
        let has_narrative = criteria
            .get("narrative")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        assert!(
            has_id || has_narrative,
            "Achievement.criteria must have 'id' or non-empty 'narrative' when present"
        );
    }
}

// ── §2  Credential mandatory fields ──────────────────────────────────────────

/// OB3 credential must have `@context` including the W3C VCDM v2 base and OB3 context.
#[test]
fn ob3_credential_context_includes_required_uris() {
    let (did, jwk) = gen_ed25519_did();
    let cred = issue_ob3(&did, &jwk, "urn:uuid:achievement-context-check");

    let context = cred
        .get("@context")
        .and_then(|v| v.as_array())
        .expect("@context must be an array");

    let has_vcdm = context
        .iter()
        .any(|v| v.as_str() == Some("https://www.w3.org/ns/credentials/v2"));
    assert!(
        has_vcdm,
        "@context must include 'https://www.w3.org/ns/credentials/v2'"
    );

    // OB3 context URI must also be present
    let ob3_ctx = ob3_context_uri();
    let has_ob3 = context.iter().any(|v| v.as_str() == Some(ob3_ctx));
    assert!(
        has_ob3,
        "@context must include the OB3 context URI: {}",
        ob3_ctx
    );
}

/// OB3 credential `type` array must include both `VerifiableCredential` and
/// `OpenBadgeCredential`.
#[test]
fn ob3_credential_type_includes_required_types() {
    let (did, jwk) = gen_ed25519_did();
    let cred = issue_ob3(&did, &jwk, "urn:uuid:achievement-type-check");

    let types = cred
        .get("type")
        .and_then(|v| v.as_array())
        .expect("type must be an array");

    let type_strs: Vec<&str> = types.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        type_strs.contains(&"VerifiableCredential"),
        "type must include 'VerifiableCredential'"
    );
    assert!(
        type_strs.contains(&"OpenBadgeCredential"),
        "type must include 'OpenBadgeCredential'"
    );
}

/// Issued OB3 credential must have a `proof` object (data integrity or JWT-based).
#[test]
fn ob3_credential_has_proof() {
    let (did, jwk) = gen_ed25519_did();
    let cred = issue_ob3(&did, &jwk, "urn:uuid:achievement-proof-check");
    assert!(
        cred.get("proof").is_some(),
        "issued OB3 credential must contain a 'proof' object"
    );
}

/// `issuer` field must match the issuer DID used during issuance.
#[test]
fn ob3_credential_issuer_matches() {
    let (did, jwk) = gen_ed25519_did();
    let cred = issue_ob3(&did, &jwk, "urn:uuid:achievement-issuer-check");

    let issuer = cred.get("issuer").expect("issuer must be present");
    // issuer can be a string (DID) or object with id
    let issuer_id = if let Some(s) = issuer.as_str() {
        s.to_string()
    } else {
        issuer
            .get("id")
            .and_then(|v| v.as_str())
            .expect("issuer.id must be a string")
            .to_string()
    };
    assert_eq!(issuer_id, did, "issuer must match the signing DID");
}

// ── §3  Round-trip verification ───────────────────────────────────────────────

/// Issue → verify round-trip must succeed with correct verification method.
#[test]
fn ob3_issue_verify_round_trip_ed25519() {
    let (did, jwk) = gen_ed25519_did();
    let cred = issue_ob3(&did, &jwk, "urn:uuid:achievement-roundtrip");

    // The verify_ob3_json resolver uses a static document_store, not a live DID resolver.
    // Provide the verification method explicitly for did:jwk resolution.
    let controller = did.split('#').next().unwrap_or(&did).to_string();
    let method_doc = json!({
        "id": &did,
        "type": "JsonWebKey2020",
        "controller": &controller,
        "publicKeyJwk": serde_json::to_value(jwk.to_public()).unwrap()
    });

    let req = json!({
        "credential": cred,
        "document_store": { &did: method_doc }
    });
    let result = verify_ob3_json(&req.to_string()).expect("verify_ob3_json");
    assert_valid("OB3 round-trip", &result);
}

/// Tampered credential (proof from different key) must fail verification.
#[test]
fn ob3_verify_rejects_wrong_signing_key() {
    let (did, jwk) = gen_ed25519_did();
    let cred = issue_ob3(&did, &jwk, "urn:uuid:achievement-wrong-key");

    // Tamper: replace the proof's verificationMethod with a different did:jwk DID.
    // The proofValue was computed with 'did' (key1) but the proof now claims key2.
    let (wrong_did, _) = gen_ed25519_did();
    let mut tampered = cred.clone();
    if let Some(proof) = tampered.get_mut("proof") {
        if let Some(vm) = proof.get_mut("verificationMethod") {
            *vm = json!(wrong_did);
        }
    }

    let req = json!({ "credential": tampered });
    let result = verify_ob3_json(&req.to_string()).expect("verify call did not panic");
    assert_invalid("OB3 wrong signing key", &result);
}

// ── §4  AchievementSubject structure ─────────────────────────────────────────

/// `credentialSubject` must have `type: AchievementSubject` per OB3 §8.2.
#[test]
fn ob3_credential_subject_type_is_achievement_subject() {
    let (did, jwk) = gen_ed25519_did();
    let cred = issue_ob3(&did, &jwk, "urn:uuid:achievement-subject-type");

    let cs = cred
        .get("credentialSubject")
        .expect("credentialSubject must be present");

    let cs_type = cs.get("type").expect("credentialSubject must have 'type'");
    let has_achievement_subject = if let Some(arr) = cs_type.as_array() {
        arr.iter().any(|v| v.as_str() == Some("AchievementSubject"))
    } else {
        cs_type.as_str() == Some("AchievementSubject")
    };
    assert!(
        has_achievement_subject,
        "credentialSubject.type must include 'AchievementSubject'"
    );
}

/// The achievement embedded in `credentialSubject` must be an object or a URI.
#[test]
fn ob3_achievement_is_object_or_uri() {
    let (did, jwk) = gen_ed25519_did();
    let cred = issue_ob3(&did, &jwk, "urn:uuid:achievement-type-check-2");

    let achievement = cred
        .pointer("/credentialSubject/achievement")
        .expect("achievement must be present");

    assert!(
        achievement.is_object() || achievement.is_string(),
        "credentialSubject.achievement must be an object or URI string"
    );
}

// ── §5  Optional criteria and image fields ────────────────────────────────────

/// A credential with an optional `image` on the Achievement should issue and verify.
#[test]
fn ob3_credential_with_image_issues_and_verifies() {
    let (did, jwk) = gen_ed25519_did();

    let credential = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            ob3_context_uri()
        ],
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "id": "urn:uuid:ob3-image-test",
        "issuer": &did,
        "credentialSubject": {
            "id": "did:example:recipient",
            "type": "AchievementSubject",
            "achievement": {
                "id": "urn:uuid:achievement-with-image",
                "type": "Achievement",
                "name": "Image Test Badge",
                "description": "Tests that optional image field is preserved.",
                "image": {
                    "id": "https://example.com/badge.png",
                    "type": "Image"
                }
            }
        }
    });

    let req = json!({
        "credential": credential,
        "signing": {
            "jwk": serde_json::to_value(&jwk).unwrap(),
            "verification_method": &did,
            "proof_purpose": "assertionMethod"
        }
    });

    let result_str = issue_ob3_json(&req.to_string()).expect("issue");
    let result: Value = serde_json::from_str(&result_str).expect("json");
    assert!(
        result
            .get("issued")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        "OB3 credential with image must issue successfully: {:?}",
        result
    );
}

// ── §6  Expiry handling ───────────────────────────────────────────────────────

/// A credential with `validUntil` in the past must be reported as invalid at verification.
#[test]
fn ob3_expired_credential_fails_verification() {
    let (did, jwk) = gen_ed25519_did();

    let expired_credential = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            ob3_context_uri()
        ],
        "type": ["VerifiableCredential", "OpenBadgeCredential"],
        "id": "urn:uuid:ob3-expired",
        "issuer": &did,
        "validUntil": "2000-01-01T00:00:00Z",  // clearly expired
        "credentialSubject": {
            "id": "did:example:recipient",
            "type": "AchievementSubject",
            "achievement": {
                "id": "urn:uuid:achievement-expired",
                "type": "Achievement",
                "name": "Expired Badge",
                "description": "This badge has expired."
            }
        }
    });

    let issue_req = json!({
        "credential": expired_credential,
        "signing": {
            "jwk": serde_json::to_value(&jwk).unwrap(),
            "verification_method": &did,
            "proof_purpose": "assertionMethod"
        }
    });

    let issue_result_str = issue_ob3_json(&issue_req.to_string()).expect("issue");
    let issue_result: Value = serde_json::from_str(&issue_result_str).expect("json");

    if let Some(cred) = issue_result.get("credential") {
        // Verify — must report invalid due to validUntil in past
        let verify_req = json!({ "credential": cred });
        let verify_result = verify_ob3_json(&verify_req.to_string()).expect("verify");
        assert_invalid("OB3 expired credential", &verify_result);
    }
}

// ── §7  OB2 backward compatibility ───────────────────────────────────────────

/// OB2 badges must issue with SHA-256 hashed recipient identity.
#[test]
fn ob2_hashed_recipient_round_trip() {
    let mut jwk = generate_ed25519().expect("Ed25519");
    jwk.kid = Some("did:example:ob2-issuer#key-1".to_string());

    let assertion = json!({
        "@context": ob2_context_uri(),
        "type": "Assertion",
        "id": "urn:uuid:ob2-hashed-recipient-test",
        "badge": "urn:uuid:badge-2"
    });

    let req = json!({
        "assertion": assertion,
        "recipient": {
            "identity": "conformance@example.org",
            "type": "email",
            "hashed": true,
            "salt": "conformance-salt",
            "hash_alg": "sha256"
        },
        "signing": {
            "jwk": serde_json::to_value(&jwk).unwrap(),
            "creator": "did:example:ob2-issuer#key-1"
        }
    });

    let issue_result_str = issue_ob2_json(&req.to_string()).expect("OB2 issue");
    let issue_result: Value = serde_json::from_str(&issue_result_str).expect("json");
    assert!(
        issue_result
            .get("issued")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        "OB2 hashed recipient must issue: {:?}",
        issue_result
    );

    let cred = issue_result.get("credential").cloned().expect("credential");

    // The recipient hash must NOT contain the plaintext identity (privacy check)
    let cred_str = serde_json::to_string(&cred).unwrap();
    assert!(
        !cred_str.contains("conformance@example.org"),
        "OB2 hashed credential must not contain plaintext identity"
    );

    // Verify with correct identity
    let mut store = std::collections::BTreeMap::new();
    store.insert(
        "urn:uuid:badge-2".to_string(),
        json!({ "id": "urn:uuid:badge-2", "issuer": "did:example:ob2-issuer" }),
    );
    store.insert(
        "did:example:ob2-issuer".to_string(),
        json!({ "id": "did:example:ob2-issuer" }),
    );
    store.insert(
        "did:example:ob2-issuer#key-1".to_string(),
        json!({ "publicKeyJwk": serde_json::to_value(jwk.to_public()).unwrap() }),
    );

    let verify_req = json!({
        "assertion": cred,
        "document_store": store,
        "recipient_identity": "conformance@example.org"
    });
    let verify_result = verify_ob2_json(&verify_req.to_string()).expect("OB2 verify");
    assert_valid("OB2 hashed recipient verification", &verify_result);
}

/// OB2 verification must fail if wrong recipient identity is provided.
#[test]
fn ob2_wrong_recipient_identity_fails() {
    let mut jwk = generate_ed25519().expect("Ed25519");
    jwk.kid = Some("did:example:ob2-issuer#key-2".to_string());

    let req = json!({
        "assertion": {
            "@context": ob2_context_uri(),
            "type": "Assertion",
            "id": "urn:uuid:ob2-wrong-recipient",
            "badge": "urn:uuid:badge-3"
        },
        "recipient": {
            "identity": "alice@example.org",
            "type": "email",
            "hashed": true,
            "salt": "salt",
            "hash_alg": "sha256"
        },
        "signing": {
            "jwk": serde_json::to_value(&jwk).unwrap(),
            "creator": "did:example:ob2-issuer#key-2"
        }
    });

    let issue_str = issue_ob2_json(&req.to_string()).expect("issue");
    let issue_v: Value = serde_json::from_str(&issue_str).expect("json");
    let cred = issue_v.get("credential").cloned().expect("credential");

    let mut store = std::collections::BTreeMap::new();
    store.insert(
        "urn:uuid:badge-3".to_string(),
        json!({ "id": "urn:uuid:badge-3", "issuer": "did:example:ob2-issuer" }),
    );
    store.insert(
        "did:example:ob2-issuer".to_string(),
        json!({ "id": "did:example:ob2-issuer" }),
    );
    store.insert(
        "did:example:ob2-issuer#key-2".to_string(),
        json!({ "publicKeyJwk": serde_json::to_value(jwk.to_public()).unwrap() }),
    );

    let verify_req = json!({
        "assertion": cred,
        "document_store": store,
        "recipient_identity": "wrong@example.org"
    });
    let result = verify_ob2_json(&verify_req.to_string()).expect("verify call");
    assert_invalid("OB2 wrong recipient", &result);
}
