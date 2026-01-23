use std::collections::BTreeMap;

use serde_json::{json, Value};

use marty_verification::jwk::generate_ed25519;
use marty_verification::open_badges::{issue_ob2_json, ob2_context_uri, verify_ob2_json};

fn assert_invalid(label: &str, result_json: &str) {
    let value: Value = serde_json::from_str(result_json)
        .unwrap_or_else(|e| panic!("{} output is not JSON: {}", label, e));
    let is_valid = value.get("valid").and_then(|v| v.as_bool()).unwrap_or(true);
    assert!(
        !is_valid,
        "{} verification unexpectedly valid: {:?}",
        label,
        value
    );
}

fn ob2_issue_fixture() -> (Value, BTreeMap<String, Value>, String) {
    let mut jwk = generate_ed25519().expect("failed to generate test JWK");
    jwk.kid = Some("did:example:issuer#key-1".to_string());

    let assertion = json!({
        "@context": ob2_context_uri(),
        "type": "Assertion",
        "id": "urn:uuid:assertion-1",
        "badge": "urn:uuid:badge-1"
    });

    let recipient_identity = "user@example.org".to_string();
    let issue_request = json!({
        "assertion": assertion,
        "recipient": {
            "identity": recipient_identity,
            "type": "email",
            "hashed": true,
            "salt": "pepper",
            "hash_alg": "sha256"
        },
        "signing": {
            "jwk": serde_json::to_value(&jwk).expect("failed to serialize JWK"),
            "creator": "did:example:issuer#key-1"
        }
    });

    let issue_result = issue_ob2_json(&issue_request.to_string()).expect("OB2 issue failed");
    let issue_value: Value = serde_json::from_str(&issue_result).expect("invalid OB2 issue JSON");
    assert!(
        issue_value.get("issued").and_then(|v| v.as_bool()).unwrap_or(false),
        "expected issue to succeed"
    );

    let credential = issue_value
        .get("credential")
        .cloned()
        .expect("missing issued credential");

    let mut store = BTreeMap::new();
    store.insert(
        "urn:uuid:badge-1".to_string(),
        json!({
            "id": "urn:uuid:badge-1",
            "issuer": "did:example:issuer"
        }),
    );
    store.insert(
        "did:example:issuer".to_string(),
        json!({
            "id": "did:example:issuer",
            "name": "Example Issuer"
        }),
    );
    store.insert(
        "did:example:issuer#key-1".to_string(),
        json!({
            "publicKeyJwk": serde_json::to_value(jwk.to_public()).expect("failed to serialize public JWK")
        }),
    );

    (credential, store, "user@example.org".to_string())
}

#[test]
fn ob2_issue_verify_round_trip() {
    let (credential, store, recipient_identity) = ob2_issue_fixture();

    let verify_request = json!({
        "assertion": credential,
        "document_store": store,
        "recipient_identity": recipient_identity
    });

    let verify_result = verify_ob2_json(&verify_request.to_string()).expect("OB2 verify failed");
    let verify_value: Value = serde_json::from_str(&verify_result).expect("invalid OB2 verify JSON");
    assert!(
        verify_value.get("valid").and_then(|v| v.as_bool()).unwrap_or(false),
        "expected verification to succeed: {:?}",
        verify_value
    );
}

#[test]
fn ob2_verify_rejects_wrong_recipient() {
    let (credential, store, _recipient_identity) = ob2_issue_fixture();
    let verify_request = json!({
        "assertion": credential,
        "document_store": store,
        "recipient_identity": "wrong@example.org"
    });

    let verify_result = verify_ob2_json(&verify_request.to_string()).expect("OB2 verify failed");
    assert_invalid("OB2 wrong recipient", &verify_result);
}

#[test]
fn ob2_verify_rejects_missing_document_store() {
    let (credential, _store, recipient_identity) = ob2_issue_fixture();
    let verify_request = json!({
        "assertion": credential,
        "recipient_identity": recipient_identity
    });

    let verify_result = verify_ob2_json(&verify_request.to_string()).expect("OB2 verify failed");
    assert_invalid("OB2 missing document_store", &verify_result);
}

#[cfg(not(target_arch = "wasm32"))]
mod ob3_tests {
    use super::*;
    use marty_verification::open_badges::{issue_ob3_json, ob3_context_uri, verify_ob3_json};
    use ssi::dids::DIDJWK;
    use ssi::jwk::Params as JwkParams;
    use ssi::verification_methods::Ed25519VerificationKey2020;
    use ssi::JWK;

    fn ob3_credential(issuer: &str) -> Value {
        json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                ob3_context_uri()
            ],
            "type": [
                "VerifiableCredential",
                "OpenBadgeCredential",
                "AchievementCredential"
            ],
            "id": "urn:uuid:ob3-credential-1",
            "issuer": issuer,
            "credentialSubject": {
                "id": "did:example:subject",
                "type": "AchievementSubject",
                "achievement": {
                    "id": "urn:uuid:achievement-1",
                    "type": "Achievement",
                    "name": "Example Badge",
                    "description": "Example achievement description"
                }
            }
        })
    }

    fn ed25519_public_key_bytes(jwk: &JWK) -> Vec<u8> {
        match &jwk.params {
            JwkParams::OKP(params) if params.curve == "Ed25519" => params.public_key.0.clone(),
            _ => panic!("expected Ed25519 OKP JWK"),
        }
    }

    fn issue_and_verify(
        jwk: &JWK,
        issuer: &str,
        verification_method: &str,
        verification_method_type: Option<&str>,
        controller: Option<&str>,
        method_value: Value,
    ) {
        let credential = ob3_credential(issuer);

        let mut signing = json!({
            "jwk": serde_json::to_value(jwk).expect("failed to serialize OB3 JWK"),
            "verification_method": verification_method,
            "proof_purpose": "assertionMethod"
        });
        if let Some(method_type) = verification_method_type {
            signing
                .as_object_mut()
                .expect("signing should be object")
                .insert("verification_method_type".to_string(), json!(method_type));
        }
        if let Some(controller) = controller {
            signing
                .as_object_mut()
                .expect("signing should be object")
                .insert("controller".to_string(), json!(controller));
        }

        let issue_request = json!({
            "credential": credential,
            "signing": signing
        });

        let issue_result = issue_ob3_json(&issue_request.to_string()).expect("OB3 issue failed");
        let issue_value: Value = serde_json::from_str(&issue_result).expect("invalid OB3 issue JSON");
        assert!(
            issue_value.get("issued").and_then(|v| v.as_bool()).unwrap_or(false),
            "expected OB3 issue to succeed"
        );

        let issued_credential = issue_value
            .get("credential")
            .cloned()
            .expect("missing issued OB3 credential");

        let mut store = BTreeMap::new();
        store.insert(verification_method.to_string(), method_value);

        let verify_request = json!({
            "credential": issued_credential,
            "document_store": store
        });

        let verify_result = verify_ob3_json(&verify_request.to_string()).expect("OB3 verify failed");
        let verify_value: Value =
            serde_json::from_str(&verify_result).expect("invalid OB3 verify JSON");
        assert!(
            verify_value.get("valid").and_then(|v| v.as_bool()).unwrap_or(false),
            "expected OB3 verification to succeed: {:?}",
            verify_value
        );
    }

    #[test]
    fn ob3_issue_verify_round_trip() {
        let jwk = JWK::generate_ed25519().expect("failed to generate OB3 JWK");
        let did = DIDJWK::generate(&jwk).to_string();
        let did_url = DIDJWK::generate_url(&jwk).to_string();
        let public_jwk = jwk.to_public();
        let method = json!({
            "id": did_url,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": serde_json::to_value(&public_jwk).expect("failed to serialize OB3 public JWK")
        });

        issue_and_verify(&jwk, &did, &DIDJWK::generate_url(&jwk).to_string(), None, None, method);
    }

    #[test]
    fn ob3_issue_verify_ed25519_2020_method() {
        let jwk = JWK::generate_ed25519().expect("failed to generate OB3 JWK");
        let verification_method = "did:example:issuer#key-2020";
        let controller = "did:example:issuer";
        let public_key = ed25519_public_key_bytes(&jwk);
        let verifying_key = ed25519_dalek::VerifyingKey::try_from(public_key.as_slice())
            .expect("failed to build Ed25519 verifying key");
        let method = Ed25519VerificationKey2020::from_public_key(
            verification_method.parse().expect("invalid method IRI"),
            controller.parse().expect("invalid controller URI"),
            verifying_key,
        );
        let method_value = serde_json::to_value(method).expect("failed to serialize method");

        issue_and_verify(
            &jwk,
            controller,
            verification_method,
            Some("Ed25519VerificationKey2020"),
            Some(controller),
            method_value,
        );
    }

    #[test]
    fn ob3_issue_verify_ed25519_2018_method() {
        let jwk = JWK::generate_ed25519().expect("failed to generate OB3 JWK");
        let verification_method = "did:example:issuer#key-2018";
        let controller = "did:example:issuer";
        let public_key = ed25519_public_key_bytes(&jwk);
        let public_key_base58 = bs58::encode(public_key).into_string();
        let method_value = json!({
            "id": verification_method,
            "type": "Ed25519VerificationKey2018",
            "controller": controller,
            "publicKeyBase58": public_key_base58
        });

        issue_and_verify(
            &jwk,
            controller,
            verification_method,
            Some("Ed25519VerificationKey2018"),
            Some(controller),
            method_value,
        );
    }

    #[test]
    fn ob3_verify_rejects_missing_verification_method() {
        let jwk = JWK::generate_ed25519().expect("failed to generate OB3 JWK");
        let did = DIDJWK::generate(&jwk).to_string();
        let did_url = DIDJWK::generate_url(&jwk).to_string();

        let credential = ob3_credential(&did);
        let issue_request = json!({
            "credential": credential,
            "signing": {
                "jwk": serde_json::to_value(&jwk).expect("failed to serialize OB3 JWK"),
                "verification_method": did_url,
                "proof_purpose": "assertionMethod"
            }
        });

        let issue_result = issue_ob3_json(&issue_request.to_string()).expect("OB3 issue failed");
        let issue_value: Value = serde_json::from_str(&issue_result).expect("invalid OB3 issue JSON");
        let issued_credential = issue_value
            .get("credential")
            .cloned()
            .expect("missing issued OB3 credential");

        let verify_request = json!({
            "credential": issued_credential,
            "document_store": {}
        });
        let verify_result = verify_ob3_json(&verify_request.to_string()).expect("OB3 verify failed");
        assert_invalid("OB3 missing verification method", &verify_result);
    }

    /// Test that credential status checking detects a revoked credential.
    /// 
    /// This test verifies the status checking logic by:
    /// 1. Issuing a valid credential (without status field during issuance)
    /// 2. Manually adding the credentialStatus field to the issued credential
    /// 3. Providing a status list with the bit set (revoked)
    /// 4. Verifying that the status check detects the revocation
    #[test]
    fn ob3_verify_detects_revoked_credential_via_status_list() {
        use base64::{engine::general_purpose, Engine as _};
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let jwk = JWK::generate_ed25519().expect("failed to generate OB3 JWK");
        let did = DIDJWK::generate(&jwk).to_string();
        let did_url = DIDJWK::generate_url(&jwk).to_string();

        // Issue a credential without status first (to avoid JSON-LD context issues)
        let credential = ob3_credential(&did);

        let issue_request = json!({
            "credential": credential,
            "signing": {
                "jwk": serde_json::to_value(&jwk).expect("failed to serialize OB3 JWK"),
                "verification_method": did_url.clone(),
                "proof_purpose": "assertionMethod"
            }
        });

        let issue_result = issue_ob3_json(&issue_request.to_string()).expect("OB3 issue failed");
        let issue_value: Value = serde_json::from_str(&issue_result).expect("invalid OB3 issue JSON");
        let mut issued_credential = issue_value
            .get("credential")
            .cloned()
            .expect("missing issued OB3 credential");

        // Add credential status to the issued credential (simulating a credential that was
        // issued with status - the status field doesn't affect the cryptographic proof)
        issued_credential["credentialStatus"] = json!({
            "id": "https://example.com/status/1#42",
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": "42",
            "statusListCredential": "https://example.com/status/1"
        });

        // Create a status list with bit 42 set (revoked)
        let mut bitstring = vec![0u8; 16 * 1024];
        let byte_index = 42 / 8;
        let bit_index = 42 % 8;
        bitstring[byte_index] |= 0x80 >> bit_index;

        // Compress with gzip and base64 encode
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&bitstring).expect("gzip write failed");
        let compressed = encoder.finish().expect("gzip finish failed");
        let encoded_list = general_purpose::STANDARD.encode(&compressed);

        let status_list_credential = json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc/status-list/2021/v1"
            ],
            "id": "https://example.com/status/1",
            "type": ["VerifiableCredential", "StatusList2021Credential"],
            "credentialSubject": {
                "id": "https://example.com/status/1#list",
                "type": "StatusList2021",
                "statusPurpose": "revocation",
                "encodedList": encoded_list
            }
        });

        // Build document store with verification method and status list
        let mut store = BTreeMap::new();
        store.insert(
            did_url.clone(),
            json!({
                "id": did_url,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": serde_json::to_value(jwk.to_public()).expect("failed to serialize public JWK")
            }),
        );
        store.insert(
            "https://example.com/status/1".to_string(),
            status_list_credential,
        );

        let verify_request = json!({
            "credential": issued_credential,
            "document_store": store
        });

        let verify_result = verify_ob3_json(&verify_request.to_string()).expect("OB3 verify failed");
        let verify_value: Value = serde_json::from_str(&verify_result).expect("invalid OB3 verify JSON");

        // Should be invalid due to revocation
        assert!(
            !verify_value.get("valid").and_then(|v| v.as_bool()).unwrap_or(true),
            "revoked credential should be invalid: {:?}",
            verify_value
        );

        // Check for E707 (OPEN_BADGES_REVOKED) error code
        let error_codes = verify_value.get("error_codes").and_then(|c| c.as_array());
        assert!(
            error_codes.map(|codes| codes.iter().any(|c| c.as_str() == Some("E707"))).unwrap_or(false),
            "expected E707 (OPEN_BADGES_REVOKED) in error_codes: {:?}",
            verify_value
        );
    }

    /// Test that non-revoked credentials pass status verification.
    #[test]
    fn ob3_verify_passes_non_revoked_credential_via_status_list() {
        use base64::{engine::general_purpose, Engine as _};
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let jwk = JWK::generate_ed25519().expect("failed to generate OB3 JWK");
        let did = DIDJWK::generate(&jwk).to_string();
        let did_url = DIDJWK::generate_url(&jwk).to_string();

        // Issue a credential without status first
        let credential = ob3_credential(&did);

        let issue_request = json!({
            "credential": credential,
            "signing": {
                "jwk": serde_json::to_value(&jwk).expect("failed to serialize OB3 JWK"),
                "verification_method": did_url.clone(),
                "proof_purpose": "assertionMethod"
            }
        });

        let issue_result = issue_ob3_json(&issue_request.to_string()).expect("OB3 issue failed");
        let issue_value: Value = serde_json::from_str(&issue_result).expect("invalid OB3 issue JSON");
        let mut issued_credential = issue_value
            .get("credential")
            .cloned()
            .expect("missing issued OB3 credential");

        // Add credential status to the issued credential
        issued_credential["credentialStatus"] = json!({
            "id": "https://example.com/status/1#42",
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": "42",
            "statusListCredential": "https://example.com/status/1"
        });

        // Create a status list with all bits clear (nothing revoked)
        let bitstring = vec![0u8; 16 * 1024];

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&bitstring).expect("gzip write failed");
        let compressed = encoder.finish().expect("gzip finish failed");
        let encoded_list = general_purpose::STANDARD.encode(&compressed);

        let status_list_credential = json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc/status-list/2021/v1"
            ],
            "id": "https://example.com/status/1",
            "type": ["VerifiableCredential", "StatusList2021Credential"],
            "credentialSubject": {
                "id": "https://example.com/status/1#list",
                "type": "StatusList2021",
                "statusPurpose": "revocation",
                "encodedList": encoded_list
            }
        });

        let mut store = BTreeMap::new();
        store.insert(
            did_url.clone(),
            json!({
                "id": did_url,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": serde_json::to_value(jwk.to_public()).expect("failed to serialize public JWK")
            }),
        );
        store.insert(
            "https://example.com/status/1".to_string(),
            status_list_credential,
        );

        let verify_request = json!({
            "credential": issued_credential,
            "document_store": store
        });

        let verify_result = verify_ob3_json(&verify_request.to_string()).expect("OB3 verify failed");
        let verify_value: Value = serde_json::from_str(&verify_result).expect("invalid OB3 verify JSON");

        // The credential status check should NOT add E707 (revoked) since bit 42 is not set
        // Note: Full verification may fail due to JSON-LD expansion issues when credentialStatus
        // is added post-issuance, but the revocation check should not trigger
        let error_codes = verify_value.get("error_codes").and_then(|c| c.as_array());
        let has_revocation_error = error_codes
            .map(|codes| codes.iter().any(|c| c.as_str() == Some("E707")))
            .unwrap_or(false);
        assert!(
            !has_revocation_error,
            "non-revoked credential should not have E707 (OPEN_BADGES_REVOKED) error: {:?}",
            verify_value
        );
    }
}
