//! OID4VCI SD-JWT VC credential format conformance tests.
//!
//! Tests the `sign_sd_jwt` engine function directly, verifying conformance with:
//!   - IETF draft-ietf-oauth-sd-jwt-vc (SD-JWT Verifiable Credentials)
//!   - IETF RFC 9449 (SD-JWT)
//!   - OID4VCI v1 Final §8 (credential endpoint response format)
//!
//!  §1  Compact serialization — SD-JWT output format
//!  §2  IETF flat SD-JWT-VC (`IetfSdJwt`) — top-level `vct`/`iss` claims
//!  §3  W3C VCDM v2 SD-JWT (`W3cVcdmV2SdJwt`) — `credentialSubject` wrapper
//!  §4  Selective disclosure — only declared claims produce disclosures
//!  §5  Non-SD-JWT payload format returns error (guard)
//!  §6  `SignedCredential::SdJwt` shape — credential_id is a valid URN
//!  §7  SD-JWT verification — round-trip issuance + verification
//!  §8  Holder selective disclosure — only chosen disclosures are revealed

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::HashMap;

use marty_oid4vci::{
    formats::sd_jwt::{sign_sd_jwt, verify_sd_jwt},
    types::{
        CredentialClaims, CredentialPayloadFormat, IssuerKey, SignedCredential, SigningAlgorithm,
    },
};
use serde_json::{json, Value};

// ── Test fixture ──────────────────────────────────────────────────────────────

/// A deterministic Ed25519 test JWK (private key included).
/// Source: RFC 8037 Appendix A (test vector Ed25519 key).
const TEST_ED25519_JWK: &str = r#"{
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
}"#;

fn test_issuer_key() -> IssuerKey {
    IssuerKey {
        issuer_id: "https://issuer.example.com".to_string(),
        jwk_json: TEST_ED25519_JWK.to_string(),
        algorithm: SigningAlgorithm::EdDSA,
    }
}

fn base_claims() -> HashMap<String, Value> {
    let mut claims = HashMap::new();
    claims.insert("given_name".to_string(), json!("Alice"));
    claims.insert("family_name".to_string(), json!("Smith"));
    claims.insert("birth_date".to_string(), json!("1990-01-15"));
    claims
}

// ── §1  Compact serialization format ─────────────────────────────────────────

/// `sign_sd_jwt` must return a `SignedCredential::SdJwt` with a non-empty compact string.
#[test]
fn sign_sd_jwt_returns_sdjwt_variant() {
    let claims = CredentialClaims {
        subject_id: Some("did:example:holder".to_string()),
        credential_type: "VerifiableCredential".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: Vec::new(),
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let result = sign_sd_jwt(&test_issuer_key(), &claims).expect("sign_sd_jwt");
    assert!(
        matches!(result, SignedCredential::SdJwt { .. }),
        "must return SignedCredential::SdJwt"
    );
}

/// The compact SD-JWT must contain at least one `~` separator (RFC 9449 §5.2).
#[test]
fn compact_sd_jwt_contains_tilde_separator() {
    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "TestVC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: Vec::new(),
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let result = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    if let SignedCredential::SdJwt { compact, .. } = result {
        assert!(
            compact.contains('~'),
            "SD-JWT compact form must contain '~' separator: {}",
            compact
        );
        // JWS portion must have 3 '.' parts
        let jws = compact.split('~').next().unwrap();
        assert_eq!(
            jws.split('.').count(),
            3,
            "JWS must have header.payload.sig"
        );
    }
}

// ── §2  IETF flat SD-JWT-VC (`IetfSdJwt`) ────────────────────────────────────

/// IETF flat format: the JWT payload must have top-level `iss`, `vct`, and `iat` claims.
#[test]
fn ietf_sd_jwt_has_required_top_level_claims() {
    let claims = CredentialClaims {
        subject_id: Some("did:example:alice".to_string()),
        credential_type: "IdentityCredential".to_string(),
        claims: base_claims(),
        expiration_seconds: Some(3600),
        selective_disclosure_claims: Vec::new(),
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let result = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    let compact = match result {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!("expected SdJwt"),
    };

    let payload = decode_jwt_payload(&compact);
    assert_eq!(
        payload.get("iss").and_then(|v| v.as_str()),
        Some("https://issuer.example.com"),
        "'iss' must match issuer_id"
    );
    assert_eq!(
        payload.get("vct").and_then(|v| v.as_str()),
        Some("IdentityCredential"),
        "'vct' must match credential_type"
    );
    assert!(
        payload.get("iat").is_some(),
        "'iat' must be present"
    );
    assert_eq!(
        payload.get("sub").and_then(|v| v.as_str()),
        Some("did:example:alice"),
        "'sub' must match subject_id when provided"
    );
    assert!(
        payload.get("exp").is_some(),
        "'exp' must be present when expiration_seconds is set"
    );
}

/// IETF flat format: non-SD claims must be top-level in the payload.
#[test]
fn ietf_sd_jwt_non_sd_claims_are_top_level() {
    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "VC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: Vec::new(), // no SD
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let result = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    let compact = match result {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!(),
    };

    let payload = decode_jwt_payload(&compact);
    assert_eq!(
        payload.get("given_name").and_then(|v| v.as_str()),
        Some("Alice"),
        "plaintext claim 'given_name' must be top-level in IETF flat format"
    );
}

// ── §3  W3C VCDM v2 SD-JWT format ────────────────────────────────────────────

/// W3C VCDM v2 format: the payload must have `@context`, `type`, `issuer`, and
/// `validFrom` in the JWT body per VCDM 2.0 §4.
#[test]
fn w3c_vcdm_v2_has_required_fields() {
    let claims = CredentialClaims {
        subject_id: Some("did:example:subject".to_string()),
        credential_type: "UniversityDegreeCredential".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: Vec::new(),
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::W3cVcdmV2SdJwt,
        w3c_context: vec!["https://example.com/credentials/v1".to_string()],
        w3c_types: vec!["UniversityDegreeCredential".to_string()],
    };

    let result = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    let compact = match result {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!(),
    };

    let payload = decode_jwt_payload(&compact);

    let context = payload.get("@context").and_then(|v| v.as_array()).expect("@context array");
    assert!(
        context.iter().any(|v| v.as_str() == Some("https://www.w3.org/ns/credentials/v2")),
        "@context must include the W3C credentials base context"
    );

    let types = payload.get("type").and_then(|v| v.as_array()).expect("type array");
    assert!(
        types.iter().any(|v| v.as_str() == Some("VerifiableCredential")),
        "'VerifiableCredential' must be in the type array"
    );

    assert!(
        payload.get("issuer").is_some(),
        "'issuer' must be present in W3C VCDM v2 payload"
    );
    assert!(
        payload.get("validFrom").is_some(),
        "'validFrom' must be present in W3C VCDM v2 payload"
    );
}

/// W3C VCDM v2: claims must be nested under `credentialSubject`.
#[test]
fn w3c_vcdm_v2_claims_under_credential_subject() {
    let claims = CredentialClaims {
        subject_id: Some("did:example:holder".to_string()),
        credential_type: "VC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: Vec::new(), // no SD — plaintext
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::W3cVcdmV2SdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let result = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    let compact = match result {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!(),
    };

    let payload = decode_jwt_payload(&compact);
    let cs = payload
        .get("credentialSubject")
        .expect("credentialSubject must be present in W3C VCDM v2 format");

    assert_eq!(
        cs.get("given_name").and_then(|v| v.as_str()),
        Some("Alice"),
        "claim 'given_name' must be under credentialSubject"
    );
    assert_eq!(
        cs.get("id").and_then(|v| v.as_str()),
        Some("did:example:holder"),
        "credentialSubject.id must match subject_id"
    );
}

// ── §4  Selective disclosure claims ──────────────────────────────────────────

/// When `selective_disclosure_claims` is non-empty, the SD claims must NOT appear
/// as plaintext in the JWT payload.
#[test]
fn sd_claims_not_in_plaintext_payload() {
    let mut claims_map = base_claims();
    claims_map.insert("secret_number".to_string(), json!(42));

    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "VC".to_string(),
        claims: claims_map,
        expiration_seconds: None,
        selective_disclosure_claims: vec!["birth_date".to_string(), "secret_number".to_string()],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let result = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    let compact = match result {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!(),
    };

    let payload = decode_jwt_payload(&compact);
    assert!(
        payload.get("birth_date").is_none(),
        "'birth_date' must not appear in plaintext payload when SD-selected"
    );
    assert!(
        payload.get("secret_number").is_none(),
        "'secret_number' must not appear in plaintext payload when SD-selected"
    );
    // The _sd array must be present
    assert!(
        payload.get("_sd").is_some(),
        "'_sd' must be present when disclosures exist"
    );
}

/// When `selective_disclosure_claims` is empty, the result must have zero disclosures
/// (compact form `JWS~`, no middle segments).
#[test]
fn no_sd_claims_produces_no_disclosures() {
    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "VC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: Vec::new(),
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let result = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    let compact = match result {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!(),
    };

    let parts: Vec<&str> = compact.split('~').collect();
    // parts[0] = JWS, parts[1] = "" (trailing ~)
    assert_eq!(
        parts.len(),
        2,
        "no-SD SD-JWT must be 'JWS~' with exactly 2 tilde segments; got {}",
        parts.len()
    );
}

// ── §5  W3cVcdmV2JwtVc payload format returns error ─────────────────────────

/// Calling `sign_sd_jwt` with `W3cVcdmV2JwtVc` payload format must return an error
/// because that format is only valid for jwt_vc_json, not SD-JWT.
#[test]
fn w3c_vcdm_v2_jwt_vc_format_returns_error() {
    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "VC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: Vec::new(),
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::W3cVcdmV2JwtVc, // invalid for SD-JWT
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let result = sign_sd_jwt(&test_issuer_key(), &claims);
    assert!(
        result.is_err(),
        "sign_sd_jwt with W3cVcdmV2JwtVc payload format must return Err"
    );
}

// ── §6  SignedCredential::SdJwt shape ────────────────────────────────────────

/// The `credential_id` must be a valid `urn:uuid:*` URN (OID4VCI §8.1 JWT `jti`).
#[test]
fn credential_id_is_urn_uuid() {
    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "VC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: Vec::new(),
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let result = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    let cred_id = match &result {
        SignedCredential::SdJwt { credential_id, .. } => credential_id.clone(),
        _ => panic!(),
    };

    assert!(
        cred_id.starts_with("urn:uuid:"),
        "credential_id must be a URN UUID: {}",
        cred_id
    );
    // Remainder must be a parseable UUID
    let uuid_part = cred_id.trim_start_matches("urn:uuid:");
    uuid::Uuid::parse_str(uuid_part).unwrap_or_else(|e| {
        panic!("credential_id UUID part must be valid: {} ({})", uuid_part, e)
    });
}

/// The `jti` in the JWT payload must match the `credential_id` field.
#[test]
fn credential_id_matches_jwt_jti() {
    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "VC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: Vec::new(),
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let result = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    let (compact, cred_id) = match result {
        SignedCredential::SdJwt { compact, credential_id } => (compact, credential_id),
        _ => panic!(),
    };

    let payload = decode_jwt_payload(&compact);
    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .expect("jti must be present in SD-JWT payload");

    assert_eq!(
        jti, cred_id,
        "JWT 'jti' must equal credential_id"
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Decode the JWT payload from a compact SD-JWT string without verification.
fn decode_jwt_payload(compact: &str) -> Value {
    let jws = compact.split('~').next().expect("JWS part");
    let b64 = jws.split('.').nth(1).expect("payload part");
    let bytes = URL_SAFE_NO_PAD.decode(b64).expect("base64url decode");
    serde_json::from_slice(&bytes).expect("payload JSON")
}

/// Extract the public-key-only version of the test Ed25519 JWK (no `d` field).
fn test_issuer_public_jwk() -> String {
    r#"{
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }"#
    .to_string()
}

// ── §7  SD-JWT Verification — round-trip ─────────────────────────────────────

/// RFC 9449 §7.3 / IETF SD-JWT-VC §4: a credential signed with `sign_sd_jwt`
/// MUST be accepted by `verify_sd_jwt` using the issuer's public key.
/// The `verified_claims` MUST contain the non-SD claims at minimum.
#[test]
fn verify_sd_jwt_round_trip_no_disclosures() {
    let issuer_key = test_issuer_key();
    let public_jwk = test_issuer_public_jwk();

    let claims = CredentialClaims {
        subject_id: Some("did:example:holder".to_string()),
        credential_type: "IdentityCredential".to_string(),
        claims: base_claims(),
        expiration_seconds: Some(3600),
        selective_disclosure_claims: Vec::new(), // all claims plaintext
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let signed = sign_sd_jwt(&issuer_key, &claims).expect("sign_sd_jwt");
    let compact = match signed {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!("expected SdJwt"),
    };

    let verified = verify_sd_jwt(&compact, &public_jwk, None, None)
        .expect("verify_sd_jwt must succeed for a freshly-signed credential");

    // Non-SD claims must be present in the verified payload
    assert_eq!(
        verified.get("given_name").and_then(|v| v.as_str()),
        Some("Alice"),
        "given_name must be present in verified_claims"
    );
    assert_eq!(
        verified.get("family_name").and_then(|v| v.as_str()),
        Some("Smith"),
        "family_name must be present in verified_claims"
    );
}

/// RFC 9449 §7.2: selectively-disclosed claims MUST appear in `verified_claims`
/// after the verifier reconstructs the payload from the provided disclosures.
#[test]
fn verify_sd_jwt_round_trip_with_disclosures() {
    let issuer_key = test_issuer_key();
    let public_jwk = test_issuer_public_jwk();

    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "IdentityCredential".to_string(),
        claims: base_claims(),
        expiration_seconds: Some(3600),
        selective_disclosure_claims: vec![
            "given_name".to_string(),
            "birth_date".to_string(),
        ],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let signed = sign_sd_jwt(&issuer_key, &claims).expect("sign_sd_jwt");
    let compact = match signed {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!("expected SdJwt"),
    };

    // The compact form must contain disclosures (tilde segments)
    let parts: Vec<&str> = compact.split('~').collect();
    assert!(
        parts.len() > 2,
        "SD claims MUST produce disclosure segments; got {} tilde parts",
        parts.len()
    );

    let verified = verify_sd_jwt(&compact, &public_jwk, None, None)
        .expect("verify_sd_jwt must succeed");

    // The non-SD claim `family_name` must always be present
    assert_eq!(
        verified.get("family_name").and_then(|v| v.as_str()),
        Some("Smith"),
        "non-SD claim family_name must be present"
    );

    // SD claims `given_name` and `birth_date` must be reconstructed from disclosures
    assert_eq!(
        verified.get("given_name").and_then(|v| v.as_str()),
        Some("Alice"),
        "SD claim given_name must be reconstructed from disclosures"
    );
    assert_eq!(
        verified.get("birth_date").and_then(|v| v.as_str()),
        Some("1990-01-15"),
        "SD claim birth_date must be reconstructed from disclosures"
    );
}

/// RFC 9449 §7: a tampered SD-JWT (bit-flipped signature) MUST be rejected
/// by `verify_sd_jwt`.
#[test]
fn verify_sd_jwt_tampered_signature_rejected() {
    let issuer_key = test_issuer_key();
    let public_jwk = test_issuer_public_jwk();

    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "VC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: Vec::new(),
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let signed = sign_sd_jwt(&issuer_key, &claims).unwrap();
    let compact = match signed {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!(),
    };

    // Corrupt the last byte of the JWS signature
    let (jws, disclosures) = compact.split_once('~').unwrap_or((&compact, ""));
    let mut jws_parts: Vec<&str> = jws.splitn(3, '.').collect();
    let mut sig_bytes = URL_SAFE_NO_PAD.decode(jws_parts[2]).unwrap();
    let last = sig_bytes.len() - 1;
    sig_bytes[last] ^= 0xFF;
    let corrupted_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
    jws_parts[2] = &corrupted_sig;
    let tampered = format!("{}.{}.{}~{}", jws_parts[0], jws_parts[1], corrupted_sig, disclosures);

    let result = verify_sd_jwt(&tampered, &public_jwk, None, None);
    assert!(
        result.is_err(),
        "tampered SD-JWT signature MUST be rejected by verify_sd_jwt"
    );
}

/// RFC 9449 §7: a completely wrong key MUST cause verification to fail.
#[test]
fn verify_sd_jwt_wrong_public_key_rejected() {
    let issuer_key = test_issuer_key();
    // Different Ed25519 public key — not the one that signed the credential
    let wrong_public_jwk = r#"{
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "JHm4sOOblT4OFLG1MWFHQ4m3OxFpMqHF6AyEXS3UKY"
    }"#;

    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "VC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: Vec::new(),
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let signed = sign_sd_jwt(&issuer_key, &claims).unwrap();
    let compact = match signed {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!(),
    };

    let result = verify_sd_jwt(&compact, wrong_public_jwk, None, None);
    assert!(
        result.is_err(),
        "SD-JWT verified with a wrong public key MUST be rejected"
    );
}

// ── §8  SD-JWT Disclosure Integrity ──────────────────────────────────────────

/// RFC 9449 §5.1: the `_sd` array in the payload MUST NOT contain the
/// plaintext claim name — it must only contain salted hash digests.
#[test]
fn sd_claims_payload_contains_only_hashes_not_plaintext() {
    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "VC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: vec!["given_name".to_string(), "birth_date".to_string()],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let signed = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    let compact = match signed {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!(),
    };

    let payload = decode_jwt_payload(&compact);
    let sd_array = payload.get("_sd").and_then(|v| v.as_array()).expect("_sd array");

    // Each element of _sd must be a string (base64url-encoded hash), not an object
    for entry in sd_array {
        assert!(
            entry.is_string(),
            "_sd entries must be base64url hash strings, not: {:?}",
            entry
        );
        let s = entry.as_str().unwrap();
        assert!(
            s.len() >= 32,
            "_sd hash digest is suspiciously short ({} chars): {}",
            s.len(),
            s
        );
    }

    // The SD claim names must NOT appear as plaintext keys in the payload
    assert!(
        payload.get("given_name").is_none(),
        "given_name must NOT appear as plaintext in the JWT body when SD-selected"
    );
    assert!(
        payload.get("birth_date").is_none(),
        "birth_date must NOT appear as plaintext when SD-selected"
    );
}

/// RFC 9449 §5.2: each disclosure in the compact form MUST be a valid
/// base64url-encoded JSON array `[salt, name, value]`.
#[test]
fn sd_jwt_disclosures_have_valid_structure() {
    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "VC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: vec![
            "given_name".to_string(),
            "family_name".to_string(),
            "birth_date".to_string(),
        ],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let signed = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    let compact = match signed {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!(),
    };

    // Disclosures are the tilde-separated segments after the JWS
    let tilde_parts: Vec<&str> = compact.split('~').collect();
    // tilde_parts[0] = JWS, tilde_parts[1..n-1] = disclosures, tilde_parts[n] = "" (trailing ~) or KB-JWT
    let disclosures: Vec<&str> = tilde_parts[1..]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect();

    assert!(
        !disclosures.is_empty(),
        "3 SD claims must produce at least 1 disclosure"
    );

    for disc in &disclosures {
        let bytes = URL_SAFE_NO_PAD.decode(disc).unwrap_or_else(|e| {
            panic!("disclosure must be valid base64url: {} ({})", disc, e)
        });
        let decoded: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("disclosure must be valid JSON: {:?} ({})", bytes, e)
        });
        let arr = decoded
            .as_array()
            .expect("disclosure must be a JSON array");
        assert_eq!(
            arr.len(),
            3,
            "disclosure must have [salt, name, value] — got {:?}",
            arr
        );
        assert!(arr[0].is_string(), "disclosure[0] (salt) must be a string");
        assert!(arr[1].is_string(), "disclosure[1] (name) must be a string");
    }
}

/// RFC 9449 §7.1: `_sd_alg` in the payload MUST default to `sha-256` when
/// no explicit algorithm is specified.
#[test]
fn sd_jwt_payload_sd_alg_defaults_to_sha256() {
    let claims = CredentialClaims {
        subject_id: None,
        credential_type: "VC".to_string(),
        claims: base_claims(),
        expiration_seconds: None,
        selective_disclosure_claims: vec!["given_name".to_string()],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };

    let signed = sign_sd_jwt(&test_issuer_key(), &claims).unwrap();
    let compact = match signed {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!(),
    };

    let payload = decode_jwt_payload(&compact);
    if let Some(alg) = payload.get("_sd_alg") {
        assert_eq!(
            alg.as_str(),
            Some("sha-256"),
            "_sd_alg must be 'sha-256' when present"
        );
    }
    // If _sd_alg is absent, sha-256 is the default per RFC 9449 §5 — both are conformant.
}
