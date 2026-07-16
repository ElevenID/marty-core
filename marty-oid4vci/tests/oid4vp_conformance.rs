//! OID4VP 1.0 Final — VerificationEngine conformance tests.
//!
//! Tests the public `VerificationEngine` API against the OpenID for Verifiable
//! Presentations 1.0 Final specification, mirroring the OIDF conformance suite
//! module names used in `test_oid4vp_verifier_conformance.py`.
//!
//! The fixtures are copied into this crate so the tests remain hermetic in an
//! isolated package checkout. Keep them aligned with the integration corpus.
//!
//! Run:
//!   cargo test --test oid4vp_conformance                (from marty-oid4vci/)
//!
//! References:
//!   OID4VP 1.0 Final: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
//!   DIF PE v2:        https://identity.foundation/presentation-exchange/
//!   OIDF suite:       https://gitlab.com/openid/conformance-suite
//!
//! §A  Happy flows                 — VPVerifierHappyFlow
//! §B  Nonce validation            — VPVerifierFailOnInvalidNonce
//! §C  Signature validation        — VPVerifierFailOnInvalidJwtProofSignature
//! §D  Expiration validation       — exp claim enforcement
//! §E  Audience validation         — aud claim enforcement
//! §F  Holder key binding          — jwk header requirement
//! §G  Presentation structure      — DIF PE descriptor mapping
//! §H  Malformed input             — graceful error (no panics)
//! §I  SIOPv2 stubs                — #[ignore] pending implementation

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use marty_oid4vci::verifier::{
    DescriptorMapEntry, PresentationDefinition, PresentationSubmission, VerificationEngine,
};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Constants (must stay in sync with generate_fixtures.py) ──────────────────

/// Verifier identifier — matches `VERIFIER_ID` in generate_fixtures.py.
const VERIFIER_ID: &str = "https://verifier.example.com";

/// Response URI for the verification engine.
const RESPONSE_URI: &str = "https://verifier.example.com/callback";

/// Nonce from `presentation_request.json` — also embedded in `vp_token_jwt.txt`.
const NONCE: &str = "n-0S6_WzA2Mj";

/// Holder DID derived from `HOLDER_KEY_SEED` (bytes 0x01..0x20) by generate_fixtures.py.
const HOLDER_DID: &str = "did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7";

// ── Static fixtures (shared corpus) ──────────────────────────────────────────

const PRESENTATION_DEFINITION_JSON: &str =
    include_str!("fixtures/conformance/presentation_definition.json");
const PRESENTATION_SUBMISSION_JSON: &str =
    include_str!("fixtures/conformance/presentation_submission.json");
/// Pre-signed VP JWT from the corpus.  Signed with `HOLDER_KEY_SEED`, `aud = VERIFIER_ID`,
/// `nonce = NONCE`, `exp = 9999999999` (year ~2286 — will not expire for practical purposes).
const STATIC_VP_TOKEN: &str = include_str!("fixtures/conformance/vp_token_jwt.txt");

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Build a deterministic Ed25519 signing key from a fixed seed.
/// Seed matches `HOLDER_KEY_SEED` in `generate_fixtures.py` (bytes 0x01..0x20).
fn test_signing_key() -> SigningKey {
    let seed: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
    SigningKey::from_bytes(&seed)
}

fn make_engine() -> VerificationEngine {
    VerificationEngine::new(VERIFIER_ID, RESPONSE_URI)
}

fn b64url_json(v: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_string(v).unwrap().as_bytes())
}

/// Build and sign a compact VP JWT suitable for `verify_vp_token`.
///
/// `exp_offset_secs` is added to the current unix timestamp:
///   - positive (e.g. 3600) → valid token
///   - negative (e.g. -300) → already-expired token
fn make_vp_jwt(sk: &SigningKey, nonce: &str, aud: &str, exp_offset_secs: i64) -> String {
    let vk = sk.verifying_key();
    let x = URL_SAFE_NO_PAD.encode(vk.as_bytes());

    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x
        }
    });

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let payload = json!({
        "iss": HOLDER_DID,
        "sub": HOLDER_DID,
        "aud": aud,
        "iat": now,
        "exp": now + exp_offset_secs,
        "nonce": nonce,
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [{
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                "credentialSubject": {
                    "given_name": "Conformance",
                    "family_name": "Test",
                    "degree": "BSc Computer Science"
                }
            }]
        }
    });

    let h = b64url_json(&header);
    let p = b64url_json(&payload);
    let signing_input = format!("{}.{}", h, p);
    let sig = sk.sign(signing_input.as_bytes());
    let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    format!("{}.{}.{}", h, p, s)
}

fn make_pd_from_fixture() -> PresentationDefinition {
    serde_json::from_str(PRESENTATION_DEFINITION_JSON)
        .expect("presentation_definition.json must be valid JSON for PresentationDefinition")
}

fn make_ps_from_fixture() -> PresentationSubmission {
    serde_json::from_str(PRESENTATION_SUBMISSION_JSON)
        .expect("presentation_submission.json must be valid JSON for PresentationSubmission")
}

// ── §A  Happy Flows ───────────────────────────────────────────────────────────

/// OID4VP 1.0 Final §7: A properly signed VP JWT with the expected nonce and
/// verifier audience must pass.  OIDF: VPVerifierHappyFlow.
#[test]
fn happy_path_vp_token_jwt() {
    let sk = test_signing_key();
    let vp = make_vp_jwt(&sk, NONCE, VERIFIER_ID, 3600);
    let engine = make_engine();

    let result = engine.verify_vp_token(&vp, NONCE);

    assert!(
        result.valid,
        "expected valid VP, got errors: {:?}",
        result.errors
    );
    assert!(
        result.errors.is_empty(),
        "no errors expected: {:?}",
        result.errors
    );
    assert!(
        result.descriptor_results.iter().any(|r| r.valid),
        "at least one valid descriptor result expected"
    );
}

/// Cross-language consistency check: the static VP token written by
/// `generate_fixtures.py` must verify against the same VERIFIER_ID and NONCE.
/// Failure here indicates the fixture generator and test constants have drifted.
#[test]
fn static_fixture_vp_token_verifies() {
    let engine = make_engine();

    let result = engine.verify_vp_token(STATIC_VP_TOKEN.trim(), NONCE);

    assert!(
        result.valid,
        "static fixture VP token (from generate_fixtures.py) must verify — \
         check VERIFIER_ID and NONCE constants are in sync: {:?}",
        result.errors
    );
}

// ── §B  Nonce Validation ──────────────────────────────────────────────────────

/// OID4VP 1.0 Final §5.2: The nonce in the VP MUST match the nonce from the
/// authorization request.  OIDF: VPVerifierFailOnInvalidNonce.
#[test]
fn invalid_nonce_rejected() {
    let sk = test_signing_key();
    let vp = make_vp_jwt(
        &sk,
        "wrong-nonce-value-that-doesnt-match",
        VERIFIER_ID,
        3600,
    );
    let engine = make_engine();

    let result = engine.verify_vp_token(&vp, NONCE);

    assert!(!result.valid, "VP with wrong nonce MUST be rejected");
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.to_lowercase().contains("nonce")),
        "error MUST mention 'nonce', got: {:?}",
        result.errors
    );
}

/// Sending the same VP token twice (replay) must fail because the nonce carried
/// in the second request would be different from the one in the token.
/// OIDF: VPVerifierFailOnReplayNonce (simulated via nonce mismatch).
#[test]
fn nonce_replay_detected() {
    let sk = test_signing_key();
    // Token was signed for NONCE; replay it with a different expected nonce.
    let vp = make_vp_jwt(&sk, NONCE, VERIFIER_ID, 3600);
    let engine = make_engine();

    let replay_nonce = "different-nonce-for-second-request";
    let result = engine.verify_vp_token(&vp, replay_nonce);

    assert!(
        !result.valid,
        "replayed VP token with stale nonce MUST be rejected"
    );
}

// ── §C  Signature Validation ──────────────────────────────────────────────────

/// OIDF: VPVerifierFailOnInvalidJwtProofSignature — bit-flipping one byte of the
/// base64url-encoded signature in the JWT's third segment must fail verification.
#[test]
fn tampered_vp_token_rejected() {
    let sk = test_signing_key();
    let vp = make_vp_jwt(&sk, NONCE, VERIFIER_ID, 3600);

    // Split into three JWT parts and corrupt the signature (third part)
    let parts: Vec<&str> = vp.split('.').collect();
    assert_eq!(parts.len(), 3, "test VP must be a 3-part compact JWT");

    let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    let last = sig_bytes.len() - 1;
    sig_bytes[last] ^= 0xFF; // flip last byte
    let tampered_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
    let tampered_vp = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);

    let engine = make_engine();
    let result = engine.verify_vp_token(&tampered_vp, NONCE);

    assert!(!result.valid, "bit-flipped VP JWT MUST be rejected");
}

// ── §D  Expiration Validation ─────────────────────────────────────────────────

/// OID4VP 1.0 Final §5.2: expired VP tokens MUST be rejected.
/// The engine grants a 60-second leeway, so we use exp = now - 300 (5 min past).
#[test]
fn expired_vp_token_rejected() {
    let sk = test_signing_key();
    let vp = make_vp_jwt(&sk, NONCE, VERIFIER_ID, -300);
    let engine = make_engine();

    let result = engine.verify_vp_token(&vp, NONCE);

    assert!(
        !result.valid,
        "expired VP JWT (exp 5 min ago) MUST be rejected"
    );
}

// ── §E  Audience Validation ───────────────────────────────────────────────────

/// OID4VP 1.0 Final §5: The VP's `aud` claim MUST contain the verifier's
/// `client_id` / `verifier_id`.
#[test]
fn audience_mismatch_rejected() {
    let sk = test_signing_key();
    let vp = make_vp_jwt(&sk, NONCE, "https://attacker.example.com", 3600);
    let engine = make_engine();

    let result = engine.verify_vp_token(&vp, NONCE);

    assert!(!result.valid, "VP with wrong `aud` MUST be rejected");
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.to_lowercase().contains("aud")),
        "error MUST mention 'aud', got: {:?}",
        result.errors
    );
}

// ── §F  Holder Key Binding ────────────────────────────────────────────────────

/// OID4VP 1.0 Final §5: The VP MUST carry the holder's public key so the
/// verifier can check holder binding.  A JWT without `jwk` in the header
/// (and without `cnf.jwk` / `sub_jwk` in payload) MUST be rejected.
#[test]
fn missing_holder_key_rejected() {
    let sk = test_signing_key();

    // Header intentionally omits the `jwk` field
    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT"
    });

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let payload = json!({
        "iss": HOLDER_DID,
        "aud": VERIFIER_ID,
        "iat": now,
        "exp": now + 3600,
        "nonce": NONCE,
        "vp": {
            "@context": [],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": []
        }
    });

    let h = b64url_json(&header);
    let p = b64url_json(&payload);
    let sig = sk.sign(format!("{}.{}", h, p).as_bytes());
    let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let vp = format!("{}.{}.{}", h, p, s);

    let engine = make_engine();
    let result = engine.verify_vp_token(&vp, NONCE);

    assert!(
        !result.valid,
        "VP without embedded holder public key MUST be rejected"
    );
}

// ── §G  Presentation Structure (DIF PE v2) ────────────────────────────────────

/// DIF PE v2 §5 + OID4VP §5: A submission whose `definition_id` and
/// `descriptor_map` match the presentation definition MUST pass structural
/// validation.  OIDF: VPVerifierHappyFlow (presentation_definition variant).
#[test]
fn presentation_definition_matching() {
    let pd = make_pd_from_fixture();
    let ps = make_ps_from_fixture();
    let engine = make_engine();

    let result = engine.verify_presentation_structure(&pd, &ps);

    assert!(
        result.valid,
        "matching PD/PS from shared fixtures MUST pass: {:?}",
        result.errors
    );
    assert!(
        result.errors.is_empty(),
        "no errors expected: {:?}",
        result.errors
    );
}

/// OIDF: VPVerifierFailOnPresentationDefinitionMismatch —
/// A submission whose `definition_id` does not match the PD MUST fail.
#[test]
fn presentation_definition_id_mismatch_rejected() {
    let pd = make_pd_from_fixture();
    let ps = PresentationSubmission {
        id: "ps-wrong-definition".to_string(),
        definition_id: "completely-different-pd-id".to_string(),
        descriptor_map: vec![DescriptorMapEntry {
            id: "university_degree".to_string(),
            format: "jwt_vp".to_string(),
            path: "$".to_string(),
            path_nested: None,
        }],
    };
    let engine = make_engine();

    let result = engine.verify_presentation_structure(&pd, &ps);

    assert!(!result.valid, "mismatched definition_id MUST fail");
    assert!(
        !result.errors.is_empty(),
        "must report at least one error for definition_id mismatch"
    );
}

/// OIDF: VPVerifierFailOnMissingDescriptor —
/// A submission with an empty `descriptor_map` for a required descriptor MUST fail.
#[test]
fn presentation_definition_missing_descriptor_rejected() {
    let pd = make_pd_from_fixture();
    let ps = PresentationSubmission {
        id: "ps-empty-map".to_string(),
        definition_id: pd.id.clone(),
        descriptor_map: vec![], // intentionally empty — required descriptor not mapped
    };
    let engine = make_engine();

    let result = engine.verify_presentation_structure(&pd, &ps);

    assert!(
        !result.valid,
        "empty descriptor_map for required descriptor MUST fail"
    );
    assert!(
        result.descriptor_results.iter().any(|r| !r.valid),
        "must have at least one failing descriptor result"
    );
}

/// A descriptor mapping that references an unsupported format (not in the PD's
/// allowed format list) MUST be marked invalid.
#[test]
fn presentation_definition_format_mismatch_rejected() {
    // Build a PD that only accepts `jwt_vp`
    let pd: PresentationDefinition = serde_json::from_value(json!({
        "id": "pd-format-test",
        "input_descriptors": [{
            "id": "university_degree",
            "constraints": { "fields": [] },
            "format": { "jwt_vp": {} }
        }]
    }))
    .unwrap();

    // Submit with `mso_mdoc` format — not in the allowed set
    let ps = PresentationSubmission {
        id: "ps-wrong-format".to_string(),
        definition_id: "pd-format-test".to_string(),
        descriptor_map: vec![DescriptorMapEntry {
            id: "university_degree".to_string(),
            format: "mso_mdoc".to_string(),
            path: "$".to_string(),
            path_nested: None,
        }],
    };

    let engine = make_engine();
    let result = engine.verify_presentation_structure(&pd, &ps);

    assert!(!result.valid, "format mismatch MUST be rejected");
    assert!(
        result.descriptor_results.iter().any(|r| !r.valid),
        "the mismatched descriptor MUST be invalid"
    );
}

// ── §H  Malformed Input ───────────────────────────────────────────────────────

/// Verify that malformed VP token strings are rejected gracefully (no panic).
#[test]
fn malformed_vp_token_too_many_parts_rejected() {
    let engine = make_engine();
    let result = engine.verify_vp_token("not.a.proper.jwt.at.all", NONCE);
    assert!(
        !result.valid,
        "malformed VP token (too many dots) MUST be rejected"
    );
}

#[test]
fn malformed_vp_token_single_part_rejected() {
    let engine = make_engine();
    let result = engine.verify_vp_token("justonepart", NONCE);
    assert!(
        !result.valid,
        "single-part string MUST be rejected as invalid JWT"
    );
}

#[test]
fn empty_vp_token_rejected() {
    let engine = make_engine();
    let result = engine.verify_vp_token("", NONCE);
    assert!(!result.valid, "empty string MUST be rejected");
}

// ── §I  SIOPv2 — stubbed pending implementation ───────────────────────────────

/// SIOPv2 Draft 13 §11: Self-Issued OP requires `iss == sub`.
/// Tracked in test_siop_v2_conformance.py (all expected-fail until implemented).
#[test]
#[ignore = "SIOPv2 not yet implemented — see test_siop_v2_conformance.py in marty-integration-tests"]
fn siop_v2_iss_sub_equality_required() {
    todo!("implement SIOPv2 support: VerificationEngine should have verify_siop_id_token()")
}

#[test]
#[ignore = "SIOPv2 not yet implemented — see test_siop_v2_conformance.py in marty-integration-tests"]
fn siop_v2_well_known_discovery() {
    todo!("implement SIOPv2 /.well-known/openid-configuration discovery")
}

// ── §J  PEX Field Constraint Evaluation (DIF PE v2 §5) ───────────────────────
//
// Tests for `verify_presentation()` — the composite function that performs
// both structural validation (§G) and field constraint evaluation against the
// decoded VP token payload.

/// When `vp_payload` is `None`, `verify_presentation` MUST fall back to
/// structural-only validation and return the same result as
/// `verify_presentation_structure`.
#[test]
fn verify_presentation_no_payload_returns_structural_result() {
    let pd = make_pd_from_fixture();
    let ps = make_ps_from_fixture();
    let engine = make_engine();

    let structural = engine.verify_presentation_structure(&pd, &ps);
    let full = engine.verify_presentation(&pd, &ps, None);

    assert_eq!(
        structural.valid, full.valid,
        "no-payload results must agree"
    );
    assert_eq!(
        structural.errors.len(),
        full.errors.len(),
        "no-payload error counts must agree"
    );
}

/// DIF PE v2 §5.1: The fixture PD + PS + decoded static VP token MUST pass
/// full PEX validation (structural check AND field constraint evaluation).
#[test]
fn verify_presentation_with_fixture_vp_payload_valid() {
    use base64::Engine as _;
    let pd = make_pd_from_fixture();
    let ps = make_ps_from_fixture();
    let engine = make_engine();

    let parts: Vec<&str> = STATIC_VP_TOKEN.trim().split('.').collect();
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("static VP token must have valid base64url payload");
    let vp_payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("VP payload must be valid JSON");

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));

    assert!(
        result.valid,
        "fixture PD+PS+payload must pass full PEX evaluation: {:?}",
        result.errors
    );
    assert!(result.errors.is_empty());
}

/// DIF PE v2 §5.1: A field constraint satisfied by the credential value MUST
/// produce per-descriptor `valid = true`.
#[test]
fn verify_presentation_field_constraint_satisfied() {
    let engine = make_engine();

    let pd: PresentationDefinition = serde_json::from_value(json!({
        "id": "pd-j1",
        "input_descriptors": [{
            "id": "degree",
            "constraints": {
                "fields": [{
                    "path": ["$.type"],
                    "filter": {
                        "type": "array",
                        "contains": { "const": "UniversityDegreeCredential" }
                    }
                }]
            }
        }]
    }))
    .unwrap();

    let ps = PresentationSubmission {
        id: "ps-j1".to_string(),
        definition_id: "pd-j1".to_string(),
        descriptor_map: vec![DescriptorMapEntry {
            id: "degree".to_string(),
            format: "jwt_vc".to_string(),
            path: "$".to_string(),
            path_nested: None,
        }],
    };

    let vp_payload = json!({
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "credentialSubject": { "given_name": "Alice" }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));

    assert!(
        result.valid,
        "satisfied field constraint MUST pass: {:?}",
        result.errors
    );
    assert!(result.errors.is_empty());
    assert!(result.descriptor_results.iter().all(|r| r.valid));
}

/// DIF PE v2 §5.1: When the `filter` is not satisfied by the claim value,
/// the descriptor MUST be `valid = false` and the overall result `valid = false`.
#[test]
fn verify_presentation_field_filter_not_satisfied_fails() {
    let engine = make_engine();

    let pd: PresentationDefinition = serde_json::from_value(json!({
        "id": "pd-j2",
        "input_descriptors": [{
            "id": "degree",
            "constraints": {
                "fields": [{
                    "path": ["$.type"],
                    "filter": {
                        "type": "array",
                        "contains": { "const": "MedicalCredential" }
                    }
                }]
            }
        }]
    }))
    .unwrap();

    let ps = PresentationSubmission {
        id: "ps-j2".to_string(),
        definition_id: "pd-j2".to_string(),
        descriptor_map: vec![DescriptorMapEntry {
            id: "degree".to_string(),
            format: "jwt_vc".to_string(),
            path: "$".to_string(),
            path_nested: None,
        }],
    };

    // Credential presents UniversityDegreeCredential, not MedicalCredential.
    let vp_payload = json!({
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "credentialSubject": { "given_name": "Alice" }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));

    assert!(!result.valid, "unsatisfied filter MUST fail");
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("filter") || e.contains("const") || e.contains("contain")),
        "error must mention filter/const/contain: {:?}",
        result.errors
    );
}

/// DIF PE v2 §5.1: A required field that is absent from the credential MUST
/// produce `valid = false` for that descriptor.
#[test]
fn verify_presentation_required_field_missing_fails() {
    let engine = make_engine();

    let pd: PresentationDefinition = serde_json::from_value(json!({
        "id": "pd-j3",
        "input_descriptors": [{
            "id": "id_cred",
            "constraints": {
                "fields": [{
                    "path": ["$.credentialSubject.passport_number"]
                }]
            }
        }]
    }))
    .unwrap();

    let ps = PresentationSubmission {
        id: "ps-j3".to_string(),
        definition_id: "pd-j3".to_string(),
        descriptor_map: vec![DescriptorMapEntry {
            id: "id_cred".to_string(),
            format: "jwt_vc".to_string(),
            path: "$".to_string(),
            path_nested: None,
        }],
    };

    // credential does not have `passport_number`
    let vp_payload = json!({
        "credentialSubject": { "given_name": "Alice" }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));

    assert!(!result.valid, "missing required field MUST fail");
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("passport_number") || e.contains("not found")),
        "error must mention the missing field or 'not found': {:?}",
        result.errors
    );
}

/// DIF PE v2 §5.1.1: A field with `optional: true` that is absent from the
/// credential MUST NOT cause the descriptor to be invalid.
#[test]
fn verify_presentation_optional_field_absent_passes() {
    let engine = make_engine();

    let pd: PresentationDefinition = serde_json::from_value(json!({
        "id": "pd-j4",
        "input_descriptors": [{
            "id": "id_cred",
            "constraints": {
                "fields": [
                    { "path": ["$.credentialSubject.given_name"] },
                    { "path": ["$.credentialSubject.middle_name"], "optional": true }
                ]
            }
        }]
    }))
    .unwrap();

    let ps = PresentationSubmission {
        id: "ps-j4".to_string(),
        definition_id: "pd-j4".to_string(),
        descriptor_map: vec![DescriptorMapEntry {
            id: "id_cred".to_string(),
            format: "jwt_vc".to_string(),
            path: "$".to_string(),
            path_nested: None,
        }],
    };

    // `middle_name` absent — allowed because optional
    let vp_payload = json!({
        "credentialSubject": { "given_name": "Alice" }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));

    assert!(
        result.valid,
        "absent optional field MUST NOT fail: {:?}",
        result.errors
    );
    assert!(result.errors.is_empty());
}

/// DIF PE v2 §5.1.1: `constraints.limit_disclosure: "required"` binds the
/// descriptor to SD-JWT formats.  Presenting a `jwt_vc_json` format
/// (incapable of selective disclosure) MUST produce `valid = false`.
#[test]
fn verify_presentation_limit_disclosure_required_non_sdjwt_fails() {
    let engine = make_engine();

    let pd: PresentationDefinition = serde_json::from_value(json!({
        "id": "pd-j5",
        "input_descriptors": [{
            "id": "id_cred",
            "constraints": {
                "fields": [{ "path": ["$.given_name"] }],
                "limit_disclosure": "required"
            }
        }]
    }))
    .unwrap();

    let ps = PresentationSubmission {
        id: "ps-j5".to_string(),
        definition_id: "pd-j5".to_string(),
        descriptor_map: vec![DescriptorMapEntry {
            id: "id_cred".to_string(),
            format: "jwt_vc_json".to_string(), // NOT sd_jwt
            path: "$".to_string(),
            path_nested: None,
        }],
    };

    let vp_payload = json!({ "given_name": "Alice" });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));

    assert!(
        !result.valid,
        "limit_disclosure:required with non-SD-JWT MUST fail"
    );
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("limit_disclosure") || e.contains("SD-JWT")),
        "error must mention limit_disclosure or SD-JWT: {:?}",
        result.errors
    );
}

/// Multi-descriptor PD: when all descriptors are satisfied, the result MUST
/// have `valid = true` and all per-descriptor results valid.
#[test]
fn verify_presentation_multi_descriptor_all_satisfied() {
    let engine = make_engine();

    let pd: PresentationDefinition = serde_json::from_value(json!({
        "id": "pd-j6",
        "input_descriptors": [
            {
                "id": "identity",
                "constraints": { "fields": [{ "path": ["$.given_name"] }] }
            },
            {
                "id": "degree",
                "constraints": { "fields": [{ "path": ["$.degree"] }] }
            }
        ]
    }))
    .unwrap();

    let ps = PresentationSubmission {
        id: "ps-j6".to_string(),
        definition_id: "pd-j6".to_string(),
        descriptor_map: vec![
            DescriptorMapEntry {
                id: "identity".to_string(),
                format: "jwt_vc".to_string(),
                path: "$".to_string(),
                path_nested: None,
            },
            DescriptorMapEntry {
                id: "degree".to_string(),
                format: "jwt_vc".to_string(),
                path: "$".to_string(),
                path_nested: None,
            },
        ],
    };

    let vp_payload = json!({
        "given_name": "Alice",
        "degree": "BSc Computer Science"
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));

    assert!(
        result.valid,
        "all descriptors satisfied MUST pass: {:?}",
        result.errors
    );
    assert_eq!(result.descriptor_results.len(), 2);
    assert!(result.descriptor_results.iter().all(|r| r.valid));
}

/// Multi-descriptor PD: when one descriptor's required field is absent,
/// the overall result MUST be `valid = false` and exactly one descriptor
/// result must be invalid.
#[test]
fn verify_presentation_multi_descriptor_one_fails() {
    let engine = make_engine();

    let pd: PresentationDefinition = serde_json::from_value(json!({
        "id": "pd-j7",
        "input_descriptors": [
            {
                "id": "identity",
                "constraints": { "fields": [{ "path": ["$.given_name"] }] }
            },
            {
                "id": "degree",
                "constraints": { "fields": [{ "path": ["$.degree"] }] }
            }
        ]
    }))
    .unwrap();

    let ps = PresentationSubmission {
        id: "ps-j7".to_string(),
        definition_id: "pd-j7".to_string(),
        descriptor_map: vec![
            DescriptorMapEntry {
                id: "identity".to_string(),
                format: "jwt_vc".to_string(),
                path: "$".to_string(),
                path_nested: None,
            },
            DescriptorMapEntry {
                id: "degree".to_string(),
                format: "jwt_vc".to_string(),
                path: "$".to_string(),
                path_nested: None,
            },
        ],
    };

    // `degree` missing from the credential
    let vp_payload = json!({ "given_name": "Alice" });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));

    assert!(
        !result.valid,
        "one failing descriptor MUST make result invalid"
    );
    let failing = result
        .descriptor_results
        .iter()
        .filter(|r| !r.valid)
        .count();
    assert_eq!(
        failing, 1,
        "exactly one descriptor should fail; got: {:?}",
        result.descriptor_results
    );
    let passing = result.descriptor_results.iter().filter(|r| r.valid).count();
    assert_eq!(
        passing, 1,
        "exactly one descriptor should pass; got: {:?}",
        result.descriptor_results
    );
}

/// DIF PE v2 §5: `path_nested` navigation — the field constraint is evaluated
/// against the nested credential document, not the VP wrapper.
#[test]
fn verify_presentation_path_nested_navigates_to_credential() {
    let engine = make_engine();

    let pd: PresentationDefinition = serde_json::from_value(json!({
        "id": "pd-j8",
        "input_descriptors": [{
            "id": "degree",
            "constraints": {
                "fields": [{
                    "path": ["$.credentialSubject.given_name"]
                }]
            }
        }]
    }))
    .unwrap();

    // path_nested navigates into the vp.verifiableCredential array
    let ps = PresentationSubmission {
        id: "ps-j8".to_string(),
        definition_id: "pd-j8".to_string(),
        descriptor_map: vec![DescriptorMapEntry {
            id: "degree".to_string(),
            format: "jwt_vp".to_string(),
            path: "$".to_string(),
            path_nested: Some(Box::new(DescriptorMapEntry {
                id: "degree".to_string(),
                format: "jwt_vc".to_string(),
                path: "$.vp.verifiableCredential[0]".to_string(),
                path_nested: None,
            })),
        }],
    };

    // VP payload: claim lives inside the nested VC, not at the root
    let vp_payload = json!({
        "iss": "did:example:holder",
        "vp": {
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [{
                "type": ["VerifiableCredential"],
                "credentialSubject": { "given_name": "Alice" }
            }]
        }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));

    assert!(
        result.valid,
        "path_nested navigation to credential MUST resolve the field constraint: {:?}",
        result.errors
    );
}

/// `minimum` filter: a numeric claim satisfying `minimum` MUST pass.
#[test]
fn verify_presentation_filter_minimum_satisfied() {
    let engine = make_engine();

    let pd: PresentationDefinition = serde_json::from_value(json!({
        "id": "pd-j9",
        "input_descriptors": [{
            "id": "age_cred",
            "constraints": {
                "fields": [{
                    "path": ["$.age"],
                    "filter": { "type": "number", "minimum": 18 }
                }]
            }
        }]
    }))
    .unwrap();

    let ps = PresentationSubmission {
        id: "ps-j9".to_string(),
        definition_id: "pd-j9".to_string(),
        descriptor_map: vec![DescriptorMapEntry {
            id: "age_cred".to_string(),
            format: "jwt_vc".to_string(),
            path: "$".to_string(),
            path_nested: None,
        }],
    };

    let result_pass = engine.verify_presentation(&pd, &ps, Some(&json!({ "age": 21 })));
    assert!(
        result_pass.valid,
        "age 21 >= minimum 18 MUST pass: {:?}",
        result_pass.errors
    );

    let result_fail = engine.verify_presentation(&pd, &ps, Some(&json!({ "age": 16 })));
    assert!(!result_fail.valid, "age 16 < minimum 18 MUST fail");
}

/// `enum` filter: a claim whose value is in the enum set MUST pass; outside
/// the set MUST fail.
#[test]
fn verify_presentation_filter_enum() {
    let engine = make_engine();

    let pd: PresentationDefinition = serde_json::from_value(json!({
        "id": "pd-j10",
        "input_descriptors": [{
            "id": "nationality_cred",
            "constraints": {
                "fields": [{
                    "path": ["$.nationality"],
                    "filter": { "enum": ["DE", "FR", "GB"] }
                }]
            }
        }]
    }))
    .unwrap();

    let ps = PresentationSubmission {
        id: "ps-j10".to_string(),
        definition_id: "pd-j10".to_string(),
        descriptor_map: vec![DescriptorMapEntry {
            id: "nationality_cred".to_string(),
            format: "jwt_vc".to_string(),
            path: "$".to_string(),
            path_nested: None,
        }],
    };

    let pass = engine.verify_presentation(&pd, &ps, Some(&json!({ "nationality": "DE" })));
    assert!(pass.valid, "DE is in enum MUST pass: {:?}", pass.errors);

    let fail = engine.verify_presentation(&pd, &ps, Some(&json!({ "nationality": "US" })));
    assert!(!fail.valid, "US is not in enum MUST fail");
}
