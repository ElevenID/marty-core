//! DIF Presentation Exchange v2 — Official spec conformance tests.
//!
//! Translates the official DIF PEX test suite
//! (https://github.com/decentralized-identity/presentation-exchange/tree/main/test)
//! from JavaScript (JSON Schema validation) into Rust, and extends it with
//! full evaluator conformance against the spec's example patterns.
//!
//! Fixture files are verbatim copies of the official DIF PEX test vectors
//! stored under `tests/fixtures/dif_pex/`.
//!
//! Run:
//!   cargo test --test dif_pex_conformance
//!
//! References:
//!   DIF PE v2 spec:        https://identity.foundation/presentation-exchange/
//!   Official test vectors: https://github.com/decentralized-identity/presentation-exchange/tree/main/test
//!   OIDF suite mapping:    https://gitlab.com/openid/conformance-suite
//!
//! §K  Official PD fixture parsing  — JSON Schema compliance (test/presentation-definition/)
//! §L  Official PS fixture parsing  — JSON Schema compliance (test/presentation-submission/)
//! §M  Evaluator conformance        — field constraint evaluation against spec example patterns

use marty_oid4vci::verifier::{
    DescriptorMapEntry, PresentationDefinition, PresentationSubmission, VerificationEngine,
};
use serde_json::{json, Value};

// ── Official fixture files (verbatim from DIF PEX repo, main branch) ─────────
//
// Source: https://github.com/decentralized-identity/presentation-exchange/tree/main/test

/// Minimal single-descriptor PD — multi-path field presence.
/// Source: test/presentation-definition/minimal_example.json
const PD_MINIMAL_JSON: &str =
    include_str!("fixtures/dif_pex/pd_minimal.json");

/// Filter-by-type PD — `contains` filter with regex pattern on `$.type`.
/// Source: test/presentation-definition/pd_filter.json
const PD_FILTER_JSON: &str =
    include_str!("fixtures/dif_pex/pd_filter.json");

/// Two-filter simplified PD — three `pattern` constraints on flat fields.
/// Source: test/presentation-definition/pd_filter2_simplified.json
const PD_FILTER2_SIMPLIFIED_JSON: &str =
    include_str!("fixtures/dif_pex/pd_filter2_simplified.json");

/// Basic two-descriptor example — `limit_disclosure`, `const`, `pattern`,
/// and the extra `intent_to_retain` / `purpose` hints (spec-defined, silently
/// ignored by our evaluator as per DIF PE v2 §5).
/// Source: test/presentation-definition/basic_example.json
const PD_BASIC_JSON: &str =
    include_str!("fixtures/dif_pex/pd_basic.json");

/// Complex banking PD — four fields with `pattern` and wildcard paths,
/// `group` annotation (spec-defined, silently ignored by our evaluator).
/// Source: test/presentation-definition/input_descriptors_example.json
const PD_INPUT_DESCRIPTORS_JSON: &str =
    include_str!("fixtures/dif_pex/pd_input_descriptors.json");

/// Multi-descriptor PS with one descriptor using 2-level `path_nested`.
/// Source: test/presentation-submission/example.json
const PS_EXAMPLE_JSON: &str =
    include_str!("fixtures/dif_pex/ps_example.json");

/// Single-descriptor PS with 3-level `path_nested`.
/// Source: test/presentation-submission/nested_submission_example.json
const PS_NESTED_JSON: &str =
    include_str!("fixtures/dif_pex/ps_nested.json");

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the `presentation_definition` object from the spec's JSON envelope
/// and deserialize it into our `PresentationDefinition` type.
fn extract_pd(envelope_json: &str) -> PresentationDefinition {
    let envelope: Value =
        serde_json::from_str(envelope_json).expect("fixture must be valid JSON");
    let pd_val = envelope
        .get("presentation_definition")
        .expect("envelope must contain 'presentation_definition'");
    serde_json::from_value(pd_val.clone())
        .expect("presentation_definition must deserialize into PresentationDefinition")
}

/// Deserialize a PS from the spec's JSON envelope (`presentation_submission` key).
fn extract_ps(envelope_json: &str) -> PresentationSubmission {
    let envelope: Value =
        serde_json::from_str(envelope_json).expect("fixture must be valid JSON");
    let ps_val = envelope
        .get("presentation_submission")
        .expect("envelope must contain 'presentation_submission'");
    serde_json::from_value(ps_val.clone())
        .expect("presentation_submission must deserialize into PresentationSubmission")
}

/// Build a single-descriptor PS that points `$` at the root of the VP payload.
/// Used to drive `verify_presentation` with a flat credential payload.
fn single_descriptor_ps(definition_id: &str, descriptor_id: &str, format: &str) -> PresentationSubmission {
    PresentationSubmission {
        id: "ps-test".to_string(),
        definition_id: definition_id.to_string(),
        descriptor_map: vec![DescriptorMapEntry {
            id: descriptor_id.to_string(),
            format: format.to_string(),
            path: "$".to_string(),
            path_nested: None,
        }],
    }
}

fn make_engine() -> VerificationEngine {
    VerificationEngine::new(
        "https://verifier.example.com",
        "https://verifier.example.com/callback",
    )
}

// ── §K  Official PD Fixture Parsing ──────────────────────────────────────────
//
// Rust translation of the official test/presentation-definition/test.js suite.
// The JS tests validate each fixture against the JSON Schema (ajv.compile +
// validate). Here we validate by deserializing into our typed PD struct; if the
// fixture does not parse, the test fails.

/// DIF PEX test: "should validate the minimal example object using JSON Schema"
/// (minimal_example.json — single descriptor, multi-path, no filter)
#[test]
fn k1_pd_minimal_parses() {
    let pd = extract_pd(PD_MINIMAL_JSON);
    assert_eq!(pd.id, "32f54163-7166-48f1-93d8-ff217bdb0653");
    assert_eq!(pd.input_descriptors.len(), 1);
    let desc = &pd.input_descriptors[0];
    assert_eq!(desc.id, "wa_driver_license");
    assert_eq!(desc.constraints.fields.len(), 1);
    assert_eq!(desc.constraints.fields[0].path.len(), 4,
        "multi-path field must have 4 candidate JSONPaths");
}

/// DIF PEX test: "should validate the Filter By Credential Type example"
/// (pd_filter.json — array `contains` with regex pattern on `$.type`)
#[test]
fn k2_pd_filter_parses() {
    let pd = extract_pd(PD_FILTER_JSON);
    assert_eq!(pd.id, "first simple example");
    assert_eq!(pd.input_descriptors.len(), 1);
    let field = &pd.input_descriptors[0].constraints.fields[0];
    assert_eq!(field.path, vec!["$.type"]);
    let filter = field.filter.as_ref().expect("filter must be present");
    assert_eq!(filter["type"], "array");
    assert!(filter.get("contains").is_some(), "contains schema must be present");
}

/// DIF PEX test: "should validate the Two Filters (simplified) example"
/// (pd_filter2_simplified.json — 3 pattern string filters)
#[test]
fn k3_pd_filter2_simplified_parses() {
    let pd = extract_pd(PD_FILTER2_SIMPLIFIED_JSON);
    assert_eq!(pd.id, "Scalable trust example");
    assert_eq!(pd.input_descriptors.len(), 1);
    let fields = &pd.input_descriptors[0].constraints.fields;
    assert_eq!(fields.len(), 3, "three field constraints");
    // All three have pattern filters
    for field in fields {
        let filter = field.filter.as_ref().expect("filter present");
        assert!(filter.get("pattern").is_some(), "pattern must be in filter: {:?}", filter);
    }
}

/// DIF PEX test: "should validate the basic example object using JSON Schema"
/// (basic_example.json — 2 descriptors, `limit_disclosure`, `const`, `pattern`,
///  plus `intent_to_retain` and descriptor-level `purpose` which must be ignored)
#[test]
fn k4_pd_basic_parses() {
    let pd = extract_pd(PD_BASIC_JSON);
    assert_eq!(pd.id, "32f54163-7166-48f1-93d8-ff217bdb0653");
    assert_eq!(pd.input_descriptors.len(), 2);

    let bank = &pd.input_descriptors[0];
    assert_eq!(bank.id, "bankaccount_input");
    assert_eq!(
        bank.constraints.limit_disclosure.as_deref(),
        Some("required"),
        "bankaccount_input must have limit_disclosure:required"
    );
    assert_eq!(bank.constraints.fields.len(), 2);

    let passport = &pd.input_descriptors[1];
    assert_eq!(passport.id, "us_passport_input");
    assert!(passport.constraints.limit_disclosure.is_none());
    assert_eq!(passport.constraints.fields.len(), 2);

    // const filter on first field of bankaccount descriptor
    let schema_id_filter = bank.constraints.fields[0]
        .filter
        .as_ref()
        .expect("filter must be present");
    assert_eq!(
        schema_id_filter["const"],
        "https://bank-standards.example.com/fullaccountroute.json"
    );

    // pattern filter on issuer field (uses alternation `|`)
    let issuer_filter = bank.constraints.fields[1]
        .filter
        .as_ref()
        .expect("filter must be present");
    assert_eq!(
        issuer_filter["pattern"],
        "^did:example:123$|^did:example:456$"
    );
}

/// DIF PEX test: "should validate the input descriptors example object using JSON Schema"
/// (input_descriptors_example.json — 4 fields, `group` annotation ignored,
///  wildcard paths `[*]`, complex banking regex patterns)
#[test]
fn k5_pd_input_descriptors_parses() {
    let pd = extract_pd(PD_INPUT_DESCRIPTORS_JSON);
    assert_eq!(pd.id, "32f54163-7166-48f1-93d8-ff217bdb0653");
    assert_eq!(pd.input_descriptors.len(), 1);
    let desc = &pd.input_descriptors[0];
    assert_eq!(desc.id, "banking_input_1");
    assert_eq!(desc.constraints.fields.len(), 4,
        "banking descriptor must have 4 field constraints");

    // Verify wildcard paths are preserved verbatim (we store them as strings)
    let account_id_field = &desc.constraints.fields[2];
    assert!(
        account_id_field.path.iter().any(|p| p.contains("[*]")),
        "wildcard path must be preserved: {:?}",
        account_id_field.path
    );
}

// ── §L  Official PS Fixture Parsing ──────────────────────────────────────────
//
// Rust translation of test/presentation-submission/test.js.

/// DIF PEX test: "should validate the example object"
/// (example.json — 4 descriptor entries, one with a 2-level path_nested)
#[test]
fn l1_ps_example_parses() {
    let ps = extract_ps(PS_EXAMPLE_JSON);
    assert_eq!(ps.id, "a30e3b91-fb77-4d22-95fa-871689c322e2");
    assert_eq!(ps.definition_id, "32f54163-7166-48f1-93d8-ff217bdb0653");
    assert_eq!(ps.descriptor_map.len(), 4);

    // The 4th entry has a 2-level path_nested
    let nested_entry = &ps.descriptor_map[3];
    assert_eq!(nested_entry.format, "jwt_vp");
    let level1 = nested_entry
        .path_nested
        .as_ref()
        .expect("path_nested level 1 must be present");
    assert_eq!(level1.format, "ldp_vc");
    let level2 = level1
        .path_nested
        .as_ref()
        .expect("path_nested level 2 must be present");
    assert_eq!(level2.format, "jwt_vc");
    assert!(level2.path_nested.is_none(), "no level 3 in ps_example");
}

/// DIF PEX test: "should validate the nested submission example object"
/// (nested_submission_example.json — 1 descriptor with a 3-level path_nested)
#[test]
fn l2_ps_nested_parses() {
    let ps = extract_ps(PS_NESTED_JSON);
    assert_eq!(ps.id, "a30e3b91-fb77-4d22-95fa-871689c322e2");
    assert_eq!(ps.descriptor_map.len(), 1);

    let top = &ps.descriptor_map[0];
    assert_eq!(top.format, "jwt_vp");
    assert_eq!(top.path, "$.outerClaim[0]");

    let l1 = top.path_nested.as_ref().expect("level 1 nested");
    assert_eq!(l1.format, "ldp_vc");
    assert_eq!(l1.path, "$.innerClaim[1]");

    let l2 = l1.path_nested.as_ref().expect("level 2 nested");
    assert_eq!(l2.format, "jwt_vc");
    assert_eq!(l2.path, "$.mostInnerClaim[2]");
    assert!(l2.path_nested.is_none(), "level 3 terminates here");
}

// ── §M  Evaluator Conformance ─────────────────────────────────────────────────
//
// Tests that our `verify_presentation()` evaluates the field constraint patterns
// from the official DIF PEX spec examples correctly.
//
// Each test uses an official PD fixture (§K) combined with a purpose-built PS
// and credential document, verifying that our evaluator conforms to DIF PE v2 §5.

// ─── §M.1  minimal_example.json — multi-path field presence ──────────────────

/// DIF PE v2 §5.1: when a field path array is provided, the evaluator MUST try
/// each path in order and succeed if any path resolves to a value.
/// Verifies the `$.credentialSubject.dob` alternate path from minimal_example.
#[test]
fn m1a_pd_minimal_dob_path_satisfies_field() {
    let pd = extract_pd(PD_MINIMAL_JSON);
    let ps = single_descriptor_ps(&pd.id, "wa_driver_license", "jwt_vc");
    let engine = make_engine();

    // Use `dob` (second path candidate) — first path `dateOfBirth` is absent
    let credential = json!({
        "credentialSubject": { "dob": "1987-01-02" }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&credential));
    assert!(
        result.valid,
        "$.credentialSubject.dob via multi-path resolution MUST satisfy the field: {:?}",
        result.errors
    );
}

/// DIF PE v2 §5.1: the primary path `$.credentialSubject.dateOfBirth` must also work.
#[test]
fn m1b_pd_minimal_dateofbirth_path_satisfies_field() {
    let pd = extract_pd(PD_MINIMAL_JSON);
    let ps = single_descriptor_ps(&pd.id, "wa_driver_license", "jwt_vc");
    let engine = make_engine();

    let credential = json!({
        "credentialSubject": { "dateOfBirth": "1987-01-02" }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&credential));
    assert!(
        result.valid,
        "$.credentialSubject.dateOfBirth MUST satisfy the first path candidate: {:?}",
        result.errors
    );
}

/// DIF PE v2 §5.1: when NONE of the multi-path candidates is present in the
/// credential, the field constraint MUST fail.
#[test]
fn m1c_pd_minimal_absent_field_fails() {
    let pd = extract_pd(PD_MINIMAL_JSON);
    let ps = single_descriptor_ps(&pd.id, "wa_driver_license", "jwt_vc");
    let engine = make_engine();

    // Neither `dateOfBirth` nor `dob` present
    let credential = json!({
        "credentialSubject": { "given_name": "Alice" }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&credential));
    assert!(
        !result.valid,
        "absent field (none of the 4 candidate paths found) MUST fail"
    );
}

// ─── §M.2  pd_filter.json — array `contains` with regex pattern ──────────────

/// DIF PE v2 §5.1: `filter.type: "array" + contains.pattern` MUST pass when the
/// `$.type` array has an element that matches the pattern exactly.
///
/// The spec's pattern text `^<the type of VC e.g. degree certificate>$` is a
/// literal ECMA 262 pattern: the string `<the type of VC e.g. degree certificate>`
/// matches it exactly (the `^`/`$` are anchors, `<...>` and spaces are literals).
#[test]
fn m2a_pd_filter_matching_type_passes() {
    let pd = extract_pd(PD_FILTER_JSON);
    let ps = single_descriptor_ps(&pd.id, "A specific type of VC", "jwt_vc");
    let engine = make_engine();

    let credential = json!({
        "type": [
            "VerifiableCredential",
            "<the type of VC e.g. degree certificate>"
        ]
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&credential));
    assert!(
        result.valid,
        "type array containing the exact pattern-matched string MUST pass: {:?}",
        result.errors
    );
}

/// DIF PE v2 §5.1: when no element of `$.type` matches the pattern, the
/// `contains` filter MUST fail.
#[test]
fn m2b_pd_filter_non_matching_type_fails() {
    let pd = extract_pd(PD_FILTER_JSON);
    let ps = single_descriptor_ps(&pd.id, "A specific type of VC", "jwt_vc");
    let engine = make_engine();

    let credential = json!({
        "type": ["VerifiableCredential", "UniversityDegreeCredential"]
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&credential));
    assert!(
        !result.valid,
        "'UniversityDegreeCredential' does not match the literal spec pattern so MUST fail"
    );
}

// ─── §M.3  pd_filter2_simplified.json — three `pattern` constraints ───────────

/// DIF PE v2 §5.1: three string pattern filters all satisfied — result MUST be valid.
/// Verifies real regex anchored matching (`^...$`) rather than substring check.
#[test]
fn m3a_pd_filter2_all_patterns_satisfied_passes() {
    let pd = extract_pd(PD_FILTER2_SIMPLIFIED_JSON);
    let ps = single_descriptor_ps(&pd.id, "any type of credit card from any bank", "jwt_vc");
    let engine = make_engine();

    // All three values exactly match their anchored patterns
    let credential = json!({
        "termsOfUse": {
            "type": "https://train.trust-scheme.de/info",
            "trustScheme": "worldbankfederation.com"
        },
        "type": "creditCard"
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&credential));
    assert!(
        result.valid,
        "all three anchored patterns satisfied MUST pass: {:?}",
        result.errors
    );
}

/// DIF PE v2 §5.1: when one pattern constraint is not satisfied, the descriptor
/// and the overall result MUST be invalid.
#[test]
fn m3b_pd_filter2_one_pattern_fails() {
    let pd = extract_pd(PD_FILTER2_SIMPLIFIED_JSON);
    let ps = single_descriptor_ps(&pd.id, "any type of credit card from any bank", "jwt_vc");
    let engine = make_engine();

    // `$.type` = "debitCard" does NOT match `^creditCard$`
    let credential = json!({
        "termsOfUse": {
            "type": "https://train.trust-scheme.de/info",
            "trustScheme": "worldbankfederation.com"
        },
        "type": "debitCard"
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&credential));
    assert!(
        !result.valid,
        "$.type = 'debitCard' does not match ^creditCard$ — MUST fail"
    );
}

// ─── §M.4  basic_example.json — `limit_disclosure: required` ─────────────────

/// DIF PE v2 §5.1.1: when `limit_disclosure: "required"` is set on a descriptor,
/// the credential format MUST support selective disclosure.  A `jwt_vc` (non-SD-JWT)
/// MUST be rejected.
///
/// Uses the `bankaccount_input` descriptor from basic_example.json.
#[test]
fn m4_pd_basic_limit_disclosure_required_non_sdjwt_fails() {
    let pd = extract_pd(PD_BASIC_JSON);
    let engine = make_engine();

    // Build a PS that maps only the bankaccount_input descriptor (the one with
    // limit_disclosure: required) using a non-SD-JWT format.
    let ps = PresentationSubmission {
        id: "ps-m4".to_string(),
        definition_id: pd.id.clone(),
        descriptor_map: vec![
            DescriptorMapEntry {
                id: "bankaccount_input".to_string(),
                format: "jwt_vc".to_string(), // NOT sd_jwt — limit_disclosure must reject this
                path: "$".to_string(),
                path_nested: None,
            },
            DescriptorMapEntry {
                id: "us_passport_input".to_string(),
                format: "jwt_vc".to_string(),
                path: "$".to_string(),
                path_nested: None,
            },
        ],
    };

    let credential = json!({
        "credentialSchema": { "id": "https://bank-standards.example.com/fullaccountroute.json" },
        "issuer": "did:example:123",
        "credentialSubject": { "birth_date": "1990-01-01" }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&credential));
    assert!(
        !result.valid,
        "limit_disclosure:required with non-SD-JWT format MUST fail"
    );
    assert!(
        result.errors.iter().any(|e| {
            e.contains("limit_disclosure") || e.contains("SD-JWT")
        }),
        "error must mention limit_disclosure or SD-JWT: {:?}",
        result.errors
    );
}

// ─── §M.5  basic_example.json — `const` filter (us_passport descriptor) ──────

/// DIF PE v2 §5.1: `filter.const` must match the claim value exactly.
/// Uses the `us_passport_input` descriptor's `credentialSchema.id` const constraint.
/// Each descriptor navigates to its own sub-document in the VP payload via `path`.
#[test]
fn m5a_pd_basic_us_passport_const_satisfied_passes() {
    let pd = extract_pd(PD_BASIC_JSON);
    let engine = make_engine();

    // Route each descriptor to its own credential sub-document using JSONPath.
    let ps = PresentationSubmission {
        id: "ps-m5a".to_string(),
        definition_id: pd.id.clone(),
        descriptor_map: vec![
            DescriptorMapEntry {
                id: "bankaccount_input".to_string(),
                format: "vc+sd-jwt".to_string(), // SD-JWT satisfies limit_disclosure
                path: "$.bank".to_string(),
                path_nested: None,
            },
            DescriptorMapEntry {
                id: "us_passport_input".to_string(),
                format: "jwt_vc".to_string(),
                path: "$.passport".to_string(),
                path_nested: None,
            },
        ],
    };

    // VP payload has two sub-documents, one per descriptor
    let vp_payload = json!({
        "bank": {
            "credentialSchema": { "id": "https://bank-standards.example.com/fullaccountroute.json" },
            "issuer": "did:example:123"
        },
        "passport": {
            "credentialSchema": { "id": "hub://did:foo:123/Collections/schema.us.gov/passport.json" },
            "credentialSubject": { "birth_date": "1987-01-02" }
        }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));
    assert!(
        result.valid,
        "us_passport credentialSchema.id const + birth_date field present MUST pass: {:?}",
        result.errors
    );
}

/// DIF PE v2 §5.1: when `filter.const` does not match the credential value,
/// the descriptor MUST be invalid.
#[test]
fn m5b_pd_basic_us_passport_const_mismatch_fails() {
    let pd = extract_pd(PD_BASIC_JSON);
    let engine = make_engine();

    let ps = PresentationSubmission {
        id: "ps-m5b".to_string(),
        definition_id: pd.id.clone(),
        descriptor_map: vec![
            DescriptorMapEntry {
                id: "bankaccount_input".to_string(),
                format: "vc+sd-jwt".to_string(),
                path: "$.bank".to_string(),
                path_nested: None,
            },
            DescriptorMapEntry {
                id: "us_passport_input".to_string(),
                format: "jwt_vc".to_string(),
                path: "$.passport".to_string(),
                path_nested: None,
            },
        ],
    };

    // passport credential has a WRONG credentialSchema.id — const mismatch
    let vp_payload = json!({
        "bank": {
            "credentialSchema": { "id": "https://bank-standards.example.com/fullaccountroute.json" },
            "issuer": "did:example:123"
        },
        "passport": {
            "credentialSchema": { "id": "https://wrong-schema.example.com/other.json" },
            "credentialSubject": { "birth_date": "1987-01-02" }
        }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));
    assert!(
        !result.valid,
        "wrong credentialSchema.id (const mismatch) MUST fail"
    );
    assert!(
        result.errors.iter().any(|e| e.contains("const")),
        "error must mention 'const': {:?}",
        result.errors
    );
}

// ─── §M.6  basic_example.json — `pattern` filter (issuer regex alternation) ───

/// DIF PE v2 §5.1: `filter.pattern` with regex alternation `|` — the `issuer`
/// claim must match `^did:example:123$|^did:example:456$`.
/// Tests both passing DIDs and a non-matching DID.
/// Each descriptor navigates to its own sub-document via `path`.
#[test]
fn m6a_pd_basic_issuer_pattern_first_alternative_passes() {
    let pd = extract_pd(PD_BASIC_JSON);
    let engine = make_engine();

    let ps = PresentationSubmission {
        id: "ps-m6a".to_string(),
        definition_id: pd.id.clone(),
        descriptor_map: vec![
            DescriptorMapEntry {
                id: "bankaccount_input".to_string(),
                format: "vc+sd-jwt".to_string(),
                path: "$.bank".to_string(),
                path_nested: None,
            },
            DescriptorMapEntry {
                id: "us_passport_input".to_string(),
                format: "jwt_vc".to_string(),
                path: "$.passport".to_string(),
                path_nested: None,
            },
        ],
    };

    // bankaccount: credentialSchema.id matches const + issuer matches first alternative
    let vp_payload = json!({
        "bank": {
            "credentialSchema": { "id": "https://bank-standards.example.com/fullaccountroute.json" },
            "issuer": "did:example:123"
        },
        "passport": {
            "credentialSchema": { "id": "hub://did:foo:123/Collections/schema.us.gov/passport.json" },
            "credentialSubject": { "birth_date": "1987-01-02" }
        }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));
    assert!(
        result.valid,
        "issuer did:example:123 matches first alternative of pattern — MUST pass: {:?}",
        result.errors
    );
}

#[test]
fn m6b_pd_basic_issuer_pattern_second_alternative_passes() {
    let pd = extract_pd(PD_BASIC_JSON);
    let engine = make_engine();

    let ps = PresentationSubmission {
        id: "ps-m6b".to_string(),
        definition_id: pd.id.clone(),
        descriptor_map: vec![
            DescriptorMapEntry {
                id: "bankaccount_input".to_string(),
                format: "vc+sd-jwt".to_string(),
                path: "$.bank".to_string(),
                path_nested: None,
            },
            DescriptorMapEntry {
                id: "us_passport_input".to_string(),
                format: "jwt_vc".to_string(),
                path: "$.passport".to_string(),
                path_nested: None,
            },
        ],
    };

    let vp_payload = json!({
        "bank": {
            "credentialSchema": { "id": "https://bank-standards.example.com/fullaccountroute.json" },
            "issuer": "did:example:456"
        },
        "passport": {
            "credentialSchema": { "id": "hub://did:foo:123/Collections/schema.us.gov/passport.json" },
            "credentialSubject": { "birth_date": "1987-01-02" }
        }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));
    assert!(
        result.valid,
        "issuer did:example:456 matches second alternative — MUST pass: {:?}",
        result.errors
    );
}

#[test]
fn m6c_pd_basic_issuer_pattern_untrusted_issuer_fails() {
    let pd = extract_pd(PD_BASIC_JSON);
    let engine = make_engine();

    let ps = PresentationSubmission {
        id: "ps-m6c".to_string(),
        definition_id: pd.id.clone(),
        descriptor_map: vec![
            DescriptorMapEntry {
                id: "bankaccount_input".to_string(),
                format: "vc+sd-jwt".to_string(),
                path: "$.bank".to_string(),
                path_nested: None,
            },
            DescriptorMapEntry {
                id: "us_passport_input".to_string(),
                format: "jwt_vc".to_string(),
                path: "$.passport".to_string(),
                path_nested: None,
            },
        ],
    };

    // Issuer not in the trusted set
    let vp_payload = json!({
        "bank": {
            "credentialSchema": { "id": "https://bank-standards.example.com/fullaccountroute.json" },
            "issuer": "did:example:attacker"
        },
        "passport": {
            "credentialSchema": { "id": "hub://did:foo:123/Collections/schema.us.gov/passport.json" },
            "credentialSubject": { "birth_date": "1987-01-02" }
        }
    });

    let result = engine.verify_presentation(&pd, &ps, Some(&vp_payload));
    assert!(
        !result.valid,
        "untrusted issuer (not matching pattern alternation) MUST fail"
    );
}
