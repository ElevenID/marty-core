#[path = "../src/benchmark_support/mdoc_payload.rs"]
mod payload;
#[path = "../benches/support/remote_signature.rs"]
mod remote_signature;
#[path = "../src/benchmark_support/selectors.rs"]
mod selectors;
#[path = "../benches/support/signed_preparation.rs"]
mod signed_preparation;

#[test]
fn benchmark_remote_signature_matches_the_public_fixture_key() {
    use base64::Engine as _;
    use p256::ecdsa::signature::Verifier as _;

    let jwk: serde_json::Value = serde_json::from_str(remote_signature::issuer_public_jwk())
        .expect("fixture public JWK must be JSON");
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwk["x"].as_str().unwrap())
        .unwrap();
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwk["y"].as_str().unwrap())
        .unwrap();
    let mut point = Vec::with_capacity(65);
    point.push(4);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
        .expect("fixture public JWK must contain a valid P-256 point");

    let message = b"benchmark remote-signature fixture";
    let signature = p256::ecdsa::Signature::from_slice(&remote_signature::sign_es256(message))
        .expect("benchmark signature must use raw ES256 encoding");
    key.verify(message, &signature)
        .expect("benchmark signature must verify with its public fixture JWK");
}

#[test]
fn benchmark_mdoc_assembly_helper_signs_the_exact_prepared_payload() {
    use marty_oid4vci::{
        remote_credential::{prepare_remote_mdoc, RemoteMdocRequest},
        types::SignedCredential,
    };

    let request = RemoteMdocRequest {
        issuer_id: "did:example:benchmark-issuer".into(),
        verification_method_id: "did:example:benchmark-issuer#key-1".into(),
        algorithm: "ES256".into(),
        issuer_public_jwk: remote_signature::issuer_public_jwk().into(),
        credential_type: "org.iso.18013.5.1.mDL".into(),
        namespace: "org.iso.18013.5.1".into(),
        claims: [("family_name".into(), serde_json::json!("Benchmark"))].into(),
        expiration_seconds: Some(86_400),
        credential_id: Some("urn:uuid:961d492d-ffb7-59f9-b2cf-66a84c47d07c".into()),
        holder_jwk: None,
    };
    let prepared = prepare_remote_mdoc(request).expect("benchmark mdoc fixture must prepare");
    let credential = remote_signature::assemble_es256_mdoc(prepared)
        .expect("benchmark helper must produce a signature accepted by assembly");
    assert!(matches!(credential, SignedCredential::MsoMdoc { .. }));
}

#[test]
fn mdoc_benchmark_preflights_use_only_the_tested_assembly_helper() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (relative, expected_calls) in [
        ("benches/mdoc_issuance.rs", 2),
        ("benches/mdoc_allocation_evidence.rs", 1),
        ("benches/mdoc_tail_evidence.rs", 1),
    ] {
        let source = std::fs::read_to_string(manifest.join(relative))
            .unwrap_or_else(|error| panic!("could not read {relative}: {error}"));
        assert_eq!(
            source
                .matches("remote_signature::assemble_es256_mdoc(prepared)")
                .count(),
            expected_calls,
            "{relative} must retain every expected functional assembly preflight"
        );
        assert!(
            !source.contains("assemble_mdoc"),
            "{relative} must not bypass the tested benchmark assembly helper"
        );
    }
}

#[test]
fn mixed_format_assembly_stage_pairs_each_prepared_payload_with_its_signature() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/es256_signing_batch.rs"),
    )
    .expect("mixed-format benchmark source must be readable");
    let trait_contract = r#"impl PreparedAssembly for BenchmarkPrepared {
    type Output = SignedCredential;

    fn signing_payload(&self) -> &[u8] {
        BenchmarkPrepared::signing_payload(self)
    }

    fn assemble(self, signature: &[u8]) -> Self::Output {
        BenchmarkPrepared::assemble(self, signature)
    }
}"#;
    assert_eq!(
        source.matches(trait_contract).count(),
        1,
        "the mixed-format prepared value must forward the exact payload and paired signature"
    );
    assert_eq!(
        source
            .matches("SignedPreparation::try_sign(prepared, |payload|")
            .count(),
        1,
        "assembly setup must sign each prepared value"
    );
    assert_eq!(
        source.matches("signer.sign(payload)").count(),
        1,
        "assembly setup must sign the payload supplied by the opaque wrapper"
    );
    assert_eq!(
        source.matches(".map(SignedPreparation::assemble)").count(),
        1,
        "the measured assembly stage must consume each opaque signed preparation"
    );
}

#[test]
fn payload_profiles_keep_labels_sizes_and_independent_cbor_expectations() {
    use payload::*;
    for (ordinal, class) in PayloadClass::ALL.into_iter().enumerate() {
        assert_eq!(class.code(), ordinal as u64 + 1);
        assert_eq!(PayloadClass::parse(class.label()), Some(class));
        for index in [0, 1, 2, 3, 4, 25, 26, 127, 511] {
            let json = json_value(class, index);
            let expected = expected_cbor_value(class, index);
            // Compare semantic values: serde_json's arbitrary_precision feature
            // uses a private number representation when serialized into CBOR.
            let actual = serde_json::to_value(expected).unwrap();
            assert_eq!(actual, json, "{} at {index}", class.label());
        }
    }
    assert_eq!(PayloadClass::parse("unknown"), None);
    assert_eq!(
        json_value(PayloadClass::LargePortrait, 0)
            .as_str()
            .unwrap()
            .len(),
        256 * 1024
    );
    assert_eq!(
        json_value(PayloadClass::MixedSize, 0)
            .as_str()
            .unwrap()
            .len(),
        64 * 1024
    );
    assert_eq!(
        json_value(PayloadClass::MixedSize, 4)
            .as_str()
            .unwrap()
            .len(),
        1024
    );
    assert_eq!(
        json_value(PayloadClass::SmallPrimitive, 3),
        serde_json::Value::Null
    );
    assert_eq!(repeated_ascii(3, 26), "AAA");
}
