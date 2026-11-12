use marty_verification::open_badges::{
    verify_ob3_async, verify_ob3_json_async, verify_ob3_with_status_lists_async, VerifyOb3Request,
};
use serde_json::{json, Value};

const OB3: &str = include_str!("fixtures/open_badges/ob3_verify_request.json");

#[test]
fn typed_ob3_preserves_signed_fixture_and_missing_authority_failure() {
    futures::executor::block_on(async {
        for valid in [true, false] {
            let mut request: Value = serde_json::from_str(OB3).unwrap();
            if !valid {
                request["document_store"] = json!({});
            }
            let typed = verify_ob3_async(serde_json::from_value(request.clone()).unwrap())
                .await
                .unwrap();
            assert_eq!(typed.valid, valid, "{:?}", typed.errors);
            assert_eq!(typed.version, "3.0");
            if !valid {
                assert!(!typed.errors.is_empty());
            }
            let explicit = verify_ob3_with_status_lists_async(
                serde_json::from_value(request.clone()).unwrap(),
                &[],
            )
            .await
            .unwrap();
            let wire: Value =
                serde_json::from_str(&verify_ob3_json_async(&request.to_string()).await.unwrap())
                    .unwrap();
            assert_eq!(serde_json::to_value(typed).unwrap(), wire);
            assert_eq!(serde_json::to_value(explicit).unwrap(), wire);
        }
    });
}

#[test]
fn request_decoding_and_json_error_context_are_preserved() {
    assert!(serde_json::from_value::<VerifyOb3Request>(json!({})).is_err());
    let error = futures::executor::block_on(verify_ob3_json_async("{}")).unwrap_err();
    assert!(error.to_string().contains("Invalid OB3 verify request:"));
    let error = futures::executor::block_on(verify_ob3_async(VerifyOb3Request {
        credential: json!({}),
        document_store: None,
    }))
    .unwrap_err();
    assert!(error.to_string().contains("Invalid OB3 credential:"));
}

#[test]
fn typed_ob3_rejects_legacy_input_before_proof_processing() {
    let legacy: Value =
        serde_json::from_str(include_str!("fixtures/open_badges/ob2_verify_request.json")).unwrap();
    let error = futures::executor::block_on(verify_ob3_async(VerifyOb3Request {
        credential: legacy["assertion"].clone(),
        document_store: None,
    }))
    .unwrap_err();
    assert!(
        error.to_string().contains("Open Badges 2 is retired"),
        "{error}"
    );
}

#[test]
fn ob3_jws2020_binds_exact_protected_header_through_rdf_verification() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signature, VerifyingKey};
    use marty_verification::error::codes::OPEN_BADGES_PROOF_INVALID;
    use marty_verification::open_badges::verify_ob3_json_at_async;

    futures::executor::block_on(async {
        // Preserve the complete signed public fixture from UI #1895. Both
        // signatures below were computed externally over the same proof and
        // credential RDF digests; this test has no signing key or signer API.
        let fixture: Value = serde_json::from_str(include_str!(
            "fixtures/open_badges/ob3_jws2020_header_binding.json"
        ))
        .unwrap();
        let canonical_digests = hex::decode(concat!(
            "fb7782c709a22ba395265a00107930e7bf72a291426e1aae99f78a0428eed744",
            "473e423da673544b947b56d6f9f285d996918cb958d69904ce38409713426fe4"
        ))
        .unwrap();
        let original_jws = fixture["credential"]["proof"]["jws"].as_str().unwrap();
        let reordered_jws = "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..-K17BVHgM4lz8_UtEvSN4ZBvzkM5XNYkSDjh6yfbTJfsdOMykH8GLsQ8IClk8BJVBQ1m_IN--oGfB2krhKu3Cg";
        let (original_header, original_signature) = original_jws.split_once("..").unwrap();
        let (reordered_header, reordered_signature) = reordered_jws.split_once("..").unwrap();
        let header_value = |header: &str| {
            serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap()
        };
        assert_eq!(
            header_value(original_header),
            header_value(reordered_header)
        );
        assert_ne!(original_header, reordered_header);
        let public_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(
                fixture["governed_method"]["public_jwk"]["x"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        let verifier = VerifyingKey::from_bytes(&public_key).unwrap();
        let evaluation_time = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let cases = [
            ("original", original_header, original_signature, true),
            ("reordered", reordered_header, reordered_signature, true),
            (
                "crossed_reordered",
                reordered_header,
                original_signature,
                false,
            ),
            (
                "crossed_original",
                original_header,
                reordered_signature,
                false,
            ),
        ];
        let mut native_results = json!({});
        for (name, header, signature, expected) in cases {
            let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
                .decode(signature)
                .unwrap()
                .try_into()
                .unwrap();
            let mut signed_bytes = header.as_bytes().to_vec();
            signed_bytes.push(b'.');
            signed_bytes.extend_from_slice(&canonical_digests);
            assert_eq!(
                verifier
                    .verify_strict(&signed_bytes, &Signature::from_bytes(&signature_bytes))
                    .is_ok(),
                expected,
                "independent public JWS2020 case {name}"
            );
            let mut credential = fixture["credential"].clone();
            credential["proof"]["jws"] = json!(format!("{header}..{signature}"));
            // The production API recomputes JSON-LD/RDF preparation from the
            // complete credential and proof. It never receives the digests
            // used solely by the independent signature check above.
            let request = json!({
                "credential": credential,
                "document_store": fixture["document_store"]
            });
            native_results[name] = serde_json::from_str::<Value>(
                &verify_ob3_json_at_async(&request.to_string(), evaluation_time)
                    .await
                    .unwrap(),
            )
            .unwrap();
        }
        // Collect all four native outcomes before enforcing either positive;
        // accepting the reordered vector cannot replace original-byte support.
        for (name, _, _, expected) in cases {
            let result = &native_results[name];
            assert_eq!(result["valid"], expected, "{name}: {native_results}");
            assert_eq!(result["version"], "3.0");
            if expected {
                assert_eq!(result["errors"], json!([]), "{name}: {native_results}");
                assert!(
                    result.get("error_codes").is_none(),
                    "{name}: {native_results}"
                );
            } else {
                assert_eq!(
                    result["error_codes"],
                    json!([OPEN_BADGES_PROOF_INVALID]),
                    "{name}: {native_results}"
                );
            }
        }
        // Also require the RDF credential bytes to remain bound to the proof.
        let mut credential = fixture["credential"].clone();
        credential["credentialSubject"]["achievement"]["criteria"]["narrative"] =
            json!("A different completion criterion");
        let tampered = json!({
            "credential": credential,
            "document_store": fixture["document_store"]
        });
        let result: Value = serde_json::from_str(
            &verify_ob3_json_at_async(&tampered.to_string(), evaluation_time)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(result["valid"], false);
        assert_eq!(result["error_codes"], json!([OPEN_BADGES_PROOF_INVALID]));
    });
}
