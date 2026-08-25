#![cfg(feature = "native")]

use marty_biometrics::{
    BiometricProvider, FaceQualityAssessment, FaceVerificationRequest, FaceVerifier,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Contract {
    schema: String,
    canonical_implementation: String,
    transport: Transport,
    mock_provider: MockProvider,
    verification_cases: Vec<VerificationCase>,
    quality: Quality,
    malformed_requests: Vec<MalformedRequest>,
}

#[derive(Debug, Deserialize)]
struct Transport {
    legacy_fastapi_status: String,
    supported_surfaces: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MockProvider {
    name: String,
    similarity: f32,
    reference_quality: f32,
    probe_quality: f32,
    default_threshold: f32,
}

#[derive(Debug, Deserialize)]
struct VerificationCase {
    name: String,
    threshold: f32,
    verified: bool,
}

#[derive(Debug, Deserialize)]
struct Quality {
    overall_score: f32,
    face_detected: bool,
    face_count: u32,
    sharpness: f32,
    brightness: f32,
    contrast: f32,
    face_size: f32,
    pose: f32,
}

#[derive(Debug, Deserialize)]
struct MalformedRequest {
    name: String,
    payload: Value,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!("../contracts/verification-behavior.json"))
        .expect("biometric behavior contract must be valid")
}

fn assert_close(actual: f32, expected: f32) {
    assert!((actual - expected).abs() < f32::EPSILON);
}

#[tokio::test]
async fn rust_mock_provider_satisfies_verification_contract() {
    let contract = contract();
    assert_eq!(contract.schema, "marty.biometric-verification-behavior/v1");
    assert_eq!(
        contract.canonical_implementation,
        "ElevenID/marty-core/marty-biometrics"
    );
    assert_eq!(
        contract.transport.legacy_fastapi_status,
        "retired-unpublished-adapter"
    );
    assert_eq!(
        contract.transport.supported_surfaces,
        ["rust-crate", "python-binding", "wasm-binding"]
    );

    let provider = BiometricProvider::mock();
    let capabilities = provider.capabilities();
    assert_eq!(capabilities.name, contract.mock_provider.name);
    assert!(capabilities.supports_verification);
    assert!(capabilities.supports_quality);

    for case in contract.verification_cases {
        let result = provider
            .verify(FaceVerificationRequest {
                reference_image: "base64-reference".to_string(),
                probe_image: "base64-probe".to_string(),
                threshold: Some(case.threshold),
                ..Default::default()
            })
            .await
            .unwrap_or_else(|error| panic!("{} failed: {error}", case.name));

        assert_eq!(result.verified, case.verified, "{}", case.name);
        assert_close(result.similarity, contract.mock_provider.similarity);
        assert_close(result.threshold, case.threshold);
        assert_close(
            result.reference_quality.expect("reference quality"),
            contract.mock_provider.reference_quality,
        );
        assert_close(
            result.probe_quality.expect("probe quality"),
            contract.mock_provider.probe_quality,
        );
        assert_eq!(result.provider, contract.mock_provider.name);
    }

    let defaulted = provider
        .verify(FaceVerificationRequest {
            reference_image: "base64-reference".to_string(),
            probe_image: "base64-probe".to_string(),
            ..Default::default()
        })
        .await
        .expect("default-threshold verification");
    assert_close(
        defaulted.threshold,
        contract.mock_provider.default_threshold,
    );
}

#[tokio::test]
async fn rust_mock_provider_satisfies_quality_contract() {
    let contract = contract();
    let result: FaceQualityAssessment = BiometricProvider::mock()
        .assess_quality("base64-image")
        .await
        .expect("quality assessment");

    assert_close(result.overall_score, contract.quality.overall_score);
    assert_eq!(result.face_detected, contract.quality.face_detected);
    assert_eq!(result.face_count, contract.quality.face_count);
    assert_close(result.factors.sharpness, contract.quality.sharpness);
    assert_close(result.factors.brightness, contract.quality.brightness);
    assert_close(result.factors.contrast, contract.quality.contrast);
    assert_close(result.factors.face_size, contract.quality.face_size);
    assert_close(result.factors.pose, contract.quality.pose);
}

#[test]
fn malformed_requests_fail_closed() {
    for case in contract().malformed_requests {
        let result = serde_json::from_value::<FaceVerificationRequest>(case.payload);
        assert!(result.is_err(), "{} unexpectedly decoded", case.name);
    }
}
