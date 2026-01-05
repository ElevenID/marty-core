//! WebAssembly bindings for marty-biometrics
//!
//! This module exposes biometric types and synchronous operations to WASM.
//! Async operations are not directly supported; use wasm-bindgen-futures
//! for promise-based APIs.
//!
//! # Building
//!
//! ```bash
//! wasm-pack build --target web --features wasm --no-default-features
//! ```

use wasm_bindgen::prelude::*;

use crate::types::*;

/// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Get the library version
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Create a face verification request from JSON
///
/// # Arguments
/// * `reference_image` - Base64 encoded reference image
/// * `probe_image` - Base64 encoded probe image
/// * `threshold` - Optional similarity threshold (0.0 - 1.0)
///
/// # Returns
/// JSON string of the request
#[wasm_bindgen]
pub fn create_verification_request(
    reference_image: &str,
    probe_image: &str,
    threshold: Option<f32>,
) -> Result<String, JsValue> {
    let request = FaceVerificationRequest {
        reference_image: reference_image.to_string(),
        probe_image: probe_image.to_string(),
        threshold,
        ..Default::default()
    };

    serde_json::to_string(&request).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Parse a face verification result from JSON
///
/// # Arguments
/// * `json` - JSON string of the result
///
/// # Returns
/// Object with verified, similarity, threshold properties
#[wasm_bindgen]
pub fn parse_verification_result(json: &str) -> Result<JsValue, JsValue> {
    let result: FaceVerificationResult =
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Convert to JS object
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"verified".into(), &result.verified.into())?;
    js_sys::Reflect::set(&obj, &"similarity".into(), &result.similarity.into())?;
    js_sys::Reflect::set(&obj, &"threshold".into(), &result.threshold.into())?;
    js_sys::Reflect::set(
        &obj,
        &"processing_time_ms".into(),
        &(result.processing_time_ms as f64).into(),
    )?;
    js_sys::Reflect::set(&obj, &"provider".into(), &result.provider.into())?;

    Ok(obj.into())
}

/// Create a face quality assessment from scores
///
/// # Arguments
/// * `overall_score` - Overall quality (0.0 - 1.0)
/// * `face_detected` - Whether a face was detected
/// * `face_count` - Number of faces detected
///
/// # Returns
/// JSON string of the assessment
#[wasm_bindgen]
pub fn create_quality_assessment(
    overall_score: f32,
    face_detected: bool,
    face_count: u32,
) -> Result<String, JsValue> {
    let assessment = FaceQualityAssessment {
        overall_score,
        face_detected,
        face_count,
        face_bounds: None,
        factors: FaceQualityFactors {
            sharpness: 0.0,
            brightness: 0.5,
            contrast: 0.0,
            face_size: 0.0,
            pose: 0.0,
        },
    };

    serde_json::to_string(&assessment).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create a liveness challenge
///
/// # Arguments
/// * `challenge_id` - Unique challenge identifier
/// * `nonce` - Random nonce for replay protection
/// * `session_id` - Session identifier
///
/// # Returns
/// JSON string of the challenge
#[wasm_bindgen]
pub fn create_liveness_challenge(
    challenge_id: &str,
    nonce: &str,
    session_id: &str,
) -> Result<String, JsValue> {
    let challenge = LivenessChallenge {
        challenge_id: challenge_id.to_string(),
        nonce: nonce.to_string(),
        session_id: session_id.to_string(),
        steps: vec![],
        issued_at: String::new(),
        expires_at: String::new(),
        signature: String::new(),
        preferred_mode: None,
        allow_network_fallback: false,
        accessibility_mode: false,
    };

    serde_json::to_string(&challenge).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Add a head pose step to a liveness challenge
///
/// # Arguments
/// * `challenge_json` - JSON string of the challenge
/// * `step_id` - Unique step identifier
/// * `direction` - Pose direction (left, right, up, down)
/// * `prompt` - User-facing prompt
/// * `time_limit_ms` - Time limit for step
///
/// # Returns
/// Updated JSON string of the challenge
#[wasm_bindgen]
pub fn add_head_pose_step(
    challenge_json: &str,
    step_id: &str,
    direction: &str,
    prompt: &str,
    time_limit_ms: u32,
) -> Result<String, JsValue> {
    let mut challenge: LivenessChallenge =
        serde_json::from_str(challenge_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    challenge.steps.push(LivenessStep {
        step_id: step_id.to_string(),
        step_type: LivenessStepType::HeadPose,
        prompt: Some(prompt.to_string()),
        pose_direction: Some(direction.to_string()),
        time_limit_ms: Some(time_limit_ms),
    });

    serde_json::to_string(&challenge).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Log a message to the browser console
#[wasm_bindgen]
pub fn log(message: &str) {
    web_sys::console::log_1(&message.into());
}
