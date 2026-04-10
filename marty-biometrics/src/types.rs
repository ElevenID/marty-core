//! Biometric types

use serde::{Deserialize, Serialize};

/// Face verification request
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FaceVerificationRequest {
    /// Reference image (from credential, base64 encoded)
    pub reference_image: String,
    /// Probe image (live capture, base64 encoded)
    pub probe_image: String,
    /// Minimum similarity threshold (0.0 - 1.0)
    pub threshold: Option<f32>,
    /// Optional liveness challenge metadata (nonce, steps, signature)
    #[serde(default)]
    pub liveness_challenge: Option<LivenessChallenge>,
    /// Preferred liveness mode (on-device vs network)
    #[serde(default)]
    pub preferred_liveness_mode: Option<LivenessMode>,
    /// Allow fallback to alternate mode if preferred mode unavailable
    #[serde(default)]
    pub allow_network_fallback: bool,
    /// Enable accessibility adjustments (e.g., pose-only challenges)
    #[serde(default)]
    pub accessibility_mode: bool,
    /// Request retention of a short audit clip
    #[serde(default)]
    pub retain_audit_clip: bool,
    /// Optional TTL for audit clip retention (seconds)
    #[serde(default)]
    pub audit_clip_ttl_seconds: Option<u32>,
}

/// Face verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceVerificationResult {
    /// Verification passed
    pub verified: bool,
    /// Similarity score (0.0 - 1.0)
    pub similarity: f32,
    /// Threshold used
    pub threshold: f32,
    /// Reference face quality score (0.0 - 1.0)
    pub reference_quality: Option<f32>,
    /// Probe face quality score (0.0 - 1.0)
    pub probe_quality: Option<f32>,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
    /// Provider used
    pub provider: String,
    /// Liveness decision and component scores (if evaluated)
    pub liveness: Option<LivenessResult>,
}

/// Face quality assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceQualityAssessment {
    /// Overall quality score (0.0 - 1.0)
    pub overall_score: f32,
    /// Face detected
    pub face_detected: bool,
    /// Number of faces detected
    pub face_count: u32,
    /// Face position (normalized bounding box)
    pub face_bounds: Option<FaceBounds>,
    /// Individual quality factors
    pub factors: FaceQualityFactors,
}

/// Face bounding box (normalized 0.0 - 1.0)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceBounds {
    /// X coordinate of top-left corner
    pub x: f32,
    /// Y coordinate of top-left corner
    pub y: f32,
    /// Width of bounding box
    pub width: f32,
    /// Height of bounding box
    pub height: f32,
}

/// Face quality factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceQualityFactors {
    /// Sharpness/blur (0.0 - 1.0)
    pub sharpness: f32,
    /// Brightness (0.0 - 1.0, 0.5 = ideal)
    pub brightness: f32,
    /// Contrast (0.0 - 1.0)
    pub contrast: f32,
    /// Face size relative to image (0.0 - 1.0)
    pub face_size: f32,
    /// Head pose quality (0.0 - 1.0, 1.0 = frontal)
    pub pose: f32,
}

/// Face template (for offline matching)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceTemplate {
    /// Template data (provider-specific, base64 encoded)
    pub data: String,
    /// Template version/format
    pub version: String,
    /// Provider that created the template
    pub provider: String,
    /// Quality score of the source image
    pub quality_score: f32,
}

/// Biometric provider capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    /// Provider name
    pub name: String,
    /// Provider version
    pub version: String,
    /// Supports 1:1 verification
    pub supports_verification: bool,
    /// Supports quality assessment
    pub supports_quality: bool,
    /// Supports template extraction
    pub supports_templates: bool,
    /// Supports liveness detection
    pub supports_liveness: bool,
    /// Works offline
    pub offline_capable: bool,
}

/// Supported liveness execution modes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum LivenessMode {
    /// Unknown mode
    #[default]
    Unknown,
    /// On-device liveness detection
    OnDevice,
    /// Network-based liveness detection
    Network,
}

/// Component scores for liveness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessScores {
    /// Presentation attack detection score
    pub pad_score: f32,
    /// Head pose verification score
    pub pose_score: f32,
    /// Speech verification score (for voice challenges)
    pub speech_score: f32,
    /// Voice spoof detection score
    pub voice_spoof_score: f32,
    /// Audio-visual synchronization score
    pub av_sync_score: f32,
}

/// Thresholds applied to each component and fused decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessThresholds {
    /// Minimum PAD score
    pub min_pad_score: f32,
    /// Minimum pose score
    pub min_pose_score: f32,
    /// Minimum speech score
    pub min_speech_score: f32,
    /// Minimum voice spoof score
    pub min_voice_spoof_score: f32,
    /// Minimum AV sync score
    pub min_av_sync_score: f32,
    /// Fused decision threshold
    pub fused_threshold: f32,
}

/// Result from a liveness evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessResult {
    /// Whether liveness check passed
    pub passed: bool,
    /// Fused score from all components
    pub fused_score: f32,
    /// Individual component scores
    pub scores: Option<LivenessScores>,
    /// Thresholds used for decision
    pub thresholds: Option<LivenessThresholds>,
    /// Mode used for evaluation
    pub mode_used: Option<LivenessMode>,
    /// Any errors encountered
    pub errors: Vec<String>,
    /// Decision rationale
    pub decision: Option<String>,
    /// TTL for audit clip if retained
    pub audit_clip_ttl_seconds: Option<u32>,
}

/// Types of liveness challenge steps
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum LivenessStepType {
    /// Unknown step type
    #[default]
    Unknown,
    /// Head pose challenge (turn head)
    HeadPose,
    /// Blink detection
    Blink,
    /// Phrase speaking challenge
    Phrase,
}

/// Individual liveness step definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessStep {
    /// Unique step identifier
    pub step_id: String,
    /// Type of challenge
    pub step_type: LivenessStepType,
    /// User-facing prompt
    pub prompt: Option<String>,
    /// Direction for head pose (e.g., "left", "right", "up", "down")
    pub pose_direction: Option<String>,
    /// Time limit for completing step
    pub time_limit_ms: Option<u32>,
}

/// Signed liveness challenge metadata passed from the caller
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessChallenge {
    /// Unique challenge identifier
    pub challenge_id: String,
    /// Random nonce for replay protection
    pub nonce: String,
    /// Session identifier
    pub session_id: String,
    /// Challenge steps to complete
    pub steps: Vec<LivenessStep>,
    /// When challenge was issued (ISO 8601)
    pub issued_at: String,
    /// When challenge expires (ISO 8601)
    pub expires_at: String,
    /// Cryptographic signature over challenge data
    pub signature: String,
    /// Preferred execution mode
    pub preferred_mode: Option<LivenessMode>,
    /// Allow fallback to network mode
    pub allow_network_fallback: bool,
    /// Enable accessibility adjustments
    pub accessibility_mode: bool,
}

// ========================================================================
// Age estimation types
// ========================================================================

/// Result of age estimation from a face image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeEstimate {
    /// Estimated age in years
    pub estimated_age: u8,
    /// Confidence of the estimate (0.0 - 1.0)
    pub confidence: f32,
    /// Predicted age range (lower, upper)
    pub age_range: (u8, u8),
}

// ========================================================================
// Face search (1:N) types
// ========================================================================

/// A single match result from a 1:N face search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchMatch {
    /// Index of the matched template in the gallery
    pub index: usize,
    /// Cosine similarity to the probe
    pub similarity: f32,
    /// Identifier of the matched template (caller-provided)
    pub template_id: String,
}

// ========================================================================
// Deepfake / presentation attack detection types
// ========================================================================

/// Classification of attack types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttackType {
    /// Printed photo held to camera
    Print,
    /// Digital screen replay
    Screen,
    /// 3D silicone or rigid mask
    Mask3D,
    /// AI-generated face (deepfake)
    Deepfake,
    /// Real-time face swap overlay
    FaceSwap,
    /// Video/image injected into the capture pipeline (virtual camera, emulator)
    Injection,
}

/// Result of deepfake / synthetic face analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepfakeAnalysis {
    /// Whether the image is classified as synthetic
    pub is_synthetic: bool,
    /// Confidence of the classification (0.0 - 1.0)
    pub confidence: f32,
    /// Detected attack type, if any
    pub attack_type: Option<AttackType>,
}

/// ISO/IEC 30107-3 Presentation Attack Detection score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PadScore {
    /// Whether an attack was detected
    pub attack_detected: bool,
    /// Classified attack type, if any
    pub attack_type: Option<AttackType>,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f32,
}

// ========================================================================
// Passive liveness types
// ========================================================================

/// Result of passive (multi-frame) liveness analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveLivenessResult {
    /// Whether the subject is determined to be live
    pub is_live: bool,
    /// Liveness confidence (0.0 - 1.0)
    pub confidence: f32,
    /// PAD score breakdown
    pub pad: Option<PadScore>,
    /// Number of frames analyzed
    pub frames_analyzed: u32,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
}

// ========================================================================
// Extended provider capabilities
// ========================================================================

/// Extended capabilities advertised by biometric providers
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtendedCapabilities {
    /// Supports age estimation
    pub supports_age_estimation: bool,
    /// Supports passive liveness detection
    pub supports_passive_liveness: bool,
    /// Supports deepfake detection
    pub supports_deepfake_detection: bool,
    /// Supports 1:N face search
    pub supports_search: bool,
    /// Supports face-to-document matching
    pub supports_document_match: bool,
    /// Supports PAD scoring (ISO 30107-3)
    pub supports_pad: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // FaceVerificationRequest
    // ====================================================================

    #[test]
    fn test_face_verification_request_default() {
        let req = FaceVerificationRequest::default();
        assert!(req.reference_image.is_empty());
        assert!(req.probe_image.is_empty());
        assert!(req.threshold.is_none());
        assert!(!req.allow_network_fallback);
        assert!(!req.accessibility_mode);
        assert!(!req.retain_audit_clip);
    }

    #[test]
    fn test_face_verification_request_serialization() {
        let req = FaceVerificationRequest {
            reference_image: "base64ref".to_string(),
            probe_image: "base64probe".to_string(),
            threshold: Some(0.75),
            ..Default::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: FaceVerificationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.reference_image, "base64ref");
        assert_eq!(back.threshold, Some(0.75));
    }

    // ====================================================================
    // FaceVerificationResult
    // ====================================================================

    #[test]
    fn test_face_verification_result_serialization() {
        let result = FaceVerificationResult {
            verified: true,
            similarity: 0.92,
            threshold: 0.70,
            reference_quality: Some(0.95),
            probe_quality: Some(0.88),
            processing_time_ms: 150,
            provider: "mock".to_string(),
            liveness: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: FaceVerificationResult = serde_json::from_str(&json).unwrap();
        assert!(back.verified);
        assert!((back.similarity - 0.92).abs() < f32::EPSILON);
        assert_eq!(back.provider, "mock");
    }

    // ====================================================================
    // FaceQualityAssessment
    // ====================================================================

    #[test]
    fn test_face_quality_assessment() {
        let assessment = FaceQualityAssessment {
            overall_score: 0.85,
            face_detected: true,
            face_count: 1,
            face_bounds: Some(FaceBounds {
                x: 0.1,
                y: 0.1,
                width: 0.5,
                height: 0.6,
            }),
            factors: FaceQualityFactors {
                sharpness: 0.9,
                brightness: 0.5,
                contrast: 0.8,
                face_size: 0.4,
                pose: 0.95,
            },
        };
        let json = serde_json::to_string(&assessment).unwrap();
        let back: FaceQualityAssessment = serde_json::from_str(&json).unwrap();
        assert!(back.face_detected);
        assert_eq!(back.face_count, 1);
        assert!((back.factors.sharpness - 0.9).abs() < f32::EPSILON);
    }

    // ====================================================================
    // ProviderCapabilities
    // ====================================================================

    #[test]
    fn test_provider_capabilities() {
        let caps = ProviderCapabilities {
            name: "MockProvider".to_string(),
            version: "1.0.0".to_string(),
            supports_verification: true,
            supports_quality: true,
            supports_templates: false,
            supports_liveness: true,
            offline_capable: true,
        };
        let json = serde_json::to_string(&caps).unwrap();
        let back: ProviderCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "MockProvider");
        assert!(back.supports_verification);
        assert!(!back.supports_templates);
        assert!(back.offline_capable);
    }

    // ====================================================================
    // LivenessMode
    // ====================================================================

    #[test]
    fn test_liveness_mode_default() {
        let mode = LivenessMode::default();
        match mode {
            LivenessMode::Unknown => {}
            _ => panic!("default should be Unknown"),
        }
    }

    #[test]
    fn test_liveness_mode_serialization() {
        let json = serde_json::to_string(&LivenessMode::OnDevice).unwrap();
        let back: LivenessMode = serde_json::from_str(&json).unwrap();
        match back {
            LivenessMode::OnDevice => {}
            _ => panic!("expected OnDevice"),
        }
    }

    // ====================================================================
    // LivenessChallenge
    // ====================================================================

    #[test]
    fn test_liveness_challenge_serialization() {
        let challenge = LivenessChallenge {
            challenge_id: "ch-1".to_string(),
            nonce: "random-nonce".to_string(),
            session_id: "sess-1".to_string(),
            steps: vec![LivenessStep {
                step_id: "step-1".to_string(),
                step_type: LivenessStepType::HeadPose,
                prompt: Some("Turn left".to_string()),
                pose_direction: Some("left".to_string()),
                time_limit_ms: Some(3000),
            }],
            issued_at: "2026-03-29T00:00:00Z".to_string(),
            expires_at: "2026-03-29T00:05:00Z".to_string(),
            signature: "sig-data".to_string(),
            preferred_mode: Some(LivenessMode::OnDevice),
            allow_network_fallback: true,
            accessibility_mode: false,
        };

        let json = serde_json::to_string(&challenge).unwrap();
        let back: LivenessChallenge = serde_json::from_str(&json).unwrap();
        assert_eq!(back.challenge_id, "ch-1");
        assert_eq!(back.steps.len(), 1);
        assert_eq!(back.steps[0].pose_direction, Some("left".to_string()));
        assert!(back.allow_network_fallback);
    }

    // ====================================================================
    // LivenessStepType
    // ====================================================================

    #[test]
    fn test_liveness_step_type_default() {
        let step = LivenessStepType::default();
        match step {
            LivenessStepType::Unknown => {}
            _ => panic!("default should be Unknown"),
        }
    }

    // ====================================================================
    // FaceTemplate
    // ====================================================================

    #[test]
    fn test_face_template_serialization() {
        let template = FaceTemplate {
            data: "base64template".to_string(),
            version: "v1".to_string(),
            provider: "mock".to_string(),
            quality_score: 0.88,
        };
        let json = serde_json::to_string(&template).unwrap();
        let back: FaceTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.data, "base64template");
        assert!((back.quality_score - 0.88).abs() < f32::EPSILON);
    }
}
