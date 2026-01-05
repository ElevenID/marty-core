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
