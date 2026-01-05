//! Liveness challenge validation
//!
//! This module provides utilities for creating, signing, and validating
//! liveness challenges to ensure the biometric sample is from a live person.

use crate::error::BiometricError;
use crate::types::{LivenessChallenge, LivenessMode, LivenessStep, LivenessStepType};
use serde::{Deserialize, Serialize};

/// Configuration for liveness challenge generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessChallengeConfig {
    /// Number of steps to include in challenge
    pub step_count: usize,
    /// Challenge validity duration in seconds
    pub validity_seconds: u64,
    /// Allow accessibility mode (simplified challenges)
    pub allow_accessibility: bool,
    /// Preferred execution mode
    pub preferred_mode: LivenessMode,
    /// Allow fallback to network mode
    pub allow_network_fallback: bool,
}

impl Default for LivenessChallengeConfig {
    fn default() -> Self {
        Self {
            step_count: 3,
            validity_seconds: 60,
            allow_accessibility: true,
            preferred_mode: LivenessMode::OnDevice,
            allow_network_fallback: true,
        }
    }
}

/// Builder for creating liveness challenges
#[derive(Debug, Clone)]
pub struct LivenessChallengeBuilder {
    challenge_id: String,
    session_id: String,
    steps: Vec<LivenessStep>,
    config: LivenessChallengeConfig,
}

impl LivenessChallengeBuilder {
    /// Create a new challenge builder
    pub fn new(challenge_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            challenge_id: challenge_id.into(),
            session_id: session_id.into(),
            steps: Vec::new(),
            config: LivenessChallengeConfig::default(),
        }
    }

    /// Set the configuration
    pub fn with_config(mut self, config: LivenessChallengeConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a head pose step
    pub fn add_head_pose(
        mut self,
        step_id: impl Into<String>,
        direction: impl Into<String>,
        prompt: impl Into<String>,
        time_limit_ms: u32,
    ) -> Self {
        self.steps.push(LivenessStep {
            step_id: step_id.into(),
            step_type: LivenessStepType::HeadPose,
            prompt: Some(prompt.into()),
            pose_direction: Some(direction.into()),
            time_limit_ms: Some(time_limit_ms),
        });
        self
    }

    /// Add a blink step
    pub fn add_blink(
        mut self,
        step_id: impl Into<String>,
        prompt: impl Into<String>,
        time_limit_ms: u32,
    ) -> Self {
        self.steps.push(LivenessStep {
            step_id: step_id.into(),
            step_type: LivenessStepType::Blink,
            prompt: Some(prompt.into()),
            pose_direction: None,
            time_limit_ms: Some(time_limit_ms),
        });
        self
    }

    /// Add a phrase step
    pub fn add_phrase(
        mut self,
        step_id: impl Into<String>,
        phrase: impl Into<String>,
        time_limit_ms: u32,
    ) -> Self {
        self.steps.push(LivenessStep {
            step_id: step_id.into(),
            step_type: LivenessStepType::Phrase,
            prompt: Some(phrase.into()),
            pose_direction: None,
            time_limit_ms: Some(time_limit_ms),
        });
        self
    }

    /// Build the challenge (unsigned)
    ///
    /// The caller must sign the challenge using `sign_challenge` before use.
    pub fn build(self, nonce: impl Into<String>) -> LivenessChallenge {
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::seconds(self.config.validity_seconds as i64);

        LivenessChallenge {
            challenge_id: self.challenge_id,
            nonce: nonce.into(),
            session_id: self.session_id,
            steps: self.steps,
            issued_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            signature: String::new(), // Must be signed by caller
            preferred_mode: Some(self.config.preferred_mode),
            allow_network_fallback: self.config.allow_network_fallback,
            accessibility_mode: self.config.allow_accessibility,
        }
    }
}

/// Validate a liveness challenge
///
/// Checks:
/// - Challenge has not expired
/// - Signature is present (actual verification is caller's responsibility)
/// - Steps are well-formed
pub fn validate_challenge(challenge: &LivenessChallenge) -> Result<(), BiometricError> {
    // Check expiration
    let expires_at = chrono::DateTime::parse_from_rfc3339(&challenge.expires_at)
        .map_err(|e| BiometricError::LivenessValidation(format!("Invalid expires_at: {}", e)))?;

    if chrono::Utc::now() > expires_at {
        return Err(BiometricError::ChallengeExpired);
    }

    // Check signature is present
    if challenge.signature.is_empty() {
        return Err(BiometricError::InvalidSignature);
    }

    // Check steps are well-formed
    for step in &challenge.steps {
        if step.step_id.is_empty() {
            return Err(BiometricError::LivenessValidation(
                "Step missing step_id".to_string(),
            ));
        }

        match step.step_type {
            LivenessStepType::HeadPose => {
                if step.pose_direction.is_none() {
                    return Err(BiometricError::LivenessValidation(
                        "HeadPose step missing pose_direction".to_string(),
                    ));
                }
            }
            LivenessStepType::Phrase => {
                if step.prompt.is_none() {
                    return Err(BiometricError::LivenessValidation(
                        "Phrase step missing prompt".to_string(),
                    ));
                }
            }
            _ => {}
        }
    }

    Ok(())
}

/// Compute the canonical bytes of a challenge for signing
///
/// This creates a deterministic byte representation of the challenge
/// that can be signed or verified.
pub fn challenge_canonical_bytes(challenge: &LivenessChallenge) -> Vec<u8> {
    // Create a canonical representation without the signature
    let canonical = serde_json::json!({
        "challenge_id": challenge.challenge_id,
        "nonce": challenge.nonce,
        "session_id": challenge.session_id,
        "steps": challenge.steps,
        "issued_at": challenge.issued_at,
        "expires_at": challenge.expires_at,
        "preferred_mode": challenge.preferred_mode,
        "allow_network_fallback": challenge.allow_network_fallback,
        "accessibility_mode": challenge.accessibility_mode,
    });

    serde_json::to_vec(&canonical).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_builder() {
        let challenge = LivenessChallengeBuilder::new("challenge-123", "session-456")
            .add_head_pose("step-1", "left", "Turn your head left", 3000)
            .add_blink("step-2", "Blink twice", 2000)
            .add_phrase("step-3", "Say: Hello World", 5000)
            .build("random-nonce");

        assert_eq!(challenge.challenge_id, "challenge-123");
        assert_eq!(challenge.session_id, "session-456");
        assert_eq!(challenge.nonce, "random-nonce");
        assert_eq!(challenge.steps.len(), 3);
        assert!(challenge.signature.is_empty()); // Unsigned
    }

    #[test]
    fn test_validate_expired_challenge() {
        let mut challenge = LivenessChallengeBuilder::new("id", "session").build("nonce");
        challenge.expires_at = "2020-01-01T00:00:00Z".to_string();
        challenge.signature = "fake-sig".to_string();

        let result = validate_challenge(&challenge);
        assert!(matches!(result, Err(BiometricError::ChallengeExpired)));
    }

    #[test]
    fn test_validate_unsigned_challenge() {
        let challenge = LivenessChallengeBuilder::new("id", "session").build("nonce");

        let result = validate_challenge(&challenge);
        assert!(matches!(result, Err(BiometricError::InvalidSignature)));
    }

    #[test]
    fn test_canonical_bytes() {
        let challenge = LivenessChallengeBuilder::new("id", "session")
            .add_blink("step-1", "Blink", 2000)
            .build("nonce");

        let bytes1 = challenge_canonical_bytes(&challenge);
        let bytes2 = challenge_canonical_bytes(&challenge);

        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }
}
