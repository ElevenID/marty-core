//! Biometric error types

use thiserror::Error;

/// Errors that can occur during biometric operations
#[derive(Error, Debug)]
pub enum BiometricError {
    /// No face was detected in the image
    #[error("Face not detected in image")]
    FaceNotDetected,

    /// Multiple faces were detected when only one was expected
    #[error("Multiple faces detected")]
    MultipleFacesDetected,

    /// Image quality is too low for verification
    #[error("Image quality too low: {0}")]
    LowQuality(String),

    /// Verification failed due to low similarity
    #[error("Verification failed: similarity {similarity:.2} below threshold {threshold:.2}")]
    VerificationFailed {
        /// Computed similarity score
        similarity: f32,
        /// Required threshold
        threshold: f32,
    },

    /// The requested provider is not available
    #[error("Provider not available: {0}")]
    ProviderUnavailable(String),

    /// An error occurred within the provider
    #[error("Provider error: {0}")]
    ProviderError(String),

    /// An error occurred during image processing
    #[error("Image processing error: {0}")]
    ImageProcessing(String),

    /// Template extraction failed
    #[error("Template extraction failed: {0}")]
    TemplateExtraction(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Liveness challenge validation failed
    #[error("Liveness validation failed: {0}")]
    LivenessValidation(String),

    /// Challenge expired
    #[error("Challenge expired")]
    ChallengeExpired,

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Model loading or inference error
    #[error("Model error: {0}")]
    ModelError(String),

    /// Feature not supported by this provider
    #[error("Not supported: {0}")]
    NotSupported(String),
}

impl serde::Serialize for BiometricError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_face_not_detected() {
        let err = BiometricError::FaceNotDetected;
        assert_eq!(err.to_string(), "Face not detected in image");
    }

    #[test]
    fn test_multiple_faces_detected() {
        let err = BiometricError::MultipleFacesDetected;
        assert_eq!(err.to_string(), "Multiple faces detected");
    }

    #[test]
    fn test_low_quality_message() {
        let err = BiometricError::LowQuality("blurry image".into());
        assert_eq!(err.to_string(), "Image quality too low: blurry image");
    }

    #[test]
    fn test_verification_failed_with_scores() {
        let err = BiometricError::VerificationFailed {
            similarity: 0.45,
            threshold: 0.70,
        };
        let msg = err.to_string();
        assert!(msg.contains("0.45"));
        assert!(msg.contains("0.70"));
    }

    #[test]
    fn test_provider_unavailable() {
        let err = BiometricError::ProviderUnavailable("OpenCV".into());
        assert_eq!(err.to_string(), "Provider not available: OpenCV");
    }

    #[test]
    fn test_challenge_expired() {
        let err = BiometricError::ChallengeExpired;
        assert_eq!(err.to_string(), "Challenge expired");
    }

    #[test]
    fn test_invalid_signature() {
        let err = BiometricError::InvalidSignature;
        assert_eq!(err.to_string(), "Invalid signature");
    }

    #[test]
    fn test_liveness_validation() {
        let err = BiometricError::LivenessValidation("session timeout".into());
        assert_eq!(
            err.to_string(),
            "Liveness validation failed: session timeout"
        );
    }

    #[test]
    fn test_error_serialization() {
        let err = BiometricError::FaceNotDetected;
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(json, "\"Face not detected in image\"");
    }

    #[test]
    fn test_error_debug() {
        let err = BiometricError::Configuration("bad config".into());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Configuration"));
    }
}

#[cfg(feature = "python")]
impl From<BiometricError> for pyo3::PyErr {
    fn from(err: BiometricError) -> pyo3::PyErr {
        pyo3::exceptions::PyRuntimeError::new_err(err.to_string())
    }
}

#[cfg(feature = "wasm")]
impl From<BiometricError> for wasm_bindgen::JsValue {
    fn from(err: BiometricError) -> wasm_bindgen::JsValue {
        wasm_bindgen::JsValue::from_str(&err.to_string())
    }
}
