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
}

impl serde::Serialize for BiometricError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
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
