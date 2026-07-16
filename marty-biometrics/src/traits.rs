//! Face verification trait

use crate::error::BiometricError;
use crate::types::*;

/// Face verification provider trait
///
/// Implement this trait to create a new biometric provider.
/// All methods are async to support both local and network-based providers.
#[allow(async_fn_in_trait)]
pub trait FaceVerifier: Send + Sync {
    /// Get provider capabilities
    fn capabilities(&self) -> ProviderCapabilities;

    /// Verify that probe image matches reference image
    ///
    /// # Arguments
    /// * `request` - Verification request with reference and probe images
    ///
    /// # Returns
    /// * `Ok(FaceVerificationResult)` - Verification result with similarity score
    /// * `Err(BiometricError)` - If verification could not be performed
    async fn verify(
        &self,
        request: FaceVerificationRequest,
    ) -> Result<FaceVerificationResult, BiometricError>;

    /// Assess image quality for face verification
    ///
    /// # Arguments
    /// * `image` - Base64 encoded image
    ///
    /// # Returns
    /// * `Ok(FaceQualityAssessment)` - Quality assessment with scores
    /// * `Err(BiometricError)` - If assessment could not be performed
    async fn assess_quality(&self, image: &str) -> Result<FaceQualityAssessment, BiometricError>;

    /// Extract face template for offline matching
    ///
    /// # Arguments
    /// * `image` - Base64 encoded image
    ///
    /// # Returns
    /// * `Ok(FaceTemplate)` - Extracted template
    /// * `Err(BiometricError)` - If extraction failed
    async fn extract_template(&self, image: &str) -> Result<FaceTemplate, BiometricError>;

    /// Compare two templates (for offline matching)
    ///
    /// # Arguments
    /// * `reference` - Reference template
    /// * `probe` - Probe template to compare
    ///
    /// # Returns
    /// * `Ok(f32)` - Similarity score (0.0 - 1.0)
    /// * `Err(BiometricError)` - If comparison failed
    async fn compare_templates(
        &self,
        reference: &FaceTemplate,
        probe: &FaceTemplate,
    ) -> Result<f32, BiometricError>;

    // ====================================================================
    // Extended capabilities (default = NotSupported)
    // ====================================================================

    /// Get extended capabilities for optional features
    fn extended_capabilities(&self) -> ExtendedCapabilities {
        ExtendedCapabilities::default()
    }

    /// Estimate the age of the subject in the image
    ///
    /// # Arguments
    /// * `image` - Base64 encoded aligned face image
    async fn estimate_age(&self, _image: &str) -> Result<AgeEstimate, BiometricError> {
        Err(BiometricError::NotSupported("age estimation".to_string()))
    }

    /// Passive liveness detection from multiple frames
    ///
    /// Analyzes a sequence of captured frames for spoof indicators
    /// (printed photos, screens, 3D masks) without requiring active user gestures.
    ///
    /// # Arguments
    /// * `frames` - Slice of base64-encoded image frames
    async fn detect_passive_liveness(
        &self,
        _frames: &[String],
    ) -> Result<PassiveLivenessResult, BiometricError> {
        Err(BiometricError::NotSupported("passive liveness".to_string()))
    }

    /// Deepfake / synthetic face analysis
    ///
    /// # Arguments
    /// * `image` - Base64 encoded image to analyze
    async fn detect_deepfake(&self, _image: &str) -> Result<DeepfakeAnalysis, BiometricError> {
        Err(BiometricError::NotSupported(
            "deepfake detection".to_string(),
        ))
    }

    /// 1:N face search against a gallery of templates
    ///
    /// # Arguments
    /// * `probe` - Template to search for
    /// * `gallery` - Gallery of templates to search against
    /// * `top_k` - Maximum number of matches to return
    async fn search(
        &self,
        _probe: &FaceTemplate,
        _gallery: &[FaceTemplate],
        _top_k: usize,
    ) -> Result<Vec<SearchMatch>, BiometricError> {
        Err(BiometricError::NotSupported("face search".to_string()))
    }

    /// Match a selfie against a document photo (e.g., mDL portrait)
    ///
    /// This is a specialized 1:1 match that accounts for the quality
    /// differences between live captures and document photos.
    ///
    /// # Arguments
    /// * `selfie` - Base64 encoded live selfie
    /// * `document_photo` - Base64 encoded document photo
    async fn match_face_to_document(
        &self,
        selfie: &str,
        document_photo: &str,
    ) -> Result<FaceVerificationResult, BiometricError> {
        // Default: delegate to standard verify with a slightly lower threshold
        self.verify(FaceVerificationRequest {
            reference_image: document_photo.to_string(),
            probe_image: selfie.to_string(),
            threshold: Some(0.6), // Lower threshold for document photos
            ..Default::default()
        })
        .await
    }
}
