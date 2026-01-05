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
}
