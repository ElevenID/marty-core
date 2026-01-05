//! Biometric provider implementations

use std::time::Instant;

use crate::error::BiometricError;
use crate::traits::FaceVerifier;
use crate::types::*;

/// Biometric provider enum for runtime selection
pub enum BiometricProvider {
    /// Local provider (OpenCV-based, placeholder)
    Local(LocalProvider),
    /// Mock provider for testing
    Mock(MockProvider),
    // Future: SITA, NEC, Idemia integrations
}

impl BiometricProvider {
    /// Create local provider
    pub fn local() -> Result<Self, BiometricError> {
        Ok(Self::Local(LocalProvider::new()?))
    }

    /// Create mock provider for testing
    pub fn mock() -> Self {
        Self::Mock(MockProvider::new())
    }
}

// Implement FaceVerifier directly on BiometricProvider
impl FaceVerifier for BiometricProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        match self {
            BiometricProvider::Local(p) => p.capabilities(),
            BiometricProvider::Mock(p) => p.capabilities(),
        }
    }

    async fn verify(
        &self,
        request: FaceVerificationRequest,
    ) -> Result<FaceVerificationResult, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.verify(request).await,
            BiometricProvider::Mock(p) => p.verify(request).await,
        }
    }

    async fn assess_quality(&self, image: &str) -> Result<FaceQualityAssessment, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.assess_quality(image).await,
            BiometricProvider::Mock(p) => p.assess_quality(image).await,
        }
    }

    async fn extract_template(&self, image: &str) -> Result<FaceTemplate, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.extract_template(image).await,
            BiometricProvider::Mock(p) => p.extract_template(image).await,
        }
    }

    async fn compare_templates(
        &self,
        reference: &FaceTemplate,
        probe: &FaceTemplate,
    ) -> Result<f32, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.compare_templates(reference, probe).await,
            BiometricProvider::Mock(p) => p.compare_templates(reference, probe).await,
        }
    }
}

/// Local face verification provider
///
/// This is a placeholder that will be implemented with OpenCV/dlib
/// for offline facial verification capability.
pub struct LocalProvider {
    threshold: f32,
}

impl LocalProvider {
    /// Create a new local provider with default threshold
    pub fn new() -> Result<Self, BiometricError> {
        Ok(Self { threshold: 0.7 })
    }

    /// Create a new local provider with custom threshold
    pub fn with_threshold(threshold: f32) -> Result<Self, BiometricError> {
        Ok(Self { threshold })
    }
}

impl FaceVerifier for LocalProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            name: "marty-local".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            supports_verification: true,
            supports_quality: true,
            supports_templates: true,
            supports_liveness: false,
            offline_capable: true,
        }
    }

    async fn verify(
        &self,
        request: FaceVerificationRequest,
    ) -> Result<FaceVerificationResult, BiometricError> {
        let start = Instant::now();
        let threshold = request.threshold.unwrap_or(self.threshold);

        // TODO: Implement actual face verification using OpenCV/dlib
        // For now, return a placeholder result
        #[cfg(feature = "tracing")]
        tracing::warn!("Local face verification not implemented - returning mock result");

        // Placeholder: check if images are non-empty
        if request.reference_image.is_empty() || request.probe_image.is_empty() {
            return Err(BiometricError::FaceNotDetected);
        }

        let similarity = 0.85; // Placeholder

        Ok(FaceVerificationResult {
            verified: similarity >= threshold,
            similarity,
            threshold,
            reference_quality: Some(0.9),
            probe_quality: Some(0.85),
            processing_time_ms: start.elapsed().as_millis() as u64,
            provider: "marty-local".to_string(),
            liveness: None,
        })
    }

    async fn assess_quality(&self, _image: &str) -> Result<FaceQualityAssessment, BiometricError> {
        // TODO: Implement quality assessment
        Ok(FaceQualityAssessment {
            overall_score: 0.85,
            face_detected: true,
            face_count: 1,
            face_bounds: Some(FaceBounds {
                x: 0.2,
                y: 0.1,
                width: 0.6,
                height: 0.8,
            }),
            factors: FaceQualityFactors {
                sharpness: 0.9,
                brightness: 0.5,
                contrast: 0.8,
                face_size: 0.7,
                pose: 0.95,
            },
        })
    }

    async fn extract_template(&self, _image: &str) -> Result<FaceTemplate, BiometricError> {
        // TODO: Implement template extraction
        Err(BiometricError::TemplateExtraction(
            "Not implemented".to_string(),
        ))
    }

    async fn compare_templates(
        &self,
        _reference: &FaceTemplate,
        _probe: &FaceTemplate,
    ) -> Result<f32, BiometricError> {
        // TODO: Implement template comparison
        Err(BiometricError::TemplateExtraction(
            "Not implemented".to_string(),
        ))
    }
}

/// Mock provider for testing
pub struct MockProvider {
    default_similarity: f32,
}

impl MockProvider {
    /// Create a new mock provider with default similarity of 0.95
    pub fn new() -> Self {
        Self {
            default_similarity: 0.95,
        }
    }

    /// Create a mock provider with custom similarity score
    pub fn with_similarity(similarity: f32) -> Self {
        Self {
            default_similarity: similarity,
        }
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FaceVerifier for MockProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            name: "mock".to_string(),
            version: "1.0.0".to_string(),
            supports_verification: true,
            supports_quality: true,
            supports_templates: false,
            supports_liveness: false,
            offline_capable: true,
        }
    }

    async fn verify(
        &self,
        request: FaceVerificationRequest,
    ) -> Result<FaceVerificationResult, BiometricError> {
        let threshold = request.threshold.unwrap_or(0.7);

        Ok(FaceVerificationResult {
            verified: self.default_similarity >= threshold,
            similarity: self.default_similarity,
            threshold,
            reference_quality: Some(0.95),
            probe_quality: Some(0.9),
            processing_time_ms: 50,
            provider: "mock".to_string(),
            liveness: None,
        })
    }

    async fn assess_quality(&self, _image: &str) -> Result<FaceQualityAssessment, BiometricError> {
        Ok(FaceQualityAssessment {
            overall_score: 0.95,
            face_detected: true,
            face_count: 1,
            face_bounds: Some(FaceBounds {
                x: 0.25,
                y: 0.15,
                width: 0.5,
                height: 0.7,
            }),
            factors: FaceQualityFactors {
                sharpness: 0.95,
                brightness: 0.5,
                contrast: 0.85,
                face_size: 0.65,
                pose: 0.98,
            },
        })
    }

    async fn extract_template(&self, _image: &str) -> Result<FaceTemplate, BiometricError> {
        Err(BiometricError::ProviderError(
            "Mock provider does not support templates".to_string(),
        ))
    }

    async fn compare_templates(
        &self,
        _reference: &FaceTemplate,
        _probe: &FaceTemplate,
    ) -> Result<f32, BiometricError> {
        Err(BiometricError::ProviderError(
            "Mock provider does not support templates".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_provider_new() {
        let provider = MockProvider::new();
        assert_eq!(provider.default_similarity, 0.95);
    }

    #[test]
    fn test_mock_provider_default() {
        let provider = MockProvider::default();
        assert_eq!(provider.default_similarity, 0.95);
    }

    #[test]
    fn test_mock_provider_capabilities() {
        let provider = MockProvider::new();
        let caps = provider.capabilities();

        assert_eq!(caps.name, "mock");
        assert_eq!(caps.version, "1.0.0");
        assert!(caps.supports_verification);
        assert!(caps.supports_quality);
        assert!(!caps.supports_templates);
        assert!(!caps.supports_liveness);
        assert!(caps.offline_capable);
    }

    #[tokio::test]
    async fn test_mock_provider_verify() {
        let provider = MockProvider::new();
        let request = FaceVerificationRequest {
            reference_image: "base64_ref".to_string(),
            probe_image: "base64_probe".to_string(),
            threshold: Some(0.7),
            ..Default::default()
        };

        let result = provider.verify(request).await.unwrap();

        assert!(result.verified);
        assert_eq!(result.similarity, 0.95);
        assert_eq!(result.threshold, 0.7);
        assert_eq!(result.provider, "mock");
    }

    #[tokio::test]
    async fn test_mock_provider_verify_below_threshold() {
        let provider = MockProvider::new();
        let request = FaceVerificationRequest {
            reference_image: "base64_ref".to_string(),
            probe_image: "base64_probe".to_string(),
            threshold: Some(0.99), // Above the 0.95 similarity
            ..Default::default()
        };

        let result = provider.verify(request).await.unwrap();

        assert!(!result.verified);
    }

    #[tokio::test]
    async fn test_mock_provider_quality() {
        let provider = MockProvider::new();
        let result = provider.assess_quality("base64_image").await.unwrap();

        assert_eq!(result.overall_score, 0.95);
        assert!(result.face_detected);
        assert_eq!(result.face_count, 1);
        assert!(result.face_bounds.is_some());
    }

    #[tokio::test]
    async fn test_mock_provider_template_not_supported() {
        let provider = MockProvider::new();
        let result = provider.extract_template("base64_image").await;

        assert!(result.is_err());
        match result {
            Err(BiometricError::ProviderError(msg)) => {
                assert!(msg.contains("does not support templates"));
            }
            _ => panic!("Expected ProviderError"),
        }
    }

    #[test]
    fn test_biometric_provider_mock() {
        let provider = BiometricProvider::mock();
        let caps = provider.capabilities();

        assert_eq!(caps.name, "mock");
    }

    #[test]
    fn test_local_provider_new() {
        let provider = LocalProvider::new().unwrap();
        assert_eq!(provider.threshold, 0.7);
    }

    #[test]
    fn test_local_provider_capabilities() {
        let provider = LocalProvider::new().unwrap();
        let caps = provider.capabilities();

        assert_eq!(caps.name, "marty-local");
        assert!(caps.supports_verification);
        assert!(caps.offline_capable);
    }
}
