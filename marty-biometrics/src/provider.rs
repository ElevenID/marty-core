//! Biometric provider implementations

use crate::error::BiometricError;
use crate::traits::FaceVerifier;
use crate::types::*;

/// Biometric provider enum for runtime selection
pub enum BiometricProvider {
    /// Local provider (OpenCV-based, placeholder)
    Local(LocalProvider),
    /// Mock provider for testing
    Mock(MockProvider),
    /// ONNX Runtime provider (SCRFD + ArcFace + age + liveness + deepfake)
    #[cfg(feature = "onnx")]
    Onnx(crate::onnx::OnnxProvider),
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

    /// Create ONNX provider with models from the given directory
    #[cfg(feature = "onnx")]
    pub fn onnx(models_dir: impl AsRef<std::path::Path>) -> Result<Self, BiometricError> {
        Ok(Self::Onnx(crate::onnx::OnnxProvider::new(models_dir)?))
    }
}

// Implement FaceVerifier directly on BiometricProvider
impl FaceVerifier for BiometricProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        match self {
            BiometricProvider::Local(p) => p.capabilities(),
            BiometricProvider::Mock(p) => p.capabilities(),
            #[cfg(feature = "onnx")]
            BiometricProvider::Onnx(p) => p.capabilities(),
        }
    }

    fn extended_capabilities(&self) -> ExtendedCapabilities {
        match self {
            BiometricProvider::Local(p) => p.extended_capabilities(),
            BiometricProvider::Mock(p) => p.extended_capabilities(),
            #[cfg(feature = "onnx")]
            BiometricProvider::Onnx(p) => p.extended_capabilities(),
        }
    }

    async fn verify(
        &self,
        request: FaceVerificationRequest,
    ) -> Result<FaceVerificationResult, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.verify(request).await,
            BiometricProvider::Mock(p) => p.verify(request).await,
            #[cfg(feature = "onnx")]
            BiometricProvider::Onnx(p) => p.verify(request).await,
        }
    }

    async fn assess_quality(&self, image: &str) -> Result<FaceQualityAssessment, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.assess_quality(image).await,
            BiometricProvider::Mock(p) => p.assess_quality(image).await,
            #[cfg(feature = "onnx")]
            BiometricProvider::Onnx(p) => p.assess_quality(image).await,
        }
    }

    async fn extract_template(&self, image: &str) -> Result<FaceTemplate, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.extract_template(image).await,
            BiometricProvider::Mock(p) => p.extract_template(image).await,
            #[cfg(feature = "onnx")]
            BiometricProvider::Onnx(p) => p.extract_template(image).await,
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
            #[cfg(feature = "onnx")]
            BiometricProvider::Onnx(p) => p.compare_templates(reference, probe).await,
        }
    }

    async fn estimate_age(&self, image: &str) -> Result<AgeEstimate, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.estimate_age(image).await,
            BiometricProvider::Mock(p) => p.estimate_age(image).await,
            #[cfg(feature = "onnx")]
            BiometricProvider::Onnx(p) => p.estimate_age(image).await,
        }
    }

    async fn detect_passive_liveness(
        &self,
        frames: &[String],
    ) -> Result<PassiveLivenessResult, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.detect_passive_liveness(frames).await,
            BiometricProvider::Mock(p) => p.detect_passive_liveness(frames).await,
            #[cfg(feature = "onnx")]
            BiometricProvider::Onnx(p) => p.detect_passive_liveness(frames).await,
        }
    }

    async fn detect_deepfake(&self, image: &str) -> Result<DeepfakeAnalysis, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.detect_deepfake(image).await,
            BiometricProvider::Mock(p) => p.detect_deepfake(image).await,
            #[cfg(feature = "onnx")]
            BiometricProvider::Onnx(p) => p.detect_deepfake(image).await,
        }
    }

    async fn search(
        &self,
        probe: &FaceTemplate,
        gallery: &[FaceTemplate],
        top_k: usize,
    ) -> Result<Vec<SearchMatch>, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.search(probe, gallery, top_k).await,
            BiometricProvider::Mock(p) => p.search(probe, gallery, top_k).await,
            #[cfg(feature = "onnx")]
            BiometricProvider::Onnx(p) => p.search(probe, gallery, top_k).await,
        }
    }

    async fn match_face_to_document(
        &self,
        selfie: &str,
        document_photo: &str,
    ) -> Result<FaceVerificationResult, BiometricError> {
        match self {
            BiometricProvider::Local(p) => p.match_face_to_document(selfie, document_photo).await,
            BiometricProvider::Mock(p) => p.match_face_to_document(selfie, document_photo).await,
            #[cfg(feature = "onnx")]
            BiometricProvider::Onnx(p) => p.match_face_to_document(selfie, document_photo).await,
        }
    }
}

/// Local face verification provider
///
/// When built with the `onnx` feature, delegates to [`OnnxProvider`] for real
/// on-device inference using SCRFD + ArcFace models.  Without `onnx`, all
/// methods return [`BiometricError::NotSupported`].
pub struct LocalProvider {
    #[cfg_attr(not(feature = "onnx"), allow(dead_code))]
    threshold: f32,
    #[cfg(feature = "onnx")]
    onnx: crate::onnx::OnnxProvider,
}

impl LocalProvider {
    /// Create a new local provider with default threshold.
    ///
    /// When the `onnx` feature is enabled, `models_dir` points to the
    /// directory containing ONNX model files.  Without `onnx`, the path
    /// is ignored.
    #[cfg(feature = "onnx")]
    pub fn new() -> Result<Self, BiometricError> {
        // Default models path – caller can use with_models_dir for custom path
        Err(BiometricError::ProviderError(
            "LocalProvider requires a models directory when using ONNX backend. \
             Use LocalProvider::with_models_dir(path) instead."
                .to_string(),
        ))
    }

    /// Create a new local provider without ONNX (stub).
    #[cfg(not(feature = "onnx"))]
    pub fn new() -> Result<Self, BiometricError> {
        Ok(Self { threshold: 0.7 })
    }

    /// Create a local provider pointing at a directory of ONNX models.
    #[cfg(feature = "onnx")]
    pub fn with_models_dir(
        models_dir: impl AsRef<std::path::Path>,
    ) -> Result<Self, BiometricError> {
        let onnx = crate::onnx::OnnxProvider::new(models_dir)?;
        Ok(Self {
            threshold: 0.7,
            onnx,
        })
    }

    /// Create a new local provider with custom threshold (non-ONNX stub).
    #[cfg(not(feature = "onnx"))]
    pub fn with_threshold(threshold: f32) -> Result<Self, BiometricError> {
        Ok(Self { threshold })
    }

    /// Create a new local provider with custom threshold + ONNX models dir.
    #[cfg(feature = "onnx")]
    pub fn with_threshold_and_models(
        threshold: f32,
        models_dir: impl AsRef<std::path::Path>,
    ) -> Result<Self, BiometricError> {
        let onnx = crate::onnx::OnnxProvider::new(models_dir)?;
        Ok(Self { threshold, onnx })
    }
}

// ── ONNX-backed LocalProvider ──────────────────────────────────────────
#[cfg(feature = "onnx")]
impl FaceVerifier for LocalProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        let mut caps = self.onnx.capabilities();
        caps.name = "marty-local".to_string();
        caps
    }

    fn extended_capabilities(&self) -> ExtendedCapabilities {
        self.onnx.extended_capabilities()
    }

    async fn verify(
        &self,
        mut request: FaceVerificationRequest,
    ) -> Result<FaceVerificationResult, BiometricError> {
        if request.threshold.is_none() {
            request.threshold = Some(self.threshold);
        }
        let mut result = self.onnx.verify(request).await?;
        result.provider = "marty-local".to_string();
        Ok(result)
    }

    async fn assess_quality(&self, image: &str) -> Result<FaceQualityAssessment, BiometricError> {
        self.onnx.assess_quality(image).await
    }

    async fn extract_template(&self, image: &str) -> Result<FaceTemplate, BiometricError> {
        self.onnx.extract_template(image).await
    }

    async fn compare_templates(
        &self,
        reference: &FaceTemplate,
        probe: &FaceTemplate,
    ) -> Result<f32, BiometricError> {
        self.onnx.compare_templates(reference, probe).await
    }

    async fn estimate_age(&self, image: &str) -> Result<AgeEstimate, BiometricError> {
        self.onnx.estimate_age(image).await
    }

    async fn detect_passive_liveness(
        &self,
        frames: &[String],
    ) -> Result<PassiveLivenessResult, BiometricError> {
        self.onnx.detect_passive_liveness(frames).await
    }

    async fn detect_deepfake(&self, image: &str) -> Result<DeepfakeAnalysis, BiometricError> {
        self.onnx.detect_deepfake(image).await
    }

    async fn search(
        &self,
        probe: &FaceTemplate,
        gallery: &[FaceTemplate],
        top_k: usize,
    ) -> Result<Vec<SearchMatch>, BiometricError> {
        self.onnx.search(probe, gallery, top_k).await
    }

    async fn match_face_to_document(
        &self,
        selfie: &str,
        document_photo: &str,
    ) -> Result<FaceVerificationResult, BiometricError> {
        let mut result = self
            .onnx
            .match_face_to_document(selfie, document_photo)
            .await?;
        result.provider = "marty-local".to_string();
        Ok(result)
    }
}

// ── Non-ONNX stub LocalProvider ────────────────────────────────────────
#[cfg(not(feature = "onnx"))]
impl FaceVerifier for LocalProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            name: "marty-local".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            supports_verification: false,
            supports_quality: false,
            supports_templates: false,
            supports_liveness: false,
            offline_capable: true,
        }
    }

    async fn verify(
        &self,
        _request: FaceVerificationRequest,
    ) -> Result<FaceVerificationResult, BiometricError> {
        Err(BiometricError::NotSupported(
            "Local verification requires the 'onnx' feature".to_string(),
        ))
    }

    async fn assess_quality(&self, _image: &str) -> Result<FaceQualityAssessment, BiometricError> {
        Err(BiometricError::NotSupported(
            "Local quality assessment requires the 'onnx' feature".to_string(),
        ))
    }

    async fn extract_template(&self, _image: &str) -> Result<FaceTemplate, BiometricError> {
        Err(BiometricError::NotSupported(
            "Local template extraction requires the 'onnx' feature".to_string(),
        ))
    }

    async fn compare_templates(
        &self,
        _reference: &FaceTemplate,
        _probe: &FaceTemplate,
    ) -> Result<f32, BiometricError> {
        Err(BiometricError::NotSupported(
            "Local template comparison requires the 'onnx' feature".to_string(),
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

    // Without the `onnx` feature LocalProvider is a stub that returns
    // NotSupported for all operations.
    #[cfg(not(feature = "onnx"))]
    mod local_stub_tests {
        use super::*;

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
            assert!(!caps.supports_verification);
            assert!(caps.offline_capable);
        }

        #[tokio::test]
        async fn test_local_provider_verify_not_supported() {
            let provider = LocalProvider::new().unwrap();
            let result = provider.verify(FaceVerificationRequest::default()).await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_local_provider_quality_not_supported() {
            let provider = LocalProvider::new().unwrap();
            let result = provider.assess_quality("img").await;
            assert!(result.is_err());
        }
    }

    // With `onnx` feature, LocalProvider::new() requires a models dir,
    // so it should return an error.
    #[cfg(feature = "onnx")]
    mod local_onnx_tests {
        use super::*;

        #[test]
        fn test_local_provider_new_requires_models_dir() {
            let result = LocalProvider::new();
            assert!(result.is_err());
        }
    }
}
