//! Python bindings for marty-biometrics
//!
//! This module exposes the biometric verification functionality to Python
//! via PyO3 bindings.
//!
//! # Building
//!
//! ```bash
//! maturin develop --features python
//! ```

use pyo3::prelude::*;

use crate::types::*;
use crate::{BiometricProvider, FaceVerifier};

// ========================================================================
// Request / Result wrappers
// ========================================================================

/// Python wrapper for FaceVerificationRequest
#[pyclass(name = "FaceVerificationRequest")]
#[derive(Clone)]
pub struct PyFaceVerificationRequest {
    inner: FaceVerificationRequest,
}

#[pymethods]
impl PyFaceVerificationRequest {
    #[new]
    #[pyo3(signature = (reference_image, probe_image, threshold=None))]
    fn new(reference_image: String, probe_image: String, threshold: Option<f32>) -> Self {
        Self {
            inner: FaceVerificationRequest {
                reference_image,
                probe_image,
                threshold,
                ..Default::default()
            },
        }
    }

    #[getter]
    fn reference_image(&self) -> &str {
        &self.inner.reference_image
    }

    #[getter]
    fn probe_image(&self) -> &str {
        &self.inner.probe_image
    }

    #[getter]
    fn threshold(&self) -> Option<f32> {
        self.inner.threshold
    }

    #[setter]
    fn set_threshold(&mut self, threshold: Option<f32>) {
        self.inner.threshold = threshold;
    }
}

/// Python wrapper for FaceVerificationResult
#[pyclass(name = "FaceVerificationResult")]
#[derive(Clone)]
pub struct PyFaceVerificationResult {
    inner: FaceVerificationResult,
}

#[pymethods]
impl PyFaceVerificationResult {
    #[getter]
    fn verified(&self) -> bool {
        self.inner.verified
    }

    #[getter]
    fn similarity(&self) -> f32 {
        self.inner.similarity
    }

    #[getter]
    fn threshold(&self) -> f32 {
        self.inner.threshold
    }

    #[getter]
    fn reference_quality(&self) -> Option<f32> {
        self.inner.reference_quality
    }

    #[getter]
    fn probe_quality(&self) -> Option<f32> {
        self.inner.probe_quality
    }

    #[getter]
    fn processing_time_ms(&self) -> u64 {
        self.inner.processing_time_ms
    }

    #[getter]
    fn provider(&self) -> &str {
        &self.inner.provider
    }

    #[getter]
    fn liveness(&self) -> Option<PyLivenessResult> {
        self.inner
            .liveness
            .as_ref()
            .map(|l| PyLivenessResult { inner: l.clone() })
    }

    fn to_dict(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
}

// ========================================================================
// Quality wrappers
// ========================================================================

/// Python wrapper for FaceBounds
#[pyclass(name = "FaceBounds")]
#[derive(Clone)]
pub struct PyFaceBounds {
    inner: FaceBounds,
}

#[pymethods]
impl PyFaceBounds {
    #[getter]
    fn x(&self) -> f32 {
        self.inner.x
    }
    #[getter]
    fn y(&self) -> f32 {
        self.inner.y
    }
    #[getter]
    fn width(&self) -> f32 {
        self.inner.width
    }
    #[getter]
    fn height(&self) -> f32 {
        self.inner.height
    }
}

/// Python wrapper for FaceQualityAssessment
#[pyclass(name = "FaceQualityAssessment")]
#[derive(Clone)]
pub struct PyFaceQualityAssessment {
    inner: FaceQualityAssessment,
}

#[pymethods]
impl PyFaceQualityAssessment {
    #[getter]
    fn overall_score(&self) -> f32 {
        self.inner.overall_score
    }

    #[getter]
    fn face_detected(&self) -> bool {
        self.inner.face_detected
    }

    #[getter]
    fn face_count(&self) -> u32 {
        self.inner.face_count
    }

    #[getter]
    fn face_bounds(&self) -> Option<PyFaceBounds> {
        self.inner
            .face_bounds
            .as_ref()
            .map(|b| PyFaceBounds { inner: b.clone() })
    }

    #[getter]
    fn sharpness(&self) -> f32 {
        self.inner.factors.sharpness
    }

    #[getter]
    fn brightness(&self) -> f32 {
        self.inner.factors.brightness
    }

    #[getter]
    fn contrast(&self) -> f32 {
        self.inner.factors.contrast
    }

    #[getter]
    fn face_size(&self) -> f32 {
        self.inner.factors.face_size
    }

    #[getter]
    fn pose(&self) -> f32 {
        self.inner.factors.pose
    }

    fn to_dict(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
}

// ========================================================================
// Capabilities wrappers
// ========================================================================

/// Python wrapper for ProviderCapabilities
#[pyclass(name = "ProviderCapabilities")]
#[derive(Clone)]
pub struct PyProviderCapabilities {
    inner: ProviderCapabilities,
}

#[pymethods]
impl PyProviderCapabilities {
    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn version(&self) -> &str {
        &self.inner.version
    }

    #[getter]
    fn supports_verification(&self) -> bool {
        self.inner.supports_verification
    }

    #[getter]
    fn supports_quality(&self) -> bool {
        self.inner.supports_quality
    }

    #[getter]
    fn supports_templates(&self) -> bool {
        self.inner.supports_templates
    }

    #[getter]
    fn supports_liveness(&self) -> bool {
        self.inner.supports_liveness
    }

    #[getter]
    fn offline_capable(&self) -> bool {
        self.inner.offline_capable
    }
}

/// Python wrapper for ExtendedCapabilities
#[pyclass(name = "ExtendedCapabilities")]
#[derive(Clone)]
pub struct PyExtendedCapabilities {
    inner: ExtendedCapabilities,
}

#[pymethods]
impl PyExtendedCapabilities {
    #[getter]
    fn supports_age_estimation(&self) -> bool {
        self.inner.supports_age_estimation
    }
    #[getter]
    fn supports_passive_liveness(&self) -> bool {
        self.inner.supports_passive_liveness
    }
    #[getter]
    fn supports_deepfake_detection(&self) -> bool {
        self.inner.supports_deepfake_detection
    }
    #[getter]
    fn supports_search(&self) -> bool {
        self.inner.supports_search
    }
    #[getter]
    fn supports_document_match(&self) -> bool {
        self.inner.supports_document_match
    }
    #[getter]
    fn supports_pad(&self) -> bool {
        self.inner.supports_pad
    }
}

// ========================================================================
// Template wrapper
// ========================================================================

/// Python wrapper for FaceTemplate
#[pyclass(name = "FaceTemplate")]
#[derive(Clone)]
pub struct PyFaceTemplate {
    inner: FaceTemplate,
}

#[pymethods]
impl PyFaceTemplate {
    #[new]
    #[pyo3(signature = (data, version, provider, quality_score=0.0))]
    fn new(data: String, version: String, provider: String, quality_score: f32) -> Self {
        Self {
            inner: FaceTemplate {
                data,
                version,
                provider,
                quality_score,
            },
        }
    }

    #[getter]
    fn data(&self) -> &str {
        &self.inner.data
    }
    #[getter]
    fn version(&self) -> &str {
        &self.inner.version
    }
    #[getter]
    fn provider(&self) -> &str {
        &self.inner.provider
    }
    #[getter]
    fn quality_score(&self) -> f32 {
        self.inner.quality_score
    }
}

// ========================================================================
// Age estimation wrapper
// ========================================================================

/// Python wrapper for AgeEstimate
#[pyclass(name = "AgeEstimate")]
#[derive(Clone)]
pub struct PyAgeEstimate {
    inner: AgeEstimate,
}

#[pymethods]
impl PyAgeEstimate {
    #[getter]
    fn estimated_age(&self) -> u8 {
        self.inner.estimated_age
    }
    #[getter]
    fn confidence(&self) -> f32 {
        self.inner.confidence
    }
    #[getter]
    fn age_range(&self) -> (u8, u8) {
        self.inner.age_range
    }
}

// ========================================================================
// Passive liveness wrapper
// ========================================================================

/// Python wrapper for PassiveLivenessResult
#[pyclass(name = "PassiveLivenessResult")]
#[derive(Clone)]
pub struct PyPassiveLivenessResult {
    inner: PassiveLivenessResult,
}

#[pymethods]
impl PyPassiveLivenessResult {
    #[getter]
    fn is_live(&self) -> bool {
        self.inner.is_live
    }
    #[getter]
    fn confidence(&self) -> f32 {
        self.inner.confidence
    }
    #[getter]
    fn frames_analyzed(&self) -> u32 {
        self.inner.frames_analyzed
    }
    #[getter]
    fn processing_time_ms(&self) -> u64 {
        self.inner.processing_time_ms
    }
}

// ========================================================================
// Deepfake analysis wrapper
// ========================================================================

/// Python wrapper for DeepfakeAnalysis
#[pyclass(name = "DeepfakeAnalysis")]
#[derive(Clone)]
pub struct PyDeepfakeAnalysis {
    inner: DeepfakeAnalysis,
}

#[pymethods]
impl PyDeepfakeAnalysis {
    #[getter]
    fn is_synthetic(&self) -> bool {
        self.inner.is_synthetic
    }
    #[getter]
    fn confidence(&self) -> f32 {
        self.inner.confidence
    }
    #[getter]
    fn attack_type(&self) -> Option<String> {
        self.inner.attack_type.as_ref().map(|a| format!("{a:?}"))
    }
}

// ========================================================================
// Search match wrapper
// ========================================================================

/// Python wrapper for SearchMatch
#[pyclass(name = "SearchMatch")]
#[derive(Clone)]
pub struct PySearchMatch {
    inner: SearchMatch,
}

#[pymethods]
impl PySearchMatch {
    #[getter]
    fn index(&self) -> usize {
        self.inner.index
    }
    #[getter]
    fn similarity(&self) -> f32 {
        self.inner.similarity
    }
    #[getter]
    fn template_id(&self) -> &str {
        &self.inner.template_id
    }
}

// ========================================================================
// Liveness result wrapper
// ========================================================================

/// Python wrapper for LivenessResult
#[pyclass(name = "LivenessResult")]
#[derive(Clone)]
pub struct PyLivenessResult {
    inner: LivenessResult,
}

#[pymethods]
impl PyLivenessResult {
    #[getter]
    fn passed(&self) -> bool {
        self.inner.passed
    }
    #[getter]
    fn fused_score(&self) -> f32 {
        self.inner.fused_score
    }
    #[getter]
    fn decision(&self) -> Option<String> {
        self.inner.decision.clone()
    }
    #[getter]
    fn errors(&self) -> Vec<String> {
        self.inner.errors.clone()
    }
}

// ========================================================================
// FaceVerifier (main entry point)
// ========================================================================

/// Python wrapper for BiometricProvider
#[pyclass(name = "FaceVerifier")]
pub struct PyFaceVerifier {
    provider: BiometricProvider,
    runtime: tokio::runtime::Runtime,
}

#[pymethods]
impl PyFaceVerifier {
    /// Create a mock provider for testing
    #[staticmethod]
    fn mock() -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self {
            provider: BiometricProvider::mock(),
            runtime,
        })
    }

    /// Create a local provider (stub without ONNX)
    #[staticmethod]
    fn local() -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let provider = BiometricProvider::local()?;
        Ok(Self { provider, runtime })
    }

    /// Create an ONNX-backed provider from a models directory
    #[staticmethod]
    #[cfg(feature = "onnx")]
    fn onnx(models_dir: &str) -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let provider = BiometricProvider::onnx(models_dir)?;
        Ok(Self { provider, runtime })
    }

    // ── Core methods ───────────────────────────────────────────────────

    /// Get provider capabilities
    fn capabilities(&self) -> PyProviderCapabilities {
        PyProviderCapabilities {
            inner: self.provider.capabilities(),
        }
    }

    /// Get extended capabilities (age, liveness, deepfake, etc.)
    fn extended_capabilities(&self) -> PyExtendedCapabilities {
        PyExtendedCapabilities {
            inner: self.provider.extended_capabilities(),
        }
    }

    /// Verify that probe image matches reference image
    fn verify(&self, request: &PyFaceVerificationRequest) -> PyResult<PyFaceVerificationResult> {
        let result = self
            .runtime
            .block_on(self.provider.verify(request.inner.clone()))?;
        Ok(PyFaceVerificationResult { inner: result })
    }

    /// Assess image quality for face verification
    fn assess_quality(&self, image: &str) -> PyResult<PyFaceQualityAssessment> {
        let result = self.runtime.block_on(self.provider.assess_quality(image))?;
        Ok(PyFaceQualityAssessment { inner: result })
    }

    // ── Template methods ───────────────────────────────────────────────

    /// Extract a face template from an image
    fn extract_template(&self, image: &str) -> PyResult<PyFaceTemplate> {
        let result = self
            .runtime
            .block_on(self.provider.extract_template(image))?;
        Ok(PyFaceTemplate { inner: result })
    }

    /// Compare two face templates, returning a similarity score
    fn compare_templates(
        &self,
        reference: &PyFaceTemplate,
        probe: &PyFaceTemplate,
    ) -> PyResult<f32> {
        let result = self.runtime.block_on(
            self.provider
                .compare_templates(&reference.inner, &probe.inner),
        )?;
        Ok(result)
    }

    // ── Extended methods ───────────────────────────────────────────────

    /// Estimate the age of the subject in the image
    fn estimate_age(&self, image: &str) -> PyResult<PyAgeEstimate> {
        let result = self.runtime.block_on(self.provider.estimate_age(image))?;
        Ok(PyAgeEstimate { inner: result })
    }

    /// Passive liveness detection from multiple frames
    fn detect_passive_liveness(&self, frames: Vec<String>) -> PyResult<PyPassiveLivenessResult> {
        let result = self
            .runtime
            .block_on(self.provider.detect_passive_liveness(&frames))?;
        Ok(PyPassiveLivenessResult { inner: result })
    }

    /// Deepfake / synthetic face analysis
    fn detect_deepfake(&self, image: &str) -> PyResult<PyDeepfakeAnalysis> {
        let result = self
            .runtime
            .block_on(self.provider.detect_deepfake(image))?;
        Ok(PyDeepfakeAnalysis { inner: result })
    }

    /// 1:N face search against a gallery of templates
    fn search(
        &self,
        probe: &PyFaceTemplate,
        gallery: Vec<PyFaceTemplate>,
        top_k: usize,
    ) -> PyResult<Vec<PySearchMatch>> {
        let gallery_inner: Vec<FaceTemplate> = gallery.into_iter().map(|t| t.inner).collect();
        let results =
            self.runtime
                .block_on(self.provider.search(&probe.inner, &gallery_inner, top_k))?;
        Ok(results
            .into_iter()
            .map(|m| PySearchMatch { inner: m })
            .collect())
    }

    /// Match a selfie against a document photo
    fn match_face_to_document(
        &self,
        selfie: &str,
        document_photo: &str,
    ) -> PyResult<PyFaceVerificationResult> {
        let result = self
            .runtime
            .block_on(self.provider.match_face_to_document(selfie, document_photo))?;
        Ok(PyFaceVerificationResult { inner: result })
    }
}

// ========================================================================
// Module-level functions
// ========================================================================

/// Create a mock face verifier for testing
#[pyfunction]
fn create_mock_verifier() -> PyResult<PyFaceVerifier> {
    PyFaceVerifier::mock()
}

/// Create a local face verifier
#[pyfunction]
fn create_local_verifier() -> PyResult<PyFaceVerifier> {
    PyFaceVerifier::local()
}

/// Create an ONNX-backed face verifier
#[cfg(feature = "onnx")]
#[pyfunction]
fn create_onnx_verifier(models_dir: &str) -> PyResult<PyFaceVerifier> {
    PyFaceVerifier::onnx(models_dir)
}

/// Get the library version
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Python module definition
#[pymodule]
pub fn _marty_biometrics(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyFaceVerificationRequest>()?;
    m.add_class::<PyFaceVerificationResult>()?;
    m.add_class::<PyFaceQualityAssessment>()?;
    m.add_class::<PyFaceBounds>()?;
    m.add_class::<PyProviderCapabilities>()?;
    m.add_class::<PyExtendedCapabilities>()?;
    m.add_class::<PyFaceTemplate>()?;
    m.add_class::<PyAgeEstimate>()?;
    m.add_class::<PyPassiveLivenessResult>()?;
    m.add_class::<PyDeepfakeAnalysis>()?;
    m.add_class::<PySearchMatch>()?;
    m.add_class::<PyLivenessResult>()?;
    m.add_class::<PyFaceVerifier>()?;
    m.add_function(wrap_pyfunction!(create_mock_verifier, m)?)?;
    m.add_function(wrap_pyfunction!(create_local_verifier, m)?)?;
    #[cfg(feature = "onnx")]
    m.add_function(wrap_pyfunction!(create_onnx_verifier, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
