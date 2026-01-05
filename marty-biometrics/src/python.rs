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

use crate::error::BiometricError;
use crate::types::*;
use crate::{BiometricProvider, FaceVerifier};

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

    fn to_dict(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
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

    /// Create a local provider
    #[staticmethod]
    fn local() -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let provider = BiometricProvider::local().map_err(BiometricError::from)?;
        Ok(Self { provider, runtime })
    }

    /// Get provider capabilities
    fn capabilities(&self) -> PyProviderCapabilities {
        PyProviderCapabilities {
            inner: self.provider.capabilities(),
        }
    }

    /// Verify that probe image matches reference image
    fn verify(&self, request: &PyFaceVerificationRequest) -> PyResult<PyFaceVerificationResult> {
        let result = self
            .runtime
            .block_on(self.provider.verify(request.inner.clone()))
            .map_err(BiometricError::from)?;
        Ok(PyFaceVerificationResult { inner: result })
    }

    /// Assess image quality for face verification
    fn assess_quality(&self, image: &str) -> PyResult<PyFaceQualityAssessment> {
        let result = self
            .runtime
            .block_on(self.provider.assess_quality(image))
            .map_err(BiometricError::from)?;
        Ok(PyFaceQualityAssessment { inner: result })
    }
}

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
    m.add_class::<PyProviderCapabilities>()?;
    m.add_class::<PyFaceVerifier>()?;
    m.add_function(wrap_pyfunction!(create_mock_verifier, m)?)?;
    m.add_function(wrap_pyfunction!(create_local_verifier, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
