//! Python adapters for chain.

use super::*;

/// Python wrapper for validation configuration.
///
/// Allows Python code to pass policy parameters to the Rust chain validator.
#[pyclass(name = "ValidationConfig", from_py_object)]
#[derive(Clone)]
pub struct PyValidationConfig {
    /// Whether to check CRL revocation.
    #[pyo3(get, set)]
    pub check_crl: bool,
    /// Whether to check OCSP revocation.
    #[pyo3(get, set)]
    pub check_ocsp: bool,
    /// Revocation mode: "hard_fail", "soft_fail", or "none".
    #[pyo3(get, set)]
    pub revocation_mode: String,
    /// Validation moment as ISO 8601 string (None = now).
    #[pyo3(get, set)]
    pub validation_moment: Option<String>,
    /// Required key usages (e.g., ["digital_signature", "key_cert_sign"]).
    #[pyo3(get, set)]
    pub required_key_usage: Vec<String>,
    /// Certificate type: "csca", "ds", "intermediate", or "any".
    #[pyo3(get, set)]
    pub certificate_type: String,
    /// OCSP responder URL override (None = use AIA extension).
    #[pyo3(get, set)]
    pub ocsp_responder_url: Option<String>,
    /// OCSP timeout in seconds.
    #[pyo3(get, set)]
    pub ocsp_timeout_secs: u64,
}

#[pymethods]
impl PyValidationConfig {
    /// Create a new validation config with default values.
    #[new]
    #[pyo3(signature = (
        check_crl = false,
        check_ocsp = false,
        revocation_mode = "soft_fail".to_string(),
        validation_moment = None,
        required_key_usage = vec![],
        certificate_type = "any".to_string(),
        ocsp_responder_url = None,
        ocsp_timeout_secs = 10
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        check_crl: bool,
        check_ocsp: bool,
        revocation_mode: String,
        validation_moment: Option<String>,
        required_key_usage: Vec<String>,
        certificate_type: String,
        ocsp_responder_url: Option<String>,
        ocsp_timeout_secs: u64,
    ) -> Self {
        Self {
            check_crl,
            check_ocsp,
            revocation_mode,
            validation_moment,
            required_key_usage,
            certificate_type,
            ocsp_responder_url,
            ocsp_timeout_secs,
        }
    }

    /// Create a config for soft-fail revocation checking.
    #[staticmethod]
    fn soft_fail_revocation() -> Self {
        Self {
            check_crl: true,
            check_ocsp: true,
            revocation_mode: "soft_fail".to_string(),
            validation_moment: None,
            required_key_usage: vec!["digital_signature".to_string()],
            certificate_type: "any".to_string(),
            ocsp_responder_url: None,
            ocsp_timeout_secs: 10,
        }
    }

    /// Create a config for hard-fail revocation checking.
    #[staticmethod]
    fn hard_fail_revocation() -> Self {
        Self {
            check_crl: true,
            check_ocsp: true,
            revocation_mode: "hard_fail".to_string(),
            validation_moment: None,
            required_key_usage: vec!["digital_signature".to_string()],
            certificate_type: "any".to_string(),
            ocsp_responder_url: None,
            ocsp_timeout_secs: 10,
        }
    }

    /// Create a config for CSCA (Country Signing CA) validation.
    #[staticmethod]
    fn csca_validation() -> Self {
        Self {
            check_crl: true,
            check_ocsp: false,
            revocation_mode: "soft_fail".to_string(),
            validation_moment: None,
            required_key_usage: vec!["key_cert_sign".to_string(), "crl_sign".to_string()],
            certificate_type: "csca".to_string(),
            ocsp_responder_url: None,
            ocsp_timeout_secs: 10,
        }
    }

    /// Create a config for Document Signer certificate validation.
    #[staticmethod]
    fn dsc_validation() -> Self {
        Self {
            check_crl: true,
            check_ocsp: true,
            revocation_mode: "soft_fail".to_string(),
            validation_moment: None,
            required_key_usage: vec!["digital_signature".to_string()],
            certificate_type: "ds".to_string(),
            ocsp_responder_url: None,
            ocsp_timeout_secs: 10,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "ValidationConfig(check_crl={}, check_ocsp={}, revocation_mode='{}', certificate_type='{}')",
            self.check_crl, self.check_ocsp, self.revocation_mode, self.certificate_type
        )
    }

    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("check_crl", self.check_crl)?;
        dict.set_item("check_ocsp", self.check_ocsp)?;
        dict.set_item("revocation_mode", self.revocation_mode.clone())?;
        dict.set_item("validation_moment", self.validation_moment.clone())?;
        dict.set_item("required_key_usage", self.required_key_usage.clone())?;
        dict.set_item("certificate_type", self.certificate_type.clone())?;
        dict.set_item("ocsp_responder_url", self.ocsp_responder_url.clone())?;
        dict.set_item("ocsp_timeout_secs", self.ocsp_timeout_secs)?;
        Ok(dict.into())
    }
}

impl PyValidationConfig {
    /// Convert to internal ChainValidatorConfig.
    pub fn to_chain_validator_config(&self) -> crate::verification::ChainValidatorConfig {
        use crate::verification::KeyUsage;

        let required_key_usage: Vec<KeyUsage> = self
            .required_key_usage
            .iter()
            .filter_map(|s| match s.to_lowercase().as_str() {
                "digital_signature" => Some(KeyUsage::DigitalSignature),
                "non_repudiation" | "content_commitment" => Some(KeyUsage::NonRepudiation),
                "key_encipherment" => Some(KeyUsage::KeyEncipherment),
                "data_encipherment" => Some(KeyUsage::DataEncipherment),
                "key_agreement" => Some(KeyUsage::KeyAgreement),
                "key_cert_sign" => Some(KeyUsage::KeyCertSign),
                "crl_sign" => Some(KeyUsage::CrlSign),
                "encipher_only" => Some(KeyUsage::EncipherOnly),
                "decipher_only" => Some(KeyUsage::DecipherOnly),
                _ => None,
            })
            .collect();

        let validation_moment = self.validation_moment.as_ref().and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        });

        crate::verification::ChainValidatorConfig {
            check_crl: self.check_crl,
            check_ocsp: self.check_ocsp,
            revocation_mode: self.revocation_mode.clone(),
            validation_moment,
            required_key_usage,
        }
    }
}

/// Python wrapper for chain validation result.
#[pyclass(name = "ChainValidationResult", from_py_object)]
#[derive(Clone)]
pub struct PyChainValidationResult {
    #[pyo3(get)]
    pub valid: bool,
    #[pyo3(get)]
    pub subject: Option<String>,
    #[pyo3(get)]
    pub issuer: Option<String>,
    #[pyo3(get)]
    pub chain_depth: usize,
    #[pyo3(get)]
    pub errors: Vec<String>,
    #[pyo3(get)]
    pub warnings: Vec<String>,
}

impl From<crate::verification::ChainValidationResult> for PyChainValidationResult {
    fn from(result: crate::verification::ChainValidationResult) -> Self {
        Self {
            valid: result.valid,
            subject: result.subject,
            issuer: result.issuer,
            chain_depth: result.chain_depth,
            errors: result.errors,
            warnings: result.warnings,
        }
    }
}

#[pymethods]
impl PyChainValidationResult {
    fn __repr__(&self) -> String {
        format!(
            "ChainValidationResult(valid={}, subject={:?}, chain_depth={})",
            self.valid, self.subject, self.chain_depth
        )
    }

    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("valid", self.valid)?;
        dict.set_item("subject", self.subject.clone())?;
        dict.set_item("issuer", self.issuer.clone())?;
        dict.set_item("chain_depth", self.chain_depth)?;
        dict.set_item("errors", self.errors.clone())?;
        dict.set_item("warnings", self.warnings.clone())?;
        Ok(dict.into())
    }
}

/// Python wrapper for certificate chain validator.
#[pyclass(name = "ChainValidator")]
pub struct PyChainValidator {
    inner: crate::verification::ChainValidator,
}

#[pymethods]
impl PyChainValidator {
    /// Create a new chain validator.
    #[new]
    fn new() -> Self {
        Self {
            inner: crate::verification::ChainValidator::new(),
        }
    }

    /// Add a trust anchor (root CA) from PEM.
    fn add_trust_anchor(&mut self, pem: &str) -> PyResult<()> {
        self.inner.add_trust_anchor_pem(pem).map_err(to_pyerr)
    }

    /// Add a trust anchor from DER bytes.
    fn add_trust_anchor_der(&mut self, der: &[u8]) -> PyResult<()> {
        self.inner.add_trust_anchor_der(der).map_err(to_pyerr)
    }

    /// Add an intermediate certificate from PEM.
    fn add_intermediate(&mut self, pem: &str) -> PyResult<()> {
        self.inner.add_intermediate_pem(pem).map_err(to_pyerr)
    }

    /// Add an intermediate certificate from DER bytes.
    fn add_intermediate_der(&mut self, der: &[u8]) -> PyResult<()> {
        self.inner.add_intermediate_der(der).map_err(to_pyerr)
    }

    /// Add a CRL for revocation checking.
    fn add_crl(&mut self, crl_der: &[u8]) -> PyResult<()> {
        self.inner.add_crl_der(crl_der).map_err(to_pyerr)
    }

    /// Add a DER OCSP response for certificate-bound revocation checking.
    fn add_ocsp_response(&mut self, response_der: &[u8]) -> PyResult<()> {
        self.inner
            .add_ocsp_response_der(response_der)
            .map_err(to_pyerr)
    }

    /// Validate a certificate chain.
    ///
    /// Args:
    ///     chain_pem: List of PEM-encoded certificates, ordered from end-entity to root
    ///
    /// Returns:
    ///     ChainValidationResult with validation status
    fn validate_chain(&self, chain_pem: Vec<String>) -> PyResult<PyChainValidationResult> {
        let result = self.inner.validate_chain(&chain_pem).map_err(to_pyerr)?;
        Ok(result.into())
    }

    /// Validate a single certificate.
    ///
    /// Args:
    ///     cert_pem: PEM-encoded certificate
    ///
    /// Returns:
    ///     ChainValidationResult with validation status
    fn validate_certificate(&self, cert_pem: &str) -> PyResult<PyChainValidationResult> {
        let result = self
            .inner
            .validate_certificate(cert_pem)
            .map_err(to_pyerr)?;
        Ok(result.into())
    }

    /// Validate a certificate chain with custom configuration.
    ///
    /// This method applies policy-based validation with configurable revocation
    /// checking, key usage requirements, and certificate type constraints.
    ///
    /// Args:
    ///     chain_pem: List of PEM-encoded certificates, ordered from end-entity to root
    ///     config: ValidationConfig with policy parameters
    ///
    /// Returns:
    ///     ChainValidationResult with validation status
    fn validate_with_config(
        &self,
        chain_pem: Vec<String>,
        config: &PyValidationConfig,
    ) -> PyResult<PyChainValidationResult> {
        let rust_config = config.to_chain_validator_config();
        let validator = self.inner.configured(rust_config);

        let result = validator.validate_chain(&chain_pem).map_err(to_pyerr)?;
        Ok(result.into())
    }

    /// Create a new chain validator with a specific configuration.
    ///
    /// Args:
    ///     config: ValidationConfig with policy parameters
    ///
    /// Returns:
    ///     A new ChainValidator configured with the given policy
    #[staticmethod]
    fn with_config(config: &PyValidationConfig) -> Self {
        let rust_config = config.to_chain_validator_config();
        Self {
            inner: crate::verification::ChainValidator::with_config(rust_config),
        }
    }

    fn __repr__(&self) -> String {
        "ChainValidator()".to_string()
    }
}
