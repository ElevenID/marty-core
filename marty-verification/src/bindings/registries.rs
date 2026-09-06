//! Python adapters for registries.

use super::*;

/// Python wrapper for MdlVerificationResult.
#[pyclass(name = "MdlVerificationResult", from_py_object)]
#[derive(Clone)]
pub struct PyMdlVerificationResult {
    #[pyo3(get)]
    pub verified: bool,
    #[pyo3(get)]
    pub common_name: Option<String>,
    #[pyo3(get)]
    pub jurisdiction: Option<String>,
    #[pyo3(get)]
    pub errors: Vec<String>,
    #[pyo3(get)]
    pub issuer_auth_status: String,
    #[pyo3(get)]
    pub device_auth_status: String,
}

impl From<MdlVerificationResult> for PyMdlVerificationResult {
    fn from(result: MdlVerificationResult) -> Self {
        Self {
            verified: result.verified,
            common_name: result.common_name,
            jurisdiction: result.jurisdiction,
            errors: result.errors,
            issuer_auth_status: match result.issuer_auth_status {
                AuthStatus::Valid => "valid".to_string(),
                AuthStatus::Invalid => "invalid".to_string(),
                AuthStatus::Unknown => "unknown".to_string(),
            },
            device_auth_status: match result.device_auth_status {
                AuthStatus::Valid => "valid".to_string(),
                AuthStatus::Invalid => "invalid".to_string(),
                AuthStatus::Unknown => "unknown".to_string(),
            },
        }
    }
}

#[pymethods]
impl PyMdlVerificationResult {
    fn __repr__(&self) -> String {
        format!(
            "MdlVerificationResult(verified={}, common_name={:?}, jurisdiction={:?}, errors={:?})",
            self.verified, self.common_name, self.jurisdiction, self.errors
        )
    }

    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("verified", self.verified)?;
        dict.set_item("common_name", self.common_name.clone())?;
        dict.set_item("jurisdiction", self.jurisdiction.clone())?;
        dict.set_item("errors", self.errors.clone())?;
        dict.set_item("issuer_auth_status", self.issuer_auth_status.clone())?;
        dict.set_item("device_auth_status", self.device_auth_status.clone())?;
        Ok(dict.into())
    }
}

/// Python wrapper for IacaRegistry.
#[pyclass(name = "IacaRegistry")]
pub struct PyIacaRegistry {
    inner: IacaRegistry,
}

#[pymethods]
impl PyIacaRegistry {
    /// Create a new empty IACA registry.
    #[new]
    fn new() -> Self {
        Self {
            inner: IacaRegistry::new(),
        }
    }

    /// Load IACA certificates from a directory.
    #[staticmethod]
    fn from_directory(path: &str) -> PyResult<Self> {
        let registry =
            IacaRegistry::from_directory(std::path::Path::new(path)).map_err(to_pyerr)?;
        Ok(Self { inner: registry })
    }

    /// Load IACA certificates from a list of PEM strings.
    #[staticmethod]
    fn from_pem_list(pem_certs: Vec<String>) -> PyResult<Self> {
        let pem_anchors: Vec<PemTrustAnchor> = pem_certs
            .into_iter()
            .map(|pem| PemTrustAnchor {
                certificate_pem: pem,
                purpose: TrustPurpose::Iaca,
                jurisdiction: None,
            })
            .collect();

        let basic_registry =
            BasicTrustRegistry::from_pem_certificates(pem_anchors).map_err(to_pyerr)?;

        // Convert to IacaRegistry
        let mut iaca_registry = IacaRegistry::new();
        for anchor in basic_registry.get_anchors() {
            iaca_registry.add_anchor(anchor.clone()).map_err(to_pyerr)?;
        }

        Ok(Self {
            inner: iaca_registry,
        })
    }

    /// Add an IACA certificate from PEM.
    fn add_certificate(&mut self, pem: &str, jurisdiction: Option<&str>) -> PyResult<()> {
        use der::DecodePem;
        use x509_cert::Certificate;

        let cert = Certificate::from_pem(pem).map_err(|e| {
            VerificationError::pem_error(format!("Failed to parse PEM certificate: {}", e))
        })?;

        let anchor = crate::trust_anchor::TrustAnchor {
            certificate: cert,
            purpose: TrustPurpose::Iaca,
            jurisdiction: jurisdiction.map(|s| s.to_string()),
        };

        self.inner.add_anchor(anchor).map_err(to_pyerr)
    }

    /// Get the number of certificates in the registry.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Get list of supported jurisdictions.
    fn supported_jurisdictions(&self) -> Vec<String> {
        self.inner
            .supported_jurisdictions()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Get the VICAL version.
    fn vical_version(&self) -> Option<String> {
        self.inner.vical_version().map(|s| s.to_string())
    }

    /// Get all trust anchors as PEM-encoded certificates.
    fn get_anchors_pem(&self) -> PyResult<Vec<String>> {
        use der::EncodePem;
        let mut pems = Vec::new();
        for anchor in self.inner.get_anchors() {
            let pem = anchor
                .certificate
                .to_pem(Default::default())
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            pems.push(pem);
        }
        Ok(pems)
    }

    /// Get trust anchors for a specific jurisdiction as PEM certificates.
    fn get_jurisdiction_anchors_pem(&self, jurisdiction: &str) -> PyResult<Vec<String>> {
        use der::EncodePem;
        let mut pems = Vec::new();
        for anchor in self.inner.get_anchors_by_jurisdiction(jurisdiction) {
            let pem = anchor
                .certificate
                .to_pem(Default::default())
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            pems.push(pem);
        }
        Ok(pems)
    }
}

/// Verify an mDL X5Chain against an IACA registry.
///
/// Args:
///     x5chain_pem: List of PEM-encoded certificates in the chain
///     registry: IacaRegistry to verify against
///     ruleset: Validation ruleset ("mdl", "aamva_mdl", "mdl_reader")
///
/// Returns:
///     MdlVerificationResult with verification status
#[pyfunction]
pub(super) fn verify_mdl_x5chain(
    x5chain_pem: Vec<String>,
    registry: &PyIacaRegistry,
    ruleset: Option<&str>,
) -> PyResult<PyMdlVerificationResult> {
    use crate::verification::mdl::{build_x5chain_from_pem, verify_x5chain};

    // Parse the X5Chain
    let pem_bytes: Vec<Vec<u8>> = x5chain_pem.iter().map(|s| s.as_bytes().to_vec()).collect();
    let pem_refs: Vec<&[u8]> = pem_bytes.iter().map(|v| v.as_slice()).collect();

    let x5chain = build_x5chain_from_pem(&pem_refs).map_err(to_pyerr)?;

    // Select ruleset
    let validation_ruleset = match ruleset.unwrap_or("aamva_mdl") {
        "mdl" => ValidationRuleset::Mdl,
        "aamva_mdl" => ValidationRuleset::AamvaMdl,
        "mdl_reader" => ValidationRuleset::MdlReaderOneStep,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown ruleset: {}. Use 'mdl', 'aamva_mdl', or 'mdl_reader'",
                other
            )));
        }
    };

    let result = verify_x5chain(&x5chain, &registry.inner, validation_ruleset);
    Ok(result.into())
}

/// Verify an mDL X5Chain from CBOR bytes.
#[pyfunction]
pub(super) fn verify_mdl_x5chain_cbor(
    x5chain_cbor: &[u8],
    registry: &PyIacaRegistry,
    ruleset: Option<&str>,
) -> PyResult<PyMdlVerificationResult> {
    use crate::verification::mdl::{parse_x5chain_from_cbor, verify_x5chain};

    let x5chain = parse_x5chain_from_cbor(x5chain_cbor).map_err(to_pyerr)?;

    let validation_ruleset = match ruleset.unwrap_or("aamva_mdl") {
        "mdl" => ValidationRuleset::Mdl,
        "aamva_mdl" => ValidationRuleset::AamvaMdl,
        "mdl_reader" => ValidationRuleset::MdlReaderOneStep,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown ruleset: {}",
                other
            )));
        }
    };

    let result = verify_x5chain(&x5chain, &registry.inner, validation_ruleset);
    Ok(result.into())
}

/// Python wrapper for EU Member State.
#[pyclass(name = "EuMemberState", from_py_object)]
#[derive(Clone)]
pub struct PyEuMemberState {
    #[pyo3(get)]
    pub code: String,
    #[pyo3(get)]
    pub name: String,
}

#[pymethods]
impl PyEuMemberState {
    #[new]
    fn new(code: &str) -> PyResult<Self> {
        match EuMemberState::from_code(code) {
            Some(state) => Ok(Self {
                code: state.code().to_string(),
                name: format!("{:?}", state),
            }),
            None => Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid EU member state code: {}",
                code
            ))),
        }
    }

    fn __repr__(&self) -> String {
        format!("EuMemberState(code='{}', name='{}')", self.code, self.name)
    }

    /// Get all EU member states.
    #[staticmethod]
    fn all() -> Vec<Self> {
        EuMemberState::all()
            .into_iter()
            .map(|state| Self {
                code: state.code().to_string(),
                name: format!("{:?}", state),
            })
            .collect()
    }
}

/// Python wrapper for Trust Service Provider.
#[pyclass(name = "TrustServiceProvider", from_py_object)]
#[derive(Clone)]
pub struct PyTrustServiceProvider {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub member_state: String,
    #[pyo3(get)]
    pub status: String,
}

#[pymethods]
impl PyTrustServiceProvider {
    fn __repr__(&self) -> String {
        format!(
            "TrustServiceProvider(id='{}', name='{}', member_state='{}', status='{}')",
            self.id, self.name, self.member_state, self.status
        )
    }
}

impl From<&TrustServiceProvider> for PyTrustServiceProvider {
    fn from(tsp: &TrustServiceProvider) -> Self {
        Self {
            id: tsp.id.clone(),
            name: tsp.name.clone(),
            member_state: tsp.member_state.code().to_string(),
            status: match &tsp.status {
                TspStatus::Granted => "granted".to_string(),
                TspStatus::Withdrawn => "withdrawn".to_string(),
                TspStatus::Suspended => "suspended".to_string(),
                TspStatus::Unknown => "unknown".to_string(),
            },
        }
    }
}

/// Python wrapper for EudiRegistry.
#[pyclass(name = "EudiRegistry")]
pub struct PyEudiRegistry {
    inner: EudiRegistry,
}

#[pymethods]
impl PyEudiRegistry {
    /// Create a new empty EUDI registry.
    #[new]
    fn new() -> Self {
        Self {
            inner: EudiRegistry::new(),
        }
    }

    /// Add a trust anchor for a specific member state.
    fn add_member_state_anchor(&mut self, member_state_code: &str, cert_pem: &str) -> PyResult<()> {
        use der::DecodePem;
        use x509_cert::Certificate;

        let member_state = EuMemberState::from_code(member_state_code).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid member state code: {}",
                member_state_code
            ))
        })?;

        let cert = Certificate::from_pem(cert_pem).map_err(|e| {
            VerificationError::pem_error(format!("Failed to parse PEM certificate: {}", e))
        })?;

        self.inner
            .add_member_state_anchor(member_state, cert, TrustPurpose::EudiQtsp);
        Ok(())
    }

    /// Get the number of certificates in the registry.
    fn __len__(&self) -> usize {
        self.inner.get_anchors().len()
    }

    /// Get list of supported member states.
    fn supported_member_states(&self) -> Vec<String> {
        self.inner
            .supported_member_states()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Get all QTSPs.
    fn get_all_qtsps(&self) -> Vec<PyTrustServiceProvider> {
        self.inner
            .get_all_qtsps()
            .into_iter()
            .map(|tsp| tsp.into())
            .collect()
    }

    /// Get QTSPs for a specific member state.
    fn get_qtsps_by_member_state(
        &self,
        member_state_code: &str,
    ) -> PyResult<Vec<PyTrustServiceProvider>> {
        let member_state = EuMemberState::from_code(member_state_code).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid member state code: {}",
                member_state_code
            ))
        })?;

        Ok(self
            .inner
            .get_qtsps_by_member_state(member_state)
            .into_iter()
            .map(|tsp| tsp.into())
            .collect())
    }

    /// Clear all anchors and reset the registry.
    fn clear(&mut self) {
        self.inner.clear();
    }

    /// Get all trust anchors as PEM-encoded certificates.
    fn get_anchors_pem(&self) -> PyResult<Vec<String>> {
        use der::EncodePem;
        let mut pems = Vec::new();
        for anchor in self.inner.get_anchors() {
            let pem = anchor
                .certificate
                .to_pem(Default::default())
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            pems.push(pem);
        }
        Ok(pems)
    }

    /// Get trust anchors for a specific member state as PEM certificates.
    fn get_member_state_anchors_pem(&self, member_state_code: &str) -> PyResult<Vec<String>> {
        use der::EncodePem;
        let member_state = EuMemberState::from_code(member_state_code).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid member state code: {}",
                member_state_code
            ))
        })?;
        let mut pems = Vec::new();
        for anchor in self.inner.get_member_state_anchors(member_state) {
            let pem = anchor
                .certificate
                .to_pem(Default::default())
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            pems.push(pem);
        }
        Ok(pems)
    }
}

/// Python wrapper for CscaRegistry.
#[cfg(feature = "csca")]
#[pyclass(name = "CscaRegistry")]
pub struct PyCscaRegistry {
    pub(super) inner: CscaRegistry,
}

#[cfg(feature = "csca")]
#[pymethods]
impl PyCscaRegistry {
    /// Create a new empty CSCA registry.
    #[new]
    fn new() -> Self {
        Self {
            inner: CscaRegistry::new(),
        }
    }

    /// Load CSCA certificates from a directory of PEM files.
    #[staticmethod]
    fn from_directory(path: &str) -> PyResult<Self> {
        let registry =
            CscaRegistry::from_directory(std::path::Path::new(path)).map_err(to_pyerr)?;
        Ok(Self { inner: registry })
    }

    /// Add a CSCA certificate for a specific country.
    fn add_country_csca(&mut self, country_code: &str, cert_pem: &str) -> PyResult<()> {
        use der::DecodePem;
        use x509_cert::Certificate;

        let cert = Certificate::from_pem(cert_pem).map_err(|e| {
            VerificationError::pem_error(format!("Failed to parse PEM certificate: {}", e))
        })?;

        self.inner
            .add_country_csca(country_code, cert)
            .map_err(to_pyerr)
    }

    /// Get CSCA certificates for a specific country as PEM strings.
    fn get_country_cscas_pem(&self, country_code: &str) -> PyResult<Vec<String>> {
        use der::EncodePem;
        let mut pems = Vec::new();
        for anchor in self.inner.get_country_cscas(country_code) {
            let pem = anchor
                .certificate
                .to_pem(Default::default())
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            pems.push(pem);
        }
        Ok(pems)
    }

    /// Get all supported countries.
    fn supported_countries(&self) -> Vec<String> {
        self.inner
            .supported_countries()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Get the number of CSCA certificates in the registry.
    fn __len__(&self) -> usize {
        self.inner.get_anchors().len()
    }

    /// Get the Master List version.
    fn master_list_version(&self) -> Option<String> {
        self.inner.master_list_version().map(|s| s.to_string())
    }

    /// Get all trust anchors as PEM-encoded certificates.
    fn get_anchors_pem(&self) -> PyResult<Vec<String>> {
        use der::EncodePem;
        let mut pems = Vec::new();
        for anchor in self.inner.get_anchors() {
            let pem = anchor
                .certificate
                .to_pem(Default::default())
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            pems.push(pem);
        }
        Ok(pems)
    }

    fn __repr__(&self) -> String {
        format!(
            "CscaRegistry(countries={}, anchors={})",
            self.inner.supported_countries().len(),
            self.inner.get_anchors().len()
        )
    }
}
