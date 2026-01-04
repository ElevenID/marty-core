//! PyO3 Python bindings for marty-verification.
//!
//! This module exposes the verification functionality to Python.
//!
//! # Available Bindings
//!
//! ## MDL Verification
//! - `IacaRegistry` - Trust anchor registry for IACA certificates
//! - `MdlVerificationResult` - Result of MDL verification
//! - `verify_mdl_x5chain()` - Verify MDL X5Chain from PEM
//! - `verify_mdl_x5chain_cbor()` - Verify MDL X5Chain from CBOR
//!
//! ## MRZ Parsing
//! - `MrzData` - Parsed MRZ data
//! - `parse_mrz()` - Parse MRZ from lines of text
//! - `compute_check_digit()` - Calculate ICAO check digit
//! - `validate_check_digit()` - Validate a check digit
//!
//! ## CRL Checking
//! - `CrlInfo` - Parsed CRL information
//! - `RevokedCertificate` - Revoked certificate entry
//! - `parse_crl()` - Parse a DER-encoded CRL
//! - `check_certificate_revocation()` - Check if cert is revoked
//!
//! ## Cryptographic Operations
//! - `hash_data()` - Hash data with specified algorithm
//! - `verify_signature()` - Verify a cryptographic signature
//!
//! ## mDL Document Parsing
//! - `DeviceResponse` - Parsed mDL DeviceResponse
//! - `parse_device_response()` - Parse CBOR DeviceResponse

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::dtc;
use crate::error::VerificationError;
use crate::trust_anchor::{
    BasicTrustRegistry, IacaRegistry, PemTrustAnchor, TrustPurpose, TrustRegistry,
};
use crate::verification::mdl::{AuthStatus, MdlVerificationResult, ValidationRuleset};

/// Python wrapper for MdlVerificationResult.
#[pyclass(name = "MdlVerificationResult")]
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
            IacaRegistry::from_directory(std::path::Path::new(path)).map_err(|e| PyErr::from(e))?;
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
            BasicTrustRegistry::from_pem_certificates(pem_anchors).map_err(|e| PyErr::from(e))?;

        // Convert to IacaRegistry
        let mut iaca_registry = IacaRegistry::new();
        for anchor in basic_registry.get_anchors() {
            iaca_registry
                .add_anchor(anchor.clone())
                .map_err(|e| PyErr::from(e))?;
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

        self.inner.add_anchor(anchor).map_err(|e| PyErr::from(e))
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
fn verify_mdl_x5chain(
    x5chain_pem: Vec<String>,
    registry: &PyIacaRegistry,
    ruleset: Option<&str>,
) -> PyResult<PyMdlVerificationResult> {
    use crate::verification::mdl::{build_x5chain_from_pem, verify_x5chain};

    // Parse the X5Chain
    let pem_bytes: Vec<Vec<u8>> = x5chain_pem.iter().map(|s| s.as_bytes().to_vec()).collect();
    let pem_refs: Vec<&[u8]> = pem_bytes.iter().map(|v| v.as_slice()).collect();

    let x5chain = build_x5chain_from_pem(&pem_refs).map_err(|e| PyErr::from(e))?;

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
fn verify_mdl_x5chain_cbor(
    x5chain_cbor: &[u8],
    registry: &PyIacaRegistry,
    ruleset: Option<&str>,
) -> PyResult<PyMdlVerificationResult> {
    use crate::verification::mdl::{parse_x5chain_from_cbor, verify_x5chain};

    let x5chain = parse_x5chain_from_cbor(x5chain_cbor).map_err(|e| PyErr::from(e))?;

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

// ============================================================================
// MRZ Parsing Bindings
// ============================================================================

/// Python wrapper for parsed MRZ data.
#[pyclass(name = "MrzData")]
#[derive(Clone)]
pub struct PyMrzData {
    #[pyo3(get)]
    pub format: String,
    #[pyo3(get)]
    pub document_type: String,
    #[pyo3(get)]
    pub issuing_country: String,
    #[pyo3(get)]
    pub surname: String,
    #[pyo3(get)]
    pub given_names: String,
    #[pyo3(get)]
    pub document_number: String,
    #[pyo3(get)]
    pub nationality: String,
    #[pyo3(get)]
    pub date_of_birth: String,
    #[pyo3(get)]
    pub sex: String,
    #[pyo3(get)]
    pub date_of_expiry: String,
    #[pyo3(get)]
    pub optional_data: String,
    #[pyo3(get)]
    pub raw_lines: Vec<String>,
}

impl From<crate::mrz::Mrz> for PyMrzData {
    fn from(mrz: crate::mrz::Mrz) -> Self {
        let format = match mrz.format {
            crate::mrz::MrzFormat::TD1 => "TD1",
            crate::mrz::MrzFormat::TD2 => "TD2",
            crate::mrz::MrzFormat::TD3 => "TD3",
        };

        Self {
            format: format.to_string(),
            document_type: mrz.document_type,
            issuing_country: mrz.issuing_country,
            surname: mrz.surname,
            given_names: mrz.given_names,
            document_number: mrz.document_number,
            nationality: mrz.nationality,
            date_of_birth: mrz.date_of_birth,
            sex: mrz.sex.to_string(),
            date_of_expiry: mrz.date_of_expiry,
            optional_data: mrz.optional_data,
            raw_lines: mrz.raw_lines,
        }
    }
}

#[pymethods]
impl PyMrzData {
    fn __repr__(&self) -> String {
        format!(
            "MrzData(format={}, doc_number={}, name='{} {}', country={})",
            self.format, self.document_number, self.given_names, self.surname, self.issuing_country
        )
    }

    /// Get full name (given names + surname).
    fn full_name(&self) -> String {
        if self.given_names.is_empty() {
            self.surname.clone()
        } else {
            format!("{} {}", self.given_names, self.surname)
        }
    }

    /// Get MRZ information string for BAC key derivation.
    fn mrz_information(&self) -> String {
        crate::mrz::checksum::compute_mrz_information(
            &self.document_number,
            &self.date_of_birth,
            &self.date_of_expiry,
        )
    }

    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("format", self.format.clone())?;
        dict.set_item("document_type", self.document_type.clone())?;
        dict.set_item("issuing_country", self.issuing_country.clone())?;
        dict.set_item("surname", self.surname.clone())?;
        dict.set_item("given_names", self.given_names.clone())?;
        dict.set_item("document_number", self.document_number.clone())?;
        dict.set_item("nationality", self.nationality.clone())?;
        dict.set_item("date_of_birth", self.date_of_birth.clone())?;
        dict.set_item("sex", self.sex.clone())?;
        dict.set_item("date_of_expiry", self.date_of_expiry.clone())?;
        dict.set_item("optional_data", self.optional_data.clone())?;
        Ok(dict.into())
    }
}

/// Parse MRZ from lines of text.
///
/// Args:
///     lines: List of MRZ lines (2 for TD3/TD2, 3 for TD1)
///
/// Returns:
///     MrzData with parsed information
#[pyfunction]
fn parse_mrz(lines: Vec<String>) -> PyResult<PyMrzData> {
    let line_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    let mrz = crate::mrz::parse_mrz(&line_refs).map_err(|e| PyErr::from(e))?;
    Ok(mrz.into())
}

/// Calculate ICAO check digit for a string.
///
/// Args:
///     input_string: The string to calculate check digit for
///
/// Returns:
///     Single digit character '0'-'9'
#[pyfunction]
fn compute_check_digit(input_string: &str) -> String {
    crate::mrz::compute_check_digit(input_string).to_string()
}

/// Validate a check digit.
///
/// Args:
///     data: The data portion (without check digit)
///     check_digit: The check digit to validate
///
/// Returns:
///     True if the check digit is correct
#[pyfunction]
fn validate_check_digit(data: &str, check_digit: &str) -> bool {
    if let Some(c) = check_digit.chars().next() {
        crate::mrz::validate_check_digit(data, c)
    } else {
        false
    }
}

// ============================================================================
// CRL Checking Bindings
// ============================================================================

/// Python wrapper for CRL information.
#[pyclass(name = "CrlInfo")]
#[derive(Clone)]
pub struct PyCrlInfo {
    #[pyo3(get)]
    pub issuer: String,
    #[pyo3(get)]
    pub this_update: Option<String>,
    #[pyo3(get)]
    pub next_update: Option<String>,
    #[pyo3(get)]
    pub crl_number: Option<u64>,
    inner_revoked: Vec<PyRevokedCertificate>,
}

#[pymethods]
impl PyCrlInfo {
    /// Get list of revoked certificates.
    fn revoked_certificates(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        let list = PyList::empty(py);
        for cert in &self.inner_revoked {
            list.append(cert.clone().into_pyobject(py)?)?;
        }
        Ok(list.into())
    }

    /// Check if a certificate serial number is revoked.
    fn is_revoked(&self, serial_number: &str) -> bool {
        self.inner_revoked
            .iter()
            .any(|r| r.serial_number == serial_number)
    }

    fn __repr__(&self) -> String {
        format!(
            "CrlInfo(issuer='{}', revoked_count={})",
            self.issuer,
            self.inner_revoked.len()
        )
    }
}

/// Python wrapper for a revoked certificate entry.
#[pyclass(name = "RevokedCertificate")]
#[derive(Clone)]
pub struct PyRevokedCertificate {
    #[pyo3(get)]
    pub serial_number: String,
    #[pyo3(get)]
    pub revocation_date: Option<String>,
    #[pyo3(get)]
    pub reason: Option<String>,
}

#[pymethods]
impl PyRevokedCertificate {
    fn __repr__(&self) -> String {
        format!("RevokedCertificate(serial={})", self.serial_number)
    }
}

/// Parse a DER-encoded CRL.
///
/// Args:
///     der_bytes: DER-encoded CRL bytes
///
/// Returns:
///     CrlInfo with parsed information
#[pyfunction]
fn parse_crl(der_bytes: &[u8]) -> PyResult<PyCrlInfo> {
    let crl = crate::asn1::crl::parse_crl(der_bytes).map_err(|e| PyErr::from(e))?;

    let revoked: Vec<PyRevokedCertificate> = crl
        .revoked_certificates
        .into_iter()
        .map(|r| PyRevokedCertificate {
            serial_number: r.serial_number,
            revocation_date: r.revocation_date.map(|d| d.to_rfc3339()),
            reason: r.reason.map(|r| format!("{:?}", r)),
        })
        .collect();

    Ok(PyCrlInfo {
        issuer: crl.issuer,
        this_update: crl.this_update.map(|d| d.to_rfc3339()),
        next_update: crl.next_update.map(|d| d.to_rfc3339()),
        crl_number: crl.crl_number,
        inner_revoked: revoked,
    })
}

/// Check if a certificate is revoked according to a CRL.
///
/// Args:
///     cert_serial: Certificate serial number (hex string)
///     cert_issuer: Certificate issuer DN
///     crl_der: DER-encoded CRL
///
/// Returns:
///     Tuple of (is_revoked: bool, reason: Optional[str])
#[pyfunction]
fn check_certificate_revocation(
    cert_serial: &str,
    cert_issuer: &str,
    crl_der: &[u8],
) -> PyResult<(bool, Option<String>)> {
    // Parse the CRL first
    let crl = crate::asn1::crl::parse_crl(crl_der).map_err(|e| PyErr::from(e))?;

    // Check against the parsed CRL
    let result = crate::asn1::check_certificate_revocation(cert_serial, cert_issuer, &[crl])
        .map_err(|e| PyErr::from(e))?;

    match result {
        Some(reason) => Ok((true, Some(format!("{:?}", reason)))),
        None => Ok((false, None)),
    }
}

// ============================================================================
// Cryptographic Operations Bindings
// ============================================================================

/// Hash data using the specified algorithm.
///
/// Args:
///     algorithm: Hash algorithm ("sha1", "sha256", "sha384", "sha512")
///     data: Data to hash
///
/// Returns:
///     Hash digest as bytes
#[pyfunction]
fn hash_data<'py>(py: Python<'py>, algorithm: &str, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    use marty_crypto::hashing;

    let result = match algorithm.to_lowercase().as_str() {
        "sha1" => hashing::hash_sha1(data),
        "sha256" => hashing::hash_sha256(data),
        "sha384" => hashing::hash_sha384(data),
        "sha512" => hashing::hash_sha512(data),
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown hash algorithm: {}. Use 'sha1', 'sha256', 'sha384', or 'sha512'",
                other
            )));
        }
    };

    Ok(PyBytes::new(py, &result))
}

/// Verify a cryptographic signature.
///
/// Args:
///     algorithm: Signature algorithm (e.g., "ecdsa-p256-sha256", "rsa-pkcs1-sha256")
///     public_key_der: DER-encoded public key (SubjectPublicKeyInfo)
///     message: The message that was signed
///     signature: The signature bytes
///
/// Returns:
///     True if signature is valid, False otherwise
#[pyfunction]
fn verify_signature(
    algorithm: &str,
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    use marty_crypto::SignatureAlgorithm;

    let alg = match algorithm.to_lowercase().replace("-", "_").as_str() {
        "ecdsa_p256_sha256" | "es256" => SignatureAlgorithm::EcdsaP256Sha256,
        "ecdsa_p384_sha384" | "es384" => SignatureAlgorithm::EcdsaP384Sha384,
        "rsa_pkcs1_sha256" | "rs256" => SignatureAlgorithm::RsaPkcs1Sha256,
        "rsa_pkcs1_sha384" | "rs384" => SignatureAlgorithm::RsaPkcs1Sha384,
        "rsa_pkcs1_sha512" | "rs512" => SignatureAlgorithm::RsaPkcs1Sha512,
        "rsa_pss_sha256" | "ps256" => SignatureAlgorithm::RsaPssSha256,
        "rsa_pss_sha384" | "ps384" => SignatureAlgorithm::RsaPssSha384,
        "rsa_pss_sha512" | "ps512" => SignatureAlgorithm::RsaPssSha512,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown signature algorithm: {}",
                other
            )));
        }
    };

    marty_crypto::verify_signature(alg, public_key_der, message, signature)
        .map_err(|e| PyErr::from(e))
}

// ============================================================================
// mDL Document Parsing Bindings
// ============================================================================

/// Python wrapper for parsed DeviceResponse.
#[pyclass(name = "DeviceResponse")]
#[derive(Clone)]
pub struct PyDeviceResponse {
    #[pyo3(get)]
    pub version: String,
    #[pyo3(get)]
    pub status: u64,
    inner: crate::mdoc::DeviceResponse,
}

#[pymethods]
impl PyDeviceResponse {
    /// Get the number of documents in the response.
    fn document_count(&self) -> usize {
        self.inner.documents.len()
    }

    /// Get list of document types (doc_type values).
    fn document_types(&self) -> Vec<String> {
        self.inner
            .documents
            .iter()
            .map(|d| d.doc_type.clone())
            .collect()
    }

    /// Get mDL fields from the first org.iso.18013.5.1 namespace.
    fn get_mdl_fields(&self) -> PyResult<std::collections::HashMap<String, String>> {
        let fields = self.inner.get_mdl_fields().map_err(|e| PyErr::from(e))?;
        // Convert Vec<(String, Value)> to HashMap<String, String>
        let map: std::collections::HashMap<String, String> = fields
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();
        Ok(map)
    }

    /// Get a specific mDL element by identifier.
    fn get_mdl_element(&self, element_id: &str) -> Option<String> {
        self.inner
            .get_mdl_element(element_id)
            .map(|v| v.to_string())
    }

    /// Check if subject is over 21.
    fn is_age_over_21(&self) -> Option<bool> {
        self.inner.is_age_over_21()
    }

    /// Get family name.
    fn get_family_name(&self) -> Option<String> {
        self.inner.get_family_name()
    }

    /// Get given name.
    fn get_given_name(&self) -> Option<String> {
        self.inner.get_given_name()
    }

    fn __repr__(&self) -> String {
        format!(
            "DeviceResponse(version='{}', status={}, documents={})",
            self.version,
            self.status,
            self.inner.documents.len()
        )
    }

    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("version", self.version.clone())?;
        dict.set_item("status", self.status)?;
        dict.set_item("document_count", self.inner.documents.len())?;
        dict.set_item("document_types", self.document_types())?;

        // Add mDL fields if available
        if let Ok(fields) = self.get_mdl_fields() {
            let fields_dict = PyDict::new(py);
            for (k, v) in fields {
                fields_dict.set_item(k, v)?;
            }
            dict.set_item("mdl_fields", fields_dict)?;
        }

        Ok(dict.into())
    }
}

/// Parse a CBOR-encoded DeviceResponse.
///
/// Args:
///     cbor_bytes: CBOR-encoded DeviceResponse bytes
///
/// Returns:
///     DeviceResponse with parsed information
#[pyfunction]
fn parse_device_response(cbor_bytes: &[u8]) -> PyResult<PyDeviceResponse> {
    let response =
        crate::mdoc::DeviceResponse::from_cbor(cbor_bytes).map_err(|e| PyErr::from(e))?;

    Ok(PyDeviceResponse {
        version: response.version.clone(),
        status: response.status,
        inner: response,
    })
}

// ============================================================================
// Certificate Chain Validation Bindings
// ============================================================================

/// Python wrapper for validation configuration.
///
/// Allows Python code to pass policy parameters to the Rust chain validator.
#[pyclass(name = "ValidationConfig")]
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
#[pyclass(name = "ChainValidationResult")]
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
        self.inner
            .add_trust_anchor_pem(pem)
            .map_err(|e| PyErr::from(e))
    }

    /// Add a trust anchor from DER bytes.
    fn add_trust_anchor_der(&mut self, der: &[u8]) -> PyResult<()> {
        self.inner
            .add_trust_anchor_der(der)
            .map_err(|e| PyErr::from(e))
    }

    /// Add an intermediate certificate from PEM.
    fn add_intermediate(&mut self, pem: &str) -> PyResult<()> {
        self.inner
            .add_intermediate_pem(pem)
            .map_err(|e| PyErr::from(e))
    }

    /// Add an intermediate certificate from DER bytes.
    fn add_intermediate_der(&mut self, der: &[u8]) -> PyResult<()> {
        self.inner
            .add_intermediate_der(der)
            .map_err(|e| PyErr::from(e))
    }

    /// Add a CRL for revocation checking.
    fn add_crl(&mut self, crl_der: &[u8]) -> PyResult<()> {
        let crl = crate::asn1::crl::parse_crl(crl_der).map_err(|e| PyErr::from(e))?;
        self.inner.add_crl(crl);
        Ok(())
    }

    /// Validate a certificate chain.
    ///
    /// Args:
    ///     chain_pem: List of PEM-encoded certificates, ordered from end-entity to root
    ///
    /// Returns:
    ///     ChainValidationResult with validation status
    fn validate_chain(&self, chain_pem: Vec<String>) -> PyResult<PyChainValidationResult> {
        let result = self
            .inner
            .validate_chain(&chain_pem)
            .map_err(|e| PyErr::from(e))?;
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
            .map_err(|e| PyErr::from(e))?;
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
        // Create a new validator with the provided config
        let rust_config = config.to_chain_validator_config();
        let validator = crate::verification::ChainValidator::with_config(rust_config);

        // Copy trust anchors and intermediates from self
        // Note: This is a workaround since we can't directly access internals
        // The validator should be pre-configured with trust anchors

        let result = validator
            .validate_chain(&chain_pem)
            .map_err(|e| PyErr::from(e))?;
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

// ============================================================================
// Key Derivation Bindings
// ============================================================================

// ============================================================================
// Certificate Bindings
// ============================================================================

/// Load a certificate from PEM format, return DER bytes.
#[pyfunction]
fn load_certificate_pem<'py>(py: Python<'py>, pem_data: &str) -> PyResult<Bound<'py, PyBytes>> {
    let der =
        marty_crypto::certificate::load_certificate_pem(pem_data).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &der))
}

/// Validate a certificate DER encoding.
#[pyfunction]
fn load_certificate_der<'py>(py: Python<'py>, der_data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let _cert =
        marty_crypto::certificate::load_certificate_der(der_data).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, der_data))
}

/// Get certificate info as a dictionary.
#[pyfunction]
fn get_certificate_info<'py>(py: Python<'py>, der_data: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    let info =
        marty_crypto::certificate::get_certificate_info(der_data).map_err(|e| PyErr::from(e))?;

    let dict = PyDict::new(py);
    dict.set_item("subject", &info.subject)?;
    dict.set_item("issuer", &info.issuer)?;
    dict.set_item("serial_number", &info.serial_number)?;
    dict.set_item("not_before", &info.not_before)?;
    dict.set_item("not_after", &info.not_after)?;
    dict.set_item("is_ca", info.is_ca)?;
    dict.set_item("key_usage", info.key_usage)?;
    dict.set_item("subject_alt_names", info.subject_alt_names)?;
    dict.set_item("fingerprint_sha256", &info.fingerprint_sha256)?;
    Ok(dict)
}

/// Convert certificate PEM to DER.
#[pyfunction]
fn certificate_pem_to_der<'py>(py: Python<'py>, pem_data: &str) -> PyResult<Bound<'py, PyBytes>> {
    let der = marty_crypto::certificate::pem_to_der(pem_data).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &der))
}

/// Convert certificate DER to PEM.
#[pyfunction]
fn certificate_der_to_pem(der_data: &[u8]) -> PyResult<String> {
    marty_crypto::certificate::der_to_pem(der_data).map_err(|e| PyErr::from(e))
}

/// Get certificate public key in SPKI DER format.
#[pyfunction]
fn get_certificate_public_key<'py>(
    py: Python<'py>,
    der_data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let pubkey = marty_crypto::certificate::get_certificate_public_key(der_data)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &pubkey))
}

/// Check if a certificate is expired.
#[pyfunction]
fn is_certificate_expired(der_data: &[u8]) -> PyResult<bool> {
    marty_crypto::certificate::is_certificate_expired(der_data).map_err(|e| PyErr::from(e))
}

/// Check if a certificate is not yet valid.
#[pyfunction]
fn is_certificate_not_yet_valid(der_data: &[u8]) -> PyResult<bool> {
    marty_crypto::certificate::is_certificate_not_yet_valid(der_data).map_err(|e| PyErr::from(e))
}

/// Verify that a certificate was signed by another certificate.
#[pyfunction]
fn verify_certificate_signature(cert_der: &[u8], issuer_der: &[u8]) -> PyResult<bool> {
    marty_crypto::certificate::verify_certificate_signature(cert_der, issuer_der)
        .map_err(|e| PyErr::from(e))
}

// ============================================================================
// Key Serialization Bindings
// ============================================================================

/// Load a private key from PEM format, return PKCS#8 DER.
#[pyfunction]
fn load_private_key_pem<'py>(py: Python<'py>, pem_data: &str) -> PyResult<Bound<'py, PyBytes>> {
    let der =
        marty_crypto::serialization::load_private_key_pem(pem_data).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &der))
}

/// Validate/load a private key from DER format.
#[pyfunction]
fn load_private_key_der<'py>(py: Python<'py>, der_data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let der =
        marty_crypto::serialization::load_private_key_der(der_data).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &der))
}

/// Save a private key to PEM format (PKCS#8).
#[pyfunction]
fn save_private_key_pem(private_key_der: &[u8]) -> PyResult<String> {
    marty_crypto::serialization::save_private_key_pem(private_key_der).map_err(|e| PyErr::from(e))
}

/// Load a public key from PEM format (SPKI), return DER.
#[pyfunction]
fn load_public_key_pem<'py>(py: Python<'py>, pem_data: &str) -> PyResult<Bound<'py, PyBytes>> {
    let der =
        marty_crypto::serialization::load_public_key_pem(pem_data).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &der))
}

/// Validate/load a public key from DER format.
#[pyfunction]
fn load_public_key_der<'py>(py: Python<'py>, der_data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let der =
        marty_crypto::serialization::load_public_key_der(der_data).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &der))
}

/// Save a public key to PEM format (SPKI).
#[pyfunction]
fn save_public_key_pem(public_key_der: &[u8]) -> PyResult<String> {
    marty_crypto::serialization::save_public_key_pem(public_key_der).map_err(|e| PyErr::from(e))
}

/// Extract public key from private key (PKCS#8 DER).
#[pyfunction]
fn extract_public_key<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let pubkey = marty_crypto::serialization::extract_public_key(private_key_der)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &pubkey))
}

/// Detect the type of a private key.
#[pyfunction]
fn detect_private_key_type(der_data: &[u8]) -> PyResult<String> {
    marty_crypto::serialization::detect_private_key_type(der_data).map_err(|e| PyErr::from(e))
}

/// Detect the type of a public key.
#[pyfunction]
fn detect_public_key_type(der_data: &[u8]) -> PyResult<String> {
    marty_crypto::serialization::detect_public_key_type(der_data).map_err(|e| PyErr::from(e))
}

/// Get the key size in bits.
#[pyfunction]
fn get_key_size(public_key_der: &[u8]) -> PyResult<usize> {
    marty_crypto::serialization::get_key_size(public_key_der).map_err(|e| PyErr::from(e))
}

/// Convert raw EC private key bytes to PKCS#8 DER format.
#[pyfunction]
fn raw_private_key_to_pkcs8<'py>(
    py: Python<'py>,
    raw_key: &[u8],
    key_type: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let der = marty_crypto::serialization::raw_private_key_to_pkcs8(raw_key, key_type)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &der))
}

/// Convert raw public key bytes to SPKI DER format.
#[pyfunction]
fn raw_public_key_to_spki<'py>(
    py: Python<'py>,
    raw_key: &[u8],
    key_type: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let der = marty_crypto::serialization::raw_public_key_to_spki(raw_key, key_type)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &der))
}

/// Extract raw private key bytes from PKCS#8 DER format.
#[pyfunction]
fn pkcs8_to_raw_private_key<'py>(
    py: Python<'py>,
    pkcs8_der: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, String)> {
    let (raw, key_type) = marty_crypto::serialization::pkcs8_to_raw_private_key(pkcs8_der)
        .map_err(|e| PyErr::from(e))?;
    Ok((PyBytes::new(py, &raw), key_type))
}

/// Extract raw public key bytes from SPKI DER format.
#[pyfunction]
fn spki_to_raw_public_key<'py>(
    py: Python<'py>,
    spki_der: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, String)> {
    let (raw, key_type) = marty_crypto::serialization::spki_to_raw_public_key(spki_der)
        .map_err(|e| PyErr::from(e))?;
    Ok((PyBytes::new(py, &raw), key_type))
}

/// Derive a key using HKDF-SHA256.
#[pyfunction]
fn hkdf_sha256<'py>(
    py: Python<'py>,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let result =
        marty_crypto::kdf::hkdf_sha256(ikm, salt, info, length).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &result))
}

/// Derive a key using HKDF-SHA384.
#[pyfunction]
fn hkdf_sha384<'py>(
    py: Python<'py>,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let result =
        marty_crypto::kdf::hkdf_sha384(ikm, salt, info, length).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &result))
}

/// Derive a key using PBKDF2-SHA256.
#[pyfunction]
fn pbkdf2_sha256<'py>(
    py: Python<'py>,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let result = marty_crypto::kdf::pbkdf2_sha256(password, salt, iterations, key_length);
    Ok(PyBytes::new(py, &result))
}

// ============================================================================
// Symmetric Encryption Bindings
// ============================================================================

/// Encrypt data using AES-GCM.
#[pyfunction]
fn aes_gcm_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = match key.len() {
        16 => marty_crypto::symmetric::aes_128_gcm_encrypt(key, nonce, plaintext, aad),
        32 => marty_crypto::symmetric::aes_256_gcm_encrypt(key, nonce, plaintext, aad),
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Key must be 16 bytes (AES-128) or 32 bytes (AES-256)",
            ))
        }
    }
    .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &result))
}

/// Decrypt data using AES-GCM.
#[pyfunction]
fn aes_gcm_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = match key.len() {
        16 => marty_crypto::symmetric::aes_128_gcm_decrypt(key, nonce, ciphertext, aad),
        32 => marty_crypto::symmetric::aes_256_gcm_decrypt(key, nonce, ciphertext, aad),
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Key must be 16 bytes (AES-128) or 32 bytes (AES-256)",
            ))
        }
    }
    .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &result))
}

/// Encrypt data using 3DES-CBC.
#[pyfunction]
fn tdes_cbc_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = marty_crypto::des::tdes_cbc_encrypt_padded(key, iv, plaintext)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &result))
}

/// Decrypt data using 3DES-CBC.
#[pyfunction]
fn tdes_cbc_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = marty_crypto::des::tdes_cbc_decrypt_padded(key, iv, ciphertext)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &result))
}

// ============================================================================
// Ed25519 Bindings
// ============================================================================

/// Generate an Ed25519 key pair.
#[pyfunction]
fn ed25519_generate<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ed25519::generate_keypair();
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Sign a message with Ed25519.
#[pyfunction]
fn ed25519_sign<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::ed25519::sign(secret_key, message).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &signature))
}

/// Verify an Ed25519 signature.
#[pyfunction]
fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    Ok(marty_crypto::ed25519::verify_bool(
        public_key, message, signature,
    ))
}

// ============================================================================
// ECDH Bindings
// ============================================================================

/// Generate an X25519 key pair.
#[pyfunction]
fn x25519_generate<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ecdh::x25519_generate_keypair();
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Perform X25519 key agreement.
#[pyfunction]
fn x25519_agree<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    peer_public: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let keypair = marty_crypto::ecdh::X25519KeyPair::from_secret_key(secret_key)
        .map_err(|e| PyErr::from(e))?;
    let shared = keypair.agree(peer_public).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &shared))
}

/// Generate a P-256 key pair.
#[pyfunction]
fn p256_generate<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = marty_crypto::ecdh::p256_generate_keypair();
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Perform P-256 ECDH key agreement.
#[pyfunction]
fn p256_agree<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    peer_public: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result =
        marty_crypto::ecdh::p256_agree(secret_key, peer_public).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &result))
}

// ============================================================================
// ECDSA Signing Bindings
// ============================================================================

/// Generate a P-256 ECDSA key pair for signing.
#[pyfunction]
fn ecdsa_p256_generate<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) =
        marty_crypto::ecdsa::generate_p256_keypair().map_err(|e| PyErr::from(e))?;
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Generate a P-384 ECDSA key pair for signing.
#[pyfunction]
fn ecdsa_p384_generate<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) =
        marty_crypto::ecdsa::generate_p384_keypair().map_err(|e| PyErr::from(e))?;
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Sign a message with ECDSA P-256 SHA-256 (ES256).
#[pyfunction]
fn ecdsa_p256_sign<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::ecdsa::sign_p256_sha256(secret_key, message).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with ECDSA P-384 SHA-384 (ES384).
#[pyfunction]
fn ecdsa_p384_sign<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::ecdsa::sign_p384_sha384(secret_key, message).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &signature))
}

/// Verify an ECDSA P-256 SHA-256 signature.
#[pyfunction]
fn ecdsa_p256_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    marty_crypto::ecdsa::verify_p256_sha256(public_key, message, signature)
        .map_err(|e| PyErr::from(e))
}

/// Verify an ECDSA P-384 SHA-384 signature.
#[pyfunction]
fn ecdsa_p384_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    marty_crypto::ecdsa::verify_p384_sha384(public_key, message, signature)
        .map_err(|e| PyErr::from(e))
}

/// Generate a P-521 ECDSA key pair for signing.
#[pyfunction]
fn ecdsa_p521_generate<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) =
        marty_crypto::ecdsa::generate_p521_keypair().map_err(|e| PyErr::from(e))?;
    Ok((PyBytes::new(py, &secret), PyBytes::new(py, &public)))
}

/// Sign a message with ECDSA P-521 SHA-512 (ES512).
#[pyfunction]
fn ecdsa_p521_sign<'py>(
    py: Python<'py>,
    secret_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::ecdsa::sign_p521_sha512(secret_key, message).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &signature))
}

/// Verify an ECDSA P-521 SHA-512 signature.
#[pyfunction]
fn ecdsa_p521_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    marty_crypto::ecdsa::verify_p521_sha512(public_key, message, signature)
        .map_err(|e| PyErr::from(e))
}

// ============================================================================
// RSA Signing Bindings
// ============================================================================

/// Generate an RSA key pair (2048 bits by default).
#[pyfunction]
#[pyo3(signature = (bits = 2048))]
fn rsa_generate<'py>(
    py: Python<'py>,
    bits: usize,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (private_der, public_der) =
        marty_crypto::rsa::generate_rsa_keypair(bits).map_err(|e| PyErr::from(e))?;
    Ok((
        PyBytes::new(py, &private_der),
        PyBytes::new(py, &public_der),
    ))
}

/// Sign a message with RSA PKCS#1 v1.5 SHA-256 (RS256).
#[pyfunction]
fn rsa_pkcs1_sha256_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::rsa::sign_pkcs1_sha256(private_key_der, message)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with RSA PKCS#1 v1.5 SHA-384 (RS384).
#[pyfunction]
fn rsa_pkcs1_sha384_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::rsa::sign_pkcs1_sha384(private_key_der, message)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with RSA PKCS#1 v1.5 SHA-512 (RS512).
#[pyfunction]
fn rsa_pkcs1_sha512_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::rsa::sign_pkcs1_sha512(private_key_der, message)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with RSA-PSS SHA-256 (PS256).
#[pyfunction]
fn rsa_pss_sha256_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::rsa::sign_pss_sha256(private_key_der, message)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with RSA-PSS SHA-384 (PS384).
#[pyfunction]
fn rsa_pss_sha384_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::rsa::sign_pss_sha384(private_key_der, message)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &signature))
}

/// Sign a message with RSA-PSS SHA-512 (PS512).
#[pyfunction]
fn rsa_pss_sha512_sign<'py>(
    py: Python<'py>,
    private_key_der: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = marty_crypto::rsa::sign_pss_sha512(private_key_der, message)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &signature))
}

/// Verify an RSA PKCS#1 v1.5 SHA-256 signature.
#[pyfunction]
fn rsa_pkcs1_sha256_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pkcs1_sha256(public_key_der, message, signature)
        .map_err(|e| PyErr::from(e))
}

/// Verify an RSA PKCS#1 v1.5 SHA-384 signature.
#[pyfunction]
fn rsa_pkcs1_sha384_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pkcs1_sha384(public_key_der, message, signature)
        .map_err(|e| PyErr::from(e))
}

/// Verify an RSA PKCS#1 v1.5 SHA-512 signature.
#[pyfunction]
fn rsa_pkcs1_sha512_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pkcs1_sha512(public_key_der, message, signature)
        .map_err(|e| PyErr::from(e))
}

/// Verify an RSA-PSS SHA-256 signature.
#[pyfunction]
fn rsa_pss_sha256_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pss_sha256(public_key_der, message, signature)
        .map_err(|e| PyErr::from(e))
}

/// Verify an RSA-PSS SHA-384 signature.
#[pyfunction]
fn rsa_pss_sha384_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pss_sha384(public_key_der, message, signature)
        .map_err(|e| PyErr::from(e))
}

/// Verify an RSA-PSS SHA-512 signature.
#[pyfunction]
fn rsa_pss_sha512_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    marty_crypto::rsa::verify_pss_sha512(public_key_der, message, signature)
        .map_err(|e| PyErr::from(e))
}

// ============================================================================
// Key Generation Bindings
// ============================================================================

/// Generate random bytes.
#[pyfunction]
fn generate_random_bytes<'py>(py: Python<'py>, length: usize) -> Bound<'py, PyBytes> {
    let bytes = marty_crypto::keygen::generate_random_bytes(length);
    PyBytes::new(py, &bytes)
}

/// Generate a cryptographic key.
#[pyfunction]
fn generate_key<'py>(
    py: Python<'py>,
    key_type: &str,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    use marty_crypto::keygen::{generate_keypair, KeyType};

    let kt = match key_type.to_lowercase().as_str() {
        "ed25519" => KeyType::Ed25519,
        "x25519" => KeyType::X25519,
        "p256" | "ecdsa_p256" | "ec_p256" => KeyType::EcdsaP256,
        "p384" | "ecdsa_p384" | "ec_p384" => KeyType::EcdsaP384,
        "rsa2048" => KeyType::Rsa2048,
        "rsa3072" => KeyType::Rsa3072,
        "rsa4096" => KeyType::Rsa4096,
        "aes128" => KeyType::Aes128,
        "aes256" => KeyType::Aes256,
        "hmac256" | "hmac_sha256" => KeyType::HmacSha256,
        "hmac384" | "hmac_sha384" => KeyType::HmacSha384,
        "hmac512" | "hmac_sha512" => KeyType::HmacSha512,
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown key type: {}",
                key_type
            )))
        }
    };

    let key = generate_keypair(kt).map_err(|e| PyErr::from(e))?;
    Ok((
        PyBytes::new(py, &key.private_key),
        PyBytes::new(py, &key.public_key),
    ))
}

// ============================================================================
// JWK/JWS/JWE Bindings
// ============================================================================

/// Python wrapper for JWK.
#[pyclass(name = "Jwk")]
#[derive(Clone)]
pub struct PyJwk {
    inner: crate::jwk::Jwk,
}

#[pymethods]
impl PyJwk {
    /// Get the key type.
    #[getter]
    fn kty(&self) -> String {
        self.inner.kty.clone()
    }

    /// Get the curve (for EC/OKP keys).
    #[getter]
    fn crv(&self) -> Option<String> {
        self.inner.crv.clone()
    }

    /// Get the key ID.
    #[getter]
    fn kid(&self) -> Option<String> {
        self.inner.kid.clone()
    }

    /// Set the key ID.
    #[setter]
    fn set_kid(&mut self, kid: Option<String>) {
        self.inner.kid = kid;
    }

    /// Get the algorithm.
    #[getter]
    fn alg(&self) -> Option<String> {
        self.inner.alg.clone()
    }

    /// Set the algorithm.
    #[setter]
    fn set_alg(&mut self, alg: Option<String>) {
        self.inner.alg = alg;
    }

    /// Check if this is a private key.
    fn is_private(&self) -> bool {
        self.inner.is_private()
    }

    /// Check if this is a symmetric key.
    fn is_symmetric(&self) -> bool {
        self.inner.is_symmetric()
    }

    /// Get the public key portion.
    fn to_public(&self) -> Self {
        Self {
            inner: self.inner.to_public(),
        }
    }

    /// Serialize to JSON.
    fn to_json(&self) -> PyResult<String> {
        self.inner.to_json().map_err(|e| PyErr::from(e))
    }

    /// Parse from JSON.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let inner = crate::jwk::Jwk::from_json(json).map_err(|e| PyErr::from(e))?;
        Ok(Self { inner })
    }

    /// Compute the thumbprint.
    fn thumbprint(&self) -> PyResult<String> {
        self.inner.thumbprint().map_err(|e| PyErr::from(e))
    }

    fn __repr__(&self) -> String {
        format!(
            "Jwk(kty='{}', crv={:?}, kid={:?})",
            self.inner.kty, self.inner.crv, self.inner.kid
        )
    }
}

/// Generate a JWK of the specified type.
#[pyfunction]
fn jwk_generate(key_type: &str) -> PyResult<PyJwk> {
    let inner = match key_type.to_lowercase().as_str() {
        "ec_p256" | "p256" | "es256" => crate::jwk::generate_ec_p256(),
        "ec_p384" | "p384" | "es384" => crate::jwk::generate_ec_p384(),
        "ed25519" | "eddsa" => crate::jwk::generate_ed25519(),
        "x25519" => crate::jwk::generate_x25519(),
        "oct" | "symmetric" => crate::jwk::generate_symmetric(32),
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown key type: {}. Use 'p256', 'p384', 'ed25519', 'x25519', or 'oct'",
                key_type
            )))
        }
    }
    .map_err(|e| PyErr::from(e))?;

    Ok(PyJwk { inner })
}

/// Sign data and create a JWS.
#[pyfunction]
fn jws_sign(payload: &[u8], key: &PyJwk, algorithm: &str) -> PyResult<String> {
    let header = crate::jwk::JwsHeader::new(algorithm);
    crate::jwk::jws_sign(&header, payload, &key.inner).map_err(|e| PyErr::from(e))
}

/// Verify a JWS and return the payload.
#[pyfunction]
fn jws_verify<'py>(py: Python<'py>, jws: &str, key: &PyJwk) -> PyResult<Bound<'py, PyBytes>> {
    let (_, payload) = crate::jwk::jws_verify(jws, &key.inner).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &payload))
}

#[pyfunction]
fn open_badge_ob2_issue(request_json: &str) -> PyResult<String> {
    crate::open_badges::issue_ob2_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn open_badge_ob2_verify(request_json: &str) -> PyResult<String> {
    crate::open_badges::verify_ob2_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn open_badge_ob3_issue(request_json: &str) -> PyResult<String> {
    crate::open_badges::issue_ob3_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn open_badge_ob3_verify(request_json: &str) -> PyResult<String> {
    crate::open_badges::verify_ob3_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Encrypt data and create a JWE.
#[pyfunction]
fn jwe_encrypt(plaintext: &[u8], recipient_key: &PyJwk, encryption: &str) -> PyResult<String> {
    crate::jwk::jwe_encrypt_direct(plaintext, &recipient_key.inner, encryption)
        .map_err(|e| PyErr::from(e))
}

/// Decrypt a JWE.
#[pyfunction]
fn jwe_decrypt<'py>(py: Python<'py>, jwe: &str, key: &PyJwk) -> PyResult<Bound<'py, PyBytes>> {
    let plaintext = crate::jwk::jwe_decrypt(jwe, &key.inner).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &plaintext))
}

// ============================================================================
// Ed448 Bindings
// ============================================================================

/// Generate an Ed448 key pair.
///
/// Returns:
///     Tuple of (private_key_bytes, public_key_bytes)
#[pyfunction]
fn ed448_generate<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (private_key, public_key) =
        marty_crypto::ed448::ed448_generate().map_err(|e| PyErr::from(e))?;
    Ok((
        PyBytes::new(py, &private_key),
        PyBytes::new(py, &public_key),
    ))
}

/// Sign a message using Ed448.
///
/// Args:
///     private_key: 57-byte private key
///     message: Message to sign
///
/// Returns:
///     114-byte signature
#[pyfunction]
fn ed448_sign<'py>(
    py: Python<'py>,
    private_key: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature =
        marty_crypto::ed448::ed448_sign(private_key, message).map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &signature))
}

/// Verify an Ed448 signature.
///
/// Args:
///     public_key: 57-byte public key
///     message: Message that was signed
///     signature: 114-byte signature
///
/// Returns:
///     True if signature is valid
#[pyfunction]
fn ed448_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    marty_crypto::ed448::ed448_verify(public_key, message, signature).map_err(|e| PyErr::from(e))
}

// ============================================================================
// PKCS#12 Bindings
// ============================================================================

/// Parsed PKCS#12 data.
#[pyclass(name = "Pkcs12Data")]
#[derive(Clone)]
pub struct PyPkcs12Data {
    #[pyo3(get)]
    pub private_key_algorithm: String,
    #[pyo3(get)]
    pub certificate_subject: Option<String>,
    #[pyo3(get)]
    pub friendly_name: Option<String>,
    #[pyo3(get)]
    pub chain_length: usize,
    private_key_der: Vec<u8>,
    certificate_der: Vec<u8>,
    certificate_chain: Vec<Vec<u8>>,
}

#[pymethods]
impl PyPkcs12Data {
    /// Get the private key in DER format.
    fn private_key_der<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.private_key_der)
    }

    /// Get the private key in PEM format.
    fn private_key_pem(&self) -> PyResult<String> {
        pem_rfc7468::encode_string(
            "PRIVATE KEY",
            pem_rfc7468::LineEnding::LF,
            &self.private_key_der,
        )
        .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to encode PEM: {}", e))
        })
    }

    /// Get the certificate in DER format.
    fn certificate_der<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.certificate_der)
    }

    /// Get the certificate in PEM format.
    fn certificate_pem(&self) -> PyResult<String> {
        pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::LF,
            &self.certificate_der,
        )
        .map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to encode PEM: {}", e))
        })
    }

    /// Get the certificate chain in PEM format.
    fn chain_pem(&self) -> PyResult<Vec<String>> {
        let mut result = vec![self.certificate_pem()?];
        for cert in &self.certificate_chain {
            let pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, cert)
                .map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Failed to encode PEM: {}", e))
                })?;
            result.push(pem);
        }
        Ok(result)
    }

    fn __repr__(&self) -> String {
        format!(
            "Pkcs12Data(algorithm={}, subject={:?}, chain_length={})",
            self.private_key_algorithm, self.certificate_subject, self.chain_length
        )
    }
}

/// Parse a PKCS#12 (PFX) file.
///
/// Args:
///     data: Raw PKCS#12 file bytes
///     password: Password to decrypt the file
///
/// Returns:
///     Pkcs12Data with private key, certificate, and chain
#[pyfunction]
fn pkcs12_parse(data: &[u8], password: &str) -> PyResult<PyPkcs12Data> {
    let parsed = marty_crypto::pkcs12::parse_pkcs12(data, password).map_err(|e| PyErr::from(e))?;

    Ok(PyPkcs12Data {
        private_key_algorithm: parsed.private_key_algorithm.to_string(),
        certificate_subject: parsed.certificate_subject,
        friendly_name: parsed.friendly_name,
        chain_length: parsed.certificate_chain.len() + 1,
        private_key_der: parsed.private_key_der,
        certificate_der: parsed.certificate_der,
        certificate_chain: parsed.certificate_chain,
    })
}

// ============================================================================
// ISO 9796-2 Bindings
// ============================================================================

/// Verify an ISO 9796-2 signature.
///
/// Args:
///     public_key_der: DER-encoded RSA public key
///     message: Message that was signed
///     signature: Signature to verify
///     scheme: Scheme number (1, 2, or 3)
///     hash_alg: Hash algorithm ("sha1", "sha256", "sha384", "sha512")
///
/// Returns:
///     True if signature is valid
#[pyfunction]
#[pyo3(signature = (public_key_der, message, signature, scheme=2, hash_alg="sha256"))]
fn iso9796_verify(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
    scheme: u8,
    hash_alg: &str,
) -> PyResult<bool> {
    use marty_crypto::iso9796::{Iso9796HashAlgorithm, Iso9796Scheme};

    let scheme = match scheme {
        1 => Iso9796Scheme::Scheme1,
        2 => Iso9796Scheme::Scheme2,
        3 => Iso9796Scheme::Scheme3,
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Scheme must be 1, 2, or 3",
            ))
        }
    };

    let hash_alg = match hash_alg.to_lowercase().as_str() {
        "sha1" => Iso9796HashAlgorithm::Sha1,
        "sha224" => Iso9796HashAlgorithm::Sha224,
        "sha256" => Iso9796HashAlgorithm::Sha256,
        "sha384" => Iso9796HashAlgorithm::Sha384,
        "sha512" => Iso9796HashAlgorithm::Sha512,
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Hash algorithm must be sha1, sha224, sha256, sha384, or sha512",
            ))
        }
    };

    marty_crypto::iso9796::iso9796_verify(public_key_der, message, signature, scheme, hash_alg)
        .map_err(|e| PyErr::from(e))
}

/// Recover message from an ISO 9796-2 signature.
///
/// Args:
///     public_key_der: DER-encoded RSA public key
///     signature: Signature to recover from
///     scheme: Scheme number (1, 2, or 3)
///     hash_alg: Hash algorithm (optional, required for scheme 2/3)
///
/// Returns:
///     Recovered message portion
#[pyfunction]
#[pyo3(signature = (public_key_der, signature, scheme=2, hash_alg=None))]
fn iso9796_recover<'py>(
    py: Python<'py>,
    public_key_der: &[u8],
    signature: &[u8],
    scheme: u8,
    hash_alg: Option<&str>,
) -> PyResult<Bound<'py, PyBytes>> {
    use marty_crypto::iso9796::{Iso9796HashAlgorithm, Iso9796Scheme};

    let scheme = match scheme {
        1 => Iso9796Scheme::Scheme1,
        2 => Iso9796Scheme::Scheme2,
        3 => Iso9796Scheme::Scheme3,
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Scheme must be 1, 2, or 3",
            ))
        }
    };

    let hash_alg = hash_alg
        .map(|h| match h.to_lowercase().as_str() {
            "sha1" => Ok(Iso9796HashAlgorithm::Sha1),
            "sha224" => Ok(Iso9796HashAlgorithm::Sha224),
            "sha256" => Ok(Iso9796HashAlgorithm::Sha256),
            "sha384" => Ok(Iso9796HashAlgorithm::Sha384),
            "sha512" => Ok(Iso9796HashAlgorithm::Sha512),
            _ => Err(pyo3::exceptions::PyValueError::new_err(
                "Hash algorithm must be sha1, sha224, sha256, sha384, or sha512",
            )),
        })
        .transpose()?;

    let recovered = marty_crypto::iso9796::iso9796_recover_message(
        public_key_der,
        signature,
        scheme,
        hash_alg,
    )
    .map_err(|e| PyErr::from(e))?;

    Ok(PyBytes::new(py, &recovered))
}

// ============================================================================
// OCSP Client Bindings
// ============================================================================

/// Build an OCSP request for a certificate.
///
/// Args:
///     cert_der: DER-encoded certificate to check
///     issuer_cert_der: DER-encoded issuer certificate
///
/// Returns:
///     DER-encoded OCSP request
#[pyfunction]
fn build_ocsp_request<'py>(
    py: Python<'py>,
    cert_der: &[u8],
    issuer_cert_der: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let request = marty_crypto::ocsp::build_ocsp_request(cert_der, issuer_cert_der)
        .map_err(|e| PyErr::from(e))?;
    Ok(PyBytes::new(py, &request))
}

/// Extract OCSP responder URL from a certificate.
///
/// Args:
///     cert_der: DER-encoded certificate
///
/// Returns:
///     OCSP responder URL if present, None otherwise
#[pyfunction]
fn get_ocsp_responder_url(cert_der: &[u8]) -> PyResult<Option<String>> {
    marty_crypto::ocsp::get_ocsp_responder_url(cert_der).map_err(|e| PyErr::from(e))
}

/// Parse an OCSP response.
///
/// Args:
///     response_der: DER-encoded OCSP response
///
/// Returns:
///     Dictionary with response information
#[pyfunction]
fn parse_ocsp_response(py: Python<'_>, response_der: &[u8]) -> PyResult<Py<PyDict>> {
    let info =
        marty_crypto::ocsp::parse_ocsp_response(response_der).map_err(|e| PyErr::from(e))?;

    let dict = PyDict::new(py);
    dict.set_item("response_status", format!("{:?}", info.response_status))?;
    dict.set_item("this_update", info.this_update)?;
    dict.set_item("next_update", info.next_update)?;
    dict.set_item("responder_id", info.responder_id)?;
    dict.set_item("produced_at", info.produced_at)?;

    if let Some(status) = info.cert_status {
        match status {
            marty_crypto::ocsp::OcspCertStatus::Good => {
                dict.set_item("cert_status", "good")?;
            }
            marty_crypto::ocsp::OcspCertStatus::Revoked {
                revocation_time,
                reason,
            } => {
                dict.set_item("cert_status", "revoked")?;
                dict.set_item("revocation_time", revocation_time)?;
                dict.set_item("revocation_reason", reason)?;
            }
            marty_crypto::ocsp::OcspCertStatus::Unknown => {
                dict.set_item("cert_status", "unknown")?;
            }
        }
    }

    Ok(dict.into())
}

// ============================================================================
// Certificate Builder Bindings (feature-gated)
// ============================================================================

/// Python-friendly certificate profile enum.
#[cfg(feature = "cert-builder")]
#[pyclass(name = "CertProfile")]
#[derive(Clone)]
pub struct PyCertProfile {
    inner: marty_crypto::cert_builder::CertProfile,
}

#[cfg(feature = "cert-builder")]
#[pymethods]
impl PyCertProfile {
    /// Create a CA profile with optional path length constraint.
    #[staticmethod]
    fn ca(path_length: Option<u8>) -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::Ca { path_length },
        }
    }

    /// Create a SubCA profile with path length constraint.
    #[staticmethod]
    fn sub_ca(path_length: u8) -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::SubCa { path_length },
        }
    }

    /// Create an EndEntity (leaf) profile.
    #[staticmethod]
    fn end_entity() -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::EndEntity,
        }
    }

    /// Create a CSCA profile for eMRTD.
    #[staticmethod]
    fn csca(country_code: &str) -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::Csca {
                country_code: country_code.to_string(),
            },
        }
    }

    /// Create an IACA profile for mDL.
    #[staticmethod]
    fn iaca(jurisdiction: &str) -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::Iaca {
                jurisdiction: jurisdiction.to_string(),
            },
        }
    }

    /// Create a DSC profile for eMRTD document signer.
    #[staticmethod]
    fn dsc(country_code: &str) -> Self {
        Self {
            inner: marty_crypto::cert_builder::CertProfile::Dsc {
                country_code: country_code.to_string(),
            },
        }
    }

    fn __repr__(&self) -> String {
        format!("CertProfile({:?})", self.inner)
    }
}

/// Python-friendly certificate builder configuration.
#[cfg(feature = "cert-builder")]
#[pyclass(name = "CertificateBuilderConfig")]
#[derive(Clone)]
pub struct PyCertificateBuilderConfig {
    subject_cn: Option<String>,
    subject_country: Option<String>,
    subject_org: Option<String>,
    subject_ou: Option<String>,
    issuer_cn: Option<String>,
    validity_days: u32,
    profile: marty_crypto::cert_builder::CertProfile,
    key_type: String,
}

#[cfg(feature = "cert-builder")]
#[pymethods]
impl PyCertificateBuilderConfig {
    /// Create a new certificate builder configuration with defaults.
    #[new]
    fn new() -> Self {
        Self {
            subject_cn: None,
            subject_country: None,
            subject_org: None,
            subject_ou: None,
            issuer_cn: None,
            validity_days: 365,
            profile: marty_crypto::cert_builder::CertProfile::EndEntity,
            key_type: "ecdsa-p256".to_string(),
        }
    }

    /// Set the subject Common Name.
    fn subject_cn(&mut self, cn: &str) -> Self {
        self.subject_cn = Some(cn.to_string());
        self.clone()
    }

    /// Set the subject Country.
    fn subject_country(&mut self, country: &str) -> Self {
        self.subject_country = Some(country.to_string());
        self.clone()
    }

    /// Set the subject Organization.
    fn subject_org(&mut self, org: &str) -> Self {
        self.subject_org = Some(org.to_string());
        self.clone()
    }

    /// Set the subject Organizational Unit.
    fn subject_ou(&mut self, ou: &str) -> Self {
        self.subject_ou = Some(ou.to_string());
        self.clone()
    }

    /// Set the issuer Common Name (for self-signed, this is optional).
    fn issuer_cn(&mut self, cn: &str) -> Self {
        self.issuer_cn = Some(cn.to_string());
        self.clone()
    }

    /// Set the validity period in days from now.
    fn validity_days(&mut self, days: u32) -> Self {
        self.validity_days = days;
        self.clone()
    }

    /// Set the certificate profile.
    fn profile(&mut self, profile: &PyCertProfile) -> Self {
        self.profile = profile.inner.clone();
        self.clone()
    }

    /// Set the key type: "ecdsa-p256", "ecdsa-p384", "rsa2048", "rsa3072", "rsa4096", "ed25519".
    fn key_type(&mut self, key_type: &str) -> Self {
        self.key_type = key_type.to_string();
        self.clone()
    }

    /// Build a self-signed certificate.
    ///
    /// Returns:
    ///     Tuple of (certificate_der_bytes, private_key_pem_str)
    fn build_self_signed<'py>(&self, py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, String)> {
        use marty_crypto::cert_builder::{CertificateBuilderConfig, DistinguishedName};
        use marty_crypto::keygen::KeyType;

        // Build distinguished name
        let mut subject = DistinguishedName::new();
        if let Some(cn) = &self.subject_cn {
            subject = subject.cn(cn);
        }
        if let Some(c) = &self.subject_country {
            subject = subject.country(c);
        }
        if let Some(o) = &self.subject_org {
            subject = subject.organization(o);
        }
        if let Some(ou) = &self.subject_ou {
            subject = subject.organizational_unit(ou);
        }

        // Parse key type
        let key_type = match self.key_type.to_lowercase().as_str() {
            "ecdsa-p256" | "p256" | "ec-p256" => KeyType::EcdsaP256,
            "ecdsa-p384" | "p384" | "ec-p384" => KeyType::EcdsaP384,
            "rsa2048" | "rsa-2048" => KeyType::Rsa2048,
            "rsa3072" | "rsa-3072" => KeyType::Rsa3072,
            "rsa4096" | "rsa-4096" => KeyType::Rsa4096,
            "ed25519" => KeyType::Ed25519,
            _ => return Err(pyo3::exceptions::PyValueError::new_err(
                format!("Unsupported key type: {}. Use: ecdsa-p256, ecdsa-p384, rsa2048, rsa3072, rsa4096, ed25519", self.key_type)
            )),
        };

        // Build the certificate
        let config = CertificateBuilderConfig::new()
            .subject(subject)
            .validity_days(self.validity_days)
            .profile(self.profile.clone())
            .key_type(key_type);

        let (cert_der, key_pem) = config.build_self_signed().map_err(|e| PyErr::from(e))?;

        Ok((PyBytes::new(py, &cert_der), key_pem))
    }

    /// Build a certificate signed by an issuer CA.
    ///
    /// Args:
    ///     issuer_cert_der: DER-encoded issuer certificate
    ///     issuer_key_pem: PEM-encoded issuer private key
    ///
    /// Returns:
    ///     Tuple of (certificate_der_bytes, private_key_pem_str)
    fn build_signed_by<'py>(
        &self,
        py: Python<'py>,
        issuer_cert_der: &[u8],
        issuer_key_pem: &str,
    ) -> PyResult<(Bound<'py, PyBytes>, String)> {
        use marty_crypto::cert_builder::{CertificateBuilderConfig, DistinguishedName};
        use marty_crypto::keygen::KeyType;

        // Build distinguished name
        let mut subject = DistinguishedName::new();
        if let Some(cn) = &self.subject_cn {
            subject = subject.cn(cn);
        }
        if let Some(c) = &self.subject_country {
            subject = subject.country(c);
        }
        if let Some(o) = &self.subject_org {
            subject = subject.organization(o);
        }
        if let Some(ou) = &self.subject_ou {
            subject = subject.organizational_unit(ou);
        }

        // Parse key type
        let key_type = match self.key_type.to_lowercase().as_str() {
            "ecdsa-p256" | "p256" | "ec-p256" => KeyType::EcdsaP256,
            "ecdsa-p384" | "p384" | "ec-p384" => KeyType::EcdsaP384,
            "rsa2048" | "rsa-2048" => KeyType::Rsa2048,
            "rsa3072" | "rsa-3072" => KeyType::Rsa3072,
            "rsa4096" | "rsa-4096" => KeyType::Rsa4096,
            "ed25519" => KeyType::Ed25519,
            _ => return Err(pyo3::exceptions::PyValueError::new_err(
                format!("Unsupported key type: {}. Use: ecdsa-p256, ecdsa-p384, rsa2048, rsa3072, rsa4096, ed25519", self.key_type)
            )),
        };

        // Build the certificate
        let config = CertificateBuilderConfig::new()
            .subject(subject)
            .validity_days(self.validity_days)
            .profile(self.profile.clone())
            .key_type(key_type);

        let (cert_der, key_pem) = config
            .build_signed_by(issuer_cert_der, issuer_key_pem)
            .map_err(|e| PyErr::from(e))?;

        Ok((PyBytes::new(py, &cert_der), key_pem))
    }

    /// Build a self-signed certificate from an existing private key.
    ///
    /// Args:
    ///     private_key_pem: PEM-encoded private key
    ///
    /// Returns:
    ///     DER-encoded certificate bytes
    fn build_self_signed_with_key<'py>(
        &self,
        py: Python<'py>,
        private_key_pem: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        use marty_crypto::cert_builder::{CertificateBuilderConfig, DistinguishedName};
        use marty_crypto::keygen::KeyType;

        // Build distinguished name
        let mut subject = DistinguishedName::new();
        if let Some(cn) = &self.subject_cn {
            subject = subject.cn(cn);
        }
        if let Some(c) = &self.subject_country {
            subject = subject.country(c);
        }
        if let Some(o) = &self.subject_org {
            subject = subject.organization(o);
        }
        if let Some(ou) = &self.subject_ou {
            subject = subject.organizational_unit(ou);
        }

        // Parse key type
        let key_type = match self.key_type.to_lowercase().as_str() {
            "ecdsa-p256" | "p256" | "ec-p256" => KeyType::EcdsaP256,
            "ecdsa-p384" | "p384" | "ec-p384" => KeyType::EcdsaP384,
            "rsa2048" | "rsa-2048" => KeyType::Rsa2048,
            "rsa3072" | "rsa-3072" => KeyType::Rsa3072,
            "rsa4096" | "rsa-4096" => KeyType::Rsa4096,
            "ed25519" => KeyType::Ed25519,
            _ => return Err(pyo3::exceptions::PyValueError::new_err(
                format!("Unsupported key type: {}. Use: ecdsa-p256, ecdsa-p384, rsa2048, rsa3072, rsa4096, ed25519", self.key_type)
            )),
        };

        // Build the certificate
        let config = CertificateBuilderConfig::new()
            .subject(subject)
            .validity_days(self.validity_days)
            .profile(self.profile.clone())
            .key_type(key_type);

        let cert_der = config
            .build_self_signed_with_key(private_key_pem)
            .map_err(|e| PyErr::from(e))?;

        Ok(PyBytes::new(py, &cert_der))
    }

    fn __repr__(&self) -> String {
        format!(
            "CertificateBuilderConfig(subject_cn={:?}, validity_days={}, key_type={})",
            self.subject_cn, self.validity_days, self.key_type
        )
    }
}

/// Create a self-signed certificate with the given parameters.
///
/// This is a convenience function for simple certificate generation.
///
/// Args:
///     common_name: Subject Common Name
///     validity_days: Certificate validity in days (default: 365)
///     key_type: Key type (default: "ecdsa-p256")
///     is_ca: Whether this is a CA certificate (default: False)
///     country: Subject country code (optional)
///     organization: Subject organization (optional)
///
/// Returns:
///     Tuple of (certificate_der_bytes, private_key_pem_str)
#[cfg(feature = "cert-builder")]
#[pyfunction]
fn build_self_signed_certificate<'py>(
    py: Python<'py>,
    common_name: &str,
    validity_days: Option<u32>,
    key_type: Option<&str>,
    is_ca: Option<bool>,
    country: Option<&str>,
    organization: Option<&str>,
) -> PyResult<(Bound<'py, PyBytes>, String)> {
    use marty_crypto::cert_builder::{CertProfile, CertificateBuilderConfig, DistinguishedName};
    use marty_crypto::keygen::KeyType;

    let validity_days = validity_days.unwrap_or(365);
    let key_type_str = key_type.unwrap_or("ecdsa-p256");
    let is_ca = is_ca.unwrap_or(false);

    // Build distinguished name
    let mut subject = DistinguishedName::new().cn(common_name);
    if let Some(c) = country {
        subject = subject.country(c);
    }
    if let Some(o) = organization {
        subject = subject.organization(o);
    }

    // Parse key type
    let key_type = match key_type_str.to_lowercase().as_str() {
        "ecdsa-p256" | "p256" | "ec-p256" => KeyType::EcdsaP256,
        "ecdsa-p384" | "p384" | "ec-p384" => KeyType::EcdsaP384,
        "rsa2048" | "rsa-2048" => KeyType::Rsa2048,
        "rsa3072" | "rsa-3072" => KeyType::Rsa3072,
        "rsa4096" | "rsa-4096" => KeyType::Rsa4096,
        "ed25519" => KeyType::Ed25519,
        _ => return Err(pyo3::exceptions::PyValueError::new_err(
            format!("Unsupported key type: {}. Use: ecdsa-p256, ecdsa-p384, rsa2048, rsa3072, rsa4096, ed25519", key_type_str)
        )),
    };

    // Determine profile
    let profile = if is_ca {
        CertProfile::Ca { path_length: None }
    } else {
        CertProfile::EndEntity
    };

    // Build the certificate
    let config = CertificateBuilderConfig::new()
        .subject(subject)
        .validity_days(validity_days)
        .profile(profile)
        .key_type(key_type);

    let (cert_der, key_pem) = config.build_self_signed().map_err(|e| PyErr::from(e))?;

    Ok((PyBytes::new(py, &cert_der), key_pem))
}

/// Create a self-signed certificate using an existing private key.
///
/// Args:
///     private_key_pem: PEM-encoded private key
///     common_name: Subject Common Name
///     validity_days: Certificate validity in days (default: 365)
///     key_type: Key type hint (required if key type cannot be auto-detected)
///     is_ca: Whether this is a CA certificate (default: False)
///     country: Subject country code (optional)
///     organization: Subject organization (optional)
///
/// Returns:
///     DER-encoded certificate bytes
#[cfg(feature = "cert-builder")]
#[pyfunction]
fn build_self_signed_certificate_with_key<'py>(
    py: Python<'py>,
    private_key_pem: &str,
    common_name: &str,
    validity_days: Option<u32>,
    key_type: Option<&str>,
    is_ca: Option<bool>,
    country: Option<&str>,
    organization: Option<&str>,
) -> PyResult<Bound<'py, PyBytes>> {
    use marty_crypto::cert_builder::{CertProfile, CertificateBuilderConfig, DistinguishedName};
    use marty_crypto::keygen::KeyType;

    let validity_days = validity_days.unwrap_or(365);
    let is_ca = is_ca.unwrap_or(false);

    // Build distinguished name
    let mut subject = DistinguishedName::new().cn(common_name);
    if let Some(c) = country {
        subject = subject.country(c);
    }
    if let Some(o) = organization {
        subject = subject.organization(o);
    }

    // Auto-detect or use provided key type
    let key_type = if let Some(kt) = key_type {
        match kt.to_lowercase().as_str() {
            "ecdsa-p256" | "p256" | "ec-p256" => KeyType::EcdsaP256,
            "ecdsa-p384" | "p384" | "ec-p384" => KeyType::EcdsaP384,
            "rsa2048" | "rsa-2048" => KeyType::Rsa2048,
            "rsa3072" | "rsa-3072" => KeyType::Rsa3072,
            "rsa4096" | "rsa-4096" => KeyType::Rsa4096,
            "ed25519" => KeyType::Ed25519,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Unsupported key type: {}",
                    kt
                )))
            }
        }
    } else {
        // Try to auto-detect from PEM
        if private_key_pem.contains("EC PRIVATE KEY") || private_key_pem.len() < 500 {
            KeyType::EcdsaP256
        } else if private_key_pem.contains("RSA PRIVATE KEY") || private_key_pem.len() > 1000 {
            KeyType::Rsa2048
        } else if private_key_pem.contains("ED25519") {
            KeyType::Ed25519
        } else {
            KeyType::EcdsaP256 // Default fallback
        }
    };

    // Determine profile
    let profile = if is_ca {
        CertProfile::Ca { path_length: None }
    } else {
        CertProfile::EndEntity
    };

    // Build the certificate
    let config = CertificateBuilderConfig::new()
        .subject(subject)
        .validity_days(validity_days)
        .profile(profile)
        .key_type(key_type);

    let cert_der = config
        .build_self_signed_with_key(private_key_pem)
        .map_err(|e| PyErr::from(e))?;

    Ok(PyBytes::new(py, &cert_der))
}

#[pyfunction]
fn dtc_create(request_json: &str) -> PyResult<String> {
    dtc::create_dtc_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn dtc_sign(dtc_json: &str) -> PyResult<String> {
    dtc::sign_dtc_json(dtc_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn dtc_verify(dtc_json: &str) -> PyResult<String> {
    dtc::verify_dtc_json(dtc_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

/// Create the Python module for marty_verification.
#[pymodule]
pub fn marty_verification(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // MDL Verification
    m.add_class::<PyMdlVerificationResult>()?;
    m.add_class::<PyIacaRegistry>()?;
    m.add_class::<PyValidationConfig>()?;
    m.add_function(wrap_pyfunction!(verify_mdl_x5chain, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mdl_x5chain_cbor, m)?)?;

    // MRZ Parsing
    m.add_class::<PyMrzData>()?;
    m.add_function(wrap_pyfunction!(parse_mrz, m)?)?;
    m.add_function(wrap_pyfunction!(compute_check_digit, m)?)?;
    m.add_function(wrap_pyfunction!(validate_check_digit, m)?)?;

    // CRL Checking
    m.add_class::<PyCrlInfo>()?;
    m.add_class::<PyRevokedCertificate>()?;
    m.add_function(wrap_pyfunction!(parse_crl, m)?)?;
    m.add_function(wrap_pyfunction!(check_certificate_revocation, m)?)?;

    // Crypto Operations - Base
    m.add_function(wrap_pyfunction!(hash_data, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;

    // Crypto Operations - Ed448
    m.add_function(wrap_pyfunction!(ed448_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ed448_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed448_verify, m)?)?;

    // Crypto Operations - PKCS#12
    m.add_class::<PyPkcs12Data>()?;
    m.add_function(wrap_pyfunction!(pkcs12_parse, m)?)?;

    // Crypto Operations - ISO 9796-2
    m.add_function(wrap_pyfunction!(iso9796_verify, m)?)?;
    m.add_function(wrap_pyfunction!(iso9796_recover, m)?)?;

    // Crypto Operations - Certificate
    m.add_function(wrap_pyfunction!(load_certificate_pem, m)?)?;
    m.add_function(wrap_pyfunction!(load_certificate_der, m)?)?;
    m.add_function(wrap_pyfunction!(get_certificate_info, m)?)?;
    m.add_function(wrap_pyfunction!(certificate_pem_to_der, m)?)?;
    m.add_function(wrap_pyfunction!(certificate_der_to_pem, m)?)?;
    m.add_function(wrap_pyfunction!(get_certificate_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(is_certificate_expired, m)?)?;
    m.add_function(wrap_pyfunction!(is_certificate_not_yet_valid, m)?)?;
    m.add_function(wrap_pyfunction!(verify_certificate_signature, m)?)?;

    // Crypto Operations - Key Serialization
    m.add_function(wrap_pyfunction!(load_private_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(load_private_key_der, m)?)?;
    m.add_function(wrap_pyfunction!(save_private_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(load_public_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(load_public_key_der, m)?)?;
    m.add_function(wrap_pyfunction!(save_public_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(extract_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(detect_private_key_type, m)?)?;
    m.add_function(wrap_pyfunction!(detect_public_key_type, m)?)?;
    m.add_function(wrap_pyfunction!(get_key_size, m)?)?;
    m.add_function(wrap_pyfunction!(raw_private_key_to_pkcs8, m)?)?;
    m.add_function(wrap_pyfunction!(raw_public_key_to_spki, m)?)?;
    m.add_function(wrap_pyfunction!(pkcs8_to_raw_private_key, m)?)?;
    m.add_function(wrap_pyfunction!(spki_to_raw_public_key, m)?)?;

    // Crypto Operations - KDF
    m.add_function(wrap_pyfunction!(hkdf_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_sha384, m)?)?;
    m.add_function(wrap_pyfunction!(pbkdf2_sha256, m)?)?;

    // Crypto Operations - Symmetric Encryption
    m.add_function(wrap_pyfunction!(aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(tdes_cbc_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(tdes_cbc_decrypt, m)?)?;

    // Crypto Operations - Ed25519
    m.add_function(wrap_pyfunction!(ed25519_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;

    // Crypto Operations - ECDH Key Agreement
    m.add_function(wrap_pyfunction!(x25519_generate, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_agree, m)?)?;
    m.add_function(wrap_pyfunction!(p256_generate, m)?)?;
    m.add_function(wrap_pyfunction!(p256_agree, m)?)?;

    // Crypto Operations - ECDSA Signing
    m.add_function(wrap_pyfunction!(ecdsa_p256_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p384_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p521_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p256_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p384_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p521_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p384_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p521_verify, m)?)?;

    // Crypto Operations - RSA Signing
    m.add_function(wrap_pyfunction!(rsa_generate, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha256_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha384_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha512_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha256_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha384_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha512_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha384_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha512_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha384_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha512_verify, m)?)?;

    // Crypto Operations - Key Generation
    m.add_function(wrap_pyfunction!(generate_random_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;

    // JWK/JWS/JWE
    m.add_class::<PyJwk>()?;
    m.add_function(wrap_pyfunction!(jwk_generate, m)?)?;
    m.add_function(wrap_pyfunction!(jws_sign, m)?)?;
    m.add_function(wrap_pyfunction!(jws_verify, m)?)?;
    m.add_function(wrap_pyfunction!(jwe_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(jwe_decrypt, m)?)?;

    // mDL Document Parsing
    m.add_class::<PyDeviceResponse>()?;
    m.add_function(wrap_pyfunction!(parse_device_response, m)?)?;

    // Certificate Chain Validation
    m.add_class::<PyChainValidationResult>()?;
    m.add_class::<PyChainValidator>()?;

    // Ed448 Operations
    m.add_function(wrap_pyfunction!(ed448_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ed448_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed448_verify, m)?)?;

    // PKCS#12 Operations
    m.add_class::<PyPkcs12Data>()?;
    m.add_function(wrap_pyfunction!(pkcs12_parse, m)?)?;

    // ISO 9796-2 Operations
    m.add_function(wrap_pyfunction!(iso9796_verify, m)?)?;
    m.add_function(wrap_pyfunction!(iso9796_recover, m)?)?;

    // OCSP Operations
    m.add_function(wrap_pyfunction!(build_ocsp_request, m)?)?;
    m.add_function(wrap_pyfunction!(get_ocsp_responder_url, m)?)?;
    m.add_function(wrap_pyfunction!(parse_ocsp_response, m)?)?;

    // Open Badges
    m.add_function(wrap_pyfunction!(open_badge_ob2_issue, m)?)?;
    m.add_function(wrap_pyfunction!(open_badge_ob2_verify, m)?)?;
    m.add_function(wrap_pyfunction!(open_badge_ob3_issue, m)?)?;
    m.add_function(wrap_pyfunction!(open_badge_ob3_verify, m)?)?;

    // DTC helpers (JSON in/out)
    m.add_function(wrap_pyfunction!(dtc_create, m)?)?;
    m.add_function(wrap_pyfunction!(dtc_sign, m)?)?;
    m.add_function(wrap_pyfunction!(dtc_verify, m)?)?;


    // Certificate Builder Operations (feature-gated)
    #[cfg(feature = "cert-builder")]
    {
        m.add_class::<PyCertProfile>()?;
        m.add_class::<PyCertificateBuilderConfig>()?;
        m.add_function(wrap_pyfunction!(build_self_signed_certificate, m)?)?;
        m.add_function(wrap_pyfunction!(build_self_signed_certificate_with_key, m)?)?;
    }

    // Add constants
    m.add("RULESET_MDL", "mdl")?;
    m.add("RULESET_AAMVA_MDL", "aamva_mdl")?;
    m.add("RULESET_MDL_READER", "mdl_reader")?;

    Ok(())
}

/// Register marty-verification functions in a parent module.
///
/// Called from marty-rs to add verification functions directly.
pub fn register_marty_verification(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // MDL Verification
    m.add_class::<PyMdlVerificationResult>()?;
    m.add_class::<PyIacaRegistry>()?;
    m.add_class::<PyValidationConfig>()?;
    m.add_function(wrap_pyfunction!(verify_mdl_x5chain, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mdl_x5chain_cbor, m)?)?;

    // MRZ Parsing
    m.add_class::<PyMrzData>()?;
    m.add_function(wrap_pyfunction!(parse_mrz, m)?)?;
    m.add_function(wrap_pyfunction!(compute_check_digit, m)?)?;
    m.add_function(wrap_pyfunction!(validate_check_digit, m)?)?;

    // CRL Checking
    m.add_class::<PyCrlInfo>()?;
    m.add_class::<PyRevokedCertificate>()?;
    m.add_function(wrap_pyfunction!(parse_crl, m)?)?;
    m.add_function(wrap_pyfunction!(check_certificate_revocation, m)?)?;

    // Crypto Operations - Base
    m.add_function(wrap_pyfunction!(hash_data, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;

    // Crypto Operations - Ed448
    m.add_function(wrap_pyfunction!(ed448_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ed448_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed448_verify, m)?)?;

    // Crypto Operations - PKCS#12
    m.add_class::<PyPkcs12Data>()?;
    m.add_function(wrap_pyfunction!(pkcs12_parse, m)?)?;

    // Crypto Operations - ISO 9796-2
    m.add_function(wrap_pyfunction!(iso9796_verify, m)?)?;
    m.add_function(wrap_pyfunction!(iso9796_recover, m)?)?;

    // Crypto Operations - Certificate
    m.add_function(wrap_pyfunction!(load_certificate_pem, m)?)?;
    m.add_function(wrap_pyfunction!(load_certificate_der, m)?)?;
    m.add_function(wrap_pyfunction!(get_certificate_info, m)?)?;
    m.add_function(wrap_pyfunction!(certificate_pem_to_der, m)?)?;
    m.add_function(wrap_pyfunction!(certificate_der_to_pem, m)?)?;
    m.add_function(wrap_pyfunction!(get_certificate_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(is_certificate_expired, m)?)?;
    m.add_function(wrap_pyfunction!(is_certificate_not_yet_valid, m)?)?;
    m.add_function(wrap_pyfunction!(verify_certificate_signature, m)?)?;

    // Crypto Operations - Key Serialization
    m.add_function(wrap_pyfunction!(load_private_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(load_private_key_der, m)?)?;
    m.add_function(wrap_pyfunction!(save_private_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(load_public_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(load_public_key_der, m)?)?;
    m.add_function(wrap_pyfunction!(save_public_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(extract_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(detect_private_key_type, m)?)?;
    m.add_function(wrap_pyfunction!(detect_public_key_type, m)?)?;
    m.add_function(wrap_pyfunction!(get_key_size, m)?)?;
    m.add_function(wrap_pyfunction!(raw_private_key_to_pkcs8, m)?)?;
    m.add_function(wrap_pyfunction!(raw_public_key_to_spki, m)?)?;
    m.add_function(wrap_pyfunction!(pkcs8_to_raw_private_key, m)?)?;
    m.add_function(wrap_pyfunction!(spki_to_raw_public_key, m)?)?;

    // Crypto Operations - KDF
    m.add_function(wrap_pyfunction!(hkdf_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_sha384, m)?)?;
    m.add_function(wrap_pyfunction!(pbkdf2_sha256, m)?)?;

    // Crypto Operations - Symmetric Encryption
    m.add_function(wrap_pyfunction!(aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(tdes_cbc_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(tdes_cbc_decrypt, m)?)?;

    // Crypto Operations - Ed25519
    m.add_function(wrap_pyfunction!(ed25519_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;

    // Crypto Operations - ECDH Key Agreement
    m.add_function(wrap_pyfunction!(x25519_generate, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_agree, m)?)?;
    m.add_function(wrap_pyfunction!(p256_generate, m)?)?;
    m.add_function(wrap_pyfunction!(p256_agree, m)?)?;

    // Crypto Operations - ECDSA Signing
    m.add_function(wrap_pyfunction!(ecdsa_p256_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p384_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p521_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p256_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p384_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p521_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p384_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p521_verify, m)?)?;

    // Crypto Operations - RSA Signing
    m.add_function(wrap_pyfunction!(rsa_generate, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha256_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha384_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha512_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha256_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha384_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha512_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha384_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha512_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha384_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha512_verify, m)?)?;

    // Crypto Operations - Key Generation
    m.add_function(wrap_pyfunction!(generate_random_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;

    // JWK/JWS/JWE
    m.add_class::<PyJwk>()?;
    m.add_function(wrap_pyfunction!(jwk_generate, m)?)?;
    m.add_function(wrap_pyfunction!(jws_sign, m)?)?;
    m.add_function(wrap_pyfunction!(jws_verify, m)?)?;
    m.add_function(wrap_pyfunction!(jwe_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(jwe_decrypt, m)?)?;

    // mDL Document Parsing
    m.add_class::<PyDeviceResponse>()?;
    m.add_function(wrap_pyfunction!(parse_device_response, m)?)?;

    // Certificate Chain Validation
    m.add_class::<PyChainValidationResult>()?;
    m.add_class::<PyChainValidator>()?;

    // Ed448 Operations
    m.add_function(wrap_pyfunction!(ed448_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ed448_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed448_verify, m)?)?;

    // PKCS#12 Operations
    m.add_class::<PyPkcs12Data>()?;
    m.add_function(wrap_pyfunction!(pkcs12_parse, m)?)?;

    // ISO 9796-2 Operations
    m.add_function(wrap_pyfunction!(iso9796_verify, m)?)?;
    m.add_function(wrap_pyfunction!(iso9796_recover, m)?)?;

    // OCSP Operations
    m.add_function(wrap_pyfunction!(build_ocsp_request, m)?)?;
    m.add_function(wrap_pyfunction!(get_ocsp_responder_url, m)?)?;
    m.add_function(wrap_pyfunction!(parse_ocsp_response, m)?)?;

    // Open Badges
    m.add_function(wrap_pyfunction!(open_badge_ob2_issue, m)?)?;
    m.add_function(wrap_pyfunction!(open_badge_ob2_verify, m)?)?;
    m.add_function(wrap_pyfunction!(open_badge_ob3_issue, m)?)?;
    m.add_function(wrap_pyfunction!(open_badge_ob3_verify, m)?)?;

    // DTC helpers (JSON in/out)
    m.add_function(wrap_pyfunction!(dtc_create, m)?)?;
    m.add_function(wrap_pyfunction!(dtc_sign, m)?)?;
    m.add_function(wrap_pyfunction!(dtc_verify, m)?)?;

    // Certificate Builder Operations (feature-gated)
    #[cfg(feature = "cert-builder")]
    {
        m.add_class::<PyCertProfile>()?;
        m.add_class::<PyCertificateBuilderConfig>()?;
        m.add_function(wrap_pyfunction!(build_self_signed_certificate, m)?)?;
        m.add_function(wrap_pyfunction!(build_self_signed_certificate_with_key, m)?)?;
    }

    // Add constants for ruleset selection
    m.add("RULESET_MDL", "mdl")?;
    m.add("RULESET_AAMVA_MDL", "aamva_mdl")?;
    m.add("RULESET_MDL_READER", "mdl_reader")?;

    Ok(())
}
