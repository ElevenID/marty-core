//! Python boundary for ISO 18013-5 presentation verification.
//!
//! Issuance signs through an issuer profile and its DID verification method.
//! These verifier bindings consume only public COSE and certificate material;
//! they neither accept nor select a KMS service or key reference.

use coset::{cbor::value::Value as CoseValue, Label};
use isomdl::definitions::device_response::{DeviceResponse, Status};
use isomdl::definitions::x509::x5chain::{X5Chain, X5CHAIN_COSE_HEADER_LABEL};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::IntoPyObjectExt;

/// Parse a DeviceResponse and fail if its envelope is not ISO-compatible.
///
/// The UI uses this only for format detection. Authentication is performed by
/// [`verify_mdoc_presentation`].
#[pyfunction]
pub(crate) fn parse_device_response(cbor_bytes: Vec<u8>) -> PyResult<bool> {
    let response: DeviceResponse = isomdl::cbor::from_slice(&cbor_bytes)
        .map_err(|error| value_error(format!("Failed to parse mdoc DeviceResponse: {error}")))?;
    if response.version != DeviceResponse::VERSION || !matches!(response.status, Status::OK) {
        return Err(value_error(
            "mdoc DeviceResponse version or status is invalid",
        ));
    }
    if response.documents.is_none() {
        return Err(value_error("mdoc DeviceResponse contains no documents"));
    }
    Ok(true)
}

/// Extract disclosed mDL claims after the caller has authenticated the
/// presentation.
#[pyfunction]
pub(crate) fn verify_mdoc_cbor(cbor_bytes: Vec<u8>, py: Python<'_>) -> PyResult<Py<PyAny>> {
    let response = marty_verification::mdoc::parse_device_response(&cbor_bytes)
        .map_err(|error| value_error(format!("Failed to parse mdoc claims: {error}")))?;
    let fields = response
        .get_mdl_fields()
        .map_err(|error| value_error(format!("Failed to extract mdoc claims: {error}")))?;
    let result = PyDict::new(py);
    for (key, value) in fields {
        result.set_item(key, json_to_python(py, &value)?)?;
    }
    Ok(result.into())
}

/// Result of complete OpenID4VP mdoc presentation authentication.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct MdocPresentationVerificationResult {
    /// Every document has a valid issuerAuth COSE signature.
    #[pyo3(get)]
    pub(crate) issuer_signature_valid: bool,
    /// Every issuer certificate chain terminates at a configured trust anchor.
    #[pyo3(get)]
    pub(crate) issuer_trusted: bool,
    /// Every holder DeviceAuthentication signature matches verifier-owned state.
    #[pyo3(get)]
    pub(crate) device_authentication_valid: bool,
    #[pyo3(get)]
    pub(crate) document_types: Vec<String>,
    #[pyo3(get)]
    pub(crate) error: Option<String>,
}

#[pymethods]
impl MdocPresentationVerificationResult {
    fn __repr__(&self) -> String {
        format!(
            "MdocPresentationVerificationResult(issuer_signature_valid={}, \
             issuer_trusted={}, device_authentication_valid={}, document_types={:?})",
            self.issuer_signature_valid,
            self.issuer_trusted,
            self.device_authentication_valid,
            self.document_types
        )
    }
}

/// Authenticate issuer and holder proofs in an OpenID4VP mdoc presentation.
///
/// `session_transcript_cbor` must be constructed from verifier-owned request
/// state. It is not accepted from the wallet. The issuer trust anchors are
/// public certificates provisioned through the trust profile.
#[pyfunction]
pub(crate) fn verify_mdoc_presentation(
    mdoc_bytes: Vec<u8>,
    session_transcript_cbor: Vec<u8>,
    trusted_issuer_certs_pem: Vec<String>,
) -> PyResult<MdocPresentationVerificationResult> {
    let issuer = verify_issuer_authentication(&mdoc_bytes, &trusted_issuer_certs_pem);
    let mut errors = issuer.error.into_iter().collect::<Vec<_>>();
    let (device_authentication_valid, device_document_types) =
        match marty_verification::verify_device_authentication(
            &mdoc_bytes,
            &session_transcript_cbor,
        ) {
            Ok(result) => (result.verified, result.document_types),
            Err(error) => {
                errors.push(format!("Holder device authentication failed: {error}"));
                (false, Vec::new())
            }
        };
    let document_types = if issuer.document_types.is_empty() {
        device_document_types
    } else {
        issuer.document_types
    };

    Ok(MdocPresentationVerificationResult {
        issuer_signature_valid: issuer.signature_valid,
        issuer_trusted: issuer.issuer_trusted,
        device_authentication_valid,
        document_types,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    })
}

struct IssuerAuthenticationResult {
    signature_valid: bool,
    issuer_trusted: bool,
    document_types: Vec<String>,
    error: Option<String>,
}

fn verify_issuer_authentication(
    mdoc_bytes: &[u8],
    trusted_issuer_certs_pem: &[String],
) -> IssuerAuthenticationResult {
    let response: DeviceResponse = match isomdl::cbor::from_slice(mdoc_bytes) {
        Ok(response) => response,
        Err(error) => {
            return issuer_failure(format!("Failed to parse mdoc DeviceResponse: {error}"));
        }
    };
    if response.version != DeviceResponse::VERSION || !matches!(response.status, Status::OK) {
        return issuer_failure("mdoc DeviceResponse version or status is invalid");
    }
    let Some(documents) = response.documents.as_ref() else {
        return issuer_failure("mdoc DeviceResponse contains no documents");
    };
    let document_types = documents
        .iter()
        .map(|document| document.doc_type.clone())
        .collect::<Vec<_>>();

    let mut chain_validator = marty_verification::verification::ChainValidator::new();
    let mut trust_configuration_valid = !trusted_issuer_certs_pem.is_empty();
    let mut errors = Vec::new();
    if trusted_issuer_certs_pem.is_empty() {
        errors.push("No trusted issuer certificates were configured".to_string());
    }
    for trusted_cert in trusted_issuer_certs_pem {
        if let Err(error) = chain_validator.add_trust_anchor_pem(trusted_cert) {
            trust_configuration_valid = false;
            errors.push(format!("Invalid trusted issuer certificate: {error}"));
        }
    }

    let mut all_signatures_valid = true;
    let mut issuer_trusted = trust_configuration_valid;
    for document in documents.iter() {
        let issuer_auth = &document.issuer_signed.issuer_auth;
        let x5chain_value = issuer_auth
            .protected
            .header
            .rest
            .iter()
            .chain(issuer_auth.unprotected.rest.iter())
            .find_map(|(label, value)| {
                (label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL)).then_some(value)
            });
        let Some(x5chain_value) = x5chain_value else {
            all_signatures_valid = false;
            issuer_trusted = false;
            errors.push(format!(
                "No issuer certificate chain in issuerAuth for {}",
                document.doc_type
            ));
            continue;
        };
        let certificate_chain = match certificate_chain_der(x5chain_value) {
            Ok(chain) => chain,
            Err(error) => {
                all_signatures_valid = false;
                issuer_trusted = false;
                errors.push(format!(
                    "Invalid issuer certificate chain for {}: {error}",
                    document.doc_type
                ));
                continue;
            }
        };
        let x5chain = match X5Chain::from_cbor(x5chain_value.clone()) {
            Ok(chain) => chain,
            Err(error) => {
                all_signatures_valid = false;
                issuer_trusted = false;
                errors.push(format!(
                    "Invalid issuer x5chain for {}: {error}",
                    document.doc_type
                ));
                continue;
            }
        };
        if let Err(error) = marty_verification::verification::mdl::verify_issuer_signature(
            &x5chain,
            &document.issuer_signed,
        ) {
            all_signatures_valid = false;
            issuer_trusted = false;
            errors.push(format!(
                "Signature verification failed for {}: {error}",
                document.doc_type
            ));
            continue;
        }
        if trust_configuration_valid {
            match chain_validator.validate_chain_der(&certificate_chain) {
                Ok(validation) if validation.valid => {}
                Ok(validation) => {
                    issuer_trusted = false;
                    errors.push(format!(
                        "Issuer certificate chain validation failed for {}: {}",
                        document.doc_type,
                        validation.errors.join("; ")
                    ));
                }
                Err(error) => {
                    issuer_trusted = false;
                    errors.push(format!(
                        "Issuer certificate chain validation failed for {}: {error}",
                        document.doc_type
                    ));
                }
            }
        } else {
            issuer_trusted = false;
        }
    }

    IssuerAuthenticationResult {
        signature_valid: all_signatures_valid,
        issuer_trusted,
        document_types,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

fn issuer_failure(error: impl Into<String>) -> IssuerAuthenticationResult {
    IssuerAuthenticationResult {
        signature_valid: false,
        issuer_trusted: false,
        document_types: Vec::new(),
        error: Some(error.into()),
    }
}

fn certificate_chain_der(value: &CoseValue) -> Result<Vec<Vec<u8>>, &'static str> {
    match value {
        CoseValue::Bytes(certificate) if !certificate.is_empty() => Ok(vec![certificate.clone()]),
        CoseValue::Array(certificates) if !certificates.is_empty() => certificates
            .iter()
            .map(|certificate| match certificate {
                CoseValue::Bytes(bytes) if !bytes.is_empty() => Ok(bytes.clone()),
                _ => Err("x5chain entries must be non-empty byte strings"),
            })
            .collect(),
        _ => Err("x5chain must be a byte string or non-empty array"),
    }
}

fn json_to_python(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    use serde_json::Value;

    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(value) => Ok(value.into_py_any(py)?),
        Value::Number(value) => {
            if let Some(integer) = value.as_i64() {
                Ok(integer.into_py_any(py)?)
            } else if let Some(unsigned) = value.as_u64() {
                Ok(unsigned.into_py_any(py)?)
            } else if let Some(float) = value.as_f64() {
                Ok(float.into_py_any(py)?)
            } else {
                Err(value_error("Invalid JSON number"))
            }
        }
        Value::String(value) => Ok(value.into_py_any(py)?),
        Value::Array(values) => {
            let result = pyo3::types::PyList::empty(py);
            for value in values {
                result.append(json_to_python(py, value)?)?;
            }
            Ok(result.into())
        }
        Value::Object(values) => {
            let result = PyDict::new(py);
            for (key, value) in values {
                result.set_item(key, json_to_python(py, value)?)?;
            }
            Ok(result.into())
        }
    }
}

fn value_error(error: impl Into<String>) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(error.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_chain_accepts_single_or_multiple_der_certificates() {
        assert_eq!(
            certificate_chain_der(&CoseValue::Bytes(vec![1, 2, 3])),
            Ok(vec![vec![1, 2, 3]])
        );
        assert_eq!(
            certificate_chain_der(&CoseValue::Array(vec![
                CoseValue::Bytes(vec![1]),
                CoseValue::Bytes(vec![2]),
            ])),
            Ok(vec![vec![1], vec![2]])
        );
    }

    #[test]
    fn certificate_chain_rejects_empty_or_non_binary_values() {
        assert!(certificate_chain_der(&CoseValue::Bytes(vec![])).is_err());
        assert!(certificate_chain_der(&CoseValue::Array(vec![])).is_err());
        assert!(certificate_chain_der(&CoseValue::Array(vec![CoseValue::Null])).is_err());
    }

    #[test]
    fn malformed_presentation_fails_closed_without_panicking() {
        let result =
            verify_mdoc_presentation(vec![0xff], vec![0x83, 0xf6, 0xf6, 0x82, 0x71], Vec::new())
                .unwrap();
        assert!(!result.issuer_signature_valid);
        assert!(!result.issuer_trusted);
        assert!(!result.device_authentication_valid);
        assert!(result.error.is_some());
    }
}
