//! Python boundary for ISO 18013-5 presentation verification.
//!
//! Issuance signs through an issuer profile and its DID verification method.
//! These verifier bindings consume only public COSE and certificate material;
//! they neither accept nor select a KMS service or key reference.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::IntoPyObjectExt;

/// Build verifier-bound ISO 18013-7 OpenID4VP `SessionTranscript` bytes.
#[pyfunction]
pub(crate) fn build_openid4vp_mdoc_session_transcript(
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    response_encryption_jwk_json: Option<&str>,
) -> PyResult<Vec<u8>> {
    marty_iso18013::openid4vp::build_mdoc_session_transcript(
        client_id,
        nonce,
        response_uri,
        response_encryption_jwk_json,
    )
    .map_err(|error| value_error(error.to_string()))
}

/// Return the raw RFC 7638 thumbprint used by OpenID4VP `HandoverInfo`.
#[pyfunction]
pub(crate) fn openid4vp_response_key_thumbprint(jwk_json: &str) -> PyResult<Vec<u8>> {
    marty_iso18013::openid4vp::response_encryption_jwk_thumbprint(jwk_json)
        .map(|thumbprint| thumbprint.to_vec())
        .map_err(|error| value_error(error.to_string()))
}

/// Return canonical non-reversible diagnostics for an mdoc request binding.
#[pyfunction]
pub(crate) fn openid4vp_mdoc_binding_digests(
    session_transcript: &[u8],
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    response_encryption_jwk_json: Option<&str>,
    presentation: &str,
) -> PyResult<String> {
    let result = marty_iso18013::openid4vp::mdoc_binding_digests(
        session_transcript,
        client_id,
        nonce,
        response_uri,
        response_encryption_jwk_json,
        presentation,
    )
    .map_err(|error| value_error(error.to_string()))?;
    serde_json::to_string(&result).map_err(|error| value_error(error.to_string()))
}

/// Parse a DeviceResponse and fail if its envelope is not ISO-compatible.
///
/// The UI uses this only for format detection. Authentication is performed by
/// [`verify_mdoc_presentation`].
#[pyfunction]
pub(crate) fn parse_device_response(cbor_bytes: Vec<u8>) -> PyResult<bool> {
    marty_verification::mdoc::parse_valid_device_response(&cbor_bytes).map_err(value_error)?;
    Ok(true)
}

/// Extract disclosed mdoc claims after the caller has authenticated the
/// presentation.
///
/// Unique element identifiers remain available as flat keys for compatibility.
/// The `_mdoc.documents` value always preserves the document type, namespace,
/// and element identifier. Ambiguous flat keys are omitted rather than
/// silently selecting one namespace.
#[pyfunction]
pub(crate) fn verify_mdoc_cbor(cbor_bytes: Vec<u8>, py: Python<'_>) -> PyResult<Py<PyAny>> {
    let claims = marty_verification::mdoc::disclosed_claims(&cbor_bytes).map_err(value_error)?;
    json_to_python(py, &claims)
}

/// Signature-authenticated evidence for one mdoc document.
#[pyclass(skip_from_py_object)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MdocDocumentVerificationEvidence {
    #[pyo3(get)]
    pub(crate) document_type: String,
    #[pyo3(get)]
    pub(crate) signature_algorithm: String,
    #[pyo3(get)]
    pub(crate) digest_algorithm: String,
    #[pyo3(get)]
    pub(crate) signed_at: String,
    #[pyo3(get)]
    pub(crate) valid_from: String,
    #[pyo3(get)]
    pub(crate) valid_until: String,
    #[pyo3(get)]
    pub(crate) issuer_certificate_sha256: String,
    #[pyo3(get)]
    pub(crate) validity_checked: bool,
    #[pyo3(get)]
    pub(crate) valid_at_verification_time: bool,
    /// Revocation is not checked by this offline binding.
    #[pyo3(get)]
    pub(crate) revocation_checked: bool,
    /// No non-revocation result is invented when no status authority ran.
    #[pyo3(get)]
    pub(crate) not_revoked: Option<bool>,
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
    /// One complete record per signature-authenticated document.
    #[pyo3(get)]
    pub(crate) document_evidence: Vec<MdocDocumentVerificationEvidence>,
    /// This offline binding does not perform CRL or status-authority retrieval.
    #[pyo3(get)]
    pub(crate) revocation_checked: bool,
    #[pyo3(get)]
    pub(crate) not_revoked: Option<bool>,
    #[pyo3(get)]
    pub(crate) error: Option<String>,
}

/// Result of issuer-only mdoc authentication for non-interactive document use.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct MdocIssuerVerificationResult {
    /// Every document has a valid issuerAuth COSE signature.
    #[pyo3(get)]
    pub(crate) signature_valid: bool,
    /// Every issuer certificate chain terminates at configured trust material.
    #[pyo3(get)]
    pub(crate) issuer_trusted: bool,
    #[pyo3(get)]
    pub(crate) document_types: Vec<String>,
    #[pyo3(get)]
    pub(crate) document_evidence: Vec<MdocDocumentVerificationEvidence>,
    #[pyo3(get)]
    pub(crate) revocation_checked: bool,
    #[pyo3(get)]
    pub(crate) not_revoked: Option<bool>,
    #[pyo3(get)]
    pub(crate) error: Option<String>,
}

impl From<marty_verification::mdoc::MdocDocumentVerificationEvidence>
    for MdocDocumentVerificationEvidence
{
    fn from(value: marty_verification::mdoc::MdocDocumentVerificationEvidence) -> Self {
        Self {
            document_type: value.document_type,
            signature_algorithm: value.signature_algorithm,
            digest_algorithm: value.digest_algorithm,
            signed_at: value.signed_at,
            valid_from: value.valid_from,
            valid_until: value.valid_until,
            issuer_certificate_sha256: value.issuer_certificate_sha256,
            validity_checked: value.validity_checked,
            valid_at_verification_time: value.valid_at_verification_time,
            revocation_checked: value.revocation_checked,
            not_revoked: value.not_revoked,
        }
    }
}

impl From<marty_verification::mdoc::MdocIssuerVerificationResult> for MdocIssuerVerificationResult {
    fn from(value: marty_verification::mdoc::MdocIssuerVerificationResult) -> Self {
        Self {
            signature_valid: value.signature_valid,
            issuer_trusted: value.issuer_trusted,
            document_types: value.document_types,
            document_evidence: value
                .document_evidence
                .into_iter()
                .map(Into::into)
                .collect(),
            revocation_checked: value.revocation_checked,
            not_revoked: value.not_revoked,
            error: value.error,
        }
    }
}

impl From<marty_verification::mdoc::MdocPresentationVerificationResult>
    for MdocPresentationVerificationResult
{
    fn from(value: marty_verification::mdoc::MdocPresentationVerificationResult) -> Self {
        Self {
            issuer_signature_valid: value.issuer_signature_valid,
            issuer_trusted: value.issuer_trusted,
            device_authentication_valid: value.device_authentication_valid,
            document_types: value.document_types,
            document_evidence: value
                .document_evidence
                .into_iter()
                .map(Into::into)
                .collect(),
            revocation_checked: value.revocation_checked,
            not_revoked: value.not_revoked,
            error: value.error,
        }
    }
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

#[pymethods]
impl MdocIssuerVerificationResult {
    fn __repr__(&self) -> String {
        format!(
            "MdocIssuerVerificationResult(signature_valid={}, issuer_trusted={}, document_types={:?})",
            self.signature_valid, self.issuer_trusted, self.document_types
        )
    }
}

/// Authenticate issuer signatures and certificate chains without inventing a
/// holder/session proof. This is suitable for stored mdoc credential checks;
/// interactive presentations must use `verify_mdoc_presentation` instead.
#[pyfunction(signature = (
    mdoc_bytes,
    trusted_root_certs_pem,
    pinned_issuer_certs_pem = None
))]
pub(crate) fn verify_mdoc_issuer(
    mdoc_bytes: Vec<u8>,
    trusted_root_certs_pem: Vec<String>,
    pinned_issuer_certs_pem: Option<Vec<String>>,
) -> MdocIssuerVerificationResult {
    marty_verification::mdoc::verify_mdoc_issuer(
        &mdoc_bytes,
        &trusted_root_certs_pem,
        pinned_issuer_certs_pem.as_deref().unwrap_or_default(),
    )
    .into()
}

/// Authenticate issuer and holder proofs in an OpenID4VP mdoc presentation.
///
/// `session_transcript_cbor` must be constructed from verifier-owned request
/// state. It is not accepted from the wallet. Root anchors and directly pinned
/// issuer certificates are public certificates provisioned through distinct
/// trust-profile source types.
#[pyfunction(signature = (
    mdoc_bytes,
    session_transcript_cbor,
    trusted_root_certs_pem,
    pinned_issuer_certs_pem = None
))]
pub(crate) fn verify_mdoc_presentation(
    mdoc_bytes: Vec<u8>,
    session_transcript_cbor: Vec<u8>,
    trusted_root_certs_pem: Vec<String>,
    pinned_issuer_certs_pem: Option<Vec<String>>,
) -> PyResult<MdocPresentationVerificationResult> {
    Ok(marty_verification::mdoc::verify_mdoc_presentation(
        &mdoc_bytes,
        &session_transcript_cbor,
        &trusted_root_certs_pem,
        pinned_issuer_certs_pem.as_deref().unwrap_or_default(),
    )
    .into())
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

    fn runtime_nonce() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos()
            .to_string()
    }

    #[test]
    fn openid4vp_mdoc_handover_binding_preserves_golden_bytes() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/vectors/openid4vp_mdoc_handover.json"
        ))
        .expect("valid handover fixture");
        let case = &fixture["valid"][0];
        let jwk_json = case["response_encryption_jwk"].to_string();
        let transcript = build_openid4vp_mdoc_session_transcript(
            case["client_id"].as_str().unwrap(),
            case["nonce"].as_str().unwrap(),
            case["response_uri"].as_str().unwrap(),
            Some(&jwk_json),
        )
        .expect("valid native transcript");
        assert_eq!(
            hex::encode(transcript),
            case["session_transcript_hex"].as_str().unwrap()
        );
        assert_eq!(
            openid4vp_response_key_thumbprint(r#"{"kty":"EC","crv":"P-256","x":"AQ","y":"Ag"}"#)
                .expect("valid thumbprint")
                .len(),
            32
        );
    }

    #[test]
    fn openid4vp_mdoc_handover_binding_fails_closed() {
        let nonce = runtime_nonce();
        assert!(build_openid4vp_mdoc_session_transcript(
            "client",
            &nonce,
            "https://verifier.example/submit",
            Some(r#"{"kty":"EC","crv":"P-256","x":"AQ"}"#),
        )
        .is_err());
    }

    #[test]
    fn openid4vp_mdoc_binding_diagnostics_are_native_json() {
        let nonce = runtime_nonce();
        let transcript = build_openid4vp_mdoc_session_transcript(
            "client",
            &nonce,
            "https://verifier.example/submit",
            None,
        )
        .unwrap();
        let diagnostics: serde_json::Value = serde_json::from_str(
            &openid4vp_mdoc_binding_digests(
                &transcript,
                "client",
                &nonce,
                "https://verifier.example/submit",
                None,
                "presentation",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(diagnostics["response_key_thumbprint_sha256"], "none");
        assert_eq!(diagnostics.as_object().unwrap().len(), 6);
    }

    #[test]
    fn malformed_presentation_fails_closed_without_panicking() {
        let native = marty_verification::mdoc::verify_mdoc_presentation(
            &[0xff],
            &[0x83, 0xf6, 0xf6, 0x82, 0x71],
            &[],
            &[],
        );
        let result = verify_mdoc_presentation(
            vec![0xff],
            vec![0x83, 0xf6, 0xf6, 0x82, 0x71],
            Vec::new(),
            None,
        )
        .unwrap();
        assert!(!result.issuer_signature_valid);
        assert!(!result.issuer_trusted);
        assert!(!result.device_authentication_valid);
        assert!(result.document_evidence.is_empty());
        assert!(!result.revocation_checked);
        assert_eq!(result.not_revoked, None);
        assert!(result.error.is_some());
        assert_eq!(result.issuer_signature_valid, native.issuer_signature_valid);
        assert_eq!(result.issuer_trusted, native.issuer_trusted);
        assert_eq!(
            result.device_authentication_valid,
            native.device_authentication_valid
        );
        assert_eq!(result.document_types, native.document_types);
        assert_eq!(
            result.document_evidence.len(),
            native.document_evidence.len()
        );
        assert_eq!(result.revocation_checked, native.revocation_checked);
        assert_eq!(result.not_revoked, native.not_revoked);
        assert_eq!(result.error, native.error);
    }
}
