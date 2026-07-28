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
use std::collections::HashMap;

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

/// Extract disclosed mdoc claims after the caller has authenticated the
/// presentation.
///
/// Unique element identifiers remain available as flat keys for compatibility.
/// The `_mdoc.documents` value always preserves the document type, namespace,
/// and element identifier. Ambiguous flat keys are omitted rather than
/// silently selecting one namespace.
#[pyfunction]
pub(crate) fn verify_mdoc_cbor(cbor_bytes: Vec<u8>, py: Python<'_>) -> PyResult<Py<PyAny>> {
    let response = marty_verification::mdoc::parse_device_response(&cbor_bytes)
        .map_err(|error| value_error(format!("Failed to parse mdoc claims: {error}")))?;
    json_to_python(py, &disclosed_claims(&response))
}

fn disclosed_claims(response: &marty_verification::mdoc::DeviceResponse) -> serde_json::Value {
    let fields = response.get_disclosed_fields();
    let mut element_counts: HashMap<&str, usize> = HashMap::new();
    for field in &fields {
        *element_counts
            .entry(field.element_identifier.as_str())
            .or_default() += 1;
    }

    let mut claims = serde_json::Map::new();
    for field in &fields {
        if element_counts.get(field.element_identifier.as_str()) == Some(&1) {
            claims.insert(
                field.element_identifier.clone(),
                field.element_value.clone(),
            );
        }
    }

    let documents = response
        .documents
        .iter()
        .map(|document| {
            let namespaces = document
                .namespaces
                .iter()
                .map(|(namespace, items)| {
                    let elements = items
                        .iter()
                        .map(|item| (item.element_identifier.clone(), item.element_value.clone()))
                        .collect::<serde_json::Map<_, _>>();
                    (namespace.clone(), serde_json::Value::Object(elements))
                })
                .collect::<serde_json::Map<_, _>>();
            serde_json::json!({
                "doc_type": document.doc_type,
                "namespaces": namespaces,
            })
        })
        .collect::<Vec<_>>();
    claims.insert(
        "_mdoc".to_string(),
        serde_json::json!({"documents": documents}),
    );
    serde_json::Value::Object(claims)
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
    let issuer = verify_issuer_authentication(
        &mdoc_bytes,
        &trusted_root_certs_pem,
        pinned_issuer_certs_pem.as_deref().unwrap_or_default(),
    );
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
    trusted_root_certs_pem: &[String],
    pinned_issuer_certs_pem: &[String],
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

    let mut root_validator = marty_verification::verification::ChainValidator::new();
    let mut trust_configuration_valid =
        !trusted_root_certs_pem.is_empty() || !pinned_issuer_certs_pem.is_empty();
    let mut errors = Vec::new();
    if !trust_configuration_valid {
        errors.push("No trusted issuer certificates were configured".to_string());
    }
    for trusted_cert in trusted_root_certs_pem {
        if let Err(error) = root_validator.add_trust_anchor_pem(trusted_cert) {
            trust_configuration_valid = false;
            errors.push(format!("Invalid mdoc root certificate: {error}"));
        }
    }
    let mut pinned_issuer_certs_der = Vec::with_capacity(pinned_issuer_certs_pem.len());
    for pinned_cert in pinned_issuer_certs_pem {
        match certificate_der_from_pem(pinned_cert) {
            Ok(certificate) => pinned_issuer_certs_der.push(certificate),
            Err(error) => {
                trust_configuration_valid = false;
                errors.push(format!("Invalid pinned mdoc issuer certificate: {error}"));
            }
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
            if let Err(error) = verify_issuer_trust(
                &certificate_chain,
                &root_validator,
                &pinned_issuer_certs_der,
            ) {
                issuer_trusted = false;
                errors.push(format!(
                    "Issuer certificate trust validation failed for {}: {error}",
                    document.doc_type
                ));
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

fn certificate_der_from_pem(pem: &str) -> Result<Vec<u8>, String> {
    let (label, der) = pem_rfc7468::decode_vec(pem.as_bytes())
        .map_err(|error| format!("invalid PEM encoding: {error}"))?;
    if label != "CERTIFICATE" {
        return Err(format!("expected CERTIFICATE PEM label, found {label}"));
    }
    if der.is_empty() {
        return Err("certificate DER is empty".to_string());
    }
    Ok(der)
}

fn verify_issuer_trust(
    certificate_chain: &[Vec<u8>],
    root_validator: &marty_verification::verification::ChainValidator,
    pinned_issuer_certs_der: &[Vec<u8>],
) -> Result<(), String> {
    let Some(leaf_certificate) = certificate_chain.first() else {
        return Err("issuer certificate chain is empty".to_string());
    };

    if pinned_issuer_certs_der
        .iter()
        .any(|pinned| pinned == leaf_certificate)
    {
        // Direct pinning establishes trust in this exact leaf certificate, not
        // in its subject name or issuing CA. Still enforce certificate validity
        // and every embedded chain signature. KeyUsage remains enforced for
        // normal ROOT_CA validation; a direct pin deliberately authorizes this
        // exact public key for issuerAuth after its COSE signature is verified.
        let direct_pin_validator = marty_verification::verification::ChainValidator::with_config(
            marty_verification::verification::ChainValidatorConfig {
                required_key_usage: Vec::new(),
                ..Default::default()
            },
        );
        return match direct_pin_validator.validate_chain_der(certificate_chain) {
            Ok(validation) if validation.valid => Ok(()),
            Ok(validation) => Err(format!(
                "directly pinned issuer certificate is invalid: {}",
                validation.errors.join("; ")
            )),
            Err(error) => Err(format!(
                "directly pinned issuer certificate validation failed: {error}"
            )),
        };
    }

    match root_validator.validate_chain_der(certificate_chain) {
        Ok(validation) if validation.valid => Ok(()),
        Ok(validation) => Err(format!(
            "certificate chain does not validate to a configured root: {}",
            validation.errors.join("; ")
        )),
        Err(error) => Err(format!("certificate chain validation failed: {error}")),
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
    use marty_verification::mdoc::{DeviceResponse, Document, IssuerSignedItem};

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
        assert!(result.error.is_some());
    }

    #[test]
    fn direct_pin_accepts_exact_leaf_without_weakening_root_validation() {
        use rcgen::{CertificateParams, DnType, KeyPair, KeyUsagePurpose};

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "Pinned mdoc document signer");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = params.self_signed(&key).unwrap();
        let certificate_der = certificate.der().to_vec();
        let certificate_pem = certificate.pem();

        let mut strict_root_validator = marty_verification::verification::ChainValidator::new();
        strict_root_validator
            .add_trust_anchor_pem(&certificate_pem)
            .unwrap();
        let strict = verify_issuer_trust(
            std::slice::from_ref(&certificate_der),
            &strict_root_validator,
            &[],
        );
        assert!(strict
            .unwrap_err()
            .contains("Certificate missing required key usage: DigitalSignature"));

        let direct_pin = certificate_der_from_pem(&certificate_pem).unwrap();
        assert!(verify_issuer_trust(
            std::slice::from_ref(&certificate_der),
            &strict_root_validator,
            &[direct_pin],
        )
        .is_ok());

        assert!(verify_issuer_trust(
            std::slice::from_ref(&certificate_der),
            &marty_verification::verification::ChainValidator::new(),
            &[vec![1, 2, 3]],
        )
        .is_err());
    }

    #[test]
    fn disclosed_claims_include_dtc_fields_and_structured_paths() {
        let response = DeviceResponse {
            version: "1.0".to_string(),
            documents: vec![Document {
                doc_type: "com.icao.dtc".to_string(),
                namespaces: HashMap::from([(
                    "com.icao.dtc".to_string(),
                    vec![IssuerSignedItem {
                        digest_id: 7,
                        random: vec![1],
                        element_identifier: "document_number".to_string(),
                        element_value: serde_json::json!("PMB09A5929"),
                    }],
                )]),
                mso: None,
                issuer_cert_chain: Vec::new(),
            }],
            status: 0,
        };

        assert_eq!(
            disclosed_claims(&response),
            serde_json::json!({
                "document_number": "PMB09A5929",
                "_mdoc": {
                    "documents": [{
                        "doc_type": "com.icao.dtc",
                        "namespaces": {
                            "com.icao.dtc": {
                                "document_number": "PMB09A5929"
                            }
                        }
                    }]
                }
            })
        );
    }

    #[test]
    fn disclosed_claims_omit_ambiguous_flat_keys() {
        let item = |value| IssuerSignedItem {
            digest_id: 0,
            random: Vec::new(),
            element_identifier: "document_number".to_string(),
            element_value: serde_json::json!(value),
        };
        let response = DeviceResponse {
            version: "1.0".to_string(),
            documents: vec![Document {
                doc_type: "example.document".to_string(),
                namespaces: HashMap::from([
                    ("example.one".to_string(), vec![item("one")]),
                    ("example.two".to_string(), vec![item("two")]),
                ]),
                mso: None,
                issuer_cert_chain: Vec::new(),
            }],
            status: 0,
        };

        let claims = disclosed_claims(&response);
        assert!(claims.get("document_number").is_none());
        assert_eq!(
            claims["_mdoc"]["documents"][0]["namespaces"]["example.one"]["document_number"],
            "one"
        );
        assert_eq!(
            claims["_mdoc"]["documents"][0]["namespaces"]["example.two"]["document_number"],
            "two"
        );
    }
}
