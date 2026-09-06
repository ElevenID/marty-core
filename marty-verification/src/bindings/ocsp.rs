//! Python adapters for ocsp.

use super::to_pyerr;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::types::PyDict;

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
pub(super) fn build_ocsp_request<'py>(
    py: Python<'py>,
    cert_der: &[u8],
    issuer_cert_der: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let request =
        marty_crypto::ocsp::build_ocsp_request(cert_der, issuer_cert_der).map_err(to_pyerr)?;
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
pub(super) fn get_ocsp_responder_url(cert_der: &[u8]) -> PyResult<Option<String>> {
    marty_crypto::ocsp::get_ocsp_responder_url(cert_der).map_err(to_pyerr)
}

/// Extract CRL distribution point URIs from a certificate.
#[pyfunction]
pub(super) fn get_crl_distribution_points(cert_der: &[u8]) -> PyResult<Vec<String>> {
    marty_crypto::certificate::get_crl_distribution_points(cert_der).map_err(to_pyerr)
}

/// Parse an OCSP response without authenticating it.
///
/// Diagnostic use only. Use `validate_ocsp_response` for trust decisions.
///
/// Args:
///     response_der: DER-encoded OCSP response
///
/// Returns:
///     Dictionary with response information
#[pyfunction]
pub(super) fn parse_ocsp_response(py: Python<'_>, response_der: &[u8]) -> PyResult<Py<PyDict>> {
    let info = marty_crypto::ocsp::parse_ocsp_response(response_der).map_err(to_pyerr)?;

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

/// Authenticate and validate an OCSP response for a certificate/issuer pair.
///
/// This is the only OCSP binding suitable for a verification trust decision.
/// It raises when the signature, responder authorization, CertID binding, or
/// freshness check fails.
#[pyfunction]
pub(super) fn validate_ocsp_response(
    py: Python<'_>,
    response_der: &[u8],
    cert_der: &[u8],
    issuer_cert_der: &[u8],
) -> PyResult<Py<PyDict>> {
    let info = marty_crypto::ocsp::validate_ocsp_response(response_der, cert_der, issuer_cert_der)
        .map_err(to_pyerr)?;

    let dict = PyDict::new(py);
    dict.set_item("this_update", info.this_update)?;
    dict.set_item("next_update", info.next_update)?;
    dict.set_item("responder_id", info.responder_id)?;
    dict.set_item("produced_at", info.produced_at)?;
    dict.set_item("responder_is_issuer", info.responder_is_issuer)?;
    dict.set_item("delegated_responder", info.delegated_responder)?;
    dict.set_item("signature_valid", info.signature_valid)?;
    dict.set_item("certificate_id_valid", info.certificate_id_valid)?;
    dict.set_item("freshness_valid", info.freshness_valid)?;
    match info.cert_status {
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
    Ok(dict.into())
}
