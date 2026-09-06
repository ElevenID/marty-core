//! Python adapters for crl.

use super::*;

/// Python wrapper for CRL information.
#[pyclass(name = "CrlInfo", from_py_object)]
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
            list.append(Py::new(py, cert.clone())?)?;
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
#[pyclass(name = "RevokedCertificate", from_py_object)]
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
pub(super) fn parse_crl(der_bytes: &[u8]) -> PyResult<PyCrlInfo> {
    let crl = crate::asn1::crl::parse_crl(der_bytes).map_err(to_pyerr)?;

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
