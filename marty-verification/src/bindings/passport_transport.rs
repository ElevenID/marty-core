//! Python adapters for passport transport.

#[cfg(feature = "csca")]
use super::to_pyerr;
use pyo3::prelude::*;
#[cfg(feature = "csca")]
use pyo3::types::PyBytes;
#[cfg(feature = "csca")]
use pyo3::types::PyDict;

#[pyfunction]
pub(super) fn compare_passport_hashes_json(request_json: &str) -> PyResult<String> {
    crate::passport_integrity::compare_json(request_json)
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))
}

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
#[pyclass(name = "NativeBacSession")]
pub(super) struct PyNativeBacSession {
    handshake: Option<crate::chip_io::BacHandshake>,
    session: Option<crate::chip_io::BacSession>,
}

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
#[pymethods]
impl PyNativeBacSession {
    #[new]
    fn new() -> Self {
        Self {
            handshake: None,
            session: None,
        }
    }

    fn start_bac<'py>(
        &mut self,
        py: Python<'py>,
        passport_number: &str,
        date_of_birth: &str,
        date_of_expiry: &str,
        chip_challenge: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mrz = bac_mrz(passport_number, date_of_birth, date_of_expiry)?;
        let handshake =
            crate::chip_io::BacHandshake::begin(&mrz, chip_challenge).map_err(to_pyerr)?;
        let command = handshake.command_data().map_err(to_pyerr)?;
        self.handshake = Some(handshake);
        self.session = None;
        Ok(PyBytes::new(py, &command))
    }

    fn finish_bac<'py>(
        &mut self,
        py: Python<'py>,
        chip_response: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let handshake = self.handshake.take().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("BAC mutual authentication state missing")
        })?;
        let session = handshake.complete(chip_response).map_err(to_pyerr)?;
        let result = bac_session_dict(py, &session)?;
        self.session = Some(session);
        Ok(result)
    }

    fn protect_command<'py>(
        &mut self,
        py: Python<'py>,
        command: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let command = crate::chip_io::ApduCommand::from_bytes(command).map_err(to_pyerr)?;
        let session = self.session.as_mut().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("Session keys not established")
        })?;
        let protected = session.protect_command(&command).map_err(to_pyerr)?;
        let encoded = protected.to_bytes().map_err(to_pyerr)?;
        Ok(PyBytes::new(py, &encoded))
    }

    fn unprotect_response<'py>(
        &mut self,
        py: Python<'py>,
        response: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let response = crate::chip_io::ApduResponse::from_bytes(response).map_err(to_pyerr)?;
        let session = self.session.as_mut().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("Session keys not established")
        })?;
        let plaintext = session.unprotect_response(&response).map_err(to_pyerr)?;
        let mut raw = plaintext.data;
        raw.extend_from_slice(&[plaintext.sw1, plaintext.sw2]);
        Ok(PyBytes::new(py, &raw))
    }

    #[getter]
    fn session_established(&self) -> bool {
        self.session.is_some()
    }
}

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
#[pyclass(name = "NativePaceSession")]
pub(super) struct PyNativePaceSession {
    handshake: Option<crate::chip_io::PaceCompatibilityHandshake>,
    session: Option<crate::chip_io::BacSession>,
}

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
#[pymethods]
impl PyNativePaceSession {
    #[new]
    fn new() -> Self {
        Self {
            handshake: None,
            session: None,
        }
    }

    #[pyo3(signature = (password, encrypted_nonce, curve="p256"))]
    fn start_pace<'py>(
        &mut self,
        py: Python<'py>,
        password: &str,
        encrypted_nonce: &[u8],
        curve: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        if curve != "p256" {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "PACE compatibility session supports only p256",
            ));
        }
        let handshake =
            crate::chip_io::PaceCompatibilityHandshake::begin(password, encrypted_nonce)
                .map_err(to_pyerr)?;
        let public_key = handshake.public_key().to_vec();
        self.handshake = Some(handshake);
        self.session = None;
        Ok(PyBytes::new(py, &public_key))
    }

    fn complete_pace<'py>(
        &mut self,
        py: Python<'py>,
        chip_public_key: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let handshake = self.handshake.take().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(
                "PACE state unavailable - call start_pace first",
            )
        })?;
        let session = handshake.complete(chip_public_key).map_err(to_pyerr)?;
        let result = bac_session_dict(py, &session)?;
        self.session = Some(session);
        Ok(result)
    }

    fn protect_command<'py>(
        &mut self,
        py: Python<'py>,
        command: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let command = crate::chip_io::ApduCommand::from_bytes(command).map_err(to_pyerr)?;
        let session = self.session.as_mut().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("PACE session keys not established")
        })?;
        let protected = session.protect_command(&command).map_err(to_pyerr)?;
        let encoded = protected.to_bytes().map_err(to_pyerr)?;
        Ok(PyBytes::new(py, &encoded))
    }

    fn unprotect_response<'py>(
        &mut self,
        py: Python<'py>,
        response: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let response = crate::chip_io::ApduResponse::from_bytes(response).map_err(to_pyerr)?;
        let session = self.session.as_mut().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("PACE session keys not established")
        })?;
        let plaintext = session.unprotect_response(&response).map_err(to_pyerr)?;
        let mut raw = plaintext.data;
        raw.extend_from_slice(&[plaintext.sw1, plaintext.sw2]);
        Ok(PyBytes::new(py, &raw))
    }

    #[getter]
    fn session_established(&self) -> bool {
        self.session.is_some()
    }
}

#[cfg(feature = "csca")]
pub(super) fn apdu_byte(name: &str, value: i64) -> PyResult<u8> {
    u8::try_from(value).map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "Invalid {name}: expected an unsigned byte"
        ))
    })
}

#[cfg(feature = "csca")]
#[pyfunction]
#[pyo3(signature = (cla, ins, p1, p2, data=None, le=None))]
pub(super) fn apdu_encode<'py>(
    py: Python<'py>,
    cla: i64,
    ins: i64,
    p1: i64,
    p2: i64,
    data: Option<&[u8]>,
    le: Option<i64>,
) -> PyResult<Bound<'py, PyBytes>> {
    let le = le
        .map(|value| {
            usize::try_from(value).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "Invalid Le: expected a non-negative integer",
                )
            })
        })
        .transpose()?;
    let encoded = crate::chip_io::encode_apdu_command(
        apdu_byte("CLA", cla)?,
        apdu_byte("INS", ins)?,
        apdu_byte("P1", p1)?,
        apdu_byte("P2", p2)?,
        data,
        le,
    )
    .map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &encoded))
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn apdu_parse_response<'py>(py: Python<'py>, response: &[u8]) -> PyResult<Py<PyDict>> {
    let response = crate::chip_io::ApduResponse::from_bytes(response).map_err(to_pyerr)?;
    let output = PyDict::new(py);
    output.set_item("data", PyBytes::new(py, &response.data))?;
    output.set_item("sw1", response.sw1)?;
    output.set_item("sw2", response.sw2)?;
    output.set_item("sw", response.status_word())?;
    output.set_item("is_success", response.is_success())?;
    output.set_item("is_warning", response.is_warning())?;
    output.set_item("is_error", response.is_error())?;
    output.set_item("status_description", response.status_description())?;
    Ok(output.unbind())
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn apdu_parse_command<'py>(py: Python<'py>, command: &[u8]) -> PyResult<Py<PyDict>> {
    let command = crate::chip_io::ApduCommand::from_bytes(command).map_err(to_pyerr)?;
    let output = PyDict::new(py);
    output.set_item("cla", command.cla)?;
    output.set_item("ins", command.ins)?;
    output.set_item("p1", command.p1)?;
    output.set_item("p2", command.p2)?;
    output.set_item(
        "data",
        (!command.data.is_empty()).then(|| PyBytes::new(py, &command.data)),
    )?;
    output.set_item("le", command.le)?;
    Ok(output.unbind())
}

#[cfg(feature = "csca")]
#[pyfunction]
#[pyo3(signature = (length, offset=0))]
pub(super) fn apdu_build_read_binary_commands<'py>(
    py: Python<'py>,
    length: usize,
    offset: usize,
) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    crate::chip_io::build_read_binary_commands(length, offset)
        .map_err(to_pyerr)?
        .iter()
        .map(|command| {
            command
                .to_bytes()
                .map(|encoded| PyBytes::new(py, &encoded))
                .map_err(to_pyerr)
        })
        .collect()
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn passport_data_group_file_id(data_group: u8) -> PyResult<u16> {
    crate::chip_io::passport_data_group_file_id(data_group).map_err(to_pyerr)
}

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
pub(super) fn bac_mrz(
    passport_number: &str,
    date_of_birth: &str,
    date_of_expiry: &str,
) -> PyResult<crate::chip_io::MrzKeyInfo> {
    let mut document: String = passport_number
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_uppercase())
        .take(9)
        .collect();
    while document.len() < 9 {
        document.push('<');
    }
    if date_of_birth.len() != 6
        || date_of_expiry.len() != 6
        || !date_of_birth.bytes().all(|value| value.is_ascii_digit())
        || !date_of_expiry.bytes().all(|value| value.is_ascii_digit())
    {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "BAC dates must be six ASCII digits (YYMMDD)",
        ));
    }
    crate::chip_io::MrzKeyInfo::try_from_mrz_fields(&document, date_of_birth, date_of_expiry)
        .map_err(to_pyerr)
}

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
pub(super) fn bac_session_dict<'py>(
    py: Python<'py>,
    _session: &crate::chip_io::BacSession,
) -> PyResult<Bound<'py, PyDict>> {
    let result = PyDict::new(py);
    result.set_item("session_established", true)?;
    Ok(result)
}
