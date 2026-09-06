//! Python adapters for passport transport.

use super::*;

#[pyfunction]
pub(super) fn compare_passport_hashes_json(request_json: &str) -> PyResult<String> {
    crate::passport_integrity::compare_json(request_json)
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))
}

#[cfg(feature = "csca")]
#[pyclass(name = "NativeBacSession")]
pub(super) struct PyNativeBacSession {
    handshake: Option<crate::chip_io::BacHandshake>,
    session: Option<crate::chip_io::BacSession>,
}

#[cfg(feature = "csca")]
#[pymethods]
impl PyNativeBacSession {
    #[new]
    fn new() -> Self {
        Self {
            handshake: None,
            session: None,
        }
    }

    fn derive_bac_keys<'py>(
        &self,
        py: Python<'py>,
        passport_number: &str,
        date_of_birth: &str,
        date_of_expiry: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let mrz = bac_mrz(passport_number, date_of_birth, date_of_expiry)?;
        let keys = crate::chip_io::derive_bac_base_keys(&mrz).map_err(to_pyerr)?;
        let result = PyDict::new(py);
        result.set_item("k_enc", PyBytes::new(py, &keys.k_enc))?;
        result.set_item("k_mac", PyBytes::new(py, &keys.k_mac))?;
        result.set_item("k_seed", PyBytes::new(py, &keys.k_seed))?;
        Ok(result)
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

    fn start_bac_with_keys<'py>(
        &mut self,
        py: Python<'py>,
        k_enc: &[u8],
        k_mac: &[u8],
        k_seed: &[u8],
        chip_challenge: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let k_enc: [u8; 16] = k_enc.try_into().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("BAC encryption key must be 16 bytes")
        })?;
        let k_mac: [u8; 16] = k_mac
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("BAC MAC key must be 16 bytes"))?;
        let k_seed: [u8; 16] = k_seed
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("BAC seed must be 16 bytes"))?;
        let keys = crate::chip_io::BacKeys::from_parts(k_enc, k_mac, k_seed);
        let handshake = crate::chip_io::BacHandshake::begin_with_keys(keys, chip_challenge)
            .map_err(to_pyerr)?;
        let command = handshake.command_data().map_err(to_pyerr)?;
        self.handshake = Some(handshake);
        self.session = None;
        Ok(PyBytes::new(py, &command))
    }

    #[allow(clippy::too_many_arguments)]
    fn start_bac_with_random<'py>(
        &mut self,
        py: Python<'py>,
        passport_number: &str,
        date_of_birth: &str,
        date_of_expiry: &str,
        chip_challenge: &[u8],
        reader_challenge: &[u8],
        reader_key: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mrz = bac_mrz(passport_number, date_of_birth, date_of_expiry)?;
        let reader_challenge: [u8; 8] = reader_challenge.try_into().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("BAC reader challenge must be 8 bytes")
        })?;
        let reader_key: [u8; 16] = reader_key.try_into().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("BAC reader key must be 16 bytes")
        })?;
        let handshake = crate::chip_io::BacHandshake::begin_with_random(
            &mrz,
            chip_challenge,
            reader_challenge,
            reader_key,
        )
        .map_err(to_pyerr)?;
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

    fn derive_session_keys<'py>(
        &mut self,
        py: Python<'py>,
        k_ifd: &[u8],
        k_ic: &[u8],
        rnd_ic: &[u8],
        rnd_ifd: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let session = crate::chip_io::derive_bac_session_keys(k_ifd, k_ic, rnd_ic, rnd_ifd)
            .map_err(to_pyerr)?;
        let result = bac_session_dict(py, &session)?;
        self.session = Some(session);
        Ok(result)
    }

    fn set_session_keys(&mut self, k_enc: &[u8], k_mac: &[u8], ssc: u64) -> PyResult<()> {
        let k_enc: [u8; 16] = k_enc.try_into().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("BAC encryption key must be 16 bytes")
        })?;
        let k_mac: [u8; 16] = k_mac
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("BAC MAC key must be 16 bytes"))?;
        self.session = Some(crate::chip_io::BacSession::from_session_keys(
            k_enc,
            k_mac,
            ssc.to_be_bytes(),
        ));
        Ok(())
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
        Ok(PyBytes::new(py, &protected.to_bytes()))
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

    fn session_keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let session = self.session.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("Session keys not established")
        })?;
        bac_session_dict(py, session)
    }
}

#[cfg(feature = "csca")]
#[pyclass(name = "NativePaceSession")]
pub(super) struct PyNativePaceSession {
    handshake: Option<crate::chip_io::PaceCompatibilityHandshake>,
}

#[cfg(feature = "csca")]
#[pymethods]
impl PyNativePaceSession {
    #[new]
    fn new() -> Self {
        Self { handshake: None }
    }

    fn derive_password_key<'py>(
        &self,
        py: Python<'py>,
        password: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let key =
            crate::chip_io::derive_compatibility_pace_password_key(password).map_err(to_pyerr)?;
        Ok(PyBytes::new(py, &key))
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
        Ok(PyBytes::new(py, &public_key))
    }

    fn start_pace_with_private_key<'py>(
        &mut self,
        py: Python<'py>,
        password: &str,
        encrypted_nonce: &[u8],
        private_key: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let handshake = crate::chip_io::PaceCompatibilityHandshake::begin_with_private_key(
            password,
            encrypted_nonce,
            private_key,
        )
        .map_err(to_pyerr)?;
        let public_key = handshake.public_key().to_vec();
        self.handshake = Some(handshake);
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
        bac_session_dict(py, &session)
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
        .map(|command| Ok(PyBytes::new(py, &command.to_bytes())))
        .collect()
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn passport_data_group_file_id(data_group: u8) -> PyResult<u16> {
    crate::chip_io::passport_data_group_file_id(data_group).map_err(to_pyerr)
}

#[cfg(feature = "csca")]
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
    Ok(crate::chip_io::MrzKeyInfo::from_mrz_fields(
        &document,
        date_of_birth,
        date_of_expiry,
    ))
}

#[cfg(feature = "csca")]
pub(super) fn bac_session_dict<'py>(
    py: Python<'py>,
    session: &crate::chip_io::BacSession,
) -> PyResult<Bound<'py, PyDict>> {
    let result = PyDict::new(py);
    result.set_item("k_s_enc", PyBytes::new(py, session.encryption_key()))?;
    result.set_item("k_s_mac", PyBytes::new(py, session.mac_key()))?;
    result.set_item("ssc", u64::from_be_bytes(*session.send_sequence_counter()))?;
    Ok(result)
}
