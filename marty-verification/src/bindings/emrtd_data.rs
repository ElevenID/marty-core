//! Python adapters for emrtd data.

use pyo3::prelude::*;

#[cfg(feature = "csca")]
pub(super) fn emrtd_data_pyerr(error: crate::emrtd_data::EmrtdDataError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(error.to_string())
}

#[cfg(feature = "csca")]
pub(super) fn emrtd_json<T: serde::Serialize>(value: &T) -> PyResult<String> {
    serde_json::to_string(value).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "EMRTD_DATA.ENCODING: native result serialization failed: {error}"
        ))
    })
}

/// Parse one bounded BER/DER TLV and return its native result as JSON.
#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn emrtd_parse_tlv_json(data: &[u8], offset: usize) -> PyResult<String> {
    let parsed = crate::emrtd_data::parse_tlv(data, offset).map_err(emrtd_data_pyerr)?;
    emrtd_json(&serde_json::json!({
        "tag": parsed.tag,
        "length": parsed.length,
        "value": parsed.value,
        "next_offset": parsed.next_offset,
    }))
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn emrtd_parse_ef_com_json(data: &[u8]) -> PyResult<String> {
    let parsed = crate::emrtd_data::parse_ef_com(data).map_err(emrtd_data_pyerr)?;
    emrtd_json(&parsed)
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn emrtd_parse_ef_dg1_json(data: &[u8]) -> PyResult<String> {
    let parsed = crate::emrtd_data::parse_ef_dg1(data).map_err(emrtd_data_pyerr)?;
    emrtd_json(&parsed)
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn emrtd_parse_ef_dg2_json(data: &[u8]) -> PyResult<String> {
    let parsed = crate::emrtd_data::parse_ef_dg2(data).map_err(emrtd_data_pyerr)?;
    emrtd_json(&parsed)
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn emrtd_parse_elementary_file_json(file_id: &str, data: &[u8]) -> PyResult<String> {
    let parsed =
        crate::emrtd_data::parse_elementary_file(file_id, data).map_err(emrtd_data_pyerr)?;
    emrtd_json(&parsed)
}

#[cfg(feature = "csca")]
pub(super) fn emrtd_biometric_type(value: &str) -> PyResult<crate::emrtd_data::BiometricType> {
    use crate::emrtd_data::BiometricType;

    match value.trim().to_ascii_lowercase().as_str() {
        "facial" | "facial_image" | "face" => Ok(BiometricType::FacialImage),
        "fingerprint" | "finger" => Ok(BiometricType::Fingerprint),
        "iris" => Ok(BiometricType::Iris),
        "voice" => Ok(BiometricType::Voice),
        "dna" => Ok(BiometricType::Dna),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "EMRTD_DATA.UNSUPPORTED: unsupported biometric type: {value}"
        ))),
    }
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn emrtd_parse_biometric_template_json(
    data: &[u8],
    biometric_type: &str,
) -> PyResult<String> {
    let biometric_type = emrtd_biometric_type(biometric_type)?;
    let parsed = crate::emrtd_data::parse_biometric_template(data, biometric_type)
        .map_err(emrtd_data_pyerr)?;
    emrtd_json(&parsed)
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn emrtd_validate_biometric_quality_json(template_json: &str) -> PyResult<String> {
    let template: crate::emrtd_data::BiometricTemplate = serde_json::from_str(template_json)
        .map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "EMRTD_DATA.INVALID_FORMAT: invalid biometric template JSON: {error}"
            ))
        })?;
    emrtd_json(&crate::emrtd_data::validate_template_quality(&template))
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn emrtd_parse_dg15_json(data: &[u8]) -> PyResult<String> {
    let parsed = crate::emrtd_data::parse_dg15(data).map_err(emrtd_data_pyerr)?;
    emrtd_json(&parsed)
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn emrtd_inspect_rsa_public_key_json(spki_der: &[u8]) -> PyResult<String> {
    let parsed = crate::emrtd_data::inspect_rsa_public_key(spki_der).map_err(emrtd_data_pyerr)?;
    emrtd_json(&parsed)
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn emrtd_rsa_public_key_spki(modulus: &str, public_exponent: u64) -> PyResult<Vec<u8>> {
    crate::emrtd_data::rsa_public_key_spki(modulus, public_exponent).map_err(emrtd_data_pyerr)
}
