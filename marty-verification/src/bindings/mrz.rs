//! Python adapters for mrz.

use super::*;

/// Python wrapper for parsed MRZ data.
#[pyclass(name = "MrzData", from_py_object)]
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
    #[pyo3(get)]
    pub check_digits_valid: bool,
}

impl From<crate::mrz::Mrz> for PyMrzData {
    fn from(mrz: crate::mrz::Mrz) -> Self {
        let check_digits_valid = mrz.validate_check_digits();
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
            check_digits_valid,
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
        dict.set_item("check_digits_valid", self.check_digits_valid)?;
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
pub(super) fn parse_mrz(lines: Vec<String>) -> PyResult<PyMrzData> {
    let line_refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    let mrz = crate::mrz::parse_mrz(&line_refs).map_err(to_pyerr)?;
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
pub(super) fn compute_check_digit(input_string: &str) -> String {
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
pub(super) fn validate_check_digit(data: &str, check_digit: &str) -> bool {
    if let Some(c) = check_digit.chars().next() {
        crate::mrz::validate_check_digit(data, c)
    } else {
        false
    }
}
