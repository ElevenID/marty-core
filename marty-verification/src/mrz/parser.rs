//! MRZ parsing for TD1, TD2, and TD3 formats.
//!
//! Per ICAO 9303 Part 3.

use super::checksum::{compute_composite_check_digit, validate_check_digit};
use crate::{VerificationError, VerificationResult};
use serde::{Deserialize, Serialize};

/// MRZ format type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MrzFormat {
    /// TD1: 3 lines × 30 characters (ID cards)
    TD1,
    /// TD2: 2 lines × 36 characters (ID cards, some visas)
    TD2,
    /// TD3: 2 lines × 44 characters (passports)
    TD3,
}

impl MrzFormat {
    /// Get the expected line length for this format.
    pub fn line_length(&self) -> usize {
        match self {
            MrzFormat::TD1 => 30,
            MrzFormat::TD2 => 36,
            MrzFormat::TD3 => 44,
        }
    }

    /// Get the expected number of lines for this format.
    pub fn line_count(&self) -> usize {
        match self {
            MrzFormat::TD1 => 3,
            MrzFormat::TD2 | MrzFormat::TD3 => 2,
        }
    }
}

/// Parsed MRZ data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mrz {
    /// MRZ format
    pub format: MrzFormat,
    /// Document type (P, I, V, etc.)
    pub document_type: String,
    /// Issuing country/organization (3-letter code)
    pub issuing_country: String,
    /// Primary identifier (surname)
    pub surname: String,
    /// Secondary identifier (given names)
    pub given_names: String,
    /// Document number
    pub document_number: String,
    /// Document number check digit
    pub document_number_check: char,
    /// Nationality (3-letter code)
    pub nationality: String,
    /// Date of birth (YYMMDD)
    pub date_of_birth: String,
    /// Date of birth check digit
    pub date_of_birth_check: char,
    /// Sex (M, F, or <)
    pub sex: char,
    /// Date of expiry (YYMMDD)
    pub date_of_expiry: String,
    /// Date of expiry check digit
    pub date_of_expiry_check: char,
    /// Optional data (varies by format)
    pub optional_data: String,
    /// Composite check digit (TD3 only)
    pub composite_check: Option<char>,
    /// Raw MRZ lines
    pub raw_lines: Vec<String>,
}

impl Mrz {
    /// Validate all check digits in the MRZ.
    pub fn validate_check_digits(&self) -> bool {
        // Document number
        if !validate_check_digit(&self.document_number, self.document_number_check) {
            return false;
        }

        // Date of birth
        if !validate_check_digit(&self.date_of_birth, self.date_of_birth_check) {
            return false;
        }

        // Date of expiry
        if !validate_check_digit(&self.date_of_expiry, self.date_of_expiry_check) {
            return false;
        }

        // Composite check (TD3)
        if let Some(composite) = self.composite_check {
            let fields = [
                (self.document_number.as_str(), self.document_number_check),
                (self.date_of_birth.as_str(), self.date_of_birth_check),
                (self.date_of_expiry.as_str(), self.date_of_expiry_check),
            ];

            let expected = compute_composite_check_digit(&fields);
            if expected != composite {
                return false;
            }
        }

        true
    }

    /// Get the MRZ information string for BAC key derivation.
    pub fn mrz_information(&self) -> String {
        super::checksum::compute_mrz_information(
            &self.document_number,
            &self.date_of_birth,
            &self.date_of_expiry,
        )
    }

    /// Get full name (given names + surname).
    pub fn full_name(&self) -> String {
        if self.given_names.is_empty() {
            self.surname.clone()
        } else {
            format!("{} {}", self.given_names, self.surname)
        }
    }
}

/// Parse MRZ from lines of text.
///
/// Automatically detects format based on line length and count.
pub fn parse_mrz(lines: &[&str]) -> VerificationResult<Mrz> {
    // Clean up lines
    let lines: Vec<String> = lines
        .iter()
        .map(|l| l.trim().to_uppercase())
        .filter(|l| !l.is_empty())
        .collect();

    if lines.is_empty() {
        return Err(VerificationError::internal(
            "No MRZ lines provided".to_string(),
        ));
    }

    // Detect format
    let format = detect_format(&lines)?;

    match format {
        MrzFormat::TD1 => parse_td1(&lines),
        MrzFormat::TD2 => parse_td2(&lines),
        MrzFormat::TD3 => parse_td3(&lines),
    }
}

/// Parse MRZ from a single string with newlines.
pub fn parse_mrz_string(mrz_text: &str) -> VerificationResult<Mrz> {
    let lines: Vec<&str> = mrz_text.lines().collect();
    parse_mrz(&lines)
}

/// Detect MRZ format from lines.
fn detect_format(lines: &[String]) -> VerificationResult<MrzFormat> {
    let line_count = lines.len();
    let first_line_len = lines.first().map(|l| l.len()).unwrap_or(0);

    match (line_count, first_line_len) {
        (3, 30) => Ok(MrzFormat::TD1),
        (2, 36) => Ok(MrzFormat::TD2),
        (2, 44) => Ok(MrzFormat::TD3),
        _ => {
            // Try to infer from line length alone
            if first_line_len == 44 {
                Ok(MrzFormat::TD3)
            } else if first_line_len == 36 {
                Ok(MrzFormat::TD2)
            } else if first_line_len == 30 {
                Ok(MrzFormat::TD1)
            } else {
                Err(VerificationError::internal(format!(
                    "Unknown MRZ format: {} lines, {} chars",
                    line_count, first_line_len
                )))
            }
        }
    }
}

/// Parse TD1 format (ID cards).
fn parse_td1(lines: &[String]) -> VerificationResult<Mrz> {
    if lines.len() < 3 {
        return Err(VerificationError::internal(
            "TD1 requires 3 lines".to_string(),
        ));
    }

    let line1 = pad_line(&lines[0], 30);
    let line2 = pad_line(&lines[1], 30);
    let line3 = pad_line(&lines[2], 30);

    // Line 1: Document type (2) + Country (3) + Doc number (9) + Check (1) + Optional (15)
    let document_type = line1[0..2].trim_end_matches('<').to_string();
    let issuing_country = line1[2..5].to_string();
    let document_number = line1[5..14].to_string();
    let document_number_check = line1.chars().nth(14).unwrap_or('<');
    let optional_data_1 = line1[15..30].to_string();

    // Line 2: DOB (6) + Check (1) + Sex (1) + DOE (6) + Check (1) + Nationality (3) + Optional (11) + Check (1)
    let date_of_birth = line2[0..6].to_string();
    let date_of_birth_check = line2.chars().nth(6).unwrap_or('<');
    let sex = line2.chars().nth(7).unwrap_or('<');
    let date_of_expiry = line2[8..14].to_string();
    let date_of_expiry_check = line2.chars().nth(14).unwrap_or('<');
    let nationality = line2[15..18].to_string();
    let optional_data_2 = line2[18..29].to_string();
    let composite_check = line2.chars().nth(29);

    // Line 3: Name
    let (surname, given_names) = parse_name(&line3);

    // Combine optional data
    let optional_data = format!(
        "{}{}",
        optional_data_1.trim_end_matches('<'),
        optional_data_2.trim_end_matches('<')
    );

    Ok(Mrz {
        format: MrzFormat::TD1,
        document_type,
        issuing_country,
        surname,
        given_names,
        document_number: document_number.trim_end_matches('<').to_string(),
        document_number_check,
        nationality,
        date_of_birth,
        date_of_birth_check,
        sex,
        date_of_expiry,
        date_of_expiry_check,
        optional_data,
        composite_check,
        raw_lines: lines.to_vec(),
    })
}

/// Parse TD2 format (ID cards, some visas).
fn parse_td2(lines: &[String]) -> VerificationResult<Mrz> {
    if lines.len() < 2 {
        return Err(VerificationError::internal(
            "TD2 requires 2 lines".to_string(),
        ));
    }

    let line1 = pad_line(&lines[0], 36);
    let line2 = pad_line(&lines[1], 36);

    // Line 1: Document type (2) + Country (3) + Name (31)
    let document_type = line1[0..2].trim_end_matches('<').to_string();
    let issuing_country = line1[2..5].to_string();
    let (surname, given_names) = parse_name(&line1[5..36]);

    // Line 2: Doc number (9) + Check (1) + Nationality (3) + DOB (6) + Check (1) +
    //         Sex (1) + DOE (6) + Check (1) + Optional (7) + Check (1)
    let document_number = line2[0..9].to_string();
    let document_number_check = line2.chars().nth(9).unwrap_or('<');
    let nationality = line2[10..13].to_string();
    let date_of_birth = line2[13..19].to_string();
    let date_of_birth_check = line2.chars().nth(19).unwrap_or('<');
    let sex = line2.chars().nth(20).unwrap_or('<');
    let date_of_expiry = line2[21..27].to_string();
    let date_of_expiry_check = line2.chars().nth(27).unwrap_or('<');
    let optional_data = line2[28..35].to_string();
    let composite_check = line2.chars().nth(35);

    Ok(Mrz {
        format: MrzFormat::TD2,
        document_type,
        issuing_country,
        surname,
        given_names,
        document_number: document_number.trim_end_matches('<').to_string(),
        document_number_check,
        nationality,
        date_of_birth,
        date_of_birth_check,
        sex,
        date_of_expiry,
        date_of_expiry_check,
        optional_data: optional_data.trim_end_matches('<').to_string(),
        composite_check,
        raw_lines: lines.to_vec(),
    })
}

/// Parse TD3 format (passports).
fn parse_td3(lines: &[String]) -> VerificationResult<Mrz> {
    if lines.len() < 2 {
        return Err(VerificationError::internal(
            "TD3 requires 2 lines".to_string(),
        ));
    }

    let line1 = pad_line(&lines[0], 44);
    let line2 = pad_line(&lines[1], 44);

    // Line 1: Document type (2) + Country (3) + Name (39)
    let document_type = line1[0..2].trim_end_matches('<').to_string();
    let issuing_country = line1[2..5].to_string();
    let (surname, given_names) = parse_name(&line1[5..44]);

    // Line 2: Doc number (9) + Check (1) + Nationality (3) + DOB (6) + Check (1) +
    //         Sex (1) + DOE (6) + Check (1) + Optional (14) + Check (1) + Composite (1)
    let document_number = line2[0..9].to_string();
    let document_number_check = line2.chars().nth(9).unwrap_or('<');
    let nationality = line2[10..13].to_string();
    let date_of_birth = line2[13..19].to_string();
    let date_of_birth_check = line2.chars().nth(19).unwrap_or('<');
    let sex = line2.chars().nth(20).unwrap_or('<');
    let date_of_expiry = line2[21..27].to_string();
    let date_of_expiry_check = line2.chars().nth(27).unwrap_or('<');
    let optional_data = line2[28..42].to_string();
    let _optional_check = line2.chars().nth(42);
    let composite_check = line2.chars().nth(43);

    Ok(Mrz {
        format: MrzFormat::TD3,
        document_type,
        issuing_country,
        surname,
        given_names,
        document_number: document_number.trim_end_matches('<').to_string(),
        document_number_check,
        nationality,
        date_of_birth,
        date_of_birth_check,
        sex,
        date_of_expiry,
        date_of_expiry_check,
        optional_data: optional_data.trim_end_matches('<').to_string(),
        composite_check,
        raw_lines: lines.to_vec(),
    })
}

/// Parse name field into surname and given names.
fn parse_name(name_field: &str) -> (String, String) {
    // Names are separated by "<<"
    // Within given names, individual names are separated by "<"
    let parts: Vec<&str> = name_field.split("<<").collect();

    let surname = parts
        .first()
        .unwrap_or(&"")
        .replace('<', " ")
        .trim()
        .to_string();

    let given_names = parts
        .get(1)
        .unwrap_or(&"")
        .replace('<', " ")
        .trim()
        .to_string();

    (surname, given_names)
}

/// Pad line to expected length.
fn pad_line(line: &str, length: usize) -> String {
    if line.len() >= length {
        line[..length].to_string()
    } else {
        format!("{:<width$}", line, width = length).replace(' ', "<")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_td3_passport() {
        let lines = [
            "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
            "L898902C36UTO6908061F9406236ZE184226B<<<<<14",
        ];

        let mrz = parse_mrz(lines.as_ref()).unwrap();

        assert_eq!(mrz.format, MrzFormat::TD3);
        assert_eq!(mrz.document_type, "P");
        assert_eq!(mrz.issuing_country, "UTO");
        assert_eq!(mrz.surname, "ERIKSSON");
        assert_eq!(mrz.given_names, "ANNA MARIA");
        assert_eq!(mrz.document_number, "L898902C3");
        assert_eq!(mrz.nationality, "UTO");
        assert_eq!(mrz.date_of_birth, "690806");
        assert_eq!(mrz.sex, 'F');
        assert_eq!(mrz.date_of_expiry, "940623");
    }

    #[test]
    fn test_parse_name() {
        assert_eq!(
            parse_name("ERIKSSON<<ANNA<MARIA<<<<<<<<"),
            ("ERIKSSON".to_string(), "ANNA MARIA".to_string())
        );

        assert_eq!(
            parse_name("SMITH<<JOHN<<<<<<<<<<<<<<<<<<"),
            ("SMITH".to_string(), "JOHN".to_string())
        );
    }

    #[test]
    fn test_mrz_format_properties() {
        assert_eq!(MrzFormat::TD1.line_length(), 30);
        assert_eq!(MrzFormat::TD1.line_count(), 3);
        assert_eq!(MrzFormat::TD3.line_length(), 44);
        assert_eq!(MrzFormat::TD3.line_count(), 2);
    }

    #[test]
    fn test_mrz_full_name() {
        let mrz = Mrz {
            format: MrzFormat::TD3,
            document_type: "P".to_string(),
            issuing_country: "USA".to_string(),
            surname: "DOE".to_string(),
            given_names: "JOHN JAMES".to_string(),
            document_number: "123456789".to_string(),
            document_number_check: '7',
            nationality: "USA".to_string(),
            date_of_birth: "850101".to_string(),
            date_of_birth_check: '0',
            sex: 'M',
            date_of_expiry: "250101".to_string(),
            date_of_expiry_check: '5',
            optional_data: String::new(),
            composite_check: Some('8'),
            raw_lines: vec![],
        };

        assert_eq!(mrz.full_name(), "JOHN JAMES DOE");
    }
}
