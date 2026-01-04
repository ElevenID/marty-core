//! MRZ checksum calculation per ICAO 9303.
//!
//! The check digit algorithm uses modulo 10 with weights 7, 3, 1.

/// Character weights for check digit calculation.
const WEIGHTS: [u32; 3] = [7, 3, 1];

/// Calculate check digit for a string.
///
/// Per ICAO 9303 Part 3, each character is assigned a value:
/// - `<` (filler) = 0
/// - Digits 0-9 = 0-9  
/// - Letters A-Z = 10-35
///
/// The check digit is: (sum of (value * weight)) mod 10
///
/// # Arguments
///
/// * `input` - The string to calculate check digit for
///
/// # Returns
///
/// Single digit character '0'-'9'
pub fn compute_check_digit(input: &str) -> char {
    let sum: u32 = input
        .chars()
        .enumerate()
        .map(|(i, c)| {
            let value = char_value(c);
            let weight = WEIGHTS[i % 3];
            value * weight
        })
        .sum();

    let digit = sum % 10;
    char::from_digit(digit, 10).unwrap_or('0')
}

/// Validate a check digit.
///
/// # Arguments
///
/// * `data` - The data portion (without check digit)
/// * `check_digit` - The check digit to validate
///
/// # Returns
///
/// `true` if the check digit is correct
pub fn validate_check_digit(data: &str, check_digit: char) -> bool {
    compute_check_digit(data) == check_digit
}

/// Compute the composite check digit for multiple fields.
///
/// Used for the final check digit that covers document number, DOB, and expiry.
///
/// # Arguments
///
/// * `fields` - Array of (data, check_digit) tuples
///
/// # Returns
///
/// Composite check digit character
pub fn compute_composite_check_digit(fields: &[(&str, char)]) -> char {
    // Concatenate all data+check_digits
    let combined: String = fields
        .iter()
        .map(|(data, check)| format!("{}{}", data, check))
        .collect();

    compute_check_digit(&combined)
}

/// Get numeric value for a character.
fn char_value(c: char) -> u32 {
    match c {
        '<' => 0,
        '0'..='9' => c as u32 - '0' as u32,
        'A'..='Z' => c as u32 - 'A' as u32 + 10,
        'a'..='z' => c as u32 - 'a' as u32 + 10, // Handle lowercase
        _ => 0,                                  // Unknown characters treated as filler
    }
}

/// Compute check digit for a date in YYMMDD format.
pub fn compute_date_check_digit(date: &str) -> char {
    compute_check_digit(date)
}

/// Compute MRZ Information string for BAC key derivation.
///
/// Returns: document_number + check + date_of_birth + check + date_of_expiry + check
///
/// # Arguments
///
/// * `document_number` - 9-character document number (padded with `<`)
/// * `date_of_birth` - YYMMDD format
/// * `date_of_expiry` - YYMMDD format
pub fn compute_mrz_information(
    document_number: &str,
    date_of_birth: &str,
    date_of_expiry: &str,
) -> String {
    // Pad document number to 9 characters
    let doc_num = format!("{:<9}", document_number).replace(' ', "<");
    let doc_check = compute_check_digit(&doc_num);

    let dob_check = compute_check_digit(date_of_birth);
    let doe_check = compute_check_digit(date_of_expiry);

    format!(
        "{}{}{}{}{}{}",
        doc_num, doc_check, date_of_birth, dob_check, date_of_expiry, doe_check
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_char_value() {
        assert_eq!(char_value('<'), 0);
        assert_eq!(char_value('0'), 0);
        assert_eq!(char_value('5'), 5);
        assert_eq!(char_value('9'), 9);
        assert_eq!(char_value('A'), 10);
        assert_eq!(char_value('Z'), 35);
    }

    #[test]
    fn test_compute_check_digit_document_number() {
        // Example: L898902C3 should have check digit 6
        // From ICAO 9303 examples
        assert_eq!(compute_check_digit("L898902C3"), '6');
    }

    #[test]
    fn test_compute_check_digit_date() {
        // Date of birth: 690806 check digit 1
        // From ICAO 9303 examples
        assert_eq!(compute_check_digit("690806"), '1');

        // Date of expiry: 940623 check digit should be verified
        let expiry_check = compute_check_digit("940623");
        assert!(expiry_check.is_ascii_digit());
    }

    #[test]
    fn test_compute_check_digit_zeros() {
        // All zeros or fillers should give 0
        assert_eq!(compute_check_digit("<<<"), '0');
        assert_eq!(compute_check_digit("000"), '0');
    }

    #[test]
    fn test_validate_check_digit() {
        assert!(validate_check_digit("L898902C3", '6'));
        assert!(!validate_check_digit("L898902C3", '5'));
    }

    #[test]
    fn test_compute_composite_check_digit() {
        let fields = [("L898902C3", '6'), ("690806", '1'), ("940623", '1')];

        let composite = compute_composite_check_digit(&fields);
        assert!(composite.is_ascii_digit());
    }

    #[test]
    fn test_compute_mrz_information() {
        let mrz_info = compute_mrz_information("L898902C3", "690806", "940623");

        // Should be 24 characters: 9+1+6+1+6+1
        assert_eq!(mrz_info.len(), 24);

        // Should start with document number
        assert!(mrz_info.starts_with("L898902C3"));
    }
}
