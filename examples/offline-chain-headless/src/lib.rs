//! Bounded, stateless JSON adapter for the offline X.509 chain kernel.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use marty_x509_verification::chain::{ChainValidator, ChainValidatorConfig};
use serde::{Deserialize, Serialize};

pub const MAX_REQUEST_BYTES: usize = 1_048_576;
const MAX_CERTIFICATES: usize = 8;
const MAX_DER_BYTES: usize = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// Ordered leaf first. The final certificate need not repeat the anchor.
    chain_der_base64: Vec<String>,
    trust_anchor_der_base64: String,
    validation_time: String,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub valid: bool,
    pub code: &'static str,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl Response {
    pub fn input_error(message: &str) -> Self {
        Self {
            valid: false,
            code: "invalid_request",
            errors: vec![message.to_owned()],
            warnings: Vec::new(),
        }
    }
}

fn decode_certificate(encoded: &str) -> Result<Vec<u8>, Response> {
    // Bound the encoded representation before allocating decoded DER.
    if encoded.len() > MAX_DER_BYTES.div_ceil(3) * 4 {
        return Err(Response::input_error("certificate exceeds DER size limit"));
    }
    let der = STANDARD
        .decode(encoded)
        .map_err(|_| Response::input_error("certificate is not standard base64"))?;
    if der.is_empty() || der.len() > MAX_DER_BYTES {
        return Err(Response::input_error("certificate DER size is invalid"));
    }
    Ok(der)
}

/// Process exactly one request. Exit code: 0 valid, 1 invalid chain, 2 invalid input.
pub fn process_request(input: &[u8]) -> (Response, u8) {
    if input.len() > MAX_REQUEST_BYTES {
        return (Response::input_error("request exceeds byte limit"), 2);
    }
    let request: Request = match serde_json::from_slice(input) {
        Ok(value) => value,
        Err(_) => return (Response::input_error("malformed request JSON"), 2),
    };
    if request.chain_der_base64.is_empty() || request.chain_der_base64.len() > MAX_CERTIFICATES {
        return (
            Response::input_error("chain must contain 1 to 8 certificates"),
            2,
        );
    }
    let moment = match DateTime::parse_from_rfc3339(&request.validation_time) {
        Ok(value) => value.with_timezone(&Utc),
        Err(_) => return (Response::input_error("validation_time must be RFC 3339"), 2),
    };
    let anchor = match decode_certificate(&request.trust_anchor_der_base64) {
        Ok(value) => value,
        Err(error) => return (error, 2),
    };
    let chain = match request
        .chain_der_base64
        .iter()
        .map(|encoded| decode_certificate(encoded))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(value) => value,
        Err(error) => return (error, 2),
    };

    let config = ChainValidatorConfig {
        validation_moment: Some(moment),
        ..Default::default()
    };
    let mut validator = ChainValidator::with_config(config);
    if validator.add_trust_anchor_der(&anchor).is_err() {
        return (
            Response::input_error("trust anchor is not a DER certificate"),
            2,
        );
    }
    match validator.validate_chain_der(&chain) {
        Ok(result) => {
            let code = if result.valid {
                "valid"
            } else {
                "invalid_chain"
            };
            let exit = if result.valid { 0 } else { 1 };
            (
                Response {
                    valid: result.valid,
                    code,
                    errors: result.errors,
                    warnings: result.warnings,
                },
                exit,
            )
        }
        Err(_) => (
            Response::input_error("chain contains a malformed DER certificate"),
            2,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn request() -> Value {
        json!({
            "chain_der_base64": ["AQ=="],
            "trust_anchor_der_base64": "AQ==",
            "validation_time": "2026-07-01T00:00:00Z",
        })
    }

    fn rejected(value: &Value, message: &str) {
        let (response, exit) = process_request(&serde_json::to_vec(value).unwrap());
        assert_eq!(exit, 2);
        assert!(!response.valid);
        assert_eq!(response.code, "invalid_request");
        assert_eq!(response.errors, [message]);
    }

    #[test]
    fn chain_count_is_bounded_before_certificate_parsing() {
        for count in [0, MAX_CERTIFICATES + 1] {
            let mut value = request();
            value["chain_der_base64"] = json!(vec!["AQ=="; count]);
            rejected(&value, "chain must contain 1 to 8 certificates");
        }
    }

    #[test]
    fn explicit_rfc3339_time_is_required() {
        for moment in ["2026-07-01T00:00:00", "not-a-time"] {
            let mut value = request();
            value["validation_time"] = json!(moment);
            rejected(&value, "validation_time must be RFC 3339");
        }
        // An explicit nonzero offset passes time parsing, then fails DER parsing.
        let mut value = request();
        value["validation_time"] = json!("2026-07-01T03:00:00+03:00");
        rejected(&value, "trust anchor is not a DER certificate");
    }

    #[test]
    fn schema_rejects_unknown_fields_duplicate_fields_and_trailing_documents() {
        let mut value = request();
        value["extra"] = json!(true);
        rejected(&value, "malformed request JSON");
        let ordinary = request().to_string();
        let duplicate = ordinary.replacen(
            "\"validation_time\":",
            "\"validation_time\":\"2026-07-01T00:00:00Z\",\"validation_time\":",
            1,
        );
        for input in [duplicate, format!("{ordinary} {{}}")] {
            let (response, exit) = process_request(input.as_bytes());
            assert_eq!(exit, 2);
            assert_eq!(response.errors, ["malformed request JSON"]);
        }
    }

    #[test]
    fn decoder_requires_standard_padded_base64_and_bounded_nonempty_der() {
        for encoded in ["AQ", "_w==", "!!=="] {
            assert_eq!(
                decode_certificate(encoded).unwrap_err().errors,
                ["certificate is not standard base64"]
            );
        }
        assert_eq!(
            decode_certificate("").unwrap_err().errors,
            ["certificate DER size is invalid"]
        );
        let maximum = vec![0; MAX_DER_BYTES];
        assert_eq!(
            decode_certificate(&STANDARD.encode(&maximum)).unwrap(),
            maximum
        );
        assert!(decode_certificate(&STANDARD.encode(vec![0; MAX_DER_BYTES + 1])).is_err());
        assert_eq!(
            decode_certificate(&"A".repeat(MAX_DER_BYTES.div_ceil(3) * 4 + 4))
                .unwrap_err()
                .errors,
            ["certificate exceeds DER size limit"]
        );
    }

    #[test]
    fn request_byte_limit_includes_the_exact_boundary() {
        let mut input = vec![b' '; MAX_REQUEST_BYTES];
        let (response, exit) = process_request(&input);
        assert_eq!(exit, 2);
        assert_eq!(response.errors, ["malformed request JSON"]);
        input.push(b' ');
        let (response, exit) = process_request(&input);
        assert_eq!(exit, 2);
        assert_eq!(response.errors, ["request exceeds byte limit"]);
    }
}
