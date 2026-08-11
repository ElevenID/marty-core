//! Canonical Marty VDS-NC document profile.
//!
//! This module is the sole owner of VDS-NC profile normalization, envelope
//! parsing, field comparison, temporal policy, and barcode-format selection.
//! Issuers and verifiers must use these functions rather than recreating the
//! profile in a service-language adapter.

use crate::error::{Oid4vciError, Oid4vciResult};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap};

pub const MAX_VDS_NC_BARCODE_BYTES: usize = 64 * 1024;
pub const MAX_VDS_NC_PAYLOAD_BYTES: usize = 48 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VdsNcDocumentType {
    Cmc,
    Mrv,
    EVisa,
}

impl VdsNcDocumentType {
    pub fn parse(value: &str) -> Oid4vciResult<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "CMC" => Ok(Self::Cmc),
            "MRV" | "V" => Ok(Self::Mrv),
            "EVISA" | "E_VISA" | "E-VISA" => Ok(Self::EVisa),
            other => Err(profile_error(format!(
                "unsupported document type '{other}'; supported: CMC, MRV, EVISA"
            ))),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cmc => "CMC",
            Self::Mrv => "MRV",
            Self::EVisa => "EVISA",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VdsNcBarcodeFormat {
    Qr,
    Aztec,
    DataMatrix,
}

impl VdsNcBarcodeFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Qr => "QR",
            Self::Aztec => "AZTEC",
            Self::DataMatrix => "DM",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VdsNcErrorCorrection {
    Low,
    Medium,
    Quartile,
    High,
}

impl VdsNcErrorCorrection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "L",
            Self::Medium => "M",
            Self::Quartile => "Q",
            Self::High => "H",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VdsNcMetadata {
    pub version: String,
    #[serde(rename = "documentType")]
    pub document_type: String,
    #[serde(rename = "issuerId")]
    pub issuer_id: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(
        rename = "certificateReference",
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_reference: Option<String>,
    pub algorithm: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedVdsNc {
    pub header: String,
    pub country: String,
    pub payload_json: String,
    pub payload: Value,
    pub signature_b64: String,
    pub signing_input: String,
    pub metadata: VdsNcMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VdsNcProfileValidation {
    pub canonical: bool,
    pub document_type: VdsNcDocumentType,
    pub field_errors: Vec<String>,
    pub temporal_errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy)]
enum FieldKind {
    Text,
    Integer,
    Json,
}

#[derive(Clone, Copy)]
struct FieldSpec {
    key: &'static str,
    required: bool,
    kind: FieldKind,
    max_chars: Option<usize>,
    pattern: Pattern,
}

#[derive(Clone, Copy)]
enum Pattern {
    None,
    Date,
    Gender,
    Country,
}

const fn text(key: &'static str, required: bool, max_chars: usize, pattern: Pattern) -> FieldSpec {
    FieldSpec {
        key,
        required,
        kind: FieldKind::Text,
        max_chars: Some(max_chars),
        pattern,
    }
}

const fn integer(key: &'static str, required: bool) -> FieldSpec {
    FieldSpec {
        key,
        required,
        kind: FieldKind::Integer,
        max_chars: None,
        pattern: Pattern::None,
    }
}

const fn json_field(key: &'static str, required: bool) -> FieldSpec {
    FieldSpec {
        key,
        required,
        kind: FieldKind::Json,
        max_chars: None,
        pattern: Pattern::None,
    }
}

const CMC_FIELDS: &[FieldSpec] = &[
    text("docType", true, 3, Pattern::None),
    text("issuingCountry", true, 3, Pattern::Country),
    text("documentNumber", true, 9, Pattern::None),
    text("surname", true, 39, Pattern::None),
    text("givenNames", true, 39, Pattern::None),
    text("dateOfBirth", true, 8, Pattern::Date),
    text("nationality", true, 3, Pattern::Country),
    text("gender", true, 1, Pattern::Gender),
    text("dateOfIssue", true, 8, Pattern::Date),
    text("dateOfExpiry", true, 8, Pattern::Date),
    text("issuingAuthority", false, 50, Pattern::None),
    text("placeOfIssue", false, 50, Pattern::None),
];

const MRV_FIELDS: &[FieldSpec] = &[
    text("docType", true, 3, Pattern::None),
    text("issuingCountry", true, 3, Pattern::Country),
    text("documentNumber", true, 9, Pattern::None),
    text("surname", true, 39, Pattern::None),
    text("givenNames", true, 39, Pattern::None),
    text("dateOfBirth", true, 8, Pattern::Date),
    text("nationality", true, 3, Pattern::Country),
    text("gender", true, 1, Pattern::Gender),
    text("visaCategory", true, 10, Pattern::None),
    text("dateOfIssue", true, 8, Pattern::Date),
    text("dateOfExpiry", true, 8, Pattern::Date),
    text("validFrom", false, 8, Pattern::Date),
    text("validUntil", false, 8, Pattern::Date),
    text("numberOfEntries", false, 10, Pattern::None),
    integer("durationOfStay", false),
    text("placeOfIssue", false, 50, Pattern::None),
];

const EVISA_FIELDS: &[FieldSpec] = &[
    text("docType", true, 10, Pattern::None),
    text("issuingCountry", true, 3, Pattern::Country),
    text("documentNumber", true, 20, Pattern::None),
    text("surname", true, 39, Pattern::None),
    text("givenNames", true, 39, Pattern::None),
    text("dateOfBirth", true, 8, Pattern::Date),
    text("nationality", true, 3, Pattern::Country),
    text("gender", true, 1, Pattern::Gender),
    text("visaCategory", true, 10, Pattern::None),
    text("dateOfIssue", true, 8, Pattern::Date),
    text("dateOfExpiry", true, 8, Pattern::Date),
    text("validFrom", false, 8, Pattern::Date),
    text("validUntil", false, 8, Pattern::Date),
    text("numberOfEntries", false, 10, Pattern::None),
    text("purposeOfTravel", false, 50, Pattern::None),
    text("placeOfIssue", false, 50, Pattern::None),
    text("passportNumber", false, 20, Pattern::None),
    text("passportCountry", false, 3, Pattern::Country),
    text("onlineReference", false, 50, Pattern::None),
    integer("issuedAt", false),
    json_field("policyConstraints", false),
];

fn profile_error(message: impl Into<String>) -> Oid4vciError {
    Oid4vciError::ConfigError(format!("VDS_NC.INVALID_PROFILE: {}", message.into()))
}

fn validate_envelope_text(field: &str, value: &str, max_chars: usize) -> Oid4vciResult<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(profile_error(format!("{field} must not be empty")));
    }
    if normalized.chars().count() > max_chars {
        return Err(profile_error(format!(
            "{field} exceeds maximum length {max_chars}"
        )));
    }
    if normalized
        .chars()
        .any(|character| character == '~' || character.is_control())
    {
        return Err(profile_error(format!(
            "{field} must not contain the envelope delimiter or control characters"
        )));
    }
    Ok(normalized.to_owned())
}

fn fields(document_type: VdsNcDocumentType) -> &'static [FieldSpec] {
    match document_type {
        VdsNcDocumentType::Cmc => CMC_FIELDS,
        VdsNcDocumentType::Mrv => MRV_FIELDS,
        VdsNcDocumentType::EVisa => EVISA_FIELDS,
    }
}

fn normalize_text(spec: FieldSpec, value: &Value) -> Oid4vciResult<String> {
    let raw = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        _ => {
            return Err(profile_error(format!(
                "field '{}' must be a scalar string",
                spec.key
            )))
        }
    };
    let normalized = raw.trim().to_uppercase();
    if normalized
        .chars()
        .any(|character| character == '~' || character.is_control())
    {
        return Err(profile_error(format!(
            "field '{}' must not contain the envelope delimiter or control characters",
            spec.key
        )));
    }
    if let Some(max_chars) = spec.max_chars {
        if normalized.chars().count() > max_chars {
            return Err(profile_error(format!(
                "field '{}' exceeds maximum length {max_chars}",
                spec.key
            )));
        }
    }
    match spec.pattern {
        Pattern::None => {}
        Pattern::Date => {
            if normalized.len() != 8 || !normalized.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(profile_error(format!(
                    "field '{}' must use YYYYMMDD",
                    spec.key
                )));
            }
            NaiveDate::parse_from_str(&normalized, "%Y%m%d")
                .map_err(|_| profile_error(format!("field '{}' is not a valid date", spec.key)))?;
        }
        Pattern::Gender => {
            if !matches!(normalized.as_str(), "M" | "F" | "X") {
                return Err(profile_error("field 'gender' must be M, F, or X"));
            }
        }
        Pattern::Country => {
            if normalized.len() != 3 || !normalized.bytes().all(|byte| byte.is_ascii_uppercase()) {
                return Err(profile_error(format!(
                    "field '{}' must contain three uppercase ASCII letters",
                    spec.key
                )));
            }
        }
    }
    Ok(normalized)
}

fn normalize_integer(spec: FieldSpec, value: &Value) -> Oid4vciResult<i64> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .ok_or_else(|| profile_error(format!("field '{}' must be an integer", spec.key))),
        Value::String(value) => value
            .trim()
            .parse::<i64>()
            .map_err(|_| profile_error(format!("field '{}' must be an integer", spec.key))),
        _ => Err(profile_error(format!(
            "field '{}' must be an integer",
            spec.key
        ))),
    }
}

fn normalize_json(field: &str, value: &Value, depth: usize) -> Oid4vciResult<Value> {
    if depth > 16 {
        return Err(profile_error(format!(
            "field '{field}' exceeds maximum JSON depth"
        )));
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(value.clone()),
        Value::String(text) => {
            if text
                .chars()
                .any(|character| character == '~' || character.is_control())
            {
                return Err(profile_error(format!(
                    "field '{field}' must not contain the envelope delimiter or control characters"
                )));
            }
            if text.chars().count() > 512 {
                return Err(profile_error(format!(
                    "field '{field}' contains a string longer than 512 characters"
                )));
            }
            Ok(Value::String(text.clone()))
        }
        Value::Array(values) => {
            if values.len() > 128 {
                return Err(profile_error(format!(
                    "field '{field}' contains more than 128 array entries"
                )));
            }
            values
                .iter()
                .map(|value| normalize_json(field, value, depth + 1))
                .collect::<Oid4vciResult<Vec<_>>>()
                .map(Value::Array)
        }
        Value::Object(values) => {
            if values.len() > 128 {
                return Err(profile_error(format!(
                    "field '{field}' contains more than 128 object entries"
                )));
            }
            let mut canonical = BTreeMap::new();
            for (key, value) in values {
                if key.is_empty()
                    || key.chars().count() > 64
                    || key
                        .chars()
                        .any(|character| character == '~' || character.is_control())
                {
                    return Err(profile_error(format!(
                        "field '{field}' contains an invalid object key"
                    )));
                }
                canonical.insert(key.clone(), normalize_json(field, value, depth + 1)?);
            }
            serde_json::to_value(canonical)
                .map_err(|error| profile_error(format!("field '{field}': {error}")))
        }
    }
}

pub fn canonicalize_document(
    document_type: VdsNcDocumentType,
    input: &Map<String, Value>,
) -> Oid4vciResult<BTreeMap<String, Value>> {
    let allowed = fields(document_type);
    let mut canonical = BTreeMap::new();
    for spec in allowed {
        let Some(value) = input.get(spec.key) else {
            if spec.required {
                return Err(profile_error(format!(
                    "required field '{}' is missing",
                    spec.key
                )));
            }
            continue;
        };
        let normalized = match spec.kind {
            FieldKind::Text => Value::String(normalize_text(*spec, value)?),
            FieldKind::Integer => Value::Number(normalize_integer(*spec, value)?.into()),
            FieldKind::Json => normalize_json(spec.key, value, 0)?,
        };
        canonical.insert(spec.key.to_owned(), normalized);
    }
    let extra: Vec<&str> = input
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.iter().any(|spec| spec.key == *key))
        .collect();
    if !extra.is_empty() {
        return Err(profile_error(format!(
            "extra fields are not allowed: {}",
            extra.join(", ")
        )));
    }
    let actual_type = canonical
        .get("docType")
        .and_then(Value::as_str)
        .ok_or_else(|| profile_error("docType is missing"))?;
    if VdsNcDocumentType::parse(actual_type)? != document_type {
        return Err(profile_error(
            "docType does not match the requested profile",
        ));
    }
    Ok(canonical)
}

#[allow(clippy::too_many_arguments)]
pub fn build_profile_payload(
    claims: &HashMap<String, Value>,
    credential_type: &str,
    issuer_id: &str,
    key_id: &str,
    algorithm: &str,
) -> Oid4vciResult<(String, VdsNcDocumentType, String)> {
    if !matches!(
        algorithm,
        "ES256" | "ES384" | "EdDSA" | "PS256" | "PS384" | "PS512"
    ) {
        return Err(profile_error(format!(
            "unsupported signature algorithm '{algorithm}'"
        )));
    }
    let mut input: Map<String, Value> = claims.clone().into_iter().collect();
    let document_type_value = input
        .get("docType")
        .and_then(Value::as_str)
        .unwrap_or(credential_type);
    let document_type = VdsNcDocumentType::parse(document_type_value)?;
    input
        .entry("docType".to_owned())
        .or_insert_with(|| Value::String(document_type.as_str().to_owned()));
    if !input.contains_key("issuingCountry") {
        for alias in ["issuing_country", "issuer_country", "country_code"] {
            if let Some(value) = input.remove(alias) {
                input.insert("issuingCountry".to_owned(), value);
                break;
            }
        }
    }
    let signer_id = match input.remove("signerId") {
        Some(Value::String(value)) => validate_envelope_text("signerId", &value, 512)?,
        Some(_) => return Err(profile_error("signerId must be a non-empty string")),
        None => validate_envelope_text("issuer_id", issuer_id, 512)?,
    };
    let certificate_reference = match input.remove("certificateReference") {
        Some(Value::String(value)) => {
            Some(validate_envelope_text("certificateReference", &value, 16)?)
        }
        Some(_) => {
            return Err(profile_error(
                "certificateReference must be a non-empty string of at most 16 characters",
            ))
        }
        None => None,
    };
    let mut canonical = canonicalize_document(document_type, &input)?;
    let metadata = VdsNcMetadata {
        version: "1.0".to_owned(),
        document_type: document_type.as_str().to_owned(),
        issuer_id: signer_id,
        key_id: validate_envelope_text("key_id", key_id, 512)?,
        certificate_reference,
        algorithm: algorithm.to_owned(),
    };
    canonical.insert(
        "_vds".to_owned(),
        serde_json::to_value(metadata).map_err(|error| profile_error(error.to_string()))?,
    );
    let payload_json = serde_json::to_string(&canonical)
        .map_err(|error| profile_error(format!("payload serialization failed: {error}")))?;
    if payload_json.len() > MAX_VDS_NC_PAYLOAD_BYTES {
        return Err(profile_error(format!(
            "payload exceeds {MAX_VDS_NC_PAYLOAD_BYTES} bytes"
        )));
    }
    let country = canonical
        .get("issuingCountry")
        .and_then(Value::as_str)
        .expect("validated issuingCountry")
        .to_owned();
    Ok((payload_json, document_type, country))
}

fn parse_header(header: &str) -> Oid4vciResult<String> {
    if header.len() != 7 || !header.starts_with("DC03") {
        return Err(profile_error(
            "header must be exactly DC03 followed by a 3-letter country code",
        ));
    }
    let country = &header[4..];
    if !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(profile_error(
            "header country code must contain three uppercase ASCII letters",
        ));
    }
    Ok(country.to_owned())
}

fn validate_payload(payload_json: &str, country: &str) -> Oid4vciResult<(Value, VdsNcMetadata)> {
    if payload_json.len() > MAX_VDS_NC_PAYLOAD_BYTES {
        return Err(profile_error(format!(
            "payload exceeds {MAX_VDS_NC_PAYLOAD_BYTES} bytes"
        )));
    }
    let payload: Value = serde_json::from_str(payload_json)
        .map_err(|error| profile_error(format!("payload is not valid JSON: {error}")))?;
    let object = payload
        .as_object()
        .ok_or_else(|| profile_error("payload must be a JSON object"))?;
    let reserialized = serde_json::to_string(&payload)
        .map_err(|error| profile_error(format!("payload serialization failed: {error}")))?;
    if reserialized != payload_json {
        return Err(profile_error("payload is not in canonical JSON form"));
    }
    let metadata: VdsNcMetadata = serde_json::from_value(
        object
            .get("_vds")
            .cloned()
            .ok_or_else(|| profile_error("payload is missing _vds metadata"))?,
    )
    .map_err(|error| profile_error(format!("invalid _vds metadata: {error}")))?;
    if metadata.version != "1.0" {
        return Err(profile_error("unsupported _vds profile version"));
    }
    let document_type = VdsNcDocumentType::parse(&metadata.document_type)?;
    if metadata.document_type != document_type.as_str() {
        return Err(profile_error(
            "_vds documentType must use its canonical profile name",
        ));
    }
    if validate_envelope_text("_vds issuerId", &metadata.issuer_id, 512)? != metadata.issuer_id {
        return Err(profile_error("_vds issuerId is not canonical"));
    }
    if validate_envelope_text("_vds keyId", &metadata.key_id, 512)? != metadata.key_id {
        return Err(profile_error("_vds keyId is not canonical"));
    }
    if let Some(reference) = metadata.certificate_reference.as_deref() {
        if validate_envelope_text("_vds certificateReference", reference, 16)? != reference {
            return Err(profile_error("_vds certificateReference is not canonical"));
        }
    }
    if !matches!(
        metadata.algorithm.as_str(),
        "ES256" | "ES384" | "EdDSA" | "PS256" | "PS384" | "PS512"
    ) {
        return Err(profile_error(format!(
            "unsupported signature algorithm '{}'",
            metadata.algorithm
        )));
    }
    let mut document = object.clone();
    document.remove("_vds");
    let canonical = canonicalize_document(document_type, &document)?;
    let canonical_value = serde_json::to_value(canonical)
        .map_err(|error| profile_error(format!("canonicalization failed: {error}")))?;
    if canonical_value != Value::Object(document) {
        return Err(profile_error("payload document fields are not canonical"));
    }
    if object.get("issuingCountry").and_then(Value::as_str) != Some(country) {
        return Err(profile_error(
            "header country does not match payload issuingCountry",
        ));
    }
    Ok((payload, metadata))
}

pub fn parse_barcode(barcode: &str) -> Oid4vciResult<ParsedVdsNc> {
    if barcode.is_empty() || barcode.len() > MAX_VDS_NC_BARCODE_BYTES || barcode.contains('\0') {
        return Err(profile_error(format!(
            "barcode must contain 1..={MAX_VDS_NC_BARCODE_BYTES} bytes and no NUL"
        )));
    }
    let mut parts = barcode.split('~');
    let header = parts.next().unwrap_or_default();
    let payload_json = parts.next().unwrap_or_default();
    let signature_b64 = parts.next().unwrap_or_default();
    if header.is_empty()
        || payload_json.is_empty()
        || signature_b64.is_empty()
        || parts.next().is_some()
    {
        return Err(profile_error(
            "barcode must contain exactly three non-empty tilde-separated segments",
        ));
    }
    let country = parse_header(header)?;
    let (payload, metadata) = validate_payload(payload_json, &country)?;
    Ok(ParsedVdsNc {
        header: header.to_owned(),
        country,
        payload_json: payload_json.to_owned(),
        payload,
        signature_b64: signature_b64.to_owned(),
        signing_input: format!("{header}~{payload_json}"),
        metadata,
    })
}

pub fn validate_signing_input(signing_input: &str) -> Oid4vciResult<(String, String)> {
    let mut parts = signing_input.split('~');
    let header = parts.next().unwrap_or_default();
    let payload = parts.next().unwrap_or_default();
    if header.is_empty() || payload.is_empty() || parts.next().is_some() {
        return Err(profile_error(
            "signing input must contain exactly header~payload",
        ));
    }
    let country = parse_header(header)?;
    validate_payload(payload, &country)?;
    Ok((header.to_owned(), payload.to_owned()))
}

pub fn validate_fields(payload: &Value, printed_values: Option<&Value>) -> Vec<String> {
    let Some(printed) = printed_values else {
        return Vec::new();
    };
    let Some(printed) = printed.as_object() else {
        return vec!["VDS_NC.INVALID_PRINTED_FIELDS: printed values must be an object".to_owned()];
    };
    let Some(document) = payload.as_object() else {
        return vec!["VDS_NC.INVALID_PROFILE: payload must be an object".to_owned()];
    };
    let mut errors = Vec::new();
    for (key, printed_value) in printed {
        let Some(vds_value) = document.get(key) else {
            errors.push(format!("VDS_NC.FIELD_MISSING: {key}"));
            continue;
        };
        let normalize = |value: &Value| match value {
            Value::String(value) => Value::String(value.trim().to_uppercase()),
            other => other.clone(),
        };
        if normalize(printed_value) != normalize(vds_value) {
            errors.push(format!("VDS_NC.FIELD_MISMATCH: {key}"));
        }
    }
    errors
}

pub fn validate_temporal(payload: &Value, evaluation_date: NaiveDate) -> Vec<String> {
    let Some(document) = payload.as_object() else {
        return vec!["VDS_NC.INVALID_PROFILE: payload must be an object".to_owned()];
    };
    let mut errors = Vec::new();
    for (field, relation, code) in [
        ("dateOfIssue", "not_before", "VDS_NC.NOT_YET_VALID"),
        ("validFrom", "not_before", "VDS_NC.NOT_YET_VALID"),
        ("dateOfExpiry", "not_after", "VDS_NC.EXPIRED"),
        ("validUntil", "not_after", "VDS_NC.EXPIRED"),
    ] {
        let Some(value) = document.get(field).and_then(Value::as_str) else {
            continue;
        };
        match NaiveDate::parse_from_str(value, "%Y%m%d") {
            Ok(date) if relation == "not_before" && evaluation_date < date => {
                errors.push(format!("{code}: before {field}"));
            }
            Ok(date) if relation == "not_after" && evaluation_date > date => {
                errors.push(format!("{code}: after {field}"));
            }
            Ok(_) => {}
            Err(_) => errors.push(format!("VDS_NC.INVALID_DATE: {field}")),
        }
    }
    errors
}

#[must_use]
pub const fn recommended_error_correction(
    document_type: VdsNcDocumentType,
) -> VdsNcErrorCorrection {
    match document_type {
        VdsNcDocumentType::Cmc | VdsNcDocumentType::EVisa => VdsNcErrorCorrection::High,
        VdsNcDocumentType::Mrv => VdsNcErrorCorrection::Quartile,
    }
}

pub fn select_barcode_format(
    payload_size: usize,
    correction: VdsNcErrorCorrection,
    preferred: Option<VdsNcBarcodeFormat>,
) -> Oid4vciResult<VdsNcBarcodeFormat> {
    let capacity = |format| match (format, correction) {
        (VdsNcBarcodeFormat::Qr, VdsNcErrorCorrection::Low) => 2_953,
        (VdsNcBarcodeFormat::Qr, VdsNcErrorCorrection::Medium) => 2_331,
        (VdsNcBarcodeFormat::Qr, VdsNcErrorCorrection::Quartile) => 1_663,
        (VdsNcBarcodeFormat::Qr, VdsNcErrorCorrection::High) => 1_273,
        (VdsNcBarcodeFormat::Aztec, VdsNcErrorCorrection::Low) => 3_832,
        (VdsNcBarcodeFormat::Aztec, VdsNcErrorCorrection::Medium) => 3_067,
        (VdsNcBarcodeFormat::Aztec, VdsNcErrorCorrection::Quartile) => 2_293,
        (VdsNcBarcodeFormat::Aztec, VdsNcErrorCorrection::High) => 1_914,
        (VdsNcBarcodeFormat::DataMatrix, _) => 2_335,
    };
    if let Some(preferred) = preferred {
        if payload_size <= capacity(preferred) {
            return Ok(preferred);
        }
    }
    if payload_size <= capacity(VdsNcBarcodeFormat::Qr) {
        return Ok(VdsNcBarcodeFormat::Qr);
    }
    if payload_size <= capacity(VdsNcBarcodeFormat::Aztec) {
        return Ok(VdsNcBarcodeFormat::Aztec);
    }
    if payload_size <= capacity(VdsNcBarcodeFormat::DataMatrix) {
        return Ok(VdsNcBarcodeFormat::DataMatrix);
    }
    Err(profile_error(format!(
        "payload size {payload_size} exceeds supported barcode capacity"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cmc() -> Map<String, Value> {
        json!({
            "docType": " cmc ",
            "issuingCountry": "aus",
            "documentNumber": "x123456",
            "surname": "Example",
            "givenNames": "Ada",
            "dateOfBirth": "19900102",
            "nationality": "aus",
            "gender": "f",
            "dateOfIssue": "20260101",
            "dateOfExpiry": "20300101"
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn shared_profile_vectors_conform() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/vectors/vds_nc_profile.json");
        let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        for vector in vectors["canonical"].as_array().unwrap() {
            let document_type =
                VdsNcDocumentType::parse(vector["document_type"].as_str().unwrap()).unwrap();
            let input = vector["input"].as_object().unwrap();
            let canonical = canonicalize_document(document_type, input).unwrap();
            assert_eq!(
                serde_json::to_string(&canonical).unwrap(),
                vector["expected_json"].as_str().unwrap(),
                "{}",
                vector["name"]
            );
        }
        for vector in vectors["invalid"].as_array().unwrap() {
            let document_type =
                VdsNcDocumentType::parse(vector["document_type"].as_str().unwrap()).unwrap();
            let error = canonicalize_document(document_type, vector["input"].as_object().unwrap())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(vector["error_contains"].as_str().unwrap()),
                "{}: {error}",
                vector["name"]
            );
        }
    }

    #[test]
    fn canonicalizes_profile_and_rejects_drift() {
        let canonical = canonicalize_document(VdsNcDocumentType::Cmc, &cmc()).unwrap();
        assert_eq!(canonical["surname"], "EXAMPLE");
        assert_eq!(canonical["issuingCountry"], "AUS");

        let mut extra = cmc();
        extra.insert("unexpected".to_owned(), json!(true));
        assert!(canonicalize_document(VdsNcDocumentType::Cmc, &extra).is_err());

        let mut invalid_date = cmc();
        invalid_date.insert("dateOfBirth".to_owned(), json!("20260231"));
        assert!(canonicalize_document(VdsNcDocumentType::Cmc, &invalid_date).is_err());

        let mut delimiter = cmc();
        delimiter.insert("surname".to_owned(), json!("EXAM~PLE"));
        assert!(canonicalize_document(VdsNcDocumentType::Cmc, &delimiter).is_err());
    }

    #[test]
    fn parses_only_canonical_bounded_envelopes() {
        let claims: HashMap<String, Value> = cmc().into_iter().collect();
        let (payload, _, country) =
            build_profile_payload(&claims, "CMC", "TESTSGN", "key-1", "ES256").unwrap();
        let barcode = format!("DC03{country}~{payload}~c2ln");
        let parsed = parse_barcode(&barcode).unwrap();
        assert_eq!(parsed.metadata.issuer_id, "TESTSGN");

        assert!(parse_barcode(&barcode.replace(":", ": ")).is_err());
        assert!(parse_barcode("DC03AUS~{}~sig~extra").is_err());
        assert!(parse_barcode(&format!("{}~{{}}~sig", "X".repeat(7))).is_err());

        assert!(build_profile_payload(&claims, "CMC", "TESTSGN", "key-1", "RS256").is_err());
        assert!(build_profile_payload(&claims, "CMC", "TEST~SGN", "key-1", "ES256").is_err());
        assert!(build_profile_payload(&claims, "CMC", "TESTSGN", "", "ES256").is_err());

        let noncanonical_metadata =
            barcode.replace(r#""documentType":"CMC""#, r#""documentType":"cmc""#);
        assert!(parse_barcode(&noncanonical_metadata).is_err());
    }

    #[test]
    fn field_and_temporal_policy_fail_closed() {
        let claims: HashMap<String, Value> = cmc().into_iter().collect();
        let (payload, _, _) =
            build_profile_payload(&claims, "CMC", "TESTSGN", "key-1", "ES256").unwrap();
        let payload: Value = serde_json::from_str(&payload).unwrap();
        assert!(validate_fields(&payload, Some(&json!({"surname": "example"}))).is_empty());
        assert_eq!(
            validate_fields(&payload, Some(&json!({"surname": "changed"}))),
            ["VDS_NC.FIELD_MISMATCH: surname"]
        );
        assert!(
            validate_temporal(&payload, NaiveDate::from_ymd_opt(2027, 1, 1).unwrap()).is_empty()
        );
        assert!(
            !validate_temporal(&payload, NaiveDate::from_ymd_opt(2031, 1, 1).unwrap()).is_empty()
        );
    }

    #[test]
    fn evisa_preserves_bounded_signed_policy_constraints() {
        let claims = serde_json::from_value(serde_json::json!({
            "docType": "EVISA",
            "issuingCountry": "AUS",
            "documentNumber": "V123456",
            "surname": "EXAMPLE",
            "givenNames": "ADA",
            "dateOfBirth": "19900102",
            "nationality": "AUS",
            "gender": "F",
            "visaCategory": "B2",
            "dateOfIssue": "20260101",
            "dateOfExpiry": "20300101",
            "placeOfIssue": "CANBERRA",
            "issuedAt": 1786442597,
            "policyConstraints": {
                "allowed_countries": ["AUS", "NZL"],
                "employment": false
            }
        }))
        .unwrap();
        let (payload, document_type, _) =
            build_profile_payload(&claims, "EVISA", "VISASGN", "key-1", "PS256").unwrap();
        let payload: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(document_type, VdsNcDocumentType::EVisa);
        assert_eq!(payload["policyConstraints"]["employment"], false);
        assert!(payload.get("passportNumber").is_none());
    }

    #[test]
    fn selects_existing_barcode_policy() {
        assert_eq!(
            recommended_error_correction(VdsNcDocumentType::EVisa),
            VdsNcErrorCorrection::High
        );
        assert_eq!(
            select_barcode_format(1_000, VdsNcErrorCorrection::High, None).unwrap(),
            VdsNcBarcodeFormat::Qr
        );
        assert_eq!(
            select_barcode_format(
                1_500,
                VdsNcErrorCorrection::High,
                Some(VdsNcBarcodeFormat::Qr)
            )
            .unwrap(),
            VdsNcBarcodeFormat::Aztec
        );
        assert!(select_barcode_format(4_000, VdsNcErrorCorrection::High, None).is_err());
    }
}
