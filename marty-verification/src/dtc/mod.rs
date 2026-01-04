//! Digital Travel Credential helpers exposed via Python bindings.
//!
//! These helpers operate on JSON blobs that mirror the Python/proto shapes for
//! DTC create/sign/verify. They normalize data groups (base64), compute
//! canonical payloads, and perform lightweight signing/verification.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose, Engine as _};
use const_oid::ObjectIdentifier;
use der::Decode;
use pkcs8::PrivateKeyInfo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey};
use p384::{PublicKey as P384PublicKey, SecretKey as P384SecretKey};
use spki::SubjectPublicKeyInfoRef;
use x509_cert::Certificate;
use crate::error::{codes as error_codes, VerificationError, VerificationResult};
use crate::verification::ChainValidator;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DataGroup {
    pub dg_number: i32,
    #[serde(default)]
    pub data: String, // base64-encoded
    #[serde(default)]
    pub data_type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Type1Profile {
    #[serde(default)]
    pub mrz_line1: String,
    #[serde(default)]
    pub mrz_line2: String,
    #[serde(default)]
    pub sod_hash: String,
    #[serde(default)]
    pub issuing_state: String,
    #[serde(default)]
    pub passive_auth_ok: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Type2Profile {
    #[serde(default)]
    pub chip_auth_public_key: String,
    #[serde(default)]
    pub device_public_key: String,
    #[serde(default)]
    pub attestation_cert_hash: String,
    #[serde(default)]
    pub passive_auth_ok: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Type3Profile {
    #[serde(default)]
    pub remote_attestation_report: String,
    #[serde(default)]
    pub device_binding_id: String,
    #[serde(default)]
    pub ephemeral_public_key: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub attestation_cert_hash: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SignatureInfo {
    #[serde(default)]
    pub signature_date: String,
    #[serde(default)]
    pub signer_id: String,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub is_valid: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PersonalDetails {
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub date_of_birth: String,
    #[serde(default)]
    pub gender: String,
    #[serde(default)]
    pub nationality: String,
    #[serde(default)]
    pub place_of_birth: String,
    #[serde(default)]
    pub portrait: String, // base64
    #[serde(default)]
    pub signature: String, // base64
    #[serde(default)]
    pub other_names: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DtcRecord {
    #[serde(default)]
    pub dtc_id: String,
    #[serde(default)]
    pub passport_number: String,
    #[serde(default)]
    pub issuing_authority: String,
    #[serde(default)]
    pub issue_date: String,
    #[serde(default)]
    pub expiry_date: String,
    #[serde(default)]
    pub personal_details: PersonalDetails,
    #[serde(default)]
    pub data_groups: Vec<DataGroup>,
    #[serde(default)]
    pub dtc_type: i32,
    #[serde(default)]
    pub access_control: i32,
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub dtc_valid_from: String,
    #[serde(default)]
    pub dtc_valid_until: String,
    #[serde(default)]
    pub type1_profile: Option<Type1Profile>,
    #[serde(default)]
    pub type2_profile: Option<Type2Profile>,
    #[serde(default)]
    pub type3_profile: Option<Type3Profile>,
    #[serde(default)]
    pub is_signed: bool,
    #[serde(default)]
    pub is_revoked: bool,
    #[serde(default)]
    pub linked_passport: Option<String>,
    #[serde(default)]
    pub creation_date: String,
    #[serde(default)]
    pub signature_info: Option<SignatureInfo>,
}

fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Coarse ISO8601 without timezone (UTC assumed)
    format!("{:010}Z", secs)
}

/// Parse an ISO8601 date string into Unix timestamp (seconds).
/// Supports formats: "YYYY-MM-DD", "YYYY-MM-DDTHH:MM:SSZ", and epoch-style "SSSSSSSSSSZ"
fn parse_iso_to_epoch(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Try epoch-style format first (e.g., "1234567890Z")
    if s.ends_with('Z') && s.chars().take(s.len() - 1).all(|c| c.is_ascii_digit()) {
        return s[..s.len() - 1].parse().ok();
    }

    // Try ISO8601 date only: YYYY-MM-DD
    if s.len() == 10 && s.chars().nth(4) == Some('-') && s.chars().nth(7) == Some('-') {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 3 {
            let year: i32 = parts[0].parse().ok()?;
            let month: u32 = parts[1].parse().ok()?;
            let day: u32 = parts[2].parse().ok()?;
            // Approximate calculation: days since epoch
            let days = (year - 1970) as i64 * 365
                + ((year - 1969) / 4) as i64 // leap years
                + days_before_month(month, is_leap_year(year)) as i64
                + (day - 1) as i64;
            return Some((days * 86400) as u64);
        }
    }

    // Try ISO8601 datetime: YYYY-MM-DDTHH:MM:SSZ
    if s.len() >= 19 && s.contains('T') {
        let s = s.trim_end_matches('Z').trim_end_matches("+00:00");
        let parts: Vec<&str> = s.split('T').collect();
        if parts.len() == 2 {
            let date_parts: Vec<&str> = parts[0].split('-').collect();
            let time_parts: Vec<&str> = parts[1].split(':').collect();
            if date_parts.len() == 3 && time_parts.len() >= 2 {
                let year: i32 = date_parts[0].parse().ok()?;
                let month: u32 = date_parts[1].parse().ok()?;
                let day: u32 = date_parts[2].parse().ok()?;
                let hour: u32 = time_parts[0].parse().ok()?;
                let minute: u32 = time_parts[1].parse().ok()?;
                let second: u32 = time_parts.get(2).and_then(|s| s.split('.').next()?.parse().ok()).unwrap_or(0);

                let days = (year - 1970) as i64 * 365
                    + ((year - 1969) / 4) as i64
                    + days_before_month(month, is_leap_year(year)) as i64
                    + (day - 1) as i64;
                let secs = days * 86400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;
                return Some(secs as u64);
            }
        }
    }

    None
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_before_month(month: u32, leap: bool) -> u32 {
    const DAYS: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    const DAYS_LEAP: [u32; 12] = [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335];
    let idx = (month.saturating_sub(1)) as usize;
    if leap { DAYS_LEAP.get(idx).copied().unwrap_or(0) } else { DAYS.get(idx).copied().unwrap_or(0) }
}

fn b64_encode(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    general_purpose::STANDARD.decode(s.as_bytes()).ok()
}

fn canonical_payload(record: &DtcRecord) -> VerificationResult<Vec<u8>> {
    // Serialize with stable key ordering (BTreeMap) and without signature_info to avoid self-reference
    let mut map = serde_json::to_value(record).map_err(|e| {
        VerificationError::dtc_invalid(format!("Failed to serialize DTC payload: {}", e))
    })?;
    if let Value::Object(ref mut obj) = map {
        obj.remove("signature_info");
        obj.remove("is_signed");
    }
    serde_json::to_vec(&map).map_err(|e| {
        VerificationError::dtc_invalid(format!("Failed to serialize DTC payload: {}", e))
    })
}

fn normalize_base64(value: &mut String) {
    // If already base64, leave as-is; otherwise attempt to interpret as bytes
    if b64_decode(value).is_none() {
        // treat as UTF-8 and encode
        let enc = b64_encode(value.as_bytes());
        *value = enc;
    }
}

fn normalize_record(mut record: DtcRecord) -> DtcRecord {
    if record.dtc_id.is_empty() {
        record.dtc_id = now_iso();
    }
    if record.creation_date.is_empty() {
        record.creation_date = now_iso();
    }
    // Normalize data groups
    for dg in &mut record.data_groups {
        normalize_base64(&mut dg.data);
    }
    // Normalize portrait/signature
    normalize_base64(&mut record.personal_details.portrait);
    normalize_base64(&mut record.personal_details.signature);

    // Fill Type1 sod_hash if missing
    if let Some(ref mut t1) = record.type1_profile {
        if t1.sod_hash.is_empty() {
            let dg_bytes: Vec<u8> = record
                .data_groups
                .iter()
                .filter_map(|dg| b64_decode(&dg.data))
                .flatten()
                .collect();
            if !dg_bytes.is_empty() {
                let mut hasher = Sha256::new();
                hasher.update(&dg_bytes);
                t1.sod_hash = hex::encode(hasher.finalize());
            }
        }
        if t1.issuing_state.is_empty() {
            t1.issuing_state = record.issuing_authority.clone();
        }
    }

    record
}

fn decode_pem_body(pem: &str) -> VerificationResult<Vec<u8>> {
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----") || line.is_empty() {
            continue;
        }
        b64.push_str(line);
    }
    if b64.is_empty() {
        return Err(VerificationError::dtc_invalid("PEM payload missing".to_string()));
    }
    general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| VerificationError::dtc_invalid(format!("Invalid PEM base64: {}", e)))
}

#[derive(Debug, Clone, Copy)]
enum EcCurve {
    P256,
    P384,
}

fn curve_from_oid(oid: ObjectIdentifier) -> Option<EcCurve> {
    match oid.to_string().as_str() {
        "1.2.840.10045.3.1.7" => Some(EcCurve::P256),
        "1.3.132.0.34" => Some(EcCurve::P384),
        _ => None,
    }
}

fn detect_curve_from_private_key_pem(pem: &str) -> VerificationResult<EcCurve> {
    let der = decode_pem_body(pem)?;
    if let Ok(pkcs8) = PrivateKeyInfo::try_from(der.as_slice()) {
        if let Some(params) = pkcs8.algorithm.parameters {
            let oid = params
                .decode_as::<ObjectIdentifier>()
                .map_err(|e| VerificationError::dtc_invalid(e.to_string()))?;
            if let Some(curve) = curve_from_oid(oid) {
                return Ok(curve);
            }
        }
    }

    if P256SecretKey::from_sec1_der(&der).is_ok() {
        return Ok(EcCurve::P256);
    }
    if P384SecretKey::from_sec1_der(&der).is_ok() {
        return Ok(EcCurve::P384);
    }

    Err(VerificationError::dtc_unsupported(
        "Unsupported EC private key format or curve".to_string(),
    ))
}

fn detect_curve_from_public_key_pem(pem: &str) -> VerificationResult<EcCurve> {
    let der = decode_pem_body(pem)?;
    if let Ok(spki) = SubjectPublicKeyInfoRef::try_from(der.as_slice()) {
        if let Some(params) = spki.algorithm.parameters {
            let oid = params
                .decode_as::<ObjectIdentifier>()
                .map_err(|e| VerificationError::dtc_invalid(e.to_string()))?;
            if let Some(curve) = curve_from_oid(oid) {
                return Ok(curve);
            }
        }
    }

    match der.len() {
        65 => Ok(EcCurve::P256),
        97 => Ok(EcCurve::P384),
        _ => Err(VerificationError::dtc_unsupported(
            "Unsupported EC public key format or curve".to_string(),
        )),
    }
}

fn parse_p256_signing_key(pem: &str) -> VerificationResult<P256SigningKey> {
    let pkcs8 = P256SigningKey::from_pkcs8_pem(pem).map_err(|e| e.to_string());
    if let Ok(key) = pkcs8 {
        return Ok(key);
    }
    let pkcs8_err = pkcs8.err().unwrap_or_else(|| "unknown PKCS#8 error".to_string());
    let der = decode_pem_body(pem)
        .map_err(|e| {
            VerificationError::dtc_invalid(format!(
                "PKCS#8 parse failed: {}; SEC1 decode failed: {}",
                pkcs8_err, e
            ))
        })?;
    let secret = P256SecretKey::from_sec1_der(&der)
        .map_err(|e| {
            VerificationError::dtc_invalid(format!(
                "PKCS#8 parse failed: {}; SEC1 parse failed: {}",
                pkcs8_err, e
            ))
        })?;
    Ok(P256SigningKey::from(secret))
}

fn parse_p384_signing_key(pem: &str) -> VerificationResult<P384SigningKey> {
    let pkcs8 = P384SigningKey::from_pkcs8_pem(pem).map_err(|e| e.to_string());
    if let Ok(key) = pkcs8 {
        return Ok(key);
    }
    let pkcs8_err = pkcs8.err().unwrap_or_else(|| "unknown PKCS#8 error".to_string());
    let der = decode_pem_body(pem)
        .map_err(|e| {
            VerificationError::dtc_invalid(format!(
                "PKCS#8 parse failed: {}; SEC1 decode failed: {}",
                pkcs8_err, e
            ))
        })?;
    let secret = P384SecretKey::from_sec1_der(&der)
        .map_err(|e| {
            VerificationError::dtc_invalid(format!(
                "PKCS#8 parse failed: {}; SEC1 parse failed: {}",
                pkcs8_err, e
            ))
        })?;
    Ok(P384SigningKey::from(secret))
}

fn sign_ecdsa(payload: &[u8], signing_key_pem: &str) -> VerificationResult<String> {
    match detect_curve_from_private_key_pem(signing_key_pem)? {
        EcCurve::P256 => {
            let sk = parse_p256_signing_key(signing_key_pem)?;
            let sig: P256Signature = sk.sign(payload);
            Ok(b64_encode(sig.to_der().as_bytes()))
        }
        EcCurve::P384 => {
            let sk = parse_p384_signing_key(signing_key_pem)?;
            let sig: P384Signature = sk.sign(payload);
            Ok(b64_encode(sig.to_der().as_bytes()))
        }
    }
}

fn parse_p256_verifying_key(pem: &str) -> VerificationResult<P256VerifyingKey> {
    if let Ok(key) = P256VerifyingKey::from_public_key_pem(pem) {
        return Ok(key);
    }
    let der = decode_pem_body(pem)?;
    let public_key = P256PublicKey::from_sec1_bytes(&der)
        .map_err(|e| VerificationError::dtc_invalid(e.to_string()))?;
    Ok(P256VerifyingKey::from(public_key))
}

fn parse_p384_verifying_key(pem: &str) -> VerificationResult<P384VerifyingKey> {
    if let Ok(key) = P384VerifyingKey::from_public_key_pem(pem) {
        return Ok(key);
    }
    let der = decode_pem_body(pem)?;
    let public_key = P384PublicKey::from_sec1_bytes(&der)
        .map_err(|e| VerificationError::dtc_invalid(e.to_string()))?;
    Ok(P384VerifyingKey::from(public_key))
}

fn verify_ecdsa(
    payload: &[u8],
    sig_b64: &str,
    public_key_pem: &str,
) -> VerificationResult<bool> {
    let sig_bytes = b64_decode(sig_b64).ok_or_else(|| {
        VerificationError::dtc_invalid("Invalid signature base64".to_string())
    })?;

    match detect_curve_from_public_key_pem(public_key_pem)? {
        EcCurve::P256 => {
            let vk = parse_p256_verifying_key(public_key_pem)?;
            let sig = P256Signature::from_der(&sig_bytes).map_err(|e| {
                VerificationError::dtc_signature_invalid(format!(
                    "Invalid P-256 signature: {}",
                    e
                ))
            })?;
            Ok(vk.verify(payload, &sig).is_ok())
        }
        EcCurve::P384 => {
            let vk = parse_p384_verifying_key(public_key_pem)?;
            let sig = P384Signature::from_der(&sig_bytes).map_err(|e| {
                VerificationError::dtc_signature_invalid(format!(
                    "Invalid P-384 signature: {}",
                    e
                ))
            })?;
            Ok(vk.verify(payload, &sig).is_ok())
        }
    }
}

fn public_key_bytes_from_pem(pem: &str) -> VerificationResult<Vec<u8>> {
    let der = decode_pem_body(pem)?;
    if let Ok(spki) = SubjectPublicKeyInfoRef::try_from(der.as_slice()) {
        return Ok(spki.subject_public_key.raw_bytes().to_vec());
    }
    Ok(der)
}

fn public_key_bytes_from_cert_pem(pem: &str) -> VerificationResult<Vec<u8>> {
    let der = decode_pem_body(pem)?;
    let cert = Certificate::from_der(&der)
        .map_err(|e| VerificationError::dtc_invalid(e.to_string()))?;
    Ok(cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
        .to_vec())
}

fn validate_chain(trust_anchors: &[String], chain: &[String]) -> VerificationResult<bool> {
    if trust_anchors.is_empty() || chain.is_empty() {
        return Ok(true); // nothing to validate
    }
    let mut validator = ChainValidator::new();
    for ta in trust_anchors {
        validator
            .add_trust_anchor_pem(ta)
            .map_err(|e| VerificationError::dtc_trust_chain_invalid(e.to_string()))?;
    }
    for (idx, cert) in chain.iter().enumerate() {
        if idx == chain.len() - 1 {
            // last element assumed root, already added above
            continue;
        }
        validator
            .add_intermediate_pem(cert)
            .map_err(|e| VerificationError::dtc_trust_chain_invalid(e.to_string()))?;
    }
    let result = validator
        .validate_chain(chain)
        .map_err(|e| VerificationError::dtc_trust_chain_invalid(e.to_string()))?;
    Ok(result.valid)
}

fn record_check(
    checks: &mut Vec<Value>,
    errors: &mut Vec<String>,
    error_codes: &mut Vec<String>,
    name: &str,
    passed: bool,
    details: Option<String>,
    error_code: Option<&'static str>,
) {
    let mut check = serde_json::Map::new();
    check.insert("check_name".to_string(), Value::String(name.to_string()));
    check.insert("passed".to_string(), Value::Bool(passed));

    if let Some(ref details) = details {
        check.insert("details".to_string(), Value::String(details.clone()));
    }
    if let Some(code) = error_code {
        check.insert("error_code".to_string(), Value::String(code.to_string()));
    }

    checks.push(Value::Object(check));

    if !passed {
        if let Some(details) = details {
            errors.push(details);
        } else {
            errors.push(format!("{} failed", name));
        }
        if let Some(code) = error_code {
            error_codes.push(code.to_string());
        }
    }
}

pub fn create_dtc_json(input: &str) -> VerificationResult<String> {
    let record: DtcRecord = serde_json::from_str(input).map_err(|e| {
        VerificationError::dtc_invalid(format!("Invalid DTC payload: {}", e))
    })?;
    let norm = normalize_record(record);
    serde_json::to_string(&norm).map_err(|e| {
        VerificationError::dtc_invalid(format!("Failed to serialize DTC payload: {}", e))
    })
}

pub fn sign_dtc_json(input: &str) -> VerificationResult<String> {
    // Accept optional signing_key_pem and signer_public_key_pem in the JSON envelope
    let value: Value = serde_json::from_str(input).map_err(|e| {
        VerificationError::dtc_invalid(format!("Invalid DTC payload: {}", e))
    })?;
    let signing_key = value
        .get("signing_key_pem")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| VerificationError::dtc_missing_field("signing_key_pem"))?;
    let signer_id = value
        .get("signer_id")
        .and_then(|v| v.as_str())
        .unwrap_or("rust-dtc");

    let mut record: DtcRecord = serde_json::from_value(value.clone()).map_err(|e| {
        VerificationError::dtc_invalid(format!("Invalid DTC payload: {}", e))
    })?;
    let norm = normalize_record(record.clone());
    let payload = canonical_payload(&norm)?;
    let sig_b64 = sign_ecdsa(&payload, &signing_key)?;

    record.is_signed = true;
    record.signature_info = Some(SignatureInfo {
        signature_date: now_iso(),
        signer_id: signer_id.to_string(),
        signature: sig_b64,
        is_valid: true,
    });

    serde_json::to_string(&record).map_err(|e| {
        VerificationError::dtc_invalid(format!("Failed to serialize DTC payload: {}", e))
    })
}

pub fn verify_dtc_json(input: &str) -> VerificationResult<String> {
    let value: Value = serde_json::from_str(input).map_err(|e| {
        VerificationError::dtc_invalid(format!("Invalid DTC payload: {}", e))
    })?;
    let record: DtcRecord = serde_json::from_value(value.clone()).map_err(|e| {
        VerificationError::dtc_invalid(format!("Invalid DTC payload: {}", e))
    })?;
    let norm = normalize_record(record.clone());

    let mut checks: Vec<Value> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut error_codes_out: Vec<String> = Vec::new();
    let mut is_valid = true;
    let signer_public_key_pem = value
        .get("signer_public_key_pem")
        .or_else(|| value.get("signature_info").and_then(|s| s.get("signer_public_key_pem")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Signature check
    if let Some(sig_info) = &record.signature_info {
        match canonical_payload(&norm) {
            Ok(payload) => {
                if let Some(pub_pem) = signer_public_key_pem.as_deref() {
                    match verify_ecdsa(&payload, &sig_info.signature, pub_pem) {
                        Ok(ok) => {
                            is_valid &= ok;
                            if ok {
                                record_check(
                                    &mut checks,
                                    &mut errors,
                                    &mut error_codes_out,
                                    "Signature",
                                    true,
                                    None,
                                    None,
                                );
                            } else {
                                record_check(
                                    &mut checks,
                                    &mut errors,
                                    &mut error_codes_out,
                                    "Signature",
                                    false,
                                    Some("signature invalid".to_string()),
                                    Some(error_codes::DTC_SIGNATURE_INVALID),
                                );
                            }
                        }
                        Err(err) => {
                            is_valid = false;
                            record_check(
                                &mut checks,
                                &mut errors,
                                &mut error_codes_out,
                                "Signature",
                                false,
                                Some(err.to_string()),
                                Some(err.code()),
                            );
                        }
                    }
                } else {
                    is_valid = false;
                    record_check(
                        &mut checks,
                        &mut errors,
                        &mut error_codes_out,
                        "Signature",
                        false,
                        Some("missing public key".to_string()),
                        Some(error_codes::DTC_MISSING_FIELD),
                    );
                }
            }
            Err(err) => {
                is_valid = false;
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "Signature",
                    false,
                    Some(err.to_string()),
                    Some(err.code()),
                );
            }
        }
    } else {
        is_valid = false;
        record_check(
            &mut checks,
            &mut errors,
            &mut error_codes_out,
            "Signature",
            false,
            Some("missing signature".to_string()),
            Some(error_codes::DTC_MISSING_FIELD),
        );
    }

    // Temporal validation: check dtc_valid_from, dtc_valid_until, and expiry_date
    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Check not-yet-valid (dtc_valid_from)
    if !record.dtc_valid_from.is_empty() {
        if let Some(valid_from) = parse_iso_to_epoch(&record.dtc_valid_from) {
            if now_epoch < valid_from {
                is_valid = false;
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "TemporalValidation",
                    false,
                    Some(format!("DTC not yet valid (valid_from: {})", record.dtc_valid_from)),
                    Some(error_codes::DTC_NOT_YET_VALID),
                );
            } else {
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "TemporalValidation_NotBefore",
                    true,
                    None,
                    None,
                );
            }
        }
    }

    // Check expired (dtc_valid_until or expiry_date)
    let expiry_to_check = if !record.dtc_valid_until.is_empty() {
        Some(&record.dtc_valid_until)
    } else if !record.expiry_date.is_empty() {
        Some(&record.expiry_date)
    } else {
        None
    };

    if let Some(expiry_str) = expiry_to_check {
        if let Some(expiry_epoch) = parse_iso_to_epoch(expiry_str) {
            if now_epoch > expiry_epoch {
                is_valid = false;
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "TemporalValidation",
                    false,
                    Some(format!("DTC has expired (expiry: {})", expiry_str)),
                    Some(error_codes::DTC_EXPIRED),
                );
            } else {
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "TemporalValidation_Expiry",
                    true,
                    None,
                    None,
                );
            }
        }
    }

    // Revocation check
    if record.is_revoked {
        is_valid = false;
        record_check(
            &mut checks,
            &mut errors,
            &mut error_codes_out,
            "RevocationStatus",
            false,
            Some("DTC has been revoked".to_string()),
            Some(error_codes::DTC_REVOKED),
        );
    } else {
        record_check(
            &mut checks,
            &mut errors,
            &mut error_codes_out,
            "RevocationStatus",
            true,
            None,
            None,
        );
    }

    // Type-specific checks
    match record.dtc_type {
        4 => {
            // Type1
            if let Some(t1) = &norm.type1_profile {
                let has_lines = !t1.mrz_line1.is_empty() && !t1.mrz_line2.is_empty();
                let dg_bytes: Vec<u8> = norm
                    .data_groups
                    .iter()
                    .filter_map(|dg| b64_decode(&dg.data))
                    .flatten()
                    .collect();
                let hash_ok = if !dg_bytes.is_empty() {
                    let mut hasher = Sha256::new();
                    hasher.update(&dg_bytes);
                    hex::encode(hasher.finalize()) == t1.sod_hash
                } else {
                    false
                };
                let ok = has_lines && hash_ok;
                is_valid &= ok;
                let details = if ok {
                    None
                } else {
                    let mut failures = Vec::new();
                    if !has_lines {
                        failures.push("missing MRZ lines");
                    }
                    if !hash_ok {
                        failures.push("SOD hash mismatch");
                    }
                    Some(failures.join("; "))
                };
                let error_code = if ok {
                    None
                } else if !hash_ok {
                    Some(error_codes::DTC_INVALID)
                } else {
                    Some(error_codes::DTC_MISSING_FIELD)
                };
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "Type1Profile",
                    ok,
                    details,
                    error_code,
                );
            } else {
                is_valid = false;
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "Type1Profile",
                    false,
                    Some("missing profile".to_string()),
                    Some(error_codes::DTC_MISSING_FIELD),
                );
            }
        }
        5 => {
            // Type2
            if let Some(t2) = &norm.type2_profile {
                let mut missing = Vec::new();
                if t2.chip_auth_public_key.is_empty() {
                    missing.push("chip_auth_public_key");
                }
                if t2.device_public_key.is_empty() {
                    missing.push("device_public_key");
                }
                let ok = missing.is_empty();
                is_valid &= ok;
                let details = if ok {
                    None
                } else {
                    Some(format!("missing fields: {}", missing.join(", ")))
                };
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "Type2Profile",
                    ok,
                    details,
                    if ok { None } else { Some(error_codes::DTC_MISSING_FIELD) },
                );
            } else {
                is_valid = false;
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "Type2Profile",
                    false,
                    Some("missing profile".to_string()),
                    Some(error_codes::DTC_MISSING_FIELD),
                );
            }
        }
        6 => {
            // Type3
            if let Some(t3) = &norm.type3_profile {
                let mut missing = Vec::new();
                if t3.remote_attestation_report.is_empty() {
                    missing.push("remote_attestation_report");
                }
                if t3.device_binding_id.is_empty() {
                    missing.push("device_binding_id");
                }
                let ok = missing.is_empty();
                is_valid &= ok;
                let details = if ok {
                    None
                } else {
                    Some(format!("missing fields: {}", missing.join(", ")))
                };
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "Type3Profile",
                    ok,
                    details,
                    if ok { None } else { Some(error_codes::DTC_MISSING_FIELD) },
                );
            } else {
                is_valid = false;
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "Type3Profile",
                    false,
                    Some("missing profile".to_string()),
                    Some(error_codes::DTC_MISSING_FIELD),
                );
            }
        }
        _ => {}
    }

    // Optional PKI trust chain validation
    let trust_anchors: Vec<String> = value
        .get("trust_anchors_pem")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(|x| x.to_string())).collect())
        .unwrap_or_default();
    let cert_chain: Vec<String> = value
        .get("certificate_chain_pem")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(|x| x.to_string())).collect())
        .unwrap_or_default();
    if let (Some(pub_pem), Some(leaf_pem)) = (signer_public_key_pem.as_deref(), cert_chain.first()) {
        match (
            public_key_bytes_from_pem(pub_pem),
            public_key_bytes_from_cert_pem(leaf_pem),
        ) {
            (Ok(signer_bytes), Ok(leaf_bytes)) => {
                let ok = signer_bytes == leaf_bytes;
                is_valid &= ok;
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "SignerKeyMatchesCertificate",
                    ok,
                    if ok {
                        None
                    } else {
                        Some("signer key does not match certificate".to_string())
                    },
                    if ok {
                        None
                    } else {
                        Some(error_codes::DTC_TRUST_CHAIN_INVALID)
                    },
                );
            }
            (Err(err), _) | (_, Err(err)) => {
                is_valid = false;
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "SignerKeyMatchesCertificate",
                    false,
                    Some(err.to_string()),
                    Some(err.code()),
                );
            }
        }
    }
    if !trust_anchors.is_empty() && !cert_chain.is_empty() {
        match validate_chain(&trust_anchors, &cert_chain) {
            Ok(chain_ok) => {
                is_valid &= chain_ok;
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "TrustChain",
                    chain_ok,
                    if chain_ok {
                        None
                    } else {
                        Some("trust chain validation failed".to_string())
                    },
                    if chain_ok {
                        None
                    } else {
                        Some(error_codes::DTC_TRUST_CHAIN_INVALID)
                    },
                );
            }
            Err(err) => {
                is_valid = false;
                record_check(
                    &mut checks,
                    &mut errors,
                    &mut error_codes_out,
                    "TrustChain",
                    false,
                    Some(err.to_string()),
                    Some(err.code()),
                );
            }
        }
    }

    let error_message = if is_valid {
        String::new()
    } else {
        errors
            .first()
            .cloned()
            .unwrap_or_else(|| "Verification failed".to_string())
    };

    let resp = json!({
        "is_valid": is_valid,
        "verification_results": checks,
        "errors": errors,
        "error_codes": error_codes_out,
        "dtc_data": record,
        "error_message": error_message,
    });

    serde_json::to_string(&resp).map_err(|e| {
        VerificationError::dtc_invalid(format!("Failed to serialize DTC verification result: {}", e))
    })
}
