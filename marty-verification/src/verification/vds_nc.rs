//! VDS-NC (Visible Digital Seal for Non-Constrained Environments) verification.
//!
//! This module verifies VDS-NC barcodes produced by the issuance pipeline.
//! The VDS-NC barcode wire format is a tilde-separated string:
//!
//! ```text
//! header~payload_json~signature_b64
//! ```
//!
//! - **header**: `DC03` version prefix followed by a 3-letter ISO-3166 country code,
//!   e.g. `DC03AUS`.
//! - **payload_json**: Canonicalized profile JSON containing the document claims
//!   and signed `_vds` signer/algorithm metadata.
//! - **signature_b64**: Standard (RFC 4648) base64-encoded raw signature over the
//!   UTF-8 bytes of `header~payload_json`.
//!
//! # Supported algorithms
//!
//! | `alg` | Key type | Hash |
//! |-------|----------|------|
//! | `ES256` | EC P-256 | SHA-256 |
//! | `ES384` | EC P-384 | SHA-384 |
//! | `PS256` | RSA-PSS  | SHA-256 |
//! | `PS384` | RSA-PSS  | SHA-384 |
//! | `PS512` | RSA-PSS  | SHA-512 |
//! | `EdDSA` | Ed25519  | —      |
//!
//! Public keys are accepted as DER-encoded SubjectPublicKeyInfo bytes or as
//! a JSON Web Key (`Jwk`).

use base64::Engine;
use chrono::NaiveDate;
use marty_oid4vci::formats::vds_nc_profile::{
    parse_barcode, recommended_error_correction, select_barcode_format, validate_fields,
    validate_temporal, ParsedVdsNc,
};
use serde::{Deserialize, Serialize};

use crate::error::{VerificationError, VerificationResult};
use crate::jwk::Jwk;

// ============================================================================
// Result type
// ============================================================================

/// Detailed result of VDS-NC barcode verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdsNcVerificationResult {
    /// Whether all checks passed.
    pub verified: bool,
    /// Country extracted from the VDS-NC header segment (e.g. `"AUS"`).
    pub country: Option<String>,
    /// Full header segment (e.g. `"DC03AUS"`).
    pub header: Option<String>,
    /// Parsed payload as a JSON value.
    pub payload: Option<serde_json::Value>,
    /// Signature check outcome.
    pub signature_status: SignatureVerificationStatus,
    /// Human-readable error descriptions; empty if verified.
    pub errors: Vec<String>,
}

impl Default for VdsNcVerificationResult {
    fn default() -> Self {
        Self {
            verified: false,
            country: None,
            header: None,
            payload: None,
            signature_status: SignatureVerificationStatus::Unknown,
            errors: Vec::new(),
        }
    }
}

/// Signature check outcome for a VDS-NC credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureVerificationStatus {
    /// Signature was verified successfully.
    Valid,
    /// Signature verification failed (wrong key or tampered data).
    Invalid,
    /// Verification was not attempted.
    Unknown,
}

// ============================================================================
// Internal parsing helper
// ============================================================================

// ============================================================================
// Public API: verify with JWK
// ============================================================================

/// Verify a VDS-NC barcode string against a JSON Web Key.
///
/// The `issuer_jwk` public key is used to verify the signature over the
/// `header~payload_json` signing input. Signed `_vds.algorithm` metadata selects
/// the algorithm; a conflicting JWK `alg` value is rejected.
///
/// # Arguments
///
/// * `barcode` – Full VDS-NC tilde-separated barcode string.
/// * `issuer_jwk` – Issuer public key as a [`Jwk`].
///
/// # Returns
///
/// A [`VdsNcVerificationResult`] describing the outcome.  This function does
/// not return `Err`; all failure details are in `result.errors`.
pub fn verify_vds_nc(barcode: &str, issuer_jwk: &Jwk) -> VdsNcVerificationResult {
    let mut result = VdsNcVerificationResult::default();

    // --- 1. Parse ----------------------------------------------------------
    let parsed = match parse_barcode(barcode) {
        Ok(p) => p,
        Err(e) => {
            result.errors.push(format!("VDS-NC parse error: {}", e));
            return result;
        }
    };

    result.country = Some(parsed.country.clone());
    result.header = Some(parsed.header.clone());

    // --- 2. Parse payload --------------------------------------------------
    result.payload = Some(parsed.payload.clone());

    // --- 3. Decode signature -----------------------------------------------
    let signature_bytes = match base64::engine::general_purpose::STANDARD
        .decode(&parsed.signature_b64)
    {
        Ok(b) => b,
        Err(_) => {
            // Try URL-safe base64 as a fallback (some encoders omit padding)
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&parsed.signature_b64) {
                Ok(b) => b,
                Err(e) => {
                    result
                        .errors
                        .push(format!("VDS-NC signature base64 decode error: {}", e));
                    result.signature_status = SignatureVerificationStatus::Invalid;
                    return result;
                }
            }
        }
    };

    // --- 4. Derive public key bytes from JWK and verify --------------------
    let alg = parsed.metadata.algorithm.as_str();
    if issuer_jwk
        .alg
        .as_deref()
        .is_some_and(|key_algorithm| key_algorithm != alg)
    {
        result.signature_status = SignatureVerificationStatus::Invalid;
        result.errors.push(format!(
            "VDS-NC signed algorithm {alg} does not match JWK algorithm {}",
            issuer_jwk.alg.as_deref().unwrap_or_default()
        ));
        return result;
    }

    let verify_ok = verify_signing_input(
        alg,
        issuer_jwk,
        parsed.signing_input.as_bytes(),
        &signature_bytes,
    );

    match verify_ok {
        Ok(true) => {
            result.signature_status = SignatureVerificationStatus::Valid;
            result.verified = true;
        }
        Ok(false) => {
            result.signature_status = SignatureVerificationStatus::Invalid;
            result
                .errors
                .push("VDS-NC signature verification failed: signature does not match".into());
        }
        Err(e) => {
            result.signature_status = SignatureVerificationStatus::Invalid;
            result
                .errors
                .push(format!("VDS-NC signature verification error: {}", e));
        }
    }

    result
}

/// Verify a VDS-NC barcode string against a JWK supplied as a JSON string.
///
/// Convenience wrapper around [`verify_vds_nc`] for callers that hold the JWK
/// as a serialized string (e.g. Python bindings).
pub fn verify_vds_nc_jwk_json(
    barcode: &str,
    jwk_json: &str,
) -> VerificationResult<VdsNcVerificationResult> {
    let jwk: Jwk = serde_json::from_str(jwk_json).map_err(|e| {
        VerificationError::vds_nc_invalid(format!("failed to parse issuer JWK: {}", e))
    })?;
    Ok(verify_vds_nc(barcode, &jwk))
}

/// Complete canonical VDS-NC profile result used by service adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdsNcProfileVerificationResult {
    pub is_valid: bool,
    pub canonicalization_ok: bool,
    pub signature_valid: bool,
    pub field_consistency_valid: bool,
    pub temporal_validity_ok: bool,
    pub document_type: String,
    pub issuing_country: String,
    pub signer_id: String,
    pub certificate_reference: Option<String>,
    pub algorithm: String,
    pub payload: serde_json::Value,
    pub barcode_format: String,
    pub error_correction: String,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Parse and validate a canonical VDS-NC profile envelope without asserting
/// authenticity. Callers may use the returned signer metadata to select a key,
/// but must still call a verification function before accepting the document.
pub fn inspect_vds_nc(barcode: &str) -> VerificationResult<ParsedVdsNc> {
    parse_barcode(barcode).map_err(|error| VerificationError::vds_nc_invalid(error.to_string()))
}

/// Verify a VDS-NC barcode with a DER SubjectPublicKeyInfo public key.
///
/// The signed profile metadata selects the algorithm; unsupported algorithms
/// fail closed. This is the canonical path for PEM-backed Python adapters after
/// PEM decoding has occurred in Rust.
pub fn verify_vds_nc_public_key_der(
    barcode: &str,
    public_key_der: &[u8],
) -> VdsNcVerificationResult {
    let mut result = VdsNcVerificationResult::default();
    let parsed = match parse_barcode(barcode) {
        Ok(parsed) => parsed,
        Err(error) => {
            result.errors.push(error.to_string());
            return result;
        }
    };
    result.country = Some(parsed.country.clone());
    result.header = Some(parsed.header.clone());
    result.payload = Some(parsed.payload.clone());
    let signature = match decode_signature(&parsed.signature_b64) {
        Ok(signature) => signature,
        Err(error) => {
            result.signature_status = SignatureVerificationStatus::Invalid;
            result.errors.push(error);
            return result;
        }
    };
    let verified = match parsed.metadata.algorithm.as_str() {
        "ES256" => marty_crypto::ecdsa::verify_p256_sha256(
            public_key_der,
            parsed.signing_input.as_bytes(),
            &signature,
        )
        .map_err(|error| error.to_string()),
        "ES384" => marty_crypto::ecdsa::verify_p384_sha384(
            public_key_der,
            parsed.signing_input.as_bytes(),
            &signature,
        )
        .map_err(|error| error.to_string()),
        "EdDSA" => marty_crypto::ed25519::parse_public_key_der(public_key_der)
            .and_then(|key| key.verify(parsed.signing_input.as_bytes(), &signature))
            .map(|()| true)
            .map_err(|error| error.to_string()),
        "PS256" => marty_crypto::rsa::verify_pss_sha256(
            public_key_der,
            parsed.signing_input.as_bytes(),
            &signature,
        )
        .map_err(|error| error.to_string()),
        "PS384" => marty_crypto::rsa::verify_pss_sha384(
            public_key_der,
            parsed.signing_input.as_bytes(),
            &signature,
        )
        .map_err(|error| error.to_string()),
        "PS512" => marty_crypto::rsa::verify_pss_sha512(
            public_key_der,
            parsed.signing_input.as_bytes(),
            &signature,
        )
        .map_err(|error| error.to_string()),
        algorithm => Err(format!("unsupported VDS-NC algorithm: {algorithm}")),
    };
    match verified {
        Ok(true) => {
            result.verified = true;
            result.signature_status = SignatureVerificationStatus::Valid;
        }
        Ok(false) => {
            result.signature_status = SignatureVerificationStatus::Invalid;
            result
                .errors
                .push("VDS-NC signature verification failed".to_owned());
        }
        Err(error) => {
            result.signature_status = SignatureVerificationStatus::Invalid;
            result.errors.push(error);
        }
    }
    result
}

/// Run canonical profile, signature, printed-field, and temporal checks using a
/// PEM public key. The caller supplies the evaluation date explicitly so test,
/// replay, and audit results are deterministic.
pub fn verify_vds_nc_profile_pem(
    barcode: &str,
    public_key_pem: &str,
    printed_values: Option<&serde_json::Value>,
    evaluation_date: NaiveDate,
) -> VerificationResult<VdsNcProfileVerificationResult> {
    let parsed = inspect_vds_nc(barcode)?;
    let public_key_der = marty_crypto::serialization::load_public_key_pem(public_key_pem)
        .map_err(|error| VerificationError::vds_nc_invalid(error.to_string()))?;
    let signature = verify_vds_nc_public_key_der(barcode, &public_key_der);
    let field_errors = validate_fields(&parsed.payload, printed_values);
    let temporal_errors = validate_temporal(&parsed.payload, evaluation_date);
    let document_type = marty_oid4vci::formats::vds_nc_profile::VdsNcDocumentType::parse(
        &parsed.metadata.document_type,
    )
    .map_err(|error| VerificationError::vds_nc_invalid(error.to_string()))?;
    let correction = recommended_error_correction(document_type);
    let format = select_barcode_format(barcode.len(), correction, None)
        .map_err(|error| VerificationError::vds_nc_invalid(error.to_string()))?;
    let mut errors = signature.errors;
    errors.extend(field_errors.iter().cloned());
    errors.extend(temporal_errors.iter().cloned());
    let warnings = if printed_values.is_none() {
        vec!["No printed values provided for field comparison".to_owned()]
    } else {
        Vec::new()
    };
    let signature_valid = signature.signature_status == SignatureVerificationStatus::Valid;
    Ok(VdsNcProfileVerificationResult {
        is_valid: signature_valid && field_errors.is_empty() && temporal_errors.is_empty(),
        canonicalization_ok: true,
        signature_valid,
        field_consistency_valid: field_errors.is_empty(),
        temporal_validity_ok: temporal_errors.is_empty(),
        document_type: document_type.as_str().to_owned(),
        issuing_country: parsed.country,
        signer_id: parsed.metadata.issuer_id,
        certificate_reference: parsed.metadata.certificate_reference,
        algorithm: parsed.metadata.algorithm,
        payload: parsed.payload,
        barcode_format: format.as_str().to_owned(),
        error_correction: correction.as_str().to_owned(),
        errors,
        warnings,
    })
}

fn decode_signature(value: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value))
        .map_err(|error| format!("VDS-NC signature base64 decode error: {error}"))
}

// ============================================================================
// Algorithm dispatch
// ============================================================================

fn verify_signing_input(
    alg: &str,
    jwk: &Jwk,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    match alg {
        "ES256" => {
            let key_bytes = jwk_ec_to_uncompressed_spki(jwk, "P-256", 32)?;
            marty_crypto::ecdsa::verify_p256_sha256(&key_bytes, message, signature)
                .map_err(|e| e.to_string())
        }
        "ES384" => {
            let key_bytes = jwk_ec_to_uncompressed_spki(jwk, "P-384", 48)?;
            marty_crypto::ecdsa::verify_p384_sha384(&key_bytes, message, signature)
                .map_err(|e| e.to_string())
        }
        "EdDSA" => {
            let key_bytes = jwk_okp_to_raw(jwk)?;
            Ok(marty_crypto::ed25519::verify_bool(
                &key_bytes, message, signature,
            ))
        }
        "PS256" | "PS384" | "PS512" => {
            Err("RSA-PSS VDS-NC verification requires a PEM or DER public key".to_owned())
        }
        other => Err(format!(
            "unsupported algorithm for VDS-NC verification: {}",
            other
        )),
    }
}

/// Convert an EC JWK (P-256 or P-384) to uncompressed point bytes.
///
/// `marty_crypto::ecdsa::verify_p*` accept SEC1 uncompressed point (04 || x || y)
/// or a full DER SubjectPublicKeyInfo.  We assemble the 65-byte uncompressed
/// point directly from the JWK `x` and `y` coordinates.
fn jwk_ec_to_uncompressed_spki(
    jwk: &Jwk,
    expected_curve: &str,
    expected_coordinate_len: usize,
) -> Result<Vec<u8>, String> {
    if jwk.kty != "EC" {
        return Err(format!("EC algorithm requires an EC JWK, got {}", jwk.kty));
    }
    if jwk.crv.as_deref() != Some(expected_curve) {
        return Err(format!("EC algorithm requires JWK curve {expected_curve}"));
    }
    let x_b64 = jwk.x.as_deref().ok_or("EC JWK missing 'x' coordinate")?;
    let y_b64 = jwk.y.as_deref().ok_or("EC JWK missing 'y' coordinate")?;

    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|e| format!("JWK 'x' base64 decode: {}", e))?;
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(y_b64)
        .map_err(|e| format!("JWK 'y' base64 decode: {}", e))?;
    if x.len() != expected_coordinate_len || y.len() != expected_coordinate_len {
        return Err(format!(
            "EC JWK coordinates must each contain {expected_coordinate_len} bytes"
        ));
    }

    // Uncompressed SEC1 point: 0x04 || x || y
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Ok(point)
}

/// Convert an OKP (Ed25519) JWK to raw 32-byte public key.
fn jwk_okp_to_raw(jwk: &Jwk) -> Result<Vec<u8>, String> {
    if jwk.kty != "OKP" {
        return Err(format!(
            "EdDSA algorithm requires an OKP JWK, got {}",
            jwk.kty
        ));
    }
    if jwk.crv.as_deref() != Some("Ed25519") {
        return Err("EdDSA algorithm requires JWK curve Ed25519".to_owned());
    }
    let x_b64 = jwk.x.as_deref().ok_or("OKP JWK missing 'x' field")?;
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|e| format!("JWK 'x' base64 decode: {}", e))?;
    if key.len() != 32 {
        return Err("Ed25519 JWK public key must contain 32 bytes".to_owned());
    }
    Ok(key)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::Jwk;
    use base64::engine::general_purpose::STANDARD as B64;
    use p256::ecdsa::{signature::Signer as _, SigningKey};
    use rand::rngs::OsRng;

    fn make_p256_jwk_and_key() -> (Jwk, SigningKey) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = point.x().expect("x coord");
        let y = point.y().expect("y coord");

        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwk = Jwk {
            kty: "EC".to_string(),
            alg: Some("ES256".to_string()),
            crv: Some("P-256".to_string()),
            x: Some(b64url.encode(x)),
            y: Some(b64url.encode(y)),
            ..Jwk::default()
        };
        (jwk, signing_key)
    }

    fn sign_barcode(signing_key: &SigningKey, header: &str, payload: &str) -> String {
        let signing_input = format!("{}~{}", header, payload);
        let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = B64.encode(sig.to_bytes());
        format!("{}~{}~{}", header, payload, sig_b64)
    }

    fn profile_payload(country: &str) -> String {
        let claims = serde_json::from_value(serde_json::json!({
            "docType": "CMC",
            "issuingCountry": country,
            "documentNumber": "X123456",
            "surname": "EXAMPLE",
            "givenNames": "ADA",
            "dateOfBirth": "19900102",
            "nationality": country,
            "gender": "F",
            "dateOfIssue": "20260101",
            "dateOfExpiry": "20300101"
        }))
        .unwrap();
        marty_oid4vci::formats::vds_nc_profile::build_profile_payload(
            &claims,
            "CMC",
            "issuer-1",
            "issuer-1#key-1",
            "ES256",
        )
        .unwrap()
        .0
    }

    #[test]
    fn verifies_valid_vds_nc_barcode() {
        let (jwk, signing_key) = make_p256_jwk_and_key();
        let payload = profile_payload("AUS");
        let barcode = sign_barcode(&signing_key, "DC03AUS", &payload);

        let result = verify_vds_nc(&barcode, &jwk);
        assert!(result.verified, "should verify: {:?}", result.errors);
        assert_eq!(result.country.as_deref(), Some("AUS"));
        assert_eq!(result.signature_status, SignatureVerificationStatus::Valid);
    }

    #[test]
    fn rejects_tampered_payload() {
        let (jwk, signing_key) = make_p256_jwk_and_key();
        let payload = profile_payload("DEU");
        let barcode = sign_barcode(&signing_key, "DC03DEU", &payload);

        // Tamper: replace part of the payload in the barcode string
        let tampered = barcode.replacen("EXAMPLE", "CHANGED", 1);
        let result = verify_vds_nc(&tampered, &jwk);
        assert!(!result.verified);
        assert_eq!(
            result.signature_status,
            SignatureVerificationStatus::Invalid
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let (_jwk, signing_key) = make_p256_jwk_and_key();
        let (other_jwk, _) = make_p256_jwk_and_key();

        let payload = profile_payload("USA");
        let barcode = sign_barcode(&signing_key, "DC03USA", &payload);

        let result = verify_vds_nc(&barcode, &other_jwk);
        assert!(!result.verified);
        assert_eq!(
            result.signature_status,
            SignatureVerificationStatus::Invalid
        );
    }

    #[test]
    fn rejects_jwk_type_and_curve_confusion() {
        let (mut jwk, signing_key) = make_p256_jwk_and_key();
        let payload = profile_payload("AUS");
        let barcode = sign_barcode(&signing_key, "DC03AUS", &payload);

        jwk.kty = "OKP".to_owned();
        let result = verify_vds_nc(&barcode, &jwk);
        assert!(!result.verified);
        assert!(result.errors.iter().any(|error| error.contains("EC JWK")));

        jwk.kty = "EC".to_owned();
        jwk.crv = Some("P-384".to_owned());
        let result = verify_vds_nc(&barcode, &jwk);
        assert!(!result.verified);
        assert!(result.errors.iter().any(|error| error.contains("P-256")));
    }

    #[test]
    fn rejects_malformed_barcode_missing_segments() {
        let (jwk, _) = make_p256_jwk_and_key();
        let result = verify_vds_nc("DC03AUS~{}", &jwk);
        assert!(!result.verified);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn rejects_invalid_header_prefix() {
        let (jwk, signing_key) = make_p256_jwk_and_key();
        let payload = profile_payload("AUS");
        let barcode = sign_barcode(&signing_key, "BADAUS", &payload);
        let result = verify_vds_nc(&barcode, &jwk);
        assert!(!result.verified);
    }

    #[test]
    fn rejects_non_alpha_country_code() {
        let (jwk, signing_key) = make_p256_jwk_and_key();
        let payload = profile_payload("AUS");
        let barcode = sign_barcode(&signing_key, "DC0312X", &payload);
        let result = verify_vds_nc(&barcode, &jwk);
        assert!(!result.verified);
    }

    #[test]
    fn verify_vds_nc_jwk_json_roundtrip() {
        let (jwk, signing_key) = make_p256_jwk_and_key();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let payload = profile_payload("GBR");
        let barcode = sign_barcode(&signing_key, "DC03GBR", &payload);

        let result = verify_vds_nc_jwk_json(&barcode, &jwk_json).unwrap();
        assert!(result.verified);
    }

    #[test]
    fn profile_verification_preserves_component_outcomes() {
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let (_jwk, signing_key) = make_p256_jwk_and_key();
        let payload = profile_payload("AUS");
        let barcode = sign_barcode(&signing_key, "DC03AUS", &payload);
        let public_key_pem = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let printed = serde_json::json!({"surname": "example"});
        let result = verify_vds_nc_profile_pem(
            &barcode,
            &public_key_pem,
            Some(&printed),
            NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        )
        .unwrap();
        assert!(result.is_valid);
        assert!(result.canonicalization_ok);
        assert!(result.signature_valid);
        assert!(result.field_consistency_valid);
        assert!(result.temporal_validity_ok);
        assert_eq!(result.signer_id, "issuer-1");

        let changed = serde_json::json!({"surname": "changed"});
        let result = verify_vds_nc_profile_pem(
            &barcode,
            &public_key_pem,
            Some(&changed),
            NaiveDate::from_ymd_opt(2031, 1, 1).unwrap(),
        )
        .unwrap();
        assert!(!result.is_valid);
        assert!(result.signature_valid);
        assert!(!result.field_consistency_valid);
        assert!(!result.temporal_validity_ok);
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("FIELD_MISMATCH")));
        assert!(result.errors.iter().any(|error| error.contains("EXPIRED")));
    }
}
