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
//! - **payload_json**: Canonicalized (BTreeMap-ordered) JSON object containing the
//!   document claims including a mandatory `"typ"` field.
//! - **signature_b64**: Standard (RFC 4648) base64-encoded raw signature over the
//!   UTF-8 bytes of `header~payload_json`.
//!
//! # Supported algorithms
//!
//! | `alg` | Key type | Hash |
//! |-------|----------|------|
//! | `ES256` | EC P-256 | SHA-256 |
//! | `ES384` | EC P-384 | SHA-384 |
//! | `EdDSA` | Ed25519  | —      |
//!
//! Public keys are accepted as DER-encoded SubjectPublicKeyInfo bytes or as
//! a JSON Web Key (`Jwk`).

use base64::Engine;
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

struct ParsedBarcode<'a> {
    header: &'a str,
    payload_json: &'a str,
    signature_b64: &'a str,
    signing_input: String,
    country: String,
}

fn parse_barcode(barcode: &str) -> Result<ParsedBarcode<'_>, String> {
    let parts: Vec<&str> = barcode.splitn(3, '~').collect();
    if parts.len() != 3 {
        return Err(format!(
            "expected 3 tilde-separated segments, got {}",
            parts.len()
        ));
    }

    let header = parts[0];
    let payload_json = parts[1];
    let signature_b64 = parts[2];

    // Validate header format: at least 7 chars, starts with "DC0" + version digit + 3-letter country
    if header.len() < 7 {
        return Err(format!(
            "header segment too short ({}), expected at least 7 chars (e.g. DC03AUS)",
            header.len()
        ));
    }
    if !header.starts_with("DC0") {
        return Err(format!(
            "header must start with 'DC0', got '{}'",
            &header[..header.len().min(4)]
        ));
    }
    let country_part = &header[4..];
    if country_part.len() < 3 || !country_part[..3].chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(format!(
            "header country code must be 3 ASCII letters, got '{}'",
            country_part
        ));
    }
    let country = country_part[..3].to_ascii_uppercase();

    let signing_input = format!("{}~{}", header, payload_json);

    Ok(ParsedBarcode {
        header,
        payload_json,
        signature_b64,
        signing_input,
        country,
    })
}

// ============================================================================
// Public API: verify with JWK
// ============================================================================

/// Verify a VDS-NC barcode string against a JSON Web Key.
///
/// The `issuer_jwk` public key is used to verify the signature over the
/// `header~payload_json` signing input.  The `alg` field of the JWK (or the
/// `algorithm` hint when absent) is used to select the verification algorithm.
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
    result.header = Some(parsed.header.to_string());

    // --- 2. Parse payload --------------------------------------------------
    match serde_json::from_str::<serde_json::Value>(parsed.payload_json) {
        Ok(v) => result.payload = Some(v),
        Err(e) => {
            result
                .errors
                .push(format!("VDS-NC payload JSON parse error: {}", e));
            return result;
        }
    }

    // --- 3. Decode signature -----------------------------------------------
    let signature_bytes = match base64::engine::general_purpose::STANDARD
        .decode(parsed.signature_b64)
    {
        Ok(b) => b,
        Err(_) => {
            // Try URL-safe base64 as a fallback (some encoders omit padding)
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parsed.signature_b64) {
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
    let alg = issuer_jwk
        .alg
        .as_deref()
        .unwrap_or_else(|| default_alg_for_jwk(issuer_jwk));

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

// ============================================================================
// Algorithm dispatch
// ============================================================================

fn default_alg_for_jwk(jwk: &Jwk) -> &'static str {
    match jwk.kty.as_str() {
        "OKP" => "EdDSA",
        "EC" => match jwk.crv.as_deref() {
            Some("P-384") => "ES384",
            _ => "ES256",
        },
        _ => "ES256",
    }
}

fn verify_signing_input(
    alg: &str,
    jwk: &Jwk,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    match alg {
        "ES256" => {
            let key_bytes = jwk_ec_to_uncompressed_spki(jwk)?;
            marty_crypto::ecdsa::verify_p256_sha256(&key_bytes, message, signature)
                .map_err(|e| e.to_string())
        }
        "ES384" => {
            let key_bytes = jwk_ec_to_uncompressed_spki(jwk)?;
            marty_crypto::ecdsa::verify_p384_sha384(&key_bytes, message, signature)
                .map_err(|e| e.to_string())
        }
        "EdDSA" => {
            let key_bytes = jwk_okp_to_raw(jwk)?;
            Ok(marty_crypto::ed25519::verify_bool(
                &key_bytes, message, signature,
            ))
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
fn jwk_ec_to_uncompressed_spki(jwk: &Jwk) -> Result<Vec<u8>, String> {
    let x_b64 = jwk.x.as_deref().ok_or("EC JWK missing 'x' coordinate")?;
    let y_b64 = jwk.y.as_deref().ok_or("EC JWK missing 'y' coordinate")?;

    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|e| format!("JWK 'x' base64 decode: {}", e))?;
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(y_b64)
        .map_err(|e| format!("JWK 'y' base64 decode: {}", e))?;

    // Uncompressed SEC1 point: 0x04 || x || y
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Ok(point)
}

/// Convert an OKP (Ed25519) JWK to raw 32-byte public key.
fn jwk_okp_to_raw(jwk: &Jwk) -> Result<Vec<u8>, String> {
    let x_b64 = jwk.x.as_deref().ok_or("OKP JWK missing 'x' field")?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|e| format!("JWK 'x' base64 decode: {}", e))
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

    #[test]
    fn verifies_valid_vds_nc_barcode() {
        let (jwk, signing_key) = make_p256_jwk_and_key();
        let payload = r#"{"issuing_country":"AUS","typ":"TestDoc"}"#;
        let barcode = sign_barcode(&signing_key, "DC03AUS", payload);

        let result = verify_vds_nc(&barcode, &jwk);
        assert!(result.verified, "should verify: {:?}", result.errors);
        assert_eq!(result.country.as_deref(), Some("AUS"));
        assert_eq!(result.signature_status, SignatureVerificationStatus::Valid);
    }

    #[test]
    fn rejects_tampered_payload() {
        let (jwk, signing_key) = make_p256_jwk_and_key();
        let payload = r#"{"typ":"TestDoc"}"#;
        let barcode = sign_barcode(&signing_key, "DC03DEU", payload);

        // Tamper: replace part of the payload in the barcode string
        let tampered = barcode.replacen("TestDoc", "TamperedDoc", 1);
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

        let payload = r#"{"typ":"TestDoc"}"#;
        let barcode = sign_barcode(&signing_key, "DC03USA", payload);

        let result = verify_vds_nc(&barcode, &other_jwk);
        assert!(!result.verified);
        assert_eq!(
            result.signature_status,
            SignatureVerificationStatus::Invalid
        );
    }

    #[test]
    fn rejects_malformed_barcode_missing_segments() {
        let (jwk, _) = make_p256_jwk_and_key();
        let result = verify_vds_nc("DC03AUS~{\"typ\":\"T\"}", &jwk);
        assert!(!result.verified);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn rejects_invalid_header_prefix() {
        let (jwk, signing_key) = make_p256_jwk_and_key();
        let payload = r#"{"typ":"T"}"#;
        // Wrong prefix: should be DC0...
        let barcode = sign_barcode(&signing_key, "BADAUS", payload);
        let result = verify_vds_nc(&barcode, &jwk);
        assert!(!result.verified);
    }

    #[test]
    fn rejects_non_alpha_country_code() {
        let (jwk, signing_key) = make_p256_jwk_and_key();
        let payload = r#"{"typ":"T"}"#;
        let barcode = sign_barcode(&signing_key, "DC0312X", payload);
        let result = verify_vds_nc(&barcode, &jwk);
        assert!(!result.verified);
    }

    #[test]
    fn verify_vds_nc_jwk_json_roundtrip() {
        let (jwk, signing_key) = make_p256_jwk_and_key();
        let jwk_json = serde_json::to_string(&jwk).unwrap();
        let payload = r#"{"typ":"TestDoc"}"#;
        let barcode = sign_barcode(&signing_key, "DC03GBR", payload);

        let result = verify_vds_nc_jwk_json(&barcode, &jwk_json).unwrap();
        assert!(result.verified);
    }
}
