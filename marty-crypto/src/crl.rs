//! Certificate Revocation List (CRL) parsing and verification.
//!
//! This module provides CRL operations for X.509 certificate revocation,
//! replacing Python cryptography CRL functionality.
//!
//! # Features
//!
//! - Parse CRLs from PEM and DER formats
//! - Access CRL extensions (CRL number, delta CRL indicator)
//! - Check if a certificate is revoked
//!
//! # Example
//!
//! ```ignore
//! use marty_crypto::crl::load_crl_pem;
//!
//! // Parse a CRL
//! let crl_info = load_crl_pem(pem_data)?;
//! println!("CRL has {} revoked certificates", crl_info.revoked_count);
//! ```

use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
use x509_cert::time::Time;
use x509_cert::Certificate;

use crate::{CryptoError, CryptoResult};

// ============================================================================
// Time Helper Functions
// ============================================================================

/// Convert a Unix duration to x509_cert::time::Time.
///
/// Uses GeneralizedTime for simplicity (valid for all dates).
#[cfg(test)]
fn duration_to_x509_time(duration: std::time::Duration) -> CryptoResult<Time> {
    use der::asn1::GeneralizedTime;

    let gt = GeneralizedTime::from_unix_duration(duration)
        .map_err(|e| CryptoError::internal(format!("Invalid time: {}", e)))?;

    Ok(Time::GeneralTime(gt))
}

// ============================================================================
// CRL Information
// ============================================================================

/// Information extracted from a CRL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlInfo {
    /// CRL issuer name
    pub issuer: String,
    /// This update time (when CRL was issued)
    pub this_update: String,
    /// Next update time (when next CRL should be issued)
    pub next_update: Option<String>,
    /// CRL number (if present)
    pub crl_number: Option<u64>,
    /// Whether this is a delta CRL
    pub is_delta_crl: bool,
    /// Number of revoked certificates
    pub revoked_count: usize,
    /// List of revoked certificate serial numbers (hex encoded)
    pub revoked_serials: Vec<String>,
}

/// Revocation reason codes (RFC 5280).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl RevocationReason {
    /// Convert from integer code.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Unspecified),
            1 => Some(Self::KeyCompromise),
            2 => Some(Self::CaCompromise),
            3 => Some(Self::AffiliationChanged),
            4 => Some(Self::Superseded),
            5 => Some(Self::CessationOfOperation),
            6 => Some(Self::CertificateHold),
            8 => Some(Self::RemoveFromCrl),
            9 => Some(Self::PrivilegeWithdrawn),
            10 => Some(Self::AaCompromise),
            _ => None,
        }
    }

    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "keyCompromise",
            Self::CaCompromise => "cACompromise",
            Self::AffiliationChanged => "affiliationChanged",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessationOfOperation",
            Self::CertificateHold => "certificateHold",
            Self::RemoveFromCrl => "removeFromCRL",
            Self::PrivilegeWithdrawn => "privilegeWithdrawn",
            Self::AaCompromise => "aACompromise",
        }
    }

    /// Convert to integer code per RFC 5280 §5.3.1.
    pub fn to_code(&self) -> u8 {
        *self as u8
    }
}

/// Information about a revoked certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedCertInfo {
    /// Serial number (hex encoded)
    pub serial_number: String,
    /// Revocation date
    pub revocation_date: String,
    /// Revocation reason (if present)
    pub reason: Option<RevocationReason>,
}

/// Authenticated and fresh CRL status for one certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedCrlStatus {
    pub revoked: bool,
    pub revocation_date: Option<String>,
    pub reason: Option<RevocationReason>,
    pub issuer: String,
    pub this_update: String,
    pub next_update: Option<String>,
    pub signature_valid: bool,
    pub freshness_valid: bool,
    pub certificate_id_valid: bool,
}

// ============================================================================
// CRL Loading Functions
// ============================================================================

/// Load a CRL from PEM-encoded data.
pub fn load_crl_pem(pem_data: &str) -> CryptoResult<CrlInfo> {
    use pem_rfc7468::decode_vec;

    // Manually decode PEM since CertificateList::from_pem has trait bound issues
    let (_, der_data) = decode_vec(pem_data.as_bytes())
        .map_err(|e| CryptoError::pem_error(format!("Failed to decode PEM: {}", e)))?;

    load_crl_der(&der_data)
}

/// Load a CRL from DER-encoded data.
pub fn load_crl_der(der_data: &[u8]) -> CryptoResult<CrlInfo> {
    let crl = CertificateList::from_der(der_data)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse DER CRL: {}", e)))?;

    extract_crl_info(&crl)
}

/// Extract information from a parsed CRL.
fn extract_crl_info(crl: &CertificateList) -> CryptoResult<CrlInfo> {
    let tbs = &crl.tbs_cert_list;

    // Extract issuer
    let issuer = tbs.issuer.to_string();

    // Extract this_update
    let this_update = format_time(&tbs.this_update);

    // Extract next_update
    let next_update = tbs.next_update.as_ref().map(format_time);

    // Extract CRL number and delta CRL indicator from extensions
    let (crl_number, is_delta_crl) = extract_crl_extensions(tbs);

    // Extract revoked certificates
    let mut revoked_serials = Vec::new();
    if let Some(revoked_certs) = &tbs.revoked_certificates {
        for cert in revoked_certs.iter() {
            let serial_hex = hex::encode(cert.serial_number.as_bytes());
            revoked_serials.push(serial_hex);
        }
    }

    let revoked_count = revoked_serials.len();

    Ok(CrlInfo {
        issuer,
        this_update,
        next_update,
        crl_number,
        is_delta_crl,
        revoked_count,
        revoked_serials,
    })
}

/// Format X.509 time to string.
fn format_time(time: &Time) -> String {
    match time {
        Time::UtcTime(ut) => ut.to_date_time().to_string(),
        Time::GeneralTime(gt) => gt.to_date_time().to_string(),
    }
}

/// Extract CRL number and delta CRL indicator from extensions.
fn extract_crl_extensions(tbs: &TbsCertList) -> (Option<u64>, bool) {
    use const_oid::db::rfc5280::{ID_CE_CRL_NUMBER, ID_CE_DELTA_CRL_INDICATOR};

    let mut crl_number = None;
    let mut is_delta = false;

    if let Some(exts) = &tbs.crl_extensions {
        for ext in exts.iter() {
            if ext.extn_id == ID_CE_CRL_NUMBER {
                // Parse CRL number (INTEGER)
                if let Ok(num) = der::asn1::Int::from_der(ext.extn_value.as_bytes()) {
                    // Convert to u64 - simplified parsing
                    let bytes = num.as_bytes();
                    if bytes.len() <= 8 {
                        let mut value: u64 = 0;
                        for b in bytes {
                            value = (value << 8) | (*b as u64);
                        }
                        crl_number = Some(value);
                    }
                }
            } else if ext.extn_id == ID_CE_DELTA_CRL_INDICATOR {
                is_delta = true;
            }
        }
    }

    (crl_number, is_delta)
}

/// Strip leading zeros from a hex string for serial number comparison.
/// ASN.1 integers may have leading zero padding for sign bit, but serial numbers
/// should be compared by their numerical value.
fn normalize_serial_hex(hex: &str) -> String {
    let lower = hex.to_lowercase();
    let trimmed = lower.trim_start_matches('0');
    // If the string is all zeros, return a single zero
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Check if a certificate serial number is in the CRL.
pub fn is_certificate_revoked(crl_der: &[u8], serial_hex: &str) -> CryptoResult<bool> {
    let crl_info = load_crl_der(crl_der)?;
    let normalized_query = normalize_serial_hex(serial_hex);
    Ok(crl_info
        .revoked_serials
        .iter()
        .any(|s| normalize_serial_hex(s) == normalized_query))
}

/// Authenticate a complete CRL against its issuer and enforce freshness.
pub fn validate_crl(crl_der: &[u8], issuer_der: &[u8]) -> CryptoResult<CrlInfo> {
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| CryptoError::crl(format!("failed to parse CRL: {e}")))?;
    let issuer = Certificate::from_der(issuer_der)
        .map_err(|e| CryptoError::crl(format!("failed to parse issuer certificate: {e}")))?;
    authenticate_crl(&crl, &issuer)?;
    extract_crl_info(&crl)
}

/// Validate a CRL and check one certificate's revocation status.
///
/// This operation fails closed unless the target certificate and CRL are both
/// bound to the supplied issuer, the CRL signature and issuer authorization are
/// valid, and the CRL is current. A delta CRL is rejected because it cannot by
/// itself prove a non-revoked status.
pub fn validate_crl_for_certificate(
    crl_der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
) -> CryptoResult<ValidatedCrlStatus> {
    validate_crl_for_certificate_at(crl_der, cert_der, issuer_der, crl_unix_now()?)
}

fn validate_crl_for_certificate_at(
    crl_der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    now: u64,
) -> CryptoResult<ValidatedCrlStatus> {
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| CryptoError::crl(format!("failed to parse CRL: {e}")))?;
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| CryptoError::crl(format!("failed to parse certificate: {e}")))?;
    let issuer = Certificate::from_der(issuer_der)
        .map_err(|e| CryptoError::crl(format!("failed to parse issuer certificate: {e}")))?;
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(CryptoError::crl(
            "certificate issuer does not match supplied issuer certificate",
        ));
    }
    if !crate::certificate::verify_certificate_signature(cert_der, issuer_der)? {
        return Err(CryptoError::crl(
            "certificate signature does not validate under supplied issuer",
        ));
    }
    authenticate_crl_at(&crl, &issuer, now)?;

    let revoked_entry = crl
        .tbs_cert_list
        .revoked_certificates
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|entry| entry.serial_number == cert.tbs_certificate.serial_number);
    let (revoked, revocation_date, reason) = if let Some(entry) = revoked_entry {
        (
            true,
            Some(format_time(&entry.revocation_date)),
            extract_revocation_reason(entry),
        )
    } else {
        (false, None, None)
    };

    Ok(ValidatedCrlStatus {
        revoked,
        revocation_date,
        reason,
        issuer: crl.tbs_cert_list.issuer.to_string(),
        this_update: format_time(&crl.tbs_cert_list.this_update),
        next_update: crl.tbs_cert_list.next_update.as_ref().map(format_time),
        signature_valid: true,
        freshness_valid: true,
        certificate_id_valid: true,
    })
}

fn authenticate_crl(crl: &CertificateList, issuer: &Certificate) -> CryptoResult<()> {
    authenticate_crl_at(crl, issuer, crl_unix_now()?)
}

fn authenticate_crl_at(crl: &CertificateList, issuer: &Certificate, now: u64) -> CryptoResult<()> {
    const CLOCK_SKEW_SECS: u64 = 5 * 60;
    const MAX_AGE_WITHOUT_NEXT_UPDATE_SECS: u64 = 24 * 60 * 60;

    if crl.tbs_cert_list.issuer != issuer.tbs_certificate.subject {
        return Err(CryptoError::crl(
            "CRL issuer does not match supplied issuer certificate",
        ));
    }
    if crl.tbs_cert_list.signature.oid != crl.signature_algorithm.oid {
        return Err(CryptoError::crl(
            "CRL inner and outer signature algorithms do not match",
        ));
    }
    let basic_constraints = issuer
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|e| CryptoError::crl(format!("invalid issuer BasicConstraints: {e}")))?
        .ok_or_else(|| CryptoError::crl("CRL issuer lacks BasicConstraints"))?
        .1;
    if !basic_constraints.ca {
        return Err(CryptoError::crl("CRL issuer is not a CA certificate"));
    }
    if let Some((_, key_usage)) = issuer
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|e| CryptoError::crl(format!("invalid issuer KeyUsage: {e}")))?
    {
        if !key_usage.crl_sign() {
            return Err(CryptoError::crl(
                "CRL issuer KeyUsage does not permit CRL signing",
            ));
        }
    }
    let (_, is_delta) = extract_crl_extensions(&crl.tbs_cert_list);
    if is_delta {
        return Err(CryptoError::crl(
            "delta CRL cannot be evaluated without its base CRL",
        ));
    }

    let tbs_der = crl
        .tbs_cert_list
        .to_der()
        .map_err(|e| CryptoError::crl(format!("failed to encode signed CRL data: {e}")))?;
    let issuer_spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| CryptoError::crl(format!("failed to encode issuer public key: {e}")))?;
    let signature = crl
        .signature
        .as_bytes()
        .ok_or_else(|| CryptoError::crl("CRL signature is not byte aligned"))?;
    if !crate::algorithm_identifier::verify_signature_with_algorithm_identifier(
        &crl.signature_algorithm,
        &issuer_spki,
        &tbs_der,
        signature,
    )? {
        return Err(CryptoError::crl("invalid CRL signature"));
    }
    validate_crl_freshness_at(
        &crl.tbs_cert_list.this_update,
        crl.tbs_cert_list.next_update.as_ref(),
        CLOCK_SKEW_SECS,
        MAX_AGE_WITHOUT_NEXT_UPDATE_SECS,
        now,
    )
}

fn crl_unix_now() -> CryptoResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CryptoError::crl("system clock is before Unix epoch"))
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
fn validate_crl_freshness(
    this_update: &Time,
    next_update: Option<&Time>,
    clock_skew_secs: u64,
    max_age_without_next_update_secs: u64,
) -> CryptoResult<()> {
    validate_crl_freshness_at(
        this_update,
        next_update,
        clock_skew_secs,
        max_age_without_next_update_secs,
        crl_unix_now()?,
    )
}

fn validate_crl_freshness_at(
    this_update: &Time,
    next_update: Option<&Time>,
    clock_skew_secs: u64,
    max_age_without_next_update_secs: u64,
    now: u64,
) -> CryptoResult<()> {
    let this = this_update.to_unix_duration().as_secs();
    if this > now.saturating_add(clock_skew_secs) {
        return Err(CryptoError::crl("CRL thisUpdate is in the future"));
    }
    if let Some(next_update) = next_update {
        let next = next_update.to_unix_duration().as_secs();
        if next < this || now > next.saturating_add(clock_skew_secs) {
            return Err(CryptoError::crl(
                "CRL is stale or has an invalid validity interval",
            ));
        }
    } else if now > this.saturating_add(max_age_without_next_update_secs + clock_skew_secs) {
        return Err(CryptoError::crl(
            "CRL without nextUpdate exceeds the maximum accepted age",
        ));
    }
    Ok(())
}

/// Get detailed information about revoked certificates.
pub fn get_revoked_certificates(crl_der: &[u8]) -> CryptoResult<Vec<RevokedCertInfo>> {
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse CRL: {}", e)))?;

    let mut result = Vec::new();

    if let Some(revoked_certs) = &crl.tbs_cert_list.revoked_certificates {
        for cert in revoked_certs.iter() {
            let serial_number = hex::encode(cert.serial_number.as_bytes());
            let revocation_date = format_time(&cert.revocation_date);

            // Extract reason from extensions (if present)
            let reason = extract_revocation_reason(cert);

            result.push(RevokedCertInfo {
                serial_number,
                revocation_date,
                reason,
            });
        }
    }

    Ok(result)
}

/// Extract revocation reason from a revoked certificate entry.
fn extract_revocation_reason(cert: &RevokedCert) -> Option<RevocationReason> {
    use const_oid::db::rfc5280::ID_CE_CRL_REASONS;

    if let Some(exts) = &cert.crl_entry_extensions {
        for ext in exts.iter() {
            if ext.extn_id == ID_CE_CRL_REASONS {
                // Every currently assigned CRLReason value fits in one DER
                // ENUMERATED octet. Reject non-canonical encodings.
                let encoded = ext.extn_value.as_bytes();
                if encoded.len() == 3 && encoded[0] == 0x0A && encoded[1] == 0x01 {
                    return RevocationReason::from_code(encoded[2]);
                }
            }
        }
    }
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn public_parser_crl() -> Vec<u8> {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/crl_parser_public.json")).unwrap();
        hex::decode(vector["crl_der_hex"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn parses_public_crl_metadata() {
        let crl_der = public_parser_crl();
        let crl_info = load_crl_der(&crl_der).expect("Failed to parse CRL");

        assert!(crl_info.issuer.contains("Test CA"));
        assert_eq!(crl_info.crl_number, Some(1));
        assert_eq!(crl_info.revoked_count, 2);
        assert!(crl_info.revoked_serials.contains(&"0102030405".to_string()));
    }

    #[test]
    fn checks_revocation_membership_from_public_crl() {
        let crl_der = public_parser_crl();
        assert!(is_certificate_revoked(&crl_der, "0102030405").unwrap());
        assert!(!is_certificate_revoked(&crl_der, "cafebabe").unwrap());
    }

    #[cfg(all(
        feature = "ecdh",
        feature = "signature-verification",
        feature = "crl",
        feature = "ocsp",
        feature = "public-key-codec"
    ))]
    #[test]
    fn authenticated_crl_is_bound_to_certificate_issuer_and_signature() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/crl_authenticated_public.json"
        ))
        .unwrap();
        let ca_der = hex::decode(vector["issuer_der_hex"].as_str().unwrap()).unwrap();
        let leaf_der = hex::decode(vector["leaf_der_hex"].as_str().unwrap()).unwrap();
        let crl_der = hex::decode(vector["crl_der_hex"].as_str().unwrap()).unwrap();
        let valid_at = vector["valid_at_unix"].as_u64().unwrap();

        let status =
            validate_crl_for_certificate_at(&crl_der, &leaf_der, &ca_der, valid_at).unwrap();
        assert!(status.revoked);
        assert_eq!(status.reason, Some(RevocationReason::KeyCompromise));
        assert!(status.signature_valid && status.freshness_valid && status.certificate_id_valid);

        let other: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/pss_certificate_public.json"
        ))
        .unwrap();
        let other_issuer = hex::decode(other["issuer_der_hex"].as_str().unwrap()).unwrap();
        assert!(
            validate_crl_for_certificate_at(&crl_der, &leaf_der, &other_issuer, valid_at).is_err()
        );
        assert!(
            validate_crl_for_certificate_at(&crl_der, &leaf_der, &ca_der, valid_at - 3600).is_err()
        );
        assert!(validate_crl_for_certificate_at(
            &crl_der,
            &leaf_der,
            &ca_der,
            valid_at + 31 * 24 * 60 * 60
        )
        .is_err());

        let mut tampered = crl_der;
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(validate_crl_for_certificate_at(&tampered, &leaf_der, &ca_der, valid_at).is_err());
    }

    #[test]
    fn stale_or_future_crl_fails_closed() {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let stale = duration_to_x509_time(now - Duration::from_secs(48 * 60 * 60)).unwrap();
        let future = duration_to_x509_time(now + Duration::from_secs(60 * 60)).unwrap();
        assert!(validate_crl_freshness(&stale, None, 300, 24 * 60 * 60).is_err());
        assert!(validate_crl_freshness(&future, None, 300, 24 * 60 * 60).is_err());
    }
}
