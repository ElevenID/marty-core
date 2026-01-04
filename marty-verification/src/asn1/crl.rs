//! Certificate Revocation List (CRL) parsing and checking.
//!
//! Per ICAO 9303 Part 12, CSCAs publish CRLs to revoke Document Signer Certificates.

use chrono::{DateTime, Utc};
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use x509_cert::crl::CertificateList;

use crate::{VerificationError, VerificationResult};

/// Parsed CRL information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlInfo {
    /// Issuer distinguished name
    pub issuer: String,
    /// This update (effective date)
    pub this_update: Option<DateTime<Utc>>,
    /// Next update (expiry date)
    pub next_update: Option<DateTime<Utc>>,
    /// List of revoked certificates
    pub revoked_certificates: Vec<RevokedCertificate>,
    /// CRL number extension (if present)
    pub crl_number: Option<u64>,
}

/// A revoked certificate entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedCertificate {
    /// Serial number of revoked certificate
    pub serial_number: String,
    /// Revocation date
    pub revocation_date: Option<DateTime<Utc>>,
    /// Revocation reason (if specified)
    pub reason: Option<RevocationReason>,
}

/// Revocation reasons per RFC 5280.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl RevocationReason {
    /// Parse from CRL reason code.
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => RevocationReason::Unspecified,
            1 => RevocationReason::KeyCompromise,
            2 => RevocationReason::CaCompromise,
            3 => RevocationReason::AffiliationChanged,
            4 => RevocationReason::Superseded,
            5 => RevocationReason::CessationOfOperation,
            6 => RevocationReason::CertificateHold,
            8 => RevocationReason::RemoveFromCrl,
            9 => RevocationReason::PrivilegeWithdrawn,
            10 => RevocationReason::AaCompromise,
            _ => RevocationReason::Unspecified,
        }
    }
}

/// Parse a DER-encoded CRL.
pub fn parse_crl(der_bytes: &[u8]) -> VerificationResult<CrlInfo> {
    let crl = CertificateList::from_der(der_bytes)
        .map_err(|e| VerificationError::der_error(format!("Failed to parse CRL: {}", e)))?;

    let tbs = &crl.tbs_cert_list;

    // Extract issuer
    let issuer = tbs.issuer.to_string();

    // Extract this_update
    let this_update = time_to_datetime(&tbs.this_update);

    // Extract next_update
    let next_update = tbs.next_update.as_ref().and_then(time_to_datetime);

    // Extract revoked certificates
    let revoked_certificates = if let Some(revoked) = &tbs.revoked_certificates {
        revoked
            .iter()
            .map(|entry| {
                let serial_number = format_serial(&entry.serial_number);
                let revocation_date = time_to_datetime(&entry.revocation_date);
                // TODO: Parse CRL entry extensions for reason
                let reason = None;

                RevokedCertificate {
                    serial_number,
                    revocation_date,
                    reason,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    // TODO: Extract CRL number from extensions
    let crl_number = None;

    Ok(CrlInfo {
        issuer,
        this_update,
        next_update,
        revoked_certificates,
        crl_number,
    })
}

/// Parse a PEM-encoded CRL.
pub fn parse_crl_pem(pem_data: &str) -> VerificationResult<CrlInfo> {
    let der_bytes = pem_to_der(pem_data, "X509 CRL")?;
    parse_crl(&der_bytes)
}

/// Check if a certificate is revoked by any of the provided CRLs.
///
/// # Arguments
///
/// * `cert_serial` - Serial number of certificate to check (hex string)
/// * `cert_issuer` - Issuer DN of certificate
/// * `crls` - List of CRLs to check against
///
/// # Returns
///
/// `Ok(Some(reason))` if revoked, `Ok(None)` if not revoked.
pub fn check_certificate_revocation(
    cert_serial: &str,
    cert_issuer: &str,
    crls: &[CrlInfo],
) -> VerificationResult<Option<RevocationReason>> {
    // Normalize serial number for comparison
    let normalized_serial = cert_serial.to_uppercase().replace(":", "").replace(" ", "");

    for crl in crls {
        // Check issuer matches (simplified comparison)
        // In production, should compare RDN components properly
        if !issuer_matches(cert_issuer, &crl.issuer) {
            continue;
        }

        // Check if CRL is still valid
        if let Some(next_update) = crl.next_update {
            if next_update < Utc::now() {
                tracing::warn!("CRL from {} has expired", crl.issuer);
                // Continue checking but log warning
            }
        }

        // Search for certificate in revoked list
        for revoked in &crl.revoked_certificates {
            let revoked_serial = revoked
                .serial_number
                .to_uppercase()
                .replace(":", "")
                .replace(" ", "");
            if revoked_serial == normalized_serial {
                return Ok(Some(
                    revoked.reason.unwrap_or(RevocationReason::Unspecified),
                ));
            }
        }
    }

    Ok(None)
}

/// Verify CRL signature against issuer's public key.
///
/// # Arguments
///
/// * `crl_der` - DER-encoded CRL
/// * `issuer_public_key` - DER-encoded SubjectPublicKeyInfo
///
/// # Returns
///
/// `Ok(true)` if signature valid, `Ok(false)` if invalid.
pub fn verify_crl_signature(crl_der: &[u8], issuer_public_key: &[u8]) -> VerificationResult<bool> {
    let crl = CertificateList::from_der(crl_der)
        .map_err(|e| VerificationError::der_error(format!("Failed to parse CRL: {}", e)))?;

    // Get TBS (to-be-signed) bytes
    let tbs_bytes = crl
        .tbs_cert_list
        .to_der()
        .map_err(|e| VerificationError::internal(format!("Failed to encode TBS: {}", e)))?;

    // Get signature algorithm
    let sig_alg = crl.signature_algorithm.oid.to_string();
    let algorithm = marty_crypto::SignatureAlgorithm::from_oid(&sig_alg)?;

    // Get signature bytes
    let signature = crl.signature.raw_bytes();

    // Verify signature
    marty_crypto::verify_signature(algorithm, issuer_public_key, &tbs_bytes, signature).map_err(|e| e.into())
}

// Helper functions

fn time_to_datetime(time: &x509_cert::time::Time) -> Option<DateTime<Utc>> {
    match time {
        x509_cert::time::Time::UtcTime(t) => {
            DateTime::from_timestamp(t.to_unix_duration().as_secs() as i64, 0)
        }
        x509_cert::time::Time::GeneralTime(t) => {
            DateTime::from_timestamp(t.to_unix_duration().as_secs() as i64, 0)
        }
    }
}

fn format_serial(serial: &x509_cert::serial_number::SerialNumber) -> String {
    serial
        .as_bytes()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn pem_to_der(pem_data: &str, expected_label: &str) -> VerificationResult<Vec<u8>> {
    use pem_rfc7468::decode_vec;

    let (label, der_bytes) = decode_vec(pem_data.as_bytes())
        .map_err(|e| VerificationError::der_error(format!("Invalid PEM encoding: {}", e)))?;

    if !label.contains(expected_label) && !expected_label.is_empty() {
        tracing::debug!(
            "PEM label '{}' doesn't contain expected '{}'",
            label,
            expected_label
        );
    }

    Ok(der_bytes)
}

fn issuer_matches(cert_issuer: &str, crl_issuer: &str) -> bool {
    // Simplified issuer comparison
    // In production, parse and compare RDN components
    let normalize = |s: &str| s.to_uppercase().replace(" ", "").replace(",", "");
    normalize(cert_issuer) == normalize(crl_issuer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_reason_from_code() {
        assert_eq!(
            RevocationReason::from_code(0),
            RevocationReason::Unspecified
        );
        assert_eq!(
            RevocationReason::from_code(1),
            RevocationReason::KeyCompromise
        );
        assert_eq!(RevocationReason::from_code(4), RevocationReason::Superseded);
        assert_eq!(
            RevocationReason::from_code(255),
            RevocationReason::Unspecified
        );
    }

    #[test]
    fn test_check_revocation_not_found() {
        let crls = vec![CrlInfo {
            issuer: "CN=Test CA, C=US".to_string(),
            this_update: Some(Utc::now()),
            next_update: Some(Utc::now() + chrono::Duration::days(30)),
            revoked_certificates: vec![RevokedCertificate {
                serial_number: "01:02:03:04".to_string(),
                revocation_date: Some(Utc::now()),
                reason: Some(RevocationReason::KeyCompromise),
            }],
            crl_number: Some(1),
        }];

        let result =
            check_certificate_revocation("FF:FF:FF:FF", "CN=Test CA, C=US", &crls).unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_check_revocation_found() {
        let crls = vec![CrlInfo {
            issuer: "CN=Test CA, C=US".to_string(),
            this_update: Some(Utc::now()),
            next_update: Some(Utc::now() + chrono::Duration::days(30)),
            revoked_certificates: vec![RevokedCertificate {
                serial_number: "01:02:03:04".to_string(),
                revocation_date: Some(Utc::now()),
                reason: Some(RevocationReason::KeyCompromise),
            }],
            crl_number: Some(1),
        }];

        let result =
            check_certificate_revocation("01:02:03:04", "CN=Test CA, C=US", &crls).unwrap();

        assert_eq!(result, Some(RevocationReason::KeyCompromise));
    }
}
