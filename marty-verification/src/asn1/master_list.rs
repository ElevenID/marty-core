//! ICAO Master List parsing.
//!
//! The Master List is a CMS-signed document containing CSCA certificates
//! that are trusted by ICAO PKD subscribers.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode, Reader};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::{VerificationError, VerificationResult};

/// Parsed ICAO Master List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterList {
    /// Version of the master list
    pub version: Option<i32>,
    /// List of CSCA certificates
    pub certificates: Vec<CscaCertificate>,
    /// Signer certificate (if embedded in CMS)
    pub signer_certificate: Option<String>,
}

/// A CSCA certificate from the master list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CscaCertificate {
    /// Subject distinguished name
    pub subject: String,
    /// Issuer distinguished name  
    pub issuer: String,
    /// Serial number (hex)
    pub serial_number: String,
    /// Country code (extracted from subject)
    pub country: Option<String>,
    /// Not before date (ISO 8601)
    pub not_before: String,
    /// Not after date (ISO 8601)
    pub not_after: String,
    /// DER-encoded certificate
    #[serde(skip_serializing)]
    pub der_bytes: Vec<u8>,
}

/// Parse an ICAO Master List from DER-encoded CMS.
///
/// The Master List is a CMS SignedData structure containing:
/// - A list of CSCA certificates as the encapsulated content
/// - One or more signer certificates
/// - Signatures from the ICAO PKD
pub fn parse_master_list(cms_der: &[u8]) -> VerificationResult<MasterList> {
    // Parse ContentInfo wrapper
    let content_info = ContentInfo::from_der(cms_der).map_err(|e| {
        VerificationError::der_error(format!("Failed to parse Master List ContentInfo: {}", e))
    })?;

    // Verify it's SignedData
    if content_info.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        return Err(VerificationError::der_error(format!(
            "Expected SignedData, got {:?}",
            content_info.content_type
        )));
    }

    // Parse SignedData
    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|e| VerificationError::der_error(format!("Failed to parse SignedData: {}", e)))?;

    // Extract encapsulated content (the actual certificate list)
    let encap_content = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| {
            VerificationError::der_error("Master List has no encapsulated content".to_string())
        })?;

    // Parse the certificate list
    // The content is typically a SEQUENCE of Certificate
    let cert_list_bytes = encap_content.value();
    let certificates = parse_certificate_sequence(cert_list_bytes)?;

    // Extract signer certificate if present
    let signer_certificate = if let Some(certs) = &signed_data.certificates {
        // Get first certificate from CertificateSet
        // This is simplified - real implementation should match signer info
        certs.0.iter().next().map(|cert_choice| match cert_choice {
            cms::cert::CertificateChoices::Certificate(cert) => {
                cert.tbs_certificate.subject.to_string()
            }
            _ => "Unknown certificate type".to_string(),
        })
    } else {
        None
    };

    Ok(MasterList {
        version: Some(signed_data.version as u8 as i32),
        certificates,
        signer_certificate,
    })
}

/// Parse a sequence of X.509 certificates.
fn parse_certificate_sequence(der_bytes: &[u8]) -> VerificationResult<Vec<CscaCertificate>> {
    let mut certificates = Vec::new();

    // Try to parse as a SEQUENCE of Certificate
    // This handles both single certificates and sequences
    let mut reader = der::SliceReader::new(der_bytes)
        .map_err(|e| VerificationError::der_error(format!("Invalid DER: {}", e)))?;

    while !reader.is_finished() {
        match Certificate::decode(&mut reader) {
            Ok(cert) => {
                let der_bytes = cert.to_der().map_err(|e| {
                    VerificationError::internal(format!("Failed to re-encode cert: {}", e))
                })?;

                let csca = extract_csca_info(&cert, der_bytes);
                certificates.push(csca);
            }
            Err(e) => {
                tracing::warn!("Failed to parse certificate in sequence: {}", e);
                break;
            }
        }
    }

    if certificates.is_empty() {
        // Try parsing the whole thing as a single certificate
        if let Ok(cert) = Certificate::from_der(der_bytes) {
            let der_bytes = cert.to_der().unwrap_or_default();
            certificates.push(extract_csca_info(&cert, der_bytes));
        }
    }

    Ok(certificates)
}

/// Extract CSCA information from a parsed certificate.
fn extract_csca_info(cert: &Certificate, der_bytes: Vec<u8>) -> CscaCertificate {
    let tbs = &cert.tbs_certificate;

    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();

    // Extract country from subject DN
    let country = extract_country(&subject);

    // Format serial number
    let serial_number = tbs
        .serial_number
        .as_bytes()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    // Format validity
    let not_before = format_time(&tbs.validity.not_before);
    let not_after = format_time(&tbs.validity.not_after);

    CscaCertificate {
        subject,
        issuer,
        serial_number,
        country,
        not_before,
        not_after,
        der_bytes,
    }
}

/// Extract country code from DN string.
fn extract_country(dn: &str) -> Option<String> {
    // Look for C= in the DN
    for part in dn.split(',') {
        let part = part.trim();
        if part.starts_with("C=") || part.starts_with("c=") {
            return Some(part[2..].trim().to_uppercase());
        }
    }
    None
}

/// Format X.509 time to ISO 8601 string.
fn format_time(time: &x509_cert::time::Time) -> String {
    match time {
        x509_cert::time::Time::UtcTime(t) => {
            // UTCTime format
            format!("{:?}", t)
        }
        x509_cert::time::Time::GeneralTime(t) => {
            // GeneralizedTime format
            format!("{:?}", t)
        }
    }
}

/// Verify Master List signature.
///
/// # Arguments
///
/// * `cms_der` - DER-encoded CMS Master List
/// * `signer_cert_der` - DER-encoded signer certificate (ICAO PKD)
///
/// # Returns
///
/// `Ok(true)` if signature is valid.
pub fn verify_master_list_signature(
    cms_der: &[u8],
    signer_cert_der: &[u8],
) -> VerificationResult<bool> {
    // Parse ContentInfo
    let content_info = ContentInfo::from_der(cms_der)
        .map_err(|e| VerificationError::der_error(format!("Failed to parse ContentInfo: {}", e)))?;

    // Parse SignedData
    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|e| VerificationError::der_error(format!("Failed to parse SignedData: {}", e)))?;

    // Parse signer certificate
    let signer_cert = Certificate::from_der(signer_cert_der).map_err(|e| {
        VerificationError::der_error(format!("Failed to parse signer certificate: {}", e))
    })?;

    // Get signer's public key
    let public_key_der = signer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| VerificationError::internal(format!("Failed to encode SPKI: {}", e)))?;

    // Get encapsulated content for signing
    let signed_attrs_or_content = if let Some(encap) = &signed_data.encap_content_info.econtent {
        encap.value().to_vec()
    } else {
        return Err(VerificationError::der_error(
            "No content to verify".to_string(),
        ));
    };

    // Verify each signer info
    for signer_info in signed_data.signer_infos.0.iter() {
        // Get digest algorithm
        let _digest_alg = &signer_info.digest_alg;

        // Get signature algorithm from certificate or signer info
        let sig_alg = &signer_info.signature_algorithm;

        // Determine algorithm from OID
        let algorithm = marty_crypto::SignatureAlgorithm::from_oid(&sig_alg.oid.to_string())?;

        // Get data to verify (signed attributes or content)
        let data_to_verify = if let Some(signed_attrs) = &signer_info.signed_attrs {
            signed_attrs.to_der().map_err(|e| {
                VerificationError::internal(format!("Failed to encode signed attrs: {}", e))
            })?
        } else {
            signed_attrs_or_content.clone()
        };

        // Verify signature
        let signature = signer_info.signature.as_bytes();
        let valid =
            marty_crypto::verify_signature(algorithm, &public_key_der, &data_to_verify, signature)?;

        if valid {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_country() {
        assert_eq!(extract_country("C=US, CN=Test"), Some("US".to_string()));
        assert_eq!(extract_country("CN=Test, C=DE"), Some("DE".to_string()));
        assert_eq!(extract_country("CN=Test"), None);
    }

    #[test]
    fn test_csca_certificate_serialization() {
        let csca = CscaCertificate {
            subject: "C=US, CN=Test CSCA".to_string(),
            issuer: "C=US, CN=Test CSCA".to_string(),
            serial_number: "01:02:03".to_string(),
            country: Some("US".to_string()),
            not_before: "2020-01-01T00:00:00Z".to_string(),
            not_after: "2030-01-01T00:00:00Z".to_string(),
            der_bytes: vec![1, 2, 3],
        };

        let json = serde_json::to_string(&csca).unwrap();
        assert!(json.contains("US"));
        // der_bytes should be skipped in serialization
        assert!(!json.contains("der_bytes"));
    }
}
