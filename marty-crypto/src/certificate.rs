//! Certificate parsing and information extraction.
//!
//! Provides X.509 certificate operations without Python cryptography dependency.

use crate::{CryptoError, CryptoResult};
use der::{Decode, DecodePem, Encode};
use hex;
use x509_cert::Certificate;

/// Certificate information extracted from X.509 certificate.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub is_ca: bool,
    pub key_usage: Vec<String>,
    pub subject_alt_names: Vec<String>,
    /// SHA-256 fingerprint as lowercase hex string
    pub fingerprint_sha256: String,
}

/// Load a certificate from PEM-encoded data.
pub fn load_certificate_pem(pem_data: &str) -> CryptoResult<Vec<u8>> {
    let cert = Certificate::from_pem(pem_data).map_err(|e| {
        CryptoError::pem_error(format!("Failed to parse PEM certificate: {}", e))
    })?;

    cert.to_der()
        .map_err(|e| CryptoError::der_error(format!("Failed to encode certificate: {}", e)))
}

/// Load a certificate from DER-encoded data and validate it.
pub fn load_certificate_der(der_data: &[u8]) -> CryptoResult<Certificate> {
    Certificate::from_der(der_data).map_err(|e| {
        CryptoError::der_error(format!("Failed to parse DER certificate: {}", e))
    })
}

/// Extract information from a DER-encoded certificate.
pub fn get_certificate_info(der_data: &[u8]) -> CryptoResult<CertificateInfo> {
    let cert = load_certificate_der(der_data)?;

    // Extract subject
    let subject = cert.tbs_certificate.subject.to_string();

    // Extract issuer
    let issuer = cert.tbs_certificate.issuer.to_string();

    // Extract serial number
    let serial_number = hex::encode(cert.tbs_certificate.serial_number.as_bytes());

    // Extract validity
    let not_before = format_x509_time(&cert.tbs_certificate.validity.not_before);
    let not_after = format_x509_time(&cert.tbs_certificate.validity.not_after);

    // Check if CA via basic constraints
    let is_ca = check_is_ca(&cert);

    // Parse key usage
    let key_usage = parse_key_usage(&cert);

    // Parse subject alternative names
    let subject_alt_names = parse_san(&cert);

    // Calculate SHA-256 fingerprint as hex string
    let fingerprint_bytes = crate::hashing::hash_sha256(der_data);
    let fingerprint_sha256 = hex::encode(&fingerprint_bytes);

    Ok(CertificateInfo {
        subject,
        issuer,
        serial_number,
        not_before,
        not_after,
        is_ca,
        key_usage,
        subject_alt_names,
        fingerprint_sha256,
    })
}

/// Check if certificate is a CA certificate.
fn check_is_ca(cert: &Certificate) -> bool {
    use const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;
    use x509_cert::ext::pkix::BasicConstraints;

    cert.tbs_certificate
        .extensions
        .as_ref()
        .and_then(|exts| {
            exts.iter().find_map(|ext| {
                if ext.extn_id == ID_CE_BASIC_CONSTRAINTS {
                    // Try to decode basic constraints
                    BasicConstraints::from_der(ext.extn_value.as_bytes())
                        .ok()
                        .map(|bc| bc.ca)
                } else {
                    None
                }
            })
        })
        .unwrap_or(false)
}

/// Parse key usage extension.
fn parse_key_usage(cert: &Certificate) -> Vec<String> {
    use const_oid::db::rfc5280::ID_CE_KEY_USAGE;
    use x509_cert::ext::pkix::KeyUsage;

    let mut usages = Vec::new();

    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts.iter() {
            if ext.extn_id == ID_CE_KEY_USAGE {
                if let Ok(ku) = KeyUsage::from_der(ext.extn_value.as_bytes()) {
                    if ku.digital_signature() {
                        usages.push("digitalSignature".to_string());
                    }
                    if ku.non_repudiation() {
                        usages.push("nonRepudiation".to_string());
                    }
                    if ku.key_encipherment() {
                        usages.push("keyEncipherment".to_string());
                    }
                    if ku.data_encipherment() {
                        usages.push("dataEncipherment".to_string());
                    }
                    if ku.key_agreement() {
                        usages.push("keyAgreement".to_string());
                    }
                    if ku.key_cert_sign() {
                        usages.push("keyCertSign".to_string());
                    }
                    if ku.crl_sign() {
                        usages.push("cRLSign".to_string());
                    }
                }
                break;
            }
        }
    }

    usages
}

/// Parse subject alternative names extension.
fn parse_san(cert: &Certificate) -> Vec<String> {
    use const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    let mut names = Vec::new();

    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts.iter() {
            if ext.extn_id == ID_CE_SUBJECT_ALT_NAME {
                if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                    for name in san.0.iter() {
                        match name {
                            GeneralName::DnsName(dns) => {
                                names.push(format!("DNS:{}", dns.as_str()));
                            }
                            GeneralName::Rfc822Name(email) => {
                                names.push(format!("email:{}", email.as_str()));
                            }
                            GeneralName::UniformResourceIdentifier(uri) => {
                                names.push(format!("URI:{}", uri.as_str()));
                            }
                            GeneralName::IpAddress(ip) => {
                                names.push(format!("IP:{}", hex::encode(ip.as_bytes())));
                            }
                            _ => {}
                        }
                    }
                }
                break;
            }
        }
    }

    names
}

/// Convert PEM certificate to DER.
pub fn pem_to_der(pem_data: &str) -> CryptoResult<Vec<u8>> {
    load_certificate_pem(pem_data)
}

/// Convert DER certificate to PEM.
pub fn der_to_pem(der_data: &[u8]) -> CryptoResult<String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der_data);

    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");

    Ok(pem)
}

/// Get the public key from a certificate in DER format (SPKI).
pub fn get_certificate_public_key(der_data: &[u8]) -> CryptoResult<Vec<u8>> {
    let cert = load_certificate_der(der_data)?;

    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| CryptoError::der_error(format!("Failed to encode public key: {}", e)))
}

/// Check if a certificate is expired.
pub fn is_certificate_expired(der_data: &[u8]) -> CryptoResult<bool> {
    let cert = load_certificate_der(der_data)?;
    let now = chrono::Utc::now();

    let not_after = &cert.tbs_certificate.validity.not_after;
    let expiry = x509_time_to_datetime(not_after)?;

    Ok(now > expiry)
}

/// Check if a certificate is not yet valid.
pub fn is_certificate_not_yet_valid(der_data: &[u8]) -> CryptoResult<bool> {
    let cert = load_certificate_der(der_data)?;
    let now = chrono::Utc::now();

    let not_before = &cert.tbs_certificate.validity.not_before;
    let start = x509_time_to_datetime(not_before)?;

    Ok(now < start)
}

/// Convert X.509 Time to chrono DateTime.
fn x509_time_to_datetime(
    time: &x509_cert::time::Time,
) -> CryptoResult<chrono::DateTime<chrono::Utc>> {
    let time_str = format_x509_time(time);

    // Parse ISO 8601 format
    chrono::DateTime::parse_from_rfc3339(&time_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| CryptoError::parse_error(format!("Failed to parse time: {}", e)))
}

/// Format X.509 time to ISO 8601 string with UTC timezone (Z suffix).
fn format_x509_time(time: &x509_cert::time::Time) -> String {
    use der::DateTime;

    let dt: DateTime = match time {
        x509_cert::time::Time::UtcTime(ut) => ut.to_date_time(),
        x509_cert::time::Time::GeneralTime(gt) => gt.to_date_time(),
    };

    // Format as ISO 8601 with Z suffix: YYYY-MM-DDTHH:MM:SSZ
    // der::DateTime provides year, month, day, hour, minutes, seconds methods
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minutes(),
        dt.seconds()
    )
}

/// Verify that a certificate was signed by another certificate (issuer).
pub fn verify_certificate_signature(
    cert_der: &[u8],
    issuer_der: &[u8],
) -> CryptoResult<bool> {
    let cert = load_certificate_der(cert_der)?;
    let issuer = load_certificate_der(issuer_der)?;

    // Get the TBS (to-be-signed) certificate data
    let tbs_der = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| CryptoError::der_error(format!("Failed to encode TBS: {}", e)))?;

    // Get signature algorithm and value
    let sig_alg = &cert.signature_algorithm;
    let signature = cert
        .signature
        .as_bytes()
        .ok_or_else(|| CryptoError::signature_error("Invalid signature bits"))?;

    // Get issuer's public key
    let issuer_pubkey_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| {
            CryptoError::der_error(format!("Failed to encode issuer public key: {}", e))
        })?;

    // Convert OID to signature algorithm enum
    let oid_str = sig_alg.oid.to_string();
    let algorithm = crate::SignatureAlgorithm::from_oid(&oid_str)?;

    crate::verify_signature(algorithm, &issuer_pubkey_der, &tbs_der, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_to_pem_format() {
        let fake_der = vec![0x30, 0x82, 0x01, 0x00]; // Minimal DER sequence
        let pem = der_to_pem(&fake_der).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex::encode([0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
