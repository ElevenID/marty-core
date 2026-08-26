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
    /// Signature algorithm object identifier.
    pub signature_algorithm: String,
    /// Subject key identifier as lowercase hex, when present.
    pub subject_key_identifier: Option<String>,
    /// Authority key identifier as lowercase hex, when present.
    pub authority_key_identifier: Option<String>,
    /// SHA-1 fingerprint as lowercase hex for legacy PKD interoperability.
    pub fingerprint_sha1: String,
    /// SHA-256 fingerprint as lowercase hex string
    pub fingerprint_sha256: String,
}

/// Load a certificate from PEM-encoded data.
pub fn load_certificate_pem(pem_data: &str) -> CryptoResult<Vec<u8>> {
    let cert = Certificate::from_pem(pem_data)
        .map_err(|e| CryptoError::pem_error(format!("Failed to parse PEM certificate: {}", e)))?;

    cert.to_der()
        .map_err(|e| CryptoError::der_error(format!("Failed to encode certificate: {}", e)))
}

/// Load a certificate from DER-encoded data and validate it.
pub fn load_certificate_der(der_data: &[u8]) -> CryptoResult<Certificate> {
    Certificate::from_der(der_data)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse DER certificate: {}", e)))
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

    let signature_algorithm = cert.signature_algorithm.oid.to_string();
    let subject_key_identifier = parse_subject_key_identifier(&cert);
    let authority_key_identifier = parse_authority_key_identifier(&cert);

    // Calculate fingerprints in the native certificate kernel.
    let fingerprint_sha1 = hex::encode(crate::hashing::hash_sha1(der_data));
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
        signature_algorithm,
        subject_key_identifier,
        authority_key_identifier,
        fingerprint_sha1,
        fingerprint_sha256,
    })
}

fn parse_subject_key_identifier(cert: &Certificate) -> Option<String> {
    use const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER;
    use x509_cert::ext::pkix::SubjectKeyIdentifier;

    cert.tbs_certificate
        .extensions
        .as_ref()
        .and_then(|extensions| {
            extensions.iter().find_map(|extension| {
                (extension.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER)
                    .then(|| SubjectKeyIdentifier::from_der(extension.extn_value.as_bytes()).ok())
                    .flatten()
                    .map(|identifier| hex::encode(identifier.0.as_bytes()))
            })
        })
}

fn parse_authority_key_identifier(cert: &Certificate) -> Option<String> {
    use const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER;
    use x509_cert::ext::pkix::AuthorityKeyIdentifier;

    cert.tbs_certificate
        .extensions
        .as_ref()
        .and_then(|extensions| {
            extensions.iter().find_map(|extension| {
                (extension.extn_id == ID_CE_AUTHORITY_KEY_IDENTIFIER)
                    .then(|| AuthorityKeyIdentifier::from_der(extension.extn_value.as_bytes()).ok())
                    .flatten()
                    .and_then(|identifier| identifier.key_identifier)
                    .map(|identifier| hex::encode(identifier.as_bytes()))
            })
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
        pem.push_str(
            std::str::from_utf8(chunk).map_err(|e| {
                CryptoError::internal(format!("UTF-8 error in base64 chunk: {}", e))
            })?,
        );
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

/// Extract HTTP(S) and LDAP CRL distribution point URIs from a certificate.
pub fn get_crl_distribution_points(der_data: &[u8]) -> CryptoResult<Vec<String>> {
    use const_oid::AssociatedOid;
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
    use x509_cert::ext::pkix::CrlDistributionPoints;

    let cert = load_certificate_der(der_data)?;
    let mut urls = Vec::new();

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for extension in extensions {
            if extension.extn_id != CrlDistributionPoints::OID {
                continue;
            }
            let points =
                CrlDistributionPoints::from_der(extension.extn_value.as_bytes()).map_err(|e| {
                    CryptoError::der_error(format!(
                        "Failed to parse CRL distribution points: {}",
                        e
                    ))
                })?;
            for point in points.0 {
                if let Some(DistributionPointName::FullName(names)) = point.distribution_point {
                    for name in names {
                        if let GeneralName::UniformResourceIdentifier(uri) = name {
                            urls.push(uri.to_string());
                        }
                    }
                }
            }
        }
    }

    Ok(urls)
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
#[cfg(feature = "x509")]
pub fn verify_certificate_signature(cert_der: &[u8], issuer_der: &[u8]) -> CryptoResult<bool> {
    let cert = load_certificate_der(cert_der)?;
    let issuer = load_certificate_der(issuer_der)?;

    verify_parsed_certificate_signature(&cert, &issuer)
}

/// Verify a parsed certificate signature against a parsed issuer certificate.
#[cfg(feature = "x509")]
pub fn verify_parsed_certificate_signature(
    cert: &Certificate,
    issuer: &Certificate,
) -> CryptoResult<bool> {
    if cert.tbs_certificate.signature != cert.signature_algorithm {
        return Ok(false);
    }

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

    crate::algorithm_identifier::verify_signature_with_algorithm_identifier(
        sig_alg,
        &issuer_pubkey_der,
        &tbs_der,
        signature,
    )
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "cert-builder")]
    use der::asn1::{Any, BitString};
    #[cfg(feature = "cert-builder")]
    use rand::rngs::OsRng;
    #[cfg(feature = "cert-builder")]
    use rsa::pkcs1::RsaPssParams;
    #[cfg(feature = "cert-builder")]
    use rsa::pkcs8::DecodePrivateKey;
    #[cfg(feature = "cert-builder")]
    use rsa::pss::{Signature as PssSignature, SigningKey as PssSigningKey};
    #[cfg(feature = "cert-builder")]
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    #[cfg(feature = "cert-builder")]
    use rsa::RsaPrivateKey;
    #[cfg(feature = "cert-builder")]
    use sha2::Sha256;
    #[cfg(feature = "cert-builder")]
    use spki::AlgorithmIdentifierOwned;

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

    #[test]
    fn test_extract_crl_distribution_points() {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .crl_distribution_points
            .push(rcgen::CrlDistributionPoint {
                uris: vec!["https://example.invalid/issuer.crl".to_string()],
            });
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();
        let urls = get_crl_distribution_points(certificate.der()).unwrap();
        assert_eq!(urls, vec!["https://example.invalid/issuer.crl"]);
    }

    #[test]
    fn test_crl_distribution_points_reject_malformed_certificate() {
        assert!(get_crl_distribution_points(b"not a certificate").is_err());
    }

    #[test]
    fn test_certificate_info_includes_native_pkd_metadata() {
        let params = rcgen::CertificateParams::new(vec!["pkd.example".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();
        let info = get_certificate_info(certificate.der()).unwrap();

        assert!(!info.signature_algorithm.is_empty());
        assert_eq!(info.fingerprint_sha1.len(), 40);
        assert_eq!(info.fingerprint_sha256.len(), 64);
    }

    #[cfg(feature = "cert-builder")]
    #[test]
    fn verifies_certificate_with_parameterized_rsa_pss_signature() {
        use crate::cert_builder::{create_ca_certificate, create_signed_certificate};
        use crate::keygen::KeyType;

        let (issuer_der, issuer_key_pem) =
            create_ca_certificate("PSS issuer", None, 30, KeyType::Rsa2048).unwrap();
        let (subject_der, _) = create_signed_certificate(
            "PSS subject",
            &issuer_der,
            &issuer_key_pem,
            7,
            false,
            KeyType::EcdsaP256,
        )
        .unwrap();

        let parameters = RsaPssParams::new::<Sha256>(17).to_der().unwrap();
        let algorithm = AlgorithmIdentifierOwned {
            oid: "1.2.840.113549.1.1.10".parse().unwrap(),
            parameters: Some(Any::from_der(&parameters).unwrap()),
        };
        let mut subject = Certificate::from_der(&subject_der).unwrap();
        subject.tbs_certificate.signature = algorithm.clone();
        subject.signature_algorithm = algorithm;

        let tbs_der = subject.tbs_certificate.to_der().unwrap();
        let issuer_key = RsaPrivateKey::from_pkcs8_pem(&issuer_key_pem).unwrap();
        let signature: PssSignature = PssSigningKey::<Sha256>::new_with_salt_len(issuer_key, 17)
            .sign_with_rng(&mut OsRng, &tbs_der);
        subject.signature = BitString::from_bytes(&signature.to_bytes()).unwrap();
        let subject_der = subject.to_der().unwrap();

        assert!(verify_certificate_signature(&subject_der, &issuer_der).unwrap());

        let mut mismatched = Certificate::from_der(&subject_der).unwrap();
        mismatched.signature_algorithm.oid = "1.2.840.113549.1.1.11".parse().unwrap();
        assert!(!verify_certificate_signature(&mismatched.to_der().unwrap(), &issuer_der).unwrap());

        let mut tampered = Certificate::from_der(&subject_der).unwrap();
        let mut signature = tampered.signature.raw_bytes().to_vec();
        signature[0] ^= 0x01;
        tampered.signature = BitString::from_bytes(&signature).unwrap();
        assert!(!verify_certificate_signature(&tampered.to_der().unwrap(), &issuer_der).unwrap());
    }
}
