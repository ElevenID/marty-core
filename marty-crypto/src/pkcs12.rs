//! PKCS#12 (PFX) file parsing.
//!
//! This module provides functionality to parse PKCS#12 files (`.p12`, `.pfx`)
//! containing private keys, certificates, and certificate chains.
//!
//! This replaces the Python `cryptography.hazmat.primitives.serialization.pkcs12`
//! functionality.
//!
//! # Example
//!
//! ```ignore
//! use marty_verification::crypto::pkcs12::{parse_pkcs12, Pkcs12Data};
//!
//! let pfx_data = std::fs::read("certificate.p12")?;
//! let password = "secret";
//!
//! let parsed = parse_pkcs12(&pfx_data, password)?;
//!
//! println!("Private key algorithm: {:?}", parsed.private_key_algorithm);
//! println!("Certificate subject: {:?}", parsed.certificate_subject);
//! println!("Chain length: {}", parsed.certificate_chain.len());
//! ```

use der::Decode;
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::{CryptoError, CryptoResult};

// ============================================================================
// PKCS#12 Data Types
// ============================================================================

/// Parsed PKCS#12 data.
#[derive(Debug, Clone)]
pub struct Pkcs12Data {
    /// DER-encoded private key (PKCS#8 format)
    pub private_key_der: Vec<u8>,
    /// Private key algorithm identifier
    pub private_key_algorithm: PrivateKeyAlgorithm,
    /// DER-encoded end-entity certificate
    pub certificate_der: Vec<u8>,
    /// Certificate subject common name (if present)
    pub certificate_subject: Option<String>,
    /// Additional certificates in the chain (DER-encoded)
    pub certificate_chain: Vec<Vec<u8>>,
    /// Friendly name (if present in the PKCS#12)
    pub friendly_name: Option<String>,
}

/// Private key algorithm types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivateKeyAlgorithm {
    /// RSA private key
    Rsa,
    /// ECDSA with P-256 curve
    EcdsaP256,
    /// ECDSA with P-384 curve
    EcdsaP384,
    /// ECDSA with P-521 curve
    EcdsaP521,
    /// Ed25519 private key
    Ed25519,
    /// Ed448 private key
    Ed448,
    /// Unknown algorithm
    Unknown,
}

impl std::fmt::Display for PrivateKeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa => write!(f, "RSA"),
            Self::EcdsaP256 => write!(f, "ECDSA-P256"),
            Self::EcdsaP384 => write!(f, "ECDSA-P384"),
            Self::EcdsaP521 => write!(f, "ECDSA-P521"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Ed448 => write!(f, "Ed448"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ============================================================================
// PKCS#12 Parsing
// ============================================================================

/// Parse a PKCS#12 (PFX) file.
///
/// # Arguments
/// * `data` - Raw PKCS#12 file bytes
/// * `password` - Password to decrypt the file (empty string for no password)
///
/// # Returns
/// Parsed PKCS#12 data including private key, certificate, and chain.
pub fn parse_pkcs12(data: &[u8], password: &str) -> CryptoResult<Pkcs12Data> {
    // Use the p12 crate to parse
    let p12 = p12::PFX::parse(data)
        .map_err(|e| CryptoError::crypto_error(format!("Failed to parse PKCS#12: {:?}", e)))?;

    // Get the key bags (private keys) - returns Vec<Vec<u8>>
    let key_bags = p12.key_bags(password).map_err(|e| {
        CryptoError::crypto_error(format!("Failed to decrypt PKCS#12 key: {:?}", e))
    })?;

    if key_bags.is_empty() {
        return Err(CryptoError::crypto_error("No private key found in PKCS#12"));
    }

    // Get the certificate bags - returns Vec<Vec<u8>> (DER-encoded)
    let cert_bags = p12.cert_x509_bags(password).map_err(|e| {
        CryptoError::crypto_error(format!("Failed to decrypt PKCS#12 certificates: {:?}", e))
    })?;

    if cert_bags.is_empty() {
        return Err(CryptoError::crypto_error(
            "No certificates found in PKCS#12",
        ));
    }

    // First key bag is the private key (already in DER format)
    let private_key_der = key_bags[0].clone();

    // Detect private key algorithm
    let private_key_algorithm = detect_key_algorithm(&private_key_der)?;

    // First certificate is the end-entity certificate (already DER)
    let certificate_der = cert_bags[0].clone();

    // Try to parse the certificate to extract subject
    let certificate_subject = Certificate::from_der(&certificate_der)
        .ok()
        .and_then(|cert| extract_certificate_subject(&cert));

    // Remaining certificates are the chain
    let certificate_chain: Vec<Vec<u8>> = cert_bags[1..].to_vec();

    // The p12 crate doesn't expose friendly_name directly
    // We could extract it from bags() but it's complex, so leaving as None for now
    let friendly_name = None;

    Ok(Pkcs12Data {
        private_key_der,
        private_key_algorithm,
        certificate_der,
        certificate_subject,
        certificate_chain,
        friendly_name,
    })
}

/// Parse PKCS#12 and return just the private key (PEM format).
///
/// # Arguments
/// * `data` - Raw PKCS#12 file bytes
/// * `password` - Password to decrypt the file
///
/// # Returns
/// PEM-encoded private key
pub fn parse_pkcs12_private_key_pem(data: &[u8], password: &str) -> CryptoResult<String> {
    let parsed = parse_pkcs12(data, password)?;

    // Convert DER to PEM
    let pem = pem_rfc7468::encode_string(
        "PRIVATE KEY",
        pem_rfc7468::LineEnding::LF,
        &parsed.private_key_der,
    )
    .map_err(|e| CryptoError::crypto_error(format!("Failed to encode PEM: {}", e)))?;

    Ok(pem)
}

/// Parse PKCS#12 and return just the certificate (PEM format).
///
/// # Arguments
/// * `data` - Raw PKCS#12 file bytes
/// * `password` - Password to decrypt the file
///
/// # Returns
/// PEM-encoded certificate
pub fn parse_pkcs12_certificate_pem(data: &[u8], password: &str) -> CryptoResult<String> {
    let parsed = parse_pkcs12(data, password)?;

    let pem = pem_rfc7468::encode_string(
        "CERTIFICATE",
        pem_rfc7468::LineEnding::LF,
        &parsed.certificate_der,
    )
    .map_err(|e| CryptoError::crypto_error(format!("Failed to encode PEM: {}", e)))?;

    Ok(pem)
}

/// Parse PKCS#12 and return the full certificate chain (PEM format).
///
/// # Arguments
/// * `data` - Raw PKCS#12 file bytes
/// * `password` - Password to decrypt the file
///
/// # Returns
/// Vector of PEM-encoded certificates (end-entity first, then chain)
pub fn parse_pkcs12_chain_pem(data: &[u8], password: &str) -> CryptoResult<Vec<String>> {
    let parsed = parse_pkcs12(data, password)?;

    let mut pem_chain = Vec::new();

    // End-entity certificate first
    let ee_pem = pem_rfc7468::encode_string(
        "CERTIFICATE",
        pem_rfc7468::LineEnding::LF,
        &parsed.certificate_der,
    )
    .map_err(|e| CryptoError::crypto_error(format!("Failed to encode PEM: {}", e)))?;
    pem_chain.push(ee_pem);

    // Then chain certificates
    for cert_der in &parsed.certificate_chain {
        let pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, cert_der)
            .map_err(|e| CryptoError::crypto_error(format!("Failed to encode PEM: {}", e)))?;
        pem_chain.push(pem);
    }

    Ok(pem_chain)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Detect the private key algorithm from PKCS#8 DER.
fn detect_key_algorithm(pkcs8_der: &[u8]) -> CryptoResult<PrivateKeyAlgorithm> {
    use pkcs8::PrivateKeyInfo;

    let pki = PrivateKeyInfo::from_der(pkcs8_der)
        .map_err(|e| CryptoError::crypto_error(format!("Failed to parse PKCS#8: {}", e)))?;

    let oid = pki.algorithm.oid;

    // Check algorithm OID
    // RSA: 1.2.840.113549.1.1.1
    if oid == const_oid::db::rfc5912::RSA_ENCRYPTION {
        return Ok(PrivateKeyAlgorithm::Rsa);
    }

    // EC: 1.2.840.10045.2.1
    if oid == const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
        // Check curve from parameters
        if let Some(params) = &pki.algorithm.parameters {
            if let Ok(curve_oid) = params.decode_as::<const_oid::ObjectIdentifier>() {
                if curve_oid == const_oid::db::rfc5912::SECP_256_R_1 {
                    return Ok(PrivateKeyAlgorithm::EcdsaP256);
                }
                if curve_oid == const_oid::db::rfc5912::SECP_384_R_1 {
                    return Ok(PrivateKeyAlgorithm::EcdsaP384);
                }
                if curve_oid == const_oid::db::rfc5912::SECP_521_R_1 {
                    return Ok(PrivateKeyAlgorithm::EcdsaP521);
                }
            }
        }
        return Ok(PrivateKeyAlgorithm::Unknown);
    }

    // Ed25519: 1.3.101.112
    if oid == const_oid::db::rfc8410::ID_ED_25519 {
        return Ok(PrivateKeyAlgorithm::Ed25519);
    }

    // Ed448: 1.3.101.113
    if oid == const_oid::db::rfc8410::ID_ED_448 {
        return Ok(PrivateKeyAlgorithm::Ed448);
    }

    Ok(PrivateKeyAlgorithm::Unknown)
}

/// Extract the subject common name from a certificate.
fn extract_certificate_subject(cert: &Certificate) -> Option<String> {
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            // CN OID: 2.5.4.3
            if atv.oid == const_oid::db::rfc4519::CN {
                if let Ok(cn) = atv.value.decode_as::<der::asn1::Utf8StringRef<'_>>() {
                    return Some(cn.to_string());
                }
                if let Ok(cn) = atv.value.decode_as::<der::asn1::PrintableStringRef<'_>>() {
                    return Some(cn.to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full tests require test PKCS#12 files
    // These tests verify the interface compiles correctly

    #[test]
    fn test_private_key_algorithm_display() {
        assert_eq!(PrivateKeyAlgorithm::Rsa.to_string(), "RSA");
        assert_eq!(PrivateKeyAlgorithm::EcdsaP256.to_string(), "ECDSA-P256");
        assert_eq!(PrivateKeyAlgorithm::Ed25519.to_string(), "Ed25519");
    }

    #[test]
    fn test_parse_invalid_data() {
        let result = parse_pkcs12(b"not a pkcs12 file", "password");
        assert!(result.is_err());
    }
}
