//! Certificate Revocation List (CRL) parsing and building.
//!
//! This module provides CRL operations for X.509 certificate revocation,
//! replacing Python cryptography CRL functionality.
//!
//! # Features
//!
//! - Parse CRLs from PEM and DER formats
//! - Build CRLs with revoked certificates
//! - Access CRL extensions (CRL number, delta CRL indicator)
//! - Check if a certificate is revoked
//!
//! # Example
//!
//! ```ignore
//! use marty_verification::crypto::crl::{load_crl_pem, CrlBuilder};
//!
//! // Parse a CRL
//! let crl_info = load_crl_pem(pem_data)?;
//! println!("CRL has {} revoked certificates", crl_info.revoked_count);
//!
//! // Build a CRL
//! let crl_der = CrlBuilder::new()
//!     .issuer_cn("My CA")
//!     .add_revoked("0102030405", RevocationReason::KeyCompromise)
//!     .build(&ca_key_pem)?;
//! ```

use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Time;
use x509_cert::Version;

use crate::{CryptoError, CryptoResult};

// ============================================================================
// Time Helper Functions
// ============================================================================

/// Convert a Unix duration to x509_cert::time::Time.
///
/// Uses GeneralizedTime for simplicity (valid for all dates).
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
                // CRL reason is an ENUMERATED value
                if let Ok(enumerated) = der::asn1::Int::from_der(ext.extn_value.as_bytes()) {
                    if let Some(&code) = enumerated.as_bytes().first() {
                        return RevocationReason::from_code(code);
                    }
                }
            }
        }
    }
    None
}

// ============================================================================
// CRL Builder
// ============================================================================

/// Entry for a revoked certificate.
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    pub serial_hex: String,
    pub reason: Option<RevocationReason>,
}

/// Builder for creating CRLs.
pub struct CrlBuilder {
    issuer: crate::cert_builder::DistinguishedName,
    validity_days: u32,
    crl_number: Option<u64>,
    revoked_entries: Vec<RevokedEntry>,
}

impl Default for CrlBuilder {
    fn default() -> Self {
        Self {
            issuer: crate::cert_builder::DistinguishedName::default(),
            validity_days: 30,
            crl_number: None,
            revoked_entries: Vec::new(),
        }
    }
}

impl CrlBuilder {
    /// Create a new CRL builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the issuer common name.
    pub fn issuer_cn(mut self, cn: &str) -> Self {
        self.issuer.common_name = Some(cn.to_string());
        self
    }

    /// Set the issuer distinguished name.
    pub fn issuer(mut self, issuer: crate::cert_builder::DistinguishedName) -> Self {
        self.issuer = issuer;
        self
    }

    /// Set validity period in days.
    pub fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Set CRL number.
    pub fn crl_number(mut self, number: u64) -> Self {
        self.crl_number = Some(number);
        self
    }

    /// Add a revoked certificate.
    pub fn add_revoked(mut self, serial_hex: &str, reason: Option<RevocationReason>) -> Self {
        self.revoked_entries.push(RevokedEntry {
            serial_hex: serial_hex.to_string(),
            reason,
        });
        self
    }

    /// Build the CRL, signed with the provided CA key.
    ///
    /// # Arguments
    /// * `ca_key_pem` - PEM-encoded CA private key
    ///
    /// # Returns
    /// DER-encoded CRL
    pub fn build(&self, ca_key_pem: &str) -> CryptoResult<Vec<u8>> {
        use p256::ecdsa::SigningKey as P256SigningKey;
        use p256::pkcs8::DecodePrivateKey;

        // Try to parse as P-256 key first
        if let Ok(signing_key) = P256SigningKey::from_pkcs8_pem(ca_key_pem) {
            return self.build_with_p256(&signing_key);
        }

        // Try P-384
        use p384::ecdsa::SigningKey as P384SigningKey;
        if let Ok(signing_key) = P384SigningKey::from_pkcs8_pem(ca_key_pem) {
            return self.build_with_p384(&signing_key);
        }

        // Try RSA
        use rsa::RsaPrivateKey;
        if let Ok(signing_key) = RsaPrivateKey::from_pkcs8_pem(ca_key_pem) {
            return self.build_with_rsa(&signing_key);
        }

        Err(CryptoError::internal(
            "Unable to parse CA key for CRL signing",
        ))
    }

    fn build_with_p256(&self, signing_key: &p256::ecdsa::SigningKey) -> CryptoResult<Vec<u8>> {
        use der::asn1::ObjectIdentifier;
        use p256::ecdsa::signature::Signer;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        // Build issuer name
        let issuer = self.build_issuer_name()?;

        // Build timestamps
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::internal("System time error"))?;

        let this_update = duration_to_x509_time(now)?;

        let next_update_duration =
            now + Duration::from_secs(self.validity_days as u64 * 24 * 60 * 60);
        let next_update = duration_to_x509_time(next_update_duration)?;

        // Build revoked certificates list
        let revoked_certs = self.build_revoked_certs()?;

        // Build TBS CertList
        let tbs = TbsCertList {
            version: Version::V2,
            signature: spki::AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new("1.2.840.10045.4.3.2") // ecdsa-with-SHA256
                    .map_err(|_| CryptoError::internal("Invalid OID"))?,
                parameters: None,
            },
            issuer,
            this_update,
            next_update: Some(next_update),
            revoked_certificates: if revoked_certs.is_empty() {
                None
            } else {
                Some(revoked_certs)
            },
            crl_extensions: self.build_crl_extensions()?,
        };

        // Encode TBS for signing
        let tbs_der = tbs
            .to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode TBS: {}", e)))?;

        // Sign
        let signature: p256::ecdsa::DerSignature = signing_key.sign(&tbs_der);
        let sig_bits = der::asn1::BitString::from_bytes(signature.as_bytes())
            .map_err(|e| CryptoError::internal(format!("Failed to create signature: {}", e)))?;

        // Build complete CRL
        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: spki::AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new("1.2.840.10045.4.3.2")
                    .map_err(|_| CryptoError::internal("Invalid OID"))?,
                parameters: None,
            },
            signature: sig_bits,
        };

        crl.to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode CRL: {}", e)))
    }

    fn build_with_p384(&self, signing_key: &p384::ecdsa::SigningKey) -> CryptoResult<Vec<u8>> {
        use der::asn1::ObjectIdentifier;
        use p384::ecdsa::signature::Signer;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let issuer = self.build_issuer_name()?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::internal("System time error"))?;

        let this_update = duration_to_x509_time(now)?;

        let next_update_duration =
            now + Duration::from_secs(self.validity_days as u64 * 24 * 60 * 60);
        let next_update = duration_to_x509_time(next_update_duration)?;

        let revoked_certs = self.build_revoked_certs()?;

        let tbs = TbsCertList {
            version: Version::V2,
            signature: spki::AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new("1.2.840.10045.4.3.3") // ecdsa-with-SHA384
                    .map_err(|_| CryptoError::internal("Invalid OID"))?,
                parameters: None,
            },
            issuer,
            this_update,
            next_update: Some(next_update),
            revoked_certificates: if revoked_certs.is_empty() {
                None
            } else {
                Some(revoked_certs)
            },
            crl_extensions: self.build_crl_extensions()?,
        };

        let tbs_der = tbs
            .to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode TBS: {}", e)))?;

        let signature: p384::ecdsa::DerSignature = signing_key.sign(&tbs_der);
        let sig_bits = der::asn1::BitString::from_bytes(signature.as_bytes())
            .map_err(|e| CryptoError::internal(format!("Failed to create signature: {}", e)))?;

        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: spki::AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new("1.2.840.10045.4.3.3")
                    .map_err(|_| CryptoError::internal("Invalid OID"))?,
                parameters: None,
            },
            signature: sig_bits,
        };

        crl.to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode CRL: {}", e)))
    }

    fn build_with_rsa(&self, signing_key: &rsa::RsaPrivateKey) -> CryptoResult<Vec<u8>> {
        use der::asn1::ObjectIdentifier;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Signer;
        use sha2::Sha256;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let issuer = self.build_issuer_name()?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::internal("System time error"))?;

        let this_update = duration_to_x509_time(now)?;

        let next_update_duration =
            now + Duration::from_secs(self.validity_days as u64 * 24 * 60 * 60);
        let next_update = duration_to_x509_time(next_update_duration)?;

        let revoked_certs = self.build_revoked_certs()?;

        let tbs = TbsCertList {
            version: Version::V2,
            signature: spki::AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new("1.2.840.113549.1.1.11") // sha256WithRSAEncryption
                    .map_err(|_| CryptoError::internal("Invalid OID"))?,
                parameters: Some(der::asn1::Null.into()),
            },
            issuer,
            this_update,
            next_update: Some(next_update),
            revoked_certificates: if revoked_certs.is_empty() {
                None
            } else {
                Some(revoked_certs)
            },
            crl_extensions: self.build_crl_extensions()?,
        };

        let tbs_der = tbs
            .to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode TBS: {}", e)))?;

        let rsa_signing_key = SigningKey::<Sha256>::new(signing_key.clone());
        let signature: rsa::pkcs1v15::Signature = rsa_signing_key.sign(&tbs_der);
        // Convert RSA signature to bytes using SignatureEncoding trait
        use rsa::signature::SignatureEncoding;
        let sig_bits = der::asn1::BitString::from_bytes(&signature.to_bytes())
            .map_err(|e| CryptoError::internal(format!("Failed to create signature: {}", e)))?;

        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: spki::AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new("1.2.840.113549.1.1.11")
                    .map_err(|_| CryptoError::internal("Invalid OID"))?,
                parameters: Some(der::asn1::Null.into()),
            },
            signature: sig_bits,
        };

        crl.to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode CRL: {}", e)))
    }

    fn build_issuer_name(&self) -> CryptoResult<Name> {
        use std::str::FromStr;

        let mut parts = Vec::new();

        if let Some(c) = &self.issuer.country {
            parts.push(format!("C={}", c));
        }
        if let Some(o) = &self.issuer.organization {
            parts.push(format!("O={}", o));
        }
        if let Some(cn) = &self.issuer.common_name {
            parts.push(format!("CN={}", cn));
        }

        if parts.is_empty() {
            return Err(CryptoError::internal(
                "CRL issuer must have at least one name component",
            ));
        }

        let name_str = parts.join(",");
        Name::from_str(&name_str)
            .map_err(|e| CryptoError::internal(format!("Failed to parse issuer name: {}", e)))
    }

    fn build_revoked_certs(&self) -> CryptoResult<Vec<RevokedCert>> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::internal("System time error"))?;

        let revocation_time = duration_to_x509_time(now)?;

        let mut result = Vec::new();

        for entry in &self.revoked_entries {
            let serial_bytes = hex::decode(&entry.serial_hex)
                .map_err(|e| CryptoError::internal(format!("Invalid serial hex: {}", e)))?;

            let serial = SerialNumber::new(&serial_bytes)
                .map_err(|e| CryptoError::internal(format!("Invalid serial number: {}", e)))?;

            result.push(RevokedCert {
                serial_number: serial,
                revocation_date: revocation_time,
                crl_entry_extensions: match entry.reason {
                    Some(reason) => {
                        // Encode CRLReason extension (OID 2.5.29.21)
                        // CRLReason ::= ENUMERATED { ... }
                        use const_oid::ObjectIdentifier;
                        use x509_cert::ext::Extension;

                        let reason_code = reason.to_code();
                        // DER-encode an ENUMERATED: tag 0x0A, length 0x01, value
                        let enum_der = vec![0x0A, 0x01, reason_code];
                        let extn_value = der::asn1::OctetString::new(enum_der)
                            .map_err(|e| CryptoError::internal(format!("DER OctetString error: {}", e)))?;
                        // id-ce-cRLReasons = 2.5.29.21
                        let oid = ObjectIdentifier::new_unwrap("2.5.29.21");
                        let ext = Extension {
                            extn_id: oid,
                            critical: false,
                            extn_value,
                        };
                        Some(vec![ext])
                    }
                    None => None,
                },
            });
        }

        Ok(result)
    }

    fn build_crl_extensions(&self) -> CryptoResult<Option<x509_cert::ext::Extensions>> {
        use const_oid::db::rfc5280::ID_CE_CRL_NUMBER;
        use x509_cert::ext::Extension;

        if let Some(crl_num) = self.crl_number {
            // Encode CRL number as INTEGER
            let num_bytes = crl_num.to_be_bytes();
            // Trim leading zeros
            let trimmed: Vec<u8> = num_bytes.iter().skip_while(|&&b| b == 0).copied().collect();
            let num_bytes = if trimmed.is_empty() { vec![0] } else { trimmed };

            let int_value = der::asn1::Int::new(&num_bytes).map_err(|e| {
                CryptoError::internal(format!("Failed to create CRL number: {}", e))
            })?;

            let value_der = int_value.to_der().map_err(|e| {
                CryptoError::internal(format!("Failed to encode CRL number: {}", e))
            })?;

            let ext = Extension {
                extn_id: ID_CE_CRL_NUMBER,
                critical: false,
                extn_value: der::asn1::OctetString::new(value_der).map_err(|e| {
                    CryptoError::internal(format!("Failed to create extension value: {}", e))
                })?,
            };

            Ok(Some(vec![ext]))
        } else {
            Ok(None)
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_builder::{create_ca_certificate, CertProfile, CertificateBuilderConfig};
    use crate::keygen::KeyType;

    #[test]
    fn test_crl_builder() {
        // Create a CA certificate first
        let (ca_cert_der, ca_key_pem) =
            create_ca_certificate("Test CA", Some("US"), 365, KeyType::EcdsaP256)
                .expect("Failed to create CA");

        // Build a CRL
        let crl_der = CrlBuilder::new()
            .issuer_cn("Test CA")
            .validity_days(30)
            .crl_number(1)
            .add_revoked("0102030405", Some(RevocationReason::KeyCompromise))
            .add_revoked("0a0b0c0d0e", Some(RevocationReason::Superseded))
            .build(&ca_key_pem)
            .expect("Failed to build CRL");

        // Parse the CRL
        let crl_info = load_crl_der(&crl_der).expect("Failed to parse CRL");

        assert!(crl_info.issuer.contains("Test CA"));
        assert_eq!(crl_info.crl_number, Some(1));
        assert_eq!(crl_info.revoked_count, 2);
        assert!(crl_info.revoked_serials.contains(&"0102030405".to_string()));
    }

    #[test]
    fn test_is_certificate_revoked() {
        let (_, ca_key_pem) = create_ca_certificate("Revocation CA", None, 365, KeyType::EcdsaP256)
            .expect("Failed to create CA");

        let crl_der = CrlBuilder::new()
            .issuer_cn("Revocation CA")
            .add_revoked("deadbeef", None)
            .build(&ca_key_pem)
            .expect("Failed to build CRL");

        assert!(is_certificate_revoked(&crl_der, "deadbeef").unwrap());
        assert!(!is_certificate_revoked(&crl_der, "cafebabe").unwrap());
    }
}
