//! X.509 Certificate Builder for creating certificates without Python cryptography.
//!
//! This module provides certificate generation capabilities using pure Rust,
//! enabling removal of the Python `cryptography` package dependency.
//!
//! # Supported Features
//!
//! - Self-signed CA certificates
//! - CA-signed leaf/DSC certificates (chain signing)
//! - Document Signer Certificates (DSC)
//! - CSCA/IACA certificates for eMRTD/mDL
//! - Certificate Signing Requests (CSR)
//! - Certificate signing with ECDSA (P-256, P-384), RSA, and Ed25519
//! - Standard X.509v3 extensions
//!
//! # Example
//!
//! ```ignore
//! use marty_verification::crypto::cert_builder::{CertificateBuilderConfig, CertProfile};
//! use marty_verification::crypto::keygen::KeyType;
//!
//! // Self-signed CA
//! let (ca_cert, ca_key) = CertificateBuilderConfig::new()
//!     .subject_cn("Test CA")
//!     .validity_days(3650)
//!     .profile(CertProfile::Ca { path_length: Some(1) })
//!     .key_type(KeyType::EcdsaP256)
//!     .build_self_signed()?;
//!
//! // CA-signed leaf certificate
//! let (leaf_cert, leaf_key) = CertificateBuilderConfig::new()
//!     .subject_cn("Test Leaf")
//!     .validity_days(365)
//!     .profile(CertProfile::EndEntity)
//!     .key_type(KeyType::EcdsaP256)
//!     .build_signed_by(&ca_cert, &ca_key)?;
//! ```

use der::{Decode, Encode};
use ed25519_dalek::{SigningKey as Ed25519SigningKey};
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::pkcs8::EncodePrivateKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use signature::Keypair; // Import for verifying_key() method
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::{
    builder::{Builder, CertificateBuilder as X509CertBuilder, Profile, RequestBuilder},
    name::Name,
    request::CertReq,
    serial_number::SerialNumber,
    time::Validity,
    Certificate,
};

use super::keygen::KeyType;
use crate::{CryptoError, CryptoResult};

// ============================================================================
// Time Helper Functions
// ============================================================================

/// Convert a Unix duration to x509_cert::time::Time.
///
/// Uses GeneralizedTime for dates after 2049, UtcTime for earlier dates.
fn duration_to_x509_time(duration: std::time::Duration) -> CryptoResult<x509_cert::time::Time> {
    use der::asn1::GeneralizedTime;

    let gt = GeneralizedTime::from_unix_duration(duration)
        .map_err(|e| CryptoError::internal(format!("Invalid time: {}", e)))?;

    Ok(x509_cert::time::Time::GeneralTime(gt))
}

// ============================================================================
// Certificate Profile Types
// ============================================================================

/// Certificate profile defining the purpose and extensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertProfile {
    /// Root CA certificate
    Ca {
        /// Maximum path length for certificate chain (None = unlimited)
        path_length: Option<u8>,
    },
    /// Intermediate CA / Document Signer Certificate
    SubCa {
        /// Maximum path length (typically 0 for DSC)
        path_length: u8,
    },
    /// End entity certificate (leaf)
    EndEntity,
    /// Country Signing CA (ICAO 9303 CSCA)
    Csca {
        /// Country code (2-letter ISO)
        country_code: String,
    },
    /// IACA certificate (ISO 18013-5 mDL)
    Iaca {
        /// Jurisdiction (e.g., "US-CA" for California)
        jurisdiction: String,
    },
    /// Document Signer Certificate (DSC for eMRTD)
    Dsc {
        /// Country code
        country_code: String,
    },
}

/// Distinguished Name components for certificate subject/issuer.
#[derive(Debug, Clone, Default)]
pub struct DistinguishedName {
    pub common_name: Option<String>,
    pub country: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub serial_number: Option<String>,
}

impl DistinguishedName {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cn(mut self, cn: &str) -> Self {
        self.common_name = Some(cn.to_string());
        self
    }

    pub fn country(mut self, c: &str) -> Self {
        self.country = Some(c.to_string());
        self
    }

    pub fn organization(mut self, o: &str) -> Self {
        self.organization = Some(o.to_string());
        self
    }

    pub fn organizational_unit(mut self, ou: &str) -> Self {
        self.organizational_unit = Some(ou.to_string());
        self
    }

    /// Build the X.509 Name from components.
    pub fn build(&self) -> CryptoResult<Name> {
        let mut name_str = String::new();

        if let Some(cn) = &self.common_name {
            if !name_str.is_empty() {
                name_str.push(',');
            }
            name_str.push_str(&format!("CN={}", cn));
        }
        if let Some(c) = &self.country {
            if !name_str.is_empty() {
                name_str.push(',');
            }
            name_str.push_str(&format!("C={}", c));
        }
        if let Some(o) = &self.organization {
            if !name_str.is_empty() {
                name_str.push(',');
            }
            name_str.push_str(&format!("O={}", o));
        }
        if let Some(ou) = &self.organizational_unit {
            if !name_str.is_empty() {
                name_str.push(',');
            }
            name_str.push_str(&format!("OU={}", ou));
        }
        if let Some(st) = &self.state {
            if !name_str.is_empty() {
                name_str.push(',');
            }
            name_str.push_str(&format!("ST={}", st));
        }
        if let Some(l) = &self.locality {
            if !name_str.is_empty() {
                name_str.push(',');
            }
            name_str.push_str(&format!("L={}", l));
        }
        if let Some(sn) = &self.serial_number {
            if !name_str.is_empty() {
                name_str.push(',');
            }
            name_str.push_str(&format!("serialNumber={}", sn));
        }

        if name_str.is_empty() {
            return Err(CryptoError::internal(
                "Distinguished name must have at least one component",
            ));
        }

        Name::from_der(
            &der::asn1::PrintableString::new(&name_str)
                .map_err(|e| CryptoError::internal(format!("Invalid name string: {}", e)))?
                .to_der()
                .map_err(|e| CryptoError::internal(format!("Failed to encode name: {}", e)))?,
        )
        .map_err(|e| CryptoError::internal(format!("Failed to parse name: {}", e)))
    }
}

// ============================================================================
// Certificate Builder
// ============================================================================

/// Builder for creating X.509 certificates.
pub struct CertificateBuilderConfig {
    subject: DistinguishedName,
    issuer: Option<DistinguishedName>,
    validity_days: u32,
    profile: CertProfile,
    key_type: KeyType,
    serial_number: Option<Vec<u8>>,
}

impl Default for CertificateBuilderConfig {
    fn default() -> Self {
        Self {
            subject: DistinguishedName::default(),
            issuer: None,
            validity_days: 365,
            profile: CertProfile::EndEntity,
            key_type: KeyType::EcdsaP256,
            serial_number: None,
        }
    }
}

impl CertificateBuilderConfig {
    /// Create a new certificate builder with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the subject distinguished name.
    pub fn subject(mut self, subject: DistinguishedName) -> Self {
        self.subject = subject;
        self
    }

    /// Convenience: set just the subject Common Name.
    pub fn subject_cn(mut self, cn: &str) -> Self {
        self.subject.common_name = Some(cn.to_string());
        self
    }

    /// Set the issuer distinguished name.
    pub fn issuer(mut self, issuer: DistinguishedName) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Convenience: set just the issuer Common Name.
    pub fn issuer_cn(mut self, cn: &str) -> Self {
        let mut issuer = self.issuer.unwrap_or_default();
        issuer.common_name = Some(cn.to_string());
        self.issuer = Some(issuer);
        self
    }

    /// Set the validity period in days from now.
    pub fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Set the certificate profile (CA, EndEntity, etc.).
    pub fn profile(mut self, profile: CertProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set the key type for the generated keypair.
    pub fn key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Set a specific serial number (otherwise random).
    pub fn serial_number(mut self, serial: Vec<u8>) -> Self {
        self.serial_number = Some(serial);
        self
    }

    /// Build a self-signed certificate.
    ///
    /// Returns (certificate_der, private_key_pem).
    pub fn build_self_signed(&self) -> CryptoResult<(Vec<u8>, String)> {
        match self.key_type {
            KeyType::EcdsaP256 => self.build_self_signed_p256(),
            KeyType::EcdsaP384 => self.build_self_signed_p384(),
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => self.build_self_signed_rsa(),
            KeyType::Ed25519 => self.build_self_signed_ed25519(),
            _ => Err(CryptoError::internal(format!(
                "Key type {:?} not supported for certificate generation",
                self.key_type
            ))),
        }
    }

    /// Build a self-signed certificate using an existing private key.
    ///
    /// This is useful when the key material is managed externally (e.g., in a KeyVault).
    ///
    /// # Arguments
    /// * `private_key_pem` - PEM-encoded private key
    ///
    /// # Returns
    /// DER-encoded certificate
    pub fn build_self_signed_with_key(&self, private_key_pem: &str) -> CryptoResult<Vec<u8>> {
        // Try to parse as different key types
        if private_key_pem.contains("EC PRIVATE KEY")
            || (private_key_pem.contains("PRIVATE KEY") && self.detect_ec_key(private_key_pem))
        {
            // Try P-256 first, then P-384
            if let Ok(result) = self.build_self_signed_with_p256_key(private_key_pem) {
                return Ok(result);
            }
            self.build_self_signed_with_p384_key(private_key_pem)
        } else if private_key_pem.contains("RSA PRIVATE KEY")
            || (private_key_pem.contains("PRIVATE KEY") && self.detect_rsa_key(private_key_pem))
        {
            self.build_self_signed_with_rsa_key(private_key_pem)
        } else if self.detect_ed25519_key(private_key_pem) {
            self.build_self_signed_with_ed25519_key(private_key_pem)
        } else {
            Err(CryptoError::internal(
                "Unable to determine key type from PEM",
            ))
        }
    }

    fn build_self_signed_with_p256_key(&self, private_key_pem: &str) -> CryptoResult<Vec<u8>> {
        use p256::pkcs8::DecodePrivateKey;

        let signing_key = P256SigningKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| CryptoError::internal(format!("Failed to parse P-256 key: {}", e)))?;
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_sec1_bytes().to_vec();

        self.build_certificate_with_ecdsa_p256(&signing_key, &public_key_bytes)
    }

    fn build_self_signed_with_p384_key(&self, private_key_pem: &str) -> CryptoResult<Vec<u8>> {
        use p384::ecdsa::SigningKey as P384SigningKey;
        use p384::pkcs8::DecodePrivateKey;

        let signing_key = P384SigningKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| CryptoError::internal(format!("Failed to parse P-384 key: {}", e)))?;
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_sec1_bytes().to_vec();

        self.build_certificate_with_ecdsa_p384(&signing_key, &public_key_bytes)
    }

    fn build_self_signed_with_rsa_key(&self, private_key_pem: &str) -> CryptoResult<Vec<u8>> {
        use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};

        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| CryptoError::internal(format!("Failed to parse RSA key: {}", e)))?;

        self.build_certificate_with_rsa(&private_key)
    }

    fn build_self_signed_with_ed25519_key(&self, private_key_pem: &str) -> CryptoResult<Vec<u8>> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        let signing_key = Ed25519SigningKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| CryptoError::internal(format!("Failed to parse Ed25519 key: {}", e)))?;
        let verifying_key = signing_key.verifying_key();

        self.build_certificate_with_ed25519(&signing_key, verifying_key.as_bytes())
    }

    /// Build a certificate signed by an issuer CA.
    ///
    /// # Arguments
    /// * `issuer_cert_der` - DER-encoded issuer certificate
    /// * `issuer_key_pem` - PEM-encoded issuer private key
    ///
    /// # Returns
    /// Tuple of (certificate_der, private_key_pem)
    pub fn build_signed_by(
        &self,
        issuer_cert_der: &[u8],
        issuer_key_pem: &str,
    ) -> CryptoResult<(Vec<u8>, String)> {
        // Parse issuer certificate to get issuer name
        let issuer_cert = Certificate::from_der(issuer_cert_der).map_err(|e| {
            CryptoError::der_error(format!("Failed to parse issuer certificate: {}", e))
        })?;

        // Determine key type from issuer key PEM by actually trying to parse
        // Order: Ed25519, RSA, EC (most specific to least)
        if self.detect_ed25519_key(issuer_key_pem) {
            return self.build_signed_by_ed25519(&issuer_cert, issuer_key_pem);
        }

        if self.detect_rsa_key(issuer_key_pem) {
            return self.build_signed_by_rsa(&issuer_cert, issuer_key_pem);
        }

        if self.detect_ec_key(issuer_key_pem) {
            // Try P-256 first, then P-384
            if let Ok(result) = self.build_signed_by_p256(&issuer_cert, issuer_key_pem) {
                return Ok(result);
            }
            return self.build_signed_by_p384(&issuer_cert, issuer_key_pem);
        }

        Err(CryptoError::internal(
            "Unable to determine issuer key type - not EC, RSA, or Ed25519",
        ))
    }

    fn detect_ec_key(&self, pem: &str) -> bool {
        // Check for EC key indicators in the PEM content
        // PKCS#8 EC keys contain EC OID 1.2.840.10045.2.1
        // Note: Can't just check length since RSA 2048 keys can overlap with P-384 sizes
        if pem.contains("EC PRIVATE KEY") {
            return true;
        }
        // Try to parse as P-256 to detect
        use p256::pkcs8::DecodePrivateKey as _;
        if p256::ecdsa::SigningKey::from_pkcs8_pem(pem).is_ok() {
            return true;
        }
        // Try P-384
        if p384::ecdsa::SigningKey::from_pkcs8_pem(pem).is_ok() {
            return true;
        }
        false
    }

    fn detect_rsa_key(&self, pem: &str) -> bool {
        // Check for RSA key indicators
        if pem.contains("RSA PRIVATE KEY") {
            return true;
        }
        // Try to parse as RSA
        use rsa::pkcs8::DecodePrivateKey as _;
        rsa::RsaPrivateKey::from_pkcs8_pem(pem).is_ok()
    }

    fn detect_ed25519_key(&self, pem: &str) -> bool {
        // Check for Ed25519 key indicators
        if pem.contains("ED25519") {
            return true;
        }
        // Try to parse as Ed25519
        use ed25519_dalek::pkcs8::DecodePrivateKey as _;
        ed25519_dalek::SigningKey::from_pkcs8_pem(pem).is_ok()
    }

    /// Build P-256 ECDSA self-signed certificate.
    fn build_self_signed_p256(&self) -> CryptoResult<(Vec<u8>, String)> {
        // Generate P-256 key pair
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Encode private key to PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        // Get public key SPKI
        let public_key_der = verifying_key.to_sec1_bytes().to_vec();

        // Build the certificate
        let cert_der = self.build_certificate_with_ecdsa_p256(&signing_key, &public_key_der)?;

        Ok((cert_der, private_key_pem))
    }

    /// Build P-384 ECDSA self-signed certificate.
    fn build_self_signed_p384(&self) -> CryptoResult<(Vec<u8>, String)> {
        use p384::ecdsa::SigningKey as P384SigningKey;
        use p384::pkcs8::EncodePrivateKey as _;

        // Generate P-384 key pair
        let signing_key = P384SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Encode private key to PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        // Get public key bytes
        let public_key_der = verifying_key.to_sec1_bytes().to_vec();

        // Build the certificate
        let cert_der = self.build_certificate_with_ecdsa_p384(&signing_key, &public_key_der)?;

        Ok((cert_der, private_key_pem))
    }

    /// Build RSA self-signed certificate.
    fn build_self_signed_rsa(&self) -> CryptoResult<(Vec<u8>, String)> {
        use rsa::{pkcs8::EncodePrivateKey as _, RsaPrivateKey};

        let bits = match self.key_type {
            KeyType::Rsa2048 => 2048,
            KeyType::Rsa3072 => 3072,
            KeyType::Rsa4096 => 4096,
            _ => 2048,
        };

        // Generate RSA key pair
        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| CryptoError::internal(format!("Failed to generate RSA key: {}", e)))?;

        // Encode private key to PEM
        let private_key_pem = private_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        // Build the certificate
        let cert_der = self.build_certificate_with_rsa(&private_key)?;

        Ok((cert_der, private_key_pem))
    }

    /// Build Ed25519 self-signed certificate.
    fn build_self_signed_ed25519(&self) -> CryptoResult<(Vec<u8>, String)> {
        use ed25519_dalek::pkcs8::EncodePrivateKey as _;
        use rand::RngCore;

        // Generate Ed25519 key pair
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = Ed25519SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        // Encode private key to PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| {
                CryptoError::internal(format!("Failed to encode Ed25519 private key: {}", e))
            })?
            .to_string();

        // Build the certificate
        let cert_der =
            self.build_certificate_with_ed25519(&signing_key, verifying_key.as_bytes())?;

        Ok((cert_der, private_key_pem))
    }

    // ========================================================================
    // Chain Signing (CA signs child certificate)
    // ========================================================================

    /// Build certificate signed by P-256 issuer.
    fn build_signed_by_p256(
        &self,
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
    ) -> CryptoResult<(Vec<u8>, String)> {
        use p256::pkcs8::DecodePrivateKey;

        // Parse issuer private key
        let issuer_signing_key = P256SigningKey::from_pkcs8_pem(issuer_key_pem).map_err(|e| {
            CryptoError::internal(format!("Failed to parse P-256 issuer key: {}", e))
        })?;

        // Generate new key pair for this certificate
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Encode private key to PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        let public_key_bytes = verifying_key.to_sec1_bytes().to_vec();

        // Build certificate signed by issuer
        let cert_der = self.build_certificate_signed_by_p256(
            &issuer_signing_key,
            &issuer_cert.tbs_certificate.subject,
            &public_key_bytes,
        )?;

        Ok((cert_der, private_key_pem))
    }

    /// Build certificate signed by P-384 issuer.
    fn build_signed_by_p384(
        &self,
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
    ) -> CryptoResult<(Vec<u8>, String)> {
        use p384::ecdsa::SigningKey as P384SigningKey;
        use p384::pkcs8::{DecodePrivateKey, EncodePrivateKey as _};

        // Parse issuer private key
        let issuer_signing_key = P384SigningKey::from_pkcs8_pem(issuer_key_pem).map_err(|e| {
            CryptoError::internal(format!("Failed to parse P-384 issuer key: {}", e))
        })?;

        // Generate new key pair for this certificate
        let signing_key = P384SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Encode private key to PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        let public_key_bytes = verifying_key.to_sec1_bytes().to_vec();

        // Build certificate signed by issuer
        let cert_der = self.build_certificate_signed_by_p384(
            &issuer_signing_key,
            &issuer_cert.tbs_certificate.subject,
            &public_key_bytes,
        )?;

        Ok((cert_der, private_key_pem))
    }

    /// Build certificate signed by RSA issuer.
    fn build_signed_by_rsa(
        &self,
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
    ) -> CryptoResult<(Vec<u8>, String)> {
        use rsa::{pkcs8::DecodePrivateKey, pkcs8::EncodePrivateKey as _, RsaPrivateKey};

        // Parse issuer private key
        let issuer_signing_key = RsaPrivateKey::from_pkcs8_pem(issuer_key_pem)
            .map_err(|e| CryptoError::internal(format!("Failed to parse RSA issuer key: {}", e)))?;

        // Generate new RSA key pair for this certificate
        let bits = match self.key_type {
            KeyType::Rsa2048 => 2048,
            KeyType::Rsa3072 => 3072,
            KeyType::Rsa4096 => 4096,
            _ => 2048,
        };

        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| CryptoError::internal(format!("Failed to generate RSA key: {}", e)))?;

        // Encode private key to PEM
        let private_key_pem = private_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        // Build certificate signed by issuer
        let cert_der = self.build_certificate_signed_by_rsa(
            &issuer_signing_key,
            &issuer_cert.tbs_certificate.subject,
            &private_key,
        )?;

        Ok((cert_der, private_key_pem))
    }

    /// Build certificate signed by Ed25519 issuer.
    fn build_signed_by_ed25519(
        &self,
        issuer_cert: &Certificate,
        issuer_key_pem: &str,
    ) -> CryptoResult<(Vec<u8>, String)> {
        use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey as _};
        use rand::RngCore;

        // Parse issuer private key
        let issuer_signing_key =
            Ed25519SigningKey::from_pkcs8_pem(issuer_key_pem).map_err(|e| {
                CryptoError::internal(format!("Failed to parse Ed25519 issuer key: {}", e))
            })?;

        // Generate new Ed25519 key pair for this certificate
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = Ed25519SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        // Encode private key to PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        // Build certificate signed by issuer
        let cert_der = self.build_certificate_signed_by_ed25519(
            &issuer_signing_key,
            &issuer_cert.tbs_certificate.subject,
            verifying_key.as_bytes(),
        )?;

        Ok((cert_der, private_key_pem))
    }

    /// Internal: build certificate TBS and sign with P-256.
    fn build_certificate_with_ecdsa_p256(
        &self,
        signing_key: &P256SigningKey,
        public_key_bytes: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        // Build subject name
        let subject = self.build_name(&self.subject)?;
        let issuer = self
            .issuer
            .as_ref()
            .map(|i| self.build_name(i))
            .transpose()?
            .unwrap_or_else(|| subject.clone());

        // Create validity period
        let validity = self.create_validity()?;

        // Generate serial number
        let serial = self.generate_serial_number()?;

        // Build the public key info for ECDSA P-256
        let spki = self.build_ecdsa_p256_spki(public_key_bytes)?;

        // Create certificate profile
        let profile = self.map_profile_to_x509_profile(&issuer);

        // Build the certificate using x509-cert builder
        let signer = EcdsaP256Signer(signing_key.clone());

        let builder = X509CertBuilder::new(profile, serial, validity, subject, spki, &signer)
            .map_err(|e| CryptoError::internal(format!("Failed to create cert builder: {}", e)))?;

        let cert = builder
            .build()
            .map_err(|e| CryptoError::internal(format!("Failed to build certificate: {}", e)))?;

        cert.to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode certificate: {}", e)))
    }

    /// Internal: build certificate with P-384.
    fn build_certificate_with_ecdsa_p384(
        &self,
        signing_key: &p384::ecdsa::SigningKey,
        public_key_bytes: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        // Build subject name
        let subject = self.build_name(&self.subject)?;
        let issuer = self
            .issuer
            .as_ref()
            .map(|i| self.build_name(i))
            .transpose()?
            .unwrap_or_else(|| subject.clone());

        // Create validity period
        let validity = self.create_validity()?;

        // Generate serial number
        let serial = self.generate_serial_number()?;

        // Build the public key info for ECDSA P-384
        let spki = self.build_ecdsa_p384_spki(public_key_bytes)?;

        // Create certificate profile
        let profile = self.map_profile_to_x509_profile(&issuer);

        // Build the certificate
        let signer = EcdsaP384Signer(signing_key.clone());

        let builder = X509CertBuilder::new(profile, serial, validity, subject, spki, &signer)
            .map_err(|e| CryptoError::internal(format!("Failed to create cert builder: {}", e)))?;

        let cert = builder
            .build()
            .map_err(|e| CryptoError::internal(format!("Failed to build certificate: {}", e)))?;

        cert.to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode certificate: {}", e)))
    }

    /// Internal: build certificate with RSA.
    fn build_certificate_with_rsa(
        &self,
        private_key: &rsa::RsaPrivateKey,
    ) -> CryptoResult<Vec<u8>> {
        use rsa::pkcs8::EncodePublicKey;

        // Build subject name
        let subject = self.build_name(&self.subject)?;
        let issuer = self
            .issuer
            .as_ref()
            .map(|i| self.build_name(i))
            .transpose()?
            .unwrap_or_else(|| subject.clone());

        // Create validity period
        let validity = self.create_validity()?;

        // Generate serial number
        let serial = self.generate_serial_number()?;

        // Get public key SPKI
        let public_key = private_key.to_public_key();
        let spki_der = public_key
            .to_public_key_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode public key: {}", e)))?;

        let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())
            .map_err(|e| CryptoError::internal(format!("Failed to parse SPKI: {}", e)))?;

        // Create certificate profile
        let profile = self.map_profile_to_x509_profile(&issuer);

        // Build the certificate
        let signer = RsaSha256Signer::new(private_key.clone());

        let builder = X509CertBuilder::new(profile, serial, validity, subject, spki, &signer)
            .map_err(|e| CryptoError::internal(format!("Failed to create cert builder: {}", e)))?;

        let cert = builder
            .build()
            .map_err(|e| CryptoError::internal(format!("Failed to build certificate: {}", e)))?;

        cert.to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode certificate: {}", e)))
    }

    /// Internal: build self-signed certificate with Ed25519.
    fn build_certificate_with_ed25519(
        &self,
        signing_key: &Ed25519SigningKey,
        public_key_bytes: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        // Build subject name
        let subject = self.build_name(&self.subject)?;
        let issuer = self
            .issuer
            .as_ref()
            .map(|i| self.build_name(i))
            .transpose()?
            .unwrap_or_else(|| subject.clone());

        // Create validity period
        let validity = self.create_validity()?;

        // Generate serial number
        let serial = self.generate_serial_number()?;

        // Build the public key info for Ed25519
        let spki = self.build_ed25519_spki(public_key_bytes)?;

        // Create certificate profile
        let profile = self.map_profile_to_x509_profile(&issuer);

        // Build the certificate
        let signer = Ed25519Signer::new(signing_key.clone());

        let builder = X509CertBuilder::new(profile, serial, validity, subject, spki, &signer)
            .map_err(|e| CryptoError::internal(format!("Failed to create cert builder: {}", e)))?;

        let cert = builder
            .build()
            .map_err(|e| CryptoError::internal(format!("Failed to build certificate: {}", e)))?;

        cert.to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode certificate: {}", e)))
    }

    // ========================================================================
    // Chain Signing Internal Methods
    // ========================================================================

    /// Build certificate signed by P-256 issuer key.
    fn build_certificate_signed_by_p256(
        &self,
        issuer_key: &P256SigningKey,
        issuer_name: &Name,
        public_key_bytes: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let subject = self.build_name(&self.subject)?;
        let validity = self.create_validity()?;
        let serial = self.generate_serial_number()?;
        let spki = self.build_ecdsa_p256_spki(public_key_bytes)?;
        let profile = self.map_profile_to_x509_profile(issuer_name);

        let signer = EcdsaP256Signer(issuer_key.clone());

        // Use issuer's name directly
        let builder = X509CertBuilder::new(profile, serial, validity, subject, spki, &signer)
            .map_err(|e| CryptoError::internal(format!("Failed to create cert builder: {}", e)))?;

        let cert = builder
            .build()
            .map_err(|e| CryptoError::internal(format!("Failed to build certificate: {}", e)))?;

        cert.to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode certificate: {}", e)))
    }

    /// Build certificate signed by P-384 issuer key.
    fn build_certificate_signed_by_p384(
        &self,
        issuer_key: &p384::ecdsa::SigningKey,
        issuer_name: &Name,
        public_key_bytes: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let subject = self.build_name(&self.subject)?;
        let validity = self.create_validity()?;
        let serial = self.generate_serial_number()?;
        let spki = self.build_ecdsa_p384_spki(public_key_bytes)?;
        let profile = self.map_profile_to_x509_profile(issuer_name);

        let signer = EcdsaP384Signer(issuer_key.clone());

        let builder = X509CertBuilder::new(profile, serial, validity, subject, spki, &signer)
            .map_err(|e| CryptoError::internal(format!("Failed to create cert builder: {}", e)))?;

        let cert = builder
            .build()
            .map_err(|e| CryptoError::internal(format!("Failed to build certificate: {}", e)))?;

        cert.to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode certificate: {}", e)))
    }

    /// Build certificate signed by RSA issuer key.
    fn build_certificate_signed_by_rsa(
        &self,
        issuer_key: &rsa::RsaPrivateKey,
        issuer_name: &Name,
        subject_key: &rsa::RsaPrivateKey,
    ) -> CryptoResult<Vec<u8>> {
        use rsa::pkcs8::EncodePublicKey;

        let subject = self.build_name(&self.subject)?;
        let validity = self.create_validity()?;
        let serial = self.generate_serial_number()?;

        // Build subject's public key SPKI
        let public_key = subject_key.to_public_key();
        let spki_der = public_key
            .to_public_key_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode public key: {}", e)))?;

        let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())
            .map_err(|e| CryptoError::internal(format!("Failed to parse SPKI: {}", e)))?;

        let profile = self.map_profile_to_x509_profile(issuer_name);

        // Sign with issuer's key
        let signer = RsaSha256Signer::new(issuer_key.clone());

        let builder = X509CertBuilder::new(profile, serial, validity, subject, spki, &signer)
            .map_err(|e| CryptoError::internal(format!("Failed to create cert builder: {}", e)))?;

        let cert = builder
            .build()
            .map_err(|e| CryptoError::internal(format!("Failed to build certificate: {}", e)))?;

        cert.to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode certificate: {}", e)))
    }

    /// Build certificate signed by Ed25519 issuer key.
    fn build_certificate_signed_by_ed25519(
        &self,
        issuer_key: &Ed25519SigningKey,
        issuer_name: &Name,
        public_key_bytes: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let subject = self.build_name(&self.subject)?;
        let validity = self.create_validity()?;
        let serial = self.generate_serial_number()?;
        let spki = self.build_ed25519_spki(public_key_bytes)?;
        let profile = self.map_profile_to_x509_profile(issuer_name);

        let signer = Ed25519Signer::new(issuer_key.clone());

        let builder = X509CertBuilder::new(profile, serial, validity, subject, spki, &signer)
            .map_err(|e| CryptoError::internal(format!("Failed to create cert builder: {}", e)))?;

        let cert = builder
            .build()
            .map_err(|e| CryptoError::internal(format!("Failed to build certificate: {}", e)))?;

        cert.to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode certificate: {}", e)))
    }

    // Helper methods

    fn build_name(&self, dn: &DistinguishedName) -> CryptoResult<Name> {
        use std::str::FromStr;

        let mut parts = Vec::new();

        if let Some(c) = &dn.country {
            parts.push(format!("C={}", c));
        }
        if let Some(o) = &dn.organization {
            parts.push(format!("O={}", o));
        }
        if let Some(ou) = &dn.organizational_unit {
            parts.push(format!("OU={}", ou));
        }
        if let Some(st) = &dn.state {
            parts.push(format!("ST={}", st));
        }
        if let Some(l) = &dn.locality {
            parts.push(format!("L={}", l));
        }
        if let Some(cn) = &dn.common_name {
            parts.push(format!("CN={}", cn));
        }
        if let Some(sn) = &dn.serial_number {
            parts.push(format!("serialNumber={}", sn));
        }

        if parts.is_empty() {
            return Err(CryptoError::internal(
                "Name must have at least one component",
            ));
        }

        let name_str = parts.join(",");
        Name::from_str(&name_str).map_err(|e| {
            CryptoError::internal(format!("Failed to parse name '{}': {}", name_str, e))
        })
    }

    fn create_validity(&self) -> CryptoResult<Validity> {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::internal("System time error"))?;

        let not_before = duration_to_x509_time(now)?;

        let not_after_duration =
            now + Duration::from_secs(self.validity_days as u64 * 24 * 60 * 60);
        let not_after = duration_to_x509_time(not_after_duration)?;

        Ok(Validity {
            not_before,
            not_after,
        })
    }

    fn generate_serial_number(&self) -> CryptoResult<SerialNumber> {
        use rand::RngCore;

        let bytes = if let Some(ref serial) = self.serial_number {
            serial.clone()
        } else {
            // Generate random 20-byte serial number
            let mut serial_bytes = [0u8; 20];
            OsRng.fill_bytes(&mut serial_bytes);
            // Ensure positive by clearing high bit
            serial_bytes[0] &= 0x7F;
            serial_bytes.to_vec()
        };

        SerialNumber::new(&bytes)
            .map_err(|e| CryptoError::internal(format!("Invalid serial number: {}", e)))
    }

    fn build_ecdsa_p256_spki(
        &self,
        public_key_bytes: &[u8],
    ) -> CryptoResult<SubjectPublicKeyInfoOwned> {
        use der::asn1::{BitString, ObjectIdentifier};
        use spki::AlgorithmIdentifierOwned;

        // OIDs for ECDSA with P-256
        let ec_public_key_oid = ObjectIdentifier::new("1.2.840.10045.2.1")
            .map_err(|e| CryptoError::internal(format!("Invalid OID: {}", e)))?;
        let secp256r1_oid = ObjectIdentifier::new("1.2.840.10045.3.1.7")
            .map_err(|e| CryptoError::internal(format!("Invalid curve OID: {}", e)))?;

        // Build parameters (curve OID)
        let params =
            der::Any::from_der(&secp256r1_oid.to_der().map_err(|e| {
                CryptoError::internal(format!("Failed to encode curve OID: {}", e))
            })?)
            .map_err(|e| CryptoError::internal(format!("Failed to parse curve OID: {}", e)))?;

        let algorithm = AlgorithmIdentifierOwned {
            oid: ec_public_key_oid,
            parameters: Some(params),
        };

        // Build uncompressed point - SEC1 format already includes 0x04 prefix
        // If already SEC1 format (65 bytes starting with 0x04), use as-is
        // Otherwise prepend 0x04 for raw x||y coordinates
        let point_bytes = if public_key_bytes.len() == 65 && public_key_bytes[0] == 0x04 {
            public_key_bytes.to_vec()
        } else {
            let mut bytes = vec![0x04];
            bytes.extend_from_slice(public_key_bytes);
            bytes
        };

        let subject_public_key = BitString::from_bytes(&point_bytes)
            .map_err(|e| CryptoError::internal(format!("Failed to create bit string: {}", e)))?;

        Ok(SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key,
        })
    }

    fn build_ecdsa_p384_spki(
        &self,
        public_key_bytes: &[u8],
    ) -> CryptoResult<SubjectPublicKeyInfoOwned> {
        use der::asn1::{BitString, ObjectIdentifier};
        use spki::AlgorithmIdentifierOwned;

        // OIDs for ECDSA with P-384
        let ec_public_key_oid = ObjectIdentifier::new("1.2.840.10045.2.1")
            .map_err(|e| CryptoError::internal(format!("Invalid OID: {}", e)))?;
        let secp384r1_oid = ObjectIdentifier::new("1.3.132.0.34")
            .map_err(|e| CryptoError::internal(format!("Invalid curve OID: {}", e)))?;

        let params =
            der::Any::from_der(&secp384r1_oid.to_der().map_err(|e| {
                CryptoError::internal(format!("Failed to encode curve OID: {}", e))
            })?)
            .map_err(|e| CryptoError::internal(format!("Failed to parse curve OID: {}", e)))?;

        let algorithm = AlgorithmIdentifierOwned {
            oid: ec_public_key_oid,
            parameters: Some(params),
        };

        // Build uncompressed point - SEC1 format already includes 0x04 prefix
        // If already SEC1 format (97 bytes starting with 0x04), use as-is
        // Otherwise prepend 0x04 for raw x||y coordinates
        let point_bytes = if public_key_bytes.len() == 97 && public_key_bytes[0] == 0x04 {
            public_key_bytes.to_vec()
        } else {
            let mut bytes = vec![0x04];
            bytes.extend_from_slice(public_key_bytes);
            bytes
        };

        let subject_public_key = BitString::from_bytes(&point_bytes)
            .map_err(|e| CryptoError::internal(format!("Failed to create bit string: {}", e)))?;

        Ok(SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key,
        })
    }

    fn build_ed25519_spki(
        &self,
        public_key_bytes: &[u8],
    ) -> CryptoResult<SubjectPublicKeyInfoOwned> {
        use der::asn1::{BitString, ObjectIdentifier};
        use spki::AlgorithmIdentifierOwned;

        // OID for Ed25519 (1.3.101.112)
        let ed25519_oid = ObjectIdentifier::new("1.3.101.112")
            .map_err(|e| CryptoError::internal(format!("Invalid Ed25519 OID: {}", e)))?;

        let algorithm = AlgorithmIdentifierOwned {
            oid: ed25519_oid,
            parameters: None, // Ed25519 has no parameters
        };

        let subject_public_key = BitString::from_bytes(public_key_bytes)
            .map_err(|e| CryptoError::internal(format!("Failed to create bit string: {}", e)))?;

        Ok(SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key,
        })
    }

    fn map_profile_to_x509_profile(&self, issuer_name: &Name) -> Profile {
        match &self.profile {
            CertProfile::Ca { path_length: _ } => {
                // Self-signed CA uses Root profile
                Profile::Root
            }
            CertProfile::SubCa { path_length } => {
                // Intermediate CA uses SubCA profile with issuer from parent
                Profile::SubCA {
                    issuer: issuer_name.clone(),
                    path_len_constraint: Some(*path_length),
                }
            }
            CertProfile::Csca { .. } | CertProfile::Iaca { .. } => {
                // Country/Issuing Authority CAs are typically root CAs
                Profile::Root
            }
            CertProfile::Dsc { .. } | CertProfile::EndEntity => Profile::Leaf {
                issuer: issuer_name.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
        }
    }
}

// ============================================================================
// Signer Implementations for x509-cert builder
// ============================================================================

// ============================================================================
// Signature Wrappers for x509-cert Builder Compatibility
// ============================================================================
// The x509-cert builder requires signatures to implement SignatureBitStringEncoding.
// Due to Rust's orphan rule, we can't implement this trait for external types directly.
// We use newtype wrappers to satisfy the trait bounds.

/// Wrapper for P-256 ECDSA DER signature.
#[derive(Clone)]
struct P256SignatureWrapper(p256::ecdsa::DerSignature);

impl AsRef<[u8]> for P256SignatureWrapper {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl signature::SignatureEncoding for P256SignatureWrapper {
    type Repr = Box<[u8]>;
}

impl From<P256SignatureWrapper> for Box<[u8]> {
    fn from(sig: P256SignatureWrapper) -> Box<[u8]> {
        sig.0.as_bytes().to_vec().into_boxed_slice()
    }
}

impl TryFrom<&[u8]> for P256SignatureWrapper {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let sig =
            p256::ecdsa::DerSignature::try_from(bytes).map_err(|_| signature::Error::new())?;
        Ok(Self(sig))
    }
}

impl spki::SignatureBitStringEncoding for P256SignatureWrapper {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::from_bytes(self.0.as_bytes())
    }
}

/// ECDSA P-256 signer wrapper for x509-cert builder.
struct EcdsaP256Signer(P256SigningKey);

impl signature::Signer<P256SignatureWrapper> for EcdsaP256Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<P256SignatureWrapper, signature::Error> {
        let sig: p256::ecdsa::DerSignature = self.0.try_sign(msg)?;
        Ok(P256SignatureWrapper(sig))
    }
}

impl spki::DynSignatureAlgorithmIdentifier for EcdsaP256Signer {
    fn signature_algorithm_identifier(
        &self,
    ) -> Result<spki::AlgorithmIdentifierOwned, spki::Error> {
        use der::asn1::ObjectIdentifier;

        // OID for ecdsa-with-SHA256
        let oid =
            ObjectIdentifier::new("1.2.840.10045.4.3.2").map_err(|_| spki::Error::KeyMalformed)?;

        Ok(spki::AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        })
    }
}

// Implement KeypairRef for EcdsaP256Signer to satisfy CertificateBuilder bounds
impl AsRef<p256::ecdsa::VerifyingKey> for EcdsaP256Signer {
    fn as_ref(&self) -> &p256::ecdsa::VerifyingKey {
        self.0.verifying_key()
    }
}

impl signature::KeypairRef for EcdsaP256Signer {
    type VerifyingKey = p256::ecdsa::VerifyingKey;
}

/// Wrapper for P-384 ECDSA DER signature.
#[derive(Clone)]
struct P384SignatureWrapper(p384::ecdsa::DerSignature);

impl AsRef<[u8]> for P384SignatureWrapper {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl signature::SignatureEncoding for P384SignatureWrapper {
    type Repr = Box<[u8]>;
}

impl From<P384SignatureWrapper> for Box<[u8]> {
    fn from(sig: P384SignatureWrapper) -> Box<[u8]> {
        sig.0.as_bytes().to_vec().into_boxed_slice()
    }
}

impl TryFrom<&[u8]> for P384SignatureWrapper {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let sig =
            p384::ecdsa::DerSignature::try_from(bytes).map_err(|_| signature::Error::new())?;
        Ok(Self(sig))
    }
}

impl spki::SignatureBitStringEncoding for P384SignatureWrapper {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::from_bytes(self.0.as_bytes())
    }
}

/// ECDSA P-384 signer wrapper.
struct EcdsaP384Signer(p384::ecdsa::SigningKey);

impl signature::Signer<P384SignatureWrapper> for EcdsaP384Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<P384SignatureWrapper, signature::Error> {
        let sig: p384::ecdsa::DerSignature = self.0.try_sign(msg)?;
        Ok(P384SignatureWrapper(sig))
    }
}

impl spki::DynSignatureAlgorithmIdentifier for EcdsaP384Signer {
    fn signature_algorithm_identifier(
        &self,
    ) -> Result<spki::AlgorithmIdentifierOwned, spki::Error> {
        use der::asn1::ObjectIdentifier;

        // OID for ecdsa-with-SHA384
        let oid =
            ObjectIdentifier::new("1.2.840.10045.4.3.3").map_err(|_| spki::Error::KeyMalformed)?;

        Ok(spki::AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        })
    }
}

// Implement KeypairRef for EcdsaP384Signer to satisfy CertificateBuilder bounds
impl AsRef<p384::ecdsa::VerifyingKey> for EcdsaP384Signer {
    fn as_ref(&self) -> &p384::ecdsa::VerifyingKey {
        self.0.verifying_key()
    }
}

impl signature::KeypairRef for EcdsaP384Signer {
    type VerifyingKey = p384::ecdsa::VerifyingKey;
}

/// Wrapper for RSA PKCS#1 v1.5 signature.
/// We store the raw signature bytes directly to avoid AsRef issues.
#[derive(Clone)]
struct RsaSignatureWrapper {
    bytes: Vec<u8>,
}

impl RsaSignatureWrapper {
    fn from_signature(sig: rsa::pkcs1v15::Signature) -> Self {
        use rsa::signature::SignatureEncoding;
        Self {
            bytes: sig.to_bytes().to_vec(),
        }
    }
}

impl AsRef<[u8]> for RsaSignatureWrapper {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl signature::SignatureEncoding for RsaSignatureWrapper {
    type Repr = Box<[u8]>;
}

impl From<RsaSignatureWrapper> for Box<[u8]> {
    fn from(sig: RsaSignatureWrapper) -> Box<[u8]> {
        sig.bytes.into_boxed_slice()
    }
}

impl TryFrom<&[u8]> for RsaSignatureWrapper {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

impl spki::SignatureBitStringEncoding for RsaSignatureWrapper {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::from_bytes(&self.bytes)
    }
}

/// RSA SHA-256 signer wrapper.
///
/// # Security Warning
/// RSA key generation and signing operations may be vulnerable to timing attacks
/// (see RUSTSEC-2023-0071). For new deployments, prefer ECDSA (P-256 or P-384)
/// or Ed25519 key types.
struct RsaSha256Signer {
    private_key: rsa::RsaPrivateKey,
    verifying_key: rsa::pkcs1v15::VerifyingKey<Sha256>,
}

impl RsaSha256Signer {
    fn new(private_key: rsa::RsaPrivateKey) -> Self {
        use rsa::pkcs1v15::SigningKey;
        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        let verifying_key = signing_key.verifying_key();
        Self {
            private_key,
            verifying_key,
        }
    }
}

impl signature::Signer<RsaSignatureWrapper> for RsaSha256Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<RsaSignatureWrapper, signature::Error> {
        use rsa::pkcs1v15::SigningKey;

        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let sig = signing_key.try_sign(msg)?;
        Ok(RsaSignatureWrapper::from_signature(sig))
    }
}

impl spki::DynSignatureAlgorithmIdentifier for RsaSha256Signer {
    fn signature_algorithm_identifier(
        &self,
    ) -> Result<spki::AlgorithmIdentifierOwned, spki::Error> {
        use der::asn1::ObjectIdentifier;

        // OID for sha256WithRSAEncryption
        let oid = ObjectIdentifier::new("1.2.840.113549.1.1.11")
            .map_err(|_| spki::Error::KeyMalformed)?;

        Ok(spki::AlgorithmIdentifierOwned {
            oid,
            parameters: Some(der::asn1::Null.into()),
        })
    }
}

// Implement KeypairRef for RsaSha256Signer to satisfy CertificateBuilder bounds
impl AsRef<rsa::pkcs1v15::VerifyingKey<Sha256>> for RsaSha256Signer {
    fn as_ref(&self) -> &rsa::pkcs1v15::VerifyingKey<Sha256> {
        &self.verifying_key
    }
}

impl signature::KeypairRef for RsaSha256Signer {
    type VerifyingKey = rsa::pkcs1v15::VerifyingKey<Sha256>;
}

/// Ed25519 signer wrapper for x509-cert builder.
/// Stores both signing and verifying keys to satisfy KeypairRef trait.
struct Ed25519Signer {
    signing_key: Ed25519SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl Ed25519Signer {
    fn new(signing_key: Ed25519SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }
}

/// Ed25519 signature wrapper for x509-cert compatibility.
/// We store the bytes directly to implement AsRef correctly.
#[derive(Clone)]
struct Ed25519SignatureWrapper {
    bytes: [u8; 64],
}

impl Ed25519SignatureWrapper {
    fn from_signature(sig: ed25519_dalek::Signature) -> Self {
        Self {
            bytes: sig.to_bytes(),
        }
    }
}

impl AsRef<[u8]> for Ed25519SignatureWrapper {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl signature::SignatureEncoding for Ed25519SignatureWrapper {
    type Repr = [u8; 64];
}

impl From<Ed25519SignatureWrapper> for [u8; 64] {
    fn from(sig: Ed25519SignatureWrapper) -> [u8; 64] {
        sig.bytes
    }
}

impl TryFrom<&[u8]> for Ed25519SignatureWrapper {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 64] = bytes.try_into().map_err(|_| signature::Error::new())?;
        Ok(Self { bytes: arr })
    }
}

impl signature::Signer<Ed25519SignatureWrapper> for Ed25519Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<Ed25519SignatureWrapper, signature::Error> {
        let sig = self.signing_key.sign(msg);
        Ok(Ed25519SignatureWrapper::from_signature(sig))
    }
}

impl spki::SignatureBitStringEncoding for Ed25519SignatureWrapper {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::from_bytes(&self.bytes)
    }
}

impl spki::DynSignatureAlgorithmIdentifier for Ed25519Signer {
    fn signature_algorithm_identifier(
        &self,
    ) -> Result<spki::AlgorithmIdentifierOwned, spki::Error> {
        use der::asn1::ObjectIdentifier;

        // OID for Ed25519 (1.3.101.112)
        let oid = ObjectIdentifier::new("1.3.101.112").map_err(|_| spki::Error::KeyMalformed)?;

        Ok(spki::AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        })
    }
}

// Implement KeypairRef for Ed25519Signer to satisfy CertificateBuilder bounds
impl AsRef<ed25519_dalek::VerifyingKey> for Ed25519Signer {
    fn as_ref(&self) -> &ed25519_dalek::VerifyingKey {
        &self.verifying_key
    }
}

impl signature::KeypairRef for Ed25519Signer {
    type VerifyingKey = ed25519_dalek::VerifyingKey;
}

// ============================================================================
// High-Level API Functions
// ============================================================================

/// Create a self-signed CA certificate.
///
/// # Arguments
/// * `common_name` - The CN for the certificate subject
/// * `country` - Optional country code (e.g., "US")
/// * `validity_days` - Number of days the certificate is valid
/// * `key_type` - Type of key to generate
///
/// # Returns
/// Tuple of (certificate_der, private_key_pem)
pub fn create_ca_certificate(
    common_name: &str,
    country: Option<&str>,
    validity_days: u32,
    key_type: KeyType,
) -> CryptoResult<(Vec<u8>, String)> {
    let mut subject = DistinguishedName::new().cn(common_name);
    if let Some(c) = country {
        subject = subject.country(c);
    }

    CertificateBuilderConfig::new()
        .subject(subject)
        .validity_days(validity_days)
        .profile(CertProfile::Ca { path_length: None })
        .key_type(key_type)
        .build_self_signed()
}

/// Create a CSCA (Country Signing CA) certificate for eMRTD.
pub fn create_csca_certificate(
    country_code: &str,
    organization: &str,
    validity_days: u32,
    key_type: KeyType,
) -> CryptoResult<(Vec<u8>, String)> {
    let subject = DistinguishedName::new()
        .cn(&format!("{} Country Signing CA", country_code))
        .country(country_code)
        .organization(organization);

    CertificateBuilderConfig::new()
        .subject(subject)
        .validity_days(validity_days)
        .profile(CertProfile::Csca {
            country_code: country_code.to_string(),
        })
        .key_type(key_type)
        .build_self_signed()
}

/// Create an IACA (Issuing Authority CA) certificate for mDL.
pub fn create_iaca_certificate(
    jurisdiction: &str,
    organization: &str,
    validity_days: u32,
    key_type: KeyType,
) -> CryptoResult<(Vec<u8>, String)> {
    let subject = DistinguishedName::new()
        .cn(&format!("{} Issuing Authority", jurisdiction))
        .organization(organization);

    // Extract country from jurisdiction (e.g., "US-CA" -> "US")
    let country = jurisdiction.split('-').next().unwrap_or(jurisdiction);
    let subject = subject.country(country);

    CertificateBuilderConfig::new()
        .subject(subject)
        .validity_days(validity_days)
        .profile(CertProfile::Iaca {
            jurisdiction: jurisdiction.to_string(),
        })
        .key_type(key_type)
        .build_self_signed()
}

/// Create a mock/test certificate for demonstration purposes.
///
/// This is a direct replacement for the Python `_create_mock_certificate` function.
pub fn create_mock_certificate(
    subject_cn: &str,
    issuer_cn: &str,
    serial_number_hex: &str,
    validity_days: u32,
    is_ca: bool,
) -> CryptoResult<Vec<u8>> {
    // Parse serial number from hex
    let serial = hex::decode(serial_number_hex)
        .map_err(|e| CryptoError::internal(format!("Invalid serial number hex: {}", e)))?;

    let profile = if is_ca {
        CertProfile::Ca { path_length: None }
    } else {
        CertProfile::EndEntity
    };

    let (cert_der, _private_key) = CertificateBuilderConfig::new()
        .subject_cn(subject_cn)
        .issuer_cn(issuer_cn)
        .validity_days(validity_days)
        .profile(profile)
        .serial_number(serial)
        .key_type(KeyType::EcdsaP256)
        .build_self_signed()?;

    Ok(cert_der)
}

/// Create a certificate signed by an issuer CA.
///
/// # Arguments
/// * `subject_cn` - Common name for the subject
/// * `issuer_cert_der` - DER-encoded issuer certificate
/// * `issuer_key_pem` - PEM-encoded issuer private key
/// * `validity_days` - Number of days the certificate is valid
/// * `is_ca` - Whether this is a CA certificate
/// * `key_type` - Type of key to generate for the new certificate
///
/// # Returns
/// Tuple of (certificate_der, private_key_pem)
pub fn create_signed_certificate(
    subject_cn: &str,
    issuer_cert_der: &[u8],
    issuer_key_pem: &str,
    validity_days: u32,
    is_ca: bool,
    key_type: KeyType,
) -> CryptoResult<(Vec<u8>, String)> {
    let profile = if is_ca {
        CertProfile::SubCa { path_length: 0 }
    } else {
        CertProfile::EndEntity
    };

    CertificateBuilderConfig::new()
        .subject_cn(subject_cn)
        .validity_days(validity_days)
        .profile(profile)
        .key_type(key_type)
        .build_signed_by(issuer_cert_der, issuer_key_pem)
}

/// Create a DSC (Document Signer Certificate) signed by a CSCA.
pub fn create_dsc_certificate(
    country_code: &str,
    organization: &str,
    csca_cert_der: &[u8],
    csca_key_pem: &str,
    validity_days: u32,
    key_type: KeyType,
) -> CryptoResult<(Vec<u8>, String)> {
    let subject = DistinguishedName::new()
        .cn(&format!("{} Document Signer", country_code))
        .country(country_code)
        .organization(organization);

    CertificateBuilderConfig::new()
        .subject(subject)
        .validity_days(validity_days)
        .profile(CertProfile::Dsc {
            country_code: country_code.to_string(),
        })
        .key_type(key_type)
        .build_signed_by(csca_cert_der, csca_key_pem)
}

// ============================================================================
// Certificate Signing Request (CSR) Builder
// ============================================================================

/// CSR builder configuration.
pub struct CsrBuilderConfig {
    subject: DistinguishedName,
    key_type: KeyType,
}

impl Default for CsrBuilderConfig {
    fn default() -> Self {
        Self {
            subject: DistinguishedName::default(),
            key_type: KeyType::EcdsaP256,
        }
    }
}

impl CsrBuilderConfig {
    /// Create a new CSR builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the subject distinguished name.
    pub fn subject(mut self, subject: DistinguishedName) -> Self {
        self.subject = subject;
        self
    }

    /// Set just the subject Common Name.
    pub fn subject_cn(mut self, cn: &str) -> Self {
        self.subject.common_name = Some(cn.to_string());
        self
    }

    /// Set the key type.
    pub fn key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Build the CSR.
    ///
    /// Returns (csr_der, private_key_pem).
    pub fn build(&self) -> CryptoResult<(Vec<u8>, String)> {
        match self.key_type {
            KeyType::EcdsaP256 => self.build_csr_p256(),
            KeyType::EcdsaP384 => self.build_csr_p384(),
            KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => self.build_csr_rsa(),
            KeyType::Ed25519 => self.build_csr_ed25519(),
            _ => Err(CryptoError::internal(format!(
                "Key type {:?} not supported for CSR generation",
                self.key_type
            ))),
        }
    }

    fn build_csr_p256(&self) -> CryptoResult<(Vec<u8>, String)> {
        // Generate P-256 key pair
        let signing_key = P256SigningKey::random(&mut OsRng);

        // Encode private key to PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        // Build subject name
        let subject = self.build_name()?;

        // Build CSR using RequestBuilder with the raw signing key
        // P256SigningKey implements Keypair and its VerifyingKey implements EncodePublicKey
        let builder = RequestBuilder::new(subject, &signing_key)
            .map_err(|e| CryptoError::internal(format!("Failed to create CSR builder: {}", e)))?;

        let csr: CertReq = builder
            .build::<p256::ecdsa::DerSignature>()
            .map_err(|e| CryptoError::internal(format!("Failed to build CSR: {}", e)))?;

        let csr_der = csr
            .to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode CSR: {}", e)))?;

        Ok((csr_der, private_key_pem))
    }

    fn build_csr_p384(&self) -> CryptoResult<(Vec<u8>, String)> {
        use p384::ecdsa::SigningKey as P384SigningKey;
        use p384::pkcs8::EncodePrivateKey as _;

        // Generate P-384 key pair
        let signing_key = P384SigningKey::random(&mut OsRng);

        // Encode private key to PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        // Build subject name
        let subject = self.build_name()?;

        // Build CSR using RequestBuilder
        let builder = RequestBuilder::new(subject, &signing_key)
            .map_err(|e| CryptoError::internal(format!("Failed to create CSR builder: {}", e)))?;

        let csr: CertReq = builder
            .build::<p384::ecdsa::DerSignature>()
            .map_err(|e| CryptoError::internal(format!("Failed to build CSR: {}", e)))?;

        let csr_der = csr
            .to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode CSR: {}", e)))?;

        Ok((csr_der, private_key_pem))
    }

    fn build_csr_rsa(&self) -> CryptoResult<(Vec<u8>, String)> {
        use rsa::{pkcs8::EncodePrivateKey as _, RsaPrivateKey};

        let bits = match self.key_type {
            KeyType::Rsa2048 => 2048,
            KeyType::Rsa3072 => 3072,
            KeyType::Rsa4096 => 4096,
            _ => 2048,
        };

        // Generate RSA key pair
        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| CryptoError::internal(format!("Failed to generate RSA key: {}", e)))?;

        // Encode private key to PEM
        let private_key_pem = private_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        // Build subject name
        let subject = self.build_name()?;

        // Build CSR using RequestBuilder with rsa::pkcs1v15::SigningKey
        // which implements the required Keypair trait
        use rsa::pkcs1v15::SigningKey as RsaSigningKeyTyped;
        let rsa_signing_key = RsaSigningKeyTyped::<Sha256>::new(private_key);

        let builder = RequestBuilder::new(subject, &rsa_signing_key)
            .map_err(|e| CryptoError::internal(format!("Failed to create CSR builder: {}", e)))?;

        let csr: CertReq = builder
            .build::<rsa::pkcs1v15::Signature>()
            .map_err(|e| CryptoError::internal(format!("Failed to build CSR: {}", e)))?;

        let csr_der = csr
            .to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode CSR: {}", e)))?;

        Ok((csr_der, private_key_pem))
    }

    fn build_csr_ed25519(&self) -> CryptoResult<(Vec<u8>, String)> {
        use ed25519_dalek::pkcs8::EncodePrivateKey as _;
        use rand::RngCore;

        // Generate Ed25519 key pair
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = Ed25519SigningKey::from_bytes(&secret_bytes);

        // Encode private key to PEM
        let private_key_pem = signing_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?
            .to_string();

        // Build subject name
        let subject = self.build_name()?;

        // Build CSR using our Ed25519Signer wrapper which produces Ed25519SignatureWrapper
        // that implements SignatureBitStringEncoding
        let signer = Ed25519Signer::new(signing_key);

        let builder = RequestBuilder::new(subject, &signer)
            .map_err(|e| CryptoError::internal(format!("Failed to create CSR builder: {}", e)))?;

        let csr: CertReq = builder
            .build::<Ed25519SignatureWrapper>()
            .map_err(|e| CryptoError::internal(format!("Failed to build CSR: {}", e)))?;

        let csr_der = csr
            .to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode CSR: {}", e)))?;

        Ok((csr_der, private_key_pem))
    }

    fn build_name(&self) -> CryptoResult<Name> {
        use std::str::FromStr;

        let mut parts = Vec::new();

        if let Some(c) = &self.subject.country {
            parts.push(format!("C={}", c));
        }
        if let Some(o) = &self.subject.organization {
            parts.push(format!("O={}", o));
        }
        if let Some(ou) = &self.subject.organizational_unit {
            parts.push(format!("OU={}", ou));
        }
        if let Some(cn) = &self.subject.common_name {
            parts.push(format!("CN={}", cn));
        }

        if parts.is_empty() {
            return Err(CryptoError::internal(
                "CSR subject must have at least one component",
            ));
        }

        let name_str = parts.join(",");
        Name::from_str(&name_str)
            .map_err(|e| CryptoError::internal(format!("Failed to parse name: {}", e)))
    }

    #[allow(dead_code)]
    fn build_ecdsa_p256_spki(
        &self,
        public_key_bytes: &[u8],
    ) -> CryptoResult<SubjectPublicKeyInfoOwned> {
        use der::asn1::{BitString, ObjectIdentifier};
        use spki::AlgorithmIdentifierOwned;

        let ec_public_key_oid = ObjectIdentifier::new("1.2.840.10045.2.1")
            .map_err(|e| CryptoError::internal(format!("Invalid OID: {}", e)))?;
        let secp256r1_oid = ObjectIdentifier::new("1.2.840.10045.3.1.7")
            .map_err(|e| CryptoError::internal(format!("Invalid curve OID: {}", e)))?;

        let params =
            der::Any::from_der(&secp256r1_oid.to_der().map_err(|e| {
                CryptoError::internal(format!("Failed to encode curve OID: {}", e))
            })?)
            .map_err(|e| CryptoError::internal(format!("Failed to parse curve OID: {}", e)))?;

        let algorithm = AlgorithmIdentifierOwned {
            oid: ec_public_key_oid,
            parameters: Some(params),
        };

        let mut point_bytes = vec![0x04];
        point_bytes.extend_from_slice(public_key_bytes);

        let subject_public_key = BitString::from_bytes(&point_bytes)
            .map_err(|e| CryptoError::internal(format!("Failed to create bit string: {}", e)))?;

        Ok(SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key,
        })
    }

    #[allow(dead_code)]
    fn build_ecdsa_p384_spki(
        &self,
        public_key_bytes: &[u8],
    ) -> CryptoResult<SubjectPublicKeyInfoOwned> {
        use der::asn1::{BitString, ObjectIdentifier};
        use spki::AlgorithmIdentifierOwned;

        let ec_public_key_oid = ObjectIdentifier::new("1.2.840.10045.2.1")
            .map_err(|e| CryptoError::internal(format!("Invalid OID: {}", e)))?;
        let secp384r1_oid = ObjectIdentifier::new("1.3.132.0.34")
            .map_err(|e| CryptoError::internal(format!("Invalid curve OID: {}", e)))?;

        let params =
            der::Any::from_der(&secp384r1_oid.to_der().map_err(|e| {
                CryptoError::internal(format!("Failed to encode curve OID: {}", e))
            })?)
            .map_err(|e| CryptoError::internal(format!("Failed to parse curve OID: {}", e)))?;

        let algorithm = AlgorithmIdentifierOwned {
            oid: ec_public_key_oid,
            parameters: Some(params),
        };

        let mut point_bytes = vec![0x04];
        point_bytes.extend_from_slice(public_key_bytes);

        let subject_public_key = BitString::from_bytes(&point_bytes)
            .map_err(|e| CryptoError::internal(format!("Failed to create bit string: {}", e)))?;

        Ok(SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key,
        })
    }

    #[allow(dead_code)]
    fn build_ed25519_spki(
        &self,
        public_key_bytes: &[u8],
    ) -> CryptoResult<SubjectPublicKeyInfoOwned> {
        use der::asn1::{BitString, ObjectIdentifier};
        use spki::AlgorithmIdentifierOwned;

        let ed25519_oid = ObjectIdentifier::new("1.3.101.112")
            .map_err(|e| CryptoError::internal(format!("Invalid Ed25519 OID: {}", e)))?;

        let algorithm = AlgorithmIdentifierOwned {
            oid: ed25519_oid,
            parameters: None,
        };

        let subject_public_key = BitString::from_bytes(public_key_bytes)
            .map_err(|e| CryptoError::internal(format!("Failed to create bit string: {}", e)))?;

        Ok(SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key,
        })
    }
}

/// Create a Certificate Signing Request (CSR).
///
/// # Arguments
/// * `common_name` - The CN for the CSR subject
/// * `key_type` - Type of key to generate
///
/// # Returns
/// Tuple of (csr_der, private_key_pem)
pub fn create_csr(common_name: &str, key_type: KeyType) -> CryptoResult<(Vec<u8>, String)> {
    CsrBuilderConfig::new()
        .subject_cn(common_name)
        .key_type(key_type)
        .build()
}

/// Load a CSR from DER bytes and return basic info.
pub fn load_csr_der(csr_der: &[u8]) -> CryptoResult<CsrInfo> {
    let csr = CertReq::from_der(csr_der)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse CSR: {}", e)))?;

    Ok(CsrInfo {
        subject: csr.info.subject.to_string(),
    })
}

/// CSR information.
#[derive(Debug, Clone)]
pub struct CsrInfo {
    pub subject: String,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::get_certificate_info;

    #[test]
    fn test_create_self_signed_p256() {
        let (cert_der, private_key_pem) = CertificateBuilderConfig::new()
            .subject_cn("Test CA")
            .validity_days(365)
            .profile(CertProfile::Ca {
                path_length: Some(1),
            })
            .key_type(KeyType::EcdsaP256)
            .build_self_signed()
            .expect("Failed to create certificate");

        assert!(!cert_der.is_empty());
        assert!(private_key_pem.contains("BEGIN PRIVATE KEY"));

        // Verify we can parse the certificate
        let info = get_certificate_info(&cert_der).expect("Failed to parse certificate");
        assert!(info.subject.contains("Test CA"));
        assert!(info.is_ca);
    }

    #[test]
    fn test_create_ca_certificate() {
        let (cert_der, private_key_pem) =
            create_ca_certificate("My Root CA", Some("US"), 365 * 10, KeyType::EcdsaP256)
                .expect("Failed to create CA certificate");

        assert!(!cert_der.is_empty());
        assert!(!private_key_pem.is_empty());

        let info = get_certificate_info(&cert_der).expect("Failed to parse certificate");
        assert!(info.is_ca);
    }

    #[test]
    fn test_create_csca_certificate() {
        let (cert_der, _) = create_csca_certificate(
            "US",
            "U.S. Department of State",
            365 * 15,
            KeyType::EcdsaP256,
        )
        .expect("Failed to create CSCA certificate");

        let info = get_certificate_info(&cert_der).expect("Failed to parse certificate");
        assert!(info.subject.contains("US"));
        assert!(info.is_ca);
    }

    #[test]
    fn test_create_mock_certificate() {
        let cert_der =
            create_mock_certificate("Test Subject", "Test Issuer", "0102030405060708", 365, true)
                .expect("Failed to create mock certificate");

        let info = get_certificate_info(&cert_der).expect("Failed to parse certificate");
        assert!(info.subject.contains("Test Subject"));
    }
}
