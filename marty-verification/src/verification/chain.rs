//! Generic X.509 certificate chain validation.
//!
//! Provides certificate chain validation functionality that can be used
//! across different document types (mDL, eMRTD, etc.).
//!
//! # Features
//!
//! - Certificate parsing (PEM/DER)
//! - Chain building and validation
//! - Validity period checking
//! - Key usage verification
//! - CRL/OCSP revocation checking (optional)

use chrono::{DateTime, Utc};
use der::{Decode, DecodePem, Encode};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::{VerificationError, VerificationResult};

/// Result of certificate chain validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainValidationResult {
    /// Whether the chain is valid.
    pub valid: bool,
    /// Subject of the end-entity certificate.
    pub subject: Option<String>,
    /// Issuer of the end-entity certificate.
    pub issuer: Option<String>,
    /// Chain depth (number of certificates).
    pub chain_depth: usize,
    /// Validation errors (empty if valid).
    pub errors: Vec<String>,
    /// Warnings (non-fatal issues).
    pub warnings: Vec<String>,
}

impl ChainValidationResult {
    /// Create a successful result.
    pub fn success(subject: String, issuer: String, chain_depth: usize) -> Self {
        Self {
            valid: true,
            subject: Some(subject),
            issuer: Some(issuer),
            chain_depth,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Create a failed result with an error.
    pub fn failure(error: String) -> Self {
        Self {
            valid: false,
            errors: vec![error],
            ..Default::default()
        }
    }

    /// Add a warning.
    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

/// Key usage flags for certificate validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyUsage {
    /// Digital signature (signing documents, authentication)
    DigitalSignature,
    /// Non-repudiation (content commitment)
    NonRepudiation,
    /// Key encipherment (encrypting keys)
    KeyEncipherment,
    /// Data encipherment (encrypting data)
    DataEncipherment,
    /// Key agreement (Diffie-Hellman)
    KeyAgreement,
    /// Certificate signing (CA certificates)
    KeyCertSign,
    /// CRL signing
    CrlSign,
    /// Encipher only (with key agreement)
    EncipherOnly,
    /// Decipher only (with key agreement)
    DecipherOnly,
}

/// Certificate chain validator configuration.
#[derive(Debug, Clone)]
pub struct ChainValidatorConfig {
    /// Whether to check CRL revocation.
    pub check_crl: bool,
    /// Whether to check OCSP revocation.
    pub check_ocsp: bool,
    /// Revocation mode: "hard_fail", "soft_fail", "none"
    pub revocation_mode: String,
    /// Validation moment (None = now)
    pub validation_moment: Option<DateTime<Utc>>,
    /// Required key usages for end-entity certificate.
    pub required_key_usage: Vec<KeyUsage>,
}

impl Default for ChainValidatorConfig {
    fn default() -> Self {
        Self {
            check_crl: false,
            check_ocsp: false,
            revocation_mode: "soft_fail".to_string(),
            validation_moment: None,
            required_key_usage: vec![KeyUsage::DigitalSignature],
        }
    }
}

/// Certificate chain validator.
pub struct ChainValidator {
    /// Trust anchors (root CA certificates).
    trust_anchors: Vec<Certificate>,
    /// Intermediate certificates.
    intermediates: Vec<Certificate>,
    /// Configuration.
    config: ChainValidatorConfig,
    /// CRLs for revocation checking.
    crls: Vec<Vec<u8>>,
    /// DER OCSP responses for certificate-bound authenticated checking.
    ocsp_responses: Vec<Vec<u8>>,
}

impl ChainValidator {
    /// Create a new chain validator.
    pub fn new() -> Self {
        Self {
            trust_anchors: Vec::new(),
            intermediates: Vec::new(),
            config: ChainValidatorConfig::default(),
            crls: Vec::new(),
            ocsp_responses: Vec::new(),
        }
    }

    /// Create a new chain validator with configuration.
    pub fn with_config(config: ChainValidatorConfig) -> Self {
        Self {
            trust_anchors: Vec::new(),
            intermediates: Vec::new(),
            config,
            crls: Vec::new(),
            ocsp_responses: Vec::new(),
        }
    }

    /// Copy this validator's trust material while applying a different policy.
    pub fn configured(&self, config: ChainValidatorConfig) -> Self {
        Self {
            trust_anchors: self.trust_anchors.clone(),
            intermediates: self.intermediates.clone(),
            config,
            crls: self.crls.clone(),
            ocsp_responses: self.ocsp_responses.clone(),
        }
    }

    /// Add a trust anchor from PEM.
    pub fn add_trust_anchor_pem(&mut self, pem: &str) -> VerificationResult<()> {
        let cert = Certificate::from_pem(pem).map_err(|e| {
            VerificationError::pem_error(format!("Invalid trust anchor PEM: {}", e))
        })?;
        self.trust_anchors.push(cert);
        Ok(())
    }

    /// Add a trust anchor from DER.
    pub fn add_trust_anchor_der(&mut self, der: &[u8]) -> VerificationResult<()> {
        let cert = Certificate::from_der(der).map_err(|e| {
            VerificationError::der_error(format!("Invalid trust anchor DER: {}", e))
        })?;
        self.trust_anchors.push(cert);
        Ok(())
    }

    /// Add an intermediate certificate from PEM.
    pub fn add_intermediate_pem(&mut self, pem: &str) -> VerificationResult<()> {
        let cert = Certificate::from_pem(pem).map_err(|e| {
            VerificationError::pem_error(format!("Invalid intermediate PEM: {}", e))
        })?;
        self.intermediates.push(cert);
        Ok(())
    }

    /// Add an intermediate certificate from DER.
    pub fn add_intermediate_der(&mut self, der: &[u8]) -> VerificationResult<()> {
        let cert = Certificate::from_der(der).map_err(|e| {
            VerificationError::der_error(format!("Invalid intermediate DER: {}", e))
        })?;
        self.intermediates.push(cert);
        Ok(())
    }

    /// Add a DER CRL for authenticated revocation checking.
    pub fn add_crl_der(&mut self, crl_der: &[u8]) -> VerificationResult<()> {
        x509_cert::crl::CertificateList::from_der(crl_der)
            .map_err(|e| VerificationError::der_error(format!("Invalid CRL DER: {e}")))?;
        self.crls.push(crl_der.to_vec());
        Ok(())
    }

    /// Add a DER OCSP response. Trust is established only when validating it
    /// against a specific certificate and issuer during chain validation.
    pub fn add_ocsp_response_der(&mut self, response_der: &[u8]) -> VerificationResult<()> {
        marty_crypto::ocsp::parse_ocsp_response(response_der).map_err(|error| {
            VerificationError::der_error(format!("Invalid OCSP response DER: {error}"))
        })?;
        self.ocsp_responses.push(response_der.to_vec());
        Ok(())
    }

    /// Validate a certificate chain.
    ///
    /// The chain should be ordered from end-entity to root (or closest to root).
    pub fn validate_chain(
        &self,
        chain_pem: &[String],
    ) -> VerificationResult<ChainValidationResult> {
        if chain_pem.is_empty() {
            return Ok(ChainValidationResult::failure(
                "Empty certificate chain".to_string(),
            ));
        }

        // Parse all certificates in the chain
        let mut chain: Vec<Certificate> = Vec::with_capacity(chain_pem.len());
        for (i, pem) in chain_pem.iter().enumerate() {
            let cert = Certificate::from_pem(pem).map_err(|e| {
                VerificationError::pem_error(format!(
                    "Failed to parse certificate {} in chain: {}",
                    i, e
                ))
            })?;
            chain.push(cert);
        }

        self.validate_parsed_chain(&chain)
    }

    /// Validate a certificate chain from DER bytes.
    pub fn validate_chain_der(
        &self,
        chain_der: &[Vec<u8>],
    ) -> VerificationResult<ChainValidationResult> {
        if chain_der.is_empty() {
            return Ok(ChainValidationResult::failure(
                "Empty certificate chain".to_string(),
            ));
        }

        let mut chain: Vec<Certificate> = Vec::with_capacity(chain_der.len());
        for (i, der) in chain_der.iter().enumerate() {
            let cert = Certificate::from_der(der).map_err(|e| {
                VerificationError::der_error(format!(
                    "Failed to parse certificate {} in chain: {}",
                    i, e
                ))
            })?;
            chain.push(cert);
        }

        self.validate_parsed_chain(&chain)
    }

    /// Validate a single certificate.
    pub fn validate_certificate(
        &self,
        cert_pem: &str,
    ) -> VerificationResult<ChainValidationResult> {
        self.validate_chain(&[cert_pem.to_string()])
    }

    fn validate_parsed_chain(
        &self,
        chain: &[Certificate],
    ) -> VerificationResult<ChainValidationResult> {
        let end_entity = &chain[0];
        let subject = end_entity.tbs_certificate.subject.to_string();
        let issuer = end_entity.tbs_certificate.issuer.to_string();

        let mut result = ChainValidationResult {
            valid: true,
            subject: Some(subject.clone()),
            issuer: Some(issuer.clone()),
            chain_depth: chain.len(),
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        // Check validity periods
        let now = self.config.validation_moment.unwrap_or_else(Utc::now);

        for (i, cert) in chain.iter().enumerate() {
            if let Err(e) = self.check_validity(cert, now) {
                result.valid = false;
                result.errors.push(format!("Certificate {}: {}", i, e));
            }
        }

        // Verify chain signatures
        if let Err(e) = self.verify_chain_signatures(chain) {
            result.valid = false;
            result.errors.push(e);
        }
        if let Err(e) = self.check_chain_constraints(chain) {
            result.valid = false;
            result.errors.push(e);
        }

        // Check key usage for end-entity
        if let Err(e) = self.check_key_usage(end_entity) {
            if self.config.required_key_usage.is_empty() {
                result.warnings.push(format!("Key usage check: {}", e));
            } else {
                result.valid = false;
                result.errors.push(format!("Key usage: {}", e));
            }
        }

        // Check revocation if configured
        if self.config.check_crl {
            if self.crls.is_empty() {
                let message = "CRL checking requested but no CRL evidence was supplied".to_string();
                if self.config.revocation_mode == "hard_fail" {
                    result.valid = false;
                    result.errors.push(message);
                } else {
                    result.warnings.push(message);
                }
            } else {
                for (i, cert) in chain.iter().enumerate() {
                    if self.is_configured_trust_anchor(cert) {
                        continue;
                    }
                    match self.check_revocation(cert, chain) {
                        Ok(false) => {} // Not revoked
                        Ok(true) => {
                            let msg = format!("Certificate {} is revoked", i);
                            if self.config.revocation_mode == "hard_fail" {
                                result.valid = false;
                                result.errors.push(msg);
                            } else {
                                result.warnings.push(msg);
                            }
                        }
                        Err(e) => {
                            let msg =
                                format!("Revocation check failed for certificate {}: {}", i, e);
                            if self.config.revocation_mode == "hard_fail" {
                                result.valid = false;
                                result.errors.push(msg);
                            } else {
                                result.warnings.push(msg);
                            }
                        }
                    }
                }
            }
        }
        if self.config.check_ocsp {
            if self.ocsp_responses.is_empty() {
                let message =
                    "OCSP checking requested but no certificate-bound response evidence was supplied"
                        .to_string();
                if self.config.revocation_mode == "hard_fail" {
                    result.valid = false;
                    result.errors.push(message);
                } else {
                    result.warnings.push(message);
                }
            } else {
                for (index, cert) in chain.iter().enumerate() {
                    if self.is_configured_trust_anchor(cert) {
                        continue;
                    }
                    match self.check_ocsp_status(cert, chain) {
                        Ok(false) => {}
                        Ok(true) => {
                            let message = format!("Certificate {index} is revoked by OCSP");
                            if self.config.revocation_mode == "hard_fail" {
                                result.valid = false;
                                result.errors.push(message);
                            } else {
                                result.warnings.push(message);
                            }
                        }
                        Err(error) => {
                            let message =
                                format!("OCSP check failed for certificate {index}: {error}");
                            if self.config.revocation_mode == "hard_fail" {
                                result.valid = false;
                                result.errors.push(message);
                            } else {
                                result.warnings.push(message);
                            }
                        }
                    }
                }
            }
        }

        // Verify chain terminates at a trust anchor
        if let Err(e) = self.verify_trust_anchor(chain) {
            result.valid = false;
            result.errors.push(e);
        }

        Ok(result)
    }

    fn check_validity(&self, cert: &Certificate, now: DateTime<Utc>) -> Result<(), String> {
        let not_before = cert.tbs_certificate.validity.not_before.to_system_time();
        let not_after = cert.tbs_certificate.validity.not_after.to_system_time();

        let now_system = std::time::SystemTime::from(now);

        if now_system < not_before {
            return Err("Certificate not yet valid".to_string());
        }

        if now_system > not_after {
            return Err("Certificate has expired".to_string());
        }

        Ok(())
    }

    fn verify_chain_signatures(&self, chain: &[Certificate]) -> Result<(), String> {
        // Verify each certificate is signed by the next one in the chain
        for i in 0..chain.len().saturating_sub(1) {
            let subject_cert = &chain[i];
            let issuer_cert = &chain[i + 1];

            // Check issuer/subject match
            if subject_cert.tbs_certificate.issuer != issuer_cert.tbs_certificate.subject {
                return Err(format!(
                    "Chain broken: cert {} issuer '{}' != cert {} subject '{}'",
                    i,
                    subject_cert.tbs_certificate.issuer,
                    i + 1,
                    issuer_cert.tbs_certificate.subject
                ));
            }

            // Verify signature
            if let Err(e) = verify_certificate_signature(subject_cert, issuer_cert) {
                return Err(format!(
                    "Signature verification failed for cert {}: {}",
                    i, e
                ));
            }
        }

        Ok(())
    }

    fn check_chain_constraints(&self, chain: &[Certificate]) -> Result<(), String> {
        use x509_cert::ext::pkix::{BasicConstraints, KeyUsage as X509KeyUsage};

        const UNDERSTOOD_CRITICAL_EXTENSIONS: &[&str] = &[
            "2.5.29.9",           // subjectDirectoryAttributes
            "2.5.29.14",          // subjectKeyIdentifier
            "2.5.29.15",          // keyUsage
            "2.5.29.16",          // privateKeyUsagePeriod
            "2.5.29.17",          // subjectAltName
            "2.5.29.18",          // issuerAltName
            "2.5.29.19",          // basicConstraints
            "2.5.29.30",          // nameConstraints (rejected below until enforced)
            "2.5.29.31",          // cRLDistributionPoints
            "2.5.29.32",          // certificatePolicies
            "2.5.29.33",          // policyMappings (rejected below)
            "2.5.29.35",          // authorityKeyIdentifier
            "2.5.29.36",          // policyConstraints (rejected below)
            "2.5.29.37",          // extendedKeyUsage
            "2.5.29.46",          // freshestCRL
            "2.5.29.54",          // inhibitAnyPolicy (rejected below)
            "1.3.6.1.5.5.7.1.1",  // authorityInfoAccess
            "1.3.6.1.5.5.7.1.11", // subjectInfoAccess
        ];
        const UNIMPLEMENTED_CONSTRAINTS: &[&str] =
            &["2.5.29.30", "2.5.29.33", "2.5.29.36", "2.5.29.54"];

        for (index, cert) in chain.iter().enumerate() {
            if cert.tbs_certificate.signature.oid != cert.signature_algorithm.oid {
                return Err(format!(
                    "Certificate {index} inner and outer signature algorithms differ"
                ));
            }
            let mut seen = std::collections::HashSet::new();
            for extension in cert
                .tbs_certificate
                .extensions
                .as_deref()
                .unwrap_or_default()
            {
                let oid = extension.extn_id.to_string();
                if !seen.insert(oid.clone()) {
                    return Err(format!("Certificate {index} has duplicate extension {oid}"));
                }
                if extension.critical && !UNDERSTOOD_CRITICAL_EXTENSIONS.contains(&oid.as_str()) {
                    return Err(format!(
                        "Certificate {index} has unsupported critical extension {oid}"
                    ));
                }
                if UNIMPLEMENTED_CONSTRAINTS.contains(&oid.as_str()) {
                    return Err(format!(
                        "Certificate {index} contains constraint extension {oid} that cannot yet be safely enforced"
                    ));
                }
            }

            if index == 0 && chain.len() > 1 {
                if let Some((_, constraints)) = cert
                    .tbs_certificate
                    .get::<BasicConstraints>()
                    .map_err(|error| format!("Invalid end-entity BasicConstraints: {error}"))?
                {
                    if constraints.ca {
                        return Err("End-entity certificate is marked as a CA".to_string());
                    }
                }
            }
        }

        for issuer_index in 1..chain.len() {
            let issuer = &chain[issuer_index];
            let constraints = issuer
                .tbs_certificate
                .get::<BasicConstraints>()
                .map_err(|error| {
                    format!("Invalid BasicConstraints on CA certificate {issuer_index}: {error}")
                })?
                .ok_or_else(|| format!("CA certificate {issuer_index} lacks BasicConstraints"))?
                .1;
            if !constraints.ca {
                return Err(format!(
                    "Certificate {issuer_index} is not authorized as a CA"
                ));
            }
            if let Some((_, key_usage)) =
                issuer
                    .tbs_certificate
                    .get::<X509KeyUsage>()
                    .map_err(|error| {
                        format!("Invalid KeyUsage on CA certificate {issuer_index}: {error}")
                    })?
            {
                if !key_usage.key_cert_sign() {
                    return Err(format!(
                        "CA certificate {issuer_index} KeyUsage lacks keyCertSign"
                    ));
                }
            }
            if let Some(path_len) = constraints.path_len_constraint {
                let subordinate_ca_count = chain[1..issuer_index]
                    .iter()
                    .filter(|certificate| {
                        certificate.tbs_certificate.subject != certificate.tbs_certificate.issuer
                    })
                    .count();
                if subordinate_ca_count > path_len as usize {
                    return Err(format!(
                        "CA certificate {issuer_index} pathLenConstraint {path_len} was exceeded"
                    ));
                }
            }
        }

        Ok(())
    }

    fn verify_trust_anchor(&self, chain: &[Certificate]) -> Result<(), String> {
        if self.trust_anchors.is_empty() {
            return Err("No trust anchors configured".to_string());
        }

        // Guard against empty chain
        if chain.is_empty() {
            return Err("Certificate chain is empty".to_string());
        }

        // Get the last certificate in the chain (closest to root)
        // Safe to unwrap since we checked for empty chain above
        let last_cert = chain.last().expect("chain is not empty");
        let last_issuer = &last_cert.tbs_certificate.issuer;

        // Check if it's self-signed (root CA)
        let last_subject = &last_cert.tbs_certificate.subject;
        if last_issuer == last_subject {
            // Self-signed, check if it's in our trust anchors
            for anchor in &self.trust_anchors {
                if &anchor.tbs_certificate.subject == last_subject {
                    // Verify it's the same certificate
                    let last_der = last_cert
                        .to_der()
                        .map_err(|error| format!("Failed to encode chain root: {error}"))?;
                    let anchor_der = anchor
                        .to_der()
                        .map_err(|error| format!("Failed to encode trust anchor: {error}"))?;
                    if last_der == anchor_der {
                        return Ok(());
                    }
                }
            }
        }

        // Check if the chain's root is signed by a trust anchor
        for anchor in &self.trust_anchors {
            if &anchor.tbs_certificate.subject == last_issuer
                && verify_certificate_signature(last_cert, anchor).is_ok()
            {
                return Ok(());
            }
        }

        // Check if any intermediate + trust anchor combination works
        for intermediate in &self.intermediates {
            if &intermediate.tbs_certificate.subject == last_issuer
                && verify_certificate_signature(last_cert, intermediate).is_ok()
            {
                // Now check if intermediate chains to a trust anchor
                let int_issuer = &intermediate.tbs_certificate.issuer;
                for anchor in &self.trust_anchors {
                    if &anchor.tbs_certificate.subject == int_issuer
                        && verify_certificate_signature(intermediate, anchor).is_ok()
                    {
                        return Ok(());
                    }
                }
            }
        }

        Err(format!("No trust anchor found for issuer: {last_issuer}"))
    }

    fn check_key_usage(&self, cert: &Certificate) -> Result<(), String> {
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;
        use der::Decode;

        if self.config.required_key_usage.is_empty() {
            return Ok(());
        }

        let extensions = match &cert.tbs_certificate.extensions {
            Some(exts) => exts,
            None => {
                // Certificate has no extensions at all — RFC 5280 §4.2.1.3:
                // KeyUsage is optional. When absent, no usage constraint applies.
                return Ok(());
            }
        };

        let ku_ext = extensions.iter().find(|ext| ext.extn_id == ID_CE_KEY_USAGE);

        let ku_ext = match ku_ext {
            Some(ext) => ext,
            None => {
                // RFC 5280 §4.2.1.3: KeyUsage is optional. When absent,
                // the certificate is not constrained to any particular usage.
                return Ok(());
            }
        };

        // KeyUsage is a BIT STRING (RFC 5280 §4.2.1.3)
        let ku_bits = der::asn1::BitString::from_der(ku_ext.extn_value.as_bytes())
            .map_err(|e| format!("Failed to parse KeyUsage extension: {e}"))?;
        let raw = ku_bits.raw_bytes();

        for required in &self.config.required_key_usage {
            let (byte_idx, bit_mask) = match required {
                KeyUsage::DigitalSignature => (0, 0x80),
                KeyUsage::NonRepudiation => (0, 0x40),
                KeyUsage::KeyEncipherment => (0, 0x20),
                KeyUsage::DataEncipherment => (0, 0x10),
                KeyUsage::KeyAgreement => (0, 0x08),
                KeyUsage::KeyCertSign => (0, 0x04),
                KeyUsage::CrlSign => (0, 0x02),
                KeyUsage::EncipherOnly => (0, 0x01),
                KeyUsage::DecipherOnly => (1, 0x80),
            };
            let byte_val = raw.get(byte_idx).copied().unwrap_or(0);
            if byte_val & bit_mask == 0 {
                return Err(format!(
                    "Certificate missing required key usage: {:?}",
                    required
                ));
            }
        }

        Ok(())
    }

    fn check_revocation(&self, cert: &Certificate, chain: &[Certificate]) -> Result<bool, String> {
        let cert_der = cert
            .to_der()
            .map_err(|e| format!("Failed to encode certificate for revocation check: {e}"))?;
        let issuer_name = &cert.tbs_certificate.issuer;
        let issuers = self
            .trust_anchors
            .iter()
            .chain(self.intermediates.iter())
            .chain(chain.iter())
            .filter(|candidate| &candidate.tbs_certificate.subject == issuer_name)
            .collect::<Vec<_>>();
        if issuers.is_empty() {
            return Err("No issuer certificate is available for CRL authentication".to_string());
        }

        let mut valid_evidence = false;
        let mut failures = Vec::new();
        for crl_der in &self.crls {
            for issuer in &issuers {
                let issuer_der = issuer
                    .to_der()
                    .map_err(|e| format!("Failed to encode CRL issuer: {e}"))?;
                match marty_crypto::crl::validate_crl_for_certificate(
                    crl_der,
                    &cert_der,
                    &issuer_der,
                ) {
                    Ok(status) => {
                        valid_evidence = true;
                        if status.revoked {
                            return Ok(true);
                        }
                    }
                    Err(error) => failures.push(error.to_string()),
                }
            }
        }
        if valid_evidence {
            Ok(false)
        } else {
            Err(format!(
                "No authenticated, current CRL matched the certificate: {}",
                failures.join("; ")
            ))
        }
    }

    fn check_ocsp_status(&self, cert: &Certificate, chain: &[Certificate]) -> Result<bool, String> {
        let cert_der = cert
            .to_der()
            .map_err(|error| format!("Failed to encode certificate for OCSP: {error}"))?;
        let issuer_name = &cert.tbs_certificate.issuer;
        let issuers = self
            .trust_anchors
            .iter()
            .chain(self.intermediates.iter())
            .chain(chain.iter())
            .filter(|candidate| &candidate.tbs_certificate.subject == issuer_name)
            .collect::<Vec<_>>();
        if issuers.is_empty() {
            return Err("No issuer certificate is available for OCSP authentication".to_string());
        }

        let mut valid_good_evidence = false;
        let mut failures = Vec::new();
        for response_der in &self.ocsp_responses {
            for issuer in &issuers {
                let issuer_der = issuer
                    .to_der()
                    .map_err(|error| format!("Failed to encode OCSP issuer: {error}"))?;
                match marty_crypto::ocsp::validate_ocsp_response(
                    response_der,
                    &cert_der,
                    &issuer_der,
                ) {
                    Ok(response) => match response.cert_status {
                        marty_crypto::ocsp::OcspCertStatus::Good => valid_good_evidence = true,
                        marty_crypto::ocsp::OcspCertStatus::Revoked { .. } => return Ok(true),
                        marty_crypto::ocsp::OcspCertStatus::Unknown => failures.push(
                            "authenticated responder returned unknown certificate status"
                                .to_string(),
                        ),
                    },
                    Err(error) => failures.push(error.to_string()),
                }
            }
        }
        if valid_good_evidence {
            Ok(false)
        } else {
            Err(format!(
                "No authenticated, current OCSP response matched the certificate: {}",
                failures.join("; ")
            ))
        }
    }

    fn is_configured_trust_anchor(&self, cert: &Certificate) -> bool {
        let Ok(cert_der) = cert.to_der() else {
            return false;
        };
        self.trust_anchors.iter().any(|anchor| {
            anchor
                .to_der()
                .is_ok_and(|anchor_der| anchor_der == cert_der)
        })
    }
}

impl Default for ChainValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify that a certificate's signature was created by the issuer.
fn verify_certificate_signature(
    subject: &Certificate,
    issuer: &Certificate,
) -> VerificationResult<()> {
    let valid = marty_crypto::certificate::verify_parsed_certificate_signature(subject, issuer)?;

    if valid {
        Ok(())
    } else {
        Err(VerificationError::internal(
            "Certificate signature verification failed".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_validation_result_default() {
        let result = ChainValidationResult::default();
        assert!(!result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_chain_validation_result_success() {
        let result =
            ChainValidationResult::success("CN=Test".to_string(), "CN=Issuer".to_string(), 2);
        assert!(result.valid);
        assert_eq!(result.chain_depth, 2);
    }

    #[test]
    fn test_chain_validation_result_failure() {
        let result = ChainValidationResult::failure("Test error".to_string());
        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_chain_validator_empty_chain() {
        let validator = ChainValidator::new();
        let result = validator.validate_chain(&[]).unwrap();
        assert!(!result.valid);
        assert!(result.errors[0].contains("Empty"));
    }

    #[test]
    fn test_key_usage_variants() {
        let usages = [
            KeyUsage::DigitalSignature,
            KeyUsage::NonRepudiation,
            KeyUsage::KeyCertSign,
        ];
        assert_eq!(usages.len(), 3);
    }

    #[test]
    fn test_valid_chain_self_signed() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        // Generate a self-signed CA certificate
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        // Validate the self-signed cert
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&ca_pem).unwrap();

        let result = validator.validate_chain(&[ca_pem]).unwrap();
        assert!(
            result.valid,
            "Self-signed CA should validate: {:?}",
            result.errors
        );
        assert_eq!(result.chain_depth, 1);
    }

    #[test]
    fn test_valid_two_cert_chain() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        // Generate CA
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        // Generate end-entity certificate signed by CA
        let mut ee_params = CertificateParams::default();
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "Test End Entity");
        ee_params.is_ca = rcgen::IsCa::NoCa;

        let ee_key = KeyPair::generate().unwrap();
        let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let ee_cert = ee_params.signed_by(&ee_key, &ca_issuer).unwrap();
        let ee_pem = ee_cert.pem();

        // Validate the chain
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&ca_pem).unwrap();

        let result = validator.validate_chain(&[ee_pem, ca_pem]).unwrap();
        assert!(
            result.valid,
            "Two-cert chain should validate: {:?}",
            result.errors
        );
        assert_eq!(result.chain_depth, 2);
    }

    #[test]
    fn test_expired_certificate() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        // Generate CA
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        // Generate expired end-entity certificate
        let mut ee_params = CertificateParams::default();
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "Expired Certificate");
        ee_params.is_ca = rcgen::IsCa::NoCa;
        // Set validity to the past
        ee_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(365);
        ee_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);

        let ee_key = KeyPair::generate().unwrap();
        let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let ee_cert = ee_params.signed_by(&ee_key, &ca_issuer).unwrap();
        let ee_pem = ee_cert.pem();

        // Validate - should fail
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&ca_pem).unwrap();

        let result = validator.validate_chain(&[ee_pem, ca_pem]).unwrap();
        assert!(!result.valid, "Expired certificate should fail validation");
        assert!(result.errors.iter().any(|e| e.contains("expired")));
    }

    #[test]
    fn test_not_yet_valid_certificate() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        // Generate CA
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        // Generate not-yet-valid end-entity certificate
        let mut ee_params = CertificateParams::default();
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "Future Certificate");
        ee_params.is_ca = rcgen::IsCa::NoCa;
        // Set validity to the future
        ee_params.not_before = time::OffsetDateTime::now_utc() + time::Duration::days(30);
        ee_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);

        let ee_key = KeyPair::generate().unwrap();
        let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let ee_cert = ee_params.signed_by(&ee_key, &ca_issuer).unwrap();
        let ee_pem = ee_cert.pem();

        // Validate - should fail
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&ca_pem).unwrap();

        let result = validator.validate_chain(&[ee_pem, ca_pem]).unwrap();
        assert!(
            !result.valid,
            "Not-yet-valid certificate should fail validation"
        );
        assert!(result.errors.iter().any(|e| e.contains("not yet valid")));
    }

    #[test]
    fn test_chain_validator_config_defaults() {
        let config = ChainValidatorConfig::default();
        assert!(!config.check_crl);
        assert!(!config.check_ocsp);
        assert_eq!(config.revocation_mode, "soft_fail");
        assert!(config.validation_moment.is_none());
        assert_eq!(config.required_key_usage, vec![KeyUsage::DigitalSignature]);
    }

    #[test]
    fn test_chain_validator_with_config() {
        let config = ChainValidatorConfig {
            check_crl: true,
            check_ocsp: true,
            revocation_mode: "hard_fail".to_string(),
            validation_moment: None,
            required_key_usage: vec![KeyUsage::KeyCertSign, KeyUsage::CrlSign],
        };

        let validator = ChainValidator::with_config(config);
        // Just verify it creates without panic
        let result = validator.validate_chain(&[]).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_validation_at_specific_moment() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        // Generate CA with long validity
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(365);
        ca_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * 10);

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        // Generate certificate that was valid in the past but not now
        let mut ee_params = CertificateParams::default();
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "Past Valid Certificate");
        ee_params.is_ca = rcgen::IsCa::NoCa;
        ee_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(365);
        ee_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(30);

        let ee_key = KeyPair::generate().unwrap();
        let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let ee_cert = ee_params.signed_by(&ee_key, &ca_issuer).unwrap();
        let ee_pem = ee_cert.pem();

        // Validate at current time - should fail (expired)
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&ca_pem).unwrap();

        let result = validator
            .validate_chain(&[ee_pem.clone(), ca_pem.clone()])
            .unwrap();
        assert!(!result.valid, "Should be expired at current time");

        // Validate at past time when cert was valid
        let past_moment = Utc::now() - chrono::Duration::days(180);
        let config = ChainValidatorConfig {
            validation_moment: Some(past_moment),
            ..Default::default()
        };

        let mut validator_past = ChainValidator::with_config(config);
        validator_past.add_trust_anchor_pem(&ca_pem).unwrap();

        let result_past = validator_past.validate_chain(&[ee_pem, ca_pem]).unwrap();
        assert!(
            result_past.valid,
            "Should be valid at past validation moment: {:?}",
            result_past.errors
        );
    }

    #[test]
    fn test_untrusted_chain() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        // Generate CA
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Unknown CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        // Generate end-entity
        let mut ee_params = CertificateParams::default();
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "Test End Entity");
        ee_params.is_ca = rcgen::IsCa::NoCa;

        let ee_key = KeyPair::generate().unwrap();
        let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let ee_cert = ee_params.signed_by(&ee_key, &ca_issuer).unwrap();
        let ee_pem = ee_cert.pem();

        // Generate a different trusted CA
        let mut trusted_ca_params = CertificateParams::default();
        trusted_ca_params
            .distinguished_name
            .push(DnType::CommonName, "Trusted CA");
        trusted_ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let trusted_ca_key = KeyPair::generate().unwrap();
        let trusted_ca_cert = trusted_ca_params.self_signed(&trusted_ca_key).unwrap();
        let trusted_ca_pem = trusted_ca_cert.pem();

        // Validate chain with different trust anchor - should fail
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&trusted_ca_pem).unwrap();

        let result = validator.validate_chain(&[ee_pem, ca_pem]).unwrap();
        assert!(!result.valid, "Chain signed by untrusted CA should fail");
        assert!(result.errors.iter().any(|e| e.contains("trust anchor")));
    }

    #[test]
    fn test_three_level_chain() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        // Generate Root CA
        let mut root_params = CertificateParams::default();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Root CA");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_pem = root_cert.pem();

        // Generate Intermediate CA
        let mut int_params = CertificateParams::default();
        int_params
            .distinguished_name
            .push(DnType::CommonName, "Intermediate CA");
        int_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));

        let int_key = KeyPair::generate().unwrap();
        let root_issuer = rcgen::Issuer::from_params(&root_params, &root_key);
        let int_cert = int_params.signed_by(&int_key, &root_issuer).unwrap();
        let int_pem = int_cert.pem();

        // Generate End Entity
        let mut ee_params = CertificateParams::default();
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "End Entity");
        ee_params.is_ca = rcgen::IsCa::NoCa;

        let ee_key = KeyPair::generate().unwrap();
        let int_issuer = rcgen::Issuer::from_params(&int_params, &int_key);
        let ee_cert = ee_params.signed_by(&ee_key, &int_issuer).unwrap();
        let ee_pem = ee_cert.pem();

        // Validate three-level chain
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&root_pem).unwrap();

        let result = validator
            .validate_chain(&[ee_pem, int_pem, root_pem])
            .unwrap();
        assert!(
            result.valid,
            "Three-level chain should validate: {:?}",
            result.errors
        );
        assert_eq!(result.chain_depth, 3);
    }

    #[test]
    fn rejects_non_ca_certificate_as_issuer() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        let mut issuer_params = CertificateParams::default();
        issuer_params
            .distinguished_name
            .push(DnType::CommonName, "Non-CA issuer");
        issuer_params.is_ca = rcgen::IsCa::NoCa;
        let issuer_key = KeyPair::generate().unwrap();
        let issuer_cert = issuer_params.self_signed(&issuer_key).unwrap();

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Leaf signed by non-CA");
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        let leaf_key = KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&issuer_params, &issuer_key);
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        let issuer_pem = issuer_cert.pem();
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&issuer_pem).unwrap();
        let result = validator
            .validate_chain(&[leaf_cert.pem(), issuer_pem])
            .unwrap();

        assert!(!result.valid);
        assert!(result.errors.iter().any(|error| {
            error.contains("lacks BasicConstraints") || error.contains("is not authorized as a CA")
        }));
    }

    #[test]
    fn rejects_ca_issuer_without_key_cert_sign_usage() {
        use rcgen::{CertificateParams, DnType, KeyPair, KeyUsagePurpose};

        let mut issuer_params = CertificateParams::default();
        issuer_params
            .distinguished_name
            .push(DnType::CommonName, "CA without certificate-signing usage");
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        issuer_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let issuer_key = KeyPair::generate().unwrap();
        let issuer_cert = issuer_params.self_signed(&issuer_key).unwrap();

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Leaf");
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        let leaf_key = KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&issuer_params, &issuer_key);
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        let issuer_pem = issuer_cert.pem();
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&issuer_pem).unwrap();
        let result = validator
            .validate_chain(&[leaf_cert.pem(), issuer_pem])
            .unwrap();

        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("KeyUsage lacks keyCertSign")));
    }

    #[test]
    fn rejects_ca_certificate_in_end_entity_position() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        let mut root_params = CertificateParams::default();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Root CA");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let mut subordinate_params = CertificateParams::default();
        subordinate_params
            .distinguished_name
            .push(DnType::CommonName, "Subordinate CA used as leaf");
        subordinate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let subordinate_key = KeyPair::generate().unwrap();
        let root_issuer = rcgen::Issuer::from_params(&root_params, &root_key);
        let subordinate_cert = subordinate_params
            .signed_by(&subordinate_key, &root_issuer)
            .unwrap();

        let root_pem = root_cert.pem();
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&root_pem).unwrap();
        let result = validator
            .validate_chain(&[subordinate_cert.pem(), root_pem])
            .unwrap();

        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("End-entity certificate is marked as a CA")));
    }

    #[test]
    fn rejects_path_length_constraint_violation() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        let mut root_params = CertificateParams::default();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Path length zero root");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let mut intermediate_params = CertificateParams::default();
        intermediate_params
            .distinguished_name
            .push(DnType::CommonName, "Prohibited intermediate");
        intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let intermediate_key = KeyPair::generate().unwrap();
        let root_issuer = rcgen::Issuer::from_params(&root_params, &root_key);
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_key, &root_issuer)
            .unwrap();

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Leaf below prohibited intermediate");
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        let leaf_key = KeyPair::generate().unwrap();
        let intermediate_issuer =
            rcgen::Issuer::from_params(&intermediate_params, &intermediate_key);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &intermediate_issuer)
            .unwrap();

        let root_pem = root_cert.pem();
        let mut validator = ChainValidator::new();
        validator.add_trust_anchor_pem(&root_pem).unwrap();
        let result = validator
            .validate_chain(&[leaf_cert.pem(), intermediate_cert.pem(), root_pem])
            .unwrap();

        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("pathLenConstraint 0 was exceeded")));
    }

    #[test]
    fn test_revocation_soft_fail_mode() {
        use rcgen::{CertificateParams, DnType, KeyPair};

        // Generate CA
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        // Generate end-entity
        let mut ee_params = CertificateParams::default();
        ee_params
            .distinguished_name
            .push(DnType::CommonName, "Test EE");
        ee_params.is_ca = rcgen::IsCa::NoCa;

        let ee_key = KeyPair::generate().unwrap();
        let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let ee_cert = ee_params.signed_by(&ee_key, &ca_issuer).unwrap();
        let ee_pem = ee_cert.pem();

        // Validate with CRL checking enabled but no CRLs (soft_fail should pass)
        let config = ChainValidatorConfig {
            check_crl: true,
            revocation_mode: "soft_fail".to_string(),
            ..Default::default()
        };

        let mut validator = ChainValidator::with_config(config);
        validator.add_trust_anchor_pem(&ca_pem).unwrap();

        let result = validator.validate_chain(&[ee_pem, ca_pem]).unwrap();
        // In soft_fail mode, missing CRL info should not cause failure
        assert!(
            result.valid,
            "Soft fail mode should pass without CRLs: {:?}",
            result.errors
        );
    }

    #[test]
    fn hard_fail_revocation_uses_authenticated_fresh_crl_evidence() {
        use marty_crypto::cert_builder::{create_ca_certificate, create_signed_certificate};
        use marty_crypto::crl::{CrlBuilder, RevocationReason};
        use marty_crypto::keygen::KeyType;

        let (ca_der, ca_key) =
            create_ca_certificate("Chain CRL CA", None, 365, KeyType::EcdsaP256).unwrap();
        let (leaf_der, _) = create_signed_certificate(
            "Revoked Chain Leaf",
            &ca_der,
            &ca_key,
            365,
            false,
            KeyType::EcdsaP256,
        )
        .unwrap();
        let leaf = Certificate::from_der(&leaf_der).unwrap();
        let serial = hex::encode(leaf.tbs_certificate.serial_number.as_bytes());
        let crl_der = CrlBuilder::new()
            .issuer_cn("Chain CRL CA")
            .add_revoked(&serial, Some(RevocationReason::KeyCompromise))
            .build(&ca_key)
            .unwrap();
        let leaf_pem =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &leaf_der)
                .unwrap();
        let ca_pem =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &ca_der)
                .unwrap();
        let config = ChainValidatorConfig {
            check_crl: true,
            revocation_mode: "hard_fail".to_string(),
            ..Default::default()
        };
        let mut validator = ChainValidator::with_config(config);
        validator.add_trust_anchor_der(&ca_der).unwrap();
        validator.add_crl_der(&crl_der).unwrap();

        let result = validator.validate_chain(&[leaf_pem, ca_pem]).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|error| error.contains("revoked")));
    }

    #[test]
    fn authenticated_ocsp_evidence_controls_hard_fail_validation() {
        use marty_crypto::cert_builder::{create_ca_certificate, create_signed_certificate};
        use marty_crypto::keygen::KeyType;
        use marty_crypto::ocsp::OcspResponseBuilder;

        let (ca_der, ca_key) =
            create_ca_certificate("OCSP Chain CA", None, 365, KeyType::EcdsaP256).unwrap();
        let (leaf_der, _) = create_signed_certificate(
            "OCSP Chain Leaf",
            &ca_der,
            &ca_key,
            365,
            false,
            KeyType::EcdsaP256,
        )
        .unwrap();
        let config = ChainValidatorConfig {
            check_ocsp: true,
            revocation_mode: "hard_fail".to_string(),
            ..Default::default()
        };

        let good_response = OcspResponseBuilder::new()
            .certificate(&leaf_der, &ca_der)
            .status_good()
            .build(&ca_key)
            .unwrap();
        let mut good_validator = ChainValidator::with_config(config.clone());
        good_validator.add_trust_anchor_der(&ca_der).unwrap();
        good_validator
            .add_ocsp_response_der(&good_response)
            .unwrap();
        let good = good_validator
            .validate_chain_der(&[leaf_der.clone(), ca_der.clone()])
            .unwrap();
        assert!(
            good.valid,
            "authenticated good OCSP should pass: {:?}",
            good.errors
        );

        let revoked_response = OcspResponseBuilder::new()
            .certificate(&leaf_der, &ca_der)
            .status_revoked(Some("keyCompromise"))
            .build(&ca_key)
            .unwrap();
        let mut revoked_validator = ChainValidator::with_config(config);
        revoked_validator.add_trust_anchor_der(&ca_der).unwrap();
        revoked_validator
            .add_ocsp_response_der(&revoked_response)
            .unwrap();
        let revoked = revoked_validator
            .validate_chain_der(&[leaf_der, ca_der])
            .unwrap();
        assert!(!revoked.valid);
        assert!(revoked
            .errors
            .iter()
            .any(|error| error.contains("revoked by OCSP")));
    }
}
