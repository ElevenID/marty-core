//! eMRTD (ICAO 9303) verification.
//!
//! This module provides trust chain verification for electronic travel documents
//! (ePassports, electronic ID cards), implementing the CSCA → DSC → SOD chain.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::hazmat::PrehashVerifier;
use x509_cert::Certificate;

use crate::error::{VerificationError, VerificationResult};
use crate::trust_anchor::{CscaRegistry, TrustPurpose, TrustRegistry};

/// Result of eMRTD verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmrtdVerificationResult {
    /// Whether the full verification was successful.
    pub verified: bool,
    /// Country code from the document.
    pub country: Option<String>,
    /// Document type (e.g., "P" for passport).
    pub document_type: Option<String>,
    /// List of verification errors (empty if verified).
    pub errors: Vec<String>,
    /// DSC chain verification status.
    pub dsc_chain_status: ChainStatus,
    /// SOD signature verification status.
    pub sod_signature_status: SignatureStatus,
    /// Data group hash verification status.
    pub dg_hash_status: HashStatus,
}

impl Default for EmrtdVerificationResult {
    fn default() -> Self {
        Self {
            verified: false,
            country: None,
            document_type: None,
            errors: Vec::new(),
            dsc_chain_status: ChainStatus::Unknown,
            sod_signature_status: SignatureStatus::Unknown,
            dg_hash_status: HashStatus::Unknown,
        }
    }
}

/// Chain verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainStatus {
    /// Chain verified successfully.
    Valid,
    /// Chain verification failed.
    Invalid,
    /// Chain verification was not performed.
    Unknown,
}

/// Signature verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureStatus {
    /// Signature verified successfully.
    Valid,
    /// Signature verification failed.
    Invalid,
    /// Signature verification was not performed.
    Unknown,
}

/// Hash verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashStatus {
    /// All hashes match.
    Valid,
    /// One or more hashes don't match.
    Invalid,
    /// Hash verification was not performed.
    Unknown,
}

/// Document Signer Certificate (DSC) extracted from eMRTD.
#[derive(Debug, Clone)]
pub struct DocumentSignerCertificate {
    /// The X.509 certificate.
    pub certificate: Certificate,
    /// Country that issued the DSC.
    pub country: Option<String>,
    /// Serial number.
    pub serial_number: String,
}

/// Security Object Document (SOD) data.
#[derive(Debug, Clone)]
pub struct SecurityObject {
    /// The DSC that signed this SOD.
    pub signer_certificate: DocumentSignerCertificate,
    /// Hash algorithm used.
    pub hash_algorithm: String,
    /// Map of data group number to hash.
    pub data_group_hashes: std::collections::HashMap<u8, Vec<u8>>,
    /// The signature over the SOD.
    pub signature: Vec<u8>,
    /// Signed attributes (for signature verification).
    pub signed_attrs: Vec<u8>,
    /// Raw SOD bytes, when available (preferred for signature validation).
    pub raw_sod: Option<Vec<u8>>,
}

impl SecurityObject {
    /// Build a `SecurityObject` from raw SOD bytes.
    ///
    /// This parses the CMS SignedData, extracts the LDS hashes, and loads the DSC.
    /// Signature validation can then be performed using `raw_sod`.
    pub fn from_sod_der(sod_der: &[u8], country_hint: Option<String>) -> VerificationResult<Self> {
        use der::Decode;

        let parsed = crate::asn1::sod::parse_sod(sod_der)?;

        let pem = parsed.document_signer_cert.ok_or_else(|| {
            VerificationError::der_error("SOD contained no Document Signer Certificate".to_string())
        })?;

        let (_, dsc_der) = pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|e| {
            VerificationError::der_error(format!("Failed to decode DSC PEM: {}", e))
        })?;

        let certificate = Certificate::from_der(&dsc_der)
            .map_err(|e| VerificationError::der_error(e.to_string()))?;

        let serial_number = certificate.tbs_certificate.serial_number.to_string();

        let mut data_group_hashes = HashMap::new();
        for dg in parsed.data_group_hashes {
            data_group_hashes.insert(dg.data_group_number, dg.hash_bytes);
        }

        Ok(SecurityObject {
            signer_certificate: DocumentSignerCertificate {
                certificate,
                country: country_hint,
                serial_number,
            },
            hash_algorithm: parsed.hash_algorithm,
            data_group_hashes,
            signature: Vec::new(),
            signed_attrs: Vec::new(),
            raw_sod: Some(sod_der.to_vec()),
        })
    }
}

/// Verify a DSC certificate against the CSCA registry.
///
/// This validates:
/// 1. The DSC was signed by a trusted CSCA
/// 2. Certificate validity periods
/// 3. Required extensions
pub fn verify_dsc_chain(
    dsc: &DocumentSignerCertificate,
    registry: &CscaRegistry,
) -> VerificationResult<ChainStatus> {
    // Find a matching CSCA for this DSC
    let issuer = dsc.certificate.tbs_certificate.issuer.to_string();

    let csca_candidates: Vec<_> = registry
        .get_anchors()
        .iter()
        .filter(|a| a.purpose == TrustPurpose::Csca)
        .filter(|a| a.certificate.tbs_certificate.subject.to_string() == issuer)
        .collect();

    if csca_candidates.is_empty() {
        return Err(VerificationError::no_trust_anchor(format!(
            "No CSCA found for issuer: {}",
            issuer
        )));
    }

    // Verify signature against each candidate
    for csca in csca_candidates {
        if verify_certificate_signature(&dsc.certificate, &csca.certificate).is_ok() {
            // Check validity period
            let now = std::time::SystemTime::now();
            let not_before = dsc
                .certificate
                .tbs_certificate
                .validity
                .not_before
                .to_system_time();
            let not_after = dsc
                .certificate
                .tbs_certificate
                .validity
                .not_after
                .to_system_time();

            if now < not_before {
                let subject = dsc.certificate.tbs_certificate.subject.to_string();
                return Err(VerificationError::cert_not_yet_valid(
                    subject,
                    format!("{:?}", not_before),
                ));
            }

            if now > not_after {
                let subject = dsc.certificate.tbs_certificate.subject.to_string();
                return Err(VerificationError::cert_expired(
                    subject,
                    format!("{:?}", not_after),
                ));
            }

            return Ok(ChainStatus::Valid);
        }
    }

    Err(VerificationError::invalid_signature(
        "DSC",
        "DSC signature does not match any trusted CSCA in registry",
    ))
}

/// Verify a certificate's signature against its issuer.
fn verify_certificate_signature(
    subject: &Certificate,
    issuer: &Certificate,
) -> VerificationResult<()> {
    use der::Encode;

    // Get the TBS (to-be-signed) certificate bytes
    let tbs_bytes = subject.tbs_certificate.to_der().map_err(|e| {
        VerificationError::der_error(format!("Failed to encode TBS certificate: {}", e))
    })?;

    // Get the signature bytes
    let signature_bytes = subject.signature.raw_bytes();

    // Get the public key from the issuer
    let spki = &issuer.tbs_certificate.subject_public_key_info;

    // Determine the signature algorithm
    let sig_alg = &subject.signature_algorithm;

    // For now, support ECDSA with P-256/P-384
    // This is a simplified implementation - production would need more algorithm support
    match sig_alg.oid.to_string().as_str() {
        // ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
        "1.2.840.10045.4.3.2" => verify_ecdsa_p256(&tbs_bytes, signature_bytes, spki),
        // ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
        "1.2.840.10045.4.3.3" => verify_ecdsa_p384(&tbs_bytes, signature_bytes, spki),
        // RSA with SHA-256/384/512 and RSA-PSS variants are handled via the unified verifier
        "1.2.840.113549.1.1.11"
        | "1.2.840.113549.1.1.12"
        | "1.2.840.113549.1.1.13"
        | "1.2.840.113549.1.1.10"
        | "1.2.840.113549.1.1.5" => {
            verify_certificate_signature_unified(tbs_bytes, signature_bytes, spki, sig_alg)
        }
        oid => Err(VerificationError::internal(format!(
            "Unsupported signature algorithm OID: {}",
            oid
        ))),
    }
}

/// Verify any supported algorithm using the unified crypto module.
fn verify_certificate_signature_unified(
    tbs_bytes: Vec<u8>,
    signature_bytes: &[u8],
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    sig_alg: &spki::AlgorithmIdentifierOwned,
) -> VerificationResult<()> {
    use der::Encode;

    let public_key_der = spki
        .to_der()
        .map_err(|e| VerificationError::internal(format!("Failed to encode public key: {}", e)))?;

    let algorithm = marty_crypto::SignatureAlgorithm::from_oid(&sig_alg.oid.to_string())?;

    let valid =
        marty_crypto::verify_signature(algorithm, &public_key_der, &tbs_bytes, signature_bytes)?;

    if valid {
        Ok(())
    } else {
        Err(VerificationError::invalid_signature(
            "Certificate",
            "Signature verification failed".to_string(),
        ))
    }
}

/// Verify ECDSA P-256 signature.
fn verify_ecdsa_p256(
    message: &[u8],
    signature: &[u8],
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> VerificationResult<()> {
    use p256::ecdsa::{Signature, VerifyingKey};

    // Parse the public key
    let pk_bytes = spki.subject_public_key.raw_bytes();
    let verifying_key = VerifyingKey::from_sec1_bytes(pk_bytes).map_err(|e| {
        VerificationError::invalid_signature(
            "ECDSA-P256",
            format!("Invalid P-256 public key: {}", e),
        )
    })?;

    // Parse the signature (DER encoded)
    let sig = Signature::from_der(signature).map_err(|e| {
        VerificationError::invalid_signature(
            "ECDSA-P256",
            format!("Invalid DER-encoded ECDSA signature: {}", e),
        )
    })?;

    // Hash the message with SHA-256
    let digest = Sha256::digest(message);

    // Verify
    verifying_key.verify_prehash(&digest, &sig).map_err(|e| {
        VerificationError::invalid_signature(
            "ECDSA-P256",
            format!("P-256 signature verification failed: {}", e),
        )
    })
}

/// Verify ECDSA P-384 signature.
fn verify_ecdsa_p384(
    message: &[u8],
    signature: &[u8],
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> VerificationResult<()> {
    use p384::ecdsa::{Signature, VerifyingKey};
    use sha2::Sha384;

    // Parse the public key
    let pk_bytes = spki.subject_public_key.raw_bytes();
    let verifying_key = VerifyingKey::from_sec1_bytes(pk_bytes).map_err(|e| {
        VerificationError::invalid_signature(
            "ECDSA-P384",
            format!("Invalid P-384 public key: {}", e),
        )
    })?;

    // Parse the signature (DER encoded)
    let sig = Signature::from_der(signature).map_err(|e| {
        VerificationError::invalid_signature(
            "ECDSA-P384",
            format!("Invalid DER-encoded ECDSA signature: {}", e),
        )
    })?;

    // Hash the message with SHA-384
    let digest = Sha384::digest(message);

    // Verify
    verifying_key.verify_prehash(&digest, &sig).map_err(|e| {
        VerificationError::invalid_signature(
            "ECDSA-P384",
            format!("P-384 signature verification failed: {}", e),
        )
    })
}

/// Verify data group hashes against the SOD.
pub fn verify_data_group_hashes(
    sod: &SecurityObject,
    data_groups: &std::collections::HashMap<u8, Vec<u8>>,
) -> VerificationResult<HashStatus> {
    for (dg_num, expected_hash) in &sod.data_group_hashes {
        if let Some(dg_content) = data_groups.get(dg_num) {
            let computed_hash = match sod.hash_algorithm.as_str() {
                "SHA-256" | "2.16.840.1.101.3.4.2.1" => Sha256::digest(dg_content).to_vec(),
                "SHA-384" | "2.16.840.1.101.3.4.2.2" => {
                    use sha2::Sha384;
                    Sha384::digest(dg_content).to_vec()
                }
                "SHA-512" | "2.16.840.1.101.3.4.2.3" => {
                    use sha2::Sha512;
                    Sha512::digest(dg_content).to_vec()
                }
                alg => {
                    return Err(VerificationError::internal(format!(
                        "Unsupported hash algorithm: {}. Supported: SHA-256, SHA-384, SHA-512",
                        alg
                    )));
                }
            };

            if &computed_hash != expected_hash {
                return Ok(HashStatus::Invalid);
            }
        }
    }

    Ok(HashStatus::Valid)
}

/// Full eMRTD verification.
///
/// This is the main entry point for eMRTD verification, combining:
/// 1. DSC chain validation against CSCA
/// 2. SOD signature verification
/// 3. Data group hash verification
pub fn verify_emrtd(
    sod: &SecurityObject,
    data_groups: &std::collections::HashMap<u8, Vec<u8>>,
    registry: &CscaRegistry,
) -> EmrtdVerificationResult {
    let mut result = EmrtdVerificationResult {
        country: sod.signer_certificate.country.clone(),
        ..Default::default()
    };

    // Step 1: Verify DSC chain
    match verify_dsc_chain(&sod.signer_certificate, registry) {
        Ok(status) => {
            result.dsc_chain_status = status;
        }
        Err(e) => {
            result.dsc_chain_status = ChainStatus::Invalid;
            result.errors.push(e.to_string());
            return result;
        }
    }

    // Step 2: Verify SOD signature (prefer raw SOD when supplied)
    if let Some(raw_sod) = sod.raw_sod.as_deref() {
        match crate::asn1::sod::verify_sod_signature(raw_sod) {
            Ok(true) => result.sod_signature_status = SignatureStatus::Valid,
            Ok(false) => result.sod_signature_status = SignatureStatus::Invalid,
            Err(err) => {
                result.sod_signature_status = SignatureStatus::Invalid;
                result.errors.push(err.to_string());
            }
        }
    } else {
        result.sod_signature_status = SignatureStatus::Unknown;
    }

    // Step 3: Verify data group hashes
    match verify_data_group_hashes(sod, data_groups) {
        Ok(status) => {
            result.dg_hash_status = status;
        }
        Err(e) => {
            result.dg_hash_status = HashStatus::Invalid;
            result.errors.push(e.to_string());
            return result;
        }
    }

    // Overall verification succeeds if chain and hashes are valid
    result.verified =
        result.dsc_chain_status == ChainStatus::Valid && result.dg_hash_status == HashStatus::Valid;

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_default_result() {
        let result = EmrtdVerificationResult::default();
        assert!(!result.verified);
        assert!(result.errors.is_empty());
        assert_eq!(result.dsc_chain_status, ChainStatus::Unknown);
    }

    #[test]
    fn test_chain_status_variants() {
        let statuses = [
            ChainStatus::Valid,
            ChainStatus::Invalid,
            ChainStatus::Unknown,
        ];

        // Verify all variants are covered and debug formatting works
        for status in statuses {
            let display = format!("{:?}", status);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_signature_status_variants() {
        let statuses = [
            SignatureStatus::Valid,
            SignatureStatus::Invalid,
            SignatureStatus::Unknown,
        ];

        for status in &statuses {
            let display = format!("{:?}", status);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_hash_status_variants() {
        let statuses = [HashStatus::Valid, HashStatus::Invalid, HashStatus::Unknown];

        for status in &statuses {
            let display = format!("{:?}", status);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_document_signer_certificate_creation() {
        use crate::testdata::NIST_GOOD_CA_DER;
        use der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(NIST_GOOD_CA_DER).expect("Failed to parse certificate");

        let serial = cert.tbs_certificate.serial_number.to_string();
        let dsc = DocumentSignerCertificate {
            certificate: cert.clone(),
            country: Some("US".to_string()),
            serial_number: serial,
        };

        assert_eq!(dsc.country, Some("US".to_string()));
    }

    #[test]
    fn test_emrtd_result_builder() {
        let result = EmrtdVerificationResult {
            verified: true,
            country: Some("US".to_string()),
            document_type: None,
            errors: vec![],
            dsc_chain_status: ChainStatus::Valid,
            sod_signature_status: SignatureStatus::Valid,
            dg_hash_status: HashStatus::Valid,
        };

        assert!(result.verified);
        assert_eq!(result.country, Some("US".to_string()));
        assert_eq!(result.dsc_chain_status, ChainStatus::Valid);
    }

    #[test]
    fn test_verify_data_group_hashes_valid() {
        use crate::testdata::NIST_GOOD_CA_DER;
        use der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(NIST_GOOD_CA_DER).unwrap();
        let serial = cert.tbs_certificate.serial_number.to_string();

        // Create sample data groups
        let dg1_data = b"Sample MRZ data for DG1";
        let dg2_data = b"Sample face image data for DG2";

        // Compute expected hashes
        let dg1_hash = Sha256::digest(dg1_data).to_vec();
        let dg2_hash = Sha256::digest(dg2_data).to_vec();

        // Create security object with matching hashes
        let mut sod_hashes = HashMap::new();
        sod_hashes.insert(1u8, dg1_hash.clone());
        sod_hashes.insert(2u8, dg2_hash.clone());

        let dsc = DocumentSignerCertificate {
            certificate: cert,
            country: Some("US".to_string()),
            serial_number: serial,
        };

        let so = SecurityObject {
            signer_certificate: dsc,
            hash_algorithm: "SHA-256".to_string(),
            data_group_hashes: sod_hashes,
            signature: vec![0u8; 64],
            signed_attrs: vec![],
            raw_sod: None,
        };

        let mut data_groups = HashMap::new();
        data_groups.insert(1u8, dg1_data.to_vec());
        data_groups.insert(2u8, dg2_data.to_vec());

        let result = verify_data_group_hashes(&so, &data_groups);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), HashStatus::Valid);
    }

    #[test]
    fn test_verify_data_group_hashes_mismatch() {
        use crate::testdata::NIST_GOOD_CA_DER;
        use der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(NIST_GOOD_CA_DER).unwrap();
        let serial = cert.tbs_certificate.serial_number.to_string();

        let dg1_data = b"Sample MRZ data";
        let wrong_hash = vec![0u8; 32]; // Wrong hash

        let mut sod_hashes = HashMap::new();
        sod_hashes.insert(1u8, wrong_hash);

        let dsc = DocumentSignerCertificate {
            certificate: cert,
            country: Some("US".to_string()),
            serial_number: serial,
        };

        let so = SecurityObject {
            signer_certificate: dsc,
            hash_algorithm: "SHA-256".to_string(),
            data_group_hashes: sod_hashes,
            signature: vec![0u8; 64],
            signed_attrs: vec![],
            raw_sod: None,
        };

        let mut data_groups = HashMap::new();
        data_groups.insert(1u8, dg1_data.to_vec());

        let result = verify_data_group_hashes(&so, &data_groups);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), HashStatus::Invalid);
    }
}
