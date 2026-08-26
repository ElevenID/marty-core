//! eMRTD (ICAO 9303) verification.
//!
//! This module provides trust chain verification for electronic travel documents
//! (ePassports, electronic ID cards), implementing the CSCA → DSC → SOD chain.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
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
    /// Stable, machine-readable error codes corresponding to `errors`.
    pub error_codes: Vec<String>,
    /// Non-fatal verification warnings.
    pub warnings: Vec<String>,
    /// Subject of the CSCA trust anchor that authenticated the DSC.
    pub trust_anchor_subject: Option<String>,
    /// Ordered certificate subjects from DSC to CSCA.
    pub certificate_chain: Vec<String>,
    /// DSC chain verification status.
    pub dsc_chain_status: ChainStatus,
    /// SOD signature verification status.
    pub sod_signature_status: SignatureStatus,
    /// Data group hash verification status.
    pub dg_hash_status: HashStatus,
    /// DSC revocation status (requires CRLs to be provided via options).
    pub revocation_status: RevocationStatus,
}

impl Default for EmrtdVerificationResult {
    fn default() -> Self {
        Self {
            verified: false,
            country: None,
            document_type: None,
            errors: Vec::new(),
            error_codes: Vec::new(),
            warnings: Vec::new(),
            trust_anchor_subject: None,
            certificate_chain: Vec::new(),
            dsc_chain_status: ChainStatus::Unknown,
            sod_signature_status: SignatureStatus::Unknown,
            dg_hash_status: HashStatus::Unknown,
            revocation_status: RevocationStatus::Unchecked,
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

/// DSC revocation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationStatus {
    /// Certificate confirmed not revoked by provided CRLs.
    NotRevoked,
    /// Certificate has been revoked.
    Revoked,
    /// CRL check was not performed (no CRLs provided).
    Unchecked,
}

/// Options for fine-grained eMRTD verification control.
///
/// Pass to [`verify_emrtd_with_options`] to enable optional checks.
#[derive(Debug, Default, Clone)]
pub struct EmrtdVerificationOptions {
    /// DER-encoded CRLs for DSC revocation checking.
    ///
    /// Each CRL is authenticated against the DSC's trusted CSCA and checked
    /// for freshness before its contents can influence the result.
    pub crls: Vec<Vec<u8>>,
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
    verify_dsc_chain_with_anchor(dsc, registry).map(|(status, _)| status)
}

fn verify_dsc_chain_with_anchor(
    dsc: &DocumentSignerCertificate,
    registry: &CscaRegistry,
) -> VerificationResult<(ChainStatus, String)> {
    // Find a matching CSCA for this DSC
    let issuer = &dsc.certificate.tbs_certificate.issuer;

    let csca_candidates: Vec<_> = registry
        .get_anchors()
        .iter()
        .filter(|a| a.purpose == TrustPurpose::Csca)
        .filter(|a| &a.certificate.tbs_certificate.subject == issuer)
        .collect();

    if csca_candidates.is_empty() {
        return Err(VerificationError::no_trust_anchor(format!(
            "No CSCA found for issuer: {}",
            issuer
        )));
    }

    let mut failures = Vec::new();
    for csca in csca_candidates {
        let failure_count_before_candidate = failures.len();
        if let Err(error) = validate_emrtd_certificate_profiles(&dsc.certificate, &csca.certificate)
        {
            failures.push(error.to_string());
            continue;
        }
        if let Err(error) = verify_certificate_signature(&dsc.certificate, &csca.certificate) {
            failures.push(error.to_string());
            continue;
        }
        let now = std::time::SystemTime::now();
        for certificate in [&dsc.certificate, &csca.certificate] {
            let validity = certificate.tbs_certificate.validity;
            if now < validity.not_before.to_system_time() {
                failures.push(format!(
                    "Certificate {} is not yet valid",
                    certificate.tbs_certificate.subject
                ));
            } else if now > validity.not_after.to_system_time() {
                failures.push(format!(
                    "Certificate {} has expired",
                    certificate.tbs_certificate.subject
                ));
            }
        }
        if failures.len() == failure_count_before_candidate {
            return Ok((
                ChainStatus::Valid,
                csca.certificate.tbs_certificate.subject.to_string(),
            ));
        }
    }

    Err(VerificationError::invalid_signature(
        "DSC",
        format!(
            "DSC did not validate against any trusted CSCA: {}",
            failures.join("; ")
        ),
    ))
}

fn validate_emrtd_certificate_profiles(
    dsc: &Certificate,
    csca: &Certificate,
) -> VerificationResult<()> {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

    if let Some((_, constraints)) = dsc
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|error| VerificationError::der_error(error.to_string()))?
    {
        if constraints.ca {
            return Err(VerificationError::internal(
                "Document Signer Certificate must not be a CA".to_string(),
            ));
        }
    }
    let dsc_key_usage = dsc
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|error| VerificationError::der_error(error.to_string()))?
        .ok_or_else(|| {
            VerificationError::internal(
                "Document Signer Certificate lacks required KeyUsage".to_string(),
            )
        })?
        .1;
    if !dsc_key_usage.digital_signature() {
        return Err(VerificationError::internal(
            "Document Signer Certificate KeyUsage lacks digitalSignature".to_string(),
        ));
    }
    let csca_constraints = csca
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|error| VerificationError::der_error(error.to_string()))?
        .ok_or_else(|| {
            VerificationError::internal("CSCA lacks required BasicConstraints".to_string())
        })?
        .1;
    if !csca_constraints.ca {
        return Err(VerificationError::internal(
            "CSCA certificate is not authorized as a CA".to_string(),
        ));
    }
    if let Some((_, key_usage)) = csca
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|error| VerificationError::der_error(error.to_string()))?
    {
        if !key_usage.key_cert_sign() {
            return Err(VerificationError::internal(
                "CSCA KeyUsage lacks keyCertSign".to_string(),
            ));
        }
    }
    Ok(())
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

    match sig_alg.oid.to_string().as_str() {
        // ECDSA with SHA-256/384/512 uses the canonical crypto verifier.
        "1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3" | "1.2.840.10045.4.3.4" => {
            verify_certificate_signature_unified(tbs_bytes, signature_bytes, spki, sig_alg)
        }
        // RSA with SHA-256/384/512 and RSA-PSS variants are handled via the unified verifier
        "1.2.840.113549.1.1.11"
        | "1.2.840.113549.1.1.12"
        | "1.2.840.113549.1.1.13"
        | "1.2.840.113549.1.1.10"
        | "1.2.840.113549.1.1.5" => {
            verify_certificate_signature_unified(tbs_bytes, signature_bytes, spki, sig_alg)
        }
        // EdDSA: Ed25519 (1.3.101.112) and Ed448 (1.3.101.113)
        // Used by a growing number of countries for DSC signing.
        "1.3.101.112" | "1.3.101.113" => {
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

/// Verify data group hashes against the SOD.
pub fn verify_data_group_hashes(
    sod: &SecurityObject,
    data_groups: &std::collections::HashMap<u8, Vec<u8>>,
) -> VerificationResult<HashStatus> {
    verify_data_group_hash_map(&sod.hash_algorithm, &sod.data_group_hashes, data_groups)
}

#[allow(deprecated)] // Legacy eMRTDs can legitimately declare SHA-1.
fn verify_data_group_hash_map(
    hash_algorithm: &str,
    expected_hashes: &HashMap<u8, Vec<u8>>,
    data_groups: &HashMap<u8, Vec<u8>>,
) -> VerificationResult<HashStatus> {
    if expected_hashes.is_empty() || expected_hashes.len() != data_groups.len() {
        return Ok(HashStatus::Invalid);
    }
    let algorithm = match hash_algorithm {
        "SHA-1" => marty_crypto::HashAlgorithm::Sha1,
        "SHA-256" => marty_crypto::HashAlgorithm::Sha256,
        "SHA-384" => marty_crypto::HashAlgorithm::Sha384,
        "SHA-512" => marty_crypto::HashAlgorithm::Sha512,
        oid => marty_crypto::HashAlgorithm::from_oid(oid).map_err(|_| {
            VerificationError::internal(format!(
                "Unsupported data-group hash algorithm: {hash_algorithm}"
            ))
        })?,
    };

    for (dg_num, expected_hash) in expected_hashes {
        let Some(dg_content) = data_groups.get(dg_num) else {
            return Ok(HashStatus::Invalid);
        };
        if expected_hash.len() != algorithm.digest_size()
            || marty_crypto::hashing::hash(algorithm, dg_content) != *expected_hash
        {
            return Ok(HashStatus::Invalid);
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
    match verify_dsc_chain_with_anchor(&sod.signer_certificate, registry) {
        Ok((status, trust_anchor_subject)) => {
            result.dsc_chain_status = status;
            result.certificate_chain = vec![
                sod.signer_certificate
                    .certificate
                    .tbs_certificate
                    .subject
                    .to_string(),
                trust_anchor_subject.clone(),
            ];
            result.trust_anchor_subject = Some(trust_anchor_subject);
        }
        Err(e) => {
            result.dsc_chain_status = ChainStatus::Invalid;
            result.errors.push(e.to_string());
            result.error_codes.push("EMRTD_CHAIN_INVALID".to_string());
            return result;
        }
    }

    // Step 2: Verify SOD signature (prefer raw SOD when supplied)
    if let Some(raw_sod) = sod.raw_sod.as_deref() {
        match crate::asn1::sod::verify_sod_signature(raw_sod) {
            Ok(true) => result.sod_signature_status = SignatureStatus::Valid,
            Ok(false) => {
                result.sod_signature_status = SignatureStatus::Invalid;
                result
                    .errors
                    .push("SOD signature verification failed".to_string());
                result
                    .error_codes
                    .push("EMRTD_SOD_SIGNATURE_INVALID".to_string());
            }
            Err(err) => {
                result.sod_signature_status = SignatureStatus::Invalid;
                result.errors.push(err.to_string());
                result
                    .error_codes
                    .push("EMRTD_SOD_SIGNATURE_INVALID".to_string());
            }
        }
    } else {
        result.sod_signature_status = SignatureStatus::Unknown;
        result
            .errors
            .push("SOD signature verification was not performed: raw SOD unavailable".to_string());
        result.error_codes.push("EMRTD_SOD_UNAVAILABLE".to_string());
    }

    // Step 3: Verify data group hashes
    match verify_data_group_hashes(sod, data_groups) {
        Ok(status) => {
            result.dg_hash_status = status;
            if status == HashStatus::Invalid {
                result
                    .errors
                    .push("One or more data-group hashes did not match the SOD".to_string());
                result.error_codes.push("EMRTD_DG_HASH_INVALID".to_string());
            }
        }
        Err(e) => {
            result.dg_hash_status = HashStatus::Invalid;
            result.errors.push(e.to_string());
            result.error_codes.push("EMRTD_DG_HASH_INVALID".to_string());
            return result;
        }
    }

    // Overall verification requires every mandatory authenticity and integrity
    // check. A valid DSC chain and matching DG hashes do not authenticate the
    // LDS Security Object when its signature is invalid or unavailable.
    result.verified = result.dsc_chain_status == ChainStatus::Valid
        && result.sod_signature_status == SignatureStatus::Valid
        && result.dg_hash_status == HashStatus::Valid;
    result
        .warnings
        .push("DSC revocation was not checked because no CRL evidence was supplied".to_string());

    result
}

/// Full eMRTD verification with optional revocation checking.
///
/// Extends [`verify_emrtd`] with:
/// - DSC revocation checking against provided CRLs
///
/// # Example
/// ```rust,ignore
/// let options = EmrtdVerificationOptions {
///     crls: vec![crl_der],
/// };
/// let result = verify_emrtd_with_options(&sod, &dgs, &registry, &options);
/// assert_eq!(result.revocation_status, RevocationStatus::NotRevoked);
/// ```
pub fn verify_emrtd_with_options(
    sod: &SecurityObject,
    data_groups: &std::collections::HashMap<u8, Vec<u8>>,
    registry: &CscaRegistry,
    options: &EmrtdVerificationOptions,
) -> EmrtdVerificationResult {
    let mut result = verify_emrtd(sod, data_groups, registry);

    // CRL revocation check on the DSC
    if !options.crls.is_empty() {
        use der::Encode;

        result
            .warnings
            .retain(|warning| !warning.starts_with("DSC revocation was not checked"));

        let dsc = &sod.signer_certificate.certificate;
        let dsc_der = match dsc.to_der() {
            Ok(value) => value,
            Err(error) => {
                result.errors.push(format!("Failed to encode DSC: {error}"));
                result
                    .error_codes
                    .push("EMRTD_REVOCATION_UNDETERMINED".to_string());
                result.verified = false;
                return result;
            }
        };
        let issuer_name = &dsc.tbs_certificate.issuer;
        let csca_candidates = registry
            .get_anchors()
            .iter()
            .filter(|anchor| anchor.purpose == TrustPurpose::Csca)
            .filter(|anchor| &anchor.certificate.tbs_certificate.subject == issuer_name)
            .collect::<Vec<_>>();
        let mut valid_evidence = false;
        let mut failures = Vec::new();
        for crl_der in &options.crls {
            for csca in &csca_candidates {
                let csca_der = match csca.certificate.to_der() {
                    Ok(value) => value,
                    Err(error) => {
                        failures.push(format!("Failed to encode CSCA: {error}"));
                        continue;
                    }
                };
                match marty_crypto::crl::validate_crl_for_certificate(crl_der, &dsc_der, &csca_der)
                {
                    Ok(status) => {
                        valid_evidence = true;
                        if status.revoked {
                            result.revocation_status = RevocationStatus::Revoked;
                            result.errors.push(format!(
                                "DSC has been revoked: {}",
                                status
                                    .reason
                                    .map(|reason| reason.as_str())
                                    .unwrap_or("unspecified")
                            ));
                            result.error_codes.push("EMRTD_DSC_REVOKED".to_string());
                            result.verified = false;
                            return result;
                        }
                    }
                    Err(error) => failures.push(error.to_string()),
                }
            }
        }
        if valid_evidence {
            result.revocation_status = RevocationStatus::NotRevoked;
        } else {
            result.revocation_status = RevocationStatus::Unchecked;
            result.verified = false;
            result.errors.push(format!(
                "No authenticated, current CRL matched the DSC: {}",
                failures.join("; ")
            ));
            result
                .error_codes
                .push("EMRTD_REVOCATION_UNDETERMINED".to_string());
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

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
    #[cfg(feature = "test-fixtures")]
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
            error_codes: vec![],
            warnings: vec![],
            trust_anchor_subject: Some("CN=Example CSCA".to_string()),
            certificate_chain: vec!["CN=Example DSC".to_string(), "CN=Example CSCA".to_string()],
            dsc_chain_status: ChainStatus::Valid,
            sod_signature_status: SignatureStatus::Valid,
            dg_hash_status: HashStatus::Valid,
            revocation_status: RevocationStatus::Unchecked,
        };

        assert!(result.verified);
        assert_eq!(result.country, Some("US".to_string()));
        assert_eq!(result.dsc_chain_status, ChainStatus::Valid);
    }

    #[test]
    fn data_group_verification_rejects_missing_or_uncommitted_groups() {
        let dg1 = b"DG1 contents".to_vec();
        let dg2 = b"DG2 contents".to_vec();
        let expected = HashMap::from([
            (1, Sha256::digest(&dg1).to_vec()),
            (2, Sha256::digest(&dg2).to_vec()),
        ]);

        assert_eq!(
            verify_data_group_hash_map(
                "SHA-256",
                &expected,
                &HashMap::from([(1, dg1.clone()), (2, dg2.clone())]),
            )
            .unwrap(),
            HashStatus::Valid
        );
        assert_eq!(
            verify_data_group_hash_map("SHA-256", &expected, &HashMap::from([(1, dg1.clone())]),)
                .unwrap(),
            HashStatus::Invalid
        );
        assert_eq!(
            verify_data_group_hash_map(
                "SHA-256",
                &HashMap::from([(1, Sha256::digest(&dg1).to_vec())]),
                &HashMap::from([(1, dg1), (2, dg2)]),
            )
            .unwrap(),
            HashStatus::Invalid
        );
    }

    #[test]
    #[cfg(feature = "test-fixtures")]
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
    #[cfg(feature = "test-fixtures")]
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
