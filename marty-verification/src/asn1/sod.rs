//! Document Security Object (SOD) parsing.
//!
//! The SOD (EF.SOD) is a CMS-signed structure in eMRTD chips that contains:
//! - LDSSecurityObject: hashes of all data groups
//! - Document Signer Certificate (DSC)
//! - Signature from the DSC
//!
//! Per ICAO 9303 Part 10.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};

use marty_crypto::HashAlgorithm;
use crate::{VerificationError, VerificationResult};

/// Parsed Document Security Object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSecurityObject {
    /// LDS version (e.g., "0107" or "0108")
    pub lds_version: String,
    /// Hash algorithm used for data group hashes
    pub hash_algorithm: String,
    /// Data group hashes
    pub data_group_hashes: Vec<DataGroupHash>,
    /// Document Signer Certificate (PEM)
    pub document_signer_cert: Option<String>,
}

/// LDS Security Object (the signed content in SOD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdsSecurityObject {
    /// Version (0 or 1)
    pub version: i32,
    /// Hash algorithm OID
    pub hash_algorithm: String,
    /// Data group hash values
    pub data_group_hashes: Vec<DataGroupHash>,
    /// LDS version info (if version 1)
    pub lds_version_info: Option<LdsVersionInfo>,
}

/// Data group hash entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataGroupHash {
    /// Data group number (1-16)
    pub data_group_number: u8,
    /// Hash value (hex encoded)
    pub hash_value: String,
    /// Raw hash bytes
    #[serde(skip_serializing)]
    pub hash_bytes: Vec<u8>,
}

/// LDS version information (for SOD version 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdsVersionInfo {
    /// LDS version (e.g., "0108")
    pub lds_version: String,
    /// Unicode version (e.g., "040000")
    pub unicode_version: String,
}

/// Parse a Document Security Object from DER bytes.
///
/// The SOD is a CMS SignedData structure where:
/// - encapContentInfo contains LDSSecurityObject
/// - certificates contains the Document Signer Certificate
/// - signerInfos contains the signature
pub fn parse_sod(der_bytes: &[u8]) -> VerificationResult<DocumentSecurityObject> {
    // Parse CMS ContentInfo
    let content_info = ContentInfo::from_der(der_bytes).map_err(|e| {
        VerificationError::der_error(format!("Failed to parse SOD ContentInfo: {}", e))
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
        .map_err(|e| {
            VerificationError::der_error(format!("Failed to parse SOD SignedData: {}", e))
        })?;

    // Extract LDSSecurityObject from encapsulated content
    let lds_so = extract_lds_security_object(&signed_data)?;

    // Extract Document Signer Certificate
    let dsc_pem = extract_document_signer_cert(&signed_data)?;

    Ok(DocumentSecurityObject {
        lds_version: lds_so
            .lds_version_info
            .as_ref()
            .map(|v| v.lds_version.clone())
            .unwrap_or_else(|| "0107".to_string()),
        hash_algorithm: lds_so.hash_algorithm.clone(),
        data_group_hashes: lds_so.data_group_hashes,
        document_signer_cert: dsc_pem,
    })
}

/// Extract and parse LDSSecurityObject from SignedData.
fn extract_lds_security_object(signed_data: &SignedData) -> VerificationResult<LdsSecurityObject> {
    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| {
            VerificationError::der_error("SOD has no encapsulated content".to_string())
        })?;

    let content_bytes = econtent.value();
    parse_lds_security_object(content_bytes)
}

/// Parse LDSSecurityObject ASN.1 structure.
///
/// ```asn1
/// LDSSecurityObject ::= SEQUENCE {
///   version          LDSSecurityObjectVersion,
///   hashAlgorithm    AlgorithmIdentifier,
///   dataGroupHashValues SEQUENCE OF DataGroupHash,
///   ldsVersionInfo   LDSVersionInfo OPTIONAL
/// }
///
/// DataGroupHash ::= SEQUENCE {
///   dataGroupNumber  DataGroupNumber,
///   dataGroupHashValue OCTET STRING
/// }
/// ```
pub fn parse_lds_security_object(der_bytes: &[u8]) -> VerificationResult<LdsSecurityObject> {
    use der::{Reader, SliceReader, Tag};

    let reader = SliceReader::new(der_bytes)
        .map_err(|e| VerificationError::der_error(format!("Invalid DER: {}", e)))?;

    // Read outer SEQUENCE
    let header = reader
        .peek_header()
        .map_err(|e| VerificationError::der_error(format!("Invalid header: {}", e)))?;

    if header.tag != Tag::Sequence {
        return Err(VerificationError::der_error(
            "Expected SEQUENCE for LDSSecurityObject".to_string(),
        ));
    }

    // For now, use a simplified parser
    // In production, define proper ASN.1 types with der derive macros
    parse_lds_security_object_simple(der_bytes)
}

/// Simplified LDSSecurityObject parser.
fn parse_lds_security_object_simple(der_bytes: &[u8]) -> VerificationResult<LdsSecurityObject> {
    // This is a simplified implementation
    // Real implementation would use proper ASN.1 decoding

    // Look for common hash algorithm OIDs in the bytes
    let hash_algorithm = detect_hash_algorithm(der_bytes);

    // Extract data group hashes
    let data_group_hashes = extract_data_group_hashes(der_bytes)?;

    Ok(LdsSecurityObject {
        version: 0,
        hash_algorithm,
        data_group_hashes,
        lds_version_info: None,
    })
}

/// Detect hash algorithm from DER bytes by looking for OIDs.
fn detect_hash_algorithm(der_bytes: &[u8]) -> String {
    // SHA-256 OID: 2.16.840.1.101.3.4.2.1
    let sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    // SHA-384 OID: 2.16.840.1.101.3.4.2.2
    let sha384_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    // SHA-512 OID: 2.16.840.1.101.3.4.2.3
    let sha512_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
    // SHA-1 OID: 1.3.14.3.2.26
    let sha1_oid = [0x2b, 0x0e, 0x03, 0x02, 0x1a];

    if contains_subsequence(der_bytes, &sha256_oid) {
        "2.16.840.1.101.3.4.2.1".to_string()
    } else if contains_subsequence(der_bytes, &sha384_oid) {
        "2.16.840.1.101.3.4.2.2".to_string()
    } else if contains_subsequence(der_bytes, &sha512_oid) {
        "2.16.840.1.101.3.4.2.3".to_string()
    } else if contains_subsequence(der_bytes, &sha1_oid) {
        "1.3.14.3.2.26".to_string()
    } else {
        "unknown".to_string()
    }
}

/// Check if bytes contain a subsequence.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Extract data group hashes from SOD content.
fn extract_data_group_hashes(der_bytes: &[u8]) -> VerificationResult<Vec<DataGroupHash>> {
    // Simplified extraction - look for typical data group hash patterns
    // Real implementation needs proper ASN.1 parsing

    let mut hashes = Vec::new();

    // Data group hashes are typically:
    // SEQUENCE { INTEGER dg_number, OCTET STRING hash }
    // Look for these patterns

    let mut i = 0;
    while i < der_bytes.len() {
        // Look for SEQUENCE tag
        if der_bytes[i] == 0x30 && i + 2 < der_bytes.len() {
            let seq_len = der_bytes[i + 1] as usize;
            if seq_len > 0 && seq_len < 100 && i + 2 + seq_len <= der_bytes.len() {
                // Check for INTEGER tag for DG number
                if der_bytes[i + 2] == 0x02 {
                    let int_len = der_bytes[i + 3] as usize;
                    if int_len == 1 && i + 4 < der_bytes.len() {
                        let dg_num = der_bytes[i + 4];
                        // Valid DG numbers are 1-16
                        if (1..=16).contains(&dg_num) {
                            // Look for OCTET STRING following
                            let hash_offset = i + 5;
                            if hash_offset < der_bytes.len() && der_bytes[hash_offset] == 0x04 {
                                let hash_len = der_bytes[hash_offset + 1] as usize;
                                // Valid hash lengths
                                if (hash_len == 20
                                    || hash_len == 32
                                    || hash_len == 48
                                    || hash_len == 64)
                                    && hash_offset + 2 + hash_len <= der_bytes.len()
                                {
                                    let hash_bytes = der_bytes
                                        [hash_offset + 2..hash_offset + 2 + hash_len]
                                        .to_vec();
                                    let hash_value = hash_bytes
                                        .iter()
                                        .map(|b| format!("{:02x}", b))
                                        .collect::<String>();

                                    hashes.push(DataGroupHash {
                                        data_group_number: dg_num,
                                        hash_value,
                                        hash_bytes,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }

    Ok(hashes)
}

/// Extract Document Signer Certificate from SignedData.
fn extract_document_signer_cert(signed_data: &SignedData) -> VerificationResult<Option<String>> {
    let certs = match &signed_data.certificates {
        Some(c) => c,
        None => return Ok(None),
    };

    // Get first certificate
    for cert_choice in certs.0.iter() {
        if let cms::cert::CertificateChoices::Certificate(cert) = cert_choice {
            // Encode to DER then PEM
            let der = cert.to_der().map_err(|e| {
                VerificationError::internal(format!("Failed to encode cert: {}", e))
            })?;

            let pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der)
                .map_err(|e| VerificationError::internal(format!("Failed to PEM encode: {}", e)))?;

            return Ok(Some(pem));
        }
    }

    Ok(None)
}

/// Verify SOD signature against Document Signer Certificate.
///
/// Returns `Ok(true)` if the signature is valid.
pub fn verify_sod_signature(sod_der: &[u8]) -> VerificationResult<bool> {
    // Parse SOD
    let content_info = ContentInfo::from_der(sod_der)
        .map_err(|e| VerificationError::der_error(format!("Failed to parse SOD: {}", e)))?;

    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|e| VerificationError::der_error(format!("Failed to parse SignedData: {}", e)))?;

    // Get DSC
    let certs = signed_data
        .certificates
        .as_ref()
        .ok_or_else(|| VerificationError::der_error("SOD has no certificates".to_string()))?;

    let dsc = certs
        .0
        .iter()
        .find_map(|c| match c {
            cms::cert::CertificateChoices::Certificate(cert) => Some(cert),
            _ => None,
        })
        .ok_or_else(|| VerificationError::der_error("No X.509 certificate in SOD".to_string()))?;

    // Get DSC public key
    let public_key_der = dsc
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| VerificationError::internal(format!("Failed to encode SPKI: {}", e)))?;

    // Get content to verify
    let content = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| VerificationError::der_error("SOD has no content".to_string()))?
        .value();

    // Verify each signer info
    for signer_info in signed_data.signer_infos.0.iter() {
        let sig_alg_oid = signer_info.signature_algorithm.oid.to_string();
        let algorithm = marty_crypto::SignatureAlgorithm::from_oid(&sig_alg_oid)?;

        // Get data to verify (signed attributes or content)
        let data_to_verify = if let Some(signed_attrs) = &signer_info.signed_attrs {
            // When signed attrs present, we sign those (DER encoded)
            signed_attrs.to_der().map_err(|e| {
                VerificationError::internal(format!("Failed to encode signed attrs: {}", e))
            })?
        } else {
            // Otherwise sign the content directly
            content.to_vec()
        };

        let signature = signer_info.signature.as_bytes();

        let valid = marty_crypto::verify_signature(
            algorithm,
            &public_key_der,
            &data_to_verify,
            signature,
        )?;

        if valid {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Verify data group hash matches the expected value.
pub fn verify_data_group_hash(
    sod: &LdsSecurityObject,
    data_group_number: u8,
    data_group_content: &[u8],
) -> VerificationResult<bool> {
    // Find hash for this data group
    let expected = sod
        .data_group_hashes
        .iter()
        .find(|h| h.data_group_number == data_group_number)
        .ok_or_else(|| {
            VerificationError::internal(format!(
                "Data group {} not found in SOD",
                data_group_number
            ))
        })?;

    // Determine hash algorithm from OID
    let algorithm = HashAlgorithm::from_oid(&sod.hash_algorithm)?;

    // Compute hash of data group
    let computed = marty_crypto::hashing::hash(algorithm, data_group_content);

    // Compare
    Ok(computed == expected.hash_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_hash_algorithm_sha256() {
        // Contains SHA-256 OID bytes
        let data = vec![
            0x00, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x00,
        ];
        assert_eq!(detect_hash_algorithm(&data), "2.16.840.1.101.3.4.2.1");
    }

    #[test]
    fn test_detect_hash_algorithm_sha1() {
        // Contains SHA-1 OID bytes
        let data = vec![0x00, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x00];
        assert_eq!(detect_hash_algorithm(&data), "1.3.14.3.2.26");
    }

    #[test]
    fn test_data_group_hash_serialization() {
        let hash = DataGroupHash {
            data_group_number: 1,
            hash_value: "abc123".to_string(),
            hash_bytes: vec![0xab, 0xc1, 0x23],
        };

        let json = serde_json::to_string(&hash).unwrap();
        assert!(json.contains("abc123"));
        // hash_bytes should be skipped
        assert!(!json.contains("hash_bytes"));
    }
}
