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
use der::{Decode, Encode, Sequence};
use serde::{Deserialize, Serialize};

use crate::{VerificationError, VerificationResult};
use marty_crypto::HashAlgorithm;

const ID_ICAO_LDS_SECURITY_OBJECT: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.23.136.1.1.1");

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

#[derive(Clone, Debug, Sequence)]
struct Asn1LdsSecurityObject {
    version: u8,
    hash_algorithm: spki::AlgorithmIdentifierOwned,
    data_group_hash_values: Vec<Asn1DataGroupHash>,
    lds_version_info: Option<Asn1LdsVersionInfo>,
}

#[derive(Clone, Debug, Sequence)]
struct Asn1DataGroupHash {
    data_group_number: u8,
    data_group_hash_value: der::asn1::OctetString,
}

#[derive(Clone, Debug, Sequence)]
struct Asn1LdsVersionInfo {
    lds_version: der::asn1::PrintableString,
    unicode_version: der::asn1::PrintableString,
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
    if signed_data.encap_content_info.econtent_type != ID_ICAO_LDS_SECURITY_OBJECT {
        return Err(VerificationError::der_error(format!(
            "Unexpected SOD encapsulated content type: {}",
            signed_data.encap_content_info.econtent_type
        )));
    }
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
#[allow(deprecated)] // SHA-1 remains necessary for legacy ICAO documents.
pub fn parse_lds_security_object(der_bytes: &[u8]) -> VerificationResult<LdsSecurityObject> {
    let parsed = Asn1LdsSecurityObject::from_der(der_bytes).map_err(|e| {
        VerificationError::der_error(format!("Invalid LDSSecurityObject ASN.1: {e}"))
    })?;
    if parsed.version > 1 {
        return Err(VerificationError::der_error(format!(
            "Unsupported LDSSecurityObject version: {}",
            parsed.version
        )));
    }
    if parsed.version == 1 && parsed.lds_version_info.is_none() {
        return Err(VerificationError::der_error(
            "LDSSecurityObject version 1 is missing LDSVersionInfo".to_string(),
        ));
    }
    if parsed.data_group_hash_values.is_empty() {
        return Err(VerificationError::der_error(
            "LDSSecurityObject contains no data-group hashes".to_string(),
        ));
    }

    let hash_algorithm = parsed.hash_algorithm.oid.to_string();
    let algorithm = HashAlgorithm::from_oid(&hash_algorithm)?;
    let expected_hash_len = match algorithm {
        HashAlgorithm::Sha1 => 20,
        HashAlgorithm::Sha256 => 32,
        HashAlgorithm::Sha384 => 48,
        HashAlgorithm::Sha512 => 64,
    };
    let mut seen = std::collections::HashSet::new();
    let mut data_group_hashes = Vec::with_capacity(parsed.data_group_hash_values.len());
    for entry in parsed.data_group_hash_values {
        if !(1..=16).contains(&entry.data_group_number) {
            return Err(VerificationError::der_error(format!(
                "Invalid data-group number: {}",
                entry.data_group_number
            )));
        }
        if !seen.insert(entry.data_group_number) {
            return Err(VerificationError::der_error(format!(
                "Duplicate data-group hash for DG{}",
                entry.data_group_number
            )));
        }
        let hash_bytes = entry.data_group_hash_value.as_bytes().to_vec();
        if hash_bytes.len() != expected_hash_len {
            return Err(VerificationError::der_error(format!(
                "DG{} hash length {} does not match algorithm {}",
                entry.data_group_number,
                hash_bytes.len(),
                hash_algorithm
            )));
        }
        data_group_hashes.push(DataGroupHash {
            data_group_number: entry.data_group_number,
            hash_value: hex::encode(&hash_bytes),
            hash_bytes,
        });
    }

    let lds_version_info = parsed.lds_version_info.map(|info| LdsVersionInfo {
        lds_version: info.lds_version.as_str().to_string(),
        unicode_version: info.unicode_version.as_str().to_string(),
    });
    Ok(LdsSecurityObject {
        version: i32::from(parsed.version),
        hash_algorithm,
        data_group_hashes,
        lds_version_info,
    })
}

/// Extract Document Signer Certificate from SignedData.
fn extract_document_signer_cert(signed_data: &SignedData) -> VerificationResult<Option<String>> {
    let certs = match &signed_data.certificates {
        Some(c) => c,
        None => return Ok(None),
    };
    let signer_info = exactly_one_signer(signed_data)?;
    let cert = find_signer_certificate(certs, &signer_info.sid)?;
    let der = cert.to_der().map_err(|e| {
        VerificationError::internal(format!("Failed to encode signer certificate: {e}"))
    })?;
    let pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der)
        .map_err(|e| VerificationError::internal(format!("Failed to PEM encode: {e}")))?;
    Ok(Some(pem))
}

fn exactly_one_signer(
    signed_data: &SignedData,
) -> VerificationResult<&cms::signed_data::SignerInfo> {
    let mut signers = signed_data.signer_infos.0.iter();
    let signer = signers
        .next()
        .ok_or_else(|| VerificationError::der_error("SOD has no signer information".to_string()))?;
    if signers.next().is_some() {
        return Err(VerificationError::der_error(
            "SOD must contain exactly one signer".to_string(),
        ));
    }
    Ok(signer)
}

fn find_signer_certificate<'a>(
    certs: &'a cms::signed_data::CertificateSet,
    signer_id: &cms::signed_data::SignerIdentifier,
) -> VerificationResult<&'a x509_cert::Certificate> {
    use cms::cert::CertificateChoices;
    use cms::signed_data::SignerIdentifier;
    use x509_cert::ext::pkix::SubjectKeyIdentifier;

    let mut matched = None;
    for choice in certs.0.iter() {
        let CertificateChoices::Certificate(cert) = choice else {
            continue;
        };
        let is_match = match signer_id {
            SignerIdentifier::IssuerAndSerialNumber(id) => {
                cert.tbs_certificate.issuer == id.issuer
                    && cert.tbs_certificate.serial_number == id.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(expected) => cert
                .tbs_certificate
                .get::<SubjectKeyIdentifier>()
                .map_err(|e| {
                    VerificationError::der_error(format!(
                        "Invalid signer SubjectKeyIdentifier extension: {e}"
                    ))
                })?
                .is_some_and(|(_, actual)| actual == *expected),
        };
        if is_match {
            if matched.is_some() {
                return Err(VerificationError::der_error(
                    "Multiple certificates match the SOD signer identifier".to_string(),
                ));
            }
            matched = Some(cert);
        }
    }
    matched.ok_or_else(|| {
        VerificationError::der_error("No certificate matches the SOD signer identifier".to_string())
    })
}

fn single_signed_attribute_value<'a>(
    attributes: &'a x509_cert::attr::Attributes,
    oid: der::asn1::ObjectIdentifier,
) -> VerificationResult<&'a der::Any> {
    let mut matching = attributes.iter().filter(|attribute| attribute.oid == oid);
    let attribute = matching.next().ok_or_else(|| {
        VerificationError::der_error(format!("Missing required CMS signed attribute {oid}"))
    })?;
    if matching.next().is_some() {
        return Err(VerificationError::der_error(format!(
            "Duplicate CMS signed attribute {oid}"
        )));
    }
    let mut values = attribute.values.iter();
    let value = values.next().ok_or_else(|| {
        VerificationError::der_error(format!("CMS signed attribute {oid} has no value"))
    })?;
    if values.next().is_some() {
        return Err(VerificationError::der_error(format!(
            "CMS signed attribute {oid} has multiple values"
        )));
    }
    Ok(value)
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

    let certs = signed_data
        .certificates
        .as_ref()
        .ok_or_else(|| VerificationError::der_error("SOD has no certificates".to_string()))?;
    let signer_info = exactly_one_signer(&signed_data)?;
    let dsc = find_signer_certificate(certs, &signer_info.sid)?;

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

    if !signed_data
        .digest_algorithms
        .iter()
        .any(|algorithm| algorithm.oid == signer_info.digest_alg.oid)
    {
        return Err(VerificationError::der_error(
            "Signer digest algorithm is absent from SignedData digestAlgorithms".to_string(),
        ));
    }
    let digest_algorithm = HashAlgorithm::from_oid(&signer_info.digest_alg.oid.to_string())?;
    let data_to_verify = if let Some(signed_attrs) = &signer_info.signed_attrs {
        let content_type_value =
            single_signed_attribute_value(signed_attrs, const_oid::db::rfc5911::ID_CONTENT_TYPE)?
                .decode_as::<der::asn1::ObjectIdentifier>()
                .map_err(|e| {
                    VerificationError::der_error(format!("Invalid contentType attribute: {e}"))
                })?;
        if content_type_value != signed_data.encap_content_info.econtent_type {
            return Ok(false);
        }
        let message_digest =
            single_signed_attribute_value(signed_attrs, const_oid::db::rfc5911::ID_MESSAGE_DIGEST)?
                .decode_as::<der::asn1::OctetString>()
                .map_err(|e| {
                    VerificationError::der_error(format!("Invalid messageDigest attribute: {e}"))
                })?;
        if marty_crypto::hashing::hash(digest_algorithm, content) != message_digest.as_bytes() {
            return Ok(false);
        }
        signed_attrs.to_der().map_err(|e| {
            VerificationError::internal(format!("Failed to encode signed attributes: {e}"))
        })?
    } else {
        content.to_vec()
    };

    let algorithm = marty_crypto::SignatureAlgorithm::from_oid(
        &signer_info.signature_algorithm.oid.to_string(),
    )?;
    marty_crypto::verify_signature(
        algorithm,
        &public_key_der,
        &data_to_verify,
        signer_info.signature.as_bytes(),
    )
    .map_err(Into::into)
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

/// Verify a data-group hash directly from an EF.SOD DER payload.
pub fn verify_data_group_hash_from_sod(
    sod_der: &[u8],
    data_group_number: u8,
    data_group_content: &[u8],
) -> VerificationResult<bool> {
    let sod = parse_sod(sod_der)?;
    let expected = sod
        .data_group_hashes
        .iter()
        .find(|hash| hash.data_group_number == data_group_number)
        .ok_or_else(|| {
            VerificationError::internal(format!(
                "Data group {} not found in SOD",
                data_group_number
            ))
        })?;
    let algorithm = HashAlgorithm::from_oid(&sod.hash_algorithm)?;
    Ok(marty_crypto::hashing::hash(algorithm, data_group_content) == expected.hash_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_lds(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
        Asn1LdsSecurityObject {
            version: 0,
            hash_algorithm: spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ID_SHA_256,
                parameters: None,
            },
            data_group_hash_values: entries
                .iter()
                .map(|(number, hash)| Asn1DataGroupHash {
                    data_group_number: *number,
                    data_group_hash_value: der::asn1::OctetString::new(hash.clone()).unwrap(),
                })
                .collect(),
            lds_version_info: None,
        }
        .to_der()
        .unwrap()
    }

    #[test]
    fn parses_strict_lds_security_object_asn1() {
        let hash = vec![0x5a; 32];
        let parsed = parse_lds_security_object(&encoded_lds(&[(1, hash.clone())])).unwrap();

        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.hash_algorithm, "2.16.840.1.101.3.4.2.1");
        assert_eq!(parsed.data_group_hashes.len(), 1);
        assert_eq!(parsed.data_group_hashes[0].data_group_number, 1);
        assert_eq!(parsed.data_group_hashes[0].hash_bytes, hash);
    }

    #[test]
    fn rejects_duplicate_missing_and_malformed_data_group_hashes() {
        assert!(parse_lds_security_object(&encoded_lds(&[])).is_err());
        assert!(parse_lds_security_object(&encoded_lds(&[
            (1, vec![0x11; 32]),
            (1, vec![0x22; 32]),
        ]))
        .is_err());
        assert!(parse_lds_security_object(&encoded_lds(&[(17, vec![0x11; 32])])).is_err());
        assert!(parse_lds_security_object(&encoded_lds(&[(1, vec![0x11; 31])])).is_err());

        let mut trailing = encoded_lds(&[(1, vec![0x11; 32])]);
        trailing.push(0);
        assert!(parse_lds_security_object(&trailing).is_err());
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
