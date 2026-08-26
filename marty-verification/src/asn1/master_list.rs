//! ICAO Master List parsing.
//!
//! The Master List is a CMS-signed document containing CSCA certificates
//! that are trusted by ICAO PKD subscribers.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode, Sequence};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::{VerificationError, VerificationResult};

const ID_ICAO_CSCA_MASTER_LIST: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.23.136.1.1.2");

#[derive(Clone, Debug, Sequence)]
struct Asn1CscaMasterList {
    version: u8,
    cert_list: der::asn1::SetOfVec<Certificate>,
}

/// Parsed ICAO Master List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterList {
    /// Version of the master list
    pub version: Option<i32>,
    /// List of CSCA certificates
    pub certificates: Vec<CscaCertificate>,
    /// Signer certificate (if embedded in CMS)
    pub signer_certificate: Option<String>,
}

/// A CSCA certificate from the master list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CscaCertificate {
    /// Subject distinguished name
    pub subject: String,
    /// Issuer distinguished name  
    pub issuer: String,
    /// Serial number (hex)
    pub serial_number: String,
    /// Country code (extracted from subject)
    pub country: Option<String>,
    /// Not before date (ISO 8601)
    pub not_before: String,
    /// Not after date (ISO 8601)
    pub not_after: String,
    /// DER-encoded certificate
    #[serde(skip_serializing)]
    pub der_bytes: Vec<u8>,
}

/// Parse an ICAO Master List from DER-encoded CMS.
///
/// The Master List is a CMS SignedData structure containing:
/// - A list of CSCA certificates as the encapsulated content
/// - One or more signer certificates
/// - Signatures from the ICAO PKD
pub fn parse_master_list(cms_der: &[u8]) -> VerificationResult<MasterList> {
    // Parse ContentInfo wrapper
    let content_info = ContentInfo::from_der(cms_der).map_err(|e| {
        VerificationError::der_error(format!("Failed to parse Master List ContentInfo: {}", e))
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
        .map_err(|e| VerificationError::der_error(format!("Failed to parse SignedData: {}", e)))?;

    // Extract encapsulated content (the actual certificate list)
    let encap_content = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| {
            VerificationError::der_error("Master List has no encapsulated content".to_string())
        })?;
    if signed_data.encap_content_info.econtent_type != ID_ICAO_CSCA_MASTER_LIST {
        return Err(VerificationError::der_error(format!(
            "Unexpected Master List content type: {}",
            signed_data.encap_content_info.econtent_type
        )));
    }

    let cert_list_bytes = encap_content.value();
    let (version, certificates) = parse_certificate_sequence(cert_list_bytes)?;

    let signer_certificate = if let Some(certs) = &signed_data.certificates {
        let signer = exactly_one_signer(&signed_data)?;
        Some(
            find_embedded_signer_certificate(certs, &signer.sid)?
                .tbs_certificate
                .subject
                .to_string(),
        )
    } else {
        None
    };

    Ok(MasterList {
        version: Some(i32::from(version)),
        certificates,
        signer_certificate,
    })
}

/// Parse the ICAO `CSCAMasterList` structure.
fn parse_certificate_sequence(der_bytes: &[u8]) -> VerificationResult<(u8, Vec<CscaCertificate>)> {
    let parsed = Asn1CscaMasterList::from_der(der_bytes)
        .map_err(|e| VerificationError::der_error(format!("Invalid CSCAMasterList ASN.1: {e}")))?;
    if parsed.version != 0 {
        return Err(VerificationError::der_error(format!(
            "Unsupported CSCAMasterList version: {}",
            parsed.version
        )));
    }
    if parsed.cert_list.is_empty() {
        return Err(VerificationError::der_error(
            "CSCAMasterList contains no CSCA certificates".to_string(),
        ));
    }
    let certificates = parsed
        .cert_list
        .iter()
        .map(|cert| {
            let der_bytes = cert.to_der().map_err(|e| {
                VerificationError::internal(format!("Failed to encode CSCA certificate: {e}"))
            })?;
            Ok(extract_csca_info(cert, der_bytes))
        })
        .collect::<VerificationResult<Vec<_>>>()?;
    Ok((parsed.version, certificates))
}

/// Extract CSCA information from a parsed certificate.
fn extract_csca_info(cert: &Certificate, der_bytes: Vec<u8>) -> CscaCertificate {
    let tbs = &cert.tbs_certificate;

    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();

    // Extract country from subject DN
    let country = extract_country(&subject);

    // Format serial number
    let serial_number = tbs
        .serial_number
        .as_bytes()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    // Format validity
    let not_before = format_time(&tbs.validity.not_before);
    let not_after = format_time(&tbs.validity.not_after);

    CscaCertificate {
        subject,
        issuer,
        serial_number,
        country,
        not_before,
        not_after,
        der_bytes,
    }
}

/// Extract country code from DN string.
fn extract_country(dn: &str) -> Option<String> {
    // Look for C= in the DN
    for part in dn.split(',') {
        let part = part.trim();
        if part.starts_with("C=") || part.starts_with("c=") {
            return Some(part[2..].trim().to_uppercase());
        }
    }
    None
}

/// Format X.509 time to ISO 8601 string.
fn format_time(time: &x509_cert::time::Time) -> String {
    time.to_string()
}

fn exactly_one_signer(
    signed_data: &SignedData,
) -> VerificationResult<&cms::signed_data::SignerInfo> {
    let mut signers = signed_data.signer_infos.0.iter();
    let signer = signers.next().ok_or_else(|| {
        VerificationError::der_error("Master List has no signer information".to_string())
    })?;
    if signers.next().is_some() {
        return Err(VerificationError::der_error(
            "Master List must contain exactly one signer".to_string(),
        ));
    }
    Ok(signer)
}

fn signer_id_matches(
    cert: &Certificate,
    signer_id: &cms::signed_data::SignerIdentifier,
) -> VerificationResult<bool> {
    use cms::signed_data::SignerIdentifier;
    use x509_cert::ext::pkix::SubjectKeyIdentifier;

    match signer_id {
        SignerIdentifier::IssuerAndSerialNumber(id) => Ok(cert.tbs_certificate.issuer == id.issuer
            && cert.tbs_certificate.serial_number == id.serial_number),
        SignerIdentifier::SubjectKeyIdentifier(expected) => Ok(cert
            .tbs_certificate
            .get::<SubjectKeyIdentifier>()
            .map_err(|e| {
                VerificationError::der_error(format!(
                    "Invalid signer SubjectKeyIdentifier extension: {e}"
                ))
            })?
            .is_some_and(|(_, actual)| actual == *expected)),
    }
}

fn find_embedded_signer_certificate<'a>(
    certs: &'a cms::signed_data::CertificateSet,
    signer_id: &cms::signed_data::SignerIdentifier,
) -> VerificationResult<&'a Certificate> {
    let mut matched = None;
    for choice in certs.0.iter() {
        let cms::cert::CertificateChoices::Certificate(cert) = choice else {
            continue;
        };
        if signer_id_matches(cert, signer_id)? {
            if matched.is_some() {
                return Err(VerificationError::der_error(
                    "Multiple embedded certificates match the Master List signer".to_string(),
                ));
            }
            matched = Some(cert);
        }
    }
    matched.ok_or_else(|| {
        VerificationError::der_error(
            "No embedded certificate matches the Master List signer".to_string(),
        )
    })
}

fn single_signed_attribute_value(
    attributes: &x509_cert::attr::Attributes,
    oid: der::asn1::ObjectIdentifier,
) -> VerificationResult<&der::Any> {
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

/// Verify Master List signature.
///
/// # Arguments
///
/// * `cms_der` - DER-encoded CMS Master List
/// * `signer_cert_der` - DER-encoded signer certificate (ICAO PKD)
///
/// # Returns
///
/// `Ok(true)` if signature is valid.
pub fn verify_master_list_signature(
    cms_der: &[u8],
    signer_cert_der: &[u8],
) -> VerificationResult<bool> {
    let content_info = ContentInfo::from_der(cms_der)
        .map_err(|e| VerificationError::der_error(format!("Failed to parse ContentInfo: {}", e)))?;
    if content_info.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        return Err(VerificationError::der_error(
            "Master List ContentInfo is not SignedData".to_string(),
        ));
    }
    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|e| VerificationError::der_error(format!("Failed to parse SignedData: {}", e)))?;
    let signer_cert = Certificate::from_der(signer_cert_der).map_err(|e| {
        VerificationError::der_error(format!("Failed to parse signer certificate: {}", e))
    })?;
    let signer_info = exactly_one_signer(&signed_data)?;
    if !signer_id_matches(&signer_cert, &signer_info.sid)? {
        return Err(VerificationError::der_error(
            "Supplied certificate does not match the Master List signer identifier".to_string(),
        ));
    }
    let public_key_der = signer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| VerificationError::internal(format!("Failed to encode SPKI: {}", e)))?;
    if signed_data.encap_content_info.econtent_type != ID_ICAO_CSCA_MASTER_LIST {
        return Err(VerificationError::der_error(
            "Unexpected Master List encapsulated content type".to_string(),
        ));
    }
    let content = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| VerificationError::der_error("No content to verify".to_string()))?
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
    let digest_algorithm =
        marty_crypto::HashAlgorithm::from_oid(&signer_info.digest_alg.oid.to_string())?;
    let data_to_verify = if let Some(signed_attrs) = &signer_info.signed_attrs {
        let content_type =
            single_signed_attribute_value(signed_attrs, const_oid::db::rfc5911::ID_CONTENT_TYPE)?
                .decode_as::<der::asn1::ObjectIdentifier>()
                .map_err(|e| {
                    VerificationError::der_error(format!("Invalid contentType attribute: {e}"))
                })?;
        if content_type != signed_data.encap_content_info.econtent_type {
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
    marty_crypto::algorithm_identifier::verify_signature_with_algorithm_identifier(
        &signer_info.signature_algorithm,
        &public_key_der,
        &data_to_verify,
        signer_info.signature.as_bytes(),
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_master_list() -> (Vec<u8>, Vec<u8>) {
        use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
        use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
        use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
        use der::{Any, Tag};
        use marty_crypto::cert_builder::create_ca_certificate;
        use marty_crypto::keygen::KeyType;
        use p256::pkcs8::DecodePrivateKey;

        let (signer_der, signer_key_pem) =
            create_ca_certificate("ICAO Master List Signer", None, 365, KeyType::EcdsaP256)
                .unwrap();
        let signer_cert = Certificate::from_der(&signer_der).unwrap();
        let mut cert_list = der::asn1::SetOfVec::new();
        cert_list.insert(signer_cert.clone()).unwrap();
        let master_list_der = Asn1CscaMasterList {
            version: 0,
            cert_list,
        }
        .to_der()
        .unwrap();
        let eci = EncapsulatedContentInfo {
            econtent_type: ID_ICAO_CSCA_MASTER_LIST,
            econtent: Some(Any::new(Tag::OctetString, master_list_der).unwrap()),
        };
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: signer_cert.tbs_certificate.issuer.clone(),
            serial_number: signer_cert.tbs_certificate.serial_number.clone(),
        });
        let digest_algorithm = spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };
        let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(&signer_key_pem).unwrap();
        let signer_info =
            SignerInfoBuilder::new(&signing_key, sid, digest_algorithm.clone(), &eci, None)
                .unwrap();
        let mut builder = SignedDataBuilder::new(&eci);
        builder
            .add_digest_algorithm(digest_algorithm)
            .unwrap()
            .add_certificate(CertificateChoices::Certificate(signer_cert))
            .unwrap()
            .add_signer_info::<p256::ecdsa::SigningKey, p256::ecdsa::DerSignature>(signer_info)
            .unwrap();
        (builder.build().unwrap().to_der().unwrap(), signer_der)
    }

    #[test]
    fn test_extract_country() {
        assert_eq!(extract_country("C=US, CN=Test"), Some("US".to_string()));
        assert_eq!(extract_country("CN=Test, C=DE"), Some("DE".to_string()));
        assert_eq!(extract_country("CN=Test"), None);
    }

    #[test]
    fn test_csca_certificate_serialization() {
        let csca = CscaCertificate {
            subject: "C=US, CN=Test CSCA".to_string(),
            issuer: "C=US, CN=Test CSCA".to_string(),
            serial_number: "01:02:03".to_string(),
            country: Some("US".to_string()),
            not_before: "2020-01-01T00:00:00Z".to_string(),
            not_after: "2030-01-01T00:00:00Z".to_string(),
            der_bytes: vec![1, 2, 3],
        };

        let json = serde_json::to_string(&csca).unwrap();
        assert!(json.contains("US"));
        // der_bytes should be skipped in serialization
        assert!(!json.contains("der_bytes"));
    }

    #[test]
    fn strict_master_list_round_trip_and_signature_binding() {
        let (cms_der, signer_der) = build_test_master_list();
        let parsed = parse_master_list(&cms_der).unwrap();
        assert_eq!(parsed.version, Some(0));
        assert_eq!(parsed.certificates.len(), 1);
        assert!(verify_master_list_signature(&cms_der, &signer_der).unwrap());

        let content_info = ContentInfo::from_der(&cms_der).unwrap();
        let signed_data = content_info.content.decode_as::<SignedData>().unwrap();
        let content = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .unwrap()
            .value()
            .to_vec();
        let offset = cms_der
            .windows(content.len())
            .position(|window| window == content)
            .unwrap();
        let mut tampered = cms_der.clone();
        tampered[offset + content.len() - 1] ^= 0x01;
        assert!(!verify_master_list_signature(&tampered, &signer_der).unwrap());
    }

    #[test]
    fn empty_or_malformed_csca_master_list_fails_closed() {
        let empty = Asn1CscaMasterList {
            version: 0,
            cert_list: der::asn1::SetOfVec::new(),
        }
        .to_der()
        .unwrap();
        assert!(parse_certificate_sequence(&empty).is_err());

        let mut malformed = empty;
        malformed.push(0);
        assert!(parse_certificate_sequence(&malformed).is_err());
    }
}
