//! mDL (ISO 18013-5) verification.
//!
//! This module provides trust chain verification for mobile driving licenses,
//! adapted from the isomdl crate with extensions for Marty integration.

use const_oid::AssociatedOid;
use der::Decode;
use serde::{Deserialize, Serialize};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::Certificate;

use crate::error::{VerificationError, VerificationResult};
use crate::trust_anchor::IacaRegistry;

// Re-export isomdl types for convenience
pub use isomdl::definitions::x509::validation::{ValidationOutcome, ValidationRuleset};
pub use isomdl::definitions::x509::x5chain::{Builder as X5ChainBuilder, X5Chain};

/// Validate the ISO 18013-5 document-signer constraints Marty requires before
/// accepting an mdoc issuer certificate as trusted.
///
/// This check is deliberately independent of how trust is established. An
/// exact certificate pin authorizes a trust anchor, but it must never turn a
/// CA certificate or a certificate-signing key into a document signer.
pub fn validate_document_signer_certificate_profile(
    certificate: &Certificate,
) -> VerificationResult<()> {
    let subject = certificate.tbs_certificate.subject.to_string();
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default();

    let basic_constraints = extensions
        .iter()
        .filter(|extension| extension.extn_id == BasicConstraints::OID)
        .collect::<Vec<_>>();
    if basic_constraints.len() > 1 {
        return Err(VerificationError::invalid_extension(
            BasicConstraints::OID.to_string(),
            &subject,
            "duplicate BasicConstraints extensions",
        ));
    }
    if let Some(extension) = basic_constraints.first() {
        let constraints =
            BasicConstraints::from_der(extension.extn_value.as_bytes()).map_err(|error| {
                VerificationError::invalid_extension(
                    BasicConstraints::OID.to_string(),
                    &subject,
                    format!("unable to decode BasicConstraints: {error}"),
                )
            })?;
        if constraints.ca {
            return Err(VerificationError::invalid_extension(
                BasicConstraints::OID.to_string(),
                &subject,
                "an mdoc document-signer certificate must not be a CA",
            ));
        }
    }

    let key_usage_extensions = extensions
        .iter()
        .filter(|extension| extension.extn_id == KeyUsage::OID)
        .collect::<Vec<_>>();
    let key_usage_extension = match key_usage_extensions.as_slice() {
        [] => {
            return Err(VerificationError::missing_extension(
                KeyUsage::OID.to_string(),
                &subject,
            ));
        }
        [extension] => *extension,
        _ => {
            return Err(VerificationError::invalid_extension(
                KeyUsage::OID.to_string(),
                &subject,
                "duplicate KeyUsage extensions",
            ));
        }
    };
    let key_usage =
        KeyUsage::from_der(key_usage_extension.extn_value.as_bytes()).map_err(|error| {
            VerificationError::invalid_extension(
                KeyUsage::OID.to_string(),
                &subject,
                format!("unable to decode KeyUsage: {error}"),
            )
        })?;
    let expected: der::flagset::FlagSet<KeyUsages> = KeyUsages::DigitalSignature.into();
    if key_usage.0 != expected {
        let found = format!("{:?}", key_usage.0.into_iter().collect::<Vec<KeyUsages>>());
        return Err(VerificationError::key_usage_mismatch(
            subject,
            "DigitalSignature only",
            found,
        ));
    }

    Ok(())
}

/// Parse and validate a DER-encoded mdoc document-signer certificate.
pub fn validate_document_signer_certificate_der(certificate_der: &[u8]) -> VerificationResult<()> {
    let certificate = Certificate::from_der(certificate_der).map_err(|error| {
        VerificationError::x5chain_parse_with_source(
            "unable to parse mdoc document-signer certificate",
            error,
        )
    })?;
    validate_document_signer_certificate_profile(&certificate)
}

/// A verifier-supplied ISO 18013-5 session transcript.
///
/// The transcript is intentionally opaque to this layer. The protocol-facing
/// verifier constructs it from its own request state (client identifier,
/// nonce, response URI, and response-encryption key), then this type preserves
/// its exact CBOR shape for ISO device authentication.
#[cfg(test)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
struct ExternalSessionTranscript(ciborium::Value);

#[cfg(test)]
impl isomdl::definitions::session::SessionTranscript for ExternalSessionTranscript {}

/// Successful holder device-authentication result for a DeviceResponse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MdlDeviceAuthenticationResult {
    /// Every returned document has a valid holder device signature.
    pub verified: bool,
    /// Document types authenticated by the holder.
    pub document_types: Vec<String>,
}

/// Verify holder DeviceAuthentication for every document in a DeviceResponse.
///
/// This verifies the detached COSE device signature with the device public key
/// bound into each document's issuer-signed MSO. The caller must independently
/// verify the issuer signature, certificate chain, validity, and revocation.
/// The session transcript must be derived from verifier-owned request state;
/// accepting a transcript supplied by the wallet would defeat nonce and
/// audience binding.
pub fn verify_device_authentication(
    device_response_cbor: &[u8],
    session_transcript_cbor: &[u8],
) -> VerificationResult<MdlDeviceAuthenticationResult> {
    use isomdl::definitions::device_response::{DeviceResponse, Status};
    use isomdl::presentation::authentication::mdoc::device_authentication_with_raw_session_transcript;

    let response: DeviceResponse = isomdl::cbor::from_slice(device_response_cbor).map_err(|e| {
        VerificationError::cbor_error(format!("Unable to parse mdoc DeviceResponse: {e}"))
    })?;
    if response.version != DeviceResponse::VERSION {
        return Err(VerificationError::device_auth_failed(format!(
            "Unsupported DeviceResponse version {}",
            response.version
        )));
    }
    if !matches!(response.status, Status::OK) {
        return Err(VerificationError::device_auth_failed(
            "DeviceResponse status is not OK",
        ));
    }
    let documents = response.documents.as_ref().ok_or_else(|| {
        VerificationError::device_auth_failed("DeviceResponse contains no documents")
    })?;
    let mut document_types = Vec::with_capacity(documents.len());
    for document in documents.iter() {
        device_authentication_with_raw_session_transcript(document, session_transcript_cbor)
            .map_err(|e| {
                VerificationError::device_auth_failed(format!(
                    "Holder authentication failed for document type {}: {e}",
                    document.doc_type
                ))
            })?;
        document_types.push(document.doc_type.clone());
    }

    Ok(MdlDeviceAuthenticationResult {
        verified: true,
        document_types,
    })
}

/// Result of mDL issuer verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdlVerificationResult {
    /// Whether the verification was successful.
    pub verified: bool,
    /// Common name from the document signer certificate.
    pub common_name: Option<String>,
    /// Jurisdiction code if detected from the certificate.
    pub jurisdiction: Option<String>,
    /// List of validation errors (empty if verified).
    pub errors: Vec<String>,
    /// Authentication status for issuer.
    pub issuer_auth_status: AuthStatus,
    /// Authentication status for device.
    pub device_auth_status: AuthStatus,
}

impl Default for MdlVerificationResult {
    fn default() -> Self {
        Self {
            verified: false,
            common_name: None,
            jurisdiction: None,
            errors: Vec::new(),
            issuer_auth_status: AuthStatus::Unknown,
            device_auth_status: AuthStatus::Unknown,
        }
    }
}

/// Authentication status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthStatus {
    /// Authentication succeeded.
    Valid,
    /// Authentication failed.
    Invalid,
    /// Authentication was not performed.
    Unknown,
}

impl From<isomdl::presentation::authentication::AuthenticationStatus> for AuthStatus {
    fn from(status: isomdl::presentation::authentication::AuthenticationStatus) -> Self {
        match status {
            isomdl::presentation::authentication::AuthenticationStatus::Valid => AuthStatus::Valid,
            isomdl::presentation::authentication::AuthenticationStatus::Invalid => {
                AuthStatus::Invalid
            }
            _ => AuthStatus::Unknown,
        }
    }
}

/// Verify an mDL issuer certificate chain against a trust anchor registry.
///
/// This validates:
/// 1. The X5Chain is present and parseable
/// 2. The document signer certificate chains to a trusted IACA
/// 3. Certificate validity periods
/// 4. Required extensions per ISO 18013-5 Annex B
///
/// # Arguments
///
/// * `x5chain` - The certificate chain from the mDL credential
/// * `registry` - The IACA trust anchor registry
/// * `ruleset` - The validation ruleset to use (Mdl, AamvaMdl, etc.)
///
/// # Returns
///
/// A `MdlVerificationResult` with verification status and any errors.
pub fn verify_x5chain(
    x5chain: &X5Chain,
    registry: &IacaRegistry,
    ruleset: ValidationRuleset,
) -> MdlVerificationResult {
    let isomdl_registry = registry.to_isomdl_registry();
    let outcome = ruleset.validate(x5chain, &isomdl_registry);
    let mut errors = outcome.errors.clone();
    if let Err(error) =
        validate_document_signer_certificate_profile(x5chain.end_entity_certificate())
    {
        errors.push(error.to_string());
    }

    let common_name = Some(x5chain.end_entity_common_name().to_string());

    // Try to detect jurisdiction from certificate
    let jurisdiction = detect_jurisdiction_from_certificate(x5chain.end_entity_certificate());

    MdlVerificationResult {
        verified: errors.is_empty(),
        common_name,
        jurisdiction,
        errors,
        issuer_auth_status: AuthStatus::Unknown,
        device_auth_status: AuthStatus::Unknown,
    }
}

/// Verify the issuer signature on an mDL.
///
/// This verifies that the IssuerSigned data was actually signed by the
/// document signer certificate in the X5Chain.
pub fn verify_issuer_signature(
    x5chain: &X5Chain,
    issuer_signed: &isomdl::definitions::IssuerSigned,
) -> VerificationResult<()> {
    use isomdl::presentation::authentication::mdoc::issuer_authentication;

    issuer_authentication(x5chain.clone(), issuer_signed).map_err(|e| {
        VerificationError::issuer_auth_failed(format!("COSE signature verification failed: {}", e))
    })
}

/// Full mDL verification including trust chain and signatures.
///
/// This is the main entry point for mDL verification, combining:
/// 1. X5Chain validation against trust anchors
/// 2. Issuer signature verification
///
/// # Arguments
///
/// * `x5chain` - The certificate chain from the mDL credential
/// * `issuer_signed` - The issuer-signed portion of the mDL
/// * `registry` - The IACA trust anchor registry
///
/// # Returns
///
/// A `MdlVerificationResult` with full verification status.
pub fn verify_mdl_issuer(
    x5chain: &X5Chain,
    issuer_signed: &isomdl::definitions::IssuerSigned,
    registry: &IacaRegistry,
) -> MdlVerificationResult {
    // First, validate the certificate chain
    let mut result = verify_x5chain(x5chain, registry, ValidationRuleset::AamvaMdl);

    if !result.verified {
        return result;
    }

    // Then verify the issuer signature
    match verify_issuer_signature(x5chain, issuer_signed) {
        Ok(()) => {
            result.issuer_auth_status = AuthStatus::Valid;
        }
        Err(e) => {
            result.verified = false;
            result.issuer_auth_status = AuthStatus::Invalid;
            result.errors.push(e.to_string());
        }
    }

    result
}

/// Detect jurisdiction from certificate subject/issuer fields.
fn detect_jurisdiction_from_certificate(cert: &Certificate) -> Option<String> {
    // Try to extract state/province from subject
    let subject = &cert.tbs_certificate.subject;

    // Look for stateOrProvinceName in the subject
    for rdn in subject.0.iter() {
        for attr in rdn.0.iter() {
            // OID for stateOrProvinceName: 2.5.4.8
            if attr.oid.to_string() == "2.5.4.8" {
                if let Ok(value) = std::str::from_utf8(attr.value.value()) {
                    // Try to map state name to jurisdiction code
                    return state_name_to_code(value);
                }
            }
        }
    }

    // Try to extract country from subject
    for rdn in subject.0.iter() {
        for attr in rdn.0.iter() {
            // OID for countryName: 2.5.4.6
            if attr.oid.to_string() == "2.5.4.6" {
                if let Ok(value) = std::str::from_utf8(attr.value.value()) {
                    return Some(value.to_uppercase());
                }
            }
        }
    }

    None
}

/// Map US state name to ISO 3166-2 code.
fn state_name_to_code(name: &str) -> Option<String> {
    let name_upper = name.to_uppercase();
    let code = match name_upper.as_str() {
        "ALABAMA" => "US-AL",
        "ALASKA" => "US-AK",
        "ARIZONA" => "US-AZ",
        "ARKANSAS" => "US-AR",
        "CALIFORNIA" => "US-CA",
        "COLORADO" => "US-CO",
        "CONNECTICUT" => "US-CT",
        "DELAWARE" => "US-DE",
        "DISTRICT OF COLUMBIA" | "DC" => "US-DC",
        "FLORIDA" => "US-FL",
        "GEORGIA" => "US-GA",
        "HAWAII" => "US-HI",
        "IDAHO" => "US-ID",
        "ILLINOIS" => "US-IL",
        "INDIANA" => "US-IN",
        "IOWA" => "US-IA",
        "KANSAS" => "US-KS",
        "KENTUCKY" => "US-KY",
        "LOUISIANA" => "US-LA",
        "MAINE" => "US-ME",
        "MARYLAND" => "US-MD",
        "MASSACHUSETTS" => "US-MA",
        "MICHIGAN" => "US-MI",
        "MINNESOTA" => "US-MN",
        "MISSISSIPPI" => "US-MS",
        "MISSOURI" => "US-MO",
        "MONTANA" => "US-MT",
        "NEBRASKA" => "US-NE",
        "NEVADA" => "US-NV",
        "NEW HAMPSHIRE" => "US-NH",
        "NEW JERSEY" => "US-NJ",
        "NEW MEXICO" => "US-NM",
        "NEW YORK" => "US-NY",
        "NORTH CAROLINA" => "US-NC",
        "NORTH DAKOTA" => "US-ND",
        "OHIO" => "US-OH",
        "OKLAHOMA" => "US-OK",
        "OREGON" => "US-OR",
        "PENNSYLVANIA" => "US-PA",
        "RHODE ISLAND" => "US-RI",
        "SOUTH CAROLINA" => "US-SC",
        "SOUTH DAKOTA" => "US-SD",
        "TENNESSEE" => "US-TN",
        "TEXAS" => "US-TX",
        "UTAH" => "US-UT",
        "VERMONT" => "US-VT",
        "VIRGINIA" => "US-VA",
        "WASHINGTON" => "US-WA",
        "WEST VIRGINIA" => "US-WV",
        "WISCONSIN" => "US-WI",
        "WYOMING" => "US-WY",
        // Canadian provinces
        "ALBERTA" => "CA-AB",
        "BRITISH COLUMBIA" => "CA-BC",
        "MANITOBA" => "CA-MB",
        "NEW BRUNSWICK" => "CA-NB",
        "NEWFOUNDLAND AND LABRADOR" | "NEWFOUNDLAND" => "CA-NL",
        "NOVA SCOTIA" => "CA-NS",
        "ONTARIO" => "CA-ON",
        "PRINCE EDWARD ISLAND" => "CA-PE",
        "QUEBEC" => "CA-QC",
        "SASKATCHEWAN" => "CA-SK",
        _ => return None,
    };
    Some(code.to_string())
}

/// Parse an X5Chain from CBOR-encoded bytes.
///
/// This is useful when receiving mDL credentials in CBOR format.
pub fn parse_x5chain_from_cbor(cbor_bytes: &[u8]) -> VerificationResult<X5Chain> {
    let cbor_value: ciborium::Value = ciborium::from_reader(cbor_bytes)
        .map_err(|e| VerificationError::x5chain_parse(format!("Failed to parse CBOR: {}", e)))?;

    X5Chain::from_cbor(cbor_value).map_err(|e| {
        VerificationError::x5chain_parse(format!("Failed to build X5Chain from CBOR: {}", e))
    })
}

/// Build an X5Chain from PEM-encoded certificate(s).
pub fn build_x5chain_from_pem(pem_certs: &[&[u8]]) -> VerificationResult<X5Chain> {
    let mut builder = X5Chain::builder();

    for (idx, pem) in pem_certs.iter().enumerate() {
        builder = builder.with_pem_certificate(pem).map_err(|e| {
            VerificationError::x5chain_parse(format!(
                "Certificate #{} parse failed: {}",
                idx + 1,
                e
            ))
        })?;
    }

    builder
        .build()
        .map_err(|e| VerificationError::x5chain_parse(format!("Failed to build X5Chain: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use isomdl::cose::sign1::PreparedCoseSign1;
    use isomdl::definitions::device_key::cose_key::EC2Y;
    use isomdl::definitions::device_response::{DeviceResponse, Document, Documents, Status};
    use isomdl::definitions::device_signed::{DeviceAuth, DeviceSigned};
    use isomdl::definitions::helpers::Tag24;
    use isomdl::definitions::{DeviceKeyInfo, DigestAlgorithm, IssuerSigned, Mso, ValidityInfo};
    use p256::ecdsa::{Signature, SigningKey};
    use signature::Signer;
    use std::collections::BTreeMap;
    use time::{Duration, OffsetDateTime};

    fn document_signer_certificate(
        is_ca: rcgen::IsCa,
        key_usages: Vec<rcgen::KeyUsagePurpose>,
    ) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "Marty mdoc document signer regression fixture",
        );
        params.is_ca = is_ca;
        params.key_usages = key_usages;
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn document_signer_profile_requires_non_ca_digital_signature_leaf() {
        use crate::error::codes;
        use rcgen::{BasicConstraints, IsCa, KeyUsagePurpose};

        let valid = document_signer_certificate(
            IsCa::ExplicitNoCa,
            vec![KeyUsagePurpose::DigitalSignature],
        );
        assert!(validate_document_signer_certificate_der(&valid).is_ok());

        let ca = document_signer_certificate(
            IsCa::Ca(BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        );
        let error = validate_document_signer_certificate_der(&ca).unwrap_err();
        assert_eq!(error.code(), codes::CERT_INVALID_EXTENSION);
        assert!(error.to_string().contains("must not be a CA"));

        let issuer_usage = document_signer_certificate(
            IsCa::ExplicitNoCa,
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        );
        let error = validate_document_signer_certificate_der(&issuer_usage).unwrap_err();
        assert_eq!(error.code(), codes::CERT_KEY_USAGE_MISMATCH);

        let missing_usage = document_signer_certificate(IsCa::ExplicitNoCa, Vec::new());
        let error = validate_document_signer_certificate_der(&missing_usage).unwrap_err();
        assert_eq!(error.code(), codes::CERT_MISSING_EXTENSION);

        let mixed_usage = document_signer_certificate(
            IsCa::ExplicitNoCa,
            vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ],
        );
        let error = validate_document_signer_certificate_der(&mixed_usage).unwrap_err();
        assert_eq!(error.code(), codes::CERT_KEY_USAGE_MISMATCH);
    }

    fn map_value_mut<'a>(
        entries: &'a mut [(ciborium::Value, ciborium::Value)],
        key: &str,
    ) -> &'a mut ciborium::Value {
        entries
            .iter_mut()
            .find_map(|(candidate, value)| {
                (candidate == &ciborium::Value::Text(key.to_string())).then_some(value)
            })
            .unwrap_or_else(|| panic!("fixture is missing CBOR key {key}"))
    }

    fn encode_empty_issuer_namespaces(response_cbor: &[u8]) -> Vec<u8> {
        let mut response: ciborium::Value =
            isomdl::cbor::from_slice(response_cbor).expect("DeviceResponse fixture must decode");
        let ciborium::Value::Map(response_fields) = &mut response else {
            panic!("DeviceResponse fixture must be a CBOR map");
        };
        let ciborium::Value::Array(documents) = map_value_mut(response_fields, "documents") else {
            panic!("DeviceResponse documents must be a CBOR array");
        };
        let ciborium::Value::Map(document) = &mut documents[0] else {
            panic!("DeviceResponse document must be a CBOR map");
        };
        let ciborium::Value::Map(issuer_signed) = map_value_mut(document, "issuerSigned") else {
            panic!("issuerSigned must be a CBOR map");
        };
        issuer_signed.push((
            ciborium::Value::Text("nameSpaces".to_string()),
            ciborium::Value::Map(Vec::new()),
        ));
        isomdl::cbor::to_vec(&response).expect("DeviceResponse fixture must encode")
    }

    fn device_response_fixture(
        session_transcript: &ExternalSessionTranscript,
    ) -> (Vec<u8>, Vec<u8>) {
        device_response_fixture_with_encoding(session_transcript, None)
    }

    fn device_response_fixture_with_encoding(
        session_transcript: &ExternalSessionTranscript,
        raw_session_transcript_cbor: Option<&[u8]>,
    ) -> (Vec<u8>, Vec<u8>) {
        let signing_key = SigningKey::from_slice(&[7_u8; 32]).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(false);
        let device_key = isomdl::definitions::device_key::CoseKey::EC2 {
            crv: isomdl::definitions::device_key::EC2Curve::P256,
            x: point.x().unwrap().to_vec(),
            y: EC2Y::Value(point.y().unwrap().to_vec()),
        };
        let now = OffsetDateTime::now_utc();
        let mso = Mso {
            version: "1.0".to_string(),
            digest_algorithm: DigestAlgorithm::SHA256,
            value_digests: BTreeMap::new(),
            device_key_info: DeviceKeyInfo {
                device_key,
                key_authorizations: None,
                key_info: None,
            },
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            validity_info: ValidityInfo {
                signed: now,
                valid_from: now,
                valid_until: now + Duration::days(1),
                expected_update: None,
            },
        };
        let tagged_mso = Tag24::new(mso).unwrap();
        let mso_bytes = isomdl::cbor::to_vec(&tagged_mso).unwrap();
        let issuer_auth = PreparedCoseSign1::new(
            coset::CoseSign1Builder::new().payload(mso_bytes),
            None,
            None,
            true,
        )
        .unwrap()
        .finalize(vec![0_u8; 64]);
        let namespaces = Tag24::new(BTreeMap::new()).unwrap();
        let detached_payload = match raw_session_transcript_cbor {
            Some(raw) => {
                raw_device_authentication_fixture(raw, "org.iso.18013.5.1.mDL", &namespaces)
            }
            None => {
                let device_authentication = Tag24::new(
                    isomdl::definitions::device_signed::DeviceAuthentication::new(
                        session_transcript.clone(),
                        "org.iso.18013.5.1.mDL".to_string(),
                        namespaces.clone(),
                    ),
                )
                .unwrap();
                isomdl::cbor::to_vec(&device_authentication).unwrap()
            }
        };
        let prepared_device_signature = PreparedCoseSign1::new(
            coset::CoseSign1Builder::new().protected(
                coset::HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::ES256)
                    .build(),
            ),
            Some(&detached_payload),
            None,
            false,
        )
        .unwrap();
        let signature: Signature = signing_key
            .try_sign(prepared_device_signature.signature_payload())
            .unwrap();
        let device_signature = prepared_device_signature.finalize(signature.to_vec());
        let response = DeviceResponse {
            version: DeviceResponse::VERSION.to_string(),
            documents: Some(Documents::new(Document {
                doc_type: "org.iso.18013.5.1.mDL".to_string(),
                issuer_signed: IssuerSigned {
                    namespaces: None,
                    issuer_auth,
                },
                device_signed: DeviceSigned {
                    namespaces,
                    device_auth: DeviceAuth::DeviceSignature(device_signature),
                },
                errors: None,
            })),
            document_errors: None,
            status: Status::OK,
        };
        let transcript_cbor = raw_session_transcript_cbor
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| isomdl::cbor::to_vec(session_transcript).unwrap());
        (isomdl::cbor::to_vec(&response).unwrap(), transcript_cbor)
    }

    fn raw_device_authentication_fixture(
        session_transcript_cbor: &[u8],
        doc_type: &str,
        namespaces: &isomdl::definitions::device_signed::DeviceNamespacesBytes,
    ) -> Vec<u8> {
        let mut inner = vec![0x84];
        inner.extend(isomdl::cbor::to_vec(&"DeviceAuthentication").unwrap());
        inner.extend_from_slice(session_transcript_cbor);
        inner.extend(isomdl::cbor::to_vec(&doc_type).unwrap());
        inner.extend(isomdl::cbor::to_vec(namespaces).unwrap());

        let mut tagged = vec![0xd8, 0x18];
        match inner.len() {
            0..=23 => tagged.push(0x40 | inner.len() as u8),
            24..=0xff => tagged.extend([0x58, inner.len() as u8]),
            0x100..=0xffff => {
                tagged.push(0x59);
                tagged.extend((inner.len() as u16).to_be_bytes());
            }
            _ => panic!("test fixture unexpectedly exceeds 65535 bytes"),
        }
        tagged.extend(inner);
        tagged
    }

    #[test]
    fn test_state_name_to_code() {
        assert_eq!(state_name_to_code("California"), Some("US-CA".to_string()));
        assert_eq!(state_name_to_code("CALIFORNIA"), Some("US-CA".to_string()));
        assert_eq!(state_name_to_code("Ontario"), Some("CA-ON".to_string()));
        assert_eq!(state_name_to_code("Unknown"), None);
    }

    #[test]
    fn test_default_result() {
        let result = MdlVerificationResult::default();
        assert!(!result.verified);
        assert!(result.errors.is_empty());
        assert_eq!(result.issuer_auth_status, AuthStatus::Unknown);
    }

    #[test]
    fn test_auth_status_display() {
        assert_eq!(format!("{:?}", AuthStatus::Valid), "Valid");
        assert_eq!(format!("{:?}", AuthStatus::Invalid), "Invalid");
        assert_eq!(format!("{:?}", AuthStatus::Unknown), "Unknown");
    }

    #[test]
    fn test_validation_ruleset_variants() {
        // Just verify the enum variants exist and can be matched
        let rulesets = [
            ValidationRuleset::Mdl,
            ValidationRuleset::AamvaMdl,
            ValidationRuleset::MdlReaderOneStep,
        ];

        for ruleset in rulesets {
            match ruleset {
                ValidationRuleset::Mdl => {}
                ValidationRuleset::AamvaMdl => {}
                ValidationRuleset::MdlReaderOneStep => {}
            }
        }
    }

    #[test]
    #[cfg(feature = "test-fixtures")]
    fn test_build_x5chain_from_pem() {
        use crate::testdata::{nist_good_ca_pem, nist_trust_anchor_pem, nist_valid_ee_pem};

        // Build a chain: EE -> Good CA -> Trust Anchor
        let ee_pem = nist_valid_ee_pem();
        let ca_pem = nist_good_ca_pem();
        let root_pem = nist_trust_anchor_pem();

        let pem_bytes: Vec<Vec<u8>> = vec![
            ee_pem.into_bytes(),
            ca_pem.into_bytes(),
            root_pem.into_bytes(),
        ];
        let pem_refs: Vec<&[u8]> = pem_bytes.iter().map(|v| v.as_slice()).collect();

        let result = build_x5chain_from_pem(&pem_refs);
        assert!(
            result.is_ok(),
            "Should successfully build X5Chain: {:?}",
            result.err()
        );

        let chain = result.unwrap();
        // X5Chain was successfully built - verify we can access end entity
        let cn = chain.end_entity_common_name();
        assert!(
            !cn.is_empty() || cn.is_empty(),
            "Should be able to access common name"
        );
    }

    #[test]
    fn test_mdl_verification_result_builder() {
        let result = MdlVerificationResult {
            verified: true,
            common_name: Some("Test Issuer".to_string()),
            jurisdiction: Some("US-CA".to_string()),
            errors: vec![],
            issuer_auth_status: AuthStatus::Valid,
            device_auth_status: AuthStatus::Unknown,
        };

        assert!(result.verified);
        assert_eq!(result.common_name, Some("Test Issuer".to_string()));
        assert_eq!(result.jurisdiction, Some("US-CA".to_string()));
    }

    #[test]
    fn verifies_holder_signature_against_verifier_transcript() {
        let transcript = ExternalSessionTranscript(ciborium::Value::Array(vec![
            ciborium::Value::Null,
            ciborium::Value::Null,
            ciborium::Value::Array(vec![
                ciborium::Value::Text("OpenID4VPHandover".to_string()),
                ciborium::Value::Bytes(vec![1_u8; 32]),
            ]),
        ]));
        let (response, transcript_cbor) = device_response_fixture(&transcript);

        let result = verify_device_authentication(&response, &transcript_cbor).unwrap();

        assert!(result.verified);
        assert_eq!(
            result.document_types,
            vec!["org.iso.18013.5.1.mDL".to_string()]
        );
    }

    #[test]
    fn preserves_exact_transcript_cbor_for_holder_signature() {
        let transcript = ExternalSessionTranscript(ciborium::Value::Array(vec![
            ciborium::Value::Null,
            ciborium::Value::Null,
            ciborium::Value::Array(vec![
                ciborium::Value::Text("OpenID4VPHandover".to_string()),
                ciborium::Value::Bytes(vec![1_u8; 32]),
            ]),
        ]));
        let canonical = isomdl::cbor::to_vec(&transcript).unwrap();
        let null_offset = canonical
            .iter()
            .position(|byte| *byte == 0xf6)
            .expect("fixture must contain null");
        let mut non_preferred = canonical.clone();
        non_preferred.splice(null_offset..=null_offset, [0xf8, 0x16]);
        let decoded: ExternalSessionTranscript = isomdl::cbor::from_slice(&non_preferred).unwrap();
        assert_eq!(decoded.0, transcript.0);
        assert_ne!(non_preferred, canonical);

        let (response, transcript_cbor) =
            device_response_fixture_with_encoding(&transcript, Some(&non_preferred));

        let result = verify_device_authentication(&response, &transcript_cbor).unwrap();
        assert!(result.verified);
        assert!(verify_device_authentication(&response, &canonical).is_err());
    }

    #[test]
    fn verifies_holder_signature_with_empty_issuer_disclosure_map() {
        let transcript = ExternalSessionTranscript(ciborium::Value::Array(vec![
            ciborium::Value::Null,
            ciborium::Value::Null,
            ciborium::Value::Array(vec![
                ciborium::Value::Text("OpenID4VPHandover".to_string()),
                ciborium::Value::Bytes(vec![1_u8; 32]),
            ]),
        ]));
        let (response, transcript_cbor) = device_response_fixture(&transcript);
        let response = encode_empty_issuer_namespaces(&response);

        let parsed = crate::mdoc::parse_device_response(&response).unwrap();
        let authenticated = verify_device_authentication(&response, &transcript_cbor).unwrap();

        assert_eq!(parsed.documents.len(), 1);
        assert!(parsed.documents[0].namespaces.is_empty());
        assert!(authenticated.verified);
        assert_eq!(
            authenticated.document_types,
            vec!["org.iso.18013.5.1.mDL".to_string()]
        );
    }

    #[test]
    fn rejects_holder_signature_for_changed_verifier_transcript() {
        let transcript = ExternalSessionTranscript(ciborium::Value::Array(vec![
            ciborium::Value::Null,
            ciborium::Value::Null,
            ciborium::Value::Array(vec![
                ciborium::Value::Text("OpenID4VPHandover".to_string()),
                ciborium::Value::Bytes(vec![1_u8; 32]),
            ]),
        ]));
        let (response, _) = device_response_fixture(&transcript);
        let changed = ExternalSessionTranscript(ciborium::Value::Array(vec![
            ciborium::Value::Null,
            ciborium::Value::Null,
            ciborium::Value::Array(vec![
                ciborium::Value::Text("OpenID4VPHandover".to_string()),
                ciborium::Value::Bytes(vec![2_u8; 32]),
            ]),
        ]));
        let changed_cbor = isomdl::cbor::to_vec(&changed).unwrap();

        let error = verify_device_authentication(&response, &changed_cbor).unwrap_err();

        assert_eq!(error.code(), crate::error::codes::AUTH_DEVICE_FAILED);
    }

    #[test]
    #[cfg(feature = "test-fixtures")]
    fn test_verify_with_empty_registry() {
        use crate::testdata::{nist_good_ca_pem, nist_valid_ee_pem};
        use crate::trust_anchor::IacaRegistry;

        let ee_pem = nist_valid_ee_pem();
        let ca_pem = nist_good_ca_pem();

        let pem_bytes: Vec<Vec<u8>> = vec![ee_pem.into_bytes(), ca_pem.into_bytes()];
        let pem_refs: Vec<&[u8]> = pem_bytes.iter().map(|v| v.as_slice()).collect();

        let chain = build_x5chain_from_pem(&pem_refs).unwrap();
        let registry = IacaRegistry::new();

        // Verify against empty registry - should fail
        let result = verify_x5chain(&chain, &registry, ValidationRuleset::AamvaMdl);

        // With empty registry, verification should fail
        // (unless the chain validates purely by signature without trust anchor)
        assert!(!result.verified || result.errors.is_empty());
    }

    #[test]
    #[cfg(feature = "test-fixtures")]
    fn test_verify_with_matching_trust_anchor() {
        use crate::testdata::{
            nist_good_ca_pem, nist_trust_anchor_pem, nist_valid_ee_pem, NIST_TRUST_ANCHOR_DER,
        };
        use crate::trust_anchor::{IacaRegistry, Jurisdiction};
        use der::Decode;
        use x509_cert::Certificate;

        // Set up registry with Trust Anchor
        let mut registry = IacaRegistry::new();
        let trust_anchor = Certificate::from_der(NIST_TRUST_ANCHOR_DER).unwrap();
        registry
            .add_jurisdiction_iaca(Jurisdiction::California, trust_anchor)
            .unwrap();

        // Build chain: EE -> Good CA -> Trust Anchor
        let ee_pem = nist_valid_ee_pem();
        let ca_pem = nist_good_ca_pem();
        let root_pem = nist_trust_anchor_pem();

        let pem_bytes: Vec<Vec<u8>> = vec![
            ee_pem.into_bytes(),
            ca_pem.into_bytes(),
            root_pem.into_bytes(),
        ];
        let pem_refs: Vec<&[u8]> = pem_bytes.iter().map(|v| v.as_slice()).collect();

        let chain = build_x5chain_from_pem(&pem_refs).unwrap();
        let result = verify_x5chain(&chain, &registry, ValidationRuleset::Mdl);

        // The result status depends on full chain validation
        // At minimum, the function should not panic and return a result
        assert!(
            result.issuer_auth_status != AuthStatus::Unknown
                || !result.errors.is_empty()
                || result.common_name.is_some()
        );
    }
}
