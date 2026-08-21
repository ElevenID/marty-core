//! Complete ISO 18013-5 issuer and holder authentication.
//!
//! This is the single reusable Rust implementation used by native services and
//! language bindings. Trust inputs are verifier-owned public certificates and
//! the session transcript is derived from verifier-owned request state.

use std::collections::HashMap;

use coset::{cbor::value::Value as CoseValue, iana, Label, RegisteredLabelWithPrivate};
use isomdl::definitions::device_response::{DeviceResponse, Status};
use isomdl::definitions::helpers::Tag24;
use isomdl::definitions::x509::x5chain::{X5Chain, X5CHAIN_COSE_HEADER_LABEL};
use isomdl::definitions::{DigestAlgorithm, Mso};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    mdoc::parse_device_response,
    verification::{
        mdl::{validate_document_signer_certificate_der, verify_issuer_signature},
        ChainValidator, ChainValidatorConfig,
    },
};

/// Signature-authenticated evidence for one mdoc document.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MdocDocumentVerificationEvidence {
    pub document_type: String,
    pub signature_algorithm: String,
    pub digest_algorithm: String,
    pub signed_at: String,
    pub valid_from: String,
    pub valid_until: String,
    pub issuer_certificate_sha256: String,
    pub validity_checked: bool,
    pub valid_at_verification_time: bool,
    /// Offline verification does not invent revocation evidence.
    pub revocation_checked: bool,
    pub not_revoked: Option<bool>,
}

/// Result of issuer-only authentication for a stored mdoc credential.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MdocIssuerVerificationResult {
    pub signature_valid: bool,
    pub issuer_trusted: bool,
    pub document_types: Vec<String>,
    pub document_evidence: Vec<MdocDocumentVerificationEvidence>,
    pub revocation_checked: bool,
    pub not_revoked: Option<bool>,
    pub error: Option<String>,
}

/// Result of complete OpenID4VP mdoc presentation authentication.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MdocPresentationVerificationResult {
    pub issuer_signature_valid: bool,
    pub issuer_trusted: bool,
    pub device_authentication_valid: bool,
    pub document_types: Vec<String>,
    pub document_evidence: Vec<MdocDocumentVerificationEvidence>,
    pub revocation_checked: bool,
    pub not_revoked: Option<bool>,
    pub error: Option<String>,
}

/// Authenticate issuer signatures and certificate chains at the current time.
#[must_use]
pub fn verify_mdoc_issuer(
    mdoc_bytes: &[u8],
    trusted_root_certs_pem: &[String],
    pinned_issuer_certs_pem: &[String],
) -> MdocIssuerVerificationResult {
    verify_mdoc_issuer_at(
        mdoc_bytes,
        trusted_root_certs_pem,
        pinned_issuer_certs_pem,
        OffsetDateTime::now_utc(),
    )
}

/// Authenticate issuer signatures and certificate chains at an explicit time.
#[must_use]
pub fn verify_mdoc_issuer_at(
    mdoc_bytes: &[u8],
    trusted_root_certs_pem: &[String],
    pinned_issuer_certs_pem: &[String],
    verification_time: OffsetDateTime,
) -> MdocIssuerVerificationResult {
    let issuer = verify_issuer_authentication(
        mdoc_bytes,
        trusted_root_certs_pem,
        pinned_issuer_certs_pem,
        verification_time,
    );
    MdocIssuerVerificationResult {
        signature_valid: issuer.signature_valid,
        issuer_trusted: issuer.issuer_trusted,
        document_types: issuer.document_types,
        document_evidence: issuer.document_evidence,
        revocation_checked: false,
        not_revoked: None,
        error: issuer.error,
    }
}

/// Authenticate issuer and holder proofs at the current time.
#[must_use]
pub fn verify_mdoc_presentation(
    mdoc_bytes: &[u8],
    session_transcript_cbor: &[u8],
    trusted_root_certs_pem: &[String],
    pinned_issuer_certs_pem: &[String],
) -> MdocPresentationVerificationResult {
    verify_mdoc_presentation_at(
        mdoc_bytes,
        session_transcript_cbor,
        trusted_root_certs_pem,
        pinned_issuer_certs_pem,
        OffsetDateTime::now_utc(),
    )
}

/// Authenticate issuer and holder proofs at an explicit verifier-owned time.
#[must_use]
pub fn verify_mdoc_presentation_at(
    mdoc_bytes: &[u8],
    session_transcript_cbor: &[u8],
    trusted_root_certs_pem: &[String],
    pinned_issuer_certs_pem: &[String],
    verification_time: OffsetDateTime,
) -> MdocPresentationVerificationResult {
    let issuer = verify_issuer_authentication(
        mdoc_bytes,
        trusted_root_certs_pem,
        pinned_issuer_certs_pem,
        verification_time,
    );
    let mut errors = issuer.error.into_iter().collect::<Vec<_>>();
    let (device_authentication_valid, device_document_types) =
        match crate::verify_device_authentication(mdoc_bytes, session_transcript_cbor) {
            Ok(result) => (result.verified, result.document_types),
            Err(error) => {
                errors.push(format!("Holder device authentication failed: {error}"));
                (false, Vec::new())
            }
        };
    let document_types = if issuer.document_types.is_empty() {
        device_document_types
    } else {
        issuer.document_types
    };

    MdocPresentationVerificationResult {
        issuer_signature_valid: issuer.signature_valid,
        issuer_trusted: issuer.issuer_trusted,
        device_authentication_valid,
        document_types,
        document_evidence: issuer.document_evidence,
        revocation_checked: false,
        not_revoked: None,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

/// Extract disclosed fields only after the caller has authenticated the mdoc.
pub fn disclosed_claims(mdoc_bytes: &[u8]) -> Result<serde_json::Value, String> {
    let response = parse_valid_device_response(mdoc_bytes)?;
    Ok(disclosed_claims_from_response(&response))
}

fn disclosed_claims_from_response(response: &crate::mdoc::DeviceResponse) -> serde_json::Value {
    let fields = response.get_disclosed_fields();
    let mut element_counts: HashMap<&str, usize> = HashMap::new();
    for field in &fields {
        *element_counts
            .entry(field.element_identifier.as_str())
            .or_default() += 1;
    }

    let mut claims = serde_json::Map::new();
    for field in &fields {
        if element_counts.get(field.element_identifier.as_str()) == Some(&1) {
            claims.insert(
                field.element_identifier.clone(),
                field.element_value.clone(),
            );
        }
    }
    let documents = response
        .documents
        .iter()
        .map(|document| {
            let namespaces = document
                .namespaces
                .iter()
                .map(|(namespace, items)| {
                    let elements = items
                        .iter()
                        .map(|item| (item.element_identifier.clone(), item.element_value.clone()))
                        .collect::<serde_json::Map<_, _>>();
                    (namespace.clone(), serde_json::Value::Object(elements))
                })
                .collect::<serde_json::Map<_, _>>();
            serde_json::json!({
                "doc_type": document.doc_type,
                "namespaces": namespaces,
            })
        })
        .collect::<Vec<_>>();
    claims.insert(
        "_mdoc".to_string(),
        serde_json::json!({"documents": documents}),
    );
    serde_json::Value::Object(claims)
}

/// Parse and validate the ISO-compatible DeviceResponse envelope.
pub fn parse_valid_device_response(
    mdoc_bytes: &[u8],
) -> Result<crate::mdoc::DeviceResponse, String> {
    let response = parse_device_response(mdoc_bytes)
        .map_err(|error| format!("Failed to parse mdoc DeviceResponse: {error}"))?;
    if response.version != "1.0" || response.status != 0 {
        return Err("mdoc DeviceResponse version or status is invalid".to_string());
    }
    if response.documents.is_empty() {
        return Err("mdoc DeviceResponse contains no documents".to_string());
    }
    Ok(response)
}

struct IssuerAuthenticationResult {
    signature_valid: bool,
    issuer_trusted: bool,
    document_types: Vec<String>,
    document_evidence: Vec<MdocDocumentVerificationEvidence>,
    error: Option<String>,
}

fn verify_issuer_authentication(
    mdoc_bytes: &[u8],
    trusted_root_certs_pem: &[String],
    pinned_issuer_certs_pem: &[String],
    verification_time: OffsetDateTime,
) -> IssuerAuthenticationResult {
    let response: DeviceResponse = match isomdl::cbor::from_slice(mdoc_bytes) {
        Ok(response) => response,
        Err(error) => {
            return issuer_failure(format!("Failed to parse mdoc DeviceResponse: {error}"));
        }
    };
    if response.version != DeviceResponse::VERSION || !matches!(response.status, Status::OK) {
        return issuer_failure("mdoc DeviceResponse version or status is invalid");
    }
    let Some(documents) = response.documents.as_ref() else {
        return issuer_failure("mdoc DeviceResponse contains no documents");
    };
    let document_types = documents
        .iter()
        .map(|document| document.doc_type.clone())
        .collect::<Vec<_>>();

    let mut root_validator = ChainValidator::new();
    let mut trust_configuration_valid =
        !trusted_root_certs_pem.is_empty() || !pinned_issuer_certs_pem.is_empty();
    let mut errors = Vec::new();
    if !trust_configuration_valid {
        errors.push("No trusted issuer certificates were configured".to_string());
    }
    for trusted_cert in trusted_root_certs_pem {
        if let Err(error) = root_validator.add_trust_anchor_pem(trusted_cert) {
            trust_configuration_valid = false;
            errors.push(format!("Invalid mdoc root certificate: {error}"));
        }
    }
    let mut pinned_issuer_certs_der = Vec::with_capacity(pinned_issuer_certs_pem.len());
    for pinned_cert in pinned_issuer_certs_pem {
        match certificate_der_from_pem(pinned_cert) {
            Ok(certificate) => pinned_issuer_certs_der.push(certificate),
            Err(error) => {
                trust_configuration_valid = false;
                errors.push(format!("Invalid pinned mdoc issuer certificate: {error}"));
            }
        }
    }

    let mut all_signatures_valid = true;
    let mut issuer_trusted = trust_configuration_valid;
    let mut document_evidence = Vec::with_capacity(documents.len());
    for document in documents.iter() {
        let issuer_auth = &document.issuer_signed.issuer_auth;
        let x5chain_value = issuer_auth
            .protected
            .header
            .rest
            .iter()
            .chain(issuer_auth.unprotected.rest.iter())
            .find_map(|(label, value)| {
                (label == &Label::Int(X5CHAIN_COSE_HEADER_LABEL)).then_some(value)
            });
        let Some(x5chain_value) = x5chain_value else {
            all_signatures_valid = false;
            issuer_trusted = false;
            errors.push(format!(
                "No issuer certificate chain in issuerAuth for {}",
                document.doc_type
            ));
            continue;
        };
        let certificate_chain = match certificate_chain_der(x5chain_value) {
            Ok(chain) => chain,
            Err(error) => {
                all_signatures_valid = false;
                issuer_trusted = false;
                errors.push(format!(
                    "Invalid issuer certificate chain for {}: {error}",
                    document.doc_type
                ));
                continue;
            }
        };
        let x5chain = match X5Chain::from_cbor(x5chain_value.clone()) {
            Ok(chain) => chain,
            Err(error) => {
                all_signatures_valid = false;
                issuer_trusted = false;
                errors.push(format!(
                    "Invalid issuer x5chain for {}: {error}",
                    document.doc_type
                ));
                continue;
            }
        };
        if let Err(error) = verify_issuer_signature(&x5chain, &document.issuer_signed) {
            all_signatures_valid = false;
            issuer_trusted = false;
            errors.push(format!(
                "Signature verification failed for {}: {error}",
                document.doc_type
            ));
            continue;
        }
        if trust_configuration_valid {
            if let Err(error) = verify_issuer_trust(
                &certificate_chain,
                &root_validator,
                &pinned_issuer_certs_der,
            ) {
                issuer_trusted = false;
                errors.push(format!(
                    "Issuer certificate trust validation failed for {}: {error}",
                    document.doc_type
                ));
            }
        } else {
            issuer_trusted = false;
        }
        match authenticated_document_evidence(document, &certificate_chain[0], verification_time) {
            Ok(evidence) => document_evidence.push(evidence),
            Err(error) => {
                all_signatures_valid = false;
                issuer_trusted = false;
                errors.push(format!(
                    "Authenticated MSO evidence is invalid for {}: {error}",
                    document.doc_type
                ));
            }
        }
    }

    IssuerAuthenticationResult {
        signature_valid: all_signatures_valid,
        issuer_trusted,
        document_types,
        document_evidence,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    }
}

fn authenticated_document_evidence(
    document: &isomdl::definitions::device_response::Document,
    issuer_certificate_der: &[u8],
    verification_time: OffsetDateTime,
) -> Result<MdocDocumentVerificationEvidence, String> {
    let signature_algorithm = match document
        .issuer_signed
        .issuer_auth
        .protected
        .header
        .alg
        .as_ref()
    {
        Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256)) => "ES256",
        Some(_) => return Err("unsupported issuer signature algorithm".to_string()),
        None => return Err("issuer signature algorithm is not protected".to_string()),
    };
    let mso_bytes = document
        .issuer_signed
        .issuer_auth
        .payload
        .as_ref()
        .ok_or_else(|| "issuerAuth payload is detached".to_string())?;
    let mso = isomdl::cbor::from_slice::<Tag24<Mso>>(mso_bytes)
        .map_err(|error| format!("unable to parse MSO: {error}"))?
        .into_inner();
    validated_mso_evidence(
        &mso,
        &document.doc_type,
        signature_algorithm,
        issuer_certificate_der,
        verification_time,
    )
}

fn validated_mso_evidence(
    mso: &Mso,
    authenticated_document_type: &str,
    signature_algorithm: &str,
    issuer_certificate_der: &[u8],
    verification_time: OffsetDateTime,
) -> Result<MdocDocumentVerificationEvidence, String> {
    if mso.version != "1.0" {
        return Err(format!("unsupported MSO version {}", mso.version));
    }
    if mso.doc_type != authenticated_document_type {
        return Err("MSO document type does not match the authenticated document".to_string());
    }
    if mso.validity_info.signed > mso.validity_info.valid_from
        || mso.validity_info.valid_from > mso.validity_info.valid_until
    {
        return Err("MSO validity window is contradictory".to_string());
    }
    if verification_time < mso.validity_info.valid_from {
        return Err("MSO is not yet valid".to_string());
    }
    if verification_time > mso.validity_info.valid_until {
        return Err("MSO is expired".to_string());
    }

    let digest_algorithm = match mso.digest_algorithm {
        DigestAlgorithm::SHA256 => "SHA-256",
        DigestAlgorithm::SHA384 => "SHA-384",
        DigestAlgorithm::SHA512 => "SHA-512",
    };
    let format_time = |value: OffsetDateTime| {
        value
            .format(&Rfc3339)
            .map_err(|error| format!("unable to format MSO validity timestamp: {error}"))
    };
    let certificate_digest = marty_crypto::hashing::hash_sha256(issuer_certificate_der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    Ok(MdocDocumentVerificationEvidence {
        document_type: authenticated_document_type.to_string(),
        signature_algorithm: signature_algorithm.to_string(),
        digest_algorithm: digest_algorithm.to_string(),
        signed_at: format_time(mso.validity_info.signed)?,
        valid_from: format_time(mso.validity_info.valid_from)?,
        valid_until: format_time(mso.validity_info.valid_until)?,
        issuer_certificate_sha256: certificate_digest,
        validity_checked: true,
        valid_at_verification_time: true,
        revocation_checked: false,
        not_revoked: None,
    })
}

fn certificate_der_from_pem(pem: &str) -> Result<Vec<u8>, String> {
    let (label, der) = pem_rfc7468::decode_vec(pem.as_bytes())
        .map_err(|error| format!("invalid PEM encoding: {error}"))?;
    if label != "CERTIFICATE" {
        return Err(format!("expected CERTIFICATE PEM label, found {label}"));
    }
    if der.is_empty() {
        return Err("certificate DER is empty".to_string());
    }
    Ok(der)
}

fn verify_issuer_trust(
    certificate_chain: &[Vec<u8>],
    root_validator: &ChainValidator,
    pinned_issuer_certs_der: &[Vec<u8>],
) -> Result<(), String> {
    let Some(leaf_certificate) = certificate_chain.first() else {
        return Err("issuer certificate chain is empty".to_string());
    };
    validate_document_signer_certificate_der(leaf_certificate)
        .map_err(|error| format!("invalid mdoc document-signer certificate profile: {error}"))?;

    if pinned_issuer_certs_der
        .iter()
        .any(|pinned| pinned == leaf_certificate)
    {
        let mut direct_pin_validator = ChainValidator::with_config(ChainValidatorConfig {
            required_key_usage: Vec::new(),
            ..Default::default()
        });
        direct_pin_validator
            .add_trust_anchor_der(
                certificate_chain
                    .last()
                    .expect("non-empty certificate chain checked above"),
            )
            .map_err(|error| format!("invalid direct-pin chain terminus: {error}"))?;
        return match direct_pin_validator.validate_chain_der(certificate_chain) {
            Ok(validation) if validation.valid => Ok(()),
            Ok(validation) => Err(format!(
                "directly pinned issuer certificate is invalid: {}",
                validation.errors.join("; ")
            )),
            Err(error) => Err(format!(
                "directly pinned issuer certificate validation failed: {error}"
            )),
        };
    }

    match root_validator.validate_chain_der(certificate_chain) {
        Ok(validation) if validation.valid => Ok(()),
        Ok(validation) => Err(format!(
            "certificate chain does not validate to a configured root: {}",
            validation.errors.join("; ")
        )),
        Err(error) => Err(format!("certificate chain validation failed: {error}")),
    }
}

fn issuer_failure(error: impl Into<String>) -> IssuerAuthenticationResult {
    IssuerAuthenticationResult {
        signature_valid: false,
        issuer_trusted: false,
        document_types: Vec::new(),
        document_evidence: Vec::new(),
        error: Some(error.into()),
    }
}

fn certificate_chain_der(value: &CoseValue) -> Result<Vec<Vec<u8>>, &'static str> {
    match value {
        CoseValue::Bytes(certificate) if !certificate.is_empty() => Ok(vec![certificate.clone()]),
        CoseValue::Array(certificates) if !certificates.is_empty() => certificates
            .iter()
            .map(|certificate| match certificate {
                CoseValue::Bytes(bytes) if !bytes.is_empty() => Ok(bytes.clone()),
                _ => Err("x5chain entries must be non-empty byte strings"),
            })
            .collect(),
        _ => Err("x5chain must be a byte string or non-empty array"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdoc::{DeviceResponse as ParsedDeviceResponse, Document, IssuerSignedItem};

    #[test]
    fn certificate_chain_accepts_single_or_multiple_der_certificates() {
        assert_eq!(
            certificate_chain_der(&CoseValue::Bytes(vec![1, 2, 3])),
            Ok(vec![vec![1, 2, 3]])
        );
        assert_eq!(
            certificate_chain_der(&CoseValue::Array(vec![
                CoseValue::Bytes(vec![1]),
                CoseValue::Bytes(vec![2]),
            ])),
            Ok(vec![vec![1], vec![2]])
        );
    }

    #[test]
    fn certificate_chain_rejects_empty_or_non_binary_values() {
        assert!(certificate_chain_der(&CoseValue::Bytes(vec![])).is_err());
        assert!(certificate_chain_der(&CoseValue::Array(vec![])).is_err());
        assert!(certificate_chain_der(&CoseValue::Array(vec![CoseValue::Null])).is_err());
    }

    fn mso_with_validity(valid_from: OffsetDateTime, valid_until: OffsetDateTime) -> Mso {
        use isomdl::definitions::device_key::cose_key::EC2Y;
        use isomdl::definitions::{DeviceKeyInfo, ValidityInfo};
        use std::collections::BTreeMap;

        Mso {
            version: "1.0".to_string(),
            digest_algorithm: DigestAlgorithm::SHA256,
            value_digests: BTreeMap::new(),
            device_key_info: DeviceKeyInfo {
                device_key: isomdl::definitions::device_key::CoseKey::EC2 {
                    crv: isomdl::definitions::device_key::EC2Curve::P256,
                    x: vec![1; 32],
                    y: EC2Y::Value(vec![2; 32]),
                },
                key_authorizations: None,
                key_info: None,
            },
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            validity_info: ValidityInfo {
                signed: valid_from - time::Duration::minutes(1),
                valid_from,
                valid_until,
                expected_update: None,
            },
        }
    }

    #[test]
    fn authenticated_mso_evidence_is_typed_without_inventing_revocation() {
        let now = OffsetDateTime::parse("2026-08-09T12:00:00Z", &Rfc3339).unwrap();
        let mso = mso_with_validity(
            now - time::Duration::hours(1),
            now + time::Duration::hours(1),
        );

        let evidence = validated_mso_evidence(
            &mso,
            "org.iso.18013.5.1.mDL",
            "ES256",
            b"issuer-certificate",
            now,
        )
        .unwrap();

        assert_eq!(evidence.document_type, "org.iso.18013.5.1.mDL");
        assert_eq!(evidence.signature_algorithm, "ES256");
        assert_eq!(evidence.digest_algorithm, "SHA-256");
        assert_eq!(evidence.signed_at, "2026-08-09T10:59:00Z");
        assert_eq!(evidence.valid_from, "2026-08-09T11:00:00Z");
        assert_eq!(evidence.valid_until, "2026-08-09T13:00:00Z");
        assert_eq!(evidence.issuer_certificate_sha256.len(), 64);
        assert!(evidence
            .issuer_certificate_sha256
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()));
        assert!(evidence.validity_checked);
        assert!(evidence.valid_at_verification_time);
        assert!(!evidence.revocation_checked);
        assert_eq!(evidence.not_revoked, None);
    }

    #[test]
    fn authenticated_mso_evidence_rejects_type_and_validity_failures() {
        let now = OffsetDateTime::parse("2026-08-09T12:00:00Z", &Rfc3339).unwrap();
        let valid = mso_with_validity(
            now - time::Duration::hours(1),
            now + time::Duration::hours(1),
        );
        assert!(validated_mso_evidence(&valid, "wrong.type", "ES256", b"cert", now).is_err());

        let future = mso_with_validity(
            now + time::Duration::seconds(1),
            now + time::Duration::hours(1),
        );
        assert!(
            validated_mso_evidence(&future, "org.iso.18013.5.1.mDL", "ES256", b"cert", now,)
                .unwrap_err()
                .contains("not yet valid")
        );

        let expired = mso_with_validity(
            now - time::Duration::hours(1),
            now - time::Duration::seconds(1),
        );
        assert!(
            validated_mso_evidence(&expired, "org.iso.18013.5.1.mDL", "ES256", b"cert", now,)
                .unwrap_err()
                .contains("expired")
        );

        let mut contradictory = valid;
        contradictory.validity_info.signed =
            contradictory.validity_info.valid_from + time::Duration::seconds(1);
        assert!(validated_mso_evidence(
            &contradictory,
            "org.iso.18013.5.1.mDL",
            "ES256",
            b"cert",
            now,
        )
        .unwrap_err()
        .contains("validity window is contradictory"));
    }

    #[test]
    fn direct_pin_requires_a_valid_mdoc_document_signer_profile() {
        use rcgen::{CertificateParams, DnType, KeyPair, KeyUsagePurpose};

        fn certificate(
            name: &str,
            is_ca: rcgen::IsCa,
            key_usages: Vec<KeyUsagePurpose>,
        ) -> (Vec<u8>, String) {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::default();
            params.distinguished_name.push(DnType::CommonName, name);
            params.is_ca = is_ca;
            params.key_usages = key_usages;
            let certificate = params.self_signed(&key).unwrap();
            (certificate.der().to_vec(), certificate.pem())
        }

        let (_, unrelated_root_pem) = certificate(
            "Unrelated mdoc root",
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        );
        let mut validator = crate::verification::ChainValidator::new();
        validator.add_trust_anchor_pem(&unrelated_root_pem).unwrap();
        let (valid_der, valid_pem) = certificate(
            "Pinned mdoc document signer",
            rcgen::IsCa::ExplicitNoCa,
            vec![KeyUsagePurpose::DigitalSignature],
        );
        let direct_pin = certificate_der_from_pem(&valid_pem).unwrap();
        let valid =
            verify_issuer_trust(std::slice::from_ref(&valid_der), &validator, &[direct_pin]);
        assert!(
            valid.is_ok(),
            "valid document signer was rejected: {valid:?}"
        );

        let (ca_der, _) = certificate(
            "Pinned CA is not a document signer",
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        );
        let error = verify_issuer_trust(
            std::slice::from_ref(&ca_der),
            &validator,
            std::slice::from_ref(&ca_der),
        )
        .unwrap_err();
        assert!(error.contains("must not be a CA"));

        let (issuer_usage_der, _) = certificate(
            "Pinned IACA usage is not a document signer",
            rcgen::IsCa::ExplicitNoCa,
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        );
        let error = verify_issuer_trust(
            std::slice::from_ref(&issuer_usage_der),
            &validator,
            std::slice::from_ref(&issuer_usage_der),
        )
        .unwrap_err();
        assert!(error.contains("DigitalSignature only"));

        let (missing_usage_der, _) = certificate(
            "Pinned certificate without key usage",
            rcgen::IsCa::ExplicitNoCa,
            Vec::new(),
        );
        let error = verify_issuer_trust(
            std::slice::from_ref(&missing_usage_der),
            &validator,
            std::slice::from_ref(&missing_usage_der),
        )
        .unwrap_err();
        assert!(error.contains("Required extension 2.5.29.15 missing"));

        let (incompatible_usage_der, _) = certificate(
            "Pinned certificate with mixed key usage",
            rcgen::IsCa::ExplicitNoCa,
            vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ],
        );
        let error = verify_issuer_trust(
            std::slice::from_ref(&incompatible_usage_der),
            &validator,
            std::slice::from_ref(&incompatible_usage_der),
        )
        .unwrap_err();
        assert!(error.contains("DigitalSignature only"));

        assert!(verify_issuer_trust(
            std::slice::from_ref(&valid_der),
            &validator,
            &[vec![1, 2, 3]],
        )
        .is_err());
    }

    #[test]
    fn disclosed_claims_include_dtc_fields_and_structured_paths() {
        let response = ParsedDeviceResponse {
            version: "1.0".to_string(),
            documents: vec![Document {
                doc_type: "com.icao.dtc".to_string(),
                namespaces: HashMap::from([(
                    "com.icao.dtc".to_string(),
                    vec![IssuerSignedItem {
                        digest_id: 7,
                        random: vec![1],
                        element_identifier: "document_number".to_string(),
                        element_value: serde_json::json!("PMB09A5929"),
                    }],
                )]),
                mso: None,
                issuer_cert_chain: Vec::new(),
            }],
            status: 0,
        };

        assert_eq!(
            disclosed_claims_from_response(&response),
            serde_json::json!({
                "document_number": "PMB09A5929",
                "_mdoc": {
                    "documents": [{
                        "doc_type": "com.icao.dtc",
                        "namespaces": {
                            "com.icao.dtc": {
                                "document_number": "PMB09A5929"
                            }
                        }
                    }]
                }
            })
        );
    }

    #[test]
    fn disclosed_claims_omit_ambiguous_flat_keys() {
        let item = |value| IssuerSignedItem {
            digest_id: 0,
            random: Vec::new(),
            element_identifier: "document_number".to_string(),
            element_value: serde_json::json!(value),
        };
        let response = ParsedDeviceResponse {
            version: "1.0".to_string(),
            documents: vec![Document {
                doc_type: "example.document".to_string(),
                namespaces: HashMap::from([
                    ("example.one".to_string(), vec![item("one")]),
                    ("example.two".to_string(), vec![item("two")]),
                ]),
                mso: None,
                issuer_cert_chain: Vec::new(),
            }],
            status: 0,
        };

        let claims = disclosed_claims_from_response(&response);
        assert!(claims.get("document_number").is_none());
        assert_eq!(
            claims["_mdoc"]["documents"][0]["namespaces"]["example.one"]["document_number"],
            "one"
        );
        assert_eq!(
            claims["_mdoc"]["documents"][0]["namespaces"]["example.two"]["document_number"],
            "two"
        );
    }

    #[test]
    fn malformed_presentations_fail_closed_without_panicking() {
        let result = verify_mdoc_presentation(&[0xff], &[0x83, 0xf6, 0xf6, 0x82, 0x71], &[], &[]);
        assert!(!result.issuer_signature_valid);
        assert!(!result.issuer_trusted);
        assert!(!result.device_authentication_valid);
        assert!(result.document_evidence.is_empty());
        assert!(!result.revocation_checked);
        assert_eq!(result.not_revoked, None);
        assert!(result.error.is_some());
    }

    #[test]
    fn disclosed_claims_preserve_paths_and_omit_ambiguous_flat_keys() {
        let item = |namespace: &str, value: &str| IssuerSignedItem {
            digest_id: 0,
            random: Vec::new(),
            element_identifier: "document_number".to_string(),
            element_value: serde_json::json!(format!("{namespace}:{value}")),
        };
        let response = ParsedDeviceResponse {
            version: "1.0".to_string(),
            documents: vec![Document {
                doc_type: "com.icao.dtc".to_string(),
                namespaces: HashMap::from([
                    ("example.one".to_string(), vec![item("one", "1")]),
                    ("example.two".to_string(), vec![item("two", "2")]),
                ]),
                mso: None,
                issuer_cert_chain: Vec::new(),
            }],
            status: 0,
        };
        let fields = response.get_disclosed_fields();
        assert_eq!(fields.len(), 2);
        let mut counts = HashMap::new();
        for field in fields {
            *counts.entry(field.element_identifier).or_insert(0) += 1;
        }
        assert_eq!(counts["document_number"], 2);
    }

    #[test]
    fn certificate_chain_shape_is_bounded_to_binary_entries() {
        assert_eq!(
            certificate_chain_der(&CoseValue::Bytes(vec![1, 2, 3])),
            Ok(vec![vec![1, 2, 3]])
        );
        assert!(certificate_chain_der(&CoseValue::Array(vec![])).is_err());
        assert!(certificate_chain_der(&CoseValue::Array(vec![CoseValue::Null])).is_err());
    }
}
