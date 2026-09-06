//! Common CMS structure checks; document-specific verification policy stays in callers.

use crate::{VerificationError, VerificationResult};
use cms::signed_data::{CertificateSet, SignedData, SignerIdentifier, SignerInfo};
use der::Encode;
use x509_cert::Certificate;

#[derive(Clone, Copy)]
pub(super) enum DocumentKind {
    Sod,
    MasterList,
}

impl DocumentKind {
    fn name(self) -> &'static str {
        match self {
            Self::Sod => "SOD",
            Self::MasterList => "Master List",
        }
    }

    fn missing_certificate(self) -> &'static str {
        match self {
            Self::Sod => "No certificate matches the SOD signer identifier",
            Self::MasterList => "No embedded certificate matches the Master List signer",
        }
    }

    fn duplicate_certificate(self) -> &'static str {
        match self {
            Self::Sod => "Multiple certificates match the SOD signer identifier",
            Self::MasterList => "Multiple embedded certificates match the Master List signer",
        }
    }
}

pub(super) fn exactly_one_signer(
    signed_data: &SignedData,
    kind: DocumentKind,
) -> VerificationResult<&SignerInfo> {
    let mut signers = signed_data.signer_infos.0.iter();
    let signer = signers.next().ok_or_else(|| {
        VerificationError::der_error(format!("{} has no signer information", kind.name()))
    })?;
    if signers.next().is_some() {
        return Err(VerificationError::der_error(format!(
            "{} must contain exactly one signer",
            kind.name()
        )));
    }
    Ok(signer)
}

pub(super) fn find_signer_certificate<'a>(
    certs: &'a CertificateSet,
    signer_id: &SignerIdentifier,
    kind: DocumentKind,
) -> VerificationResult<&'a Certificate> {
    let mut matched = None;
    for choice in certs.0.iter() {
        let cms::cert::CertificateChoices::Certificate(cert) = choice else {
            continue;
        };
        if signer_id_matches(cert, signer_id)? {
            if matched.is_some() {
                return Err(VerificationError::der_error(
                    kind.duplicate_certificate().to_string(),
                ));
            }
            matched = Some(cert);
        }
    }
    matched.ok_or_else(|| VerificationError::der_error(kind.missing_certificate().to_string()))
}

pub(super) fn signer_id_matches(
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

pub(super) fn single_signed_attribute_value(
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

/// Verify the common CMS content binding and signature after caller-specific admission.
pub(super) fn verify_bound_signature(
    signed_data: &SignedData,
    signer_info: &SignerInfo,
    content: &[u8],
    public_key_der: &[u8],
) -> VerificationResult<bool> {
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
        public_key_der,
        &data_to_verify,
        signer_info.signature.as_bytes(),
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use cms::cert::CertificateChoices;
    use der::{asn1::SetOfVec, Any, Decode, Tag};
    use x509_cert::attr::{Attribute, Attributes};

    fn signed_data() -> SignedData {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/emrtd_verification_vectors.json"
        ))
        .unwrap();
        let der = base64::engine::general_purpose::STANDARD
            .decode(fixture["sod_der_base64"].as_str().unwrap())
            .unwrap();
        cms::content_info::ContentInfo::from_der(&der)
            .unwrap()
            .content
            .decode_as()
            .unwrap()
    }

    fn attribute(values: &[u8]) -> Attribute {
        Attribute {
            oid: const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
            values: SetOfVec::try_from(
                values
                    .iter()
                    .map(|value| Any::new(Tag::OctetString, vec![*value]).unwrap())
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        }
    }

    #[test]
    fn signed_attribute_requires_one_attribute_and_one_value() {
        let oid = const_oid::db::rfc5911::ID_MESSAGE_DIGEST;
        let valid = Attributes::try_from(vec![attribute(&[1])]).unwrap();
        assert_eq!(
            single_signed_attribute_value(&valid, oid).unwrap().value(),
            &[1]
        );
        for (attributes, message) in [
            (vec![], "Missing required CMS signed attribute"),
            (vec![attribute(&[])], "has no value"),
            (vec![attribute(&[1, 2])], "has multiple values"),
            (
                vec![attribute(&[1]), attribute(&[2])],
                "Duplicate CMS signed attribute",
            ),
        ] {
            let attributes = Attributes::try_from(attributes).unwrap();
            assert!(single_signed_attribute_value(&attributes, oid)
                .unwrap_err()
                .to_string()
                .contains(message));
        }
    }

    #[test]
    fn signer_count_preserves_document_context() {
        let valid = signed_data();
        for (kind, name) in [
            (DocumentKind::Sod, "SOD"),
            (DocumentKind::MasterList, "Master List"),
        ] {
            assert!(exactly_one_signer(&valid, kind).is_ok());
            let mut empty = valid.clone();
            empty.signer_infos.0 = SetOfVec::new();
            assert!(exactly_one_signer(&empty, kind)
                .unwrap_err()
                .to_string()
                .contains(&format!("{name} has no signer information")));
            let mut multiple = valid.clone();
            let mut second = valid.signer_infos.0.iter().next().unwrap().clone();
            second.signature = der::asn1::OctetString::new(vec![1]).unwrap();
            multiple.signer_infos.0.insert(second).unwrap();
            assert!(exactly_one_signer(&multiple, kind)
                .unwrap_err()
                .to_string()
                .contains(&format!("{name} must contain exactly one signer")));
        }
    }

    #[test]
    fn certificate_selection_requires_a_unique_identity_match() {
        let data = signed_data();
        let signer = data.signer_infos.0.iter().next().unwrap();
        let certs = data.certificates.as_ref().unwrap();
        for kind in [DocumentKind::Sod, DocumentKind::MasterList] {
            let cert = find_signer_certificate(certs, &signer.sid, kind).unwrap();
            let mut duplicate = cert.clone();
            // Different certificate encoding with the same issuer/serial identity.
            duplicate.tbs_certificate.subject = Default::default();
            let ambiguous = CertificateSet(
                SetOfVec::try_from(vec![
                    CertificateChoices::Certificate(cert.clone()),
                    CertificateChoices::Certificate(duplicate),
                ])
                .unwrap(),
            );
            assert!(find_signer_certificate(&ambiguous, &signer.sid, kind)
                .unwrap_err()
                .to_string()
                .contains(kind.duplicate_certificate()));
            let empty = CertificateSet(SetOfVec::new());
            assert!(find_signer_certificate(&empty, &signer.sid, kind)
                .unwrap_err()
                .to_string()
                .contains(kind.missing_certificate()));
            let ski = cert
                .tbs_certificate
                .get::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
                .unwrap()
                .unwrap()
                .1;
            assert!(signer_id_matches(cert, &SignerIdentifier::SubjectKeyIdentifier(ski)).unwrap());
            let missing =
                SignerIdentifier::SubjectKeyIdentifier(x509_cert::ext::pkix::SubjectKeyIdentifier(
                    der::asn1::OctetString::new(vec![0]).unwrap(),
                ));
            assert!(!signer_id_matches(cert, &missing).unwrap());
        }
    }
}
