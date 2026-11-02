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

/// Verify the common CMS envelope after the caller has admitted the document's
/// content type, content presence, signer count and certificate identity.
pub(super) fn verify_cms_signature(
    signed_data: &SignedData,
    signer: &SignerInfo,
    public_key_der: &[u8],
    content: &[u8],
) -> VerificationResult<bool> {
    let Some(input) = signature_input(signed_data, signer, content)? else {
        return Ok(false);
    };
    marty_crypto::algorithm_identifier::verify_signature_with_algorithm_identifier(
        &signer.signature_algorithm,
        public_key_der,
        &input,
        signer.signature.as_bytes(),
    )
    .map_err(Into::into)
}

/// `None` preserves the existing non-error verdict for content-type or digest
/// mismatches. Malformed or ambiguous attributes remain structural errors.
fn signature_input(
    signed_data: &SignedData,
    signer: &SignerInfo,
    content: &[u8],
) -> VerificationResult<Option<Vec<u8>>> {
    if !signed_data
        .digest_algorithms
        .iter()
        .any(|algorithm| algorithm.oid == signer.digest_alg.oid)
    {
        return Err(VerificationError::der_error(
            "Signer digest algorithm is absent from SignedData digestAlgorithms".to_string(),
        ));
    }
    let digest_algorithm =
        marty_crypto::HashAlgorithm::from_oid(&signer.digest_alg.oid.to_string())?;
    let input = if let Some(attributes) = &signer.signed_attrs {
        let content_type =
            single_signed_attribute_value(attributes, const_oid::db::rfc5911::ID_CONTENT_TYPE)?
                .decode_as::<der::asn1::ObjectIdentifier>()
                .map_err(|e| {
                    VerificationError::der_error(format!("Invalid contentType attribute: {e}"))
                })?;
        if content_type != signed_data.encap_content_info.econtent_type {
            return Ok(None);
        }
        let message_digest =
            single_signed_attribute_value(attributes, const_oid::db::rfc5911::ID_MESSAGE_DIGEST)?
                .decode_as::<der::asn1::OctetString>()
                .map_err(|e| {
                    VerificationError::der_error(format!("Invalid messageDigest attribute: {e}"))
                })?;
        if marty_crypto::hashing::hash(digest_algorithm, content) != message_digest.as_bytes() {
            return Ok(None);
        }
        attributes.to_der().map_err(|e| {
            VerificationError::internal(format!("Failed to encode signed attributes: {e}"))
        })?
    } else {
        content.to_vec()
    };
    Ok(Some(input))
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

    fn content_and_public_key(data: &SignedData) -> (Vec<u8>, Vec<u8>) {
        let signer = exactly_one_signer(data, DocumentKind::Sod).unwrap();
        let certificate = find_signer_certificate(
            data.certificates.as_ref().unwrap(),
            &signer.sid,
            DocumentKind::Sod,
        )
        .unwrap();
        (
            data.encap_content_info
                .econtent
                .as_ref()
                .unwrap()
                .value()
                .to_vec(),
            certificate
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap(),
        )
    }

    fn replace_attribute(
        signer: &SignerInfo,
        oid: der::asn1::ObjectIdentifier,
        replacements: Vec<Attribute>,
    ) -> SignerInfo {
        let mut signer = signer.clone();
        let mut attributes = signer
            .signed_attrs
            .as_ref()
            .unwrap()
            .iter()
            .filter(|attribute| attribute.oid != oid)
            .cloned()
            .collect::<Vec<_>>();
        attributes.extend(replacements);
        signer.signed_attrs = Some(Attributes::try_from(attributes).unwrap());
        signer
    }

    #[test]
    fn golden_signature_uses_der_set_of_signed_attributes() {
        let data = signed_data();
        let signer = exactly_one_signer(&data, DocumentKind::Sod).unwrap();
        let (content, public_key) = content_and_public_key(&data);
        let input = signature_input(&data, signer, &content).unwrap().unwrap();
        assert_eq!(
            input,
            signer.signed_attrs.as_ref().unwrap().to_der().unwrap()
        );
        // CMS signs the DER SET OF encoding, not the context-specific [0] tag
        // used to carry those same attributes within SignerInfo.
        assert_eq!(input.first(), Some(&0x31));
        assert_ne!(input, content);
        assert!(verify_cms_signature(&data, signer, &public_key, &content).unwrap());
    }

    #[test]
    fn absent_signed_attributes_preserve_raw_content_input_and_digest_admission() {
        let mut data = signed_data();
        let (content, _) = content_and_public_key(&data);
        let mut signer = exactly_one_signer(&data, DocumentKind::Sod)
            .unwrap()
            .clone();
        signer.signed_attrs = None;
        assert_eq!(
            signature_input(&data, &signer, &content).unwrap(),
            Some(content.clone())
        );
        data.digest_algorithms = SetOfVec::new();
        assert!(signature_input(&data, &signer, &content)
            .unwrap_err()
            .to_string()
            .contains("Signer digest algorithm is absent from SignedData digestAlgorithms"));

        // Even without signed attributes, the existing code admits the hash
        // algorithm before handing raw content to the signature verifier.
        signer.digest_alg.oid = der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4");
        data.digest_algorithms = SetOfVec::try_from(vec![signer.digest_alg.clone()]).unwrap();
        assert!(signature_input(&data, &signer, &content).is_err());
    }

    #[test]
    fn content_type_and_digest_mismatches_are_false_verdicts() {
        let data = signed_data();
        let signer = exactly_one_signer(&data, DocumentKind::Sod).unwrap();
        let (content, public_key) = content_and_public_key(&data);
        let oid = const_oid::db::rfc5911::ID_CONTENT_TYPE;
        let mismatched_type = Attribute {
            oid,
            values: SetOfVec::try_from(vec![Any::new(
                Tag::ObjectIdentifier,
                der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4").as_bytes(),
            )
            .unwrap()])
            .unwrap(),
        };
        let wrong_type = replace_attribute(signer, oid, vec![mismatched_type]);
        let wrong_digest = replace_attribute(
            signer,
            const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
            vec![attribute(&[0])],
        );
        for rejected in [wrong_type, wrong_digest] {
            assert!(signature_input(&data, &rejected, &content)
                .unwrap()
                .is_none());
            assert!(!verify_cms_signature(&data, &rejected, &public_key, &content).unwrap());
        }
        assert!(!verify_cms_signature(&data, signer, &public_key, b"altered content").unwrap());
    }

    #[test]
    fn malformed_required_attributes_remain_errors_in_the_signature_path() {
        let data = signed_data();
        let signer = exactly_one_signer(&data, DocumentKind::Sod).unwrap();
        let (content, public_key) = content_and_public_key(&data);
        for (oid, malformed_message) in [
            (
                const_oid::db::rfc5911::ID_CONTENT_TYPE,
                "Invalid contentType attribute",
            ),
            (
                const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
                "Invalid messageDigest attribute",
            ),
        ] {
            let entry = |values| Attribute { oid, values };
            let octets = |value| Any::new(Tag::OctetString, vec![value]).unwrap();
            let wrong_tag = Any::new(Tag::Integer, vec![1]).unwrap();
            for (replacements, expected) in [
                (vec![], "Missing required CMS signed attribute"),
                (vec![entry(SetOfVec::new())], "has no value"),
                (
                    vec![entry(
                        SetOfVec::try_from(vec![octets(1), octets(2)]).unwrap(),
                    )],
                    "has multiple values",
                ),
                (
                    vec![
                        entry(SetOfVec::try_from(vec![octets(1)]).unwrap()),
                        entry(SetOfVec::try_from(vec![octets(2)]).unwrap()),
                    ],
                    "Duplicate CMS signed attribute",
                ),
                (
                    vec![entry(SetOfVec::try_from(vec![wrong_tag]).unwrap())],
                    malformed_message,
                ),
            ] {
                let rejected = replace_attribute(signer, oid, replacements);
                assert!(
                    verify_cms_signature(&data, &rejected, &public_key, &content)
                        .unwrap_err()
                        .to_string()
                        .contains(expected)
                );
            }
        }
    }

    #[test]
    fn master_list_keeps_its_document_content_type_gate() {
        let data = signed_data();
        let signer = exactly_one_signer(&data, DocumentKind::Sod).unwrap();
        let certificate = find_signer_certificate(
            data.certificates.as_ref().unwrap(),
            &signer.sid,
            DocumentKind::Sod,
        )
        .unwrap();
        let cms = cms::content_info::ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::encode_from(&data).unwrap(),
        }
        .to_der()
        .unwrap();
        assert!(super::super::master_list::verify_master_list_signature(
            &cms,
            &certificate.to_der().unwrap(),
        )
        .unwrap_err()
        .to_string()
        .contains("Unexpected Master List encapsulated content type"));
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
