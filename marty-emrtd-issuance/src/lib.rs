//! EF.SOD preparation and assembly without access to a document-signing key.
//!
//! The caller obtains a DSC certificate and an opaque signing reference from
//! its issuer profile, sends [`PreparedSod::signing_input`] to the authorized
//! KMS signing service, then calls [`PreparedSod::assemble`] with the returned
//! signature. This crate never accepts private-key material.

use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedAttributes, SignedData, SignerIdentifier,
        SignerInfo, SignerInfos,
    },
};
use const_oid::ObjectIdentifier;
use der::{
    asn1::{Any, OctetString, SetOfVec},
    AnyRef, Decode, Encode, Sequence, Tag,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{attr::Attribute, Certificate};

const LDS_SECURITY_OBJECT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.136.1.1.1");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// The issuer-profile algorithm used by the remote document signer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SodSignatureAlgorithm {
    Es256,
    Es384,
    Rs256,
    Ed25519,
}

impl TryFrom<&str> for SodSignatureAlgorithm {
    type Error = SodError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "ES256" => Ok(Self::Es256),
            "ES384" => Ok(Self::Es384),
            "RS256" => Ok(Self::Rs256),
            "EdDSA" => Ok(Self::Ed25519),
            _ => Err(SodError::UnsupportedAlgorithm),
        }
    }
}

impl SodSignatureAlgorithm {
    /// Canonical issuer-profile algorithm identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Rs256 => "RS256",
            Self::Ed25519 => "EdDSA",
        }
    }

    fn digest_oid(self) -> ObjectIdentifier {
        match self {
            Self::Es256 | Self::Rs256 => SHA256,
            Self::Es384 => SHA384,
            Self::Ed25519 => SHA512,
        }
    }

    fn digest(self, content: &[u8]) -> Vec<u8> {
        match self {
            Self::Es256 | Self::Rs256 => Sha256::digest(content).to_vec(),
            Self::Es384 => Sha384::digest(content).to_vec(),
            Self::Ed25519 => Sha512::digest(content).to_vec(),
        }
    }

    fn signature_identifier(self) -> Result<AlgorithmIdentifierOwned, SodError> {
        let (oid, parameters) = match self {
            Self::Es256 => (ECDSA_SHA256, None),
            Self::Es384 => (ECDSA_SHA384, None),
            Self::Rs256 => (RSA_SHA256, Some(Any::new(Tag::Null, Vec::new())?)),
            Self::Ed25519 => (ED25519, None),
        };
        Ok(AlgorithmIdentifierOwned { oid, parameters })
    }
}

/// Rejects malformed input and signatures without disclosing document data.
#[derive(Debug, thiserror::Error)]
pub enum SodError {
    #[error("Unsupported ICAO document-signer algorithm")]
    UnsupportedAlgorithm,
    #[error("SOD data groups must be unique ICAO numbers 1 through 20")]
    InvalidDataGroups,
    #[error("Document signer certificate is invalid")]
    InvalidCertificate,
    #[error("SOD ASN.1 construction failed")]
    Encoding(#[from] der::Error),
    #[error("Document signer signature does not match its certificate and signing input")]
    InvalidSignature,
}

#[derive(Clone, Debug, Sequence)]
struct DataGroupHash {
    number: u8,
    value: OctetString,
}

#[derive(Clone, Debug, Sequence)]
struct LdsSecurityObject {
    version: u8,
    hash_algorithm: AlgorithmIdentifierOwned,
    data_group_hash_values: Vec<DataGroupHash>,
}

/// Single-use prepared SOD. No private key, signing service credential, or
/// bearer token is stored in this value.
pub struct PreparedSod {
    algorithm: SodSignatureAlgorithm,
    certificate: Certificate,
    econtent: EncapsulatedContentInfo,
    attributes: SignedAttributes,
    signing_input: Vec<u8>,
}

impl PreparedSod {
    /// DER-encoded CMS signed attributes to send to the selected KMS signer.
    #[must_use]
    pub fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }

    /// The issuer-profile algorithm that must be used for this signature.
    #[must_use]
    pub const fn algorithm(&self) -> SodSignatureAlgorithm {
        self.algorithm
    }

    /// Verify the returned signature against the DSC public key before
    /// producing a DER-encoded CMS ContentInfo/EF.SOD.
    pub fn assemble(self, signature: &[u8]) -> Result<Vec<u8>, SodError> {
        let signature_algorithm = self.algorithm.signature_identifier()?;
        let public_key = self
            .certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()?;
        if !marty_crypto::algorithm_identifier::verify_signature_with_algorithm_identifier(
            &signature_algorithm,
            &public_key,
            &self.signing_input,
            signature,
        )
        .map_err(|_| SodError::InvalidSignature)?
        {
            return Err(SodError::InvalidSignature);
        }

        let digest_algorithm = AlgorithmIdentifierOwned {
            oid: self.algorithm.digest_oid(),
            parameters: None,
        };
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: self.certificate.tbs_certificate.issuer.clone(),
            serial_number: self.certificate.tbs_certificate.serial_number.clone(),
        });
        let signer = SignerInfo {
            version: CmsVersion::V1,
            sid,
            digest_alg: digest_algorithm.clone(),
            signed_attrs: Some(self.attributes),
            signature_algorithm,
            signature: OctetString::new(signature.to_vec())?,
            unsigned_attrs: None,
        };
        let signed_data = SignedData {
            // Non-id-data encapsulated content requires CMS version 3.
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::try_from(vec![digest_algorithm])?,
            encap_content_info: self.econtent,
            certificates: Some(CertificateSet::try_from(vec![
                CertificateChoices::Certificate(self.certificate),
            ])?),
            crls: None,
            signer_infos: SignerInfos::try_from(vec![signer])?,
        };
        let signed_data_der = signed_data.to_der()?;
        ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::from(AnyRef::try_from(signed_data_der.as_slice())?),
        }
        .to_der()
        .map_err(Into::into)
    }
}

/// Hash the raw EF.DG contents and prepare the keyless CMS signing input.
/// EF.SOD always uses SHA-256 for its LDS data-group hashes; the CMS signer
/// digest follows the selected issuer-profile signature algorithm.
pub fn prepare_sod(
    data_groups: &[(u8, Vec<u8>)],
    dsc_certificate_der: &[u8],
    algorithm: SodSignatureAlgorithm,
) -> Result<PreparedSod, SodError> {
    let mut groups = data_groups.to_vec();
    groups.sort_by_key(|(number, _)| *number);
    if groups.is_empty()
        || groups.len() > 20
        || groups.iter().any(|(number, _)| !(1..=20).contains(number))
        || groups.windows(2).any(|pair| pair[0].0 == pair[1].0)
    {
        return Err(SodError::InvalidDataGroups);
    }

    let certificate =
        Certificate::from_der(dsc_certificate_der).map_err(|_| SodError::InvalidCertificate)?;
    let hashes = groups
        .iter()
        .map(|(number, content)| {
            Ok(DataGroupHash {
                number: *number,
                value: OctetString::new(Sha256::digest(content).to_vec())?,
            })
        })
        .collect::<Result<Vec<_>, SodError>>()?;
    let lds_der = LdsSecurityObject {
        version: 0,
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: SHA256,
            parameters: None,
        },
        data_group_hash_values: hashes,
    }
    .to_der()?;
    let attributes = SetOfVec::try_from(vec![
        single_attribute(
            const_oid::db::rfc5911::ID_CONTENT_TYPE,
            Any::new(
                Tag::ObjectIdentifier,
                LDS_SECURITY_OBJECT.as_bytes().to_vec(),
            )?,
        )?,
        single_attribute(
            const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
            Any::new(Tag::OctetString, algorithm.digest(&lds_der))?,
        )?,
    ])?;
    let signing_input = attributes.to_der()?;
    let econtent = EncapsulatedContentInfo {
        econtent_type: LDS_SECURITY_OBJECT,
        econtent: Some(Any::new(Tag::OctetString, lds_der)?),
    };
    Ok(PreparedSod {
        algorithm,
        certificate,
        econtent,
        attributes,
        signing_input,
    })
}

fn single_attribute(oid: ObjectIdentifier, value: Any) -> Result<Attribute, SodError> {
    Ok(Attribute {
        oid,
        values: SetOfVec::try_from(vec![value])?,
    })
}
