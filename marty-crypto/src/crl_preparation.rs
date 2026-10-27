//! Public-certificate CRL preparation for an external signing service.
//! This module never holds or uses a private key.

use std::collections::BTreeSet;
use std::time::Duration;

use der::{
    asn1::{BitString, GeneralizedTime, OctetString, Uint, UtcTime},
    Decode, Encode,
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    crl::{CertificateList, RevokedCert, TbsCertList},
    ext::pkix::{
        AuthorityKeyIdentifier, BasicConstraints, CrlNumber, CrlReason, KeyUsage,
        SubjectKeyIdentifier,
    },
    ext::{AsExtension, Extension},
    serial_number::SerialNumber,
    time::Time,
    Certificate, Version,
};

use crate::{CryptoError, CryptoResult};

/// A revoked serial and its public revocation metadata.
#[derive(Clone, Copy)]
pub struct CrlRevocation<'a> {
    pub serial: &'a [u8],
    pub revoked_at_unix: u64,
    pub reason: CrlReason,
}

/// Immutable DER signing input bound to the issuer public certificate.
pub struct PreparedCrl {
    tbs: TbsCertList,
    tbs_der: Vec<u8>,
    issuer: Certificate,
}

impl PreparedCrl {
    /// The exact DER bytes to submit to the external KMS signer.
    pub fn signing_bytes(&self) -> &[u8] {
        &self.tbs_der
    }

    /// Assemble and authenticate a signature over the exact prepared TBS.
    /// The signature must use the certificate algorithm's X.509 wire encoding
    /// (for example, DER ECDSA rather than a JOSE concatenated signature).
    /// A lost or changed signing input cannot be finalized under this object.
    pub fn finalize(&self, signed_tbs: &[u8], signature: &[u8]) -> CryptoResult<Vec<u8>> {
        if signed_tbs != self.tbs_der || signature.is_empty() {
            return Err(CryptoError::crl(
                "CRL signing input or signature is invalid",
            ));
        }
        let spki = self
            .issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| CryptoError::crl(format!("issuer public key encoding failed: {e}")))?;
        if !crate::algorithm_identifier::verify_signature_with_algorithm_identifier(
            &self.tbs.signature,
            &spki,
            &self.tbs_der,
            signature,
        )? {
            return Err(CryptoError::crl(
                "external CRL signature does not match issuer and TBS",
            ));
        }
        let crl = CertificateList {
            tbs_cert_list: self.tbs.clone(),
            signature_algorithm: self.tbs.signature.clone(),
            signature: BitString::from_bytes(signature)
                .map_err(|e| CryptoError::crl(format!("invalid CRL signature bits: {e}")))?,
        };
        crl.to_der()
            .map_err(|e| CryptoError::crl(format!("CRL encoding failed: {e}")))
    }
}

/// Prepare a numbered v2 CRL using only an issuer public certificate and public entries.
/// The algorithm is explicit because a CA certificate may have been signed by a different key.
pub fn prepare_crl(
    issuer_der: &[u8],
    signature_algorithm: AlgorithmIdentifierOwned,
    number: u64,
    this_update_unix: u64,
    next_update_unix: u64,
    revoked: &[CrlRevocation<'_>],
) -> CryptoResult<PreparedCrl> {
    let issuer = Certificate::from_der(issuer_der)
        .map_err(|e| CryptoError::crl(format!("invalid issuer certificate: {e}")))?;
    if issuer.tbs_certificate.subject.is_empty() {
        return Err(CryptoError::crl(
            "CRL issuer has an empty distinguished name",
        ));
    }
    let constraints = issuer
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|e| CryptoError::crl(format!("invalid CA constraints: {e}")))?
        .ok_or_else(|| CryptoError::crl("issuer lacks CA constraints"))?
        .1;
    if !constraints.ca {
        return Err(CryptoError::crl("issuer is not a CA"));
    }
    let usage = issuer
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|e| CryptoError::crl(format!("invalid issuer key usage: {e}")))?
        .ok_or_else(|| CryptoError::crl("issuer lacks key usage"))?
        .1;
    if !usage.crl_sign() {
        return Err(CryptoError::crl("issuer cannot sign CRLs"));
    }
    let ski = issuer
        .tbs_certificate
        .get::<SubjectKeyIdentifier>()
        .map_err(|e| CryptoError::crl(format!("invalid subject key identifier: {e}")))?
        .ok_or_else(|| CryptoError::crl("issuer lacks subject key identifier"))?
        .1;
    if ski.0.as_bytes().is_empty() {
        return Err(CryptoError::crl("issuer has empty subject key identifier"));
    }
    if next_update_unix <= this_update_unix {
        return Err(CryptoError::crl("CRL validity interval is invalid"));
    }
    let this_update = crl_time(this_update_unix)?;
    let next_update = crl_time(next_update_unix)?;
    let mut serials = BTreeSet::new();
    let mut entries = Vec::with_capacity(revoked.len());
    for entry in revoked {
        // removeFromCRL is meaningful only for a delta CRL; this helper emits full CRLs.
        if entry.reason == CrlReason::RemoveFromCRL {
            return Err(CryptoError::crl("removeFromCRL requires a delta CRL"));
        }
        let serial = SerialNumber::new(entry.serial)
            .map_err(|e| CryptoError::crl(format!("invalid revoked serial: {e}")))?;
        if serial.as_bytes() == [0] || !serials.insert(serial.as_bytes().to_vec()) {
            return Err(CryptoError::crl("zero or duplicate revoked serial"));
        }
        if entry.revoked_at_unix > this_update_unix {
            return Err(CryptoError::crl("revocation date is after thisUpdate"));
        }
        let reason = entry
            .reason
            .to_extension(&issuer.tbs_certificate.subject, &[])
            .map_err(|e| CryptoError::crl(format!("invalid reason extension: {e}")))?;
        entries.push(RevokedCert {
            serial_number: serial,
            revocation_date: crl_time(entry.revoked_at_unix)?,
            crl_entry_extensions: Some(vec![reason]),
        });
    }
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(
            OctetString::new(ski.0.as_bytes())
                .map_err(|e| CryptoError::crl(format!("invalid authority key identifier: {e}")))?,
        ),
        ..Default::default()
    };
    let extensions: Vec<Extension> = vec![
        aki.to_extension(&issuer.tbs_certificate.subject, &[])
            .map_err(|e| CryptoError::crl(format!("invalid AKI extension: {e}")))?,
        CrlNumber(
            Uint::new(&number.to_be_bytes())
                .map_err(|e| CryptoError::crl(format!("invalid CRL number: {e}")))?,
        )
        .to_extension(&issuer.tbs_certificate.subject, &[])
        .map_err(|e| CryptoError::crl(format!("invalid CRL number extension: {e}")))?,
    ];
    let tbs = TbsCertList {
        version: Version::V2,
        signature: signature_algorithm,
        issuer: issuer.tbs_certificate.subject.clone(),
        this_update,
        next_update: Some(next_update),
        revoked_certificates: (!entries.is_empty()).then_some(entries),
        crl_extensions: Some(extensions),
    };
    let tbs_der = tbs
        .to_der()
        .map_err(|e| CryptoError::crl(format!("CRL TBS encoding failed: {e}")))?;
    Ok(PreparedCrl {
        tbs,
        tbs_der,
        issuer,
    })
}

fn crl_time(unix: u64) -> CryptoResult<Time> {
    // RFC 5280 section 5.1.2.4 uses UTCTime through 2049 and GeneralizedTime thereafter.
    let duration = Duration::from_secs(unix);
    if unix < 2_524_608_000 {
        UtcTime::from_unix_duration(duration)
            .map(Time::UtcTime)
            .map_err(|e| CryptoError::crl(format!("invalid CRL UTC date: {e}")))
    } else {
        GeneralizedTime::from_unix_duration(duration)
            .map(Time::GeneralTime)
            .map_err(|e| CryptoError::crl(format!("invalid CRL generalized date: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_vector() -> (Vec<u8>, CertificateList) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/crl_authenticated_public.json"
        ))
        .unwrap();
        let issuer = hex::decode(fixture["issuer_der_hex"].as_str().unwrap()).unwrap();
        let crl = CertificateList::from_der(
            &hex::decode(fixture["crl_der_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        (issuer, crl)
    }

    #[test]
    fn prepares_public_issuer_numbered_crl_with_aki_and_reason() {
        let (issuer, signed) = public_vector();
        let serial = signed.tbs_cert_list.revoked_certificates.as_ref().unwrap()[0]
            .serial_number
            .as_bytes();
        let prepared = prepare_crl(
            &issuer,
            signed.signature_algorithm.clone(),
            1,
            1_791_460_937,
            1_794_052_137,
            &[CrlRevocation {
                serial,
                revoked_at_unix: 1_791_460_937,
                reason: CrlReason::KeyCompromise,
            }],
        )
        .unwrap();
        let decoded = TbsCertList::from_der(prepared.signing_bytes()).unwrap();
        assert_eq!(decoded.version, Version::V2);
        assert_eq!(decoded.issuer, prepared.issuer.tbs_certificate.subject);
        assert!(matches!(decoded.this_update, Time::UtcTime(_)));
        let extensions = decoded.crl_extensions.as_ref().unwrap();
        assert_eq!(extensions.len(), 2);
        let aki = AuthorityKeyIdentifier::from_der(extensions[0].extn_value.as_bytes()).unwrap();
        let ski = prepared
            .issuer
            .tbs_certificate
            .get::<SubjectKeyIdentifier>()
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(aki.key_identifier.unwrap().as_bytes(), ski.0.as_bytes());
        let number = CrlNumber::from_der(extensions[1].extn_value.as_bytes()).unwrap();
        assert_eq!(number.0.as_bytes(), &[1]);
        let entries = decoded.revoked_certificates.as_ref().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].serial_number.as_bytes(), serial);
        let reason = CrlReason::from_der(
            entries[0].crl_entry_extensions.as_ref().unwrap()[0]
                .extn_value
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(reason, CrlReason::KeyCompromise);
        assert!(prepared
            .finalize(prepared.signing_bytes(), &[1, 2, 3])
            .is_err());
    }

    #[test]
    fn public_signed_vector_finalizes_only_exact_tbs_and_signature() {
        let (issuer_der, crl) = public_vector();
        let issuer = Certificate::from_der(&issuer_der).unwrap();
        let tbs_der = crl.tbs_cert_list.to_der().unwrap();
        let prepared = PreparedCrl {
            tbs: crl.tbs_cert_list.clone(),
            tbs_der: tbs_der.clone(),
            issuer,
        };
        let signature = crl.signature.as_bytes().unwrap();
        let final_der = prepared.finalize(&tbs_der, signature).unwrap();
        assert_eq!(CertificateList::from_der(&final_der).unwrap(), crl);
        let mut changed = tbs_der.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(prepared.finalize(&changed, signature).is_err());
        let mut wrong_signature = signature.to_vec();
        *wrong_signature.last_mut().unwrap() ^= 1;
        assert!(prepared.finalize(&tbs_der, &wrong_signature).is_err());
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/crl_authenticated_public.json"
        ))
        .unwrap();
        let wrong_issuer =
            Certificate::from_der(&hex::decode(fixture["leaf_der_hex"].as_str().unwrap()).unwrap())
                .unwrap();
        let wrong = PreparedCrl {
            tbs: crl.tbs_cert_list,
            tbs_der,
            issuer: wrong_issuer,
        };
        assert!(wrong.finalize(wrong.signing_bytes(), signature).is_err());
    }

    #[test]
    fn accepts_zero_number_and_rejects_invalid_interval_serial_and_duplicate() {
        let (issuer, crl) = public_vector();
        let algorithm = crl.signature_algorithm;
        let entry = CrlRevocation {
            serial: &[1],
            revoked_at_unix: 1,
            reason: CrlReason::KeyCompromise,
        };
        let initial = prepare_crl(&issuer, algorithm.clone(), 0, 2, 3, &[]).unwrap();
        let tbs = TbsCertList::from_der(initial.signing_bytes()).unwrap();
        let number = CrlNumber::from_der(
            tbs.crl_extensions.as_ref().unwrap()[1]
                .extn_value
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(number.0.as_bytes(), &[0]);
        assert!(prepare_crl(&issuer, algorithm.clone(), 1, 3, 2, &[]).is_err());
        assert!(prepare_crl(&issuer, algorithm.clone(), 1, 2, 3, &[entry, entry]).is_err());
        assert!(prepare_crl(
            &issuer,
            algorithm.clone(),
            1,
            2,
            3,
            &[CrlRevocation {
                serial: &[0],
                revoked_at_unix: 1,
                reason: CrlReason::KeyCompromise,
            }]
        )
        .is_err());
        assert!(prepare_crl(
            &issuer,
            algorithm,
            1,
            2,
            3,
            &[CrlRevocation {
                serial: &[1],
                revoked_at_unix: 1,
                reason: CrlReason::RemoveFromCRL,
            }]
        )
        .is_err());
        assert!(matches!(crl_time(2_524_607_999).unwrap(), Time::UtcTime(_)));
        assert!(matches!(
            crl_time(2_524_608_000).unwrap(),
            Time::GeneralTime(_)
        ));
    }

    #[test]
    fn rejects_leaf_and_empty_issuer_name_before_signing() {
        let (issuer_der, crl) = public_vector();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/crl_authenticated_public.json"
        ))
        .unwrap();
        let leaf = hex::decode(fixture["leaf_der_hex"].as_str().unwrap()).unwrap();
        assert!(prepare_crl(&leaf, crl.signature_algorithm.clone(), 1, 2, 3, &[]).is_err());

        // Alter only public certificate DER; no key, signature, or fixture regeneration.
        let mut issuer = Certificate::from_der(&issuer_der).unwrap();
        issuer.tbs_certificate.subject = x509_cert::name::RdnSequence(Vec::new());
        assert!(prepare_crl(
            &issuer.to_der().unwrap(),
            crl.signature_algorithm,
            1,
            2,
            3,
            &[]
        )
        .is_err());
    }
}
