//! Private, transport-independent verification of an ICAO TD3 digital handoff package.
//!
//! This reuses the existing eMRTD chain, SOD signature, and data-group hash
//! verifier. Flow, KMS profile custody, encryption, and reviewer receipts are
//! separate checks performed by the calling service before a handoff is ready.

use std::collections::{BTreeMap, HashMap};

use der::{Decode, Encode, Tag, Tagged};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_cert::Certificate;

use crate::emrtd_data::{
    extract_ef_dg1_mrz, parse_elementary_file, parse_icao_ef_dg2, validate_icao_optional_dg,
    verify_icao_39794_face, verify_icao_image, IcaoFaceBiometric,
};
use crate::mrz::{parse_mrz, MrzFormat};
use crate::trust_anchor::CscaRegistry;
use crate::verification::emrtd::{verify_emrtd, SecurityObject};
use crate::verification::passport_country_codes::alpha2_for_alpha3;

/// Exact protected bytes from one immutable package revision.
pub struct DigitalPassportPackage<'a> {
    pub sod_der: &'a [u8],
    pub data_groups: &'a HashMap<u8, Vec<u8>>,
    /// The source MRZ is exactly two concatenated 44-byte lines.
    pub source_mrz: &'a [u8],
    /// DER certificates resolved from the selected managed issuer profiles.
    pub dsc_cert_der: &'a [u8],
    pub csca_cert_der: &'a [u8],
}

/// Digest evidence for an authorized, encrypted private manifest only.
///
/// This attests the selected issuer chain, SOD signature, hash binding, MRZ,
/// and required DG2 face decoding. Optional DG3/DG4 image bytes are signed and
/// length framed; their codec conformance is not asserted by this result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDigitalPassportPackage {
    pub sod_sha256: [u8; 32],
    pub mrz_sha256: [u8; 32],
    pub dsc_certificate_sha256: [u8; 32],
    pub csca_certificate_sha256: [u8; 32],
    pub data_group_sha256: BTreeMap<u8, [u8; 32]>,
    pub sod_data_group_sha256: BTreeMap<u8, [u8; 32]>,
}

/// Failure categories contain no MRZ, biometric, certificate, or key bytes.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum DigitalPassportPackageError {
    #[error("invalid TD3 source or DG1 MRZ")]
    InvalidMrz,
    #[error("source MRZ and DG1 differ")]
    MrzMismatch,
    #[error("invalid or unsupported data group")]
    InvalidDataGroup,
    #[error("invalid SOD or non-SHA-256 data-group hashes")]
    InvalidSod,
    #[error("embedded document signer certificate differs from selected profile")]
    DscMismatch,
    #[error("selected CSCA certificate is invalid")]
    InvalidCsca,
    #[error("passport issuer and selected certificate countries differ")]
    IssuerCountryMismatch,
    #[error("SOD, data-group, or DSC chain verification failed")]
    VerificationFailed,
}

/// Verify the exact SOD and encoded DG bytes intended for an encrypted handoff.
///
/// The selected CSCA is the only trust anchor, so a different valid CSCA in a
/// wider registry cannot satisfy this package revision. KMS SPKI and signed
/// custody-receipt checks remain obligations of the caller. A biometric-use
/// consumer must separately decode and validate optional DG3/DG4 images.
pub fn verify_digital_passport_package(
    package: DigitalPassportPackage<'_>,
) -> Result<VerifiedDigitalPassportPackage, DigitalPassportPackageError> {
    let source_mrz = parse_td3_bytes(package.source_mrz)?;
    let groups = package.data_groups;
    if !groups.contains_key(&1)
        || !groups.contains_key(&2)
        || groups.keys().any(|number| !(1..=16).contains(number))
    {
        return Err(DigitalPassportPackageError::InvalidDataGroup);
    }
    for (&number, bytes) in groups {
        match number {
            1 if parse_elementary_file("EF.DG1", bytes)
                .map(|file| file.tag == 0x61)
                .unwrap_or(false) => {}
            2 => {
                let faces = parse_icao_ef_dg2(bytes)
                    .map_err(|_| DigitalPassportPackageError::InvalidDataGroup)?;
                for face in faces {
                    verify_face_record(face)?;
                }
            }
            3..=16 => validate_icao_optional_dg(number, bytes)
                .map_err(|_| DigitalPassportPackageError::InvalidDataGroup)?,
            _ => {
                return Err(DigitalPassportPackageError::InvalidDataGroup);
            }
        }
    }

    let dg1_mrz = extract_ef_dg1_mrz(&groups[&1])
        .map_err(|_| DigitalPassportPackageError::InvalidDataGroup)?;
    parse_td3_bytes(dg1_mrz)?;
    if dg1_mrz != package.source_mrz {
        return Err(DigitalPassportPackageError::MrzMismatch);
    }

    let sod =
        SecurityObject::from_sod_der(package.sod_der, Some(source_mrz.issuing_country.clone()))
            .map_err(|_| DigitalPassportPackageError::InvalidSod)?;
    if !matches!(
        marty_crypto::HashAlgorithm::from_oid(&sod.hash_algorithm),
        Ok(marty_crypto::HashAlgorithm::Sha256)
    ) {
        return Err(DigitalPassportPackageError::InvalidSod);
    }
    let embedded_dsc = sod
        .signer_certificate
        .certificate
        .to_der()
        .map_err(|_| DigitalPassportPackageError::InvalidSod)?;
    if embedded_dsc != package.dsc_cert_der {
        return Err(DigitalPassportPackageError::DscMismatch);
    }
    let csca = Certificate::from_der(package.csca_cert_der)
        .map_err(|_| DigitalPassportPackageError::InvalidCsca)?;
    let expected_alpha2 = alpha2_for_alpha3(&source_mrz.issuing_country)
        .ok_or(DigitalPassportPackageError::IssuerCountryMismatch)?;
    if certificate_country(&csca) != Some(expected_alpha2)
        || certificate_country(&sod.signer_certificate.certificate) != Some(expected_alpha2)
    {
        return Err(DigitalPassportPackageError::IssuerCountryMismatch);
    }
    let mut registry = CscaRegistry::new();
    registry
        .add_country_csca(&source_mrz.issuing_country, csca)
        .map_err(|_| DigitalPassportPackageError::InvalidCsca)?;
    if !verify_emrtd(&sod, groups, &registry).verified {
        return Err(DigitalPassportPackageError::VerificationFailed);
    }

    let mut data_group_sha256 = BTreeMap::new();
    let mut sod_data_group_sha256 = BTreeMap::new();
    for (&number, bytes) in groups {
        data_group_sha256.insert(number, Sha256::digest(bytes).into());
        let hash = sod
            .data_group_hashes
            .get(&number)
            .ok_or(DigitalPassportPackageError::VerificationFailed)?;
        let hash: [u8; 32] = hash
            .as_slice()
            .try_into()
            .map_err(|_| DigitalPassportPackageError::InvalidSod)?;
        sod_data_group_sha256.insert(number, hash);
    }

    Ok(VerifiedDigitalPassportPackage {
        sod_sha256: Sha256::digest(package.sod_der).into(),
        mrz_sha256: Sha256::digest(package.source_mrz).into(),
        dsc_certificate_sha256: Sha256::digest(package.dsc_cert_der).into(),
        csca_certificate_sha256: Sha256::digest(package.csca_cert_der).into(),
        data_group_sha256,
        sod_data_group_sha256,
    })
}

fn certificate_country(certificate: &Certificate) -> Option<&str> {
    let mut country = None;
    for rdn in &certificate.tbs_certificate.subject.0 {
        for attribute in rdn.0.iter() {
            if attribute.oid == const_oid::db::rfc4519::COUNTRY_NAME {
                if attribute.value.tag() != Tag::PrintableString {
                    return None;
                }
                let value = std::str::from_utf8(attribute.value.value()).ok()?;
                if value.len() != 2
                    || !value.bytes().all(|byte| byte.is_ascii_uppercase())
                    || country.is_some()
                {
                    return None;
                }
                country = Some(value);
            }
        }
    }
    country
}

fn verify_face_record(face: IcaoFaceBiometric<'_>) -> Result<(), DigitalPassportPackageError> {
    if face.data_tag == 0x7f2e && face.format_owner == 0x0101 && face.format_type == 0x002a {
        return verify_icao_39794_face(face.data)
            .map_err(|_| DigitalPassportPackageError::InvalidDataGroup);
    }
    if face.data_tag != 0x5f2e || face.format_owner != 0x0101 || face.format_type != 0x0008 {
        return Err(DigitalPassportPackageError::InvalidDataGroup);
    }
    let record = face.data;
    if record.len() < 14
        || &record[..4] != b"FAC\0"
        || &record[4..8] != b"010\0"
        || u32::from_be_bytes(record[8..12].try_into().unwrap()) as usize != record.len()
    {
        return Err(DigitalPassportPackageError::InvalidDataGroup);
    }
    let image_count = usize::from(u16::from_be_bytes([record[12], record[13]]));
    if !(1..=9).contains(&image_count) {
        return Err(DigitalPassportPackageError::InvalidDataGroup);
    }
    let mut offset = 14usize;
    for _ in 0..image_count {
        let facial_info = record
            .get(offset..offset + 20)
            .ok_or(DigitalPassportPackageError::InvalidDataGroup)?;
        let data_length = u32::from_be_bytes(facial_info[..4].try_into().unwrap()) as usize;
        let feature_count = usize::from(u16::from_be_bytes(facial_info[4..6].try_into().unwrap()));
        let end = offset
            .checked_add(data_length)
            .ok_or(DigitalPassportPackageError::InvalidDataGroup)?;
        let info_start = offset
            .checked_add(20)
            .and_then(|start| {
                feature_count
                    .checked_mul(8)
                    .and_then(|points| start.checked_add(points))
            })
            .ok_or(DigitalPassportPackageError::InvalidDataGroup)?;
        let image_start = info_start
            .checked_add(12)
            .ok_or(DigitalPassportPackageError::InvalidDataGroup)?;
        if image_start >= end || end > record.len() {
            return Err(DigitalPassportPackageError::InvalidDataGroup);
        }
        let image_info = &record[info_start..image_start];
        if !matches!(image_info[1], 0 | 1) {
            return Err(DigitalPassportPackageError::InvalidDataGroup);
        }
        let width = u16::from_be_bytes([image_info[2], image_info[3]]);
        let height = u16::from_be_bytes([image_info[4], image_info[5]]);
        let image = &record[image_start..end];
        if (image_info[1] == 0 && !image.starts_with(&[0xff, 0xd8]))
            || (image_info[1] == 1 && image.starts_with(&[0xff, 0xd8]))
        {
            return Err(DigitalPassportPackageError::InvalidDataGroup);
        }
        verify_icao_image(image, Some((width, height)))
            .map_err(|_| DigitalPassportPackageError::InvalidDataGroup)?;
        offset = end;
    }
    if offset != record.len() {
        return Err(DigitalPassportPackageError::InvalidDataGroup);
    }
    Ok(())
}

fn parse_td3_bytes(bytes: &[u8]) -> Result<crate::mrz::Mrz, DigitalPassportPackageError> {
    if bytes.len() != 88
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'<')
    {
        return Err(DigitalPassportPackageError::InvalidMrz);
    }
    let line1 =
        std::str::from_utf8(&bytes[..44]).map_err(|_| DigitalPassportPackageError::InvalidMrz)?;
    let line2 =
        std::str::from_utf8(&bytes[44..]).map_err(|_| DigitalPassportPackageError::InvalidMrz)?;
    let parsed = parse_mrz(&[line1, line2]).map_err(|_| DigitalPassportPackageError::InvalidMrz)?;
    if parsed.format != MrzFormat::TD3
        || !parsed.document_type.starts_with('P')
        || !parsed.validate_check_digits()
    {
        return Err(DigitalPassportPackageError::InvalidMrz);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    const MRZ: &str = concat!(
        "P<USAERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
        "L898902C36USA7408122F1204159ZE184226B<<<<<10"
    );

    struct Fixture {
        sod: Vec<u8>,
        groups: HashMap<u8, Vec<u8>>,
        mrz: Vec<u8>,
        dsc: Vec<u8>,
        csca: Vec<u8>,
    }

    impl Fixture {
        fn package(&self) -> DigitalPassportPackage<'_> {
            DigitalPassportPackage {
                sod_der: &self.sod,
                data_groups: &self.groups,
                source_mrz: &self.mrz,
                dsc_cert_der: &self.dsc,
                csca_cert_der: &self.csca,
            }
        }
    }

    fn fixture() -> Fixture {
        fixture_from(include_str!(
            "../../tests/fixtures/passport_digital_package_td3.json"
        ))
    }

    fn fixture_from(json: &str) -> Fixture {
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let decode = |text: &str| {
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .unwrap()
        };
        let mrz = value["source_mrz"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|line| line.as_str().unwrap().as_bytes().iter().copied())
            .collect();
        let groups = value["data_groups"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(number, bytes)| {
                (
                    number.parse::<u8>().unwrap(),
                    decode(bytes.as_str().unwrap()),
                )
            })
            .collect();
        Fixture {
            sod: decode(value["sod_der_base64"].as_str().unwrap()),
            groups,
            mrz,
            dsc: decode(value["dsc_der_base64"].as_str().unwrap()),
            csca: decode(value["csca_der_base64"].as_str().unwrap()),
        }
    }

    #[test]
    fn signed_optional_ec_dg15_is_preserved_in_complete_hash_map() {
        let fixture = fixture_from(include_str!(
            "../../tests/fixtures/passport_digital_package_td3_with_dg15.json"
        ));
        let proof = verify_digital_passport_package(fixture.package()).unwrap();
        assert_eq!(
            proof.data_group_sha256.keys().copied().collect::<Vec<_>>(),
            [1, 2, 15]
        );
        assert_eq!(proof.data_group_sha256, proof.sod_data_group_sha256);
    }

    #[test]
    fn iso19794_face_record_accepts_jpeg2000_image_type() {
        let image = include_bytes!("../../tests/fixtures/passport_face_2x2.jp2");
        let facial_record_len = 20 + 12 + image.len();
        let mut record = b"FAC\0".to_vec();
        record.extend(b"010\0");
        record.extend(u32::try_from(14 + facial_record_len).unwrap().to_be_bytes());
        record.extend(1u16.to_be_bytes());
        record.extend(u32::try_from(facial_record_len).unwrap().to_be_bytes());
        record.extend([0u8; 16]);
        record.extend([0, 1, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0]);
        record.extend(image);
        let face = IcaoFaceBiometric {
            data_tag: 0x5f2e,
            format_owner: 0x0101,
            format_type: 0x0008,
            data: &record,
        };
        assert!(verify_face_record(face).is_ok());
        let mut invalid_record = record.clone();
        invalid_record[14 + 20 + 1] = 0;
        assert!(verify_face_record(IcaoFaceBiometric {
            data: &invalid_record,
            ..face
        })
        .is_err());
    }

    #[test]
    fn exact_td3_package_verifies_and_binds_every_digest() {
        let fixture = fixture();
        assert_eq!(fixture.mrz, MRZ.as_bytes());
        let proof = verify_digital_passport_package(fixture.package()).unwrap();
        let mrz_digest: [u8; 32] = Sha256::digest(MRZ.as_bytes()).into();
        let sod_digest: [u8; 32] = Sha256::digest(&fixture.sod).into();
        assert_eq!(proof.mrz_sha256, mrz_digest);
        assert_eq!(proof.sod_sha256, sod_digest);
        assert_eq!(proof.data_group_sha256, proof.sod_data_group_sha256);
        assert_eq!(
            proof.data_group_sha256.keys().copied().collect::<Vec<_>>(),
            [1, 2]
        );
    }

    #[test]
    fn changed_group_and_selected_signer_fail_closed() {
        let mut altered = fixture();
        let dg2 = altered.groups.get_mut(&2).unwrap();
        let face_offset = dg2.windows(4).position(|bytes| bytes == b"FAC\0").unwrap();
        dg2[face_offset + 45] ^= 1; // Valid quality byte, changed signed DG2.
        assert_eq!(
            verify_digital_passport_package(altered.package()).unwrap_err(),
            DigitalPassportPackageError::VerificationFailed
        );
        let mut wrong_dsc = fixture();
        wrong_dsc.dsc[10] ^= 1;
        assert_eq!(
            verify_digital_passport_package(wrong_dsc.package()).unwrap_err(),
            DigitalPassportPackageError::DscMismatch
        );

        let mut altered_sod = fixture();
        *altered_sod.sod.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify_digital_passport_package(altered_sod.package()).unwrap_err(),
            DigitalPassportPackageError::VerificationFailed
        );

        let mut wrong_csca = fixture();
        let other: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/emrtd_verification_vectors.json"
        ))
        .unwrap();
        wrong_csca.csca = base64::engine::general_purpose::STANDARD
            .decode(other["csca_der_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            verify_digital_passport_package(wrong_csca.package()).unwrap_err(),
            DigitalPassportPackageError::IssuerCountryMismatch
        );
    }

    #[test]
    fn mrz_and_data_group_shape_cannot_be_normalized_into_a_pass() {
        let mut altered = fixture();
        altered.groups.get_mut(&1).unwrap()[10] = b'F';
        assert_eq!(
            verify_digital_passport_package(altered.package()).unwrap_err(),
            DigitalPassportPackageError::MrzMismatch
        );
        let valid = fixture();
        let mut lowercase = MRZ.as_bytes().to_vec();
        lowercase[0] = b'p';
        assert_eq!(
            verify_digital_passport_package(DigitalPassportPackage {
                source_mrz: &lowercase,
                ..valid.package()
            })
            .unwrap_err(),
            DigitalPassportPackageError::InvalidMrz
        );
        let mut unsupported = fixture();
        unsupported.groups.insert(17, vec![0x71, 0x00]);
        assert_eq!(
            verify_digital_passport_package(unsupported.package()).unwrap_err(),
            DigitalPassportPackageError::InvalidDataGroup
        );

        let mut invalid_face = fixture();
        let dg2 = invalid_face.groups.get_mut(&2).unwrap();
        let image_offset = dg2
            .windows(3)
            .position(|bytes| bytes == [0xff, 0xd8, 0xff])
            .unwrap();
        dg2[image_offset] = 0;
        assert_eq!(
            verify_digital_passport_package(invalid_face.package()).unwrap_err(),
            DigitalPassportPackageError::InvalidDataGroup
        );

        let mut wrong_issuer = fixture();
        let country_offset = wrong_issuer
            .csca
            .windows(4)
            .rposition(|bytes| bytes == [0x13, 0x02, b'U', b'S'])
            .unwrap()
            + 2;
        wrong_issuer.csca[country_offset..country_offset + 2].copy_from_slice(b"GB");
        assert_eq!(
            verify_digital_passport_package(wrong_issuer.package()).unwrap_err(),
            DigitalPassportPackageError::IssuerCountryMismatch
        );
    }
}
