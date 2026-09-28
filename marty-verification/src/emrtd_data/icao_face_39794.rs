//! ISO/IEC 39794-5 facial image extraction for ICAO Doc 9303 EF.DG2.
//!
//! Implements the DER tagged-binary layout in the ICAO eMRTD application
//! profile. Optional extension fields are retained as signed bytes and skipped
//! only after the mandatory image path has been validated.

use der::Decode;

use super::elementary::{parse_complete_tlv, parse_tlv, Tlv};
use super::icao_image::verify_icao_image;
use super::{EmrtdDataError, EmrtdDataResult};

pub(crate) fn verify_icao_39794_face(data: &[u8]) -> EmrtdDataResult<()> {
    let envelope = parse_complete_tlv(data, 0xa1, "ISO 39794 BDB envelope")?;
    let face = parse_complete_tlv(envelope.value, 0x65, "ISO 39794 face block")?;
    let version = expect(face.value, 0, 0xa0, "version block")?;
    verify_version(version.value)?;
    let representations = expect(face.value, version.next_offset, 0xa1, "representations")?;
    verify_representations(representations.value)?;
    verify_extensions(
        face.value,
        representations.next_offset,
        1,
        OptionalScope::Future,
    )?;
    Ok(())
}

pub(super) fn verify_version(data: &[u8]) -> EmrtdDataResult<()> {
    let generation = expect(data, 0, 0x80, "version generation")?;
    let generation_number = unsigned_der_integer(generation.value)?;
    let year = expect(data, generation.next_offset, 0x81, "version year")?;
    let year_number = unsigned_der_integer(year.value)?;
    if !(3..=65535).contains(&generation_number) || !(2019..=9999).contains(&year_number) {
        return Err(invalid("unsupported ISO 39794 face version"));
    }
    verify_extensions(data, year.next_offset, 1, OptionalScope::Future)
}

fn verify_representations(data: &[u8]) -> EmrtdDataResult<()> {
    // The ICAO 39794-5 application profile carries one facial representation.
    let representation = parse_complete_tlv(data, 0x30, "face representation sequence")?;
    let id = expect(representation.value, 0, 0x80, "representation identifier")?;
    unsigned_der_integer(id.value)?;
    let image = expect(
        representation.value,
        id.next_offset,
        0xa1,
        "image representation",
    )?;
    verify_image_representation(image.value)?;
    verify_extensions(
        representation.value,
        image.next_offset,
        1,
        OptionalScope::Representation,
    )
}

fn verify_image_representation(data: &[u8]) -> EmrtdDataResult<()> {
    let base = parse_complete_tlv(data, 0xa0, "base image representation")?;
    let two_d = parse_complete_tlv(base.value, 0xa0, "2D image representation")?;
    let encoded = expect(two_d.value, 0, 0x80, "2D image octets")?;
    let information = expect(
        two_d.value,
        encoded.next_offset,
        0xa1,
        "2D image information",
    )?;
    let format = expect(information.value, 0, 0xa0, "image data format")?;
    let format_code = parse_complete_tlv(format.value, 0x80, "image format code")?;
    let code = unsigned_der_integer(format_code.value)?;
    if !matches!(code, 2..=4)
        || (code == 2 && !encoded.value.starts_with(&[0xff, 0xd8]))
        || (code != 2 && encoded.value.starts_with(&[0xff, 0xd8]))
    {
        return Err(invalid("ISO 39794 image format differs from encoded image"));
    }
    verify_icao_image(encoded.value, None)?;
    verify_extensions(
        information.value,
        format.next_offset,
        0,
        OptionalScope::ImageInformation,
    )?;
    verify_extensions(two_d.value, information.next_offset, 1, OptionalScope::TwoD)
}

fn verify_face_kind(data: &[u8]) -> EmrtdDataResult<()> {
    let extension = parse_complete_tlv(data, 0xa1, "2D face kind extension")?;
    let fallback = expect(extension.value, 0, 0x80, "2D face kind fallback")?;
    if unsigned_der_integer(fallback.value)? != 0 {
        return Err(invalid("ISO 39794 face kind must be MRTD"));
    }
    verify_extensions(
        extension.value,
        fallback.next_offset,
        0,
        OptionalScope::Future,
    )
}

fn expect<'a>(data: &'a [u8], offset: usize, tag: u32, kind: &str) -> EmrtdDataResult<Tlv<'a>> {
    let field = parse_tlv(data, offset)?;
    if field.tag != tag {
        return Err(invalid(&format!("invalid ISO 39794 {kind}")));
    }
    der::Any::from_der(&data[offset..field.next_offset])
        .map_err(|_| invalid(&format!("non-DER ISO 39794 {kind}")))?;
    Ok(field)
}

#[derive(Clone, Copy)]
enum OptionalScope {
    Future,
    Representation,
    TwoD,
    ImageInformation,
    IdentityMetadata,
}

fn verify_extensions(
    data: &[u8],
    mut offset: usize,
    mut last_tag: u32,
    scope: OptionalScope,
) -> EmrtdDataResult<()> {
    while offset < data.len() {
        let extension = parse_tlv(data, offset)?;
        let tag_number = context_tag_number(extension.tag)?;
        if tag_number <= last_tag {
            return Err(invalid("duplicate or out-of-order ISO 39794 field"));
        }
        der::Any::from_der(&data[offset..extension.next_offset])
            .map_err(|_| invalid("non-DER ISO 39794 extension"))?;
        verify_known_optional_field(&extension, tag_number, scope)?;
        last_tag = tag_number;
        offset = extension.next_offset;
    }
    Ok(())
}

fn verify_known_optional_field(
    field: &Tlv<'_>,
    number: u32,
    scope: OptionalScope,
) -> EmrtdDataResult<()> {
    match scope {
        OptionalScope::Future => Ok(()),
        OptionalScope::TwoD if number == 2 => require_constructed(field, 0xa2),
        OptionalScope::Representation => match number {
            2 => {
                require_tag(field, 0xa2)?;
                verify_capture_datetime(field.value)
            }
            3 | 4 | 7 | 9 => require_constructed(field, 0xa0 + number),
            8 => {
                require_constructed(field, 0xa8)?;
                verify_identity_metadata(field.value)
            }
            5 | 6 => {
                require_tag(field, 0x80 + number)?;
                unsigned_der_integer(field.value).map(|_| ())
            }
            _ => Ok(()),
        },
        OptionalScope::ImageInformation => match number {
            1 => {
                require_tag(field, 0xa1)?;
                verify_face_kind(field.value)
            }
            2 => {
                require_tag(field, 0xa2)?;
                verify_boolean_fields(field.value, 11)
            }
            3 | 9 => {
                require_tag(field, 0xa0 + number)?;
                verify_enum_fallback(field.value, if number == 3 { 3 } else { 6 })
            }
            4..=6 => {
                require_tag(field, 0x80 + number)?;
                let value = unsigned_der_integer(field.value)?;
                let max = match number {
                    4 => 50_000,
                    5 | 6 => 2_000,
                    _ => unreachable!(),
                };
                if value > max {
                    return Err(invalid("ISO 39794 image metadata integer out of range"));
                }
                Ok(())
            }
            7 => {
                require_tag(field, 0xa7)?;
                let width = expect(field.value, 0, 0x80, "image width")?;
                let height = expect(field.value, width.next_offset, 0x81, "image height")?;
                if unsigned_der_integer(width.value)? > 65535
                    || unsigned_der_integer(height.value)? > 65535
                {
                    return Err(invalid("ISO 39794 image size out of range"));
                }
                verify_extensions(field.value, height.next_offset, 1, OptionalScope::Future)
            }
            8 | 10 => require_constructed(field, 0xa0 + number),
            _ => Ok(()),
        },
        OptionalScope::TwoD => Ok(()),
        OptionalScope::IdentityMetadata => match number {
            1 | 2 => {
                require_tag(field, 0xa0 + number)?;
                verify_enum_fallback(field.value, 9)
            }
            3 => {
                require_tag(field, 0x83)?;
                if !matches!(unsigned_der_integer(field.value)?, 1..=65535) {
                    return Err(invalid("ISO 39794 subject height out of range"));
                }
                Ok(())
            }
            4 | 5 => {
                require_tag(field, 0xa0 + number)?;
                verify_boolean_fields(field.value, if number == 4 { 10 } else { 5 })
            }
            6 => require_constructed(field, 0xa6),
            _ => Ok(()),
        },
    }
}

fn verify_capture_datetime(data: &[u8]) -> EmrtdDataResult<()> {
    let year = expect(data, 0, 0x80, "capture year")?;
    if unsigned_der_integer(year.value)? > 9999 {
        return Err(invalid("ISO 39794 capture year out of range"));
    }
    let mut offset = year.next_offset;
    let mut last = 0;
    while offset < data.len() {
        let field = parse_tlv(data, offset)?;
        let number = context_tag_number(field.tag)?;
        if number <= last || number > 6 || field.tag != 0x80 + number {
            return Err(invalid("invalid ISO 39794 capture time field"));
        }
        let value = unsigned_der_integer(field.value)?;
        let valid = match number {
            1 => (1..=12).contains(&value),
            2 => (1..=31).contains(&value),
            3 => value <= 23,
            4 | 5 => value <= 59,
            6 => value <= 999,
            _ => false,
        };
        if !valid {
            return Err(invalid("ISO 39794 capture time value out of range"));
        }
        last = number;
        offset = field.next_offset;
    }
    Ok(())
}

fn verify_identity_metadata(data: &[u8]) -> EmrtdDataResult<()> {
    let mut offset = 0;
    let mut last_tag = 0;
    if !data.is_empty() {
        let gender = parse_tlv(data, 0)?;
        if gender.tag == 0xa0 {
            let extension = parse_complete_tlv(gender.value, 0xa1, "gender extension")?;
            let fallback = expect(extension.value, 0, 0x80, "gender fallback")?;
            if !matches!(unsigned_der_integer(fallback.value)?, 1..=3) {
                return Err(invalid("ISO 39794 gender must be other, male, or female"));
            }
            verify_extensions(
                extension.value,
                fallback.next_offset,
                0,
                OptionalScope::Future,
            )?;
            offset = gender.next_offset;
            last_tag = 0;
        }
    }
    verify_extensions(data, offset, last_tag, OptionalScope::IdentityMetadata)
}

fn require_tag(field: &Tlv<'_>, expected: u32) -> EmrtdDataResult<()> {
    if field.tag != expected {
        return Err(invalid("invalid known ISO 39794 optional field tag"));
    }
    Ok(())
}

fn require_constructed(field: &Tlv<'_>, expected: u32) -> EmrtdDataResult<()> {
    require_tag(field, expected)
}

fn verify_enum_fallback(data: &[u8], max: u32) -> EmrtdDataResult<()> {
    let extension = parse_complete_tlv(data, 0xa1, "enumeration extension")?;
    let fallback = expect(extension.value, 0, 0x80, "enumeration fallback")?;
    if unsigned_der_integer(fallback.value)? > max {
        return Err(invalid("ISO 39794 enumeration fallback out of range"));
    }
    verify_extensions(
        extension.value,
        fallback.next_offset,
        0,
        OptionalScope::Future,
    )
}

fn verify_boolean_fields(data: &[u8], max_tag: u32) -> EmrtdDataResult<()> {
    let mut offset = 0;
    let mut last_tag = None;
    while offset < data.len() {
        let field = parse_tlv(data, offset)?;
        let number = context_tag_number(field.tag)?;
        if last_tag.is_some_and(|previous| number <= previous) {
            return Err(invalid("duplicate ISO 39794 Boolean field"));
        }
        if number <= max_tag
            && (field.tag != 0x80 + number
                || field.value.len() != 1
                || !matches!(field.value[0], 0 | 0xff))
        {
            return Err(invalid("invalid ISO 39794 Boolean field"));
        }
        last_tag = Some(number);
        offset = field.next_offset;
    }
    Ok(())
}

pub(super) fn context_tag_number(tag: u32) -> EmrtdDataResult<u32> {
    let octets = tag.to_be_bytes();
    let first_index = octets.iter().position(|octet| *octet != 0).unwrap_or(3);
    let first = octets[first_index];
    if first & 0xc0 != 0x80 {
        return Err(invalid("ISO 39794 extension is not context-specific"));
    }
    if first & 0x1f != 0x1f {
        return Ok(u32::from(first & 0x1f));
    }
    let mut number = 0u32;
    for octet in &octets[first_index + 1..] {
        number = number
            .checked_mul(128)
            .and_then(|value| value.checked_add(u32::from(octet & 0x7f)))
            .ok_or_else(|| invalid("oversized ISO 39794 extension tag"))?;
    }
    Ok(number)
}

pub(super) fn unsigned_der_integer(data: &[u8]) -> EmrtdDataResult<u32> {
    if data.is_empty()
        || data.len() > 5
        || data[0] & 0x80 != 0
        || (data.len() > 1 && data[0] == 0 && data[1] & 0x80 == 0)
    {
        return Err(invalid("invalid ISO 39794 unsigned integer"));
    }
    let value = data
        .iter()
        .fold(0u64, |current, octet| (current << 8) | u64::from(*octet));
    u32::try_from(value).map_err(|_| invalid("oversized ISO 39794 unsigned integer"))
}

fn invalid(message: &str) -> EmrtdDataError {
    EmrtdDataError::InvalidFormat(message.into())
}

#[cfg(test)]
mod tests {
    use super::{verify_capture_datetime, verify_icao_39794_face, verify_identity_metadata};

    fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
        let mut result = tag.to_vec();
        if value.len() < 128 {
            result.push(value.len() as u8);
        } else if value.len() < 256 {
            result.extend([0x81, value.len() as u8]);
        } else {
            result.extend([0x82, (value.len() >> 8) as u8, value.len() as u8]);
        }
        result.extend(value);
        result
    }

    fn generated_face(image_info_tail: &[u8]) -> Vec<u8> {
        let jp2 = include_bytes!("../../tests/fixtures/passport_face_2x2.jp2");
        let mut version = tlv(&[0x80], &[3]);
        version.extend(tlv(&[0x81], &[0x07, 0xe3]));
        let version = tlv(&[0xa0], &version);
        let image_data = tlv(&[0x80], jp2);
        let mut image_info_fields = tlv(&[0xa0], &tlv(&[0x80], &[3]));
        image_info_fields.extend(image_info_tail);
        let image_info = tlv(&[0xa1], &image_info_fields);
        let mut two_d = image_data;
        two_d.extend(image_info);
        let image = tlv(&[0xa1], &tlv(&[0xa0], &tlv(&[0xa0], &two_d)));
        let mut representation = tlv(&[0x80], &[0]);
        representation.extend(image);
        let representations = tlv(&[0xa1], &tlv(&[0x30], &representation));
        let mut face = version;
        face.extend(representations);
        tlv(&[0xa1], &tlv(&[0x65], &face))
    }

    #[test]
    fn tagged_binary_face_with_jpeg2000_decodes() {
        let encoded = generated_face(&[]);
        assert!(
            verify_icao_39794_face(&encoded).is_ok(),
            "{:?}",
            verify_icao_39794_face(&encoded)
        );
    }

    #[test]
    fn known_face_kind_must_be_mrtd_and_unique() {
        let mrtd_kind = tlv(&[0xa1], &tlv(&[0xa1], &tlv(&[0x80], &[0])));
        assert!(verify_icao_39794_face(&generated_face(&mrtd_kind)).is_ok());
        let wrong_kind = tlv(&[0xa1], &tlv(&[0xa1], &tlv(&[0x80], &[1])));
        assert!(verify_icao_39794_face(&generated_face(&wrong_kind)).is_err());
        assert!(verify_icao_39794_face(&generated_face(&[0x81, 0x00])).is_err());
        assert!(verify_icao_39794_face(&generated_face(&[0xa7, 0x00])).is_err());
        assert!(verify_icao_39794_face(&generated_face(&[0xa8, 0x00])).is_ok());
        assert!(verify_icao_39794_face(&generated_face(&[0xaa, 0x00])).is_ok());
        let mut duplicate = mrtd_kind.clone();
        duplicate.extend(mrtd_kind);
        assert!(verify_icao_39794_face(&generated_face(&duplicate)).is_err());
    }

    #[test]
    fn known_gender_uses_the_icao_profile_values() {
        let female = tlv(&[0xa0], &tlv(&[0xa1], &tlv(&[0x80], &[3])));
        assert!(verify_identity_metadata(&female).is_ok());
        let unknown = tlv(&[0xa0], &tlv(&[0xa1], &tlv(&[0x80], &[0])));
        assert!(verify_identity_metadata(&unknown).is_err());
        assert!(verify_identity_metadata(&[0x80, 0x00]).is_err());
        assert!(verify_identity_metadata(&[0xa1, 0x00]).is_err());
        assert!(verify_identity_metadata(&[0xa2, 0x00]).is_err());
        assert!(verify_identity_metadata(&[0x83, 0x01, 0x00]).is_err());
        assert!(verify_identity_metadata(&[0x83, 0x03, 0x01, 0x00, 0x00]).is_err());
    }

    #[test]
    fn capture_date_requires_year_and_valid_ranges() {
        assert!(verify_capture_datetime(&[]).is_err());
        assert!(verify_capture_datetime(&[0x80, 0x02, 0x07, 0xe8]).is_ok());
        assert!(verify_capture_datetime(&[0x80, 0x02, 0x07, 0xe8, 0x81, 0x01, 13]).is_err());
    }

    #[test]
    #[ignore = "set ICAO_39794_SILVER to an ICAO WG3 DG2 silver dataset"]
    fn official_icao_silver_dg2_decodes_when_supplied() {
        let path = std::env::var("ICAO_39794_SILVER").expect("ICAO_39794_SILVER is required");
        let dg2 = std::fs::read(path).unwrap();
        let faces = crate::emrtd_data::parse_icao_ef_dg2(&dg2).unwrap();
        assert_eq!(faces.len(), 1);
        assert_eq!(faces[0].data_tag, 0x7f2e);
        assert_eq!(faces[0].format_owner, 0x0101);
        assert_eq!(faces[0].format_type, 0x002a);
        assert!(
            verify_icao_39794_face(faces[0].data).is_ok(),
            "{:?}",
            verify_icao_39794_face(faces[0].data)
        );
    }
}
