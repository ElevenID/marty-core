//! Bounded ICAO Doc 9303 Part 10 structural checks for optional data groups.
//!
//! Issuer-defined payloads (DG6, DG8-10, DG13) remain opaque after their
//! standard envelope is checked. DG3/DG4 biometric image bytes are length
//! framed but not codec-decoded: ISO permits raw, WSQ, JPEG-LS, PNG, JPEG,
//! and JPEG 2000, including registered extensions. Exact bytes are still
//! authenticated by SOD. Callers must separately decode biometric images
//! before displaying, matching, or claiming image conformance.

use std::collections::BTreeSet;

use der::{asn1::SetOfVec, Decode, Encode, Tagged};
use spki::SubjectPublicKeyInfoOwned;

use super::elementary::{parse_complete_tlv, parse_tlv};
use super::icao_face_39794::{context_tag_number, unsigned_der_integer, verify_version};
use super::icao_image::verify_icao_image;
use super::{EmrtdDataError, EmrtdDataResult};

/// Validate the defined envelope and nested TLV structure of DG3 through DG16.
/// DG3/DG4 image codec conformance is outside this structural check.
pub fn validate_icao_optional_dg(number: u8, data: &[u8]) -> EmrtdDataResult<()> {
    let tag = match number {
        3 => 0x63,
        4 => 0x76,
        5..=15 => u32::from(number) + 0x60,
        16 => 0x70,
        _ => return Err(invalid("unsupported optional data group")),
    };
    let outer = parse_complete_tlv(data, tag, "optional ICAO data group")?;
    match number {
        3 => validate_biometric_group(outer.value, 0x08),
        4 => validate_biometric_group(outer.value, 0x10),
        5 => validate_displayed_images(outer.value, 0x5f40),
        6 | 13 => Ok(()),
        7 => validate_displayed_images(outer.value, 0x5f43),
        8..=10 => validate_proprietary_templates(outer.value),
        11 | 12 => validate_tag_list_group(outer.value, number),
        14 => validate_security_infos(outer.value),
        15 => validate_active_auth_key(outer.value),
        16 => validate_notification_templates(outer.value),
        _ => unreachable!(),
    }
}

fn validate_biometric_group(data: &[u8], biometric_type: u8) -> EmrtdDataResult<()> {
    let group = parse_tlv(data, 0)?;
    if group.tag != 0x7f61 {
        return Err(invalid("optional biometric BIT group tag"));
    }
    let count = parse_count(group.value, 0, true)?;
    let mut offset = count.1;
    for index in 0..count.0 {
        let bit = parse_tlv(group.value, offset)?;
        if bit.tag != 0x7f60 {
            return Err(invalid("optional biometric BIT tag"));
        }
        let header = parse_tlv(bit.value, 0)?;
        if header.tag != 0xa1 {
            return Err(invalid("optional biometric header tag"));
        }
        let mut owner = None;
        let mut format_type = None;
        let mut has_subtype = false;
        let mut seen = BTreeSet::new();
        let mut header_offset = 0;
        while header_offset < header.value.len() {
            let field = parse_tlv(header.value, header_offset)?;
            if !seen.insert(field.tag) {
                return Err(invalid("duplicate optional biometric header field"));
            }
            match field.tag {
                0x81 if (1..=3).contains(&field.value.len())
                    && (field.value.len() != 1 || field.value[0] == biometric_type) => {}
                0x80 if field.value == [0x01, 0x01] => {}
                0x82 if field.value.len() == 1 => has_subtype = true,
                0x83 if field.value.len() == 7 => {}
                0x85 if field.value.len() == 8 => {}
                0x86 if field.value.len() == 4 => {}
                0x87 if field.value.len() == 2 => {
                    owner = Some(u16::from_be_bytes([field.value[0], field.value[1]]));
                }
                0x88 if field.value.len() == 2 => {
                    format_type = Some(u16::from_be_bytes([field.value[0], field.value[1]]));
                }
                _ => return Err(invalid("invalid optional biometric header field")),
            }
            header_offset = field.next_offset;
        }
        if owner.is_none() || format_type.is_none() || !has_subtype {
            return Err(invalid("missing optional biometric format binding"));
        }
        if index == 0
            && !matches!(
                (biometric_type, owner.unwrap(), format_type.unwrap()),
                (0x08, 0x0101, 0x0007 | 0x0028) | (0x10, 0x0101, 0x0009 | 0x000b | 0x002c)
            )
        {
            return Err(invalid(
                "first optional biometric record must use an ICAO format",
            ));
        }
        let bdb = parse_tlv(bit.value, header.next_offset)?;
        if !matches!(bdb.tag, 0x5f2e | 0x7f2e)
            || bdb.value.is_empty()
            || bdb.next_offset != bit.value.len()
        {
            return Err(invalid("invalid optional biometric data block"));
        }
        validate_known_biometric_record(
            biometric_type,
            owner.unwrap(),
            format_type.unwrap(),
            bdb.tag,
            bdb.value,
        )?;
        offset = bit.next_offset;
    }
    if offset != group.value.len() {
        return Err(invalid("trailing optional biometric data"));
    }
    let mut outer_offset = group.next_offset;
    if count.0 == 0 && outer_offset < data.len() {
        let filler = parse_tlv(data, outer_offset)?;
        if filler.tag != 0x53 {
            return Err(invalid("invalid empty biometric filler"));
        }
        outer_offset = filler.next_offset;
    }
    if outer_offset != data.len() {
        return Err(invalid("trailing optional biometric data"));
    }
    Ok(())
}

fn validate_known_biometric_record(
    biometric_type: u8,
    owner: u16,
    format_type: u16,
    data_tag: u32,
    data: &[u8],
) -> EmrtdDataResult<()> {
    if owner != 0x0101 {
        return Ok(());
    }
    match (biometric_type, format_type, data_tag) {
        (0x08, 0x0007, 0x5f2e) => validate_19794_finger(data),
        (0x10, 0x0009 | 0x000b, 0x5f2e) => validate_19794_iris(data, format_type),
        (0x08, 0x0028, 0x7f2e) => validate_tagged_binary_bdb(data, 0x64),
        (0x10, 0x002c, 0x7f2e) => validate_tagged_binary_bdb(data, 0x66),
        (0x08, 0x0007 | 0x0028, _) | (0x10, 0x0009 | 0x000b | 0x002c, _) => {
            Err(invalid("optional biometric format differs from data block"))
        }
        // Issuer-specific and later registered formats remain signed opaque
        // bytes rather than being forced through a different ISO layout.
        _ => Ok(()),
    }
}

fn validate_19794_finger(data: &[u8]) -> EmrtdDataResult<()> {
    // ISO/IEC 19794-4:2005: 32-byte general header and a 14-byte
    // representation header. ICAO binds this format to one image per BIT.
    if data.len() < 47 || &data[..4] != b"FIR\0" || &data[4..8] != b"010\0" {
        return Err(invalid("invalid ISO 19794-4 finger header"));
    }
    let total = data[8..14]
        .iter()
        .fold(0u64, |length, octet| (length << 8) | u64::from(*octet));
    if total != data.len() as u64 || data[18] != 1 {
        return Err(invalid("invalid ISO 19794-4 finger record length or count"));
    }
    let image_block_length = u32::from_be_bytes(data[32..36].try_into().unwrap()) as usize;
    if image_block_length < 15 || image_block_length != data.len() - 32 {
        return Err(invalid("invalid ISO 19794-4 finger image length"));
    }
    if u16::from_be_bytes(data[41..43].try_into().unwrap()) == 0
        || u16::from_be_bytes(data[43..45].try_into().unwrap()) == 0
    {
        return Err(invalid("invalid ISO 19794-4 finger image dimensions"));
    }
    Ok(())
}

fn validate_19794_iris(data: &[u8], format_type: u16) -> EmrtdDataResult<()> {
    // ISO/IEC 19794-6:2005: 45-byte general header, then each eye's
    // three-byte subtype header and one or more 11-byte image headers.
    if data.len() < 16 || &data[..4] != b"IIR\0" {
        return Err(invalid("invalid ISO 19794-6 iris header"));
    }
    if &data[4..8] == b"020\0" && format_type == 0x0009 {
        return validate_19794_iris_2011(data);
    }
    if data.len() < 60 || !data[4..7].iter().all(u8::is_ascii_digit) || data[7] != 0 {
        return Err(invalid("unsupported ISO 19794-6 iris version"));
    }
    let total = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;
    let header_length = usize::from(u16::from_be_bytes(data[15..17].try_into().unwrap()));
    let subtypes = usize::from(data[14]);
    if total != data.len()
        || header_length < 45
        || header_length > data.len()
        || !(1..=2).contains(&subtypes)
    {
        return Err(invalid("invalid ISO 19794-6 iris record length or count"));
    }
    let mut offset = header_length;
    for _ in 0..subtypes {
        let subtype = data
            .get(offset..offset + 3)
            .ok_or_else(|| invalid("truncated ISO 19794-6 iris subtype"))?;
        let images = usize::from(u16::from_be_bytes(subtype[1..3].try_into().unwrap()));
        if images == 0 {
            return Err(invalid("empty ISO 19794-6 iris subtype"));
        }
        offset += 3;
        for _ in 0..images {
            let image_header = data
                .get(offset..offset + 11)
                .ok_or_else(|| invalid("truncated ISO 19794-6 iris image header"))?;
            let image_length = u32::from_be_bytes(image_header[7..11].try_into().unwrap()) as usize;
            if image_length == 0 {
                return Err(invalid("empty ISO 19794-6 iris image"));
            }
            offset = offset
                .checked_add(11)
                .and_then(|value| value.checked_add(image_length))
                .ok_or_else(|| invalid("ISO 19794-6 iris image length overflow"))?;
            if offset > data.len() {
                return Err(invalid("truncated ISO 19794-6 iris image"));
            }
        }
    }
    if offset != data.len() {
        return Err(invalid("trailing ISO 19794-6 iris data"));
    }
    Ok(())
}

fn validate_19794_iris_2011(data: &[u8]) -> EmrtdDataResult<()> {
    // ISO/IEC 19794-6:2011 uses a 16-byte header and length-framed
    // representation blocks. Its layout is distinct from the 2005 format.
    if data.len() < 69
        || u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize != data.len()
        || data[14] != 0
        || data[15] > 2
    {
        return Err(invalid("invalid ISO 19794-6:2011 iris header"));
    }
    let count = usize::from(u16::from_be_bytes(data[12..14].try_into().unwrap()));
    if count == 0 {
        return Err(invalid("empty ISO 19794-6:2011 iris representations"));
    }
    let mut offset = 16usize;
    for _ in 0..count {
        let header = data
            .get(offset..offset + 4)
            .ok_or_else(|| invalid("truncated ISO 19794-6:2011 representation"))?;
        let length = u32::from_be_bytes(header.try_into().unwrap()) as usize;
        if length < 53 {
            return Err(invalid("empty ISO 19794-6:2011 iris image"));
        }
        offset = offset
            .checked_add(length)
            .ok_or_else(|| invalid("ISO 19794-6:2011 representation length overflow"))?;
        if offset > data.len() {
            return Err(invalid("truncated ISO 19794-6:2011 iris image"));
        }
    }
    if offset != data.len() {
        return Err(invalid("trailing ISO 19794-6:2011 iris data"));
    }
    Ok(())
}

fn validate_tagged_binary_bdb(data: &[u8], application_tag: u32) -> EmrtdDataResult<()> {
    let envelope = parse_complete_tlv(data, 0xa1, "optional ISO 39794 BDB envelope")?;
    let record = parse_complete_tlv(envelope.value, application_tag, "optional ISO 39794 record")?;
    let version = parse_tlv(record.value, 0)?;
    if version.tag != 0xa0 {
        return Err(invalid("missing optional ISO 39794 version"));
    }
    verify_version(version.value)?;
    let representations = parse_tlv(record.value, version.next_offset)?;
    if representations.tag != 0xa1 || representations.value.is_empty() {
        return Err(invalid("missing optional ISO 39794 representations"));
    }
    let mut offset = 0;
    while offset < representations.value.len() {
        let representation = parse_tlv(representations.value, offset)?;
        if representation.tag != 0x30 {
            return Err(invalid("invalid optional ISO 39794 representation"));
        }
        verify_39794_biometric_representation(representation.value, application_tag)?;
        offset = representation.next_offset;
    }
    verify_39794_optional_fields(record.value, representations.next_offset, 1)?;
    Ok(())
}

fn verify_39794_biometric_representation(data: &[u8], application_tag: u32) -> EmrtdDataResult<()> {
    let required: &[u32] = match application_tag {
        0x64 => &[0xa0, 0xa1, 0xa2, 0x83],
        0x66 => &[0x80, 0xa1, 0x82, 0xa3, 0x84, 0x85, 0x86, 0xa7, 0x88],
        _ => return Err(invalid("unsupported optional ISO 39794 biometric type")),
    };
    let mut offset = 0;
    for (index, expected_tag) in required.iter().enumerate() {
        let field = parse_tlv(data, offset)?;
        if field.tag != *expected_tag {
            return Err(invalid("missing optional ISO 39794 representation field"));
        }
        der::Any::from_der(&data[offset..field.next_offset])
            .map_err(|_| invalid("non-DER optional ISO 39794 representation field"))?;
        if field.tag & 0x20 != 0 {
            let nested = parse_tlv(field.value, 0)?;
            if field.tag != 0xa7 && nested.next_offset != field.value.len() {
                return Err(invalid("invalid optional ISO 39794 choice"));
            }
            if field.tag == 0xa7 {
                if nested.tag != 0x80 {
                    return Err(invalid("invalid optional ISO 39794 capture date"));
                }
            } else if nested.tag == 0x80 {
                unsigned_der_integer(nested.value)?;
            } else if nested.tag == 0xa1 {
                if !matches!(field.tag, 0xa2 | 0xa3) && nested.value.is_empty() {
                    return Err(invalid("empty optional ISO 39794 choice extension"));
                }
            } else {
                return Err(invalid("invalid optional ISO 39794 choice"));
            }
        } else if field.tag == 0x83 || field.tag == 0x88 {
            if field.value.is_empty() {
                return Err(invalid("empty optional ISO 39794 biometric image"));
            }
        } else {
            unsigned_der_integer(field.value)?;
        }
        if field.tag == 0xa7 {
            let year = parse_tlv(field.value, 0)?;
            let value = unsigned_der_integer(year.value)?;
            if !(1900..=9999).contains(&value) {
                return Err(invalid("invalid optional ISO 39794 capture year"));
            }
            verify_39794_optional_fields(field.value, year.next_offset, 0)?;
        }
        offset = field.next_offset;
        if index == required.len() - 1 {
            verify_39794_optional_fields(data, offset, (required.len() - 1) as u32)?;
        }
    }
    Ok(())
}

fn verify_39794_optional_fields(
    data: &[u8],
    mut offset: usize,
    mut last: u32,
) -> EmrtdDataResult<()> {
    while offset < data.len() {
        let field = parse_tlv(data, offset)?;
        let number = context_tag_number(field.tag)?;
        if number <= last {
            return Err(invalid(
                "duplicate or out-of-order optional ISO 39794 field",
            ));
        }
        der::Any::from_der(&data[offset..field.next_offset])
            .map_err(|_| invalid("non-DER optional ISO 39794 extension"))?;
        last = number;
        offset = field.next_offset;
    }
    Ok(())
}

fn validate_displayed_images(data: &[u8], expected_tag: u32) -> EmrtdDataResult<()> {
    let count = parse_count(data, 0, false)?;
    if count.0 > 9 {
        return Err(invalid("too many displayed images"));
    }
    let mut offset = count.1;
    for _ in 0..count.0 {
        let image = parse_tlv(data, offset)?;
        if image.tag != expected_tag {
            return Err(invalid("invalid displayed image"));
        }
        verify_icao_image(image.value, None)?;
        offset = image.next_offset;
    }
    if offset != data.len() {
        return Err(invalid("trailing displayed image data"));
    }
    Ok(())
}

fn validate_proprietary_templates(data: &[u8]) -> EmrtdDataResult<()> {
    let count = parse_count(data, 0, false)?;
    if count.0 > 9 || count.1 == data.len() {
        return Err(invalid("invalid proprietary instance count or payload"));
    }
    // DG8-DG10 instance layout is issuer-defined. The SOD authenticates these
    // exact bytes; interpreting an assumed header/data TLV pair loses valid data.
    Ok(())
}

fn validate_tag_list_group(data: &[u8], group: u8) -> EmrtdDataResult<()> {
    let tag_list = parse_tlv(data, 0)?;
    if tag_list.tag != 0x5c || tag_list.value.is_empty() {
        return Err(invalid("missing data-group tag list"));
    }
    let declared = parse_tag_list(tag_list.value)?;
    let mut actual = Vec::new();
    let mut offset = tag_list.next_offset;
    while offset < data.len() {
        let field = parse_tlv(data, offset)?;
        if !allowed_personal_or_document_tag(group, field.tag) {
            return Err(invalid("invalid detail field tag"));
        }
        if field.tag == 0xa0 {
            validate_other_names(field.value, group)?;
        } else if field.value.is_empty() {
            return Err(invalid("empty detail field"));
        }
        if matches!((group, field.tag), (11, 0x5f2b) | (12, 0x5f26))
            && (field.value.len() != 8 || !field.value.iter().all(u8::is_ascii_digit))
        {
            return Err(invalid("invalid detail date"));
        }
        if (group, field.tag) == (12, 0x5f55)
            && (field.value.len() != 14 || !field.value.iter().all(u8::is_ascii_digit))
        {
            return Err(invalid("invalid personalization time"));
        }
        actual.push(field.tag);
        offset = field.next_offset;
    }
    if actual != declared {
        return Err(invalid("detail tag list differs from fields"));
    }
    Ok(())
}

fn parse_tag_list(data: &[u8]) -> EmrtdDataResult<Vec<u32>> {
    let mut tags = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let first = data[offset];
        offset += 1;
        let mut tag = u32::from(first);
        if first & 0x1f == 0x1f {
            loop {
                let next = *data
                    .get(offset)
                    .ok_or_else(|| invalid("truncated tag list"))?;
                offset += 1;
                tag = (tag << 8) | u32::from(next);
                if next & 0x80 == 0 {
                    break;
                }
                if offset > data.len() || tag > 0x00ff_ffff {
                    return Err(invalid("oversized tag list entry"));
                }
            }
        }
        if tags.contains(&tag) {
            return Err(invalid("duplicate detail tag list entry"));
        }
        tags.push(tag);
    }
    Ok(tags)
}

fn allowed_personal_or_document_tag(group: u8, tag: u32) -> bool {
    match group {
        11 => matches!(
            tag,
            0x5f0e | 0xa0 | 0x5f10 | 0x5f2b | 0x5f11 | 0x5f42 | 0x5f12..=0x5f18
        ),
        12 => matches!(
            tag,
            0x5f19 | 0x5f26 | 0xa0 | 0x5f1b..=0x5f1e | 0x5f55 | 0x5f56
        ),
        _ => false,
    }
}

fn validate_other_names(data: &[u8], group: u8) -> EmrtdDataResult<()> {
    let count = parse_count(data, 0, false)?;
    let expected = if group == 11 { 0x5f0f } else { 0x5f1a };
    let mut offset = count.1;
    for _ in 0..count.0 {
        let name = parse_tlv(data, offset)?;
        if name.tag != expected || name.value.is_empty() {
            return Err(invalid("invalid other-name field"));
        }
        offset = name.next_offset;
    }
    if offset != data.len() {
        return Err(invalid("trailing other-name data"));
    }
    Ok(())
}

fn validate_security_infos(data: &[u8]) -> EmrtdDataResult<()> {
    let infos = SetOfVec::<der::Any>::from_der(data)
        .map_err(|_| invalid("invalid DG14 SecurityInfos DER"))?;
    if infos.is_empty() {
        return Err(invalid("empty DG14 SecurityInfos"));
    }
    for info in infos.iter() {
        if info.tag() != der::Tag::Sequence {
            return Err(invalid("invalid DG14 SecurityInfo sequence"));
        }
        let fields = info.value();
        let protocol = parse_tlv(fields, 0)?;
        if protocol.tag != 0x06 {
            return Err(invalid("missing DG14 SecurityInfo protocol OID"));
        }
        if !valid_der_oid(protocol.value) {
            return Err(invalid("invalid DG14 SecurityInfo protocol OID"));
        }
        let required = parse_tlv(fields, protocol.next_offset)?;
        der::Any::from_der(&fields[protocol.next_offset..required.next_offset])
            .map_err(|_| invalid("invalid DG14 SecurityInfo requiredData"))?;
        if required.next_offset < fields.len() {
            let optional = parse_tlv(fields, required.next_offset)?;
            der::Any::from_der(&fields[required.next_offset..optional.next_offset])
                .map_err(|_| invalid("invalid DG14 SecurityInfo optionalData"))?;
            if optional.next_offset != fields.len() {
                return Err(invalid("trailing DG14 SecurityInfo data"));
            }
        }
    }
    Ok(())
}

fn valid_der_oid(value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut offset = 0;
    while offset < value.len() {
        // DER forbids a base-128 subidentifier with a redundant leading zero.
        if value[offset] == 0x80 {
            return false;
        }
        loop {
            let octet = value[offset];
            offset += 1;
            if octet & 0x80 == 0 {
                break;
            }
            if offset == value.len() {
                return false;
            }
        }
    }
    true
}

fn validate_active_auth_key(data: &[u8]) -> EmrtdDataResult<()> {
    let spki = SubjectPublicKeyInfoOwned::from_der(data)
        .map_err(|_| invalid("invalid DG15 active-auth public key"))?;
    if spki.to_der().map_err(|_| invalid("invalid DG15 DER"))? != data {
        return Err(invalid("non-canonical DG15 active-auth key"));
    }
    Ok(())
}

fn validate_notification_templates(data: &[u8]) -> EmrtdDataResult<()> {
    let count = parse_count(data, 0, false)?;
    if count.0 > 15 {
        return Err(invalid("too many DG16 notification templates"));
    }
    let mut offset = count.1;
    for index in 0..count.0 {
        let template = parse_tlv(data, offset)?;
        if template.tag != 0xa1 + u32::from(index) {
            return Err(invalid("invalid DG16 notification template tag"));
        }
        let mut inner = 0;
        let mut seen_date = false;
        let mut seen_name = false;
        let mut seen_phone = false;
        let mut seen_address = false;
        while inner < template.value.len() {
            let field = parse_tlv(template.value, inner)?;
            match field.tag {
                0x5f50
                    if field.value.len() == 8
                        && field.value.iter().all(u8::is_ascii_digit)
                        && !seen_date =>
                {
                    seen_date = true;
                }
                0x5f51 if !field.value.is_empty() && !seen_name => seen_name = true,
                0x5f52 if !field.value.is_empty() && !seen_phone => seen_phone = true,
                0x5f53 if !field.value.is_empty() && !seen_address => seen_address = true,
                _ => return Err(invalid("invalid DG16 notification field")),
            }
            inner = field.next_offset;
        }
        if !seen_date || !seen_name || !seen_phone || !seen_address {
            return Err(invalid("missing DG16 notification field"));
        }
        offset = template.next_offset;
    }
    if offset != data.len() {
        return Err(invalid("trailing DG16 notification data"));
    }
    Ok(())
}

fn parse_count(data: &[u8], offset: usize, zero_allowed: bool) -> EmrtdDataResult<(u8, usize)> {
    let count = parse_tlv(data, offset)?;
    if count.tag != 0x02 || count.value.len() != 1 || (count.value[0] == 0 && !zero_allowed) {
        return Err(invalid("invalid data-group instance count"));
    }
    Ok((count.value[0], count.next_offset))
}

fn invalid(message: &str) -> EmrtdDataError {
    EmrtdDataError::InvalidFormat(message.into())
}

#[cfg(test)]
mod tests {
    use super::{validate_icao_optional_dg, validate_known_biometric_record};

    fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
        let mut encoded = tag.to_vec();
        if value.len() < 128 {
            encoded.push(value.len() as u8);
        } else if value.len() <= u8::MAX as usize {
            encoded.extend([0x81, value.len() as u8]);
        } else if value.len() <= u16::MAX as usize {
            encoded.extend([0x82, (value.len() >> 8) as u8, value.len() as u8]);
        } else {
            encoded.extend([
                0x83,
                (value.len() >> 16) as u8,
                (value.len() >> 8) as u8,
                value.len() as u8,
            ]);
        }
        encoded.extend(value);
        encoded
    }

    fn finger_19794_record() -> Vec<u8> {
        let mut record = vec![0; 47];
        record[..4].copy_from_slice(b"FIR\0");
        record[4..8].copy_from_slice(b"010\0");
        record[13] = 47;
        record[18] = 1;
        record[19] = 1;
        record[28] = 8;
        record[35] = 15;
        record[36] = 1;
        record[37] = 1;
        record[38] = 1;
        record[39] = 100;
        record[42] = 1;
        record[44] = 1;
        record
    }

    fn iris_19794_record() -> Vec<u8> {
        let mut record = vec![0; 60];
        record[..4].copy_from_slice(b"IIR\0");
        record[4..8].copy_from_slice(b"010\0");
        record[11] = 60;
        record[14] = 1;
        record[16] = 45;
        record[45] = 1;
        record[47] = 1;
        record[49] = 1;
        record[50] = 100;
        record[58] = 1;
        record
    }

    #[test]
    fn zero_instance_biometric_group_allows_issuer_sibling() {
        let mut content = tlv(&[0x7f, 0x61], &[0x02, 0x01, 0x00]);
        content.extend(tlv(&[0x53], &[0x7a]));
        assert!(validate_icao_optional_dg(3, &tlv(&[0x63], &content)).is_ok());
        assert!(validate_icao_optional_dg(4, &tlv(&[0x76], &content)).is_ok());
    }

    #[test]
    fn biometric_group_requires_subtype_and_unique_header_fields() {
        let mut header = tlv(&[0x87], &[0x01, 0x01]);
        header.extend(tlv(&[0x88], &[0x00, 0x07]));
        let block = tlv(&[0x5f, 0x2e], &finger_19794_record());
        let make_group = |header: &[u8]| {
            let mut bit = tlv(&[0xa1], header);
            bit.extend(&block);
            let mut group = vec![0x02, 0x01, 0x01];
            group.extend(tlv(&[0x7f, 0x60], &bit));
            tlv(&[0x63], &tlv(&[0x7f, 0x61], &group))
        };
        assert!(validate_icao_optional_dg(3, &make_group(&header)).is_err());
        header.extend(tlv(&[0x82], &[0x00]));
        assert!(validate_icao_optional_dg(3, &make_group(&header)).is_ok());
        header.extend(tlv(&[0x82], &[0x00]));
        assert!(validate_icao_optional_dg(3, &make_group(&header)).is_err());
    }

    #[test]
    fn first_biometric_record_rejects_issuer_only_format() {
        let mut header = tlv(&[0x81], &[0x08]);
        header.extend(tlv(&[0x82], &[0x01]));
        header.extend(tlv(&[0x87], &[0x12, 0x34]));
        header.extend(tlv(&[0x88], &[0x56, 0x78]));
        let mut bit = tlv(&[0xa1], &header);
        bit.extend(tlv(&[0x5f, 0x2e], &[0x01]));
        let mut group = vec![0x02, 0x01, 0x01];
        group.extend(tlv(&[0x7f, 0x60], &bit));
        let dg3 = tlv(&[0x63], &tlv(&[0x7f, 0x61], &group));
        assert!(validate_icao_optional_dg(3, &dg3)
            .unwrap_err()
            .to_string()
            .contains("first optional biometric record"));
    }

    #[test]
    fn known_optional_biometric_formats_require_complete_records() {
        assert!(validate_known_biometric_record(
            0x08,
            0x0101,
            0x0007,
            0x5f2e,
            &finger_19794_record()
        )
        .is_ok());
        assert!(validate_known_biometric_record(0x08, 0x0101, 0x0007, 0x5f2e, b"FIR\0").is_err());
        assert!(validate_known_biometric_record(0x08, 0x0101, 0x0007, 0x5f2e, b"junk").is_err());
        assert!(validate_known_biometric_record(
            0x10,
            0x0101,
            0x000b,
            0x5f2e,
            &iris_19794_record()
        )
        .is_ok());
        assert!(validate_known_biometric_record(0x10, 0x0101, 0x000b, 0x5f2e, b"IIR\0").is_err());
        assert!(validate_known_biometric_record(0x10, 0x0101, 0x000b, 0x7f2e, b"IIR\0").is_err());
        let finger_39794 = tlv(&[0xa1], &tlv(&[0x64], &[0xa0, 0x00]));
        assert!(
            validate_known_biometric_record(0x08, 0x0101, 0x0028, 0x7f2e, &finger_39794).is_err()
        );
        assert!(validate_known_biometric_record(0x08, 0x0101, 0x0028, 0x7f2e, &[1]).is_err());
    }

    #[test]
    fn legacy_iris_numeric_versions_and_eye_count_follow_2005_layout() {
        let mut iris = iris_19794_record();
        iris[4..8].copy_from_slice(b"123\0");
        assert!(validate_known_biometric_record(0x10, 0x0101, 0x0009, 0x5f2e, &iris).is_ok());
        iris[14] = 3;
        assert!(validate_known_biometric_record(0x10, 0x0101, 0x0009, 0x5f2e, &iris).is_err());
    }

    #[test]
    #[ignore = "set ISO_39794_FINGER and ISO_39794_IRIS to ISO's official DER samples"]
    fn official_iso_39794_finger_and_iris_samples_decode_when_supplied() {
        for (variable, biometric_type, format_type) in [
            ("ISO_39794_FINGER", 0x08, 0x0028),
            ("ISO_39794_IRIS", 0x10, 0x002c),
        ] {
            let path = std::env::var(variable).expect("ISO sample path is required");
            let sample = std::fs::read(path).expect("ISO sample must be readable");
            let bdb = tlv(&[0xa1], &sample);
            assert!(
                validate_known_biometric_record(biometric_type, 0x0101, format_type, 0x7f2e, &bdb,)
                    .is_ok(),
                "official ISO 39794 sample failed for {variable}"
            );
        }
    }

    #[test]
    fn displayed_and_proprietary_instance_counts_are_bounded() {
        let mut displayed = vec![0x02, 0x01, 10];
        for _ in 0..10 {
            displayed.extend(tlv(&[0x5f, 0x40], &[0x01]));
        }
        assert!(validate_icao_optional_dg(5, &tlv(&[0x65], &displayed)).is_err());
        let proprietary = tlv(&[0x68], &[0x02, 0x01, 10, 0x01]);
        assert!(validate_icao_optional_dg(8, &proprietary).is_err());
        // The actual instance format is at the issuing state's discretion.
        assert!(validate_icao_optional_dg(8, &tlv(&[0x68], &[0x02, 0x01, 1, 0xff])).is_ok());
    }

    #[test]
    fn displayed_image_must_decode_as_jpeg_or_jpeg2000() {
        let image = include_bytes!("../../tests/fixtures/passport_face_2x2.jp2");
        let mut displayed = vec![0x02, 0x01, 1];
        displayed.extend(tlv(&[0x5f, 0x40], image));
        assert!(validate_icao_optional_dg(5, &tlv(&[0x65], &displayed)).is_ok());
        let fake = tlv(&[0x65], &[0x02, 0x01, 1, 0x5f, 0x40, 0x01, 0x01]);
        assert!(validate_icao_optional_dg(5, &fake).is_err());
    }

    #[test]
    fn detail_dates_have_declared_width() {
        let personal = tlv(&[0x6b], &[0x5c, 0x02, 0x5f, 0x2b, 0x5f, 0x2b, 0x01, b'2']);
        assert!(validate_icao_optional_dg(11, &personal).is_err());
        let document = tlv(&[0x6c], &[0x5c, 0x02, 0x5f, 0x55, 0x5f, 0x55, 0x01, b'2']);
        assert!(validate_icao_optional_dg(12, &document).is_err());
    }

    #[test]
    fn security_info_needs_oid_and_required_data() {
        let malformed = tlv(&[0x6e], &[0x31, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01]);
        assert!(validate_icao_optional_dg(14, &malformed).is_err());
        let valid = tlv(
            &[0x6e],
            &[
                0x31, 0x09, 0x30, 0x07, 0x06, 0x02, 0x2a, 0x03, 0x02, 0x01, 0x01,
            ],
        );
        assert!(validate_icao_optional_dg(14, &valid).is_ok());
    }

    #[test]
    fn notification_needs_unique_telephone_and_address() {
        let mut fields = tlv(&[0x5f, 0x50], b"20260101");
        fields.extend(tlv(&[0x5f, 0x51], b"DOE<<JANE"));
        fields.extend(tlv(&[0x5f, 0x53], b"address"));
        let wrap = |fields: &[u8]| {
            let mut content = vec![0x02, 0x01, 0x01];
            content.extend(tlv(&[0xa1], fields));
            tlv(&[0x70], &content)
        };
        assert!(validate_icao_optional_dg(16, &wrap(&fields)).is_err());
        fields.extend(tlv(&[0x5f, 0x52], b"+12025550100"));
        assert!(validate_icao_optional_dg(16, &wrap(&fields)).is_ok());
        fields.extend(tlv(&[0x5f, 0x52], b"+12025550101"));
        assert!(validate_icao_optional_dg(16, &wrap(&fields)).is_err());
    }
}
