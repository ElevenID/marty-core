use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ensure_bounded, EmrtdDataError, EmrtdDataResult, MAX_EMRTD_DATA_BYTES};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u32,
    pub length: usize,
    pub value: &'a [u8],
    pub next_offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EfCom {
    /// Compatibility field retained for callers that observed the historical typo.
    pub lod_version: Option<String>,
    pub lds_version: Option<String>,
    pub unicode_version: Option<String>,
    pub data_groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MrzInfo {
    pub document_code: String,
    pub issuing_country: String,
    pub surname: String,
    pub given_names: String,
    pub passport_number: String,
    pub nationality: String,
    pub date_of_birth: String,
    pub sex: String,
    pub date_of_expiry: String,
    pub personal_number: Option<String>,
    pub check_digit_composite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BiometricInfo {
    pub biometric_type: u8,
    pub biometric_subtype: u8,
    pub creation_date: Option<String>,
    pub validity_period: Option<(String, String)>,
    pub creator: Option<String>,
    pub format_owner: u16,
    pub format_type: u16,
    pub quality: Option<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ElementaryFile {
    pub file_id: String,
    pub tag: u32,
    pub length: usize,
    pub data: Vec<u8>,
    pub parsed_content: Option<Value>,
}

pub fn parse_tlv(data: &[u8], offset: usize) -> EmrtdDataResult<Tlv<'_>> {
    ensure_bounded(data, "TLV data")?;
    if offset >= data.len() {
        return Err(EmrtdDataError::Truncated("offset is beyond TLV data"));
    }

    let mut cursor = offset;
    let first = data[cursor];
    cursor += 1;
    let mut tag = u32::from(first);
    if first & 0x1f == 0x1f {
        let mut tag_octets = 1usize;
        loop {
            let octet = *data
                .get(cursor)
                .ok_or(EmrtdDataError::Truncated("multi-byte tag"))?;
            cursor += 1;
            tag_octets += 1;
            if tag_octets > 4 {
                return Err(EmrtdDataError::InvalidTlv(
                    "tags longer than four octets are not supported".into(),
                ));
            }
            tag = (tag << 8) | u32::from(octet);
            if octet & 0x80 == 0 {
                break;
            }
        }
    }

    let first_length = *data
        .get(cursor)
        .ok_or(EmrtdDataError::Truncated("TLV length"))?;
    cursor += 1;
    let length = if first_length & 0x80 == 0 {
        usize::from(first_length)
    } else {
        let octets = usize::from(first_length & 0x7f);
        if octets == 0 {
            return Err(EmrtdDataError::InvalidTlv(
                "indefinite lengths are not supported".into(),
            ));
        }
        if octets > 4 {
            return Err(EmrtdDataError::InvalidTlv(
                "lengths longer than four octets are not supported".into(),
            ));
        }
        let length_bytes = data
            .get(cursor..cursor + octets)
            .ok_or(EmrtdDataError::Truncated("long-form TLV length"))?;
        if length_bytes[0] == 0 {
            return Err(EmrtdDataError::InvalidTlv(
                "non-canonical long-form length".into(),
            ));
        }
        cursor += octets;
        let mut value = 0usize;
        for octet in length_bytes {
            value = value
                .checked_mul(256)
                .and_then(|current| current.checked_add(usize::from(*octet)))
                .ok_or_else(|| EmrtdDataError::InvalidTlv("TLV length overflow".into()))?;
        }
        if value < 128 {
            return Err(EmrtdDataError::InvalidTlv(
                "non-minimal long-form length".into(),
            ));
        }
        value
    };

    if length > MAX_EMRTD_DATA_BYTES {
        return Err(EmrtdDataError::Oversized("TLV value"));
    }
    let next_offset = cursor
        .checked_add(length)
        .ok_or_else(|| EmrtdDataError::InvalidTlv("TLV length overflow".into()))?;
    let value = data
        .get(cursor..next_offset)
        .ok_or(EmrtdDataError::Truncated("TLV value"))?;

    Ok(Tlv {
        tag,
        length,
        value,
        next_offset,
    })
}

fn parse_complete_tlv<'a>(
    data: &'a [u8],
    expected_tag: u32,
    kind: &str,
) -> EmrtdDataResult<Tlv<'a>> {
    let tlv = parse_tlv(data, 0)?;
    if tlv.tag != expected_tag {
        return Err(EmrtdDataError::InvalidFormat(format!(
            "invalid {kind} tag 0x{:X}; expected 0x{expected_tag:X}",
            tlv.tag
        )));
    }
    if tlv.next_offset != data.len() {
        return Err(EmrtdDataError::InvalidTlv(format!(
            "trailing data after {kind}"
        )));
    }
    Ok(tlv)
}

pub fn parse_ef_com(data: &[u8]) -> EmrtdDataResult<EfCom> {
    let outer = parse_complete_tlv(data, 0x60, "EF.COM")?;
    let mut result = EfCom {
        lod_version: None,
        lds_version: None,
        unicode_version: None,
        data_groups: Vec::new(),
    };
    let mut offset = 0usize;
    while offset < outer.value.len() {
        let item = parse_tlv(outer.value, offset)?;
        match item.tag {
            0x5f01 => result.lds_version = Some(decode_ascii(item.value, "LDS version")?),
            0x5f36 => result.unicode_version = Some(decode_ascii(item.value, "Unicode version")?),
            0x5c => {
                for tag in item.value {
                    let group = match *tag {
                        0x61 => Some(1),
                        0x75 => Some(2),
                        0x63 => Some(3),
                        0x76 => Some(4),
                        0x65..=0x70 => Some(tag - 0x60),
                        _ => None,
                    };
                    if let Some(group) = group {
                        let name = format!("DG{group}");
                        if !result.data_groups.contains(&name) {
                            result.data_groups.push(name);
                        }
                    }
                }
            }
            _ => {}
        }
        offset = item.next_offset;
    }
    Ok(result)
}

pub fn parse_ef_dg1(data: &[u8]) -> EmrtdDataResult<MrzInfo> {
    let outer = parse_complete_tlv(data, 0x61, "EF.DG1")?;
    let mrz_tlv = parse_complete_tlv(outer.value, 0x5f1f, "DG1 MRZ")?;
    let text = decode_ascii(mrz_tlv.value, "MRZ")?;
    let owned_lines = if text.contains('\n') || text.contains('\r') {
        text.lines().map(str::to_owned).collect::<Vec<_>>()
    } else {
        let width = match text.len() {
            72 => 36,
            88 => 44,
            90 => 30,
            length => {
                return Err(EmrtdDataError::InvalidFormat(format!(
                    "unsupported MRZ byte length: {length}"
                )))
            }
        };
        text.as_bytes()
            .chunks(width)
            .map(|line| String::from_utf8(line.to_vec()).expect("ASCII already validated"))
            .collect()
    };
    let lines = owned_lines.iter().map(String::as_str).collect::<Vec<_>>();
    let parsed = crate::mrz::parse_mrz(&lines)
        .map_err(|error| EmrtdDataError::InvalidFormat(error.to_string()))?;

    Ok(MrzInfo {
        document_code: parsed.document_type,
        issuing_country: parsed.issuing_country,
        surname: parsed.surname,
        given_names: parsed.given_names,
        passport_number: parsed.document_number,
        nationality: parsed.nationality,
        date_of_birth: parsed.date_of_birth,
        sex: parsed.sex.to_string(),
        date_of_expiry: parsed.date_of_expiry,
        personal_number: (!parsed.optional_data.is_empty()).then_some(parsed.optional_data),
        check_digit_composite: parsed.composite_check.unwrap_or('<').to_string(),
    })
}

pub fn parse_ef_dg2(data: &[u8]) -> EmrtdDataResult<BiometricInfo> {
    let outer = parse_complete_tlv(data, 0x75, "EF.DG2")?;
    let template = parse_complete_tlv(outer.value, 0x7f2e, "DG2 biometric template")?;
    parse_biometric_information(template.value)
}

fn parse_biometric_information(data: &[u8]) -> EmrtdDataResult<BiometricInfo> {
    let mut result = BiometricInfo {
        biometric_type: 0,
        biometric_subtype: 0,
        creation_date: None,
        validity_period: None,
        creator: None,
        format_owner: 0,
        format_type: 0,
        quality: None,
        data: Vec::new(),
    };
    let mut offset = 0usize;
    while offset < data.len() {
        let field = parse_tlv(data, offset)?;
        match field.tag {
            0x81 => {}
            0x82 => result.biometric_type = one_byte(field.value, "biometric type")?,
            0x83 => result.biometric_subtype = one_byte(field.value, "biometric subtype")?,
            0x87 => result.format_owner = two_bytes(field.value, "format owner")?,
            0x88 => result.format_type = two_bytes(field.value, "format type")?,
            0x5f2e => result.data = field.value.to_vec(),
            _ => {}
        }
        offset = field.next_offset;
    }
    Ok(result)
}

pub fn parse_elementary_file(file_id: &str, data: &[u8]) -> EmrtdDataResult<ElementaryFile> {
    let outer = parse_tlv(data, 0)?;
    if outer.next_offset != data.len() {
        return Err(EmrtdDataError::InvalidTlv(
            "trailing data after elementary file".into(),
        ));
    }
    let parsed_content = match file_id {
        "EF.COM" => Some(serde_json::to_value(parse_ef_com(data)?).map_err(json_error)?),
        "EF.DG1" => Some(serde_json::to_value(parse_ef_dg1(data)?).map_err(json_error)?),
        "EF.DG2" => Some(serde_json::to_value(parse_ef_dg2(data)?).map_err(json_error)?),
        _ => None,
    };
    Ok(ElementaryFile {
        file_id: file_id.to_owned(),
        tag: outer.tag,
        length: outer.length,
        data: data.to_vec(),
        parsed_content,
    })
}

fn json_error(error: serde_json::Error) -> EmrtdDataError {
    EmrtdDataError::Encoding(format!("JSON serialization failed: {error}"))
}

fn decode_ascii(data: &[u8], kind: &str) -> EmrtdDataResult<String> {
    if !data.is_ascii() {
        return Err(EmrtdDataError::Encoding(format!(
            "{kind} must contain ASCII data"
        )));
    }
    String::from_utf8(data.to_vec())
        .map_err(|error| EmrtdDataError::Encoding(format!("invalid {kind}: {error}")))
}

fn one_byte(data: &[u8], kind: &str) -> EmrtdDataResult<u8> {
    data.first()
        .copied()
        .filter(|_| data.len() == 1)
        .ok_or_else(|| EmrtdDataError::InvalidFormat(format!("{kind} must be one byte")))
}

fn two_bytes(data: &[u8], kind: &str) -> EmrtdDataResult<u16> {
    let bytes: [u8; 2] = data
        .try_into()
        .map_err(|_| EmrtdDataError::InvalidFormat(format!("{kind} must be two bytes")))?;
    Ok(u16::from_be_bytes(bytes))
}
