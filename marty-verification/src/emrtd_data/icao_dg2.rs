//! ICAO Doc 9303 Part 10 EF.DG2 nesting, separate from the legacy flat reader.

use std::collections::BTreeSet;

use super::elementary::{parse_complete_tlv, parse_tlv};
use super::{EmrtdDataError, EmrtdDataResult};

/// One facial biometric data block in a nested ICAO BIT.
#[derive(Debug, Clone, Copy)]
pub struct IcaoFaceBiometric<'a> {
    /// `0x5f2e` for ISO 19794 or `0x7f2e` for ISO 39794.
    pub data_tag: u32,
    pub format_owner: u16,
    pub format_type: u16,
    pub data: &'a [u8],
}

/// Parse the complete DG2 `75 > 7F61 > 02 + 7F60*` envelope.
///
/// The instance count, BIT headers, required format identifiers, and exact
/// TLV boundaries are checked without modifying the signed source bytes.
pub fn parse_icao_ef_dg2(data: &[u8]) -> EmrtdDataResult<Vec<IcaoFaceBiometric<'_>>> {
    let outer = parse_complete_tlv(data, 0x75, "ICAO EF.DG2")?;
    let group = parse_complete_tlv(outer.value, 0x7f61, "DG2 BIT group")?;
    let count = parse_tlv(group.value, 0)?;
    if count.tag != 0x02 || count.value.len() != 1 || !(1..=9).contains(&count.value[0]) {
        return Err(invalid("DG2 biometric instance count"));
    }
    let mut offset = count.next_offset;
    let mut records = Vec::with_capacity(usize::from(count.value[0]));
    for _ in 0..count.value[0] {
        let bit = parse_tlv(group.value, offset)?;
        if bit.tag != 0x7f60 {
            return Err(invalid("DG2 BIT tag"));
        }
        records.push(parse_bit(bit.value)?);
        offset = bit.next_offset;
    }
    if offset != group.value.len() {
        return Err(invalid("trailing DG2 BIT data"));
    }
    Ok(records)
}

fn parse_bit(data: &[u8]) -> EmrtdDataResult<IcaoFaceBiometric<'_>> {
    let header = parse_tlv(data, 0)?;
    if header.tag != 0xa1 {
        return Err(invalid("DG2 biometric header"));
    }
    let mut owner = None;
    let mut format_type = None;
    let mut seen = BTreeSet::new();
    let mut offset = 0;
    while offset < header.value.len() {
        let field = parse_tlv(header.value, offset)?;
        if !seen.insert(field.tag) {
            return Err(invalid("duplicate DG2 biometric header field"));
        }
        match field.tag {
            0x80 if field.value == [0x01, 0x01] => {}
            0x81 if field.value == [0x02] => {}
            0x82 if field.value.len() == 1 => {}
            0x83 if field.value.len() == 7 => {}
            0x85 if field.value.len() == 8 => {}
            0x86 if field.value.len() == 4 => {}
            0x87 if field.value.len() == 2 => {
                owner = Some(u16::from_be_bytes([field.value[0], field.value[1]]));
            }
            0x88 if field.value.len() == 2 => {
                format_type = Some(u16::from_be_bytes([field.value[0], field.value[1]]));
            }
            _ => return Err(invalid("invalid DG2 biometric header field")),
        }
        offset = field.next_offset;
    }
    let bdb = parse_tlv(data, header.next_offset)?;
    if !matches!(bdb.tag, 0x5f2e | 0x7f2e) || bdb.value.is_empty() || bdb.next_offset != data.len()
    {
        return Err(invalid("invalid DG2 biometric data block"));
    }
    Ok(IcaoFaceBiometric {
        data_tag: bdb.tag,
        format_owner: owner.ok_or_else(|| invalid("missing DG2 format owner"))?,
        format_type: format_type.ok_or_else(|| invalid("missing DG2 format type"))?,
        data: bdb.value,
    })
}

fn invalid(message: &str) -> EmrtdDataError {
    EmrtdDataError::InvalidFormat(message.into())
}
