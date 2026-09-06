use base64::Engine;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub(crate) const MAX_RSA_SIGNATURE_BYTES: usize = 1024;

#[derive(Clone, Copy)]
pub(crate) struct CompactJwtLimits {
    pub total: usize,
    pub header: usize,
    pub claims: usize,
    pub signature: usize,
}

pub(crate) struct CompactJwtSegments<'a> {
    pub header: &'a str,
    pub claims: &'a str,
    pub signature: &'a str,
}

const fn max_encoded_len(decoded: usize) -> usize {
    decoded.div_ceil(3) * 4
}

pub(crate) fn split_compact_jwt(
    compact: &str,
    limits: CompactJwtLimits,
) -> Result<CompactJwtSegments<'_>, &'static str> {
    if compact.is_empty() || compact.len() > limits.total {
        return Err("compact JWT exceeds its size limit");
    }
    let (header, remainder) = compact
        .split_once('.')
        .ok_or("compact JWT must contain exactly three non-empty parts")?;
    let (claims, signature) = remainder
        .split_once('.')
        .ok_or("compact JWT must contain exactly three non-empty parts")?;
    if header.is_empty() || claims.is_empty() || signature.is_empty() || signature.contains('.') {
        return Err("compact JWT must contain exactly three non-empty parts");
    }
    if header.len() > max_encoded_len(limits.header) {
        return Err("compact JWT header exceeds its size limit");
    }
    if claims.len() > max_encoded_len(limits.claims) {
        return Err("compact JWT claims exceed their size limit");
    }
    if signature.len() > max_encoded_len(limits.signature) {
        return Err("compact JWT signature exceeds its size limit");
    }
    Ok(CompactJwtSegments {
        header,
        claims,
        signature,
    })
}

pub(crate) fn decode_segment(
    encoded: &str,
    max_decoded: usize,
    invalid_message: &'static str,
    oversized_message: &'static str,
) -> Result<Vec<u8>, &'static str> {
    if encoded.len() > max_encoded_len(max_decoded) {
        return Err(oversized_message);
    }
    let decoded = B64.decode(encoded).map_err(|_| invalid_message)?;
    if decoded.len() > max_decoded {
        return Err(oversized_message);
    }
    if B64.encode(&decoded) != encoded {
        return Err(invalid_message);
    }
    Ok(decoded)
}
