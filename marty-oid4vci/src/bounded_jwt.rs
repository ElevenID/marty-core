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

/// Shared JOSE admission limits, independent of any crypto/role feature.
pub(crate) const JOSE_JWT_LIMITS: CompactJwtLimits = CompactJwtLimits {
    total: 256 * 1024,
    header: 144 * 1024,
    claims: 64 * 1024,
    signature: MAX_RSA_SIGNATURE_BYTES,
};

pub(crate) fn parse_unique_object(
    bytes: &[u8],
    field: &str,
) -> crate::Oid4vciResult<serde_json::Value> {
    let value = marty_crypto::strict_json::parse_unique_json(bytes)
        .map_err(|error| crate::Oid4vciError::JwtError(format!("Invalid {field} JSON: {error}")))?;
    if !value.is_object() {
        return Err(crate::Oid4vciError::JwtError(format!(
            "Invalid {field} JSON: expected an object"
        )));
    }
    Ok(value)
}

pub(crate) fn decode_unverified_compact_jwt(
    compact_jwt: &str,
) -> crate::Oid4vciResult<(serde_json::Value, serde_json::Value)> {
    let limits = JOSE_JWT_LIMITS;
    let parts = split_compact_jwt(compact_jwt, limits)
        .map_err(|message| crate::Oid4vciError::JwtError(message.into()))?;
    let header_bytes = decode_segment(
        parts.header,
        limits.header,
        "compact JWT header is not base64url",
        "compact JWT header exceeds its size limit",
    )
    .map_err(|message| crate::Oid4vciError::JwtError(message.into()))?;
    let claims_bytes = decode_segment(
        parts.claims,
        limits.claims,
        "compact JWT claims are not base64url",
        "compact JWT claims exceed their size limit",
    )
    .map_err(|message| crate::Oid4vciError::JwtError(message.into()))?;
    decode_segment(
        parts.signature,
        limits.signature,
        "compact JWT signature is not base64url",
        "compact JWT signature exceeds its size limit",
    )
    .map_err(|message| crate::Oid4vciError::JwtError(message.into()))?;
    Ok((
        parse_unique_object(&header_bytes, "JWT header")?,
        parse_unique_object(&claims_bytes, "JWT claims")?,
    ))
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
