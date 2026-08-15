//! Fail-closed verification helpers for compact JWT/JWS inputs.
//!
//! Product services retain claim and tenant policy composition, while this
//! module owns JOSE parsing, public-key validation, and signature verification.

use base64::Engine;
use jsonwebtoken::{
    crypto::verify as verify_jws_signature, decode, decode_header, jwk::Jwk, Algorithm,
    DecodingKey, Validation,
};
use serde::de::{Error as DeError, MapAccess, Visitor};
use serde::Deserializer;
use serde_json::{Map, Value};
use std::fmt;

use crate::error::{Oid4vciError, Oid4vciResult};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const PRIVATE_JWK_FIELDS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// A compact JWT whose signature has been verified with the supplied public JWK.
#[derive(Debug, Clone)]
pub struct VerifiedCompactJwt {
    /// Unique-member protected JOSE header.
    pub header: Value,
    /// Unique-member JSON claims object.
    pub claims: Value,
}

struct UniqueObjectVisitor;

impl<'de> Visitor<'de> for UniqueObjectVisitor {
    type Value = Map<String, Value>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object with unique member names")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some((name, value)) = access.next_entry::<String, Value>()? {
            if object.insert(name.clone(), value).is_some() {
                return Err(A::Error::custom(format!(
                    "duplicate JSON member is not allowed: {name}"
                )));
            }
        }
        Ok(object)
    }
}

pub(crate) fn parse_unique_object(bytes: &[u8], field: &str) -> Oid4vciResult<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let object = deserializer
        .deserialize_map(UniqueObjectVisitor)
        .map_err(|error| Oid4vciError::JwtError(format!("Invalid {field} JSON: {error}")))?;
    deserializer.end().map_err(|error| {
        Oid4vciError::JwtError(format!("Invalid trailing data in {field}: {error}"))
    })?;
    Ok(Value::Object(object))
}

/// Decode the protected header of a compact JWT without treating its claims as trusted.
///
/// This is crate-private so protocol validators can select an externally trusted
/// key before calling [`verify_compact_jwt_with_public_jwk`]. Callers must never
/// use the returned header as proof that the JWT is authentic.
pub(crate) fn decode_unverified_compact_jwt_header(compact_jwt: &str) -> Oid4vciResult<Value> {
    decode_unverified_compact_jwt(compact_jwt).map(|(header, _)| header)
}

/// Decode unique JOSE header and claim objects for protocol-specific key selection.
///
/// The values remain untrusted until a protocol validator selects an allowed key
/// and calls [`verify_compact_jwt_with_public_jwk`].
pub(crate) fn decode_unverified_compact_jwt(compact_jwt: &str) -> Oid4vciResult<(Value, Value)> {
    let parts: Vec<&str> = compact_jwt.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(Oid4vciError::JwtError(
            "Compact JWT must contain three non-empty parts".into(),
        ));
    }
    let header_bytes = B64.decode(parts[0]).map_err(|error| {
        Oid4vciError::JwtError(format!("Invalid JWT header base64url: {error}"))
    })?;
    let claims_bytes = B64.decode(parts[1]).map_err(|error| {
        Oid4vciError::JwtError(format!("Invalid JWT claims base64url: {error}"))
    })?;
    Ok((
        parse_unique_object(&header_bytes, "JWT header")?,
        parse_unique_object(&claims_bytes, "JWT claims")?,
    ))
}

fn algorithm(name: &str) -> Oid4vciResult<Algorithm> {
    match name {
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        "RS256" => Ok(Algorithm::RS256),
        "PS256" => Ok(Algorithm::PS256),
        _ => Err(Oid4vciError::JwtError(format!(
            "Unsupported JWT signature algorithm: {name}"
        ))),
    }
}

fn validate_public_jwk(value: &Value, expected_algorithm: &str) -> Oid4vciResult<Jwk> {
    let object = value
        .as_object()
        .ok_or_else(|| Oid4vciError::KeyError("Public JWK must be an object".into()))?;
    if let Some(field) = PRIVATE_JWK_FIELDS
        .iter()
        .find(|field| object.contains_key(**field))
    {
        return Err(Oid4vciError::KeyError(format!(
            "Public JWK contains private key material: {field}"
        )));
    }
    if let Some(value) = object.get("alg") {
        if value.as_str() != Some(expected_algorithm) {
            return Err(Oid4vciError::KeyError(
                "Public JWK alg does not match the JWT algorithm".into(),
            ));
        }
    }
    if let Some(value) = object.get("use") {
        if value.as_str() != Some("sig") {
            return Err(Oid4vciError::KeyError(
                "Public JWK use must be sig when present".into(),
            ));
        }
    }
    if let Some(operations) = object.get("key_ops") {
        let operations = operations
            .as_array()
            .ok_or_else(|| Oid4vciError::KeyError("Public JWK key_ops must be an array".into()))?;
        if operations.len() != 1 || operations[0].as_str() != Some("verify") {
            return Err(Oid4vciError::KeyError(
                "Public JWK key_ops must contain only verify".into(),
            ));
        }
    }
    serde_json::from_value(value.clone())
        .map_err(|error| Oid4vciError::KeyError(format!("Invalid public JWK: {error}")))
}

/// Verify a compact JWT with an explicitly trusted public JWK.
///
/// Registered-client and DPoP callers use this primitive after selecting the
/// applicable key and before applying protocol-specific claim policy. It does
/// not trust an embedded key, perform network resolution, or apply claim
/// defaults. Duplicate JOSE or claim members and private JWK material fail
/// closed.
pub fn verify_compact_jwt_with_public_jwk(
    compact_jwt: &str,
    public_jwk_json: &str,
    expected_algorithm: &str,
) -> Oid4vciResult<VerifiedCompactJwt> {
    let (header_value, claims) = decode_unverified_compact_jwt(compact_jwt)?;

    let expected = algorithm(expected_algorithm)?;
    let header = decode_header(compact_jwt)
        .map_err(|error| Oid4vciError::JwtError(format!("Invalid JWT header: {error}")))?;
    if header.alg != expected
        || header_value.get("alg").and_then(Value::as_str) != Some(expected_algorithm)
    {
        return Err(Oid4vciError::JwtError(
            "JWT algorithm does not match the expected algorithm".into(),
        ));
    }

    let public_jwk_value = parse_unique_object(public_jwk_json.as_bytes(), "public JWK")?;
    let public_jwk = validate_public_jwk(&public_jwk_value, expected_algorithm)?;
    let decoding_key = DecodingKey::from_jwk(&public_jwk).map_err(|error| {
        Oid4vciError::KeyError(format!("Could not construct JWT verification key: {error}"))
    })?;

    let mut validation = Validation::new(expected);
    validation.required_spec_claims.clear();
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    decode::<Value>(compact_jwt, &decoding_key, &validation).map_err(|error| {
        Oid4vciError::JwtError(format!("JWT signature verification failed: {error}"))
    })?;

    Ok(VerifiedCompactJwt {
        header: header_value,
        claims,
    })
}

/// Verify a detached signature with an explicitly trusted public JWK.
///
/// This is the native boundary used for provider/KMS sign-and-verify health
/// challenges. Public-key policy is identical to compact JWT verification:
/// private fields, algorithm confusion, non-signing use, and unexpected
/// `key_ops` fail closed. ECDSA signatures may use JOSE raw or ASN.1 DER form.
pub fn verify_detached_signature_with_public_jwk(
    message: &[u8],
    signature: &[u8],
    public_jwk_json: &str,
    expected_algorithm: &str,
) -> Oid4vciResult<bool> {
    let expected = algorithm(expected_algorithm)?;
    let public_jwk_value = parse_unique_object(public_jwk_json.as_bytes(), "public JWK")?;
    let public_jwk = validate_public_jwk(&public_jwk_value, expected_algorithm)?;
    let decoding_key = DecodingKey::from_jwk(&public_jwk).map_err(|error| {
        Oid4vciError::KeyError(format!(
            "Could not construct signature verification key: {error}"
        ))
    })?;

    let normalized_signature = match expected_algorithm {
        "ES256" | "ES384" => normalize_ecdsa_signature(signature, expected_algorithm)?,
        _ => signature.to_vec(),
    };
    let encoded_signature = B64.encode(normalized_signature);
    verify_jws_signature(&encoded_signature, message, &decoding_key, expected).map_err(|error| {
        Oid4vciError::JwtError(format!("Detached signature verification failed: {error}"))
    })
}

/// Normalize an ES256 or ES384 signature to IEEE P1363/JOSE encoding.
///
/// Remote signers commonly return ASN.1 DER while COSE and JWS carry the fixed
/// width `r || s` form. Raw signatures are length-checked and DER integers are
/// decoded in Rust so application adapters never perform cryptographic
/// encoding transformations.
pub fn normalize_ecdsa_signature(
    signature: &[u8],
    expected_algorithm: &str,
) -> Oid4vciResult<Vec<u8>> {
    marty_crypto::ecdsa::normalize_signature(signature, expected_algorithm)
        .map_err(|error| Oid4vciError::JwtError(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::EncodePrivateKey;
    use p256::SecretKey;
    use serde_json::json;

    fn signed_token() -> (String, String) {
        let secret = SecretKey::random(&mut rand::rngs::OsRng);
        let public = secret.public_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(public.x().expect("x coordinate"));
        let y = URL_SAFE_NO_PAD.encode(public.y().expect("y coordinate"));
        let jwk = json!({"kty":"EC","crv":"P-256","alg":"ES256","x":x,"y":y});
        let der = secret.to_pkcs8_der().expect("PKCS#8 key");
        let token = encode(
            &Header::new(Algorithm::ES256),
            &json!({"sub":"wallet","jti":"assertion-1"}),
            &EncodingKey::from_ec_der(der.as_bytes()),
        )
        .expect("signed JWT");
        (token, jwk.to_string())
    }

    #[test]
    fn verifies_public_jwk_and_returns_unique_json_objects() {
        let (token, jwk) = signed_token();
        let verified = verify_compact_jwt_with_public_jwk(&token, &jwk, "ES256")
            .expect("verified compact JWT");
        assert_eq!(verified.header["alg"], "ES256");
        assert_eq!(verified.claims["jti"], "assertion-1");
    }

    #[test]
    fn rejects_tampering_private_material_and_algorithm_confusion() {
        let (token, jwk) = signed_token();
        let mut tampered = token.into_bytes();
        let index = tampered.len() - 1;
        tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).expect("ASCII JWT");
        assert!(verify_compact_jwt_with_public_jwk(&tampered, &jwk, "ES256").is_err());

        let mut private_jwk: Value = serde_json::from_str(&jwk).expect("public JWK");
        private_jwk["d"] = Value::String("private".into());
        assert!(verify_compact_jwt_with_public_jwk(
            &signed_token().0,
            &private_jwk.to_string(),
            "ES256"
        )
        .is_err());
        assert!(verify_compact_jwt_with_public_jwk(&signed_token().0, &jwk, "PS256").is_err());
    }

    #[test]
    fn verifies_detached_raw_and_der_ecdsa_signatures() {
        let (token, jwk) = signed_token();
        let parts: Vec<&str> = token.split('.').collect();
        let message = format!("{}.{}", parts[0], parts[1]);
        let raw_signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("JWT signature encoding");

        assert!(verify_detached_signature_with_public_jwk(
            message.as_bytes(),
            &raw_signature,
            &jwk,
            "ES256"
        )
        .expect("raw signature verification"));

        let signature =
            p256::ecdsa::Signature::from_slice(&raw_signature).expect("raw P-256 signature");
        assert!(verify_detached_signature_with_public_jwk(
            message.as_bytes(),
            signature.to_der().as_bytes(),
            &jwk,
            "ES256"
        )
        .expect("DER signature verification"));

        assert!(!verify_detached_signature_with_public_jwk(
            b"tampered",
            &raw_signature,
            &jwk,
            "ES256"
        )
        .expect("invalid signature result"));

        assert_eq!(
            normalize_ecdsa_signature(signature.to_der().as_bytes(), "ES256")
                .expect("DER normalization"),
            raw_signature
        );
        assert!(normalize_ecdsa_signature(&raw_signature, "RS256").is_err());
    }
}
