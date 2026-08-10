//! Fail-closed verification helpers for compact JWT/JWS inputs.
//!
//! Product services retain claim and tenant policy composition, while this
//! module owns JOSE parsing, public-key validation, and signature verification.

use base64::Engine;
use jsonwebtoken::{decode, decode_header, jwk::Jwk, Algorithm, DecodingKey, Validation};
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

fn parse_unique_object(bytes: &[u8], field: &str) -> Oid4vciResult<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let object = deserializer
        .deserialize_map(UniqueObjectVisitor)
        .map_err(|error| Oid4vciError::JwtError(format!("Invalid {field} JSON: {error}")))?;
    deserializer.end().map_err(|error| {
        Oid4vciError::JwtError(format!("Invalid trailing data in {field}: {error}"))
    })?;
    Ok(Value::Object(object))
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
    if object
        .get("alg")
        .and_then(Value::as_str)
        .is_some_and(|value| value != expected_algorithm)
    {
        return Err(Oid4vciError::KeyError(
            "Public JWK alg does not match the JWT algorithm".into(),
        ));
    }
    if object
        .get("use")
        .and_then(Value::as_str)
        .is_some_and(|value| value != "sig")
    {
        return Err(Oid4vciError::KeyError(
            "Public JWK use must be sig when present".into(),
        ));
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
    let header_value = parse_unique_object(&header_bytes, "JWT header")?;
    let claims = parse_unique_object(&claims_bytes, "JWT claims")?;

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
}
