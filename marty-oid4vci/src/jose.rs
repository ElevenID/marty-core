//! Signing and fail-closed verification helpers for compact JWT/JWS inputs.
//!
//! Product services retain claim and tenant policy composition, while this
//! module owns JOSE encoding, parsing, key validation, signing, and verification.

use base64::Engine;
#[cfg(any(test, feature = "jose-verification"))]
use jsonwebtoken::{
    crypto::verify as verify_jws_signature, decode, decode_header, DecodingKey, Validation,
};
use jsonwebtoken::{
    jwk::{AlgorithmParameters, Jwk},
    Algorithm,
};
use serde_json::Value;

use crate::bounded_jwt::JOSE_JWT_LIMITS;
use crate::error::{Oid4vciError, Oid4vciResult};

/// Construct an ES256 compact JWS with a scoped, non-exportable test KMS key.
#[cfg(test)]
pub(crate) fn sign_test_compact_es256(
    signer: &crate::openbao_transit::ScopedTransitSigner,
    header: &serde_json::Value,
    payload: &serde_json::Value,
) -> String {
    let protected = B64.encode(serde_json::to_vec(header).expect("test header JSON"));
    let payload = B64.encode(serde_json::to_vec(payload).expect("test payload JSON"));
    let signing_input = format!("{protected}.{payload}");
    let signature = signer
        .sign(signing_input.as_bytes())
        .expect("remote ES256 signature");
    format!("{signing_input}.{}", B64.encode(signature))
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const PRIVATE_JWK_FIELDS: &[&str] = &["d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k"];
/// Maximum compact JWT accepted by the direct JOSE verification boundary.
pub const MAX_COMPACT_JWT_BYTES: usize = JOSE_JWT_LIMITS.total;
/// Maximum public JWK JSON accepted by direct JOSE verification helpers.
pub const MAX_PUBLIC_JWK_BYTES: usize = 16 * 1024;
#[cfg(feature = "wallet")]
pub(crate) const MAX_JWT_CLAIMS_BYTES: usize = JOSE_JWT_LIMITS.claims;

/// A compact JWT whose signature has been verified with the supplied public JWK.
#[derive(Debug, Clone)]
pub struct VerifiedCompactJwt {
    /// Unique-member protected JOSE header.
    pub header: Value,
    /// Unique-member JSON claims object.
    pub claims: Value,
}

pub(crate) fn parse_unique_object(bytes: &[u8], field: &str) -> Oid4vciResult<Value> {
    crate::bounded_jwt::parse_unique_object(bytes, field)
}

/// Decode the protected header of a compact JWT without treating its claims as trusted.
///
/// This is crate-private so protocol validators can select an externally trusted
/// key before calling `verify_compact_jwt_with_public_jwk`. Callers must never
/// use the returned header as proof that the JWT is authentic.
#[cfg(feature = "jose-verification")]
pub(crate) fn decode_unverified_compact_jwt_header(compact_jwt: &str) -> Oid4vciResult<Value> {
    decode_unverified_compact_jwt(compact_jwt).map(|(header, _)| header)
}

/// Decode unique JOSE header and claim objects for protocol-specific key selection.
///
/// The values remain untrusted until a protocol validator selects an allowed key
/// and calls `verify_compact_jwt_with_public_jwk`.
pub(crate) fn decode_unverified_compact_jwt(compact_jwt: &str) -> Oid4vciResult<(Value, Value)> {
    let (header, claims) = crate::bounded_jwt::decode_unverified_compact_jwt(compact_jwt)?;
    // `Header::jwk` is optional, so retain its absent/null behavior. An embedded
    // key is still untrusted, but JWT 11 must not widen its admitted shapes even
    // when verification will use a separately trusted public key.
    if let Some(jwk) = header.get("jwk").filter(|value| !value.is_null()) {
        parse_public_asymmetric_jwk(jwk)
            .map_err(|_| Oid4vciError::JwtError("Invalid protected header public JWK".into()))?;
    }
    Ok((header, claims))
}

fn algorithm(name: &str) -> Oid4vciResult<Algorithm> {
    match name {
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        _ => Err(Oid4vciError::JwtError(format!(
            "Unsupported JWT signature algorithm: {name}"
        ))),
    }
}

/// Parse only the public asymmetric key shapes admitted before JWT 11.
///
/// JWT 11 preserves unknown or malformed key parameters in `Other`. Successful
/// deserialization alone therefore does not establish public-key admission.
/// Algorithm and profile policy remains with the caller.
pub(crate) fn parse_public_asymmetric_jwk(value: &Value) -> Oid4vciResult<Jwk> {
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
    if !matches!(
        object.get("kty").and_then(Value::as_str),
        Some("EC" | "RSA" | "OKP")
    ) {
        return Err(Oid4vciError::KeyError(
            "Public JWK must contain a known asymmetric key type".into(),
        ));
    }
    let jwk: Jwk = serde_json::from_value(value.clone())
        .map_err(|error| Oid4vciError::KeyError(format!("Invalid public JWK: {error}")))?;
    validate_public_jwk_shape(&jwk)?;
    Ok(jwk)
}

pub(crate) fn validate_public_jwk_shape(jwk: &Jwk) -> Oid4vciResult<()> {
    if !matches!(
        &jwk.algorithm,
        AlgorithmParameters::EllipticCurve(_)
            | AlgorithmParameters::RSA(_)
            | AlgorithmParameters::OctetKeyPair(_)
    ) {
        return Err(Oid4vciError::KeyError(
            "Public JWK must contain supported asymmetric key parameters".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_public_jwk(value: &Value, expected_algorithm: &str) -> Oid4vciResult<Jwk> {
    let jwk = parse_public_asymmetric_jwk(value)?;
    if let Some(value) = value.get("alg") {
        if value.as_str() != Some(expected_algorithm) {
            return Err(Oid4vciError::KeyError(
                "Public JWK alg does not match the JWT algorithm".into(),
            ));
        }
    }
    if let Some(value) = value.get("use") {
        if value.as_str() != Some("sig") {
            return Err(Oid4vciError::KeyError(
                "Public JWK use must be sig when present".into(),
            ));
        }
    }
    if let Some(operations) = value.get("key_ops") {
        let operations = operations
            .as_array()
            .ok_or_else(|| Oid4vciError::KeyError("Public JWK key_ops must be an array".into()))?;
        if operations.len() != 1 || operations[0].as_str() != Some("verify") {
            return Err(Oid4vciError::KeyError(
                "Public JWK key_ops must contain only verify".into(),
            ));
        }
    }
    Ok(jwk)
}

#[cfg(any(test, feature = "jose-verification"))]
fn parse_public_signing_jwk(public_jwk_json: &str, expected_algorithm: &str) -> Oid4vciResult<Jwk> {
    if public_jwk_json.len() > MAX_PUBLIC_JWK_BYTES {
        return Err(Oid4vciError::KeyError(
            "Public JWK exceeds its size limit".into(),
        ));
    }
    let value = parse_unique_object(public_jwk_json.as_bytes(), "public JWK")?;
    validate_public_jwk(&value, expected_algorithm)
}

/// Check the same public-key policy used by JOSE verification before contacting a signer.
///
/// This validates bounded unique JSON, absence of private material, signing use,
/// algorithm metadata and decoding-key construction. Signature verification is
/// still required to prove that a signer controls the corresponding key.
#[cfg(any(test, feature = "jose-verification"))]
pub fn validate_public_signing_jwk_json(
    public_jwk_json: &str,
    expected_algorithm: &str,
) -> Oid4vciResult<()> {
    algorithm(expected_algorithm)?;
    let jwk = parse_public_signing_jwk(public_jwk_json, expected_algorithm)?;
    DecodingKey::from_jwk(&jwk).map(|_| ()).map_err(|_| {
        Oid4vciError::KeyError("Could not construct public signature verification key".into())
    })
}

/// Verify a compact JWT with an explicitly trusted public JWK.
///
/// Registered-client and DPoP callers use this primitive after selecting the
/// applicable key and before applying protocol-specific claim policy. It does
/// not trust an embedded key, perform network resolution, or apply claim
/// defaults. Duplicate JOSE or claim members and private JWK material fail
/// closed.
#[cfg(any(test, feature = "jose-verification"))]
pub fn verify_compact_jwt_with_public_jwk(
    compact_jwt: &str,
    public_jwk_json: &str,
    expected_algorithm: &str,
) -> Oid4vciResult<VerifiedCompactJwt> {
    sd_jwt_rs::install_crypto_provider().map_err(|error| {
        Oid4vciError::JwtError(format!("JWT verification backend unavailable: {error}"))
    })?;
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

    let public_jwk = parse_public_signing_jwk(public_jwk_json, expected_algorithm)?;
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
#[cfg(any(test, feature = "jose-verification"))]
pub fn verify_detached_signature_with_public_jwk(
    message: &[u8],
    signature: &[u8],
    public_jwk_json: &str,
    expected_algorithm: &str,
) -> Oid4vciResult<bool> {
    sd_jwt_rs::install_crypto_provider().map_err(|error| {
        Oid4vciError::JwtError(format!("JWT verification backend unavailable: {error}"))
    })?;
    let expected = algorithm(expected_algorithm)?;
    let public_jwk = parse_public_signing_jwk(public_jwk_json, expected_algorithm)?;
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
    use serde_json::json;

    fn signed_token() -> (String, String) {
        let signer = crate::openbao_transit::DisposableOpenBao::from_marked_env().create_es256();
        let mut jwk: Value = serde_json::from_str(signer.public_jwk()).expect("public JWK");
        jwk["alg"] = json!("ES256");
        let token = sign_test_compact_es256(
            &signer,
            &json!({"alg":"ES256","typ":"JWT"}),
            &json!({"sub":"wallet","jti":"assertion-1"}),
        );
        (token, jwk.to_string())
    }

    fn public_curve_vectors() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/wasm_provider_public.json"))
            .expect("fixed public verification vectors")
    }

    #[test]
    fn public_jwk_admission_rejects_unknown_and_malformed_key_shapes() {
        for jwk in [
            json!({}),
            json!({"kty": "future-key-family", "public": "opaque"}),
            json!({"kty": "oct"}),
            json!({"kty": "EC", "crv": "P-256", "x": "AA"}),
            json!({"kty": "EC", "crv": "future-curve", "x": "AA", "y": "AA"}),
            json!({"kty": "RSA", "n": "AQAB"}),
            json!({"kty": "RSA", "n": 17, "e": "AQAB"}),
            json!({"kty": "OKP", "crv": "Ed25519"}),
            json!({"kty": "OKP", "crv": "future-curve", "x": "AA"}),
        ] {
            assert!(matches!(
                validate_public_jwk(&jwk, "ES256"),
                Err(Oid4vciError::KeyError(_))
            ));
        }
    }

    #[test]
    fn protected_header_jwk_keeps_known_shapes_and_rejects_parser_fallbacks() {
        let compact = |header: Value| {
            format!(
                "{}.e30.AA",
                B64.encode(serde_json::to_vec(&header).unwrap())
            )
        };
        let public = json!({
            "kty": "OKP", "crv": "Ed25519",
            "x": public_curve_vectors()["ed25519"]["x"]
        });
        for header in [
            json!({"alg": "EdDSA"}),
            json!({"alg": "EdDSA", "jwk": null}),
            json!({"alg": "EdDSA", "jwk": public}),
        ] {
            let (parsed, claims) = decode_unverified_compact_jwt(&compact(header.clone())).unwrap();
            assert_eq!(parsed, header);
            assert_eq!(claims, json!({}));
        }
        for jwk in [
            json!({"kty": "future-key-family", "public": "opaque"}),
            json!({"kty": "EC", "crv": "P-256", "x": "AA"}),
            json!({"kty": "RSA", "n": "AQAB"}),
            json!({"kty": "OKP", "crv": "Ed25519"}),
        ] {
            let token = compact(json!({"alg": "EdDSA", "jwk": jwk}));
            assert!(
                decode_header(&token).is_ok(),
                "JWT 11 preserves these shapes"
            );
            assert!(decode_unverified_compact_jwt(&token).is_err());
            let error = verify_compact_jwt_with_public_jwk(&token, &public.to_string(), "EdDSA")
                .unwrap_err();
            assert!(error.to_string().contains("protected header public JWK"));
        }
    }

    #[test]
    fn known_public_key_shapes_keep_algorithm_and_usage_metadata_policy() {
        let vectors = public_curve_vectors();
        for (algorithm, mut jwk) in [
            (
                "ES384",
                json!({"kty": "EC", "crv": "P-384", "x": vectors["p384"]["x"], "y": vectors["p384"]["y"]}),
            ),
            (
                "EdDSA",
                json!({"kty": "OKP", "crv": "Ed25519", "x": vectors["ed25519"]["x"]}),
            ),
            (
                "RS256",
                json!({"kty": "RSA", "n": B64.encode([0xA5; 256]), "e": "AQAB"}),
            ),
        ] {
            assert!(validate_public_jwk(&jwk, algorithm).is_ok());
            jwk["alg"] = json!(algorithm);
            jwk["use"] = json!("sig");
            jwk["key_ops"] = json!(["verify"]);
            assert!(validate_public_jwk(&jwk, algorithm).is_ok());
            for (field, value) in [
                ("alg", json!("HS256")),
                ("use", json!("enc")),
                ("key_ops", json!(["sign"])),
                ("key_ops", json!(["verify", "sign"])),
            ] {
                let mut rejected = jwk.clone();
                rejected[field] = value;
                assert!(validate_public_jwk(&rejected, algorithm).is_err());
            }
            for member in PRIVATE_JWK_FIELDS {
                let mut rejected = jwk.clone();
                rejected[*member] = Value::Null;
                assert!(validate_public_jwk(&rejected, algorithm).is_err());
            }
        }
    }

    #[test]
    fn shared_provider_verifies_public_vectors_and_rejects_algorithm_confusion() {
        let vectors = public_curve_vectors();
        for (algorithm, jwk, vector) in [
            (
                "ES384",
                json!({"kty": "EC", "crv": "P-384", "x": vectors["p384"]["x"], "y": vectors["p384"]["y"]}),
                &vectors["p384"],
            ),
            (
                "EdDSA",
                json!({"kty": "OKP", "crv": "Ed25519", "x": vectors["ed25519"]["x"]}),
                &vectors["ed25519"],
            ),
        ] {
            let public = jwk.to_string();
            let signature = B64.decode(vector["signature"].as_str().unwrap()).unwrap();
            assert!(verify_detached_signature_with_public_jwk(
                b"shared browser verification provider",
                &signature,
                &public,
                algorithm,
            )
            .unwrap());
            assert!(!verify_detached_signature_with_public_jwk(
                b"changed message",
                &signature,
                &public,
                algorithm,
            )
            .unwrap());
            for rejected_algorithm in ["HS256", "none", "ES512", "RS256"] {
                assert!(verify_detached_signature_with_public_jwk(
                    b"shared browser verification provider",
                    &signature,
                    &public,
                    rejected_algorithm,
                )
                .is_err());
            }
        }
    }

    #[test]
    fn shared_provider_never_enables_local_signing_or_private_key_conversion() {
        use jsonwebtoken::{errors::ErrorKind, EncodingKey};

        sd_jwt_rs::install_crypto_provider().unwrap();
        for (algorithm, key) in [
            (Algorithm::ES256, EncodingKey::from_ec_der(&[0; 48])),
            (Algorithm::EdDSA, EncodingKey::from_ed_der(&[0; 48])),
            (Algorithm::RS256, EncodingKey::from_rsa_der(&[0; 48])),
            (
                Algorithm::HS256,
                EncodingKey::from_secret(b"not a credential key"),
            ),
        ] {
            let error = jsonwebtoken::crypto::sign(b"prepared.payload", &key, algorithm)
                .expect_err("Core must use the verification-only provider");
            assert!(matches!(error.kind(), ErrorKind::Provider(_)));
            if algorithm != Algorithm::HS256 {
                assert!(matches!(
                    Jwk::from_encoding_key(&key, algorithm).unwrap_err().kind(),
                    ErrorKind::Provider(_)
                ));
            }
        }
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn verifies_public_jwk_and_returns_unique_json_objects() {
        let (token, jwk) = signed_token();
        let verified = verify_compact_jwt_with_public_jwk(&token, &jwk, "ES256")
            .expect("verified compact JWT");
        assert_eq!(verified.header["alg"], "ES256");
        assert_eq!(verified.claims["jti"], "assertion-1");
    }

    #[test]
    fn unique_json_parser_rejects_nested_duplicate_members() {
        let error = parse_unique_object(br#"{"cnf":{"jwk":{"kty":"EC","kty":"oct"}}}"#, "claims")
            .unwrap_err();
        assert!(error.to_string().contains("duplicate JSON object member"));
    }

    #[test]
    fn unique_object_wrapper_keeps_root_policy_and_field_diagnostics() {
        for raw in [b"null".as_slice(), b"[]", b"true", b"42"] {
            let Oid4vciError::JwtError(message) = parse_unique_object(raw, "claims").unwrap_err()
            else {
                panic!("expected JWT error");
            };
            assert_eq!(message, "Invalid claims JSON: expected an object");
        }
        let Oid4vciError::JwtError(message) =
            parse_unique_object(br#"{"a":1,"\u0061":2}"#, "header").unwrap_err()
        else {
            panic!("expected JWT error");
        };
        assert!(message.starts_with("Invalid header JSON: duplicate JSON object member"));
        assert!(message.contains("line 1 column"));
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn rejects_tampering_private_material_and_algorithm_confusion() {
        let (token, jwk) = signed_token();
        let (input, encoded_signature) = token.rsplit_once('.').expect("compact JWS");
        let mut signature = URL_SAFE_NO_PAD
            .decode(encoded_signature)
            .expect("signature encoding");
        signature[0] ^= 1;
        let tampered = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
        assert!(verify_compact_jwt_with_public_jwk(&tampered, &jwk, "ES256").is_err());

        for member in PRIVATE_JWK_FIELDS {
            let mut private_jwk: Value = serde_json::from_str(&jwk).expect("public JWK");
            private_jwk[*member] = Value::String("private".into());
            assert!(
                verify_compact_jwt_with_public_jwk(&token, &private_jwk.to_string(), "ES256")
                    .is_err()
            );
        }
        assert!(verify_compact_jwt_with_public_jwk(&token, &jwk, "PS256").is_err());
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn direct_jose_inputs_are_bounded_before_decode_and_key_parsing() {
        let oversized =
            "secret-sentinel".repeat(MAX_COMPACT_JWT_BYTES / "secret-sentinel".len() + 1);
        let error =
            verify_compact_jwt_with_public_jwk(&oversized, "not-json", "ES256").unwrap_err();
        assert!(error.to_string().contains("size limit"));
        assert!(!error.to_string().contains("secret-sentinel"));

        let many_parts = std::iter::repeat_n("secret-sentinel", 10_000)
            .collect::<Vec<_>>()
            .join(".");
        let error =
            verify_compact_jwt_with_public_jwk(&many_parts, "not-json", "ES256").unwrap_err();
        assert!(error.to_string().contains("exactly three"));
        assert!(!error.to_string().contains("secret-sentinel"));

        let (token, _) = signed_token();
        let oversized_jwk = " ".repeat(MAX_PUBLIC_JWK_BYTES + 1);
        let error =
            verify_compact_jwt_with_public_jwk(&token, &oversized_jwk, "ES256").unwrap_err();
        assert!(error.to_string().contains("JWK exceeds"));
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
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
