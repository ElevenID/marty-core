//! Proof-of-possession verification and creation for OID4VCI (§8.2).
//!
//! This module implements cryptographic verification of JWT proofs submitted
//! with credential requests. This replaces the previous insecure approach of
//! only extracting the `kid` header without signature verification.
//!
//! It also exposes `create_proof_jwt` for generating spec-correct holder
//! proof-of-possession JWTs (e.g. for integration tests and wallet clients).

use base64::Engine;
#[cfg(any(test, feature = "holder-key-operations"))]
use ed25519_dalek::{Signer, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
#[cfg(any(test, feature = "holder-key-operations"))]
use rand::rngs::OsRng;
use serde::Deserialize;
use ssi_jwk::{Params, JWK};

use crate::bounded_jwt::{decode_segment, split_compact_jwt, CompactJwtLimits};
use crate::error::{Oid4vciError, Oid4vciResult};

/// Maximum compact OID4VCI proof JWT accepted before parsing or key resolution.
pub const MAX_COMPACT_PROOF_JWT_BYTES: usize = 256 * 1024;
/// Maximum already-validated key-attestation JWT accepted at the proof boundary.
pub const MAX_COMPACT_KEY_ATTESTATION_JWT_BYTES: usize = 128 * 1024;
const MAX_PROOF_HEADER_BYTES: usize = 144 * 1024;
const MAX_PROOF_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_ATTESTATION_HEADER_BYTES: usize = 16 * 1024;
const MAX_ATTESTATION_PAYLOAD_BYTES: usize = 96 * 1024;
const MAX_JWT_SIGNATURE_BYTES: usize = crate::bounded_jwt::MAX_RSA_SIGNATURE_BYTES;
const PROOF_JWT_LIMITS: CompactJwtLimits = CompactJwtLimits {
    total: MAX_COMPACT_PROOF_JWT_BYTES,
    header: MAX_PROOF_HEADER_BYTES,
    claims: MAX_PROOF_PAYLOAD_BYTES,
    signature: MAX_JWT_SIGNATURE_BYTES,
};
const ATTESTATION_JWT_LIMITS: CompactJwtLimits = CompactJwtLimits {
    total: MAX_COMPACT_KEY_ATTESTATION_JWT_BYTES,
    header: MAX_ATTESTATION_HEADER_BYTES,
    claims: MAX_ATTESTATION_PAYLOAD_BYTES,
    signature: MAX_JWT_SIGNATURE_BYTES,
};

/// Parsed and verified JWT proof from a credential request.
#[derive(Debug, Clone)]
pub struct VerifiedProof {
    /// The holder's DID or key identifier (from JWT `kid` header or `iss` claim).
    pub holder_id: String,
    /// The JWK from the proof (if provided via `jwk` header).
    pub holder_jwk: Option<JWK>,
    /// The c_nonce that was proven.
    pub nonce: Option<String>,
    /// The audience (should match credential issuer URL).
    pub audience: Option<String>,
    /// Issued-at timestamp.
    pub iat: Option<i64>,
}

/// JWT proof header fields we need to extract.
#[derive(Debug, Deserialize)]
struct ProofHeader {
    /// Algorithm used for signing.
    alg: String,
    /// Key ID (DID URL or key reference).
    #[serde(default)]
    kid: Option<String>,
    /// JWK public key (if not using kid).
    #[serde(default)]
    jwk: Option<serde_json::Value>,
    /// Type (must be "openid4vci-proof+jwt").
    #[serde(default)]
    typ: Option<String>,
    /// A key attestation JWT validated by the issuer's tenant-bound policy.
    #[serde(default)]
    key_attestation: Option<String>,
}

enum ProofKeySource<'a> {
    Header,
    ValidatedKeyAttestation { jwt: &'a str },
}

#[derive(Debug, Deserialize)]
struct KeyAttestationPayload {
    attested_keys: Vec<JWK>,
}

/// JWT proof payload fields.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ProofPayload {
    /// Issuer (holder DID).
    #[serde(default)]
    iss: Option<String>,
    /// Audience (credential issuer URL).
    #[serde(default)]
    aud: Option<String>,
    /// Issued at.
    #[serde(default)]
    iat: Option<i64>,
    /// Expiration.
    #[serde(default)]
    exp: Option<i64>,
    /// The c_nonce value.
    #[serde(default)]
    nonce: Option<String>,
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Verify a JWT proof of possession from a credential request.
///
/// Performs the following checks per OID4VCI v1 §8.2:
/// 1. JWT structure validation (3 parts, valid base64url)
/// 2. Header `typ` must be "openid4vci-proof+jwt"
/// 3. Header must contain `kid` or `jwk` (but not both)  
/// 4. **Cryptographic signature verification** against the public key
/// 5. `aud` must match the credential issuer URL
/// 6. `nonce` must match the expected c_nonce (if provided)
/// 7. `iat` must be present and not too old
/// 8. `exp` must not have passed (if present)
pub fn verify_jwt_proof(
    proof_jwt: &str,
    expected_issuer_url: &str,
    expected_c_nonce: Option<&str>,
    max_age_seconds: i64,
) -> Oid4vciResult<VerifiedProof> {
    verify_jwt_proof_with_key_source(
        proof_jwt,
        expected_issuer_url,
        expected_c_nonce,
        max_age_seconds,
        ProofKeySource::Header,
    )
}

/// Verify a key-attestation-bound OID4VCI JWT proof.
///
/// The caller is responsible for validating `validated_key_attestation_jwt`
/// against the organization and issuer profile's trust policy, including its
/// certificate chain, signature, time, nonce, status, and assurance claims.
/// This function enforces the cryptographic boundary after that policy check:
/// the proof must carry that exact attestation JWT, the key identified in its
/// JOSE header must be one of the `attested_keys` embedded in that JWT, and its
/// signature must verify with that key. OID4VCI wallets can identify the proof
/// key with an embedded `jwk` or a standards-defined `kid`; Marty does not add
/// a private key-index convention to either form.
///
/// Keeping the complete validated attestation token in this interface prevents
/// a caller from accidentally validating one token and accepting public keys
/// for a different token.
pub fn verify_key_attestation_bound_jwt_proof(
    proof_jwt: &str,
    expected_issuer_url: &str,
    expected_c_nonce: Option<&str>,
    max_age_seconds: i64,
    validated_key_attestation_jwt: &str,
) -> Oid4vciResult<VerifiedProof> {
    verify_jwt_proof_with_key_source(
        proof_jwt,
        expected_issuer_url,
        expected_c_nonce,
        max_age_seconds,
        ProofKeySource::ValidatedKeyAttestation {
            jwt: validated_key_attestation_jwt,
        },
    )
}

fn verify_jwt_proof_with_key_source(
    proof_jwt: &str,
    expected_issuer_url: &str,
    expected_c_nonce: Option<&str>,
    max_age_seconds: i64,
    key_source: ProofKeySource<'_>,
) -> Oid4vciResult<VerifiedProof> {
    if max_age_seconds < 0 {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Proof JWT max age must be nonnegative".into(),
        ));
    }
    if let ProofKeySource::ValidatedKeyAttestation { jwt } = &key_source {
        if jwt.len() > MAX_COMPACT_KEY_ATTESTATION_JWT_BYTES {
            return Err(Oid4vciError::ProofVerificationFailed(
                "Validated key attestation exceeds its size limit".into(),
            ));
        }
    }

    // Step 1: Split and decode within fixed allocation bounds.
    let parts = split_compact_jwt(proof_jwt, PROOF_JWT_LIMITS)
        .map_err(|message| Oid4vciError::ProofVerificationFailed(message.into()))?;

    let header_bytes = decode_segment(
        parts.header,
        MAX_PROOF_HEADER_BYTES,
        "Proof JWT header is not base64url",
        "Proof JWT header exceeds its size limit",
    )
    .map_err(|message| Oid4vciError::ProofVerificationFailed(message.into()))?;
    let payload_bytes = decode_segment(
        parts.claims,
        MAX_PROOF_PAYLOAD_BYTES,
        "Proof JWT payload is not base64url",
        "Proof JWT payload exceeds its size limit",
    )
    .map_err(|message| Oid4vciError::ProofVerificationFailed(message.into()))?;
    let signature_bytes = decode_segment(
        parts.signature,
        MAX_JWT_SIGNATURE_BYTES,
        "Proof JWT signature is not base64url",
        "Proof JWT signature exceeds its size limit",
    )
    .map_err(|message| Oid4vciError::ProofVerificationFailed(message.into()))?;

    let header: ProofHeader = serde_json::from_slice(&header_bytes).map_err(|e| {
        Oid4vciError::ProofVerificationFailed(format!("Invalid header JSON: {}", e))
    })?;
    let payload: ProofPayload = serde_json::from_slice(&payload_bytes).map_err(|e| {
        Oid4vciError::ProofVerificationFailed(format!("Invalid payload JSON: {}", e))
    })?;

    // Step 2: Validate the required explicit proof type.
    match header.typ.as_deref() {
        Some("openid4vci-proof+jwt") => {}
        Some(typ) => {
            return Err(Oid4vciError::ProofVerificationFailed(format!(
                "Invalid typ header: expected 'openid4vci-proof+jwt', got '{}'",
                typ
            )));
        }
        None => {
            return Err(Oid4vciError::ProofVerificationFailed(
                "Missing required typ header 'openid4vci-proof+jwt'".into(),
            ));
        }
    }

    // Step 3: Resolve the proof key through exactly one trusted path. A key
    // attestation header must never be ignored by the ordinary verifier.
    let (derived_holder_id, holder_jwk) = match key_source {
        ProofKeySource::Header => {
            if header.key_attestation.is_some() {
                return Err(Oid4vciError::ProofVerificationFailed(
                    "Proof carries key_attestation but no validated issuer policy context was provided"
                        .into(),
                ));
            }
            extract_holder_key(&header)?
        }
        ProofKeySource::ValidatedKeyAttestation { jwt } => {
            extract_key_attestation_holder_key(&header, jwt)?
        }
    };

    // Step 4: Cryptographic signature verification.  `extract_holder_key`
    // resolves every accepted header to public key material.  Keep this
    // explicit guard so a future key-reference variant cannot accidentally
    // reintroduce an unverified success path.
    let verification_jwk = holder_jwk.as_ref().ok_or_else(|| {
        Oid4vciError::ProofVerificationFailed(
            "Proof key could not be resolved to public key material".into(),
        )
    })?;
    verify_signature(
        verification_jwk,
        &header.alg,
        parts.header,
        parts.claims,
        &signature_bytes,
    )?;

    // `iss`, when present, is the OAuth client_id.  It is not generally a
    // holder identity.  Preserve a self-certifying DID client identifier only
    // when it resolves to the exact key that just verified the proof.
    let holder_id =
        verified_holder_id(&derived_holder_id, verification_jwk, payload.iss.as_deref())?;

    // Step 5: The audience is required even when the caller has already
    // validated its value at a routing boundary.
    let audience = payload.aud.as_deref().ok_or_else(|| {
        Oid4vciError::ProofVerificationFailed("Missing required aud claim".into())
    })?;
    if !expected_issuer_url.is_empty() && audience != expected_issuer_url {
        return Err(Oid4vciError::ProofVerificationFailed(format!(
            "Audience mismatch: expected '{}', got '{}'",
            expected_issuer_url, audience
        )));
    }

    // Step 7: iat is required by the JWT proof profile.
    let issued_at = payload.iat.ok_or_else(|| {
        Oid4vciError::ProofVerificationFailed("Missing required iat claim".into())
    })?;
    let now = chrono::Utc::now().timestamp();
    let age = now.checked_sub(issued_at).ok_or_else(|| {
        Oid4vciError::ProofVerificationFailed(
            "Proof JWT iat is outside the supported timestamp range".into(),
        )
    })?;
    if age > max_age_seconds {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Proof JWT is older than the allowed freshness window".into(),
        ));
    }
    // Allow small clock skew (30 seconds into the future)
    let future_limit = now.checked_add(30).ok_or_else(|| {
        Oid4vciError::ProofVerificationFailed(
            "Proof JWT clock is outside the supported timestamp range".into(),
        )
    })?;
    if issued_at > future_limit {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Proof JWT iat is in the future".into(),
        ));
    }

    // Step 8: Validate exp
    if let Some(exp) = payload.exp {
        if now > exp {
            return Err(Oid4vciError::ProofVerificationFailed(format!(
                "Proof JWT has expired: exp={}, now={}",
                exp, now
            )));
        }
    }

    // Step 6: Validate c_nonce
    if let Some(expected_nonce) = expected_c_nonce {
        match &payload.nonce {
            Some(nonce) if nonce == expected_nonce => {} // OK
            Some(nonce) => {
                return Err(Oid4vciError::InvalidCNonce {
                    expected: expected_nonce.to_string(),
                    got: nonce.clone(),
                });
            }
            None => {
                return Err(Oid4vciError::ProofVerificationFailed(
                    "Missing nonce in proof JWT, but c_nonce was expected".into(),
                ));
            }
        }
    }

    Ok(VerifiedProof {
        holder_id,
        holder_jwk,
        nonce: payload.nonce,
        audience: payload.aud,
        iat: Some(issued_at),
    })
}

fn public_jwk_holder_id(jwk: &JWK) -> Oid4vciResult<String> {
    let jwk_json = serde_json::to_string(jwk).map_err(|error| {
        Oid4vciError::ProofVerificationFailed(format!(
            "Failed to serialize attested public JWK: {error}"
        ))
    })?;
    Ok(format!("did:jwk:{}", B64.encode(jwk_json.as_bytes())))
}

fn jwk_has_private_material(jwk: &JWK) -> bool {
    match &jwk.params {
        Params::OKP(params) => params.private_key.is_some(),
        Params::EC(params) => params.ecc_private_key.is_some(),
        Params::RSA(params) => {
            params.private_exponent.is_some()
                || params.first_prime_factor.is_some()
                || params.second_prime_factor.is_some()
                || params.first_prime_factor_crt_exponent.is_some()
                || params.second_prime_factor_crt_exponent.is_some()
                || params.first_crt_coefficient.is_some()
                || params.other_primes_info.is_some()
        }
        Params::Symmetric(_) => true,
    }
}

fn raw_jwk_has_private_material(jwk: &serde_json::Value) -> bool {
    const PRIVATE_MEMBERS: [&str; 9] = ["d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    jwk.as_object().is_some_and(|object| {
        PRIVATE_MEMBERS
            .iter()
            .any(|member| object.contains_key(*member))
    })
}

fn extract_key_attestation_holder_key(
    header: &ProofHeader,
    validated_key_attestation_jwt: &str,
) -> Oid4vciResult<(String, Option<JWK>)> {
    if header.kid.is_some() && header.jwk.is_some() {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Key-attestation-bound proof must not contain both 'kid' and 'jwk'".into(),
        ));
    }
    let header_attestation = header.key_attestation.as_deref().ok_or_else(|| {
        Oid4vciError::ProofVerificationFailed(
            "Key-attestation-bound proof is missing key_attestation header".into(),
        )
    })?;
    if header_attestation != validated_key_attestation_jwt {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Proof key_attestation does not match the issuer-validated attestation".into(),
        ));
    }
    let attestation_parts =
        split_compact_jwt(validated_key_attestation_jwt, ATTESTATION_JWT_LIMITS)
            .map_err(|message| Oid4vciError::ProofVerificationFailed(message.into()))?;
    decode_segment(
        attestation_parts.header,
        MAX_ATTESTATION_HEADER_BYTES,
        "Validated key attestation header is not base64url",
        "Validated key attestation header exceeds its size limit",
    )
    .map_err(|message| Oid4vciError::ProofVerificationFailed(message.into()))?;
    let attestation_payload = decode_segment(
        attestation_parts.claims,
        MAX_ATTESTATION_PAYLOAD_BYTES,
        "Validated key attestation payload is not base64url",
        "Validated key attestation payload exceeds its size limit",
    )
    .map_err(|message| Oid4vciError::ProofVerificationFailed(message.into()))?;
    decode_segment(
        attestation_parts.signature,
        MAX_JWT_SIGNATURE_BYTES,
        "Validated key attestation signature is not base64url",
        "Validated key attestation signature exceeds its size limit",
    )
    .map_err(|message| Oid4vciError::ProofVerificationFailed(message.into()))?;
    let raw_attestation: serde_json::Value =
        serde_json::from_slice(&attestation_payload).map_err(|error| {
            Oid4vciError::ProofVerificationFailed(format!(
                "Validated key attestation payload is invalid: {error}"
            ))
        })?;
    if raw_attestation
        .get("attested_keys")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|keys| keys.iter().any(raw_jwk_has_private_material))
    {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Validated key attestation must contain public keys only".into(),
        ));
    }
    let attestation: KeyAttestationPayload =
        serde_json::from_value(raw_attestation).map_err(|error| {
            Oid4vciError::ProofVerificationFailed(format!(
                "Validated key attestation payload is invalid: {error}"
            ))
        })?;
    if attestation.attested_keys.is_empty() {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Validated key attestation has no attested public keys".into(),
        ));
    }
    if attestation
        .attested_keys
        .iter()
        .any(jwk_has_private_material)
    {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Validated key attestation must contain public keys only".into(),
        ));
    }

    let jwk = match (&header.kid, &header.jwk) {
        (None, Some(jwk_value)) => {
            if raw_jwk_has_private_material(jwk_value) {
                return Err(Oid4vciError::ProofVerificationFailed(
                    "Key-attestation-bound proof header must contain a public JWK only".into(),
                ));
            }
            let proof_jwk: JWK = serde_json::from_value(jwk_value.clone()).map_err(|error| {
                Oid4vciError::ProofVerificationFailed(format!(
                    "Invalid JWK in key-attestation-bound proof header: {error}"
                ))
            })?;
            if jwk_has_private_material(&proof_jwk) {
                return Err(Oid4vciError::ProofVerificationFailed(
                    "Key-attestation-bound proof header must contain a public JWK only".into(),
                ));
            }
            let proof_thumbprint = proof_jwk.thumbprint().map_err(|error| {
                Oid4vciError::ProofVerificationFailed(format!(
                    "Could not fingerprint key-attestation-bound proof JWK: {error}"
                ))
            })?;
            let matches_attestation = attestation.attested_keys.iter().any(|attested_jwk| {
                attested_jwk
                    .thumbprint()
                    .is_ok_and(|thumbprint| thumbprint == proof_thumbprint)
            });
            if !matches_attestation {
                return Err(Oid4vciError::ProofVerificationFailed(
                    "Key-attestation-bound proof JWK is not contained in attested_keys".into(),
                ));
            }
            proof_jwk
        }
        (Some(kid), None) => select_etsi_attested_key(kid, &attestation.attested_keys)?,
        (None, None) => {
            return Err(Oid4vciError::ProofVerificationFailed(
                "Key-attestation-bound proof must contain either 'kid' or 'jwk'".into(),
            ));
        }
        (Some(_), Some(_)) => {
            return Err(Oid4vciError::ProofVerificationFailed(
                "Key-attestation-bound proof cannot contain both 'kid' and 'jwk'".into(),
            ));
        }
    };
    Ok((public_jwk_holder_id(&jwk)?, Some(jwk)))
}

fn select_etsi_attested_key(kid: &str, attested_keys: &[JWK]) -> Oid4vciResult<JWK> {
    // ETSI TS 119 472-3 binds this proof to the first public key in the
    // validated attestation. The current EUDI wallet reference implementation
    // represents that position as the canonical JOSE `kid` value "0".
    // This is deliberately not a general numeric-index or key-id fallback.
    if kid != "0" {
        return Err(Oid4vciError::ProofVerificationFailed(format!(
            "ETSI key-attestation-bound proof kid must be the canonical first-key selector '0', got '{kid}'"
        )));
    }

    attested_keys.first().cloned().ok_or_else(|| {
        Oid4vciError::ProofVerificationFailed(
            "Validated key attestation has no first public key".into(),
        )
    })
}

/// Decode a base58btc string to raw bytes (Bitcoin alphabet, no padding).
fn base58btc_decode(input: &str) -> Oid4vciResult<Vec<u8>> {
    const ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let n_leading = input.bytes().take_while(|&b| b == b'1').count();
    let mut result: Vec<u8> = Vec::new();
    for &c in input.as_bytes() {
        let digit = ALPHA.iter().position(|&a| a == c).ok_or_else(|| {
            Oid4vciError::ProofVerificationFailed(format!(
                "Invalid base58btc character 0x{c:02x} in did:key"
            ))
        })? as u32;
        let mut carry = digit;
        for byte in result.iter_mut() {
            carry += 58 * (*byte as u32);
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            result.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    result.extend(std::iter::repeat_n(0, n_leading));
    result.reverse();
    Ok(result)
}

/// Decompress a P-256 SEC1 public key (compressed 33-byte or uncompressed 65-byte)
/// into (x, y) raw 32-byte coordinate vectors.
fn p256_sec1_to_xy(sec1: &[u8]) -> Oid4vciResult<(Vec<u8>, Vec<u8>)> {
    let pk = p256::PublicKey::from_sec1_bytes(sec1)
        .map_err(|e| Oid4vciError::KeyError(format!("Invalid P-256 SEC1 key in did:key: {e}")))?;
    let ep = pk.to_encoded_point(false); // false = uncompressed
    let x = ep
        .x()
        .ok_or_else(|| Oid4vciError::KeyError("P-256: missing x coordinate".into()))?
        .to_vec();
    let y = ep
        .y()
        .ok_or_else(|| Oid4vciError::KeyError("P-256: missing y coordinate".into()))?
        .to_vec();
    Ok((x, y))
}

/// Resolve a `did:key` DID (or DID URL) to a `(holder_id, JWK)` pair.
///
/// Supports Ed25519 (`z6Mk…`, multicodec `0xed01`) and P-256 (`zDna…`,
/// multicodec `0x1200`) key types as defined in the
/// [did:key spec](https://w3c-ccg.github.io/did-method-key/).
/// No network I/O required — the public key is embedded in the DID itself.
fn resolve_did_key_to_jwk(kid: &str) -> Oid4vciResult<(String, Option<JWK>)> {
    let did = kid.split('#').next().unwrap_or(kid);
    let encoded = did.strip_prefix("did:key:z").ok_or_else(|| {
        Oid4vciError::ProofVerificationFailed(format!("Not a did:key DID: {did}"))
    })?;
    let raw = base58btc_decode(encoded)?;
    let (prefix_a, prefix_b) = (raw.first().copied(), raw.get(1).copied());
    let jwk: JWK = match (prefix_a, prefix_b) {
        // Ed25519-pub: multicodec 0xed01
        (Some(0xed), Some(0x01)) => {
            let key_bytes = &raw[2..];
            if key_bytes.len() != 32 {
                return Err(Oid4vciError::KeyError(format!(
                    "Ed25519 did:key: expected 32 key bytes, got {}",
                    key_bytes.len()
                )));
            }
            serde_json::from_value(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": B64.encode(key_bytes)
            }))
            .map_err(|e| Oid4vciError::KeyError(format!("Ed25519 JWK build error: {e}")))?
        }
        // P-256-pub: multicodec 0x1200, varint-encoded as [0x80, 0x24]
        (Some(0x80), Some(0x24)) => {
            let key_bytes = &raw[2..];
            let (x, y) = p256_sec1_to_xy(key_bytes)?;
            serde_json::from_value(serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": B64.encode(&x),
                "y": B64.encode(&y)
            }))
            .map_err(|e| Oid4vciError::KeyError(format!("P-256 JWK build error: {e}")))?
        }
        _ => {
            return Err(Oid4vciError::ProofVerificationFailed(format!(
                "Unsupported multicodec prefix in did:key: 0x{:02x}{:02x}",
                prefix_a.unwrap_or(0),
                prefix_b.unwrap_or(0)
            )));
        }
    };
    Ok((did.to_string(), Some(jwk)))
}

/// Extract the holder's identity and optional JWK from the proof header.
fn extract_holder_key(header: &ProofHeader) -> Oid4vciResult<(String, Option<JWK>)> {
    match (&header.kid, &header.jwk) {
        (Some(_), Some(_)) => Err(Oid4vciError::ProofVerificationFailed(
            "Proof JWT header must not contain both 'kid' and 'jwk'".into(),
        )),
        // JWK embedded in header — we can verify the signature
        (None, Some(jwk_value)) => {
            if raw_jwk_has_private_material(jwk_value) {
                return Err(Oid4vciError::ProofVerificationFailed(
                    "Proof header must contain a public JWK only".into(),
                ));
            }
            let jwk: JWK = serde_json::from_value(jwk_value.clone()).map_err(|e| {
                Oid4vciError::ProofVerificationFailed(format!("Invalid JWK in proof header: {}", e))
            })?;
            if jwk_has_private_material(&jwk) {
                return Err(Oid4vciError::ProofVerificationFailed(
                    "Proof header must contain a public JWK only".into(),
                ));
            }

            Ok((public_jwk_holder_id(&jwk)?, Some(jwk)))
        }
        // kid only — resolve did:key locally.  Other DID methods require a
        // trusted resolver and verification-method authorization supplied by
        // the caller; accepting them here would skip signature verification.
        (Some(kid), None) => {
            if kid.contains("did:key:z") {
                resolve_did_key_to_jwk(kid)
            } else {
                Err(Oid4vciError::ProofVerificationFailed(format!(
                    "Proof JWT kid '{}' cannot be resolved locally; provide an embedded public JWK or a did:key verification method",
                    kid
                )))
            }
        }
        // Neither kid nor jwk
        (None, None) => Err(Oid4vciError::ProofVerificationFailed(
            "Proof JWT header must contain either 'kid' or 'jwk'".into(),
        )),
    }
}

fn verified_holder_id(
    derived_holder_id: &str,
    verification_jwk: &JWK,
    client_id: Option<&str>,
) -> Oid4vciResult<String> {
    let Some(client_id) = client_id else {
        return Ok(derived_holder_id.to_string());
    };
    if !client_id.starts_with("did:key:z") {
        return Ok(derived_holder_id.to_string());
    }

    let (client_did, client_jwk) = resolve_did_key_to_jwk(client_id)?;
    let client_jwk = client_jwk.ok_or_else(|| {
        Oid4vciError::ProofVerificationFailed(
            "Self-certifying proof client_id did not resolve to key material".into(),
        )
    })?;
    let client_thumbprint = client_jwk.thumbprint().map_err(|error| {
        Oid4vciError::ProofVerificationFailed(format!(
            "Could not fingerprint proof client_id key: {error}"
        ))
    })?;
    let verification_thumbprint = verification_jwk.thumbprint().map_err(|error| {
        Oid4vciError::ProofVerificationFailed(format!(
            "Could not fingerprint verified proof key: {error}"
        ))
    })?;
    if client_thumbprint != verification_thumbprint {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Self-certifying proof client_id does not identify the verified proof key".into(),
        ));
    }
    Ok(client_did)
}

/// Cryptographically verify the JWT signature using the provided JWK.
fn verify_signature(
    jwk: &JWK,
    alg: &str,
    header_b64: &str,
    payload_b64: &str,
    signature: &[u8],
) -> Oid4vciResult<()> {
    let message = format!("{}.{}", header_b64, payload_b64);

    if alg == "RS256" {
        return verify_rsa_signature(jwk, alg, &message, signature);
    }

    let verified = match (alg, &jwk.params) {
        ("EdDSA", Params::OKP(params)) if params.curve == "Ed25519" => {
            marty_crypto::ed25519::verify(&params.public_key.0, message.as_bytes(), signature)
                .is_ok()
        }
        ("ES256", Params::EC(params)) if params.curve.as_deref() == Some("P-256") => {
            require_jose_signature_len("ES256", signature, 64)?;
            let public_key = ec_sec1_public_key(params, 32)?;
            marty_crypto::ecdsa::verify_p256_sha256(&public_key, message.as_bytes(), signature)
                .map_err(|error| {
                    Oid4vciError::ProofVerificationFailed(format!(
                        "Signature verification failed: {error}"
                    ))
                })?
        }
        ("ES384", Params::EC(params)) if params.curve.as_deref() == Some("P-384") => {
            require_jose_signature_len("ES384", signature, 96)?;
            let public_key = ec_sec1_public_key(params, 48)?;
            marty_crypto::ecdsa::verify_p384_sha384(&public_key, message.as_bytes(), signature)
                .map_err(|error| {
                    Oid4vciError::ProofVerificationFailed(format!(
                        "Signature verification failed: {error}"
                    ))
                })?
        }
        ("ES256K", Params::EC(params)) if params.curve.as_deref() == Some("secp256k1") => {
            verify_secp256k1_signature(params, message.as_bytes(), signature)?
        }
        ("ES256" | "ES384" | "ES256K" | "EdDSA", _) => {
            return Err(Oid4vciError::ProofVerificationFailed(format!(
                "Proof algorithm {alg} does not match the supplied public JWK"
            )));
        }
        _ => {
            return Err(Oid4vciError::ProofVerificationFailed(format!(
                "Unsupported proof signing algorithm: {alg}"
            )));
        }
    };

    if !verified {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Signature verification failed: invalid signature".into(),
        ));
    }

    Ok(())
}

fn require_jose_signature_len(
    algorithm: &str,
    signature: &[u8],
    expected: usize,
) -> Oid4vciResult<()> {
    if signature.len() != expected {
        return Err(Oid4vciError::ProofVerificationFailed(format!(
            "{algorithm} proof signature must contain exactly {expected} bytes"
        )));
    }
    Ok(())
}

fn ec_sec1_public_key(params: &ssi_jwk::ECParams, coordinate_len: usize) -> Oid4vciResult<Vec<u8>> {
    let x = params
        .x_coordinate
        .as_ref()
        .ok_or_else(|| Oid4vciError::KeyError("Missing EC x coordinate".into()))?;
    let y = params
        .y_coordinate
        .as_ref()
        .ok_or_else(|| Oid4vciError::KeyError("Missing EC y coordinate".into()))?;
    if x.0.len() != coordinate_len || y.0.len() != coordinate_len {
        return Err(Oid4vciError::KeyError(format!(
            "EC public key coordinates must each contain {coordinate_len} bytes"
        )));
    }

    let mut public_key = Vec::with_capacity(1 + 2 * coordinate_len);
    public_key.push(0x04);
    public_key.extend_from_slice(&x.0);
    public_key.extend_from_slice(&y.0);
    Ok(public_key)
}

fn verify_secp256k1_signature(
    params: &ssi_jwk::ECParams,
    message: &[u8],
    signature: &[u8],
) -> Oid4vciResult<bool> {
    use sha2::Digest as _;

    let public_key = ec_sec1_public_key(params, 32)?;
    let public_key = k256::PublicKey::from_sec1_bytes(&public_key).map_err(|error| {
        Oid4vciError::KeyError(format!("Invalid secp256k1 public key: {error}"))
    })?;
    let signature = k256::ecdsa::Signature::from_slice(signature).map_err(|error| {
        Oid4vciError::ProofVerificationFailed(format!("Invalid ES256K signature encoding: {error}"))
    })?;
    let digest = sha2::Sha256::digest(message);
    let z = k256::ecdsa::hazmat::bits2field::<k256::Secp256k1>(&digest).map_err(|error| {
        Oid4vciError::ProofVerificationFailed(format!(
            "Could not prepare ES256K signature digest: {error}"
        ))
    })?;
    let public_point = k256::ProjectivePoint::from(*public_key.as_affine());
    Ok(
        k256::ecdsa::hazmat::verify_prehashed::<k256::Secp256k1>(&public_point, &z, &signature)
            .is_ok(),
    )
}

/// Verify an RSA signature (RS256).
fn verify_rsa_signature(
    _jwk: &JWK,
    _alg: &str,
    _message: &str,
    _signature: &[u8],
) -> Oid4vciResult<()> {
    // RSA proofs are uncommon in OID4VCI; most wallets use ES256 or EdDSA.
    // Reject rather than silently accepting unverified signatures.
    Err(Oid4vciError::ProofVerificationFailed(
        "RSA proof verification is not yet implemented; use ES256 or EdDSA".into(),
    ))
}

/// Extract JWT proof(s) from an OID4VCI v1 credential request.
pub fn extract_proof_jwts(request: &crate::types::CredentialRequest) -> Oid4vciResult<Vec<String>> {
    if let Some(ref proofs) = request.proofs {
        if let Some(ref jwts) = proofs.jwt {
            if jwts.is_empty() {
                return Err(Oid4vciError::ProofVerificationFailed(
                    "proofs.jwt array is empty".into(),
                ));
            }
            return Ok(jwts.clone());
        }
    }

    Err(Oid4vciError::ProofVerificationFailed(
        "No proof provided in credential request. 'proofs.jwt' is required.".into(),
    ))
}

// ---------------------------------------------------------------------------
// Proof creation (wallet-side / test helper)
// ---------------------------------------------------------------------------

/// Base58btc encoder using the Bitcoin alphabet (no multibase prefix).
#[cfg(any(test, feature = "holder-key-operations"))]
fn base58btc_encode(data: &[u8]) -> String {
    const ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let n_leading = data.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for d in &mut digits {
            carry += (*d as u32) * 256;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    digits.extend(std::iter::repeat_n(0u8, n_leading));
    digits.reverse();
    digits.iter().map(|&d| ALPHA[d as usize] as char).collect()
}

/// Create a spec-correct OID4VCI proof-of-possession JWT (OID4VCI §8.2).
///
/// Generates an ephemeral Ed25519 key pair, derives a `did:key` from it,
/// and returns a compact JWT signed with that key.  The JWT contains:
///   - header: `{"alg":"EdDSA","typ":"openid4vci-proof+jwt","kid":"<did:key>#<did:key>"}`
///   - payload: `{"iss":"<did:key>","aud":"<aud>","iat":<now>,"nonce":"<c_nonce>"}`
///
/// The returned JWT passes `verify_jwt_proof` because the `kid` is a `did:key`
/// whose public key is resolved inline (no network I/O) and the signature is
/// verified cryptographically.
#[cfg(any(test, feature = "holder-key-operations"))]
pub fn create_proof_jwt(aud: &str, c_nonce: &str) -> Oid4vciResult<String> {
    // Generate ephemeral Ed25519 key pair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Derive did:key: multicodec prefix 0xed 0x01 + raw pub key → base58btc
    let pub_bytes = verifying_key.to_bytes();
    let mut prefixed = vec![0xed_u8, 0x01];
    prefixed.extend_from_slice(&pub_bytes);
    let did = format!("did:key:z{}", base58btc_encode(&prefixed));
    let kid = format!("{}#{}", did, did);

    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "openid4vci-proof+jwt",
        "kid": kid,
    });
    let payload = serde_json::json!({
        "iss": did,
        "aud": aud,
        "iat": chrono::Utc::now().timestamp(),
        "nonce": c_nonce,
    });

    let header_b64 = B64.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let payload_b64 = B64.encode(serde_json::to_string(&payload).unwrap().as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = B64.encode(signature.to_bytes());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, sig_b64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};
    use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
    use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};

    fn embedded_ed25519_jwk(signing_key: &SigningKey) -> serde_json::Value {
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": B64.encode(signing_key.verifying_key().to_bytes()),
        })
    }

    fn sign_test_proof(
        signing_key: &SigningKey,
        header: serde_json::Value,
        payload: serde_json::Value,
    ) -> String {
        let header_b64 = B64.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = B64.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64.encode(signature.to_bytes()))
    }

    fn embedded_p256_jwk(signing_key: &P256SigningKey) -> serde_json::Value {
        let point = signing_key.verifying_key().to_encoded_point(false);
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": B64.encode(point.x().expect("P-256 x coordinate")),
            "y": B64.encode(point.y().expect("P-256 y coordinate")),
            "kid": "wallet-proof-key",
        })
    }

    fn sign_test_p256_proof(
        signing_key: &P256SigningKey,
        header: serde_json::Value,
        payload: serde_json::Value,
    ) -> String {
        let header_b64 = B64.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = B64.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature: P256Signature = signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64.encode(signature.to_bytes()))
    }

    fn validated_key_attestation_jwt(attested_keys: Vec<serde_json::Value>) -> String {
        let header = B64.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg": "ES256",
                "typ": "key-attestation+jwt",
            }))
            .unwrap(),
        );
        let payload = B64.encode(
            serde_json::to_vec(&serde_json::json!({
                "attested_keys": attested_keys,
            }))
            .unwrap(),
        );
        // Signature validation belongs to the tenant-bound issuer policy.
        // This protocol-layer fixture needs only the exact already-validated
        // compact token so it can prove key selection is bound to its payload.
        format!("{header}.{payload}.{}", B64.encode(b"validated-signature"))
    }

    #[test]
    fn verifier_only_backends_cover_es384_and_es256k() {
        let header = "header";
        let payload = "payload";
        let signing_input = format!("{header}.{payload}");

        let p384_key = P384SigningKey::random(&mut OsRng);
        let p384_point = p384_key.verifying_key().to_encoded_point(false);
        let p384_jwk: JWK = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-384",
            "x": B64.encode(p384_point.x().unwrap()),
            "y": B64.encode(p384_point.y().unwrap()),
        }))
        .unwrap();
        let p384_signature: P384Signature = p384_key.sign(signing_input.as_bytes());
        assert!(verify_signature(
            &p384_jwk,
            "ES384",
            header,
            payload,
            &p384_signature.to_bytes(),
        )
        .is_ok());

        let k256_key = K256SigningKey::random(&mut OsRng);
        let k256_point = k256_key.verifying_key().to_encoded_point(false);
        let k256_jwk: JWK = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": B64.encode(k256_point.x().unwrap()),
            "y": B64.encode(k256_point.y().unwrap()),
        }))
        .unwrap();
        let k256_signature: K256Signature = k256_key.sign(signing_input.as_bytes());
        assert!(verify_signature(
            &k256_jwk,
            "ES256K",
            header,
            payload,
            &k256_signature.to_bytes(),
        )
        .is_ok());

        let mut tampered = k256_signature.to_bytes();
        tampered[0] ^= 0x01;
        assert!(verify_signature(&k256_jwk, "ES256K", header, payload, &tampered).is_err());
        assert!(verify_signature(
            &k256_jwk,
            "ES256",
            header,
            payload,
            &k256_signature.to_bytes(),
        )
        .unwrap_err()
        .to_string()
        .contains("does not match"));
    }

    #[test]
    fn test_extract_proof_jwts_v1_format() {
        let request = crate::types::CredentialRequest {
            format: Some("jwt_vc_json".into()),
            credential_configuration_id: Some("employee".into()),
            credential_identifier: None,
            proofs: Some(crate::types::ProofsObject {
                jwt: Some(vec!["header.payload.sig".into()]),
            }),
            credential_definition: None,
            vct: None,
            doctype: None,
            claims: None,
        };

        let jwts = extract_proof_jwts(&request).unwrap();
        assert_eq!(jwts, vec!["header.payload.sig"]);
    }

    #[test]
    fn test_extract_proof_jwts_no_proof() {
        let request = crate::types::CredentialRequest {
            format: Some("jwt_vc_json".into()),
            credential_configuration_id: Some("employee".into()),
            credential_identifier: None,
            proofs: None,
            credential_definition: None,
            vct: None,
            doctype: None,
            claims: None,
        };

        assert!(extract_proof_jwts(&request).is_err());
    }

    #[test]
    fn proof_and_attestation_inputs_are_bounded_before_decode_or_key_selection() {
        let oversized =
            "secret-sentinel".repeat(MAX_COMPACT_PROOF_JWT_BYTES / "secret-sentinel".len() + 1);
        let error = verify_jwt_proof(&oversized, "", None, 300).unwrap_err();
        assert!(error.to_string().contains("size limit"));
        assert!(!error.to_string().contains("secret-sentinel"));

        let many_parts = std::iter::repeat_n("secret-sentinel", 10_000)
            .collect::<Vec<_>>()
            .join(".");
        let error = verify_jwt_proof(&many_parts, "", None, 300).unwrap_err();
        assert!(error.to_string().contains("exactly three"));
        assert!(!error.to_string().contains("secret-sentinel"));

        let attestation = "secret-sentinel"
            .repeat(MAX_COMPACT_KEY_ATTESTATION_JWT_BYTES / "secret-sentinel".len() + 1);
        let error =
            verify_key_attestation_bound_jwt_proof("invalid-proof", "", None, 300, &attestation)
                .unwrap_err();
        assert!(error.to_string().contains("attestation exceeds"));
        assert!(!error.to_string().contains("secret-sentinel"));
    }

    #[test]
    fn proof_freshness_rejects_extreme_iat_and_negative_policy() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "openid4vci-proof+jwt",
            "jwk": embedded_ed25519_jwk(&signing_key),
        });
        for issued_at in [i64::MIN, i64::MAX] {
            let proof = sign_test_proof(
                &signing_key,
                header.clone(),
                serde_json::json!({
                    "aud": "https://issuer.example",
                    "iat": issued_at,
                }),
            );
            assert!(verify_jwt_proof(&proof, "https://issuer.example", None, 300).is_err());
        }

        let error = verify_jwt_proof("invalid-proof", "", None, -1).unwrap_err();
        assert!(error.to_string().contains("must be nonnegative"));
    }

    #[test]
    fn test_extract_holder_key_from_kid() {
        let header = ProofHeader {
            alg: "ES256".into(),
            kid: Some("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into()),
            jwk: None,
            typ: Some("openid4vci-proof+jwt".into()),
            key_attestation: None,
        };

        let (holder_id, jwk) = extract_holder_key(&header).unwrap();
        assert_eq!(
            holder_id,
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        // did:key:z6Mk... is an Ed25519 key; resolve_did_key_to_jwk returns the
        // public JWK so signature verification can be performed without network I/O.
        assert!(jwk.is_some());
    }

    #[test]
    fn test_extract_holder_key_neither() {
        let header = ProofHeader {
            alg: "ES256".into(),
            kid: None,
            jwk: None,
            typ: Some("openid4vci-proof+jwt".into()),
            key_attestation: None,
        };

        assert!(extract_holder_key(&header).is_err());
    }

    #[test]
    fn ordinary_proof_header_rejects_all_private_jwk_key_types() {
        let private_jwks = [
            serde_json::json!({"kty":"EC","crv":"P-256","x":"x","y":"y","d":"secret"}),
            serde_json::json!({"kty":"EC","crv":"P-256","x":"x","y":"y","rsa_d":"secret"}),
            serde_json::json!({"kty":"OKP","crv":"Ed25519","x":"x","d":"secret"}),
            serde_json::json!({"kty":"RSA","n":"n","e":"AQAB","d":"secret"}),
            serde_json::json!({"kty":"RSA","n":"n","e":"AQAB","p":"secret"}),
            serde_json::json!({"kty":"RSA","n":"n","e":"AQAB","oth":[{"r":"secret","d":"secret","t":"secret"}]}),
            serde_json::json!({"kty":"oct","k":"secret"}),
        ];

        for jwk in private_jwks {
            let header = ProofHeader {
                alg: "ES256".into(),
                kid: None,
                jwk: Some(jwk),
                typ: Some("openid4vci-proof+jwt".into()),
                key_attestation: None,
            };
            let error = extract_holder_key(&header).unwrap_err();
            assert!(error.to_string().contains("public JWK only"));
        }
    }

    #[test]
    fn test_non_self_resolving_kid_cannot_bypass_signature_verification() {
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "kid": "did:web:wallet.example#holder-key",
        });
        let payload = serde_json::json!({
            "iss": "did:web:wallet.example",
            "aud": "https://issuer.example",
            "iat": chrono::Utc::now().timestamp(),
            "nonce": "nonce-1",
        });
        let proof = format!(
            "{}.{}.{}",
            B64.encode(serde_json::to_vec(&header).unwrap()),
            B64.encode(serde_json::to_vec(&payload).unwrap()),
            B64.encode([0_u8; 64]),
        );

        let error =
            verify_jwt_proof(&proof, "https://issuer.example", Some("nonce-1"), 300).unwrap_err();
        assert!(
            error.to_string().contains("cannot be resolved locally"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_required_typ_aud_and_iat_are_enforced() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let jwk = embedded_ed25519_jwk(&signing_key);
        let base_payload = serde_json::json!({
            "aud": "https://issuer.example",
            "iat": chrono::Utc::now().timestamp(),
            "nonce": "nonce-1",
        });

        let missing_typ = sign_test_proof(
            &signing_key,
            serde_json::json!({"alg": "EdDSA", "jwk": jwk}),
            base_payload.clone(),
        );
        assert!(
            verify_jwt_proof(&missing_typ, "https://issuer.example", Some("nonce-1"), 300,)
                .unwrap_err()
                .to_string()
                .contains("Missing required typ")
        );

        let valid_header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "openid4vci-proof+jwt",
            "jwk": embedded_ed25519_jwk(&signing_key),
        });
        let missing_aud = sign_test_proof(
            &signing_key,
            valid_header.clone(),
            serde_json::json!({
                "iat": chrono::Utc::now().timestamp(),
                "nonce": "nonce-1",
            }),
        );
        assert!(verify_jwt_proof(&missing_aud, "", Some("nonce-1"), 300)
            .unwrap_err()
            .to_string()
            .contains("Missing required aud"));

        let missing_iat = sign_test_proof(
            &signing_key,
            valid_header,
            serde_json::json!({
                "aud": "https://issuer.example",
                "nonce": "nonce-1",
            }),
        );
        assert!(
            verify_jwt_proof(&missing_iat, "https://issuer.example", Some("nonce-1"), 300,)
                .unwrap_err()
                .to_string()
                .contains("Missing required iat")
        );
    }

    #[test]
    fn test_kid_and_jwk_are_mutually_exclusive() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let proof = sign_test_proof(
            &signing_key,
            serde_json::json!({
                "alg": "EdDSA",
                "typ": "openid4vci-proof+jwt",
                "kid": "did:key:z6MkhInvalidForThisTest",
                "jwk": embedded_ed25519_jwk(&signing_key),
            }),
            serde_json::json!({
                "aud": "https://issuer.example",
                "iat": chrono::Utc::now().timestamp(),
                "nonce": "nonce-1",
            }),
        );

        assert!(
            verify_jwt_proof(&proof, "https://issuer.example", Some("nonce-1"), 300,)
                .unwrap_err()
                .to_string()
                .contains("must not contain both")
        );
    }

    #[test]
    fn test_iss_client_id_cannot_replace_cryptographic_holder_identity() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let proof = sign_test_proof(
            &signing_key,
            serde_json::json!({
                "alg": "EdDSA",
                "typ": "openid4vci-proof+jwt",
                "jwk": embedded_ed25519_jwk(&signing_key),
            }),
            serde_json::json!({
                "iss": "wallet-oauth-client",
                "aud": "https://issuer.example",
                "iat": chrono::Utc::now().timestamp(),
                "nonce": "nonce-1",
            }),
        );

        let verified =
            verify_jwt_proof(&proof, "https://issuer.example", Some("nonce-1"), 300).unwrap();
        assert_ne!(verified.holder_id, "wallet-oauth-client");
        assert!(verified.holder_id.starts_with("did:jwk:"));
        assert!(verified.holder_jwk.is_some());
    }

    #[test]
    fn test_mismatched_self_certifying_client_id_is_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let mut prefixed = vec![0xed_u8, 0x01];
        prefixed.extend_from_slice(&other_key.verifying_key().to_bytes());
        let other_did = format!("did:key:z{}", base58btc_encode(&prefixed));
        let proof = sign_test_proof(
            &signing_key,
            serde_json::json!({
                "alg": "EdDSA",
                "typ": "openid4vci-proof+jwt",
                "jwk": embedded_ed25519_jwk(&signing_key),
            }),
            serde_json::json!({
                "iss": other_did,
                "aud": "https://issuer.example",
                "iat": chrono::Utc::now().timestamp(),
                "nonce": "nonce-1",
            }),
        );

        assert!(
            verify_jwt_proof(&proof, "https://issuer.example", Some("nonce-1"), 300,)
                .unwrap_err()
                .to_string()
                .contains("does not identify the verified proof key")
        );
    }

    #[test]
    fn test_tampered_proof_signature_is_rejected() {
        let proof = create_proof_jwt("https://issuer.example", "nonce-1").unwrap();
        assert!(
            verify_jwt_proof(&proof, "https://issuer.example", Some("nonce-1"), 300).is_ok(),
            "the unmodified proof is the positive control for this test"
        );
        let (head, payload, signature) = proof
            .split_once('.')
            .and_then(|(head, rest)| {
                rest.split_once('.')
                    .map(|(payload, signature)| (head, payload, signature))
            })
            .unwrap();
        // Match the OpenID Foundation conformance module: mutate every raw
        // signature byte, then serialize it back as unpadded base64url.
        let mut tampered_signature = B64.decode(signature).unwrap();
        for byte in &mut tampered_signature {
            *byte ^= 0x5A;
        }
        let tampered = format!("{head}.{payload}.{}", B64.encode(tampered_signature));

        assert!(
            verify_jwt_proof(&tampered, "https://issuer.example", Some("nonce-1"), 300).is_err(),
            "a modified JWT signature must never verify"
        );
    }

    #[test]
    fn key_attestation_bound_proof_accepts_oidf_jwk_binding() {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let proof_jwk = embedded_p256_jwk(&signing_key);
        let attestation = validated_key_attestation_jwt(vec![proof_jwk.clone()]);
        let proof = sign_test_p256_proof(
            &signing_key,
            serde_json::json!({
                "alg": "ES256",
                "typ": "openid4vci-proof+jwt",
                "jwk": proof_jwk,
                "key_attestation": &attestation,
            }),
            serde_json::json!({
                "aud": "https://issuer.example",
                "iat": chrono::Utc::now().timestamp(),
                "nonce": "nonce-1",
            }),
        );

        let verified = verify_key_attestation_bound_jwt_proof(
            &proof,
            "https://issuer.example",
            Some("nonce-1"),
            300,
            &attestation,
        )
        .unwrap();

        assert!(verified.holder_id.starts_with("did:jwk:"));
        assert!(verified.holder_jwk.is_some());
    }

    #[test]
    fn key_attestation_bound_proof_rejects_jwk_not_in_attestation() {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let other_key = P256SigningKey::random(&mut OsRng);
        let proof_jwk = embedded_p256_jwk(&signing_key);
        let attestation = validated_key_attestation_jwt(vec![embedded_p256_jwk(&other_key)]);
        let proof = sign_test_p256_proof(
            &signing_key,
            serde_json::json!({
                "alg": "ES256",
                "typ": "openid4vci-proof+jwt",
                "jwk": proof_jwk,
                "key_attestation": &attestation,
            }),
            serde_json::json!({
                "aud": "https://issuer.example",
                "iat": chrono::Utc::now().timestamp(),
                "nonce": "nonce-1",
            }),
        );

        let error = verify_key_attestation_bound_jwt_proof(
            &proof,
            "https://issuer.example",
            Some("nonce-1"),
            300,
            &attestation,
        )
        .unwrap_err();
        assert!(error.to_string().contains("not contained in attested_keys"));
    }

    #[test]
    fn key_attestation_bound_proof_accepts_current_etsi_first_key_selector() {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let attestation = validated_key_attestation_jwt(vec![embedded_p256_jwk(&signing_key)]);
        let proof = sign_test_p256_proof(
            &signing_key,
            serde_json::json!({
                "alg": "ES256",
                "typ": "openid4vci-proof+jwt",
                "kid": "0",
                "key_attestation": &attestation,
            }),
            serde_json::json!({
                "aud": "https://issuer.example",
                "iat": chrono::Utc::now().timestamp(),
                "nonce": "nonce-1",
            }),
        );

        assert!(verify_key_attestation_bound_jwt_proof(
            &proof,
            "https://issuer.example",
            Some("nonce-1"),
            300,
            &attestation,
        )
        .is_ok());
    }

    #[test]
    fn key_attestation_bound_proof_rejects_noncanonical_etsi_key_selectors() {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let attestation = validated_key_attestation_jwt(vec![embedded_p256_jwk(&signing_key)]);
        let payload = serde_json::json!({
            "aud": "https://issuer.example",
            "iat": chrono::Utc::now().timestamp(),
            "nonce": "nonce-1",
        });

        for kid in ["1", "-1", "00", "wallet-proof-key"] {
            let proof = sign_test_p256_proof(
                &signing_key,
                serde_json::json!({
                    "alg": "ES256",
                    "typ": "openid4vci-proof+jwt",
                    "kid": kid,
                    "key_attestation": &attestation,
                }),
                payload.clone(),
            );
            let error = verify_key_attestation_bound_jwt_proof(
                &proof,
                "https://issuer.example",
                Some("nonce-1"),
                300,
                &attestation,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("canonical first-key selector '0'"),
                "unexpected error for kid {kid}: {error}"
            );
        }
    }

    #[test]
    fn key_attestation_bound_proof_uses_only_first_attested_key() {
        let first_key = P256SigningKey::random(&mut OsRng);
        let second_key = P256SigningKey::random(&mut OsRng);
        let attestation = validated_key_attestation_jwt(vec![
            embedded_p256_jwk(&first_key),
            embedded_p256_jwk(&second_key),
        ]);
        let payload = serde_json::json!({
            "aud": "https://issuer.example",
            "iat": chrono::Utc::now().timestamp(),
            "nonce": "nonce-1",
        });
        let first_key_proof = sign_test_p256_proof(
            &first_key,
            serde_json::json!({
                "alg": "ES256",
                "typ": "openid4vci-proof+jwt",
                "kid": "0",
                "key_attestation": &attestation,
            }),
            payload.clone(),
        );
        assert!(verify_key_attestation_bound_jwt_proof(
            &first_key_proof,
            "https://issuer.example",
            Some("nonce-1"),
            300,
            &attestation,
        )
        .is_ok());

        let second_key_proof = sign_test_p256_proof(
            &second_key,
            serde_json::json!({
                "alg": "ES256",
                "typ": "openid4vci-proof+jwt",
                "kid": "0",
                "key_attestation": &attestation,
            }),
            payload,
        );
        assert!(verify_key_attestation_bound_jwt_proof(
            &second_key_proof,
            "https://issuer.example",
            Some("nonce-1"),
            300,
            &attestation,
        )
        .is_err());
    }

    #[test]
    fn ordinary_verifier_never_ignores_key_attestation_header() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let proof = sign_test_proof(
            &signing_key,
            serde_json::json!({
                "alg": "EdDSA",
                "typ": "openid4vci-proof+jwt",
                "kid": "0",
                "key_attestation": "unvalidated.attestation.jwt",
            }),
            serde_json::json!({
                "aud": "https://issuer.example",
                "iat": chrono::Utc::now().timestamp(),
                "nonce": "nonce-1",
            }),
        );

        let error =
            verify_jwt_proof(&proof, "https://issuer.example", Some("nonce-1"), 300).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no validated issuer policy context"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn key_attestation_binding_rejects_token_key_and_private_material_mismatch() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let proof_jwk = embedded_ed25519_jwk(&signing_key);
        let attestation = validated_key_attestation_jwt(vec![proof_jwk.clone()]);
        let payload = serde_json::json!({
            "aud": "https://issuer.example",
            "iat": chrono::Utc::now().timestamp(),
            "nonce": "nonce-1",
        });
        let proof = sign_test_proof(
            &signing_key,
            serde_json::json!({
                "alg": "EdDSA",
                "typ": "openid4vci-proof+jwt",
                "jwk": proof_jwk.clone(),
                "key_attestation": &attestation,
            }),
            payload.clone(),
        );

        let mismatch = verify_key_attestation_bound_jwt_proof(
            &proof,
            "https://issuer.example",
            Some("nonce-1"),
            300,
            "different.key.attestation",
        )
        .unwrap_err();
        assert!(mismatch.to_string().contains("does not match"));

        let wrong_attestation =
            validated_key_attestation_jwt(vec![embedded_ed25519_jwk(&other_key)]);
        let wrong_key_proof = sign_test_proof(
            &signing_key,
            serde_json::json!({
                "alg": "EdDSA",
                "typ": "openid4vci-proof+jwt",
                "jwk": proof_jwk,
                "key_attestation": &wrong_attestation,
            }),
            payload.clone(),
        );
        let wrong_key = verify_key_attestation_bound_jwt_proof(
            &wrong_key_proof,
            "https://issuer.example",
            Some("nonce-1"),
            300,
            &wrong_attestation,
        )
        .unwrap_err();
        assert!(wrong_key
            .to_string()
            .contains("not contained in attested_keys"));

        let noncanonical_numeric_kid = sign_test_proof(
            &signing_key,
            serde_json::json!({
                "alg": "EdDSA",
                "typ": "openid4vci-proof+jwt",
                "kid": "1",
                "key_attestation": &attestation,
            }),
            payload,
        );
        let kid_error = verify_key_attestation_bound_jwt_proof(
            &noncanonical_numeric_kid,
            "https://issuer.example",
            Some("nonce-1"),
            300,
            &attestation,
        )
        .unwrap_err();
        assert!(kid_error
            .to_string()
            .contains("canonical first-key selector '0'"));

        let private_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": B64.encode(signing_key.verifying_key().to_bytes()),
            "d": B64.encode(signing_key.to_bytes()),
        });
        let private_attestation = validated_key_attestation_jwt(vec![private_jwk]);
        let private_proof = sign_test_proof(
            &signing_key,
            serde_json::json!({
                "alg": "EdDSA",
                "typ": "openid4vci-proof+jwt",
                "jwk": embedded_ed25519_jwk(&signing_key),
                "key_attestation": &private_attestation,
            }),
            serde_json::json!({
                "aud": "https://issuer.example",
                "iat": chrono::Utc::now().timestamp(),
                "nonce": "nonce-1",
            }),
        );
        let private_error = verify_key_attestation_bound_jwt_proof(
            &private_proof,
            "https://issuer.example",
            Some("nonce-1"),
            300,
            &private_attestation,
        )
        .unwrap_err();
        assert!(private_error.to_string().contains("public keys only"));
    }

    #[test]
    fn key_attestation_binding_rejects_malformed_or_empty_attestation_payloads() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let proof_for = |attestation: &str| {
            sign_test_proof(
                &signing_key,
                serde_json::json!({
                    "alg": "EdDSA",
                    "typ": "openid4vci-proof+jwt",
                    "kid": "0",
                    "key_attestation": attestation,
                }),
                serde_json::json!({
                    "aud": "https://issuer.example",
                    "iat": chrono::Utc::now().timestamp(),
                    "nonce": "nonce-1",
                }),
            )
        };

        let malformed = "not.*.signature";
        let malformed_error = verify_key_attestation_bound_jwt_proof(
            &proof_for(malformed),
            "https://issuer.example",
            Some("nonce-1"),
            300,
            malformed,
        )
        .unwrap_err();
        assert!(malformed_error.to_string().contains("not base64url"));

        let empty = validated_key_attestation_jwt(Vec::new());
        let empty_error = verify_key_attestation_bound_jwt_proof(
            &proof_for(&empty),
            "https://issuer.example",
            Some("nonce-1"),
            300,
            &empty,
        )
        .unwrap_err();
        assert!(empty_error.to_string().contains("no attested public keys"));
    }

    #[test]
    fn key_attestation_binding_rejects_every_raw_private_jwk_member() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_jwk = embedded_ed25519_jwk(&signing_key);
        let payload = serde_json::json!({
            "aud": "https://issuer.example",
            "iat": chrono::Utc::now().timestamp(),
            "nonce": "nonce-1",
        });

        for member in ["d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            let mut private_attested_jwk = public_jwk.clone();
            private_attested_jwk
                .as_object_mut()
                .expect("test JWK is an object")
                .insert(member.into(), serde_json::json!("secret"));
            let private_attestation = validated_key_attestation_jwt(vec![private_attested_jwk]);
            let proof = sign_test_proof(
                &signing_key,
                serde_json::json!({
                    "alg": "EdDSA",
                    "typ": "openid4vci-proof+jwt",
                    "jwk": public_jwk.clone(),
                    "key_attestation": &private_attestation,
                }),
                payload.clone(),
            );
            let error = verify_key_attestation_bound_jwt_proof(
                &proof,
                "https://issuer.example",
                Some("nonce-1"),
                300,
                &private_attestation,
            )
            .unwrap_err();
            assert!(error.to_string().contains("public keys only"));

            let attestation = validated_key_attestation_jwt(vec![public_jwk.clone()]);
            let mut private_header_jwk = public_jwk.clone();
            private_header_jwk
                .as_object_mut()
                .expect("test JWK is an object")
                .insert(member.into(), serde_json::json!("secret"));
            let proof = sign_test_proof(
                &signing_key,
                serde_json::json!({
                    "alg": "EdDSA",
                    "typ": "openid4vci-proof+jwt",
                    "jwk": private_header_jwk,
                    "key_attestation": &attestation,
                }),
                payload.clone(),
            );
            let error = verify_key_attestation_bound_jwt_proof(
                &proof,
                "https://issuer.example",
                Some("nonce-1"),
                300,
                &attestation,
            )
            .unwrap_err();
            assert!(error.to_string().contains("public JWK only"));
        }
    }
}
