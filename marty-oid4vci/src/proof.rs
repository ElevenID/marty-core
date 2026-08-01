//! Proof-of-possession verification and creation for OID4VCI (§8.2).
//!
//! This module implements cryptographic verification of JWT proofs submitted
//! with credential requests. This replaces the previous insecure approach of
//! only extracting the `kid` header without signature verification.
//!
//! It also exposes `create_proof_jwt` for generating spec-correct holder
//! proof-of-possession JWTs (e.g. for integration tests and wallet clients).

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use serde::Deserialize;
use ssi_crypto::AlgorithmInstance;
use ssi_jwk::{Params, JWK};

use crate::error::{Oid4vciError, Oid4vciResult};

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
/// the proof must carry that exact attestation JWT, its `kid` must select one
/// of the `attested_keys` embedded in that JWT, and its signature must verify
/// with the selected key.
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
    // Step 1: Split and decode
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(Oid4vciError::ProofVerificationFailed(
            "JWT must have exactly 3 parts (header.payload.signature)".into(),
        ));
    }

    let header_bytes = B64.decode(parts[0]).map_err(|e| {
        Oid4vciError::ProofVerificationFailed(format!("Invalid header base64: {}", e))
    })?;
    let payload_bytes = B64.decode(parts[1]).map_err(|e| {
        Oid4vciError::ProofVerificationFailed(format!("Invalid payload base64: {}", e))
    })?;
    let signature_bytes = B64.decode(parts[2]).map_err(|e| {
        Oid4vciError::ProofVerificationFailed(format!("Invalid signature base64: {}", e))
    })?;

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
        parts[0],
        parts[1],
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
    if now - issued_at > max_age_seconds {
        return Err(Oid4vciError::ProofVerificationFailed(format!(
            "Proof JWT too old: iat={}, now={}, max_age={}s",
            issued_at, now, max_age_seconds
        )));
    }
    // Allow small clock skew (30 seconds into the future)
    if issued_at > now + 30 {
        return Err(Oid4vciError::ProofVerificationFailed(format!(
            "Proof JWT iat is in the future: iat={}, now={}",
            issued_at, now
        )));
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

fn extract_key_attestation_holder_key(
    header: &ProofHeader,
    validated_key_attestation_jwt: &str,
) -> Oid4vciResult<(String, Option<JWK>)> {
    if header.jwk.is_some() {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Key-attestation-bound proof must select an attested key with kid, not embed jwk"
                .into(),
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
    let attestation_parts: Vec<&str> = validated_key_attestation_jwt.split('.').collect();
    if attestation_parts.len() != 3 {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Validated key attestation JWT must have exactly 3 parts".into(),
        ));
    }
    let attestation_payload = B64.decode(attestation_parts[1]).map_err(|error| {
        Oid4vciError::ProofVerificationFailed(format!(
            "Validated key attestation payload is not base64url: {error}"
        ))
    })?;
    let attestation: KeyAttestationPayload =
        serde_json::from_slice(&attestation_payload).map_err(|error| {
            Oid4vciError::ProofVerificationFailed(format!(
                "Validated key attestation payload is invalid: {error}"
            ))
        })?;
    if attestation.attested_keys.is_empty() {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Validated key attestation has no attested public keys".into(),
        ));
    }
    let kid = header.kid.as_deref().ok_or_else(|| {
        Oid4vciError::ProofVerificationFailed(
            "Key-attestation-bound proof is missing attested key index in kid".into(),
        )
    })?;
    let key_index = kid.parse::<usize>().map_err(|_| {
        Oid4vciError::ProofVerificationFailed(format!(
            "Key-attestation-bound proof kid must be a non-negative attested key index, got '{kid}'"
        ))
    })?;
    let jwk = attestation.attested_keys.get(key_index).ok_or_else(|| {
        Oid4vciError::ProofVerificationFailed(format!(
            "Attested key index {key_index} is out of range for {} keys",
            attestation.attested_keys.len()
        ))
    })?;
    if jwk_has_private_material(jwk) {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Validated key attestation must contain public keys only".into(),
        ));
    }
    Ok((public_jwk_holder_id(jwk)?, Some(jwk.clone())))
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
            let jwk: JWK = serde_json::from_value(jwk_value.clone()).map_err(|e| {
                Oid4vciError::ProofVerificationFailed(format!("Invalid JWK in proof header: {}", e))
            })?;

            // Derive a holder ID from the JWK (thumbprint or did:jwk)
            let jwk_json = serde_json::to_string(&jwk).map_err(|e| {
                Oid4vciError::ProofVerificationFailed(format!("Failed to serialize JWK: {}", e))
            })?;
            let encoded = B64.encode(jwk_json.as_bytes());
            let holder_id = format!("did:jwk:{}", encoded);

            Ok((holder_id, Some(jwk)))
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

    // Map algorithm string to SSI AlgorithmInstance
    let alg_instance = match alg {
        "ES256" => AlgorithmInstance::ES256,
        "EdDSA" => AlgorithmInstance::EdDSA,
        "ES256K" => AlgorithmInstance::ES256K,
        "ES384" => AlgorithmInstance::ES384,
        "RS256" => {
            // RSA verification requires different handling
            return verify_rsa_signature(jwk, alg, &message, signature);
        }
        _ => {
            return Err(Oid4vciError::ProofVerificationFailed(format!(
                "Unsupported proof signing algorithm: {}",
                alg
            )));
        }
    };

    // Extract public key from JWK
    let public_key = extract_public_key(jwk)?;

    // Verify using SSI's crypto
    let verified = public_key
        .verify(alg_instance, message.as_bytes(), signature)
        .map_err(|e| {
            Oid4vciError::ProofVerificationFailed(format!("Signature verification failed: {:?}", e))
        })?;

    // `ssi_crypto::AlgorithmInstance::verify` communicates an invalid
    // cryptographic signature as `Ok(false)`, not an error.  Treat both forms
    // of failure identically: accepting `false` would issue a credential for
    // a tampered proof.
    if !verified {
        return Err(Oid4vciError::ProofVerificationFailed(
            "Signature verification failed: invalid signature".into(),
        ));
    }

    Ok(())
}

/// Extract a public key from a JWK for verification.
fn extract_public_key(jwk: &JWK) -> Oid4vciResult<ssi_crypto::PublicKey> {
    match &jwk.params {
        Params::OKP(params) => ssi_crypto::PublicKey::new_ed25519(&params.public_key.0)
            .map_err(|e| Oid4vciError::KeyError(format!("Invalid Ed25519 public key: {:?}", e))),
        Params::EC(params) => {
            // For EC keys, we need both x and y coordinates
            let x = params
                .x_coordinate
                .as_ref()
                .ok_or_else(|| Oid4vciError::KeyError("Missing EC x coordinate".into()))?;
            let y = params
                .y_coordinate
                .as_ref()
                .ok_or_else(|| Oid4vciError::KeyError("Missing EC y coordinate".into()))?;

            match params.curve.as_deref() {
                Some("P-256") => ssi_crypto::PublicKey::new_p256(&x.0, &y.0).map_err(|e| {
                    Oid4vciError::KeyError(format!("Invalid P-256 public key: {:?}", e))
                }),
                Some("secp256k1") => {
                    ssi_crypto::PublicKey::new_secp256k1(&x.0, &y.0).map_err(|e| {
                        Oid4vciError::KeyError(format!("Invalid secp256k1 public key: {:?}", e))
                    })
                }
                Some(curve) => Err(Oid4vciError::KeyError(format!(
                    "Unsupported EC curve for proof verification: {}",
                    curve
                ))),
                None => Err(Oid4vciError::KeyError("Missing curve in EC JWK".into())),
            }
        }
        _ => Err(Oid4vciError::KeyError(
            "Unsupported key type for proof verification (expected OKP or EC)".into(),
        )),
    }
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
    fn key_attestation_bound_proof_selects_and_verifies_attested_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let attestation = validated_key_attestation_jwt(vec![embedded_ed25519_jwk(&signing_key)]);
        let proof = sign_test_proof(
            &signing_key,
            serde_json::json!({
                "alg": "EdDSA",
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
    fn key_attestation_binding_rejects_token_index_key_and_private_material_mismatch() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let attestation = validated_key_attestation_jwt(vec![embedded_ed25519_jwk(&signing_key)]);
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
                "kid": "0",
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
                "kid": "0",
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
        assert!(wrong_key.to_string().contains("invalid signature"));

        let out_of_range = sign_test_proof(
            &signing_key,
            serde_json::json!({
                "alg": "EdDSA",
                "typ": "openid4vci-proof+jwt",
                "kid": "1",
                "key_attestation": &attestation,
            }),
            payload,
        );
        let index_error = verify_key_attestation_bound_jwt_proof(
            &out_of_range,
            "https://issuer.example",
            Some("nonce-1"),
            300,
            &attestation,
        )
        .unwrap_err();
        assert!(index_error.to_string().contains("out of range"));

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
                "kid": "0",
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
}
