//! Explicit issuer verification keys shared by wallet and verifier boundaries.

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::types::SigningAlgorithm;

/// Issuer verification material returned by an SD-JWT key resolver.
///
/// The identity metadata is carried alongside the public JWK so the wallet can
/// fail closed if a resolver returns a key for a different issuer, key ID, or
/// JOSE algorithm than the credential's unverified key-selection context.
#[derive(Clone)]
pub struct ResolvedSdJwtIssuerKey {
    issuer: String,
    key_id: Option<String>,
    algorithm: SigningAlgorithm,
    public_jwk_json: String,
}

impl std::fmt::Debug for ResolvedSdJwtIssuerKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResolvedSdJwtIssuerKey([redacted])")
    }
}

impl ResolvedSdJwtIssuerKey {
    /// Construct resolved public verification material.
    pub fn new(
        issuer: impl Into<String>,
        key_id: Option<String>,
        algorithm: SigningAlgorithm,
        public_jwk_json: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            key_id,
            algorithm,
            public_jwk_json: public_jwk_json.into(),
        }
    }

    /// Issuer identifier to which the resolver bound this key.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Verification-method identifier to which the resolver bound this key.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// JOSE algorithm to which the resolver bound this key.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// Public-only JWK JSON used for issuer-signature verification.
    pub fn public_jwk_json(&self) -> &str {
        &self.public_jwk_json
    }
}

/// Resolve an issuer verification key from an unverified SD-JWT VC
/// key-selection context.
///
/// Implementations may consult a DID document, trusted issuer profile, or a
/// prevalidated local key set. Network and trust-policy decisions remain with
/// the caller; the wallet independently checks the returned binding metadata.
/// The `issuer`, `key_id`, and `algorithm` inputs are unverified key-selection
/// hints. A resolver must apply its own allowlist and SSRF policy and must not
/// treat those inputs as authenticated. After resolution,
/// the wallet verified-presentation composition
/// verifies the JWS before using its signed claims or the holder key.
pub trait SdJwtIssuerKeyResolver {
    fn resolve(
        &self,
        issuer: &str,
        key_id: Option<&str>,
        algorithm: SigningAlgorithm,
    ) -> Oid4vciResult<ResolvedSdJwtIssuerKey>;
}

/// Explicit public-key allowlist supplied by an independently trusted source.
/// It never discovers keys from a credential or presentation request.
#[derive(Clone)]
pub struct TrustedSdJwtIssuerKeys {
    keys: Vec<ResolvedSdJwtIssuerKey>,
}

impl TrustedSdJwtIssuerKeys {
    pub fn new(keys: Vec<ResolvedSdJwtIssuerKey>) -> Oid4vciResult<Self> {
        if keys.is_empty() {
            return Err(Oid4vciError::KeyError(
                "Trusted SD-JWT issuer key set must not be empty".into(),
            ));
        }
        let mut tuples = std::collections::BTreeSet::new();
        for key in &keys {
            if key.issuer.is_empty()
                || key.issuer.trim() != key.issuer
                || key
                    .key_id
                    .as_ref()
                    .is_some_and(|id| id.is_empty() || id.trim() != id)
                || !matches!(
                    key.algorithm,
                    SigningAlgorithm::ES256
                        | SigningAlgorithm::ES384
                        | SigningAlgorithm::EdDSA
                        | SigningAlgorithm::RS256
                )
            {
                return Err(Oid4vciError::KeyError(
                    "Trusted SD-JWT issuer key identity is invalid".into(),
                ));
            }
            if key.public_jwk_json.len() > crate::jose::MAX_PUBLIC_JWK_BYTES {
                return Err(Oid4vciError::KeyError(
                    "Trusted SD-JWT issuer public JWK exceeds its size limit".into(),
                ));
            }
            let jwk = crate::jose::parse_unique_object(
                key.public_jwk_json.as_bytes(),
                "trusted issuer public JWK",
            )?;
            crate::jose::validate_public_jwk(&jwk, key.algorithm.as_str())?;
            if !issuer_key_family_matches(&jwk, key.algorithm) {
                return Err(Oid4vciError::KeyError(
                    "Trusted SD-JWT issuer public JWK type or curve is incompatible with its algorithm".into(),
                ));
            }
            if let Some(jwk_id) = jwk.get("kid") {
                let jwk_id = jwk_id.as_str().filter(|id| !id.is_empty()).ok_or_else(|| {
                    Oid4vciError::KeyError(
                        "Trusted SD-JWT issuer public JWK kid must be a non-empty string".into(),
                    )
                })?;
                if Some(jwk_id) != key.key_id.as_deref() {
                    return Err(Oid4vciError::KeyError(
                        "Trusted SD-JWT issuer public JWK kid does not match its identity".into(),
                    ));
                }
            }
            if !tuples.insert((
                key.issuer.clone(),
                key.key_id.clone(),
                key.algorithm.as_str(),
            )) {
                return Err(Oid4vciError::KeyError(
                    "Trusted SD-JWT issuer key identity is ambiguous".into(),
                ));
            }
        }
        Ok(Self { keys })
    }
}

impl SdJwtIssuerKeyResolver for TrustedSdJwtIssuerKeys {
    fn resolve(
        &self,
        issuer: &str,
        key_id: Option<&str>,
        algorithm: SigningAlgorithm,
    ) -> Oid4vciResult<ResolvedSdJwtIssuerKey> {
        self.keys
            .iter()
            .find(|key| {
                key.issuer == issuer
                    && key.key_id.as_deref() == key_id
                    && key.algorithm == algorithm
            })
            .cloned()
            .ok_or_else(|| Oid4vciError::KeyError("Issuer key is not explicitly trusted".into()))
    }
}

pub(crate) fn issuer_key_family_matches(
    jwk: &serde_json::Value,
    algorithm: SigningAlgorithm,
) -> bool {
    let key_type = jwk.get("kty").and_then(serde_json::Value::as_str);
    let curve = jwk.get("crv").and_then(serde_json::Value::as_str);
    match algorithm {
        SigningAlgorithm::ES256 => key_type == Some("EC") && curve == Some("P-256"),
        SigningAlgorithm::ES384 => key_type == Some("EC") && curve == Some("P-384"),
        SigningAlgorithm::EdDSA => key_type == Some("OKP") && curve == Some("Ed25519"),
        SigningAlgorithm::RS256 => key_type == Some("RSA"),
        SigningAlgorithm::ES256K => false,
    }
}
