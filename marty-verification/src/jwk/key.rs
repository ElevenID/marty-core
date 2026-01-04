//! JSON Web Key (JWK) representation.
//!
//! Implements RFC 7517 JWK format for various key types.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{VerificationError, VerificationResult};

// ============================================================================
// JWK Structure
// ============================================================================

/// JSON Web Key (RFC 7517).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (kty): EC, RSA, OKP, oct
    pub kty: String,

    /// Key use: sig (signature) or enc (encryption)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,

    /// Key operations: sign, verify, encrypt, decrypt, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,

    /// Algorithm intended for use with this key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Key ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// X.509 URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// X.509 certificate chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    /// X.509 certificate SHA-1 thumbprint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// X.509 certificate SHA-256 thumbprint
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,

    // EC parameters
    /// Curve name (P-256, P-384, P-521, Ed25519, X25519)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,

    /// X coordinate (EC public key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,

    /// Y coordinate (EC public key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    /// D value (EC/OKP private key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    // RSA parameters
    /// Modulus (RSA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,

    /// Exponent (RSA)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    /// Private exponent (RSA private key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa_d: Option<String>,

    /// First prime factor (RSA private key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,

    /// Second prime factor (RSA private key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,

    /// First factor CRT exponent (RSA private key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,

    /// Second factor CRT exponent (RSA private key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,

    /// First CRT coefficient (RSA private key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,

    // Symmetric key
    /// Key value (symmetric key, base64url-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,

    /// Additional parameters
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

// Manual Default implementation is preferred here because:
// 1. The derive would produce identical code, but having it explicit makes
//    the semantics clear (empty kty, all optional fields None)
// 2. Future changes may need custom default values
#[allow(clippy::derivable_impls)]
impl Default for Jwk {
    fn default() -> Self {
        Self {
            kty: String::new(),
            use_: None,
            key_ops: None,
            alg: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            crv: None,
            x: None,
            y: None,
            d: None,
            n: None,
            e: None,
            rsa_d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            k: None,
            extra: HashMap::new(),
        }
    }
}

impl Jwk {
    /// Create a new empty JWK with the specified key type.
    pub fn new(kty: &str) -> Self {
        Self {
            kty: kty.to_string(),
            ..Default::default()
        }
    }

    /// Check if this is a private key.
    pub fn is_private(&self) -> bool {
        self.d.is_some() || self.rsa_d.is_some() || self.k.is_some()
    }

    /// Check if this is a public key (asymmetric key without private component).
    pub fn is_public(&self) -> bool {
        !self.is_private() && self.kty != "oct"
    }

    /// Check if this is a symmetric key.
    pub fn is_symmetric(&self) -> bool {
        self.kty == "oct"
    }

    /// Get the key type.
    pub fn key_type(&self) -> KeyType {
        match self.kty.as_str() {
            "EC" => match self.crv.as_deref() {
                Some("P-256") => KeyType::EcP256,
                Some("P-384") => KeyType::EcP384,
                Some("P-521") => KeyType::EcP521,
                _ => KeyType::Unknown,
            },
            "OKP" => match self.crv.as_deref() {
                Some("Ed25519") => KeyType::Ed25519,
                Some("X25519") => KeyType::X25519,
                _ => KeyType::Unknown,
            },
            "RSA" => KeyType::Rsa,
            "oct" => KeyType::Symmetric,
            _ => KeyType::Unknown,
        }
    }

    /// Get the public key portion (strips private key data).
    pub fn to_public(&self) -> Self {
        let mut public = self.clone();
        public.d = None;
        public.rsa_d = None;
        public.p = None;
        public.q = None;
        public.dp = None;
        public.dq = None;
        public.qi = None;
        public.k = None;
        public
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> VerificationResult<String> {
        serde_json::to_string(self)
            .map_err(|e| VerificationError::internal(format!("JWK serialization failed: {}", e)))
    }

    /// Serialize to pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> VerificationResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| VerificationError::internal(format!("JWK serialization failed: {}", e)))
    }

    /// Parse from JSON string.
    pub fn from_json(json: &str) -> VerificationResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| VerificationError::internal(format!("JWK parsing failed: {}", e)))
    }

    /// Compute the thumbprint (RFC 7638).
    pub fn thumbprint(&self) -> VerificationResult<String> {
        use sha2::{Digest, Sha256};

        // Build canonical JSON representation (sorted keys, no whitespace)
        let canonical =
            match self.kty.as_str() {
                "EC" => {
                    let crv = self.crv.as_ref().ok_or_else(|| {
                        VerificationError::internal("EC key missing crv".to_string())
                    })?;
                    let x = self.x.as_ref().ok_or_else(|| {
                        VerificationError::internal("EC key missing x".to_string())
                    })?;
                    let y = self.y.as_ref().ok_or_else(|| {
                        VerificationError::internal("EC key missing y".to_string())
                    })?;
                    format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, crv, x, y)
                }
                "OKP" => {
                    let crv = self.crv.as_ref().ok_or_else(|| {
                        VerificationError::internal("OKP key missing crv".to_string())
                    })?;
                    let x = self.x.as_ref().ok_or_else(|| {
                        VerificationError::internal("OKP key missing x".to_string())
                    })?;
                    format!(r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, crv, x)
                }
                "RSA" => {
                    let e = self.e.as_ref().ok_or_else(|| {
                        VerificationError::internal("RSA key missing e".to_string())
                    })?;
                    let n = self.n.as_ref().ok_or_else(|| {
                        VerificationError::internal("RSA key missing n".to_string())
                    })?;
                    format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e, n)
                }
                "oct" => {
                    let k = self.k.as_ref().ok_or_else(|| {
                        VerificationError::internal("Symmetric key missing k".to_string())
                    })?;
                    format!(r#"{{"k":"{}","kty":"oct"}}"#, k)
                }
                _ => {
                    return Err(VerificationError::internal(format!(
                        "Unsupported key type for thumbprint: {}",
                        self.kty
                    )))
                }
            };

        let hash = Sha256::digest(canonical.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(hash))
    }
}

// ============================================================================
// Key Types
// ============================================================================

/// Key type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// P-256 elliptic curve
    EcP256,
    /// P-384 elliptic curve
    EcP384,
    /// P-521 elliptic curve
    EcP521,
    /// Ed25519 (EdDSA)
    Ed25519,
    /// X25519 (key agreement)
    X25519,
    /// RSA
    Rsa,
    /// Symmetric (oct)
    Symmetric,
    /// Unknown key type
    Unknown,
}

// ============================================================================
// JWK Set
// ============================================================================

/// JSON Web Key Set (RFC 7517).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    /// Array of JWK values
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Create an empty JWK Set.
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Add a key to the set.
    pub fn add(&mut self, key: Jwk) {
        self.keys.push(key);
    }

    /// Find a key by ID.
    pub fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }

    /// Find keys by algorithm.
    pub fn find_by_alg(&self, alg: &str) -> Vec<&Jwk> {
        self.keys
            .iter()
            .filter(|k| k.alg.as_deref() == Some(alg))
            .collect()
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> VerificationResult<String> {
        serde_json::to_string(self).map_err(|e| {
            VerificationError::internal(format!("JWK Set serialization failed: {}", e))
        })
    }

    /// Parse from JSON string.
    pub fn from_json(json: &str) -> VerificationResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| VerificationError::internal(format!("JWK Set parsing failed: {}", e)))
    }
}

impl Default for JwkSet {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Key Generation
// ============================================================================

/// Generate a new EC P-256 JWK.
pub fn generate_ec_p256() -> VerificationResult<Jwk> {
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    use rand::rngs::OsRng;

    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let point = public.to_encoded_point(false);

    let x = point
        .x()
        .ok_or_else(|| VerificationError::internal("Failed to get x coordinate".to_string()))?;
    let y = point
        .y()
        .ok_or_else(|| VerificationError::internal("Failed to get y coordinate".to_string()))?;

    Ok(Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(x)),
        y: Some(URL_SAFE_NO_PAD.encode(y)),
        d: Some(URL_SAFE_NO_PAD.encode(secret.to_bytes())),
        ..Default::default()
    })
}

/// Generate a new EC P-384 JWK.
pub fn generate_ec_p384() -> VerificationResult<Jwk> {
    use elliptic_curve::sec1::ToEncodedPoint;
    use p384::SecretKey;
    use rand::rngs::OsRng;

    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let point = public.to_encoded_point(false);

    let x = point
        .x()
        .ok_or_else(|| VerificationError::internal("Failed to get x coordinate".to_string()))?;
    let y = point
        .y()
        .ok_or_else(|| VerificationError::internal("Failed to get y coordinate".to_string()))?;

    Ok(Jwk {
        kty: "EC".to_string(),
        crv: Some("P-384".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(x)),
        y: Some(URL_SAFE_NO_PAD.encode(y)),
        d: Some(URL_SAFE_NO_PAD.encode(secret.to_bytes())),
        ..Default::default()
    })
}

/// Generate a new Ed25519 JWK.
pub fn generate_ed25519() -> VerificationResult<Jwk> {
    use marty_crypto::ed25519::Ed25519KeyPair;

    let keypair = Ed25519KeyPair::generate();

    Ok(Jwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(keypair.public_key())),
        d: Some(URL_SAFE_NO_PAD.encode(keypair.secret_key())),
        ..Default::default()
    })
}

/// Generate a new X25519 JWK.
pub fn generate_x25519() -> VerificationResult<Jwk> {
    use marty_crypto::ecdh::x25519_generate_keypair;

    let (secret, public) = x25519_generate_keypair();

    Ok(Jwk {
        kty: "OKP".to_string(),
        crv: Some("X25519".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(public)),
        d: Some(URL_SAFE_NO_PAD.encode(secret)),
        ..Default::default()
    })
}

/// Generate a new symmetric key JWK.
pub fn generate_symmetric(size: usize) -> VerificationResult<Jwk> {
    use marty_crypto::keygen::generate_random_bytes;

    let key = generate_random_bytes(size);

    Ok(Jwk {
        kty: "oct".to_string(),
        k: Some(URL_SAFE_NO_PAD.encode(&key)),
        ..Default::default()
    })
}

// ============================================================================
// Key Import/Export
// ============================================================================

/// Import an Ed25519 public key from raw bytes.
pub fn import_ed25519_public(bytes: &[u8]) -> VerificationResult<Jwk> {
    if bytes.len() != 32 {
        return Err(VerificationError::internal(
            "Ed25519 public key must be 32 bytes".to_string(),
        ));
    }

    Ok(Jwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(bytes)),
        ..Default::default()
    })
}

/// Import an Ed25519 private key from raw bytes.
pub fn import_ed25519_private(secret: &[u8], public: &[u8]) -> VerificationResult<Jwk> {
    if secret.len() != 32 || public.len() != 32 {
        return Err(VerificationError::internal(
            "Ed25519 keys must be 32 bytes each".to_string(),
        ));
    }

    Ok(Jwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(public)),
        d: Some(URL_SAFE_NO_PAD.encode(secret)),
        ..Default::default()
    })
}

/// Export an Ed25519 public key to raw bytes.
pub fn export_ed25519_public(jwk: &Jwk) -> VerificationResult<Vec<u8>> {
    if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
        return Err(VerificationError::internal(
            "Not an Ed25519 key".to_string(),
        ));
    }

    let x = jwk
        .x
        .as_ref()
        .ok_or_else(|| VerificationError::internal("Ed25519 key missing x".to_string()))?;

    URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| VerificationError::internal(format!("Invalid base64url: {}", e)))
}

/// Export an Ed25519 private key to raw bytes.
pub fn export_ed25519_private(jwk: &Jwk) -> VerificationResult<Vec<u8>> {
    if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
        return Err(VerificationError::internal(
            "Not an Ed25519 key".to_string(),
        ));
    }

    let d = jwk.d.as_ref().ok_or_else(|| {
        VerificationError::internal("Ed25519 key missing d (private key)".to_string())
    })?;

    URL_SAFE_NO_PAD
        .decode(d)
        .map_err(|e| VerificationError::internal(format!("Invalid base64url: {}", e)))
}

// ============================================================================
// Base64URL Helpers
// ============================================================================

/// Encode bytes to base64url (no padding).
pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url (no padding) to bytes.
pub fn base64url_decode(data: &str) -> VerificationResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| VerificationError::internal(format!("Invalid base64url: {}", e)))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ec_p256() {
        let jwk = generate_ec_p256().unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, Some("P-256".to_string()));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());
        assert!(jwk.d.is_some());
        assert!(jwk.is_private());
    }

    #[test]
    fn test_generate_ed25519() {
        let jwk = generate_ed25519().unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, Some("Ed25519".to_string()));
        assert!(jwk.x.is_some());
        assert!(jwk.d.is_some());
        assert!(jwk.is_private());
    }

    #[test]
    fn test_generate_symmetric() {
        let jwk = generate_symmetric(32).unwrap();
        assert_eq!(jwk.kty, "oct");
        assert!(jwk.k.is_some());
        assert!(jwk.is_symmetric());
    }

    #[test]
    fn test_to_public() {
        let private = generate_ec_p256().unwrap();
        let public = private.to_public();

        assert!(private.is_private());
        assert!(public.is_public());
        assert!(public.d.is_none());
        assert_eq!(private.x, public.x);
        assert_eq!(private.y, public.y);
    }

    #[test]
    fn test_json_roundtrip() {
        let original = generate_ec_p256().unwrap();
        let json = original.to_json().unwrap();
        let parsed = Jwk::from_json(&json).unwrap();

        assert_eq!(original.kty, parsed.kty);
        assert_eq!(original.crv, parsed.crv);
        assert_eq!(original.x, parsed.x);
        assert_eq!(original.y, parsed.y);
        assert_eq!(original.d, parsed.d);
    }

    #[test]
    fn test_thumbprint() {
        let jwk = generate_ec_p256().unwrap();
        let thumbprint = jwk.thumbprint().unwrap();

        // Thumbprint should be base64url-encoded SHA-256 (43 chars without padding)
        assert_eq!(thumbprint.len(), 43);

        // Same key should produce same thumbprint
        let thumbprint2 = jwk.thumbprint().unwrap();
        assert_eq!(thumbprint, thumbprint2);
    }

    #[test]
    fn test_jwk_set() {
        let mut set = JwkSet::new();

        let mut key1 = generate_ec_p256().unwrap();
        key1.kid = Some("key-1".to_string());
        key1.alg = Some("ES256".to_string());

        let mut key2 = generate_ed25519().unwrap();
        key2.kid = Some("key-2".to_string());
        key2.alg = Some("EdDSA".to_string());

        set.add(key1);
        set.add(key2);

        assert_eq!(set.keys.len(), 2);
        assert!(set.find_by_kid("key-1").is_some());
        assert!(set.find_by_kid("key-2").is_some());
        assert!(set.find_by_kid("key-3").is_none());
        assert_eq!(set.find_by_alg("ES256").len(), 1);
    }

    #[test]
    fn test_key_type() {
        let ec = generate_ec_p256().unwrap();
        assert_eq!(ec.key_type(), KeyType::EcP256);

        let ed = generate_ed25519().unwrap();
        assert_eq!(ed.key_type(), KeyType::Ed25519);

        let sym = generate_symmetric(32).unwrap();
        assert_eq!(sym.key_type(), KeyType::Symmetric);
    }

    #[test]
    fn test_import_export_ed25519() {
        let original = generate_ed25519().unwrap();

        let public_bytes = export_ed25519_public(&original).unwrap();
        let private_bytes = export_ed25519_private(&original).unwrap();

        assert_eq!(public_bytes.len(), 32);
        assert_eq!(private_bytes.len(), 32);

        let imported = import_ed25519_private(&private_bytes, &public_bytes).unwrap();
        assert_eq!(original.x, imported.x);
        assert_eq!(original.d, imported.d);
    }
}
