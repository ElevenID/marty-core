//! Pure cryptographic primitives for the Marty ecosystem.
//!
//! This crate provides low-level cryptographic operations used across Marty products:
//!
//! - **Signature algorithms**: ECDSA, EdDSA, RSA
//! - **X.509 certificates**: Parsing and information extraction
//! - **Symmetric encryption**: AES-GCM, AES-CBC, 3DES
//! - **Key derivation**: HKDF, PBKDF2
//! - **Key agreement**: ECDH (X25519)
//!
//! # Design Principles
//!
//! - **No policy decisions**: This crate provides primitives only. Verification
//!   policies belong in `marty-verification`.
//! - **No network I/O**: All operations are synchronous and local.
//! - **Pure Rust**: Uses RustCrypto crates exclusively.

//! # Example
//!
//! ```rust,ignore
//! use marty_crypto::{ecdsa, certificate, SignatureAlgorithm};
//!
//! // Generate a P-256 key pair
//! let (private_key, public_key) = ecdsa::generate_p256_keypair()?;
//!
//! // Sign a message
//! let message = b"Hello, World!";
//! let signature = ecdsa::sign_p256(&private_key, message)?;
//!
//! // Verify the signature
//! ecdsa::verify_p256(&public_key, message, &signature)?;
//! ```

pub mod bbs;
pub mod cert_builder;
pub mod certificate;
pub mod crl;
pub mod des;
pub mod ecdh;
pub mod ecdsa;
pub mod ed25519;
pub mod ed448;
pub mod error;
pub mod hashing;
pub mod iso9796;
pub mod kdf;
pub mod keygen;
pub mod ocsp;
pub mod pkcs12;
pub mod rsa;
pub mod serialization;
pub mod sod_builder;
pub mod symmetric;

pub use error::{CryptoError, CryptoResult};

use serde::{Deserialize, Serialize};

/// Supported signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// ECDSA with P-256 curve and SHA-256 (ES256)
    EcdsaP256Sha256,
    /// ECDSA with P-384 curve and SHA-384 (ES384)
    EcdsaP384Sha384,
    /// ECDSA with P-521 curve and SHA-512 (ES512)
    EcdsaP521Sha512,
    /// Ed25519 pure EdDSA
    Ed25519,
    /// Ed448 pure EdDSA
    Ed448,
    /// RSA PKCS#1 v1.5 with SHA-1 (legacy)
    #[deprecated(note = "SHA-1 is cryptographically weak; use only for legacy compatibility")]
    RsaPkcs1Sha1,
    /// RSA PKCS#1 v1.5 with SHA-256 (RS256)
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384 (RS384)
    RsaPkcs1Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512 (RS512)
    RsaPkcs1Sha512,
    /// RSA PSS with SHA-256 (PS256)
    RsaPssSha256,
    /// RSA PSS with SHA-384 (PS384)
    RsaPssSha384,
    /// RSA PSS with SHA-512 (PS512)
    RsaPssSha512,
    /// BBS+ with BLS12-381 and SHA-256
    BbsBls12381Sha256,
    /// BBS+ with BLS12-381 and SHAKE-256 (IETF recommended)
    BbsBls12381Shake256,
}

impl SignatureAlgorithm {
    /// Get the OID for this signature algorithm.
    #[allow(deprecated)]
    pub fn oid(&self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "1.2.840.10045.4.3.2",
            Self::EcdsaP384Sha384 => "1.2.840.10045.4.3.3",
            Self::EcdsaP521Sha512 => "1.2.840.10045.4.3.4",
            Self::Ed25519 => "1.3.101.112",
            Self::Ed448 => "1.3.101.113",
            Self::RsaPkcs1Sha1 => "1.2.840.113549.1.1.5",
            Self::RsaPkcs1Sha256 => "1.2.840.113549.1.1.11",
            Self::RsaPkcs1Sha384 => "1.2.840.113549.1.1.12",
            Self::RsaPkcs1Sha512 => "1.2.840.113549.1.1.13",
            Self::RsaPssSha256 | Self::RsaPssSha384 | Self::RsaPssSha512 => "1.2.840.113549.1.1.10",
            // BBS+ does not have an ASN.1 OID; use the IETF ciphersuite identifiers
            Self::BbsBls12381Sha256 => "BBS_BLS12381_SHA256",
            Self::BbsBls12381Shake256 => "BBS_BLS12381_SHAKE256",
        }
    }

    /// Try to determine algorithm from OID string.
    #[allow(deprecated)]
    pub fn from_oid(oid: &str) -> CryptoResult<Self> {
        match oid {
            "1.2.840.10045.4.3.2" => Ok(Self::EcdsaP256Sha256),
            "1.2.840.10045.4.3.3" => Ok(Self::EcdsaP384Sha384),
            "1.2.840.10045.4.3.4" => Ok(Self::EcdsaP521Sha512),
            "1.3.101.112" => Ok(Self::Ed25519),
            "1.3.101.113" => Ok(Self::Ed448),
            "1.2.840.113549.1.1.5" => Ok(Self::RsaPkcs1Sha1),
            "1.2.840.113549.1.1.11" => Ok(Self::RsaPkcs1Sha256),
            "1.2.840.113549.1.1.12" => Ok(Self::RsaPkcs1Sha384),
            "1.2.840.113549.1.1.13" => Ok(Self::RsaPkcs1Sha512),
            "BBS_BLS12381_SHA256" => Ok(Self::BbsBls12381Sha256),
            "BBS_BLS12381_SHAKE256" => Ok(Self::BbsBls12381Shake256),
            _ => Err(CryptoError::unsupported_algorithm(format!(
                "Unsupported signature algorithm OID: {}",
                oid
            ))),
        }
    }

    /// Check if this is an ECDSA algorithm.
    pub fn is_ecdsa(&self) -> bool {
        matches!(
            self,
            Self::EcdsaP256Sha256 | Self::EcdsaP384Sha384 | Self::EcdsaP521Sha512
        )
    }

    /// Check if this is an EdDSA algorithm.
    pub fn is_eddsa(&self) -> bool {
        matches!(self, Self::Ed25519 | Self::Ed448)
    }

    /// Check if this is an RSA algorithm.
    #[allow(deprecated)]
    pub fn is_rsa(&self) -> bool {
        matches!(
            self,
            Self::RsaPkcs1Sha1
                | Self::RsaPkcs1Sha256
                | Self::RsaPkcs1Sha384
                | Self::RsaPkcs1Sha512
                | Self::RsaPssSha256
                | Self::RsaPssSha384
                | Self::RsaPssSha512
        )
    }

    /// Check if this is a BBS+ algorithm.
    pub fn is_bbs(&self) -> bool {
        matches!(self, Self::BbsBls12381Sha256 | Self::BbsBls12381Shake256)
    }

    /// Get the expected signature size in bytes for this algorithm.
    #[allow(deprecated)]
    pub fn signature_size(&self) -> usize {
        match self {
            Self::EcdsaP256Sha256 => 64,
            Self::EcdsaP384Sha384 => 96,
            Self::EcdsaP521Sha512 => 132,
            Self::Ed25519 => 64,
            Self::Ed448 => 114,
            Self::RsaPkcs1Sha1
            | Self::RsaPkcs1Sha256
            | Self::RsaPkcs1Sha384
            | Self::RsaPkcs1Sha512
            | Self::RsaPssSha256
            | Self::RsaPssSha384
            | Self::RsaPssSha512 => 256, // Typical 2048-bit RSA
            Self::BbsBls12381Sha256 | Self::BbsBls12381Shake256 => 80, // BBS+ signature is 80 bytes
        }
    }
}

/// Supported hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA-1 (legacy, use only for compatibility)
    #[deprecated(note = "SHA-1 is cryptographically weak")]
    Sha1,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl HashAlgorithm {
    /// Get the OID for this hash algorithm.
    #[allow(deprecated)]
    pub fn oid(&self) -> &'static str {
        match self {
            Self::Sha1 => "1.3.14.3.2.26",
            Self::Sha256 => "2.16.840.1.101.3.4.2.1",
            Self::Sha384 => "2.16.840.1.101.3.4.2.2",
            Self::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    /// Try to determine algorithm from OID string.
    #[allow(deprecated)]
    pub fn from_oid(oid: &str) -> CryptoResult<Self> {
        match oid {
            "1.3.14.3.2.26" => Ok(Self::Sha1),
            "2.16.840.1.101.3.4.2.1" => Ok(Self::Sha256),
            "2.16.840.1.101.3.4.2.2" => Ok(Self::Sha384),
            "2.16.840.1.101.3.4.2.3" => Ok(Self::Sha512),
            _ => Err(CryptoError::unsupported_algorithm(format!(
                "Unsupported hash algorithm OID: {}",
                oid
            ))),
        }
    }

    /// Get the digest size in bytes.
    #[allow(deprecated)]
    pub fn digest_size(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Verify a signature using the specified algorithm.
///
/// This is the main entry point for signature verification. It dispatches
/// to the appropriate implementation based on the algorithm.
///
/// # Arguments
///
/// * `algorithm` - The signature algorithm to use
/// * `public_key_der` - DER-encoded public key (SubjectPublicKeyInfo)
/// * `message` - The message that was signed
/// * `signature` - The signature bytes
///
/// # Returns
///
/// `Ok(true)` if signature is valid, `Ok(false)` if invalid,
/// or `Err` if verification cannot be performed.
#[allow(deprecated)]
pub fn verify_signature(
    algorithm: SignatureAlgorithm,
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    match algorithm {
        SignatureAlgorithm::EcdsaP256Sha256 => {
            ecdsa::verify_p256_sha256(public_key_der, message, signature)
        }
        SignatureAlgorithm::EcdsaP384Sha384 => {
            ecdsa::verify_p384_sha384(public_key_der, message, signature)
        }
        SignatureAlgorithm::EcdsaP521Sha512 => {
            ecdsa::verify_p521_sha512(public_key_der, message, signature)
        }
        SignatureAlgorithm::Ed25519 => {
            ed25519::verify_ed25519_spki(public_key_der, message, signature)
        }
        SignatureAlgorithm::Ed448 => ed448::verify_ed448_spki(public_key_der, message, signature),
        SignatureAlgorithm::RsaPkcs1Sha1 =>
        {
            #[allow(deprecated)]
            rsa::verify_pkcs1_sha1(public_key_der, message, signature)
        }
        SignatureAlgorithm::RsaPkcs1Sha256 => {
            rsa::verify_pkcs1_sha256(public_key_der, message, signature)
        }
        SignatureAlgorithm::RsaPkcs1Sha384 => {
            rsa::verify_pkcs1_sha384(public_key_der, message, signature)
        }
        SignatureAlgorithm::RsaPkcs1Sha512 => {
            rsa::verify_pkcs1_sha512(public_key_der, message, signature)
        }
        SignatureAlgorithm::RsaPssSha256 => {
            rsa::verify_pss_sha256(public_key_der, message, signature)
        }
        SignatureAlgorithm::RsaPssSha384 => {
            rsa::verify_pss_sha384(public_key_der, message, signature)
        }
        SignatureAlgorithm::RsaPssSha512 => {
            rsa::verify_pss_sha512(public_key_der, message, signature)
        }
        SignatureAlgorithm::BbsBls12381Sha256 | SignatureAlgorithm::BbsBls12381Shake256 => {
            Err(CryptoError::unsupported_algorithm(
                "BBS+ signatures use multi-message API; use bbs module directly".to_string(),
            ))
        }
    }
}
