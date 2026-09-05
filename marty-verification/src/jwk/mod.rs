//! JSON Web Key (JWK) implementation.
//!
//! This module provides RFC 7517 JSON Web Key support for:
//! - Key representation (EC, RSA, OKP, Symmetric)
//! - Key operations (sign, verify, encrypt, decrypt)
//! - Key import/export (JSON, PEM, JWK Set)
//!
//! This replaces the Python `jwcrypto` dependency.

mod jwe;
mod jws;
mod key;
mod public_key;

pub use jwe::*;
pub use jws::*;
pub use key::*;
pub use public_key::*;

#[cfg(not(feature = "local-key-operations"))]
/// Marker documenting the verification-only JWK boundary.
///
/// JWK generation and local JWS signing do not exist in this build:
///
/// ```compile_fail
/// let _ = marty_verification::jwk::generate_ec_p256();
/// ```
///
/// ```compile_fail
/// # use marty_verification::jwk::{Jwk, JwsHeader};
/// let _ = marty_verification::jwk::jws_sign(&JwsHeader::new("ES256"), b"payload", &Jwk::default());
/// ```
///
/// ```compile_fail
/// # use marty_verification::jwk::Jwk;
/// let _ = Jwk { d: Some("secret".into()), ..Jwk::default() };
/// ```
pub struct VerificationOnly;

#[cfg(not(feature = "ephemeral-session-keys"))]
/// The ordinary verifier surface can inspect HAIP headers but cannot create or
/// decrypt JWE payloads or generate session keys.
///
/// ```compile_fail
/// # use marty_verification::jwk::Jwk;
/// let _ = marty_verification::jwk::jwe_encrypt_direct(b"payload", &Jwk::default(), "A256GCM");
/// ```
///
/// ```compile_fail
/// let _ = marty_verification::jwk::generate_haip_response_encryption_jwk_pair();
/// ```
pub struct NoEphemeralSessionKeys;
