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

pub use jwe::*;
pub use jws::*;
pub use key::*;
