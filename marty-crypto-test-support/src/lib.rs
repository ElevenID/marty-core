//! Disposable remote-signing and public-key fixtures for Marty tests.
//!
//! This crate is deliberately `publish = false` and must only appear in
//! `dev-dependencies`. Shipping crates expose remote-signing inputs instead.

pub mod openbao_transit;
pub mod remote_certificate;

/// Public Ed25519 JWK coordinate for tests that only need a valid key point.
pub const ED25519_PUBLIC_JWK_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

/// Public P-256 JWK coordinates for tests that do not sign or decrypt.
pub const P256_PUBLIC_JWK_X: &str = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY";
pub const P256_PUBLIC_JWK_Y: &str = "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU";
