//! # marty-oid4vci
//!
//! OID4VCI (OpenID for Verifiable Credential Issuance) and OID4VP (OpenID for
//! Verifiable Presentations) protocol engine for the Marty digital identity platform.
//!
//! This crate provides a library-backed implementation of the OID4VCI v1 and OID4VP v1
//! specifications, replacing hand-rolled protocol code with a structured, tested engine.
//!
//! ## Architecture
//!
//! The crate is organized into layers:
//!
//! - **`types`** — Protocol data types (credential offers, token requests/responses,
//!   credential requests/responses, issuer metadata)
//! - **`issuer`** — Credential issuer engine handling the complete OID4VCI server flow
//! - **`formats`** — Format-specific credential construction (`jwt_vc_json`, `vc+sd-jwt`, `mso_mdoc`, `zk_mdoc`)
//! - **`proof`** — Proof-of-possession verification (JWT proof type)
//! - **`metadata`** — Issuer metadata and OAuth authorization server metadata generation
//! - **`verifier`** — OID4VP presentation verification with ZK predicate support
//! - **`error`** — Unified error types
//!
//! ## Credential Formats
//!
//! All three major credential formats are supported:
//!
//! - **`jwt_vc_json`** — W3C VC-JWT (ES256, EdDSA, RS256)
//! - **`vc+sd-jwt`** — IETF SD-JWT with selective disclosure
//! - **`mso_mdoc`** — ISO 18013-5 mobile document with CBOR/COSE signing
//! - **`zk_mdoc`** — ZK-enabled mDoc with Longfellow/Ligero predicate proofs
//!
//! ## Usage
//!
//! ```rust,ignore
//! use marty_oid4vci::issuer::IssuanceEngine;
//! use marty_oid4vci::types::{IssuerConfig, IssuerKey, OfferConfig, SigningAlgorithm};
//!
//! let config = IssuerConfig { /* ... */ };
//! let engine = IssuanceEngine::new(config);
//!
//! // Create a credential offer
//! let offer = engine.create_offer(&OfferConfig {
//!     credential_configuration_ids: vec!["UniversityDegree".into()],
//!     pre_authorized_code: Some("code123".into()),
//!     user_pin_required: false,
//!     issuer_state: None,
//! }).unwrap();
//! ```

pub mod error;
pub mod formats;
pub mod issuer;
pub mod metadata;
pub mod proof;
pub mod types;
pub mod verifier;

#[cfg(feature = "wallet")]
pub mod wallet;

pub use error::{Oid4vciError, Oid4vciResult};
pub use issuer::{generate_pkce_challenge_s256, verify_pkce_s256, IssuanceEngine};
pub use types::{
    AuthorizationCodeGrant, AuthorizationCodeTokenRequest, AuthorizationDetail,
    AuthorizationRequest, AuthorizationResponse, AuthorizationSession, CodeChallengeMethod,
    CredentialFormat, GrantType, ZkPredicateBinding,
};
pub use verifier::VerificationEngine;

#[cfg(feature = "wallet")]
pub use wallet::{IssuerMetadata, PresentationResponse, WalletEngine, ZkProofEntry};
