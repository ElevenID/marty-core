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

#[cfg(all(
    feature = "kms-only",
    any(feature = "holder-key-operations", feature = "local-key-operations")
))]
compile_error!("kms-only builds cannot include local issuer or holder key operations");

mod bounded_jwt;
pub mod discovery;
pub mod error;
pub mod formats;
#[cfg(any(test, feature = "holder-key-operations"))]
pub mod holder_key;
#[cfg(feature = "issuer")]
pub mod issuer;
pub mod jose;
#[cfg(feature = "lti")]
pub mod lti;
pub mod metadata;
pub mod oidc;
pub mod presentation_request;
pub mod proof;
#[cfg(all(feature = "issuer", feature = "mso_mdoc", feature = "sd_jwt"))]
pub mod remote_credential;
#[cfg(any(test, feature = "issuer"))]
pub mod signer;
#[cfg(all(feature = "issuer", feature = "mso_mdoc", feature = "sd_jwt"))]
pub mod signing_batch;
pub mod siop;
pub mod types;
#[cfg(feature = "verifier")]
pub mod verifier;
pub mod wallet_input;

#[cfg(feature = "wallet")]
pub mod wallet;
#[cfg(feature = "wallet")]
mod wallet_sd_jwt;

pub use error::{Oid4vciError, Oid4vciResult};
#[cfg(feature = "holder-key-operations")]
pub use holder_key::{
    generate_p256_did_jwk_holder_key, p256_did_jwk_holder_key_from_private_jwk,
    DidJwkHolderKeyMaterial,
};

#[cfg(not(feature = "local-key-operations"))]
/// The default issuer surface cannot construct or use an in-process issuer key.
///
/// ```compile_fail
/// use marty_oid4vci::types::{IssuerKey, SigningAlgorithm};
/// let _ = IssuerKey {
///     issuer_id: "did:example:issuer".into(),
///     jwk_json: "{\"d\":\"private\"}".into(),
///     algorithm: SigningAlgorithm::ES256,
/// };
/// ```
///
/// ```compile_fail
/// use marty_oid4vci::issuer::generate_p256_jwk_pair;
/// ```
///
/// ```compile_fail
/// use marty_oid4vci::issuer::detect_algorithm;
/// ```
mod local_issuer_key_compile_boundary {}

#[cfg(not(feature = "holder-key-operations"))]
/// Issuer and verifier artifacts cannot create holder proof keys.
///
/// ```compile_fail
/// use marty_oid4vci::proof::create_proof_jwt;
/// let _ = create_proof_jwt("https://issuer.example", "nonce");
/// ```
mod holder_key_compile_boundary {}

#[cfg(not(feature = "issuer"))]
/// Verifier-only artifacts do not expose credential preparation or signer callbacks.
///
/// ```compile_fail
/// use marty_oid4vci::CredentialSigner;
/// ```
///
/// ```compile_fail
/// use marty_oid4vci::formats::sd_jwt::prepare_sd_jwt;
/// ```
///
/// ```compile_fail
/// use marty_oid4vci::formats::jwt_vc::prepare_jwt_vc;
/// ```
///
/// ```compile_fail
/// use marty_oid4vci::formats::mdoc::prepare_mdoc;
/// ```
///
/// ```compile_fail
/// use marty_oid4vci::formats::vds_nc::sign_vds_nc_with_signer;
/// ```
mod verifier_role_compile_boundary {}

#[cfg(feature = "issuer")]
pub use issuer::{generate_pkce_challenge_s256, verify_pkce_s256, IssuanceEngine};
#[cfg(feature = "issuer")]
pub use signer::CredentialSigner;
pub use types::{
    AuthorizationCodeGrant, AuthorizationCodeTokenRequest, AuthorizationDetail,
    AuthorizationRequest, AuthorizationResponse, AuthorizationSession, CodeChallengeMethod,
    CredentialFormat, GrantType, ZkPredicateBinding,
};
#[cfg(feature = "verifier")]
pub use verifier::VerificationEngine;
pub use wallet_input::{
    classify_wallet_input, normalize_credential_offer_uri, ClassifiedWalletInput, WalletInputKind,
    MAX_WALLET_INPUT_BYTES,
};

#[cfg(feature = "wallet")]
pub use wallet::{
    DcqlClaimQuery, DcqlCredentialQuery, DcqlQuery, IssuerMetadata, ParsedPresentationRequest,
    PresentationRequestQueryType, PresentationResponse, WalletEngine, ZkProofEntry,
};
#[cfg(feature = "wallet")]
pub use wallet_sd_jwt::{ResolvedSdJwtIssuerKey, SdJwtIssuerKeyResolver};

#[cfg(feature = "lti")]
pub use lti::{CanvasLtiPlatformProbe, VerifiedLtiLaunch};
