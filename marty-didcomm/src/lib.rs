//! # marty-didcomm
//!
//! DIDComm Messaging 2.1 support for the Marty digital identity platform.
//!
//! This crate provides DID resolution (did:key, did:web, did:peer, did:jwk)
//! and deliberately narrow one-recipient-DID credential-delivery profiles:
//! every authorized X25519 key-agreement method, `ECDH-ES+A256KW` anonymous encryption,
//! `ECDH-1PU+A256KW` sender-authenticated encryption, and the required
//! `A256CBC-HS512` content encryption algorithm. Key material must be
//! explicitly authorized by each DID document's `keyAgreement` relationship.
//! The encrypted-envelope implementation is checked against unmodified
//! Appendix C data.
//!
//! This is not a claim that Marty is a complete general-purpose DIDComm agent.
//! The public Marty API does not yet expose signed envelopes, mediator
//! routing/forwarding, multi-DID encryption, every required
//! key-agreement curve, or every protocol state machine. Those capabilities
//! need product-boundary and interoperability tests before they can be
//! advertised as supported.
//!
//! ## Supported DID Methods
//!
//! - **`did:key`** — Local derivation from public key (Ed25519, X25519, P-256)
//! - **`did:web`** — Via a deployment-managed resolver by default, or direct
//!   HTTPS only when a Rust caller supplies an exact host allowlist
//! - **`did:peer`** — Peer-local resolution (method 0 and 2)
//! - **`did:jwk`** — JWK-encoded public key
//!
//! ## Non-Goals
//!
//! Ledger-based DID methods (did:ion, did:ethr, did:sov, etc.) are explicitly
//! out of scope. For those methods, use the DIF Universal Resolver as an HTTP
//! proxy and configure its HTTP(S) base URL explicitly.

#[cfg(all(feature = "kms-only", feature = "local-key-operations"))]
compile_error!("kms-only DIDComm builds cannot accept caller-supplied private keys");

#[cfg(not(feature = "local-key-operations"))]
/// Marker for public-recipient encryption builds that cannot accept local
/// sender or recipient private keys.
///
/// ```compile_fail
/// use marty_didcomm::{decrypt_jwe, encrypt_for_recipient_authenticated};
/// ```
///
/// ```compile_fail
/// # use marty_didcomm::types::Jwk;
/// let _ = Jwk {
///     kty: "OKP".into(), crv: Some("X25519".into()), x: Some("public".into()),
///     y: None, kid: None, additional_properties: Default::default(),
/// };
/// ```
///
/// ```compile_fail
/// use marty_didcomm::types::VerificationMethod;
/// let mut method: VerificationMethod = serde_json::from_str(
///     r#"{"id":"did:example:1#key","type":"JsonWebKey2020","controller":"did:example:1"}"#
/// ).unwrap();
/// method.additional_properties.insert(
///     "publicKeyJwk".into(),
///     serde_json::json!({"kty":"EC","d":"secret"}),
/// );
/// ```
///
/// ```compile_fail
/// use marty_didcomm::types::DidDocument;
/// let mut document: DidDocument = serde_json::from_str(r#"{"id":"did:example:1"}"#).unwrap();
/// document.additional_properties.insert(
///     "verificationMethod".into(),
///     serde_json::json!([{"publicKeyJwk":{"kty":"EC","d":"secret"}}]),
/// );
/// ```
///
/// ```compile_fail
/// use marty_didcomm::types::DidDocument;
/// let mut document = DidDocument::new("did:example:1");
/// document.key_agreement.push(serde_json::json!({
///     "id":"#key-1", "type":"JsonWebKey2020", "controller":"did:example:1",
///     "publicKeyJwk":{"kty":"EC","d":"secret"}
/// }));
/// ```
pub struct NoLocalKeyOperations;

#[cfg(not(feature = "encrypted-envelope"))]
/// Marker for resolver/plaintext-message builds that omit software envelope
/// cryptography and its broader transitive signing backends.
///
/// ```compile_fail
/// use marty_didcomm::encrypt_for_recipient;
/// ```
pub struct NoEncryptedEnvelope;

pub mod did_identifier;
pub mod did_resolver;
#[cfg(feature = "encrypted-envelope")]
pub mod encrypted_envelope;
pub mod envelope;
pub mod error;
pub mod types;

pub use did_identifier::{derive_p256_did_identifier, derive_p256_did_jwk, derive_p256_did_key};
pub use did_resolver::{DidResolutionResult, DidResolver};
#[cfg(feature = "encrypted-envelope")]
pub use encrypted_envelope::encrypt_for_recipient;
#[cfg(feature = "local-key-operations")]
pub use encrypted_envelope::{
    decrypt_authenticated_jwe, decrypt_jwe, encrypt_for_recipient_authenticated,
    AuthenticatedDecryption,
};
pub use envelope::{pack_credential_for_holder, unpack_didcomm_message};
pub use error::{DidcommError, DidcommResult};
pub use types::{DidDocument, DidcommMessage, ServiceEndpoint, VerificationMethod};
