//! # marty-didcomm
//!
//! DIDComm Messaging 2.1 support for the Marty digital identity platform.
//!
//! This crate provides DID resolution (did:key, did:web, did:peer, did:jwk)
//! and a deliberately narrow credential-delivery profile: X25519 key
//! agreement, `ECDH-ES+A256KW` anonymous encryption, and the required
//! `A256CBC-HS512` content encryption algorithm. The encrypted-envelope
//! implementation is checked against unmodified Appendix C data.
//!
//! This is not a claim that Marty is a complete general-purpose DIDComm agent.
//! The public Marty API does not yet expose authcrypt, signed envelopes,
//! mediator routing/forwarding, every required key-agreement curve, or every
//! protocol state machine. Those capabilities need product-boundary and
//! interoperability tests before they can be advertised as supported.
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

pub mod did_resolver;
pub mod encrypted_envelope;
pub mod envelope;
pub mod error;
pub mod types;

pub use did_resolver::{DidResolutionResult, DidResolver};
pub use encrypted_envelope::{decrypt_jwe, encrypt_for_recipient};
pub use envelope::{pack_credential_for_holder, unpack_didcomm_message};
pub use error::{DidcommError, DidcommResult};
pub use types::{DidDocument, DidcommMessage, ServiceEndpoint, VerificationMethod};
