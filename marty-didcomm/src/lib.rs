//! # marty-didcomm
//!
//! DIDComm v2 messaging support for the Marty digital identity platform.
//!
//! This crate provides DID resolution (did:key, did:web, did:peer, did:jwk)
//! and DIDComm v2 envelope packing/unpacking for credential delivery.
//!
//! ## Supported DID Methods
//!
//! - **`did:key`** — Local derivation from public key (Ed25519, X25519, P-256)
//! - **`did:web`** — HTTP-based resolution (`did:web:example.com` → `https://example.com/.well-known/did.json`)
//! - **`did:peer`** — Peer-local resolution (method 0 and 2)
//! - **`did:jwk`** — JWK-encoded public key
//!
//! ## Non-Goals
//!
//! Ledger-based DID methods (did:ion, did:ethr, did:sov, etc.) are explicitly
//! out of scope. For those methods, use the DIF Universal Resolver as an HTTP
//! proxy and configure it as a `did:web`-style endpoint.

pub mod did_resolver;
pub mod encrypted_envelope;
pub mod envelope;
pub mod error;
pub mod types;

pub use did_resolver::DidResolver;
pub use encrypted_envelope::{decrypt_jwe, encrypt_for_recipient};
pub use envelope::{pack_credential_for_holder, unpack_didcomm_message};
pub use error::{DidcommError, DidcommResult};
pub use types::{DidDocument, DidcommMessage, ServiceEndpoint, VerificationMethod};
