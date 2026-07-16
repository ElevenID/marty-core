use crate::{AttributeRequest, MdocProveInput};

/// Convenience wrapper that collects all inputs required to generate or verify
/// a ZK proof for a single mDoc presentation.
///
/// Mirrors [`MdocProveInput`] but provides named constructors that align with
/// the ISO 18013-5 / OID4VP parsing flow.
pub struct MdocZkInput {
    /// Full CBOR-encoded ISO 18013-5 mDoc bytes (the `DeviceResponse` document).
    pub mdoc: Vec<u8>,
    /// Issuer public key X coordinate as `"0x..."` hex string.
    pub issuer_pkx: String,
    /// Issuer public key Y coordinate as `"0x..."` hex string.
    pub issuer_pky: String,
    /// Session transcript bytes.
    pub transcript: Vec<u8>,
    /// Attributes to prove in zero-knowledge.
    pub attributes: Vec<AttributeRequest>,
    /// Current time in ISO 8601 format, e.g. `"2026-01-30T09:00:00Z"`.
    pub now: String,
    /// mDoc docType, e.g. `"org.iso.18013.5.1.mDL"`.
    pub doc_type: String,
}

impl MdocZkInput {
    pub fn new(
        mdoc: Vec<u8>,
        issuer_pkx: impl Into<String>,
        issuer_pky: impl Into<String>,
        transcript: Vec<u8>,
        attributes: Vec<AttributeRequest>,
        now: impl Into<String>,
        doc_type: impl Into<String>,
    ) -> Self {
        Self {
            mdoc,
            issuer_pkx: issuer_pkx.into(),
            issuer_pky: issuer_pky.into(),
            transcript,
            attributes,
            now: now.into(),
            doc_type: doc_type.into(),
        }
    }

    /// Convert into a [`MdocProveInput`] for use with [`crate::Prover`] and
    /// [`crate::Verifier`].
    pub fn into_prove_input(self) -> MdocProveInput {
        MdocProveInput {
            mdoc: self.mdoc,
            issuer_pkx: self.issuer_pkx,
            issuer_pky: self.issuer_pky,
            transcript: self.transcript,
            attributes: self.attributes,
            now: self.now,
            doc_type: self.doc_type,
        }
    }
}
