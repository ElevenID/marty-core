mod ffi;
pub mod mdoc_support;

use std::ffi::CString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Predicate ────────────────────────────────────────────────────────

/// A zero-knowledge predicate that can be proved over an mDoc claim.
///
/// Using an enum rather than raw strings ensures that predicates are
/// well-formed at compile time and that new circuits are registered
/// centrally rather than scattered across call sites.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ZkPredicate {
    /// Prove that the holder's age is ≥ `threshold` without revealing birth date.
    AgeOver(u8),
    /// Prove that an integer claim lies within [min, max] (inclusive).
    ValueInRange { min: i64, max: i64 },
    /// Prove set-membership for an opaque value.
    Membership,
    /// Escape hatch for forward-compatible / custom predicates carried as a
    /// wire-format predicate identifier string.
    Custom(String),
}

impl ZkPredicate {
    /// Parse a wire-format predicate identifier (e.g. from a
    /// `ZkPredicateRequest.predicate` field) into a `ZkPredicate`.
    ///
    /// Handles `"age_over_N"` for any valid u8 age threshold, plus
    /// passthrough to `Custom` for unrecognized identifiers.
    pub fn from_id(id: &str) -> Self {
        if let Some(rest) = id.strip_prefix("age_over_") {
            if let Ok(n) = rest.parse::<u8>() {
                return Self::AgeOver(n);
            }
        }
        match id {
            "membership" => Self::Membership,
            other => Self::Custom(other.to_string()),
        }
    }

    /// Return the canonical wire-format identifier for this predicate.
    pub fn id(&self) -> String {
        match self {
            Self::AgeOver(n) => format!("age_over_{}", n),
            Self::ValueInRange { min, max } => format!("value_in_range_{}_{}", min, max),
            Self::Membership => "membership".to_string(),
            Self::Custom(s) => s.clone(),
        }
    }

    /// Human-readable description of what this predicate proves.
    pub fn description(&self) -> String {
        match self {
            Self::AgeOver(n) => format!("Proves age is at least {} without revealing exact birth date", n),
            Self::ValueInRange { min, max } => format!("Proves value is between {} and {}", min, max),
            Self::Membership => "Proves value is a member of an authorized set".to_string(),
            Self::Custom(s) => format!("Custom predicate: {}", s),
        }
    }

    /// The name of the mDoc claim that this predicate operates on.
    /// Used to look up the claim value in the secrets map.
    pub fn required_claim(&self) -> &'static str {
        match self {
            Self::AgeOver(_) => "birth_date",
            Self::ValueInRange { .. } => "value",
            Self::Membership => "value",
            Self::Custom(_) => "value",
        }
    }
}

impl std::fmt::Display for ZkPredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}

// ── Error ─────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum ZkError {
    #[error("Generic ZK error")]
    Generic,
    #[error("Invalid input data")]
    InvalidInput,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Unsupported predicate: {0}")]
    UnsupportedPredicate(String),
    #[error("Prover error code: {0}")]
    ProverError(u32),
    #[error("Verifier error code: {0}")]
    VerifierError(u32),
    #[error("Circuit generation error code: {0}")]
    CircuitError(u32),
    #[error("Unknown error code: {0}")]
    Unknown(u32),
}

impl From<ffi::MdocProverErrorCode> for ZkError {
    fn from(code: ffi::MdocProverErrorCode) -> Self {
        ZkError::ProverError(code as u32)
    }
}

impl From<ffi::MdocVerifierErrorCode> for ZkError {
    fn from(code: ffi::MdocVerifierErrorCode) -> Self {
        ZkError::VerifierError(code as u32)
    }
}

impl From<ffi::CircuitGenerationErrorCode> for ZkError {
    fn from(code: ffi::CircuitGenerationErrorCode) -> Self {
        ZkError::CircuitError(code as u32)
    }
}

// ── ZkTranscript ──────────────────────────────────────────────────────

/// Session transcript bytes (binds the ZK proof to a specific presentation session).
///
/// In the ISO 18013-5 / OID4VP flow the transcript is the serialised
/// `SessionTranscript` CBOR structure that was included in the device
/// authentication.  The Longfellow prover uses it as a Fiat-Shamir
/// context input so every proof is cryptographically bound to exactly
/// one session and cannot be replayed in a different session.
#[derive(Clone)]
pub struct ZkTranscript(Vec<u8>);

impl ZkTranscript {
    pub fn new(transcript_bytes: &[u8]) -> Self {
        Self(transcript_bytes.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ── AttributeRequest ─────────────────────────────────────────────────

/// A single mDoc attribute to prove (namespace, element identifier, CBOR value).
#[derive(Clone)]
pub struct AttributeRequest {
    /// mDoc namespace, e.g. `"org.iso.18013.5.1"`.
    pub namespace: String,
    /// Element identifier, e.g. `"age_over_18"`.
    pub id: String,
    /// Raw CBOR bytes of the expected element value, e.g. `\xf5` for CBOR true.
    pub cbor_value: Vec<u8>,
}

impl AttributeRequest {
    pub fn new(namespace: impl Into<String>, id: impl Into<String>, cbor_value: Vec<u8>) -> Self {
        Self { namespace: namespace.into(), id: id.into(), cbor_value }
    }

    /// Convert to the C-ABI `RequestedAttribute` struct.
    fn to_ffi(&self) -> Result<ffi::RequestedAttribute, ZkError> {
        let ns = self.namespace.as_bytes();
        let id = self.id.as_bytes();
        let cv = &self.cbor_value;

        if ns.len() > 64 || id.len() > 32 || cv.len() > 64 {
            return Err(ZkError::InvalidInput);
        }

        let mut attr = ffi::RequestedAttribute {
            namespace_id: [0u8; 64],
            id: [0u8; 32],
            cbor_value: [0u8; 64],
            namespace_len: ns.len(),
            id_len: id.len(),
            cbor_value_len: cv.len(),
        };
        attr.namespace_id[..ns.len()].copy_from_slice(ns);
        attr.id[..id.len()].copy_from_slice(id);
        attr.cbor_value[..cv.len()].copy_from_slice(cv);
        Ok(attr)
    }
}

// ── MdocProveInput ────────────────────────────────────────────────────

/// All public inputs required to run the mDoc ZK prover or verifier.
#[derive(Clone)]
pub struct MdocProveInput {
    /// Full CBOR-encoded ISO 18013-5 mDoc (the `DeviceResponse` document bytes).
    pub mdoc: Vec<u8>,
    /// Issuer public key X coordinate as a `"0x..."` hex string.
    pub issuer_pkx: String,
    /// Issuer public key Y coordinate as a `"0x..."` hex string.
    pub issuer_pky: String,
    /// Session transcript (binds proof to this presentation session).
    pub transcript: Vec<u8>,
    /// Attributes to disclose in zero-knowledge.
    pub attributes: Vec<AttributeRequest>,
    /// Current time in ISO 8601 format, e.g. `"2026-01-30T09:00:00Z"`.
    pub now: String,
    /// mDoc docType, e.g. `"org.iso.18013.5.1.mDL"`.
    pub doc_type: String,
}

// ── Circuit ───────────────────────────────────────────────────────────

/// Pre-generated compressed circuit for a given number of attributes.
///
/// Generate once with [`Circuit::generate`] and pass to every
/// [`Prover::prove`] / [`Verifier::verify`] call.  Circuits are
/// large (~100 MB uncompressed) and expensive to generate, so callers
/// should cache them.
pub struct Circuit {
    bytes: Vec<u8>,
    spec_index: usize,
}

impl std::fmt::Debug for Circuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Circuit")
            .field("bytes_len", &self.bytes.len())
            .field("spec_index", &self.spec_index)
            .finish()
    }
}

impl Circuit {
    /// Generate a compressed circuit for the ZK spec that supports exactly
    /// `num_attributes` attributes.
    ///
    /// `kZkSpecs` is searched for the highest-version matching entry.
    /// Returns an error if no such spec exists or if the generator fails.
    pub fn generate(num_attributes: usize) -> Result<Self, ZkError> {
        let spec_index = unsafe {
            (0..ffi::NUM_ZK_SPECS)
                .filter(|&i| ffi::kZkSpecs[i].num_attributes == num_attributes)
                .max_by_key(|&i| ffi::kZkSpecs[i].version)
                .ok_or(ZkError::InvalidInput)?
        };

        let mut cb: *mut u8 = std::ptr::null_mut();
        let mut clen: usize = 0;

        let rc = unsafe {
            ffi::generate_circuit(&ffi::kZkSpecs[spec_index], &mut cb, &mut clen)
        };
        if rc != ffi::CircuitGenerationErrorCode::Success {
            return Err(ZkError::from(rc));
        }
        if cb.is_null() {
            return Err(ZkError::CircuitError(0));
        }

        let bytes = unsafe { std::slice::from_raw_parts(cb, clen).to_vec() };
        unsafe { libc::free(cb as *mut libc::c_void) };

        Ok(Self { bytes, spec_index })
    }

    fn spec(&self) -> *const ffi::ZkSpecStruct {
        unsafe { &ffi::kZkSpecs[self.spec_index] }
    }
}

// ── Prover ────────────────────────────────────────────────────────────

pub struct Prover;

impl Prover {
    /// Generate a ZK proof that the mDoc attributes in `input` satisfy
    /// the requested values without revealing the underlying document.
    ///
    /// The returned bytes must be passed to [`Verifier::verify`] unchanged.
    pub fn prove(circuit: &Circuit, input: &MdocProveInput) -> Result<Vec<u8>, ZkError> {
        let ffi_attrs = input.attributes.iter()
            .map(|a| a.to_ffi())
            .collect::<Result<Vec<_>, _>>()?;

        let pkx = CString::new(input.issuer_pkx.as_str()).map_err(|_| ZkError::InvalidInput)?;
        let pky = CString::new(input.issuer_pky.as_str()).map_err(|_| ZkError::InvalidInput)?;
        let now = CString::new(input.now.as_str()).map_err(|_| ZkError::InvalidInput)?;

        let mut proof_ptr: *mut u8 = std::ptr::null_mut();
        let mut proof_len: usize = 0;

        let rc = unsafe {
            ffi::run_mdoc_prover(
                circuit.bytes.as_ptr(),
                circuit.bytes.len(),
                input.mdoc.as_ptr(),
                input.mdoc.len(),
                pkx.as_ptr(),
                pky.as_ptr(),
                input.transcript.as_ptr(),
                input.transcript.len(),
                ffi_attrs.as_ptr(),
                ffi_attrs.len(),
                now.as_ptr(),
                &mut proof_ptr,
                &mut proof_len,
                circuit.spec(),
            )
        };

        if rc != ffi::MdocProverErrorCode::Success {
            return Err(ZkError::from(rc));
        }
        if proof_ptr.is_null() {
            return Err(ZkError::Generic);
        }

        let proof = unsafe { std::slice::from_raw_parts(proof_ptr, proof_len).to_vec() };
        unsafe { libc::free(proof_ptr as *mut libc::c_void) };
        Ok(proof)
    }
}

// ── Verifier ──────────────────────────────────────────────────────────

pub struct Verifier;

impl Verifier {
    /// Verify a ZK proof, returning `Ok(true)` on success, `Ok(false)` if the
    /// proof does not verify, or `Err` for structural / input failures.
    pub fn verify(
        circuit: &Circuit,
        input: &MdocProveInput,
        proof: &[u8],
    ) -> Result<bool, ZkError> {
        if proof.is_empty() {
            return Ok(false);
        }

        let ffi_attrs = input.attributes.iter()
            .map(|a| a.to_ffi())
            .collect::<Result<Vec<_>, _>>()?;

        let pkx = CString::new(input.issuer_pkx.as_str()).map_err(|_| ZkError::InvalidInput)?;
        let pky = CString::new(input.issuer_pky.as_str()).map_err(|_| ZkError::InvalidInput)?;
        let now = CString::new(input.now.as_str()).map_err(|_| ZkError::InvalidInput)?;
        let doc_type = CString::new(input.doc_type.as_str()).map_err(|_| ZkError::InvalidInput)?;

        let rc = unsafe {
            ffi::run_mdoc_verifier(
                circuit.bytes.as_ptr(),
                circuit.bytes.len(),
                pkx.as_ptr(),
                pky.as_ptr(),
                input.transcript.as_ptr(),
                input.transcript.len(),
                ffi_attrs.as_ptr(),
                ffi_attrs.len(),
                now.as_ptr(),
                proof.as_ptr(),
                proof.len(),
                doc_type.as_ptr(),
                circuit.spec(),
            )
        };

        match rc {
            ffi::MdocVerifierErrorCode::Success => Ok(true),
            ffi::MdocVerifierErrorCode::GeneralFailure
            | ffi::MdocVerifierErrorCode::CircuitParsingFailure
            | ffi::MdocVerifierErrorCode::ProofTooSmall
            | ffi::MdocVerifierErrorCode::HashParsingFailure
            | ffi::MdocVerifierErrorCode::SignatureParsingFailure
            | ffi::MdocVerifierErrorCode::InvalidCbor
            | ffi::MdocVerifierErrorCode::AttributeNumberMismatch => Ok(false),
            _ => Err(ZkError::from(rc)),
        }
    }
}

// ── Python bindings ───────────────────────────────────────────────────

#[cfg(feature = "python")]
pub mod python {
    use super::*;
    use pyo3::prelude::*;

    /// Verify a ZK proof for an mDoc presentation.
    ///
    /// * `mdoc`       — full CBOR mDoc bytes
    /// * `issuer_pkx` — issuer public key X as `"0x..."` hex string
    /// * `issuer_pky` — issuer public key Y as `"0x..."` hex string
    /// * `transcript` — session transcript bytes
    /// * `namespace`  — attribute namespace, e.g. `"org.iso.18013.5.1"`
    /// * `attr_id`    — attribute element identifier, e.g. `"age_over_18"`
    /// * `cbor_value` — expected raw CBOR bytes, e.g. `b"\xf5"` for true
    /// * `now`        — current time, e.g. `"2026-01-30T09:00:00Z"`
    /// * `doc_type`   — mDoc docType, e.g. `"org.iso.18013.5.1.mDL"`
    /// * `proof`      — ZK proof bytes to verify
    #[allow(clippy::too_many_arguments)]
    #[pyfunction]
    pub fn verify_mdoc_zk(
        mdoc: &[u8],
        issuer_pkx: &str,
        issuer_pky: &str,
        transcript: &[u8],
        namespace: &str,
        attr_id: &str,
        cbor_value: &[u8],
        now: &str,
        doc_type: &str,
        proof: &[u8],
    ) -> PyResult<bool> {
        let circuit = Circuit::generate(1)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let input = MdocProveInput {
            mdoc: mdoc.to_vec(),
            issuer_pkx: issuer_pkx.to_string(),
            issuer_pky: issuer_pky.to_string(),
            transcript: transcript.to_vec(),
            attributes: vec![AttributeRequest::new(namespace, attr_id, cbor_value.to_vec())],
            now: now.to_string(),
            doc_type: doc_type.to_string(),
        };

        Verifier::verify(&circuit, &input, proof)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
}
