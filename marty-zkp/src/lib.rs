mod ffi;
pub mod mdoc_support;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

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
    #[error("Unknown error code: {0}")]
    Unknown(u32),
}

impl From<ffi::ZkStatus> for Result<(), ZkError> {
    fn from(status: ffi::ZkStatus) -> Self {
        match status {
            ffi::ZkStatus::Success => Ok(()),
            ffi::ZkStatus::ErrorGeneric => Err(ZkError::Generic),
            ffi::ZkStatus::ErrorInvalidInput => Err(ZkError::InvalidInput),
            ffi::ZkStatus::ErrorVerificationFailed => Err(ZkError::VerificationFailed),
        }
    }
}

// ── Transcript ────────────────────────────────────────────────────────

pub struct ZkTranscript {
    inner: *mut libc::c_void,
}

// SAFETY: ZkTranscript wraps an opaque C pointer. The underlying Longfellow
// library is documented as thread-safe for distinct transcript instances.
unsafe impl Send for ZkTranscript {}

impl Drop for ZkTranscript {
    fn drop(&mut self) {
        unsafe {
            ffi::zk_free_transcript(self.inner);
        }
    }
}

impl ZkTranscript {
    pub fn new(nonce: &[u8]) -> Self {
        let inner = unsafe { ffi::zk_create_transcript(nonce.as_ptr(), nonce.len()) };
        Self { inner }
    }
}

// ── Prover ────────────────────────────────────────────────────────────

pub struct Prover;

impl Prover {
    /// Generate a ZK proof for the given predicate.
    ///
    /// * `predicate`   — which statement to prove
    /// * `transcript`  — challenge transcript (contains session nonce)
    /// * `mso_bytes`   — raw MSO (Mobile Security Object) bytes from the mDoc
    /// * `signature`   — COSE signature over the MSO
    /// * `claim_value` — the plaintext claim value (e.g. "1990-01-15" for birth_date)
    ///                   This value is *only* used locally; it is never transmitted.
    pub fn prove(
        predicate: &ZkPredicate,
        transcript: &ZkTranscript,
        mso_bytes: &[u8],
        signature: &[u8],
        claim_value: &str,
    ) -> Result<Vec<u8>, ZkError> {
        let predicate_id = std::ffi::CString::new(predicate.id())
            .map_err(|_| ZkError::InvalidInput)?;
        let claim_value_c = std::ffi::CString::new(claim_value)
            .map_err(|_| ZkError::InvalidInput)?;

        let mut proof_ptr: *mut u8 = std::ptr::null_mut();
        let mut proof_len: usize = 0;

        let status = unsafe {
            ffi::zk_prove_predicate(
                transcript.inner,
                predicate_id.as_ptr(),
                mso_bytes.as_ptr(),
                mso_bytes.len(),
                signature.as_ptr(),
                signature.len(),
                claim_value_c.as_ptr(),
                &mut proof_ptr,
                &mut proof_len,
            )
        };

        Result::from(status)?;

        if proof_ptr.is_null() {
            return Err(ZkError::Generic);
        }

        let proof = unsafe { std::slice::from_raw_parts(proof_ptr, proof_len).to_vec() };
        unsafe { ffi::zk_free_buffer(proof_ptr) };

        Ok(proof)
    }

    /// Convenience: parse a predicate ID string and prove in one call.
    pub fn prove_by_id(
        predicate_id: &str,
        transcript: &ZkTranscript,
        mso_bytes: &[u8],
        signature: &[u8],
        claim_value: &str,
    ) -> Result<Vec<u8>, ZkError> {
        let predicate = ZkPredicate::from_id(predicate_id);
        Self::prove(&predicate, transcript, mso_bytes, signature, claim_value)
    }

    /// Deprecated — use [`Prover::prove`] with [`ZkPredicate::AgeOver(18)`].
    #[deprecated(since = "0.2.0", note = "use Prover::prove(&ZkPredicate::AgeOver(18), ...)")]
    #[allow(dead_code)]
    pub fn prove_age_over_18(
        transcript: &ZkTranscript,
        mso_bytes: &[u8],
        signature: &[u8],
        birth_date: &str,
    ) -> Result<Vec<u8>, ZkError> {
        Self::prove(&ZkPredicate::AgeOver(18), transcript, mso_bytes, signature, birth_date)
    }
}

// ── Verifier ──────────────────────────────────────────────────────────

pub struct Verifier;

impl Verifier {
    /// Verify a ZK proof for the given predicate.
    ///
    /// Returns `Ok(true)` if the proof is valid, `Ok(false)` if it is
    /// structurally valid but the predicate does not hold, and `Err` for
    /// any other failure (invalid bytes, corrupt proof, etc.).
    pub fn verify(
        predicate: &ZkPredicate,
        transcript: &ZkTranscript,
        mso_bytes: &[u8],
        proof: &[u8],
    ) -> Result<bool, ZkError> {
        let predicate_id = std::ffi::CString::new(predicate.id())
            .map_err(|_| ZkError::InvalidInput)?;

        let status = unsafe {
            ffi::zk_verify_predicate(
                transcript.inner,
                predicate_id.as_ptr(),
                mso_bytes.as_ptr(),
                mso_bytes.len(),
                proof.as_ptr(),
                proof.len(),
            )
        };

        match status {
            ffi::ZkStatus::Success => Ok(true),
            ffi::ZkStatus::ErrorVerificationFailed => Ok(false),
            _ => {
                Result::from(status)?;
                Ok(false) // unreachable
            }
        }
    }

    /// Convenience: parse a predicate ID string and verify in one call.
    pub fn verify_by_id(
        predicate_id: &str,
        transcript: &ZkTranscript,
        mso_bytes: &[u8],
        proof: &[u8],
    ) -> Result<bool, ZkError> {
        let predicate = ZkPredicate::from_id(predicate_id);
        Self::verify(&predicate, transcript, mso_bytes, proof)
    }

    /// Deprecated — use [`Verifier::verify`] with [`ZkPredicate::AgeOver(18)`].
    #[deprecated(since = "0.2.0", note = "use Verifier::verify(&ZkPredicate::AgeOver(18), ...)")]
    #[allow(dead_code)]
    pub fn verify_age_over_18(
        transcript: &ZkTranscript,
        mso_bytes: &[u8],
        proof: &[u8],
    ) -> Result<bool, ZkError> {
        Self::verify(&ZkPredicate::AgeOver(18), transcript, mso_bytes, proof)
    }
}

// ── Python bindings ───────────────────────────────────────────────────

#[cfg(feature = "python")]
pub mod python {
    use super::*;
    use pyo3::prelude::*;
    use std::sync::Arc;
    use std::sync::Mutex;

    // Safe wrapper for ZkTranscript that is Send + Sync
    struct SafeZkTranscript {
        inner: *mut libc::c_void,
    }

    unsafe impl Send for SafeZkTranscript {}
    unsafe impl Sync for SafeZkTranscript {}

    impl Drop for SafeZkTranscript {
        fn drop(&mut self) {
            if !self.inner.is_null() {
                unsafe {
                    ffi::zk_free_transcript(self.inner);
                }
            }
        }
    }

    #[pyclass]
    pub struct PyZkTranscript {
        transcript: Arc<Mutex<SafeZkTranscript>>,
    }

    #[pymethods]
    impl PyZkTranscript {
        #[new]
        fn new(nonce: &[u8]) -> Self {
            let inner = unsafe { ffi::zk_create_transcript(nonce.as_ptr(), nonce.len()) };
            let transcript = Arc::new(Mutex::new(SafeZkTranscript { inner }));
            Self { transcript }
        }
    }

    /// Verify a ZK proof for a named predicate.
    ///
    /// `predicate_id` follows the wire format (e.g. `"age_over_18"`, `"age_over_21"`).
    #[pyfunction]
    pub fn verify_zk_predicate(
        predicate_id: &str,
        nonce: &[u8],
        mso: &[u8],
        proof: &[u8],
    ) -> PyResult<bool> {
        let transcript = ZkTranscript::new(nonce);
        Verifier::verify_by_id(predicate_id, &transcript, mso, proof)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Deprecated — use [`verify_zk_predicate`] with `predicate_id = "age_over_18"`.
    #[pyfunction]
    #[deprecated(since = "0.2.0", note = "use verify_zk_predicate")]
    pub fn verify_age_zkp(nonce: &[u8], mso: &[u8], proof: &[u8]) -> PyResult<bool> {
        verify_zk_predicate("age_over_18", nonce, mso, proof)
    }
}
