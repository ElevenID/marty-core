mod ffi;
#[cfg(feature = "prover")]
pub mod mdoc_support;

#[cfg(not(feature = "prover"))]
/// Marker for verifier-only artifacts, where proof and circuit generation are
/// not present in the Rust API or selected native source set.
///
/// ```compile_fail
/// let _ = marty_zkp::Circuit::generate(1);
/// ```
///
/// ```compile_fail
/// let _ = marty_zkp::Prover;
/// ```
pub struct VerifierOnly;

// Belt-and-suspenders: the build script already hard-errors, but this
// compile_error! catches any path where cfg(zk_mock) leaks into a release build.
#[cfg(all(zk_mock, not(debug_assertions)))]
compile_error!(
    "ZK mock (feature \"zk-mock\" / USE_ZK_MOCK=1) must not be compiled \
     in release mode. Remove --features marty-zkp/zk-mock and unset USE_ZK_MOCK."
);

use serde::{Deserialize, Serialize};
use std::ffi::CString;
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
    /// Prove that an issuer-signed `age_over_N` boolean is true without
    /// revealing other mDoc claims.
    AgeOver(u8),
    /// Prove that an integer claim lies within [min, max] (inclusive).
    ValueInRange { min: i64, max: i64 },
    /// Prove set-membership for an opaque value.
    Membership,
    /// Escape hatch for forward-compatible / custom predicates carried as a
    /// wire-format predicate identifier string.
    Custom(String),
    /// Sentinel for the Longfellow `pk_circuit` key-ownership proof.
    ///
    /// **NOT SUPPORTED WITH HSM/KMS KEY MANAGEMENT.**
    ///
    /// `pk_circuit` requires every bit of the raw private scalar `sk` for its
    /// double-and-add loop. No HSM exposes this. There is no compatible shim.
    /// This variant is recognised by [`ZkPredicate::from_id`] and causes
    /// `Prover::prove_key_ownership` in prover-enabled builds to return
    /// [`ZkError::HsmIncompatible`].
    KeyOwnership,
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
            // Explicitly catch known key-ownership identifiers and map them to
            // the unsupported sentinel. Callers that check the returned variant
            // before dispatching will see ZkPredicate::KeyOwnership and can
            // surface a clear error rather than falling into the Custom path.
            "key_ownership" | "prove_key" | "ecpk" | "pk_prove" => Self::KeyOwnership,
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
            Self::KeyOwnership => "key_ownership".to_string(),
        }
    }

    /// Human-readable description of what this predicate proves.
    pub fn description(&self) -> String {
        match self {
            Self::AgeOver(n) => format!("Proves the issuer-signed age_over_{} boolean is true", n),
            Self::ValueInRange { min, max } => {
                format!("Proves value is between {} and {}", min, max)
            }
            Self::Membership => "Proves value is a member of an authorized set".to_string(),
            Self::Custom(s) => format!("Custom predicate: {}", s),
            Self::KeyOwnership => {
                "NOT SUPPORTED: key-ownership proof requires raw scalar (HSM-incompatible)"
                    .to_string()
            }
        }
    }

    /// The name of the mDoc claim that this predicate operates on.
    /// Used to look up the claim value in the secrets map.
    pub fn required_claim(&self) -> String {
        match self {
            Self::AgeOver(_) => self.id(),
            Self::ValueInRange { .. } => "value".to_string(),
            Self::Membership => "value".to_string(),
            Self::Custom(_) => "value".to_string(),
            Self::KeyOwnership => "key_ownership".to_string(),
        }
    }

    /// Returns true if this predicate can be run with an HSM-backed device key.
    /// Use this before constructing a [`MdocProveInput`] to catch incompatible
    /// predicates early.
    pub fn is_hsm_compatible(&self) -> bool {
        !matches!(self, Self::KeyOwnership)
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
    /// Returned when a caller attempts to use a ZK circuit that requires direct
    /// access to the raw private key scalar, which is fundamentally incompatible
    /// with HSM/KMS key management.
    ///
    /// Specifically, the Longfellow `pk_circuit` / `PkWitness::compute_witness(Nat sk)`
    /// performs a bit-by-bit double-and-add scalar multiplication and needs every
    /// individual bit of `sk`. No standard HSM (PKCS#11, AWS KMS, Cloud KMS) can
    /// expose this — they treat the scalar as opaque.
    ///
    /// There is no shim that makes `pk_circuit` HSM-compatible without redesigning
    /// it as a sigma-protocol signature-verification proof (i.e. `VerifyWitness3`).
    /// Note: `pk_circuit` is NOT exported through the public Longfellow C API
    /// (`mdoc_zk.h`) and is therefore unreachable from this crate under normal
    /// operation. This error exists as an explicit, discoverable contract.
    #[error(
        "HSM-incompatible circuit: '{0}' requires raw private key scalar bits \
        (pk_circuit / PkWitness). No HSM/KMS can provide this. \
        Use VerifyWitness3-based proofs (run_mdoc_prover) instead."
    )]
    HsmIncompatible(String),
    #[error("Prover error code: {0}")]
    ProverError(u32),
    #[error("Verifier error code: {0}")]
    VerifierError(u32),
    #[error("Circuit generation error code: {0}")]
    CircuitError(u32),
    #[error("Unknown error code: {0}")]
    Unknown(u32),
}

#[cfg(feature = "prover")]
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

#[cfg(feature = "prover")]
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
        Self {
            namespace: namespace.into(),
            id: id.into(),
            cbor_value,
        }
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

const MAX_COMPRESSED_CIRCUIT_BYTES: usize = 4 * 1024 * 1024;
#[cfg(any(test, feature = "prover"))]
const MAX_MDOC_BYTES: usize = 4 * 1024 * 1024;
const MAX_TRANSCRIPT_BYTES: usize = 4096;
const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
const MAX_PUBLIC_KEY_TEXT_BYTES: usize = 140;
const MAX_DOC_TYPE_BYTES: usize = 256;

fn is_canonical_utc_time(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
    }
    let pair =
        |start: usize| u16::from(bytes[start] - b'0') * 10 + u16::from(bytes[start + 1] - b'0');
    (1..=12).contains(&pair(5))
        && (1..=31).contains(&pair(8))
        && pair(11) <= 23
        && pair(14) <= 59
        && pair(17) <= 59
}

fn validate_common_input(input: &MdocProveInput) -> Result<(), ZkError> {
    if input.transcript.is_empty()
        || input.transcript.len() > MAX_TRANSCRIPT_BYTES
        || input.issuer_pkx.is_empty()
        || input.issuer_pkx.len() > MAX_PUBLIC_KEY_TEXT_BYTES
        || input.issuer_pky.is_empty()
        || input.issuer_pky.len() > MAX_PUBLIC_KEY_TEXT_BYTES
        || !is_canonical_utc_time(&input.now)
        || input.doc_type.is_empty()
        || input.doc_type.len() > MAX_DOC_TYPE_BYTES
    {
        return Err(ZkError::InvalidInput);
    }
    Ok(())
}

#[cfg(feature = "prover")]
fn validate_prover_input(input: &MdocProveInput) -> Result<(), ZkError> {
    validate_common_input(input)?;
    if input.mdoc.is_empty() || input.mdoc.len() > MAX_MDOC_BYTES {
        return Err(ZkError::InvalidInput);
    }
    Ok(())
}

fn validate_verifier_input(input: &MdocProveInput, proof: &[u8]) -> Result<(), ZkError> {
    validate_common_input(input)?;
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES {
        return Err(ZkError::InvalidInput);
    }
    Ok(())
}

// Circuit decompression and parsing can approach the 130 MB native cap.
// Serialize native verification so attacker-controlled concurrency cannot
// multiply that allocation by the number of request threads.
static NATIVE_VERIFICATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── Circuit ───────────────────────────────────────────────────────────

/// Pre-generated compressed circuit for a given number of attributes.
///
/// In prover-enabled builds, generate once with `Circuit::generate` and pass
/// to every `Prover::prove` call. Verifier-only builds load an authenticated
/// circuit with [`Circuit::from_bytes`] and pass it to [`Verifier::verify`].
/// Circuits are large (~100 MB uncompressed), so callers should cache them.
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
    /// Load a pre-generated compressed circuit for verifier-only use.
    pub fn from_bytes(bytes: Vec<u8>, num_attributes: usize) -> Result<Self, ZkError> {
        if bytes.is_empty() || bytes.len() > MAX_COMPRESSED_CIRCUIT_BYTES {
            return Err(ZkError::InvalidInput);
        }
        let spec_index = unsafe {
            (0..ffi::NUM_ZK_SPECS)
                .filter(|&i| ffi::kZkSpecs[i].num_attributes == num_attributes)
                .max_by_key(|&i| ffi::kZkSpecs[i].version)
                .ok_or(ZkError::InvalidInput)?
        };
        #[cfg(not(zk_mock))]
        {
            let _native_guard = NATIVE_VERIFICATION_LOCK
                .lock()
                .map_err(|_| ZkError::Generic)?;
            validate_circuit_identity(&bytes, spec_index)?;
        }
        Ok(Self { bytes, spec_index })
    }

    /// Generate a compressed circuit for the ZK spec that supports exactly
    /// `num_attributes` attributes.
    ///
    /// `kZkSpecs` is searched for the highest-version matching entry.
    /// Returns an error if no such spec exists or if the generator fails.
    #[cfg(feature = "prover")]
    pub fn generate(num_attributes: usize) -> Result<Self, ZkError> {
        let spec_index = unsafe {
            (0..ffi::NUM_ZK_SPECS)
                .filter(|&i| ffi::kZkSpecs[i].num_attributes == num_attributes)
                .max_by_key(|&i| ffi::kZkSpecs[i].version)
                .ok_or(ZkError::InvalidInput)?
        };

        let mut cb: *mut u8 = std::ptr::null_mut();
        let mut clen: usize = 0;

        let rc = unsafe { ffi::generate_circuit(&ffi::kZkSpecs[spec_index], &mut cb, &mut clen) };
        if rc != ffi::CircuitGenerationErrorCode::Success {
            return Err(ZkError::from(rc));
        }
        if cb.is_null() {
            return Err(ZkError::CircuitError(0));
        }

        // Safety: bound-check clen before constructing a slice from an FFI pointer
        // to prevent out-of-bounds reads from a misbehaving C library.
        if clen > MAX_COMPRESSED_CIRCUIT_BYTES {
            unsafe { libc::free(cb as *mut libc::c_void) };
            return Err(ZkError::CircuitError(0));
        }

        let bytes = unsafe { std::slice::from_raw_parts(cb, clen).to_vec() };
        unsafe { libc::free(cb as *mut libc::c_void) };

        Ok(Self { bytes, spec_index })
    }

    fn spec(&self) -> *const ffi::ZkSpecStruct {
        assert!(
            self.spec_index < ffi::NUM_ZK_SPECS,
            "spec_index {} out of bounds (max {})",
            self.spec_index,
            ffi::NUM_ZK_SPECS
        );
        unsafe { &ffi::kZkSpecs[self.spec_index] }
    }
}

#[cfg(not(zk_mock))]
fn validate_circuit_identity(bytes: &[u8], spec_index: usize) -> Result<(), ZkError> {
    let spec = unsafe { &ffi::kZkSpecs[spec_index] };
    let mut digest = [0u8; 32];
    let valid = unsafe { ffi::circuit_id(digest.as_mut_ptr(), bytes.as_ptr(), bytes.len(), spec) };
    if valid != 1 {
        return Err(ZkError::InvalidInput);
    }

    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in digest.iter().copied().enumerate() {
        let high = HEX[(byte >> 4) as usize];
        let low = HEX[(byte & 0x0f) as usize];
        if spec.circuit_hash[index * 2] as u8 != high
            || spec.circuit_hash[index * 2 + 1] as u8 != low
        {
            return Err(ZkError::InvalidInput);
        }
    }
    if spec.circuit_hash[64] != 0 {
        return Err(ZkError::InvalidInput);
    }
    Ok(())
}

// ── Prover ────────────────────────────────────────────────────────────

#[cfg(feature = "prover")]
pub struct Prover;

#[cfg(feature = "prover")]
impl Prover {
    /// Generate a ZK proof that the mDoc attributes in `input` satisfy
    /// the requested values without revealing the underlying document.
    ///
    /// The returned bytes must be passed to [`Verifier::verify`] unchanged.
    pub fn prove(circuit: &Circuit, input: &MdocProveInput) -> Result<Vec<u8>, ZkError> {
        validate_prover_input(input)?;
        let expected_n = unsafe { (*circuit.spec()).num_attributes };
        if input.attributes.len() != expected_n {
            return Err(ZkError::InvalidInput);
        }
        let ffi_attrs = input
            .attributes
            .iter()
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

        if proof_len == 0 || proof_len > MAX_PROOF_BYTES {
            unsafe { libc::free(proof_ptr as *mut libc::c_void) };
            return Err(ZkError::InvalidInput);
        }
        let proof = unsafe { std::slice::from_raw_parts(proof_ptr, proof_len).to_vec() };
        unsafe { libc::free(proof_ptr as *mut libc::c_void) };
        Ok(proof)
    }

    /// Attempt to produce a key-ownership ZK proof (Longfellow `pk_circuit`).
    ///
    /// **Always returns [`ZkError::HsmIncompatible`].**
    ///
    /// `pk_circuit` (`PkWitness::compute_witness`) requires every individual bit
    /// of the raw private scalar `sk`. No HSM/KMS (PKCS#11, AWS KMS, Cloud KMS)
    /// can expose this — the scalar is treated as opaque. There is no shim that
    /// bridges this gap without materially weakening the HSM security boundary.
    ///
    /// The Longfellow C API (`mdoc_zk.h`) does not export a `run_pk_prover`
    /// function, so this circuit is already unreachable through our FFI layer.
    /// This stub exists as an explicit, compile-time-visible, runtime-enforced
    /// contract so developers discover the limitation immediately rather than
    /// hitting a link error or undefined behaviour.
    ///
    /// If key-ownership proof is ever required, it must be redesigned as a
    /// sigma-protocol over a device signature (i.e., using `VerifyWitness3` /
    /// `run_mdoc_prover` to verify a nonce-signed ECDSA signature), which IS
    /// HSM-compatible.
    pub fn prove_key_ownership(_circuit: &Circuit) -> Result<Vec<u8>, ZkError> {
        Err(ZkError::HsmIncompatible("pk_circuit".to_string()))
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
        validate_verifier_input(input, proof)?;

        let expected_n = unsafe { (*circuit.spec()).num_attributes };
        if input.attributes.len() != expected_n {
            return Err(ZkError::InvalidInput);
        }

        let ffi_attrs = input
            .attributes
            .iter()
            .map(|a| a.to_ffi())
            .collect::<Result<Vec<_>, _>>()?;

        let pkx = CString::new(input.issuer_pkx.as_str()).map_err(|_| ZkError::InvalidInput)?;
        let pky = CString::new(input.issuer_pky.as_str()).map_err(|_| ZkError::InvalidInput)?;
        let now = CString::new(input.now.as_str()).map_err(|_| ZkError::InvalidInput)?;
        let doc_type = CString::new(input.doc_type.as_str()).map_err(|_| ZkError::InvalidInput)?;

        let _native_guard = NATIVE_VERIFICATION_LOCK
            .lock()
            .map_err(|_| ZkError::Generic)?;

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

#[cfg(test)]
mod resource_boundary_tests {
    use super::*;

    fn input() -> MdocProveInput {
        MdocProveInput {
            mdoc: Vec::new(),
            issuer_pkx: "0x01".into(),
            issuer_pky: "0x02".into(),
            transcript: vec![0xf6],
            attributes: vec![AttributeRequest::new(
                "org.iso.18013.5.1",
                "age_over_18",
                vec![0xf5],
            )],
            now: "2026-09-05T00:00:00Z".into(),
            doc_type: "org.iso.18013.5.1.mDL".into(),
        }
    }

    #[test]
    fn verifier_bounds_only_inputs_consumed_by_the_native_verifier() {
        let mut value = input();
        assert!(validate_verifier_input(&value, &[1]).is_ok());

        value.mdoc = vec![0; MAX_MDOC_BYTES + 1];
        assert!(validate_verifier_input(&value, &[1]).is_ok());

        value.transcript = vec![0; MAX_TRANSCRIPT_BYTES + 1];
        assert!(matches!(
            validate_verifier_input(&value, &[1]),
            Err(ZkError::InvalidInput)
        ));

        let value = input();
        assert!(matches!(
            validate_verifier_input(&value, &vec![1; MAX_PROOF_BYTES + 1]),
            Err(ZkError::InvalidInput)
        ));
    }

    #[test]
    fn verifier_rejects_noncanonical_time_before_ffi() {
        for invalid in [
            "x",
            "2026-09-05T00:00:0Z",
            "2026-09-05T00:00:000Z",
            "2026-13-05T00:00:00Z",
            "2026-09-05T24:00:00Z",
            "2026-09-05 00:00:00Z",
        ] {
            let mut value = input();
            value.now = invalid.into();
            assert!(matches!(
                validate_verifier_input(&value, &[1]),
                Err(ZkError::InvalidInput)
            ));
        }
    }

    #[cfg(feature = "prover")]
    #[test]
    fn prover_bounds_mdoc_before_native_code() {
        let mut value = input();
        assert!(matches!(
            validate_prover_input(&value),
            Err(ZkError::InvalidInput)
        ));
        value.mdoc = vec![1];
        assert!(validate_prover_input(&value).is_ok());
        value.mdoc = vec![0; MAX_MDOC_BYTES + 1];
        assert!(matches!(
            validate_prover_input(&value),
            Err(ZkError::InvalidInput)
        ));
    }

    #[test]
    fn native_verification_concurrency_is_serialized() {
        use std::sync::mpsc;
        use std::time::Duration;

        let guard = NATIVE_VERIFICATION_LOCK.lock().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let _guard = NATIVE_VERIFICATION_LOCK.lock().unwrap();
            entered_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(entered_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(guard);
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }
}

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
        circuits: &[u8],
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
        let circuit = Circuit::from_bytes(circuits.to_vec(), 1)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let input = MdocProveInput {
            mdoc: mdoc.to_vec(),
            issuer_pkx: issuer_pkx.to_string(),
            issuer_pky: issuer_pky.to_string(),
            transcript: transcript.to_vec(),
            attributes: vec![AttributeRequest::new(
                namespace,
                attr_id,
                cbor_value.to_vec(),
            )],
            now: now.to_string(),
            doc_type: doc_type.to_string(),
        };

        Verifier::verify(&circuit, &input, proof)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
}
