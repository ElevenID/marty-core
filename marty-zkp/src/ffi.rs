//! FFI bindings to the Longfellow mdoc ZK C API (mdoc_zk.h).
//!
//! When compiled with USE_ZK_MOCK=1 these symbols are provided by
//! zk_mock.cpp which mirrors the same ABI with trivial stub behaviour.

use libc::{c_char, c_uchar, size_t};

// ── RequestedAttribute ────────────────────────────────────────────────

/// A single attribute that the prover must disclose (namespace + id + value).
#[repr(C)]
pub struct RequestedAttribute {
    pub namespace_id: [u8; 64],
    pub id: [u8; 32],
    pub cbor_value: [u8; 64],
    pub namespace_len: size_t,
    pub id_len: size_t,
    pub cbor_value_len: size_t,
}

// ── Error codes ───────────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MdocProverErrorCode {
    Success = 0,
    NullInput = 1,
    InvalidInput = 2,
    CircuitParsingFailure = 3,
    HashParsingFailure = 4,
    WitnessCreationFailure = 5,
    GeneralFailure = 6,
    MemoryAllocationFailure = 7,
    InvalidZkSpecVersion = 8,
    RootDecodingFailure = 9,
    DocumentsMissing = 10,
    Document0Missing = 11,
    DoctypeMissing = 12,
    IssuerSignedMissing = 13,
    IssuerAuthMissing = 14,
    MsoMissing = 15,
    NsigMissing = 16,
    NamespacesMissing = 17,
    DeviceSignedMissing = 18,
    DeviceAuthMissing = 19,
    DeviceSignatureMissing = 20,
    DeviceKeyMissing = 21,
    MsoDecodingFailure = 22,
    ValidityInfoMissing = 23,
    DeviceKeyInfoMissing = 24,
    AttributeDecodeFailure = 25,
    AttributeEiMissing = 26,
    AttributeEvMissing = 27,
    AttributeDidMissing = 28,
    SignatureFailure = 29,
    DeviceSignatureFailure = 30,
    AttributeNotFound = 31,
    AttributeTooLong = 32,
    TaggedMsoTooBig = 33,
    VersionNotSupported = 34,
    AttributeRandomMissing = 35,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MdocVerifierErrorCode {
    Success = 0,
    CircuitParsingFailure = 1,
    ProofTooSmall = 2,
    HashParsingFailure = 3,
    SignatureParsingFailure = 4,
    GeneralFailure = 5,
    NullInput = 6,
    InvalidInput = 7,
    ArgumentsTooSmall = 8,
    AttributeNumberMismatch = 9,
    InvalidZkSpecVersion = 10,
    InvalidCbor = 11,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CircuitGenerationErrorCode {
    Success = 0,
    NullInput = 1,
    ZlibFailure = 2,
    GeneralFailure = 3,
    InvalidZkSpecVersion = 4,
}

// ── ZkSpecStruct ──────────────────────────────────────────────────────

/// Versioned ZK specification (circuit identity, attribute count, params).
#[repr(C)]
pub struct ZkSpecStruct {
    /// Null-terminated ZK system name, e.g. `"longfellow-libzk-v3"`.
    pub system: *const c_char,
    /// 64-char lowercase hex circuit hash + NUL terminator.
    pub circuit_hash: [c_char; 65],
    pub num_attributes: size_t,
    pub version: size_t,
    pub block_enc_hash: size_t,
    pub block_enc_sig: size_t,
}

// SAFETY: ZkSpecStruct contains raw pointers to static C string data that
// live for the duration of the program.  These are conceptually 'static.
unsafe impl Sync for ZkSpecStruct {}
unsafe impl Send for ZkSpecStruct {}

pub const NUM_ZK_SPECS: usize = 12;

// ── Extern functions ──────────────────────────────────────────────────

extern "C" {
    /// Generate a compressed circuit for the given ZK spec.
    /// Caller must free `*cb` via `libc::free`.
    pub fn generate_circuit(
        zk_spec: *const ZkSpecStruct,
        cb: *mut *mut c_uchar,
        clen: *mut size_t,
    ) -> CircuitGenerationErrorCode;

    /// Prove a set of mDoc attributes in zero-knowledge.
    /// Caller must free `*prf` via `libc::free`.
    pub fn run_mdoc_prover(
        bcp: *const c_uchar,
        bcsz: size_t,
        mdoc: *const c_uchar,
        mdoc_len: size_t,
        pkx: *const c_char,
        pky: *const c_char,
        transcript: *const c_uchar,
        tr_len: size_t,
        attrs: *const RequestedAttribute,
        attrs_len: size_t,
        now: *const c_char,
        prf: *mut *mut c_uchar,
        proof_len: *mut size_t,
        zk_spec: *const ZkSpecStruct,
    ) -> MdocProverErrorCode;

    /// Verify a previously generated mDoc ZK proof.
    pub fn run_mdoc_verifier(
        bcp: *const c_uchar,
        bcsz: size_t,
        pkx: *const c_char,
        pky: *const c_char,
        transcript: *const c_uchar,
        tr_len: size_t,
        attrs: *const RequestedAttribute,
        attrs_len: size_t,
        now: *const c_char,
        zkproof: *const c_uchar,
        proof_len: size_t,
        doc_type: *const c_char,
        zk_spec: *const ZkSpecStruct,
    ) -> MdocVerifierErrorCode;

    /// Global array of all supported ZK specifications.
    pub static kZkSpecs: [ZkSpecStruct; NUM_ZK_SPECS];

    /// Find a spec by system name and circuit hash; returns null if not found.
    #[allow(dead_code)]
    pub fn find_zk_spec(
        system_name: *const c_char,
        circuit_hash: *const c_char,
    ) -> *const ZkSpecStruct;
}
