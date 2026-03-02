use libc::{c_char, c_uchar, c_void, size_t};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum ZkStatus {
    Success = 0,
    ErrorGeneric = 1,
    ErrorInvalidInput = 2,
    ErrorVerificationFailed = 3,
}

extern "C" {
    // ── Session / Transcript ─────────────────────────────────────────

    pub fn zk_create_transcript(nonce: *const c_uchar, nonce_len: size_t) -> *mut c_void;
    pub fn zk_free_transcript(transcript: *mut c_void);

    // ── Generic predicate API (preferred) ────────────────────────────

    /// Generate a ZK proof for any registered predicate.
    ///
    /// `predicate_id` — wire-format predicate string (e.g. `"age_over_18"`, `"age_over_21"`)
    /// `claim_value`  — plaintext claim value (e.g. `"1990-06-15"` for birth_date)
    pub fn zk_prove_predicate(
        transcript: *mut c_void,
        predicate_id: *const c_char,
        mso_bytes: *const c_uchar,
        mso_len: size_t,
        signature: *const c_uchar,
        sig_len: size_t,
        claim_value: *const c_char,
        proof_out: *mut *mut c_uchar,
        proof_len_out: *mut size_t,
    ) -> ZkStatus;

    /// Verify a ZK proof for any registered predicate.
    pub fn zk_verify_predicate(
        transcript: *mut c_void,
        predicate_id: *const c_char,
        mso_bytes: *const c_uchar,
        mso_len: size_t,
        proof: *const c_uchar,
        proof_len: size_t,
    ) -> ZkStatus;

    // ── Utils ─────────────────────────────────────────────────────────

    pub fn zk_free_buffer(buffer: *mut c_uchar);
}
