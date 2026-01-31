use libc::{c_char, c_int, c_uchar, c_void, size_t};

#[repr(C)]
pub struct CRandomBytes {
    pub ptr: *const c_uchar,
    pub len: size_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum ZkStatus {
    Success = 0,
    ErrorGeneric = 1,
    ErrorInvalidInput = 2,
    ErrorVerificationFailed = 3,
}

extern "C" {
    // Session / Transcript
    pub fn zk_create_transcript(nonce: *const c_uchar, nonce_len: size_t) -> *mut c_void;
    pub fn zk_free_transcript(transcript: *mut c_void);

    // Prover
    pub fn zk_prove_age_over_18(
        transcript: *mut c_void,
        mso_bytes: *const c_uchar,
        mso_len: size_t,
        signature: *const c_uchar,
        sig_len: size_t,
        birth_date_str: *const c_char, // "YYYY-MM-DD"
        proof_out: *mut *mut c_uchar,
        proof_len_out: *mut size_t,
    ) -> ZkStatus;

    // Verifier
    pub fn zk_verify_age_over_18(
        transcript: *mut c_void,
        mso_bytes: *const c_uchar,
        mso_len: size_t,
        proof: *const c_uchar,
        proof_len: size_t,
    ) -> ZkStatus;

    // Utils
    pub fn zk_free_buffer(buffer: *mut c_uchar);
}
