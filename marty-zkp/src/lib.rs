mod ffi;
pub mod mdoc_support;

use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum ZkError {
    #[error("Generic ZK error")]
    Generic,
    #[error("Invalid input data")]
    InvalidInput,
    #[error("Verification failed")]
    VerificationFailed,
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

pub struct ZkTranscript {
    inner: *mut libc::c_void,
}

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

pub struct Prover;

impl Prover {
    pub fn prove_age_over_18(
        transcript: &ZkTranscript,
        mso_bytes: &[u8],
        signature: &[u8],
        birth_date: &str,
    ) -> Result<Vec<u8>, ZkError> {
        let birth_date_c = std::ffi::CString::new(birth_date).map_err(|_| ZkError::InvalidInput)?;
        
        let mut proof_ptr: *mut u8 = std::ptr::null_mut();
        let mut proof_len: usize = 0;

        let status = unsafe {
            ffi::zk_prove_age_over_18(
                transcript.inner,
                mso_bytes.as_ptr(),
                mso_bytes.len(),
                signature.as_ptr(),
                signature.len(),
                birth_date_c.as_ptr(),
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
}

pub struct Verifier;

impl Verifier {
    pub fn verify_age_over_18(
        transcript: &ZkTranscript,
        mso_bytes: &[u8],
        proof: &[u8],
    ) -> Result<bool, ZkError> {
        let status = unsafe {
            ffi::zk_verify_age_over_18(
                transcript.inner,
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
                Result::from(status)?; // Will return Err for other codes
                Ok(false) // Unreachable
            }
        }
    }
}

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

    // SAFETY: The mock ZK library is assumed to be thread-safe
    // For a real implementation, we'd verify this with the library's documentation
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
    
    // Simple stateless verify wrapper for Python
    #[pyfunction]
    pub fn verify_age_zkp(nonce: &[u8], mso: &[u8], proof: &[u8]) -> PyResult<bool> {
        let transcript = ZkTranscript::new(nonce);
        Verifier::verify_age_over_18(&transcript, mso, proof)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
}
