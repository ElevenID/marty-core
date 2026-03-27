//! Generated error code definitions
//! DO NOT EDIT - Generated from schema/error_codes.yaml

#[cfg(feature = "python")]
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// Hierarchical error code with category and specific code
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass)]
pub struct ErrorCode {
    /// Error category (e.g., "CRED", "KEY", "CRYPTO")
    pub category: String,
    /// Specific error code within category
    pub code: String,
    /// Human-readable error message
    pub message: String,
    /// Whether the operation can be retried
    pub retryable: bool,
    /// Error severity level
    pub severity: ErrorSeverity,
}

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyclass)]
pub enum ErrorSeverity {
    Info,
    Warning,
    Error,
}

impl ErrorCode {
    /// Get the full error code string (e.g., "CRED.ISSUANCE_FAILED")
    pub fn full_code(&self) -> String {
        format!("{}.{}", self.category, self.code)
    }
}

#[cfg(feature = "python")]
#[pymethods]
impl ErrorCode {
    #[getter]
    fn full_code_py(&self) -> String {
        self.full_code()
    }
}

/// Predefined error codes
pub mod codes {
    use super::*;

    
    /// Credential operations
    pub mod cred {
        use super::*;

        
        /// Failed to issue credential
        pub fn issuance_failed() -> ErrorCode {
            ErrorCode {
                category: "CRED".to_string(),
                code: "ISSUANCE_FAILED".to_string(),
                message: "Failed to issue credential".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Credential verification failed
        pub fn verification_failed() -> ErrorCode {
            ErrorCode {
                category: "CRED".to_string(),
                code: "VERIFICATION_FAILED".to_string(),
                message: "Credential verification failed".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Failed to check revocation status
        pub fn revocation_check_failed() -> ErrorCode {
            ErrorCode {
                category: "CRED".to_string(),
                code: "REVOCATION_CHECK_FAILED".to_string(),
                message: "Failed to check revocation status".to_string(),
                retryable: true,
                severity: ErrorSeverity::Warning,
            }
        }
        
        /// Invalid credential format
        pub fn invalid_format() -> ErrorCode {
            ErrorCode {
                category: "CRED".to_string(),
                code: "INVALID_FORMAT".to_string(),
                message: "Invalid credential format".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Credential has expired
        pub fn expired() -> ErrorCode {
            ErrorCode {
                category: "CRED".to_string(),
                code: "EXPIRED".to_string(),
                message: "Credential has expired".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Credential is not yet valid
        pub fn not_yet_valid() -> ErrorCode {
            ErrorCode {
                category: "CRED".to_string(),
                code: "NOT_YET_VALID".to_string(),
                message: "Credential is not yet valid".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Failed to parse credential
        pub fn parse_error() -> ErrorCode {
            ErrorCode {
                category: "CRED".to_string(),
                code: "PARSE_ERROR".to_string(),
                message: "Failed to parse credential".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
    }
    
    /// Key management operations
    pub mod key {
        use super::*;

        
        /// Key not found
        pub fn not_found() -> ErrorCode {
            ErrorCode {
                category: "KEY".to_string(),
                code: "NOT_FOUND".to_string(),
                message: "Key not found".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Failed to generate key
        pub fn generation_failed() -> ErrorCode {
            ErrorCode {
                category: "KEY".to_string(),
                code: "GENERATION_FAILED".to_string(),
                message: "Failed to generate key".to_string(),
                retryable: true,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Invalid key format or parameters
        pub fn invalid_key() -> ErrorCode {
            ErrorCode {
                category: "KEY".to_string(),
                code: "INVALID_KEY".to_string(),
                message: "Invalid key format or parameters".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Failed to store key
        pub fn storage_failed() -> ErrorCode {
            ErrorCode {
                category: "KEY".to_string(),
                code: "STORAGE_FAILED".to_string(),
                message: "Failed to store key".to_string(),
                retryable: true,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Key access denied
        pub fn access_denied() -> ErrorCode {
            ErrorCode {
                category: "KEY".to_string(),
                code: "ACCESS_DENIED".to_string(),
                message: "Key access denied".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
    }
    
    /// Cryptographic operations
    pub mod crypto {
        use super::*;

        
        /// Invalid signature
        pub fn signature_invalid() -> ErrorCode {
            ErrorCode {
                category: "CRYPTO".to_string(),
                code: "SIGNATURE_INVALID".to_string(),
                message: "Invalid signature".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Encryption failed
        pub fn encryption_failed() -> ErrorCode {
            ErrorCode {
                category: "CRYPTO".to_string(),
                code: "ENCRYPTION_FAILED".to_string(),
                message: "Encryption failed".to_string(),
                retryable: true,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Decryption failed
        pub fn decryption_failed() -> ErrorCode {
            ErrorCode {
                category: "CRYPTO".to_string(),
                code: "DECRYPTION_FAILED".to_string(),
                message: "Decryption failed".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Hash computation failed
        pub fn hash_failed() -> ErrorCode {
            ErrorCode {
                category: "CRYPTO".to_string(),
                code: "HASH_FAILED".to_string(),
                message: "Hash computation failed".to_string(),
                retryable: true,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Unsupported or invalid algorithm
        pub fn invalid_algorithm() -> ErrorCode {
            ErrorCode {
                category: "CRYPTO".to_string(),
                code: "INVALID_ALGORITHM".to_string(),
                message: "Unsupported or invalid algorithm".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
    }
    
    /// ISO 18013-5 session operations
    pub mod session {
        use super::*;

        
        /// Failed to establish secure session
        pub fn establishment_failed() -> ErrorCode {
            ErrorCode {
                category: "SESSION".to_string(),
                code: "ESTABLISHMENT_FAILED".to_string(),
                message: "Failed to establish secure session".to_string(),
                retryable: true,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Invalid session state
        pub fn invalid_state() -> ErrorCode {
            ErrorCode {
                category: "SESSION".to_string(),
                code: "INVALID_STATE".to_string(),
                message: "Invalid session state".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Session timeout
        pub fn timeout() -> ErrorCode {
            ErrorCode {
                category: "SESSION".to_string(),
                code: "TIMEOUT".to_string(),
                message: "Session timeout".to_string(),
                retryable: true,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Session terminated
        pub fn terminated() -> ErrorCode {
            ErrorCode {
                category: "SESSION".to_string(),
                code: "TERMINATED".to_string(),
                message: "Session terminated".to_string(),
                retryable: false,
                severity: ErrorSeverity::Info,
            }
        }
        
        /// Session encryption error
        pub fn encryption_error() -> ErrorCode {
            ErrorCode {
                category: "SESSION".to_string(),
                code: "ENCRYPTION_ERROR".to_string(),
                message: "Session encryption error".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
    }
    
    /// Transport layer operations
    pub mod transport {
        use super::*;

        
        /// Transport connection failed
        pub fn connection_failed() -> ErrorCode {
            ErrorCode {
                category: "TRANSPORT".to_string(),
                code: "CONNECTION_FAILED".to_string(),
                message: "Transport connection failed".to_string(),
                retryable: true,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Transport disconnected
        pub fn disconnected() -> ErrorCode {
            ErrorCode {
                category: "TRANSPORT".to_string(),
                code: "DISCONNECTED".to_string(),
                message: "Transport disconnected".to_string(),
                retryable: true,
                severity: ErrorSeverity::Warning,
            }
        }
        
        /// Failed to send data
        pub fn send_failed() -> ErrorCode {
            ErrorCode {
                category: "TRANSPORT".to_string(),
                code: "SEND_FAILED".to_string(),
                message: "Failed to send data".to_string(),
                retryable: true,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Failed to receive data
        pub fn receive_failed() -> ErrorCode {
            ErrorCode {
                category: "TRANSPORT".to_string(),
                code: "RECEIVE_FAILED".to_string(),
                message: "Failed to receive data".to_string(),
                retryable: true,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Transport not supported
        pub fn unsupported() -> ErrorCode {
            ErrorCode {
                category: "TRANSPORT".to_string(),
                code: "UNSUPPORTED".to_string(),
                message: "Transport not supported".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Bluetooth Low Energy error
        pub fn ble_error() -> ErrorCode {
            ErrorCode {
                category: "TRANSPORT".to_string(),
                code: "BLE_ERROR".to_string(),
                message: "Bluetooth Low Energy error".to_string(),
                retryable: true,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Near Field Communication error
        pub fn nfc_error() -> ErrorCode {
            ErrorCode {
                category: "TRANSPORT".to_string(),
                code: "NFC_ERROR".to_string(),
                message: "Near Field Communication error".to_string(),
                retryable: true,
                severity: ErrorSeverity::Error,
            }
        }
        
    }
    
    /// Trust chain validation
    pub mod trust {
        use super::*;

        
        /// Trust chain validation failed
        pub fn chain_invalid() -> ErrorCode {
            ErrorCode {
                category: "TRUST".to_string(),
                code: "CHAIN_INVALID".to_string(),
                message: "Trust chain validation failed".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Trust anchor not found
        pub fn anchor_not_found() -> ErrorCode {
            ErrorCode {
                category: "TRUST".to_string(),
                code: "ANCHOR_NOT_FOUND".to_string(),
                message: "Trust anchor not found".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Certificate has expired
        pub fn certificate_expired() -> ErrorCode {
            ErrorCode {
                category: "TRUST".to_string(),
                code: "CERTIFICATE_EXPIRED".to_string(),
                message: "Certificate has expired".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Certificate has been revoked
        pub fn certificate_revoked() -> ErrorCode {
            ErrorCode {
                category: "TRUST".to_string(),
                code: "CERTIFICATE_REVOKED".to_string(),
                message: "Certificate has been revoked".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
        /// Failed to build certification path
        pub fn path_build_failed() -> ErrorCode {
            ErrorCode {
                category: "TRUST".to_string(),
                code: "PATH_BUILD_FAILED".to_string(),
                message: "Failed to build certification path".to_string(),
                retryable: false,
                severity: ErrorSeverity::Error,
            }
        }
        
    }
    
}

#[cfg(feature = "python")]
pub fn register_error_code_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    parent_module.add_class::<ErrorCode>()?;
    parent_module.add_class::<ErrorSeverity>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_creation() {
        let err = codes::cred::issuance_failed();
        assert_eq!(err.category, "CRED");
        assert_eq!(err.code, "ISSUANCE_FAILED");
        assert_eq!(err.full_code(), "CRED.ISSUANCE_FAILED");
        assert!(!err.retryable);
    }
}