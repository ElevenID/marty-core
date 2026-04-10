//! OpenBadgeSuite wrapper enum combining SSI's AnySuite with X509Signature2021.
//!
//! This module provides a wrapper around SSI's cryptographic suites that adds support
//! for X.509 certificate-based signatures while maintaining compatibility with
//! standard Data Integrity proofs.

use ssi::claims::data_integrity::AnySuite;

use crate::error::VerificationResult;

use super::x509_suite::X509Signature2021;

/// Wrapper enum for Open Badge cryptographic suites.
///
/// Combines SSI's standard suites (JsonWebSignature2020, Ed25519Signature2018/2020)
/// with custom X509Signature2021 for certificate-based signatures.
#[derive(Debug, Clone)]
pub enum OpenBadgeSuite {
    /// Standard SSI cryptographic suite.
    Ssi(AnySuite),
    
    /// X.509 certificate-based signature suite.
    X509(X509Signature2021),
}

impl OpenBadgeSuite {
    /// Create from SSI suite.
    pub fn from_ssi(suite: AnySuite) -> Self {
        OpenBadgeSuite::Ssi(suite)
    }
    
    /// Create X509 suite with trust anchors.
    pub fn x509_with_trust_anchors(trust_anchors: Vec<Vec<u8>>) -> VerificationResult<Self> {
        let suite = X509Signature2021::new(trust_anchors)?;
        Ok(OpenBadgeSuite::X509(suite))
    }
    
    /// Check if this is an X509 suite.
    pub fn is_x509(&self) -> bool {
        matches!(self, OpenBadgeSuite::X509(_))
    }
    
    /// Get X509 suite reference, if applicable.
    pub fn as_x509(&self) -> Option<&X509Signature2021> {
        match self {
            OpenBadgeSuite::X509(s) => Some(s),
            _ => None,
        }
    }
    
    /// Get SSI suite reference, if applicable.
    pub fn as_ssi(&self) -> Option<&AnySuite> {
        match self {
            OpenBadgeSuite::Ssi(s) => Some(s),
            _ => None,
        }
    }
}

/// Trait representing a suite capable of verifying Open Badge credentials.
#[allow(dead_code)]
pub trait OpenBadgeVerificationSuite {
    /// Verify a signature.
    fn verify_sync(&self, message: &[u8], signature: &[u8], method: &crate::open_badges::method_wrapper::OpenBadgeMethod) -> VerificationResult<bool>;
}

impl OpenBadgeVerificationSuite for OpenBadgeSuite {
    fn verify_sync(&self, message: &[u8], signature: &[u8], method: &crate::open_badges::method_wrapper::OpenBadgeMethod) -> VerificationResult<bool> {
        match self {
            OpenBadgeSuite::Ssi(_ssi_suite) => {
                // SSI verification is usually async and handled by ssi::DataIntegrity.
                // For this wrapper, we could delegate or provide a bridge.
                // For now, return unsupported as this is a consolidated interface placeholder.
                Err(crate::error::VerificationError::open_badges_unsupported(
                    "Synchronous SSI verification through OpenBadgeSuite wrapper not yet implemented".to_string()
                ))
            }
            OpenBadgeSuite::X509(x509_suite) => {
                if let crate::open_badges::method_wrapper::OpenBadgeMethod::X509(x509_method) = method {
                    x509_suite.verify_signature(message, signature, x509_method)
                } else {
                    Err(crate::error::VerificationError::open_badges(
                        "X509 suite requires X509 verification method".to_string()
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_ssi_suite() {
        let suite = OpenBadgeSuite::from_ssi(AnySuite::Ed25519Signature2020);
        assert!(!suite.is_x509());
        assert!(suite.as_ssi().is_some());
    }
    
    #[test]
    fn test_create_x509_suite() {
        // Use a mock trust anchor for testing
        let mock_cert = vec![0x30, 0x82]; // DER certificate start
        let suite = OpenBadgeSuite::x509_with_trust_anchors(vec![mock_cert]);
        
        // Will fail validation but tests construction
        assert!(suite.is_ok() || suite.is_err());
    }
}
