//! Compatibility facade for the shared offline X.509 kernel.

use crate::{VerificationError, VerificationResult};
pub use marty_x509_verification::chain::{ChainValidationResult, ChainValidatorConfig, KeyUsage};
use marty_x509_verification::{ErrorKind, VerificationError as KernelError};

pub struct ChainValidator(marty_x509_verification::chain::ChainValidator);

fn map_error(error: Box<KernelError>) -> Box<VerificationError> {
    match error.kind {
        ErrorKind::Pem => VerificationError::pem_error(error.reason),
        ErrorKind::Der => VerificationError::der_error(error.reason),
        ErrorKind::Internal => VerificationError::internal(error.reason),
    }
}

impl ChainValidator {
    pub fn new() -> Self {
        Self(marty_x509_verification::chain::ChainValidator::new())
    }
    pub fn with_config(config: ChainValidatorConfig) -> Self {
        Self(marty_x509_verification::chain::ChainValidator::with_config(
            config,
        ))
    }
    pub fn configured(&self, config: ChainValidatorConfig) -> Self {
        Self(self.0.configured(config))
    }
    pub fn add_trust_anchor_pem(&mut self, pem: &str) -> VerificationResult<()> {
        self.0.add_trust_anchor_pem(pem).map_err(map_error)
    }
    pub fn add_trust_anchor_der(&mut self, der: &[u8]) -> VerificationResult<()> {
        self.0.add_trust_anchor_der(der).map_err(map_error)
    }
    pub fn add_intermediate_pem(&mut self, pem: &str) -> VerificationResult<()> {
        self.0.add_intermediate_pem(pem).map_err(map_error)
    }
    pub fn add_intermediate_der(&mut self, der: &[u8]) -> VerificationResult<()> {
        self.0.add_intermediate_der(der).map_err(map_error)
    }
    pub fn add_crl_der(&mut self, der: &[u8]) -> VerificationResult<()> {
        self.0.add_crl_der(der).map_err(map_error)
    }
    pub fn add_ocsp_response_der(&mut self, der: &[u8]) -> VerificationResult<()> {
        self.0.add_ocsp_response_der(der).map_err(map_error)
    }
    pub fn validate_chain(
        &self,
        chain_pem: &[String],
    ) -> VerificationResult<ChainValidationResult> {
        self.0.validate_chain(chain_pem).map_err(map_error)
    }
    pub fn validate_chain_der(
        &self,
        chain_der: &[Vec<u8>],
    ) -> VerificationResult<ChainValidationResult> {
        self.0.validate_chain_der(chain_der).map_err(map_error)
    }
    pub fn validate_certificate(
        &self,
        cert_pem: &str,
    ) -> VerificationResult<ChainValidationResult> {
        self.0.validate_certificate(cert_pem).map_err(map_error)
    }
}

impl Default for ChainValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    #[test]
    fn parser_and_status_input_errors_keep_existing_categories_and_codes() {
        let mut validator = ChainValidator::new();
        for error in [
            validator.add_trust_anchor_pem("not a PEM").unwrap_err(),
            validator.add_intermediate_pem("not a PEM").unwrap_err(),
        ] {
            assert!(matches!(&*error, VerificationError::PemError { .. }));
            assert_eq!(error.code(), "E602");
        }
        for error in [
            validator.add_trust_anchor_der(&[0]).unwrap_err(),
            validator.add_intermediate_der(&[0]).unwrap_err(),
            validator.add_crl_der(&[0]).unwrap_err(),
            validator.add_ocsp_response_der(&[0]).unwrap_err(),
            validator.validate_chain_der(&[vec![0]]).unwrap_err(),
        ] {
            assert!(matches!(&*error, VerificationError::DerError { .. }));
            assert_eq!(error.code(), "E601");
        }
    }

    #[test]
    fn crypto_failure_mapping_keeps_internal_error() {
        let error = map_error(KernelError::internal("signature verification failed"));
        assert!(matches!(&*error, VerificationError::Internal { .. }));
        assert_eq!(error.code(), "E999");
    }
}
