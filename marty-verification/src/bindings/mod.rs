//! PyO3 Python bindings for marty-verification.
//!
//! This module exposes the verification functionality to Python.
//!
//! # Available Bindings
//!
//! ## MDL Verification
//! - `IacaRegistry` - Trust anchor registry for IACA certificates
//! - `MdlVerificationResult` - Result of MDL verification
//! - `verify_mdl_x5chain()` - Verify MDL X5Chain from PEM
//! - `verify_mdl_x5chain_cbor()` - Verify MDL X5Chain from CBOR
//!
//! ## MRZ Parsing
//! - `MrzData` - Parsed MRZ data
//! - `parse_mrz()` - Parse MRZ from lines of text
//! - `compute_check_digit()` - Calculate ICAO check digit
//! - `validate_check_digit()` - Validate a check digit
//!
//! ## CRL Checking
//! - `CrlInfo` - Parsed CRL information
//! - `RevokedCertificate` - Revoked certificate entry
//! - `parse_crl()` - Parse a DER-encoded CRL
//! - `validate_crl_for_certificate()` - Authenticate CRL evidence and check revocation
//!
//! ## Cryptographic Operations
//! - `hash_data()` - Hash data with specified algorithm
//! - `verify_signature()` - Verify a cryptographic signature
//!
//! ## mDL Document Parsing
//! - `DeviceResponse` - Parsed mDL DeviceResponse
//! - `parse_device_response()` - Parse CBOR DeviceResponse

use crate::error::VerificationError;
use pyo3::prelude::*;

mod registries;
pub use registries::*;
mod mrz;
pub use mrz::*;
mod crl;
pub use crl::*;
mod document_verification;
use document_verification::*;
mod mdoc;
pub use mdoc::*;
mod chain;
pub use chain::*;
mod crypto;
use crypto::*;
mod open_badges;
use open_badges::*;
mod passport_transport;
use passport_transport::*;
#[cfg(feature = "csca")]
mod active_authentication;
#[cfg(feature = "csca")]
use active_authentication::*;
#[cfg(feature = "csca")]
mod eac;
#[cfg(feature = "csca")]
use eac::*;
mod ocsp;
use ocsp::*;
mod dtc;
use dtc::*;
#[cfg(feature = "csca")]
mod emrtd_data;
#[cfg(feature = "csca")]
use emrtd_data::*;
mod trust_sync;
use trust_sync::*;

/// Trait for converting various error types to PyErr
trait IntoPyErr {
    fn into_pyerr(self) -> PyErr;
}

impl IntoPyErr for marty_crypto::CryptoError {
    fn into_pyerr(self) -> PyErr {
        let verr: VerificationError = self.into();
        verr.into()
    }
}

impl IntoPyErr for VerificationError {
    fn into_pyerr(self) -> PyErr {
        self.into()
    }
}

impl IntoPyErr for Box<VerificationError> {
    fn into_pyerr(self) -> PyErr {
        (*self).into()
    }
}

/// Helper function to convert any error implementing IntoPyErr to PyErr
fn to_pyerr<E: IntoPyErr>(e: E) -> PyErr {
    e.into_pyerr()
}

/// Create the Python module for marty_verification.
#[pymodule]
pub fn _marty_verification(m: &Bound<'_, PyModule>) -> PyResult<()> {
    register_marty_verification(m)
}

/// Register marty-verification functions in a parent module.
///
/// Called from marty-rs to add verification functions directly.
pub fn register_marty_verification(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Trust-registry synchronization kernel
    m.add_function(wrap_pyfunction!(trust_registry_catalog_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_behavior_fixture_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_import_decision_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_public_sync_query_json, m)?)?;
    m.add_function(wrap_pyfunction!(
        trust_registry_public_sync_metadata_json,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(trust_registry_sync_is_due_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_validate_url, m)?)?;
    m.add_function(wrap_pyfunction!(
        trust_registry_destination_decision_json,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        trust_registry_private_host_allowlist_json,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(trust_registry_request_plan_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_validate_feed_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_validate_state_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_evaluate_pages_json, m)?)?;
    m.add_function(wrap_pyfunction!(trust_registry_revalidate_state_json, m)?)?;

    // MDL Verification
    m.add_class::<PyMdlVerificationResult>()?;
    m.add_class::<PyIacaRegistry>()?;
    m.add_class::<PyValidationConfig>()?;
    m.add_function(wrap_pyfunction!(verify_mdl_x5chain, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mdl_x5chain_cbor, m)?)?;

    // EUDI Trust Registry
    m.add_class::<PyEudiRegistry>()?;
    m.add_class::<PyEuMemberState>()?;
    m.add_class::<PyTrustServiceProvider>()?;

    // CSCA Trust Registry (feature-gated)
    #[cfg(feature = "csca")]
    {
        m.add_class::<PyCscaRegistry>()?;
        #[cfg(feature = "ephemeral-session-keys")]
        m.add_class::<PyNativeBacSession>()?;
        #[cfg(feature = "ephemeral-session-keys")]
        m.add_class::<PyNativePaceSession>()?;
        m.add_function(wrap_pyfunction!(apdu_encode, m)?)?;
        m.add_function(wrap_pyfunction!(apdu_parse_response, m)?)?;
        m.add_function(wrap_pyfunction!(apdu_parse_command, m)?)?;
        m.add_function(wrap_pyfunction!(apdu_build_read_binary_commands, m)?)?;
        m.add_function(wrap_pyfunction!(passport_data_group_file_id, m)?)?;
        m.add_function(wrap_pyfunction!(verify_emrtd, m)?)?;
        m.add_function(wrap_pyfunction!(emrtd_parse_tlv_json, m)?)?;
        m.add_function(wrap_pyfunction!(emrtd_parse_ef_com_json, m)?)?;
        m.add_function(wrap_pyfunction!(emrtd_parse_ef_dg1_json, m)?)?;
        m.add_function(wrap_pyfunction!(emrtd_parse_ef_dg2_json, m)?)?;
        m.add_function(wrap_pyfunction!(emrtd_parse_elementary_file_json, m)?)?;
        m.add_function(wrap_pyfunction!(emrtd_parse_biometric_template_json, m)?)?;
        m.add_function(wrap_pyfunction!(emrtd_validate_biometric_quality_json, m)?)?;
        m.add_function(wrap_pyfunction!(emrtd_parse_dg15_json, m)?)?;
        m.add_function(wrap_pyfunction!(emrtd_inspect_rsa_public_key_json, m)?)?;
        m.add_function(wrap_pyfunction!(emrtd_rsa_public_key_spki, m)?)?;
    }

    // MRZ Parsing
    m.add_class::<PyMrzData>()?;
    m.add_function(wrap_pyfunction!(parse_mrz, m)?)?;
    m.add_function(wrap_pyfunction!(compute_check_digit, m)?)?;
    m.add_function(wrap_pyfunction!(validate_check_digit, m)?)?;

    // CRL Checking
    m.add_class::<PyCrlInfo>()?;
    m.add_class::<PyRevokedCertificate>()?;
    m.add_function(wrap_pyfunction!(parse_crl, m)?)?;
    m.add_function(wrap_pyfunction!(crl_pem_to_der, m)?)?;
    m.add_function(wrap_pyfunction!(verify_crl_signature, m)?)?;
    m.add_function(wrap_pyfunction!(validate_crl, m)?)?;
    m.add_function(wrap_pyfunction!(validate_crl_for_certificate, m)?)?;

    // Crypto Operations - Base
    m.add_function(wrap_pyfunction!(hash_data, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(verify_sod_signature, m)?)?;
    m.add_function(wrap_pyfunction!(parse_sod, m)?)?;
    m.add_function(wrap_pyfunction!(verify_sod_data_group_hash, m)?)?;
    m.add_function(wrap_pyfunction!(parse_master_list, m)?)?;
    m.add_function(wrap_pyfunction!(verify_master_list_signature, m)?)?;

    // Crypto Operations - Ed448
    #[cfg(feature = "csca")]
    m.add_function(wrap_pyfunction!(ed448_verify, m)?)?;

    // Crypto Operations - PKCS#12

    // Crypto Operations - ISO 9796-2
    #[cfg(feature = "csca")]
    {
        m.add_function(wrap_pyfunction!(iso9796_verify, m)?)?;
        m.add_function(wrap_pyfunction!(iso9796_recover, m)?)?;
        m.add_function(wrap_pyfunction!(
            active_authentication_generate_challenge,
            m
        )?)?;
        m.add_function(wrap_pyfunction!(active_authentication_build_apdu, m)?)?;
        m.add_function(wrap_pyfunction!(active_authentication_parse_response, m)?)?;
        m.add_function(wrap_pyfunction!(active_authentication_verify, m)?)?;
        #[cfg(feature = "ephemeral-session-keys")]
        m.add_class::<PyNativeEacChipAuthentication>()?;
        #[cfg(feature = "ephemeral-session-keys")]
        m.add_class::<PyNativeEacSecureMessaging>()?;
        m.add_function(wrap_pyfunction!(eac_verify_certificate_signature, m)?)?;
        m.add_function(wrap_pyfunction!(eac_certificate_fingerprint, m)?)?;
        m.add_function(wrap_pyfunction!(eac_serialize_certificate, m)?)?;
    }

    // Crypto Operations - Certificate
    m.add_function(wrap_pyfunction!(load_certificate_pem, m)?)?;
    m.add_function(wrap_pyfunction!(load_certificate_der, m)?)?;
    m.add_function(wrap_pyfunction!(get_certificate_info, m)?)?;
    m.add_function(wrap_pyfunction!(certificate_pem_to_der, m)?)?;
    m.add_function(wrap_pyfunction!(certificate_der_to_pem, m)?)?;
    m.add_function(wrap_pyfunction!(get_certificate_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(is_certificate_expired, m)?)?;
    m.add_function(wrap_pyfunction!(is_certificate_not_yet_valid, m)?)?;
    m.add_function(wrap_pyfunction!(verify_certificate_signature, m)?)?;

    // Crypto Operations - Key Serialization
    m.add_function(wrap_pyfunction!(load_public_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(load_public_key_der, m)?)?;
    m.add_function(wrap_pyfunction!(save_public_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(public_key_pem_to_jwk, m)?)?;
    m.add_function(wrap_pyfunction!(public_key_der_to_jwk, m)?)?;
    m.add_function(wrap_pyfunction!(certificate_pem_to_jwk, m)?)?;
    m.add_function(wrap_pyfunction!(certificate_der_to_jwk, m)?)?;
    m.add_function(wrap_pyfunction!(p256_public_jwk_to_pem, m)?)?;
    m.add_function(wrap_pyfunction!(detect_public_key_type, m)?)?;
    m.add_function(wrap_pyfunction!(get_key_size, m)?)?;
    m.add_function(wrap_pyfunction!(raw_public_key_to_spki, m)?)?;
    m.add_function(wrap_pyfunction!(spki_to_raw_public_key, m)?)?;

    // Crypto Operations - Ed25519
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;

    // Crypto Operations - ECDH Key Agreement

    // Crypto Operations - ECDSA Signing
    m.add_function(wrap_pyfunction!(ecdsa_p256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p384_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_p521_verify, m)?)?;

    // Crypto Operations - RSA Signing
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha384_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pkcs1_sha512_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha256_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha384_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_pss_sha512_verify, m)?)?;

    // JWK/JWS/JWE

    // mDL Document Parsing
    m.add_class::<PyDeviceResponse>()?;
    m.add_function(wrap_pyfunction!(parse_device_response, m)?)?;

    // Certificate Chain Validation
    m.add_class::<PyChainValidationResult>()?;
    m.add_class::<PyChainValidator>()?;

    // OCSP Operations
    m.add_function(wrap_pyfunction!(build_ocsp_request, m)?)?;
    m.add_function(wrap_pyfunction!(get_ocsp_responder_url, m)?)?;
    m.add_function(wrap_pyfunction!(get_crl_distribution_points, m)?)?;
    m.add_function(wrap_pyfunction!(parse_ocsp_response, m)?)?;
    m.add_function(wrap_pyfunction!(validate_ocsp_response, m)?)?;

    // Open Badges
    m.add_function(wrap_pyfunction!(open_badge_ob2_verify, m)?)?;
    m.add_function(wrap_pyfunction!(open_badge_ob3_verify, m)?)?;
    m.add_function(wrap_pyfunction!(compare_passport_hashes_json, m)?)?;

    // DTC helpers (JSON in/out)
    m.add_function(wrap_pyfunction!(dtc_create, m)?)?;
    m.add_function(wrap_pyfunction!(dtc_prepare_signing, m)?)?;
    m.add_function(wrap_pyfunction!(dtc_assemble_signature, m)?)?;
    m.add_function(wrap_pyfunction!(dtc_verify, m)?)?;

    // Certificate Builder Operations (feature-gated)

    // Add constants for ruleset selection
    m.add("RULESET_MDL", "mdl")?;
    m.add("RULESET_AAMVA_MDL", "aamva_mdl")?;
    m.add("RULESET_MDL_READER", "mdl_reader")?;

    Ok(())
}

#[cfg(test)]
mod domain_contract_tests {
    use super::*;
    use pyo3::exceptions::PyValueError;

    #[test]
    fn both_entry_points_exclude_generic_secret_byte_apis() {
        Python::initialize();
        Python::attach(|py| {
            for standalone in [true, false] {
                let module = PyModule::new(py, "_verification_contract").unwrap();
                if standalone {
                    _marty_verification(&module).unwrap();
                } else {
                    register_marty_verification(&module).unwrap();
                }
                for operation in [
                    "hkdf_sha256",
                    "hkdf_sha384",
                    "pbkdf2_sha256",
                    "generate_random_bytes",
                    "aes_gcm_encrypt",
                    "aes_gcm_decrypt",
                    "tdes_cbc_encrypt",
                    "tdes_cbc_decrypt",
                ] {
                    assert!(!module.hasattr(operation).unwrap(), "{operation}");
                }
            }
        });
    }

    #[test]
    fn both_entry_points_preserve_mrz_objects_and_errors() {
        Python::initialize();
        Python::attach(|py| {
            for standalone in [true, false] {
                let module = PyModule::new(py, "_verification_contract").unwrap();
                if standalone {
                    _marty_verification(&module).unwrap();
                } else {
                    register_marty_verification(&module).unwrap();
                }
                let lines = vec![
                    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
                    "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
                ];
                let result = module
                    .getattr("parse_mrz")
                    .unwrap()
                    .call1((lines,))
                    .unwrap();
                assert!(result
                    .is_instance(&module.getattr("MrzData").unwrap())
                    .unwrap());
                assert_eq!(
                    result
                        .getattr("surname")
                        .unwrap()
                        .extract::<String>()
                        .unwrap(),
                    "ERIKSSON"
                );
                assert_eq!(
                    result
                        .call_method0("full_name")
                        .unwrap()
                        .extract::<String>()
                        .unwrap(),
                    "ANNA MARIA ERIKSSON"
                );
                assert!(result
                    .getattr("check_digits_valid")
                    .unwrap()
                    .extract::<bool>()
                    .unwrap());
                let dict = result.call_method0("to_dict").unwrap();
                assert_eq!(
                    dict.get_item("document_number")
                        .unwrap()
                        .extract::<String>()
                        .unwrap(),
                    "L898902C3"
                );
                assert_eq!(
                    module
                        .getattr("compute_check_digit")
                        .unwrap()
                        .call1(("L898902C3",))
                        .unwrap()
                        .extract::<String>()
                        .unwrap(),
                    "6"
                );
                let error = module
                    .getattr("parse_mrz")
                    .unwrap()
                    .call1((Vec::<String>::new(),))
                    .unwrap_err();
                assert!(error.is_instance_of::<PyValueError>(py));
                assert_eq!(
                    module
                        .getattr("RULESET_MDL")
                        .unwrap()
                        .extract::<String>()
                        .unwrap(),
                    "mdl"
                );
            }
        });
    }
}
