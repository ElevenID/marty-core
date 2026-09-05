//! Python adapters for document verification.

use super::to_pyerr;
#[cfg(feature = "csca")]
use super::PyCscaRegistry;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::types::PyDict;
use pyo3::types::PyList;

// ============================================================================
// Cryptographic Operations Bindings
// ============================================================================

/// Hash data using the specified algorithm.
///
/// Args:
///     algorithm: Hash algorithm ("sha1", "sha256", "sha384", "sha512")
///     data: Data to hash
///
/// Returns:
///     Hash digest as bytes
#[pyfunction]
pub(super) fn hash_data<'py>(
    py: Python<'py>,
    algorithm: &str,
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    use marty_crypto::hashing;

    let result = match algorithm.to_lowercase().as_str() {
        "sha1" => hashing::hash_sha1(data),
        "sha256" => hashing::hash_sha256(data),
        "sha384" => hashing::hash_sha384(data),
        "sha512" => hashing::hash_sha512(data),
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown hash algorithm: {}. Use 'sha1', 'sha256', 'sha384', or 'sha512'",
                other
            )));
        }
    };

    Ok(PyBytes::new(py, &result))
}

/// Verify a cryptographic signature.
///
/// Args:
///     algorithm: Signature algorithm (e.g., "ecdsa-p256-sha256", "rsa-pkcs1-sha256")
///     public_key_der: DER-encoded public key (SubjectPublicKeyInfo)
///     message: The message that was signed
///     signature: The signature bytes
///
/// Returns:
///     True if signature is valid, False otherwise
#[pyfunction]
pub(super) fn verify_signature(
    algorithm: &str,
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    use marty_crypto::SignatureAlgorithm;

    let alg = match algorithm.to_lowercase().replace("-", "_").as_str() {
        "ecdsa_p256_sha256" | "es256" => SignatureAlgorithm::EcdsaP256Sha256,
        "ecdsa_p384_sha384" | "es384" => SignatureAlgorithm::EcdsaP384Sha384,
        "rsa_pkcs1_sha256" | "rs256" => SignatureAlgorithm::RsaPkcs1Sha256,
        "rsa_pkcs1_sha384" | "rs384" => SignatureAlgorithm::RsaPkcs1Sha384,
        "rsa_pkcs1_sha512" | "rs512" => SignatureAlgorithm::RsaPkcs1Sha512,
        "rsa_pss_sha256" | "ps256" => SignatureAlgorithm::RsaPssSha256,
        "rsa_pss_sha384" | "ps384" => SignatureAlgorithm::RsaPssSha384,
        "rsa_pss_sha512" | "ps512" => SignatureAlgorithm::RsaPssSha512,
        "eddsa" => match marty_crypto::serialization::detect_public_key_type(public_key_der)
            .map_err(to_pyerr)?
            .as_str()
        {
            "Ed25519" => SignatureAlgorithm::Ed25519,
            "Ed448" => SignatureAlgorithm::Ed448,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "EdDSA signature requires an Ed25519 or Ed448 public key",
                ));
            }
        },
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown signature algorithm: {}",
                other
            )));
        }
    };

    marty_crypto::verify_signature(alg, public_key_der, message, signature).map_err(to_pyerr)
}

/// Verify an eMRTD EF.SOD CMS signature using the native ICAO verifier.
#[pyfunction]
pub(super) fn verify_sod_signature(sod_der: &[u8]) -> PyResult<bool> {
    crate::asn1::sod::verify_sod_signature(sod_der).map_err(to_pyerr)
}

/// Convert a PEM-encoded CRL to DER.
#[pyfunction]
pub(super) fn crl_pem_to_der<'py>(
    py: Python<'py>,
    pem_data: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let der = crate::asn1::crl::crl_pem_to_der(pem_data).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &der))
}

/// Verify a DER-encoded CRL using its issuer certificate.
#[pyfunction]
pub(super) fn verify_crl_signature(crl_der: &[u8], issuer_cert_der: &[u8]) -> PyResult<bool> {
    let issuer_public_key =
        marty_crypto::certificate::get_certificate_public_key(issuer_cert_der).map_err(to_pyerr)?;
    crate::asn1::crl::verify_crl_signature(crl_der, &issuer_public_key).map_err(to_pyerr)
}

/// Authenticate a CRL against its issuer and enforce freshness.
#[pyfunction]
pub(super) fn validate_crl(
    py: Python<'_>,
    crl_der: &[u8],
    issuer_cert_der: &[u8],
) -> PyResult<Py<PyDict>> {
    let info = marty_crypto::crl::validate_crl(crl_der, issuer_cert_der).map_err(to_pyerr)?;
    let result = PyDict::new(py);
    result.set_item("issuer", info.issuer)?;
    result.set_item("this_update", info.this_update)?;
    result.set_item("next_update", info.next_update)?;
    result.set_item("crl_number", info.crl_number)?;
    result.set_item("revoked_count", info.revoked_count)?;
    result.set_item("signature_valid", true)?;
    result.set_item("freshness_valid", true)?;
    Ok(result.into())
}

/// Authenticate a CRL and check one exact certificate/issuer pair.
#[pyfunction]
pub(super) fn validate_crl_for_certificate(
    py: Python<'_>,
    crl_der: &[u8],
    cert_der: &[u8],
    issuer_cert_der: &[u8],
) -> PyResult<Py<PyDict>> {
    let info = marty_crypto::crl::validate_crl_for_certificate(crl_der, cert_der, issuer_cert_der)
        .map_err(to_pyerr)?;
    let result = PyDict::new(py);
    result.set_item("revoked", info.revoked)?;
    result.set_item("revocation_date", info.revocation_date)?;
    result.set_item("reason", info.reason.map(|reason| reason.as_str()))?;
    result.set_item("issuer", info.issuer)?;
    result.set_item("this_update", info.this_update)?;
    result.set_item("next_update", info.next_update)?;
    result.set_item("signature_valid", info.signature_valid)?;
    result.set_item("freshness_valid", info.freshness_valid)?;
    result.set_item("certificate_id_valid", info.certificate_id_valid)?;
    Ok(result.into())
}

/// Parse an EF.SOD and return its native verification metadata.
#[pyfunction]
pub(super) fn parse_sod<'py>(py: Python<'py>, sod_der: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    let sod = crate::asn1::sod::parse_sod(sod_der).map_err(to_pyerr)?;
    let result = PyDict::new(py);
    result.set_item("lds_version", sod.lds_version)?;
    result.set_item("hash_algorithm", sod.hash_algorithm)?;
    result.set_item(
        "document_signer_cert",
        sod.document_signer_cert.unwrap_or_default(),
    )?;
    let hashes = PyList::empty(py);
    for hash in sod.data_group_hashes {
        let item = PyDict::new(py);
        item.set_item("data_group_number", hash.data_group_number)?;
        item.set_item("hash_value", hash.hash_value)?;
        hashes.append(item)?;
    }
    result.set_item("data_group_hashes", hashes)?;
    Ok(result)
}

/// Verify one data-group hash against a native EF.SOD payload.
#[pyfunction]
pub(super) fn verify_sod_data_group_hash(
    sod_der: &[u8],
    data_group_number: u8,
    data_group_content: &[u8],
) -> PyResult<bool> {
    crate::asn1::sod::verify_data_group_hash_from_sod(
        sod_der,
        data_group_number,
        data_group_content,
    )
    .map_err(to_pyerr)
}

/// Perform complete native ICAO eMRTD verification.
///
/// The returned mapping is deliberately stable and contains both human-readable
/// errors and normalized status/code fields for service-layer adapters.
#[cfg(feature = "csca")]
#[pyfunction]
#[pyo3(signature = (sod_der, data_groups, registry, crls=None, country_hint=None))]
pub(super) fn verify_emrtd(
    py: Python<'_>,
    sod_der: &[u8],
    data_groups: std::collections::HashMap<u8, Vec<u8>>,
    registry: &PyCscaRegistry,
    crls: Option<Vec<Vec<u8>>>,
    country_hint: Option<String>,
) -> PyResult<Py<PyDict>> {
    use crate::verification::emrtd::{
        ChainStatus, EmrtdVerificationOptions, HashStatus, RevocationStatus, SecurityObject,
        SignatureStatus,
    };

    let sod = SecurityObject::from_sod_der(sod_der, country_hint).map_err(to_pyerr)?;
    let options = EmrtdVerificationOptions {
        crls: crls.unwrap_or_default(),
    };
    let result = crate::verification::emrtd::verify_emrtd_with_options(
        &sod,
        &data_groups,
        &registry.inner,
        &options,
    );

    let output = PyDict::new(py);
    output.set_item("verified", result.verified)?;
    output.set_item("country", result.country)?;
    output.set_item("document_type", result.document_type)?;
    output.set_item("errors", result.errors)?;
    output.set_item("error_codes", result.error_codes)?;
    output.set_item("warnings", result.warnings)?;
    output.set_item("trust_anchor_subject", result.trust_anchor_subject)?;
    output.set_item("certificate_chain", result.certificate_chain)?;
    output.set_item(
        "dsc_chain_status",
        match result.dsc_chain_status {
            ChainStatus::Valid => "valid",
            ChainStatus::Invalid => "invalid",
            ChainStatus::Unknown => "unknown",
        },
    )?;
    output.set_item(
        "sod_signature_status",
        match result.sod_signature_status {
            SignatureStatus::Valid => "valid",
            SignatureStatus::Invalid => "invalid",
            SignatureStatus::Unknown => "unknown",
        },
    )?;
    output.set_item(
        "dg_hash_status",
        match result.dg_hash_status {
            HashStatus::Valid => "valid",
            HashStatus::Invalid => "invalid",
            HashStatus::Unknown => "unknown",
        },
    )?;
    output.set_item(
        "revocation_status",
        match result.revocation_status {
            RevocationStatus::NotRevoked => "not_revoked",
            RevocationStatus::Revoked => "revoked",
            RevocationStatus::Unchecked => "unchecked",
        },
    )?;
    Ok(output.into())
}

/// Parse an ICAO CSCA Master List with the native CMS/X.509 implementation.
#[pyfunction]
pub(super) fn parse_master_list<'py>(
    py: Python<'py>,
    cms_der: &[u8],
) -> PyResult<Bound<'py, PyDict>> {
    let master_list = crate::asn1::master_list::parse_master_list(cms_der).map_err(to_pyerr)?;
    let result = PyDict::new(py);
    result.set_item("version", master_list.version)?;
    result.set_item("signer_certificate", master_list.signer_certificate)?;
    let certificates = PyList::empty(py);
    for certificate in master_list.certificates {
        let item = PyDict::new(py);
        item.set_item("subject", certificate.subject)?;
        item.set_item("issuer", certificate.issuer)?;
        item.set_item("serial_number", certificate.serial_number)?;
        item.set_item("country", certificate.country)?;
        item.set_item("not_before", certificate.not_before)?;
        item.set_item("not_after", certificate.not_after)?;
        item.set_item("der_bytes", PyBytes::new(py, &certificate.der_bytes))?;
        certificates.append(item)?;
    }
    result.set_item("certificates", certificates)?;
    Ok(result)
}

/// Verify an ICAO CSCA Master List CMS signature against a pinned signer certificate.
#[pyfunction]
pub(super) fn verify_master_list_signature(
    cms_der: &[u8],
    signer_cert_der: &[u8],
) -> PyResult<bool> {
    crate::asn1::master_list::verify_master_list_signature(cms_der, signer_cert_der)
        .map_err(to_pyerr)
}
