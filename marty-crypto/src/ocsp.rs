//! OCSP (Online Certificate Status Protocol) request and response handling.
//!
//! This module provides OCSP functionality for certificate revocation checking,
//! replacing Python cryptography OCSP functionality.
//!
//! # Features
//!
//! - Build OCSP requests
//! - Parse OCSP responses
//! - Build OCSP responses (for testing)
//! - Certificate status checking
//!
//! # Example
//!
//! ```ignore
//! use marty_verification::crypto::ocsp::{OcspRequestBuilder, parse_ocsp_response, OcspCertStatus};
//!
//! // Build an OCSP request
//! let request_der = OcspRequestBuilder::new()
//!     .add_certificate(&cert_der, &issuer_cert_der)
//!     .build()?;
//!
//! // Parse an OCSP response
//! let response = parse_ocsp_response(&response_der)?;
//! match response.cert_status {
//!     OcspCertStatus::Good => println!("Certificate is valid"),
//!     OcspCertStatus::Revoked { .. } => println!("Certificate is revoked"),
//!     OcspCertStatus::Unknown => println!("Certificate status unknown"),
//! }
//! ```

use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspGeneralizedTime, OcspRequest, OcspResponse,
    OcspResponseStatus, Request, TbsRequest,
};

use crate::{CryptoError, CryptoResult};

// ============================================================================
// OCSP Certificate Status
// ============================================================================

/// OCSP certificate status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OcspCertStatus {
    /// Certificate is good (not revoked)
    Good,
    /// Certificate is revoked
    Revoked {
        /// Revocation time
        revocation_time: String,
        /// Revocation reason (if present)
        reason: Option<String>,
    },
    /// Certificate status is unknown
    Unknown,
}

/// OCSP response status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OcspResponseStatusCode {
    /// Response has valid confirmations
    Successful,
    /// Illegal confirmation request
    MalformedRequest,
    /// Internal error in issuer
    InternalError,
    /// Try again later
    TryLater,
    /// Must sign the request
    SigRequired,
    /// Request unauthorized
    Unauthorized,
}

impl OcspResponseStatusCode {
    /// Convert from x509-ocsp response status.
    fn from_ocsp_status(status: OcspResponseStatus) -> Self {
        match status {
            OcspResponseStatus::Successful => Self::Successful,
            OcspResponseStatus::MalformedRequest => Self::MalformedRequest,
            OcspResponseStatus::InternalError => Self::InternalError,
            OcspResponseStatus::TryLater => Self::TryLater,
            OcspResponseStatus::SigRequired => Self::SigRequired,
            OcspResponseStatus::Unauthorized => Self::Unauthorized,
        }
    }
}

/// Parsed OCSP response information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspResponseInfo {
    /// Response status
    pub response_status: OcspResponseStatusCode,
    /// Certificate status (only if response_status is Successful)
    pub cert_status: Option<OcspCertStatus>,
    /// This update time
    pub this_update: Option<String>,
    /// Next update time
    pub next_update: Option<String>,
    /// Responder ID (if available)
    pub responder_id: Option<String>,
    /// Produced at time
    pub produced_at: Option<String>,
}

// ============================================================================
// OCSP Request Builder
// ============================================================================

/// Entry for a certificate to query.
#[derive(Debug, Clone)]
struct CertQueryEntry {
    cert_der: Vec<u8>,
    issuer_der: Vec<u8>,
}

/// Builder for OCSP requests.
#[derive(Default)]
pub struct OcspRequestBuilder {
    certificates: Vec<CertQueryEntry>,
}

impl OcspRequestBuilder {
    /// Create a new OCSP request builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a certificate to query.
    ///
    /// # Arguments
    /// * `cert_der` - DER-encoded certificate to check
    /// * `issuer_cert_der` - DER-encoded issuer certificate
    pub fn add_certificate(mut self, cert_der: &[u8], issuer_cert_der: &[u8]) -> Self {
        self.certificates.push(CertQueryEntry {
            cert_der: cert_der.to_vec(),
            issuer_der: issuer_cert_der.to_vec(),
        });
        self
    }

    /// Build the OCSP request.
    ///
    /// # Returns
    /// DER-encoded OCSP request
    pub fn build(&self) -> CryptoResult<Vec<u8>> {
        if self.certificates.is_empty() {
            return Err(CryptoError::internal(
                "OCSP request must have at least one certificate",
            ));
        }

        let mut request_list = Vec::new();

        for entry in &self.certificates {
            let cert_id = self.build_cert_id(&entry.cert_der, &entry.issuer_der)?;
            request_list.push(Request {
                req_cert: cert_id,
                single_request_extensions: None,
            });
        }

        let tbs_request = TbsRequest {
            version: Default::default(),
            requestor_name: None,
            request_list,
            request_extensions: None,
        };

        let ocsp_request = OcspRequest {
            tbs_request,
            optional_signature: None,
        };

        ocsp_request
            .to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode OCSP request: {}", e)))
    }

    /// Build CertID for a certificate/issuer pair.
    fn build_cert_id(&self, cert_der: &[u8], issuer_der: &[u8]) -> CryptoResult<CertId> {
        use der::asn1::OctetString;
        use spki::AlgorithmIdentifierOwned;

        // Parse certificates
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| CryptoError::der_error(format!("Failed to parse certificate: {}", e)))?;
        let issuer = Certificate::from_der(issuer_der).map_err(|e| {
            CryptoError::der_error(format!("Failed to parse issuer certificate: {}", e))
        })?;

        // Hash algorithm (SHA-256)
        let hash_algorithm = AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };

        // Hash issuer name
        let issuer_name_der =
            issuer.tbs_certificate.subject.to_der().map_err(|e| {
                CryptoError::internal(format!("Failed to encode issuer name: {}", e))
            })?;
        let issuer_name_hash = Sha256::digest(&issuer_name_der);

        // Hash issuer public key
        let issuer_key_der = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let issuer_key_hash = Sha256::digest(issuer_key_der);

        Ok(CertId {
            hash_algorithm,
            issuer_name_hash: OctetString::new(issuer_name_hash.to_vec()).map_err(|e| {
                CryptoError::internal(format!("Failed to create octet string: {}", e))
            })?,
            issuer_key_hash: OctetString::new(issuer_key_hash.to_vec()).map_err(|e| {
                CryptoError::internal(format!("Failed to create octet string: {}", e))
            })?,
            serial_number: cert.tbs_certificate.serial_number.clone(),
        })
    }
}

// ============================================================================
// OCSP Response Parsing
// ============================================================================

/// Parse an OCSP response.
pub fn parse_ocsp_response(response_der: &[u8]) -> CryptoResult<OcspResponseInfo> {
    let response = OcspResponse::from_der(response_der)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse OCSP response: {}", e)))?;

    let response_status = OcspResponseStatusCode::from_ocsp_status(response.response_status);

    // If not successful, return early
    if response_status != OcspResponseStatusCode::Successful {
        return Ok(OcspResponseInfo {
            response_status,
            cert_status: None,
            this_update: None,
            next_update: None,
            responder_id: None,
            produced_at: None,
        });
    }

    // Parse the response bytes (BasicOCSPResponse)
    let response_bytes = response.response_bytes.ok_or_else(|| {
        CryptoError::internal("Missing response bytes in successful OCSP response")
    })?;

    // Check OID is id-pkix-ocsp-basic
    if response_bytes.response_type != const_oid::db::rfc6960::ID_PKIX_OCSP_BASIC {
        return Err(CryptoError::internal("Unsupported OCSP response type"));
    }

    let basic_response = BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .map_err(|e| CryptoError::der_error(format!("Failed to parse BasicOCSPResponse: {}", e)))?;

    let tbs = &basic_response.tbs_response_data;

    // Extract produced_at
    let produced_at = Some(format_ocsp_generalized_time(&tbs.produced_at));

    // Extract responder ID
    let responder_id = match &tbs.responder_id {
        x509_ocsp::ResponderId::ByName(name) => Some(name.to_string()),
        x509_ocsp::ResponderId::ByKey(key_hash) => Some(hex::encode(key_hash.as_bytes())),
    };

    // Get first response (typically there's only one)
    let single_response = tbs
        .responses
        .first()
        .ok_or_else(|| CryptoError::internal("No single responses in OCSP response"))?;

    // Extract certificate status
    let cert_status = match &single_response.cert_status {
        CertStatus::Good(_) => OcspCertStatus::Good,
        CertStatus::Revoked(revoked_info) => {
            let revocation_time = format_ocsp_generalized_time(&revoked_info.revocation_time);
            let reason = revoked_info.revocation_reason.as_ref().map(|r| {
                // Map CRL reason to string
                format!("{:?}", r)
            });
            OcspCertStatus::Revoked {
                revocation_time,
                reason,
            }
        }
        CertStatus::Unknown(_) => OcspCertStatus::Unknown,
    };

    // Extract this_update and next_update
    let this_update = Some(format_ocsp_generalized_time(&single_response.this_update));
    let next_update = single_response
        .next_update
        .as_ref()
        .map(format_ocsp_generalized_time);

    Ok(OcspResponseInfo {
        response_status,
        cert_status: Some(cert_status),
        this_update,
        next_update,
        responder_id,
        produced_at,
    })
}

/// Format GeneralizedTime to string.
fn format_generalized_time(time: &der::asn1::GeneralizedTime) -> String {
    time.to_date_time().to_string()
}

/// Format OcspGeneralizedTime to string.
fn format_ocsp_generalized_time(time: &x509_ocsp::OcspGeneralizedTime) -> String {
    format_generalized_time(&time.0)
}

/// Check if a certificate is revoked via OCSP response.
pub fn is_revoked_via_ocsp(response_der: &[u8]) -> CryptoResult<bool> {
    let response = parse_ocsp_response(response_der)?;

    match response.cert_status {
        Some(OcspCertStatus::Revoked { .. }) => Ok(true),
        Some(OcspCertStatus::Good) => Ok(false),
        Some(OcspCertStatus::Unknown) => Err(CryptoError::internal("OCSP returned unknown status")),
        None => Err(CryptoError::internal("OCSP response was not successful")),
    }
}

// ============================================================================
// OCSP Response Builder (for testing)
// ============================================================================

/// Builder for OCSP responses (primarily for testing).
pub struct OcspResponseBuilder {
    responder_cn: Option<String>,
    cert_status: OcspCertStatus,
    cert_der: Option<Vec<u8>>,
    issuer_der: Option<Vec<u8>>,
}

impl Default for OcspResponseBuilder {
    fn default() -> Self {
        Self {
            responder_cn: None,
            cert_status: OcspCertStatus::Good,
            cert_der: None,
            issuer_der: None,
        }
    }
}

impl OcspResponseBuilder {
    /// Create a new OCSP response builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the responder common name.
    pub fn responder_cn(mut self, cn: &str) -> Self {
        self.responder_cn = Some(cn.to_string());
        self
    }

    /// Set the certificate being responded about.
    pub fn certificate(mut self, cert_der: &[u8], issuer_der: &[u8]) -> Self {
        self.cert_der = Some(cert_der.to_vec());
        self.issuer_der = Some(issuer_der.to_vec());
        self
    }

    /// Set the certificate status to Good.
    pub fn status_good(mut self) -> Self {
        self.cert_status = OcspCertStatus::Good;
        self
    }

    /// Set the certificate status to Revoked.
    pub fn status_revoked(mut self, reason: Option<&str>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| format!("{}", d.as_secs()))
            .unwrap_or_else(|_| "0".to_string());

        self.cert_status = OcspCertStatus::Revoked {
            revocation_time: now,
            reason: reason.map(|s| s.to_string()),
        };
        self
    }

    /// Set the certificate status to Unknown.
    pub fn status_unknown(mut self) -> Self {
        self.cert_status = OcspCertStatus::Unknown;
        self
    }

    /// Build the OCSP response.
    ///
    /// # Arguments
    /// * `responder_key_pem` - PEM-encoded private key for signing the response
    ///
    /// # Returns
    /// DER-encoded OCSP response
    pub fn build(&self, responder_key_pem: &str) -> CryptoResult<Vec<u8>> {
        use der::asn1::{GeneralizedTime, Null, OctetString};
        use p256::ecdsa::SigningKey as P256SigningKey;
        use p256::pkcs8::DecodePrivateKey;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let cert_der = self
            .cert_der
            .as_ref()
            .ok_or_else(|| CryptoError::internal("Certificate required for OCSP response"))?;
        let issuer_der = self.issuer_der.as_ref().ok_or_else(|| {
            CryptoError::internal("Issuer certificate required for OCSP response")
        })?;

        // Parse certificates
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| CryptoError::der_error(format!("Failed to parse certificate: {}", e)))?;
        let issuer = Certificate::from_der(issuer_der).map_err(|e| {
            CryptoError::der_error(format!("Failed to parse issuer certificate: {}", e))
        })?;

        // Build CertId
        let hash_algorithm = spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };

        let issuer_name_der =
            issuer.tbs_certificate.subject.to_der().map_err(|e| {
                CryptoError::internal(format!("Failed to encode issuer name: {}", e))
            })?;
        let issuer_name_hash = Sha256::digest(&issuer_name_der);

        let issuer_key_der = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let issuer_key_hash = Sha256::digest(issuer_key_der);

        let cert_id = CertId {
            hash_algorithm: hash_algorithm.clone(),
            issuer_name_hash: OctetString::new(issuer_name_hash.to_vec()).map_err(|e| {
                CryptoError::internal(format!("Failed to create octet string: {}", e))
            })?,
            issuer_key_hash: OctetString::new(issuer_key_hash.to_vec()).map_err(|e| {
                CryptoError::internal(format!("Failed to create octet string: {}", e))
            })?,
            serial_number: cert.tbs_certificate.serial_number.clone(),
        };

        // Build times
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::internal("System time error"))?;

        let produced_at = GeneralizedTime::from_unix_duration(now)
            .map_err(|e| CryptoError::internal(format!("Invalid time: {}", e)))?;

        let this_update = produced_at;

        let next_update_duration = now + Duration::from_secs(7 * 24 * 60 * 60); // 7 days
        let next_update = GeneralizedTime::from_unix_duration(next_update_duration)
            .map_err(|e| CryptoError::internal(format!("Invalid time: {}", e)))?;

        // Build cert status
        let cert_status = match &self.cert_status {
            OcspCertStatus::Good => CertStatus::Good(Null),
            OcspCertStatus::Revoked { .. } => {
                let revoked_info = x509_ocsp::RevokedInfo {
                    revocation_time: OcspGeneralizedTime(produced_at),
                    revocation_reason: None,
                };
                CertStatus::Revoked(revoked_info)
            }
            OcspCertStatus::Unknown => CertStatus::Unknown(Null),
        };

        // Build single response
        let single_response = x509_ocsp::SingleResponse {
            cert_id,
            cert_status,
            this_update: OcspGeneralizedTime(this_update),
            next_update: Some(OcspGeneralizedTime(next_update)),
            single_extensions: None,
        };

        // Build responder ID
        let responder_id = x509_ocsp::ResponderId::ByName(issuer.tbs_certificate.subject.clone());

        // Build TBS response data
        let tbs_response_data = x509_ocsp::ResponseData {
            version: Default::default(),
            responder_id,
            produced_at: OcspGeneralizedTime(produced_at),
            responses: vec![single_response],
            response_extensions: None,
        };

        // Sign the response
        let tbs_der = tbs_response_data
            .to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode TBS: {}", e)))?;

        // Try P-256 key
        let (signature, sig_algorithm) =
            if let Ok(signing_key) = P256SigningKey::from_pkcs8_pem(responder_key_pem) {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::DerSignature = signing_key.sign(&tbs_der);
                let sig_alg = spki::AlgorithmIdentifierOwned {
                    oid: der::asn1::ObjectIdentifier::new("1.2.840.10045.4.3.2")
                        .map_err(|_| CryptoError::internal("Invalid OID"))?,
                    parameters: None,
                };
                (sig.as_bytes().to_vec(), sig_alg)
            } else {
                return Err(CryptoError::internal("Unable to parse responder key"));
            };

        let sig_bits = der::asn1::BitString::from_bytes(&signature)
            .map_err(|e| CryptoError::internal(format!("Failed to create signature: {}", e)))?;

        // Build BasicOCSPResponse
        let basic_response = BasicOcspResponse {
            tbs_response_data,
            signature_algorithm: sig_algorithm,
            signature: sig_bits,
            certs: None,
        };

        let basic_response_der = basic_response.to_der().map_err(|e| {
            CryptoError::internal(format!("Failed to encode BasicOCSPResponse: {}", e))
        })?;

        // Build complete OCSP response
        let response_bytes = x509_ocsp::ResponseBytes {
            response_type: const_oid::db::rfc6960::ID_PKIX_OCSP_BASIC,
            response: OctetString::new(basic_response_der).map_err(|e| {
                CryptoError::internal(format!("Failed to create response bytes: {}", e))
            })?,
        };

        let ocsp_response = OcspResponse {
            response_status: OcspResponseStatus::Successful,
            response_bytes: Some(response_bytes),
        };

        ocsp_response
            .to_der()
            .map_err(|e| CryptoError::internal(format!("Failed to encode OCSP response: {}", e)))
    }
}

/// Build a simple OCSP request for a certificate.
pub fn build_ocsp_request(cert_der: &[u8], issuer_cert_der: &[u8]) -> CryptoResult<Vec<u8>> {
    OcspRequestBuilder::new()
        .add_certificate(cert_der, issuer_cert_der)
        .build()
}

// ============================================================================
// OCSP Client (Async HTTP)
// ============================================================================

/// OCSP check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspCheckResult {
    /// Certificate status
    pub status: OcspCertStatus,
    /// This update time
    pub this_update: Option<String>,
    /// Next update time  
    pub next_update: Option<String>,
    /// Raw response (base64 encoded)
    pub raw_response: Option<String>,
}

/// Check certificate revocation status via OCSP.
///
/// This function performs an HTTP request to the OCSP responder.
///
/// # Arguments
/// * `cert_der` - DER-encoded certificate to check
/// * `issuer_cert_der` - DER-encoded issuer certificate
/// * `responder_url` - URL of the OCSP responder
///
/// # Returns
/// OCSP check result with certificate status.
#[cfg(feature = "aamva-client")]
pub async fn ocsp_check(
    cert_der: &[u8],
    issuer_cert_der: &[u8],
    responder_url: &str,
) -> CryptoResult<OcspCheckResult> {
    use base64::Engine;

    // Build OCSP request
    let request_der = build_ocsp_request(cert_der, issuer_cert_der)?;

    // Make HTTP POST request to OCSP responder
    let client = reqwest::Client::new();
    let response = client
        .post(responder_url)
        .header("Content-Type", "application/ocsp-request")
        .header("Accept", "application/ocsp-response")
        .body(request_der)
        .send()
        .await
        .map_err(|e| CryptoError::network_error(format!("OCSP request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(CryptoError::network_error(format!(
            "OCSP responder returned status: {}",
            response.status()
        )));
    }

    let response_bytes = response
        .bytes()
        .await
        .map_err(|e| CryptoError::network_error(format!("Failed to read OCSP response: {}", e)))?;

    // Parse the OCSP response
    let response_info = parse_ocsp_response(&response_bytes)?;

    let status = response_info.cert_status.unwrap_or(OcspCertStatus::Unknown);
    let raw_response = base64::engine::general_purpose::STANDARD.encode(&response_bytes);

    Ok(OcspCheckResult {
        status,
        this_update: response_info.this_update,
        next_update: response_info.next_update,
        raw_response: Some(raw_response),
    })
}

/// Check certificate revocation status via OCSP (GET method).
///
/// Uses HTTP GET with base64-encoded request in URL (per RFC 6960).
/// Useful when POST is not supported by the responder.
#[cfg(feature = "aamva-client")]
pub async fn ocsp_check_get(
    cert_der: &[u8],
    issuer_cert_der: &[u8],
    responder_url: &str,
) -> CryptoResult<OcspCheckResult> {
    use base64::Engine;

    // Build OCSP request
    let request_der = build_ocsp_request(cert_der, issuer_cert_der)?;

    // Base64 encode the request for URL
    let encoded_request = base64::engine::general_purpose::URL_SAFE.encode(&request_der);

    // Build URL
    let url = if responder_url.ends_with('/') {
        format!("{}{}", responder_url, encoded_request)
    } else {
        format!("{}/{}", responder_url, encoded_request)
    };

    // Make HTTP GET request
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("Accept", "application/ocsp-response")
        .send()
        .await
        .map_err(|e| CryptoError::network_error(format!("OCSP GET request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(CryptoError::network_error(format!(
            "OCSP responder returned status: {}",
            response.status()
        )));
    }

    let response_bytes = response
        .bytes()
        .await
        .map_err(|e| CryptoError::network_error(format!("Failed to read OCSP response: {}", e)))?;

    let response_info = parse_ocsp_response(&response_bytes)?;

    let status = response_info.cert_status.unwrap_or(OcspCertStatus::Unknown);
    let raw_response = base64::engine::general_purpose::STANDARD.encode(&response_bytes);

    Ok(OcspCheckResult {
        status,
        this_update: response_info.this_update,
        next_update: response_info.next_update,
        raw_response: Some(raw_response),
    })
}

/// Extract OCSP responder URL from certificate's AIA extension.
pub fn get_ocsp_responder_url(cert_der: &[u8]) -> CryptoResult<Option<String>> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse certificate: {}", e)))?;

    // Look for Authority Information Access extension
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            // AIA OID: 1.3.6.1.5.5.7.1.1
            if ext.extn_id == const_oid::db::rfc5912::ID_PE_AUTHORITY_INFO_ACCESS {
                // Parse AIA extension value
                if let Ok(aia) = x509_cert::ext::pkix::AuthorityInfoAccessSyntax::from_der(
                    ext.extn_value.as_bytes(),
                ) {
                    for access_desc in aia.0.iter() {
                        // OCSP access method: 1.3.6.1.5.5.7.48.1
                        if access_desc.access_method == const_oid::db::rfc5912::ID_AD_OCSP {
                            if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) = &access_desc.access_location {
                                return Ok(Some(uri.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

// ============================================================================
// OCSP Client with Caching
// ============================================================================

/// Cache key for OCSP responses - combination of cert serial and issuer key hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OcspCacheKey {
    /// Certificate serial number (hex encoded)
    pub serial_number: String,
    /// Issuer key hash (hex encoded)
    pub issuer_key_hash: String,
}

impl OcspCacheKey {
    /// Create a cache key from certificate and issuer DER bytes.
    pub fn from_certs(cert_der: &[u8], issuer_der: &[u8]) -> CryptoResult<Self> {
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| CryptoError::der_error(format!("Failed to parse certificate: {}", e)))?;
        let issuer = Certificate::from_der(issuer_der).map_err(|e| {
            CryptoError::der_error(format!("Failed to parse issuer certificate: {}", e))
        })?;

        let serial_number = cert
            .tbs_certificate
            .serial_number
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        let issuer_key_der = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let issuer_key_hash = hex::encode(Sha256::digest(issuer_key_der));

        Ok(Self {
            serial_number,
            issuer_key_hash,
        })
    }
}

/// Cached OCSP response entry.
#[derive(Debug, Clone)]
pub struct CachedOcspResponse {
    /// The OCSP check result
    pub result: OcspCheckResult,
    /// When this cache entry expires (based on nextUpdate)
    pub expires_at: std::time::Instant,
}

/// Configuration for the OCSP client.
#[derive(Debug, Clone)]
pub struct OcspClientConfig {
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Maximum cache entries
    pub max_cache_entries: u64,
    /// Default cache TTL when nextUpdate is not provided (seconds)
    pub default_cache_ttl_secs: u64,
    /// Whether to use HTTP GET method instead of POST
    pub use_get_method: bool,
}

impl Default for OcspClientConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            max_cache_entries: 1000,
            default_cache_ttl_secs: 3600, // 1 hour
            use_get_method: false,
        }
    }
}

/// OCSP client with async HTTP and caching support.
///
/// This client provides:
/// - Async HTTP requests to OCSP responders (POST or GET)
/// - In-memory LRU cache with TTL based on OCSP nextUpdate
/// - Configurable timeouts
/// - Session reuse via persistent reqwest::Client
#[cfg(feature = "ocsp-client")]
pub struct OcspClient {
    /// HTTP client with session reuse
    http_client: reqwest::Client,
    /// Response cache (key: cert serial + issuer key hash)
    cache: moka::future::Cache<String, CachedOcspResponse>,
    /// Configuration
    config: OcspClientConfig,
}

#[cfg(feature = "ocsp-client")]
impl OcspClient {
    /// Create a new OCSP client with default configuration.
    pub fn new() -> Self {
        Self::with_config(OcspClientConfig::default())
    }

    /// Create a new OCSP client with custom configuration.
    pub fn with_config(config: OcspClientConfig) -> Self {
        use std::time::Duration;

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let cache = moka::future::Cache::builder()
            .max_capacity(config.max_cache_entries)
            .time_to_live(Duration::from_secs(config.default_cache_ttl_secs))
            .build();

        Self {
            http_client,
            cache,
            config,
        }
    }

    /// Check certificate revocation status, using cache if available.
    ///
    /// # Arguments
    /// * `cert_der` - DER-encoded certificate to check
    /// * `issuer_cert_der` - DER-encoded issuer certificate
    /// * `responder_url` - URL of the OCSP responder (or None to use AIA extension)
    ///
    /// # Returns
    /// OCSP check result with certificate status and cache hit indicator.
    pub async fn check(
        &self,
        cert_der: &[u8],
        issuer_cert_der: &[u8],
        responder_url: Option<&str>,
    ) -> CryptoResult<(OcspCheckResult, bool)> {
        // Build cache key
        let cache_key = OcspCacheKey::from_certs(cert_der, issuer_cert_der)?;
        let key_string = format!("{}:{}", cache_key.serial_number, cache_key.issuer_key_hash);

        // Check cache first
        if let Some(cached) = self.cache.get(&key_string).await {
            if cached.expires_at > std::time::Instant::now() {
                return Ok((cached.result.clone(), true)); // Cache hit
            }
        }

        // Determine responder URL
        let url = match responder_url {
            Some(url) => url.to_string(),
            None => get_ocsp_responder_url(cert_der)?.ok_or_else(|| {
                CryptoError::internal("No OCSP responder URL found in certificate")
            })?,
        };

        // Perform OCSP check
        let result = if self.config.use_get_method {
            self.check_via_get(cert_der, issuer_cert_der, &url).await?
        } else {
            self.check_via_post(cert_der, issuer_cert_der, &url).await?
        };

        // Calculate cache TTL from nextUpdate
        let ttl = self.calculate_ttl(&result);
        let cached_entry = CachedOcspResponse {
            result: result.clone(),
            expires_at: std::time::Instant::now() + ttl,
        };

        // Store in cache
        self.cache.insert(key_string, cached_entry).await;

        Ok((result, false)) // Cache miss
    }

    /// Perform OCSP check via HTTP POST.
    async fn check_via_post(
        &self,
        cert_der: &[u8],
        issuer_cert_der: &[u8],
        responder_url: &str,
    ) -> CryptoResult<OcspCheckResult> {
        use base64::Engine;

        let request_der = build_ocsp_request(cert_der, issuer_cert_der)?;

        let response = self
            .http_client
            .post(responder_url)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .body(request_der)
            .send()
            .await
            .map_err(|e| CryptoError::network_error(format!("OCSP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(CryptoError::network_error(format!(
                "OCSP responder returned status: {}",
                response.status()
            )));
        }

        let response_bytes = response.bytes().await.map_err(|e| {
            CryptoError::network_error(format!("Failed to read OCSP response: {}", e))
        })?;

        let response_info = parse_ocsp_response(&response_bytes)?;
        let status = response_info.cert_status.unwrap_or(OcspCertStatus::Unknown);
        let raw_response = base64::engine::general_purpose::STANDARD.encode(&response_bytes);

        Ok(OcspCheckResult {
            status,
            this_update: response_info.this_update,
            next_update: response_info.next_update,
            raw_response: Some(raw_response),
        })
    }

    /// Perform OCSP check via HTTP GET.
    async fn check_via_get(
        &self,
        cert_der: &[u8],
        issuer_cert_der: &[u8],
        responder_url: &str,
    ) -> CryptoResult<OcspCheckResult> {
        use base64::Engine;

        let request_der = build_ocsp_request(cert_der, issuer_cert_der)?;
        let encoded_request = base64::engine::general_purpose::URL_SAFE.encode(&request_der);

        let url = if responder_url.ends_with('/') {
            format!("{}{}", responder_url, encoded_request)
        } else {
            format!("{}/{}", responder_url, encoded_request)
        };

        let response = self
            .http_client
            .get(&url)
            .header("Accept", "application/ocsp-response")
            .send()
            .await
            .map_err(|e| CryptoError::network_error(format!("OCSP GET request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(CryptoError::network_error(format!(
                "OCSP responder returned status: {}",
                response.status()
            )));
        }

        let response_bytes = response.bytes().await.map_err(|e| {
            CryptoError::network_error(format!("Failed to read OCSP response: {}", e))
        })?;

        let response_info = parse_ocsp_response(&response_bytes)?;
        let status = response_info.cert_status.unwrap_or(OcspCertStatus::Unknown);
        let raw_response = base64::engine::general_purpose::STANDARD.encode(&response_bytes);

        Ok(OcspCheckResult {
            status,
            this_update: response_info.this_update,
            next_update: response_info.next_update,
            raw_response: Some(raw_response),
        })
    }

    /// Calculate cache TTL from OCSP response nextUpdate field.
    fn calculate_ttl(&self, result: &OcspCheckResult) -> std::time::Duration {
        use std::time::Duration;

        if let Some(next_update) = &result.next_update {
            // Try to parse nextUpdate as RFC 3339 datetime
            if let Ok(next_update_dt) = chrono::DateTime::parse_from_rfc3339(next_update) {
                let now = chrono::Utc::now();
                let next_update_utc = next_update_dt.with_timezone(&chrono::Utc);
                if next_update_utc > now {
                    let duration = (next_update_utc - now).num_seconds() as u64;
                    return Duration::from_secs(duration);
                }
            }
        }

        // Fall back to default TTL
        Duration::from_secs(self.config.default_cache_ttl_secs)
    }

    /// Clear the cache.
    pub async fn clear_cache(&self) {
        self.cache.invalidate_all();
        self.cache.run_pending_tasks().await;
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> (u64, u64) {
        (self.cache.entry_count(), self.config.max_cache_entries)
    }
}

#[cfg(feature = "ocsp-client")]
impl Default for OcspClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_request_builder_basic() {
        // Test that an empty builder fails
        let builder = OcspRequestBuilder::new();
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_ocsp_response_status_variants() {
        // Test all response status codes
        let codes = [
            OcspResponseStatusCode::Successful,
            OcspResponseStatusCode::MalformedRequest,
            OcspResponseStatusCode::InternalError,
            OcspResponseStatusCode::TryLater,
            OcspResponseStatusCode::SigRequired,
            OcspResponseStatusCode::Unauthorized,
        ];
        assert_eq!(codes.len(), 6);
    }

    #[test]
    fn test_ocsp_cert_status_variants() {
        let good = OcspCertStatus::Good;
        let revoked = OcspCertStatus::Revoked {
            revocation_time: "2024-01-01T00:00:00Z".to_string(),
            reason: Some("keyCompromise".to_string()),
        };
        let unknown = OcspCertStatus::Unknown;

        assert_eq!(good, OcspCertStatus::Good);
        assert!(matches!(revoked, OcspCertStatus::Revoked { .. }));
        assert_eq!(unknown, OcspCertStatus::Unknown);
    }

    #[cfg(feature = "ocsp-client")]
    #[test]
    fn test_ocsp_client_config_defaults() {
        let config = OcspClientConfig::default();
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.max_cache_entries, 1000);
        assert_eq!(config.default_cache_ttl_secs, 3600);
        assert!(!config.use_get_method);
    }
}

#[cfg(all(test, feature = "cert-builder"))]
mod tests_with_cert_builder {
    use super::*;
    use crate::cert_builder::{create_ca_certificate, create_signed_certificate};
    use crate::keygen::KeyType;

    #[test]
    fn test_ocsp_request_builder() {
        // Create CA and leaf certificate
        let (ca_cert_der, ca_key_pem) =
            create_ca_certificate("OCSP Test CA", Some("US"), 365, KeyType::EcdsaP256)
                .expect("Failed to create CA");

        let (leaf_cert_der, _) = create_signed_certificate(
            "OCSP Test Leaf",
            &ca_cert_der,
            &ca_key_pem,
            365,
            false,
            KeyType::EcdsaP256,
        )
        .expect("Failed to create leaf cert");

        // Build OCSP request
        let request_der = OcspRequestBuilder::new()
            .add_certificate(&leaf_cert_der, &ca_cert_der)
            .build()
            .expect("Failed to build OCSP request");

        assert!(!request_der.is_empty());

        // Verify we can parse it back
        let _request = OcspRequest::from_der(&request_der).expect("Failed to parse OCSP request");
    }

    #[test]
    fn test_ocsp_response_builder() {
        // Create CA and leaf certificate
        let (ca_cert_der, ca_key_pem) =
            create_ca_certificate("OCSP Responder CA", Some("US"), 365, KeyType::EcdsaP256)
                .expect("Failed to create CA");

        let (leaf_cert_der, _) = create_signed_certificate(
            "OCSP Test Subject",
            &ca_cert_der,
            &ca_key_pem,
            365,
            false,
            KeyType::EcdsaP256,
        )
        .expect("Failed to create leaf cert");

        // Build OCSP response (Good status)
        let response_der = OcspResponseBuilder::new()
            .certificate(&leaf_cert_der, &ca_cert_der)
            .status_good()
            .build(&ca_key_pem)
            .expect("Failed to build OCSP response");

        // Parse and verify
        let response_info =
            parse_ocsp_response(&response_der).expect("Failed to parse OCSP response");

        assert_eq!(
            response_info.response_status,
            OcspResponseStatusCode::Successful
        );
        assert_eq!(response_info.cert_status, Some(OcspCertStatus::Good));
    }

    #[test]
    fn test_ocsp_revoked_status() {
        let (ca_cert_der, ca_key_pem) =
            create_ca_certificate("OCSP Revoked CA", None, 365, KeyType::EcdsaP256)
                .expect("Failed to create CA");

        let (leaf_cert_der, _) = create_signed_certificate(
            "Revoked Cert",
            &ca_cert_der,
            &ca_key_pem,
            365,
            false,
            KeyType::EcdsaP256,
        )
        .expect("Failed to create leaf cert");

        // Build OCSP response (Revoked status)
        let response_der = OcspResponseBuilder::new()
            .certificate(&leaf_cert_der, &ca_cert_der)
            .status_revoked(Some("keyCompromise"))
            .build(&ca_key_pem)
            .expect("Failed to build OCSP response");

        // Check revocation
        assert!(is_revoked_via_ocsp(&response_der).unwrap());
    }
}
