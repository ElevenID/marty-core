//! OID4VP verifier identity kernels.
//!
//! Certificate parsing, key matching, thumbprint construction, and `x5c`
//! shaping are security-sensitive protocol operations. Keep them here so
//! language adapters only load configuration and transport structured values.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use der::DecodePem;
use p256::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::jwk::{base64url_decode, Jwk};

const MAX_CERTIFICATE_BUNDLE_BYTES: usize = 512 * 1024;
const MAX_CERTIFICATE_COUNT: usize = 16;
const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// Stable failures from OID4VP verifier identity construction.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Oid4vpIdentityError {
    #[error("OID4VP.X509_BUNDLE_TOO_LARGE: certificate bundle exceeds {MAX_CERTIFICATE_BUNDLE_BYTES} bytes")]
    BundleTooLarge,
    #[error("OID4VP.X509_CERTIFICATE_MISSING: certificate bundle contains no PEM certificate")]
    CertificateMissing,
    #[error("OID4VP.X509_CERTIFICATE_LIMIT: certificate bundle exceeds {MAX_CERTIFICATE_COUNT} certificates")]
    CertificateLimit,
    #[error("OID4VP.X509_CERTIFICATE_INVALID: certificate {index} is invalid: {reason}")]
    CertificateInvalid { index: usize, reason: String },
    #[error("OID4VP.X509_LEAF_KEY_UNSUPPORTED: leaf certificate must contain a P-256 public key")]
    UnsupportedLeafKey,
    #[error("OID4VP.X509_PUBLIC_JWK_INVALID: {0}")]
    InvalidPublicJwk(String),
    #[error("OID4VP.X509_PUBLIC_KEY_MISMATCH: leaf certificate public key does not match the issuer profile signing identity")]
    PublicKeyMismatch,
}

/// Canonical `x509_hash` client identifier and JOSE certificate chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X509HashClientIdentity {
    pub client_id: String,
    pub x5c: Vec<String>,
}

/// Build an OID4VP `x509_hash` identity from a leaf-first PEM bundle.
///
/// The final certificate is omitted from `x5c` when it is self-issued, matching
/// HAIP's requirement that trust anchors come from the verifier's trust store.
pub fn x509_hash_client_identity(
    certificate_bundle_pem: &str,
    public_jwk: &Jwk,
) -> Result<X509HashClientIdentity, Oid4vpIdentityError> {
    let certificates = parse_certificate_bundle(certificate_bundle_pem)?;
    let leaf = &certificates[0];
    let profile_public_key = p256_public_key_from_jwk(public_jwk)?;
    let leaf_public_key = p256_public_key_from_certificate(leaf)?;
    if leaf_public_key != profile_public_key {
        return Err(Oid4vpIdentityError::PublicKeyMismatch);
    }

    let leaf_der =
        der::Encode::to_der(leaf).map_err(|error| Oid4vpIdentityError::CertificateInvalid {
            index: 0,
            reason: error.to_string(),
        })?;
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(&leaf_der));

    let mut header_certificates = certificates.as_slice();
    if certificates.len() > 1 {
        let final_certificate = certificates.last().expect("non-empty certificate bundle");
        if final_certificate.tbs_certificate.issuer == final_certificate.tbs_certificate.subject {
            header_certificates = &certificates[..certificates.len() - 1];
        }
    }

    let x5c = header_certificates
        .iter()
        .enumerate()
        .map(|(index, certificate)| {
            der::Encode::to_der(certificate)
                .map(|der| STANDARD.encode(der))
                .map_err(|error| Oid4vpIdentityError::CertificateInvalid {
                    index,
                    reason: error.to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(X509HashClientIdentity {
        client_id: format!("x509_hash:{digest}"),
        x5c,
    })
}

fn parse_certificate_bundle(
    certificate_bundle_pem: &str,
) -> Result<Vec<Certificate>, Oid4vpIdentityError> {
    if certificate_bundle_pem.len() > MAX_CERTIFICATE_BUNDLE_BYTES {
        return Err(Oid4vpIdentityError::BundleTooLarge);
    }

    let mut remaining = certificate_bundle_pem;
    let mut certificates = Vec::new();
    while let Some(begin) = remaining.find(PEM_BEGIN) {
        let certificate_start = &remaining[begin..];
        let end = certificate_start.find(PEM_END).ok_or_else(|| {
            Oid4vpIdentityError::CertificateInvalid {
                index: certificates.len(),
                reason: "PEM end marker is missing".to_owned(),
            }
        })? + PEM_END.len();
        if certificates.len() == MAX_CERTIFICATE_COUNT {
            return Err(Oid4vpIdentityError::CertificateLimit);
        }
        let pem = &certificate_start[..end];
        let certificate = Certificate::from_pem(pem).map_err(|error| {
            Oid4vpIdentityError::CertificateInvalid {
                index: certificates.len(),
                reason: error.to_string(),
            }
        })?;
        certificates.push(certificate);
        remaining = &certificate_start[end..];
    }

    if certificates.is_empty() {
        return Err(Oid4vpIdentityError::CertificateMissing);
    }
    Ok(certificates)
}

fn p256_public_key_from_jwk(public_jwk: &Jwk) -> Result<PublicKey, Oid4vpIdentityError> {
    if public_jwk.is_private() {
        return Err(Oid4vpIdentityError::InvalidPublicJwk(
            "public JWK contains private key material".to_owned(),
        ));
    }
    if public_jwk.kty != "EC" || public_jwk.crv.as_deref() != Some("P-256") {
        return Err(Oid4vpIdentityError::InvalidPublicJwk(
            "issuer profile must publish an EC P-256 public JWK".to_owned(),
        ));
    }
    let x = decode_coordinate(public_jwk.x.as_deref(), "x")?;
    let y = decode_coordinate(public_jwk.y.as_deref(), "y")?;
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    PublicKey::from_sec1_bytes(&point).map_err(|error| {
        Oid4vpIdentityError::InvalidPublicJwk(format!("invalid P-256 point: {error}"))
    })
}

fn decode_coordinate(value: Option<&str>, name: &str) -> Result<Vec<u8>, Oid4vpIdentityError> {
    let value = value.ok_or_else(|| {
        Oid4vpIdentityError::InvalidPublicJwk(format!("public JWK is missing {name}"))
    })?;
    let decoded = base64url_decode(value).map_err(|error| {
        Oid4vpIdentityError::InvalidPublicJwk(format!("invalid {name} coordinate: {error}"))
    })?;
    if decoded.len() != 32 {
        return Err(Oid4vpIdentityError::InvalidPublicJwk(format!(
            "P-256 {name} coordinate must be 32 bytes"
        )));
    }
    Ok(decoded)
}

fn p256_public_key_from_certificate(
    certificate: &Certificate,
) -> Result<PublicKey, Oid4vpIdentityError> {
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != const_oid::db::rfc5912::ID_EC_PUBLIC_KEY
        || spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.decode_as::<const_oid::ObjectIdentifier>().ok())
            != Some(const_oid::db::rfc5912::SECP_256_R_1)
    {
        return Err(Oid4vpIdentityError::UnsupportedLeafKey);
    }
    PublicKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
        .map_err(|_| Oid4vpIdentityError::UnsupportedLeafKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::sec1::ToEncodedPoint;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    fn public_jwk(key: &KeyPair) -> Jwk {
        let public = PublicKey::from_sec1_bytes(key.public_key_raw()).unwrap();
        let point = public.to_encoded_point(false);
        Jwk {
            kty: "EC".to_owned(),
            crv: Some("P-256".to_owned()),
            x: Some(URL_SAFE_NO_PAD.encode(point.x().unwrap())),
            y: Some(URL_SAFE_NO_PAD.encode(point.y().unwrap())),
            ..Jwk::default()
        }
    }

    fn certificate_bundle() -> (String, Jwk, Vec<u8>) {
        let mut root_params = CertificateParams::default();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "OID4VP Root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_key = KeyPair::generate().unwrap();
        let root = root_params.self_signed(&root_key).unwrap();

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "OID4VP Verifier");
        let leaf_key = KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&root_params, &root_key);
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        (
            format!("{}\n{}", leaf.pem(), root.pem()),
            public_jwk(&leaf_key),
            leaf.der().to_vec(),
        )
    }

    #[test]
    fn builds_hash_and_omits_self_signed_root_from_x5c() {
        let (bundle, jwk, leaf_der) = certificate_bundle();
        let result = x509_hash_client_identity(&bundle, &jwk).unwrap();
        assert_eq!(
            result.client_id,
            format!(
                "x509_hash:{}",
                URL_SAFE_NO_PAD.encode(Sha256::digest(&leaf_der))
            )
        );
        assert_eq!(result.x5c, vec![STANDARD.encode(leaf_der)]);
    }

    #[test]
    fn rejects_mismatched_or_private_profile_keys() {
        let (bundle, _, _) = certificate_bundle();
        let other_key = KeyPair::generate().unwrap();
        assert_eq!(
            x509_hash_client_identity(&bundle, &public_jwk(&other_key)).unwrap_err(),
            Oid4vpIdentityError::PublicKeyMismatch
        );

        let mut private = public_jwk(&other_key);
        private.d = Some("secret".to_owned());
        assert!(matches!(
            x509_hash_client_identity(&bundle, &private),
            Err(Oid4vpIdentityError::InvalidPublicJwk(_))
        ));
    }

    #[test]
    fn rejects_missing_malformed_and_oversized_bundles() {
        assert_eq!(
            x509_hash_client_identity("not a certificate", &Jwk::default()).unwrap_err(),
            Oid4vpIdentityError::CertificateMissing
        );
        assert!(matches!(
            x509_hash_client_identity(PEM_BEGIN, &Jwk::default()),
            Err(Oid4vpIdentityError::CertificateInvalid { .. })
        ));
        let oversized = "x".repeat(MAX_CERTIFICATE_BUNDLE_BYTES + 1);
        assert_eq!(
            x509_hash_client_identity(&oversized, &Jwk::default()).unwrap_err(),
            Oid4vpIdentityError::BundleTooLarge
        );
    }
}
