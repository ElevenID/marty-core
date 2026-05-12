//! Format-specific credential construction and signing.
//!
//! Dispatches to the correct signing pipeline based on the requested credential format:
//! - `jwt_vc_json` → W3C VC-JWT
//! - `vc+sd-jwt` → IETF SD-JWT with selective disclosure
//! - `mso_mdoc` → ISO 18013-5 CBOR/COSE
//! - `zk_mdoc` → ISO 18013-5 mDoc with ZK proof capability (Longfellow/Ligero)
//! - `vds_nc` → ICAO 9303 VDS-NC barcode payload

pub mod jwt_vc;
pub mod mdoc;
pub mod sd_jwt;
pub mod vds_nc;
pub mod zk_mdoc;

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::signer::CredentialSigner;
use crate::types::{CredentialClaims, CredentialFormat, IssuerKey, SignedCredential};

/// Sign a credential in the requested format.
///
/// This is the central dispatch function that routes to the correct signing
/// pipeline based on the `format` parameter. All format-specific complexity
/// is handled internally.
pub fn sign_credential(
    format: &CredentialFormat,
    issuer_key: &IssuerKey,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    match format {
        CredentialFormat::JwtVcJson => jwt_vc::sign_jwt_vc(issuer_key, claims),
        CredentialFormat::SdJwt => sd_jwt::sign_sd_jwt(issuer_key, claims),
        CredentialFormat::MsoMdoc => mdoc::sign_mdoc(issuer_key, claims),
        CredentialFormat::ZkMdoc => zk_mdoc::sign_zk_mdoc(issuer_key, claims),
        CredentialFormat::VdsNc => vds_nc::sign_vds_nc(issuer_key, claims),
    }
}

/// Sign a credential using any [`CredentialSigner`] implementation.
///
/// This is the BYOK-aware entry point. Pass an `&IssuerKey` for local JWK
/// signing, or a custom [`CredentialSigner`] for HSM/KMS-backed signing.
pub fn sign_credential_with_signer(
    format: &CredentialFormat,
    signer: &dyn CredentialSigner,
    claims: &CredentialClaims,
) -> Oid4vciResult<SignedCredential> {
    match format {
        CredentialFormat::JwtVcJson => jwt_vc::sign_jwt_vc_with_signer(signer, claims),
        CredentialFormat::SdJwt => sd_jwt::sign_sd_jwt_with_signer(signer, claims),
        CredentialFormat::MsoMdoc => mdoc::sign_mdoc_with_signer(signer, claims),
        CredentialFormat::ZkMdoc => zk_mdoc::sign_zk_mdoc_with_signer(signer, claims),
        CredentialFormat::VdsNc => vds_nc::sign_vds_nc_with_signer(signer, claims),
    }
}

/// Negotiate the best credential format from what the issuer supports and what the
/// holder requested.
pub fn negotiate_format(
    requested: Option<&str>,
    supported: &[CredentialFormat],
) -> Oid4vciResult<CredentialFormat> {
    if let Some(req) = requested {
        let format = CredentialFormat::from_str_loose(req).ok_or_else(|| {
            Oid4vciError::UnsupportedFormat(format!(
                "Unknown format '{}'. Supported: jwt_vc_json, spruce-vc+sd-jwt, mso_mdoc, zk_mdoc, vds_nc",
                req
            ))
        })?;

        if supported.contains(&format) {
            Ok(format)
        } else {
            Err(Oid4vciError::UnsupportedFormat(format!(
                "Format '{}' is not supported by this issuer. Supported: {:?}",
                req,
                supported.iter().map(|f| f.as_str()).collect::<Vec<_>>()
            )))
        }
    } else {
        // Default to the first supported format
        supported.first().cloned().ok_or_else(|| {
            Oid4vciError::ConfigError("No credential formats configured".into())
        })
    }
}
