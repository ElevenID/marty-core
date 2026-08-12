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
pub mod vds_nc_profile;
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
        supported
            .first()
            .cloned()
            .ok_or_else(|| Oid4vciError::ConfigError("No credential formats configured".into()))
    }
}

/// Return canonical OID4VP/DCQL metadata for an application credential profile.
///
/// Application-facing profile aliases are accepted only at this boundary. The
/// returned values are the exact wire-format and credential types emitted by
/// the corresponding Rust issuer profile.
pub fn credential_profile_presentation_metadata(
    profile: &str,
    credential_format: &str,
    type_identifier: &str,
) -> Oid4vciResult<serde_json::Value> {
    match profile.trim().to_ascii_lowercase().as_str() {
        "open_badge" | "open_badge_v3" | "openbadge-v3" | "openbadgecredential" => {
            match credential_format.trim().to_ascii_lowercase().as_str() {
                "jwt_vp" | "jwt_vc" | "jwt_vc_json" => Ok(serde_json::json!({
                    "format": CredentialFormat::JwtVcJson.as_str(),
                    "meta": {
                        "type_values": [[
                            "VerifiableCredential",
                            jwt_vc::OPEN_BADGES_V3_CREDENTIAL_TYPE,
                        ]],
                    },
                })),
                "sd_jwt_vc" | "vc+sd-jwt" | "dc+sd-jwt" => {
                    let type_identifier = type_identifier.trim();
                    if type_identifier.is_empty() {
                        return Err(Oid4vciError::ConfigError(
                            "Open Badge SD-JWT presentation metadata requires a vct".into(),
                        ));
                    }
                    let mut vct_values = vec![type_identifier];
                    const LEGACY_OPEN_BADGE_VCT: &str =
                        "https://marty.example/credentials/open_badge";
                    if type_identifier != LEGACY_OPEN_BADGE_VCT {
                        vct_values.push(LEGACY_OPEN_BADGE_VCT);
                    }
                    Ok(serde_json::json!({
                        "format": CredentialFormat::SdJwt.as_str(),
                        "meta": {"vct_values": vct_values},
                    }))
                }
                _ => Err(Oid4vciError::UnsupportedFormat(format!(
                    "Unsupported Open Badge presentation format: {credential_format}"
                ))),
            }
        }
        _ => Err(Oid4vciError::UnsupportedFormat(format!(
            "Unsupported credential presentation profile: {profile}"
        ))),
    }
}

#[cfg(test)]
mod presentation_metadata_tests {
    use super::*;

    #[test]
    fn open_badge_aliases_resolve_to_the_issued_ob3_wire_contract() {
        for profile in [
            "open_badge",
            "open_badge_v3",
            "openbadge-v3",
            "OpenBadgeCredential",
        ] {
            let metadata =
                credential_profile_presentation_metadata(profile, "jwt_vc_json", "").unwrap();
            assert_eq!(metadata["format"], "jwt_vc_json");
            assert_eq!(
                metadata["meta"]["type_values"],
                serde_json::json!([["VerifiableCredential", "OpenBadgeCredential"]])
            );
        }
    }

    #[test]
    fn unknown_presentation_profile_fails_closed() {
        let error = credential_profile_presentation_metadata("unknown-profile", "jwt_vc_json", "")
            .unwrap_err();
        assert!(matches!(error, Oid4vciError::UnsupportedFormat(_)));
    }

    #[test]
    fn legacy_open_badge_sd_jwt_metadata_preserves_current_and_legacy_vcts() {
        let metadata = credential_profile_presentation_metadata(
            "open_badge",
            "dc+sd-jwt",
            "https://beta.elevenidllc.com/credentials/marty-verified-member-badge",
        )
        .unwrap();
        assert_eq!(metadata["format"], "dc+sd-jwt");
        assert_eq!(
            metadata["meta"]["vct_values"],
            serde_json::json!([
                "https://beta.elevenidllc.com/credentials/marty-verified-member-badge",
                "https://marty.example/credentials/open_badge",
            ])
        );
    }

    #[test]
    fn open_badge_metadata_rejects_unsupported_formats_and_missing_vct() {
        assert!(credential_profile_presentation_metadata("open_badge", "ldp_vc", "").is_err());
        assert!(credential_profile_presentation_metadata("open_badge", "dc+sd-jwt", "").is_err());
    }
}
