//! Operational proof through the same authenticated IPC and JOSE paths as the wallet.
use base64::Engine as _;
use marty_oid4vci::jose::{
    validate_public_signing_jwk_json, verify_detached_signature_with_public_jwk,
};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::signer_ipc::{request_signature, SignerAuthenticationKey, MAX_KEY_ID_BYTES};

#[derive(Debug, thiserror::Error)]
pub enum HolderSigningProbeError {
    #[error("Holder signing preflight public configuration is invalid")]
    Configuration,
    #[error("Holder signing preflight could not obtain an authenticated signature")]
    Signing,
    #[error(
        "Holder signing preflight signature does not verify against the configured public key"
    )]
    Verification,
}

/// Public, independently verifiable observations only; never a credential or demo pass.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderSigningProbeReceipt {
    pub schema_version: u8,
    pub scope: &'static str,
    pub production_demo_ready: bool,
    pub holder_key_id: String,
    pub public_jwk: Value,
    pub algorithm: &'static str,
    pub challenge: String,
    pub signature_base64url: String,
    pub verified: bool,
}

/// Sign a fresh, domain-separated non-JWT challenge and verify the actual result.
/// KMS credentials belong to the existing signer agent and are not arguments here.
pub async fn probe_holder_signing(
    endpoint: &str,
    authentication_key: &SignerAuthenticationKey,
    holder_key_id: &str,
    public_jwk_json: &str,
) -> Result<HolderSigningProbeReceipt, HolderSigningProbeError> {
    validate_public_signing_jwk_json(public_jwk_json, "ES256")
        .map_err(|_| HolderSigningProbeError::Configuration)?;
    let public_jwk: Value = serde_json::from_str(public_jwk_json)
        .map_err(|_| HolderSigningProbeError::Configuration)?;
    if holder_key_id.is_empty()
        || holder_key_id.len() > MAX_KEY_ID_BYTES
        || public_jwk["kty"] != "EC"
        || public_jwk["crv"] != "P-256"
    {
        return Err(HolderSigningProbeError::Configuration);
    }
    let challenge = format!(
        "marty-test-wallet/holder-signing-preflight/v1:{}",
        Uuid::new_v4()
    );
    let signature = request_signature(
        endpoint,
        authentication_key,
        "ES256",
        holder_key_id,
        challenge.as_bytes(),
    )
    .await
    .map_err(|_| HolderSigningProbeError::Signing)?;
    let verified = verify_detached_signature_with_public_jwk(
        challenge.as_bytes(),
        &signature,
        public_jwk_json,
        "ES256",
    )
    .map_err(|_| HolderSigningProbeError::Verification)?;
    if !verified {
        return Err(HolderSigningProbeError::Verification);
    }
    Ok(HolderSigningProbeReceipt {
        schema_version: 1,
        scope: "HOLDER_SIGNING_PREFLIGHT_ONLY",
        production_demo_ready: false,
        holder_key_id: holder_key_id.into(),
        // Retain only actual public key coordinates, not arbitrary caller metadata.
        public_jwk: serde_json::json!({"kty":"EC","crv":"P-256",
            "x":public_jwk["x"],"y":public_jwk["y"]}),
        algorithm: "ES256",
        challenge,
        signature_base64url: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature),
        verified,
    })
}
