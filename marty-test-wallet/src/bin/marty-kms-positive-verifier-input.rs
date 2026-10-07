//! Build fresh public verifier input through the remote issuer and wallet signers.
//!
//! This non-publishable acceptance tool never generates or accepts private keys.
//! Its two authenticated IPC endpoints must be backed by separately scoped KMS
//! signer agents. It writes only the presentation and issuer public JWK to stdout.

use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use marty_oid4vci::{
    formats::sd_jwt::assemble_sd_jwt,
    remote_credential::{prepare_remote_sd_jwt, RemoteSdJwtRequest},
    types::{SignedCredential, SigningAlgorithm},
    wallet::WalletEngine,
    Oid4vciResult, ResolvedSdJwtIssuerKey, SdJwtIssuerKeyResolver,
};
use marty_test_wallet::signer_ipc::{request_signature, SignerAuthenticationKey};
use serde_json::{json, Value};
use zeroize::Zeroizing;

const ISSUER: &str = "did:example:verifier-runtime-gate-issuer";
const HOLDER: &str = "did:example:runtime-gate-holder";
const NONCE: &str = "runtime-gate-nonce-with-at-least-32-bytes";
const AUDIENCE: &str = "https://verifier.runtime-gate.invalid";
const MAX_PUBLIC_JWK_BYTES: usize = 4096;

struct FixedIssuerResolver {
    public_jwk_json: String,
}

impl SdJwtIssuerKeyResolver for FixedIssuerResolver {
    fn resolve(
        &self,
        issuer: &str,
        key_id: Option<&str>,
        algorithm: SigningAlgorithm,
    ) -> Oid4vciResult<ResolvedSdJwtIssuerKey> {
        if issuer != ISSUER || key_id != Some(ISSUER) || algorithm != SigningAlgorithm::ES256 {
            return Err(marty_oid4vci::Oid4vciError::KeyError(
                "positive gate issuer identity mismatch".into(),
            ));
        }
        Ok(ResolvedSdJwtIssuerKey::new(
            ISSUER,
            Some(ISSUER.into()),
            SigningAlgorithm::ES256,
            self.public_jwk_json.clone(),
        ))
    }
}

fn required_env(name: &'static str) -> Result<String, &'static str> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(name)
}

fn public_jwk(name: &'static str, issuer: bool) -> Result<Value, &'static str> {
    let encoded = required_env(name)?;
    if encoded.len() > MAX_PUBLIC_JWK_BYTES {
        return Err("public JWK exceeds its size limit");
    }
    let value: Value =
        serde_json::from_str(&encoded).map_err(|_| "public JWK is not valid JSON")?;
    let object = value.as_object().ok_or("public JWK must be an object")?;
    let required: &[&str] = &["kty", "crv", "x", "y"];
    let allowed: &[&str] = &["kty", "crv", "x", "y", "kid", "alg"];
    if !required.iter().all(|member| object.contains_key(*member))
        || !object
            .keys()
            .all(|member| allowed.contains(&member.as_str()))
        || (issuer && object.len() != allowed.len())
    {
        return Err("public JWK contains missing or unsupported members");
    }
    if value["kty"] != "EC" || value["crv"] != "P-256" {
        return Err("public JWK must be P-256");
    }
    if issuer && (value["kid"] != ISSUER || value["alg"] != "ES256") {
        return Err("issuer public JWK identity mismatch");
    }
    for coordinate in ["x", "y"] {
        let encoded = value[coordinate]
            .as_str()
            .ok_or("public JWK coordinate is invalid")?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "public JWK coordinate is invalid")?;
        if decoded.len() != 32 {
            return Err("public JWK coordinate is invalid");
        }
    }
    if issuer {
        Ok(value)
    } else {
        // The shared wallet accepts an optional public kid/alg. The confirmation
        // JWK carries only the point, as the verifier's original vector did.
        if value.get("alg").is_some_and(|alg| alg != "ES256") {
            return Err("holder public JWK algorithm mismatch");
        }
        if let Some(kid) = value.get("kid") {
            let allowed_kid = required_env("MARTY_TEST_WALLET_HOLDER_KID")?;
            if kid != &allowed_kid {
                return Err("holder public JWK key identifier mismatch");
            }
        }
        Ok(json!({
            "kty": "EC", "crv": "P-256", "x": value["x"], "y": value["y"]
        }))
    }
}

async fn remote_sign(
    endpoint_name: &'static str,
    auth_name: &'static str,
    kid_name: &'static str,
    payload: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let endpoint = required_env(endpoint_name)?;
    let key_id = required_env(kid_name)?;
    let encoded_auth = Zeroizing::new(required_env(auth_name)?);
    let auth = SignerAuthenticationKey::from_base64url(&encoded_auth)
        .map_err(|_| "signer authentication configuration is invalid")?;
    request_signature(&endpoint, &auth, "ES256", &key_id, payload)
        .await
        .map_err(|_| "remote signer rejected exact signing input")
}

async fn produce() -> Result<Value, &'static str> {
    let issuer_public = public_jwk("MARTY_POSITIVE_GATE_ISSUER_PUBLIC_JWK", true)?;
    let holder_public = public_jwk("MARTY_TEST_WALLET_HOLDER_PUBLIC_JWK", false)?;
    if required_env("MARTY_POSITIVE_GATE_ISSUER_KID")? != ISSUER {
        return Err("issuer signer key identifier mismatch");
    }
    let holder_kid = required_env("MARTY_TEST_WALLET_HOLDER_KID")?;
    if holder_kid != HOLDER && !holder_kid.starts_with(&format!("{HOLDER}#")) {
        return Err("holder key identifier mismatch");
    }
    if issuer_public["x"] == holder_public["x"] && issuer_public["y"] == holder_public["y"] {
        return Err("issuer and holder must use separate KMS keys");
    }

    let prepared = prepare_remote_sd_jwt(RemoteSdJwtRequest {
        issuer_id: ISSUER.into(),
        verification_method_id: ISSUER.into(),
        algorithm: "ES256".into(),
        issuer_public_jwk: issuer_public.to_string(),
        subject_id: Some(HOLDER.into()),
        credential_type: "RuntimeGateCredential".into(),
        claims: HashMap::from([("email".into(), json!("runtime-gate@example.invalid"))]),
        expiration_seconds: Some(600),
        selective_disclosure_claims: vec!["email".into()],
        credential_format: Some("vc+sd-jwt".into()),
        credential_id: None,
        holder_jwk: Some(holder_public.clone()),
        issuer_certificate_chain: Vec::new(),
    })
    .map_err(|_| "remote credential preparation failed")?;
    let issuer_signature = remote_sign(
        "MARTY_POSITIVE_GATE_ISSUER_SIGNER_ENDPOINT",
        "MARTY_POSITIVE_GATE_ISSUER_SIGNER_AUTHENTICATION_KEY",
        "MARTY_POSITIVE_GATE_ISSUER_KID",
        prepared.signing_payload(),
    )
    .await?;
    let credential = match assemble_sd_jwt(prepared, &issuer_signature)
        .map_err(|_| "remote issuer signature rejected")?
    {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => return Err("remote issuer returned another credential format"),
    };

    let resolver = FixedIssuerResolver {
        public_jwk_json: issuer_public.to_string(),
    };
    let prepared = WalletEngine::new()
        .prepare_verified_sd_jwt_presentation(
            &credential,
            &["email".into()],
            NONCE,
            AUDIENCE,
            &holder_public.to_string(),
            &resolver,
        )
        .map_err(|_| "wallet rejected issued credential or holder binding")?;
    let holder_signature = remote_sign(
        "MARTY_TEST_WALLET_HOLDER_SIGNER_ENDPOINT",
        "MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY",
        "MARTY_TEST_WALLET_HOLDER_KID",
        prepared.signing_input(),
    )
    .await?;
    let presentation = prepared
        .complete(&holder_signature)
        .map_err(|_| "remote holder signature rejected")?;
    Ok(json!({
        "presentation": presentation,
        "issuer_public_jwk": issuer_public,
    }))
}

#[tokio::main]
async fn main() {
    match produce().await {
        Ok(public_input) => println!("{public_input}"),
        Err(message) => {
            eprintln!("KMS positive verifier input unavailable: {message}");
            std::process::exit(2);
        }
    }
}
