//! Fail-closed classification and normalization for wallet QR/deep-link input.
//!
//! This module is intentionally network-free. It identifies protocol envelopes
//! and normalizes credential-offer handoffs before a wallet elects to resolve
//! any by-reference object through [`crate::wallet::WalletEngine`].

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Oid4vciError, Oid4vciResult};

/// Maximum accepted QR/deep-link input size.
pub const MAX_WALLET_INPUT_BYTES: usize = 64 * 1024;
const MAX_WRAPPER_DEPTH: usize = 4;
const CREDENTIAL_OFFER_SCHEME: &str = "openid-credential-offer";

/// Protocol-aware classification of a wallet input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletInputKind {
    CredentialOffer,
    PresentationRequest,
    MdocDeviceEngagement,
}

/// A recognized wallet input with its canonical handoff value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedWalletInput {
    pub kind: WalletInputKind,
    pub normalized: String,
}

/// Classify supported OID4VC and ISO 18013 QR/deep-link inputs without I/O.
///
/// Unknown generic URLs and documents return `Ok(None)`. Inputs claiming a
/// supported protocol scheme are rejected when malformed or unsupported.
pub fn classify_wallet_input(input: &str) -> Oid4vciResult<Option<ClassifiedWalletInput>> {
    classify_wallet_input_inner(input, 0)
}

/// Normalize a credential-offer handoff to the standard
/// `openid-credential-offer://` envelope.
///
/// Bare HTTPS offer endpoints become by-reference offers. Inline JSON becomes
/// a by-value offer. Wallet wrapper and Android intent links are unwrapped with
/// a strict recursion limit.
pub fn normalize_credential_offer_uri(input: &str) -> Oid4vciResult<String> {
    normalize_credential_offer_uri_inner(input, 0)
}

fn classify_wallet_input_inner(
    input: &str,
    depth: usize,
) -> Oid4vciResult<Option<ClassifiedWalletInput>> {
    let raw = checked_input(input, depth)?;

    if raw.starts_with("mdoc:") {
        return Ok(Some(ClassifiedWalletInput {
            kind: WalletInputKind::MdocDeviceEngagement,
            normalized: raw.to_owned(),
        }));
    }

    if is_inline_credential_offer(raw) {
        return Ok(Some(ClassifiedWalletInput {
            kind: WalletInputKind::CredentialOffer,
            normalized: normalize_credential_offer_uri_inner(raw, depth)?,
        }));
    }

    let parsed = match Url::parse(raw) {
        Ok(parsed) => parsed,
        Err(_) if raw.starts_with("openid") || raw.starts_with("haip-vci:") => {
            return Err(invalid("Malformed OID4VC wallet input"));
        }
        Err(_) => return Ok(None),
    };
    let scheme = parsed.scheme().to_ascii_lowercase();

    if is_wallet_wrapper(&scheme) {
        if has_any_query(&parsed, &["offer_uri", "offer", "credential_offer_uri"]) {
            return Ok(Some(ClassifiedWalletInput {
                kind: WalletInputKind::CredentialOffer,
                normalized: normalize_credential_offer_uri_inner(raw, depth)?,
            }));
        }
        let nested = first_query_value(&parsed, &["inner", "uri"])
            .ok_or_else(|| invalid("Wallet wrapper does not contain a nested URI"))?;
        return classify_wallet_input_inner(&nested, depth + 1);
    }

    if scheme == "intent" {
        if has_any_query(&parsed, &["credential_offer_uri", "credential_offer"])
            || intent_fragment_scheme(parsed.fragment()).as_deref() == Some(CREDENTIAL_OFFER_SCHEME)
        {
            return Ok(Some(ClassifiedWalletInput {
                kind: WalletInputKind::CredentialOffer,
                normalized: normalize_credential_offer_uri_inner(raw, depth)?,
            }));
        }
        if let Some(nested) = first_query_value(&parsed, &["inner", "uri"]) {
            return classify_wallet_input_inner(&nested, depth + 1);
        }
        return Ok(None);
    }

    if matches!(
        scheme.as_str(),
        CREDENTIAL_OFFER_SCHEME | "haip-vci" | "openid-vc"
    ) {
        return Ok(Some(ClassifiedWalletInput {
            kind: WalletInputKind::CredentialOffer,
            normalized: normalize_credential_offer_uri_inner(raw, depth)?,
        }));
    }

    if scheme == "openid4vp" {
        ensure_presentation_parameters(&parsed)?;
        return Ok(Some(ClassifiedWalletInput {
            kind: WalletInputKind::PresentationRequest,
            normalized: raw.to_owned(),
        }));
    }

    if scheme == "http" || scheme == "https" {
        if has_any_query(&parsed, &["credential_offer", "credential_offer_uri"])
            || credential_offer_path(&parsed)
        {
            return Ok(Some(ClassifiedWalletInput {
                kind: WalletInputKind::CredentialOffer,
                normalized: normalize_credential_offer_uri_inner(raw, depth)?,
            }));
        }
        if has_any_query(
            &parsed,
            &[
                "request_uri",
                "request",
                "presentation_definition",
                "presentation_definition_uri",
                "dcql_query",
            ],
        ) || parsed
            .path()
            .to_ascii_lowercase()
            .contains("presentation-request")
        {
            return Ok(Some(ClassifiedWalletInput {
                kind: WalletInputKind::PresentationRequest,
                normalized: raw.to_owned(),
            }));
        }
        return Ok(None);
    }

    if scheme.starts_with("openid") || scheme == "haip-vci" {
        return Err(invalid(format!(
            "Unsupported wallet protocol scheme: {scheme}"
        )));
    }

    Ok(None)
}

fn normalize_credential_offer_uri_inner(input: &str, depth: usize) -> Oid4vciResult<String> {
    let raw = checked_input(input, depth)?;
    if is_inline_credential_offer(raw) {
        return Ok(credential_offer_envelope("credential_offer", raw));
    }

    let parsed = Url::parse(raw)
        .map_err(|error| invalid(format!("Invalid credential offer URI: {error}")))?;
    let scheme = parsed.scheme().to_ascii_lowercase();

    if is_wallet_wrapper(&scheme) {
        let nested = first_query_value(
            &parsed,
            &["inner", "uri", "offer_uri", "offer", "credential_offer_uri"],
        )
        .ok_or_else(|| invalid("Wallet wrapper does not contain a credential offer"))?;
        return normalize_credential_offer_uri_inner(&nested, depth + 1);
    }

    if scheme == "intent" {
        if let Some(value) = first_query_value(&parsed, &["credential_offer_uri"]) {
            return normalize_offer_reference_or_envelope(&value, depth + 1);
        }
        if let Some(value) = first_query_value(&parsed, &["credential_offer"]) {
            return normalize_offer_value_or_envelope(&value, depth + 1);
        }
        if intent_fragment_scheme(parsed.fragment()).as_deref() == Some(CREDENTIAL_OFFER_SCHEME)
            && parsed.query().is_some()
        {
            return Ok(format!(
                "{CREDENTIAL_OFFER_SCHEME}://?{}",
                parsed.query().unwrap_or_default()
            ));
        }
        return Err(invalid(
            "Android intent does not contain a credential offer",
        ));
    }

    if scheme == "openid-vc" {
        // Microsoft issuance handoffs are provider-specific. Preserve the
        // envelope for the external adapter; never reinterpret it as standard
        // OID4VCI JSON.
        if first_query_value(&parsed, &["request_uri"]).is_none() {
            return Err(invalid("openid-vc input is missing request_uri"));
        }
        return Ok(raw.to_owned());
    }

    if scheme == CREDENTIAL_OFFER_SCHEME || scheme == "haip-vci" {
        if let Some(value) = first_query_value(&parsed, &["credential_offer_uri"]) {
            return normalize_offer_reference_or_envelope(&value, depth + 1);
        }
        if let Some(value) = first_query_value(&parsed, &["credential_offer"]) {
            return normalize_offer_value_or_envelope(&value, depth + 1);
        }
        if let Some(value) = first_query_value(&parsed, &["inner", "uri"]) {
            return normalize_credential_offer_uri_inner(&value, depth + 1);
        }
        return Err(invalid("Credential offer URI contains no offer parameter"));
    }

    if scheme == "http" || scheme == "https" {
        if let Some(value) = first_query_value(&parsed, &["credential_offer_uri"]) {
            return normalize_offer_reference_or_envelope(&value, depth + 1);
        }
        if let Some(value) = first_query_value(&parsed, &["credential_offer"]) {
            return normalize_offer_value_or_envelope(&value, depth + 1);
        }
        return Ok(credential_offer_envelope("credential_offer_uri", raw));
    }

    Err(invalid(format!(
        "Unsupported credential offer scheme: {scheme}"
    )))
}

fn normalize_offer_reference_or_envelope(value: &str, depth: usize) -> Oid4vciResult<String> {
    if looks_like_offer_envelope(value) {
        normalize_credential_offer_uri_inner(value, depth)
    } else {
        let parsed = Url::parse(value)
            .map_err(|_| invalid("credential_offer_uri must be an absolute URI"))?;
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(invalid("credential_offer_uri must use HTTP(S)"));
        }
        Ok(credential_offer_envelope("credential_offer_uri", value))
    }
}

fn normalize_offer_value_or_envelope(value: &str, depth: usize) -> Oid4vciResult<String> {
    if looks_like_offer_envelope(value) {
        return normalize_credential_offer_uri_inner(value, depth);
    }
    if !is_json_object(value) {
        return Err(invalid("credential_offer must be a JSON object"));
    }
    Ok(credential_offer_envelope("credential_offer", value))
}

fn checked_input(input: &str, depth: usize) -> Oid4vciResult<&str> {
    if depth > MAX_WRAPPER_DEPTH {
        return Err(invalid("Wallet input wrapper depth exceeded"));
    }
    let raw = input.trim();
    if raw.is_empty() {
        return Err(invalid("Wallet input is empty"));
    }
    if raw.len() > MAX_WALLET_INPUT_BYTES {
        return Err(invalid("Wallet input exceeds the maximum size"));
    }
    if raw.contains('\0') {
        return Err(invalid("Wallet input contains a NUL byte"));
    }
    Ok(raw)
}

fn ensure_presentation_parameters(parsed: &Url) -> Oid4vciResult<()> {
    if has_any_query(
        parsed,
        &[
            "request_uri",
            "request",
            "presentation_definition",
            "presentation_definition_uri",
            "dcql_query",
        ],
    ) {
        Ok(())
    } else {
        Err(invalid(
            "Presentation request contains no request or query parameter",
        ))
    }
}

fn first_query_value(parsed: &Url, keys: &[&str]) -> Option<String> {
    parsed
        .query_pairs()
        .find(|(key, value)| keys.contains(&key.as_ref()) && !value.trim().is_empty())
        .map(|(_, value)| value.into_owned())
}

fn has_any_query(parsed: &Url, keys: &[&str]) -> bool {
    first_query_value(parsed, keys).is_some()
}

fn is_wallet_wrapper(scheme: &str) -> bool {
    matches!(scheme, "marty-authenticator" | "martywallet")
}

fn looks_like_offer_envelope(value: &str) -> bool {
    Url::parse(value)
        .map(|parsed| {
            matches!(
                parsed.scheme().to_ascii_lowercase().as_str(),
                CREDENTIAL_OFFER_SCHEME
                    | "haip-vci"
                    | "openid-vc"
                    | "marty-authenticator"
                    | "martywallet"
                    | "intent"
            )
        })
        .unwrap_or(false)
}

fn credential_offer_path(parsed: &Url) -> bool {
    let path = parsed.path().to_ascii_lowercase();
    path.contains("credential-offer") || path.contains("/offers/")
}

fn is_inline_credential_offer(value: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(value)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .and_then(|object| object.get("credential_issuer").cloned())
        .and_then(|issuer| issuer.as_str().map(str::to_owned))
        .is_some()
}

fn is_json_object(value: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(value)
        .map(|value| value.is_object())
        .unwrap_or(false)
}

fn credential_offer_envelope(key: &str, value: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair(key, value)
        .finish();
    format!("{CREDENTIAL_OFFER_SCHEME}://?{query}")
}

fn intent_fragment_scheme(fragment: Option<&str>) -> Option<String> {
    fragment?.split(';').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == "scheme").then(|| value.to_ascii_lowercase())
    })
}

fn invalid(message: impl Into<String>) -> Oid4vciError {
    Oid4vciError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_by_reference_and_by_value_offers() {
        assert_eq!(
            normalize_credential_offer_uri("https://issuer.example/offers/123").unwrap(),
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123"
        );

        let offer = r#"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{}}"#;
        let normalized = normalize_credential_offer_uri(offer).unwrap();
        let parsed = Url::parse(&normalized).unwrap();
        assert_eq!(
            first_query_value(&parsed, &["credential_offer"]).as_deref(),
            Some(offer)
        );
    }

    #[test]
    fn unwraps_wallet_and_android_intent_links() {
        let inner = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123";
        let wrapped = format!(
            "martywallet://open?inner={}",
            url::form_urlencoded::byte_serialize(inner.as_bytes()).collect::<String>()
        );
        assert_eq!(normalize_credential_offer_uri(&wrapped).unwrap(), inner);

        let wrapped_reference =
            "martywallet://open?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fref";
        let classified = classify_wallet_input(wrapped_reference).unwrap().unwrap();
        assert_eq!(classified.kind, WalletInputKind::CredentialOffer);
        assert_eq!(
            classified.normalized,
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fref"
        );

        let intent = "intent://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F123#Intent;scheme=openid-credential-offer;package=example;end";
        assert_eq!(normalize_credential_offer_uri(intent).unwrap(), inner);
    }

    #[test]
    fn classifies_supported_protocol_inputs() {
        let offer = classify_wallet_input("https://issuer.example/offers/123")
            .unwrap()
            .unwrap();
        assert_eq!(offer.kind, WalletInputKind::CredentialOffer);
        assert!(offer.normalized.starts_with("openid-credential-offer://"));

        let request = classify_wallet_input(
            "openid4vp://?client_id=wallet&request_uri=https%3A%2F%2Fverifier.example%2Frequest",
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.kind, WalletInputKind::PresentationRequest);

        let mdoc = classify_wallet_input("mdoc:owBjMS4w").unwrap().unwrap();
        assert_eq!(mdoc.kind, WalletInputKind::MdocDeviceEngagement);
    }

    #[test]
    fn generic_and_malformed_inputs_fail_safely() {
        assert!(classify_wallet_input("https://example.com/")
            .unwrap()
            .is_none());
        assert!(classify_wallet_input("plain text").unwrap().is_none());
        assert!(classify_wallet_input("openid4vp://").is_err());
        assert!(normalize_credential_offer_uri("javascript:alert(1)").is_err());
        assert!(classify_wallet_input(&"x".repeat(MAX_WALLET_INPUT_BYTES + 1)).is_err());
    }

    #[test]
    fn wrapper_depth_is_bounded() {
        let mut value = "https://issuer.example/offers/123".to_owned();
        for _ in 0..=MAX_WRAPPER_DEPTH {
            let encoded =
                url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
            value = format!("marty-authenticator://open?inner={encoded}");
        }
        assert!(classify_wallet_input(&value).is_err());
    }

    #[test]
    fn preserves_provider_specific_openid_vc_handoff() {
        let input = "openid-vc://?request_uri=https%3A%2F%2Fissuer.example%2FissuanceRequests%2F1";
        let classified = classify_wallet_input(input).unwrap().unwrap();
        assert_eq!(classified.kind, WalletInputKind::CredentialOffer);
        assert_eq!(classified.normalized, input);
    }
}
