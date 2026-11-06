//! Canonical credential-format routing.
//!
//! Detection only selects the verifier. It does not establish authenticity;
//! the selected verifier must still validate the full credential and proof.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const OB2_CONTEXT: &str = "https://w3id.org/openbadges/v2";
const OB3_CONTEXTS: [&str; 3] = [
    "https://purl.imsglobal.org/spec/ob/v3p0/context.json",
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
    "https://w3id.org/openbadges/v3",
];

/// Credential format selected for downstream cryptographic verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectedCredentialFormat {
    W3cVc,
    W3cVcdmDi,
    SdJwt,
    Mdoc,
    OpenbadgeV3,
    Unknown,
}

impl DetectedCredentialFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::W3cVc => "w3c-vc",
            Self::W3cVcdmDi => "w3c-vcdm-di",
            Self::SdJwt => "sd-jwt",
            Self::Mdoc => "mdoc",
            Self::OpenbadgeV3 => "openbadge-v3",
            Self::Unknown => "unknown",
        }
    }
}

/// Identify retired OB2 assertions before choosing a supported verifier.
///
/// This recognizes legacy context/type markers in raw credentials and common
/// request/presentation envelopes. JWT claims are decoded only for rejection;
/// this does not verify a signature or convert a credential.
/// Mixed OB2/OB3 markers remain retired and must not reach another verifier.
pub fn is_retired_ob2(value: &Value) -> bool {
    match value {
        Value::Array(values) => return values.iter().any(is_retired_ob2),
        Value::String(token) => {
            let issuer_token = token.split('~').next().unwrap_or_default();
            return decode_jwt_parts(issuer_token)
                .is_some_and(|(_, payload)| is_retired_ob2(&payload));
        }
        _ => {}
    }
    if ["@context", "context"].iter().any(|field| {
        string_values(value.get(*field))
            .iter()
            .any(|context| context == OB2_CONTEXT)
    }) || string_values(value.get("type")).iter().any(|kind| {
        matches!(
            kind.chars()
                .filter(char::is_ascii_alphanumeric)
                .flat_map(char::to_lowercase)
                .collect::<String>()
                .as_str(),
            "assertion" | "openbadgev2"
        )
    }) {
        return true;
    }
    [
        "credential",
        "vc",
        "assertion",
        "vp",
        "verifiableCredential",
    ]
    .iter()
    .any(|field| value.get(*field).is_some_and(is_retired_ob2))
}

/// Detect the credential format without accepting malformed candidates.
pub fn detect_credential_format(input: &str) -> DetectedCredentialFormat {
    let input = input.trim();
    if input.is_empty() {
        return DetectedCredentialFormat::Unknown;
    }

    if let Ok(value) = serde_json::from_str::<Value>(input) {
        return detect_json(&value);
    }
    if input.contains('~') {
        return detect_sd_jwt(input);
    }
    if input.matches('.').count() == 2 {
        return detect_jwt(input);
    }
    if input.starts_with("\\x") {
        return DetectedCredentialFormat::Mdoc;
    }

    let candidate = input
        .strip_prefix("mso_mdoc:")
        .or_else(|| input.strip_prefix("mdoc:"))
        .unwrap_or(input);
    if !candidate.contains('.') && !candidate.contains('~') {
        if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(candidate) {
            if crate::mdoc::parse_device_response(&bytes).is_ok() {
                return DetectedCredentialFormat::Mdoc;
            }
        }
    }
    DetectedCredentialFormat::Unknown
}

fn detect_sd_jwt(input: &str) -> DetectedCredentialFormat {
    let issuer_jwt = input.split('~').next().unwrap_or_default();
    let Some((_, payload)) = decode_jwt_parts(issuer_jwt) else {
        return DetectedCredentialFormat::Unknown;
    };
    if is_retired_ob2(&payload) {
        return DetectedCredentialFormat::Unknown;
    }
    DetectedCredentialFormat::SdJwt
}

fn detect_jwt(input: &str) -> DetectedCredentialFormat {
    let Some((header, payload)) = decode_jwt_parts(input) else {
        return DetectedCredentialFormat::Unknown;
    };
    if is_retired_ob2(&payload) {
        return DetectedCredentialFormat::Unknown;
    }
    if header.get("typ").and_then(Value::as_str) == Some("openBadgeCredential") {
        return DetectedCredentialFormat::OpenbadgeV3;
    }
    let credential = payload.get("vc").unwrap_or(&payload);
    match detect_json(credential) {
        DetectedCredentialFormat::OpenbadgeV3 => DetectedCredentialFormat::OpenbadgeV3,
        _ if credential.is_object() => DetectedCredentialFormat::W3cVc,
        _ => DetectedCredentialFormat::Unknown,
    }
}

fn decode_jwt_parts(input: &str) -> Option<(Value, Value)> {
    let mut parts = input.split('.');
    let header = decode_json_segment(parts.next()?)?;
    let payload = decode_json_segment(parts.next()?)?;
    let signature = parts.next()?;
    if signature.is_empty() || parts.next().is_some() {
        return None;
    }
    Some((header, payload))
}

fn decode_json_segment(segment: &str) -> Option<Value> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn detect_json(value: &Value) -> DetectedCredentialFormat {
    if is_retired_ob2(value) {
        return DetectedCredentialFormat::Unknown;
    }
    let credential = value.get("credential").unwrap_or(value);
    let has_data_integrity = match credential.get("proof") {
        Some(Value::Object(proof)) => {
            proof.get("type").and_then(Value::as_str) == Some("DataIntegrityProof")
        }
        Some(Value::Array(proofs)) => proofs
            .iter()
            .any(|proof| proof.get("type").and_then(Value::as_str) == Some("DataIntegrityProof")),
        _ => false,
    };
    if has_data_integrity {
        return DetectedCredentialFormat::W3cVcdmDi;
    }

    let contexts = string_values(credential.get("@context"));
    let types = string_values(credential.get("type"));
    if types.iter().any(|value| {
        matches!(
            value.as_str(),
            "OpenBadgeCredential" | "AchievementCredential"
        )
    }) || contexts
        .iter()
        .any(|value| OB3_CONTEXTS.contains(&value.as_str()))
    {
        return DetectedCredentialFormat::OpenbadgeV3;
    }
    DetectedCredentialFormat::Unknown
}

fn string_values(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(header: Value, payload: Value) -> String {
        let encode = |value: Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        };
        format!("{}.{}.signature", encode(header), encode(payload))
    }

    #[test]
    fn detects_open_badges_from_signed_jwt_payload_not_only_header() {
        let token = jwt(
            serde_json::json!({"alg": "ES256", "typ": "vc+jwt"}),
            serde_json::json!({
                "vc": {
                    "@context": [
                        "https://www.w3.org/ns/credentials/v2",
                        "https://purl.imsglobal.org/spec/ob/v3p0/context.json"
                    ],
                    "type": ["VerifiableCredential", "OpenBadgeCredential"],
                    "credentialSubject": {"type": "AchievementSubject"}
                }
            }),
        );
        assert_eq!(
            detect_credential_format(&token),
            DetectedCredentialFormat::OpenbadgeV3
        );
    }

    #[test]
    fn generic_and_malformed_jwts_fail_to_the_narrowest_safe_route() {
        let generic = jwt(
            serde_json::json!({"alg": "ES256", "typ": "vc+jwt"}),
            serde_json::json!({"vc": {"type": ["VerifiableCredential"]}}),
        );
        assert_eq!(
            detect_credential_format(&generic),
            DetectedCredentialFormat::W3cVc
        );
        assert_eq!(
            detect_credential_format("not-json.not-json.signature"),
            DetectedCredentialFormat::Unknown
        );
        assert_eq!(
            detect_credential_format("not-a-jwt~disclosure~"),
            DetectedCredentialFormat::Unknown
        );
    }

    #[test]
    fn detects_json_open_badges_and_data_integrity_documents() {
        assert_eq!(
            detect_credential_format(
                &serde_json::json!({
                    "credential": {
                        "@context": ["https://w3id.org/openbadges/v2"]
                    }
                })
                .to_string()
            ),
            DetectedCredentialFormat::Unknown
        );
        assert_eq!(
            detect_credential_format(
                &serde_json::json!({
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "proof": {"type": "DataIntegrityProof"}
                })
                .to_string()
            ),
            DetectedCredentialFormat::W3cVcdmDi
        );
    }
}
