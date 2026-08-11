//! Canonical device-registration proof and key-eligibility decisions.
//!
//! Storage, challenge allocation, and compare-and-swap key rotation remain
//! service concerns. This module owns deterministic key parsing, thumbprints,
//! challenge messages, proof verification, and transition eligibility.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, FixedOffset};
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::DecodePublicKey,
    traits::PublicKeyParts,
    RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CHALLENGE_AUDIENCE: &str = "marty-device-registration";
pub const MAX_KEY_VERSION: u64 = 9_007_199_254_740_991;
pub const MAX_ROTATION_GRACE_SECONDS: u64 = 900;
const MAX_ENCODED_KEY_BYTES: usize = 16 * 1024;
const MAX_CHALLENGE_MESSAGE_BYTES: usize = 16 * 1024;
const MIN_RSA_BITS: usize = 2048;
const MAX_RSA_BITS: usize = 8192;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeviceAuthError {
    #[error("DEVICE_AUTH.INVALID_BASE64URL: {0}")]
    InvalidBase64Url(&'static str),
    #[error("DEVICE_AUTH.INVALID_PUBLIC_KEY: {0}")]
    InvalidPublicKey(&'static str),
    #[error("DEVICE_AUTH.UNSUPPORTED_KEY: {0}")]
    UnsupportedKey(String),
    #[error("DEVICE_AUTH.PUBLIC_KEY_KID_MISMATCH: public_key_kid must be the RFC 7638 thumbprint of public_key_der")]
    PublicKeyKidMismatch,
    #[error("DEVICE_AUTH.INVALID_CHALLENGE: {0}")]
    InvalidChallenge(String),
    #[error("DEVICE_AUTH.INVALID_SIGNATURE: device challenge signature is invalid")]
    InvalidSignature,
    #[error("DEVICE_AUTH.INVALID_TIMESTAMP: {0}")]
    InvalidTimestamp(String),
    #[error("DEVICE_AUTH.SERIALIZATION_FAILED: {0}")]
    SerializationFailed(String),
}

pub type DeviceAuthResult<T> = Result<T, DeviceAuthError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DevicePublicKeyInspection {
    pub public_key_kid: String,
    pub public_key_sha256: String,
    pub key_bits: usize,
}

struct ParsedDevicePublicKey {
    raw_der: Vec<u8>,
    key: RsaPublicKey,
    inspection: DevicePublicKeyInspection,
}

fn decode_base64url(value: &str, kind: &'static str, max_len: usize) -> DeviceAuthResult<Vec<u8>> {
    if value.is_empty() || value.len() > max_len {
        return Err(DeviceAuthError::InvalidBase64Url(kind));
    }
    let padding = value.len() - value.trim_end_matches('=').len();
    let unpadded = value.trim_end_matches('=');
    if padding > 2
        || unpadded.contains('=')
        || !unpadded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DeviceAuthError::InvalidBase64Url(kind));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(unpadded)
        .map_err(|_| DeviceAuthError::InvalidBase64Url(kind))?;
    if decoded.is_empty() || URL_SAFE_NO_PAD.encode(&decoded) != unpadded {
        return Err(DeviceAuthError::InvalidBase64Url(kind));
    }
    Ok(decoded)
}

fn parse_device_public_key(encoded: &str) -> DeviceAuthResult<ParsedDevicePublicKey> {
    let raw_der = decode_base64url(encoded, "public_key_der", MAX_ENCODED_KEY_BYTES)?;
    let key = match RsaPublicKey::from_pkcs1_der(&raw_der) {
        Ok(key) => key,
        Err(_) if RsaPublicKey::from_public_key_der(&raw_der).is_ok() => {
            return Err(DeviceAuthError::InvalidPublicKey(
                "public_key_der must use canonical PKCS#1 DER encoding",
            ));
        }
        Err(_) => {
            return Err(DeviceAuthError::InvalidPublicKey(
                "public_key_der must contain a valid RSA public key",
            ));
        }
    };
    let canonical = key.to_pkcs1_der().map_err(|_| {
        DeviceAuthError::InvalidPublicKey("public_key_der could not be canonicalized")
    })?;
    if canonical.as_bytes() != raw_der {
        return Err(DeviceAuthError::InvalidPublicKey(
            "public_key_der must use canonical PKCS#1 DER encoding",
        ));
    }
    let key_bits = key.n().bits();
    if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&key_bits) {
        return Err(DeviceAuthError::UnsupportedKey(format!(
            "device RSA public keys must be at least {MIN_RSA_BITS} bits and no more than {MAX_RSA_BITS} bits"
        )));
    }
    let modulus = URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
    let exponent = URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
    let canonical_jwk = format!(r#"{{"e":"{exponent}","kty":"RSA","n":"{modulus}"}}"#);
    let inspection = DevicePublicKeyInspection {
        public_key_kid: URL_SAFE_NO_PAD.encode(Sha256::digest(canonical_jwk.as_bytes())),
        public_key_sha256: hex::encode(Sha256::digest(&raw_der)),
        key_bits,
    };
    Ok(ParsedDevicePublicKey {
        raw_der,
        key,
        inspection,
    })
}

pub fn inspect_device_public_key(encoded: &str) -> DeviceAuthResult<DevicePublicKeyInspection> {
    Ok(parse_device_public_key(encoded)?.inspection)
}

pub fn validate_device_public_key(
    encoded: &str,
    claimed_kid: &str,
) -> DeviceAuthResult<DevicePublicKeyInspection> {
    let inspection = inspect_device_public_key(encoded)?;
    if !constant_time_eq(&inspection.public_key_kid, claimed_kid) {
        return Err(DeviceAuthError::PublicKeyKidMismatch);
    }
    Ok(inspection)
}

fn default_audience() -> String {
    CHALLENGE_AUDIENCE.to_string()
}

fn default_purpose() -> String {
    "device_registration".to_string()
}

fn default_message_version() -> u8 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceChallengeRecord {
    pub challenge_id: String,
    pub user_id: String,
    pub device_id: String,
    pub public_key_kid: String,
    pub public_key_sha256: String,
    pub nonce: String,
    pub created_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub registration_id: Option<String>,
    #[serde(default)]
    pub key_version: Option<u64>,
    #[serde(default = "default_purpose")]
    pub purpose: String,
    #[serde(default = "default_audience")]
    pub audience: String,
    #[serde(default = "default_message_version")]
    pub message_version: u8,
}

#[derive(Serialize)]
struct ChallengeMessageV2<'a> {
    audience: &'a str,
    challenge_id: &'a str,
    device_id: &'a str,
    expires_at: &'a str,
    key_version: Option<u64>,
    nonce: &'a str,
    public_key_kid: &'a str,
    purpose: &'a str,
    registration_id: Option<&'a str>,
    user_id: &'a str,
}

impl DeviceChallengeRecord {
    fn validate(&self) -> DeviceAuthResult<()> {
        let fields = [
            ("challenge_id", self.challenge_id.as_str()),
            ("user_id", self.user_id.as_str()),
            ("device_id", self.device_id.as_str()),
            ("public_key_kid", self.public_key_kid.as_str()),
            ("public_key_sha256", self.public_key_sha256.as_str()),
            ("nonce", self.nonce.as_str()),
            ("created_at", self.created_at.as_str()),
            ("expires_at", self.expires_at.as_str()),
            ("purpose", self.purpose.as_str()),
            ("audience", self.audience.as_str()),
        ];
        for (name, value) in fields {
            if value.is_empty() || value.len() > 2048 {
                return Err(DeviceAuthError::InvalidChallenge(format!(
                    "{name} is empty or exceeds 2048 bytes"
                )));
            }
        }
        if self
            .key_version
            .is_some_and(|version| version > MAX_KEY_VERSION)
        {
            return Err(DeviceAuthError::InvalidChallenge(
                "key_version exceeds the interoperable integer limit".to_string(),
            ));
        }
        if !matches!(self.message_version, 1 | 2) {
            return Err(DeviceAuthError::InvalidChallenge(
                "unsupported challenge message version".to_string(),
            ));
        }
        Ok(())
    }

    pub fn message(&self) -> DeviceAuthResult<Vec<u8>> {
        self.validate()?;
        let message = if self.message_version == 1 {
            format!(
                "marty-device-registration-v1\n{CHALLENGE_AUDIENCE}\n{}\n{}\n{}\n{}\n{}",
                self.challenge_id, self.user_id, self.device_id, self.public_key_kid, self.nonce
            )
            .into_bytes()
        } else {
            let payload = ChallengeMessageV2 {
                audience: &self.audience,
                challenge_id: &self.challenge_id,
                device_id: &self.device_id,
                expires_at: &self.expires_at,
                key_version: self.key_version,
                nonce: &self.nonce,
                public_key_kid: &self.public_key_kid,
                purpose: &self.purpose,
                registration_id: self.registration_id.as_deref(),
                user_id: &self.user_id,
            };
            let json = serde_json::to_string(&payload)
                .map_err(|error| DeviceAuthError::SerializationFailed(error.to_string()))?;
            format!("marty-device-registration-v2\n{json}").into_bytes()
        };
        if message.len() > MAX_CHALLENGE_MESSAGE_BYTES {
            return Err(DeviceAuthError::InvalidChallenge(
                "challenge message exceeds its size limit".to_string(),
            ));
        }
        Ok(message)
    }

    pub fn encoded_message(&self) -> DeviceAuthResult<String> {
        Ok(URL_SAFE_NO_PAD.encode(self.message()?))
    }

    pub fn is_expired_at(&self, now: &str) -> DeviceAuthResult<bool> {
        self.validate()?;
        Ok(parse_time("now", now)? >= parse_time("challenge.expires_at", &self.expires_at)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceChallengeBindingRequest {
    pub challenge: DeviceChallengeRecord,
    pub user_id: String,
    pub device_id: String,
    pub public_key_kid: String,
    pub public_key_sha256: String,
    #[serde(default)]
    pub registration_id: Option<String>,
    #[serde(default)]
    pub key_version: Option<u64>,
    pub purpose: String,
    pub audience: String,
    pub now: String,
}

pub fn evaluate_device_challenge_binding(
    request: &DeviceChallengeBindingRequest,
) -> DeviceAuthResult<DeviceKeyEligibilityResult> {
    request.challenge.validate()?;
    let now = parse_time("now", &request.now)?;
    let expires_at = parse_time("challenge.expires_at", &request.challenge.expires_at)?;
    if now >= expires_at {
        return Ok(DeviceKeyEligibilityResult::deny("CHALLENGE_EXPIRED"));
    }
    if request.challenge.user_id != request.user_id
        || request.challenge.device_id != request.device_id
        || !constant_time_eq(&request.challenge.public_key_kid, &request.public_key_kid)
        || !constant_time_eq(
            &request.challenge.public_key_sha256,
            &request.public_key_sha256,
        )
        || request.challenge.registration_id != request.registration_id
        || request.challenge.key_version != request.key_version
        || request.challenge.purpose != request.purpose
        || request.challenge.audience != request.audience
    {
        return Ok(DeviceKeyEligibilityResult::deny(
            "CHALLENGE_BINDING_MISMATCH",
        ));
    }
    Ok(DeviceKeyEligibilityResult::allow("CHALLENGE_BINDING_MATCH"))
}

pub fn verify_device_challenge_signature(
    public_key_der: &str,
    challenge: &DeviceChallengeRecord,
    signature_b64url: &str,
) -> DeviceAuthResult<()> {
    let parsed = parse_device_public_key(public_key_der)?;
    let signature = decode_base64url(signature_b64url, "signature", MAX_ENCODED_KEY_BYTES)?;
    if signature.len() != parsed.key.size() {
        return Err(DeviceAuthError::InvalidSignature);
    }
    let message = challenge.message()?;
    match marty_crypto::rsa::verify_pss_sha256(&parsed.raw_der, &message, &signature) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(DeviceAuthError::InvalidSignature),
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviceKeyState {
    Current,
    Retiring,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceKeyRecord {
    pub id: String,
    pub registration_id: String,
    pub key_version: u64,
    pub public_key_der: String,
    pub public_key_kid: String,
    pub state: DeviceKeyState,
    pub valid_from: String,
    #[serde(default)]
    pub valid_until: Option<String>,
    #[serde(default)]
    pub rotated_at: Option<String>,
    #[serde(default)]
    pub retire_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceKeyEligibilityRequest {
    pub key: DeviceKeyRecord,
    pub registration_active: bool,
    pub challenge: DeviceChallengeRecord,
    pub purpose: String,
    pub audience: String,
    pub now: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceKeyEligibilityResult {
    pub eligible: bool,
    pub code: String,
}

impl DeviceKeyEligibilityResult {
    fn allow(code: &str) -> Self {
        Self {
            eligible: true,
            code: code.to_string(),
        }
    }

    fn deny(code: &str) -> Self {
        Self {
            eligible: false,
            code: code.to_string(),
        }
    }
}

fn parse_time(name: &str, value: &str) -> DeviceAuthResult<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(value)
        .map_err(|_| DeviceAuthError::InvalidTimestamp(name.to_string()))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn purpose_allows_rotation_grace(purpose: &str) -> bool {
    !matches!(
        purpose,
        "device_registration" | "device_key_rotation" | "device_registration_update"
    )
}

pub fn evaluate_device_key_eligibility(
    request: &DeviceKeyEligibilityRequest,
) -> DeviceAuthResult<DeviceKeyEligibilityResult> {
    let now = parse_time("now", &request.now)?;
    let valid_from = parse_time("key.valid_from", &request.key.valid_from)?;
    let expires_at = parse_time("challenge.expires_at", &request.challenge.expires_at)?;
    let inspection = match inspect_device_public_key(&request.key.public_key_der) {
        Ok(value) => value,
        Err(_) => return Ok(DeviceKeyEligibilityResult::deny("KEY_MATERIAL_INVALID")),
    };

    if !request.registration_active {
        return Ok(DeviceKeyEligibilityResult::deny("REGISTRATION_INACTIVE"));
    }
    if matches!(
        request.key.state,
        DeviceKeyState::Retired | DeviceKeyState::Revoked
    ) {
        return Ok(DeviceKeyEligibilityResult::deny("KEY_STATE_INELIGIBLE"));
    }
    if request.key.key_version > MAX_KEY_VERSION {
        return Ok(DeviceKeyEligibilityResult::deny("KEY_VERSION_INVALID"));
    }
    if !constant_time_eq(&request.key.public_key_kid, &inspection.public_key_kid)
        || !constant_time_eq(
            &request.challenge.public_key_sha256,
            &inspection.public_key_sha256,
        )
    {
        return Ok(DeviceKeyEligibilityResult::deny("KEY_MATERIAL_MISMATCH"));
    }
    if request.challenge.registration_id.as_deref() != Some(&request.key.registration_id)
        || request.challenge.key_version != Some(request.key.key_version)
        || !constant_time_eq(
            &request.challenge.public_key_kid,
            &request.key.public_key_kid,
        )
        || request.challenge.purpose != request.purpose
        || request.challenge.audience != request.audience
    {
        return Ok(DeviceKeyEligibilityResult::deny(
            "CHALLENGE_BINDING_MISMATCH",
        ));
    }
    if now >= expires_at {
        return Ok(DeviceKeyEligibilityResult::deny("CHALLENGE_EXPIRED"));
    }
    if now < valid_from {
        return Ok(DeviceKeyEligibilityResult::deny("KEY_NOT_YET_VALID"));
    }
    if let Some(valid_until) = request.key.valid_until.as_deref() {
        if now >= parse_time("key.valid_until", valid_until)? {
            return Ok(DeviceKeyEligibilityResult::deny("KEY_EXPIRED"));
        }
    }
    if request.key.state == DeviceKeyState::Current {
        return Ok(DeviceKeyEligibilityResult::allow("ELIGIBLE_CURRENT"));
    }
    if request.key.state != DeviceKeyState::Retiring
        || !purpose_allows_rotation_grace(&request.purpose)
    {
        return Ok(DeviceKeyEligibilityResult::deny(
            "ROTATION_GRACE_DISALLOWED",
        ));
    }
    let Some(rotated_at) = request.key.rotated_at.as_deref() else {
        return Ok(DeviceKeyEligibilityResult::deny("ROTATION_WINDOW_INVALID"));
    };
    let Some(retire_at) = request.key.retire_at.as_deref() else {
        return Ok(DeviceKeyEligibilityResult::deny("ROTATION_WINDOW_INVALID"));
    };
    let rotated_at = parse_time("key.rotated_at", rotated_at)?;
    let retire_at = parse_time("key.retire_at", retire_at)?;
    let created_at = parse_time("challenge.created_at", &request.challenge.created_at)?;
    if retire_at <= rotated_at
        || (retire_at - rotated_at).num_seconds() > MAX_ROTATION_GRACE_SECONDS as i64
    {
        return Ok(DeviceKeyEligibilityResult::deny("ROTATION_WINDOW_INVALID"));
    }
    if created_at >= rotated_at {
        return Ok(DeviceKeyEligibilityResult::deny(
            "CHALLENGE_NOT_PRE_ROTATION",
        ));
    }
    if now >= retire_at {
        return Ok(DeviceKeyEligibilityResult::deny("ROTATION_GRACE_EXPIRED"));
    }
    Ok(DeviceKeyEligibilityResult::allow("ELIGIBLE_ROTATION_GRACE"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
    use rsa::pkcs8::EncodePublicKey;

    #[derive(Deserialize)]
    struct ChallengeVectors {
        schema_version: u8,
        challenge_cases: Vec<ChallengeVector>,
    }

    #[derive(Deserialize)]
    struct ChallengeVector {
        name: String,
        challenge: DeviceChallengeRecord,
        expected_message_base64url: String,
    }

    fn key_material(bits: usize) -> (Vec<u8>, String) {
        let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap();
        let private_der = private.to_pkcs1_der().unwrap().as_bytes().to_vec();
        let public_der = private
            .to_public_key()
            .to_pkcs1_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        (private_der, URL_SAFE_NO_PAD.encode(public_der))
    }

    fn challenge(inspection: &DevicePublicKeyInspection) -> DeviceChallengeRecord {
        DeviceChallengeRecord {
            challenge_id: "challenge-1".to_string(),
            user_id: "user-1".to_string(),
            device_id: "device-1".to_string(),
            public_key_kid: inspection.public_key_kid.clone(),
            public_key_sha256: inspection.public_key_sha256.clone(),
            nonce: "nonce-1".to_string(),
            created_at: "2026-08-11T00:00:00+00:00".to_string(),
            expires_at: "2026-08-11T00:05:00+00:00".to_string(),
            registration_id: Some("registration-1".to_string()),
            key_version: Some(1),
            purpose: "device_authentication".to_string(),
            audience: CHALLENGE_AUDIENCE.to_string(),
            message_version: 2,
        }
    }

    #[test]
    fn inspects_canonical_pkcs1_and_verifies_ps256() {
        let (private_der, public_key_der) = key_material(2048);
        let inspection = inspect_device_public_key(&public_key_der).unwrap();
        assert_eq!(inspection.key_bits, 2048);
        assert_eq!(inspection.public_key_kid.len(), 43);
        assert_eq!(inspection.public_key_sha256.len(), 64);
        let challenge = challenge(&inspection);
        let signature =
            marty_crypto::rsa::sign_pss_sha256(&private_der, &challenge.message().unwrap())
                .unwrap();
        verify_device_challenge_signature(
            &public_key_der,
            &challenge,
            &URL_SAFE_NO_PAD.encode(signature),
        )
        .unwrap();
    }

    #[test]
    fn challenge_v2_message_is_byte_stable() {
        let inspection = DevicePublicKeyInspection {
            public_key_kid: "kid".to_string(),
            public_key_sha256: "digest".to_string(),
            key_bits: 2048,
        };
        let challenge = challenge(&inspection);
        assert_eq!(
            String::from_utf8(challenge.message().unwrap()).unwrap(),
            "marty-device-registration-v2\n{\"audience\":\"marty-device-registration\",\"challenge_id\":\"challenge-1\",\"device_id\":\"device-1\",\"expires_at\":\"2026-08-11T00:05:00+00:00\",\"key_version\":1,\"nonce\":\"nonce-1\",\"public_key_kid\":\"kid\",\"purpose\":\"device_authentication\",\"registration_id\":\"registration-1\",\"user_id\":\"user-1\"}"
        );
    }

    #[test]
    fn shared_challenge_vectors_are_byte_stable() {
        let vectors: ChallengeVectors =
            serde_json::from_str(include_str!("../../tests/vectors/device_auth.json")).unwrap();
        assert_eq!(vectors.schema_version, 1);
        assert!(!vectors.challenge_cases.is_empty());
        for vector in vectors.challenge_cases {
            assert_eq!(
                vector.challenge.encoded_message().unwrap(),
                vector.expected_message_base64url,
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn eligibility_preserves_current_and_rotation_rules() {
        let (_private_der, public_key_der) = key_material(2048);
        let inspection = inspect_device_public_key(&public_key_der).unwrap();
        let challenge = challenge(&inspection);
        let mut request = DeviceKeyEligibilityRequest {
            key: DeviceKeyRecord {
                id: "key-1".to_string(),
                registration_id: "registration-1".to_string(),
                key_version: 1,
                public_key_der,
                public_key_kid: inspection.public_key_kid,
                state: DeviceKeyState::Current,
                valid_from: "2026-08-10T00:00:00+00:00".to_string(),
                valid_until: None,
                rotated_at: None,
                retire_at: None,
                revoked_at: None,
                created_at: None,
            },
            registration_active: true,
            challenge,
            purpose: "device_authentication".to_string(),
            audience: CHALLENGE_AUDIENCE.to_string(),
            now: "2026-08-11T00:01:00+00:00".to_string(),
        };
        assert_eq!(
            evaluate_device_key_eligibility(&request).unwrap(),
            DeviceKeyEligibilityResult::allow("ELIGIBLE_CURRENT")
        );
        request.key.state = DeviceKeyState::Retiring;
        request.key.rotated_at = Some("2026-08-11T00:00:30+00:00".to_string());
        request.key.retire_at = Some("2026-08-11T00:05:30+00:00".to_string());
        assert_eq!(
            evaluate_device_key_eligibility(&request).unwrap(),
            DeviceKeyEligibilityResult::allow("ELIGIBLE_ROTATION_GRACE")
        );
        request.challenge.purpose = "device_key_rotation".to_string();
        request.purpose = "device_key_rotation".to_string();
        assert_eq!(
            evaluate_device_key_eligibility(&request).unwrap().code,
            "ROTATION_GRACE_DISALLOWED"
        );
    }

    #[test]
    fn challenge_binding_is_contextual_and_expiring() {
        let inspection = DevicePublicKeyInspection {
            public_key_kid: "kid".to_string(),
            public_key_sha256: "digest".to_string(),
            key_bits: 2048,
        };
        let challenge = challenge(&inspection);
        let mut request = DeviceChallengeBindingRequest {
            user_id: challenge.user_id.clone(),
            device_id: challenge.device_id.clone(),
            public_key_kid: challenge.public_key_kid.clone(),
            public_key_sha256: challenge.public_key_sha256.clone(),
            registration_id: challenge.registration_id.clone(),
            key_version: challenge.key_version,
            purpose: challenge.purpose.clone(),
            audience: challenge.audience.clone(),
            now: "2026-08-11T00:01:00+00:00".to_string(),
            challenge,
        };
        assert_eq!(
            evaluate_device_challenge_binding(&request).unwrap(),
            DeviceKeyEligibilityResult::allow("CHALLENGE_BINDING_MATCH")
        );
        request.user_id = "different-user".to_string();
        assert_eq!(
            evaluate_device_challenge_binding(&request).unwrap().code,
            "CHALLENGE_BINDING_MISMATCH"
        );
        request.user_id = request.challenge.user_id.clone();
        request.now = request.challenge.expires_at.clone();
        assert_eq!(
            evaluate_device_challenge_binding(&request).unwrap().code,
            "CHALLENGE_EXPIRED"
        );
    }

    #[test]
    fn rejects_weak_or_noncanonical_keys_and_bad_signatures() {
        let (_private_der, weak_key) = key_material(1024);
        assert!(matches!(
            inspect_device_public_key(&weak_key),
            Err(DeviceAuthError::UnsupportedKey(_))
        ));
        let spki_private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let spki = spki_private.to_public_key().to_public_key_der().unwrap();
        assert_eq!(
            inspect_device_public_key(&URL_SAFE_NO_PAD.encode(spki.as_bytes())),
            Err(DeviceAuthError::InvalidPublicKey(
                "public_key_der must use canonical PKCS#1 DER encoding"
            ))
        );
        let (_private_der, public_key_der) = key_material(2048);
        let inspection = inspect_device_public_key(&public_key_der).unwrap();
        assert_eq!(
            validate_device_public_key(&public_key_der, "wrong-kid"),
            Err(DeviceAuthError::PublicKeyKidMismatch)
        );
        let wrong_length_signature = URL_SAFE_NO_PAD.encode([0_u8]);
        assert_eq!(
            verify_device_challenge_signature(
                &public_key_der,
                &challenge(&inspection),
                &wrong_length_signature,
            ),
            Err(DeviceAuthError::InvalidSignature)
        );
    }
}
