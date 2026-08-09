use std::collections::{HashMap, HashSet};
use std::io::Read;

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use iref::IriBuf;
use serde_json::Value;
use ssi_claims::VerificationParameters;

use crate::error::codes as error_codes;

use super::contexts::open_badges_context_loader;
use super::ob3::{
    collect_verification_methods, credential_issuer, push_error,
    validate_issuer_proof_authorization, AnyCredential,
};
use super::types::{AuthenticatedStatusList, OpenBadgeStatusCheck, OpenBadgeStatusOutcome};

const MAX_STATUS_ENTRIES: usize = 32;
const MAX_AUTHENTICATED_LISTS: usize = 32;
const MAX_ENCODED_LIST_CHARS: usize = 2 * 1024 * 1024;
const MAX_COMPRESSED_LIST_BYTES: usize = 1024 * 1024;
const MAX_UNCOMPRESSED_LIST_BYTES: usize = 16 * 1024 * 1024;
const MINIMUM_STATUS_ENTRIES: usize = 131_072;
const MAX_SUPPORTED_STATUS_SIZE: u8 = 8;

pub(super) async fn check_credential_status(
    credential: &Value,
    authenticated_status_lists: &[AuthenticatedStatusList],
    errors: &mut Vec<String>,
    error_codes_out: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Vec<OpenBadgeStatusCheck> {
    let Some(status) = credential.get("credentialStatus") else {
        return Vec::new();
    };

    let statuses: Vec<&Value> = match status {
        Value::Array(entries) => entries.iter().collect(),
        _ => vec![status],
    };
    if statuses.is_empty() || statuses.len() > MAX_STATUS_ENTRIES {
        push_error(
            errors,
            error_codes_out,
            error_codes::OPEN_BADGES_STATUS_CHECK_FAILED,
            "Credential status must contain between 1 and 32 entries",
        );
        return Vec::new();
    }

    let Some(status_lists) =
        authenticated_list_map(authenticated_status_lists, errors, error_codes_out)
    else {
        return Vec::new();
    };

    let mut status_checks = Vec::new();
    for status_entry in statuses {
        let status_type = status_entry.get("type").and_then(Value::as_str);
        match status_type {
            Some("BitstringStatusListEntry") => {
                if let Some(status_check) = check_bitstring_status_entry(
                    status_entry,
                    &status_lists,
                    errors,
                    error_codes_out,
                    warnings,
                )
                .await
                {
                    status_checks.push(status_check);
                }
            }
            Some(unsupported) => push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_UNSUPPORTED,
                format!(
                    "Unsupported Open Badges v3 credential status type '{unsupported}'; expected BitstringStatusListEntry"
                ),
            ),
            None => push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_STATUS_CHECK_FAILED,
                "Credential status entry missing 'type' field",
            ),
        }
    }
    status_checks
}

fn authenticated_list_map<'a>(
    authenticated_status_lists: &'a [AuthenticatedStatusList],
    errors: &mut Vec<String>,
    error_codes_out: &mut Vec<String>,
) -> Option<HashMap<&'a str, &'a AuthenticatedStatusList>> {
    if authenticated_status_lists.len() > MAX_AUTHENTICATED_LISTS {
        push_error(
            errors,
            error_codes_out,
            error_codes::OPEN_BADGES_STATUS_AUTHORITY_UNTRUSTED,
            "Authenticated status-list context exceeds the supported bound",
        );
        return None;
    }

    let mut by_url = HashMap::new();
    for status_list in authenticated_status_lists {
        if by_url.insert(status_list.url(), status_list).is_some() {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_STATUS_AUTHORITY_UNTRUSTED,
                format!(
                    "Authenticated status-list URL '{}' is ambiguous",
                    status_list.url()
                ),
            );
            return None;
        }
    }
    Some(by_url)
}

async fn check_bitstring_status_entry(
    status_entry: &Value,
    status_lists: &HashMap<&str, &AuthenticatedStatusList>,
    errors: &mut Vec<String>,
    error_codes_out: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Option<OpenBadgeStatusCheck> {
    let entry = match parse_status_entry(status_entry) {
        Ok(entry) => entry,
        Err(message) => {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_STATUS_CHECK_FAILED,
                message,
            );
            return None;
        }
    };

    let Some(authenticated) = status_lists.get(entry.list_url).copied() else {
        push_error(
            errors,
            error_codes_out,
            error_codes::OPEN_BADGES_STATUS_AUTHORITY_UNTRUSTED,
            format!(
                "Status-list credential '{}' has no authenticated authority context",
                entry.list_url
            ),
        );
        return None;
    };

    let now = Utc::now();
    if authenticated.retrieved_at() > now || authenticated.fresh_until() <= now {
        push_error(
            errors,
            error_codes_out,
            error_codes::OPEN_BADGES_STATUS_CHECK_FAILED,
            format!(
                "Authenticated status-list credential '{}' is future-dated or stale",
                entry.list_url
            ),
        );
        return None;
    }

    let status_list = authenticated.credential();
    let signed_valid_until =
        match validate_status_list_model(status_list, &entry, authenticated, now) {
            Ok(valid_until) => valid_until,
            Err((code, message)) => {
                push_error(errors, error_codes_out, code, message);
                return None;
            }
        };
    if authenticated.fresh_until() > signed_valid_until {
        push_error(
            errors,
            error_codes_out,
            error_codes::OPEN_BADGES_STATUS_CHECK_FAILED,
            "Status-list cache freshness cannot extend its signed validity period",
        );
        return None;
    }

    let mut authorization_errors = Vec::new();
    let mut authorization_codes = Vec::new();
    let collected = collect_verification_methods(authenticated.authority_documents(), warnings);
    validate_issuer_proof_authorization(
        status_list,
        &collected,
        &mut authorization_errors,
        &mut authorization_codes,
    );
    if !authorization_codes.is_empty() {
        push_error(
            errors,
            error_codes_out,
            error_codes::OPEN_BADGES_STATUS_AUTHORITY_UNTRUSTED,
            format!(
                "Status-list issuer '{}' is not authorized by its assertion method",
                authenticated.trusted_issuer()
            ),
        );
        return None;
    }

    let secured_status_list: AnyCredential = match serde_json::from_value(status_list.clone()) {
        Ok(credential) => credential,
        Err(error) => {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_STATUS_CHECK_FAILED,
                format!("Invalid status-list credential: {error}"),
            );
            return None;
        }
    };
    let loader = match open_badges_context_loader() {
        Ok(loader) => loader,
        Err(error) => {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_STATUS_CHECK_FAILED,
                format!("Unable to load pinned status-list contexts: {error}"),
            );
            return None;
        }
    };
    let parameters =
        VerificationParameters::from_resolver(collected.resolver).with_json_ld_loader(loader);
    match secured_status_list.verify(parameters).await {
        Ok(Ok(())) => {}
        Ok(Err(invalid)) => {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_PROOF_INVALID,
                format!("Status-list credential proof is invalid: {invalid}"),
            );
            return None;
        }
        Err(error) => {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_PROOF_INVALID,
                format!("Status-list credential proof verification failed: {error}"),
            );
            return None;
        }
    }

    let Some(encoded_list) = status_list
        .get("credentialSubject")
        .and_then(Value::as_object)
        .and_then(|subject| subject.get("encodedList"))
        .and_then(Value::as_str)
    else {
        push_error(
            errors,
            error_codes_out,
            error_codes::OPEN_BADGES_STATUS_CHECK_FAILED,
            "Status-list credential missing encodedList",
        );
        return None;
    };
    let status_value = match decode_status_value(encoded_list, entry.index, entry.status_size) {
        Ok(value) => value,
        Err(message) => {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_STATUS_CHECK_FAILED,
                message,
            );
            return None;
        }
    };
    let outcome = if status_value == 0 {
        OpenBadgeStatusOutcome::Good
    } else if entry.purpose == "revocation" {
        push_error(
            errors,
            error_codes_out,
            error_codes::OPEN_BADGES_REVOKED,
            format!(
                "Credential has been revoked (statusListIndex: {}, status: 0x{status_value:x})",
                entry.index
            ),
        );
        OpenBadgeStatusOutcome::Revoked
    } else {
        push_error(
            errors,
            error_codes_out,
            error_codes::OPEN_BADGES_STATUS_ASSERTED,
            format!(
                "Credential status '{}' is asserted at index {} with value 0x{status_value:x}",
                entry.purpose, entry.index
            ),
        );
        if entry.purpose == "suspension" {
            OpenBadgeStatusOutcome::Suspended
        } else {
            OpenBadgeStatusOutcome::Message
        }
    };

    Some(OpenBadgeStatusCheck {
        status_list_url: entry.list_url.to_string(),
        status_issuer: authenticated.trusted_issuer().to_string(),
        status_purpose: entry.purpose.to_string(),
        status_list_index: entry.index,
        status_size: entry.status_size,
        status_value,
        outcome,
        checked_at: now,
        retrieved_at: authenticated.retrieved_at(),
        fresh_until: authenticated.fresh_until(),
        authority_provenance: authenticated.provenance().clone(),
    })
}

struct ParsedStatusEntry<'a> {
    list_url: &'a str,
    index: u64,
    purpose: &'a str,
    status_size: u8,
}

fn parse_status_entry(status_entry: &Value) -> Result<ParsedStatusEntry<'_>, String> {
    let object = status_entry
        .as_object()
        .ok_or_else(|| "Credential status entry must be an object".to_string())?;
    let list_url = object
        .get("statusListCredential")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Bitstring status entry missing 'statusListCredential' URL".to_string())?;
    IriBuf::new(list_url.to_string())
        .map_err(|_| "Bitstring statusListCredential must be an absolute IRI".to_string())?;

    if let Some(id) = object.get("id") {
        let id = id
            .as_str()
            .ok_or_else(|| "Bitstring status entry id must be a URL".to_string())?;
        IriBuf::new(id.to_string())
            .map_err(|_| "Bitstring status entry id must be an absolute IRI".to_string())?;
        if id == list_url {
            return Err("Bitstring status entry id must not equal the status-list URL".to_string());
        }
    }

    let index_text = object
        .get("statusListIndex")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| {
            "Bitstring statusListIndex must be a non-negative base-10 integer string".to_string()
        })?;
    let index = index_text
        .parse::<u64>()
        .map_err(|_| "Bitstring statusListIndex exceeds the supported range".to_string())?;

    let purpose = object
        .get("statusPurpose")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "revocation" | "suspension" | "message"))
        .ok_or_else(|| {
            "Supported Bitstring statusPurpose must be revocation, suspension, or message"
                .to_string()
        })?;
    let status_size = match object.get("statusSize") {
        None => 1,
        Some(value) => value
            .as_u64()
            .and_then(|size| u8::try_from(size).ok())
            .filter(|size| (1..=MAX_SUPPORTED_STATUS_SIZE).contains(size))
            .ok_or_else(|| {
                "Bitstring statusSize must be an integer from 1 through 8".to_string()
            })?,
    };
    if purpose == "message"
        && (!object.contains_key("statusSize") || !object.contains_key("statusMessage"))
    {
        return Err(
            "Bitstring message status requires explicit statusSize and statusMessage".to_string(),
        );
    }
    validate_status_messages(object.get("statusMessage"), status_size)?;
    validate_status_references(object.get("statusReference"))?;

    Ok(ParsedStatusEntry {
        list_url,
        index,
        purpose,
        status_size,
    })
}

fn validate_status_messages(value: Option<&Value>, status_size: u8) -> Result<(), String> {
    let required_count = 1usize << status_size;
    let Some(messages) = value else {
        if status_size > 1 {
            return Err(
                "Bitstring statusMessage is required when statusSize exceeds 1".to_string(),
            );
        }
        return Ok(());
    };
    let messages = messages
        .as_array()
        .filter(|messages| messages.len() == required_count)
        .ok_or_else(|| {
            format!("Bitstring statusMessage must contain exactly {required_count} entries")
        })?;
    let mut values = HashSet::new();
    for message in messages {
        let object = message
            .as_object()
            .ok_or_else(|| "Each Bitstring statusMessage must be an object".to_string())?;
        let status = object
            .get("status")
            .and_then(Value::as_str)
            .and_then(|value| value.strip_prefix("0x"))
            .and_then(|value| u16::from_str_radix(value, 16).ok())
            .filter(|value| usize::from(*value) < required_count)
            .ok_or_else(|| {
                "Bitstring statusMessage status must be an in-range 0x value".to_string()
            })?;
        if !values.insert(status) {
            return Err("Bitstring statusMessage values must be unique".to_string());
        }
        object
            .get("message")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "Each Bitstring statusMessage must have a non-empty message".to_string()
            })?;
    }
    Ok(())
}

fn validate_status_references(value: Option<&Value>) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let references: Vec<&Value> = match value {
        Value::Array(values) if !values.is_empty() => values.iter().collect(),
        Value::String(_) => vec![value],
        _ => {
            return Err(
                "Bitstring statusReference must be a URL or non-empty URL array".to_string(),
            )
        }
    };
    for reference in references {
        let reference = reference
            .as_str()
            .ok_or_else(|| "Every Bitstring statusReference must be a URL".to_string())?;
        IriBuf::new(reference.to_string())
            .map_err(|_| "Every Bitstring statusReference must be an absolute IRI".to_string())?;
    }
    Ok(())
}

fn validate_status_list_model(
    status_list: &Value,
    entry: &ParsedStatusEntry<'_>,
    authenticated: &AuthenticatedStatusList,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, (&'static str, String)> {
    let fail = |message: String| (error_codes::OPEN_BADGES_STATUS_CHECK_FAILED, message);
    let untrusted =
        |message: String| (error_codes::OPEN_BADGES_STATUS_AUTHORITY_UNTRUSTED, message);

    if status_list.get("id").and_then(Value::as_str) != Some(entry.list_url) {
        return Err(fail(
            "Status-list credential id must exactly match statusListCredential URL".to_string(),
        ));
    }
    if !uses_vcdm_v2_context(status_list) {
        return Err(fail(
            "Status-list credential must use the pinned VCDM v2 context first".to_string(),
        ));
    }
    if !has_type(status_list, "VerifiableCredential")
        || !has_type(status_list, "BitstringStatusListCredential")
    {
        return Err(fail(
            "Status-list credential type must include VerifiableCredential and BitstringStatusListCredential"
                .to_string(),
        ));
    }
    if credential_issuer(status_list).as_deref() != Some(authenticated.trusted_issuer()) {
        return Err(untrusted(
            "Status-list credential issuer does not match authenticated authority provenance"
                .to_string(),
        ));
    }

    let subject = status_list
        .get("credentialSubject")
        .and_then(Value::as_object)
        .ok_or_else(|| fail("Status-list credentialSubject must be one object".to_string()))?;
    if !value_has_type(subject.get("type"), "BitstringStatusList") {
        return Err(fail(
            "Status-list credentialSubject type must be BitstringStatusList".to_string(),
        ));
    }
    if subject.get("statusPurpose").and_then(Value::as_str) != Some(entry.purpose) {
        return Err(fail(
            "Status-list credential purpose does not match the status entry".to_string(),
        ));
    }
    subject
        .get("encodedList")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| fail("Status-list credential missing encodedList".to_string()))?;

    let valid_from = parse_required_time(status_list, "validFrom").map_err(&fail)?;
    let valid_until = parse_required_time(status_list, "validUntil").map_err(&fail)?;
    if valid_until <= valid_from {
        return Err(fail(
            "Status-list credential validUntil must be later than validFrom".to_string(),
        ));
    }
    if valid_from > now || valid_until <= now {
        return Err(fail(
            "Status-list credential is not currently within its signed validity period".to_string(),
        ));
    }
    if authenticated.retrieved_at() < valid_from {
        return Err(fail(
            "Status-list credential was cached before its signed validity period".to_string(),
        ));
    }
    Ok(valid_until)
}

fn parse_required_time(credential: &Value, name: &str) -> Result<DateTime<Utc>, String> {
    let value = credential
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Status-list credential requires RFC 3339 {name}"))?;
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| format!("Status-list credential {name} must be RFC 3339"))
}

fn has_type(value: &Value, expected: &str) -> bool {
    value_has_type(value.get("type"), expected)
}

fn uses_vcdm_v2_context(value: &Value) -> bool {
    const VCDM_V2: &str = "https://www.w3.org/ns/credentials/v2";
    match value.get("@context") {
        Some(Value::String(context)) => context == VCDM_V2,
        Some(Value::Array(contexts)) => contexts.first().and_then(Value::as_str) == Some(VCDM_V2),
        _ => false,
    }
}

fn value_has_type(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn decode_status_value(encoded: &str, index: u64, status_size: u8) -> Result<u16, String> {
    if encoded.len() > MAX_ENCODED_LIST_CHARS || encoded.contains('=') {
        return Err(
            "Status-list encodedList exceeds bounds or contains base64 padding".to_string(),
        );
    }
    let payload = encoded.strip_prefix('u').ok_or_else(|| {
        "Status-list encodedList must use multibase base64url prefix 'u'".to_string()
    })?;
    let compressed = general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| format!("Status-list base64url decode failed: {error}"))?;
    if compressed.is_empty() || compressed.len() > MAX_COMPRESSED_LIST_BYTES {
        return Err("Compressed status list is empty or exceeds the supported bound".to_string());
    }

    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut bitstring = Vec::new();
    decoder
        .by_ref()
        .take((MAX_UNCOMPRESSED_LIST_BYTES + 1) as u64)
        .read_to_end(&mut bitstring)
        .map_err(|error| format!("Status-list gzip expansion failed: {error}"))?;
    if bitstring.len() > MAX_UNCOMPRESSED_LIST_BYTES {
        return Err("Expanded status list exceeds the supported bound".to_string());
    }

    let status_size = usize::from(status_size);
    let total_bits = bitstring
        .len()
        .checked_mul(8)
        .ok_or_else(|| "Status-list length overflow".to_string())?;
    if total_bits / status_size < MINIMUM_STATUS_ENTRIES {
        return Err(format!(
            "Status list has fewer than {MINIMUM_STATUS_ENTRIES} entries"
        ));
    }
    let start = usize::try_from(index)
        .ok()
        .and_then(|index| index.checked_mul(status_size))
        .ok_or_else(|| "Status-list index exceeds the supported range".to_string())?;
    let end = start
        .checked_add(status_size)
        .ok_or_else(|| "Status-list index exceeds the supported range".to_string())?;
    if end > total_bits {
        return Err("Status-list index is out of bounds".to_string());
    }

    let mut value = 0u16;
    for bit_offset in start..end {
        let byte = bitstring[bit_offset / 8];
        let bit = (byte >> (7 - (bit_offset % 8))) & 1;
        value = (value << 1) | u16::from(bit);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Write;

    use chrono::Duration;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use serde_json::json;
    use ssi_dids::DIDJWK;
    use ssi_jwk::JWK;

    use super::*;
    use crate::open_badges::ob3::{
        issue_ob3_json_async, verify_ob3_json_async, verify_ob3_json_with_status_lists_async,
    };
    use crate::open_badges::types::{
        ArtifactProvenance, AuthenticatedStatusList, DocumentStore, StatusAuthorityProvenance,
    };

    const LIST_URL: &str = "https://status.example/lists/1";
    const STATUS_INDEX: u64 = 42;

    struct Fixture {
        request: String,
        status_list: Value,
        status_issuer: String,
        status_documents: DocumentStore,
        provenance: StatusAuthorityProvenance,
    }

    impl Fixture {
        async fn new(purpose: &str, status_size: u8, status_value: u16) -> Self {
            let credential_jwk = JWK::generate_ed25519().expect("generate credential issuer key");
            let credential_issuer = DIDJWK::generate(&credential_jwk).to_string();
            let credential_method = DIDJWK::generate_url(&credential_jwk).to_string();
            let status_jwk = JWK::generate_ed25519().expect("generate status issuer key");
            let status_issuer = DIDJWK::generate(&status_jwk).to_string();
            let status_method = DIDJWK::generate_url(&status_jwk).to_string();
            let now = Utc::now();

            let status_entry = status_entry(purpose, status_size);
            let credential = json!({
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
                ],
                "id": "https://issuer.example/credentials/1",
                "type": ["VerifiableCredential", "OpenBadgeCredential"],
                "issuer": credential_issuer,
                "validFrom": (now - Duration::minutes(10)).to_rfc3339(),
                "validUntil": (now + Duration::hours(1)).to_rfc3339(),
                "credentialSubject": {
                    "id": "did:example:holder",
                    "type": "AchievementSubject",
                    "achievement": {
                        "id": "https://issuer.example/achievements/1",
                        "type": "Achievement",
                        "name": "Status authority test",
                        "description": "Marty-owned status verification regression"
                    }
                },
                "credentialStatus": status_entry
            });
            let credential = sign_credential(credential, &credential_jwk, &credential_method).await;

            let encoded_list = encode_status_list(status_size, STATUS_INDEX, status_value);
            let status_list = json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": LIST_URL,
                "type": ["VerifiableCredential", "BitstringStatusListCredential"],
                "issuer": status_issuer,
                "validFrom": (now - Duration::minutes(10)).to_rfc3339(),
                "validUntil": (now + Duration::hours(1)).to_rfc3339(),
                "credentialSubject": {
                    "id": "https://status.example/lists/1#list",
                    "type": "BitstringStatusList",
                    "statusPurpose": purpose,
                    "encodedList": encoded_list
                }
            });
            let status_list = sign_credential(status_list, &status_jwk, &status_method).await;

            let mut store = BTreeMap::new();
            store.insert(
                credential_method.clone(),
                verification_method(&credential_jwk, &credential_method, &credential_issuer),
            );
            let mut status_documents = BTreeMap::new();
            status_documents.insert(
                status_method.clone(),
                verification_method(&status_jwk, &status_method, &status_issuer),
            );
            let request = json!({
                "credential": credential,
                "document_store": store
            })
            .to_string();

            Self {
                request,
                status_list,
                status_issuer,
                status_documents,
                provenance: provenance(),
            }
        }

        fn authenticated(&self) -> AuthenticatedStatusList {
            self.authenticated_with(
                self.status_list.clone(),
                self.status_issuer.clone(),
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::minutes(30),
            )
        }

        fn authenticated_with(
            &self,
            credential: Value,
            trusted_issuer: String,
            retrieved_at: DateTime<Utc>,
            fresh_until: DateTime<Utc>,
        ) -> AuthenticatedStatusList {
            self.authenticated_with_documents(
                credential,
                trusted_issuer,
                self.status_documents.clone(),
                retrieved_at,
                fresh_until,
            )
        }

        fn authenticated_with_documents(
            &self,
            credential: Value,
            trusted_issuer: String,
            authority_documents: DocumentStore,
            retrieved_at: DateTime<Utc>,
            fresh_until: DateTime<Utc>,
        ) -> AuthenticatedStatusList {
            AuthenticatedStatusList::new(
                LIST_URL,
                credential,
                trusted_issuer,
                authority_documents,
                retrieved_at,
                fresh_until,
                self.provenance.clone(),
            )
            .expect("valid authenticated status-list test input")
        }
    }

    async fn sign_credential(credential: Value, jwk: &JWK, method: &str) -> Value {
        let request = json!({
            "credential": credential,
            "signing": {
                "jwk": serde_json::to_value(jwk).expect("serialize signing key"),
                "verification_method": method,
                "proof_purpose": "assertionMethod"
            }
        });
        let result = issue_ob3_json_async(&request.to_string())
            .await
            .expect("sign test credential");
        serde_json::from_str::<Value>(&result).expect("parse issue result")["credential"].clone()
    }

    fn verification_method(jwk: &JWK, method: &str, controller: &str) -> Value {
        json!({
            "id": method,
            "type": "JsonWebKey2020",
            "controller": controller,
            "publicKeyJwk": serde_json::to_value(jwk.to_public()).expect("serialize public key")
        })
    }

    fn status_entry(purpose: &str, status_size: u8) -> Value {
        let mut entry = json!({
            "id": format!("{LIST_URL}#{STATUS_INDEX}"),
            "type": "BitstringStatusListEntry",
            "statusPurpose": purpose,
            "statusListIndex": STATUS_INDEX.to_string(),
            "statusListCredential": LIST_URL
        });
        if status_size > 1 {
            entry["statusSize"] = json!(status_size);
            entry["statusMessage"] = Value::Array(
                (0..(1u16 << status_size))
                    .map(|value| {
                        json!({
                            "status": format!("0x{value:x}"),
                            "message": format!("status_{value}")
                        })
                    })
                    .collect(),
            );
        }
        entry
    }

    fn encode_status_list(status_size: u8, index: u64, value: u16) -> String {
        let mut bitstring = vec![0u8; 16 * 1024 * usize::from(status_size)];
        let start = usize::try_from(index).expect("test index") * usize::from(status_size);
        for offset in 0..usize::from(status_size) {
            let source_shift = usize::from(status_size) - 1 - offset;
            let bit = ((value >> source_shift) & 1) as u8;
            let target = start + offset;
            bitstring[target / 8] |= bit << (7 - (target % 8));
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&bitstring).expect("compress status list");
        let compressed = encoder.finish().expect("finish status list compression");
        format!("u{}", general_purpose::URL_SAFE_NO_PAD.encode(compressed))
    }

    fn provenance() -> StatusAuthorityProvenance {
        let artifact = |id: &str, byte: char| {
            ArtifactProvenance::new(id, "1", format!("sha256:{}", byte.to_string().repeat(64)))
                .expect("valid provenance")
        };
        StatusAuthorityProvenance::new(
            artifact("trust-profile", 'a'),
            artifact("offline-resolver", 'b'),
            artifact("marty-verification", 'c'),
        )
    }

    fn result_value(result: String) -> Value {
        serde_json::from_str(&result).expect("parse verification result")
    }

    fn has_code(result: &Value, code: &str) -> bool {
        result["error_codes"]
            .as_array()
            .is_some_and(|codes| codes.iter().any(|value| value.as_str() == Some(code)))
    }

    #[test]
    fn authenticated_delegated_status_issuer_can_prove_clear_status() {
        futures::executor::block_on(async {
            let fixture = Fixture::new("revocation", 1, 0).await;
            let result = result_value(
                verify_ob3_json_with_status_lists_async(
                    &fixture.request,
                    &[fixture.authenticated()],
                )
                .await
                .expect("verify with authenticated status list"),
            );
            assert_eq!(result["valid"], true, "{result:#}");
            assert!(result.get("error_codes").is_none(), "{result:#}");
            assert_eq!(result["status_checks"].as_array().map(Vec::len), Some(1));
            assert_eq!(result["status_checks"][0]["outcome"], "GOOD");
            assert_eq!(result["status_checks"][0]["status_value"], 0);
            assert_eq!(
                result["status_checks"][0]["authority_provenance"]["trust_profile"]["id"],
                "trust-profile"
            );
        });
    }

    #[test]
    fn revocation_suspension_and_multibit_statuses_are_enforced() {
        futures::executor::block_on(async {
            let revoked = Fixture::new("revocation", 1, 1).await;
            let result = result_value(
                verify_ob3_json_with_status_lists_async(
                    &revoked.request,
                    &[revoked.authenticated()],
                )
                .await
                .expect("verify revoked status"),
            );
            assert!(has_code(&result, error_codes::OPEN_BADGES_REVOKED));
            assert_eq!(result["status_checks"][0]["outcome"], "REVOKED");
            assert_eq!(result["status_checks"][0]["status_value"], 1);

            let suspended = Fixture::new("suspension", 1, 1).await;
            let result = result_value(
                verify_ob3_json_with_status_lists_async(
                    &suspended.request,
                    &[suspended.authenticated()],
                )
                .await
                .expect("verify suspended status"),
            );
            assert!(has_code(&result, error_codes::OPEN_BADGES_STATUS_ASSERTED));
            assert_eq!(result["status_checks"][0]["outcome"], "SUSPENDED");

            let message = Fixture::new("message", 2, 2).await;
            let result = result_value(
                verify_ob3_json_with_status_lists_async(
                    &message.request,
                    &[message.authenticated()],
                )
                .await
                .expect("verify multi-bit status"),
            );
            assert!(has_code(&result, error_codes::OPEN_BADGES_STATUS_ASSERTED));
            assert_eq!(result["status_checks"][0]["outcome"], "MESSAGE");
            assert_eq!(result["status_checks"][0]["status_value"], 2);
        });
    }

    #[test]
    fn unsigned_bad_proof_wrong_key_and_untrusted_issuer_cannot_prove_status() {
        futures::executor::block_on(async {
            let fixture = Fixture::new("revocation", 1, 0).await;

            let mut unsigned = fixture.status_list.clone();
            unsigned
                .as_object_mut()
                .expect("status list object")
                .remove("proof");
            let unsigned = fixture.authenticated_with(
                unsigned,
                fixture.status_issuer.clone(),
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::minutes(30),
            );
            let result = result_value(
                verify_ob3_json_with_status_lists_async(&fixture.request, &[unsigned])
                    .await
                    .expect("reject unsigned status list"),
            );
            assert!(has_code(
                &result,
                error_codes::OPEN_BADGES_STATUS_AUTHORITY_UNTRUSTED
            ));
            assert!(result.get("status_checks").is_none());

            let mut bad_proof = fixture.status_list.clone();
            bad_proof["proof"]["proofValue"] = json!("zBadProof");
            let bad_proof = fixture.authenticated_with(
                bad_proof,
                fixture.status_issuer.clone(),
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::minutes(30),
            );
            let result = result_value(
                verify_ob3_json_with_status_lists_async(&fixture.request, &[bad_proof])
                    .await
                    .expect("reject bad status proof"),
            );
            assert!(has_code(&result, error_codes::OPEN_BADGES_PROOF_INVALID));
            assert!(result.get("status_checks").is_none());

            let wrong_jwk = JWK::generate_ed25519().expect("generate wrong status key");
            let mut wrong_authority_documents = fixture.status_documents.clone();
            for document in wrong_authority_documents.values_mut() {
                document["publicKeyJwk"] = serde_json::to_value(wrong_jwk.to_public())
                    .expect("serialize wrong public key");
            }
            let wrong_key = fixture.authenticated_with_documents(
                fixture.status_list.clone(),
                fixture.status_issuer.clone(),
                wrong_authority_documents,
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::minutes(30),
            );
            let mut request: Value =
                serde_json::from_str(&fixture.request).expect("parse badge request");
            let request_store = request["document_store"]
                .as_object_mut()
                .expect("request document store");
            for (id, document) in &fixture.status_documents {
                request_store.insert(id.clone(), document.clone());
            }
            let result = result_value(
                verify_ob3_json_with_status_lists_async(&request.to_string(), &[wrong_key])
                    .await
                    .expect("reject wrong resolver-owned status key"),
            );
            assert!(has_code(&result, error_codes::OPEN_BADGES_PROOF_INVALID));

            let untrusted = fixture.authenticated_with(
                fixture.status_list.clone(),
                "did:example:untrusted".to_string(),
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::minutes(30),
            );
            let result = result_value(
                verify_ob3_json_with_status_lists_async(&fixture.request, &[untrusted])
                    .await
                    .expect("reject untrusted status issuer"),
            );
            assert!(has_code(
                &result,
                error_codes::OPEN_BADGES_STATUS_AUTHORITY_UNTRUSTED
            ));
        });
    }

    #[test]
    fn wrong_binding_future_and_stale_status_lists_cannot_pass() {
        futures::executor::block_on(async {
            let fixture = Fixture::new("revocation", 1, 0).await;

            for (field, value) in [
                ("id", json!("https://status.example/lists/substituted")),
                ("type", json!(["VerifiableCredential", "OtherCredential"])),
                (
                    "validFrom",
                    json!((Utc::now() + Duration::hours(1)).to_rfc3339()),
                ),
            ] {
                let mut list = fixture.status_list.clone();
                list[field] = value;
                let authenticated = fixture.authenticated_with(
                    list,
                    fixture.status_issuer.clone(),
                    Utc::now() - Duration::minutes(1),
                    Utc::now() + Duration::minutes(30),
                );
                let result = result_value(
                    verify_ob3_json_with_status_lists_async(&fixture.request, &[authenticated])
                        .await
                        .expect("reject malformed status binding"),
                );
                assert!(has_code(
                    &result,
                    error_codes::OPEN_BADGES_STATUS_CHECK_FAILED
                ));
            }

            let mut wrong_purpose = fixture.status_list.clone();
            wrong_purpose["credentialSubject"]["statusPurpose"] = json!("suspension");
            let wrong_purpose = fixture.authenticated_with(
                wrong_purpose,
                fixture.status_issuer.clone(),
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::minutes(30),
            );
            let result = result_value(
                verify_ob3_json_with_status_lists_async(&fixture.request, &[wrong_purpose])
                    .await
                    .expect("reject wrong status purpose"),
            );
            assert!(has_code(
                &result,
                error_codes::OPEN_BADGES_STATUS_CHECK_FAILED
            ));

            let mut non_scalar_purpose = fixture.status_list.clone();
            non_scalar_purpose["credentialSubject"]["statusPurpose"] = json!(["revocation"]);
            let non_scalar_purpose = fixture.authenticated_with(
                non_scalar_purpose,
                fixture.status_issuer.clone(),
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::minutes(30),
            );
            let result = result_value(
                verify_ob3_json_with_status_lists_async(&fixture.request, &[non_scalar_purpose])
                    .await
                    .expect("reject non-scalar status purpose"),
            );
            assert!(has_code(
                &result,
                error_codes::OPEN_BADGES_STATUS_CHECK_FAILED
            ));

            let stale = fixture.authenticated_with(
                fixture.status_list.clone(),
                fixture.status_issuer.clone(),
                Utc::now() - Duration::hours(2),
                Utc::now() - Duration::hours(1),
            );
            let result = result_value(
                verify_ob3_json_with_status_lists_async(&fixture.request, &[stale])
                    .await
                    .expect("reject stale status list"),
            );
            assert!(has_code(
                &result,
                error_codes::OPEN_BADGES_STATUS_CHECK_FAILED
            ));
        });
    }

    #[test]
    fn untyped_document_store_status_list_cannot_prove_clear_status() {
        futures::executor::block_on(async {
            let fixture = Fixture::new("revocation", 1, 0).await;
            let mut request: Value = serde_json::from_str(&fixture.request).expect("parse request");
            request["document_store"][LIST_URL] = fixture.status_list.clone();
            let result = result_value(
                verify_ob3_json_async(&request.to_string())
                    .await
                    .expect("legacy verifier fails closed"),
            );
            assert!(has_code(
                &result,
                error_codes::OPEN_BADGES_STATUS_AUTHORITY_UNTRUSTED
            ));
        });
    }

    #[test]
    fn bitstring_decoder_enforces_current_encoding_and_bounds() {
        let encoded = encode_status_list(1, STATUS_INDEX, 1);
        assert_eq!(decode_status_value(&encoded, STATUS_INDEX, 1), Ok(1));
        assert!(decode_status_value(encoded.trim_start_matches('u'), STATUS_INDEX, 1).is_err());
        assert!(decode_status_value("uAA", STATUS_INDEX, 1).is_err());

        let undersized = {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&[0u8; 8]).expect("compress short list");
            format!(
                "u{}",
                general_purpose::URL_SAFE_NO_PAD
                    .encode(encoder.finish().expect("finish short list"))
            )
        };
        assert!(decode_status_value(&undersized, 0, 1).is_err());
    }
}
