use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use chrono::{DateTime, Utc};
use marty_verification::open_badges::{verify_ob3_json, DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustProfile {
    trusted_issuer: String,
    document_store: DocumentStore,
    allow_credentials_without_status: bool,
}

#[derive(Serialize)]
struct Decision {
    accepted: bool,
    profile_sha256: String,
    reasons: Vec<String>,
    verification: Value,
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("{} exceeds the 1 MiB input limit", path.display()));
    }
    Ok(bytes)
}

fn credential_issuer(credential: &Value) -> Option<&str> {
    credential.get("issuer").and_then(|issuer| {
        issuer
            .as_str()
            .or_else(|| issuer.get("id").and_then(Value::as_str))
    })
}

fn check_time(credential: &Value, field: &str, now: DateTime<Utc>) -> Result<(), String> {
    let Some(value) = credential.get(field) else {
        return Ok(());
    };
    let Some(value) = value.as_str() else {
        return Err(format!("{field} must be an RFC 3339 timestamp"));
    };
    let timestamp = DateTime::parse_from_rfc3339(value)
        .map_err(|_| format!("{field} must be an RFC 3339 timestamp"))?;
    match field {
        "validFrom" if timestamp > now => Err("credential is not yet valid".to_string()),
        "validUntil" if timestamp <= now => Err("credential has expired".to_string()),
        _ => Ok(()),
    }
}

fn verify(
    credential_bytes: &[u8],
    profile_bytes: &[u8],
    expected_sha256: &str,
    now: DateTime<Utc>,
) -> Result<Decision, String> {
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("--trust-sha256 must contain exactly 64 hexadecimal characters".to_string());
    }
    let actual_sha256 = format!("{:x}", Sha256::digest(profile_bytes));
    if !actual_sha256.eq_ignore_ascii_case(expected_sha256) {
        return Err("trust profile does not match the pinned SHA-256 digest".to_string());
    }
    let profile: TrustProfile = serde_json::from_slice(profile_bytes)
        .map_err(|error| format!("invalid trust profile: {error}"))?;
    if profile.trusted_issuer.is_empty() || profile.document_store.is_empty() {
        return Err("trust profile requires an issuer and verification documents".to_string());
    }
    let credential: Value = serde_json::from_slice(credential_bytes)
        .map_err(|error| format!("invalid credential JSON: {error}"))?;
    if !credential.is_object() {
        return Err("credential must be a JSON object".to_string());
    }
    let request = json!({
        "credential": credential,
        "document_store": profile.document_store,
    });
    let raw = verify_ob3_json(&request.to_string())
        .map_err(|error| format!("verification could not run: {error}"))?;
    let verification: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("invalid verification result: {error}"))?;
    let credential = &request["credential"];
    let mut reasons = Vec::new();
    if credential_issuer(credential) != Some(profile.trusted_issuer.as_str()) {
        reasons.push("issuer is not approved by the pinned trust profile".to_string());
    }
    for field in ["validFrom", "validUntil"] {
        if let Err(reason) = check_time(credential, field, now) {
            reasons.push(reason);
        }
    }
    if credential.get("credentialStatus").is_none() && !profile.allow_credentials_without_status {
        reasons.push("profile requires credential status evidence".to_string());
    }
    if verification["valid"] != true {
        reasons
            .push("cryptographic, issuer authorization, or status verification failed".to_string());
    }
    Ok(Decision {
        accepted: reasons.is_empty(),
        profile_sha256: actual_sha256,
        reasons,
        verification,
    })
}

fn argument_map() -> Result<BTreeMap<String, String>, String> {
    let mut args = env::args().skip(1);
    if args.next().as_deref() != Some("verify") {
        return Err("usage: marty-headless-verify verify --credential FILE --trust-profile FILE --trust-sha256 HEX".to_string());
    }
    let mut options = BTreeMap::new();
    while let Some(name) = args.next() {
        if !matches!(
            name.as_str(),
            "--credential" | "--trust-profile" | "--trust-sha256"
        ) {
            return Err(format!("unknown option: {name}"));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {name}"))?;
        if options.insert(name.clone(), value).is_some() {
            return Err(format!("duplicate option: {name}"));
        }
    }
    if options.len() != 3 {
        return Err("--credential, --trust-profile, and --trust-sha256 are required".to_string());
    }
    Ok(options)
}

fn run() -> Result<ExitCode, String> {
    let options = argument_map()?;
    let credential = read_bounded(Path::new(&options["--credential"]))?;
    let profile = read_bounded(Path::new(&options["--trust-profile"]))?;
    let decision = verify(
        &credential,
        &profile,
        &options["--trust-sha256"],
        Utc::now(),
    )?;
    println!(
        "{}",
        serde_json::to_string(&decision).map_err(|error| error.to_string())?
    );
    Ok(if decision.accepted {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use marty_verification::error::codes::OPEN_BADGES_STATUS_AUTHORITY_UNTRUSTED;

    const FIXTURE: &str =
        include_str!("../../marty-verification/tests/fixtures/open_badges/ob3_verify_request.json");

    fn input() -> (Value, Vec<u8>) {
        let request: Value = serde_json::from_str(FIXTURE).unwrap();
        let profile = json!({
            "trusted_issuer": "did:example:issuer",
            "document_store": request["document_store"],
            "allow_credentials_without_status": true,
        });
        (
            request["credential"].clone(),
            serde_json::to_vec(&profile).unwrap(),
        )
    }

    fn evaluate(credential: &Value, profile: &[u8]) -> Decision {
        let digest = format!("{:x}", Sha256::digest(profile));
        verify(
            &serde_json::to_vec(credential).unwrap(),
            profile,
            &digest,
            Utc.with_ymd_and_hms(2026, 10, 11, 0, 0, 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn trusted_signed_badge_passes() {
        let (credential, profile) = input();
        let result = evaluate(&credential, &profile);
        assert!(result.accepted, "{:?}", result.reasons);
    }

    #[test]
    fn tampered_badge_and_wrong_trust_fail() {
        let (mut credential, profile) = input();
        credential["credentialSubject"]["achievement"]["name"] = json!("Tampered");
        assert!(!evaluate(&credential, &profile).accepted);
        let (credential, _) = input();
        let wrong = json!({
            "trusted_issuer": "did:example:other",
            "document_store": serde_json::from_slice::<Value>(&profile).unwrap()["document_store"],
            "allow_credentials_without_status": true,
        });
        assert!(!evaluate(&credential, &serde_json::to_vec(&wrong).unwrap()).accepted);
    }

    #[test]
    fn profile_pin_status_and_expiry_fail_closed() {
        let (credential, profile) = input();
        assert!(verify(
            &serde_json::to_vec(&credential).unwrap(),
            &profile,
            &"0".repeat(64),
            Utc::now()
        )
        .is_err());
        let mut strict_profile: Value = serde_json::from_slice(&profile).unwrap();
        strict_profile["allow_credentials_without_status"] = json!(false);
        assert!(
            evaluate(&credential, &serde_json::to_vec(&strict_profile).unwrap())
                .reasons
                .contains(&"profile requires credential status evidence".to_string())
        );
        let mut with_status = credential.clone();
        with_status["credentialStatus"] = json!({"type":"BitstringStatusListEntry","statusListCredential":"https://example.test/status","statusListIndex":"0","statusPurpose":"revocation"});
        let result = evaluate(&with_status, &profile);
        assert!(!result.accepted);
        assert!(result.verification["error_codes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|code| code.as_str() == Some(OPEN_BADGES_STATUS_AUTHORITY_UNTRUSTED)));
        let mut expired = credential;
        expired["validUntil"] = json!("2026-10-10T00:00:00Z");
        assert!(evaluate(&expired, &profile)
            .reasons
            .contains(&"credential has expired".to_string()));
    }
}
