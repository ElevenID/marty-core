//! OID4VCI key-attestation trust and Token Status List validation.
//!
//! Network fetching remains caller-owned. Everything that interprets policy,
//! JOSE, X.509, attestation claims, or status-list bytes is fail-closed here.

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use flate2::read::ZlibDecoder;
use marty_crypto::SignatureAlgorithm;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::BTreeSet, io::Read};
use url::{Host, Url};

use crate::verification::{ChainValidator, ChainValidatorConfig, KeyUsage};

const MAX_STATUS_LIST_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAttestationPolicy {
    pub mode: String,
    pub trusted_root_certificates_pem: Vec<String>,
    pub allowed_algorithms: BTreeSet<String>,
    pub required_key_storage: BTreeSet<String>,
    pub required_user_authentication: BTreeSet<String>,
    pub max_age_seconds: i64,
    pub require_nonce: bool,
    pub status_validation: String,
    pub status_list_allowed_origins: Vec<String>,
    pub status_list_trusted_root_certificates_pem: Vec<String>,
    pub status_list_allowed_algorithms: BTreeSet<String>,
    pub status_list_max_age_seconds: i64,
    pub status_list_allow_private_hosts: bool,
    pub status_list_tls_ca_certificates_pem: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRequest {
    issuer_context: Value,
    organization_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteRequest {
    proof_jwt: String,
    issuer_context: Option<Value>,
    organization_id: String,
}

#[derive(Debug, Serialize)]
struct RouteResult {
    action: &'static str,
    key_attestation: Option<String>,
    policy: Option<KeyAttestationPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateAttestationRequest {
    jwt: String,
    policy: KeyAttestationPolicy,
    expected_nonce: Option<String>,
    now: String,
}

#[derive(Debug, Serialize)]
struct ValidatedAttestation {
    jwt: String,
    attested_keys: Vec<Map<String, Value>>,
    claims: Map<String, Value>,
    statuses: Vec<Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusReferenceRequest {
    status: Value,
    policy: KeyAttestationPolicy,
}

#[derive(Debug, Serialize)]
struct StatusReference {
    uri: String,
    index: u64,
    hostname: String,
    port: u16,
    allow_private_hosts: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusTokenRequest {
    token: String,
    uri: String,
    index: u64,
    policy: KeyAttestationPolicy,
    now: String,
}

pub fn policy_from_issuer_context_json(raw: &str) -> Result<String, String> {
    let request: PolicyRequest = serde_json::from_str(raw)
        .map_err(|error| format!("invalid key attestation policy request: {error}"))?;
    let policy = policy_from_context(&request.issuer_context, &request.organization_id)?;
    serde_json::to_string(&policy).map_err(|error| error.to_string())
}

pub fn route_proof_json(raw: &str) -> Result<String, String> {
    let request: RouteRequest = serde_json::from_str(raw)
        .map_err(|error| format!("invalid key attestation route request: {error}"))?;
    let header = proof_header(&request.proof_jwt)?;
    let attestation = header.get("key_attestation");
    let policy = request
        .issuer_context
        .as_ref()
        .filter(|context| context.get("issuer_profile").is_some_and(Value::is_object))
        .map(|context| policy_from_context(context, &request.organization_id))
        .transpose()?;

    let result = match attestation {
        None | Some(Value::Null) => {
            if policy
                .as_ref()
                .is_some_and(|policy| policy.mode == "required")
            {
                return Err("Issuer profile requires a key-attestation-bound proof".into());
            }
            RouteResult {
                action: "ordinary",
                key_attestation: None,
                policy,
            }
        }
        Some(Value::String(attestation)) if !attestation.is_empty() => {
            let Some(policy) = policy else {
                return Err(
                    "Key-attestation-bound proof has no resolved tenant issuer policy".into(),
                );
            };
            if policy.mode == "disabled" {
                return Err("Issuer profile does not allow key-attestation-bound proofs".into());
            }
            RouteResult {
                action: "bound",
                key_attestation: Some(attestation.clone()),
                policy: Some(policy),
            }
        }
        _ => return Err("Proof key_attestation header must be a compact JWT".into()),
    };
    serde_json::to_string(&result).map_err(|error| error.to_string())
}

pub fn validate_attestation_json(raw: &str) -> Result<String, String> {
    let request: ValidateAttestationRequest = serde_json::from_str(raw)
        .map_err(|error| format!("invalid key attestation validation request: {error}"))?;
    let now = parse_now(&request.now)?;
    let result = validate_attestation(
        request.jwt,
        &request.policy,
        request.expected_nonce.as_deref(),
        now,
    )?;
    serde_json::to_string(&result).map_err(|error| error.to_string())
}

pub fn validate_status_reference_json(raw: &str) -> Result<String, String> {
    let request: StatusReferenceRequest = serde_json::from_str(raw)
        .map_err(|error| format!("invalid status-list reference request: {error}"))?;
    let reference = validate_status_reference(&request.status, &request.policy)?;
    serde_json::to_string(&reference).map_err(|error| error.to_string())
}

pub fn validate_status_token_json(raw: &str) -> Result<u8, String> {
    let request: StatusTokenRequest = serde_json::from_str(raw)
        .map_err(|error| format!("invalid status-list token request: {error}"))?;
    let now = parse_now(&request.now)?;
    status_list_value(
        &request.token,
        &request.uri,
        request.index,
        &request.policy,
        now,
    )
}

fn policy_from_context(
    context: &Value,
    organization_id: &str,
) -> Result<KeyAttestationPolicy, String> {
    let profile = context
        .get("issuer_profile")
        .and_then(Value::as_object)
        .ok_or_else(|| "Resolved issuer context has no issuer profile".to_string())?;
    let context_org = context
        .get("organization_id")
        .or_else(|| profile.get("organization_id"))
        .map(py_string)
        .unwrap_or_default()
        .trim()
        .to_string();
    if context_org.is_empty() || context_org != organization_id {
        return Err("Issuer-profile key attestation policy is not tenant-bound".into());
    }
    let Some(raw) = profile.get("key_attestation_policy") else {
        return Ok(disabled_policy());
    };
    if raw.is_null() {
        return Ok(disabled_policy());
    }
    let raw = raw
        .as_object()
        .ok_or_else(|| "Issuer-profile key attestation policy must be an object".to_string())?;
    let mode = scalar_or_default(raw.get("mode"), "disabled");
    if !["disabled", "optional", "required"].contains(&mode.as_str()) {
        return Err(format!("Unsupported key attestation policy mode {mode:?}"));
    }
    let status_validation = scalar_or_default(raw.get("status_validation"), "required");
    if !["disabled", "if_present", "required"].contains(&status_validation.as_str()) {
        return Err(format!(
            "Unsupported key attestation status policy {status_validation:?}"
        ));
    }
    let roots = string_list(raw.get("trusted_root_certificates_pem"))?;
    let algorithms: BTreeSet<String> = string_list(raw.get("allowed_algorithms"))?
        .into_iter()
        .collect();
    let max_age = bounded_integer(raw.get("max_age_seconds"), 300, 1, 86_400)
        .map_err(|_| "max_age_seconds must be an integer from 1 through 86400".to_string())?;
    let status_max_age =
        bounded_integer(raw.get("status_list_max_age_seconds"), 86_400, 1, 604_800).map_err(
            |_| "status_list_max_age_seconds must be an integer from 1 through 604800".to_string(),
        )?;
    if mode != "disabled" && (roots.is_empty() || algorithms.is_empty()) {
        return Err(
            "Enabled key attestation policy requires trusted roots and allowed algorithms".into(),
        );
    }
    let allow_private = boolean_or_default(raw.get("status_list_allow_private_hosts"), false)
        .ok_or_else(|| "status_list_allow_private_hosts must be a boolean".to_string())?;
    let require_nonce = boolean_or_default(raw.get("require_nonce"), true)
        .ok_or_else(|| "require_nonce must be a boolean".to_string())?;
    let origins = string_list(raw.get("status_list_allowed_origins"))?
        .into_iter()
        .map(|origin| normalize_https_origin(&origin))
        .collect::<Result<Vec<_>, _>>()?;
    let status_roots = {
        let values = string_list(raw.get("status_list_trusted_root_certificates_pem"))?;
        if values.is_empty() {
            roots.clone()
        } else {
            values
        }
    };
    let status_algorithms = {
        let values: BTreeSet<String> = string_list(raw.get("status_list_allowed_algorithms"))?
            .into_iter()
            .collect();
        if values.is_empty() {
            algorithms.clone()
        } else {
            values
        }
    };
    if mode != "disabled" && status_validation != "disabled" && origins.is_empty() {
        return Err(
            "Enabled status validation requires an HTTPS status-list origin allowlist".into(),
        );
    }
    Ok(KeyAttestationPolicy {
        mode,
        trusted_root_certificates_pem: roots,
        allowed_algorithms: algorithms,
        required_key_storage: string_list(raw.get("required_key_storage"))?
            .into_iter()
            .collect(),
        required_user_authentication: string_list(raw.get("required_user_authentication"))?
            .into_iter()
            .collect(),
        max_age_seconds: max_age,
        require_nonce,
        status_validation,
        status_list_allowed_origins: origins,
        status_list_trusted_root_certificates_pem: status_roots,
        status_list_allowed_algorithms: status_algorithms,
        status_list_max_age_seconds: status_max_age,
        status_list_allow_private_hosts: allow_private,
        status_list_tls_ca_certificates_pem: string_list(
            raw.get("status_list_tls_ca_certificates_pem"),
        )?,
    })
}

fn disabled_policy() -> KeyAttestationPolicy {
    KeyAttestationPolicy {
        mode: "disabled".into(),
        trusted_root_certificates_pem: Vec::new(),
        allowed_algorithms: BTreeSet::new(),
        required_key_storage: BTreeSet::new(),
        required_user_authentication: BTreeSet::new(),
        max_age_seconds: 300,
        require_nonce: true,
        status_validation: "required".into(),
        status_list_allowed_origins: Vec::new(),
        status_list_trusted_root_certificates_pem: Vec::new(),
        status_list_allowed_algorithms: BTreeSet::new(),
        status_list_max_age_seconds: 86_400,
        status_list_allow_private_hosts: false,
        status_list_tls_ca_certificates_pem: Vec::new(),
    }
}

fn validate_attestation(
    jwt: String,
    policy: &KeyAttestationPolicy,
    expected_nonce: Option<&str>,
    now: DateTime<Utc>,
) -> Result<ValidatedAttestation, String> {
    if policy.mode == "disabled" {
        return Err("Issuer profile does not allow key-attestation-bound proofs".into());
    }
    let parts = jwt_parts(&jwt, "Key attestation JWT")?;
    let header = decode_json_object(parts[0], "header")?;
    let claims = decode_json_object(parts[1], "claims")?;
    if header.get("typ").and_then(Value::as_str) != Some("key-attestation+jwt") {
        return Err("Key attestation typ must be key-attestation+jwt".into());
    }
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| "Key attestation algorithm is not allowed by issuer profile".to_string())?;
    if !policy.allowed_algorithms.contains(algorithm) {
        return Err("Key attestation algorithm is not allowed by issuer profile".into());
    }
    let leaf = validate_certificate_chain(
        header.get("x5c"),
        &policy.trusted_root_certificates_pem,
        now,
    )?;
    verify_signature(
        &leaf,
        parts[2],
        &format!("{}.{}", parts[0], parts[1]),
        algorithm,
    )?;

    let iat = required_timestamp(&claims, "iat", "Key attestation")?;
    let exp = required_timestamp(&claims, "exp", "Key attestation")?;
    let now_timestamp = now.timestamp();
    if iat > now_timestamp + 30 {
        return Err("Key attestation iat is in the future".into());
    }
    if now_timestamp - iat > policy.max_age_seconds {
        return Err("Key attestation is older than issuer policy allows".into());
    }
    if exp <= now_timestamp {
        return Err("Key attestation has expired".into());
    }
    if exp <= iat {
        return Err("Key attestation exp must be later than iat".into());
    }
    if policy.require_nonce
        && (expected_nonce.is_none()
            || claims.get("nonce").and_then(Value::as_str) != expected_nonce)
    {
        return Err("Key attestation nonce does not match issuance nonce".into());
    }

    let keys = claims
        .get("attested_keys")
        .and_then(Value::as_array)
        .filter(|keys| !keys.is_empty())
        .ok_or_else(|| "Key attestation requires a non-empty attested_keys array".to_string())?;
    let private = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    let mut attested_keys = Vec::with_capacity(keys.len());
    for key in keys {
        let key = key.as_object().ok_or_else(|| {
            "Key attestation requires a non-empty attested_keys array".to_string()
        })?;
        if private.iter().any(|field| key.contains_key(*field)) {
            return Err("Key attestation contains private key material".into());
        }
        attested_keys.push(key.clone());
    }
    validate_assurance_list(
        claims.get("key_storage"),
        &policy.required_key_storage,
        "key_storage",
        "key-storage",
    )?;
    validate_assurance_list(
        claims.get("user_authentication"),
        &policy.required_user_authentication,
        "user_authentication",
        "user-authentication",
    )?;
    if let Some(certification) = claims.get("certification") {
        if !certification
            .as_str()
            .is_some_and(|value| value.starts_with("https://"))
        {
            return Err("Key attestation certification must be an HTTPS URL".into());
        }
    }

    let mut statuses = Vec::new();
    if let Some(status) = claims.get("status") {
        statuses.push(
            status
                .as_object()
                .ok_or_else(|| "Key attestation status must be an object".to_string())?
                .clone(),
        );
    }
    if let Some(storage_status) = claims.get("key_storage_status") {
        let storage_status = storage_status
            .as_object()
            .ok_or_else(|| "Key attestation key_storage_status must be an object".to_string())?;
        if required_timestamp(storage_status, "exp", "Key attestation")? <= now_timestamp {
            return Err("Key storage status has expired".into());
        }
        if let Some(status) = storage_status.get("status") {
            statuses.push(
                status
                    .as_object()
                    .ok_or_else(|| "Key storage status status claim must be an object".to_string())?
                    .clone(),
            );
        }
    }
    if policy.status_validation == "required" && statuses.is_empty() {
        return Err("Issuer policy requires key attestation status information".into());
    }
    Ok(ValidatedAttestation {
        jwt,
        attested_keys,
        claims,
        statuses,
    })
}

fn validate_assurance_list(
    value: Option<&Value>,
    required: &BTreeSet<String>,
    claim_name: &str,
    requirement_name: &str,
) -> Result<(), String> {
    let parsed = value.map(|value| {
        value
            .as_array()
            .filter(|values| !values.is_empty())
            .filter(|values| {
                values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
            })
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect::<BTreeSet<_>>()
            })
            .ok_or_else(|| format!("Key attestation {claim_name} must be a non-empty string array"))
    });
    if let Some(parsed) = parsed {
        let parsed = parsed?;
        if !required.is_subset(&parsed) {
            return Err(format!(
                "Key attestation does not meet {requirement_name} requirements"
            ));
        }
    } else if !required.is_empty() {
        return Err(format!(
            "Key attestation does not meet {requirement_name} requirements"
        ));
    }
    Ok(())
}

fn validate_status_reference(
    status: &Value,
    policy: &KeyAttestationPolicy,
) -> Result<StatusReference, String> {
    let reference = status
        .get("status_list")
        .and_then(Value::as_object)
        .ok_or_else(|| "Status claim requires a status_list object".to_string())?;
    let index = reference
        .get("idx")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Status-list idx must be a non-negative integer".to_string())?;
    let uri = reference
        .get("uri")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Status-list uri must be a non-empty string".to_string())?;
    let parsed = Url::parse(uri)
        .map_err(|_| "Status-list uri must be an HTTPS URL without credentials".to_string())?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err("Status-list uri must be an HTTPS URL without credentials".into());
    }
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "Status-list uri has an invalid port".to_string())?;
    let hostname = parsed
        .host_str()
        .ok_or_else(|| "Status-list uri must be an HTTPS URL without credentials".to_string())?
        .to_lowercase();
    let origin = origin(&parsed)?;
    if !policy.status_list_allowed_origins.contains(&origin) {
        return Err("Status-list uri origin is not allowed by issuer profile".into());
    }
    Ok(StatusReference {
        uri: uri.to_string(),
        index,
        hostname,
        port,
        allow_private_hosts: policy.status_list_allow_private_hosts,
    })
}

fn status_list_value(
    token: &str,
    uri: &str,
    index: u64,
    policy: &KeyAttestationPolicy,
    now: DateTime<Utc>,
) -> Result<u8, String> {
    let parts = jwt_parts(token, "Status List Token JWT")?;
    let header = decode_json_object(parts[0], "status-list header")?;
    let claims = decode_json_object(parts[1], "status-list claims")?;
    if header.get("typ").and_then(Value::as_str) != Some("statuslist+jwt") {
        return Err("Status List Token typ must be statuslist+jwt".into());
    }
    let algorithm = header.get("alg").and_then(Value::as_str).ok_or_else(|| {
        "Status List Token algorithm is not allowed by issuer profile".to_string()
    })?;
    if !policy.status_list_allowed_algorithms.contains(algorithm) {
        return Err("Status List Token algorithm is not allowed by issuer profile".into());
    }
    let leaf = validate_certificate_chain(
        header.get("x5c"),
        &policy.status_list_trusted_root_certificates_pem,
        now,
    )?;
    verify_signature(
        &leaf,
        parts[2],
        &format!("{}.{}", parts[0], parts[1]),
        algorithm,
    )?;
    if claims.get("sub").and_then(Value::as_str) != Some(uri) {
        return Err("Status List Token subject does not match referenced URI".into());
    }
    let iat = required_timestamp(&claims, "iat", "Status List Token")?;
    let now_timestamp = now.timestamp();
    if iat > now_timestamp + 30 {
        return Err("Status List Token iat is in the future".into());
    }
    if now_timestamp - iat > policy.status_list_max_age_seconds {
        return Err("Status List Token is older than issuer policy allows".into());
    }
    if let Some(exp) = claims.get("exp") {
        let exp =
            integer(exp).ok_or_else(|| "Status List Token exp must be an integer".to_string())?;
        if exp <= now_timestamp {
            return Err("Status List Token has expired".into());
        }
    }
    if let Some(ttl) = claims.get("ttl") {
        if integer(ttl).is_none_or(|ttl| ttl <= 0) {
            return Err("Status List Token ttl must be a positive integer".into());
        }
    }
    let status_list = claims
        .get("status_list")
        .and_then(Value::as_object)
        .ok_or_else(|| "Status List Token requires a status_list object".to_string())?;
    let bits = status_list
        .get("bits")
        .and_then(Value::as_u64)
        .filter(|bits| [1, 2, 4, 8].contains(bits))
        .ok_or_else(|| "Status List Token bits must be one of 1, 2, 4, or 8".to_string())?;
    let encoded = status_list
        .get("lst")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Status List Token lst must be base64url data".to_string())?;
    let compressed = b64url_decode(encoded)?;
    let mut decoder = ZlibDecoder::new(compressed.as_slice());
    let mut bytes = Vec::new();
    decoder
        .by_ref()
        .take((MAX_STATUS_LIST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "Status List Token lst is not valid ZLIB data".to_string())?;
    if bytes.len() > MAX_STATUS_LIST_BYTES || decoder.total_in() != compressed.len() as u64 {
        return Err("Status List Token expands beyond the safe size limit".into());
    }
    let bit_index = index
        .checked_mul(bits)
        .ok_or_else(|| "Status List Token index is out of bounds".to_string())?;
    let byte_index = usize::try_from(bit_index / 8)
        .map_err(|_| "Status List Token index is out of bounds".to_string())?;
    let byte = bytes
        .get(byte_index)
        .ok_or_else(|| "Status List Token index is out of bounds".to_string())?;
    let mask = if bits == 8 {
        u8::MAX
    } else {
        (1_u8 << bits) - 1
    };
    Ok((byte >> (bit_index % 8)) & mask)
}

fn validate_certificate_chain(
    encoded_chain: Option<&Value>,
    roots: &[String],
    now: DateTime<Utc>,
) -> Result<Vec<u8>, String> {
    let chain = encoded_chain
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| "Key attestation x5c must be a non-empty certificate array".to_string())?;
    if chain
        .iter()
        .any(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err("Key attestation x5c must be a non-empty certificate array".into());
    }
    let chain = chain
        .iter()
        .map(|value| {
            general_purpose::STANDARD
                .decode(value.as_str().unwrap_or_default())
                .map_err(|_| "Key attestation certificate encoding is invalid".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if roots.is_empty() {
        return Err("Key attestation policy has no trusted roots".into());
    }
    let config = ChainValidatorConfig {
        check_crl: false,
        check_ocsp: false,
        revocation_mode: "hard_fail".into(),
        validation_moment: Some(now),
        required_key_usage: vec![KeyUsage::DigitalSignature],
    };
    let mut validator = ChainValidator::with_config(config);
    for root in roots {
        validator
            .add_trust_anchor_pem(root)
            .map_err(|_| "Key attestation certificate encoding is invalid".to_string())?;
    }
    let result = validator
        .validate_chain_der(&chain)
        .map_err(|_| "Key attestation certificate encoding is invalid".to_string())?;
    if !result.valid {
        let detail = if result.errors.is_empty() {
            "native chain validation failed".into()
        } else {
            result.errors.join("; ")
        };
        return Err(format!(
            "Key attestation certificate chain is not trusted by issuer profile: {detail}"
        ));
    }
    Ok(chain[0].clone())
}

fn verify_signature(
    certificate: &[u8],
    encoded_signature: &str,
    message: &str,
    algorithm: &str,
) -> Result<(), String> {
    let public_key = marty_crypto::certificate::get_certificate_public_key(certificate)
        .map_err(|_| "Key attestation algorithm does not match certificate key".to_string())?;
    let algorithm = signature_algorithm(algorithm, &public_key)
        .map_err(|_| "Key attestation algorithm does not match certificate key".to_string())?;
    let signature = b64url_decode(encoded_signature)?;
    let valid =
        marty_crypto::verify_signature(algorithm, &public_key, message.as_bytes(), &signature)
            .map_err(|_| "Key attestation algorithm does not match certificate key".to_string())?;
    if !valid {
        return Err("Key attestation signature verification failed".into());
    }
    Ok(())
}

fn signature_algorithm(value: &str, public_key: &[u8]) -> Result<SignatureAlgorithm, String> {
    match value.to_ascii_lowercase().replace('-', "_").as_str() {
        "ecdsa_p256_sha256" | "es256" => Ok(SignatureAlgorithm::EcdsaP256Sha256),
        "ecdsa_p384_sha384" | "es384" => Ok(SignatureAlgorithm::EcdsaP384Sha384),
        "rsa_pkcs1_sha256" | "rs256" => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
        "rsa_pkcs1_sha384" | "rs384" => Ok(SignatureAlgorithm::RsaPkcs1Sha384),
        "rsa_pkcs1_sha512" | "rs512" => Ok(SignatureAlgorithm::RsaPkcs1Sha512),
        "rsa_pss_sha256" | "ps256" => Ok(SignatureAlgorithm::RsaPssSha256),
        "rsa_pss_sha384" | "ps384" => Ok(SignatureAlgorithm::RsaPssSha384),
        "rsa_pss_sha512" | "ps512" => Ok(SignatureAlgorithm::RsaPssSha512),
        "eddsa" => match marty_crypto::serialization::detect_public_key_type(public_key)
            .map_err(|error| error.to_string())?
            .as_str()
        {
            "Ed25519" => Ok(SignatureAlgorithm::Ed25519),
            "Ed448" => Ok(SignatureAlgorithm::Ed448),
            _ => Err("EdDSA signature requires an Ed25519 or Ed448 public key".into()),
        },
        _ => Err("unsupported signature algorithm".into()),
    }
}

fn proof_header(jwt: &str) -> Result<Map<String, Value>, String> {
    let parts = jwt_parts(jwt, "Proof JWT")?;
    decode_json_object(parts[0], "proof header")
        .map_err(|_| "Proof JWT has an invalid JOSE header".to_string())
}

fn jwt_parts<'a>(jwt: &'a str, name: &str) -> Result<[&'a str; 3], String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    parts.try_into().map_err(|_| match name {
        "Proof JWT" => "Proof JWT must have exactly three parts".into(),
        "Status List Token JWT" => "Status List Token JWT must have exactly three parts".into(),
        _ => "Key attestation JWT must have exactly three parts".into(),
    })
}

fn decode_json_object(value: &str, name: &str) -> Result<Map<String, Value>, String> {
    let bytes = b64url_decode(value)?;
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|_| format!("Key attestation has invalid {name} JSON"))?
        .as_object()
        .cloned()
        .ok_or_else(|| format!("Key attestation {name} must be a JSON object"))
}

fn b64url_decode(value: &str) -> Result<Vec<u8>, String> {
    let mut padded = value.to_string();
    padded.extend(std::iter::repeat_n('=', (4 - value.len() % 4) % 4));
    general_purpose::URL_SAFE
        .decode(padded)
        .map_err(|_| "JWT contains invalid base64url".to_string())
}

fn required_timestamp(
    values: &Map<String, Value>,
    name: &str,
    subject: &str,
) -> Result<i64, String> {
    values
        .get(name)
        .and_then(integer)
        .ok_or_else(|| format!("{subject} requires integer {name} claim"))
}

fn integer(value: &Value) -> Option<i64> {
    value.as_i64()
}

fn parse_now(value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| "validation time must be RFC3339".to_string())
}

fn string_list(value: Option<&Value>) -> Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| "Key attestation policy list field must be an array".to_string())?;
    let result: Vec<String> = values
        .iter()
        .map(|value| py_string(value).trim().to_string())
        .collect();
    if result.iter().any(String::is_empty) {
        return Err("Key attestation policy list values must be non-empty strings".into());
    }
    Ok(result)
}

fn py_string(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn scalar_or_default(value: Option<&Value>, default: &str) -> String {
    value
        .filter(|value| !is_falsy(value))
        .map_or_else(|| default.to_string(), py_string)
}

fn is_falsy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => true,
        Value::Number(value) => value.as_f64() == Some(0.0),
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        Value::Bool(true) => false,
    }
}

fn bounded_integer(value: Option<&Value>, default: i64, min: i64, max: i64) -> Result<i64, ()> {
    let value = value.map_or(Some(default), Value::as_i64).ok_or(())?;
    (min..=max).contains(&value).then_some(value).ok_or(())
}

fn boolean_or_default(value: Option<&Value>, default: bool) -> Option<bool> {
    value.map_or(Some(default), Value::as_bool)
}

fn normalize_https_origin(value: &str) -> Result<String, String> {
    let parsed = Url::parse(value).map_err(|_| {
        "Status-list allowed origins must be HTTPS origins without paths or credentials".to_string()
    })?;
    if parsed.scheme() != "https"
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !matches!(parsed.path(), "" | "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "Status-list allowed origins must be HTTPS origins without paths or credentials".into(),
        );
    }
    origin(&parsed)
}

fn origin(url: &Url) -> Result<String, String> {
    let host = match url.host() {
        Some(Host::Ipv6(value)) => format!("[{value}]"),
        Some(value) => value.to_string().to_lowercase(),
        None => return Err("Status-list allowed origin has an invalid port".into()),
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "Status-list allowed origin has an invalid port".to_string())?;
    Ok(format!(
        "https://{host}{}",
        if port == 443 {
            String::new()
        } else {
            format!(":{port}")
        }
    ))
}
