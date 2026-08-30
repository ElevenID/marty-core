//! Reusable credential preparation for DID-mediated remote signers.
//!
//! The preparation retains all format state in Rust while an external KMS
//! signs only the exact bytes returned by the canonical format kernel.

use std::{collections::HashMap, fmt};

use isomdl::digest_executor::{DigestExecutor, SerialDigestExecutor};
use rand::Rng;
use serde_json::Value;

use crate::{
    formats::{
        jwt_vc::{
            apply_open_badge_v3_profile, prepare_jwt_vc_with_options, JwtVcPreparationOptions,
            PreparedJwtVc,
        },
        mdoc::{
            plan_validated_mdoc_batch, prepare_mdoc_with_credential_id_and_device_key,
            prepare_validated_mdoc_batch_with_digest_executor, validate_mdoc_credential_id,
            validate_mdoc_preparation, MdocBatchPlanError, PreparedMdoc,
            ValidatedMdocBatchPlanItem,
        },
        sd_jwt::{prepare_sd_jwt_with_options, PreparedSdJwt, SdJwtPreparationOptions},
    },
    signer::CredentialSigner,
    types::{CredentialClaims, CredentialPayloadFormat, SigningAlgorithm},
    Oid4vciError, Oid4vciResult,
};

const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const DUPLICATE_MDOC_BATCH_ID: &str = "mDoc preparation batch contains duplicate batch identity";
const DUPLICATE_MDOC_CREDENTIAL_ID: &str =
    "mDoc preparation batch contains duplicate credential ID";

#[derive(Clone, Debug)]
pub struct RemoteSignerMetadata {
    issuer_id: String,
    verification_method_id: String,
    algorithm: SigningAlgorithm,
}

impl RemoteSignerMetadata {
    pub fn new(
        issuer_id: &str,
        verification_method_id: &str,
        algorithm: &str,
    ) -> Oid4vciResult<Self> {
        if !issuer_id.starts_with("did:") {
            return Err(protocol_error("issuer_id must be a DID"));
        }
        if !verification_method_id.starts_with(&format!("{issuer_id}#")) {
            return Err(protocol_error(
                "verification_method_id must identify a key controlled by the issuer DID",
            ));
        }
        Ok(Self {
            issuer_id: issuer_id.to_owned(),
            verification_method_id: verification_method_id.to_owned(),
            algorithm: parse_algorithm(algorithm)?,
        })
    }
}

impl CredentialSigner for RemoteSignerMetadata {
    fn sign(&self, _message: &[u8]) -> Oid4vciResult<Vec<u8>> {
        Err(Oid4vciError::SigningError(
            "metadata-only remote signer cannot sign".to_owned(),
        ))
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    fn kid_url(&self) -> String {
        self.verification_method_id.clone()
    }
}

#[derive(Clone, Debug)]
pub struct RemoteSdJwtRequest {
    pub issuer_id: String,
    pub verification_method_id: String,
    pub algorithm: String,
    pub subject_id: Option<String>,
    pub credential_type: String,
    pub claims: HashMap<String, Value>,
    pub expiration_seconds: Option<i64>,
    pub selective_disclosure_claims: Vec<String>,
    pub credential_format: Option<String>,
    pub credential_id: Option<String>,
    pub holder_jwk: Option<Value>,
    pub issuer_certificate_chain: Vec<String>,
}

pub fn prepare_remote_sd_jwt(request: RemoteSdJwtRequest) -> Oid4vciResult<PreparedSdJwt> {
    validate_credential_id(request.credential_id.as_deref())?;
    validate_certificate_chain(&request.issuer_certificate_chain)?;
    let signer = RemoteSignerMetadata::new(
        &request.issuer_id,
        &request.verification_method_id,
        &request.algorithm,
    )?;
    let confirmation = holder_confirmation(request.subject_id.as_deref(), request.holder_jwk)?;
    let claims = credential_claims(
        request.subject_id,
        request.credential_type,
        request.claims,
        request.expiration_seconds,
        request.selective_disclosure_claims,
        CredentialPayloadFormat::IetfSdJwt,
    );
    prepare_sd_jwt_with_options(
        &signer,
        &claims,
        SdJwtPreparationOptions {
            credential_id: request.credential_id,
            typ: Some(
                if request.credential_format.as_deref() == Some("dc+sd-jwt") {
                    "dc+sd-jwt"
                } else {
                    "vc+sd-jwt"
                }
                .to_owned(),
            ),
            confirmation,
            x5c: request.issuer_certificate_chain,
            include_nbf: true,
        },
    )
}

#[derive(Clone, Debug)]
pub struct RemoteJwtVcRequest {
    pub issuer_id: String,
    pub verification_method_id: String,
    pub algorithm: String,
    pub subject_id: Option<String>,
    pub credential_type: String,
    pub claims: HashMap<String, Value>,
    pub expiration_seconds: Option<i64>,
    pub credential_id: Option<String>,
    pub credential_subject: Option<Value>,
    pub credential_profile: Option<String>,
    pub achievement_id: Option<String>,
}

pub fn prepare_remote_jwt_vc(request: RemoteJwtVcRequest) -> Oid4vciResult<PreparedJwtVc> {
    validate_credential_id(request.credential_id.as_deref())?;
    let signer = RemoteSignerMetadata::new(
        &request.issuer_id,
        &request.verification_method_id,
        &request.algorithm,
    )?;
    let mut raw_claims = request.claims;
    let credential_status = raw_claims.remove("credentialStatus");
    validate_explicit_subject(request.credential_subject.as_ref())?;
    if request.credential_subject.is_some() && !raw_claims.is_empty() {
        return Err(protocol_error(
            "explicit credential_subject cannot be combined with subject claims",
        ));
    }
    let include_subject_claim = request.subject_id.as_deref().is_some_and(|holder| {
        request
            .credential_subject
            .as_ref()
            .is_none_or(|subject| explicit_subject_identifies_holder(subject, holder))
    });
    let mut claims = credential_claims(
        request.subject_id,
        request.credential_type,
        raw_claims,
        request.expiration_seconds,
        Vec::new(),
        CredentialPayloadFormat::W3cVcdmV2JwtVc,
    );
    let mut options = JwtVcPreparationOptions {
        credential_id: request.credential_id,
        credential_subject: request.credential_subject,
        credential_status,
        include_subject_claim,
        include_vc_id: false,
        include_nbf: true,
    };
    match request.credential_profile.as_deref() {
        Some("open_badge_v3") => {
            let achievement_id = request
                .achievement_id
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| protocol_error("open_badge_v3 profile requires achievement_id"))?;
            apply_open_badge_v3_profile(&mut claims, &mut options, achievement_id)?;
        }
        Some(profile) => {
            return Err(protocol_error(format!(
                "Unsupported JWT-VC credential profile: {profile}"
            )))
        }
        None if request.achievement_id.is_some() => {
            return Err(protocol_error(
                "achievement_id is only valid with the open_badge_v3 profile",
            ))
        }
        None => {}
    }
    prepare_jwt_vc_with_options(&signer, &claims, options)
}

#[derive(Clone, Debug)]
pub struct RemoteMdocRequest {
    pub issuer_id: String,
    pub algorithm: String,
    pub credential_type: String,
    pub namespace: String,
    pub claims: HashMap<String, Value>,
    pub expiration_seconds: Option<i64>,
    pub credential_id: Option<String>,
    pub holder_jwk: Option<Value>,
}

/// One caller-ordered remote mdoc preparation in a digest batch.
///
/// `batch_id` is routing metadata only. It is distinct from the optional
/// `urn:uuid` credential identifier embedded in the prepared credential. The
/// request can contain sensitive claims, so its debug representation is fully
/// redacted.
#[derive(Clone)]
pub struct RemoteMdocBatchItem {
    batch_id: u64,
    request: RemoteMdocRequest,
}

impl RemoteMdocBatchItem {
    pub fn new(batch_id: u64, request: RemoteMdocRequest) -> Self {
        Self { batch_id, request }
    }

    pub fn batch_id(&self) -> u64 {
        self.batch_id
    }
}

impl fmt::Debug for RemoteMdocBatchItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteMdocBatchItem")
            .field("contents", &"[redacted]")
            .finish()
    }
}

/// One prepared mdoc restored to its caller-assigned batch identity.
///
/// The wrapper deliberately has no serialization representation. Callers can
/// borrow or consume the existing opaque [`PreparedMdoc`] and use the existing
/// signing and assembly route unchanged.
pub struct PreparedRemoteMdocBatchItem {
    batch_id: u64,
    prepared_mdoc: PreparedMdoc,
}

impl PreparedRemoteMdocBatchItem {
    pub fn batch_id(&self) -> u64 {
        self.batch_id
    }

    pub fn prepared_mdoc(&self) -> &PreparedMdoc {
        &self.prepared_mdoc
    }

    pub fn into_prepared_mdoc(self) -> PreparedMdoc {
        self.prepared_mdoc
    }
}

impl fmt::Debug for PreparedRemoteMdocBatchItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRemoteMdocBatchItem")
            .field("contents", &"[redacted]")
            .finish()
    }
}

pub fn prepare_remote_mdoc(request: RemoteMdocRequest) -> Oid4vciResult<PreparedMdoc> {
    validate_credential_id(request.credential_id.as_deref())?;
    let algorithm = parse_mdoc_algorithm(&request.algorithm)?;
    let holder_jwk = request.holder_jwk.map(public_jwk).transpose()?;
    let signer = MdocSignerMetadata {
        issuer_id: request.issuer_id,
        algorithm,
    };
    prepare_mdoc_with_credential_id_and_device_key(
        &signer,
        &mdoc_credential_claims(
            request.credential_type,
            request.namespace,
            request.claims,
            request.expiration_seconds,
        ),
        request.credential_id.as_deref(),
        holder_jwk.as_ref(),
    )
}

/// Prepare a caller-ordered batch of remote mdocs with one scalar digest call.
///
/// Every request is validated before UUID, time, or salt allocation. Digest
/// jobs from all credentials are then flattened into one serial executor call
/// and restored by `(batch_id, job_id)`. Any error discards the entire batch;
/// this function prepares signing inputs only and does not sign, activate, or
/// persist credentials.
pub fn prepare_remote_mdoc_batch(
    batch: Vec<RemoteMdocBatchItem>,
) -> Oid4vciResult<Vec<PreparedRemoteMdocBatchItem>> {
    let mut rng = rand::thread_rng();
    prepare_remote_mdoc_batch_with_sources(
        batch,
        uuid::Uuid::new_v4,
        chrono::Utc::now,
        || rng.gen(),
        &SerialDigestExecutor,
    )
}

fn prepare_remote_mdoc_batch_with_sources(
    batch: Vec<RemoteMdocBatchItem>,
    mut next_uuid: impl FnMut() -> uuid::Uuid,
    mut next_now: impl FnMut() -> chrono::DateTime<chrono::Utc>,
    next_salt: impl FnMut() -> [u8; 32],
    digest_executor: &dyn DigestExecutor,
) -> Oid4vciResult<Vec<PreparedRemoteMdocBatchItem>> {
    let routed = batch
        .into_iter()
        .map(|item| (item.batch_id, item.request))
        .collect();
    let inputs = plan_validated_mdoc_batch(
        routed,
        validate_remote_mdoc_batch_item,
        &mut next_uuid,
        &mut next_now,
    )
    .map_err(map_mdoc_batch_plan_error)?;

    if inputs.is_empty() {
        return Ok(Vec::new());
    }

    prepare_validated_mdoc_batch_with_digest_executor(inputs, next_salt, digest_executor).map(
        |prepared| {
            prepared
                .into_iter()
                .map(|item| PreparedRemoteMdocBatchItem {
                    batch_id: item.batch_id,
                    prepared_mdoc: item.prepared_mdoc,
                })
                .collect()
        },
    )
}

fn validate_remote_mdoc_batch_item(
    request: RemoteMdocRequest,
) -> Oid4vciResult<ValidatedMdocBatchPlanItem> {
    validate_credential_id(request.credential_id.as_deref())?;
    let algorithm = parse_mdoc_algorithm(&request.algorithm)?;
    let holder_jwk = request.holder_jwk.map(public_jwk).transpose()?;
    let credential_id = request
        .credential_id
        .map(|credential_id| {
            validate_mdoc_credential_id(&credential_id)
                .map(|credential_uuid| (credential_id, credential_uuid))
        })
        .transpose()?;
    let claims = mdoc_credential_claims(
        request.credential_type,
        request.namespace,
        request.claims,
        request.expiration_seconds,
    );
    let preparation = validate_mdoc_preparation(algorithm, &claims, holder_jwk.as_ref())?;

    Ok(match credential_id {
        Some((credential_id, credential_uuid)) => {
            ValidatedMdocBatchPlanItem::with_explicit_credential_id(
                credential_id,
                credential_uuid,
                preparation,
            )
        }
        None => ValidatedMdocBatchPlanItem::with_generated_credential_id(preparation),
    })
}

fn map_mdoc_batch_plan_error(error: MdocBatchPlanError) -> Oid4vciError {
    let _ordinal = error.ordinal();
    match error {
        MdocBatchPlanError::DuplicateBatchIdentity { .. } => {
            protocol_error(DUPLICATE_MDOC_BATCH_ID)
        }
        MdocBatchPlanError::DuplicateCredentialId { .. } => {
            protocol_error(DUPLICATE_MDOC_CREDENTIAL_ID)
        }
        MdocBatchPlanError::ItemValidation { source, .. }
        | MdocBatchPlanError::ItemPreparation { source, .. } => source,
    }
}

fn parse_mdoc_algorithm(algorithm: &str) -> Oid4vciResult<SigningAlgorithm> {
    match algorithm {
        "ES256" => Ok(SigningAlgorithm::ES256),
        "ES384" => Ok(SigningAlgorithm::ES384),
        _ => Err(protocol_error(
            "mDoc remote signing supports ES256 and ES384 only",
        )),
    }
}

fn mdoc_credential_claims(
    credential_type: String,
    namespace: String,
    claims: HashMap<String, Value>,
    expiration_seconds: Option<i64>,
) -> CredentialClaims {
    CredentialClaims {
        subject_id: None,
        credential_type: credential_type.clone(),
        claims,
        expiration_seconds,
        selective_disclosure_claims: Vec::new(),
        mdoc_namespace: Some(namespace),
        mdoc_doctype: Some(credential_type),
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::default(),
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    }
}

#[derive(Debug)]
struct MdocSignerMetadata {
    issuer_id: String,
    algorithm: SigningAlgorithm,
}

impl CredentialSigner for MdocSignerMetadata {
    fn sign(&self, _message: &[u8]) -> Oid4vciResult<Vec<u8>> {
        Err(Oid4vciError::SigningError(
            "metadata-only mDoc signer cannot sign".to_owned(),
        ))
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    fn kid_url(&self) -> String {
        self.issuer_id.clone()
    }
}

fn credential_claims(
    subject_id: Option<String>,
    credential_type: String,
    claims: HashMap<String, Value>,
    expiration_seconds: Option<i64>,
    selective_disclosure_claims: Vec<String>,
    credential_payload_format: CredentialPayloadFormat,
) -> CredentialClaims {
    CredentialClaims {
        subject_id,
        credential_type,
        claims,
        expiration_seconds,
        selective_disclosure_claims,
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    }
}

fn holder_confirmation(
    subject_id: Option<&str>,
    holder_jwk: Option<Value>,
) -> Oid4vciResult<Option<Value>> {
    match (subject_id, holder_jwk) {
        (Some(_), Some(holder)) => Ok(Some(serde_json::json!({"jwk": public_jwk(holder)?}))),
        (Some(subject), None) => Ok(Some(serde_json::json!({"kid": subject}))),
        (None, Some(_)) => Err(protocol_error("holder_jwk requires subject_id")),
        (None, None) => Ok(None),
    }
}

fn public_jwk(mut holder: Value) -> Oid4vciResult<Value> {
    let object = holder
        .as_object_mut()
        .ok_or_else(|| protocol_error("holder JWK must be an object"))?;
    for secret in PRIVATE_JWK_MEMBERS {
        object.remove(*secret);
    }
    Ok(holder)
}

fn validate_explicit_subject(subject: Option<&Value>) -> Oid4vciResult<()> {
    let Some(subject) = subject else {
        return Ok(());
    };
    let valid = match subject {
        Value::Object(object) => !object.is_empty(),
        Value::Array(items) => {
            !items.is_empty()
                && items
                    .iter()
                    .all(|item| item.as_object().is_some_and(|object| !object.is_empty()))
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(protocol_error(
            "credential_subject must be a non-empty object or list of non-empty objects",
        ))
    }
}

fn explicit_subject_identifies_holder(subject: &Value, holder: &str) -> bool {
    match subject {
        Value::Object(object) => object.get("id").and_then(Value::as_str) == Some(holder),
        Value::Array(subjects) => subjects.iter().any(|item| {
            item.as_object()
                .and_then(|object| object.get("id"))
                .and_then(Value::as_str)
                == Some(holder)
        }),
        _ => false,
    }
}

fn validate_credential_id(credential_id: Option<&str>) -> Oid4vciResult<()> {
    if credential_id.is_some_and(|value| value.trim().is_empty()) {
        Err(protocol_error("credential_id cannot be empty"))
    } else {
        Ok(())
    }
}

fn validate_certificate_chain(chain: &[String]) -> Oid4vciResult<()> {
    if chain
        .iter()
        .any(|certificate| certificate.trim().is_empty())
    {
        Err(protocol_error(
            "issuer certificate chain contains an invalid x5c entry",
        ))
    } else {
        Ok(())
    }
}

fn parse_algorithm(algorithm: &str) -> Oid4vciResult<SigningAlgorithm> {
    match algorithm {
        "ES256" => Ok(SigningAlgorithm::ES256),
        "EdDSA" => Ok(SigningAlgorithm::EdDSA),
        "ES256K" => Ok(SigningAlgorithm::ES256K),
        "ES384" => Ok(SigningAlgorithm::ES384),
        "RS256" => Ok(SigningAlgorithm::RS256),
        _ => Err(protocol_error(format!("Unknown algorithm: {algorithm}"))),
    }
}

fn protocol_error(message: impl Into<String>) -> Oid4vciError {
    Oid4vciError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        collections::HashMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use isomdl::digest_executor::{
        DigestExecutionError, DigestExecutor, DigestJob, DigestResult, SerialDigestExecutor,
    };

    use super::{
        prepare_remote_jwt_vc, prepare_remote_mdoc, prepare_remote_mdoc_batch,
        prepare_remote_mdoc_batch_with_sources, prepare_remote_sd_jwt, RemoteJwtVcRequest,
        RemoteMdocBatchItem, RemoteMdocRequest, RemoteSdJwtRequest,
    };

    #[derive(Default)]
    struct CountingDigestExecutor {
        calls: AtomicUsize,
        jobs: AtomicUsize,
    }

    impl DigestExecutor for CountingDigestExecutor {
        fn execute(&self, jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.jobs.store(jobs.len(), Ordering::Relaxed);
            SerialDigestExecutor.execute(jobs)
        }
    }

    struct MustNotExecute;

    impl DigestExecutor for MustNotExecute {
        fn execute(&self, _jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError> {
            panic!("invalid or empty batches must not invoke the executor")
        }
    }

    fn segment(value: &str, index: usize) -> serde_json::Value {
        let encoded = value.split('.').nth(index).expect("JWT segment");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).expect("base64url")).expect("JSON")
    }

    fn remote_mdoc_request(
        credential_id: Option<&str>,
        algorithm: &str,
        claims: HashMap<String, serde_json::Value>,
    ) -> RemoteMdocRequest {
        RemoteMdocRequest {
            issuer_id: "did:web:issuer.example".into(),
            algorithm: algorithm.into(),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            namespace: "org.iso.18013.5.1".into(),
            claims,
            expiration_seconds: Some(3600),
            credential_id: credential_id.map(str::to_owned),
            holder_jwk: None,
        }
    }

    fn fixed_time(second: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(&format!("2026-08-29T12:34:{second:02}Z"))
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn invalid_batch_error_without_sources(invalid: RemoteMdocRequest) -> crate::Oid4vciError {
        let valid = remote_mdoc_request(
            None,
            "ES256",
            HashMap::from([("family_name".into(), serde_json::json!("Sensitive Smith"))]),
        );
        prepare_remote_mdoc_batch_with_sources(
            vec![
                RemoteMdocBatchItem::new(91, valid),
                RemoteMdocBatchItem::new(7, invalid),
            ],
            || panic!("validation must finish before UUID allocation"),
            || panic!("validation must finish before time allocation"),
            || panic!("validation must finish before salt allocation"),
            &MustNotExecute,
        )
        .unwrap_err()
    }

    #[test]
    fn sd_jwt_preserves_remote_security_metadata() {
        let prepared = prepare_remote_sd_jwt(RemoteSdJwtRequest {
            issuer_id: "did:web:issuer.example".to_owned(),
            verification_method_id: "did:web:issuer.example#key-1".to_owned(),
            algorithm: "ES256".to_owned(),
            subject_id: Some("did:key:holder".to_owned()),
            credential_type: "AccessBadge".to_owned(),
            claims: HashMap::from([("name".to_owned(), serde_json::json!("Alice"))]),
            expiration_seconds: Some(3600),
            selective_disclosure_claims: vec!["name".to_owned()],
            credential_format: Some("dc+sd-jwt".to_owned()),
            credential_id: Some("urn:uuid:00000000-0000-0000-0000-000000000123".to_owned()),
            holder_jwk: Some(
                serde_json::json!({"kty":"EC","crv":"P-256","x":"x","y":"y","d":"secret"}),
            ),
            issuer_certificate_chain: vec!["leaf".to_owned(), "issuer".to_owned()],
        })
        .expect("SD-JWT preparation");
        let header = segment(&prepared.signing_input, 0);
        let payload = segment(&prepared.signing_input, 1);
        assert_eq!(header["typ"], "dc+sd-jwt");
        assert_eq!(header["x5c"], serde_json::json!(["leaf", "issuer"]));
        assert!(payload["cnf"]["jwk"].get("d").is_none());
        assert!(payload.get("_sd").is_some());
    }

    #[test]
    fn jwt_vc_preserves_explicit_subject_and_status() {
        let prepared = prepare_remote_jwt_vc(RemoteJwtVcRequest {
            issuer_id: "did:web:issuer.example".to_owned(),
            verification_method_id: "did:web:issuer.example#key-1".to_owned(),
            algorithm: "ES256".to_owned(),
            subject_id: Some("did:key:holder".to_owned()),
            credential_type: "AccessBadge".to_owned(),
            claims: HashMap::from([(
                "credentialStatus".to_owned(),
                serde_json::json!({"type":"BitstringStatusListEntry"}),
            )]),
            expiration_seconds: Some(3600),
            credential_id: Some("urn:uuid:00000000-0000-0000-0000-000000000456".to_owned()),
            credential_subject: Some(serde_json::json!([{"id":"did:example:subject"}])),
            credential_profile: None,
            achievement_id: None,
        })
        .expect("JWT-VC preparation");
        let payload = segment(&prepared.signing_input, 1);
        assert!(payload.get("sub").is_none());
        assert_eq!(
            payload["vc"]["credentialStatus"]["type"],
            "BitstringStatusListEntry"
        );
    }

    #[test]
    fn mdoc_preserves_reserved_identity_and_device_binding() {
        let prepared = prepare_remote_mdoc(RemoteMdocRequest {
            issuer_id: "did:web:issuer.example".to_owned(),
            algorithm: "ES256".to_owned(),
            credential_type: "org.iso.18013.5.1.mDL".to_owned(),
            namespace: "org.iso.18013.5.1".to_owned(),
            claims: HashMap::from([("family_name".to_owned(), serde_json::json!("Smith"))]),
            expiration_seconds: Some(3600),
            credential_id: Some("urn:uuid:00000000-0000-0000-0000-000000000789".to_owned()),
            holder_jwk: Some(serde_json::json!({
                "kty": "EC", "crv": "P-256", "alg": "ES256",
                "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
                "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
                "d": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
            })),
        })
        .expect("mDoc preparation");
        assert_eq!(
            prepared.credential_id,
            "urn:uuid:00000000-0000-0000-0000-000000000789"
        );
        assert!(!prepared.tbs_data.is_empty());
    }

    #[test]
    fn mdoc_batch_preserves_caller_order_identity_and_redacts_debug_output() {
        let requests = [
            (91, "000000000091", 2usize),
            (7, "000000000007", 1usize),
            (42, "000000000042", 0usize),
        ];
        let batch = requests
            .iter()
            .map(|(batch_id, suffix, claim_count)| {
                let claims = (0..*claim_count)
                    .map(|index| {
                        (
                            format!("private_claim_{index}"),
                            serde_json::json!(format!("Sensitive value {index}")),
                        )
                    })
                    .collect();
                RemoteMdocBatchItem::new(
                    *batch_id,
                    remote_mdoc_request(
                        Some(&format!("urn:uuid:00000000-0000-0000-0000-{suffix}")),
                        if *batch_id == 7 { "ES384" } else { "ES256" },
                        claims,
                    ),
                )
            })
            .collect::<Vec<_>>();
        let input_debug = format!("{:?}", batch[0]);
        for sensitive in ["Sensitive", "private_claim", "91", "000000000091"] {
            assert!(!input_debug.contains(sensitive));
        }

        let executor = CountingDigestExecutor::default();
        let mut times = [fixed_time(56), fixed_time(57), fixed_time(58)].into_iter();
        let mut salts = (0..3).map(|salt| std::array::from_fn(|index| (salt * 41 + index) as u8));
        let prepared = prepare_remote_mdoc_batch_with_sources(
            batch,
            || panic!("reserved credential IDs must not allocate UUIDs"),
            || times.next().expect("one timestamp per credential"),
            || salts.next().expect("one salt per claim"),
            &executor,
        )
        .unwrap();

        assert!(times.next().is_none());
        assert!(salts.next().is_none());
        assert_eq!(executor.calls.load(Ordering::Relaxed), 1);
        assert_eq!(executor.jobs.load(Ordering::Relaxed), 3);
        assert_eq!(
            prepared
                .iter()
                .map(|item| item.batch_id())
                .collect::<Vec<_>>(),
            [91, 7, 42]
        );
        for (prepared, (_, suffix, _)) in prepared.iter().zip(requests) {
            assert_eq!(
                prepared.prepared_mdoc().credential_id,
                format!("urn:uuid:00000000-0000-0000-0000-{suffix}")
            );
            assert!(!prepared.prepared_mdoc().tbs_data.is_empty());
            let debug = format!("{prepared:?}");
            for sensitive in ["Sensitive", suffix, "91", "42"] {
                assert!(!debug.contains(sensitive));
            }
        }
        let consumed = prepared.into_iter().next().unwrap().into_prepared_mdoc();
        assert_eq!(
            consumed.credential_id,
            "urn:uuid:00000000-0000-0000-0000-000000000091"
        );
    }

    #[test]
    fn mdoc_batch_validates_every_request_before_uuid_time_salt_or_execution() {
        let error =
            invalid_batch_error_without_sources(remote_mdoc_request(None, "RS256", HashMap::new()));
        let crate::Oid4vciError::InvalidRequest(message) = error else {
            panic!("remote mdoc algorithm failures must use the request error boundary")
        };
        assert_eq!(message, "mDoc remote signing supports ES256 and ES384 only");
        invalid_batch_error_without_sources(remote_mdoc_request(
            Some("not-a-uuid"),
            "ES256",
            HashMap::new(),
        ));

        let mut invalid_holder = remote_mdoc_request(None, "ES256", HashMap::new());
        invalid_holder.holder_jwk = Some(serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": "missing-y"
        }));
        invalid_batch_error_without_sources(invalid_holder);

        invalid_batch_error_without_sources(remote_mdoc_request(
            None,
            "ES256",
            HashMap::from([("_mdoc_x5c".into(), serde_json::json!("not-an-array"))]),
        ));
    }

    #[test]
    fn mdoc_batch_rejects_extreme_validity_before_every_source_without_a_prefix() {
        for expiration_seconds in [i64::MIN, i64::MAX] {
            let mut invalid = remote_mdoc_request(
                None,
                "ES256",
                HashMap::from([("family_name".into(), serde_json::json!("Sensitive Smith"))]),
            );
            invalid.expiration_seconds = Some(expiration_seconds);

            let error = invalid_batch_error_without_sources(invalid);
            let crate::Oid4vciError::MdocError(message) = error else {
                panic!("validity range failures must use the mdoc error boundary")
            };
            assert_eq!(message, "mdoc validity period is out of range");
            assert!(!message.contains(&expiration_seconds.to_string()));
        }
    }

    #[test]
    fn mdoc_batch_rejects_signed_at_overflow_before_salts_or_execution() {
        let mut first = remote_mdoc_request(
            Some("urn:uuid:00000000-0000-0000-0000-000000000091"),
            "ES256",
            HashMap::from([("family_name".into(), serde_json::json!("Sensitive Smith"))]),
        );
        first.expiration_seconds = Some(86_400);
        let mut overflow = remote_mdoc_request(
            Some("urn:uuid:00000000-0000-0000-0000-000000000007"),
            "ES256",
            HashMap::from([("family_name".into(), serde_json::json!("Sensitive Jones"))]),
        );
        overflow.expiration_seconds = Some(86_400);
        let mut times = [fixed_time(56), chrono::DateTime::<chrono::Utc>::MAX_UTC].into_iter();

        let error = prepare_remote_mdoc_batch_with_sources(
            vec![
                RemoteMdocBatchItem::new(91, first),
                RemoteMdocBatchItem::new(7, overflow),
            ],
            || panic!("reserved credential IDs must not allocate UUIDs"),
            || times.next().expect("one timestamp per validated input"),
            || panic!("timestamp overflow must precede salt allocation"),
            &MustNotExecute,
        )
        .unwrap_err();
        assert!(times.next().is_none());
        let crate::Oid4vciError::MdocError(message) = error else {
            panic!("validity range failures must use the mdoc error boundary")
        };
        assert_eq!(message, "mdoc validity period is out of range");
        for sensitive in ["Sensitive", "family_name", "91"] {
            assert!(!message.contains(sensitive));
        }
    }

    #[test]
    fn mdoc_batch_rejects_duplicate_routing_and_reserved_ids_before_sources() {
        let first_id = "urn:uuid:00000000-0000-0000-0000-000000000091";
        let second_id = "urn:uuid:00000000-0000-0000-0000-000000000007";
        let duplicate_route = vec![
            RemoteMdocBatchItem::new(
                91,
                remote_mdoc_request(Some(first_id), "ES256", HashMap::new()),
            ),
            RemoteMdocBatchItem::new(
                91,
                remote_mdoc_request(Some(second_id), "ES256", HashMap::new()),
            ),
        ];
        let duplicate_id = vec![
            RemoteMdocBatchItem::new(
                91,
                remote_mdoc_request(Some(first_id), "ES256", HashMap::new()),
            ),
            RemoteMdocBatchItem::new(
                7,
                remote_mdoc_request(
                    Some("urn:uuid:00000000000000000000000000000091"),
                    "ES256",
                    HashMap::new(),
                ),
            ),
        ];

        for (batch, expected) in [
            (duplicate_route, "duplicate batch identity"),
            (duplicate_id, "duplicate credential ID"),
        ] {
            let error = prepare_remote_mdoc_batch_with_sources(
                batch,
                || panic!("duplicate validation must precede UUID allocation"),
                || panic!("duplicate validation must precede time allocation"),
                || panic!("duplicate validation must precede salt allocation"),
                &MustNotExecute,
            )
            .unwrap_err();
            assert!(error.to_string().contains(expected));
        }
    }

    #[test]
    fn mdoc_batch_preserves_duplicate_and_request_validation_precedence() {
        let credential_id = "urn:uuid:00000000-0000-0000-0000-000000000091";
        let invalid_duplicate_route = vec![
            RemoteMdocBatchItem::new(
                91,
                remote_mdoc_request(Some(credential_id), "ES256", HashMap::new()),
            ),
            RemoteMdocBatchItem::new(
                91,
                remote_mdoc_request(Some(credential_id), "RS256", HashMap::new()),
            ),
        ];
        let error = prepare_remote_mdoc_batch_with_sources(
            invalid_duplicate_route,
            || panic!("duplicate route must precede UUID allocation"),
            || panic!("duplicate route must precede time allocation"),
            || panic!("duplicate route must precede salt allocation"),
            &MustNotExecute,
        )
        .unwrap_err();
        let crate::Oid4vciError::InvalidRequest(message) = error else {
            panic!("duplicate route must retain the remote request boundary")
        };
        assert_eq!(
            message,
            "mDoc preparation batch contains duplicate batch identity"
        );

        let invalid_duplicate_credential = vec![
            RemoteMdocBatchItem::new(
                91,
                remote_mdoc_request(Some(credential_id), "ES256", HashMap::new()),
            ),
            RemoteMdocBatchItem::new(
                7,
                remote_mdoc_request(Some(credential_id), "RS256", HashMap::new()),
            ),
        ];
        let error = prepare_remote_mdoc_batch_with_sources(
            invalid_duplicate_credential,
            || panic!("request validation must precede UUID allocation"),
            || panic!("request validation must precede time allocation"),
            || panic!("request validation must precede salt allocation"),
            &MustNotExecute,
        )
        .unwrap_err();
        let crate::Oid4vciError::InvalidRequest(message) = error else {
            panic!("algorithm validation must retain the remote request boundary")
        };
        assert_eq!(message, "mDoc remote signing supports ES256 and ES384 only");
    }

    #[test]
    fn generated_mdoc_id_collision_with_later_explicit_id_precedes_time_and_salts() {
        let batch = vec![
            RemoteMdocBatchItem::new(91, remote_mdoc_request(None, "ES256", HashMap::new())),
            RemoteMdocBatchItem::new(
                7,
                remote_mdoc_request(
                    Some("urn:uuid:00000000000000000000000000000091"),
                    "ES256",
                    HashMap::new(),
                ),
            ),
        ];
        let colliding_uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000091").unwrap();
        let uuid_calls = Cell::new(0usize);
        let error = prepare_remote_mdoc_batch_with_sources(
            batch,
            || {
                uuid_calls.set(uuid_calls.get() + 1);
                colliding_uuid
            },
            || panic!("explicit IDs must be reserved before time allocation"),
            || panic!("ID collisions must fail before salt allocation"),
            &MustNotExecute,
        )
        .unwrap_err();

        assert!(error.to_string().contains("duplicate credential ID"));
        assert_eq!(uuid_calls.get(), 1);
    }

    #[test]
    fn generated_mdoc_id_collision_fails_before_salts_or_execution() {
        let batch = vec![
            RemoteMdocBatchItem::new(91, remote_mdoc_request(None, "ES256", HashMap::new())),
            RemoteMdocBatchItem::new(7, remote_mdoc_request(None, "ES256", HashMap::new())),
        ];
        let colliding_uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000091").unwrap();
        let uuid_calls = Cell::new(0usize);
        let time_calls = Cell::new(0usize);
        let error = prepare_remote_mdoc_batch_with_sources(
            batch,
            || {
                uuid_calls.set(uuid_calls.get() + 1);
                colliding_uuid
            },
            || {
                let call = time_calls.get();
                time_calls.set(call + 1);
                fixed_time(56 + call as u32)
            },
            || panic!("ID collisions must fail before salt allocation"),
            &MustNotExecute,
        )
        .unwrap_err();

        assert!(error.to_string().contains("duplicate credential ID"));
        assert_eq!(uuid_calls.get(), 2);
        assert_eq!(time_calls.get(), 1);
    }

    #[test]
    fn empty_and_claimless_mdoc_batches_have_explicit_executor_semantics() {
        let empty = prepare_remote_mdoc_batch_with_sources(
            Vec::new(),
            || panic!("empty batch must not allocate UUIDs"),
            || panic!("empty batch must not allocate time"),
            || panic!("empty batch must not allocate salts"),
            &MustNotExecute,
        )
        .unwrap();
        assert!(empty.is_empty());

        let executor = CountingDigestExecutor::default();
        let mut times = [fixed_time(56), fixed_time(57)].into_iter();
        let claimless = prepare_remote_mdoc_batch_with_sources(
            vec![
                RemoteMdocBatchItem::new(
                    91,
                    remote_mdoc_request(
                        Some("urn:uuid:00000000-0000-0000-0000-000000000091"),
                        "ES256",
                        HashMap::new(),
                    ),
                ),
                RemoteMdocBatchItem::new(
                    7,
                    remote_mdoc_request(
                        Some("urn:uuid:00000000-0000-0000-0000-000000000007"),
                        "ES384",
                        HashMap::new(),
                    ),
                ),
            ],
            || panic!("reserved IDs must not allocate UUIDs"),
            || times.next().unwrap(),
            || panic!("claimless credentials must not allocate salts"),
            &executor,
        )
        .unwrap();
        assert_eq!(claimless.len(), 2);
        assert_eq!(executor.calls.load(Ordering::Relaxed), 1);
        assert_eq!(executor.jobs.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn public_mdoc_batch_route_preserves_reserved_identity_and_device_binding() {
        let mut request = remote_mdoc_request(
            Some("urn:uuid:00000000-0000-0000-0000-000000000789"),
            "ES256",
            HashMap::from([("family_name".into(), serde_json::json!("Smith"))]),
        );
        request.holder_jwk = Some(serde_json::json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256",
            "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
            "d": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
        }));
        let prepared = prepare_remote_mdoc_batch(vec![RemoteMdocBatchItem::new(789, request)])
            .expect("public batch preparation");
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].batch_id(), 789);
        assert_eq!(
            prepared[0].prepared_mdoc().credential_id,
            "urn:uuid:00000000-0000-0000-0000-000000000789"
        );
        assert!(!prepared[0].prepared_mdoc().tbs_data.is_empty());
    }
}
