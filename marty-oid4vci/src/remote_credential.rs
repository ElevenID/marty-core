//! Reusable credential preparation for DID-mediated remote signers.
//!
//! The preparation retains all format state in Rust while an external KMS
//! signs only the exact bytes returned by the canonical format kernel.

use std::collections::HashMap;

use serde_json::Value;

use crate::{
    formats::{
        jwt_vc::{
            apply_open_badge_v3_profile, prepare_jwt_vc_with_options, JwtVcPreparationOptions,
            PreparedJwtVc,
        },
        mdoc::{prepare_mdoc_with_credential_id_and_device_key, PreparedMdoc},
        sd_jwt::{prepare_sd_jwt_with_options, PreparedSdJwt, SdJwtPreparationOptions},
    },
    signer::CredentialSigner,
    types::{CredentialClaims, CredentialPayloadFormat, SigningAlgorithm},
    Oid4vciError, Oid4vciResult,
};

const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

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

pub fn prepare_remote_mdoc(request: RemoteMdocRequest) -> Oid4vciResult<PreparedMdoc> {
    validate_credential_id(request.credential_id.as_deref())?;
    let algorithm = match request.algorithm.as_str() {
        "ES256" => SigningAlgorithm::ES256,
        "ES384" => SigningAlgorithm::ES384,
        _ => {
            return Err(protocol_error(
                "mDoc remote signing supports ES256 and ES384 only",
            ))
        }
    };
    let holder_jwk = request.holder_jwk.map(public_jwk).transpose()?;
    let signer = MdocSignerMetadata {
        issuer_id: request.issuer_id,
        algorithm,
    };
    prepare_mdoc_with_credential_id_and_device_key(
        &signer,
        &CredentialClaims {
            subject_id: None,
            credential_type: request.credential_type.clone(),
            claims: request.claims,
            expiration_seconds: request.expiration_seconds,
            selective_disclosure_claims: Vec::new(),
            mdoc_namespace: Some(request.namespace),
            mdoc_doctype: Some(request.credential_type),
            zk_predicate_claims: Vec::new(),
            credential_payload_format: CredentialPayloadFormat::default(),
            w3c_context: Vec::new(),
            w3c_types: Vec::new(),
        },
        request.credential_id.as_deref(),
        holder_jwk.as_ref(),
    )
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
    use std::collections::HashMap;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    use super::{
        prepare_remote_jwt_vc, prepare_remote_mdoc, prepare_remote_sd_jwt, RemoteJwtVcRequest,
        RemoteMdocRequest, RemoteSdJwtRequest,
    };

    fn segment(value: &str, index: usize) -> serde_json::Value {
        let encoded = value.split('.').nth(index).expect("JWT segment");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).expect("base64url")).expect("JSON")
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
        let coordinate = URL_SAFE_NO_PAD.encode([0x11; 32]);
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
                "x": coordinate, "y": URL_SAFE_NO_PAD.encode([0x22; 32]),
                "d": URL_SAFE_NO_PAD.encode([0x33; 32]),
            })),
        })
        .expect("mDoc preparation");
        assert_eq!(
            prepared.credential_id,
            "urn:uuid:00000000-0000-0000-0000-000000000789"
        );
        assert!(!prepared.tbs_data.is_empty());
    }
}
