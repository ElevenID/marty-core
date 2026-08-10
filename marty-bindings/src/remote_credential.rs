use base64::Engine;
use marty_oid4vci::signer::CredentialSigner;
use marty_oid4vci::types::{
    CredentialClaims, CredentialPayloadFormat, SignedCredential, SigningAlgorithm,
};
use pyo3::prelude::*;

#[derive(Debug)]
struct MetadataSigner {
    issuer_id: String,
    verification_method_id: String,
    algorithm: SigningAlgorithm,
}

impl CredentialSigner for MetadataSigner {
    fn sign(&self, _message: &[u8]) -> marty_oid4vci::Oid4vciResult<Vec<u8>> {
        Err(marty_oid4vci::Oid4vciError::SigningError(
            "metadata-only remote signer cannot sign".to_string(),
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

fn metadata_signer(
    issuer_id: &str,
    verification_method_id: &str,
    algorithm: &str,
) -> PyResult<MetadataSigner> {
    if !verification_method_id.starts_with(&format!("{issuer_id}#")) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "verification_method_id must identify a key controlled by the issuer DID",
        ));
    }
    let algorithm = match algorithm {
        "ES256" => SigningAlgorithm::ES256,
        "EdDSA" => SigningAlgorithm::EdDSA,
        "ES256K" => SigningAlgorithm::ES256K,
        "ES384" => SigningAlgorithm::ES384,
        "RS256" => SigningAlgorithm::RS256,
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown algorithm: {algorithm}"
            )))
        }
    };
    Ok(MetadataSigner {
        issuer_id: issuer_id.to_string(),
        verification_method_id: verification_method_id.to_string(),
        algorithm,
    })
}

enum PreparedCredential {
    SdJwt(marty_oid4vci::formats::sd_jwt::PreparedSdJwt),
    JwtVc(marty_oid4vci::formats::jwt_vc::PreparedJwtVc),
}

#[pyclass]
struct PreparedRemoteCredential {
    inner: Option<PreparedCredential>,
}

#[pymethods]
impl PreparedRemoteCredential {
    #[getter]
    fn signing_input(&self) -> PyResult<String> {
        match self.inner.as_ref() {
            Some(PreparedCredential::SdJwt(prepared)) => Ok(prepared.signing_input.clone()),
            Some(PreparedCredential::JwtVc(prepared)) => Ok(prepared.signing_input.clone()),
            None => Err(pyo3::exceptions::PyRuntimeError::new_err(
                "credential preparation has already been assembled",
            )),
        }
    }

    #[getter]
    fn credential_id(&self) -> PyResult<String> {
        match self.inner.as_ref() {
            Some(PreparedCredential::SdJwt(prepared)) => Ok(prepared.credential_id.clone()),
            Some(PreparedCredential::JwtVc(prepared)) => Ok(prepared.credential_id.clone()),
            None => Err(pyo3::exceptions::PyRuntimeError::new_err(
                "credential preparation has already been assembled",
            )),
        }
    }
}

fn credential_claims(
    subject_id: Option<&str>,
    credential_type: &str,
    claims: std::collections::HashMap<String, serde_json::Value>,
    expiration_seconds: Option<i64>,
    selective_disclosure_claims: Vec<String>,
    credential_payload_format: CredentialPayloadFormat,
) -> CredentialClaims {
    CredentialClaims {
        subject_id: subject_id.map(str::to_string),
        credential_type: credential_type.to_string(),
        claims,
        expiration_seconds,
        selective_disclosure_claims,
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        credential_payload_format,
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn parse_claims(
    claims_json: &str,
) -> PyResult<std::collections::HashMap<String, serde_json::Value>> {
    serde_json::from_str(claims_json).map_err(|error| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid claims JSON: {error}"))
    })
}

fn decode_signature(signature_b64: &str) -> PyResult<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid signature base64: {error}"))
        })
}

/// Prepare a complete SD-JWT issuer payload while retaining disclosure state
/// inside Rust for remote signing.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    issuer_id,
    verification_method_id,
    algorithm,
    subject_id,
    credential_type,
    claims_json,
    expiration_seconds=None,
    selective_disclosure_claims=vec![],
    credential_format=None,
    credential_id=None,
    holder_jwk_json=None,
    issuer_certificate_chain=vec![]
))]
fn oid4vci_prepare_sd_jwt(
    issuer_id: &str,
    verification_method_id: &str,
    algorithm: &str,
    subject_id: Option<&str>,
    credential_type: &str,
    claims_json: &str,
    expiration_seconds: Option<i64>,
    selective_disclosure_claims: Vec<String>,
    credential_format: Option<&str>,
    credential_id: Option<&str>,
    holder_jwk_json: Option<&str>,
    issuer_certificate_chain: Vec<String>,
) -> PyResult<PreparedRemoteCredential> {
    use marty_oid4vci::formats::sd_jwt::{prepare_sd_jwt_with_options, SdJwtPreparationOptions};

    let signer = metadata_signer(issuer_id, verification_method_id, algorithm)?;
    let confirmation = match (subject_id, holder_jwk_json) {
        (Some(_), Some(holder_json)) => {
            let mut holder: serde_json::Value =
                serde_json::from_str(holder_json).map_err(|error| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "Invalid holder JWK JSON: {error}"
                    ))
                })?;
            let object = holder.as_object_mut().ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("holder JWK must be an object")
            })?;
            for secret in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
                object.remove(secret);
            }
            Some(serde_json::json!({"jwk": holder}))
        }
        (Some(subject), None) => Some(serde_json::json!({"kid": subject})),
        (None, Some(_)) => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "holder_jwk_json requires subject_id",
            ));
        }
        (None, None) => None,
    };
    if issuer_certificate_chain
        .iter()
        .any(|certificate| certificate.trim().is_empty())
    {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "issuer certificate chain contains an invalid x5c entry",
        ));
    }
    if credential_id.is_some_and(|value| value.trim().is_empty()) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "credential_id cannot be empty",
        ));
    }

    let claims = credential_claims(
        subject_id,
        credential_type,
        parse_claims(claims_json)?,
        expiration_seconds,
        selective_disclosure_claims,
        CredentialPayloadFormat::IetfSdJwt,
    );
    let prepared = prepare_sd_jwt_with_options(
        &signer,
        &claims,
        SdJwtPreparationOptions {
            credential_id: credential_id.map(str::to_string),
            typ: Some(if credential_format == Some("dc+sd-jwt") {
                "dc+sd-jwt".to_string()
            } else {
                "vc+sd-jwt".to_string()
            }),
            confirmation,
            x5c: issuer_certificate_chain,
            include_nbf: true,
        },
    )
    .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    Ok(PreparedRemoteCredential {
        inner: Some(PreparedCredential::SdJwt(prepared)),
    })
}

#[pyfunction]
fn oid4vci_assemble_sd_jwt(
    mut prepared: PyRefMut<'_, PreparedRemoteCredential>,
    signature_b64: &str,
) -> PyResult<(String, String)> {
    let signature = decode_signature(signature_b64)?;
    let state = prepared.inner.take().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "credential preparation has already been assembled",
        )
    })?;
    let PreparedCredential::SdJwt(state) = state else {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "prepared credential is not an SD-JWT",
        ));
    };
    match marty_oid4vci::formats::sd_jwt::assemble_sd_jwt(state, &signature) {
        SignedCredential::SdJwt {
            compact,
            credential_id,
        } => Ok((compact, credential_id)),
        _ => Err(pyo3::exceptions::PyRuntimeError::new_err(
            "SD-JWT assembler returned an unexpected credential format",
        )),
    }
}

fn explicit_subject_identifies_holder(subject: &serde_json::Value, holder: &str) -> bool {
    match subject {
        serde_json::Value::Object(object) => {
            object.get("id").and_then(serde_json::Value::as_str) == Some(holder)
        }
        serde_json::Value::Array(subjects) => subjects.iter().any(|item| {
            item.as_object()
                .and_then(|object| object.get("id"))
                .and_then(serde_json::Value::as_str)
                == Some(holder)
        }),
        _ => false,
    }
}

/// Prepare a VCDM v2 JWT-VC while retaining protocol assembly in Rust.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    issuer_id,
    verification_method_id,
    algorithm,
    subject_id,
    credential_type,
    claims_json,
    expiration_seconds=None,
    credential_id=None,
    credential_subject_json=None
))]
fn oid4vci_prepare_jwt_vc(
    issuer_id: &str,
    verification_method_id: &str,
    algorithm: &str,
    subject_id: Option<&str>,
    credential_type: &str,
    claims_json: &str,
    expiration_seconds: Option<i64>,
    credential_id: Option<&str>,
    credential_subject_json: Option<&str>,
) -> PyResult<PreparedRemoteCredential> {
    use marty_oid4vci::formats::jwt_vc::{prepare_jwt_vc_with_options, JwtVcPreparationOptions};

    let signer = metadata_signer(issuer_id, verification_method_id, algorithm)?;
    let mut claims = parse_claims(claims_json)?;
    let credential_status = claims.remove("credentialStatus");
    let explicit_subject = credential_subject_json
        .map(serde_json::from_str::<serde_json::Value>)
        .transpose()
        .map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid credential subject JSON: {error}"
            ))
        })?;
    if explicit_subject.is_some() && !claims.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "explicit credential_subject cannot be combined with subject claims",
        ));
    }
    if let Some(subject) = explicit_subject.as_ref() {
        let valid = match subject {
            serde_json::Value::Object(object) => !object.is_empty(),
            serde_json::Value::Array(items) => {
                !items.is_empty()
                    && items
                        .iter()
                        .all(|item| item.as_object().is_some_and(|object| !object.is_empty()))
            }
            _ => false,
        };
        if !valid {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "credential_subject must be a non-empty object or list of non-empty objects",
            ));
        }
    }
    if credential_id.is_some_and(|value| value.trim().is_empty()) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "credential_id cannot be empty",
        ));
    }
    let include_subject_claim = subject_id.is_some_and(|holder| {
        explicit_subject
            .as_ref()
            .is_none_or(|subject| explicit_subject_identifies_holder(subject, holder))
    });

    let claims = credential_claims(
        subject_id,
        credential_type,
        claims,
        expiration_seconds,
        vec![],
        CredentialPayloadFormat::W3cVcdmV2JwtVc,
    );
    let prepared = prepare_jwt_vc_with_options(
        &signer,
        &claims,
        JwtVcPreparationOptions {
            credential_id: credential_id.map(str::to_string),
            credential_subject: explicit_subject,
            credential_status,
            include_subject_claim,
            include_vc_id: false,
            include_nbf: true,
        },
    )
    .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    Ok(PreparedRemoteCredential {
        inner: Some(PreparedCredential::JwtVc(prepared)),
    })
}

#[pyfunction]
fn oid4vci_assemble_jwt_vc(
    mut prepared: PyRefMut<'_, PreparedRemoteCredential>,
    signature_b64: &str,
) -> PyResult<(String, String)> {
    let signature = decode_signature(signature_b64)?;
    let state = prepared.inner.take().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(
            "credential preparation has already been assembled",
        )
    })?;
    let PreparedCredential::JwtVc(state) = state else {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "prepared credential is not a JWT-VC",
        ));
    };
    match marty_oid4vci::formats::jwt_vc::assemble_jwt_vc(state, &signature) {
        SignedCredential::JwtVcJson { jwt, credential_id } => Ok((jwt, credential_id)),
        _ => Err(pyo3::exceptions::PyRuntimeError::new_err(
            "JWT-VC assembler returned an unexpected credential format",
        )),
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PreparedRemoteCredential>()?;
    m.add_function(wrap_pyfunction!(oid4vci_prepare_sd_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_assemble_sd_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_prepare_jwt_vc, m)?)?;
    m.add_function(wrap_pyfunction!(oid4vci_assemble_jwt_vc, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_segment(segment: &str) -> serde_json::Value {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .expect("valid base64url");
        serde_json::from_slice(&bytes).expect("valid JSON")
    }

    #[test]
    fn remote_sd_jwt_preparation_preserves_security_metadata() {
        let prepared = oid4vci_prepare_sd_jwt(
            "did:web:issuer.example",
            "did:web:issuer.example#key-1",
            "ES256",
            Some("did:key:holder"),
            "AccessBadge",
            r#"{"name":"Alice"}"#,
            Some(3600),
            vec!["name".to_string()],
            Some("dc+sd-jwt"),
            Some("urn:uuid:00000000-0000-0000-0000-000000000123"),
            Some(r#"{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"secret"}"#),
            vec!["leaf".to_string(), "issuer".to_string()],
        )
        .expect("native SD-JWT preparation");
        let PreparedCredential::SdJwt(state) = prepared.inner.expect("prepared state") else {
            panic!("expected SD-JWT state")
        };
        let mut segments = state.signing_input.split('.');
        let header = decode_segment(segments.next().expect("header"));
        let payload = decode_segment(segments.next().expect("payload"));
        assert_eq!(header["kid"], "did:web:issuer.example#key-1");
        assert_eq!(header["typ"], "dc+sd-jwt");
        assert_eq!(header["x5c"], serde_json::json!(["leaf", "issuer"]));
        assert_eq!(payload["jti"], state.credential_id);
        assert_eq!(payload["cnf"]["jwk"]["x"], "x");
        assert!(payload["cnf"]["jwk"].get("d").is_none());
        assert!(payload.get("nbf").is_some());
        assert!(payload.get("name").is_none());
        assert!(payload.get("_sd").is_some());
    }

    #[test]
    fn remote_jwt_vc_preparation_preserves_explicit_subject_and_status() {
        let prepared = oid4vci_prepare_jwt_vc(
            "did:web:issuer.example",
            "did:web:issuer.example#key-1",
            "ES256",
            Some("did:key:holder"),
            "AccessBadge",
            r#"{"credentialStatus":{"type":"BitstringStatusListEntry"}}"#,
            Some(3600),
            Some("urn:uuid:00000000-0000-0000-0000-000000000456"),
            Some(r#"[{"id":"did:example:subject"}]"#),
        )
        .expect("native JWT-VC preparation");
        let PreparedCredential::JwtVc(state) = prepared.inner.expect("prepared state") else {
            panic!("expected JWT-VC state")
        };
        let mut segments = state.signing_input.split('.');
        let header = decode_segment(segments.next().expect("header"));
        let payload = decode_segment(segments.next().expect("payload"));
        assert_eq!(header["kid"], "did:web:issuer.example#key-1");
        assert_eq!(payload["jti"], state.credential_id);
        assert!(payload.get("sub").is_none());
        assert!(payload.get("nbf").is_some());
        assert_eq!(
            payload["vc"]["credentialSubject"],
            serde_json::json!([{"id": "did:example:subject"}])
        );
        assert_eq!(
            payload["vc"]["credentialStatus"]["type"],
            "BitstringStatusListEntry"
        );
        assert!(payload["vc"].get("id").is_none());
    }
}
