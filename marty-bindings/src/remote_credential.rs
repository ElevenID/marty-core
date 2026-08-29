use base64::Engine;
use marty_oid4vci::{
    remote_credential::{
        prepare_remote_jwt_vc, prepare_remote_sd_jwt, RemoteJwtVcRequest, RemoteSdJwtRequest,
    },
    types::SignedCredential,
};
use pyo3::prelude::*;

pub(crate) fn remote_pyerr(error: marty_oid4vci::Oid4vciError) -> PyErr {
    match error {
        marty_oid4vci::Oid4vciError::InvalidRequest(detail) => {
            pyo3::exceptions::PyValueError::new_err(detail)
        }
        other => pyo3::exceptions::PyRuntimeError::new_err(other.to_string()),
    }
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
    let holder_jwk = holder_jwk_json
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid holder JWK JSON: {error}"))
        })?;
    let prepared = prepare_remote_sd_jwt(RemoteSdJwtRequest {
        issuer_id: issuer_id.to_owned(),
        verification_method_id: verification_method_id.to_owned(),
        algorithm: algorithm.to_owned(),
        subject_id: subject_id.map(str::to_owned),
        credential_type: credential_type.to_owned(),
        claims: parse_claims(claims_json)?,
        expiration_seconds,
        selective_disclosure_claims,
        credential_format: credential_format.map(str::to_owned),
        credential_id: credential_id.map(str::to_owned),
        holder_jwk,
        issuer_certificate_chain,
    })
    .map_err(remote_pyerr)?;
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
    credential_subject_json=None,
    credential_profile=None,
    achievement_id=None
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
    credential_profile: Option<&str>,
    achievement_id: Option<&str>,
) -> PyResult<PreparedRemoteCredential> {
    let explicit_subject = credential_subject_json
        .map(serde_json::from_str::<serde_json::Value>)
        .transpose()
        .map_err(|error| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid credential subject JSON: {error}"
            ))
        })?;
    let prepared = prepare_remote_jwt_vc(RemoteJwtVcRequest {
        issuer_id: issuer_id.to_owned(),
        verification_method_id: verification_method_id.to_owned(),
        algorithm: algorithm.to_owned(),
        subject_id: subject_id.map(str::to_owned),
        credential_type: credential_type.to_owned(),
        claims: parse_claims(claims_json)?,
        expiration_seconds,
        credential_id: credential_id.map(str::to_owned),
        credential_subject: explicit_subject,
        credential_profile: credential_profile.map(str::to_owned),
        achievement_id: achievement_id.map(str::to_owned),
    })
    .map_err(remote_pyerr)?;
    Ok(PreparedRemoteCredential {
        inner: Some(PreparedCredential::JwtVc(prepared)),
    })
}

/// Prepare a canonical Open Badges 3.0 JWT-VC for remote signing.
///
/// The dedicated binding name is also the startup capability contract. It
/// prevents callers from mistaking an older generic JWT-VC binding for one
/// that understands the Open Badges profile.
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
    credential_subject_json=None,
    *,
    achievement_id
))]
fn oid4vci_prepare_open_badge_v3_jwt_vc(
    issuer_id: &str,
    verification_method_id: &str,
    algorithm: &str,
    subject_id: Option<&str>,
    credential_type: &str,
    claims_json: &str,
    expiration_seconds: Option<i64>,
    credential_id: Option<&str>,
    credential_subject_json: Option<&str>,
    achievement_id: &str,
) -> PyResult<PreparedRemoteCredential> {
    oid4vci_prepare_jwt_vc(
        issuer_id,
        verification_method_id,
        algorithm,
        subject_id,
        credential_type,
        claims_json,
        expiration_seconds,
        credential_id,
        credential_subject_json,
        Some("open_badge_v3"),
        Some(achievement_id),
    )
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
    m.add_function(wrap_pyfunction!(oid4vci_prepare_open_badge_v3_jwt_vc, m)?)?;
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
            None,
            None,
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

    #[test]
    fn remote_jwt_vc_open_badge_profile_is_canonical_and_fail_closed() {
        let prepared = oid4vci_prepare_open_badge_v3_jwt_vc(
            "did:web:issuer.example",
            "did:web:issuer.example#key-1",
            "ES256",
            Some("did:key:holder"),
            "open_badge",
            r#"{"achievement_name":"Member Badge","achievement_description":"Verified member","email":"holder@example.test"}"#,
            Some(3600),
            Some("urn:uuid:00000000-0000-0000-0000-000000000789"),
            None,
            "https://issuer.example/credentials/member-badge",
        )
        .expect("native Open Badges JWT-VC preparation");
        let PreparedCredential::JwtVc(state) = prepared.inner.expect("prepared state") else {
            panic!("expected JWT-VC state")
        };
        let payload = decode_segment(state.signing_input.split('.').nth(1).expect("payload"));
        assert_eq!(
            payload["vc"]["type"],
            serde_json::json!(["VerifiableCredential", "OpenBadgeCredential"])
        );
        assert_eq!(
            payload["vc"]["credentialSubject"]["achievement"]["name"],
            "Member Badge"
        );
        assert_eq!(
            payload["vc"]["credentialSubject"]["email"],
            "holder@example.test"
        );

        assert!(oid4vci_prepare_jwt_vc(
            "did:web:issuer.example",
            "did:web:issuer.example#key-1",
            "ES256",
            Some("did:key:holder"),
            "open_badge",
            r#"{"achievement_name":"Member Badge"}"#,
            Some(3600),
            None,
            None,
            Some("open_badge_v3"),
            Some("https://issuer.example/credentials/member-badge"),
        )
        .is_err());
    }
}
