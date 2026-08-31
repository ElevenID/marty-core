//! Marty-owned regressions for proof-bound scalar SD-JWT VC issuance.

use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_oid4vci::{
    formats::sd_jwt::verify_sd_jwt,
    issuer::IssuanceEngine,
    jose::verify_compact_jwt_with_public_jwk,
    proof,
    types::{
        CredentialClaims, CredentialFormat, CredentialPayloadFormat, CredentialRequest,
        CredentialTypeConfig, IssuerConfig, IssuerKey, ProofsObject, SignedCredential,
        SigningAlgorithm,
    },
    Oid4vciError,
};
use p256::ecdsa::signature::Signer as _;
use serde_json::{json, Value};
use ssi_jwk::JWK;

const ISSUER_URL: &str = "https://issuer.example.test";
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

struct IssuerFixture {
    engine: IssuanceEngine,
    public_jwk: String,
}

struct ProofFixture {
    compact: String,
    public_jwk: Value,
}

fn issuer_key() -> (IssuerKey, String) {
    let jwk = JWK::generate_p256();
    let public_jwk = serde_json::to_string(&jwk.to_public()).unwrap();
    (
        IssuerKey {
            issuer_id: "did:example:scalar-sd-jwt-issuer".into(),
            jwk_json: serde_json::to_string(&jwk).unwrap(),
            algorithm: SigningAlgorithm::ES256,
        },
        public_jwk,
    )
}

fn engine_with_key(issuer_key: IssuerKey) -> IssuanceEngine {
    IssuanceEngine::new(IssuerConfig {
        credential_issuer_url: ISSUER_URL.into(),
        issuer_name: "Scalar SD-JWT holder-binding issuer".into(),
        credential_types: vec![CredentialTypeConfig {
            id: "EmployeeCredential".into(),
            name: "Employee credential".into(),
            formats: vec![CredentialFormat::SdJwt, CredentialFormat::JwtVcJson],
            vc_types: vec!["VerifiableCredential".into()],
            vct: Some("https://credentials.example.test/employee".into()),
            doctype: None,
            claims: HashMap::new(),
            display: None,
        }],
        issuer_key,
        token_endpoint: None,
        credential_endpoint: None,
        authorization_endpoint: None,
        deferred_credential_endpoint: None,
        binding_methods: vec!["jwk".into(), "did:key".into()],
        proof_signing_alg_values: vec!["ES256".into(), "EdDSA".into()],
    })
}

fn issuer_fixture() -> IssuerFixture {
    let (key, public_jwk) = issuer_key();
    IssuerFixture {
        engine: engine_with_key(key),
        public_jwk,
    }
}

fn claims(payload_format: CredentialPayloadFormat) -> CredentialClaims {
    CredentialClaims {
        subject_id: Some("did:example:employee-holder".into()),
        credential_type: "https://credentials.example.test/employee".into(),
        claims: HashMap::from([
            ("employee_id".into(), json!("employee-123")),
            ("department".into(), json!("engineering")),
        ]),
        expiration_seconds: Some(3_600),
        selective_disclosure_claims: vec!["department".into()],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        credential_payload_format: payload_format,
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn request(format: &str, proof_jwt: String) -> CredentialRequest {
    CredentialRequest {
        format: Some(format.into()),
        credential_configuration_id: Some("EmployeeCredential".into()),
        credential_identifier: None,
        proofs: Some(ProofsObject {
            jwt: Some(vec![proof_jwt]),
        }),
        credential_definition: None,
        vct: None,
        doctype: None,
        claims: None,
    }
}

fn fresh_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn p256_proof(nonce: &str) -> ProofFixture {
    let holder = marty_oid4vci::generate_p256_did_jwk_holder_key().unwrap();
    let private_jwk: Value = serde_json::from_str(&holder.private_jwk).unwrap();
    let public_jwk: Value = serde_json::from_str(&holder.public_jwk).unwrap();
    let private_scalar = URL_SAFE_NO_PAD
        .decode(private_jwk["d"].as_str().unwrap())
        .unwrap();
    let signing_key = p256::ecdsa::SigningKey::from_slice(&private_scalar).unwrap();
    let header = json!({
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt",
        "jwk": public_jwk,
    });
    let payload = json!({
        "iss": holder.kid,
        "aud": ISSUER_URL,
        "iat": chrono::Utc::now().timestamp(),
        "nonce": nonce,
    });
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header}.{payload}");
    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());

    ProofFixture {
        compact: format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ),
        public_jwk,
    }
}

fn ed25519_did_key_proof(nonce: &str) -> ProofFixture {
    let compact = proof::create_proof_jwt(ISSUER_URL, nonce).unwrap();
    let verified = proof::verify_jwt_proof(&compact, ISSUER_URL, Some(nonce), 300).unwrap();
    let public_jwk = serde_json::to_value(
        verified
            .holder_jwk
            .expect("did:key proof must resolve to public key material")
            .to_public(),
    )
    .unwrap();
    ProofFixture {
        compact,
        public_jwk,
    }
}

fn response_compact(response: marty_oid4vci::types::CredentialResponse) -> String {
    response
        .credential
        .and_then(|credential| credential.as_str().map(str::to_owned))
        .expect("scalar issuance must return one compact credential")
}

fn decode_jwt_payload(compact: &str) -> Value {
    let issuer_jwt = compact.split('~').next().unwrap();
    let payload = issuer_jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn tamper_jwt_signature(compact: &str) -> String {
    let mut parts = compact.split('.');
    let header = parts.next().unwrap();
    let payload = parts.next().unwrap();
    let signature = parts.next().unwrap();
    assert!(parts.next().is_none());

    let mut signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
    signature[0] ^= 0x01;
    format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn assert_public_confirmation(payload: &Value, expected_public_jwk: &Value) {
    assert_eq!(payload["cnf"], json!({"jwk": expected_public_jwk}));
    let cnf_jwk = payload["cnf"]["jwk"]
        .as_object()
        .expect("cnf.jwk must be a JWK object");
    for name in PRIVATE_JWK_MEMBERS {
        assert!(
            !cnf_jwk.contains_key(*name),
            "issuer payload must never copy private JWK member {name}"
        );
    }
    assert!(
        payload
            .get("credentialSubject")
            .and_then(Value::as_object)
            .is_none_or(|subject| !subject.contains_key("cnf")),
        "holder confirmation must be a top-level issuer claim"
    );
}

fn issue_and_verify_bound_sd_jwt(
    proof: ProofFixture,
    payload_format: CredentialPayloadFormat,
    nonce: &str,
) -> Value {
    let fixture = issuer_fixture();
    let response = fixture
        .engine
        .issue_credential(
            &request("dc+sd-jwt", proof.compact),
            &claims(payload_format),
            nonce,
            None,
        )
        .unwrap();
    let compact = response_compact(response);
    let signed_payload = decode_jwt_payload(&compact);
    assert_public_confirmation(&signed_payload, &proof.public_jwk);

    let verified = verify_sd_jwt(&compact, &fixture.public_jwk, None, None)
        .expect("issuer signature and disclosures must verify");
    assert_public_confirmation(&verified, &proof.public_jwk);
    verified
}

#[test]
fn p256_proof_key_is_bound_into_w3c_sd_jwt() {
    let nonce = fresh_nonce();
    let verified = issue_and_verify_bound_sd_jwt(
        p256_proof(&nonce),
        CredentialPayloadFormat::W3cVcdmV2SdJwt,
        &nonce,
    );
    assert_eq!(verified["credentialSubject"]["employee_id"], "employee-123");
}

#[test]
fn ed25519_did_key_proof_is_bound_into_ietf_sd_jwt() {
    let nonce = fresh_nonce();
    let verified = issue_and_verify_bound_sd_jwt(
        ed25519_did_key_proof(&nonce),
        CredentialPayloadFormat::IetfSdJwt,
        &nonce,
    );
    assert_eq!(verified["employee_id"], "employee-123");
}

#[test]
fn proof_failure_precedes_and_prevents_sd_jwt_signing() {
    let (mut key, _) = issuer_key();
    key.jwk_json = "{malformed-issuer-jwk".into();
    let engine = engine_with_key(key);
    let nonce = fresh_nonce();
    let proof = p256_proof(&nonce).compact;
    let tampered = tamper_jwt_signature(&proof);

    let error = engine
        .issue_credential(
            &request("dc+sd-jwt", tampered),
            &claims(CredentialPayloadFormat::IetfSdJwt),
            &nonce,
            None,
        )
        .unwrap_err();
    assert!(matches!(error, Oid4vciError::ProofVerificationFailed(_)));

    let signing_sentinel = engine
        .issue_credential(
            &request("dc+sd-jwt", proof),
            &claims(CredentialPayloadFormat::IetfSdJwt),
            &nonce,
            None,
        )
        .unwrap_err();
    assert!(matches!(signing_sentinel, Oid4vciError::KeyError(_)));
}

#[test]
fn proof_binding_does_not_change_non_sd_jwt_or_direct_issuance() {
    let fixture = issuer_fixture();
    let nonce = fresh_nonce();
    let proof = p256_proof(&nonce);
    let response = fixture
        .engine
        .issue_credential(
            &request("jwt_vc_json", proof.compact),
            &claims(CredentialPayloadFormat::W3cVcdmV2JwtVc),
            &nonce,
            None,
        )
        .unwrap();
    let jwt = response_compact(response);
    assert!(!jwt.contains('~'));
    let verified = verify_compact_jwt_with_public_jwk(&jwt, &fixture.public_jwk, "ES256")
        .expect("non-SD-JWT issuer signature must remain valid");
    assert!(verified.claims.get("cnf").is_none());
    assert_eq!(
        verified.claims["vc"]["credentialSubject"]["employee_id"],
        "employee-123"
    );

    let direct = fixture
        .engine
        .issue_credential_in_format(
            &CredentialFormat::SdJwt,
            &claims(CredentialPayloadFormat::IetfSdJwt),
        )
        .unwrap();
    let SignedCredential::SdJwt { compact, .. } = direct else {
        panic!("direct format issuance must remain SD-JWT")
    };
    assert!(decode_jwt_payload(&compact).get("cnf").is_none());
}
