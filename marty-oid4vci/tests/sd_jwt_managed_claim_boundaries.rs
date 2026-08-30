//! Marty-owned regressions for SD-JWT issuer-managed claim boundaries.

use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicUsize, Ordering},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_oid4vci::{
    formats::sd_jwt::{
        prepare_sd_jwt, prepare_sd_jwt_with_options, sign_sd_jwt, sign_sd_jwt_with_signer,
        PreparedSdJwt, SdJwtPreparationOptions,
    },
    remote_credential::{prepare_remote_sd_jwt, RemoteSdJwtRequest},
    signer::CredentialSigner,
    types::{
        CredentialClaims, CredentialPayloadFormat, IssuerKey, SignedCredential, SigningAlgorithm,
    },
    Oid4vciError, Oid4vciResult,
};
use ssi_jwk::JWK;

const MANAGED_COLLISION: &str = "SD-JWT claims conflict with issuer-controlled claims";
const NON_DISCLOSABLE_SELECTOR: &str = "SD-JWT selector targets a non-disclosable claim";
const EXPLICIT_CREDENTIAL_ID: &str = "urn:uuid:00000000-0000-0000-0000-000000000123";
const IETF_NON_DISCLOSABLE: &[&str] = &[
    "iss",
    "nbf",
    "exp",
    "cnf",
    "vct",
    "vct#integrity",
    "aka_vcts",
    "status",
];

#[derive(Default)]
struct SignerSpy {
    calls: AtomicUsize,
}

impl std::fmt::Debug for SignerSpy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SignerSpy([redacted])")
    }
}

impl CredentialSigner for SignerSpy {
    fn sign(&self, _message: &[u8]) -> Oid4vciResult<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(vec![0x5a; 64])
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::ES256
    }

    fn issuer_id(&self) -> &str {
        "did:example:managed-claim-test-issuer"
    }

    fn kid_url(&self) -> String {
        "did:example:managed-claim-test-issuer#key-1".into()
    }
}

fn test_key() -> IssuerKey {
    let jwk = JWK::generate_p256();
    let jwk_json = serde_json::to_string(&jwk).unwrap();
    let issuer_id = format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(jwk_json.as_bytes()));
    IssuerKey {
        issuer_id,
        jwk_json,
        algorithm: SigningAlgorithm::ES256,
    }
}

fn claims(format: CredentialPayloadFormat) -> CredentialClaims {
    CredentialClaims {
        subject_id: Some("did:example:canonical-holder".into()),
        credential_type: "https://credentials.example/ManagedBoundary".into(),
        claims: HashMap::from([(
            "name".into(),
            serde_json::json!("Sensitive managed-claim sentinel"),
        )]),
        expiration_seconds: Some(3_600),
        selective_disclosure_claims: vec![],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        credential_payload_format: format,
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn payload_from_prepared(prepared: &PreparedSdJwt) -> serde_json::Value {
    let payload = prepared.signing_input.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn signed_parts(signed: SignedCredential) -> (String, String, serde_json::Value) {
    let SignedCredential::SdJwt {
        compact,
        credential_id,
    } = signed
    else {
        panic!("expected SD-JWT")
    };
    let payload = compact.split('.').nth(1).unwrap();
    let decoded = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    (compact, credential_id, decoded)
}

fn decoded_disclosures(suffix_or_compact: &str) -> Vec<serde_json::Value> {
    suffix_or_compact
        .split('~')
        .skip(1)
        .filter(|value| !value.is_empty())
        .map(|value| serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value).unwrap()).unwrap())
        .collect()
}

fn assert_sd_jwt_error<T>(result: Oid4vciResult<T>, expected: &str) {
    let error = match result {
        Ok(_) => panic!("unsafe SD-JWT input must be rejected"),
        Err(error) => error,
    };
    let Oid4vciError::SdJwtError(message) = error else {
        panic!("claim-boundary failures must use the SD-JWT error boundary")
    };
    assert_eq!(message, expected);
    assert!(!message.contains("Sensitive managed-claim sentinel"));
    assert!(!message.contains("Sensitive replacement value"));
}

fn assert_direct_boundaries_reject(
    key: &IssuerKey,
    spy: &SignerSpy,
    submitted: &CredentialClaims,
    expected: &str,
) {
    assert_sd_jwt_error(sign_sd_jwt(key, submitted), expected);
    assert_sd_jwt_error(prepare_sd_jwt(spy, submitted), expected);
    assert_sd_jwt_error(sign_sd_jwt_with_signer(spy, submitted), expected);
}

fn remote_request() -> RemoteSdJwtRequest {
    RemoteSdJwtRequest {
        issuer_id: "did:web:issuer.example".into(),
        verification_method_id: "did:web:issuer.example#key-1".into(),
        algorithm: "ES256".into(),
        subject_id: Some("did:example:canonical-holder".into()),
        credential_type: "https://credentials.example/ManagedBoundary".into(),
        claims: HashMap::from([(
            "name".into(),
            serde_json::json!("Sensitive managed-claim sentinel"),
        )]),
        expiration_seconds: Some(3_600),
        selective_disclosure_claims: vec![],
        credential_format: Some("dc+sd-jwt".into()),
        credential_id: Some(EXPLICIT_CREDENTIAL_ID.into()),
        holder_jwk: Some(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "public-x",
            "y": "public-y",
            "d": "Sensitive private key sentinel"
        })),
        issuer_certificate_chain: vec![],
    }
}

#[test]
fn ietf_rejects_raw_collisions_only_when_marty_authors_the_claim() {
    let key = test_key();
    let spy = SignerSpy::default();

    for name in ["iss", "iat", "jti", "vct", "sub", "exp"] {
        let mut submitted = claims(CredentialPayloadFormat::IetfSdJwt);
        submitted.claims.insert(
            name.into(),
            serde_json::json!("Sensitive replacement value"),
        );
        assert_direct_boundaries_reject(&key, &spy, &submitted, MANAGED_COLLISION);
    }

    for (name, options) in [
        (
            "nbf",
            SdJwtPreparationOptions {
                include_nbf: true,
                ..SdJwtPreparationOptions::default()
            },
        ),
        (
            "cnf",
            SdJwtPreparationOptions {
                confirmation: Some(serde_json::json!({"kid": "did:example:canonical-holder"})),
                ..SdJwtPreparationOptions::default()
            },
        ),
    ] {
        let mut submitted = claims(CredentialPayloadFormat::IetfSdJwt);
        submitted.claims.insert(
            name.into(),
            serde_json::json!("Sensitive replacement value"),
        );
        assert_sd_jwt_error(
            prepare_sd_jwt_with_options(&spy, &submitted, options),
            MANAGED_COLLISION,
        );
    }

    assert_eq!(
        spy.calls.load(Ordering::Relaxed),
        0,
        "validation failures must not invoke an external signer"
    );
}

#[test]
fn ietf_preserves_unmanaged_optional_raw_claims_and_exact_generated_identity() {
    let key = test_key();
    let mut submitted = claims(CredentialPayloadFormat::IetfSdJwt);
    submitted.subject_id = None;
    submitted.expiration_seconds = None;
    submitted.claims.extend([
        ("sub".into(), serde_json::json!("raw-subject")),
        ("exp".into(), serde_json::json!(4_200_000_000_i64)),
        ("nbf".into(), serde_json::json!(1_700_000_000_i64)),
        (
            "cnf".into(),
            serde_json::json!({"kid": "did:example:raw-holder"}),
        ),
    ]);

    let prepared = prepare_sd_jwt_with_options(
        &SignerSpy::default(),
        &submitted,
        SdJwtPreparationOptions {
            credential_id: Some(EXPLICIT_CREDENTIAL_ID.into()),
            ..SdJwtPreparationOptions::default()
        },
    )
    .unwrap();
    let payload = payload_from_prepared(&prepared);
    assert_eq!(prepared.credential_id, EXPLICIT_CREDENTIAL_ID);
    assert_eq!(payload["jti"], EXPLICIT_CREDENTIAL_ID);
    assert_eq!(payload["iss"], "did:example:managed-claim-test-issuer");
    assert_eq!(
        payload["vct"],
        "https://credentials.example/ManagedBoundary"
    );
    assert!(payload["iat"].is_i64());
    assert_eq!(payload["sub"], "raw-subject");
    assert_eq!(payload["exp"], 4_200_000_000_i64);
    assert_eq!(payload["nbf"], 1_700_000_000_i64);
    assert_eq!(payload["cnf"]["kid"], "did:example:raw-holder");

    let (_, generated_id, signed_payload) = signed_parts(sign_sd_jwt(&key, &submitted).unwrap());
    assert_eq!(signed_payload["jti"], generated_id);
    let uuid = generated_id.strip_prefix("urn:uuid:").unwrap();
    assert_eq!(uuid::Uuid::parse_str(uuid).unwrap().get_version_num(), 4);
    assert_eq!(signed_payload["sub"], "raw-subject");
    assert_eq!(signed_payload["cnf"]["kid"], "did:example:raw-holder");
}

#[test]
fn direct_preparation_preserves_every_typed_canonical_field_and_explicit_id() {
    let submitted = claims(CredentialPayloadFormat::IetfSdJwt);
    let confirmation = serde_json::json!({
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "canonical-x",
            "y": "canonical-y"
        }
    });
    let prepared = prepare_sd_jwt_with_options(
        &SignerSpy::default(),
        &submitted,
        SdJwtPreparationOptions {
            credential_id: Some(EXPLICIT_CREDENTIAL_ID.into()),
            confirmation: Some(confirmation.clone()),
            include_nbf: true,
            ..SdJwtPreparationOptions::default()
        },
    )
    .unwrap();
    let payload = payload_from_prepared(&prepared);
    let issued_at = payload["iat"].as_i64().unwrap();

    assert_eq!(prepared.credential_id, EXPLICIT_CREDENTIAL_ID);
    assert_eq!(payload["jti"], EXPLICIT_CREDENTIAL_ID);
    assert_eq!(payload["iss"], "did:example:managed-claim-test-issuer");
    assert_eq!(
        payload["vct"],
        "https://credentials.example/ManagedBoundary"
    );
    assert_eq!(payload["sub"], "did:example:canonical-holder");
    assert_eq!(payload["nbf"].as_i64(), Some(issued_at));
    assert_eq!(payload["exp"].as_i64(), Some(issued_at + 3_600));
    assert_eq!(payload["cnf"], confirmation);
    assert_eq!(prepared.disclosures_suffix, "~");
}

#[test]
fn ietf_selector_policy_rejects_the_exact_draft_18_non_disclosable_list() {
    let key = test_key();
    let spy = SignerSpy::default();

    for name in IETF_NON_DISCLOSABLE {
        let mut submitted = claims(CredentialPayloadFormat::IetfSdJwt);
        submitted.subject_id = None;
        submitted.expiration_seconds = None;
        submitted.selective_disclosure_claims = vec![(*name).into()];
        assert_direct_boundaries_reject(&key, &spy, &submitted, NON_DISCLOSABLE_SELECTOR);
    }
    assert_eq!(spy.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn ietf_sub_iat_jti_and_aud_selectors_remain_unrestricted() {
    let key = test_key();
    let mut allowed = claims(CredentialPayloadFormat::IetfSdJwt);
    allowed.expiration_seconds = None;
    allowed
        .claims
        .insert("aud".into(), serde_json::json!("verifier.example"));
    allowed.selective_disclosure_claims = vec![
        "sub".into(),
        "iat".into(),
        "jti".into(),
        "aud".into(),
        "unknown-selector".into(),
    ];
    let prepared = prepare_sd_jwt_with_options(
        &SignerSpy::default(),
        &allowed,
        SdJwtPreparationOptions {
            credential_id: Some(EXPLICIT_CREDENTIAL_ID.into()),
            ..SdJwtPreparationOptions::default()
        },
    )
    .unwrap();
    let payload = payload_from_prepared(&prepared);
    assert!(payload.get("sub").is_none());
    assert!(payload.get("iat").is_none());
    assert!(payload.get("jti").is_none());
    assert!(payload.get("aud").is_none());
    assert_eq!(payload["iss"], "did:example:managed-claim-test-issuer");
    assert_eq!(
        payload["vct"],
        "https://credentials.example/ManagedBoundary"
    );

    let disclosures = decoded_disclosures(&prepared.disclosures_suffix);
    let names = disclosures
        .iter()
        .map(|disclosure| disclosure[1].as_str().unwrap())
        .collect::<HashSet<_>>();
    assert_eq!(names, HashSet::from(["sub", "iat", "jti", "aud"]));
    let disclosed_jti = disclosures
        .iter()
        .find(|disclosure| disclosure[1] == "jti")
        .unwrap();
    assert_eq!(disclosed_jti[2], EXPLICIT_CREDENTIAL_ID);
    let disclosed_aud = disclosures
        .iter()
        .find(|disclosure| disclosure[1] == "aud")
        .unwrap();
    assert_eq!(disclosed_aud[2], "verifier.example");

    let (compact, generated_id, signed_payload) =
        signed_parts(sign_sd_jwt(&key, &allowed).unwrap());
    assert!(signed_payload.get("sub").is_none());
    // The pinned local issuer has historically kept `iat` permanently
    // disclosed. Accepting the selector must not turn that legacy route into
    // an error, while the Marty preparation route above remains capable of
    // disclosing `iat` as draft-18 permits.
    assert!(signed_payload["iat"].is_i64());
    assert!(signed_payload.get("jti").is_none());
    assert!(signed_payload.get("aud").is_none());
    let signed_disclosures = decoded_disclosures(&compact);
    let signed_names = signed_disclosures
        .iter()
        .map(|disclosure| disclosure[1].as_str().unwrap())
        .collect::<HashSet<_>>();
    assert_eq!(signed_names, HashSet::from(["sub", "jti", "aud"]));
    let signed_jti = signed_disclosures
        .iter()
        .find(|disclosure| disclosure[1] == "jti")
        .unwrap();
    assert_eq!(signed_jti[2], generated_id);
    let signed_aud = signed_disclosures
        .iter()
        .find(|disclosure| disclosure[1] == "aud")
        .unwrap();
    assert_eq!(signed_aud[2], "verifier.example");
}

#[test]
fn w3c_subject_id_collision_is_conditional_and_generated_id_remains_selectable() {
    let key = test_key();
    let spy = SignerSpy::default();
    let mut collision = claims(CredentialPayloadFormat::W3cVcdmV2SdJwt);
    collision.claims.insert(
        "id".into(),
        serde_json::json!("did:example:Sensitive-replacement"),
    );
    assert_direct_boundaries_reject(&key, &spy, &collision, MANAGED_COLLISION);
    assert_eq!(spy.calls.load(Ordering::Relaxed), 0);

    let mut generated = claims(CredentialPayloadFormat::W3cVcdmV2SdJwt);
    generated.selective_disclosure_claims = vec!["id".into()];
    let prepared = prepare_sd_jwt_with_options(
        &SignerSpy::default(),
        &generated,
        SdJwtPreparationOptions {
            credential_id: Some(EXPLICIT_CREDENTIAL_ID.into()),
            ..SdJwtPreparationOptions::default()
        },
    )
    .unwrap();
    let payload = payload_from_prepared(&prepared);
    assert_eq!(payload["jti"], EXPLICIT_CREDENTIAL_ID);
    assert!(payload["credentialSubject"].get("id").is_none());
    let disclosures = decoded_disclosures(&prepared.disclosures_suffix);
    assert_eq!(disclosures.len(), 1);
    assert_eq!(disclosures[0][1], "id");
    assert_eq!(disclosures[0][2], "did:example:canonical-holder");

    let mut caller_id = claims(CredentialPayloadFormat::W3cVcdmV2SdJwt);
    caller_id.subject_id = None;
    caller_id
        .claims
        .insert("id".into(), serde_json::json!("did:example:caller-subject"));
    caller_id.selective_disclosure_claims = vec!["id".into()];
    let prepared = prepare_sd_jwt(&SignerSpy::default(), &caller_id).unwrap();
    let disclosures = decoded_disclosures(&prepared.disclosures_suffix);
    assert_eq!(disclosures[0][2], "did:example:caller-subject");
}

#[test]
fn w3c_subject_names_do_not_inherit_flat_ietf_selector_policy() {
    let mut submitted = claims(CredentialPayloadFormat::W3cVcdmV2SdJwt);
    for name in IETF_NON_DISCLOSABLE {
        submitted.claims.insert(
            (*name).into(),
            serde_json::json!(format!("subject-value-{name}")),
        );
    }
    submitted.selective_disclosure_claims = IETF_NON_DISCLOSABLE
        .iter()
        .map(|name| (*name).into())
        .collect();

    let prepared = prepare_sd_jwt(&SignerSpy::default(), &submitted).unwrap();
    let payload = payload_from_prepared(&prepared);
    assert_eq!(payload["iss"], "did:example:managed-claim-test-issuer");
    assert!(payload["iat"].is_i64());
    assert_eq!(
        payload["vct"],
        "https://credentials.example/ManagedBoundary"
    );
    let names = decoded_disclosures(&prepared.disclosures_suffix)
        .into_iter()
        .map(|disclosure| disclosure[1].as_str().unwrap().to_owned())
        .collect::<HashSet<_>>();
    assert_eq!(
        names,
        IETF_NON_DISCLOSABLE
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    );
}

#[test]
fn remote_preparation_enforces_collisions_and_selector_policy_before_output() {
    for name in ["iss", "iat", "jti", "vct", "sub", "exp", "nbf", "cnf"] {
        let mut request = remote_request();
        request.claims.insert(
            name.into(),
            serde_json::json!("Sensitive replacement value"),
        );
        assert_sd_jwt_error(prepare_remote_sd_jwt(request), MANAGED_COLLISION);
    }

    for name in IETF_NON_DISCLOSABLE {
        let mut request = remote_request();
        request.selective_disclosure_claims = vec![(*name).into()];
        assert_sd_jwt_error(prepare_remote_sd_jwt(request), NON_DISCLOSABLE_SELECTOR);
    }
}

#[test]
fn remote_preparation_preserves_conditional_claims_and_unrestricted_selectors() {
    let mut raw_optional = remote_request();
    raw_optional.subject_id = None;
    raw_optional.holder_jwk = None;
    raw_optional.expiration_seconds = None;
    raw_optional.claims.extend([
        ("sub".into(), serde_json::json!("raw-remote-subject")),
        ("exp".into(), serde_json::json!(4_200_000_000_i64)),
        (
            "cnf".into(),
            serde_json::json!({"kid": "did:example:raw-remote-holder"}),
        ),
    ]);
    let prepared = prepare_remote_sd_jwt(raw_optional).unwrap();
    let payload = payload_from_prepared(&prepared);
    assert_eq!(prepared.credential_id, EXPLICIT_CREDENTIAL_ID);
    assert_eq!(payload["jti"], EXPLICIT_CREDENTIAL_ID);
    assert_eq!(payload["iss"], "did:web:issuer.example");
    assert_eq!(payload["nbf"], payload["iat"]);
    assert_eq!(payload["sub"], "raw-remote-subject");
    assert_eq!(payload["exp"], 4_200_000_000_i64);
    assert_eq!(payload["cnf"]["kid"], "did:example:raw-remote-holder");

    let mut allowed = remote_request();
    allowed
        .claims
        .insert("aud".into(), serde_json::json!("remote-verifier.example"));
    allowed.selective_disclosure_claims =
        vec!["sub".into(), "iat".into(), "jti".into(), "aud".into()];
    let prepared = prepare_remote_sd_jwt(allowed).unwrap();
    let payload = payload_from_prepared(&prepared);
    assert_eq!(prepared.credential_id, EXPLICIT_CREDENTIAL_ID);
    let not_before = payload["nbf"].as_i64().unwrap();
    assert!(payload.get("sub").is_none());
    assert!(payload.get("iat").is_none());
    assert!(payload.get("jti").is_none());
    assert!(payload.get("aud").is_none());
    assert_eq!(payload["cnf"]["jwk"]["kty"], "EC");
    assert!(payload["cnf"]["jwk"].get("d").is_none());

    let disclosures = decoded_disclosures(&prepared.disclosures_suffix);
    let names = disclosures
        .iter()
        .map(|disclosure| disclosure[1].as_str().unwrap())
        .collect::<HashSet<_>>();
    assert_eq!(names, HashSet::from(["sub", "iat", "jti", "aud"]));
    let disclosed_jti = disclosures
        .iter()
        .find(|disclosure| disclosure[1] == "jti")
        .unwrap();
    assert_eq!(disclosed_jti[2], EXPLICIT_CREDENTIAL_ID);
    let disclosed_iat = disclosures
        .iter()
        .find(|disclosure| disclosure[1] == "iat")
        .unwrap();
    assert_eq!(disclosed_iat[2].as_i64(), Some(not_before));
    let disclosed_aud = disclosures
        .iter()
        .find(|disclosure| disclosure[1] == "aud")
        .unwrap();
    assert_eq!(disclosed_aud[2], "remote-verifier.example");
}

#[test]
fn reserved_matching_is_exact_and_unknown_selectors_keep_legacy_skip_behavior() {
    let mut submitted = claims(CredentialPayloadFormat::IetfSdJwt);
    submitted.subject_id = None;
    submitted.expiration_seconds = None;
    submitted.claims = HashMap::from([
        ("ISS".into(), serde_json::json!("upper-issuer")),
        ("Vct".into(), serde_json::json!("mixed-type")),
        ("Status".into(), serde_json::json!("mixed-status")),
    ]);
    submitted.selective_disclosure_claims = vec!["ISS".into(), "missing".into()];

    let prepared = prepare_sd_jwt(&SignerSpy::default(), &submitted).unwrap();
    let disclosures = decoded_disclosures(&prepared.disclosures_suffix);
    assert_eq!(disclosures.len(), 1);
    assert_eq!(disclosures[0][1], "ISS");
    assert_eq!(disclosures[0][2], "upper-issuer");
}
