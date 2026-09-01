mod es256_signing_matrix;

use std::{
    collections::HashMap,
    fmt,
    hint::black_box,
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::Value as CborValue;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use marty_oid4vci::{
    formats::{
        jwt_vc::{assemble_jwt_vc, prepare_jwt_vc, PreparedJwtVc},
        mdoc::{assemble_mdoc, prepare_mdoc, PreparedMdoc},
        sd_jwt::{
            assemble_sd_jwt, prepare_sd_jwt_with_options, PreparedSdJwt, SdJwtPreparationOptions,
        },
    },
    signer::CredentialSigner,
    signing_batch::{
        BoundedConcurrentCredentialSigner, ConcurrentEs256SignerScope, Es256SignerScope,
        Es256SigningBatchInput, JwtVcSigningBatchInput, MdocSigningBatchInput,
        SdJwtSigningBatchInput, SigningRouteId,
    },
    types::{CredentialClaims, CredentialPayloadFormat, SignedCredential, SigningAlgorithm},
    Oid4vciResult,
};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use sha2::{Digest as _, Sha256};
use ssi_jwk::JWK;

use es256_signing_matrix::{
    expected_claim_names, expected_payload_value, matrix_claims, matrix_enabled, MatrixFormat,
    MatrixSelection, PayloadClass,
};

const BATCH_SIZES: [usize; 4] = [1, 8, 32, 256];
const WORKER_LIMIT: usize = 8;
const WORKER_LIMITS: [usize; 4] = [1, 2, 4, 8];
const MDOC_NAMESPACE: &str = "org.iso.18013.5.1";
const MATRIX_MDOC_NAMESPACE: &str = "org.example.benchmark.payload";
const CBOR_TAG_ENCODED_CBOR: u64 = 24;

#[derive(Clone, Copy, Debug)]
enum BenchmarkFormat {
    JwtVc,
    SdJwt,
    Mdoc,
}

#[derive(Clone, Copy, Debug)]
enum BenchmarkComposition {
    JwtVc,
    SdJwt,
    Mdoc,
    JwtMdoc,
    ThreeFormat,
}

impl BenchmarkComposition {
    const fn label(self) -> &'static str {
        match self {
            Self::JwtVc => "jwt_vc",
            Self::SdJwt => "proof_bound_sd_jwt",
            Self::Mdoc => "mdoc",
            Self::JwtMdoc => "mixed_jwt_mdoc",
            Self::ThreeFormat => "mixed_jwt_sd_jwt_mdoc",
        }
    }

    const fn format_at(self, ordinal: usize) -> BenchmarkFormat {
        match self {
            Self::JwtVc => BenchmarkFormat::JwtVc,
            Self::SdJwt => BenchmarkFormat::SdJwt,
            Self::Mdoc => BenchmarkFormat::Mdoc,
            Self::JwtMdoc if ordinal.is_multiple_of(2) => BenchmarkFormat::JwtVc,
            Self::JwtMdoc => BenchmarkFormat::Mdoc,
            Self::ThreeFormat => match ordinal % 3 {
                0 => BenchmarkFormat::JwtVc,
                1 => BenchmarkFormat::SdJwt,
                _ => BenchmarkFormat::Mdoc,
            },
        }
    }

    const fn includes_sd_jwt(self) -> bool {
        matches!(self, Self::SdJwt | Self::ThreeFormat)
    }
}

struct BenchmarkSigner {
    signing_key: p256::ecdsa::SigningKey,
    max_workers: NonZeroUsize,
}

impl BenchmarkSigner {
    fn new(max_workers: usize) -> Self {
        Self {
            signing_key: p256::ecdsa::SigningKey::from_slice(&[0x31; 32]).unwrap(),
            max_workers: NonZeroUsize::new(max_workers).unwrap(),
        }
    }
}

impl fmt::Debug for BenchmarkSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BenchmarkSigner([redacted])")
    }
}

impl CredentialSigner for BenchmarkSigner {
    fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
        let signature: p256::ecdsa::Signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::ES256
    }

    fn issuer_id(&self) -> &str {
        "did:example:benchmark-issuer"
    }

    fn kid_url(&self) -> String {
        "did:example:benchmark-issuer#key-1".into()
    }
}

impl BoundedConcurrentCredentialSigner for BenchmarkSigner {
    fn max_concurrent_signing_workers(&self) -> NonZeroUsize {
        self.max_workers
    }
}

fn jwt_claims(ordinal: usize) -> CredentialClaims {
    CredentialClaims {
        subject_id: Some(format!("did:example:benchmark-holder-{ordinal}")),
        credential_type: "BenchmarkCredential".into(),
        claims: [("ordinal".into(), serde_json::json!(ordinal))].into(),
        expiration_seconds: Some(3_600),
        selective_disclosure_claims: vec![],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        credential_payload_format: CredentialPayloadFormat::W3cVcdmV2JwtVc,
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn sd_jwt_claims(ordinal: usize) -> CredentialClaims {
    CredentialClaims {
        subject_id: Some(format!("did:example:benchmark-holder-{ordinal}")),
        credential_type: "BenchmarkSdJwtCredential".into(),
        claims: [
            ("ordinal".into(), serde_json::json!(ordinal)),
            (
                "selective_value".into(),
                serde_json::json!(format!("benchmark-selective-{ordinal}")),
            ),
        ]
        .into(),
        expiration_seconds: Some(3_600),
        selective_disclosure_claims: vec!["selective_value".into()],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn holder_public_jwk() -> JWK {
    serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
    }))
    .unwrap()
}

fn sd_jwt_preparation_options() -> SdJwtPreparationOptions {
    SdJwtPreparationOptions {
        confirmation: Some(serde_json::json!({"jwk": holder_public_jwk()})),
        ..SdJwtPreparationOptions::default()
    }
}

fn mdoc_claims(ordinal: usize) -> CredentialClaims {
    CredentialClaims {
        subject_id: Some(format!("did:example:benchmark-holder-{ordinal}")),
        credential_type: "org.iso.18013.5.1.mDL".into(),
        claims: [
            ("family_name".into(), serde_json::json!("Benchmark")),
            ("ordinal".into(), serde_json::json!(ordinal)),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>(),
        expiration_seconds: Some(86_400),
        selective_disclosure_claims: vec![],
        mdoc_namespace: Some(MDOC_NAMESPACE.into()),
        mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
        zk_predicate_claims: vec![],
        credential_payload_format: CredentialPayloadFormat::default(),
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn claims_for(format: BenchmarkFormat, ordinal: usize) -> CredentialClaims {
    match format {
        BenchmarkFormat::JwtVc => jwt_claims(ordinal),
        BenchmarkFormat::SdJwt => sd_jwt_claims(ordinal),
        BenchmarkFormat::Mdoc => mdoc_claims(ordinal),
    }
}

fn claims_batch(composition: BenchmarkComposition, batch_size: usize) -> Vec<CredentialClaims> {
    (0..batch_size)
        .map(|ordinal| claims_for(composition.format_at(ordinal), ordinal))
        .collect()
}

fn signing_inputs(
    composition: BenchmarkComposition,
    batch_size: usize,
) -> Vec<Es256SigningBatchInput> {
    let holder_jwk = composition.includes_sd_jwt().then(holder_public_jwk);
    claims_batch(composition, batch_size)
        .into_iter()
        .enumerate()
        .map(|(ordinal, claims)| {
            let route = SigningRouteId::new(ordinal as u64);
            match composition.format_at(ordinal) {
                BenchmarkFormat::JwtVc => JwtVcSigningBatchInput::new(route, claims).into(),
                BenchmarkFormat::SdJwt => SdJwtSigningBatchInput::new(
                    route,
                    claims,
                    holder_jwk.as_ref().expect("SD-JWT composition holder key"),
                )
                .into(),
                BenchmarkFormat::Mdoc => MdocSigningBatchInput::new(route, claims).into(),
            }
        })
        .collect()
}

fn matrix_signing_inputs(
    format: MatrixFormat,
    class: PayloadClass,
    item_count: usize,
    batch_size: usize,
) -> Vec<Es256SigningBatchInput> {
    let holder_jwk = format.is_sd_jwt().then(holder_public_jwk);
    (0..batch_size)
        .map(|ordinal| {
            let route = SigningRouteId::new(ordinal as u64);
            let claims = matrix_claims(format, class, item_count, ordinal);
            match format {
                MatrixFormat::JwtVc => JwtVcSigningBatchInput::new(route, claims).into(),
                MatrixFormat::IetfSdJwt | MatrixFormat::W3cSdJwt => SdJwtSigningBatchInput::new(
                    route,
                    claims,
                    holder_jwk.as_ref().expect("SD-JWT matrix holder key"),
                )
                .into(),
                MatrixFormat::Mdoc => MdocSigningBatchInput::new(route, claims).into(),
            }
        })
        .collect()
}

enum BenchmarkPrepared {
    JwtVc(PreparedJwtVc),
    SdJwt(PreparedSdJwt),
    Mdoc(Box<PreparedMdoc>),
}

impl BenchmarkPrepared {
    fn signing_payload(&self) -> &[u8] {
        match self {
            Self::JwtVc(prepared) => prepared.signing_payload(),
            Self::SdJwt(prepared) => prepared.signing_input.as_bytes(),
            Self::Mdoc(prepared) => prepared.signing_payload(),
        }
    }

    fn assemble(self, signature: &[u8]) -> SignedCredential {
        match self {
            Self::JwtVc(prepared) => assemble_jwt_vc(prepared, signature),
            Self::SdJwt(prepared) => assemble_sd_jwt(prepared, signature),
            Self::Mdoc(prepared) => assemble_mdoc(*prepared, signature).unwrap(),
        }
    }
}

fn prepare_batch(
    signer: &dyn CredentialSigner,
    composition: BenchmarkComposition,
    claims: Vec<CredentialClaims>,
) -> Vec<BenchmarkPrepared> {
    let sd_jwt_options = composition
        .includes_sd_jwt()
        .then(sd_jwt_preparation_options);
    claims
        .into_iter()
        .enumerate()
        .map(|(ordinal, claims)| match composition.format_at(ordinal) {
            BenchmarkFormat::JwtVc => {
                BenchmarkPrepared::JwtVc(prepare_jwt_vc(signer, &claims).unwrap())
            }
            BenchmarkFormat::SdJwt => BenchmarkPrepared::SdJwt(
                prepare_sd_jwt_with_options(
                    signer,
                    &claims,
                    sd_jwt_options
                        .as_ref()
                        .expect("SD-JWT composition preparation options")
                        .clone(),
                )
                .unwrap(),
            ),
            BenchmarkFormat::Mdoc => {
                BenchmarkPrepared::Mdoc(Box::new(prepare_mdoc(signer, &claims).unwrap()))
            }
        })
        .collect()
}

fn sign_payloads_serially(
    signer: &dyn CredentialSigner,
    prepared: &[BenchmarkPrepared],
) -> Vec<Vec<u8>> {
    prepared
        .iter()
        .map(|prepared| signer.sign(prepared.signing_payload()).unwrap())
        .collect()
}

fn signing_worker(
    signer: &BenchmarkSigner,
    prepared: &[BenchmarkPrepared],
    next_ordinal: &AtomicUsize,
) -> Vec<Vec<u8>> {
    let mut signatures = Vec::new();
    loop {
        let ordinal = next_ordinal.fetch_add(1, Ordering::Relaxed);
        let Some(prepared) = prepared.get(ordinal) else {
            break;
        };
        signatures.push(signer.sign(prepared.signing_payload()).unwrap());
    }
    signatures
}

fn sign_payloads_concurrently(
    signer: &BenchmarkSigner,
    prepared: &[BenchmarkPrepared],
    worker_limit: usize,
) -> Vec<Vec<u8>> {
    if prepared.is_empty() {
        return Vec::new();
    }
    let workers = prepared.len().min(worker_limit);
    let next_ordinal = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.saturating_sub(1));
        for _ in 1..workers {
            handles.push(scope.spawn(|| signing_worker(signer, prepared, &next_ordinal)));
        }
        let mut signatures = signing_worker(signer, prepared, &next_ordinal);
        for handle in handles {
            signatures.extend(handle.join().unwrap());
        }
        signatures
    })
}

fn available_worker_limits() -> Vec<usize> {
    let available = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    WORKER_LIMITS
        .into_iter()
        .filter(|worker_limit| *worker_limit <= available)
        .collect()
}

fn verify_jws(jwt: &str, verifying_key: &p256::ecdsa::VerifyingKey) -> serde_json::Value {
    let segments = jwt.split('.').collect::<Vec<_>>();
    assert_eq!(segments.len(), 3);
    let protected: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
    assert_eq!(protected["alg"], "ES256");
    let signature =
        p256::ecdsa::Signature::from_slice(&URL_SAFE_NO_PAD.decode(segments[2]).unwrap()).unwrap();
    verifying_key
        .verify(
            format!("{}.{}", segments[0], segments[1]).as_bytes(),
            &signature,
        )
        .unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap()
}

fn assert_json_keys(value: &serde_json::Value, expected: &[&str]) {
    let mut actual = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

fn assert_preflight_credential(
    expected_format: BenchmarkFormat,
    ordinal: usize,
    credential: &SignedCredential,
    verifying_key: &p256::ecdsa::VerifyingKey,
) {
    assert!(credential.credential_id().starts_with("urn:uuid:"));
    match (expected_format, credential) {
        (BenchmarkFormat::JwtVc, SignedCredential::JwtVcJson { jwt, .. }) => {
            let payload = verify_jws(jwt, verifying_key);
            assert_eq!(
                payload.pointer("/vc/credentialSubject/ordinal"),
                Some(&serde_json::json!(ordinal))
            );
        }
        (BenchmarkFormat::SdJwt, SignedCredential::SdJwt { compact, .. }) => {
            let mut segments = compact.split('~');
            let payload = verify_jws(segments.next().unwrap(), verifying_key);
            let disclosures = segments
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>();
            assert_eq!(disclosures.len(), 1);
            let disclosure: serde_json::Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(disclosures[0]).unwrap()).unwrap();
            assert!(disclosure[0].as_str().is_some_and(|salt| !salt.is_empty()));
            assert_eq!(
                disclosure,
                serde_json::json!([
                    disclosure[0].clone(),
                    "selective_value",
                    format!("benchmark-selective-{ordinal}")
                ])
            );
            assert_eq!(payload["ordinal"], ordinal);
            assert!(payload.get("selective_value").is_none());
            assert_eq!(payload["_sd_alg"], "sha-256");
            let disclosure_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(disclosures[0].as_bytes()));
            let signed_hashes = payload["_sd"].as_array().unwrap();
            assert_eq!(signed_hashes.len(), 1);
            assert!(signed_hashes.iter().any(|hash| hash == &disclosure_hash));
            assert_eq!(
                payload["cnf"]["jwk"],
                serde_json::to_value(holder_public_jwk()).unwrap()
            );
            for private_member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
                assert!(payload["cnf"]["jwk"].get(private_member).is_none());
            }
        }
        (
            BenchmarkFormat::Mdoc,
            SignedCredential::MsoMdoc {
                issuer_signed_b64, ..
            },
        ) => {
            let issuer_signed: isomdl::definitions::IssuerSigned =
                isomdl::cbor::from_slice(&URL_SAFE_NO_PAD.decode(issuer_signed_b64).unwrap())
                    .unwrap();
            assert_eq!(
                issuer_signed.issuer_auth.protected.header.alg.as_ref(),
                Some(&coset::Algorithm::Assigned(coset::iana::Algorithm::ES256))
            );
            let signature =
                p256::ecdsa::Signature::from_slice(&issuer_signed.issuer_auth.signature).unwrap();
            verifying_key
                .verify(&issuer_signed.issuer_auth.tbs_data(&[]), &signature)
                .unwrap();
            let namespaces = issuer_signed.namespaces.as_ref().unwrap();
            assert_eq!(namespaces.len(), 1);
            let items = namespaces.get(MDOC_NAMESPACE).unwrap();
            let ordinal_item = items
                .iter()
                .find(|item| item.as_ref().element_identifier == "ordinal")
                .unwrap();
            assert_eq!(
                ordinal_item.as_ref().element_value,
                CborValue::Integer((ordinal as u64).into())
            );
        }
        (expected, actual) => {
            panic!("preflight format mismatch: expected {expected:?}, got {actual:?}")
        }
    }
}

fn assert_matrix_preflight_credential(
    format: MatrixFormat,
    class: PayloadClass,
    item_count: usize,
    credential_ordinal: usize,
    credential: &SignedCredential,
    verifying_key: &p256::ecdsa::VerifyingKey,
) {
    let expected_names = expected_claim_names(item_count);
    match (format, credential) {
        (MatrixFormat::JwtVc, SignedCredential::JwtVcJson { jwt, .. }) => {
            let payload = verify_jws(jwt, verifying_key);
            let expected_subject = format!("urn:example:benchmark-holder:{credential_ordinal}");
            assert_eq!(payload["sub"], expected_subject);
            let subject = payload
                .pointer("/vc/credentialSubject")
                .and_then(serde_json::Value::as_object)
                .unwrap();
            assert_eq!(subject.len(), item_count + 1);
            assert_eq!(
                subject.get("id"),
                Some(&serde_json::json!(format!(
                    "urn:example:benchmark-holder:{credential_ordinal}"
                )))
            );
            for (index, name) in expected_names.iter().enumerate() {
                assert_eq!(
                    subject.get(name),
                    Some(&expected_payload_value(class, index))
                );
            }
        }
        (
            MatrixFormat::IetfSdJwt | MatrixFormat::W3cSdJwt,
            SignedCredential::SdJwt { compact, .. },
        ) => {
            let mut compact_parts = compact.split('~');
            let payload = verify_jws(compact_parts.next().unwrap(), verifying_key);
            let disclosures = compact_parts
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>();
            assert_eq!(disclosures.len(), item_count);

            let expected_root_keys: &[&str] = match format {
                MatrixFormat::IetfSdJwt => &[
                    "_sd", "_sd_alg", "cnf", "exp", "iat", "iss", "jti", "sub", "vct",
                ],
                MatrixFormat::W3cSdJwt => &[
                    "@context",
                    "_sd_alg",
                    "cnf",
                    "credentialSubject",
                    "exp",
                    "iat",
                    "iss",
                    "issuer",
                    "jti",
                    "sub",
                    "type",
                    "validFrom",
                    "validUntil",
                    "vct",
                ],
                _ => unreachable!(),
            };
            assert_json_keys(&payload, expected_root_keys);

            let disclosure_target = match format {
                MatrixFormat::IetfSdJwt => &payload,
                MatrixFormat::W3cSdJwt => &payload["credentialSubject"],
                _ => unreachable!(),
            };
            let expected_subject = format!("urn:example:benchmark-holder:{credential_ordinal}");
            assert_eq!(payload["sub"], expected_subject);
            if format == MatrixFormat::W3cSdJwt {
                assert_json_keys(&payload["credentialSubject"], &["_sd", "id"]);
                assert_eq!(payload["credentialSubject"]["id"], expected_subject);
            }
            let signed_hashes = disclosure_target["_sd"].as_array().unwrap();
            assert_eq!(signed_hashes.len(), item_count);
            for name in &expected_names {
                assert!(disclosure_target.get(name).is_none());
            }

            let mut disclosed_names = Vec::with_capacity(item_count);
            for disclosure in disclosures {
                let decoded: serde_json::Value =
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(disclosure).unwrap()).unwrap();
                let decoded = decoded.as_array().unwrap();
                assert_eq!(decoded.len(), 3);
                assert!(decoded[0].as_str().is_some_and(|salt| !salt.is_empty()));
                let name = decoded[1].as_str().unwrap().to_owned();
                let index = expected_names
                    .iter()
                    .position(|expected| expected == &name)
                    .unwrap();
                assert_eq!(decoded[2], expected_payload_value(class, index));
                disclosed_names.push(name);
                let disclosure_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()));
                assert!(signed_hashes.iter().any(|hash| hash == &disclosure_hash));
            }
            disclosed_names.sort_unstable();
            assert_eq!(disclosed_names, expected_names);
            assert_eq!(payload["_sd_alg"], "sha-256");
            assert_eq!(
                payload["cnf"]["jwk"],
                serde_json::to_value(holder_public_jwk()).unwrap()
            );
            for private_member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
                assert!(payload["cnf"]["jwk"].get(private_member).is_none());
            }
        }
        (
            MatrixFormat::Mdoc,
            SignedCredential::MsoMdoc {
                issuer_signed_b64, ..
            },
        ) => {
            let issuer_signed: isomdl::definitions::IssuerSigned =
                isomdl::cbor::from_slice(&URL_SAFE_NO_PAD.decode(issuer_signed_b64).unwrap())
                    .unwrap();
            assert_eq!(
                issuer_signed.issuer_auth.protected.header.alg.as_ref(),
                Some(&coset::Algorithm::Assigned(coset::iana::Algorithm::ES256))
            );
            let signature =
                p256::ecdsa::Signature::from_slice(&issuer_signed.issuer_auth.signature).unwrap();
            verifying_key
                .verify(&issuer_signed.issuer_auth.tbs_data(&[]), &signature)
                .unwrap();
            let namespaces = issuer_signed.namespaces.as_ref().unwrap();
            assert_eq!(namespaces.len(), 1);
            let namespace = namespaces.get(MATRIX_MDOC_NAMESPACE).unwrap();
            assert_eq!(namespace.len(), item_count);
            let wrapped_mso: CborValue = isomdl::cbor::from_slice(
                issuer_signed
                    .issuer_auth
                    .payload
                    .as_ref()
                    .expect("MSO payload"),
            )
            .unwrap();
            let CborValue::Tag(CBOR_TAG_ENCODED_CBOR, encoded_mso) = wrapped_mso else {
                panic!("issuerAuth payload must be tag 24");
            };
            let CborValue::Bytes(encoded_mso) = *encoded_mso else {
                panic!("MobileSecurityObjectBytes must wrap bytes");
            };
            let CborValue::Map(mso) = isomdl::cbor::from_slice(&encoded_mso).unwrap() else {
                panic!("MSO must be a map");
            };
            assert_eq!(
                cbor_map_value(&mso, "docType"),
                &CborValue::Text("org.example.benchmark.payload".into())
            );
            assert_eq!(
                cbor_map_value(&mso, "digestAlgorithm"),
                &CborValue::Text("SHA-256".into())
            );
            let CborValue::Map(value_digests) = cbor_map_value(&mso, "valueDigests") else {
                panic!("valueDigests must be a map");
            };
            assert_eq!(value_digests.len(), 1);
            let CborValue::Map(namespace_digests) = value_digests
                .iter()
                .find_map(|(key, value)| {
                    (key == &CborValue::Text(MATRIX_MDOC_NAMESPACE.into())).then_some(value)
                })
                .expect("matrix namespace digests")
            else {
                panic!("namespace valueDigests must be a map");
            };
            assert_eq!(namespace_digests.len(), item_count);

            let mut actual_names = Vec::with_capacity(item_count);
            for tagged_item in namespace.iter() {
                let item = tagged_item.as_ref();
                let index = expected_names
                    .iter()
                    .position(|expected| expected == &item.element_identifier)
                    .unwrap();
                assert_eq!(item.element_value, expected_cbor_value(class, index));
                actual_names.push(item.element_identifier.clone());
                let digest_id = serde_json::to_value(item.digest_id)
                    .unwrap()
                    .as_u64()
                    .unwrap();
                let CborValue::Bytes(expected_digest) = namespace_digests
                    .iter()
                    .find_map(|(key, value)| {
                        (key == &CborValue::Integer(digest_id.into())).then_some(value)
                    })
                    .expect("item valueDigest")
                else {
                    panic!("valueDigest must be bytes");
                };
                let encoded_wrapper = isomdl::cbor::to_vec(tagged_item).unwrap();
                assert_eq!(Sha256::digest(encoded_wrapper).as_slice(), expected_digest);
            }
            actual_names.sort_unstable();
            assert_eq!(actual_names, expected_names);
        }
        (expected, actual) => {
            panic!("matrix preflight format mismatch: expected {expected:?}, got {actual:?}")
        }
    }
}

fn cbor_map_value<'a>(entries: &'a [(CborValue, CborValue)], name: &str) -> &'a CborValue {
    entries
        .iter()
        .find_map(|(key, value)| (key == &CborValue::Text(name.into())).then_some(value))
        .unwrap_or_else(|| panic!("{name} must be present"))
}

fn expected_cbor_value(class: PayloadClass, index: usize) -> CborValue {
    fn json_to_cbor(value: &serde_json::Value) -> CborValue {
        match value {
            serde_json::Value::Null => CborValue::Null,
            serde_json::Value::Bool(value) => CborValue::Bool(*value),
            serde_json::Value::Number(value) => value
                .as_i64()
                .map(|value| CborValue::Integer(value.into()))
                .or_else(|| value.as_f64().map(CborValue::Float))
                .expect("matrix number must fit CBOR"),
            serde_json::Value::String(value) => CborValue::Text(value.clone()),
            serde_json::Value::Array(values) => {
                CborValue::Array(values.iter().map(json_to_cbor).collect())
            }
            serde_json::Value::Object(values) => CborValue::Map(
                values
                    .iter()
                    .map(|(name, value)| (CborValue::Text(name.clone()), json_to_cbor(value)))
                    .collect(),
            ),
        }
    }

    json_to_cbor(&expected_payload_value(class, index))
}

fn preflight_payload_matrix(selection: &MatrixSelection) {
    let worker_limit = *available_worker_limits().last().unwrap();
    for &format in &selection.formats {
        for &class in &selection.classes {
            for item_count in [1, 512] {
                let serial_signer = BenchmarkSigner::new(1);
                let serial = Es256SignerScope::new(&serial_signer)
                    .unwrap()
                    .sign_batch(matrix_signing_inputs(format, class, item_count, 1))
                    .unwrap();
                assert_eq!(serial.len(), 1);
                assert_matrix_preflight_credential(
                    format,
                    class,
                    item_count,
                    0,
                    &serial[0],
                    serial_signer.signing_key.verifying_key(),
                );

                let mut concurrent_signer = BenchmarkSigner::new(worker_limit);
                let concurrent = ConcurrentEs256SignerScope::new(&mut concurrent_signer)
                    .unwrap()
                    .sign_batch_concurrently(matrix_signing_inputs(format, class, item_count, 1))
                    .unwrap();
                assert_eq!(concurrent.len(), 1);
                assert_matrix_preflight_credential(
                    format,
                    class,
                    item_count,
                    0,
                    &concurrent[0],
                    concurrent_signer.signing_key.verifying_key(),
                );
            }
        }
    }
}

fn preflight() {
    let worker_limit = *available_worker_limits().last().unwrap();
    for composition in [
        BenchmarkComposition::JwtVc,
        BenchmarkComposition::SdJwt,
        BenchmarkComposition::Mdoc,
        BenchmarkComposition::JwtMdoc,
        BenchmarkComposition::ThreeFormat,
    ] {
        for batch_size in BATCH_SIZES {
            let serial_signer = BenchmarkSigner::new(1);
            let serial = Es256SignerScope::new(&serial_signer)
                .unwrap()
                .sign_batch(signing_inputs(composition, batch_size))
                .unwrap();
            assert_eq!(serial.len(), batch_size);
            for (ordinal, credential) in serial.iter().enumerate() {
                assert_preflight_credential(
                    composition.format_at(ordinal),
                    ordinal,
                    credential,
                    serial_signer.signing_key.verifying_key(),
                );
            }

            let mut concurrent_signer = BenchmarkSigner::new(worker_limit);
            let concurrent = ConcurrentEs256SignerScope::new(&mut concurrent_signer)
                .unwrap()
                .sign_batch_concurrently(signing_inputs(composition, batch_size))
                .unwrap();
            assert_eq!(concurrent.len(), batch_size);
            for (ordinal, credential) in concurrent.iter().enumerate() {
                assert_preflight_credential(
                    composition.format_at(ordinal),
                    ordinal,
                    credential,
                    concurrent_signer.signing_key.verifying_key(),
                );
            }
        }
    }
}

fn benchmark_stages(c: &mut Criterion, group_name: &str, composition: BenchmarkComposition) {
    let signer = BenchmarkSigner::new(WORKER_LIMIT);
    let mut group = c.benchmark_group(group_name);
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
    group.noise_threshold(0.05);

    for batch_size in BATCH_SIZES {
        group.throughput(Throughput::Elements(batch_size as u64));

        for route in ["serial", "concurrent"] {
            group.bench_with_input(
                BenchmarkId::new(format!("preparation/{route}"), batch_size),
                &batch_size,
                |bencher, &batch_size| {
                    bencher.iter_batched(
                        || claims_batch(composition, batch_size),
                        |claims| black_box(prepare_batch(&signer, composition, black_box(claims))),
                        BatchSize::SmallInput,
                    );
                },
            );
        }

        let prepared = prepare_batch(&signer, composition, claims_batch(composition, batch_size));
        group.bench_with_input(
            BenchmarkId::new("signing/serial", batch_size),
            &batch_size,
            |bencher, _| {
                bencher.iter(|| black_box(sign_payloads_serially(&signer, black_box(&prepared))));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("signing/concurrent", batch_size),
            &batch_size,
            |bencher, _| {
                bencher.iter(|| {
                    black_box(sign_payloads_concurrently(
                        &signer,
                        black_box(&prepared),
                        WORKER_LIMIT,
                    ))
                });
            },
        );

        for route in ["serial", "concurrent"] {
            group.bench_with_input(
                BenchmarkId::new(format!("assembly/{route}"), batch_size),
                &batch_size,
                |bencher, &batch_size| {
                    bencher.iter_batched(
                        || {
                            prepare_batch(
                                &signer,
                                composition,
                                claims_batch(composition, batch_size),
                            )
                        },
                        |prepared| {
                            black_box(
                                prepared
                                    .into_iter()
                                    .map(|prepared| prepared.assemble(&[0x5a; 64]))
                                    .collect::<Vec<_>>(),
                            )
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }

        group.bench_with_input(
            BenchmarkId::new("total/serial", batch_size),
            &batch_size,
            |bencher, &batch_size| {
                bencher.iter_batched(
                    || {
                        (
                            BenchmarkSigner::new(1),
                            signing_inputs(composition, batch_size),
                        )
                    },
                    |(signer, inputs)| {
                        black_box(
                            Es256SignerScope::new(&signer)
                                .unwrap()
                                .sign_batch(inputs)
                                .unwrap(),
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        group.bench_with_input(
            BenchmarkId::new("total/concurrent", batch_size),
            &batch_size,
            |bencher, &batch_size| {
                bencher.iter_batched(
                    || {
                        (
                            BenchmarkSigner::new(WORKER_LIMIT),
                            signing_inputs(composition, batch_size),
                        )
                    },
                    |(mut signer, inputs)| {
                        let scope = ConcurrentEs256SignerScope::new(&mut signer).unwrap();
                        black_box(scope.sign_batch_concurrently(inputs).unwrap())
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn benchmark_composition_totals(c: &mut Criterion) {
    let mut group = c.benchmark_group("es256_signing_batch_total_by_composition");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
    group.noise_threshold(0.05);
    let worker_limits = available_worker_limits();

    for batch_size in BATCH_SIZES {
        group.throughput(Throughput::Elements(batch_size as u64));
        for composition in [
            BenchmarkComposition::JwtVc,
            BenchmarkComposition::SdJwt,
            BenchmarkComposition::Mdoc,
            BenchmarkComposition::ThreeFormat,
        ] {
            group.bench_with_input(
                BenchmarkId::new(format!("{}/serial", composition.label()), batch_size),
                &batch_size,
                |bencher, &batch_size| {
                    bencher.iter_batched(
                        || {
                            (
                                BenchmarkSigner::new(1),
                                signing_inputs(composition, batch_size),
                            )
                        },
                        |(signer, inputs)| {
                            black_box(
                                Es256SignerScope::new(&signer)
                                    .unwrap()
                                    .sign_batch(inputs)
                                    .unwrap(),
                            )
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            for &worker_limit in &worker_limits {
                group.bench_with_input(
                    BenchmarkId::new(
                        format!("{}/concurrent/p={worker_limit}", composition.label()),
                        batch_size,
                    ),
                    &batch_size,
                    |bencher, &batch_size| {
                        bencher.iter_batched(
                            || {
                                (
                                    BenchmarkSigner::new(worker_limit),
                                    signing_inputs(composition, batch_size),
                                )
                            },
                            |(mut signer, inputs)| {
                                let scope = ConcurrentEs256SignerScope::new(&mut signer).unwrap();
                                black_box(scope.sign_batch_concurrently(inputs).unwrap())
                            },
                            BatchSize::SmallInput,
                        );
                    },
                );
            }
        }
    }
    group.finish();
}

fn benchmark_payload_matrix(c: &mut Criterion, selection: &MatrixSelection) {
    let mut group = c.benchmark_group("es256_signing_batch_total_payload_matrix");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
    group.noise_threshold(0.05);
    let worker_limits = available_worker_limits();

    for &batch_size in &selection.batch_sizes {
        group.throughput(Throughput::Elements(batch_size as u64));
        for &format in &selection.formats {
            for &class in &selection.classes {
                for &item_count in &selection.item_counts {
                    let case = format!("{}/{}/n={item_count}", format.label(), class.label());
                    group.bench_with_input(
                        BenchmarkId::new(format!("{case}/serial"), format!("b={batch_size}")),
                        &batch_size,
                        |bencher, &batch_size| {
                            bencher.iter_batched(
                                || {
                                    (
                                        BenchmarkSigner::new(1),
                                        matrix_signing_inputs(
                                            format, class, item_count, batch_size,
                                        ),
                                    )
                                },
                                |(signer, inputs)| {
                                    black_box(
                                        Es256SignerScope::new(&signer)
                                            .unwrap()
                                            .sign_batch(inputs)
                                            .unwrap(),
                                    )
                                },
                                BatchSize::PerIteration,
                            );
                        },
                    );

                    for &worker_limit in &worker_limits {
                        group.bench_with_input(
                            BenchmarkId::new(
                                format!("{case}/concurrent/p={worker_limit}"),
                                format!("b={batch_size}"),
                            ),
                            &batch_size,
                            |bencher, &batch_size| {
                                bencher.iter_batched(
                                    || {
                                        (
                                            BenchmarkSigner::new(worker_limit),
                                            matrix_signing_inputs(
                                                format, class, item_count, batch_size,
                                            ),
                                        )
                                    },
                                    |(mut signer, inputs)| {
                                        let scope =
                                            ConcurrentEs256SignerScope::new(&mut signer).unwrap();
                                        black_box(scope.sign_batch_concurrently(inputs).unwrap())
                                    },
                                    BatchSize::PerIteration,
                                );
                            },
                        );
                    }
                }
            }
        }
    }
    group.finish();
}

fn benchmark_es256_signing_batch(c: &mut Criterion) {
    let matrix_selection = matrix_enabled().then(MatrixSelection::from_env);
    preflight();
    benchmark_stages(
        c,
        "es256_signing_batch_mixed_jwt_mdoc",
        BenchmarkComposition::JwtMdoc,
    );
    benchmark_stages(
        c,
        "es256_signing_batch_proof_bound_sd_jwt",
        BenchmarkComposition::SdJwt,
    );
    benchmark_composition_totals(c);
    if let Some(selection) = matrix_selection {
        preflight_payload_matrix(&selection);
        benchmark_payload_matrix(c, &selection);
    }
}

criterion_group!(benches, benchmark_es256_signing_batch);
criterion_main!(benches);
