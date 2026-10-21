use std::{
    collections::{HashMap, HashSet},
    hint::black_box,
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use marty_oid4vci::{
    formats::sd_jwt::{assemble_sd_jwt, PreparedSdJwt},
    remote_credential::{
        prepare_remote_sd_jwt, prepare_remote_sd_jwt_batch, RemoteSdJwtBatchItem,
        RemoteSdJwtRequest,
    },
    types::SignedCredential,
};
use sha2::{Digest, Sha256};

#[path = "support/openbao_signer.rs"]
mod openbao_signer;

const BATCH_SIZES: [usize; 4] = [1, 8, 32, 256];
const SELECTIVE_CLAIM_COUNT: usize = 8;
const SELECTIVE_CLAIM_BYTES: usize = 256;

fn credential_id(index: usize) -> String {
    format!("urn:uuid:{index:08x}-0000-4000-8000-{index:012x}")
}

fn fixture_with_credential_id(credential_id: &str) -> RemoteSdJwtRequest {
    let selective_disclosure_claims = (0..SELECTIVE_CLAIM_COUNT)
        .map(|index| format!("private_claim_{index:02}"))
        .collect::<Vec<_>>();
    let mut claims = selective_disclosure_claims
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let value = format!("{index:02}{}", "v".repeat(SELECTIVE_CLAIM_BYTES - 2));
            assert_eq!(value.len(), SELECTIVE_CLAIM_BYTES);
            (name.clone(), serde_json::Value::String(value))
        })
        .collect::<HashMap<_, _>>();
    claims.insert("visible".into(), serde_json::json!(true));

    RemoteSdJwtRequest {
        issuer_id: "did:web:issuer.example".into(),
        verification_method_id: "did:web:issuer.example#key-1".into(),
        algorithm: "ES256".into(),
        issuer_public_jwk: openbao_signer::public_jwk().to_owned(),
        subject_id: Some("did:key:holder".into()),
        credential_type: "AccessBadge".into(),
        claims,
        expiration_seconds: Some(365 * 86_400),
        selective_disclosure_claims,
        credential_format: Some("dc+sd-jwt".into()),
        credential_id: Some(credential_id.into()),
        holder_jwk: Some(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        })),
        issuer_certificate_chain: vec!["leaf".into(), "issuer".into()],
    }
}

fn decode_json_segment(signing_input: &str, index: usize) -> serde_json::Value {
    let encoded = signing_input.split('.').nth(index).expect("JWT segment");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).expect("base64url segment"))
        .expect("JSON segment")
}

fn assert_prepared(request: &RemoteSdJwtRequest, prepared: PreparedSdJwt) {
    let credential_id = request
        .credential_id
        .as_deref()
        .expect("benchmark fixture credential ID");
    assert_eq!(prepared.credential_id(), credential_id);
    assert_eq!(prepared.signing_input().split('.').count(), 2);

    let header = decode_json_segment(prepared.signing_input(), 0);
    let payload = decode_json_segment(prepared.signing_input(), 1);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["kid"], request.verification_method_id);
    assert_eq!(header["typ"], "dc+sd-jwt");
    assert_eq!(header["x5c"], serde_json::json!(["leaf", "issuer"]));
    assert_eq!(payload["iss"], request.issuer_id);
    assert_eq!(payload["sub"], request.subject_id.as_deref().unwrap());
    assert_eq!(payload["vct"], request.credential_type);
    assert_eq!(payload["jti"], credential_id);
    assert_eq!(payload["_sd_alg"], "sha-256");
    assert_eq!(payload["visible"], true);
    assert!(payload.get("nbf").is_some());
    assert_eq!(
        payload["cnf"]["jwk"],
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        })
    );
    assert!(payload["cnf"]["jwk"].get("d").is_none());

    let sd_digests = payload["_sd"].as_array().expect("SD digest array");
    assert_eq!(sd_digests.len(), SELECTIVE_CLAIM_COUNT);
    let mut expected_digests = sd_digests
        .iter()
        .map(|digest| digest.as_str().expect("string digest").to_owned())
        .collect::<HashSet<_>>();
    assert_eq!(expected_digests.len(), SELECTIVE_CLAIM_COUNT);

    assert!(prepared.disclosures_suffix().starts_with('~'));
    assert!(prepared.disclosures_suffix().ends_with('~'));
    let disclosures = prepared
        .disclosures_suffix()
        .split('~')
        .filter(|disclosure| !disclosure.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(disclosures.len(), SELECTIVE_CLAIM_COUNT);
    for (ordinal, (disclosure, claim_name)) in disclosures
        .iter()
        .zip(&request.selective_disclosure_claims)
        .enumerate()
    {
        let decoded: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(disclosure)
                .expect("base64url disclosure"),
        )
        .expect("JSON disclosure");
        let fields = decoded.as_array().expect("object-property disclosure");
        assert_eq!(fields.len(), 3);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(fields[0].as_str().expect("salt string"))
                .expect("base64url salt")
                .len(),
            16
        );
        assert_eq!(fields[1], claim_name.as_str());
        assert_eq!(
            &fields[2],
            request
                .claims
                .get(claim_name)
                .expect("disclosed input claim")
        );
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()));
        assert_eq!(sd_digests[ordinal], digest);
        assert!(expected_digests.remove(&digest));
        assert!(payload.get(claim_name).is_none());
    }
    assert!(expected_digests.is_empty());

    let signature = openbao_signer::sign(prepared.signing_payload());
    let signing_input = prepared.signing_input().to_owned();
    let disclosures_suffix = prepared.disclosures_suffix().to_owned();
    let SignedCredential::SdJwt {
        compact,
        credential_id: assembled_id,
    } = assemble_sd_jwt(prepared, &signature).expect("valid fixture signature")
    else {
        panic!("fixture must assemble as SD-JWT")
    };
    assert_eq!(assembled_id, credential_id);
    assert!(compact.starts_with(&format!("{signing_input}.")));
    assert!(compact.ends_with(&disclosures_suffix));
}

fn batch_fixtures(batch_size: usize) -> (Vec<RemoteSdJwtRequest>, Vec<RemoteSdJwtBatchItem>) {
    let requests = (0..batch_size)
        .map(|index| fixture_with_credential_id(&credential_id(index)))
        .collect::<Vec<_>>();
    let batch = requests
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, request)| RemoteSdJwtBatchItem::new(10_000 + index as u64, request))
        .collect();
    (requests, batch)
}

fn preflight_batch(batch_size: usize) {
    let (requests, batch) = batch_fixtures(batch_size);
    let sequential = requests
        .iter()
        .cloned()
        .map(prepare_remote_sd_jwt)
        .collect::<Result<Vec<_>, _>>()
        .expect("sequential fixture must prepare");
    assert_eq!(sequential.len(), batch_size);
    for (request, prepared) in requests.iter().zip(sequential) {
        assert_prepared(request, prepared);
    }

    let prepared = prepare_remote_sd_jwt_batch(batch).expect("batch fixture must prepare");
    assert_eq!(prepared.len(), batch_size);
    for (index, (request, prepared)) in requests.into_iter().zip(prepared).enumerate() {
        assert_eq!(prepared.batch_id(), 10_000 + index as u64);
        assert_prepared(&request, prepared.into_prepared_sd_jwt());
    }
}

fn benchmark_sd_jwt_batch_issuance(c: &mut Criterion) {
    let mut group = c.benchmark_group("sd_jwt_issuance_prepare_batch");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    group.significance_level(0.05);
    group.noise_threshold(0.03);

    for batch_size in BATCH_SIZES {
        preflight_batch(batch_size);
        let (requests, batch) = batch_fixtures(batch_size);
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("sequential_8_disclosures_256b", batch_size),
            &requests,
            |bencher, requests| {
                bencher.iter_batched(
                    || requests.clone(),
                    |requests| {
                        black_box(
                            requests
                                .into_iter()
                                .map(prepare_remote_sd_jwt)
                                .collect::<Result<Vec<_>, _>>()
                                .unwrap(),
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        group.bench_with_input(
            BenchmarkId::new("batch_8_disclosures_256b", batch_size),
            &batch,
            |bencher, batch| {
                bencher.iter_batched(
                    || batch.clone(),
                    |batch| black_box(prepare_remote_sd_jwt_batch(black_box(batch)).unwrap()),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, benchmark_sd_jwt_batch_issuance);
criterion_main!(benches);
