use std::{
    collections::HashMap,
    fmt,
    hint::black_box,
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use marty_oid4vci::{
    formats::{
        jwt_vc::{assemble_jwt_vc, prepare_jwt_vc, PreparedJwtVc},
        mdoc::{assemble_mdoc, prepare_mdoc, PreparedMdoc},
    },
    signer::CredentialSigner,
    signing_batch::{
        BoundedConcurrentCredentialSigner, ConcurrentEs256SignerScope, Es256SignerScope,
        Es256SigningBatchInput, JwtVcSigningBatchInput, MdocSigningBatchInput, SigningRouteId,
    },
    types::{CredentialClaims, CredentialPayloadFormat, SignedCredential, SigningAlgorithm},
    Oid4vciResult,
};
use p256::ecdsa::signature::Signer as _;

const BATCH_SIZES: [usize; 4] = [1, 8, 32, 256];
const WORKER_LIMIT: usize = 8;

struct BenchmarkSigner {
    signing_key: p256::ecdsa::SigningKey,
}

impl BenchmarkSigner {
    fn new() -> Self {
        Self {
            signing_key: p256::ecdsa::SigningKey::from_slice(&[0x31; 32]).unwrap(),
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
        NonZeroUsize::new(WORKER_LIMIT).unwrap()
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
        mdoc_namespace: Some("org.iso.18013.5.1".into()),
        mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
        zk_predicate_claims: vec![],
        credential_payload_format: CredentialPayloadFormat::default(),
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn claims_batch(batch_size: usize) -> Vec<CredentialClaims> {
    (0..batch_size)
        .map(|ordinal| {
            if ordinal % 2 == 0 {
                jwt_claims(ordinal)
            } else {
                mdoc_claims(ordinal)
            }
        })
        .collect()
}

fn signing_inputs(batch_size: usize) -> Vec<Es256SigningBatchInput> {
    claims_batch(batch_size)
        .into_iter()
        .enumerate()
        .map(|(ordinal, claims)| {
            let route = SigningRouteId::new(ordinal as u64);
            if ordinal % 2 == 0 {
                JwtVcSigningBatchInput::new(route, claims).into()
            } else {
                MdocSigningBatchInput::new(route, claims).into()
            }
        })
        .collect()
}

enum BenchmarkPrepared {
    JwtVc(PreparedJwtVc),
    Mdoc(Box<PreparedMdoc>),
}

impl BenchmarkPrepared {
    fn signing_payload(&self) -> &[u8] {
        match self {
            Self::JwtVc(prepared) => prepared.signing_payload(),
            Self::Mdoc(prepared) => prepared.signing_payload(),
        }
    }

    fn assemble(self, signature: &[u8]) -> SignedCredential {
        match self {
            Self::JwtVc(prepared) => assemble_jwt_vc(prepared, signature),
            Self::Mdoc(prepared) => assemble_mdoc(*prepared, signature).unwrap(),
        }
    }
}

fn prepare_batch(
    signer: &dyn CredentialSigner,
    claims: Vec<CredentialClaims>,
) -> Vec<BenchmarkPrepared> {
    claims
        .into_iter()
        .enumerate()
        .map(|(ordinal, claims)| {
            if ordinal % 2 == 0 {
                BenchmarkPrepared::JwtVc(prepare_jwt_vc(signer, &claims).unwrap())
            } else {
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
) -> Vec<Vec<u8>> {
    if prepared.is_empty() {
        return Vec::new();
    }
    let workers = prepared.len().min(WORKER_LIMIT);
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

fn benchmark_es256_signing_batch(c: &mut Criterion) {
    let signer = BenchmarkSigner::new();
    let mut group = c.benchmark_group("es256_signing_batch_mixed_jwt_mdoc");
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
                        || claims_batch(batch_size),
                        |claims| black_box(prepare_batch(&signer, black_box(claims))),
                        BatchSize::SmallInput,
                    );
                },
            );
        }

        let prepared = prepare_batch(&signer, claims_batch(batch_size));
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
                bencher
                    .iter(|| black_box(sign_payloads_concurrently(&signer, black_box(&prepared))));
            },
        );

        for route in ["serial", "concurrent"] {
            group.bench_with_input(
                BenchmarkId::new(format!("assembly/{route}"), batch_size),
                &batch_size,
                |bencher, &batch_size| {
                    bencher.iter_batched(
                        || prepare_batch(&signer, claims_batch(batch_size)),
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
                    || (BenchmarkSigner::new(), signing_inputs(batch_size)),
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
                    || (BenchmarkSigner::new(), signing_inputs(batch_size)),
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

criterion_group!(benches, benchmark_es256_signing_batch);
criterion_main!(benches);
