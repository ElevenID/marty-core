use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use marty_verification::mrz::parse_mrz;
use marty_verification::policy::service::{
    evaluate_service_policy, ServicePolicyEvaluationRequest,
};
use std::hint::black_box;

const TD3_MRZ: [&str; 2] = [
    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
    "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
];

fn benchmark_verification_kernels(c: &mut Criterion) {
    let mut group = c.benchmark_group("document_verification");

    group.bench_function("parse_td3_mrz", |b| {
        b.iter(|| parse_mrz(black_box(&TD3_MRZ)).expect("parse benchmark MRZ"));
    });
    group.finish();

    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/vectors/presentation_policy_service.json"
    ))
    .expect("parse presentation-policy benchmark fixture");
    let request: ServicePolicyEvaluationRequest =
        serde_json::from_value(fixture["request"].clone())
            .expect("parse presentation-policy benchmark request");
    let mut policy_group = c.benchmark_group("presentation_policy");
    policy_group.bench_function("evaluate_service_policy", |b| {
        b.iter_batched(
            || request.clone(),
            |request| {
                black_box(
                    evaluate_service_policy(request)
                        .expect("evaluate presentation-policy benchmark request"),
                );
            },
            BatchSize::SmallInput,
        );
    });
    policy_group.finish();

    let claims = serde_json::from_value(serde_json::json!({
        "docType": "CMC",
        "issuingCountry": "AUS",
        "documentNumber": "X123456",
        "surname": "EXAMPLE",
        "givenNames": "ADA",
        "dateOfBirth": "19900102",
        "nationality": "AUS",
        "gender": "F",
        "dateOfIssue": "20260101",
        "dateOfExpiry": "20300101"
    }))
    .expect("build VDS-NC benchmark claims");
    let (payload, _, country) = marty_oid4vci::formats::vds_nc_profile::build_profile_payload(
        &claims,
        "CMC",
        "benchmark-issuer",
        "benchmark-issuer#key-1",
        "ES256",
    )
    .expect("build VDS-NC benchmark profile");
    let barcode = format!("DC03{country}~{payload}~c2lnbmF0dXJl");
    let mut vds_group = c.benchmark_group("vds_nc_profile");
    vds_group.bench_function("parse_canonical_profile", |b| {
        b.iter(|| {
            black_box(
                marty_oid4vci::formats::vds_nc_profile::parse_barcode(black_box(&barcode))
                    .expect("parse benchmark VDS-NC profile"),
            );
        });
    });
    vds_group.finish();
}

criterion_group!(benches, benchmark_verification_kernels);
criterion_main!(benches);
