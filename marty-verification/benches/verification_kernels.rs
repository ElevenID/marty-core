use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use marty_verification::asn1::sod::{parse_sod, verify_sod_signature};
use marty_verification::issuance::CscaAuthority;
use marty_verification::mrz::parse_mrz;
use marty_verification::policy::service::{
    evaluate_service_policy, ServicePolicyEvaluationRequest,
};
use marty_verification::verification::ChainValidator;
use std::hint::black_box;

const TD3_MRZ: [&str; 2] = [
    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
    "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
];

struct EmrtdFixture {
    sod_der: Vec<u8>,
    certificate_chain_der: Vec<Vec<u8>>,
    validator: ChainValidator,
}

fn emrtd_fixture() -> EmrtdFixture {
    let csca =
        CscaAuthority::new("TST", "Criterion Test Country", 3650).expect("generate benchmark CSCA");
    let dsc = csca
        .issue_dsc("Criterion Document Signer", 90)
        .expect("generate benchmark DSC");
    let passport = dsc
        .personalizer()
        .set_mrz(TD3_MRZ.concat().as_bytes())
        .set_face_image(&[0x5a; 1024])
        .build()
        .expect("build benchmark EF.SOD");

    assert!(
        verify_sod_signature(&passport.sod_der).expect("verify benchmark EF.SOD"),
        "generated EF.SOD must have a valid signature"
    );

    let mut validator = ChainValidator::new();
    validator
        .add_trust_anchor_der(csca.cert_der())
        .expect("add benchmark CSCA trust anchor");
    let certificate_chain_der = vec![dsc.cert_der.clone(), csca.cert_der.clone()];
    assert!(
        validator
            .validate_chain_der(&certificate_chain_der)
            .expect("validate benchmark certificate chain")
            .valid,
        "generated DSC chain must be valid"
    );

    EmrtdFixture {
        sod_der: passport.sod_der,
        certificate_chain_der,
        validator,
    }
}

fn benchmark_verification_kernels(c: &mut Criterion) {
    let mut group = c.benchmark_group("emrtd_verification");
    let fixture = emrtd_fixture();

    group.bench_function("parse_td3_mrz", |b| {
        b.iter(|| parse_mrz(black_box(&TD3_MRZ)).expect("parse benchmark MRZ"));
    });
    group.bench_function("parse_sod", |b| {
        b.iter(|| parse_sod(black_box(&fixture.sod_der)).expect("parse benchmark EF.SOD"));
    });
    group.bench_function("verify_sod_signature", |b| {
        b.iter(|| {
            assert!(
                verify_sod_signature(black_box(&fixture.sod_der)).expect("verify benchmark EF.SOD")
            );
        });
    });
    group.bench_function("validate_csca_dsc_chain", |b| {
        b.iter(|| {
            assert!(
                fixture
                    .validator
                    .validate_chain_der(black_box(&fixture.certificate_chain_der))
                    .expect("validate benchmark certificate chain")
                    .valid
            );
        });
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
