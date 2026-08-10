use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use der::Decode;
use marty_verification::asn1::sod::{
    parse_sod, verify_data_group_hash_from_sod, verify_sod_signature,
};
use marty_verification::trust_anchor::CscaRegistry;
use marty_verification::verification::emrtd::{
    verify_emrtd, ChainStatus, HashStatus, SecurityObject, SignatureStatus,
};
use marty_verification::verification::ChainValidator;
use serde::Deserialize;
use std::collections::HashMap;
use x509_cert::Certificate;

#[derive(Deserialize)]
struct EmrtdFixture {
    schema_version: u32,
    generated_at: String,
    csca_der_base64: String,
    dsc_der_base64: String,
    sod_der_base64: String,
    data_groups: HashMap<String, String>,
}

fn fixture() -> EmrtdFixture {
    serde_json::from_str(include_str!("fixtures/emrtd_verification_vectors.json"))
        .expect("parse shared eMRTD fixture")
}

fn decode(value: &str) -> Vec<u8> {
    STANDARD.decode(value).expect("decode fixture base64")
}

#[test]
fn rust_matches_shared_emrtd_golden_vector() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.generated_at, "2026-08-10T09:06:30Z");
    let sod = decode(&fixture.sod_der_base64);
    let dsc = decode(&fixture.dsc_der_base64);
    let csca = decode(&fixture.csca_der_base64);
    let dg1 = decode(&fixture.data_groups["1"]);
    let dg2 = decode(&fixture.data_groups["2"]);

    let parsed = parse_sod(&sod).expect("parse golden EF.SOD");
    assert_eq!(parsed.data_group_hashes.len(), 2);
    assert!(verify_sod_signature(&sod).expect("verify golden EF.SOD"));
    assert!(verify_data_group_hash_from_sod(&sod, 1, &dg1).expect("verify DG1 hash"));
    assert!(verify_data_group_hash_from_sod(&sod, 2, &dg2).expect("verify DG2 hash"));

    let mut registry = CscaRegistry::new();
    registry
        .add_country_csca(
            "TST",
            Certificate::from_der(&csca).expect("parse golden CSCA"),
        )
        .expect("add golden CSCA to eMRTD registry");
    let security_object =
        SecurityObject::from_sod_der(&sod, Some("TST".to_string())).expect("load golden SOD");
    let data_groups = HashMap::from([(1, dg1.clone()), (2, dg2.clone())]);
    let result = verify_emrtd(&security_object, &data_groups, &registry);
    assert!(result.verified);
    assert_eq!(result.dsc_chain_status, ChainStatus::Valid);
    assert_eq!(result.sod_signature_status, SignatureStatus::Valid);
    assert_eq!(result.dg_hash_status, HashStatus::Valid);
    assert!(result.error_codes.is_empty());
    assert!(result.trust_anchor_subject.is_some());
    assert_eq!(result.certificate_chain.len(), 2);

    let mut altered_dg1 = dg1.clone();
    altered_dg1[0] ^= 1;
    assert!(!verify_data_group_hash_from_sod(&sod, 1, &altered_dg1).expect("reject altered DG1"));
    let altered_result = verify_emrtd(
        &security_object,
        &HashMap::from([(1, altered_dg1), (2, dg2.clone())]),
        &registry,
    );
    assert!(!altered_result.verified);
    assert_eq!(altered_result.dg_hash_status, HashStatus::Invalid);
    assert!(altered_result
        .error_codes
        .contains(&"EMRTD_DG_HASH_INVALID".to_string()));

    let mut altered_sod = sod.clone();
    let last = altered_sod.len() - 1;
    altered_sod[last] ^= 1;
    assert!(
        !matches!(verify_sod_signature(&altered_sod), Ok(true)),
        "altered EF.SOD must fail closed"
    );

    let mut validator = ChainValidator::new();
    validator
        .add_trust_anchor_der(&csca)
        .expect("add golden CSCA");
    assert!(
        validator
            .validate_chain_der(&[dsc.clone(), csca.clone()])
            .expect("validate golden chain")
            .valid
    );
    assert!(
        !ChainValidator::new()
            .validate_chain_der(&[dsc, csca])
            .expect("reject untrusted chain")
            .valid,
        "a chain without a trust anchor must fail closed"
    );
}
