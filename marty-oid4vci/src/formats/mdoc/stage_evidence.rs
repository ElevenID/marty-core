use std::{
    collections::{HashMap, HashSet},
    hint::black_box,
    time::Duration,
};

use chrono::{TimeZone, Utc};
use criterion::{BatchSize, Criterion, Throughput};
use sha2::{Digest, Sha256};

use super::*;
use crate::types::SigningAlgorithm;

const EVIDENCE_ENABLE_ENV: &str = "MARTY_MDOC_STAGE_EVIDENCE";
const MATRIX_CLASSES_ENV: &str = "MARTY_MDOC_MATRIX_CLASSES";
const MATRIX_ITEM_COUNTS_ENV: &str = "MARTY_MDOC_MATRIX_ITEM_COUNTS";
const EVIDENCE_GROUP: &str = "mdoc_internal_stage_evidence";
const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
const NAMESPACE: &str = "org.iso.18013.5.1";
const LARGE_PORTRAIT_BYTES: usize = 256 * 1024;
const MIXED_MEDIUM_BYTES: usize = 1024;
const MIXED_LARGE_BYTES: usize = 64 * 1024;
const ITEM_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];
const EVIDENCE_SAMPLE_SIZE: usize = 10;
const EVIDENCE_WARM_UP: Duration = Duration::from_millis(250);
const EVIDENCE_MEASUREMENT: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadClass {
    SmallPrimitive,
    MediumNested,
    LargePortrait,
    MixedSize,
}

impl PayloadClass {
    const ALL: [Self; 4] = [
        Self::SmallPrimitive,
        Self::MediumNested,
        Self::LargePortrait,
        Self::MixedSize,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::SmallPrimitive => "small_primitive",
            Self::MediumNested => "medium_nested",
            Self::LargePortrait => "large_portrait",
            Self::MixedSize => "mixed_size",
        }
    }

    const fn code(self) -> u64 {
        match self {
            Self::SmallPrimitive => 1,
            Self::MediumNested => 2,
            Self::LargePortrait => 3,
            Self::MixedSize => 4,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "small_primitive" => Some(Self::SmallPrimitive),
            "medium_nested" => Some(Self::MediumNested),
            "large_portrait" => Some(Self::LargePortrait),
            "mixed_size" => Some(Self::MixedSize),
            _ => None,
        }
    }
}

struct EvidenceSelection {
    classes: Vec<PayloadClass>,
    item_counts: Vec<usize>,
}

impl EvidenceSelection {
    fn from_env() -> Self {
        Self {
            classes: parse_named_selector(
                MATRIX_CLASSES_ENV,
                &PayloadClass::ALL,
                PayloadClass::label,
                PayloadClass::parse,
            ),
            item_counts: parse_numeric_selector(MATRIX_ITEM_COUNTS_ENV, &ITEM_COUNTS),
        }
    }
}

struct EvidenceFixture {
    class: PayloadClass,
    item_count: usize,
    claims: CredentialClaims,
    holder_public_jwk: serde_json::Value,
    credential_id: String,
    now: chrono::DateTime<Utc>,
}

#[derive(Debug)]
struct EvidenceSigner;

impl CredentialSigner for EvidenceSigner {
    fn sign(&self, _message: &[u8]) -> Oid4vciResult<Vec<u8>> {
        panic!("stage evidence must stop before issuer signing")
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::ES256
    }

    fn issuer_id(&self) -> &str {
        "did:example:stage-evidence-issuer"
    }

    fn kid_url(&self) -> String {
        "did:example:stage-evidence-issuer#key-1".into()
    }
}

fn require_evidence_enable() {
    match std::env::var(EVIDENCE_ENABLE_ENV) {
        Ok(value) => assert_eq!(
            value, "1",
            "{EVIDENCE_ENABLE_ENV} must equal 1 when this ignored test is requested"
        ),
        Err(std::env::VarError::NotPresent) => {
            panic!("{EVIDENCE_ENABLE_ENV}=1 is required to run this ignored test")
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("{EVIDENCE_ENABLE_ENV} must contain Unicode text")
        }
    }
}

fn selector_values(name: &str) -> Option<Vec<String>> {
    let value = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return None,
        Err(std::env::VarError::NotUnicode(_)) => panic!("{name} must contain Unicode text"),
    };
    let values = value
        .split(',')
        .map(|value| {
            assert!(!value.is_empty(), "{name} contains an empty value");
            let value = value.trim();
            assert!(!value.is_empty(), "{name} contains an empty value");
            value.to_owned()
        })
        .collect::<Vec<_>>();
    assert!(!values.is_empty(), "{name} must select at least one value");
    if values.iter().any(|value| value == "all") {
        assert_eq!(values, ["all"], "{name}=all cannot be combined with values");
        None
    } else {
        Some(values)
    }
}

fn parse_named_selector<T: Copy + Eq>(
    name: &str,
    allowed: &[T],
    label: impl Fn(T) -> &'static str,
    parse: impl Fn(&str) -> Option<T>,
) -> Vec<T> {
    let Some(values) = selector_values(name) else {
        return allowed.to_vec();
    };
    let selected = values
        .iter()
        .map(|value| {
            parse(value).unwrap_or_else(|| {
                panic!(
                    "unsupported {name} value '{value}'; expected one of {}",
                    allowed
                        .iter()
                        .copied()
                        .map(&label)
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
        })
        .collect::<Vec<_>>();
    assert_unique(name, &selected, |value| label(value).to_owned());
    selected
}

fn parse_numeric_selector(name: &str, allowed: &[usize]) -> Vec<usize> {
    let Some(values) = selector_values(name) else {
        return allowed.to_vec();
    };
    let selected = values
        .iter()
        .map(|value| {
            let parsed = value
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("{name} value '{value}' is not an integer"));
            assert_eq!(
                parsed.to_string(),
                *value,
                "{name} value '{value}' is not canonical"
            );
            assert!(
                allowed.contains(&parsed),
                "unsupported {name} value '{value}'; expected one of {}",
                allowed
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            parsed
        })
        .collect::<Vec<_>>();
    assert_unique(name, &selected, |value| value.to_string());
    selected
}

fn assert_unique<T: Copy + Eq>(name: &str, values: &[T], label: impl Fn(T) -> String) {
    for (ordinal, value) in values.iter().copied().enumerate() {
        assert!(
            !values[..ordinal].contains(&value),
            "{name} repeats '{}'",
            label(value)
        );
    }
}

fn claim_name(index: usize) -> String {
    format!("benchmark_claim_{index:04}")
}

fn claim_index(identifier: &str, item_count: usize) -> usize {
    let encoded = identifier
        .strip_prefix("benchmark_claim_")
        .unwrap_or_else(|| panic!("unexpected stage-evidence claim identifier {identifier}"));
    let index = encoded
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("stage-evidence claim identifier must end in an integer"));
    assert_eq!(identifier, claim_name(index));
    assert!(
        index < item_count,
        "stage-evidence claim index must be in range"
    );
    index
}

fn repeated_ascii(length: usize, index: usize) -> String {
    let byte = b'A' + u8::try_from(index % 26).expect("fixture alphabet index must fit u8");
    String::from_utf8(vec![byte; length]).expect("fixture bytes must be ASCII")
}

fn json_value(class: PayloadClass, index: usize) -> serde_json::Value {
    match class {
        PayloadClass::SmallPrimitive => match index % 4 {
            0 => serde_json::json!(index),
            1 => serde_json::json!(index.is_multiple_of(2)),
            2 => serde_json::json!(format!("value-{index:04}")),
            _ => serde_json::Value::Null,
        },
        PayloadClass::MediumNested => serde_json::json!({
            "group": index % 8,
            "metadata": {
                "enabled": index.is_multiple_of(2),
                "label": format!("nested-{index:04}"),
                "sequence": index
            },
            "values": [index, index + 1, index + 2, index + 3]
        }),
        PayloadClass::LargePortrait if index == 0 => {
            serde_json::Value::String(repeated_ascii(LARGE_PORTRAIT_BYTES, index))
        }
        PayloadClass::LargePortrait => serde_json::Value::String(format!("value-{index:04}")),
        PayloadClass::MixedSize => match index % 4 {
            0 if index == 0 => serde_json::Value::String(repeated_ascii(MIXED_LARGE_BYTES, index)),
            0 => serde_json::Value::String(repeated_ascii(MIXED_MEDIUM_BYTES, index)),
            1 => serde_json::json!({
                "flags": [true, false, index.is_multiple_of(2)],
                "sequence": index
            }),
            2 => serde_json::json!(index),
            _ => serde_json::Value::String(format!("mixed-{index:04}")),
        },
    }
}

fn cbor_integer(value: usize) -> CborValue {
    CborValue::Integer(
        u64::try_from(value)
            .expect("fixture integer must fit u64")
            .into(),
    )
}

fn expected_cbor_value(class: PayloadClass, index: usize) -> CborValue {
    match class {
        PayloadClass::SmallPrimitive => match index % 4 {
            0 => cbor_integer(index),
            1 => CborValue::Bool(index.is_multiple_of(2)),
            2 => CborValue::Text(format!("value-{index:04}")),
            _ => CborValue::Null,
        },
        PayloadClass::MediumNested => CborValue::Map(vec![
            (CborValue::Text("group".into()), cbor_integer(index % 8)),
            (
                CborValue::Text("metadata".into()),
                CborValue::Map(vec![
                    (
                        CborValue::Text("enabled".into()),
                        CborValue::Bool(index.is_multiple_of(2)),
                    ),
                    (
                        CborValue::Text("label".into()),
                        CborValue::Text(format!("nested-{index:04}")),
                    ),
                    (CborValue::Text("sequence".into()), cbor_integer(index)),
                ]),
            ),
            (
                CborValue::Text("values".into()),
                CborValue::Array((index..index + 4).map(cbor_integer).collect()),
            ),
        ]),
        PayloadClass::LargePortrait if index == 0 => {
            CborValue::Text(repeated_ascii(LARGE_PORTRAIT_BYTES, index))
        }
        PayloadClass::LargePortrait => CborValue::Text(format!("value-{index:04}")),
        PayloadClass::MixedSize => match index % 4 {
            0 if index == 0 => CborValue::Text(repeated_ascii(MIXED_LARGE_BYTES, index)),
            0 => CborValue::Text(repeated_ascii(MIXED_MEDIUM_BYTES, index)),
            1 => CborValue::Map(vec![
                (
                    CborValue::Text("flags".into()),
                    CborValue::Array(vec![
                        CborValue::Bool(true),
                        CborValue::Bool(false),
                        CborValue::Bool(index.is_multiple_of(2)),
                    ]),
                ),
                (CborValue::Text("sequence".into()), cbor_integer(index)),
            ]),
            2 => cbor_integer(index),
            _ => CborValue::Text(format!("mixed-{index:04}")),
        },
    }
}

fn fixture(class: PayloadClass, item_count: usize) -> EvidenceFixture {
    assert!(ITEM_COUNTS.contains(&item_count));
    let claims = (0..item_count)
        .map(|index| (claim_name(index), json_value(class, index)))
        .collect::<HashMap<_, _>>();
    if class == PayloadClass::LargePortrait {
        assert_eq!(
            claims
                .values()
                .filter(|value| {
                    matches!(value, serde_json::Value::String(value) if value.len() == LARGE_PORTRAIT_BYTES)
                })
                .count(),
            1,
            "large portrait fixtures must contain exactly one 256-KiB value"
        );
    }
    let tail = (class.code() << 40) | (u64::try_from(item_count).unwrap() << 24);
    EvidenceFixture {
        class,
        item_count,
        claims: CredentialClaims {
            subject_id: Some("did:example:stage-evidence-holder".into()),
            credential_type: DOC_TYPE.into(),
            claims,
            expiration_seconds: Some(365 * 86_400),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some(NAMESPACE.into()),
            mdoc_doctype: Some(DOC_TYPE.into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        },
        holder_public_jwk: serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        }),
        credential_id: format!(
            "urn:uuid:{:08x}-{item_count:04x}-4000-8000-{tail:012x}",
            class.code()
        ),
        now: Utc
            .with_ymd_and_hms(2024, 1, 2, 3, 4, 5)
            .single()
            .expect("fixture timestamp must be unambiguous"),
    }
}

fn salt(class: PayloadClass, item_count: usize, ordinal: usize) -> [u8; 32] {
    let item_count = u64::try_from(item_count).expect("fixture item count must fit u64");
    let ordinal = u64::try_from(ordinal).expect("fixture ordinal must fit u64");
    std::array::from_fn(|byte_index| {
        let shift = u32::try_from((byte_index % 8) * 8).unwrap();
        let item_byte = item_count.wrapping_shr(shift) as u8;
        let ordinal_byte = ordinal.rotate_left(17).wrapping_shr(shift) as u8;
        (class.code() as u8)
            .wrapping_mul(0x31)
            .wrapping_add(byte_index as u8)
            ^ item_byte
            ^ ordinal_byte
    })
}

fn validate_fixture(fixture: &EvidenceFixture) -> ValidatedMdocPreparation {
    validate_mdoc_preparation(
        SigningAlgorithm::ES256,
        &fixture.claims,
        Some(&fixture.holder_public_jwk),
    )
    .expect("stage-evidence fixture must validate")
}

fn plan_claims(
    fixture: &EvidenceFixture,
    issuer_claims: Vec<ValidatedMdocClaim>,
) -> MdocDigestPlan {
    let mut ordinal = 0usize;
    let plan = plan_validated_mdoc_digests(SINGLE_MDOC_DIGEST_CREDENTIAL_ID, issuer_claims, || {
        let next = salt(fixture.class, fixture.item_count, ordinal);
        ordinal += 1;
        next
    })
    .expect("stage-evidence digest plan must succeed");
    assert_eq!(ordinal, fixture.item_count, "salt source call count");
    plan
}

fn plan_fixture(fixture: &EvidenceFixture) -> MdocDigestPlan {
    let mut preparation = validate_fixture(fixture);
    let issuer_claims = std::mem::take(&mut preparation.issuer_claims);
    plan_claims(fixture, issuer_claims)
}

fn final_inputs(
    fixture: &EvidenceFixture,
) -> (
    ValidatedMdocPreparation,
    String,
    chrono::DateTime<Utc>,
    MdocDigestAssembly,
) {
    let mut preparation = validate_fixture(fixture);
    let valid_until = checked_mdoc_valid_until(fixture.now, preparation.validity_duration)
        .expect("stage-evidence validity must be in range");
    let issuer_claims = std::mem::take(&mut preparation.issuer_claims);
    let plan = plan_claims(fixture, issuer_claims);
    let results = execute_mdoc_digest_plan(&plan, &SerialDigestExecutor)
        .expect("stage-evidence serial digest must succeed");
    let assembly = assemble_mdoc_digest_plan(plan, results)
        .expect("stage-evidence digest restoration must succeed");
    (
        preparation,
        fixture.credential_id.clone(),
        valid_until,
        assembly,
    )
}

fn map_value<'a>(entries: &'a [(CborValue, CborValue)], name: &str) -> &'a CborValue {
    entries
        .iter()
        .find_map(|(key, value)| (key == &CborValue::Text(name.to_owned())).then_some(value))
        .unwrap_or_else(|| panic!("{name} must be present"))
}

fn assert_validated_fixture(fixture: &EvidenceFixture, preparation: &ValidatedMdocPreparation) {
    assert_eq!(preparation.doc_type, DOC_TYPE);
    assert_eq!(preparation.namespace, NAMESPACE);
    assert!(preparation.x5chain_der.is_empty());
    assert!(preparation.device_key.is_some());
    assert_eq!(preparation.cose_algorithm, iana::Algorithm::ES256);
    assert_eq!(preparation.validity_duration, chrono::TimeDelta::days(365));
    assert_eq!(preparation.issuer_claims.len(), fixture.item_count);

    let mut seen = HashSet::with_capacity(fixture.item_count);
    for claim in &preparation.issuer_claims {
        let index = claim_index(&claim.element_identifier, fixture.item_count);
        assert!(
            seen.insert(index),
            "converted claim identifiers must be unique"
        );
        assert_eq!(
            claim.element_value,
            expected_cbor_value(fixture.class, index),
            "converted semantic claim value"
        );
    }
    assert_eq!(seen.len(), fixture.item_count);
}

fn assert_plan(fixture: &EvidenceFixture, plan: &MdocDigestPlan) {
    assert_eq!(plan.entries.len(), fixture.item_count);
    assert_eq!(plan.jobs.len(), fixture.item_count);
    for (ordinal, (entry, job)) in plan.entries.iter().zip(&plan.jobs).enumerate() {
        let digest_id = u64::try_from(ordinal).unwrap();
        assert_eq!(entry.credential_id, SINGLE_MDOC_DIGEST_CREDENTIAL_ID);
        assert_eq!(entry.job_id, digest_id);
        assert_eq!(entry.ordinal, ordinal);
        assert_eq!(entry.digest_id, digest_id);
        assert_eq!(job.credential_id, SINGLE_MDOC_DIGEST_CREDENTIAL_ID);
        assert_eq!(job.job_id, digest_id);
        assert_eq!(job.ordinal, ordinal);
        assert!(matches!(job.algorithm, DigestAlgorithm::SHA256));
        assert_eq!(
            job.input,
            cbor_encode(&entry.issuer_signed_item_bytes)
                .expect("tagged stage-evidence item must encode")
        );

        let CborValue::Tag(CBOR_TAG_ENCODED_CBOR, encoded_item) = &entry.issuer_signed_item_bytes
        else {
            panic!("planned IssuerSignedItemBytes must use tag 24")
        };
        let CborValue::Bytes(encoded_item) = encoded_item.as_ref() else {
            panic!("planned tag 24 must wrap encoded bytes")
        };
        let CborValue::Map(item) = ciborium::from_reader::<CborValue, _>(&encoded_item[..])
            .expect("planned IssuerSignedItem must decode")
        else {
            panic!("planned IssuerSignedItem must be a map")
        };
        assert_eq!(
            map_value(&item, "digestID"),
            &CborValue::Integer(digest_id.into())
        );
        assert_eq!(
            map_value(&item, "random"),
            &CborValue::Bytes(salt(fixture.class, fixture.item_count, ordinal).to_vec())
        );
        let CborValue::Text(identifier) = map_value(&item, "elementIdentifier") else {
            panic!("elementIdentifier must be text")
        };
        let claim_index = claim_index(identifier, fixture.item_count);
        assert_eq!(
            map_value(&item, "elementValue"),
            &expected_cbor_value(fixture.class, claim_index)
        );
    }
}

fn assert_digest_results(plan: &MdocDigestPlan, results: &[DigestResult]) {
    assert_eq!(results.len(), plan.jobs.len());
    for (job, result) in plan.jobs.iter().zip(results) {
        assert_eq!(result.credential_id, job.credential_id);
        assert_eq!(result.job_id, job.job_id);
        assert_eq!(result.ordinal, job.ordinal);
        assert_eq!(result.digest, Sha256::digest(&job.input).to_vec());
    }
}

fn assert_assembly(plan: &MdocDigestPlan, results: &[DigestResult], assembly: &MdocDigestAssembly) {
    assert_eq!(assembly.issuer_signed_items.len(), plan.entries.len());
    assert_eq!(assembly.value_digests.len(), plan.entries.len());
    for (((entry, result), item), (digest_id, digest)) in plan
        .entries
        .iter()
        .zip(results)
        .zip(&assembly.issuer_signed_items)
        .zip(&assembly.value_digests)
    {
        assert_eq!(item, &entry.issuer_signed_item_bytes);
        assert_eq!(*digest_id, entry.digest_id);
        assert_eq!(digest, &result.digest);
    }
}

fn assert_prepared_fixture(
    fixture: &EvidenceFixture,
    plan: &MdocDigestPlan,
    results: &[DigestResult],
    prepared: &PreparedMdoc,
) {
    assert_eq!(prepared.credential_id, fixture.credential_id);
    assert_eq!(prepared.namespace, NAMESPACE);
    assert_eq!(prepared.issuer_signed_items.len(), fixture.item_count);
    for (item, entry) in prepared.issuer_signed_items.iter().zip(&plan.entries) {
        assert_eq!(item, &entry.issuer_signed_item_bytes);
    }

    let CborValue::Tag(CBOR_TAG_ENCODED_CBOR, encoded_mso) =
        ciborium::from_reader::<CborValue, _>(&prepared.mobile_security_object_bytes[..])
            .expect("MobileSecurityObjectBytes must decode")
    else {
        panic!("MobileSecurityObjectBytes must use tag 24")
    };
    let CborValue::Bytes(encoded_mso) = encoded_mso.as_ref() else {
        panic!("MobileSecurityObjectBytes tag 24 must wrap bytes")
    };
    let CborValue::Map(mso) = ciborium::from_reader::<CborValue, _>(&encoded_mso[..])
        .expect("MobileSecurityObject must decode")
    else {
        panic!("MobileSecurityObject must be a map")
    };
    assert_eq!(
        map_value(&mso, "docType"),
        &CborValue::Text(DOC_TYPE.into())
    );
    assert_eq!(
        map_value(&mso, "digestAlgorithm"),
        &CborValue::Text("SHA-256".into())
    );
    let CborValue::Map(value_digests) = map_value(&mso, "valueDigests") else {
        panic!("valueDigests must be a map")
    };
    let CborValue::Map(namespace_digests) = value_digests
        .iter()
        .find_map(|(key, value)| (key == &CborValue::Text(NAMESPACE.into())).then_some(value))
        .expect("stage-evidence namespace digest map must be present")
    else {
        panic!("namespace valueDigests must be a map")
    };
    assert_eq!(namespace_digests.len(), fixture.item_count);
    for (entry, result) in plan.entries.iter().zip(results) {
        assert_eq!(
            namespace_digests
                .iter()
                .find_map(|(key, value)| {
                    (key == &CborValue::Integer(entry.digest_id.into())).then_some(value)
                })
                .expect("each planned digest ID must be in the MSO"),
            &CborValue::Bytes(result.digest.clone())
        );
    }

    let mut salt_ordinal = 0usize;
    let replay = prepare_mdoc_with_inputs(
        &EvidenceSigner,
        &fixture.claims,
        fixture.credential_id.clone(),
        Some(&fixture.holder_public_jwk),
        fixture.now,
        fixture
            .claims
            .claims
            .iter()
            .map(|(name, value)| (name.as_str(), value)),
        || {
            let next = salt(fixture.class, fixture.item_count, salt_ordinal);
            salt_ordinal += 1;
            next
        },
    )
    .expect("production scalar replay must prepare");
    assert_eq!(salt_ordinal, fixture.item_count);
    assert_eq!(prepared.tbs_data, replay.tbs_data);
    assert_eq!(prepared.credential_id, replay.credential_id);
    assert_eq!(prepared.protected_header, replay.protected_header);
    assert_eq!(prepared.unprotected_header, replay.unprotected_header);
    assert_eq!(
        prepared.mobile_security_object_bytes,
        replay.mobile_security_object_bytes
    );
    assert_eq!(prepared.namespace, replay.namespace);
    assert_eq!(prepared.issuer_signed_items, replay.issuer_signed_items);
}

fn preflight(fixture: &EvidenceFixture) {
    let mut preparation = validate_fixture(fixture);
    assert_validated_fixture(fixture, &preparation);

    let valid_until = checked_mdoc_valid_until(fixture.now, preparation.validity_duration)
        .expect("stage-evidence validity must be in range");
    let issuer_claims = std::mem::take(&mut preparation.issuer_claims);
    let plan = plan_claims(fixture, issuer_claims);
    assert_plan(fixture, &plan);
    let results = execute_mdoc_digest_plan(&plan, &SerialDigestExecutor)
        .expect("stage-evidence serial digest must succeed");
    assert_digest_results(&plan, &results);
    let assembly = assemble_mdoc_digest_plan(plan.clone(), results.clone())
        .expect("stage-evidence digest restoration must succeed");
    assert_assembly(&plan, &results, &assembly);

    let prepared = finish_mdoc_preparation(
        preparation,
        fixture.credential_id.clone(),
        fixture.now,
        valid_until,
        assembly,
    )
    .expect("stage-evidence final preparation must succeed");
    assert_prepared_fixture(fixture, &plan, &results, &prepared);
}

fn measure_fixture(criterion: &mut Criterion, fixture: &EvidenceFixture) {
    preflight(fixture);
    let mut group = criterion.benchmark_group(format!(
        "{EVIDENCE_GROUP}/{}/n={}",
        fixture.class.label(),
        fixture.item_count
    ));
    group.throughput(Throughput::Elements(
        u64::try_from(fixture.item_count).unwrap(),
    ));

    group.bench_function("validate_convert", |bencher| {
        bencher.iter_batched(
            || (),
            |()| {
                black_box(
                    validate_mdoc_preparation(
                        SigningAlgorithm::ES256,
                        black_box(&fixture.claims),
                        Some(black_box(&fixture.holder_public_jwk)),
                    )
                    .expect("stage-evidence fixture must validate"),
                )
            },
            BatchSize::PerIteration,
        );
    });

    group.bench_function("salt_encode_plan", |bencher| {
        bencher.iter_batched(
            || {
                let mut preparation = validate_fixture(fixture);
                std::mem::take(&mut preparation.issuer_claims)
            },
            |issuer_claims| {
                let mut ordinal = 0usize;
                black_box(
                    plan_validated_mdoc_digests(
                        SINGLE_MDOC_DIGEST_CREDENTIAL_ID,
                        issuer_claims,
                        || {
                            let next = salt(fixture.class, fixture.item_count, ordinal);
                            ordinal += 1;
                            next
                        },
                    )
                    .expect("stage-evidence digest plan must succeed"),
                )
            },
            BatchSize::PerIteration,
        );
    });

    let digest_plan = plan_fixture(fixture);
    group.bench_function("sha256_digest_serial", |bencher| {
        bencher.iter_batched(
            || (),
            |()| {
                black_box(
                    execute_mdoc_digest_plan(black_box(&digest_plan), &SerialDigestExecutor)
                        .expect("stage-evidence serial digest must succeed"),
                )
            },
            BatchSize::PerIteration,
        );
    });

    let digest_results = execute_mdoc_digest_plan(&digest_plan, &SerialDigestExecutor)
        .expect("stage-evidence serial digest must succeed");
    group.bench_function("restore_digest_results", |bencher| {
        bencher.iter_batched(
            || (digest_plan.clone(), digest_results.clone()),
            |(plan, results)| {
                black_box(
                    assemble_mdoc_digest_plan(plan, results)
                        .expect("stage-evidence digest restoration must succeed"),
                )
            },
            BatchSize::PerIteration,
        );
    });

    group.bench_function("mso_and_tbs", |bencher| {
        bencher.iter_batched(
            || final_inputs(fixture),
            |(preparation, credential_id, valid_until, assembly)| {
                black_box(
                    finish_mdoc_preparation(
                        preparation,
                        credential_id,
                        fixture.now,
                        valid_until,
                        assembly,
                    )
                    .expect("stage-evidence final preparation must succeed"),
                )
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

#[test]
#[ignore = "opt-in release-profile evidence; see benches/README.md"]
fn collect_mdoc_stage_evidence() {
    if cfg!(debug_assertions) {
        panic!("mdoc stage evidence must be collected with cargo test --release");
    }
    require_evidence_enable();

    // Parse and reject the complete selection before allocating any fixture.
    let selection = EvidenceSelection::from_env();
    let mut criterion = Criterion::default()
        .without_plots()
        .sample_size(EVIDENCE_SAMPLE_SIZE)
        .warm_up_time(EVIDENCE_WARM_UP)
        .measurement_time(EVIDENCE_MEASUREMENT);
    for class in selection.classes {
        for &item_count in &selection.item_counts {
            measure_fixture(&mut criterion, &fixture(class, item_count));
        }
    }
    criterion.final_summary();
}
