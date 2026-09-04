use std::{
    collections::{HashMap, HashSet},
    hint::black_box,
    time::Duration,
};

use base64::Engine;
use ciborium::Value as CborValue;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use marty_oid4vci::{
    formats::mdoc::{assemble_mdoc, PreparedMdoc},
    remote_credential::{
        prepare_remote_mdoc, prepare_remote_mdoc_batch, RemoteMdocBatchItem, RemoteMdocRequest,
    },
    types::SignedCredential,
};
use sha2::{Digest, Sha256};

const CBOR_TAG_ENCODED_CBOR: u64 = 24;
const CREDENTIAL_ID: &str = "urn:uuid:961d492d-ffb7-59f9-b2cf-66a84c47d07c";
const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
const NAMESPACE: &str = "org.iso.18013.5.1";
const ITEM_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];
const BATCH_SIZES: [usize; 4] = [1, 8, 32, 256];
const BATCH_ITEM_COUNT: usize = 8;
const MATRIX_ENABLE_ENV: &str = "MARTY_MDOC_MATRIX";
const MATRIX_CLASSES_ENV: &str = "MARTY_MDOC_MATRIX_CLASSES";
const MATRIX_ITEM_COUNTS_ENV: &str = "MARTY_MDOC_MATRIX_ITEM_COUNTS";
const MATRIX_BATCH_SIZES_ENV: &str = "MARTY_MDOC_MATRIX_BATCH_SIZES";
const MATRIX_GROUP: &str = "mdoc_issuance_payload_matrix";
const LARGE_PORTRAIT_BYTES: usize = 256 * 1024;
const MIXED_MEDIUM_BYTES: usize = 1024;
const MIXED_LARGE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MatrixPayloadClass {
    SmallPrimitive,
    MediumNested,
    LargePortrait,
    MixedSize,
}

impl MatrixPayloadClass {
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

#[derive(Debug, Eq, PartialEq)]
struct MatrixSelection {
    classes: Vec<MatrixPayloadClass>,
    item_counts: Vec<usize>,
    batch_sizes: Vec<usize>,
}

impl MatrixSelection {
    fn from_env() -> Self {
        Self {
            classes: parse_named_selector(
                MATRIX_CLASSES_ENV,
                &MatrixPayloadClass::ALL,
                MatrixPayloadClass::label,
                MatrixPayloadClass::parse,
            ),
            item_counts: parse_numeric_selector(MATRIX_ITEM_COUNTS_ENV, &ITEM_COUNTS),
            batch_sizes: parse_numeric_selector(MATRIX_BATCH_SIZES_ENV, &BATCH_SIZES),
        }
    }
}

fn matrix_enabled() -> bool {
    match std::env::var(MATRIX_ENABLE_ENV) {
        Ok(value) => value == "1",
        Err(std::env::VarError::NotPresent) => false,
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("{MATRIX_ENABLE_ENV} must contain Unicode text")
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

fn fixture(item_count: usize) -> RemoteMdocRequest {
    fixture_with_credential_id(item_count, CREDENTIAL_ID)
}

fn fixture_with_credential_id(item_count: usize, credential_id: &str) -> RemoteMdocRequest {
    let claims = (0..item_count)
        .map(|index| {
            let name = format!("element_{index:04}");
            let value = format!("{index:04}{}", "v".repeat(252));
            assert_eq!(value.len(), 256);
            (name, serde_json::Value::String(value))
        })
        .collect::<HashMap<_, _>>();

    RemoteMdocRequest {
        issuer_id: "did:example:issuer".into(),
        algorithm: "ES256".into(),
        credential_type: DOC_TYPE.into(),
        namespace: NAMESPACE.into(),
        claims,
        expiration_seconds: Some(365 * 86_400),
        credential_id: Some(credential_id.into()),
        holder_jwk: Some(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        })),
    }
}

fn map_value<'a>(entries: &'a [(CborValue, CborValue)], name: &str) -> &'a CborValue {
    entries
        .iter()
        .find_map(|(key, value)| (key == &CborValue::Text(name.to_owned())).then_some(value))
        .unwrap_or_else(|| panic!("{name} must be present"))
}

fn preflight(request: &RemoteMdocRequest, item_count: usize) {
    let prepared = prepare_remote_mdoc(request.clone()).expect("fixture must prepare");
    assert_prepared(request, item_count, CREDENTIAL_ID, prepared);
}

fn assert_prepared(
    request: &RemoteMdocRequest,
    item_count: usize,
    credential_id: &str,
    prepared: PreparedMdoc,
) {
    use isomdl::definitions::IssuerSigned;

    assert_eq!(prepared.credential_id, credential_id);
    let credential = assemble_mdoc(prepared, &[0xa5; 64]).expect("fixture must assemble");
    let SignedCredential::MsoMdoc {
        issuer_signed_b64,
        credential_id,
    } = credential
    else {
        panic!("fixture must produce mso_mdoc");
    };
    assert_eq!(credential_id, request.credential_id.as_deref().unwrap());

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(issuer_signed_b64)
        .expect("IssuerSigned must be base64url");
    let issuer_signed: IssuerSigned =
        isomdl::cbor::from_slice(&bytes).expect("IssuerSigned must decode");
    let namespaces = issuer_signed
        .namespaces
        .as_ref()
        .expect("nameSpaces present");
    assert_eq!(namespaces.len(), 1);
    let items = namespaces
        .get(NAMESPACE)
        .expect("fixture namespace present");
    assert_eq!(items.len(), item_count);

    let wrapped_mso: CborValue = isomdl::cbor::from_slice(
        issuer_signed
            .issuer_auth
            .payload
            .as_ref()
            .expect("issuerAuth payload present"),
    )
    .expect("MobileSecurityObjectBytes must decode");
    let CborValue::Tag(CBOR_TAG_ENCODED_CBOR, encoded_mso) = wrapped_mso else {
        panic!("issuerAuth payload must be tag 24");
    };
    let CborValue::Bytes(encoded_mso) = *encoded_mso else {
        panic!("MobileSecurityObjectBytes must wrap bytes");
    };
    let CborValue::Map(mso) = isomdl::cbor::from_slice(&encoded_mso).expect("MSO must decode")
    else {
        panic!("MSO must be a map");
    };
    assert_eq!(
        map_value(&mso, "digestAlgorithm"),
        &CborValue::Text("SHA-256".into())
    );
    let CborValue::Map(value_digests) = map_value(&mso, "valueDigests") else {
        panic!("valueDigests must be a map");
    };
    assert_eq!(value_digests.len(), 1);
    let CborValue::Map(namespace_digests) = value_digests
        .iter()
        .find_map(|(key, value)| (key == &CborValue::Text(NAMESPACE.into())).then_some(value))
        .expect("fixture namespace digests present")
    else {
        panic!("namespace valueDigests must be a map");
    };
    assert_eq!(namespace_digests.len(), item_count);

    let mut seen_identifiers = HashSet::with_capacity(item_count);
    for (expected_id, tagged_item) in items.iter().enumerate() {
        let item = tagged_item.as_ref();
        let digest_id = serde_json::to_value(item.digest_id)
            .expect("digest ID must serialize")
            .as_u64()
            .expect("digest ID must be unsigned");
        assert_eq!(digest_id, expected_id as u64);
        assert!(
            seen_identifiers.insert(item.element_identifier.as_str()),
            "each emitted identifier must be unique"
        );
        let expected_value = request
            .claims
            .get(&item.element_identifier)
            .unwrap_or_else(|| panic!("{} must match an input claim", item.element_identifier));
        let serde_json::Value::String(expected_value) = expected_value else {
            panic!("fixture claims must be strings");
        };
        assert_eq!(
            item.element_value,
            CborValue::Text(expected_value.clone()),
            "{} must preserve its complete input value",
            item.element_identifier
        );
        let CborValue::Bytes(expected_digest) = namespace_digests
            .iter()
            .find_map(|(key, value)| {
                (key == &CborValue::Integer(digest_id.into())).then_some(value)
            })
            .expect("each item must have a valueDigest")
        else {
            panic!("valueDigest must be bytes");
        };
        let encoded_wrapper =
            isomdl::cbor::to_vec(tagged_item).expect("IssuerSignedItemBytes must encode");
        assert_eq!(Sha256::digest(encoded_wrapper).as_slice(), expected_digest);
    }
    assert_eq!(seen_identifiers.len(), request.claims.len());
}

fn batch_fixtures(batch_size: usize) -> (Vec<RemoteMdocRequest>, Vec<RemoteMdocBatchItem>) {
    let requests = (0..batch_size)
        .map(|index| {
            let credential_id = format!("urn:uuid:{index:08x}-0000-4000-8000-{index:012x}");
            fixture_with_credential_id(BATCH_ITEM_COUNT, &credential_id)
        })
        .collect::<Vec<_>>();
    let batch = requests
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, request)| RemoteMdocBatchItem::new(10_000 + index as u64, request))
        .collect();
    (requests, batch)
}

fn preflight_batch(batch_size: usize) {
    let (requests, batch) = batch_fixtures(batch_size);
    let prepared = prepare_remote_mdoc_batch(batch).expect("batch fixture must prepare");
    assert_eq!(prepared.len(), batch_size);
    for (index, (request, prepared)) in requests.into_iter().zip(prepared).enumerate() {
        assert_eq!(prepared.batch_id(), 10_000 + index as u64);
        let credential_id = request.credential_id.clone().unwrap();
        assert_prepared(
            &request,
            BATCH_ITEM_COUNT,
            &credential_id,
            prepared.into_prepared_mdoc(),
        );
    }
}

fn matrix_claim_name(index: usize) -> String {
    format!("benchmark_claim_{index:04}")
}

fn repeated_ascii(length: usize, index: usize) -> String {
    let byte = b'A' + u8::try_from(index % 26).expect("fixture alphabet index must fit u8");
    String::from_utf8(vec![byte; length]).expect("fixture bytes must be ASCII")
}

fn matrix_json_value(class: MatrixPayloadClass, index: usize) -> serde_json::Value {
    match class {
        MatrixPayloadClass::SmallPrimitive => match index % 4 {
            0 => serde_json::json!(index),
            1 => serde_json::json!(index.is_multiple_of(2)),
            2 => serde_json::json!(format!("value-{index:04}")),
            _ => serde_json::Value::Null,
        },
        MatrixPayloadClass::MediumNested => serde_json::json!({
            "group": index % 8,
            "metadata": {
                "enabled": index.is_multiple_of(2),
                "label": format!("nested-{index:04}"),
                "sequence": index
            },
            "values": [index, index + 1, index + 2, index + 3]
        }),
        MatrixPayloadClass::LargePortrait if index == 0 => {
            serde_json::Value::String(repeated_ascii(LARGE_PORTRAIT_BYTES, index))
        }
        MatrixPayloadClass::LargePortrait => serde_json::Value::String(format!("value-{index:04}")),
        MatrixPayloadClass::MixedSize => match index % 4 {
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

fn matrix_expected_cbor_value(class: MatrixPayloadClass, index: usize) -> CborValue {
    match class {
        MatrixPayloadClass::SmallPrimitive => match index % 4 {
            0 => cbor_integer(index),
            1 => CborValue::Bool(index.is_multiple_of(2)),
            2 => CborValue::Text(format!("value-{index:04}")),
            _ => CborValue::Null,
        },
        MatrixPayloadClass::MediumNested => CborValue::Map(vec![
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
        MatrixPayloadClass::LargePortrait if index == 0 => {
            CborValue::Text(repeated_ascii(LARGE_PORTRAIT_BYTES, index))
        }
        MatrixPayloadClass::LargePortrait => CborValue::Text(format!("value-{index:04}")),
        MatrixPayloadClass::MixedSize => match index % 4 {
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

fn matrix_credential_id(
    class: MatrixPayloadClass,
    item_count: usize,
    batch_size: usize,
    credential_ordinal: usize,
) -> String {
    assert!(ITEM_COUNTS.contains(&item_count));
    assert!(batch_size == 0 || BATCH_SIZES.contains(&batch_size));
    assert!(credential_ordinal < batch_size.max(1));
    let tail = (class.code() << 40)
        | (u64::try_from(item_count).unwrap() << 24)
        | (u64::try_from(batch_size).unwrap() << 12)
        | u64::try_from(credential_ordinal).unwrap();
    format!(
        "urn:uuid:{:08x}-{item_count:04x}-4{batch_size:03x}-8{credential_ordinal:03x}-{tail:012x}",
        class.code()
    )
}

fn matrix_batch_id(
    class: MatrixPayloadClass,
    item_count: usize,
    batch_size: usize,
    credential_ordinal: usize,
) -> u64 {
    (class.code() << 56)
        | (u64::try_from(item_count).unwrap() << 40)
        | (u64::try_from(batch_size).unwrap() << 24)
        | u64::try_from(credential_ordinal).unwrap()
}

fn matrix_request(
    class: MatrixPayloadClass,
    item_count: usize,
    batch_size: usize,
    credential_ordinal: usize,
) -> RemoteMdocRequest {
    assert!(ITEM_COUNTS.contains(&item_count));
    let claims = (0..item_count)
        .map(|index| (matrix_claim_name(index), matrix_json_value(class, index)))
        .collect::<HashMap<_, _>>();
    if class == MatrixPayloadClass::LargePortrait {
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

    RemoteMdocRequest {
        issuer_id: format!(
            "did:example:matrix-issuer:{}:{item_count}:{batch_size}:{credential_ordinal}",
            class.label()
        ),
        algorithm: "ES256".into(),
        credential_type: DOC_TYPE.into(),
        namespace: NAMESPACE.into(),
        claims,
        expiration_seconds: Some(365 * 86_400),
        credential_id: Some(matrix_credential_id(
            class,
            item_count,
            batch_size,
            credential_ordinal,
        )),
        holder_jwk: Some(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        })),
    }
}

fn matrix_requests(
    class: MatrixPayloadClass,
    item_count: usize,
    batch_size: usize,
) -> Vec<RemoteMdocRequest> {
    (0..batch_size)
        .map(|credential_ordinal| matrix_request(class, item_count, batch_size, credential_ordinal))
        .collect()
}

fn matrix_batch(
    class: MatrixPayloadClass,
    item_count: usize,
    batch_size: usize,
) -> Vec<RemoteMdocBatchItem> {
    matrix_requests(class, item_count, batch_size)
        .into_iter()
        .enumerate()
        .map(|(credential_ordinal, request)| {
            RemoteMdocBatchItem::new(
                matrix_batch_id(class, item_count, batch_size, credential_ordinal),
                request,
            )
        })
        .collect()
}

fn matrix_claim_index(identifier: &str, item_count: usize) -> usize {
    let encoded = identifier
        .strip_prefix("benchmark_claim_")
        .unwrap_or_else(|| panic!("unexpected matrix claim identifier {identifier}"));
    let index = encoded
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("matrix claim identifier must end in an integer"));
    assert_eq!(
        identifier,
        matrix_claim_name(index),
        "matrix claim identifier must be canonical"
    );
    assert!(index < item_count, "matrix claim index must be in range");
    index
}

fn assert_matrix_prepared(
    class: MatrixPayloadClass,
    item_count: usize,
    expected_credential_id: &str,
    prepared: PreparedMdoc,
) {
    use isomdl::definitions::IssuerSigned;

    assert_eq!(prepared.credential_id, expected_credential_id);
    let credential = assemble_mdoc(prepared, &[0xa5; 64]).expect("matrix fixture must assemble");
    let SignedCredential::MsoMdoc {
        issuer_signed_b64,
        credential_id,
    } = credential
    else {
        panic!("matrix fixture must produce mso_mdoc");
    };
    assert_eq!(credential_id, expected_credential_id);

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(issuer_signed_b64)
        .expect("matrix IssuerSigned must be base64url");
    let issuer_signed: IssuerSigned =
        isomdl::cbor::from_slice(&bytes).expect("matrix IssuerSigned must decode");
    let mso_bytes = issuer_signed
        .issuer_auth
        .payload
        .as_ref()
        .expect("matrix issuerAuth payload must be present");
    let namespaces = issuer_signed
        .namespaces
        .as_ref()
        .expect("matrix nameSpaces must be present");
    assert_eq!(namespaces.len(), 1, "matrix fixtures have one namespace");
    let items = namespaces
        .get(NAMESPACE)
        .expect("matrix namespace must be present");
    assert_eq!(items.len(), item_count, "matrix fixtures contain no decoys");

    let CborValue::Tag(CBOR_TAG_ENCODED_CBOR, encoded_mso) =
        isomdl::cbor::from_slice::<CborValue>(mso_bytes)
            .expect("matrix MobileSecurityObjectBytes must decode")
    else {
        panic!("matrix MobileSecurityObjectBytes must use tag 24");
    };
    let CborValue::Bytes(encoded_mso) = *encoded_mso else {
        panic!("matrix MobileSecurityObjectBytes must wrap bytes");
    };
    let CborValue::Map(mso) =
        isomdl::cbor::from_slice::<CborValue>(&encoded_mso).expect("matrix MSO must decode")
    else {
        panic!("matrix MSO must be a map");
    };
    assert_eq!(
        map_value(&mso, "digestAlgorithm"),
        &CborValue::Text("SHA-256".into())
    );
    assert_eq!(
        map_value(&mso, "docType"),
        &CborValue::Text(DOC_TYPE.into())
    );
    let CborValue::Map(value_digests) = map_value(&mso, "valueDigests") else {
        panic!("matrix valueDigests must be a map");
    };
    assert_eq!(value_digests.len(), 1, "matrix MSO has one namespace");
    let CborValue::Map(namespace_digests) = value_digests
        .iter()
        .find_map(|(key, value)| (key == &CborValue::Text(NAMESPACE.into())).then_some(value))
        .expect("matrix namespace digests must be present")
    else {
        panic!("matrix namespace valueDigests must be a map");
    };
    assert_eq!(
        namespace_digests.len(),
        item_count,
        "matrix MSO contains no decoy digests"
    );

    let mut seen_indices = HashSet::with_capacity(item_count);
    for (expected_digest_id, (tagged_item, (digest_key, digest_value))) in
        items.iter().zip(namespace_digests).enumerate()
    {
        let item = tagged_item.as_ref();
        let digest_id = serde_json::to_value(item.digest_id)
            .expect("matrix digest ID must serialize")
            .as_u64()
            .expect("matrix digest ID must be unsigned");
        assert_eq!(digest_id, expected_digest_id as u64);
        assert_eq!(
            digest_key,
            &CborValue::Integer(digest_id.into()),
            "MSO digest order must match IssuerSignedItem order"
        );
        let CborValue::Bytes(expected_digest) = digest_value else {
            panic!("matrix valueDigest must be bytes");
        };
        let encoded_wrapper =
            isomdl::cbor::to_vec(tagged_item).expect("matrix tag-24 item must encode");
        assert_eq!(
            Sha256::digest(encoded_wrapper).as_slice(),
            expected_digest,
            "matrix MSO must commit to the complete tag-24 item"
        );

        let claim_index = matrix_claim_index(&item.element_identifier, item_count);
        assert!(
            seen_indices.insert(claim_index),
            "matrix claim identifiers must be unique"
        );
        assert_eq!(
            item.element_value,
            matrix_expected_cbor_value(class, claim_index),
            "matrix item must preserve its independently constructed CBOR value"
        );
    }
    assert_eq!(seen_indices.len(), item_count);
}

fn assert_unique_matrix_request_ids(requests: &[RemoteMdocRequest]) {
    let mut credential_ids = HashSet::with_capacity(requests.len());
    let mut issuer_ids = HashSet::with_capacity(requests.len());
    for request in requests {
        assert!(
            credential_ids.insert(request.credential_id.as_deref().unwrap()),
            "matrix credential identities must be unique"
        );
        assert!(
            issuer_ids.insert(request.issuer_id.as_str()),
            "matrix issuer identities must be unique"
        );
    }
}

fn preflight_matrix_sequential(class: MatrixPayloadClass, item_count: usize, batch_size: usize) {
    let requests = matrix_requests(class, item_count, batch_size);
    assert_unique_matrix_request_ids(&requests);
    for request in requests {
        let credential_id = request.credential_id.clone().unwrap();
        let prepared = prepare_remote_mdoc(request).expect("matrix scalar fixture must prepare");
        assert_matrix_prepared(class, item_count, &credential_id, prepared);
    }
}

fn preflight_matrix_batch(class: MatrixPayloadClass, item_count: usize, batch_size: usize) {
    let requests = matrix_requests(class, item_count, batch_size);
    assert_unique_matrix_request_ids(&requests);
    let expected = requests
        .iter()
        .enumerate()
        .map(|(credential_ordinal, request)| {
            (
                matrix_batch_id(class, item_count, batch_size, credential_ordinal),
                request.credential_id.clone().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let mut seen_batch_ids = HashSet::with_capacity(batch_size);
    let batch = requests
        .into_iter()
        .zip(&expected)
        .map(|(request, (batch_id, _))| {
            assert!(
                seen_batch_ids.insert(*batch_id),
                "matrix routing identities must be unique"
            );
            RemoteMdocBatchItem::new(*batch_id, request)
        })
        .collect();
    let prepared = prepare_remote_mdoc_batch(batch).expect("matrix batch fixture must prepare");
    assert_eq!(prepared.len(), batch_size);
    for ((expected_batch_id, credential_id), prepared) in expected.into_iter().zip(prepared) {
        assert_eq!(
            prepared.batch_id(),
            expected_batch_id,
            "matrix batch results must preserve caller order and identity"
        );
        assert_matrix_prepared(
            class,
            item_count,
            &credential_id,
            prepared.into_prepared_mdoc(),
        );
    }
}

fn preflight_payload_matrix(selection: &MatrixSelection) {
    for &class in &selection.classes {
        for &item_count in &selection.item_counts {
            let request = matrix_request(class, item_count, 0, 0);
            let credential_id = request.credential_id.clone().unwrap();
            let prepared = prepare_remote_mdoc(request).expect("matrix fixture must prepare");
            assert_matrix_prepared(class, item_count, &credential_id, prepared);

            for &batch_size in &selection.batch_sizes {
                preflight_matrix_sequential(class, item_count, batch_size);
                preflight_matrix_batch(class, item_count, batch_size);
            }
        }
    }
}

fn benchmark_mdoc_issuance(c: &mut Criterion) {
    let mut group = c.benchmark_group("mdoc_issuance_prepare");
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    group.significance_level(0.05);
    group.noise_threshold(0.03);

    for item_count in ITEM_COUNTS {
        let request = fixture(item_count);
        preflight(&request, item_count);
        group.throughput(Throughput::Elements(item_count as u64));
        group.bench_with_input(
            BenchmarkId::new("claims_256b", item_count),
            &request,
            |bencher, request| {
                bencher.iter_batched(
                    || request.clone(),
                    |request| black_box(prepare_remote_mdoc(black_box(request)).unwrap()),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn benchmark_mdoc_batch_issuance(c: &mut Criterion) {
    let mut group = c.benchmark_group("mdoc_issuance_prepare_batch");
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
            BenchmarkId::new("sequential_8_claims_256b", batch_size),
            &requests,
            |bencher, requests| {
                bencher.iter_batched(
                    || requests.clone(),
                    |requests| {
                        black_box(
                            requests
                                .into_iter()
                                .map(prepare_remote_mdoc)
                                .collect::<Result<Vec<_>, _>>()
                                .unwrap(),
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        group.bench_with_input(
            BenchmarkId::new("batch_8_claims_256b", batch_size),
            &batch,
            |bencher, batch| {
                bencher.iter_batched(
                    || batch.clone(),
                    |batch| black_box(prepare_remote_mdoc_batch(black_box(batch)).unwrap()),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn benchmark_mdoc_payload_matrix(c: &mut Criterion, selection: &MatrixSelection) {
    let mut group = c.benchmark_group(MATRIX_GROUP);
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
    group.significance_level(0.05);
    group.noise_threshold(0.05);

    for &class in &selection.classes {
        for &item_count in &selection.item_counts {
            let request = matrix_request(class, item_count, 0, 0);
            group.throughput(Throughput::Elements(item_count as u64));
            group.bench_function(
                format!("{}/n={item_count}/scalar", class.label()),
                |bencher| {
                    bencher.iter_batched(
                        || request.clone(),
                        |request| black_box(prepare_remote_mdoc(black_box(request)).unwrap()),
                        BatchSize::PerIteration,
                    );
                },
            );

            for &batch_size in &selection.batch_sizes {
                group.throughput(Throughput::Elements(batch_size as u64));
                let requests = matrix_requests(class, item_count, batch_size);
                group.bench_with_input(
                    BenchmarkId::new(
                        format!("{}/n={item_count}/sequential", class.label()),
                        format!("b={batch_size}"),
                    ),
                    &requests,
                    |bencher, requests| {
                        bencher.iter_batched(
                            || requests.clone(),
                            |requests| {
                                black_box(
                                    requests
                                        .into_iter()
                                        .map(prepare_remote_mdoc)
                                        .collect::<Result<Vec<_>, _>>()
                                        .unwrap(),
                                )
                            },
                            BatchSize::PerIteration,
                        );
                    },
                );
                drop(requests);

                let batch = matrix_batch(class, item_count, batch_size);
                group.bench_with_input(
                    BenchmarkId::new(
                        format!("{}/n={item_count}/batch", class.label()),
                        format!("b={batch_size}"),
                    ),
                    &batch,
                    |bencher, batch| {
                        bencher.iter_batched(
                            || batch.clone(),
                            |batch| black_box(prepare_remote_mdoc_batch(black_box(batch)).unwrap()),
                            BatchSize::PerIteration,
                        );
                    },
                );
            }
        }
    }
    group.finish();
}

fn benchmark_all_mdoc_issuance(c: &mut Criterion) {
    let matrix_selection = matrix_enabled().then(MatrixSelection::from_env);
    benchmark_mdoc_issuance(c);
    benchmark_mdoc_batch_issuance(c);
    if let Some(selection) = matrix_selection {
        preflight_payload_matrix(&selection);
        benchmark_mdoc_payload_matrix(c, &selection);
    }
}

criterion_group!(benches, benchmark_all_mdoc_issuance);
criterion_main!(benches);
