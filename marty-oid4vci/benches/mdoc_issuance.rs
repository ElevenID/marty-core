use std::{
    collections::{HashMap, HashSet},
    hint::black_box,
    time::Duration,
};

use base64::Engine;
use ciborium::Value as CborValue;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use marty_oid4vci::{
    formats::mdoc::assemble_mdoc,
    remote_credential::{prepare_remote_mdoc, RemoteMdocRequest},
    types::SignedCredential,
};
use sha2::{Digest, Sha256};

const CBOR_TAG_ENCODED_CBOR: u64 = 24;
const CREDENTIAL_ID: &str = "urn:uuid:961d492d-ffb7-59f9-b2cf-66a84c47d07c";
const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
const NAMESPACE: &str = "org.iso.18013.5.1";
const ITEM_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];

fn fixture(item_count: usize) -> RemoteMdocRequest {
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
        credential_id: Some(CREDENTIAL_ID.into()),
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
    use isomdl::definitions::IssuerSigned;

    let prepared = prepare_remote_mdoc(request.clone()).expect("fixture must prepare");
    assert_eq!(prepared.credential_id, CREDENTIAL_ID);
    let credential = assemble_mdoc(prepared, &[0xa5; 64]).expect("fixture must assemble");
    let SignedCredential::MsoMdoc {
        issuer_signed_b64,
        credential_id,
    } = credential
    else {
        panic!("fixture must produce mso_mdoc");
    };
    assert_eq!(credential_id, CREDENTIAL_ID);

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

criterion_group!(benches, benchmark_mdoc_issuance);
criterion_main!(benches);
