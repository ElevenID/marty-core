use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use marty_status::{BitstringStatusList, TokenStatusList, W3C_MIN_STATUS_LIST_BITS};

fn benchmark_status_lists(c: &mut Criterion) {
    let mut group = c.benchmark_group("status_lists");

    let token = TokenStatusList::new(W3C_MIN_STATUS_LIST_BITS, 2).unwrap();
    let token_encoded = token.to_base64url().unwrap();
    group.throughput(Throughput::Elements(W3C_MIN_STATUS_LIST_BITS as u64));
    group.bench_function("token_encode_131072", |b| {
        b.iter(|| token.to_base64url().unwrap())
    });
    group.bench_function("token_decode_131072", |b| {
        b.iter(|| {
            TokenStatusList::from_base64url(&token_encoded, W3C_MIN_STATUS_LIST_BITS, 2).unwrap()
        })
    });

    let bitstring = BitstringStatusList::new(W3C_MIN_STATUS_LIST_BITS).unwrap();
    let bitstring_encoded = bitstring.to_base64url().unwrap();
    group.bench_function("bitstring_encode_131072", |b| {
        b.iter(|| bitstring.to_base64url().unwrap())
    });
    group.bench_function("bitstring_decode_131072", |b| {
        b.iter(|| {
            BitstringStatusList::from_base64url(&bitstring_encoded, W3C_MIN_STATUS_LIST_BITS)
                .unwrap()
        })
    });

    group.bench_function("bitstring_mutate_131072", |b| {
        b.iter_batched(
            || BitstringStatusList::new(W3C_MIN_STATUS_LIST_BITS).unwrap(),
            |mut list| {
                list.revoke(W3C_MIN_STATUS_LIST_BITS / 2).unwrap();
                list
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, benchmark_status_lists);
criterion_main!(benches);
