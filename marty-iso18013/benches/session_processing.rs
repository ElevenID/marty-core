use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use marty_iso18013::session::SessionKeyAgreement;
use marty_iso18013::{DeviceEngagement, Session, SessionConfig};
use std::hint::black_box;

fn benchmark_session_processing(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("create benchmark runtime");
    let peer = SessionKeyAgreement::new().expect("create benchmark peer key");
    let engagement = DeviceEngagement::new_qr().expect("create benchmark engagement");
    let session = runtime
        .block_on(Session::from_engagement(
            &engagement,
            SessionConfig::default(),
        ))
        .expect("create benchmark session");
    runtime
        .block_on(session.establish(&peer.public_key()))
        .expect("establish benchmark session");
    let payload = vec![0x5a; 1024];

    let mut group = c.benchmark_group("iso18013_session");
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function("encrypted_round_trip_1kib", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let ciphertext = session
                    .send_encrypted(black_box(&payload))
                    .await
                    .expect("encrypt benchmark message");
                let plaintext = session
                    .receive_encrypted(black_box(&ciphertext))
                    .await
                    .expect("decrypt benchmark message");
                black_box(plaintext);
            });
        });
    });
    group.finish();
}

criterion_group!(benches, benchmark_session_processing);
criterion_main!(benches);
