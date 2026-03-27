use criterion::{black_box, criterion_group, criterion_main, Criterion};
use slh_dsa::hash::ShakeHash;
use slh_dsa::params::Shake_128f;
use slh_dsa::slhdsa::{keygen, sign, verify};
use rand::rngs::OsRng;

// ---------------------------------------------------------------------------
// SLH-DSA-SHAKE-128f benchmarks (fastest parameter set)
// ---------------------------------------------------------------------------

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh-dsa-keygen");
    group.sample_size(10); // SLH-DSA keygen is slow; reduce sample count
    group.bench_function("SLH-DSA-SHAKE-128f", |b| {
        b.iter(|| keygen::<Shake_128f, ShakeHash>(black_box(&mut OsRng)))
    });
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let msg = b"PQC benchmark message for SLH-DSA signing";

    let mut group = c.benchmark_group("slh-dsa-sign");
    group.sample_size(10);

    let (sk, _pk) = keygen::<Shake_128f, ShakeHash>(&mut OsRng);
    group.bench_function("SLH-DSA-SHAKE-128f", |b| {
        b.iter(|| sign::<Shake_128f, ShakeHash>(black_box(&sk), black_box(msg)))
    });

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let msg = b"PQC benchmark message for SLH-DSA verification";

    let mut group = c.benchmark_group("slh-dsa-verify");
    group.sample_size(10);

    let (sk, pk) = keygen::<Shake_128f, ShakeHash>(&mut OsRng);
    let sig = sign::<Shake_128f, ShakeHash>(&sk, msg);
    group.bench_function("SLH-DSA-SHAKE-128f", |b| {
        b.iter(|| verify::<Shake_128f, ShakeHash>(black_box(&pk), black_box(msg), black_box(&sig)))
    });

    group.finish();
}

criterion_group!(benches, bench_keygen, bench_sign, bench_verify);
criterion_main!(benches);
