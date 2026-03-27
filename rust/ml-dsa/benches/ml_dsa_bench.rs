use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ml_dsa::dsa::{keygen, sign, verify};
use ml_dsa::params::{MlDsa44, MlDsa65, MlDsa87};
use rand::rngs::OsRng;

// ---------------------------------------------------------------------------
// Key generation benchmarks
// ---------------------------------------------------------------------------

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml-dsa-keygen");
    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| keygen::<MlDsa44>(black_box(&mut OsRng)))
    });
    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| keygen::<MlDsa65>(black_box(&mut OsRng)))
    });
    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| keygen::<MlDsa87>(black_box(&mut OsRng)))
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Signing benchmarks
// ---------------------------------------------------------------------------

fn bench_sign(c: &mut Criterion) {
    let msg = b"PQC benchmark message for ML-DSA signing";

    let mut group = c.benchmark_group("ml-dsa-sign");

    let (_, sk44) = keygen::<MlDsa44>(&mut OsRng);
    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| sign::<MlDsa44>(black_box(&sk44), black_box(msg)))
    });

    let (_, sk65) = keygen::<MlDsa65>(&mut OsRng);
    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| sign::<MlDsa65>(black_box(&sk65), black_box(msg)))
    });

    let (_, sk87) = keygen::<MlDsa87>(&mut OsRng);
    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| sign::<MlDsa87>(black_box(&sk87), black_box(msg)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Verification benchmarks
// ---------------------------------------------------------------------------

fn bench_verify(c: &mut Criterion) {
    let msg = b"PQC benchmark message for ML-DSA verification";

    let mut group = c.benchmark_group("ml-dsa-verify");

    let (pk44, sk44) = keygen::<MlDsa44>(&mut OsRng);
    let sig44 = sign::<MlDsa44>(&sk44, msg);
    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| verify::<MlDsa44>(black_box(&pk44), black_box(msg), black_box(&sig44)))
    });

    let (pk65, sk65) = keygen::<MlDsa65>(&mut OsRng);
    let sig65 = sign::<MlDsa65>(&sk65, msg);
    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| verify::<MlDsa65>(black_box(&pk65), black_box(msg), black_box(&sig65)))
    });

    let (pk87, sk87) = keygen::<MlDsa87>(&mut OsRng);
    let sig87 = sign::<MlDsa87>(&sk87, msg);
    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| verify::<MlDsa87>(black_box(&pk87), black_box(msg), black_box(&sig87)))
    });

    group.finish();
}

criterion_group!(benches, bench_keygen, bench_sign, bench_verify);
criterion_main!(benches);
