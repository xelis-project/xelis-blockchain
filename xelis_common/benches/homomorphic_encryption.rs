use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::Scalar;
use xelis_common::crypto::KeyPair;

// Current Homomorphic Encryption operations used by XELIS network
// Those are based on the Twisted elGamal encryption scheme. 
fn bench_he_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("he_operations");

    let keypair = KeyPair::new();
    let amount = 100u64;
    let scalar = Scalar::from(50u64);

    // Generate the ciphertexts
    let ct1 = keypair.get_public_key().encrypt(amount);
    let ct2 = keypair.get_public_key().encrypt(scalar);

    group.bench_function("add", |b| {
        b.iter(|| {
            let _result = black_box(ct1.clone() + ct2.clone());
        })
    });

    group.bench_function("add scalar", |b| {
        b.iter(|| {
            let _result = black_box(ct1.clone() - scalar);
        })
    });

    group.bench_function("sub", |b| {
        b.iter(|| {
            let _result = black_box(ct1.clone() - ct2.clone());
        })
    });

    group.bench_function("sub scalar", |b| {
        b.iter(|| {
            let _result = black_box(ct1.clone() - scalar);
        })
    });

    group.finish();
}


criterion_group!(
    he_benches,
    bench_he_operations
);
criterion_main!(he_benches);