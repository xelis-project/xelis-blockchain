use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use xelis_common::crypto::{Address, AddressType, KeyPair};

fn bench_address_to_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("address_to_string");

    // Create a normal mainnet address
    let keypair = KeyPair::new();
    let address = Address::new(true, AddressType::Normal, keypair.get_public_key().compress());

    group.bench_function("normal", |b| {
        b.iter(|| {
            black_box(address.to_string());
        })
    });

    group.finish();
}

fn bench_address_from_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("address_from_string");

    // Create a normal mainnet address and convert to string
    let keypair = KeyPair::new();
    let address = Address::new(true, AddressType::Normal, keypair.get_public_key().compress());
    let address_string = address.to_string();

    group.bench_function("normal", |b| {
        b.iter(|| {
            Address::from_string(black_box(&address_string)).expect("Failed to parse address");
        })
    });

    group.finish();
}

fn bench_address_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("address_roundtrip");

    let keypair = KeyPair::new();
    let address = Address::new(true, AddressType::Normal, keypair.get_public_key().compress());

    group.bench_function("to_string_and_from_string", |b| {
        b.iter(|| {
            let address_string = black_box(&address).to_string();
            Address::from_string(black_box(&address_string)).expect("Failed to parse address");
        })
    });

    group.finish();
}

criterion_group!(
    address_benches,
    bench_address_to_string,
    bench_address_from_string,
    bench_address_roundtrip
);
criterion_main!(address_benches);
