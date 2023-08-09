use criterion::{criterion_group, criterion_main};

mod merkle;
mod crypto;

criterion_group!(benches, merkle::map, crypto::sigs);
criterion_main!(benches);