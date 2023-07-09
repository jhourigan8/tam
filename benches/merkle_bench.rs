use blst::BLST_ERROR;
use ed25519_dalek::{Signer, Verifier};
use tammany::*;

use criterion::{criterion_group, criterion_main, Criterion};
use sha2::{Sha256, Digest};

fn merkle_map(crit: &mut Criterion) {
    let mut node_copy: merkle::Map<usize> = merkle::Map::default();
    crit.bench_function("merkle map copy insert 10k", |b| b.iter(|| {
        for i in 1usize..10_000 {
            node_copy.insert(&i.to_be_bytes(), i);
        }
    }));

    crit.bench_function("merkle map get 10k", |b| b.iter(|| {
        for i in 1usize..10_000 {
            node_copy.get(&i.to_be_bytes());
        }
    }));

    crit.bench_function("merkle map iter 10k", |b| b.iter(|| {
        let mut sum = 0;
        for val in node_copy.iter() {
            sum += val;
        }
    }));

    crit.bench_function("merkle map remove 10k", |b| b.iter(|| {
        for i in 1usize..10_000 {
            node_copy.remove(&i.to_be_bytes());
        }
    }));

    let (alice, snap) = <(account::Keypair, block::Snap)>::default();
    let mut builder = block::Builder::new(&alice, 1, &snap);
    let bob = account::Keypair::gen();
    crit.bench_function("state payment", |b| b.iter(|| {
        assert!(builder.add(alice.send(bob.kp.public, 1, &builder.state)).is_ok());
    }));
}

fn sigs(crit: &mut Criterion) {
    let alice = account::Keypair::gen();
    let sig = alice.kp.sign(b"message");
    crit.bench_function("eddsa sign", |b| b.iter(|| {
        let _ = alice.kp.sign(b"message");
    }));
    crit.bench_function("eddsa verify", |b| b.iter(|| {
        assert!(alice.kp.public.verify(b"message", &sig).is_ok());
    }));
}

criterion_group!(benches, merkle_map, sigs);
criterion_main!(benches);