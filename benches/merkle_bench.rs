use blst::BLST_ERROR;
use ed25519_dalek::{Verifier, Signer};
use tammany::{merkle::MerkleMap, state::{self, Keypair, State, Signed, Txn, AccountData}};

use criterion::{criterion_group, criterion_main, Criterion};
use sha2::{Sha256, Digest};

fn merkle_map(crit: &mut Criterion) {
    let mut node_copy: tammany::merkletmp::MerkleMap<usize> = tammany::merkletmp::MerkleMap::default();
    crit.bench_function("merkle map copy insert 10k", |b| b.iter(|| {
        for i in 1usize..10_000 {
            node_copy.insert(&i.to_be_bytes(), i);
        }
    }));

    crit.bench_function("merkle map copy get 10k", |b| b.iter(|| {
        for i in 1usize..10_000 {
            node_copy.get(&i.to_be_bytes());
        }
    }));

    crit.bench_function("merkle map copy iter 10k", |b| b.iter(|| {
        let mut sum = 0;
        for val in node_copy.iter() {
            sum += val;
        }
    }));

    crit.bench_function("merkle map copy search 10k", |b| b.iter(|| {
        let mut sum = 0;
        for i in 1usize..10_000 {
            if let Some(_) = node_copy.search(|k, _| match k.last() {
                Some(x) => x % 16 == (i & 0xff) as u8,
                None => true
            }) {
                sum += 1;
            }
        }
    }));

    crit.bench_function("merkle map copy remove 10k", |b| b.iter(|| {
        for i in 1usize..10_000 {
            node_copy.remove(&i.to_be_bytes());
        }
    }));

    let mut node: MerkleMap<Sha256, usize> = MerkleMap::default();
    crit.bench_function("merkle map insert 10k", |b| b.iter(|| {
        for i in 1usize..10_000 {
            node.insert(&i.to_be_bytes(), i);
        }
        node.commit();
    }));

    crit.bench_function("merkle map get 10k", |b| b.iter(|| {
        for i in 1usize..10_000 {
            node.get(&i.to_be_bytes());
        }
    }));

    crit.bench_function("merkle map iter 10k", |b| b.iter(|| {
        let mut sum = 0;
        for val in node.iter() {
            sum += val;
        }
    }));

    crit.bench_function("merkle map search 10k", |b| b.iter(|| {
        let mut sum = 0;
        for i in 1usize..10_000 {
            if let Some(_) = node.search(|k, _| match k.last() {
                Some(x) => x % 16 == (i & 0xff) as u8,
                None => true
            }) {
                sum += 1;
            }
        }
    }));

    crit.bench_function("merkle map remove 10k", |b| b.iter(|| {
        for i in 1usize..10_000 {
            node.remove(&i.to_be_bytes());
        }
        node.commit();
    }));
    let alice = Keypair::gen();
    let mut state = State {
        accounts: tammany::merkletmp::MerkleMap::default(),
        validators: tammany::merkletmp::MerkleMap::default(),
        round: 0,
        seed: [0u8; 32]
    };
    state.accounts.insert(
        &Sha256::digest(alice.kp.public.to_bytes()),
        AccountData { bal: 1 << 17, nonce: 0 }
    );
    let bob = Keypair::gen();
    crit.bench_function("state payment", |b| b.iter(|| {
        let mut state = state.clone();
        assert!(state.apply(&alice.send(bob.kp.public, 1, &state)).is_ok());
    }));
}

fn sigs(crit: &mut Criterion) {
    let alice = Keypair::gen();
    let sig = alice.kp.sign(b"message");
    crit.bench_function("eddsa sign", |b| b.iter(|| {
        let _ = alice.kp.sign(b"message");
    }));
    crit.bench_function("eddsa verify", |b| b.iter(|| {
        assert!(alice.kp.public.verify(b"message", &sig).is_ok());
    }));
    let alice = tammany::state::Validator::Keypair::gen();
    let sig = alice.sk.sign(b"message", &[], &[]);
    crit.bench_function("bls sign", |b| b.iter(|| {
        let _ = alice.sk.sign(b"message", &[], &[]);
    }));
    crit.bench_function("bls verify", |b| b.iter(|| {
        assert_eq!(sig.verify(true, b"message", &[], &[], &alice.pk, true), BLST_ERROR::BLST_SUCCESS);
    }));
}

criterion_group!(benches, merkle_map, sigs);
criterion_main!(benches);