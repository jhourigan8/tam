use ed25519_dalek::{Signer, Verifier};
use tammany::*;
use criterion::Criterion;

pub fn sigs(crit: &mut Criterion) {
    let alice = account::Keypair::gen();
    let sig = alice.kp.sign(b"message");
    crit.bench_function("eddsa sign", |b| b.iter(|| {
        let _ = alice.kp.sign(b"message");
    }));
    crit.bench_function("eddsa verify", |b| b.iter(|| {
        assert!(alice.kp.public.verify(b"message", &sig).is_ok());
    }));
}