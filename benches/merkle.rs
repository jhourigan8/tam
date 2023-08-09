use tammany::*;
use criterion::Criterion;

pub fn map(crit: &mut Criterion) {
    let mut node_copy: merkle::Map<usize> = merkle::Map::default();
    crit.bench_function("merkle map copy insert 10k", |b| b.iter(|| {
        for i in 1usize..10_000 {
            assert!(node_copy.insert(&i.to_be_bytes(), i).is_ok());
        }
    }));

    crit.bench_function("merkle map get 10k", |b| b.iter(|| {
        for i in 1usize..10_000 {
            assert!(node_copy.get(&i.to_be_bytes()).is_ok());
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
            assert!(node_copy.remove(&i.to_be_bytes()).is_ok());
        }
    }));

    let (alice, snap) = <(account::Keypair, block::Snap)>::default();
    let mut builder = block::Builder::new(&alice, 1, &snap);
    let bob = account::Keypair::gen();
    crit.bench_function("state payment", |b| b.iter(|| {
        assert!(builder.add(alice.send(bob.kp.public, 1, &builder.state)).is_ok());
    }));
}