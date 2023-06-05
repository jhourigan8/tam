use std::collections::HashMap;
use std::time::Instant;
use blst::min_pk::*;
use blst::BLST_ERROR;
use digest::generic_array::sequence::Split;
use rand::prelude::*;
use sha2::{Sha256, Digest};
use names::Generator;
use either::Either;
use std::mem;
use nibble_vec::*;
use smallvec::Array;
use std::hash::{Hash, Hasher};
use core::array;
use serde::{Serialize, Deserialize};
use ethnum::U256;
use std::fmt::Debug;

pub mod merkle;
pub mod state;
pub mod account;
pub mod validator;
pub mod txn;

/*

const NUM_NODES: usize = 8;
const NUM_ROUNDS: usize = 100;
const LEADER_DELAY: usize = 20;

// ....................................................................

#[derive(Debug, Clone)]
struct Header {
    round: u32,
    timestamp: u64,
    prev_hash: [u8; 32],
    state_hash: [u8; 32],
    txns_hash: [u8; 32],
    seed: Either<Signature, [u8; 32]>,
}

impl Hashable for Header {
    fn add_hash(&self, hasher: &mut Sha256) {
        hasher.update(self.round.to_be_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.state_hash);
        hasher.update(&self.txns_hash);
        match &self.seed {
            Either::Left(sig) => hasher.update(sig.to_bytes()),
            Either::Right(hash) => hasher.update(hash)
        }
    }
}

impl Header {
    fn beacon(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        match &self.seed {
            Either::Left(sig) => hasher.update(sig.to_bytes()),
            Either::Right(hash) => hasher.update(hash)
        }
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone)]
struct Block {
    sheader: Signed<Header>,
    txns: TxnSeq
}

impl Hashable for Block {
    fn add_hash(&self, hasher: &mut Sha256) {
        &self.sheader.add_hash(hasher);
        &self.txns.add_hash(hasher);
    }
}

#[derive(Debug, Clone)]
struct Snapshot {
    header: Header,
    state: State,
    header_hash: [u8; 32],
    beacon: [u8; 32],
    next_leader: PublicKey
}

impl Snapshot {
    fn new(header: Header, state: State) -> Self {
        let beacon = header.beacon();
        Snapshot {
            header_hash: header.hash(),
            next_leader: (ValidatorIter { beacon, state: &state }).next().unwrap(),
            header,
            state,
            beacon,
        }
    }
}

#[derive(Debug, Clone)]
struct Node {
    keypair: KeyPair,
    curr: Snapshot,
}

impl Node {
    fn make_block(&self, txns: TxnSeq) -> Block {
        let mut state_clone = self.curr.state.clone();
        state_clone.apply_seq(&txns);
        let header = Header {
            round: self.curr.header.round + 1,
            timestamp: 0u64,
            prev_hash: self.curr.header_hash,
            state_hash: state_clone.hash(),
            txns_hash: txns.hash(),
            seed: Either::Left(self.keypair.sk.sign(&self.curr.beacon, &[], &[])),
        };
        Block {
            sheader: Signed::new(header, &self.keypair.sk),
            txns
        }
    }

    fn random_txn(&self) -> Signed<Txn> {
        let mut rng = rand::thread_rng();
        let to = self.curr.state.select_validator(rng.gen::<usize>() as f64 / usize::MAX as f64).unwrap();
        let my_acc = self.curr.state.accounts.get(&Sha256::digest(self.keypair.pk.to_bytes()).into()).unwrap();
        let nonce = my_acc.nonce + 1;
        let amount = my_acc.bal / 2;
        let txn = Txn { to, nonce, amount };
        let sig = self.keypair.sk.sign(&txn.hash(), &[], &[]);
        Signed::<Txn> { msg: txn, pk: self.keypair.pk, sig }
    }

    // TODO: throw error with reason
    fn validate_block(&self, block: &Block) -> Option<State> {
        // bad sig
        if !block.sheader.verify() { return None; }
        // not building on my curr
        if &block.sheader.msg.prev_hash != &self.curr.header_hash { return None; }
        // wrong round
        if block.sheader.msg.round != &self.curr.header.round + 1 { return None; }
        // wrong state transition
        let mut state_clone = self.curr.state.clone();
        state_clone.apply_seq(&block.txns);
        if state_clone.hash() != block.sheader.msg.state_hash { return None; }
        match &block.sheader.msg.seed {
            Either::Left(sig) => {
                // bad seed
                if BLST_ERROR::BLST_SUCCESS != sig.verify(true, &self.curr.beacon, &[], &[], &self.curr.next_leader, true) {
                    return None;
                }
            },
            Either::Right(hash) => {
                // txns without leader
                if block.txns.seq.len() > 0 { return None; }
                // bad seed
                let seed: [u8; 32] = Sha256::digest(&self.curr.beacon).into();
                if &seed != hash { return None; }
            }
        }
        Some(state_clone)
    }

    fn send(&self) -> Option<Block> {
        let mut vseq = ValidatorIter { beacon: self.curr.beacon, state: &self.curr.state };
        let leader = vseq.next().unwrap();
        if self.keypair.pk == leader {
            let txnseq = TxnSeq { seq: Vec::from([self.random_txn()]) };
            let block = self.make_block(txnseq.clone());
            Some(block)
        } else {
            None
        }
    }

    fn receive(&mut self, block: Block) {
        if let Some(state) = self.validate_block(&block) {
            self.curr = Snapshot::new(block.sheader.msg, state);
        }
    }
}

// ....................................................................

#[derive(Debug, Clone)]
struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}

fn gen() -> KeyPair {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = core::array::from_fn(|_| rng.gen());
    let sk = SecretKey::key_gen(&seed, &[]).unwrap();
    KeyPair { sk: sk.clone(), pk: sk.sk_to_pk() }
}

fn main() {
    // Simulating a simple synchronous network.
    let keypairs: [KeyPair; NUM_NODES] = core::array::from_fn(|_| gen());

    let mut generator = Generator::default();
    let mut name = HashMap::new();
    for kp in &keypairs {
        name.insert(kp.pk.clone().to_bytes(), generator.next().unwrap());
    }

    // TODO: use Output::<Sha256>::default().to_something()
    let mut genesis_state = State { 
        accounts: MerkleTrie::new(),
        validators: MerkleTrie::new(),
        validator_idx: [0]
        // stakes : keypairs.clone().map(|kp| Account { pk: kp.pk, bal: 1 << 16, nonce: 0 }).into() 
    };
    for kp in &keypairs {
        genesis_state.accounts.insert(
            &Sha256::digest(&kp.pk.to_bytes()).into(),
            AccountData { bal: 1 << 16, nonce: 0 }
        );
        for i in 0..128 / NUM_NODES {
            let txn = Txn {
                to: PublicKey::default(),
                amount: 0,
                nonce: (i+1) as u64
            };
            genesis_state.apply(&Signed::new(txn, &kp.sk));
        }
    }
    genesis_state.accounts.finalize();
    genesis_state.validators.finalize();

    let genesis_header = Header {
        round: 0, 
        timestamp: 0,
        prev_hash: [0u8; 32], 
        state_hash: genesis_state.hash(), 
        txns_hash: [0u8; 32],
        seed: Either::Right([0u8; 32])
    };
    let genesis = Snapshot::new(genesis_header, genesis_state);

    let mut nodes: [Node; NUM_NODES] = core::array::from_fn(|i| Node { keypair: keypairs[i].clone(), curr: genesis.clone() });

    let now = Instant::now();
    for r in 1..NUM_ROUNDS {
        println!("Round {:#?}", r);
        let mut bcasts: Vec<Block> = Vec::new();
        for node in &mut nodes {
            if let Some(msg) = node.send() {
                bcasts.push(msg);
            }
        }
        for node in &mut nodes {
            for bcast in &bcasts {
                node.receive(bcast.clone()); 
            }
        }
        for kp in &keypairs {
            println!("Bal of {:?} is {:?}", name.get(&kp.pk.to_bytes()).unwrap(), &nodes[0].curr.state.accounts.get(&Sha256::digest(kp.pk.to_bytes()).into()).unwrap().bal);
        }
    }
    println!("Elapsed time: {} ms", now.elapsed().as_millis());

}

*/