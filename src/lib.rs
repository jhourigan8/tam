use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;
use std::time::Instant;
use std::time::SystemTime;
use blst::min_pk::*;
use blst::BLST_ERROR;
use digest::generic_array::sequence::Split;
use ed25519_dalek::Verifier;
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
use std::time::UNIX_EPOCH;

use crate::{
    txn::Txn,
    account::Signed,
    merkle::MerkleMap,
    state::{State, BlockBuilder}
};

pub mod merkle;
pub mod state;
pub mod account;
pub mod validator;
pub mod txn;

const NUM_NODES: usize = 8;
const NUM_ROUNDS: usize = 100;
const LEADER_DELAY: usize = 20;
const MAX_FORK: usize = 256;

const BLOCK_TIME: u64 = 10_000; // ms
const MAX_PROP_TIME: u64 = 250; 
const MAX_CLOCK_GAP: u64 = 3_000; 

#[derive(Debug, Clone, Serialize)]
struct Header {
    round: u32,
    timestamp: u64,
    prev_hash: [u8; 32],
    state_commit: [u8; 32],
    txnseq_commit: [u8; 32],
    beacon: account::Signature,
    seed: [u8; 32]
}

impl Header {
    pub fn commit(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.round.to_be_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.prev_hash);
        hasher.update(self.state_commit);
        hasher.update(self.txnseq_commit);
        hasher.update(self.beacon);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone)]
struct Block {
    sheader: account::Signed<Header>,
    txnseq: MerkleMap<Signed<Txn>>
}

#[derive(Debug, Clone)]
struct Snap {
    block: Block,
    state: State,
    received_time: u64
}

#[derive(Debug)]
struct Node<'a> {
    kp: account::Keypair,
    snaps: [HashMap<[u8; 32], Snap>; MAX_FORK],
    head: ([u8; 32], &'a Snap),
    txpool: HashSet<Signed<Txn>>,
    leading: bool
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlockError {
    BadSig,
    BadRound,
    BigTimestamp,
    SmallTimestamp,
    BadBlockTime,
    BadBeacon,
    BadSeed,
    BadTxnseq,
    BadTxn,
    BadState,
    NoPrev
}

impl<'a> Node<'a> {
    // TODO: need to build async in the background and send at time cutoff
    // TODO: selection for 2nd, 3rd, ... leaders (not impl here doe)
    fn make_block(&self, propsal_no: u64) -> Block {
        let round = self.head.1.block.sheader.msg.round + 1;
        let timestamp = self.head.1.block.sheader.msg.timestamp + propsal_no * BLOCK_TIME;
        let beacon = self.kp.sign(&self.head.1.block.sheader.msg.seed);
        let seed = Sha256::digest(beacon).into();
        let external = state::ExternalData { round, timestamp, seed };
        let mut builder = BlockBuilder {
            txnseq: MerkleMap::default(),
            count: 0,
            state: self.head.1.state.clone(),
            external
        };
        for txn in self.txpool { // does this drain?
            if let Err((txn, err)) = builder.add(txn) {
                // TODO: decide when to remove from txpool
            }
        }
        let header = Header {
            round,
            timestamp,
            prev_hash: self.head.0,
            state_commit: builder.state.commit(),
            beacon,
            txnseq_commit: builder.txnseq.commit(),
            seed
        };
        let sig = self.kp.sign(&header);
        Block {
            sheader: Signed::<Header> {
                msg: header,
                from: self.kp.kp.public,
                sig
            },
            txnseq: builder.txnseq
        }
    }

    fn validate_block(&self, block: &Block) -> Result<(State, u64), BlockError> {
        let header = block.sheader.msg;
        if !block.sheader.verify() { return Err(BlockError::BadSig); }
        let timestamp = state::timestamp();
        if timestamp > header.timestamp + MAX_CLOCK_GAP + MAX_PROP_TIME {
            return Err(BlockError::SmallTimestamp);
        }
        if timestamp + MAX_CLOCK_GAP < header.timestamp {
            return Err(BlockError::BigTimestamp);
        }
        let prev = self
            .snaps[(header.round - 1) as usize % MAX_FORK]
            .get(&header.prev_hash)
            .ok_or(BlockError::NoPrev)?;
        if header.round != prev.block.sheader.msg.round + 1 {
            return Err(BlockError::BadRound);
        }
        if header.timestamp != prev.block.sheader.msg.timestamp + BLOCK_TIME  {
            return Err(BlockError::BadBlockTime);
        }
        if block.sheader.from.verify(
            &header.round.to_be_bytes(), 
            &header.beacon
        ).is_err() {
            return Err(BlockError::BadBeacon);
        }
        let seed: [u8; 32] = Sha256::digest(&header.beacon).into();
        if header.seed != seed {
            return Err(BlockError::BadSeed)
        }
        if header.txnseq_commit != block.txnseq.commit() {
            return Err(BlockError::BadTxnseq);
        }
        // TODO: check is leader
        let external = state::ExternalData { 
            round: header.round, 
            timestamp: header.timestamp, 
            seed: header.seed
        };
        let mut builder = BlockBuilder {
            txnseq: MerkleMap::default(),
            count: 0, // ugly
            state: self.head.1.state.clone(),
            external
        };
        for txn in block.txnseq.iter() {
            if builder.add(txn.clone()).is_err() {
                return Err(BlockError::BadTxn);
            }
        }
        if header.state_commit != builder.state.commit() {
            return Err(BlockError::BadState);
        }
        Ok((builder.state, timestamp))
    }

    fn is_leader(&mut self, proposal_no: usize) -> bool {
        self.head.1.state.leader(&self.head.1.block.sheader.msg.seed, proposal_no) == &self.kp.kp.public
    }

    fn send(&self) -> Option<Block> {
        let 
    }

    fn receive(&mut self, block: Block) {
        if let Some(state) = self.validate_block(&block) {
            self.curr = Snapshot::new(block.sheader.msg, state);
        }
    }
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
