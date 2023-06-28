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
const MAX_FORK: u32 = 256;

const BLOCK_TIME: u64 = 10_000; // ms
const MAX_PROP_TIME: u64 = 250; 
const MAX_CLOCK_GAP: u64 = 3_000; 

#[derive(Debug, Clone, Serialize)]
struct Header {
    round: u32,
    proposal: u32,
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
        hasher.update(self.proposal.to_be_bytes());
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

#[derive(Debug, Clone)]
struct BlockStreamer {
    pub txnseq: MerkleMap<Signed<Txn>>,
    pub count: u32,
    pub state: State,
    pub external: state::ExternalData,
    next_batch: u32,
    unprocessed_batches: HashMap<u32, Vec<Signed<Txn>>>,
    num_batches: u32
}

impl BlockStreamer {
    fn new(state: State, external: state::ExternalData) -> Self {
        Self {
            txnseq: MerkleMap::default(),
            count: 0,
            state,
            external,
            next_batch: 0,
            unprocessed_batches: HashMap::default(),
            num_batches: u32::MAX
        }
    }

    fn add(&mut self, batch: Vec<Signed<Txn>>, batch_no: u32) -> Result<bool, BlockError> {
        if batch_no >= self.next_batch {
            self.unprocessed_batches.insert(batch_no, batch);
        }
        if batch_no > self.num_batches {
            return Err(BlockError::BigBatch);
        }
        while let Some(batch) = self.unprocessed_batches.remove(&self.next_batch) {
            for txn in batch {
                if self.count as usize == state::MAX_BLOCK_SIZE {
                    return Err(BlockError::BadTxn);
                }
                self.state.apply(&txn, &self.external)
                    .map_err(|_| BlockError::BadTxn)?;
            }
            self.next_batch += 1;
        }
        if batch_no > num_batches {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// compute and build on only one chain
// have code to resync on a fork: if longer chain pops up process seq of blocks
// to start resync just need to see longer valid header chain

#[derive(Debug)]
struct Node {
    kp: account::Keypair,
    snaps: [HashMap<[u8; 32], Snap>; MAX_FORK as usize], // self hash indexed.
    head: ([u8; 32], u32), // largest round valid block received in correct time window
    next: Either<BlockBuilder, BlockStreamer>, // builder if we are leading, streamer if we are not
    txpool: HashSet<Signed<Txn>>, // cached txns
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
    AlreadyStreaming,
    AlreadyBuilding,
    NotStreaming,
    NotBuilding,
    NoPrev,
    NoBuilder,
    BigBatch
}

impl Node {
    fn head_snap(&self) -> &Snap {
        &self.snaps[self.head.1 as usize][&self.head.0]
    }

    fn start_stream(&mut self, external: state::ExternalData) -> Result<(), BlockError> {
        if let Either::Right(streamer) = self.next {
            if streamer.external == external {
                return Err(BlockError::AlreadyStreaming);
            }
        }
        self.next = Either::Right(
            BlockStreamer::new(
                self.head_snap().state.clone(),
                external
            )
        );
        Ok(())
    }

    fn add_stream(&mut self, batch: Vec<Signed<Txn>>, batch_no: u32) -> Result<(), BlockError> {
        if let Either::Right(mut streamer) = self.next {
            streamer.add(batch, batch_no)
        } else {
            Err(BlockError::NotStreaming)
        }
    }

    fn finalize_stream(&mut self, sheader: Signed<Header>) -> Result<State, BlockError> {
        let header = sheader.msg;
        if !sheader.verify() { return Err(BlockError::BadSig); }
        let timestamp = state::timestamp();
        if timestamp > header.timestamp + MAX_CLOCK_GAP + MAX_PROP_TIME {
            return Err(BlockError::SmallTimestamp);
        }
        if timestamp + MAX_CLOCK_GAP < header.timestamp {
            return Err(BlockError::BigTimestamp);
        }
        let prev = self
            .snaps[(header.round - 1 % MAX_FORK) as usize]
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
        let mut builder = BlockBuilder::new(self.head.1.state.clone(), external);
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

    fn start_build(&mut self, proposal: u32) -> Result<(), BlockError> {
        let head_snap = self.head_snap();
        let round = head_snap.block.sheader.msg.round + 1;
        let timestamp = head_snap.block.sheader.msg.timestamp + proposal as u64 * BLOCK_TIME;
        let beacon = self.kp.sign(&head_snap.block.sheader.msg.seed);
        let seed = Sha256::digest(beacon).into();
        let external = state::ExternalData { round, timestamp, seed };
        if let Either::Left(builder) = self.next {
            if builder.external == external {
                return Err(BlockError::AlreadyBuilding);
            }
        }
        self.next = Either::Left(
            BlockBuilder::new(head_snap.state.clone(), external)
        );
        Ok(())
    }

    fn add_build(&mut self, txn: Signed<Txn>) -> Result<Option<String>, BlockError> {
        if let Either::Left(mut builder) = self.next {
            if let Ok(opt_str) = builder.add(txn) {
                Ok(opt_str)
            } else {
                Ok(None)
            }
        } else {
            Err(BlockError::NotBuilding)
        }
    }

    fn finalize_build(&self, proposal: u32) -> Result<(Option<String>, Block), BlockError> {
        if let Either::Left(mut builder) = self.next {
            let opt_str = builder.finalize();
            let header = Header {
                round: builder.external.round,
                proposal,
                timestamp: builder.external.timestamp,
                prev_hash: self.head.0,
                state_commit: builder.state.commit(),
                beacon: self.kp.sign(&self.head_snap().block.sheader.msg.seed),
                txnseq_commit: builder.txnseq.commit(),
                seed: builder.external.seed
            };
            let sig = self.kp.sign(&header);
            Ok((
                opt_str,
                Block {
                    sheader: Signed::<Header> {
                        msg: header,
                        from: self.kp.kp.public,
                        sig
                    },
                    txnseq: builder.txnseq
                }
            ))
        } else {
            Err(BlockError::NotBuilding)
        }
    }

    fn validate_block(&self, block: &Block) -> Result<(State, u64), BlockError> {
        
    }

    fn leader<'a>(&mut self, proposal_no: usize) -> &'a account::PublicKey {
        let head_snap = self.head_snap();
        head_snap.state.leader(&head_snap.block.sheader.msg.seed, proposal_no)
    }

    // todo
    // tick function runs every blocktime from init to decide if we should send
    // receive updates data structures with new block
    /*
    fn send(&self) -> Option<Block> {
        if self.is_leader()
    }

    fn receive(&mut self, block: Block) {
        if let Some(state) = self.validate_block(&block) {
            self.curr = Snapshot::new(block.sheader.msg, state);
        }
    }
    */
}

fn main() {
    /*
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
    */
}
