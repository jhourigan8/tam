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

pub mod merkle;
pub mod state;
pub mod account;
pub mod validator;
pub mod txn;
pub mod block;

const NUM_NODES: usize = 8;
const NUM_ROUNDS: usize = 100;
const LEADER_DELAY: usize = 20;
const MAX_FORK: u32 = 256;

const BLOCK_TIME: u64 = 10_000; // ms
const MAX_PROP_TIME: u64 = 250; 
const MAX_CLOCK_GAP: u64 = 3_000; 

// compute and build on only one chain
// have code to resync on a fork: if longer chain pops up process seq of blocks
// to start resync just need to see longer valid header chain

#[derive(Debug)]
struct Node<'a> {
    kp: account::Keypair,
    snaps: [HashMap<[u8; 32], block::Snap>; MAX_FORK as usize], // self hash indexed.
    head: &'a block::Snap, // largest round valid block received in correct time window
    opt_builder: Option<block::Builder::<'a>>,
    txpool: HashSet<account::Signed<txn::Txn>>, // cached txns
}

impl<'a> Node<'a> {
    // timestamp tick!
    // may return block to prop
    fn tick(&'a mut self, time: u64) -> Option<String> {
        let ret = match self.opt_builder.take() {
            Some(builder) => {
                let snap = builder.finalize();
                let ser = serde_json::to_string(&snap.block).expect("can't serialize value");
                self.add_snap(snap);
                Some(ser)
            },
            None => None
        };
        let gap = time - self.head.block.sheader.msg.data.timestamp;
        assert!(gap % BLOCK_TIME == 0);
        let proposal = (gap / BLOCK_TIME) as u32;
        let leader = self.head.leader(proposal).unwrap();
        if leader == &self.kp.kp.public {
            self.opt_builder = Some(block::Builder::<'a>::new(
                &self.kp, proposal, self.head
            ));
        }
        ret
    }

    fn add_snap(&mut self, snap: block::Snap) {
        assert!(snap.block.sheader.msg.data.round <= self.head.block.sheader.msg.data.round + 1);
        if snap.block.sheader.msg.data.round == self.head.block.sheader.msg.data.round + 1 {
            self.snaps[(snap.block.sheader.msg.data.round % MAX_FORK) as usize] = HashMap::default();
            self.opt_builder = None;
        }
        self.snaps[(snap.block.sheader.msg.data.round % MAX_FORK) as usize]
            .insert(snap.block.sheader.msg.data.prev_hash, snap);
    }

    fn receive_chain(&mut self, chain: Vec<block::Block>) -> Result<(), block::Error> {
        let first = chain.get(0).ok_or(block::Error::TooShort)?;
        let last = chain.last().unwrap();
        if last.sheader.msg.data.round <= self.head.block.sheader.msg.data.round {
            return Err(block::Error::TooShort);
        }
        // last block has to be received at correct time
        let timestamp = state::timestamp();
        if timestamp > last.sheader.msg.data.timestamp + MAX_CLOCK_GAP + MAX_PROP_TIME {
            return Err(block::Error::SmallTimestamp);
        }
        if timestamp + MAX_CLOCK_GAP < last.sheader.msg.data.timestamp {
            return Err(block::Error::BigTimestamp);
        }
        let mut prev = self.snaps
            [((first.sheader.msg.data.round - 1) % MAX_FORK) as usize]
            .get(&first.sheader.msg.data.prev_hash)
            .ok_or(block::Error::BadPrev)?;
        let mut snaps = Vec::default();
        for block in chain {
            let verif = block::Verifier::new(prev, block);
            let snap = verif.finalize()?;
            snaps.push(snap);
            prev = snaps.last().unwrap();
        }
        for snap in snaps {
            self.add_snap(snap);
        }
        Ok(())
    }
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
