use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;
use digest::Digest;

use crate::account;
use crate::merkle;
use crate::state;
use crate::txn;
use crate::validator;

pub const TXN_BATCH_SIZE: usize = 128;
pub const MAX_BLOCK_SIZE: usize = 1024;

pub const BLOCK_TIME: u64 = 2_000; // ms

impl Default for Metadata {
    fn default() -> Self {
        let beacon = account::Keypair::default()
            .sign(&[0u8; 32]);
        Self { 
            prev_hash: [0u8; 32],
            round: 0, 
            proposal: 1,
            timestamp: state::timestamp(), 
            seed: Sha256::digest(&beacon).into(),
            beacon
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commits {
    pub state: [u8; 32],
    pub txnseq: [u8; 32],
}

impl Default for Commits {
    fn default() -> Self {
        let state = state::State::default();
        let txnseq = txn::Seq::default();
        Self { 
            state: state.commit(),
            txnseq: txnseq.commit()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Header {
    pub data: Metadata,
    pub commits: Commits,
}

impl Header {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.data.prev_hash);
        hasher.update(&self.data.round.to_be_bytes());
        hasher.update(&self.data.proposal.to_be_bytes());
        hasher.update(&self.data.timestamp.to_be_bytes());
        hasher.update(&self.data.seed);
        hasher.update(&self.data.beacon);
        hasher.update(&self.commits.state);
        hasher.update(&self.commits.txnseq);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Metadata {
    pub prev_hash: [u8; 32],
    pub round: u32,
    pub proposal: u32,
    pub timestamp: u64,
    pub seed: [u8; 32],
    pub beacon: account::Signature,
}

impl Metadata {
    pub fn new(kp: &account::Keypair, proposal: u32, head: &Snap) -> Self {
        let timestamp = head.block.sheader.msg.data.timestamp + BLOCK_TIME * (proposal as u64);
        let beacon = kp.sign(&head.block.sheader.msg.data.seed);
        let seed = Sha256::digest(beacon).into();
        Metadata {
            prev_hash: head.block_hash,
            round: head.block.sheader.msg.data.round + 1,
            proposal,
            timestamp,
            seed,
            beacon
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub sheader: account::Signed<Header>,
    pub txnseq: txn::Seq
}

impl Default for Block {
    fn default() -> Self {
        let msg = Header::default();
        let kp = account::Keypair::default();
        let sig = kp.sign(&msg);
        let from = kp.kp.public;
        Self {
            sheader: account::Signed::<Header> { msg, from, sig },
            txnseq: txn::Seq::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Error {
    BadSig,
    BadRound,
    BadBlockTime,
    BadBeacon,
    BadSeed,
    BadTxnseq,
    BadTxn(account::Signed<txn::Txn>, txn::Error),
    BadState,
    NotLeader,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snap {
    pub block: Block,
    pub block_hash: [u8; 32],
    pub state: state::State,
}

impl Default for Snap {
    fn default() -> Self {
        let block = Block::default();
        let block_hash = block.sheader.msg.hash();
        Self { block, block_hash, state: state::State::default() }
    }
}

impl Snap {
    pub fn leader(&self, proposal: u32) -> Result<&account::PublicKey, txn::Error> {
        validator::leader(&self.block.sheader.msg.data.seed, &self.state.validators, proposal)
    }
}

#[derive(Debug, Clone)]
pub struct Builder {
    pub txnseq: merkle::Map::<account::Signed::<txn::Txn>>,
    pub batch: u32,
    pub count: u32,
    pub state: state::State,
    pub metadata: Metadata
}

impl Builder {
    pub fn new(kp: &account::Keypair, proposal: u32, head: &Snap) -> Self {
        Self {
            txnseq: txn::Seq::default(),
            count: 0,
            batch: 0,
            state: head.state.clone(),
            metadata: Metadata::new(kp, proposal, head)
        }
    }

    pub fn add(&mut self, stxn: account::Signed<txn::Txn>) -> Result<(), (account::Signed<txn::Txn>, txn::Error)> {
        match self.state.apply(&stxn, &self.metadata) {
            Ok(()) => {
                let idx = (self.batch as u64) << 32 | (self.count as u64);
                assert!(
                    self.txnseq.insert(&idx.to_be_bytes(), stxn).is_ok()
                );
                self.count += 1;
                if self.count == TXN_BATCH_SIZE as u32 {
                    self.count = 0;
                    self.batch += 1;
                }
                Ok(())
            },
            Err(txnerr) => {
                Err((stxn, txnerr))
            }
        }
    }

    pub fn finalize(self, kp: &account::Keypair) -> Snap {
        let header = Header {
            data: self.metadata,
            commits: Commits {
                state: self.state.commit(),
                txnseq: self.txnseq.commit()
            }
        };
        let block_hash = header.hash();
        let sig = kp.sign(&header);
        let block = Block {
            sheader: account::Signed::<Header> {
                msg: header,
                from: kp.kp.public,
                sig
            },
            txnseq: self.txnseq.clone()
        };
        Snap { block, block_hash, state: self.state }
    }
}


#[derive(Debug, Clone)]
pub struct Verifier<'a> {
    pub head: &'a Snap,
    pub block: Block,
    pub batch: u32
}

impl<'a> Verifier<'a> {
    pub fn new(head: &'a Snap, block: Block) -> Self {
        Self { head, block, batch: 0 }
    }

    // possible alternative later: streaming build
    /*
    fn add_batch(&mut self, batch: Vec<Signed<Txn>>, batch_no: u32) -> Result<bool, BlockError> {
        if let Some(num) = self.num_batches {
            if batch_no > num {
                return Err(BlockError::BigBatch);
            }
        }
        if batch_no >= self.next_batch {
            self.unprocessed_batches.insert(batch_no, batch);
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
        if let Some(num) = self.num_batches {
            if self.next_batch > num {
                if self.sheader.is_some() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    */

    pub fn finalize(self) -> Result<Snap, (Block, Error)> {
        let sheader = &self.block.sheader;
        let header = &sheader.msg;
        assert_eq!(header.data.prev_hash, self.head.block_hash);
        if !sheader.verify() { return Err((self.block, Error::BadSig)); }
        if header.data.round != self.head.block.sheader.msg.data.round + 1 {
            return Err((self.block, Error::BadRound));
        }
        if header.data.timestamp != self.head.block.sheader.msg.data.timestamp + (header.data.proposal as u64) * BLOCK_TIME  {
            return Err((self.block, Error::BadBlockTime));
        }
        let sbeacon = account::Signed::<[u8; 32]> {
            msg: self.head.block.sheader.msg.data.seed,
            from: sheader.from.clone(),
            sig: header.data.beacon
        };
        if !sbeacon.verify() {
            return Err((self.block, Error::BadBeacon));
        }
        let seed: [u8; 32] = Sha256::digest(&header.data.beacon).into();
        if header.data.seed != seed {
            return Err((self.block, Error::BadSeed));
        }
        if header.commits.txnseq != self.block.txnseq.commit() {
            return Err((self.block, Error::BadTxnseq));
        }
        if self.block.txnseq.valid_commits().is_err() {
            return Err((self.block, Error::BadTxnseq));
        }
        let leader = self.head.leader(
            header.data.proposal
        ).unwrap();
        if leader != &sheader.from {
            return Err((self.block, Error::NotLeader));
        }
        let mut state = self.head.state.clone();
        for txn in self.block.txnseq.iter() {
            if let Err(e) = state.apply(txn, &header.data) {
                let txn_clone = txn.clone();
                return Err((self.block, Error::BadTxn(txn_clone, e)));
            }
        }
        if header.commits.state != state.commit() {
            return Err((self.block, Error::BadState));
        }
        let block_hash = self.block.sheader.msg.hash();
        Ok( Snap { block: self.block, block_hash, state } )
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::BTreeMap;
    use super::*;

    /*
    BadSig,
    BadRound,
    BigTimestamp,
    SmallTimestamp,
    BadBlockTime,
    BadBeacon,
    BadSeed,
    BadTxnseq,
    BadTxn,
    BadState,f
    BadPrev,
    NotLeader
     */

    fn setup() -> (account::Keypair, account::Keypair, Vec<account::Signed<txn::Txn>>) {
        let alice = account::Keypair::default();
        let bob = account::Keypair::gen();
        let mut vec = Vec::default();
        for i in 0..128 {
            let txn = txn::Txn {
                to: bob.kp.public.to_bytes(),
                amount: 1, 
                nonce: i + state::JENNY_SLOTS,
                data: BTreeMap::default()
            };
            let sig = alice.sign(&txn);
            vec.push(account::Signed::<txn::Txn> {
                msg: txn,
                from: alice.kp.public,
                sig
            });
        }
        (alice, bob, vec)
    }

    #[test]
    fn ok() {
        let (alice, _, txns) = setup();
        let head = Snap::default();
        let mut builder = Builder::new(&alice, 1, &head);
        for txn in txns {
            assert_eq!(builder.add(txn), Ok(()));
        }
        let block = builder.finalize(&alice).block;
        let verifier = Verifier::new(&head, block);
        assert!(verifier.finalize().is_ok());
    }

    #[test]
    fn badsig() {
        let (alice, _, txns) = setup();
        let head = Snap::default();
        let mut builder = Builder::new(&alice, 1, &head);
        for txn in txns {
            assert_eq!(builder.add(txn), Ok(()));
        }
        let mut block = builder.finalize(&alice).block;
        block.sheader.sig = alice.sign(&b"other text");
        let verifier = Verifier::new(&head, block);
        assert_eq!(verifier.finalize().map_err(|(_, e)| e), Err(Error::BadSig));
    }

    #[test]
    fn badround() {
        let (alice, _, txns) = setup();
        let mut head = Snap::default();
        head.block.sheader.msg.data.round += 1;
        let mut builder = Builder::new(&alice, 1, &head);
        for txn in txns {
            assert_eq!(builder.add(txn), Ok(()));
        }
        let block = builder.finalize(&alice).block;
        head.block.sheader.msg.data.round -= 1;
        let verifier = Verifier::new(&head, block);
        assert_eq!(verifier.finalize().map_err(|(_, e)| e), Err(Error::BadRound));
    }

    #[test]
    fn badblocktime() {
        let (alice, _, txns) = setup();
        let mut head = Snap::default();
        head.block.sheader.msg.data.timestamp += 1_000;
        let mut builder = Builder::new(&alice, 1, &head);
        for txn in txns {
            assert_eq!(builder.add(txn), Ok(()));
        }
        let block = builder.finalize(&alice).block;
        head.block.sheader.msg.data.timestamp -= 1_000;
        let verifier = Verifier::new(&head, block);
        assert_eq!(verifier.finalize().map_err(|(_, e)| e), Err(Error::BadBlockTime));
    }

    #[test]
    fn badbeacon() {
        let (alice, _, txns) = setup();
        let head = Snap::default();
        let mut builder = Builder::new(&alice, 1, &head);
        builder.metadata.beacon = alice.sign(b"other data");
        for txn in txns {
            assert_eq!(builder.add(txn), Ok(()));
        }
        let block = builder.finalize(&alice).block;
        let verifier = Verifier::new(&head, block);
        assert_eq!(verifier.finalize().map_err(|(_, e)| e), Err(Error::BadBeacon));
    }

    #[test]
    fn badseed() {
        let (alice, _, txns) = setup();
        let head = Snap::default();
        let mut builder = Builder::new(&alice, 1, &head);
        builder.metadata.seed = [0u8; 32];
        for txn in txns {
            assert_eq!(builder.add(txn), Ok(()));
        }
        let block = builder.finalize(&alice).block;
        let verifier = Verifier::new(&head, block);
        assert_eq!(verifier.finalize().map_err(|(_, e)| e), Err(Error::BadSeed));
    }

    #[test]
    fn badtxnseq() {
        let (alice, _, txns) = setup();
        let head = Snap::default();
        let mut builder = Builder::new(&alice, 1, &head);
        for txn in txns {
            assert_eq!(builder.add(txn), Ok(()));
        }
        let mut block = builder.finalize(&alice).block;
        block.sheader.msg.commits.txnseq = [0u8; 32];
        block.sheader.sig = alice.sign(&block.sheader.msg);
        let verifier = Verifier::new(&head, block);
        assert_eq!(verifier.finalize().map_err(|(_, e)| e), Err(Error::BadTxnseq));
    }

    #[test]
    fn badtxn() {
        let (alice, bob, txns) = setup();
        let head = Snap::default();
        let mut builder = Builder::new(&alice, 1, &head);
        for txn in txns {
            assert_eq!(builder.add(txn), Ok(()));
        }
        let bad = alice.send(
            bob.kp.public, 
            state::VALIDATOR_STAKE * state::VALIDATOR_SLOTS, 
            state::JENNY_SLOTS + 128
        );
        assert_eq!(builder.txnseq.insert(&[0u8], bad.clone()), Ok(None));
        let block = builder.finalize(&alice).block;
        let verifier = Verifier::new(&head, block);
        assert_eq!(verifier.finalize().map_err(|(_, e)| e), Err(Error::BadTxn(bad, txn::Error::InsuffBal)));
    }

    #[test]
    fn badstate() {
        let (alice, _, txns) = setup();
        let head = Snap::default();
        let mut builder = Builder::new(&alice, 1, &head);
        for txn in txns {
            assert_eq!(builder.add(txn), Ok(()));
        }
        let mut block = builder.finalize(&alice).block;
        block.sheader.msg.commits.state = [0u8; 32];
        block.sheader.sig = alice.sign(&block.sheader.msg);
        let verifier = Verifier::new(&head, block);
        assert_eq!(verifier.finalize().map_err(|(_, e)| e), Err(Error::BadState));
    }

    #[test]
    fn notleader() {
        let (_, bob, txns) = setup();
        let head = Snap::default();
        let mut builder = Builder::new(&bob, 1, &head);
        for txn in txns {
            assert_eq!(builder.add(txn), Ok(()));
        }
        let block = builder.finalize(&bob).block;
        let verifier = Verifier::new(&head, block);
        assert_eq!(verifier.finalize().map_err(|(_, e)| e), Err(Error::NotLeader));
    }
}