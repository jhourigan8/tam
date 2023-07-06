use serde::Serialize;
use sha2::Sha256;
use digest::Digest;

use crate::account;
use crate::merkle;
use crate::state;
use crate::txn;

pub const TXN_BATCH_SIZE: usize = 128;
pub const MAX_BLOCK_SIZE: usize = 1024;

#[derive(Debug, Clone, Serialize, Default)]
pub struct Header {
    pub data: Data,
    pub commits: Commits,
}

#[derive(Debug, Clone, Serialize)]
pub struct Data {
    pub prev_hash: [u8; 32],
    pub round: u32,
    pub proposal: u32,
    pub timestamp: u64,
    pub seed: [u8; 32],
    pub beacon: account::Signature,
}

impl Default for Data {
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

#[derive(Debug, Clone, Serialize)]
pub struct Commits {
    pub state: [u8; 32],
    pub txnseq: [u8; 32],
}

impl Default for Commits {
    fn default() -> Self {
        let state = state::State::default();
        let txnseq = txn::Txnseq::default();
        Self { 
            state: state.commit(),
            txnseq: txnseq.commit()
        }
    }
}

#[derive(Debug, Clone)]
struct Block {
    sheader: account::Signed<Header>,
    txnseq: txn::Txnseq
}

#[derive(Debug, Clone)]
struct Snap {
    block: Block,
    state: state::State,
}

#[derive(Debug, Clone)]
pub struct Builder<'a> {
    pub kp: &'a account::Keypair,
    pub txnseq: txn::Txnseq,
    pub batch: u32,
    pub count: u32,
    pub state: state::State,
    pub headerdata: Data
}

impl<'a> Builder<'a> {
    pub fn new(kp: &'a account::Keypair, state: state::State, headerdata: Data) -> Self {
        Self {
            kp,
            txnseq: txn::Txnseq::default(),
            count: 0,
            batch: 0,
            state,
            headerdata
        }
    }

    pub fn add(&mut self, stxn: account::Signed<txn::Txn>) -> Result<(), (account::Signed<txn::Txn>, state::TxnError)> {
        match self.state.apply(&stxn, &self.headerdata) {
            Ok(()) => {
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

    pub fn finalize(&self) -> Block {
        let header = Header {
            data: self.headerdata,
            commits: Commits {
                state: self.state.commit(),
                txnseq: self.txnseq.commit()
            }
        };
        let sig = self.kp.sign(&header);
        Block {
            sheader: account::Signed::<Header> {
                msg: header,
                from: self.kp.kp.public,
                sig
            },
            txnseq: self.txnseq.clone()
        }
    }
}


#[derive(Debug, Clone)]
struct Verifier<'a> {
    pub head: &'a Snap,
    pub block: Block
}

impl<'a> Verifier<'a> {
    fn new(head: &Snap, block: Block) -> Self {
        Self { head, block }
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

    fn finalize(self) -> Result<Block, BlockError> {
        let sheader = self.sheader.unwrap();
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
        if sheader.from.verify(
            &header.round.to_be_bytes(), 
            &header.beacon
        ).is_err() {
            return Err(BlockError::BadBeacon);
        }
        let seed: [u8; 32] = Sha256::digest(&header.beacon).into();
        if header.seed != seed {
            return Err(BlockError::BadSeed)
        }
        if header.txnseq_commit != self.txnseq.commit() {
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
        Block {
            sheader: self.header.unwrap(),
            txnseq: self.txnseq
        }
    }
}