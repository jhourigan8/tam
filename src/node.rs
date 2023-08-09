use std::collections::BTreeSet;
use std::collections::HashMap;
use std::mem;
use core::array;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use tokio::sync::Mutex;
use std::fmt::Debug;

use crate::{block, state, txn, account};

const NUM_NODES: usize = 8;
const NUM_ROUNDS: usize = 100;
const LEADER_DELAY: usize = 20;
const MAX_FORK: u32 = 256;

const MAX_PROP_TIME: u64 = 250; 
const MAX_CLOCK_GAP: u64 = 300; 

// compute and build on only one chain
// have code to resync on a fork: if longer chain pops up process seq of blocks
// to start resync just need to see longer valid header chain

#[derive(Serialize, Deserialize)]
pub enum Message {
    Blocks(Vec<block::Block>),
    Txns(Vec<account::Signed<txn::Txn>>)
}
#[derive(Serialize, Deserialize)]
enum Error {
    BadBlock(block::Block, block::Error),
    BigTimestamp,
    SmallTimestamp,
    BadPrev,
    TooShort
}

#[derive(Debug)]
pub struct Node { // TODO: acquire locks in total order so we never deadcock
    pub kp: account::Keypair,
    pub snaps: [Mutex<HashMap<[u8; 32], block::Snap>>; MAX_FORK as usize], // self hash indexed.
    pub head: Mutex<block::Snap>, // largest round valid block received in correct time window
    pub opt_builder: Mutex<Option<block::Builder>>,
    pub txpool: Mutex<BTreeSet<account::Signed<txn::Txn>>>, // cached txns
}

impl Node {
    pub fn new(kp: account::Keypair, genesis: block::Snap) -> Self {
        let snaps = array::from_fn(|i| {
            let mut map = HashMap::default();
            if i == 0 { 
                map.insert(genesis.block_hash, genesis.clone());
            }
            Mutex::new(map)
        });
        Self {
            kp,
            snaps,
            head: Mutex::new(genesis),
            opt_builder: Mutex::new(None),
            txpool: Mutex::new(BTreeSet::default())
        }
    }

    pub async fn get_head(&self) -> block::Snap {
        self.head.lock().await.clone()
    }

    // timestamp tick!
    // may return block to prop
    // time can be a little bit after exact tick moment
    pub async fn tick(&self) -> Option<String> {
        let mut empty_builder = None;
        {
            let mut opt_builder = self.opt_builder.lock().await;
            mem::swap(&mut empty_builder, &mut *opt_builder);
        }
        let ret = match empty_builder {
            Some(builder) => {
                let mut snap = builder.finalize(&self.kp);
                let prop = Message::Blocks(Vec::from([snap.block]));
                let ser = serde_json::to_string(&prop).expect("can't serialize value");
                if let Message::Blocks(mut vecy) = prop {
                    snap.block = vecy.pop().unwrap();
                    self.add_snap(snap).await;
                    Some(ser)
                } else {
                    panic!("unreachable")
                }
            },
            None => None
        };
        self.check_leader().await;
        ret
    }

    async fn check_leader(&self) {
        let time = state::timestamp() as u64;
        let head = self.head.lock().await;
        let gap = time - head.block.sheader.msg.data.timestamp.min(time);
        let proposal = (gap / block::BLOCK_TIME) as u32 + 1;
        let leader = head.leader(proposal).unwrap();
        println!("{:?} has seed {:?} and says leader is {:?}", self.kp.kp.public.as_bytes()[0], head.block.sheader.msg.data.seed[0], leader.as_bytes()[0]);
        let mut new_builder = if leader == &self.kp.kp.public {
            println!("{:?} ready to lead next", self.kp.kp.public.as_bytes()[0]);
            let mut builder = block::Builder::new(
                &self.kp, proposal, &head
            );
            let mut empty_pool = BTreeSet::default();
            let mut txpool = self.txpool.lock().await;
            std::mem::swap(&mut empty_pool, &mut *txpool);
            // TODO: this pool 
            for txn in empty_pool {
                let _ = builder.add(txn);
            }
            Some(builder)
        } else {
            None
        };
        {
            let mut opt_builder = self.opt_builder.lock().await;
            mem::swap(&mut new_builder, &mut *opt_builder);
        }
    }

    async fn add_snap(&self, snap: block::Snap) {
        let mut new_head = false;
        {
            let mut head = self.head.lock().await;
            assert!(snap.block.sheader.msg.data.round <= head.block.sheader.msg.data.round + 1);
            // New head!
            if snap.block.sheader.msg.data.round == head.block.sheader.msg.data.round + 1 {
                new_head = true;
                let mut arr = self.snaps[(snap.block.sheader.msg.data.round % MAX_FORK) as usize].lock().await;
                *arr = HashMap::default();
                *head = snap.clone();
                {
                    let mut txpool = self.txpool.lock().await;
                    for txn in head.block.txnseq.iter() {
                        txpool.remove(txn);
                    }
                }
            }
        }
        if new_head {
            self.check_leader().await;
        }
        let mut arr = self.snaps[(snap.block.sheader.msg.data.round % MAX_FORK) as usize].lock().await;
        arr.insert(snap.block.sheader.msg.hash(), snap);
    }

    async fn receive_txns(&self, txns: Vec<account::Signed<txn::Txn>>) -> Option<String> {
        let head = self.head.lock().await;
        let meta = block::Metadata::new(&self.kp, 1, &head);
        let mut valid = Vec::default();
        match *self.opt_builder.lock().await {
            Some(ref mut builder) => {
                // Building keep rule: no pool just try to add
                for txn in txns {
                    let _ = builder.add(txn.clone());
                }
            },
            None => {
                // Not building keep rule
                for txn in txns {
                    let txpool = self.txpool.lock().await;
                    if !(*txpool).contains(&txn) {
                        if head.state.verify(&txn, &meta).is_ok() {
                            valid.push(txn);
                        }
                    }
                }
            }
        }
        if valid.is_empty() {
            None
        } else {
            let prop = Message::Txns(valid);
            let ser = serde_json::to_string(&prop).expect("can't serialize value");
            if let Message::Txns(vecy) = prop {
                let mut txpool = self.txpool.lock().await;
                for txn in vecy {
                    (*txpool).insert(txn);
                }
            } else {
                panic!("unreachable")
            }
            Some(ser)
        }
    }

    async fn receive_chain(&self, chain: Vec<block::Block>) -> Result<(), Error> {
        let first = chain.get(0).ok_or(Error::TooShort)?;
        let last = chain.last().unwrap();
        let forked = {
            let head = self.head.lock().await;
            // println!("received {:#?} and head is {:#?}", first.sheader.msg, head.block.sheader.msg);
            if last.sheader.msg.data.round <= head.block.sheader.msg.data.round {
                return Err(Error::TooShort);
            }
            first.sheader.msg.data.prev_hash != head.block_hash
        };
        // last block has to be received at correct time
        let timestamp = state::timestamp();
        if timestamp > last.sheader.msg.data.timestamp + MAX_CLOCK_GAP + MAX_PROP_TIME {
            return Err(Error::SmallTimestamp);
        }
        println!("BigTimestamp check: it's {:?}, block says {:?}", timestamp, last.sheader.msg.data.timestamp);
        if timestamp + MAX_CLOCK_GAP < last.sheader.msg.data.timestamp {
            return Err(Error::BigTimestamp);
        }
        let snaps = {
            let arr = self.snaps
                [((first.sheader.msg.data.round - 1) % MAX_FORK) as usize]
                .lock()
                .await;
            let mut prev = arr
                .get(&first.sheader.msg.data.prev_hash)
                .ok_or(Error::BadPrev)?;
            let mut snaps = Vec::default();
            for block in chain {
                let verif = block::Verifier::new(prev, block);
                let snap = verif.finalize().map_err(|(b, e)| Error::BadBlock(b, e))?;
                snaps.push(snap);
                prev = snaps.last().unwrap();
            }
            snaps
        };
        // Now it's good!
        if forked {
            self.txpool.lock().await.clear();
        }
        for snap in snaps {
            self.add_snap(snap).await;
        }
        Ok(())
    }

    pub async fn receive(&self, msg: String) -> Option<String> {
        match serde_json::from_str(&msg).unwrap() {
            Message::Blocks(blocks) => {
                self.receive_chain(blocks)
                .await
                .err()
                .map(|e| serde_json::to_string(&e).unwrap())
            },
            Message::Txns(txns) => self.receive_txns(txns).await
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::{thread::sleep, time::{Duration, SystemTime, UNIX_EPOCH}};
    use sha2::{Sha256, Digest};
    
    use tokio::time;
    use crate::validator;

    use crate::block::BLOCK_TIME;

    use super::*;

    async fn setup<'a>() -> (time::Interval, Node, Node) {
        let now = time::Instant::now();
        let gen = block::Snap::default();
        /*
        // Block time sync!
        let now =  SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let wait_for = ((BLOCK_TIME - (now - gen.block.sheader.msg.data.timestamp) % BLOCK_TIME)) % BLOCK_TIME;
        sleep(Duration::from_millis(wait_for));
        */
        // Now synced!
        let mut interval = time::interval_at(now, Duration::from_millis(BLOCK_TIME));
        println!("init gang {:?}", state::timestamp());
        interval.tick().await;
        println!("block0 gang {:?}", state::timestamp());
        let mut alice = Node::new(account::Keypair::default(), gen.clone());
        let mut bob = Node::new(account::Keypair::gen(), gen.clone());
        alice.tick().await;
        bob.tick().await;
        (interval, alice, bob)
    }

    #[tokio::test]
    async fn bigtimestamp() {
        let (_, mut alice, mut bob) = setup().await;
        println!("It's {:?}", state::timestamp());
        // Don't wait long enough.
        sleep(Duration::from_millis((block::BLOCK_TIME - MAX_CLOCK_GAP) >> 1));
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        println!("It's {:?}", state::timestamp());
        assert_eq!(bob.receive(bcast).await, Some(serde_json::to_string(&Error::BigTimestamp).unwrap()));
    }

    #[tokio::test]
    async fn smalltimestamp() {
        let (_, mut alice, mut bob) = setup().await;
        // Wait too long.
        sleep(Duration::from_millis(BLOCK_TIME + MAX_CLOCK_GAP + MAX_PROP_TIME + 1_000));
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(bob.receive(bcast).await, Some(serde_json::to_string(&Error::SmallTimestamp).unwrap()));
    }

    #[tokio::test]
    async fn badprev() {
        let (mut interval, mut alice, mut bob) = setup().await;
        interval.tick().await;
        let _ = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        interval.tick().await;
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(bob.receive(bcast).await, Some(serde_json::to_string(&Error::BadPrev).unwrap()));
    }

    #[tokio::test]
    async fn tooshort() {
        let (mut interval, mut alice, mut bob) = setup().await;
        let head = { alice.head.lock().await.clone() };
        let mut evil_alice = Node::new(account::Keypair::default(), head);
        evil_alice.tick().await;
        let state = { (evil_alice.head.lock().await).state.clone() };
        evil_alice.receive(serde_json::to_string(
            &Message::Txns(Vec::from([alice.kp.send(
                bob.kp.kp.public, 
                1, 
                &state
            )]))
        ).unwrap()).await;
        interval.tick().await;
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(bob.receive(bcast).await, None);
        interval.tick().await;
        let bcast = alice.tick().await.expect("Alice should lead");
        let evil_bcast = evil_alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(bob.receive(bcast).await, None);
        assert_eq!(bob.receive(evil_bcast).await, Some(serde_json::to_string(&Error::TooShort).unwrap()));
    }

    #[tokio::test]
    async fn ok() {
        let (mut interval, mut alice, mut bob) = setup().await;
        interval.tick().await;
        println!("block1 gang {:?}", state::timestamp());
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(bob.receive(bcast).await, None);
        interval.tick().await;
        println!("second");
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(bob.receive(bcast).await, None);
        let mut txns = Vec::default();
        let state = { alice.head.lock().await.state.clone() };
        txns.push(
            alice.kp.send(
                bob.kp.kp.public, 
                state.accounts.get(&Sha256::digest(alice.kp.kp.public.to_bytes())).unwrap().unwrap().bal,
                &state
            )
        );
        alice.receive(
            serde_json::to_string(
                &Message::Txns(txns)
            ).unwrap()
        ).await;
        interval.tick().await;
        println!("third");
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(bob.receive(bcast).await, None);
        let (mut state, meta) = {
            let head = bob.head.lock().await;
            (head.state.clone(), head.block.sheader.msg.data.clone())
        };
        let mut txns = Vec::default();
        for _ in 0..state::VALIDATOR_SLOTS >> 1 {
            let stake = bob.kp.stake(&state);
            txns.push(stake.clone());
            assert!(
                state.apply(
                    &stake, 
                    &meta
                ).is_ok()
            );
        }
        alice.receive(
            serde_json::to_string(
                &Message::Txns(txns)
            ).unwrap()
        ).await;
        interval.tick().await;
        println!("fourth");
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(bob.receive(bcast).await, None);
        // Now they should lead evenly.
        let mut alice_ctr = 0;
        for _ in 0..25 {
            interval.tick().await;
            println!("looper");
            match alice.tick().await {
                Some(bcast) => {
                    println!("alice gang");
                    alice_ctr += 1;
                    assert_eq!(bob.tick().await, None);
                    assert_eq!(bob.receive(bcast).await, None);
                },
                None => {
                    println!("bob gang");
                    let bcast = bob.tick().await.expect("Bob should lead");
                    assert_eq!(alice.receive(bcast).await, None);
                }
            }
        }
        println!("{:?}", alice_ctr);
        // Stdev is sqrt(N) / 2, so w.h.p. should be within sqrt(N) of N
        assert!((7..=18).contains(&alice_ctr));
    }
}