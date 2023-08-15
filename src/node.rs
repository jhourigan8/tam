use std::collections::BTreeSet;
use std::collections::HashMap;
use std::mem;
use core::array;
use serde::{Serialize, Deserialize};
use tokio::sync::Mutex;
use std::fmt::Debug;

use crate::{block, state, txn, account, app, msg};


const MAX_FORK: u32 = 256;
const MAX_PROP_TIME: u64 = 250; 
const MAX_CLOCK_GAP: u64 = 300; 

// compute and build on only one chain
// have code to resync on a fork: if longer chain pops up process seq of blocks
// to start resync just need to see longer valid header chain

#[derive(Debug)]
pub struct Node { // TODO: acquire locks in total order so we never deadcock
    pub kp: account::Keypair,
    pub nonce: Mutex<u32>, // own nonce. may be ahead of nonce on chain
    pub snaps: [Mutex<HashMap<[u8; 32], block::Snap>>; MAX_FORK as usize], // self hash indexed.
    pub head: Mutex<block::Snap>, // largest round valid block received in correct time window
    pub opt_builder: Mutex<Option<block::Builder>>,
    pub txpool: Mutex<BTreeSet<account::Signed<txn::Txn>>>, // cached txns
}

impl Node {
    pub fn new(kp: account::Keypair, genesis: block::Snap, nonce: u32) -> Self {
        let snaps = array::from_fn(|i| {
            let mut map = HashMap::default();
            if i == 0 { 
                map.insert(genesis.block_hash, genesis.clone());
            }
            Mutex::new(map)
        });
        Self {
            kp,
            nonce: Mutex::new(nonce),
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
    pub async fn tick(&self) -> Option<msg::Serialized<msg::chain::Broadcast>> {
        let mut empty_builder = None;
        {
            let mut opt_builder = self.opt_builder.lock().await;
            mem::swap(&mut empty_builder, &mut *opt_builder);
        }
        let ret = match empty_builder {
            Some(builder) => {
                let snap = builder.finalize(&self.kp);
                let req = msg::chain::Broadcast { chain: Vec::from([snap.block.clone()]) };
                let prop = msg::Serialized::new(&req);
                self.add_snap(snap).await;
                Some(prop)
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
        let mut new_builder = if leader == &self.kp.kp.public {
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

    pub async fn receive_txns(&self, txns: msg::txn::Broadcast) -> 
        (msg::Serialized<Result<(), msg::txn::Error>>, Option<msg::Serialized<msg::txn::Broadcast>>)
    {
        let txns = txns.txns;
        let head = self.head.lock().await;
        let meta = block::Metadata::new(&self.kp, 1, &head);
        let mut valid = Vec::default();
        let mut txpool = self.txpool.lock().await;
        // Keep txns which pass or have big nonce (TODO: need to flush txpool...)
        match *self.opt_builder.lock().await {
            Some(ref mut builder) => {
                for txn in txns {
                    if let Err((txn, err)) = builder.add(txn.clone()) {
                        if err == txn::Error::BigNonce {
                            if !(*txpool).contains(&txn) {
                                if head.state.verify(&txn, &meta).is_ok() {
                                    valid.push(txn);
                                }
                            }
                        }
                    }
                }
            },
            None => {
                for txn in txns {
                    if !(*txpool).contains(&txn) {
                        match head.state.verify(&txn, &meta) {
                            Ok(_) | Err(txn::Error::BigNonce) => valid.push(txn),
                            _ => {} ,
                        }
                    }
                }
            }
        }
        let resp = msg::Serialized::new(&Ok::<(), msg::txn::Error>(()));
        if valid.is_empty() {
            (resp, None)
        } else {
            let req = msg::txn::Broadcast { txns: valid };
            let prop = msg::Serialized::new(&req);
            for txn in req.txns {
                (*txpool).insert(txn);
            }
            (resp, Some(prop))
        }
    }

    async fn process_chain(&self, mut chain: Vec<block::Block>) -> 
        Result<Option<msg::Serialized<msg::chain::Broadcast>>, msg::chain::Error> 
    {
        // Drop anything that isn't new.
        let mut first = chain.get(0).ok_or(msg::chain::Error::AlreadyHave)?;
        while self.snaps[(first.sheader.msg.data.round % MAX_FORK) as usize]
            .lock()
            .await
            .contains_key(&first.sheader.msg.hash()) {
                chain.remove(0);
                first = chain.get(0).ok_or(msg::chain::Error::AlreadyHave)?;
        }
        let last = chain.last().unwrap();
        let (forked, new_head) = {
            let head = self.head.lock().await;
            // println!("received {:#?} and head is {:#?}", first.sheader.msg, head.block.sheader.msg);
            if last.sheader.msg.data.round <= head.block.sheader.msg.data.round {
                return Err(msg::chain::Error::TooShort);
            }
            (
                first.sheader.msg.data.prev_hash != head.block_hash, 
                last.sheader.msg.data.round > head.block.sheader.msg.data.round
            )
        };
        // last block has to be received at correct time
        let timestamp = state::timestamp();
        if timestamp > last.sheader.msg.data.timestamp + MAX_CLOCK_GAP + MAX_PROP_TIME {
            return Err(msg::chain::Error::SmallTimestamp);
        }
        if timestamp + MAX_CLOCK_GAP < last.sheader.msg.data.timestamp {
            return Err(msg::chain::Error::BigTimestamp);
        }
        let arr = self.snaps
            [((first.sheader.msg.data.round - 1) % MAX_FORK) as usize]
            .lock()
            .await;
        let mut prev = arr
            .get(&first.sheader.msg.data.prev_hash)
            .ok_or(msg::chain::Error::BadPrev)?;
        let mut snaps = Vec::default();
        // serialize
        let bcast = msg::chain::Broadcast { chain: chain.clone() };
        let prop = msg::Serialized::new(&bcast);
        for block in chain {
            let verif = block::Verifier::new(prev, block);
            let snap = verif.finalize().map_err(|(b, e)| msg::chain::Error::BadBlock(b, e))?;
            snaps.push(snap);
            prev = snaps.last().unwrap();
        }
        // Now it's good!
        if forked {
            self.txpool.lock().await.clear();
        }
        for snap in snaps {
            self.add_snap(snap).await;
        }
        if new_head {
            Ok(Some(prop))
        } else {
            Ok(None)
        }
    }

    pub async fn receive_chain(&self, chain: msg::chain::Broadcast) -> 
        (msg::Serialized<Result<(), msg::chain::Error>>, Option<msg::Serialized<msg::chain::Broadcast>>)
    {
        match self.process_chain(chain.chain).await {
            Ok(opt) => {
                (msg::Serialized::new(&Ok(())), opt)
            },
            Err(e) => {
                (msg::Serialized::new(&Err(e)), None)
            }
        }
    }

    // for now super dummy impl: just take the snap and make it head!
    pub async fn receive_resync(&mut self, resync: msg::resync::Response) {
        for snap in &mut self.snaps {
            snap.lock().await.clear();
        }
        *self.head.lock().await = resync.snap.clone();
        self.snaps[(resync.snap.block.sheader.msg.data.round % MAX_FORK) as usize]
            .lock()
            .await
            .insert(resync.snap.block_hash, resync.snap);
    }
}

#[cfg(test)]
pub mod tests {
    use std::{thread::sleep, time::Duration};
    use sha2::{Sha256, Digest};
    
    use tokio::time;

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
        let alice = Node::new(account::Keypair::default(), gen.clone(), state::JENNY_SLOTS);
        let bob = Node::new(account::Keypair::gen(), gen.clone(), 0);
        alice.tick().await;
        bob.tick().await;
        (interval, alice, bob)
    }

    #[tokio::test]
    async fn bigtimestamp() {
        let (_, alice, bob) = setup().await;
        println!("It's {:?}", state::timestamp());
        // Don't wait long enough.
        sleep(Duration::from_millis((block::BLOCK_TIME - MAX_CLOCK_GAP) >> 1));
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        println!("It's {:?}", state::timestamp());
        assert_eq!(
            bob.receive_chain(bcast.deser()).await, 
            (
                msg::Serialized::new(&Err(msg::chain::Error::BigTimestamp)),
                None
            )
        );
    }

    #[tokio::test]
    async fn smalltimestamp() {
        let (_, alice, bob) = setup().await;
        // Wait too long.
        sleep(Duration::from_millis(BLOCK_TIME + MAX_CLOCK_GAP + MAX_PROP_TIME + 1_000));
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(
            bob.receive_chain(bcast.deser()).await, 
            (
                msg::Serialized::new(&Err(msg::chain::Error::SmallTimestamp)),
                None
            )
        );
    }

    #[tokio::test]
    async fn badprev() {
        let (mut interval, alice, bob) = setup().await;
        interval.tick().await;
        let _ = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        interval.tick().await;
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(
            bob.receive_chain(bcast.deser()).await, 
            (
                msg::Serialized::new(&Err(msg::chain::Error::BadPrev)),
                None
            )
        );
    }

    #[tokio::test]
    async fn tooshort() {
        let (mut interval, alice, bob) = setup().await;
        let head = { alice.head.lock().await.clone() };
        let evil_alice = Node::new(account::Keypair::default(), head, 0);
        evil_alice.tick().await;
        evil_alice.receive_txns(
            msg::txn::Broadcast {
                txns: Vec::from([
                    alice.kp.send(
                        bob.kp.kp.public, 
                        1, 
                        0
                    )
                ])
            }
        ).await;
        interval.tick().await;
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(
            bob.receive_chain(bcast.deser()).await, 
            (
                msg::Serialized::new(&Ok(())),
                None
            )
        );
        interval.tick().await;
        let bcast = alice.tick().await.expect("Alice should lead");
        let evil_bcast = evil_alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(
            bob.receive_chain(bcast.deser()).await, 
            (
                msg::Serialized::new(&Ok(())),
                None
            )
        );
        assert_eq!(
            bob.receive_chain(evil_bcast.deser()).await, 
            (
                msg::Serialized::new(&Err(msg::chain::Error::TooShort)),
                None
            )
        );
    }

    #[tokio::test]
    async fn ok() {
        let (mut interval, alice, bob) = setup().await;
        interval.tick().await;
        println!("block1 gang {:?}", state::timestamp());
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(
            bob.receive_chain(bcast.deser()).await, 
            (
                msg::Serialized::new(&Ok(())),
                None
            )
        );
        interval.tick().await;
        println!("second");
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(
            bob.receive_chain(bcast.deser()).await, 
            (
                msg::Serialized::new(&Ok(())),
                None
            )
        );
        let mut txns = Vec::default();
        let state = { alice.head.lock().await.state.clone() };
        txns.push(
            alice.kp.send(
                bob.kp.kp.public, 
                state.accounts.get(&Sha256::digest(alice.kp.kp.public.to_bytes())).unwrap().unwrap().bal,
                state::JENNY_SLOTS
            )
        );
        alice.receive_txns(
            msg::txn::Broadcast { txns }
        ).await;
        interval.tick().await;
        println!("third");
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(
            bob.receive_chain(bcast.deser()).await, 
            (
                msg::Serialized::new(&Ok(())),
                None
            )
        );
        let (mut state, meta) = {
            let head = bob.head.lock().await;
            (head.state.clone(), head.block.sheader.msg.data.clone())
        };
        let mut txns = Vec::default();
        for i in 0..state::VALIDATOR_SLOTS >> 1 {
            let stake = bob.kp.stake(&state, i);
            txns.push(stake.clone());
            assert!(
                state.apply(
                    &stake, 
                    &meta
                ).is_ok()
            );
        }
        alice.receive_txns(
            msg::txn::Broadcast { txns }
        ).await;
        interval.tick().await;
        println!("fourth");
        let bcast = alice.tick().await.expect("Alice should lead");
        assert_eq!(bob.tick().await, None);
        assert_eq!(
            bob.receive_chain(bcast.deser()).await, 
            (
                msg::Serialized::new(&Ok(())),
                None
            )
        );
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
                    assert_eq!(
                        bob.receive_chain(bcast.deser()).await, 
                        (
                            msg::Serialized::new(&Ok(())),
                            None
                        )
                    );
                },
                None => {
                    println!("bob gang");
                    let bcast = bob.tick().await.expect("Bob should lead");
                    assert_eq!(
                        alice.receive_chain(bcast.deser()).await, 
                        (
                            msg::Serialized::new(&Ok(())),
                            None
                        )
                    );
                }
            }
        }
        println!("{:?}", alice_ctr);
        // Stdev is sqrt(N) / 2, so w.h.p. should be within sqrt(N) of N
        assert!((7..=18).contains(&alice_ctr));
    }
}