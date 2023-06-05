use std::collections::HashMap;
use std::time::Instant;
use blst::min_pk::*;
use blst::BLST_ERROR;
use rand::prelude::*;
use sha2::{Sha256, Digest};
use names::Generator;

const NUM_NODES: usize = 8;
const NUM_ROUNDS: usize = 100;
const LEADER_DELAY: usize = 20;

pub trait Hashable {
    fn add_hash(&self, hasher: &mut Sha256);

    fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        self.add_hash(&mut hasher);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone)]
struct Txn {
    from: PublicKey,
    to: PublicKey, 
    amount: u64,
    nonce: u64,
}

impl Hashable for Txn {
    fn add_hash(&self, hasher: &mut Sha256) {
        hasher.update(&self.from.to_bytes());
        hasher.update(&self.to.to_bytes());
        hasher.update(&self.amount.to_be_bytes());
        hasher.update(&self.nonce.to_be_bytes());
    }
}

#[derive(Debug, Clone)]
struct SignedTxn {
    txn: Txn,
    sig: Signature
}

impl Hashable for SignedTxn {
    fn add_hash(&self, hasher: &mut Sha256) {
        self.txn.add_hash(hasher);
        hasher.update(&self.sig.to_bytes());
    }
}

impl SignedTxn {
    fn validate(&self) -> bool {
        match self.sig.verify(true, &self.txn.hash(), &[], &[], &self.txn.from, true) {
            BLST_ERROR::BLST_SUCCESS => true,
            _ => false
        }
    }
}

#[derive(Debug, Clone)]
struct TxnSeq {
    seq: Vec<SignedTxn>
}

impl Hashable for TxnSeq {
    fn add_hash(&self, hasher: &mut Sha256) {
        for stxn in &self.seq {
            stxn.add_hash(hasher);
        }
    }
}

#[derive(Debug, Clone)]
struct Account {
    pk: PublicKey,
    bal: u64,
    nonce: u64
}

impl Hashable for Account {
    fn add_hash(&self, hasher: &mut Sha256) {
        hasher.update(&self.pk.to_bytes());
        hasher.update(&self.bal.to_be_bytes());
        hasher.update(&self.nonce.to_be_bytes());
    }
}

struct ValidatorIter<'a> {
    state: &'a State,
    beacon: [u8; 32]
}

impl<'a> Iterator for ValidatorIter<'a> {
    type Item = PublicKey;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.state.select_validator(
            u64::from_be_bytes(self.beacon[0..8].try_into().unwrap()) as f64 / u64::MAX as f64
        );
        self.beacon = Sha256::digest(self.beacon).into();
        item
    }
}

#[derive(Debug, Clone)]
struct State {
    stakes: Vec<Account>
}

impl Hashable for State {
    fn add_hash(&self, hasher: &mut Sha256) {
        for acc in &self.stakes {
            acc.add_hash(hasher)
        }
    }
}

impl State {
    fn get(&mut self, pk: PublicKey) -> Option<&mut Account> {
        for acc in &mut self.stakes {
            if acc.pk == pk {
                return Some(acc);
            }
        }
        None
    }

    fn add(&mut self, pk: PublicKey, amount: u64) {
        for acc in &mut self.stakes {
            if acc.pk == pk {
                acc.bal += amount;
                return
            }
        }
        self.stakes.push(Account { pk , bal: amount, nonce: 0 })
    }

    fn apply(&mut self, seq: &TxnSeq) -> State {
        let mut next = self.clone();
        for stxn in &seq.seq {
            if let Some(mut from) = next.get(stxn.txn.from) {
                if stxn.validate() && from.bal >= stxn.txn.amount && from.nonce + 1 == stxn.txn.nonce {
                    from.bal -= stxn.txn.amount;
                    from.nonce += 1;
                    next.add(stxn.txn.to, stxn.txn.amount);
                } else {
                    println!("Fail2");
                }
            }
        }
        next
    }

    fn select_validator(&self, seed: f64) -> Option<PublicKey> {
        let mut sum: u64 = 0;
        for acc in &self.stakes {
            sum += acc.bal;
        }
        sum = (seed * sum as f64).floor() as u64;
        for acc in &self.stakes {
            if acc.bal >= sum {
                println!("Leader won with {:?}", acc.bal);
                return Some(acc.pk);
            }
            sum -= acc.bal;
        }
        None
    }
}

// ....................................................................

#[derive(Debug, Clone)]
struct Block {
    round: u32,
    prev_hash: [u8; 32],
    state_hash: [u8; 32],
    update: Option<Update>,
}

impl Hashable for Block {
    fn add_hash(&self, hasher: &mut Sha256) {
        hasher.update(self.round.to_be_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.state_hash);
        if let Some(update) = &self.update {
            update.add_hash(hasher)
        }
    }
}

impl Block {
    fn beacon(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        match &self.update {
            Some(update) => {
                hasher.update(update.seed.to_bytes());
            }
            None => {
                hasher.update(self.prev_hash);
            }
        }
        hasher.finalize().into()
    }
}

#[derive(Debug)]
struct Snapshot {
    block: Block,
    beacon: [u8; 32],
    state: State,
    block_hash: [u8; 32],
}

#[derive(Debug, Clone)]
struct Update {
    txns_hash: [u8; 32],
    seed: Signature,
}

impl Hashable for Update {
    fn add_hash(&self, hasher: &mut Sha256) {
        hasher.update(&self.txns_hash);
        hasher.update(&self.seed.to_bytes());
    }
}

#[derive(Debug)]
struct Node {
    keypair: KeyPair,
    blocks: HashMap<[u8; 32], Block>,
    states: HashMap<[u8; 32], State>,
    snap: Snapshot,
}

impl Node {
    fn new(keypair: KeyPair, genesis: Block, genesis_state: State) -> Self {
        let mut blocks = HashMap::new();
        let mut states = HashMap::new();
        blocks.insert(genesis.hash(), genesis.clone());
        states.insert(genesis.state_hash, genesis_state.clone());
        Node {
            keypair,
            blocks,
            states,
            snap: Snapshot {
                block: genesis.clone(),
                beacon: Sha256::digest([0u8; 32]).into(),
                state: genesis_state.clone(),
                block_hash: genesis.hash()
            }
        }
    }

    fn make_block(&mut self, txns: TxnSeq) -> Block {
        let next_state = self.snap.state.apply(&txns);
        Block {
            round: self.snap.block.round + 1,
            prev_hash: self.snap.block_hash,
            update: Some( Update {
                txns_hash: txns.hash(),
                seed: self.keypair.sk.sign(&self.snap.beacon, &[], &[])
            } ),
            state_hash: next_state.hash()
        }
    }

    fn random_txn(&mut self) -> SignedTxn {
        let mut rng = rand::thread_rng();
        let idx: usize = rng.gen::<usize>() % self.snap.state.stakes.len();
        let to = self.snap.state.stakes[idx].pk;
        let my_acc = self.snap.state.get(self.keypair.pk).unwrap();
        let nonce = my_acc.nonce + 1;
        let amount = my_acc.bal / 2;
        let txn = Txn { from: self.keypair.pk, to, nonce, amount };
        let sig = self.keypair.sk.sign(&txn.hash(), &[], &[]);
        SignedTxn { txn, sig }
    }

    fn validator_seq(&mut self, prev_hash: &[u8; 32]) -> ValidatorIter { // TODO make this an iter
        let mut block = self.blocks.get(prev_hash).unwrap();
        for _ in 1..= LEADER_DELAY {
            if let Some(prev) = self.blocks.get(&block.prev_hash) {
                block = prev;
            } else {
                break;
            }
        }
        ValidatorIter { beacon: block.beacon(), state: self.states.get(&block.state_hash).unwrap() }
    }

    fn validate_proposal(&mut self, sbp: Signed<BlockProposal>) -> Option<State> {
        // Find prev block and state
        // 0 round plus one
        // 1 is leader
        // 2 correct state transition
        // 3 correct next seed
        if !sbp.verify() { return None; }
        if let Some(prev_block) = self.blocks.get(&sbp.msg.block.prev_hash) {
            if let Some(state) = self.states.get(&prev_block.state_hash) {
                if sbp.msg.block.round != prev_block.round + 1 { return None; }
                match &sbp.msg.block.update {
                    None => {
                        if prev_block.state_hash != sbp.msg.block.state_hash { return None; }
                        if sbp.msg.txns.seq.len() > 0 { return None; }
                        return Some(state.clone());
                    },
                    Some(update) => {
                        let next_state = self.snap.state.apply(&sbp.msg.txns);
                        if next_state.hash() != sbp.msg.block.state_hash { return None; }
                        if let BLST_ERROR::BLST_SUCCESS = update.seed.verify(true, &prev_block.beacon(), &[], &[], &sbp.pk, true) {
                            return Some(next_state);
                        }
                        let mut vseq = self.validator_seq(&sbp.msg.block.prev_hash);
                        if sbp.pk != vseq.next().unwrap() { return None; }
                        return None;
                    }
                }
            }
        }
        None
    }

    fn send(&mut self) -> Option<Signed<BlockProposal>> {
        let mut vseq = self.validator_seq(&self.snap.block_hash.clone());
        let leader = vseq.next().unwrap();
        if self.keypair.pk == leader {
            let txnseq = TxnSeq { seq: Vec::from([self.random_txn()]) };
            let block = self.make_block(txnseq.clone());
            Some(Signed::new(
                BlockProposal { block: block.clone(), txns: txnseq },
                &self.keypair.sk
            ))
        } else {
            None
        }
    }

    fn receive(&mut self, sbp: Signed<BlockProposal>) {
        if let Some(state) = self.validate_proposal(sbp.clone()) {
            if sbp.msg.block.round > self.snap.block.round {
                self.snap = Snapshot {
                    block: sbp.msg.block.clone(),
                    beacon: sbp.msg.block.beacon(),
                    state: state.clone(),
                    block_hash: sbp.msg.block.hash()
                }
            }
            self.blocks.insert(sbp.msg.block.hash(), sbp.msg.block.clone());
            self.states.insert(state.hash(), state.clone());
        }
    }
}

// ....................................................................


#[derive(Debug, Clone)]
struct BlockProposal {
    block: Block,
    txns: TxnSeq
}

impl Hashable for BlockProposal {
    fn add_hash(&self, hasher: &mut Sha256) {
        self.block.add_hash(hasher);
        self.txns.add_hash(hasher);
    }
}

#[derive(Debug, Clone)]
struct BlockVote {
    block_hash: [u8; 32]
}

impl Hashable for BlockVote {
    fn add_hash(&self, hasher: &mut Sha256) {
        hasher.update(&self.block_hash);
    }
}

#[derive(Debug, Clone)]
struct Signed<T: Hashable> {
    msg: T,
    pk: PublicKey,
    sig: Signature
}

impl<T: Hashable> Signed<T> {
    fn new(msg: T, sk: &SecretKey) -> Self {
        let sig = sk.sign(&msg.hash(), &[], &[]);
        Signed::<T> {
            msg,
            pk: sk.sk_to_pk(),
            sig
        }
    }

    fn verify(&self) -> bool {
        match self.sig.verify(true, &self.msg.hash(), &[], &[], &self.pk, true) {
            BLST_ERROR::BLST_SUCCESS => true,
            _ => false
        }
    }
}

impl<T: Hashable> Hashable for Signed<T> {
    fn add_hash(&self, hasher: &mut Sha256) {
        self.msg.add_hash(hasher);
        hasher.update(&self.pk.to_bytes());
        hasher.update(&self.sig.to_bytes());
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
    let genesis_state = State { stakes : keypairs.clone().map(|kp| Account { pk: kp.pk, bal: 1 << 16, nonce: 0 }).into() };
    let genesis = Block { round: 0, prev_hash: [0u8; 32], state_hash: genesis_state.hash(), update: None };

    let mut nodes: [Node; NUM_NODES] = core::array::from_fn(|i| Node::new(keypairs[i].clone(), genesis.clone(), genesis_state.clone()));

    let now = Instant::now();
    for r in 1..NUM_ROUNDS {
        println!("Round {:#?}", r);
        let mut bcasts: Vec<Signed<BlockProposal>> = Vec::new();
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
            println!("Bal of {:?} is {:?}", name.get(&kp.pk.to_bytes()).unwrap(), &nodes[0].snap.state.get(kp.pk).unwrap().bal);
        }
    }
    println!("Elapsed time: {} ms", now.elapsed().as_millis());

}
