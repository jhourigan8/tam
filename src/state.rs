use blst::{self, BLST_ERROR};
use ed25519_dalek::{self, Verifier, Signer};
use either::Either;
use rand::Rng;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::{fmt::Debug, collections::HashMap};
use serde_big_array::BigArray;
use rand::rngs::OsRng;

use crate::merkle::MerkleMap;

const VALIDATOR_SLOTS: u32 = 256;
const VALIDATOR_STAKE: u32 = 1024;
const MAX_FORK: u32 = 128;
const VALIDATOR_ROOT: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountData {
    pub bal: u32,
    pub nonce: u32
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeData {
    round: u32,
    owner: ed25519_dalek::PublicKey,
    #[serde(with = "BigArray")]
    validator: [u8; 96] // bls pk bytes
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Txn {
    #[serde(with = "BigArray")]
    pub to: [u8; 32], // account
    pub amount: u32,
    pub nonce: u32,
    pub data: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signed<T> {
    pub msg: T,
    pub from: ed25519_dalek::PublicKey,
    pub sig: ed25519_dalek::Signature
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Keypair {
    pub kp: ed25519_dalek::Keypair
}

impl Keypair {
    pub fn gen() -> Self {
        let mut csprng = OsRng {};
        Self { kp: ed25519_dalek::Keypair::generate(&mut csprng) }
    }

    fn sign<T: Serialize>(&self, msg: &T) -> ed25519_dalek::Signature {
        self.kp.sign(&serde_json::to_string(&msg).expect("").as_bytes())
    }

    pub fn send(&self, to: ed25519_dalek::PublicKey, amount: u32, state: &State) -> Signed<Txn> {
        let msg = Txn {
            to: Sha256::digest(to).into(),
            amount,
            nonce: state.accounts.get(&Sha256::digest(self.kp.public.to_bytes())).unwrap().nonce,
            data: HashMap::default()
        };
        let sig = self.sign(&msg);
        Signed::<Txn> {
            msg,
            from: self.kp.public.clone(),
            sig
        }
    }

    fn stake(&self, validator: blst::min_sig::PublicKey, state: &State) -> Signed<Txn> {
        let mut rng = rand::thread_rng();
        let idx = loop {
            let rand = rng.gen::<u32>() % VALIDATOR_SLOTS;
            if state.validators.get(&rand.to_be_bytes()).is_none() {
                break rand;
            }
        };
        let mut data = HashMap::default();
        data.insert(String::from("idx"), Vec::from(idx.to_be_bytes()));
        data.insert(String::from("validator"), validator.to_bytes().to_vec());
        let msg = Txn {
            to: VALIDATOR_ROOT,
            amount: VALIDATOR_STAKE,
            nonce: state.accounts.get(&Sha256::digest(self.kp.public.to_bytes())).unwrap().nonce,
            data
        };
        let sig = self.sign(&msg);
        Signed::<Txn> {
            msg,
            from: self.kp.public.clone(),
            sig
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlockBuilder {
    pub txnseq: MerkleMap<Signed<Txn>>,
    pub count: u32,
    pub state: State
}

impl BlockBuilder {
    pub fn add(&mut self, stxn: Signed<Txn>) -> Result<(), TxnError> {
        self.state.apply(&stxn)?;
        self.txnseq.insert(
            &self.count.to_be_bytes(),
            stxn
        );
        self.count += 1;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct State {
    pub accounts: MerkleMap<AccountData>,
    pub validators: MerkleMap<StakeData>,
    pub round: u32,
    pub seed: [u8; 32]
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxnError {
    BadFromPk,
    BadSig,
    BadToPk,
    BadValidPk,
    BadStakeIdx,
    InsuffBal,
    InsuffStake,
    SmallNonce,
    BigNonce,
}

impl State {
    fn verify(&self, stxn: &Signed<Txn>) -> Result<([u8; 32], AccountData, Either<AccountData, ([u8; 4], StakeData)>), TxnError> {
        let from_addy: [u8; 32] = Sha256::digest(&stxn.from.to_bytes()).into();
        let mut from_account = self.accounts.get(&from_addy)
            .ok_or(TxnError::BadFromPk)?
            .clone();
        if !stxn.from.verify(serde_json::to_string(&stxn.msg).expect("").as_bytes(), &stxn.sig).is_ok() {
            return Err(TxnError::BadSig);
        }
        /* --- from old bls ---
        let from_pk = PublicKey::from_bytes(&stxn.from).unwrap();
        let sig = Signature::from_bytes(&stxn.sig)
            .map_err(|_| TxnError::BadSig)?;
        if BLST_ERROR::BLST_SUCCESS != sig.verify(
            true, serde_json::to_string(&stxn.msg).expect("").as_bytes(), &[], &[], &from_pk, true
        ) {
            return Err(TxnError::BadSig);
        }
        */
        if from_account.nonce > stxn.msg.nonce {
            return Err(TxnError::SmallNonce);
        } else if from_account.nonce < stxn.msg.nonce {
            return Err(TxnError::BigNonce);
        }
        if from_account.bal < stxn.msg.amount {
            return Err(TxnError::InsuffBal);
        }
        from_account.bal -= stxn.msg.amount;
        from_account.nonce += 1;
        if stxn.msg.to == VALIDATOR_ROOT {
            if stxn.msg.amount < VALIDATOR_STAKE {
                return Err(TxnError::InsuffStake);
            }
            let validator_pk = match stxn.msg.data.get("validator") {
                None => Err(TxnError::BadValidPk),
                Some(val_pk_bytes) => 
                    blst::min_sig::PublicKey::from_bytes(val_pk_bytes)
                        .map_err(|_| TxnError::BadStakeIdx)
            }?;
            let idx: [u8; 4] = match stxn.msg.data.get("idx") {
                None => {println!("a"); Err(TxnError::BadStakeIdx)},
                Some(idx_bytes) => {
                    println!("idx bytes {:?}", idx_bytes);
                    idx_bytes
                        .clone()
                        .try_into()
                        .map_err(|_| {println!("c"); TxnError::BadStakeIdx})
                }
            }?;
            if self.validators.get(&idx).is_some() {
                println!("b");
                return Err(TxnError::BadStakeIdx);
            }
            Ok((
                from_addy, 
                from_account, 
                Either::Right((
                    idx,
                    StakeData { 
                        round: self.round, 
                        owner: stxn.from.clone(), 
                        validator: validator_pk.to_bytes()
                    }
                ))
            ))
        } else {
            match self.accounts.get(&stxn.msg.to) {
                Some(to_account) => {
                    let mut to_account = to_account.clone();
                    if from_addy != stxn.msg.to {
                        to_account.bal += stxn.msg.amount;
                    } else {
                        to_account.nonce += 1;
                    }
                    Ok((from_addy, from_account, Either::Left(to_account)))
                }
                None => {
                    Ok((from_addy, from_account, Either::Left(AccountData { bal: stxn.msg.amount, nonce: 0 })))
                }
            }
        }
    }

    pub fn apply<'a> (&mut self, stxn: &'a Signed<Txn>) -> Result<(), TxnError> {
        let accs = self.verify(stxn)?;
        match accs {
            (from_addy, from_acc, Either::Left(to_acc)) => {
                self.accounts.insert(&from_addy, from_acc);
                self.accounts.insert(&stxn.msg.to, to_acc);
            },
            (from_addy, from_acc, Either::Right((idx, stake_data))) => {
                self.accounts.insert(&from_addy, from_acc);
                self.validators.insert(
                    &idx,
                    stake_data
                );
            }
        }
        Ok(())
    }

    pub fn validators<'a> (&'a self) -> impl Iterator<Item = blst::min_sig::PublicKey> + 'a { // impl Iterator<Item = PublicKey> + 'a {
        ValidatorIter { seed: self.seed, validators: &self.validators }
    }
}

struct ValidatorIter<'a> {
    seed: [u8; 32],
    validators: &'a MerkleMap<StakeData>,
}

impl<'a> Iterator for ValidatorIter<'a> {
    type Item = blst::min_sig::PublicKey;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let idx = ValidatorIter::idx_from_seed(&self.seed);
            self.seed = Sha256::digest(&self.seed).into();
            let from_account = self.validators.get(&idx.to_be_bytes());
            if let Some(ref k) = from_account {
                let from_pk = blst::min_sig::PublicKey::from_bytes(&k.validator);
                if let Ok(pk) = from_pk {
                    return Some(pk);
                }
            }
        }
    }
}

impl<'a> ValidatorIter<'a> {
    fn rand_from_seed(seed: &[u8]) -> u64 {
        u64::from_be_bytes(
            Sha256::digest(seed)[..8]
            .try_into()
            .expect("sha256 output is more than 8 bytes")
        )
    }

    fn idx_from_seed(seed: &[u8]) -> u32 {
        ((Self::rand_from_seed(seed) as f64 / u64::MAX as f64) * VALIDATOR_SLOTS as f64).floor() as u32
    }
}

pub mod Validator {
    use serde::Serialize;
    use crate::state::Signed;
    use rand::Rng;

    #[derive(Debug, Clone)]
    pub struct Keypair {
        pub sk: blst::min_sig::SecretKey,
        pub pk: blst::min_sig::PublicKey,
    }

    impl Keypair {
        pub fn gen() -> Self {
            let mut rng = rand::thread_rng();
            let seed: [u8; 32] = core::array::from_fn(|_| rng.gen());
            let sk = blst::min_sig::SecretKey::key_gen(&seed, &[]).unwrap();
            Self { sk: sk.clone(), pk: sk.sk_to_pk() }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn setup() -> (Keypair, BlockBuilder) {
        let alice = Keypair::gen();
        let mut state = State {
            accounts: MerkleMap::default(),
            validators: MerkleMap::default(),
            round: 0,
            seed: [0u8; 32]
        };
        state.accounts.insert(
            &Sha256::digest(alice.kp.public.to_bytes()),
            AccountData { bal: 1 << 17, nonce: 0 }
        );
        let builder = BlockBuilder {
            txnseq: MerkleMap::<Signed<Txn>>::default(),
            count: 0,
            state
        };
        (alice, builder)
    }

    #[test]
    fn payments() {
        let (alice, mut builder) = setup();
        let old = builder.state.clone();
        let bob = Keypair::gen();
        let charlie = Keypair::gen();
        assert!(
            builder.add(
                alice.send(bob.kp.public, 1 << 15, &builder.state)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                alice.send(charlie.kp.public, 1 << 5, &builder.state)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                bob.send(charlie.kp.public, 1 << 1, &builder.state)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                charlie.send(bob.kp.public, (1 << 5) + (1 << 1), &builder.state)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                alice.send(bob.kp.public, 1 << 8, &builder.state)
            )
            .is_ok()
        );
        let old_accs = old.accounts.iter().collect::<Vec<&AccountData>>();
        assert!(old_accs.contains(&&AccountData { bal: (1 << 17), nonce: 0 })); // alice
        let new_accs = builder.state.accounts.iter().collect::<Vec<&AccountData>>();
        println!("{:?}", new_accs);
        assert!(new_accs.contains(&&AccountData { bal: (1 << 17) - (1 << 15) - (1 << 5) - (1 << 8), nonce: 3 })); // alice
        assert!(new_accs.contains(&&AccountData { bal: (1 << 15) + (1 << 5) + (1 << 8), nonce: 1 })); // bob
        assert!(new_accs.contains(&&AccountData { bal: 0, nonce: 1 })); // charlie
    }

    #[test]
    fn validators() {
        let (alice, mut builder) = setup();
        let bob = Keypair::gen();
        println!("{:?}", builder.add(
            alice.send(bob.kp.public, 1 << 15,  &builder.state)
        ));
        let alice_val = Validator::Keypair::gen();
        for _ in 0..64 {
            println!("{:?}", builder.add(
                alice.stake(alice_val.pk, &builder.state)
            ));
        }
        let bob_val = Validator::Keypair::gen();
        for _ in 64..80 {
            builder.add(
                bob.stake(bob_val.pk, &builder.state)
            );
        }
        println!("{:?}", builder.state);
        println!("{:?}", builder.state.validators.iter().collect::<Vec<&StakeData>>());
        assert_eq!(builder.state.validators.iter().filter(|s| s.owner == alice.kp.public).count(), 64);
        assert_eq!(builder.state.validators.iter().filter(|s| s.owner == bob.kp.public).count(), 16);
        let mut val_iter = builder.state.validators();
        let mut alice_count = 0;
        for _ in 0..1000 {
            if val_iter.next().unwrap() == alice_val.pk {
                alice_count += 1;
            }
        }
        // alice count variance 160 => stdev < 13 => 800 +- 65 should be guaranteed
        assert!((800-65..=800+65).contains(&alice_count));
    }
    
}
