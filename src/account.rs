use ed25519_dalek::{self, Verifier, Signer};
use rand::Rng;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use rand::rngs::OsRng;

use crate::state::{State, VALIDATOR_SLOTS, VALIDATOR_STAKE};
use crate::{txn, rollup, merkle, validator};

pub type Id = [u8; 32];
pub type PublicKey = ed25519_dalek::PublicKey;
pub type SecretKey = ed25519_dalek::SecretKey;
pub type Signature = ed25519_dalek::Signature;

pub const JENNY_PK_BYTES: [u8; 32] = [
    78, 236, 79, 93, 128, 157, 88, 31, 
    180, 214, 106, 188, 148, 28, 247, 180, 
    192, 230, 246, 236, 44, 60, 26, 166, 
    80, 178, 25, 196, 255, 66, 189, 177
];
pub const JENNY_SK_BYTES: [u8; 32] = [
    191, 138, 2, 115, 144, 114, 100, 247, 
    67, 205, 70, 44, 129, 0, 4, 97, 
    247, 20, 168, 62, 111, 208, 138, 117, 
    205, 14, 172, 198, 231, 24, 204, 42
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Data {
    pub bal: u32,
    pub nonce: u32
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Keypair {
    pub kp: ed25519_dalek::Keypair,
}

impl Keypair {
    pub fn gen() -> Self {
        let mut csprng = OsRng {};
        Self { kp: ed25519_dalek::Keypair::generate(&mut csprng) }
    }

    pub fn sign<T: Serialize>(&self, msg: &T) -> Signature {
        self.kp.sign(&serde_json::to_string(&msg).expect("").as_bytes())
    }

    pub fn send(&self, to: PublicKey, amount: u32, nonce: u32, opt_rollup: Option<rollup::Id>) -> Signed<txn::Txn> {
        self.send_acc(Sha256::digest(to).into(), amount, nonce, opt_rollup)
    }

    pub fn send_acc(&self, to: [u8; 32], amount: u32, nonce: u32, opt_rollup: Option<rollup::Id>) -> Signed<txn::Txn> {
        let msg = txn::Txn {
            payload: txn::Payload::Payment(to, amount),
            opt_rollup,
            nonce
        };
        let sig = self.sign(&msg);
        Signed::<txn::Txn> {
            msg,
            from: self.kp.public.clone(),
            sig
        }
    }

    pub fn stake(&self, validators: &merkle::Map<validator::Data>, nonce: u32) -> Signed<txn::Txn> {
        let mut rng = rand::thread_rng();
        let idx = loop {
            let rand = rng.gen::<u32>() % VALIDATOR_SLOTS;
            if validators.get(&rand.to_be_bytes()).unwrap().is_none() {
                break rand;
            }
        };
        let msg = txn::Txn {
            payload: txn::Payload::Stake(idx.to_be_bytes()),
            opt_rollup: None,
            nonce
        };
        let sig = self.sign(&msg);
        Signed::<txn::Txn> {
            msg,
            from: self.kp.public.clone(),
            sig
        }
    }

    pub fn unstake(&self, validators: &merkle::Map<validator::Data>, nonce: u32) -> Signed<txn::Txn> {
        let mut rng = rand::thread_rng();
        let idx = loop {
            let rand = rng.gen::<u32>() % VALIDATOR_SLOTS;
            if let Some(stake_data) = validators.get(&rand.to_be_bytes()).unwrap() {
                if stake_data.pk == self.kp.public {
                    break rand;
                }
            }
        };
        let msg = txn::Txn {
            payload: txn::Payload::Unstake(idx.to_be_bytes()),
            opt_rollup: None,
            nonce
        };
        let sig = self.sign(&msg);
        Signed::<txn::Txn> {
            msg,
            from: self.kp.public.clone(),
            sig
        }
    }
}

impl Default for Keypair {
    fn default() -> Self {
        Keypair { 
            kp: ed25519_dalek::Keypair {
                public: PublicKey::from_bytes(&JENNY_PK_BYTES).unwrap(),
                secret: SecretKey::from_bytes(&JENNY_SK_BYTES).unwrap()
            } 
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signed<T> {
    pub msg: T,
    pub from: PublicKey,
    pub sig: Signature
}

impl<T: PartialOrd> PartialOrd for Signed<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let  opt_cmp = self.msg.partial_cmp(&other.msg);
        if let Some(cmp) = opt_cmp {
            if cmp.is_ne() { return Some(cmp); }
        }
        let cmp = self.from.to_bytes().cmp(&other.from.to_bytes());
        if cmp.is_ne() { return Some(cmp); }
        Some(self.sig.to_bytes().cmp(&other.sig.to_bytes()))
    }
}

impl<T: PartialOrd + Eq> Ord for Signed<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(&other).unwrap()
    }
}

impl<T: Serialize> Signed<T> {
    pub fn verify(&self) -> bool {
        self.from.verify(serde_json::to_string(&self.msg).expect("").as_bytes(), &self.sig).is_ok()
    }
}