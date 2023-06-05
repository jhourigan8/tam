use ed25519_dalek::{self, Verifier, Signer};
use rand::Rng;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::{fmt::Debug, collections::HashMap};
use rand::rngs::OsRng;

use crate::state::{State, VALIDATOR_SLOTS, VALIDATOR_STAKE, VALIDATOR_ROOT};
use crate::txn::Txn;

pub type Account = [u8; 32];
pub type PublicKey = ed25519_dalek::PublicKey;
pub type Signature = ed25519_dalek::Signature;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Data {
    pub bal: u32,
    pub nonce: u32
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

    fn sign<T: Serialize>(&self, msg: &T) -> Signature {
        self.kp.sign(&serde_json::to_string(&msg).expect("").as_bytes())
    }

    pub fn send(&self, to: PublicKey, amount: u32, state: &State) -> Signed<Txn> {
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

    pub fn stake(&self, validator: blst::min_sig::PublicKey, state: &State) -> Signed<Txn> {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signed<T> {
    pub msg: T,
    pub from: PublicKey,
    pub sig: Signature
}

impl<T: Serialize> Signed<T> {
    pub fn verify(&self) -> bool {
        self.from.verify(serde_json::to_string(&self.msg).expect("").as_bytes(), &self.sig).is_ok()
    }
}