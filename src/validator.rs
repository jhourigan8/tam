use blst;
use rand::Rng;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::fmt::Debug;
use serde_big_array::BigArray;

use crate::{account, merkle::MerkleMap, state::VALIDATOR_SLOTS};

pub type Slot = [u8; 4];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Data {
    pub round: u32,
    pub owner: account::PublicKey
}

fn idx_from_seed(seed: &[u8]) -> u32 {
    ((u64::from_be_bytes(
        Sha256::digest(seed)[..8]
        .try_into()
        .expect("sha256 output is more than 8 bytes")) 
        as f64 / u64::MAX as f64) 
        * VALIDATOR_SLOTS as f64
        ).floor() as u32
}

pub fn leader<'a>(seed: &[u8], validators: &'a MerkleMap<Data>, mut proposal_no: usize) -> &'a account::PublicKey {
    let mut seed = Vec::from(seed);
    loop {
        let idx = idx_from_seed(&seed);
        let from_account = validators.get(&idx.to_be_bytes());
        if let Some(ref k) = from_account {
            proposal_no -= 1;
            if proposal_no == 0 {
                return &k.owner;
            }
        }
        seed = Sha256::digest(&seed).to_vec();
    }
}