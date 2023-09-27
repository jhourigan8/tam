use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::{fmt::Debug, collections::BTreeSet};

use crate::{account, merkle, state, txn, senator};

pub type Slot = [u8; 4];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlotData {
    pub round: u32,
    pub owner: Id
}

pub type Id = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Data {
    // Can't unstake with anything in here!
    pub opposed: merkle::Map<()>,
    pub slots: u32,
    pub pk: account::PublicKey
}

fn idx_from_seed(seed: &[u8]) -> u32 {
    ((u64::from_be_bytes(
        Sha256::digest(seed)[..8]
        .try_into()
        .expect("sha256 output is less than 8 bytes")) 
        as f64 / u64::MAX as f64) 
        * state::VALIDATOR_SLOTS as f64
        ).floor() as u32
}

pub fn leader<'a>(
    seed: &[u8], 
    slots: &'a merkle::Map<SlotData>,
    validators: &'a merkle::Map<Data>, 
    mut proposal_no: u32
) -> Result<&'a account::PublicKey, txn::Error> {
    let mut seed = Vec::from(seed);
    loop {
        let idx = idx_from_seed(&seed);
        let from_account = slots.get(&idx.to_be_bytes()).map_err(|_| txn::Error::NoPreimage)?;
        if let Some(ref k) = from_account {
            proposal_no -= 1;
            if proposal_no == 0 {
                return Ok(&validators.get(&k.owner).unwrap().unwrap().pk);
            }
        }
        seed = Sha256::digest(&seed).to_vec();
    }
}