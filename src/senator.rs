use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::fmt::Debug;

use crate::{account, merkle, state, txn, validator};

pub type Id = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Data {
    // If a majority of validators vote against guy gets removed.
    // TODO: collateral validator slots
    pub votes_against: u32,
    pub owner: validator::Id
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verifier {
    id: Id,
    at_round: u32
}