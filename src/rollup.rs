use ed25519_dalek::{self, Verifier, Signer};
use rand::Rng;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use rand::rngs::OsRng;
use serde_big_array::BigArray;

use crate::{merkle, account, senator};

pub type Id = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Data {
    #[serde(with = "BigArray")]
    pub state_hash: [u8; 32],
    // Set of senators validating this rollup and their current rounds
    pub senators: Vec<senator::Verifier>,
    // Fixed (for now ?) block proposer + their round
    pub sequencer: senator::Verifier,
    // Prevent contagion: transfers use this balance
    pub bal: u32
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub accounts: merkle::Map<account::Data>
}