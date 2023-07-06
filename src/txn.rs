use serde::{Serialize, Deserialize};
use std::{fmt::Debug, collections::HashMap};
use serde_big_array::BigArray;

use crate::account;
use crate::merkle;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Txn {
    #[serde(with = "BigArray")]
    pub to: account::Account, 
    pub amount: u32,
    pub nonce: u32,
    pub data: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Txnseq {
    pub seq: merkle::Map<account::Signed<Txn>>
}

impl Txnseq {
    pub fn commit(&self) -> [u8; 32] {
        self.seq.commit()
    }
}
