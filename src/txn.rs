use serde::{Serialize, Deserialize};
use std::{fmt::Debug, collections::HashMap};
use serde_big_array::BigArray;

use crate::{account, merkle};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Txn {
    #[serde(with = "BigArray")]
    pub to: account::Account, 
    pub amount: u32,
    pub nonce: u32,
    pub data: HashMap<String, Vec<u8>>,
}

pub type Seq = merkle::Map::<account::Signed::<Txn>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Error {
    BadFromPk,
    BadSig,
    BadStakeIdx,
    BadMethod,
    InsuffBal,
    InsuffStake,
    SmallNonce,
    BigNonce,
    FullBlock,
    NoPreimage
}
