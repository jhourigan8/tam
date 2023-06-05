use serde::{Serialize, Deserialize};
use std::{fmt::Debug, collections::HashMap};
use serde_big_array::BigArray;

use crate::account;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Txn {
    #[serde(with = "BigArray")]
    pub to: account::Account, 
    pub amount: u32,
    pub nonce: u32,
    pub data: HashMap<String, Vec<u8>>,
}