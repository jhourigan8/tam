use serde::{Serialize, Deserialize};
use std::{fmt::Debug, collections::{HashMap, BTreeMap}};
use serde_big_array::BigArray;

use crate::{account, merkle};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Txn {
    #[serde(with = "BigArray")]
    pub to: account::Account, 
    pub amount: u32,
    pub nonce: u32,
    pub data: BTreeMap<String, Vec<u8>>,
}

impl PartialOrd for Txn {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let cmp = self.to.cmp(&other.to);
        if cmp.is_ne() { return Some(cmp); }
        let cmp = self.amount.cmp(&other.amount);
        if cmp.is_ne() { return Some(cmp) }
        let cmp = self.nonce.cmp(&other.nonce);
        if cmp.is_ne() { return Some(cmp) }
        let mut iter = self.data.iter();
        let mut entry = iter.next();
        let mut other_iter = other.data.iter();
        let mut other_entry = other_iter.next();
        Some( loop {
            if let Some(e) = entry {
                if let Some(o) = other_entry {
                    let cmp = e.cmp(&o);
                    if cmp.is_ne() { break cmp; }
                    entry = iter.next();
                    other_entry = other_iter.next();
                } else {
                    break std::cmp::Ordering::Greater;
                }
            } else {
                if other_entry.is_some() {
                    break std::cmp::Ordering::Less;
                } else {
                    break std::cmp::Ordering::Equal;
                }
            }
        })
        
    }
}

pub type Seq = merkle::Map::<account::Signed::<Txn>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
