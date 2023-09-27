use serde::{Serialize, Deserialize};
use std::{fmt::Debug, collections::BTreeMap};
use serde_big_array::BigArray;

use crate::{account, merkle, validator, rollup, txn, senator};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Txn {
    pub payload: Payload,
    pub opt_rollup: Option<rollup::Id>,
    pub nonce: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Payload {
    Payment(account::Id, u32),
    Stake(validator::Slot),
    Unstake(validator::Slot),
    Debit(account::Id, Option<rollup::Id>, u32),
    Credit(account::Id, u32),
    Header(rollup::Id, Vec<txn::Txn>), // TODO add more things
    Oppose(senator::Id),
    Support(senator::Id)
}

pub type Seq = merkle::Map::<account::Signed::<Txn>>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Error {
    BadFromPk,
    BadSig,
    BadStakeIdx,
    InsuffBal,
    InsuffStake,
    SmallNonce,
    BigNonce,
    FullBlock,
    NoRollup,
    NotSenator,
    NoPreimage,
    LockedStake
}
