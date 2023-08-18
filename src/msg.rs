use serde::{Serialize, Deserialize};
use crate::{block, state, txn, account, app, merkle};

// Clients send a Message::X and recieve Result<ok::X, error::X>

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    Txn(Vec<account::Signed<txn::Txn>>),
    Chain(Vec<block::Block>),
    Resync(),
    Batch([u8; 32], u32)
}

impl Message {
    pub fn txn(self) -> Option<Vec<account::Signed<txn::Txn>>> {
        if let Message::Txn(vec) = self {
            Some(vec)
        } else {
            None
        }
    }

    pub fn chain(self) -> Option<Vec<block::Block>> {
        if let Message::Chain(vec) = self {
            Some(vec)
        } else {
            None
        }
    }

    pub fn resync(self) -> Option<()> {
        if let Message::Resync() = self {
            Some(())
        } else {
            None
        }
    }

    pub fn batch(self) -> Option<([u8; 32], u32)> {
        if let Message::Batch(block_hash, batch) = self {
            Some((block_hash, batch))
        } else {
            None
        }
    }
}

pub mod ok {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct Txn {}

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct Chain {}

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct Resync { snap: block::Snap }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct Batch { batch: merkle::Map<account::Signed<txn::Txn>> }
}

pub mod error {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub enum Txn {}

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub enum Chain {
        BadBlock(block::Block, block::Error),
        BigTimestamp,
        SmallTimestamp,
        BadPrev,
        TooShort,
        AlreadyHave
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub enum Resync {
        NotSaved
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub enum Batch {
        DoesntExist
    }
}

pub fn ser<T: Serialize>(x: &T) -> String {
    serde_json::to_string(x).unwrap()
}

pub fn deser<'a, T: Deserialize<'a>>(s: &'a str) -> T {
    println!("{}", s);
    serde_json::from_str(s).unwrap()
}

pub type Response = String;
pub type Bcasts = Vec<String>;
