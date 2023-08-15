use std::marker::PhantomData;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Serialized<T> {
    pub str: String,
    _phantom: PhantomData<T>
}

impl<'a, T: Serialize + Deserialize<'a>> Serialized<T> {
    pub fn new(x: &T) -> Self {
        let str = serde_json::to_string(x).expect("can't serialize value");
        Self { str, _phantom: PhantomData::default() }
    }

    pub fn deser(self) -> T {
        serde_json::from_str(&self.str).unwrap()
    }
}

pub mod txn {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    pub struct Broadcast {
        pub txns: Vec<crate::account::Signed<crate::txn::Txn>>
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    pub enum Error {

    }
}

pub mod chain {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    pub struct Broadcast {
        pub chain: Vec<crate::block::Block>
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    pub enum Error {
        BadBlock(crate::block::Block, crate::block::Error),
        BigTimestamp,
        SmallTimestamp,
        BadPrev,
        TooShort,
        AlreadyHave
    }
}

pub mod resync {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    pub struct Request { }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    pub struct Response {
        pub snap: crate::block::Snap
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    pub enum Error {
        NotSaved
    }
}

pub mod batch {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    pub struct Request {
        pub block_hash: [u8; 32],
        pub batch: u32
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    pub struct Response {
        pub batch: crate::merkle::Map<crate::account::Signed<crate::txn::Txn>>
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    pub enum Error {
        TooBig
    }
}