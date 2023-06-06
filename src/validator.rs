use blst;
use rand::Rng;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::fmt::Debug;
use serde_big_array::BigArray;

use crate::{account, merkle::MerkleMap, state::VALIDATOR_SLOTS};

pub type Slot = [u8; 4];
pub type PublicKey = blst::min_sig::PublicKey;
pub type SecretKey = blst::min_sig::SecretKey;
pub type Signature = blst::min_sig::Signature;
pub type PublicKeyBytes = [u8; 96];
pub type SignatureBytes = [u8; 48];

#[derive(Debug, Clone)]
pub struct Keypair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}

impl Keypair {
    pub fn gen() -> Self {
        let mut rng = rand::thread_rng();
        let seed: [u8; 32] = core::array::from_fn(|_| rng.gen());
        let sk = SecretKey::key_gen(&seed, &[]).unwrap();
        Self { sk: sk.clone(), pk: sk.sk_to_pk() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Data {
    pub round: u32,
    pub owner: account::PublicKey,
    #[serde(with = "BigArray")]
    pub validator: PublicKeyBytes
}

pub struct ValidatorIter<'a> {
    pub seed: [u8; 32],
    pub validators: &'a MerkleMap<Data>,
}

impl<'a> Iterator for ValidatorIter<'a> {
    type Item = PublicKey;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let idx = ValidatorIter::idx_from_seed(&self.seed);
            self.seed = Sha256::digest(&self.seed).into();
            let from_account = self.validators.get(&idx.to_be_bytes());
            if let Some(ref k) = from_account {
                let from_pk = blst::min_sig::PublicKey::from_bytes(&k.validator);
                if let Ok(pk) = from_pk {
                    return Some(pk);
                }
            }
        }
    }
}

impl<'a> ValidatorIter<'a> {
    fn rand_from_seed(seed: &[u8]) -> u64 {
        u64::from_be_bytes(
            Sha256::digest(seed)[..8]
            .try_into()
            .expect("sha256 output is more than 8 bytes")
        )
    }

    fn idx_from_seed(seed: &[u8]) -> u32 {
        ((Self::rand_from_seed(seed) as f64 / u64::MAX as f64) * VALIDATOR_SLOTS as f64).floor() as u32
    }
}