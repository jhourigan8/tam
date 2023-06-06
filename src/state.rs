use sha2::{Sha256, Digest};

use crate::merkle::MerkleMap;
use crate::account::{self, Signed};
use crate::validator;
use crate::txn::Txn;

pub const VALIDATOR_ROOT: account::Account = [0u8; 32];
pub const VALIDATOR_SLOTS: u32 = 256;
pub const VALIDATOR_STAKE: u32 = 1024;

pub const JENNY_ACC_PK_BYTES: [u8; 32] = [
    78, 236, 79, 93, 128, 157, 88, 31, 
    180, 214, 106, 188, 148, 28, 247, 180, 
    192, 230, 246, 236, 44, 60, 26, 166, 
    80, 178, 25, 196, 255, 66, 189, 177
];
pub const JENNY_ACC_SK_BYTES: [u8; 32] = [
    191, 138, 2, 115, 144, 114, 100, 247, 
    67, 205, 70, 44, 129, 0, 4, 97, 
    247, 20, 168, 62, 111, 208, 138, 117, 
    205, 14, 172, 198, 231, 24, 204, 42
];
pub const JENNY_VALID_PK_BYTES: [u8; 96] = [
    133, 12, 37, 99, 41, 10, 199, 203, 
    22, 230, 70, 244, 192, 87, 233, 78, 
    140, 82, 222, 2, 209, 217, 83, 23, 
    241, 142, 75, 84, 27, 120, 155, 41, 
    39, 209, 130, 40, 10, 242, 125, 211, 
    15, 200, 167, 209, 7, 245, 212, 32, 
    21, 243, 23, 93, 61, 3, 170, 201, 
    45, 25, 28, 37, 167, 235, 118, 203, 
    206, 161, 50, 254, 69, 141, 226, 96, 
    43, 87, 199, 240, 86, 91, 27, 143, 
    152, 122, 208, 186, 140, 74, 177, 190, 
    135, 40, 61, 83, 46, 74, 87, 56
];
pub const JENNY_VALID_SK_BYTES: [u8; 32] =[
    30, 37, 233, 107, 196, 128, 92, 235, 
    104, 132, 120, 23, 5, 215, 213, 158, 
    95, 233, 10, 73, 143, 23, 31, 31, 
    141, 36, 195, 143, 96, 194, 43, 51
];

const _MAX_FORK: u32 = 128;

#[derive(Debug, Clone)]
pub struct BlockBuilder {
    pub txnseq: MerkleMap<Signed<Txn>>,
    pub count: u32,
    pub state: State
}

impl BlockBuilder {
    pub fn new(state: State) -> Self {
        Self {
            txnseq: MerkleMap::default(),
            count: 0,
            state
        }
    }

    pub fn add(&mut self, stxn: Signed<Txn>) -> Result<(), TxnError> {
        self.state.apply(&stxn)?;
        self.txnseq.insert(
            &self.count.to_be_bytes(),
            stxn
        );
        self.count += 1;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct State {
    pub accounts: MerkleMap<account::Data>,
    pub validators: MerkleMap<validator::Data>,
    pub round: u32,
    pub seed: [u8; 32]
}

impl Default for State {
    fn default() -> Self {
        let mut def = Self {
            accounts: MerkleMap::default(),
            validators: MerkleMap::default(),
            round: 0,
            seed: [0u8; 32]
        };
        let jenny_acc = account::Keypair { kp: ed25519_dalek::Keypair {
            public: account::PublicKey::from_bytes(&JENNY_ACC_PK_BYTES).unwrap(),
            secret: account::SecretKey::from_bytes(&JENNY_ACC_SK_BYTES).unwrap()
        }};
        def.accounts.insert(
            &Sha256::digest(jenny_acc.kp.public.to_bytes()),
            account::Data { 
                bal: VALIDATOR_SLOTS * VALIDATOR_STAKE, 
                nonce: 0 
            }
        );
        let mut bb = BlockBuilder::new(def);
        let jenny_val = validator::Keypair {
            pk: validator::PublicKey::from_bytes(&JENNY_VALID_PK_BYTES).unwrap(),
            sk: validator::SecretKey::from_bytes(&JENNY_VALID_SK_BYTES).unwrap(),
        };
        for _ in 0..VALIDATOR_SLOTS >> 1 {
            assert_eq!(bb.add(jenny_acc.stake(jenny_val.pk, &bb.state)), Ok(()));
        }
        println!("{:?}", bb.state);
        bb.state
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxnError {
    BadFromPk,
    BadSig,
    BadValidPk,
    BadStakeIdx,
    BadMethod,
    InsuffBal,
    InsuffStake,
    SmallNonce,
    BigNonce,
}

pub enum Update {
    AccountUp(account::Account, Option<account::Data>),
    ValidatorUp(validator::Slot, Option<validator::Data>)
}

impl State {
    fn verify(&self, stxn: &Signed<Txn>) -> Result<Vec<Update>, TxnError> {
        let from_addy: [u8; 32] = Sha256::digest(&stxn.from.to_bytes()).into();
        let mut from_account = self.accounts.get(&from_addy)
            .ok_or(TxnError::BadFromPk)?
            .clone();
        if !stxn.verify() {
            return Err(TxnError::BadSig);
        }
        if from_account.nonce > stxn.msg.nonce {
            return Err(TxnError::SmallNonce);
        } else if from_account.nonce < stxn.msg.nonce {
            return Err(TxnError::BigNonce);
        }
        if from_account.bal < stxn.msg.amount {
            return Err(TxnError::InsuffBal);
        }
        from_account.bal -= stxn.msg.amount;
        from_account.nonce += 1;
        if stxn.msg.to == VALIDATOR_ROOT {
            let staking = match stxn.msg.data.get("method") {
                Some(v) => match &v[..] {
                    b"stake" => true,
                    b"unstake" => false,
                    _ => return Err(TxnError::BadMethod)
                }
                _ => return Err(TxnError::BadMethod)
            };
            let idx: [u8; 4] = match stxn.msg.data.get("idx") {
                None => Err(TxnError::BadStakeIdx),
                Some(idx_bytes) =>
                    idx_bytes
                        .clone()
                        .try_into()
                        .map_err(|_| TxnError::BadStakeIdx)
            }?;
            if staking {
                if stxn.msg.amount != VALIDATOR_STAKE {
                    return Err(TxnError::InsuffStake);
                }
                let validator_pk = match stxn.msg.data.get("validator") {
                    None => Err(TxnError::BadValidPk),
                    Some(val_pk_bytes) => 
                        blst::min_sig::PublicKey::from_bytes(val_pk_bytes)
                            .map_err(|_| TxnError::BadValidPk)
                }?;
                if self.validators.get(&idx).is_some() {
                    return Err(TxnError::BadStakeIdx);
                }
                let val_data = validator::Data { 
                    round: self.round, 
                    owner: stxn.from.clone(), 
                    validator: validator_pk.to_bytes()
                };
                Ok(Vec::from([
                    Update::AccountUp(from_addy, Some(from_account)),
                    Update::ValidatorUp(idx, Some(val_data))
                ]))
            } else {
                if stxn.msg.amount != 0 {
                    return Err(TxnError::InsuffStake);
                }
                from_account.bal += VALIDATOR_STAKE;
                match self.validators.get(&idx) {
                    Some(stake_data) => {
                        if stake_data.owner != stxn.from {
                            return Err(TxnError::BadStakeIdx)
                        }
                    }
                    _ => return Err(TxnError::BadStakeIdx)
                }
                Ok(Vec::from([
                    Update::AccountUp(from_addy, Some(from_account)),
                    Update::ValidatorUp(idx, None)
                ]))
            }
        } else {
            match self.accounts.get(&stxn.msg.to) {
                Some(to_account) => {
                    let mut to_account = to_account.clone();
                    if from_addy != stxn.msg.to {
                        to_account.bal += stxn.msg.amount;
                    } else {
                        to_account.nonce += 1;
                    }
                    Ok(Vec::from([
                        Update::AccountUp(from_addy, Some(from_account)),
                        Update::AccountUp(stxn.msg.to, Some(to_account))
                    ]))
                }
                None => {
                    Ok(Vec::from([
                        Update::AccountUp(from_addy, Some(from_account)),
                        Update::AccountUp(stxn.msg.to, Some(account::Data { bal: stxn.msg.amount, nonce: 0 }))
                    ]))
                }
            }
        }
    }

    pub fn apply<'a> (&mut self, stxn: &'a Signed<Txn>) -> Result<(), TxnError> {
        for up in self.verify(stxn)? {
            match up {
                Update::AccountUp(addy, opt_acc) => {
                    match opt_acc {
                        Some(acc) => self.accounts.insert(&addy, acc),
                        None => self.accounts.remove(&addy)
                    };
                },
                Update::ValidatorUp(idx, opt_stake) => {
                    match opt_stake {
                        Some(stake) => self.validators.insert(&idx, stake),
                        None => self.validators.remove(&idx)
                    };
                }
            }
        }
        Ok(())
    }

    pub fn validators<'a> (&'a self) -> impl Iterator<Item = blst::min_sig::PublicKey> + 'a { // impl Iterator<Item = PublicKey> + 'a {
        validator::ValidatorIter { seed: self.seed, validators: &self.validators }
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use super::*;

    pub fn setup() -> (account::Keypair, validator::Keypair, BlockBuilder) {
        let jenny_acc = account::Keypair { kp: ed25519_dalek::Keypair {
            public: account::PublicKey::from_bytes(&JENNY_ACC_PK_BYTES).unwrap(),
            secret: account::SecretKey::from_bytes(&JENNY_ACC_SK_BYTES).unwrap()
        }};
        let jenny_val = validator::Keypair {
            pk: validator::PublicKey::from_bytes(&JENNY_VALID_PK_BYTES).unwrap(),
            sk: validator::SecretKey::from_bytes(&JENNY_VALID_SK_BYTES).unwrap(),
        };
        let builder = BlockBuilder::new(State::default());
        (jenny_acc, jenny_val, builder)
    }

    #[test]
    fn payments() {
        let (alice, _, mut builder) = setup();
        let old = builder.state.clone();
        let bob = account::Keypair::gen();
        let charlie = account::Keypair::gen();
        assert!(
            builder.add(
                alice.send(bob.kp.public, 1 << 15, &builder.state)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                alice.send(charlie.kp.public, 1 << 5, &builder.state)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                bob.send(charlie.kp.public, 1 << 1, &builder.state)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                charlie.send(bob.kp.public, (1 << 5) + (1 << 1), &builder.state)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                alice.send(bob.kp.public, 1 << 8, &builder.state)
            )
            .is_ok()
        );
        let old_accs = old.accounts.iter().collect::<Vec<&account::Data>>();
        println!("{:?}", &&account::Data { bal: (VALIDATOR_SLOTS * VALIDATOR_STAKE) >> 1, nonce: VALIDATOR_SLOTS >> 1 });
        assert!(old_accs.contains(&&account::Data { bal: (VALIDATOR_SLOTS * VALIDATOR_STAKE) >> 1, nonce: VALIDATOR_SLOTS >> 1 })); // alice
        let new_accs = builder.state.accounts.iter().collect::<Vec<&account::Data>>();
        assert!(new_accs.contains(&&account::Data { bal: ((VALIDATOR_SLOTS * VALIDATOR_STAKE) >> 1) - (1 << 15) - (1 << 5) - (1 << 8), nonce: 3 + (VALIDATOR_SLOTS >> 1) })); // alice
        assert!(new_accs.contains(&&account::Data { bal: (1 << 15) + (1 << 5) + (1 << 8), nonce: 1 })); // bob
        assert!(new_accs.contains(&&account::Data { bal: 0, nonce: 1 })); // charlie
    }

    #[test]
    fn validators() {
        let (alice, alice_val, mut builder) = setup();
        let bob = account::Keypair::gen();
        println!("{:?}", builder.add(
            alice.send(bob.kp.public, 1 << 15,  &builder.state)
        ));
        for _ in 0..64 {
            println!("{:?}", builder.add(
                alice.stake(alice_val.pk, &builder.state)
            ));
        }
        let bob_val = validator::Keypair::gen();
        for _ in 64..80 {
            assert!(builder.add(bob.stake(bob_val.pk, &builder.state)).is_ok());
        }
        println!("{:?}", builder.state);
        println!("{:?}", builder.state.validators.iter().collect::<Vec<&validator::Data>>());
        assert_eq!(builder.state.validators.iter().filter(|s| s.owner == alice.kp.public).count(), 64 + (VALIDATOR_SLOTS >> 1) as usize);
        assert_eq!(builder.state.validators.iter().filter(|s| s.owner == bob.kp.public).count(), 16);
        for _ in 0..VALIDATOR_SLOTS >> 1 {
            println!("{:?}", builder.add(
                alice.unstake(&builder.state)
            ));
        }
        let mut val_iter = builder.state.validators();
        let mut alice_count = 0;
        for _ in 0..1000 {
            if val_iter.next().unwrap() == alice_val.pk {
                alice_count += 1;
            }
        }
        // alice count variance 160 => stdev < 13 => 800 +- 65 should be guaranteed
        assert!((800-65..=800+65).contains(&alice_count));
    }

    #[test]
    fn badfrompk() {
        let (alice, _, mut builder) = setup();
        let bob = account::Keypair::gen();
        // BadFromPk
        let msg = Txn {
            to: Sha256::digest(alice.kp.public.to_bytes()).into(),
            amount: 1,
            nonce: 0,
            data: HashMap::default()
        };
        assert_eq!(
            builder.add(Signed::<Txn> {
                msg: msg.clone(),
                sig: bob.sign(&msg),
                from: bob.kp.public
            }), 
            Err(TxnError::BadFromPk)
        );
    }

    #[test]
    fn badsig() {
        let (alice, _, mut builder) = setup();
        let bob = account::Keypair::gen();
        // BadSig
        let msg = Txn {
            to: Sha256::digest(bob.kp.public.to_bytes()).into(),
            amount: 1,
            nonce: VALIDATOR_SLOTS >> 1,
            data: HashMap::default()
        };
        assert_eq!(
            builder.add(Signed::<Txn> {
                msg: msg.clone(),
                sig: bob.sign(&msg),
                from: alice.kp.public
            }), 
            Err(TxnError::BadSig)
        );
        let msg = Txn {
            to: Sha256::digest(bob.kp.public.to_bytes()).into(),
            amount: 1,
            nonce: VALIDATOR_SLOTS >> 1,
            data: HashMap::default()
        };
        let other_msg = Txn {
            to: Sha256::digest(bob.kp.public.to_bytes()).into(),
            amount: 2,
            nonce: VALIDATOR_SLOTS >> 1,
            data: HashMap::default()
        };
        assert_eq!(
            builder.add(Signed::<Txn> {
                msg: msg.clone(),
                sig: alice.sign(&other_msg),
                from: alice.kp.public
            }), 
            Err(TxnError::BadSig)
        );
    }

    #[test]
    fn badvalidpk() {
        let (alice, alice_val, mut builder) = setup();
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(alice_val.pk.clone(), &builder.state).msg.data.get("idx").unwrap().clone()
        );
        data.insert(
            String::from("method"), 
            b"stake".to_vec()
        );
        let msg = Txn {
            to: VALIDATOR_ROOT,
            amount: VALIDATOR_STAKE,
            nonce: VALIDATOR_SLOTS >> 1,
            data
        };
        assert_eq!(
            builder.add(Signed::<Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }), 
            Err(TxnError::BadValidPk)
        );
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(alice_val.pk.clone(), &builder.state).msg.data.get("idx").unwrap().clone()
        );
        data.insert(
            String::from("validator"), 
            b"silly string".to_vec()
        );
        data.insert(
            String::from("method"), 
            b"stake".to_vec()
        );
        let msg = Txn {
            to: VALIDATOR_ROOT,
            amount: VALIDATOR_STAKE,
            nonce: VALIDATOR_SLOTS >> 1,
            data
        };
        assert_eq!(
            builder.add(Signed::<Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }), 
            Err(TxnError::BadValidPk)
        );
    }

    #[test]
    fn badstakeidx() {
        let (alice, alice_val, mut builder) = setup();
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.unstake(&builder.state).msg.data.get("idx").unwrap().clone()
        );
        data.insert(
            String::from("validator"), 
            Vec::from(alice_val.pk.to_bytes())
        );
        data.insert(
            String::from("method"), 
            b"stake".to_vec()
        );
        let msg = Txn {
            to: VALIDATOR_ROOT,
            amount: VALIDATOR_STAKE,
            nonce: VALIDATOR_SLOTS >> 1,
            data
        };
        assert_eq!(
            builder.add(Signed::<Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }), 
            Err(TxnError::BadStakeIdx)
        );
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(alice_val.pk.clone(), &builder.state).msg.data.get("idx").unwrap().clone()
        );
        data.insert(
            String::from("validator"), 
            Vec::from(alice_val.pk.to_bytes())
        );
        data.insert(
            String::from("method"), 
            b"unstake".to_vec()
        );
        let msg = Txn {
            to: VALIDATOR_ROOT,
            amount: 0,
            nonce: VALIDATOR_SLOTS >> 1,
            data
        };
        assert_eq!(
            builder.add(Signed::<Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }), 
            Err(TxnError::BadStakeIdx)
        );
    }

    #[test]
    fn badmethod() {
        let (alice, alice_val, mut builder) = setup();
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(alice_val.pk.clone(), &builder.state).msg.data.get("idx").unwrap().clone()
        );
        data.insert(
            String::from("validator"), 
            Vec::from(alice_val.pk.to_bytes())
        );
        let msg = Txn {
            to: VALIDATOR_ROOT,
            amount: VALIDATOR_STAKE,
            nonce: VALIDATOR_SLOTS >> 1,
            data
        };
        assert_eq!(
            builder.add(Signed::<Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }), 
            Err(TxnError::BadMethod)
        );
        let (alice, alice_val, mut builder) = setup();
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(alice_val.pk.clone(), &builder.state).msg.data.get("idx").unwrap().clone()
        );
        data.insert(
            String::from("validator"), 
            Vec::from(alice_val.pk.to_bytes())
        );
        data.insert(
            String::from("method"), 
            b"silly string".to_vec()
        );
        let msg = Txn {
            to: VALIDATOR_ROOT,
            amount: VALIDATOR_STAKE,
            nonce: VALIDATOR_SLOTS >> 1,
            data
        };
        assert_eq!(
            builder.add(Signed::<Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }), 
            Err(TxnError::BadMethod)
        );
    }

    #[test]
    fn insuffbal() {
        let (alice, _, mut builder) = setup();
        let bob = account::Keypair::gen();
        assert_eq!(
            builder.add(alice.send(bob.kp.public, 1 << 20, &builder.state)), 
            Err(TxnError::InsuffBal)
        );
    }

    #[test]
    fn insuffstake() {
        let (alice, alice_val, mut builder) = setup();
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(alice_val.pk.clone(), &builder.state).msg.data.get("idx").unwrap().clone()
        );
        data.insert(
            String::from("validator"), 
            Vec::from(alice_val.pk.to_bytes())
        );
        data.insert(
            String::from("method"), 
            b"stake".to_vec()
        );
        let msg = Txn {
            to: VALIDATOR_ROOT,
            amount: VALIDATOR_STAKE - 1,
            nonce: VALIDATOR_SLOTS >> 1,
            data
        };
        assert_eq!(
            builder.add(Signed::<Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }), 
            Err(TxnError::InsuffStake)
        );
    }

    #[test]
    fn smallnonce() {
        let (alice, _, mut builder) = setup();
        let bob = account::Keypair::gen();
        let old = builder.clone();
        assert_eq!(
            builder.add(alice.send(bob.kp.public, 1, &builder.state)), 
            Ok(())
        );
        assert_eq!(
            builder.add(alice.send(bob.kp.public, 1, &old.state)), 
            Err(TxnError::SmallNonce)
        );
    }

    #[test]
    fn bignonce() {
        let (alice, _, mut builder) = setup();
        let bob = account::Keypair::gen();
        let mut old = builder.clone();
        assert_eq!(
            builder.add(alice.send(bob.kp.public, 1, &builder.state)), 
            Ok(())
        );
        assert_eq!(
            old.add(alice.send(bob.kp.public, 1, &builder.state)), 
            Err(TxnError::BigNonce)
        );
    }
    
    
}
