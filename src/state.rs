use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Sha256, Digest};
use crate::merkle::MerkleMap;
use crate::account::{self, Signed};
use crate::validator;
use crate::txn::Txn;
use crate::block;

pub const VALIDATOR_ROOT: account::Account = [0u8; 32];
pub const VALIDATOR_SLOTS: u32 = 256;
pub const VALIDATOR_STAKE: u32 = 1024;
pub const NUM_SHARDS: u8 = 1;

const _MAX_FORK: u32 = 128;

#[derive(Debug, Clone)]
pub struct State {
    pub accounts: MerkleMap<account::Data>,
    pub validators: MerkleMap<validator::Data>,
}

impl Default for State {
    fn default() -> Self {
        let mut def = Self {
            accounts: MerkleMap::default(),
            validators: MerkleMap::default(),
        };
        let jenny_acc = account::Keypair::default();
        def.accounts.insert(
            &Sha256::digest(jenny_acc.kp.public.to_bytes()),
            account::Data { 
                bal: VALIDATOR_SLOTS * VALIDATOR_STAKE, 
                nonce: 0 
            }
        );
        let headerdata = block::Data::default();
        let sig = jenny_acc.sign(&headerdata);
        let mut bb = BlockBuilder::new(
            def, 
            Signed {
                from: jenny_acc.kp.public,
                msg: headerdata,
                sig
            }
        );
        for _ in 0..VALIDATOR_SLOTS >> 1 {
            assert!(bb.add(jenny_acc.stake(&bb.state)).is_ok());
        }
        println!("{:?}", bb.state);
        bb.state
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxnError {
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

pub enum Update {
    AccountUp(account::Account, Option<account::Data>),
    ValidatorUp(validator::Slot, Option<validator::Data>)
}

impl State {
    fn verify(&self, stxn: &Signed<Txn>, headerdata: &block::Data) -> Result<Vec<Update>, TxnError> {
        let from_addy: [u8; 32] = Sha256::digest(&stxn.from.to_bytes()).into();
        let mut from_account = self.accounts.get(&from_addy)
            .map_err(|_| TxnError::NoPreimage)?
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
                if self.validators.get(&idx).map_err(|_| TxnError::NoPreimage)?.is_some() {
                    return Err(TxnError::BadStakeIdx);
                }
                let val_data = validator::Data { 
                    round: headerdata.round, 
                    owner: stxn.from.clone()
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
                match self.validators.get(&idx).map_err(|_| TxnError::NoPreimage)? {
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
            match self.accounts.get(&stxn.msg.to).map_err(|_| TxnError::NoPreimage)? {
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

    pub fn apply<'a> (&mut self, stxn: &'a Signed<Txn>, headerdata: &block::Data) -> Result<(), TxnError> {
        for up in self.verify(stxn, headerdata)? {
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

    pub fn commit(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.accounts.commit());
        hasher.update(self.validators.commit());
        hasher.finalize().into()
    }

    pub fn leader<'a> (&'a self, seed: &[u8; 32], proposal_no: usize) -> &'a account::PublicKey {
        validator::leader(seed, &self.validators, proposal_no)
    }
}

pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use super::*;

    pub fn setup() -> (account::Keypair, BlockBuilder) {
        let jenny_acc = account::Keypair { kp: ed25519_dalek::Keypair {
            public: account::PublicKey::from_bytes(&JENNY_ACC_PK_BYTES).unwrap(),
            secret: account::SecretKey::from_bytes(&JENNY_ACC_SK_BYTES).unwrap()
        }};
        let headerdata = block::Data::default();
        let sig = jenny_acc.sign(&headerdata);
        let builder = BlockBuilder::new(
            State::default(),
            Signed {
                from: jenny_acc.kp.public,
                msg: headerdata,
                sig
            }
        );
        (jenny_acc, builder)
    }

    #[test]
    fn payments() {
        let (alice, mut builder) = setup();
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
    fn leader() {
        let (alice, mut builder) = setup();
        let bob = account::Keypair::gen();
        println!("{:?}", builder.add(
            alice.send(bob.kp.public, 1 << 15,  &builder.state)
        ));
        for _ in 0..64 {
            println!("{:?}", builder.add(
                alice.stake(&builder.state)
            ));
        }
        for _ in 64..80 {
            assert!(builder.add(bob.stake(&builder.state)).is_ok());
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
        let mut alice_count = 0;
        for i in 0u32..1000u32 {
            if builder.state.leader(&Sha256::digest(i.to_be_bytes()).into(), 1) == &alice.kp.public {
                alice_count += 1;
            }
        }
        // alice count variance 160 => stdev < 13 => 800 +- 65 should be guaranteed
        assert!((800-65..=800+65).contains(&alice_count));
        alice_count = 0;
        for i in 0..1000 {
            if builder.state.leader(&Sha256::digest(1u32.to_be_bytes()).into(), i) == &alice.kp.public {
                alice_count += 1;
            }
        }
        assert!((800-65..=800+65).contains(&alice_count));
    }

    #[test]
    fn badfrompk() {
        let (alice, mut builder) = setup();
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
            }).map_err(|e| e.1), 
            Err(TxnError::BadFromPk)
        );
    }

    #[test]
    fn badsig() {
        let (alice, mut builder) = setup();
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
            }).map_err(|e| e.1), 
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
            }).map_err(|e| e.1), 
            Err(TxnError::BadSig)
        );
    }

    #[test]
    fn badstakeidx() {
        let (alice, mut builder) = setup();
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.unstake(&builder.state).msg.data.get("idx").unwrap().clone()
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
            }).map_err(|e| e.1), 
            Err(TxnError::BadStakeIdx)
        );
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(&builder.state).msg.data.get("idx").unwrap().clone()
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
            }).map_err(|e| e.1), 
            Err(TxnError::BadStakeIdx)
        );
    }

    #[test]
    fn badmethod() {
        let (alice, mut builder) = setup();
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(&builder.state).msg.data.get("idx").unwrap().clone()
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
            }).map_err(|e| e.1), 
            Err(TxnError::BadMethod)
        );
        let (alice, mut builder) = setup();
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(&builder.state).msg.data.get("idx").unwrap().clone()
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
            }).map_err(|e| e.1), 
            Err(TxnError::BadMethod)
        );
    }

    #[test]
    fn insuffbal() {
        let (alice, mut builder) = setup();
        let bob = account::Keypair::gen();
        assert_eq!(
            builder.add(alice.send(bob.kp.public, 1 << 20, &builder.state)).map_err(|e| e.1), 
            Err(TxnError::InsuffBal)
        );
    }

    #[test]
    fn insuffstake() {
        let (alice, mut builder) = setup();
        let mut data = HashMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake( &builder.state).msg.data.get("idx").unwrap().clone()
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
            }).map_err(|e| e.1), 
            Err(TxnError::InsuffStake)
        );
    }

    #[test]
    fn smallnonce() {
        let (alice, mut builder) = setup();
        let bob = account::Keypair::gen();
        let old = builder.clone();
        assert!(
            builder.add(alice.send(bob.kp.public, 1, &builder.state)).is_ok()
        );
        assert_eq!(
            builder.add(alice.send(bob.kp.public, 1, &old.state)).map_err(|e| e.1), 
            Err(TxnError::SmallNonce)
        );
    }

    #[test]
    fn bignonce() {
        let (alice, mut builder) = setup();
        let bob = account::Keypair::gen();
        let mut old = builder.clone();
        assert!(
            builder.add(alice.send(bob.kp.public, 1, &builder.state)).is_ok()
        );
        assert_eq!(
            old.add(alice.send(bob.kp.public, 1, &builder.state)).map_err(|e| e.1), 
            Err(TxnError::BigNonce)
        );
    }
    
    
}
