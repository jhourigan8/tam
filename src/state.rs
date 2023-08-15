use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde::Serialize;
use sha2::{Sha256, Digest};
use crate::merkle;
use crate::account;
use crate::validator;
use crate::txn;
use crate::block;

pub const VALIDATOR_ROOT: account::Account = [0u8; 32];
pub const VALIDATOR_SLOTS: u32 = 256;
pub const VALIDATOR_STAKE: u32 = 1024;
pub const JENNY_COINS: u32 = VALIDATOR_SLOTS * VALIDATOR_STAKE >> 1;
pub const JENNY_SLOTS: u32 = VALIDATOR_SLOTS >> 1;
pub const NUM_SHARDS: u8 = 1;

const _MAX_FORK: u32 = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub accounts: merkle::Map<account::Data>,
    pub validators: merkle::Map<validator::Data>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            accounts: merkle::Map::default(),
            validators: merkle::Map::default(),
        };
        let jenny_acc = account::Keypair::default();
        assert!(
            state.accounts.insert(
                &Sha256::digest(jenny_acc.kp.public.to_bytes()),
                account::Data { 
                    bal: JENNY_COINS + JENNY_SLOTS * VALIDATOR_STAKE, 
                    nonce: 0 
                }
            ).is_ok()
        );
        let meta = block::Metadata {
            prev_hash: [0u8; 32],
            round: 0,
            proposal: 1,
            timestamp: timestamp(),
            seed: [0u8; 32],
            beacon: jenny_acc.sign(&[0u8; 32])
        };
        for i in 0..VALIDATOR_SLOTS >> 1 {
            assert!(
                state.apply(
                    &jenny_acc.stake(&state, i), 
                    &meta
                ).is_ok()
            );
        }
        state
    }
}

pub enum Update {
    AccountUp(account::Account, Option<account::Data>),
    ValidatorUp(validator::Slot, Option<validator::Data>)
}

impl State {
    pub fn verify(&self, stxn: &account::Signed<txn::Txn>, headerdata: &block::Metadata) -> Result<Vec<Update>, txn::Error> {
        let from_addy: [u8; 32] = Sha256::digest(&stxn.from.to_bytes()).into();
        let mut from_account = self.accounts.get(&from_addy)
            .map_err(|_| txn::Error::NoPreimage)?
            .ok_or(txn::Error::BadFromPk)?
            .clone();
        if !stxn.verify() {
            return Err(txn::Error::BadSig);
        }
        if from_account.nonce > stxn.msg.nonce {
            return Err(txn::Error::SmallNonce);
        } else if from_account.nonce < stxn.msg.nonce {
            return Err(txn::Error::BigNonce);
        }
        if from_account.bal < stxn.msg.amount {
            return Err(txn::Error::InsuffBal);
        }
        from_account.bal -= stxn.msg.amount;
        from_account.nonce += 1;
        if stxn.msg.to == VALIDATOR_ROOT {
            let staking = match stxn.msg.data.get("method") {
                Some(v) => match &v[..] {
                    b"stake" => true,
                    b"unstake" => false,
                    _ => return Err(txn::Error::BadMethod)
                }
                _ => return Err(txn::Error::BadMethod)
            };
            let idx: [u8; 4] = match stxn.msg.data.get("idx") {
                None => Err(txn::Error::BadStakeIdx),
                Some(idx_bytes) =>
                    idx_bytes
                        .clone()
                        .try_into()
                        .map_err(|_| txn::Error::BadStakeIdx)
            }?;
            if staking {
                if stxn.msg.amount != VALIDATOR_STAKE {
                    return Err(txn::Error::InsuffStake);
                }
                if self.validators.get(&idx).map_err(|_| txn::Error::NoPreimage)?.is_some() {
                    return Err(txn::Error::BadStakeIdx);
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
                    return Err(txn::Error::InsuffStake);
                }
                from_account.bal += VALIDATOR_STAKE;
                match self.validators.get(&idx).map_err(|_| txn::Error::NoPreimage)? {
                    Some(stake_data) => {
                        if stake_data.owner != stxn.from {
                            return Err(txn::Error::BadStakeIdx)
                        }
                    }
                    _ => return Err(txn::Error::BadStakeIdx)
                }
                Ok(Vec::from([
                    Update::AccountUp(from_addy, Some(from_account)),
                    Update::ValidatorUp(idx, None)
                ]))
            }
        } else {
            match self.accounts.get(&stxn.msg.to).map_err(|_| txn::Error::NoPreimage)? {
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

    pub fn apply<'a> (&mut self, stxn: &'a account::Signed<txn::Txn>, headerdata: &block::Metadata) -> Result<(), txn::Error> {
        for up in self.verify(stxn, headerdata)? {
            match up {
                Update::AccountUp(addy, opt_acc) => {
                    match opt_acc {
                        Some(acc) => self.accounts.insert(&addy, acc).map_err(|_| txn::Error::NoPreimage)?,
                        None => self.accounts.remove(&addy).map_err(|_| txn::Error::NoPreimage)?
                    };
                },
                Update::ValidatorUp(idx, opt_stake) => {
                    match opt_stake {
                        Some(stake) => self.validators.insert(&idx, stake).map_err(|_| txn::Error::NoPreimage)?,
                        None => self.validators.remove(&idx).map_err(|_| txn::Error::NoPreimage)?
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
}

pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

#[cfg(test)]
pub mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn payments() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let old = builder.state.clone();
        let bob = account::Keypair::gen();
        let charlie = account::Keypair::gen();
        assert!(
            builder.add(
                alice.send(bob.kp.public, 1 << 15, JENNY_SLOTS)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                alice.send(charlie.kp.public, 1 << 5, JENNY_SLOTS + 1)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                bob.send(charlie.kp.public, 1 << 1, 0)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                charlie.send(bob.kp.public, (1 << 5) + (1 << 1), 0)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                alice.send(bob.kp.public, 1 << 8, JENNY_SLOTS + 2)
            )
            .is_ok()
        );
        let old_accs = old.accounts.iter().collect::<Vec<&account::Data>>();
        assert!(old_accs.contains(&&account::Data { bal: (VALIDATOR_SLOTS * VALIDATOR_STAKE) >> 1, nonce: VALIDATOR_SLOTS >> 1 })); // alice
        let new_accs = builder.state.accounts.iter().collect::<Vec<&account::Data>>();
        assert!(new_accs.contains(&&account::Data { bal: ((VALIDATOR_SLOTS * VALIDATOR_STAKE) >> 1) - (1 << 15) - (1 << 5) - (1 << 8), nonce: 3 + (VALIDATOR_SLOTS >> 1) })); // alice
        assert!(new_accs.contains(&&account::Data { bal: (1 << 15) + (1 << 5) + (1 << 8), nonce: 1 })); // bob
        assert!(new_accs.contains(&&account::Data { bal: 0, nonce: 1 })); // charlie
    }

    /*
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
            if builder.state.leader(&Sha256::digest(i.to_be_bytes()).into(), 1).unwrap() == &alice.kp.public {
                alice_count += 1;
            }
        }
        // alice count variance 160 => stdev < 13 => 800 +- 65 should be guaranteed
        assert!((800-65..=800+65).contains(&alice_count));
        alice_count = 0;
        for i in 0..1000 {
            if builder.state.leader(&Sha256::digest(1u32.to_be_bytes()).into(), i).unwrap() == &alice.kp.public {
                alice_count += 1;
            }
        }
        assert!((800-65..=800+65).contains(&alice_count));
    }
    */

    #[test]
    fn badfrompk() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let bob = account::Keypair::gen();
        // BadFromPk
        let msg = txn::Txn {
            to: Sha256::digest(alice.kp.public.to_bytes()).into(),
            amount: 1,
            nonce: 0,
            data: BTreeMap::default()
        };
        assert_eq!(
            builder.add(account::Signed::<txn::Txn> {
                msg: msg.clone(),
                sig: bob.sign(&msg),
                from: bob.kp.public
            }).map_err(|e| e.1), 
            Err(txn::Error::BadFromPk)
        );
    }

    #[test]
    fn badsig() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let bob = account::Keypair::gen();
        // BadSig
        let msg = txn::Txn {
            to: Sha256::digest(bob.kp.public.to_bytes()).into(),
            amount: 1,
            nonce: VALIDATOR_SLOTS >> 1,
            data: BTreeMap::default()
        };
        assert_eq!(
            builder.add(account::Signed::<txn::Txn> {
                msg: msg.clone(),
                sig: bob.sign(&msg),
                from: alice.kp.public
            }).map_err(|e| e.1), 
            Err(txn::Error::BadSig)
        );
        let msg = txn::Txn {
            to: Sha256::digest(bob.kp.public.to_bytes()).into(),
            amount: 1,
            nonce: VALIDATOR_SLOTS >> 1,
            data: BTreeMap::default()
        };
        let other_msg = txn::Txn {
            to: Sha256::digest(bob.kp.public.to_bytes()).into(),
            amount: 2,
            nonce: VALIDATOR_SLOTS >> 1,
            data: BTreeMap::default()
        };
        assert_eq!(
            builder.add(account::Signed::<txn::Txn> {
                msg: msg.clone(),
                sig: alice.sign(&other_msg),
                from: alice.kp.public
            }).map_err(|e| e.1), 
            Err(txn::Error::BadSig)
        );
    }

    #[test]
    fn badstakeidx() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let mut data = BTreeMap::default();
        data.insert(
            String::from("idx"), 
            alice.unstake(&builder.state, JENNY_SLOTS).msg.data.get("idx").unwrap().clone()
        );
        data.insert(
            String::from("method"), 
            b"stake".to_vec()
        );
        let msg = txn::Txn {
            to: VALIDATOR_ROOT,
            amount: VALIDATOR_STAKE,
            nonce: VALIDATOR_SLOTS >> 1,
            data
        };
        assert_eq!(
            builder.add(account::Signed::<txn::Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }).map_err(|e| e.1), 
            Err(txn::Error::BadStakeIdx)
        );
        let mut data = BTreeMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(&builder.state, JENNY_SLOTS).msg.data.get("idx").unwrap().clone()
        );
        data.insert(
            String::from("method"), 
            b"unstake".to_vec()
        );
        let msg = txn::Txn {
            to: VALIDATOR_ROOT,
            amount: 0,
            nonce: VALIDATOR_SLOTS >> 1,
            data
        };
        assert_eq!(
            builder.add(account::Signed::<txn::Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }).map_err(|e| e.1), 
            Err(txn::Error::BadStakeIdx)
        );
    }

    #[test]
    fn badmethod() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let mut data = BTreeMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(&builder.state, JENNY_SLOTS).msg.data.get("idx").unwrap().clone()
        );
        let msg = txn::Txn {
            to: VALIDATOR_ROOT,
            amount: VALIDATOR_STAKE,
            nonce: VALIDATOR_SLOTS >> 1,
            data
        };
        assert_eq!(
            builder.add(account::Signed::<txn::Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }).map_err(|e| e.1), 
            Err(txn::Error::BadMethod)
        );
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let mut data = BTreeMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(&builder.state, JENNY_SLOTS).msg.data.get("idx").unwrap().clone()
        );
        data.insert(
            String::from("method"), 
            b"silly string".to_vec()
        );
        let msg = txn::Txn {
            to: VALIDATOR_ROOT,
            amount: VALIDATOR_STAKE,
            nonce: VALIDATOR_SLOTS >> 1,
            data
        };
        assert_eq!(
            builder.add(account::Signed::<txn::Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }).map_err(|e| e.1), 
            Err(txn::Error::BadMethod)
        );
    }

    #[test]
    fn insuffbal() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let bob = account::Keypair::gen();
        assert_eq!(
            builder.add(alice.send(bob.kp.public, JENNY_COINS + 1, JENNY_SLOTS)).map_err(|e| e.1), 
            Err(txn::Error::InsuffBal)
        );
    }

    #[test]
    fn insuffstake() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let mut data = BTreeMap::default();
        data.insert(
            String::from("idx"), 
            alice.stake(&builder.state, JENNY_SLOTS).msg.data.get("idx").unwrap().clone()
        );
        data.insert(
            String::from("method"), 
            b"stake".to_vec()
        );
        let msg = txn::Txn {
            to: VALIDATOR_ROOT,
            amount: VALIDATOR_STAKE - 1,
            nonce: JENNY_SLOTS,
            data
        };
        assert_eq!(
            builder.add(account::Signed::<txn::Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }).map_err(|e| e.1), 
            Err(txn::Error::InsuffStake)
        );
    }

    #[test]
    fn smallnonce() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let bob = account::Keypair::gen();
        assert!(
            builder.add(alice.send(bob.kp.public, 1, JENNY_SLOTS)).is_ok()
        );
        assert_eq!(
            builder.add(alice.send(bob.kp.public, 1, JENNY_SLOTS)).map_err(|e| e.1), 
            Err(txn::Error::SmallNonce)
        );
    }

    #[test]
    fn bignonce() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let bob = account::Keypair::gen();
        let mut old = builder.clone();
        assert!(
            builder.add(alice.send(bob.kp.public, 1, JENNY_SLOTS)).is_ok()
        );
        assert_eq!(
            old.add(alice.send(bob.kp.public, 1, JENNY_SLOTS + 1)).map_err(|e| e.1), 
            Err(txn::Error::BigNonce)
        );
    }
    
    
}
