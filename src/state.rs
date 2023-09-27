use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde::Serialize;
use sha2::{Sha256, Digest};
use crate::{merkle, account, validator, txn, block, senator, rollup};

pub const VALIDATOR_SLOTS: u32 = 256;
pub const VALIDATOR_STAKE: u32 = 1024;
pub const JENNY_COINS: u32 = VALIDATOR_SLOTS * VALIDATOR_STAKE >> 1;
pub const JENNY_SLOTS: u32 = VALIDATOR_SLOTS >> 1;
pub const NUM_SHARDS: u8 = 1;

const _MAX_FORK: u32 = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    // Accounts and balances. Indexed by hash of pk.
    pub accounts: merkle::Map<account::Data>,
    // Validator slots.
    // One slot is randomly chosen to lead each tick.
    pub slots: merkle::Map<validator::SlotData>,
    // Validators who can own any number of slots. Also indexed by hash of pk.
    pub validators: merkle::Map<validator::Data>,
    // Senators on any rollup. Indexed by hash of pk.
    pub senators: merkle::Map<senator::Data>,
    // Arbitrary index?
    pub rollups: merkle::Map<rollup::Data>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            accounts: merkle::Map::default(),
            slots: merkle::Map::default(),
            validators: merkle::Map::default(),
            senators: merkle::Map::default(),
            rollups: merkle::Map::default()
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
                    &jenny_acc.stake(&state.validators, i), 
                    &meta
                ).is_ok()
            );
        }
        state
    }
}

pub enum Update {
    Account(account::Id, Option<account::Data>),
    Slot(validator::Slot, Option<validator::SlotData>),
    Validator(validator::Id, Option<validator::Data>),
    Senator(senator::Id, Option<senator::Data>),
    Rollup(rollup::Id, Option<rollup::Data>)
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
        from_account.nonce += 1;
        let mut ups = Vec::default();
        match stxn.msg.payload {
            txn::Payload::Payment(to_id, amount) => {
                if from_account.bal < amount {
                    return Err(txn::Error::InsuffBal);
                }
                match self.accounts.get(&to_id).map_err(|_| txn::Error::NoPreimage)? {
                    Some(to_account) => {
                        let mut to_account = to_account.clone();
                        if from_addy != to_id {
                            from_account.nonce += 1;
                            from_account.bal -= amount;
                            to_account.bal += amount;
                            ups.push(
                                Update::Account(to_id, Some(to_account))
                            );
                        }
                        ups.push(
                            Update::Account(from_addy, Some(from_account))
                        );
                    }
                    None => {
                        from_account.nonce += 1;
                        from_account.bal -= amount;
                        ups.push(
                            Update::Account(from_addy, Some(from_account))
                        );
                        let to_account = account::Data {
                            bal: amount,
                            nonce: 0
                        };
                        ups.push(
                            Update::Account(to_id, Some(to_account))
                        );
                    }
                }
            },
            txn::Payload::Stake(slot) => {
                if from_account.bal < VALIDATOR_STAKE {
                    return Err(txn::Error::InsuffBal);
                }
                if self.slots.get(&slot).map_err(|_| txn::Error::NoPreimage)?.is_some() {
                    return Err(txn::Error::BadStakeIdx);
                }
                let slot_data = validator::SlotData { 
                    round: headerdata.round, 
                    owner: from_addy
                };
                ups.push(
                    Update::Slot(slot, Some(slot_data))
                );
                let val_data = match self.validators.get(&from_addy).map_err(|_| txn::Error::NoPreimage)? {
                    Some(val) => {
                        let mut val = val.clone();
                        val.slots += 1;
                        val
                    },
                    None => {
                        validator::Data {
                            opposed: merkle::Map::default(),
                            slots: 1,
                            pk: stxn.from.clone()
                        }
                    }
                };
                if !val_data.opposed.is_empty() {
                    return Err(txn::Error::LockedStake)
                }
                ups.push(
                    Update::Validator(from_addy, Some(val_data))
                );
            },
            txn::Payload::Unstake(slot) => {
                match self.slots.get(&slot).map_err(|_| txn::Error::NoPreimage)? {
                    Some(stake_data) => {
                        if stake_data.owner != from_addy {
                            return Err(txn::Error::BadStakeIdx)
                        }
                    }
                    _ => return Err(txn::Error::BadStakeIdx)
                }
                ups.push(
                    Update::Slot(slot, None)
                );
                let mut val = self.validators.get(&from_addy)
                    .map_err(|_| txn::Error::NoPreimage)?
                    .unwrap()
                    .clone();
                if !val.opposed.is_empty() {
                    return Err(txn::Error::LockedStake)
                }
                if val.slots == 1 {
                    ups.push(
                        Update::Validator(from_addy, None)
                    );
                } else {
                    val.slots -= 1;
                    ups.push(
                        Update::Validator(from_addy, Some(val))
                    );
                }
            },
            txn::Payload::Debit(acc_id, opt_rollup, amount) => {
                todo!()
            },
            txn::Payload::Credit(acc_id, amount) => {
                todo!()
            },
            txn::Payload::Header(rollup, txns) => {
                todo!()
            },
            txn::Payload::Oppose(senator_id) => {
                todo!()
            },
            txn::Payload::Support(senator_id) => {
                todo!()
            },
        }
        Ok(ups)
    }

    pub fn apply<'a> (&mut self, stxn: &'a account::Signed<txn::Txn>, headerdata: &block::Metadata) -> Result<(), txn::Error> {
        for up in self.verify(stxn, headerdata)? {
            match up { // TODO lots of boilerplate!
                Update::Account(addy, opt_data) => {
                    match opt_data {
                        Some(data) => self.accounts.insert(&addy, data).map_err(|_| txn::Error::NoPreimage)?,
                        None => self.accounts.remove(&addy).map_err(|_| txn::Error::NoPreimage)?
                    };
                },
                Update::Validator(addy, opt_data) => {
                    match opt_data {
                        Some(data) => self.validators.insert(&addy, data).map_err(|_| txn::Error::NoPreimage)?,
                        None => self.validators.remove(&addy).map_err(|_| txn::Error::NoPreimage)?
                    };
                },
                Update::Slot(slot, opt_data) => {
                    match opt_data {
                        Some(data) => self.slots.insert(&slot, data).map_err(|_| txn::Error::NoPreimage)?,
                        None => self.slots.remove(&slot).map_err(|_| txn::Error::NoPreimage)?
                    };
                },
                Update::Senator(addy, opt_data) => {
                    match opt_data {
                        Some(data) => self.senators.insert(&addy, data).map_err(|_| txn::Error::NoPreimage)?,
                        None => self.senators.remove(&addy).map_err(|_| txn::Error::NoPreimage)?
                    };
                },
                Update::Rollup(addy, opt_data) => {
                    match opt_data {
                        Some(data) => self.rollups.insert(&addy, data).map_err(|_| txn::Error::NoPreimage)?,
                        None => self.rollups.remove(&addy).map_err(|_| txn::Error::NoPreimage)?
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
                alice.send(bob.kp.public, 1 << 15, JENNY_SLOTS, None)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                alice.send(charlie.kp.public, 1 << 5, JENNY_SLOTS + 1, None)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                bob.send(charlie.kp.public, 1 << 1, 0, None)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                charlie.send(bob.kp.public, (1 << 5) + (1 << 1), 0, None)
            )
            .is_ok()
        );
        assert!(
            builder.add(
                alice.send(bob.kp.public, 1 << 8, JENNY_SLOTS + 2, None)
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
            payload: txn::Payload::Payment(
                    Sha256::digest(alice.kp.public.to_bytes()).into(),
                    1
                ),
            nonce: 0,
            opt_rollup: None
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
            payload: txn::Payload::Payment(
                    Sha256::digest(bob.kp.public.to_bytes()).into(),
                    1
                ),
            nonce: JENNY_SLOTS,
            opt_rollup: None
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
            payload: txn::Payload::Payment(
                    Sha256::digest(bob.kp.public.to_bytes()).into(),
                    1
                ),
            nonce: JENNY_SLOTS,
            opt_rollup: None
        };
        let other_msg = txn::Txn {
            payload: txn::Payload::Payment(
                    Sha256::digest(bob.kp.public.to_bytes()).into(),
                    2
                ),
            nonce: JENNY_SLOTS,
            opt_rollup: None
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
        let unstake = alice.unstake(&builder.state.validators, 0);
        let slot = if let txn::Payload::Unstake(slot) = unstake.msg.payload {
            slot
        } else {
            panic!("unreachable")
        };
        let msg = txn::Txn {
            payload: txn::Payload::Stake(slot),
            opt_rollup: None,
            nonce: JENNY_SLOTS
        };
        assert_eq!(
            builder.add(account::Signed::<txn::Txn> {
                msg: msg.clone(),
                sig: alice.sign(&msg),
                from: alice.kp.public
            }).map_err(|e| e.1), 
            Err(txn::Error::BadStakeIdx)
        );
        let stake = alice.stake(&builder.state.validators, 0);
        let slot = if let txn::Payload::Stake(slot) = unstake.msg.payload {
            slot
        } else {
            panic!("unreachable")
        };
        let msg = txn::Txn {
            payload: txn::Payload::Unstake(slot),
            opt_rollup: None,
            nonce: JENNY_SLOTS
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
    fn insuffbal() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let bob = account::Keypair::gen();
        assert_eq!(
            builder.add(alice.send(bob.kp.public, JENNY_COINS + 1, JENNY_SLOTS, None)).map_err(|e| e.1), 
            Err(txn::Error::InsuffBal)
        );
    }

    #[test]
    fn insuffstake() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let bob = account::Keypair::gen();
        let txn = bob.stake(&builder.state.validators, 0);
        assert_eq!(
            builder.add(txn).map_err(|e| e.1), 
            Err(txn::Error::InsuffStake)
        );
    }

    #[test]
    fn smallnonce() {
        let (alice, snap) = <(account::Keypair, block::Snap)>::default();
        let mut builder = block::Builder::new(&alice, 1, &snap);
        let bob = account::Keypair::gen();
        assert!(
            builder.add(alice.send(bob.kp.public, 1, JENNY_SLOTS, None)).is_ok()
        );
        assert_eq!(
            builder.add(alice.send(bob.kp.public, 1, JENNY_SLOTS, None)).map_err(|e| e.1), 
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
            builder.add(alice.send(bob.kp.public, 1, JENNY_SLOTS, None)).is_ok()
        );
        assert_eq!(
            old.add(alice.send(bob.kp.public, 1, JENNY_SLOTS + 1, None)).map_err(|e| e.1), 
            Err(txn::Error::BigNonce)
        );
    }
    
    
}
