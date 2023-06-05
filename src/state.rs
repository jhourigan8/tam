use either::Either;
use sha2::{Sha256, Digest};

use crate::merkle::MerkleMap;
use crate::account::{self, Signed};
use crate::validator;
use crate::txn::Txn;

pub const VALIDATOR_ROOT: account::Account = [0u8; 32];
pub const VALIDATOR_SLOTS: u32 = 256;
pub const VALIDATOR_STAKE: u32 = 1024;
const _MAX_FORK: u32 = 128;

#[derive(Debug, Clone)]
pub struct BlockBuilder {
    pub txnseq: MerkleMap<Signed<Txn>>,
    pub count: u32,
    pub state: State
}

impl BlockBuilder {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxnError {
    BadFromPk,
    BadSig,
    BadToPk,
    BadValidPk,
    BadStakeIdx,
    InsuffBal,
    InsuffStake,
    SmallNonce,
    BigNonce,
}

impl State {
    fn verify(&self, stxn: &Signed<Txn>) -> Result<([u8; 32], account::Data, Either<account::Data, ([u8; 4], validator::Data)>), TxnError> {
        let from_addy: [u8; 32] = Sha256::digest(&stxn.from.to_bytes()).into();
        let mut from_account = self.accounts.get(&from_addy)
            .ok_or(TxnError::BadFromPk)?
            .clone();
        if !stxn.verify() {
            return Err(TxnError::BadSig);
        }
        /* --- from old bls ---
        let from_pk = PublicKey::from_bytes(&stxn.from).unwrap();
        let sig = Signature::from_bytes(&stxn.sig)
            .map_err(|_| TxnError::BadSig)?;
        if BLST_ERROR::BLST_SUCCESS != sig.verify(
            true, serde_json::to_string(&stxn.msg).expect("").as_bytes(), &[], &[], &from_pk, true
        ) {
            return Err(TxnError::BadSig);
        }
        */
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
            if stxn.msg.amount < VALIDATOR_STAKE {
                return Err(TxnError::InsuffStake);
            }
            let validator_pk = match stxn.msg.data.get("validator") {
                None => Err(TxnError::BadValidPk),
                Some(val_pk_bytes) => 
                    blst::min_sig::PublicKey::from_bytes(val_pk_bytes)
                        .map_err(|_| TxnError::BadStakeIdx)
            }?;
            let idx: [u8; 4] = match stxn.msg.data.get("idx") {
                None => {println!("a"); Err(TxnError::BadStakeIdx)},
                Some(idx_bytes) => {
                    println!("idx bytes {:?}", idx_bytes);
                    idx_bytes
                        .clone()
                        .try_into()
                        .map_err(|_| {println!("c"); TxnError::BadStakeIdx})
                }
            }?;
            if self.validators.get(&idx).is_some() {
                println!("b");
                return Err(TxnError::BadStakeIdx);
            }
            Ok((
                from_addy, 
                from_account, 
                Either::Right((
                    idx,
                    validator::Data { 
                        round: self.round, 
                        owner: stxn.from.clone(), 
                        validator: validator_pk.to_bytes()
                    }
                ))
            ))
        } else {
            match self.accounts.get(&stxn.msg.to) {
                Some(to_account) => {
                    let mut to_account = to_account.clone();
                    if from_addy != stxn.msg.to {
                        to_account.bal += stxn.msg.amount;
                    } else {
                        to_account.nonce += 1;
                    }
                    Ok((from_addy, from_account, Either::Left(to_account)))
                }
                None => {
                    Ok((from_addy, from_account, Either::Left(account::Data { bal: stxn.msg.amount, nonce: 0 })))
                }
            }
        }
    }

    pub fn apply<'a> (&mut self, stxn: &'a Signed<Txn>) -> Result<(), TxnError> {
        let accs = self.verify(stxn)?;
        match accs {
            (from_addy, from_acc, Either::Left(to_acc)) => {
                self.accounts.insert(&from_addy, from_acc);
                self.accounts.insert(&stxn.msg.to, to_acc);
            },
            (from_addy, from_acc, Either::Right((idx, stake_data))) => {
                self.accounts.insert(&from_addy, from_acc);
                self.validators.insert(
                    &idx,
                    stake_data
                );
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
    use super::*;

    pub fn setup() -> (account::Keypair, BlockBuilder) {
        let alice = account::Keypair::gen();
        let mut state = State {
            accounts: MerkleMap::default(),
            validators: MerkleMap::default(),
            round: 0,
            seed: [0u8; 32]
        };
        state.accounts.insert(
            &Sha256::digest(alice.kp.public.to_bytes()),
            account::Data { bal: 1 << 17, nonce: 0 }
        );
        let builder = BlockBuilder {
            txnseq: MerkleMap::<Signed<Txn>>::default(),
            count: 0,
            state
        };
        (alice, builder)
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
        assert!(old_accs.contains(&&account::Data { bal: (1 << 17), nonce: 0 })); // alice
        let new_accs = builder.state.accounts.iter().collect::<Vec<&account::Data>>();
        println!("{:?}", new_accs);
        assert!(new_accs.contains(&&account::Data { bal: (1 << 17) - (1 << 15) - (1 << 5) - (1 << 8), nonce: 3 })); // alice
        assert!(new_accs.contains(&&account::Data { bal: (1 << 15) + (1 << 5) + (1 << 8), nonce: 1 })); // bob
        assert!(new_accs.contains(&&account::Data { bal: 0, nonce: 1 })); // charlie
    }

    #[test]
    fn validators() {
        let (alice, mut builder) = setup();
        let bob = account::Keypair::gen();
        println!("{:?}", builder.add(
            alice.send(bob.kp.public, 1 << 15,  &builder.state)
        ));
        let alice_val = validator::Keypair::gen();
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
        assert_eq!(builder.state.validators.iter().filter(|s| s.owner == alice.kp.public).count(), 64);
        assert_eq!(builder.state.validators.iter().filter(|s| s.owner == bob.kp.public).count(), 16);
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
    
}
