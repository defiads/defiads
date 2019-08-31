//
// Copyright 2019 Tamas Blummer
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use bitcoin::network::constants::Network;
use bitcoin_hashes::{sha256, sha256d};
use bitcoin_wallet::account::{MasterAccount, Unlocker, AccountAddressType, Account, MasterKeyEntropy};
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::{Block, Transaction, Address, TxIn, Script, TxOut, SigHashType, PublicKey};
use bitcoin_wallet::proved::ProvedTransaction;
use bitcoin_wallet::coins::{Coins};
use crate::error::BiadNetError;
use rand::{RngCore, thread_rng};
use bitcoin::consensus::serialize;
use crate::trunk::Trunk;
use std::sync::Arc;
use crate::funding::funding_script;

pub const KEY_LOOK_AHEAD: u32 = 10;
const KEY_PURPOSE: u32 = 0xb1ad;
const DUST :u64 = 546;
const MAX_FEE_PER_VBYTE: u64 = 100;
const MIN_FEE_PER_VBYTE: u64 = 1;
const MAX_TERM:u16 = 6*24*30; // approx. one month.
const RBF:u32 = 0xffffffff - 2;

pub struct Wallet {
    coins: Coins,
    pub master: MasterAccount
}

impl Wallet {
    pub fn master_public (&self) ->&ExtendedPubKey {
        &self.master.master_public()
    }

    pub fn encrypted(&self) -> &Vec<u8> {
        &self.master.encrypted()
    }

    pub fn birth (&self) -> u64 {
        self.master.birth()
    }

    pub fn coins(&self) -> &Coins {
        &self.coins
    }

    pub fn balance(&self) -> u64 {
        self.coins.confirmed_balance() + self.coins.unconfirmed_balance()
    }

    pub fn confirmed_balance(&self) -> u64 {
        self.coins.confirmed_balance()
    }

    pub fn unconfirmed_balance(&self) -> u64 {
        self.coins.unconfirmed_balance()
    }

    pub fn available_balance<H>(&self, height: u32, height_for_block: H) -> u64
        where H: Fn(&sha256d::Hash) -> Option<u32> {
        self.coins.available_balance(height, height_for_block)
    }

    pub fn unwind_tip(&mut self, block_hash: &sha256d::Hash) {
        self.coins.unwind_tip(block_hash)
    }

    pub fn rescan(&mut self) {
        self.coins = Coins::new();
    }

    pub fn process(&mut self, block: &Block) -> bool {
        self.coins.process(&mut self.master, block)
    }

    pub fn prove (&self, txid: &sha256d::Hash) -> Option<&ProvedTransaction> {
        self.coins.proofs().get(txid)
    }

    pub fn fund (&mut self, id: &sha256::Hash, mut term: u16, passpharse: String, mut fee_per_vbyte: u64, amount: u64, trunk: Arc<dyn Trunk>) -> Result<(Transaction, PublicKey), BiadNetError> {
        let network = self.master.master_public().network;
        let mut unlocker = Unlocker::new(
            self.master.encrypted(), passpharse.as_str(), None,
            network, Some(self.master.master_public()))?;
        fee_per_vbyte = std::cmp::min(MAX_FEE_PER_VBYTE, std::cmp::max(MIN_FEE_PER_VBYTE, fee_per_vbyte));
        term = std::cmp::min(MAX_TERM, term);
        let mut fee = 0;
        let change_address = self.master.get_mut((0,1)).unwrap().next_key().unwrap().address.clone();
        let height = trunk.len();
        let coins = self.coins.get_confirmed_coins(amount, height, |h| trunk.get_height(h));
        let total_input = coins.iter().map(|(_,c,_)|c.output.value).sum::<u64>();
        let contract_address;
        let funder;
        {
            let commit_account = self.master.get_mut((1, 0)).unwrap();
            let next_key = commit_account.next();
            funder = commit_account.compute_base_public_key(next_key).expect("can not compute base public key");
            let script_code = funding_script(&funder, id, term, unlocker.context());
            let kix = commit_account.add_script_key(funder, script_code, Some(&id[..]), Some(term)).expect("can not commit to ad");
            contract_address = commit_account.get_key(kix).unwrap().address.clone();
        }
        if amount > total_input {
            return Err(BiadNetError::Unsupported("insufficient funds"));
        }
        let mut tx = Transaction {
            input: coins.iter().map(|(point, coin, h)|
                TxIn {
                    previous_output: point.clone(),
                    script_sig: Script::new(),
                    sequence: if let Some(csv) = coin.derivation.csv {
                        std::cmp::min(csv as u32, height - *h)
                    }else{RBF},
                    witness: vec![]
                }).collect(),
            output: Vec::new(),
            version: 2,
            lock_time: 0
        };
        loop {
            tx.output.clear();
            if amount - fee > DUST {
                tx.output.push(TxOut {
                    value: amount - fee,
                    script_pubkey: contract_address.script_pubkey()
                });
            }
            else {
                return Err(BiadNetError::Unsupported("withdraw amount is less than the fees needed (+DUST limit)"));
            }
            if total_input > amount && (total_input - amount) > DUST {
                tx.output.insert((thread_rng().next_u32() % 2) as usize, TxOut {
                    value: total_input - amount,
                    script_pubkey: change_address.script_pubkey()
                });
            }
            self.master.sign(&mut tx, SigHashType::All, &|point| {
                coins.iter().find(|(o, _, _)| *o == *point).map(|(_, c,_)| c.output.clone())
            }, &mut unlocker)?;
            if fee == 0 {
                fee = (tx.get_weight() as u64 * fee_per_vbyte + 3)/4;
            }
            else {
                let txs = serialize(&tx);
                for (idx, (_, coin,_)) in coins.iter().enumerate() {
                    coin.output.script_pubkey.verify(idx, coin.output.value, txs.as_slice())?;
                }
                if tx.output.len() > 1 {
                    debug!("compiled transaction to fund {} change to {}, fee {}", id, change_address, fee);
                }
                else {
                    debug!("compiled transaction to fund {} fee {}", id, fee);
                }
                break;
            }
        }
        self.coins.process_unconfirmed_transaction(&mut self.master, &tx);
        Ok((tx, funder))
    }

    pub fn withdraw (&mut self, passpharse: String, address: Address, mut fee_per_vbyte: u64, amount: Option<u64>, trunk: Arc<dyn Trunk>) -> Result<Transaction, BiadNetError> {
        let network = self.master.master_public().network;
        let mut unlocker = Unlocker::new(
            self.master.encrypted(), passpharse.as_str(), None,
            network, Some(self.master.master_public()))?;
        let balance = self.confirmed_balance();
        let amount = amount.unwrap_or(balance);
        fee_per_vbyte = std::cmp::min(MAX_FEE_PER_VBYTE, std::cmp::max(MIN_FEE_PER_VBYTE, fee_per_vbyte));
        let mut fee = 0;
        let change_address = self.master.get_mut((0,1)).unwrap().next_key().unwrap().address.clone();
        let height = trunk.len();
        let coins = self.coins.get_confirmed_coins(amount, height, |h| trunk.get_height(h));
        let total_input = coins.iter().map(|(_,c,_)|c.output.value).sum::<u64>();
        if amount > total_input {
            return Err(BiadNetError::Unsupported("insufficient funds"));
        }
        let mut tx = Transaction {
            input: coins.iter().map(|(point, coin, h)|
                TxIn {
                    previous_output: point.clone(),
                    script_sig: Script::new(),
                    sequence: if let Some(csv) = coin.derivation.csv {
                        std::cmp::min(csv as u32, height - *h)
                    }else{RBF},
                    witness: vec![]
                }).collect(),
            output: Vec::new(),
            version: 2,
            lock_time: 0
        };
        loop {
            tx.output.clear();
            if amount - fee > DUST {
                tx.output.push(TxOut {
                    value: amount - fee,
                    script_pubkey: address.script_pubkey()
                });
            }
            else {
                return Err(BiadNetError::Unsupported("withdraw amount is less than the fees needed (+DUST limit)"));
            }
            if total_input > amount && (total_input - amount) > DUST {
                tx.output.insert((thread_rng().next_u32() % 2) as usize, TxOut {
                    value: total_input - amount,
                    script_pubkey: change_address.script_pubkey()
                });
            }
            self.master.sign(&mut tx, SigHashType::All, &|point| {
                coins.iter().find(|(o, _, _)| *o == *point).map(|(_, c,_)| c.output.clone())
            }, &mut unlocker)?;
            if fee == 0 {
                fee = (tx.get_weight() as u64 * fee_per_vbyte + 3)/4;
            }
            else {
                let txs = serialize(&tx);
                for (idx, (_, coin,_)) in coins.iter().enumerate() {
                    coin.output.script_pubkey.verify(idx, coin.output.value, txs.as_slice())?;
                }
                if tx.output.len() > 1 {
                    debug!("compiled transaction to withdraw {} to {}, change to {}, fee {}", amount - fee, address, change_address, fee);
                }
                else {
                    debug!("compiled transaction to withdraw {} to {}, fee {}", amount - fee, address, fee);
                }
                break;
            }
        }
        self.coins.process_unconfirmed_transaction(&mut self.master, &tx);
        Ok(tx)
    }

    pub fn from_storage(coins: Coins, mut master: MasterAccount) -> Wallet {
        for (_, coin) in coins.confirmed() {
            let ref d = coin.derivation;
            master.get_mut((d.account, d.sub)).unwrap().do_look_ahead(Some(d.kix)).expect("can not look ahead of storage");
        }
        for (_, coin) in coins.unconfirmed() {
            let ref d = coin.derivation;
            master.get_mut((d.account, d.sub)).unwrap().do_look_ahead(Some(d.kix)).expect("can not look ahead of storage");
        }
        Wallet { coins: coins, master }
    }

    pub fn from_encrypted(encrypted: &[u8], public_master_key: ExtendedPubKey, birth: u64) -> Wallet {
        let master = MasterAccount::from_encrypted(encrypted, public_master_key, birth);
        Wallet { coins: Coins::new(), master}
    }

    pub fn new(bitcoin_network: Network) -> Wallet {
        eprintln!();
        eprintln!("============================= Initializing bitcoin wallet =================================");
        eprintln!("The randomly generated key for your wallet will be stored ENCRYPTED in the config-file");
        eprintln!();
        eprint!("Set wallet encryption password (minimum length 8):");
        let mut password = String::new();
        std::io::stdin().read_line(&mut password).expect("expecting a password");
        password.remove(password.len()-1); // remove EOL
        assert!(password.len() >= 8, "Password should have at least 8 characters");
        let mut master = MasterAccount::new(MasterKeyEntropy::Recommended, bitcoin_network,
                                                password.as_str(), None).expect("can not generate wallet");
        let mut unlocker = Unlocker::new(master.encrypted().as_slice(),
                                         password.as_str(), None, bitcoin_network,
                                         Some(&master.master_public())).expect("Internal error in wallet generation");
        let receiver = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 0, 0, KEY_LOOK_AHEAD)
            .expect("can not create receiver account");
        master.add_account(receiver);
        let change = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 0, 1, KEY_LOOK_AHEAD)
            .expect("can not create change account");
        master.add_account(change);
        let commitments = Account::new(&mut unlocker, AccountAddressType::P2WSH(KEY_PURPOSE), 1, 0, 0)
            .expect("can not create commitments account");
        master.add_account(commitments);
        let receiver = master.get((0,0)).unwrap().get_key(0).unwrap().address.clone();
        eprintln!();
        eprintln!("You will need the encryption password to use the funds with biadnet.");
        eprintln!();
        eprintln!("Uncommitted funds in the wallet can also be accessed with programs and devices");
        eprintln!("compatible with BIP32, BIP39, BIP44, BIP49, BIP84, such as TREZOR or Ledger");
        eprintln!();
        eprintln!("Write down the following human readable key,");
        eprintln!("to evtl. restore your biadnet wallet or import into compatible programs and devices.");
        eprintln!();
        for (i, word) in master.mnemonic(password.as_str()).unwrap().iter().enumerate() {
            eprintln!("{} {}", i+1, word);
        }
        eprintln!();
        eprintln!("Compatible programs and devices should show if initialized with above key,");
        eprintln!("this first receiver address (BIP44 keypath: m/49'/0'/0/0): {}", receiver);
        eprintln!();
        eprint!("Did you write above words down, then answer with yes:");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).expect("expecting yes");
        answer.remove(answer.len()-1); // remove EOL
        assert_eq!(answer, "yes", "expecting yes");
        eprintln!("===========================================================================================");
        eprintln!();
        Wallet {
            master,
            coins: Coins::new()
        }
    }
}