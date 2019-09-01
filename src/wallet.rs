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

    pub fn fund<W> (&mut self, id: &sha256::Hash, mut term: u16, passpharse: String, mut fee_per_vbyte: u64, amount: u64, trunk: Arc<dyn Trunk>, scripter: W) -> Result<(Transaction, PublicKey, u64), BiadNetError>
        where W: FnOnce(&PublicKey, Option<u16>) -> Script {
        let network = self.master.master_public().network;
        let mut unlocker = Unlocker::new(
            self.master.encrypted(), passpharse.as_str(), None,
            network, Some(self.master.master_public()))?;
        fee_per_vbyte = std::cmp::min(MAX_FEE_PER_VBYTE, std::cmp::max(MIN_FEE_PER_VBYTE, fee_per_vbyte));
        term = std::cmp::min(MAX_TERM, term);
        let mut fee = 0;
        let change_address = self.master.get_mut((0,1)).unwrap().next_key().unwrap().address.clone();
        let height = trunk.len();
        let coins = self.coins.choose_inputs(amount, height, |h| trunk.get_height(h));
        let total_input = coins.iter().map(|(_,c,_)|c.output.value).sum::<u64>();
        let contract_address;
        let funder;
        {
            let commit_account = self.master.get_mut((1, 0)).unwrap();
            let kix = commit_account.add_script_key(scripter, Some(&id[..]), Some(term)).expect("can not commit to ad");
            contract_address = commit_account.get_key(kix).unwrap().address.clone();
            funder = commit_account.compute_base_public_key(kix).expect("can not compute base public key");
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
            if self.master.sign(&mut tx, SigHashType::All,
                                &|point| {
                                    coins.iter().find(|(o, _, _)| *o == *point).map(|(_, c, _)| c.output.clone())
                                }, &mut unlocker)?
                != tx.input.len () {
                error!("could not sign all inputs of our transaction {:?} {}", tx, hex::encode(serialize(&tx)));
                return Err(BiadNetError::Unsupported("could not sign for all inputs"));
            }
            if fee == 0 {
                fee = (tx.get_weight() as u64 * fee_per_vbyte + 3)/4;
            }
            else {
                match tx.verify(|o| coins.iter().find_map(|(p, c, _)| if *p == *o { Some(c.output.clone())} else {None})) {
                    Ok(()) => debug!("compiled transaction to fund {} fee {}", id, fee),
                    Err(e) => {
                        error!("our transaction does not verify {:?} {}", tx, hex::encode(serialize(&tx)));
                        return Err(BiadNetError::Script(e))
                    }
                }
                break;
            }
        }
        self.coins.process_unconfirmed_transaction(&mut self.master, &tx);
        Ok((tx, funder, fee))
    }

    pub fn withdraw (&mut self, passpharse: String, address: Address, mut fee_per_vbyte: u64, amount: Option<u64>, trunk: Arc<dyn Trunk>) -> Result<(Transaction, u64), BiadNetError> {
        let network = self.master.master_public().network;
        let mut unlocker = Unlocker::new(
            self.master.encrypted(), passpharse.as_str(), None,
            network, Some(self.master.master_public()))?;
        let height = trunk.len();
        let balance = self.available_balance(height, |h| trunk.get_height(h));
        let amount = amount.unwrap_or(balance);
        fee_per_vbyte = std::cmp::min(MAX_FEE_PER_VBYTE, std::cmp::max(MIN_FEE_PER_VBYTE, fee_per_vbyte));
        let mut fee = 0;
        let change_address = self.master.get_mut((0,1)).unwrap().next_key().unwrap().address.clone();
        let coins = self.coins.choose_inputs(amount, height, |h| trunk.get_height(h));
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
            if self.master.sign(&mut tx, SigHashType::All,
                                &|point| {
                                    coins.iter().find(|(o, _, _)| *o == *point).map(|(_, c, _)| c.output.clone())
                                }, &mut unlocker)?
                != tx.input.len () {
                error!("could not sign all inputs of our transaction {:?} {}", tx, hex::encode(serialize(&tx)));
                return Err(BiadNetError::Unsupported("could not sign for all inputs"));
            }
            if fee == 0 {
                fee = (tx.get_weight() as u64 * fee_per_vbyte + 3)/4;
            }
            else {
                match tx.verify(|o| coins.iter().find_map(|(p, c, _)| if *p == *o { Some(c.output.clone())} else {None})) {
                    Ok(()) => debug!("compiled transaction to withdraw {} fee {}", amount, fee),
                    Err(e) => {
                        error!("our transaction does not verify {:?} {}", tx, hex::encode(serialize(&tx)));
                        return Err(BiadNetError::Script(e))
                    }
                }
                break;
            }
        }
        self.coins.process_unconfirmed_transaction(&mut self.master, &tx);
        Ok((tx, fee))
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

#[cfg(test)]
mod test {
    use crate::wallet::Wallet;
    use bitcoin::{network::constants::Network, blockdata::opcodes::all, BlockHeader, Block, BitcoinHash, util::bip32::ExtendedPubKey, Address, Transaction, TxIn, OutPoint, TxOut, PublicKey};
    use std::{
        sync::{Arc, Mutex},
        str::FromStr
    };
    use bitcoin_hashes::{sha256, sha256d};
    use crate::trunk::Trunk;
    use bitcoin::blockdata::constants::genesis_block;
    use std::time::{SystemTime, UNIX_EPOCH};
    use bitcoin::util::hash::MerkleRoot;
    use bitcoin_wallet::account::{Account, AccountAddressType, Unlocker};
    use bitcoin::blockdata::script::Builder;
    use crate::store::ContentStore;

    const NEW_COINS:u64 = 1000000000;
    const PASSPHRASE:&str = "whatever";

    struct TestTrunk {
        trunk: Arc<Mutex<Vec<BlockHeader>>>
    }

    impl TestTrunk {
        fn extend(&self, header: &BlockHeader) {
            self.trunk.lock().unwrap().push(header.clone());
        }
    }

    impl Trunk for TestTrunk {
        fn is_on_trunk(&self, block_hash: &sha256d::Hash) -> bool {
            self.trunk.lock().unwrap().iter().any(|h| h.bitcoin_hash() == *block_hash)
        }

        fn get_header(&self, block_hash: &sha256d::Hash) -> Option<BlockHeader> {
            self.trunk.lock().unwrap().iter().find(|h| h.bitcoin_hash() == *block_hash).map(|h| h.clone())
        }

        fn get_header_for_height(&self, height: u32) -> Option<BlockHeader> {
            self.trunk.lock().unwrap().get(height as usize).map(|h| h.clone())
        }

        fn get_height(&self, block_hash: &sha256d::Hash) -> Option<u32> {
            self.trunk.lock().unwrap().iter().enumerate().find_map(|(i, h)| if h.bitcoin_hash() == *block_hash {Some(i as u32)} else {None})
        }

        fn get_tip(&self) -> Option<BlockHeader> {
            let len = self.trunk.lock().unwrap().len();
            if len > 0 {
                self.trunk.lock().unwrap().get(len - 1).map(|h| h.clone())
            }
            else {
                None
            }
        }

        fn len(&self) -> u32 {
            self.trunk.lock().unwrap().len() as u32
        }
    }

    fn new_wallet () -> Wallet {
        let mut wallet = Wallet::from_encrypted(
            hex::decode("0e05ba48bb0fdc7285dc9498202aeee5e1777ac4f55072b30f15f6a8632ad0f3fde1c41d9e162dbe5d3153282eaebd081cf3b3312336fc56f5dd18a2df6ea48c1cdd11a1ed11281cd2e0f864f02e5bed5ab03326ed24e43b8a184acff9cb4e730db484e33f2b24295a97b2ca87871a69384eb64d4160ce8b3e8b4d90234040970e531d4333a8979dbe533c2b2668bf43b6607b2d24c5b42765ebfdd075fd173c").unwrap().as_slice(),
            ExtendedPubKey::from_str("tpubD6NzVbkrYhZ4XKz4vgwBmnnVmA7EgWhnXvimQ4krq94yUgcSSbroi4uC1xbZ3UGMxG9M2utmaPjdpMrWW2uKRY9Mj4DZWrrY8M4pry8shsK").unwrap(),
            1567260002);
        let mut unlocker = Unlocker::new_for_master(&wallet.master, PASSPHRASE, None).unwrap();
        wallet.master.add_account(Account::new(&mut unlocker, AccountAddressType::P2WPKH, 0, 0, 10).unwrap());
        wallet.master.add_account(Account::new(&mut unlocker, AccountAddressType::P2WPKH, 0, 1, 10).unwrap());
        wallet.master.add_account(Account::new(&mut unlocker, AccountAddressType::P2WSH(4711), 1, 0, 0).unwrap());
        wallet
    }

    fn new_block (prev: &sha256d::Hash) -> Block {
        Block {
            header :BlockHeader {
                version: 1,
                time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32,
                nonce: 0,
                bits: 0x1d00ffff,
                prev_blockhash: prev.clone(),
                merkle_root: sha256d::Hash::default()
            },
            txdata: Vec::new()
        }
    }

    fn coin_base(miner: &Address, height: u32) -> Transaction {
        Transaction {
            version: 2,
            lock_time: 0,
            input: vec!(TxIn {
                sequence: 0xffffffff,
                witness: Vec::new(),
                previous_output: OutPoint{ txid: sha256d::Hash::default(), vout: 0 },
                script_sig: Builder::new().push_int(height as i64).into_script()
            }),
            output: vec!(TxOut{
                value: NEW_COINS,
                script_pubkey: miner.script_pubkey()
            })
        }
    }

    fn add_tx (block: &mut Block, tx: Transaction) {
        block.txdata.push(tx);
        block.header.merkle_root = block.merkle_root();
    }

    fn mine(tip: &sha256d::Hash, height: u32, miner: &Address) -> Block {
        let mut block = new_block(tip);
        add_tx(&mut block, coin_base(miner, height));
        block
    }


    #[test]
    pub fn test () {
        let trunk = Arc::new(
            TestTrunk{trunk: Arc::new(Mutex::new(Vec::new()))});
        let mut wallet = new_wallet();
        let genesis = genesis_block(Network::Testnet);
        let miner = wallet.master.get_mut((0,0)).unwrap().next_key().unwrap().address.clone();

        trunk.extend(&genesis.header);
        wallet.process(&genesis);

        let next = mine(&genesis.bitcoin_hash(), 1, &miner);
        trunk.extend(&next.header);
        wallet.process(&next);

        assert_eq!(wallet.balance(), NEW_COINS);

        let burn = Address::p2shwsh(&Builder::new().push_opcode(all::OP_VERIFY).into_script(), Network::Testnet);
        let (burn_half, _) = wallet.withdraw(PASSPHRASE.to_string(), burn, 1, Some(NEW_COINS/2), trunk.clone()).unwrap();

        let mut next = mine(&next.bitcoin_hash(), 2, &miner);
        add_tx(&mut next, burn_half);
        trunk.extend(&next.header);
        wallet.process(&next);
        assert_eq!(wallet.balance(), NEW_COINS + NEW_COINS/2);

        let (fund, _, fee) = wallet.fund(&sha256::Hash::default(), 1, PASSPHRASE.to_string(), 5, NEW_COINS/10, trunk.clone(),
            |pk: &PublicKey, term: Option<u16>| {
                ContentStore::funding_script(pk, term.unwrap())
            }).unwrap();

        let mut next = mine(&next.bitcoin_hash(), 3, &miner);
        add_tx(&mut next, fund);
        trunk.extend(&next.header);
        wallet.process(&next);
        assert_eq!(wallet.balance(), 2*NEW_COINS + NEW_COINS/2 - fee);
        assert_eq!(wallet.available_balance(3, |h| trunk.get_height(h)), 2*NEW_COINS + NEW_COINS/2 - NEW_COINS/10);

        let next = mine(&next.bitcoin_hash(), 4, &miner);
        trunk.extend(&next.header);
        wallet.process(&next);
        assert_eq!(wallet.balance(), 3*NEW_COINS + NEW_COINS/2 - fee);
        assert_eq!(wallet.available_balance(4, |h| trunk.get_height(h)), 3*NEW_COINS + NEW_COINS/2 - fee);
    }
}