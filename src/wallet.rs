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
use bitcoin_hashes::sha256d;
use bitcoin_wallet::account::{MasterAccount, Unlocker, AccountAddressType, Account, MasterKeyEntropy};
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::{Block};
use bitcoin_wallet::proved::ProvedTransaction;
use bitcoin_wallet::coins::Coins;

const KEY_LOOK_AHEAD: u32 = 10;
const KEY_PURPOSE: u32 = 0xb1ad;

pub struct Wallet {
    coins: Coins,
    pub master: MasterAccount,
    look_ahead: u32
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

    pub fn look_ahead(&self) -> u32 {
        self.look_ahead
    }

    pub fn coins(&self) -> &Coins {
        &self.coins
    }

    pub fn unwind_tip(&mut self, block_hash: &sha256d::Hash) {
        self.coins.unwind_tip(block_hash)
    }

    pub fn process(&mut self, block: &Block) -> bool {
        self.coins.process(&mut self.master, block)
    }

    pub fn prove (&self, txid: &sha256d::Hash) -> Option<&ProvedTransaction> {
        self.coins.proofs().get(txid)
    }

    pub fn from_storage(coins: Coins, master: MasterAccount, look_ahead: u32) -> Wallet {
        Wallet { coins, master, look_ahead }
    }

    pub fn from_encrypted(encrypted: &[u8], public_master_key: ExtendedPubKey, birth: u64, look_ahead: u32) -> Wallet {
        let master = MasterAccount::from_encrypted(encrypted, public_master_key, birth);
        Wallet { coins: Coins::new(), master, look_ahead}
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
            coins: Coins::new(),
            look_ahead: KEY_LOOK_AHEAD
        }
    }
}