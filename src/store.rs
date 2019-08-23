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

//! store

use bitcoin::{BlockHeader, BitcoinHash, Block, Address};
use bitcoin_hashes::{sha256, sha256d};
use secp256k1::{Secp256k1, All};
use std::sync::{RwLock, Arc};

use crate::error::BiadNetError;
use crate::content::Content;
use crate::funding::funding_script;
use crate::db::{SharedDB, RetrievedContent};
use crate::iblt::IBLT;
use crate::content::ContentKey;

use std::collections::HashMap;
use crate::iblt::add_to_min_sketch;
use crate::trunk::Trunk;
use crate::wallet::Wallet;
use bitcoin::network::message::NetworkMessage;
use crate::sendtx::TxSender;

const MIN_SKETCH_SIZE: usize = 20;

pub type SharedContentStore = Arc<RwLock<ContentStore>>;

/// the distributed content storage
pub struct ContentStore {
    ctx: Secp256k1<All>,
    trunk: Arc<dyn Trunk + Send + Sync>,
    db: SharedDB,
    storage_limit: u64,
    iblts: HashMap<u32, IBLT<ContentKey>>,
    min_sketch: Vec<u64>,
    ksequence: Vec<(u64, u64)>,
    n_keys: u32,
    wallet: Wallet,
    txout: Option<TxSender>
}

impl ContentStore {
    /// new content store
    pub fn new(db: SharedDB, storage_limit: u64, trunk: Arc<dyn Trunk + Send + Sync>, wallet: Wallet) -> Result<ContentStore, BiadNetError> {
        let mut mins;
        let ksequence;
        let n_keys;
        {
            let mut db = db.lock().unwrap();
            let mut tx = db.transaction();
            let (m, k, n) = tx.compute_content_sketch(MIN_SKETCH_SIZE)?;
            mins = m;
            ksequence = k;
            n_keys = n;
        }
        Ok(ContentStore {
            ctx: Secp256k1::new(),
            trunk,
            db,
            storage_limit,
            iblts: HashMap::new(),
            min_sketch: mins,
            ksequence,
            n_keys,
            wallet,
            txout: None
        })
    }

    pub fn set_tx_sender(&mut self, txout: TxSender) {
        self.txout = Some(txout);
    }

    pub fn deposit_address(&mut self) -> Address {
        self.wallet.master.get_mut((0,0)).expect("can not find 0/0 account")
            .next_key().expect("can not generate receiver address in 0/0").address.clone()
    }

    pub fn withdraw (&mut self, passpharse: String, address: Address, fee_per_vbyte: u64, amount: Option<u64>) -> Result<sha256d::Hash, BiadNetError> {
        let tx = self.wallet.withdraw(passpharse, address, fee_per_vbyte, amount)?;
        let txid = tx.txid();
        if let Some(ref txout) = self.txout {
            txout.send(NetworkMessage::Tx(tx));
        }
        Ok(txid)
    }

    pub fn get_nkeys (&self) -> u32 {
        self.n_keys
    }

    pub fn get_sketch(&self) -> &Vec<u64> {
        &self.min_sketch
    }

    pub fn get_tip (&self) -> Option<sha256d::Hash> {
        if let Some(header) = self.trunk.get_tip() {
            return Some(header.bitcoin_hash());
        }
        None
    }

    pub fn get_iblt(&mut self, size: u32) -> Result<&IBLT<ContentKey>, BiadNetError> {
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        Ok(self.iblts.entry(size).or_insert(tx.compute_content_iblt(size)?))
    }

    pub fn block_connected(&mut self, block: &Block, height: u32) -> Result<(), BiadNetError> {
        debug!("processing block {} {}", height, block.header.bitcoin_hash());
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        if self.wallet.process(block) {
            tx.store_coins(&self.wallet.coins())?;
            info!("New wallet balance {} satoshis {} unconfirmed", self.wallet.balance(), self.wallet.unconfirmed_balance());
        }
        tx.store_processed(&block.header.bitcoin_hash())?;
        tx.commit();
        Ok(())
    }

    /// add a header to the tip of the chain
    pub fn add_header(&mut self, height: u32, header: &BlockHeader) -> Result<(), BiadNetError> {
        info!("new chain tip at height {} {}", height, header.bitcoin_hash());
        let mut deleted_some = false;
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        for key in &mut tx.delete_expired(height)? {
            for (_, i) in &mut self.iblts {
                i.delete(key);
                deleted_some = true;
            }
        }
        if deleted_some {
            let (m, k, n) = tx.compute_content_sketch(MIN_SKETCH_SIZE)?;
            self.min_sketch = m;
            self.ksequence = k;
            self.n_keys = n;
        }
        tx.commit();
        Ok(())
    }

    /// unwind the tip
    pub fn unwind_tip(&mut self, header: &BlockHeader) -> Result<(), BiadNetError> {
        info!("unwind tip {}", header.bitcoin_hash());
        let mut deleted_some = false;
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        for key in &mut tx.delete_confirmed(&header.bitcoin_hash())? {
            for (_, i) in &mut self.iblts {
                i.delete(key);
                deleted_some = true;
            }
        }
        if deleted_some {
            let (m, k, n) = tx.compute_content_sketch(MIN_SKETCH_SIZE)?;
            self.min_sketch = m;
            self.ksequence = k;
            self.n_keys = n;
        }
        tx.commit();
        self.wallet.unwind_tip(&header.bitcoin_hash());
        return Ok(())
    }

    pub fn truncate_to_limit(&mut self) -> Result<(), BiadNetError> {
        let mut deleted_some = false;
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        for key in &mut tx.truncate_content(self.storage_limit)? {
            for (_, i) in &mut self.iblts {
                i.delete(key);
                deleted_some = true;
            }
        }
        if deleted_some {
            let (m, k, n) = tx.compute_content_sketch(MIN_SKETCH_SIZE)?;
            self.min_sketch = m;
            self.ksequence = k;
            self.n_keys = n;
        }
        tx.commit();
        return Ok(())
    }

    pub fn get_content(&self, digest: &sha256::Hash) -> Result<Option<Content>, BiadNetError> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction();
        Ok(tx.read_content(digest)?)
    }

    /// add content
    pub fn add_content(&mut self, content: &Content) -> Result<bool, BiadNetError> {
        // is the block on trunk the proof refers to
        if let Some(height) = self.trunk.get_height(content.funding.get_block_hash()) {
            // not yet expired
            if height + content.term as u32 > self.trunk.len() {
                // get that header
                if let Some(header) = self.trunk.get_header(content.funding.get_block_hash()) {
                    // check if header's merkle root matches that of the proof
                    if header.merkle_root == content.funding.merkle_root() {
                        let t = content.funding.get_transaction();
                        // only use version 2 transactions to avoid malleability
                        if t.version as u32 >= 2 {
                            let digest = content.ad.digest();
                            // expected commitment script to this ad
                            let commitment = funding_script(&content.funder, &digest, content.term, &self.ctx);
                            if let Some((_, o)) = t.output.iter().enumerate().find(|(_, o)| o.script_pubkey == commitment) {
                                // ok there is a commitment to this ad
                                info!("add content {}", &digest);
                                let key = ContentKey::new(&digest[..]);
                                for (_, i) in &mut self.iblts {
                                    i.insert(&key);
                                }
                                add_to_min_sketch(&mut self.min_sketch, &key, &self.ksequence);
                                self.n_keys += 1;
                                {
                                    let mut db = self.db.lock().unwrap();
                                    let mut tx = db.transaction();
                                    tx.store_content(height, &header.bitcoin_hash(),content, o.value)?;
                                    tx.commit();
                                }
                                return Ok(true)
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    pub fn list_categories(&self) -> Result<Vec<String>, BiadNetError> {
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        Ok(tx.list_categories()?)
    }

    pub fn list_abstracts(&self, cats: Vec<String>) -> Result<Vec<Vec<String>>, BiadNetError> {
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        Ok(tx.list_abstracts(cats)?)
    }

    pub fn read_contents(&self, ids: Vec<String>) -> Result<Vec<Readable>, BiadNetError> {
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        Ok(tx.retrieve_contents(ids)?.iter().map( |r| Readable::new(r, self.trunk.clone())).collect())
    }
}

#[derive(Serialize, Clone)]
pub struct Readable {
    pub id: String,
    pub cat: String,
    pub abs: String,
    pub text: String,
    pub start: u64,
    pub end: u64,
    pub publisher: String,
    pub height: u32,
    pub term: u16,
    pub length: u32,
    pub weight: u32
}

impl Readable {
    pub fn new(retrieved: &RetrievedContent, trunk: Arc<dyn Trunk>) -> Readable {
        let start = trunk.get_header_for_height(retrieved.height).unwrap().time as u64;
        let end = if let Some(header) = trunk.get_header_for_height(retrieved.height + retrieved.term as u32) {
            header.time as u64
        }
        else {
            start + (retrieved.term * 600) as u64
        };
        Readable {
            id: retrieved.id.clone(),
            cat: retrieved.cat.clone(),
            abs: retrieved.abs.clone(),
            text: retrieved.text.clone(),
            start,
            end,
            publisher: retrieved.publisher.clone(),
            height: retrieved.height,
            term: retrieved.term,
            length: retrieved.length,
            weight: retrieved.weight
        }
    }
}