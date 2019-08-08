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

use bitcoin::{BlockHeader, BitcoinHash};
use bitcoin_hashes::{sha256, sha256d};
use secp256k1::{Secp256k1, All};
use bitcoin_wallet::trunk::Trunk;
use std::sync::{RwLock, Arc};

use crate::error::BiadNetError;
use crate::content::Content;
use crate::funding::funding_script;
use crate::db::SharedDB;
use crate::iblt::IBLT;
use crate::content::ContentKey;

use std::collections::HashMap;
use crate::iblt::add_to_min_sketch;

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
    n_keys: u32
}

impl ContentStore {
    /// new content store
    pub fn new(db: SharedDB, storage_limit: u64, trunk: Arc<dyn Trunk + Send + Sync>) -> Result<ContentStore, BiadNetError> {
        let mut mins;
        let ksequence;
        let n_keys;
        {
            let mut db = db.lock().unwrap();
            let mut tx = db.transaction();
            let (m, k, n) = tx.compute_min_sketch(MIN_SKETCH_SIZE)?;
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
            n_keys
        })
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
        Ok(self.iblts.entry(size).or_insert(tx.compute_iblt(size)?))
    }

    /// add a header to the tip of the chain
    pub fn add_header(&mut self, height: u32, header: &BlockHeader) -> Result<(), BiadNetError> {
        info!("new chain tip {}", header.bitcoin_hash());
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
            let (m, k, n) = tx.compute_min_sketch(MIN_SKETCH_SIZE)?;
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
            let (m, k, n) = tx.compute_min_sketch(MIN_SKETCH_SIZE)?;
            self.min_sketch = m;
            self.ksequence = k;
            self.n_keys = n;
        }
        tx.commit();
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
            let (m, k, n) = tx.compute_min_sketch(MIN_SKETCH_SIZE)?;
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
}
