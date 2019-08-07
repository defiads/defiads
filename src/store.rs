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
use secp256k1::{Secp256k1, All};
use bitcoin_wallet::trunk::Trunk;
use std::sync::{RwLock, Arc};

use crate::error::BiadNetError;
use crate::content::Content;
use crate::funding::funding_script;
use crate::db::SharedDB;
use crate::iblt::IBLT;
use crate::content::ContentKey;
use rand::{RngCore, thread_rng};

pub type SharedContentStore = Arc<RwLock<ContentStore>>;

// random, I swear
const K0:u64 = 1614418600579272000;
const K1:u64 = 8727507265883984962;
// number of hash functions
const NH:usize = 4;

/// the distributed content torage
pub struct ContentStore {
    ctx: Secp256k1<All>,
    trunk: Arc<dyn Trunk + Send + Sync>,
    db: SharedDB,
    storage_limit: u64,
    iblts: Vec<IBLT<ContentKey>>
}

impl ContentStore {
    /// new content store
    pub fn new(db: SharedDB, storage_limit: u64, trunk: Arc<dyn Trunk + Send + Sync>) -> Result<ContentStore, BiadNetError> {
        let mut iblts = Vec::new();
        {
            let mut db = db.lock().unwrap();
            let mut tx = db.transaction();
            let smallest = 100usize;
            for pow in 0..7 {
                let size = smallest * 4 ^ pow;
                iblts.push(
                    tx.read_iblt(size).unwrap_or(
                        IBLT::new(size, NH, K0, K1))
                )
            }
        }
        Ok(ContentStore {
            ctx: Secp256k1::new(),
            trunk,
            db,
            storage_limit,
            iblts
        })
    }

    /// add a header to the tip of the chain
    pub fn add_header(&mut self, height: u32, header: &BlockHeader) -> Result<(), BiadNetError> {
        info!("new chain tip {}", header.bitcoin_hash());
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        for key in &mut tx.delete_expired(height)? {
            for i in &mut self.iblts {
                i.delete(key);
            }
        }
        tx.commit();
        Ok(())
    }

    /// unwind the tip
    pub fn unwind_tip(&mut self, header: &BlockHeader) -> Result<(), BiadNetError> {
        info!("unwind tip {}", header.bitcoin_hash());
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        for key in &mut tx.delete_confirmed(&header.bitcoin_hash())? {
            for i in &mut self.iblts {
                i.delete(key);
            }
        }
        tx.commit();
        return Ok(())
    }

    pub fn truncate_to_limit(&mut self) -> Result<(), BiadNetError> {
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        for key in &mut tx.truncate_content(self.storage_limit)? {
            for i in &mut self.iblts {
                i.delete(key);
            }
        }
        tx.commit();
        return Ok(())
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
                                let weight = (content.length() as u64/o.value) as u32;
                                for i in &mut self.iblts {
                                    i.insert(&ContentKey::new(&digest[..], weight));
                                }
                                {
                                    let mut db = self.db.lock().unwrap();
                                    let mut tx = db.transaction();
                                    tx.store_content(height, &header.bitcoin_hash(),content, o.value)?;
                                    for i in &self.iblts {
                                        tx.store_iblt(i)?;
                                    }
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
