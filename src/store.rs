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

use bitcoin::{OutPoint, BlockHeader, BitcoinHash};
use bitcoin_hashes::{sha256d, sha256, hex::ToHex};
use bitcoin_wallet::{proved::ProvedTransaction};
use secp256k1::{Secp256k1, All};
use bitcoin_wallet::trunk::Trunk;
use std::collections::HashMap;
use std::error;
use std::sync::{RwLock, Arc};

use crate::error::BiadNetError;
use crate::content::Content;
use crate::funding::funding_script;
use crate::db::SharedDB;

pub type SharedContentStore = Arc<RwLock<ContentStore>>;

/// the distributed content torage
pub struct ContentStore {
    ctx: Secp256k1<All>,
    trunk: Arc<dyn Trunk + Send + Sync>,
    db: SharedDB,
    storage_limit: u64
}

impl ContentStore {
    /// new content store
    pub fn new(db: SharedDB, storage_limit: u64, trunk: Arc<dyn Trunk + Send + Sync>) -> ContentStore {
        ContentStore {
            ctx: Secp256k1::new(),
            trunk,
            db,
            storage_limit
        }
    }

    /// add a header to the tip of the chain
    pub fn add_header(&mut self, height: u32, header: &BlockHeader) -> Result<(), BiadNetError> {
        info!("new chain tip {}", header.bitcoin_hash());
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        tx.delete_expired(height)?;
        tx.commit();
        Ok(())
    }

    /// unwind the tip
    pub fn unwind_tip(&mut self, header: &BlockHeader) -> Result<(), BiadNetError> {
        info!("unwind tip {}", header.bitcoin_hash());
        let header_hash = header.bitcoin_hash();
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        tx.delete_confirmed(&header.bitcoin_hash())?;
        tx.commit();
        return Ok(())
    }

    pub fn truncate_to_limit(&mut self) -> Result<(), BiadNetError> {
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        tx.truncate_content(self.storage_limit)?;
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
                            if let Some((vout, o)) = t.output.iter().enumerate().find(|(_, o)| o.script_pubkey == commitment) {
                                // ok there is a commitment to this ad
                                info!("add content {}", &digest);
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
