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
use std::sync::Arc;

use crate::error::BiadNetError;
use crate::content::Content;
use crate::funding::funding_script;
use crate::db::SharedDB;


const STORAGE_LIMIT: u64 = 2^30; // 1 GiB

/// a slot in the in-memory stored part of distributed content
pub struct MemStoredContent {
    digest: sha256::Hash,
    funding: OutPoint,
    abs: String,
    weight: u64,
    length: u64
}

/// the distributed content torage
pub struct ContentStore {
    ctx: Secp256k1<All>,
    trans_store: Vec<MemStoredContent>,
    proofs: HashMap<sha256d::Hash, ProvedTransaction>,
    trunk: Arc<dyn Trunk + Send + Sync>,
    db: SharedDB
}

impl ContentStore {
    /// new content store
    pub fn new(db: SharedDB, trunk: Arc<dyn Trunk + Send + Sync>) -> ContentStore {
        ContentStore {
            ctx: Secp256k1::new(),
            trans_store: Vec::new(),
            proofs: HashMap::new(),
            trunk,
            db
        }
    }

    /// add a header to the tip of the chain
    /// the caller should do SPV check and evtl. unwind
    /// before adding this header after a reorg.
    pub fn add_header(&mut self, header: &BlockHeader) -> Result<(), BiadNetError> {
        info!("new chain tip {}", header.bitcoin_hash());
        Ok(())
    }

    /// unwind the tip
    pub fn unwind_tip(&mut self, header: &BlockHeader) -> Result<(), BiadNetError> {
        info!("unwind tip {}", header.bitcoin_hash());
        let header_hash = header.bitcoin_hash();
        let lost_content = self.proofs.values()
            .filter_map(|t| if *t.get_block_hash() == header_hash {
                Some(t.get_transaction().txid())
            } else { None })
            .flat_map(|txid| {
                self.trans_store.iter()
                    .filter_map(move |s|
                        if s.funding.txid == txid {Some(s.digest)} else {None})
            }).collect::<Vec<sha256::Hash>>();

        // remove those points and associated content
        for id in lost_content {
            self.remove_content(&id)?;
        }
        return Ok(())
    }

    /// remove a content from store
    fn remove_content(&mut self, digest: &sha256::Hash) -> Result<(), BiadNetError> {
        if let Some(pos) = self.trans_store.iter().rposition(|s| s.digest == *digest) {
            self.trans_store.remove(pos);
        }
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        tx.delete_content(digest)?;
        tx.commit();
        info!("remove content {}", digest.to_hex());
        Ok(())
    }

    /// add content
    pub fn add_content(&mut self, content: &Content) -> Result<bool, BiadNetError> {
        if let Some(height) = self.trunk.get_height(content.funding.get_block_hash()) {
            if let Some(header) = self.trunk.get_header(content.funding.get_block_hash()) {
                if header.merkle_root == content.funding.merkle_root() {
                    let t = content.funding.get_transaction();
                    if t.version as u32 >= 2 {
                        let digest = content.ad.digest();
                        let commitment = funding_script(&content.funder, &digest, content.term, &self.ctx);
                        if let Some((vout, o)) = t.output.iter().enumerate().find(|(_, o)| o.script_pubkey == commitment) {
                            info!("add content {}", &digest);
                            {
                                let mut db = self.db.lock().unwrap();
                                let mut tx = db.transaction();
                                tx.store_content(content)?;
                                tx.commit();
                            }
                            return Ok(self.add_to_trans_store(content, o.value, OutPoint { txid: t.txid(), vout: vout as u32 })?)
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    fn add_to_trans_store (&mut self, content: &Content, value: u64, point: OutPoint) -> Result<bool, BiadNetError> {
        let length = content.length()? as u64;
        let weight = length / value;
        let stored_at;
        match self.trans_store.as_slice().binary_search_by(|a| a.weight.cmp(&weight)) {
            Ok(pos) | Err(pos) => { self.trans_store.insert(pos,
                                                            MemStoredContent {
                                                                weight,
                                                                digest: content.ad.digest(),
                                                                abs: content.ad.abs.clone(),
                                                                length,
                                                                funding: point
                                                            }); stored_at = pos; }
        }
        let mut total_length = 0u64;
        let mut cut = 0;
        for (i, s) in self.trans_store.iter().enumerate() {
            total_length += s.length;
            if total_length > STORAGE_LIMIT {
                cut = i;
            }
        }
        let removed = self.trans_store.iter().skip(cut).map(|s| s.digest).collect::<Vec<_>>();
        for d in &removed {
            self.remove_content(d)?;
        }
        return Ok(cut < stored_at);
    }
}
