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
use bitcoin_hashes::{sha256d, sha256};
use bitcoin_wallet::{proved::ProvedTransaction};
use secp256k1::{Secp256k1, All};
use std::collections::HashMap;
use std::error;

use crate::error::BiadNetError;
use crate::content::Content;
use crate::funding::funding_script;

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
    headers: Vec<BlockHeader>
}

impl ContentStore {
    /// get the tip hash of the header chain
    pub fn get_tip (&self) -> Option<&BlockHeader> {
        self.headers.last()
    }

    /// get the chain height
    pub fn get_height(&self) -> u32 {
        self.headers.len() as u32
    }

    /// add a header to the tip of the chain
    /// the caller should do SPV check and evtl. unwind
    /// before adding this header after a reorg.
    pub fn add_header(&mut self, header: BlockHeader) -> Result<(), BiadNetError> {
        if self.headers.len() > 0 {
            // only append to tip
            if self.get_tip().unwrap().bitcoin_hash() == header.prev_blockhash {
                self.headers.push(header);
            }
            else {
                return Err(BiadNetError::Unsupported("only add header connected to tip"));
            }
        }
        else {
            // add genesis
            self.headers.push(header);
        }
        Ok(())
    }

    /// unwind the tip
    pub fn unwind_tip(&mut self) -> Result<(), BiadNetError> {
        let len = self.headers.len();
        if len > 0 {
            // remove tip
            self.headers.remove(len-1);
            let lost_content = self.proofs.values()
                .filter_map(|t| if t.get_block_height() as usize == len - 1 {
                    Some(t.get_transaction().txid())
                } else { None })
                .flat_map(|txid| {
                    self.trans_store.iter()
                        .filter_map(move |s|
                            if s.funding.txid == txid {Some(s.digest)} else {None})
                }).collect::<Vec<sha256::Hash>>();

            // remove those points and associated content
            for id in lost_content {
                self.remove_content(&id);
            }
            return Ok(())
        }
        Err(BiadNetError::Unsupported("unwind on empty chain"))
    }

    /// remove a content from store
    fn remove_content(&mut self, digest: &sha256::Hash) {
        if let Some(pos) = self.trans_store.iter().rposition(|s| s.digest == *digest) {
            self.trans_store.remove(pos);
        }
        // TODO persistent store
    }

    /// add content
    pub fn add_content(&mut self, content: &Content) -> Result<bool, Box<error::Error>> {
        let height = content.funding.get_block_height();
        if let Some(ref h) = self.headers.get(height as usize) {
            if h.merkle_root == content.funding.merkle_root() {
                let t = content.funding.get_transaction();
                let commitment = funding_script(&content.funder, &content.ad.digest(), content.term, &self.ctx);
                if let Some((vout, o)) = t.output.iter().enumerate().find(|(_, o)| o.script_pubkey == commitment) {
                    return Ok(self.add_to_trans_store(content, o.value, OutPoint{txid: t.txid(), vout: vout as u32})?)
                    // TODO persistent store
                }
            }
        }
        Ok(false)
    }

    fn add_to_trans_store (&mut self, content: &Content, value: u64, point: OutPoint) -> Result<bool, Box<error::Error>> {
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
            self.remove_content(d);
        }
        return Ok(cut < stored_at);
    }
}