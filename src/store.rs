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

use bitcoin::{BlockHeader, BitcoinHash, Block, Address, PublicKey, Script};
use bitcoin_hashes::{sha256, sha256d, Hash};
use std::sync::{RwLock, Arc};

use crate::error::BiadNetError;
use crate::content::Content;
use crate::db::{SharedDB, RetrievedContent};
use crate::iblt::IBLT;
use crate::content::ContentKey;

use std::collections::HashMap;
use crate::iblt::add_to_min_sketch;
use crate::trunk::Trunk;
use crate::wallet::Wallet;
use bitcoin::network::message::NetworkMessage;
use murmel::p2p::{PeerMessageSender, PeerMessage};
use crate::ad::Ad;
use bitcoin_wallet::context::SecpContext;
use bitcoin_wallet::proved::ProvedTransaction;
use bitcoin::{
    network::constants::Network,
    blockdata::{
        opcodes::all,
        script::Builder
    }
};

const MIN_SKETCH_SIZE: usize = 20;

pub type SharedContentStore = Arc<RwLock<ContentStore>>;

/// the distributed content storage
pub struct ContentStore {
    ctx: Arc<SecpContext>,
    trunk: Arc<dyn Trunk + Send + Sync>,
    db: SharedDB,
    storage_limit: u64,
    iblts: HashMap<u32, IBLT<ContentKey>>,
    min_sketch: Vec<u64>,
    ksequence: Vec<(u64, u64)>,
    n_keys: u32,
    wallet: Wallet,
    txout: Option<PeerMessageSender<NetworkMessage>>
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
            ctx: Arc::new(SecpContext::new()),
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

    pub fn set_tx_sender(&mut self, txout: PeerMessageSender<NetworkMessage>) {
        self.txout = Some(txout);
    }

    pub fn balance(&self) -> Vec<u64> {
        vec!(self.wallet.balance(), self.wallet.available_balance(self.trunk.len(), |h| self.trunk.get_height(h)))
    }

    pub fn deposit_address(&mut self) -> Address {
        self.wallet.master.get_mut((0,0)).expect("can not find 0/0 account")
            .next_key().expect("can not generate receiver address in 0/0").address.clone()
    }

    pub fn read_prepared(&self, id: &sha256::Hash) -> Option<Ad> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction();
        tx.read_publication(id).expect("can not list publications")
    }

    pub fn list_prepared(&self) -> Vec<sha256::Hash> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction();
        tx.list_publication().expect("can not list publications")
    }

    pub fn prepare_publication(&mut self, cat: String, abs: String, content: String) -> sha256::Hash {
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        let id = tx.prepare_publication(&Ad::new(cat, abs, content.as_str())).expect("can not store publication");
        tx.commit();
        id
    }

    pub fn fund (&mut self, id: &sha256::Hash, term: u16, amount: u64, fee_per_vbyte: u64, passpharse: String) -> Result<sha256d::Hash, BiadNetError> {
        let (transaction, funder) = self.wallet.fund(id, term, passpharse, fee_per_vbyte, amount, self.trunk.clone(),
            |pk, term| Self::funding_script(pk, term.unwrap()))?;
        let txid = transaction.txid();
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        tx.store_account(&self.wallet.master.get((1,0)).unwrap())?;
        tx.store_txout(&transaction, Some((&funder, id, term))).expect("can not store outgoing transaction");
        tx.commit();
        if let Some(ref txout) = self.txout {
            txout.send(PeerMessage::Outgoing(NetworkMessage::Tx(transaction)));
        }
        info!("Wallet balance: {} satoshis {} available", self.wallet.balance(), self.wallet.available_balance(self.trunk.len(), |h| self.trunk.get_height(h)));
        Ok(txid)
    }

    fn funding_script (tweaked: &PublicKey, term: u16) -> Script {
        let script = Builder::new()
            .push_int(term as i64)
            .push_opcode(all::OP_CSV)
            .push_opcode(all::OP_DROP)
            .push_slice(tweaked.to_bytes().as_slice())
            .push_opcode(all::OP_CHECKSIG)
            .into_script();

        Address::p2wsh(&script, Network::Bitcoin).script_pubkey()
    }

    pub fn withdraw (&mut self, passpharse: String, address: Address, fee_per_vbyte: u64, amount: Option<u64>) -> Result<sha256d::Hash, BiadNetError> {
        let transaction = self.wallet.withdraw(passpharse, address, fee_per_vbyte, amount, self.trunk.clone())?;
        let txid = transaction.txid();
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        tx.store_account(&self.wallet.master.get((0,1)).unwrap())?;
        tx.store_txout(&transaction, None).expect("can not store outgoing transaction");
        tx.commit();
        if let Some(ref txout) = self.txout {
            txout.send(PeerMessage::Outgoing(NetworkMessage::Tx(transaction)));
        }
        info!("Wallet balance: {} satoshis {} available", self.wallet.balance(), self.wallet.available_balance(self.trunk.len(), |h| self.trunk.get_height(h)));
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
        let newly_confirmed_publication;
        {
            let mut db = self.db.lock().unwrap();
            let mut tx = db.transaction();

            newly_confirmed_publication = tx.read_unconfirmed()?.iter()
                .filter_map(|(t, p)|
                    if let Some((p, id, term)) = p {
                        if let Some((tix, _)) = block.txdata.iter().enumerate().find(|(_, c)| c.txid() == t.txid()) {
                            Some((tix, p.clone(), id.clone(), tx.read_publication(id).expect("error reading confirmed publication"), *term))
                        } else { None }
                    } else { None }).collect::<Vec<_>>();

            if self.wallet.process(block) {
                tx.store_coins(&self.wallet.coins())?;
                info!("New wallet balance {} satoshis {} available", self.wallet.balance(), self.wallet.available_balance(self.trunk.len(), |h| self.trunk.get_height(h)));
            }
            tx.store_processed(&block.header.bitcoin_hash())?;
            tx.commit();
        }
        for (tix, funder, id, ad, term) in newly_confirmed_publication {
            if let Some(ad) = ad {
                let funding = ProvedTransaction::new(block, tix);
                if self.add_content(&Content { funding, ad, funder, term})? {
                    info!("confirmed publication {}", id);
                }
            }
        }

        Ok(())
    }

    /// add a header to the tip of the chain
    pub fn add_header(&mut self, height: u32, header: &BlockHeader) -> Result<(), BiadNetError> {
        info!("new chain tip at height {} {}", height, header.bitcoin_hash());
        let mut deleted_some = false;
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        for key in &mut tx.delete_expired(height)? {
            debug!("delete expired content {}", sha256::Hash::from_slice(&key.digest[..]).unwrap());
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
            debug!("delete un-confirmed content {}", sha256::Hash::from_slice(&key.digest[..]).unwrap());
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
            debug!("delete content exceeding memory limit {}", sha256::Hash::from_slice(&key.digest[..]).unwrap());
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
                        // only use version 2 transactions
                        if t.version as u32 >= 2 {
                            let digest = content.ad.digest();
                            // expected commitment script to this ad
                            let mut tweaked = content.funder.clone();
                            self.ctx.tweak_exp_add(&mut tweaked, &digest[..]).unwrap();

                            let commitment = Self::funding_script(&tweaked, content.term);
                            if let Some((_, o)) = t.output.iter().enumerate().find(|(_, o)| o.script_pubkey == commitment) {
                                // ok there is a commitment to this ad
                                debug!("add content {}", &digest);
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