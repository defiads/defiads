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

use bitcoin_hashes::{
    sha256d, sha256,
    hex::{FromHex, ToHex}
};
use log::Level;
use rusqlite::{Connection, Transaction, ToSql, OptionalExtension};
use std::net::SocketAddr;
use std::hash::Hasher;
use crate::byteorder::ByteOrder;
use crate::error::BiadNetError;
use std::time::SystemTime;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::collections::{HashSet};
use rand::{thread_rng, Rng, RngCore};
use crate::content::Content;
use serde_cbor;
use rusqlite::NO_PARAMS;
use crate::iblt::IBLT;
use crate::content::ContentKey;
use crate::iblt::min_sketch;
use rand_distr::Poisson;
use crate::text::Text;
use bitcoin::{PublicKey, OutPoint, TxOut, Script};
use std::time::UNIX_EPOCH;
use crate::discovery::NetAddress;
use bitcoin_wallet::account::{AccountAddressType, Account, MasterAccount, KeyDerivation};
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::network::constants::Network;
use bitcoin_wallet::coins::{Coin, Coins};
use bitcoin_wallet::proved::ProvedTransaction;
use siphasher::sip::SipHasher;
use byteorder::LittleEndian;
use bitcoin::consensus::serialize;


pub type SharedDB = Arc<Mutex<DB>>;

// number of hash functions
const NH:usize = 4;
// random, I swear
const K0:u64 = 1614418600579272000;
const K1:u64 = 8727507265883984962;

const ADDRESS_SLOTS:u64 = 10000;

pub struct DB {
    connection: Connection
}

impl DB {
    pub fn memory () -> Result<DB, BiadNetError> {
        Ok(DB{connection: Connection::open_in_memory()?})
    }

    pub fn new(path: &std::path::Path) -> Result<DB, BiadNetError> {
        Ok(DB{connection: Connection::open(path)?})
    }

    pub fn transaction(&mut self) -> TX {
        TX{tx: self.connection.transaction().expect("can not start db transaction")}
    }
}

pub struct TX<'db> {
    tx: Transaction<'db>
}

impl<'db> TX<'db> {
    pub fn commit (self) {
        self.tx.commit().expect("failed to commit db transaction");
    }

    pub fn rollback(self) {
        self.tx.rollback().expect("failed to roll back db transaction");
    }

    pub fn create_tables (&mut self) {
        self.tx.execute_batch(r#"
            create table if not exists seed (
                k0 number,
                k1 number
            );

            create table if not exists address (
                network text,
                slot number,
                ip text,
                connected number,
                last_seen number,
                banned number,
                primary key(network, slot)
            ) without rowid;

            create table if not exists content (
                id text primary key,
                cat text,
                abs text,
                ad blob,
                block_id text,
                height number,
                proof blob,
                publisher blob,
                term number,
                weight number,
                length number
            ) without rowid;

            create table if not exists account (
                account_number,
                sub number,
                address_type number,
                master text,
                instantiated blob,
                primary key(account_number, sub)
            ) without rowid;

            create table if not exists coins (
                txid text,
                vout number,
                value number,
                script blob,
                account number,
                sub number,
                kix number,
                tweak text,
                proof blob,
                primary key(txid, vout)
            ) without rowid;

            create table if not exists processed (
                block text
            );

            create table if not exists txout (
                txid text primary key,
                tx blob
                lastsend number,
                confirmed text
            ) without rowid;
        "#).expect("failed to create db tables");
    }

    pub fn store_txout (&mut self, tx: &bitcoin::Transaction) -> Result<(), BiadNetError> {
        self.tx.execute(r#"
            insert or replace into txout (txid, tx, lastsend, confirmed) values (?1, ?2, ?3, ?4)
        "#, &[&tx.txid().to_string() as &ToSql,
            &serialize(tx), &0i64, &("".to_string())])?;
        Ok(())
    }

    pub fn read_seed(&mut self) -> Result<(u64, u64), BiadNetError> {
        if let Some(seed) = self.tx.query_row(r#"
            select k0, k1 from seed where rowid = 1
        "#,NO_PARAMS, |r| Ok(
            (r.get_unwrap::<usize, i64>(0) as u64,
            r.get_unwrap::<usize, i64>(1) as u64))).optional()? {
            return Ok(seed);
        }
        else {
            let k0 = thread_rng().next_u64();
            let k1 = thread_rng().next_u64();
            self.tx.execute(r#"
                insert or replace into seed (rowid, k0, k1) values (1, ?1, ?2)
            "#, &[&(k0 as i64) as &ToSql, &(k1 as i64)])?;
            return Ok((k0, k1));
        }
    }

    pub fn read_processed(&mut self) -> Result<Option<sha256d::Hash>, BiadNetError> {
        Ok(self.tx.query_row(r#"
            select block from processed where rowid = 1
        "#,NO_PARAMS, |r| Ok(sha256d::Hash::from_hex(r.get_unwrap::<usize, String>(0).as_str())
            .expect("stored block not hex"))).optional()?)
    }

    pub fn store_processed(&mut self, block_id: &sha256d::Hash) -> Result<(), BiadNetError> {
        self.tx.execute(r#"
            insert or replace into processed (rowid, block) values (1, ?1)
        "#, &[&block_id.to_string() as &ToSql])?;
        Ok(())
    }

    pub fn store_coins(&mut self, coins: &Coins) -> Result<(), BiadNetError> {
        self.tx.execute (r#"
            delete from coins;
        "#, NO_PARAMS)?;
        let mut statement = self.tx.prepare(r#"
            insert into coins (txid, vout, value, script, account, sub, kix, tweak, proof)
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#)?;
        let proofs = coins.proofs();
        for (outpoint, coin) in coins.owned() {
            let tweak = if let Some(ref tweak) = coin.derivation.tweak {
                    hex::encode(tweak)
                }
                else {
                    String::new()
                };
            let proof = proofs.get(&outpoint.txid).expect("inconsistent wallet, missing proof");
            statement.execute(&[
                &outpoint.txid.to_string() as &ToSql, &outpoint.vout,
                &(coin.output.value as i64), &coin.output.script_pubkey.to_bytes(),
                &coin.derivation.account, &coin.derivation.sub, &coin.derivation.kix, &tweak,
                &serde_cbor::ser::to_vec(&proof).expect("can not serialize proof")
            ])?;
        }
        Ok(())
    }

    pub fn read_coins(&mut self) -> Result<Coins, BiadNetError> {
        let mut query = self.tx.prepare(r#"
            select txid, vout, value, script, account, sub, kix, tweak, proof from coins
        "#)?;
        let mut coins = Coins::new();
        for r in query.query_map::<(OutPoint, Coin, ProvedTransaction),&[&ToSql],_> (NO_PARAMS, |r| {
            Ok((
                OutPoint{ txid: sha256d::Hash::from_hex(r.get_unwrap::<usize, String>(0).as_str()).expect("transaction id not hex"),
                    vout: r.get_unwrap::<usize, u32>(1)},
                Coin{
                    output: TxOut{script_pubkey: Script::from(r.get_unwrap::<usize,Vec<u8>>(3)),
                        value: r.get_unwrap::<usize, i32>(2) as u64},
                    derivation: KeyDerivation {
                        account: r.get_unwrap::<usize, u32> (4),
                        sub: r.get_unwrap::<usize, u32> (5),
                        kix: r.get_unwrap::<usize, u32> (6),
                        tweak: {
                            let tweak = r.get_unwrap::<usize, String>(7);
                            if tweak.len() == 0 {
                                None
                            }
                            else {
                                Some(hex::decode(tweak).expect("tweak not hex"))
                            }
                        }
                    }
                },
                serde_cbor::from_slice(r.get_unwrap::<usize, Vec<u8>>(8).as_slice()).expect("can not deserialize stored proof")
                ))
        })? {
            let (point, coin, proof) = r?;
            coins.add_from_storage(point, coin, proof);
        }
        Ok(coins)
    }

    pub fn store_master(&mut self, master: &MasterAccount) -> Result<usize, BiadNetError> {
        debug!("store master account");
        self.tx.execute (r#"
            delete from account;
        "#, NO_PARAMS)?;
        let mut inserted = 0;
        for (_, account) in master.accounts().iter() {
            inserted += self.store_account(account)?;
        }
        Ok(inserted)
    }

    pub fn store_account(&mut self, account: &Account) -> Result<usize, BiadNetError> {
        debug!("store account {}/{}", account.account_number(), account.sub_account_number());
        Ok(self.tx.execute(r#"
            insert or replace into account (account_number, address_type, sub, master, instantiated)
            values (?1, ?2, ?3, ?4, ?5)
        "#, &[&account.account_number() as &ToSql,
            &account.address_type().as_u32(), &account.sub_account_number(), &account.master_public().to_string(),
            &serde_cbor::ser::to_vec(&account.instantiated())?]
        )?)
    }

    pub fn read_account(&mut self, account_number: u32, sub: u32, network: Network, look_ahead: u32) -> Result<Account, BiadNetError> {
        debug!("read account {}/{}", account_number, sub);
        Ok(self.tx.query_row(r#"
            select address_type, master, instantiated from account where account_number = ?1 and sub = ?2
        "#, &[&account_number as &ToSql, &sub], |r| {
            Ok(Account::new_from_storage(
                AccountAddressType::from_u32(r.get_unwrap::<usize, u32>(0)),
                account_number,
                sub,
                ExtendedPubKey::from_str(r.get_unwrap::<usize, String>(1).as_str()).expect("malformed master public stored"),
                serde_cbor::from_slice(r.get_unwrap::<usize, Vec<u8>>(2).as_slice()).expect("malformed instantiated keys stored"),
                0,
                look_ahead,
                network
            ))
        })?)
    }

    pub fn compute_content_iblt(&mut self, len: u32) -> Result<IBLT<ContentKey>, BiadNetError> {
        let mut iblt = IBLT::new(len, NH, K0, K1);

        let mut query = self.tx.prepare(r#"
            select id from content
        "#)?;
        for r in query.query_map::<String,&[&ToSql],_>(NO_PARAMS,
                                                              |r| Ok(r.get(0)?))? {
            if let Ok(id) = r {
                iblt.insert(&ContentKey::new(&sha256::Hash::from_hex(id.as_str())?[..]));
            }
        }
        Ok(iblt)
    }

    pub fn compute_content_sketch(&mut self, len: usize) -> Result<(Vec<u64>, Vec<(u64, u64)>, u32), BiadNetError> {
        let mut query = self.tx.prepare(r#"
            select id from content
        "#)?;
        let mut key_iterator = query.query_map::<String,&[&ToSql],_>(NO_PARAMS,
                                                     |r| Ok(r.get(0)?))?
            .filter_map(|r| if let Ok(id) = r {
                Some(ContentKey::new(&sha256::Hash::from_hex(id.as_str()).unwrap()[..]))}else{None});

        Ok(min_sketch(len, K0, K1, &mut key_iterator))
    }


    pub fn compute_address_iblt(&mut self, len: u32) -> Result<IBLT<NetAddress>, BiadNetError> {
        let mut iblt = IBLT::new(len, NH, K0, K1);

        let mut query = self.tx.prepare(r#"
            select ip from address where network = ?1 and last_seen > ?2 and banned < ?2
        "#)?;
        let yesterday = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 24*60*60;
        for r in query.query_map::<String,&[&ToSql],_>(
            &[&("biadnet".to_string()) as &dyn ToSql, &(yesterday as i64)], |r| Ok(r.get(0)?))? {
            if let Ok(s) = r {
                iblt.insert(&NetAddress::new(&SocketAddr::from_str(s.as_str()).expect("address stored in db should be parsable")));
            }
        }
        Ok(iblt)
    }

    pub fn compute_address_sketch (&mut self, len: usize) -> Result<(Vec<u64>, u32), BiadNetError> {
        let mut query = self.tx.prepare(r#"
            select ip from address where network = ?1 and last_seen > ?2 and banned < ?2
        "#)?;
        let yesterday = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 24*60*60;
        let mut key_iterator = query.query_map::<String,&[&ToSql],_>(
            &[&("biadnet".to_string()) as &dyn ToSql, &(yesterday as i64)], |r| Ok(r.get(0)?))?
            .filter_map(|r| if let Ok(s) = r {
                Some(NetAddress::new(&SocketAddr::from_str(s.as_str()).expect("address stored in db should be parsable")))}else{None});

        let (sketch, _, n_keys) = min_sketch(len, K0, K1, &mut key_iterator);
        Ok((sketch, n_keys))
    }


    pub fn store_content(&mut self, height: u32, block_id: &sha256d::Hash, c: &Content, amount: u64) -> Result<usize, BiadNetError> {
        let id = c.ad.digest();
        let ser_ad = c.ad.serialize();
        let proof = serde_cbor::ser::to_vec(&c.funding).unwrap();
        let publisher = serde_cbor::ser::to_vec(&c.funder).unwrap();
        let length = c.length();
        debug!("store content {}", id);
        Ok(self.tx.execute(r#"
            insert or replace into content (id, cat, abs, ad, block_id, height, proof, publisher, term, weight, length)
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#, &[&id.to_hex() as &ToSql,
            &c.ad.cat, &c.ad.abs, &ser_ad,
            &block_id.to_hex(), &height, &proof, &publisher, &c.term,
            &((amount / length as u64) as u32), &length]
        )?)
    }

    pub fn read_content(&self, digest: &sha256::Hash) -> Result<Option<Content>, BiadNetError> {
        Ok(self.tx.query_row(r#"
            select (ad, proof, publisher, term)
            from content where id = ?1
        "#, &[digest.to_hex()], |r| Ok(
            Some(Content {
                ad: serde_cbor::from_reader(std::io::Cursor::new(r.get_unwrap::<usize, Vec<u8>>(0))).unwrap(),
                funding: serde_cbor::from_reader(std::io::Cursor::new(r.get_unwrap::<usize, Vec<u8>>(1))).unwrap(),
                funder: serde_cbor::from_reader(std::io::Cursor::new(r.get_unwrap::<usize, Vec<u8>>(2))).unwrap(),
                term: r.get_unwrap(3)
            })
        ))?)
    }

    pub fn truncate_content(&mut self, limit: u64) -> Result<Vec<ContentKey>, BiadNetError> {
        let mut statement = self.tx.prepare(r#"
            select id, length from content order by weight desc
        "#)?;

        let mut to_delete = Vec::new();
        let mut size = 0u64;
        for result in statement.query_map(NO_PARAMS,
                                                |r|
                                                    Ok((r.get_unwrap::<usize, String>(0),
                                                        r.get_unwrap::<usize, i64>(1))))? {
            if let Ok((id, length)) = result {
                size += length as u64;
                if size > limit {
                    to_delete.push(id);
                }
            }
        }
        let mut keys = Vec::new();
        for id in &to_delete {
            keys.push(ContentKey::new(&sha256::Hash::from_hex(id.as_str())?[..]));
            debug!("drop content due to strorage limit {}", id);
            self.tx.execute(r#"
                delete from content where id = ?1
                            "#, &[id as &ToSql])?;
        }
        Ok(keys)
    }

    pub fn delete_expired(&mut self, height: u32) -> Result<Vec<ContentKey>, BiadNetError> {
        let mut keys = Vec::new();
        self.tx.execute(r#"
            create temp table ids (
                id text
            );
        "#, NO_PARAMS)?;
        self.tx.execute(r#"
            insert into temp.ids (id) select id from content where height + term <= ?1
        "#, &[&height as &ToSql])?;

        let mut query = self.tx.prepare(r#"
            select id from temp.ids
        "#)?;

        for r in query.query_map::<String,&[&ToSql],_>(NO_PARAMS,
                                                               |r| Ok(r.get(0)?))? {
            if let Ok(id) = r {
                keys.push(ContentKey::new(&sha256::Hash::from_hex(id.as_str())?[..]));
            }
        }

        if log_enabled!(Level::Debug) {
            let mut statement = self.tx.prepare(r#"
                select id from temp.ids
            "#)?;
            for id in statement
                .query_map(NO_PARAMS, |r| Ok(r.get_unwrap::<usize, String>(0)))? {
                if let Ok(s) = id {
                    debug!("drop expired content {}", s);
                }
            }
        }

        self.tx.execute_batch(r#"
            delete from content where id in (select id from temp.ids);
            drop table temp.ids;
        "#)?;

        Ok(keys)
    }

    pub fn delete_confirmed(&mut self, block_id: &sha256d::Hash) -> Result<Vec<ContentKey>, BiadNetError> {
        let mut keys = Vec::new();
        self.tx.execute(r#"
            create temp table ids (
                id text
            );
        "#, NO_PARAMS)?;
        self.tx.execute(r#"
            insert into temp.ids (id) select id from content where block_id = ?1
        "#, &[&block_id.to_hex() as &ToSql])?;

        let mut query = self.tx.prepare(r#"
            select id from temp.ids
        "#)?;

        for r in query.query_map::<String,&[&ToSql],_>(NO_PARAMS,
                                                              |r| Ok(r.get(0)?))? {
            if let Ok(id) = r {
                keys.push(ContentKey::new(&sha256::Hash::from_hex(id.as_str())?[..]));
            }
        }

        if log_enabled!(Level::Debug) {
            let mut statement = self.tx.prepare(r#"
                select ip from temp.ids
            "#)?;
            for id in statement
                .query_map(NO_PARAMS, |r| Ok(r.get_unwrap::<usize, String>(0)))? {
                if let Ok(s) = id {
                    debug!("drop content due to chain re-org {}", s);
                }
            }
        }

        self.tx.execute_batch(r#"
            delete from content where id in (select id from temp.ids);
            drop table temp.ids;
        "#)?;

        Ok(keys)
    }

    pub fn store_address(&mut self, network: &str, address: &SocketAddr, mut connected: u64, mut last_seen: u64, mut banned: u64) -> Result<usize, BiadNetError>  {
        let (k0, k1) = self.read_seed()?;
        let mut siphasher = SipHasher::new_with_keys(k0, k1);
        siphasher.write(network.as_bytes());
        for a in NetAddress::new(address).address.iter() {
            let mut buf = [0u8; 2];
            LittleEndian::write_u16(&mut buf, *a);
            siphasher.write(&buf);
        }
        let slot = (siphasher.finish() % ADDRESS_SLOTS) as u16;
        if let Ok((oldip, oldconnect, oldls, oldban)) = self.tx.query_row(r#"
                select ip, connected, last_seen, banned from address where network = ?1 and slot = ?2
            "#, &[&network.to_string() as &dyn ToSql, &slot],
                                               |r| Ok(
                                                   (SocketAddr::from_str(r.get_unwrap::<usize, String>(0).as_str()).expect("address stored in db should be parsable"),
                                                    r.get_unwrap::<usize, i64>(1) as u64,
                                                    r.get_unwrap::<usize, i64>(2) as u64,
                                                    r.get_unwrap::<usize, i64>(3) as u64))) {
            // do not reduce last_seen or banned fields
            if oldip != *address {
                let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
                const OLD_CONNECTION: u64 = 5*24*60*60;
                if oldban > 0 || oldconnect < now - OLD_CONNECTION {
                    return Ok(
                        self.tx.execute(r#"
                            insert or replace into address (network, slot, ip, connected, last_seen, banned) values (?1, ?2, ?3, ?4, ?5, ?6)
                        "#, &[&network.to_string() as &dyn ToSql, &slot, &address.to_string(),
                                        &(connected as i64), &(last_seen as i64), &(banned as i64)])?
                    );
                }
            }
            else {
                connected = std::cmp::max(oldconnect as u64, connected);
                last_seen = std::cmp::max(oldls as u64, last_seen);
                banned = std::cmp::max(oldban as u64, banned);
                return Ok(self.tx.execute(r#"
                        insert or replace into address (network, slot, ip, connected, last_seen, banned) values (?1, ?2, ?3, ?4, ?5, ?6)
                    "#, &[&network.to_string() as &dyn ToSql, &slot, &address.to_string(),
                    &(connected as i64), &(last_seen as i64), &(banned as i64)])?);
            }
            Ok(0)
        }
        else {
            Ok(
                self.tx.execute(r#"
                insert or replace into address (network, slot, ip, connected, last_seen, banned) values (?1, ?2, ?3, ?4, ?5, ?6)
            "#, &[&network.to_string() as &dyn ToSql, &slot, &address.to_string(),
                    &(connected as i64), &(last_seen as i64), &(banned as i64)])?
            )
        }
    }

    // get an address not banned during the last day
    // the probability to be selected is exponentially higher for those with higher last_seen time
    // TODO mark tried connections, build slots instead of storing all. Replace only if not tried for long or banned
    pub fn get_an_address(&self, network: &str, other_than: &HashSet<SocketAddr>) -> Result<Option<SocketAddr>, BiadNetError> {
        const BAN_TIME: u64 = 60*60*24; // a day

        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let mut statement = self.tx.prepare(r#"
            select ip from address where network = ?2 and banned < ?1 order by last_seen desc
        "#)?;
        let eligible = statement.query_map::<SocketAddr, _, _>(
            &[&((now - BAN_TIME) as i64) as &ToSql, &network.to_string()],
            |row| {
                let s = row.get_unwrap::<usize, String>(0);
                let addr = SocketAddr::from_str(s.as_str()).expect("address stored in db should be parsable");
                Ok(addr) })?
            .filter_map(|socket|
                match socket {
                    Ok(a) => if !other_than.contains(&a) { Some(a)} else {None},
                    Err(_) =>   None }).collect::<Vec<_>>();
        let len = eligible.len();
        if len == 0 {
            return Ok(None);
        }
        Ok(Some(
            eligible[
                std::cmp::min(len-1, thread_rng().sample::<f64,_>(
                    Poisson::new(len as f64 / 4.0).unwrap()) as usize)]))
    }

    pub fn list_categories(&mut self) -> Result<Vec<String>, BiadNetError> {
        let mut statement = self.tx.prepare(r#"
            select distinct cat from content order by cat
        "#)?;

        let result = statement.query_map(NO_PARAMS, |r| {
            Ok(r.get_unwrap::<usize, String>(0))
        })?.filter_map(|r| if let Ok(c) = r { Some(c) } else {None})
            .collect::<Vec<_>>();

        Ok(result)
    }

    pub fn list_abstracts(&mut self, cats: Vec<String>) -> Result<Vec<Vec<String>>, BiadNetError> {
        // mut &self because using temp table
        self.tx.execute(r#"
            create temp table cats (
                cat text
            );
        "#, NO_PARAMS)?;
        for c in &cats {
            self.tx.execute(r#"
                insert into temp.cats (cat) values(?1)
            "#, &[c as &ToSql])?;
        }
        let mut statement = self.tx.prepare(r#"
            select id, cat, abs from content where cat in (select cat from temp.cats) order by cat, weight desc
        "#)?;

        let result = statement.query_map(NO_PARAMS, |r| {
            Ok((r.get_unwrap::<usize, String>(0), r.get_unwrap::<usize, String>(1), r.get_unwrap::<usize, String>(2)))
        })?.filter_map(|r| if let Ok((i,c, a)) = r { Some(vec![i,c,a]) } else {None})
            .collect::<Vec<_>>();

        self.tx.execute(r#"
            drop table temp.cats
        "#, NO_PARAMS)?;

        Ok(result)
    }

    pub fn retrieve_contents(&mut self, ids: Vec<String>) -> Result<Vec<RetrievedContent>, BiadNetError> {
        // mut &self because using temp table
        self.tx.execute(r#"
            create temp table ids (
                id text
            );
        "#, NO_PARAMS)?;
        for id in &ids {
            self.tx.execute(r#"
                insert into temp.ids (id) values (?1)
            "#, &[id as &ToSql]).unwrap();
        }

        let mut statement = self.tx.prepare(r#"
            select id, cat, abs, ad, publisher, height, term, length, weight from content where id in (select id from temp.ids) order by weight desc
        "#)?;

        let result = statement.query_map(NO_PARAMS, |r| {
            Ok(RetrievedContent{
                id: r.get_unwrap::<usize, String>(0),
                cat: r.get_unwrap::<usize, String>(1),
                abs: r.get_unwrap::<usize, String>(2),
                text: Text::from_encoded(r.get_unwrap::<usize, Vec<u8>>(3).as_slice()).as_string().unwrap(),
                publisher: PublicKey::from_slice(r.get_unwrap::<usize, Vec<u8>>(4).as_slice()).unwrap().to_string(),
                height: r.get_unwrap::<usize, u32>(5),
                term: r.get_unwrap::<usize, u16>(6),
                length: r.get_unwrap::<usize, u32>(7),
                weight: r.get_unwrap::<usize, u32>(8)
            })
        })?.filter_map(|r| if let Ok(r) = r { Some(r) } else {None})
            .collect::<Vec<_>>();

        self.tx.execute(r#"
            drop table temp.ids
        "#, NO_PARAMS)?;
        Ok(result)
    }
}


pub struct RetrievedContent {
    pub id: String,
    pub cat: String,
    pub abs: String,
    pub text: String,
    pub publisher: String,
    pub height: u32,
    pub term: u16,
    pub length: u32,
    pub weight: u32
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use bitcoin::BitcoinHash;
    use bitcoin_wallet::proved::ProvedTransaction;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::network::constants::Network;
    use bitcoin::util::key::PublicKey;
    use crate::ad::Ad;
    use std::time::UNIX_EPOCH;
    use bitcoin_wallet::account::{MasterAccount, MasterKeyEntropy, Unlocker};

    #[test]
    pub fn test_db () {
        let mut db = DB::memory().unwrap();
        {
            let addr = SocketAddr::from_str("127.0.0.1:8444").unwrap();
            let mut seen = HashSet::new();
            seen.insert (addr);

            let mut tx = db.transaction();
            tx.create_tables();
            // store address
            tx.store_address("biadnet", &addr, 0, 0, 0).unwrap();
            // update
            tx.store_address("biadnet", &addr, 0, 1, 1).unwrap();
            //find
            tx.get_an_address("biadnet", &HashSet::new()).unwrap();
            // should not find if seen
            assert!(tx.get_an_address("biadnet", &seen).unwrap().is_none());
            // ban
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            tx.store_address("biadnet", &SocketAddr::from_str("127.0.0.1:8444").unwrap(), 0, 1, now).unwrap();
            // should not find if banned
            assert!(tx.get_an_address("biadnet", &HashSet::new()).unwrap().is_none());

            let master = MasterAccount::new(MasterKeyEntropy::Recommended, Network::Bitcoin, "", None).unwrap();
            let mut unlocker = Unlocker::new(master.encrypted().as_slice(), "", None, Network::Bitcoin, Some(master.master_public())).unwrap();
            let account = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 1, 2, 10).unwrap();
            tx.store_account(&account).unwrap();
            tx.read_account(1, 2, Network::Bitcoin, 0).unwrap();

            let genesis = genesis_block(Network::Bitcoin);

            let mut coins = Coins::new();
            coins.add_from_storage(
                OutPoint {
                    txid: genesis.txdata[0].bitcoin_hash(),
                    vout: 0
                },
                Coin{
                    output: TxOut{
                        script_pubkey: Script::new(),
                        value: 50000000
                    },
                    derivation: KeyDerivation {
                        tweak: None,
                        account: 1,
                        sub: 2,
                        kix: 3
                    }
                },
                ProvedTransaction::new(&genesis, 0));
            tx.store_coins(&coins).unwrap();
            let other = tx.read_coins().unwrap();
            assert!(coins == other);
            tx.commit();
        }
        {
            let mut tx = db.transaction();
            let block = genesis_block(Network::Bitcoin);
            let satoshi_key = PublicKey::from_slice(&block.txdata[0].output[0].script_pubkey [1..66]).unwrap();
            let ad = Ad::new("a".to_string(), "b".to_string(), "c");
            let content = Content{
                ad: ad.clone(),
                funding: ProvedTransaction::new(&block, 0),
                funder: satoshi_key,
                term: 1
            };
            tx.store_content(0, &block.bitcoin_hash(), &content, 5000000000).unwrap();
            tx.delete_confirmed(&block.bitcoin_hash()).unwrap();
            tx.delete_expired(1).unwrap();
            tx.truncate_content(1024).unwrap();

            assert!(tx.read_processed().unwrap().is_none());
            tx.store_processed(&sha256d::Hash::default()).unwrap();
            tx.store_processed(&block.bitcoin_hash()).unwrap();
            assert_eq!(tx.read_processed().unwrap().unwrap(), block.bitcoin_hash());
            assert_eq!(tx.read_seed().unwrap(), tx.read_seed().unwrap());
            tx.commit();
        }
    }
}