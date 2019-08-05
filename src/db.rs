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

use rusqlite::{Connection, Transaction, ToSql};
use std::net::SocketAddr;
use crate::error::BiadNetError;
use std::time::SystemTime;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use rand::{thread_rng, RngCore, Rng};
use futures::{FutureExt, StreamExt};

pub type SharedDB = Arc<Mutex<DB>>;

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
            create table if not exists address (
                network text,
                ip text,
                last_seen number,
                banned number,
                primary key(network, ip)
            ) without rowid
        "#).expect("failed to create db tables");
    }

    pub fn store_address(&mut self, network: &str, address: &SocketAddr, last_seen: u64, banned: u64) -> Result<usize, BiadNetError>  {
        Ok(
            self.tx.execute(r#"
                insert or replace into address (network, ip, last_seen, banned) values (?1, ?2, ?3, ?4)
            "#, &[&network.to_string() as &dyn ToSql, &address.to_string(), &(last_seen as i64), &(banned as i64)])?
        )
    }

    pub fn delete_address(&mut self, network: &str, address: &SocketAddr) -> Result<usize, BiadNetError>  {
        Ok(self.tx.execute(r#"
                delete from address where ip = ?1 and network = ?2
            "#, &[&address.to_string() as &dyn ToSql, &network.to_string()])?)
    }

    // get an address not banned during the last day
    // the probability to be selected is exponentially higher for those with higher last_seen time
    pub fn get_an_address(&self, other_than: &HashSet<SocketAddr>) -> Result<Option<SocketAddr>, BiadNetError> {
        const BAN_TIME: u64 = 60*60*24; // a day

        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let mut statement = self.tx.prepare(r#"
            select ip from address where banned < :banned order by last_seen desc
        "#)?;
        let eligible = statement.query_map_named::<String, _>(&[(":banned", &((now - BAN_TIME) as i64))],
                                                 |row| row.get(0))?
            .filter_map(|r| match r { Ok(ref s) => Some(s.clone()), _ => None})
            .filter(move |s| !other_than.contains(&SocketAddr::from_str(s).expect("address stored in db should be parsable")))
            .collect::<Vec<String>>();
        let len = eligible.len();
        if len == 0 {
            return Ok(None);
        }
        Ok(Some(SocketAddr::from_str(eligible.iter().take_while(|_| thread_rng().gen_bool(0.7)).last().unwrap_or(&eligible[0]).as_str())?))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    #[test]
    pub fn test_db () {
        let mut db = DB::memory().unwrap();
        {
            let mut tx = db.transaction();
            tx.create_tables();
            tx.store_address("biadnet", &SocketAddr::from_str("127.0.0.1:8444").unwrap(), 0, 0).unwrap();
            tx.store_address("biadnet", &SocketAddr::from_str("127.0.0.1:8444").unwrap(), 1, 1).unwrap();
            tx.get_an_address(&HashSet::new()).unwrap();
            assert!(tx.get_an_address(&vec!(SocketAddr::from_str("127.0.0.1:8444").unwrap()).iter().cloned().collect::<HashSet<SocketAddr>>()).unwrap().is_none());
            tx.commit();
        }
        {
            let mut tx = db.transaction();
            tx.delete_address("biadnet", &SocketAddr::from_str("127.0.0.1:8444").unwrap()).unwrap();
        }
    }
}