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

#[macro_use]extern crate log;

use simple_logger;
use log::Level;
use std::env::args;

use futures::{
    future,
    Async, Future, Never,
    executor::{Executor, ThreadPoolBuilder}
};

use bitcoin::network::constants::Network;
use biadne::p2p_bitcoin::BitcoinAdaptor;
use biadne::p2p_biadnet::BiadNetAdaptor;
use biadne::db::DB;
use futures::future::Empty;
use murmel::chaindb::ChainDB;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc,RwLock, Mutex};


const MY_SERVER: &str = "87.230.22.85";
const BIADNET_PORT: u16 = 8444;
const BITCOIN_PORT: u16 = 8333;

pub fn main () {
    simple_logger::init_with_level(Level::Debug).unwrap();
    info!("biadnet starting.");
    let cmd = CommandLine::new();
    let bitcoin_network = Network::from_str(cmd.opt_arg("bitcoin_network").unwrap_or("bitcoin".to_string()).as_str()).expect("unkown Bitcoin network");
    let biadnet_connections = cmd.opt_arg_usize("biadnet-connections").unwrap_or(5);
    let bitcoin_connections = cmd.opt_arg_usize("bitcoin-connections").unwrap_or(5);

    let biadnet_peers = get_socket_vec(cmd.opt_arg("biadnet-peers"), (MY_SERVER.to_string() + ":") + BIADNET_PORT.to_string().as_str());
    let bitcoin_peers = get_socket_vec(cmd.opt_arg("bitcoin-peers"), (MY_SERVER.to_string() + ":") + BITCOIN_PORT.to_string().as_str());

    let biadnet_listen = get_socket_vec(cmd.opt_arg("biadnet-peers"), ("0.0.0.0".to_string() + ":") + BIADNET_PORT.to_string().as_str());

    let db_name = cmd.opt_arg("db").unwrap_or("biadnet".to_string());
    let db_path = std::path::Path::new(db_name.as_str());
    let chaindb = Arc::new(RwLock::new(
        ChainDB::new(&db_path, bitcoin_network, 0).expect("can not open chain db")));
    let db = Arc::new(Mutex::new(DB::new(db_path).expect("can not open db")));

    let mut thread_pool = ThreadPoolBuilder::new().name_prefix("futures ").create().expect("can not start thread pool");
    BitcoinAdaptor::new(bitcoin_network, bitcoin_connections, bitcoin_peers, chaindb.clone(), db.clone()).start(&mut thread_pool);
    BiadNetAdaptor::new(biadnet_connections, biadnet_peers, biadnet_listen, chaindb.clone(), db.clone()).start(&mut thread_pool);
    thread_pool.run::<Empty<(), Never>>(future::empty()).unwrap();
}

fn get_socket_vec(s: Option<String>, default: String) -> Vec<SocketAddr> {
    s.unwrap_or(default).split(",").map(|s| SocketAddr::from_str(s).expect("invalid biadnet socket address")).collect::<Vec<_>>()
}

struct CommandLine {
    pub arguments: Vec<String>,
    options: HashMap<String, Option<String>>
}

impl CommandLine {
    pub fn has_opt (&self, opt: &str) -> bool {
        self.options.contains_key(&opt.to_string())
    }

    pub fn opt_arg (&self, opt: &str) -> Option<String> {
        if let Some(a) = self.options.get(&opt.to_string()) {
            return a.clone();
        }
        None
    }

    pub fn opt_arg_usize (&self, opt: &str) -> Option<usize> {
        if let Some(a) = self.options.get(&opt.to_string()) {
            if let Some(s) = a {
                if let Ok(n) = s.parse::<usize>() {
                    return Some(n);
                }
            }
        }
        None
    }


    pub fn new () -> CommandLine {
        let mut arguments = Vec::new();
        let mut options = HashMap::new();
        let mut oi = args().skip(1).take_while(|a| a.as_str() != "--");
        let mut next = oi.next();
        while let Some(ref a) = next {
            if a.starts_with("--") {
                let (_, option) = a.split_at(2);
                if let Some(ref optargs) = oi.next() {
                    if optargs.starts_with("--") {
                        options.insert(option.to_string(), None);
                        next = Some(optargs.clone());
                    }
                    else {
                        options.insert(option.to_string(), Some(optargs.clone()));
                        next = oi.next();
                    }
                }
                else {
                    options.insert(option.to_string(), None);
                    next = None;
                }
            }
            else {
                arguments.push(a.clone());
                next = oi.next();
            }
        }
        for a in args().skip_while(|a| a.as_str() != "--").skip(1) {
            arguments.push(a);
        }
        CommandLine{arguments, options}
    }
}
