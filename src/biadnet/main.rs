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
#[macro_use]extern crate serde_derive;
extern crate clap;
extern crate toml;
extern crate base64;
extern crate hex;
use clap::{Arg, App};

use simplelog;

use futures::{
    future, Never,
    executor::ThreadPoolBuilder
};

use bitcoin::network::constants::Network;
use biadne::p2p_bitcoin::{ChainDBTrunk, P2PBitcoin};
use biadne::p2p_biadnet::P2PBiadNet;
use biadne::db::DB;
use biadne::store::ContentStore;
use biadne::wallet::Wallet;
use futures::future::Empty;
use murmel::chaindb::ChainDB;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc,RwLock, Mutex};
use std::thread;
use biadne::api::start_api;
use std::fs;
use rand::{thread_rng, RngCore};
use log_panics;
use biadne::find_peers::BIADNET_PORT;
use bitcoin::util::bip32::ExtendedPubKey;

const HTTP_RPC: &str = "127.0.0.1";
const BIADNET_LISTEN: &str = "0.0.0.0"; // this also implies ipv6 [::]

#[derive(Serialize, Deserialize)]
struct Config {
    apikey: String,
    encryptedwalletkey: String,
    keyroot: String,
    lookahead: u32,
    birth: u64
}

pub fn main () {
    log_panics::init();

    let biadnet_listen = (BIADNET_LISTEN.to_string() + ":") + (BIADNET_PORT.to_string().as_str());
    let http_rpc = (HTTP_RPC.to_string() + ":") + ((BIADNET_PORT + 1).to_string().as_str());

    let matches = App::new("biadnet").version("0.1.0").author("tamas.blummer@protonmail.com")
        .about("Bitcoin Advertizing Network")
        .arg(Arg::with_name("log-level")
            .long("log-level")
            .value_name("LEVEL")
            .help("Set log level.")
            .takes_value(true)
            .possible_values(&["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"])
            .case_insensitive(true)
            .default_value("DEBUG"))
        .arg(Arg::with_name("bitcoin-network")
            .long("bitcoin-network")
            .value_name("NETWORK")
            .help("Set the used bitcoin network.")
            .takes_value(true)
            .possible_values(&["bitcoin", "testnet", "regtest"])
            .default_value("bitcoin"))
        .arg(Arg::with_name("bitcoin-connections")
            .value_name("n")
            .long("bitcoin-connections")
            .help("Desired number of connections to the bitcoin network")
            .takes_value(true).default_value("5"))
        .arg(Arg::with_name("biadnet-connections")
            .value_name("n")
            .long("biadnet-connections")
            .help("Desired number of connections to the biadnet network")
            .takes_value(true).default_value("5"))
        .arg(Arg::with_name("bitcoin-peers")
            .long("bitcoin-peers")
            .value_name("ADDRESS")
            .help("Bitcoin network peers to connect")
            .multiple(true)
            .use_delimiter(true)
            .min_values(1)
            .takes_value(true))
        .arg(Arg::with_name("biadnet-peers")
            .long("biadnet-peers")
            .value_name("ADDRESS")
            .help("Biadnet network peers to connect")
            .multiple(true)
            .use_delimiter(true)
            .min_values(1)
            .takes_value(true))
        .arg(Arg::with_name("http-rpc")
            .long("http-rpc")
            .value_name("ADDRESS")
            .help("Listen to http-rpc on this address.")
            .takes_value(true)
            .default_value(http_rpc.as_str())
            .min_values(1))
        .arg(Arg::with_name("listen")
            .long("listen")
            .value_name("ADDRESS")
            .multiple(true)
            .help("Listen to incoming biadnet connections")
            .takes_value(true)
            .use_delimiter(true)
            .default_value(biadnet_listen.as_str())
            .min_values(1))
        .arg(Arg::with_name("db")
            .value_name("FILE")
            .long("db")
            .help("Database name")
            .takes_value(true)
            .default_value("biadnet.db"))
        .arg(Arg::with_name("storage-limit")
            .value_name("n")
            .long("storage-limit")
            .help("Storage limit in GB")
            .takes_value(true)
            .default_value("1"))
        .arg(Arg::with_name("config")
            .value_name("FILE")
            .long("config")
            .help("Configuration file in .toml format")
            .takes_value(true)
            .default_value("biadnet.cfg"))
        .arg(Arg::with_name("log-file")
            .value_name("FILE")
            .long("log-file")
            .help("Log file path.")
            .takes_value(true)
            .default_value("biadnet.log"))
        .arg(Arg::with_name("bitcoin-discovery")
            .long("bitcoin-discovery")
            .help("Enable/Disable bitcoin network discovery")
            .takes_value(true)
            .possible_values(&["ON", "OFF"])
            .case_insensitive(true)
            .default_value("ON"))
        .arg(Arg::with_name("biadnet-discovery")
            .long("biadnet-discovery")
            .help("Enable/Disable biadnet network discovery")
            .takes_value(true)
            .possible_values(&["ON", "OFF"])
            .case_insensitive(true)
            .default_value("ON"))
        .get_matches();

    let level = log::LevelFilter::from_str(matches.value_of("log-level").unwrap()).unwrap();
    let log_file = matches.value_of("log-file").unwrap();
    let mut log_config = simplelog::Config::default();
    log_config.filter_ignore = Some(&["tokio_reactor"]);
    simplelog::CombinedLogger::init(
        vec![
            simplelog::TermLogger::new(log::LevelFilter::Warn, simplelog::Config::default(), simplelog::TerminalMode::Stderr).unwrap(),
            simplelog::WriteLogger::new(level, log_config, std::fs::File::create(log_file).unwrap()),
        ]
    ).unwrap();
    info!("biadnet starting, with log-level {}", level);

    let bitcoin_network = matches.value_of("bitcoin-network").unwrap().parse::<Network>().unwrap();
    let mut biadnet_connections = matches.value_of("biadnet-connections").unwrap().parse::<usize>().unwrap();
    let mut bitcoin_connections = matches.value_of("bitcoin-connections").unwrap().parse::<usize>().unwrap();

    let biadnet_peers = matches.values_of("biadnet-peers").unwrap_or_default().map(
        |s| SocketAddr::from_str(s).expect("invalid socket address")).collect::<Vec<SocketAddr>>();

    let bitcoin_peers = matches.values_of("bitcoin-peers").unwrap_or_default().map(
        |s| SocketAddr::from_str(s).expect("invalid socket address")).collect::<Vec<SocketAddr>>();

    let bitcoin_discovery = matches.value_of("bitcoin-discovery").unwrap().eq_ignore_ascii_case("ON");
    if bitcoin_discovery == false  {
        if bitcoin_peers.len() == 0 {
            panic!("You have to provide bitcoin-peers or enable bitcoin-discovery");
        }
        bitcoin_connections = bitcoin_peers.len();
    }

    let biadnet_discovery = matches.value_of("biadnet-discovery").unwrap().eq_ignore_ascii_case("ON");
    if biadnet_discovery == false  {
        if biadnet_peers.len() == 0 {
            panic!("You have to provide biadnet-peers or enable biadnet-discovery");
        }
        biadnet_connections = biadnet_peers.len();
    }

    let http_rpc = matches.value_of("http-rpc").map(|s| SocketAddr::from_str(s).expect("invalid socket address"));
    let biadnet_listen = matches.values_of("listen").unwrap_or_default().map(
        |s| SocketAddr::from_str(s).expect("invalid socket address")).collect();

    let db_name = matches.value_of("db").unwrap();
    let db_path = std::path::Path::new(db_name);

    let storage_limit = matches.value_of("storage-limit").unwrap().parse::<u64>().expect("expecting number of GB") * 1000*1000;

    let config_path = std::path::Path::new(matches.value_of("config").unwrap());
    let config = if let Ok(config_string) = fs::read_to_string( config_path) {
        toml::from_str::<Config>(config_string.as_str()).expect("can not parse config file")
    } else {
        let wallet = Wallet::new(bitcoin_network);
        let mut apikey = [0u8;12];
        thread_rng().fill_bytes(&mut apikey);
        let config = Config {
            apikey: base64::encode(&apikey),
            encryptedwalletkey: hex::encode(wallet.encrypted().as_slice()),
            keyroot: wallet.master_public().to_string(),
            birth: wallet.birth(),
            lookahead: wallet.look_ahead()
        };
        fs::write(config_path, toml::to_string(&config).unwrap()).expect("can not write config file");
        config
    };

    let bitcoin_wallet = Wallet::from_encrypted(
        hex::decode(config.encryptedwalletkey).unwrap().as_slice(),
        ExtendedPubKey::from_str(config.keyroot.as_str()).expect("can not decode key root"),
        config.birth, config.lookahead);

    eprintln!("Starting biadnet.");
    eprintln!("Observe progress in the log file.");
    eprintln!("Warnings and errors will be also printed to stderr.");

    let mut chaindb = ChainDB::new(db_path, bitcoin_network, 0).expect("can not open chain db");
    chaindb.init(false).expect("can not initialize db");
    let chaindb = Arc::new(RwLock::new(chaindb));

    let mut db = DB::new(db_path).expect("can not open db");
    let mut tx = db.transaction();
    tx.create_tables();
    tx.commit();
    let db = Arc::new(Mutex::new(db));

    let content_store =
        Arc::new(RwLock::new(ContentStore::new(db.clone(), storage_limit,
                                               Arc::new(ChainDBTrunk{chaindb: chaindb.clone()}))
            .expect("can not initialize content store")));

    if let Some(http) = http_rpc {
        let address = http.clone();
        let store = content_store.clone();
        let apikey = config.apikey.clone();
        thread::Builder::new().name("http".to_string()).spawn(
            move || start_api(&address, store, apikey)).expect("can not start http api");
    }

    let mut thread_pool = ThreadPoolBuilder::new().name_prefix("futures ").create().expect("can not start thread pool");
    P2PBitcoin::new(bitcoin_network, bitcoin_connections, bitcoin_peers, bitcoin_discovery, chaindb.clone(), db.clone(),
                    content_store.clone()).start(&mut thread_pool);
    P2PBiadNet::new(biadnet_connections, biadnet_peers, biadnet_listen, biadnet_discovery, db.clone(),
                    content_store.clone()).start(&mut thread_pool);
    thread_pool.run::<Empty<(), Never>>(future::empty()).unwrap();
}
