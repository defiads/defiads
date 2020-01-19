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
    future,
    executor::ThreadPoolBuilder
};

use bitcoin::network::constants::Network;
use defiads::p2p_bitcoin::{ChainDBTrunk, P2PBitcoin};
use defiads::p2p_defiads::P2PBiadNet;
use defiads::db::DB;
use defiads::store::ContentStore;
use defiads::wallet::{Wallet, KEY_LOOK_AHEAD};
use murmel::chaindb::ChainDB;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc,RwLock, Mutex};
use std::thread;
use defiads::api::start_api;
use std::fs;
use rand::{thread_rng, RngCore};
use log_panics;
use defiads::find_peers::BIADNET_PORT;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin_wallet::account::{MasterAccount};
use bitcoin::BitcoinHash;
use defiads::trunk::Trunk;

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

    let matches = App::new("defiads").version("0.2.2").author("tamas.blummer@protonmail.com")
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
            .default_value("testnet"))
        .arg(Arg::with_name("bitcoin-connections")
            .value_name("n")
            .long("bitcoin-connections")
            .help("Desired number of connections to the bitcoin network")
            .takes_value(true).default_value("5"))
        .arg(Arg::with_name("defiads-connections")
            .value_name("n")
            .long("defiads-connections")
            .help("Desired number of connections to the defiads network")
            .takes_value(true).default_value("5"))
        .arg(Arg::with_name("bitcoin-peers")
            .long("bitcoin-peers")
            .value_name("ADDRESS")
            .help("Bitcoin network peers to connect")
            .multiple(true)
            .use_delimiter(true)
            .min_values(1)
            .takes_value(true))
        .arg(Arg::with_name("defiads-peers")
            .long("defiads-peers")
            .value_name("ADDRESS")
            .help("defiads network peers to connect")
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
            .help("Listen to incoming defiads connections")
            .takes_value(true)
            .use_delimiter(true)
            .default_value(biadnet_listen.as_str())
            .min_values(1))
        .arg(Arg::with_name("storage-limit")
            .value_name("n")
            .long("storage-limit")
            .help("Storage limit in GB")
            .takes_value(true)
            .default_value("1"))
        .arg(Arg::with_name("bitcoin-discovery")
            .long("bitcoin-discovery")
            .help("Enable/Disable bitcoin network discovery")
            .takes_value(true)
            .possible_values(&["ON", "OFF"])
            .case_insensitive(true)
            .default_value("ON"))
        .arg(Arg::with_name("defiads-discovery")
            .long("defiads-discovery")
            .help("Enable/Disable defiads network discovery")
            .takes_value(true)
            .possible_values(&["ON", "OFF"])
            .case_insensitive(true)
            .default_value("ON"))
        .arg(Arg::with_name("rescan")
            .long("rescan")
            .help("Re-scan blockchain, forget unconfirmed transactions")
            .takes_value(false))
        .get_matches();

    let bitcoin_network = matches.value_of("bitcoin-network").unwrap().parse::<Network>().unwrap();

    let mut workdir = dirs::home_dir().expect("unknown home directory");
    workdir.push(".defiads");
    workdir.push(bitcoin_network.to_string());
    fs::DirBuilder::new().recursive(true).create(workdir.clone()).expect("can not create work directory");


    let level = log::LevelFilter::from_str(matches.value_of("log-level").unwrap()).unwrap();
    let mut log_file = workdir.clone();
    log_file.push("defiads.log");
    let mut log_config = simplelog::Config::default();
    log_config.filter_ignore = Some(&["tokio", "hyper"]);
    simplelog::CombinedLogger::init(
        vec![
            simplelog::TermLogger::new(log::LevelFilter::Warn, simplelog::Config::default(), simplelog::TerminalMode::Stderr).unwrap(),
            simplelog::WriteLogger::new(level, log_config, std::fs::File::create(log_file.clone()).unwrap()),
        ]
    ).unwrap();
    eprintln!("Starting defiads, connected to {} network.", bitcoin_network);
    eprintln!("Observe progress in the log file: {}", log_file.as_path().display());
    eprintln!("Warnings and errors will be also printed to stderr.");
    info!("defiads connects to {} network", bitcoin_network);
    let mut biadnet_connections = matches.value_of("defiads-connections").unwrap().parse::<usize>().unwrap();
    let mut bitcoin_connections = matches.value_of("bitcoin-connections").unwrap().parse::<usize>().unwrap();

    let biadnet_peers = matches.values_of("defiads-peers").unwrap_or_default().map(
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

    let biadnet_discovery = matches.value_of("defiads-discovery").unwrap().eq_ignore_ascii_case("ON");
    if biadnet_discovery == false  {
        if biadnet_peers.len() == 0 {
            panic!("You have to provide defiads-peers or enable defiads-discovery");
        }
        biadnet_connections = biadnet_peers.len();
    }

    let http_rpc = matches.value_of("http-rpc").map(|s| {
        let mut sock = SocketAddr::from_str(s).expect("invalid socket address");
        if bitcoin_network != Network::Bitcoin {
            sock.set_port(sock.port() + 100);
        }
        sock
    });
    let biadnet_listen = matches.values_of("listen").unwrap_or_default().map(
        |s|
            {
                let mut sock = SocketAddr::from_str(s).expect("invalid socket address");
                if bitcoin_network != Network::Bitcoin {
                    sock.set_port(sock.port() + 100);
                }
                sock
            }).collect();

    let mut db_path = workdir.clone();
    db_path.push("defiads.db");

    let mut db = DB::new(db_path.as_path()).expect("can not open db");
    {
        let mut tx = db.transaction();
        tx.create_tables();
        tx.commit();
    }

    let storage_limit = matches.value_of("storage-limit").unwrap().parse::<u64>().expect("expecting number of GB") * 1000*1000;

    let mut config_path = workdir.clone();
    config_path.push("defiads.cfg");

    let mut bitcoin_wallet;
    let config;
    if let Ok(config_string) = fs::read_to_string( config_path.clone()) {
        config = toml::from_str::<Config>(config_string.as_str()).expect("can not parse config file");
        let mut master_account = MasterAccount::from_encrypted(
            hex::decode(config.encryptedwalletkey).expect("encryptedwalletkey is not hex").as_slice(),
            ExtendedPubKey::from_str(config.keyroot.as_str()).expect("keyroot is malformed"),
            config.birth
        );
        if bitcoin_network == Network::Regtest {
            assert_eq!(Network::Testnet, master_account.master_public().network);
        } else {
            assert_eq!(bitcoin_network, master_account.master_public().network);
        };
        {
            let mut tx = db.transaction();
            let account = tx.read_account(0, 0, bitcoin_network, config.lookahead).expect("can not read account 0/0");
            master_account.add_account(account);
            let account = tx.read_account(0, 1, bitcoin_network, config.lookahead).expect("can not read account 0/1");
            master_account.add_account(account);
            let account = tx.read_account(1, 0, bitcoin_network, 0).expect("can not read account 1/0");
            master_account.add_account(account);
            let coins = tx.read_coins(&mut master_account).expect ("can not read coins");
            bitcoin_wallet = Wallet::from_storage(coins,master_account);
        }
    } else {

        bitcoin_wallet = Wallet::new(bitcoin_network);
        let mut apikey = [0u8;12];
        thread_rng().fill_bytes(&mut apikey);
        config = Config {
            apikey: base64::encode(&apikey),
            encryptedwalletkey: hex::encode(bitcoin_wallet.encrypted().as_slice()),
            keyroot: bitcoin_wallet.master_public().to_string(),
            birth: bitcoin_wallet.birth(),
            lookahead: KEY_LOOK_AHEAD
        };
        {
            let mut tx = db.transaction();
            tx.store_coins(&bitcoin_wallet.coins()).expect("can not store new wallet's coins");
            tx.store_master(&bitcoin_wallet.master).expect("can not store new master account");
            tx.commit();
        }
        fs::write(config_path, toml::to_string(&config).unwrap()).expect("can not write config file");
    };


    let mut chaindb = ChainDB::new(db_path.as_path(), bitcoin_network).expect("can not open chain db");
    chaindb.init().expect("can not initialize db");
    let chaindb = Arc::new(RwLock::new(chaindb));

    let db = Arc::new(Mutex::new(db));

    if matches.is_present("rescan") {
        let chaindb = chaindb.read().unwrap();
        let mut after = None;
        for t in chaindb.iter_trunk_rev(None) {
            if (t.stored.header.time as u64) < config.birth {
                after = Some(t.bitcoin_hash());
                break;
            }
        }
        if let Some(after) = after {
            info!("Re-scanning after block {}", &after);
            let mut db = db.lock().unwrap();
            let mut tx = db.transaction();
            tx.rescan(&after).expect("can not re-scan");
            tx.commit();
            bitcoin_wallet.rescan();
        }
    }

    let trunk = Arc::new(ChainDBTrunk { chaindb: chaindb.clone() });
    info!("Wallet balance: {} satoshis {} available", bitcoin_wallet.balance(), bitcoin_wallet.available_balance(trunk.len(), |h| trunk.get_height(h)));

    let content_store =
        Arc::new(RwLock::new(
            ContentStore::new(db.clone(), storage_limit,
                              trunk,
                              bitcoin_wallet)
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
                    content_store.clone(), config.birth).start(&mut thread_pool);
    P2PBiadNet::new(biadnet_connections, biadnet_peers, biadnet_listen, biadnet_discovery, db.clone(),
                    content_store.clone(), bitcoin_network != Network::Bitcoin).start(&mut thread_pool);
    thread_pool.run(future::pending::<()>());
}
