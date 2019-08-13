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
use futures::future::Empty;
use murmel::chaindb::ChainDB;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc,RwLock, Mutex};
use std::thread;
use biadne::api::start_api;
use std::fs;
use std::time::SystemTime;
use rand::{thread_rng, RngCore};
use std::time::UNIX_EPOCH;
use log_panics;
use biadne::find_peers::BIADNET_PORT;
use bitcoin_wallet::account::{MasterAccount, MasterKeyEntropy, Unlocker, Account, AccountAddressType};
use bitcoin::util::bip32::ExtendedPubKey;

const HTTP_RPC: &str = "127.0.0.1";
const BIADNET_LISTEN: &str = "0.0.0.0"; // this also implies ipv6 [::]
const KEY_LOOK_AHEAD: u32 = 10;

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
        eprintln!();
        eprintln!("============================= Initializing bitcoin wallet =================================");
        eprintln!("The randomly generated key for your wallet will be stored ENCRYPTED in the config-file");
        eprintln!();
        eprint!("Set wallet encryption password (minimum length 8):");
        let mut password = String::new();
        std::io::stdin().read_line(&mut password).expect("expecting a password");
        password.remove(password.len()-1); // remove EOL
        assert!(password.len() >= 8, "Password should have at least 8 characters");
        let mut apikey = [0u8;12];
        thread_rng().fill_bytes(&mut apikey);
        let bitcoin_wallet = MasterAccount::new(MasterKeyEntropy::Recommended, bitcoin_network,
                                                password.as_str(), None).expect("can not generate wallet");
        let mut unlocker = Unlocker::new(bitcoin_wallet.encrypted().as_slice(),
                              password.as_str(), None, bitcoin_network,
                              Some(&bitcoin_wallet.master_public())).expect("Internal error in wallet generation");
        let first = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 0, 0, KEY_LOOK_AHEAD)
            .expect("can not create first account");
        let first_address = first.get_key(0).unwrap().address.clone();
        eprintln!();
        eprintln!("You will need the encryption password to use the funds with biadnet.");
        eprintln!();
        eprintln!("Uncommitted funds in the wallet can also be accessed with programs and devices");
        eprintln!("compatible with BIP32, BIP39, BIP44, BIP49, BIP84, such as TREZOR or Ledger");
        eprintln!();
        eprintln!("Write down the following human readable key,");
        eprintln!("to evtl. restore your biadnet wallet or import into compatible programs and devices.");
        eprintln!();
        for (i, word) in bitcoin_wallet.mnemonic(password.as_str()).unwrap().iter().enumerate() {
            eprintln!("{} {}", i+1, word);
        }
        eprintln!();
        eprintln!("Compatible programs and devices should show if initialized with above key,");
        eprintln!("this first receiver address (BIP44 keypath: m/49'/0'/0/0): {}", first_address);
        eprintln!();
        eprint!("Did you write above words down, then answer with yes:");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).expect("expecting yes");
        answer.remove(answer.len()-1); // remove EOL
        assert_eq!(answer, "yes", "expecting yes");
        eprintln!("===========================================================================================");
        eprintln!();
        let config = Config {
            apikey: base64::encode(&apikey),
            encryptedwalletkey: hex::encode(bitcoin_wallet.encrypted().as_slice()),
            keyroot: bitcoin_wallet.master_public().to_string(),
            birth: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            lookahead: KEY_LOOK_AHEAD
        };
        fs::write(config_path, toml::to_string(&config).unwrap()).expect("can not write config file");
        config
    };

    let bitcoin_wallet = MasterAccount::from_encrypted(
        hex::decode(config.encryptedwalletkey).unwrap().as_slice(),
        ExtendedPubKey::from_str(config.keyroot.as_str()).expect("can not decode key root"),
        config.birth);

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
