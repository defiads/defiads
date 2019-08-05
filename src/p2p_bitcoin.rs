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

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr, SocketAddrV4},
    path::Path,
    sync::{Arc, Mutex, RwLock, mpsc, atomic::AtomicUsize}
};
use bitcoin::{
    Block, BlockHeader,
    network::{
        constants::Network,
        message::{
            RawNetworkMessage,
            NetworkMessage,
        }
    }
};
use bitcoin_hashes::sha256d;
use bitcoin_wallet::trunk::Trunk;
use future::Future;
use futures::{future, Never, Async, Poll, task,
              executor::{Executor, ThreadPoolBuilder}
};

use log::Level;
use murmel::{
    dispatcher::Dispatcher,
    p2p::P2P,
    chaindb::{ChainDB, SharedChainDB},
    dns::dns_seed,
    downstream::Downstream,
    error::MurmelError,
    headerdownload::HeaderDownload,
    ping::Ping,
    p2p::{
        PeerMessageSender, PeerSource,
        BitcoinP2PConfig,
        P2PControl
    },
    timeout::Timeout
};
use rand::{RngCore, thread_rng};
use simple_logger::init_with_level;

use crate::error::BiadNetError;
use crate::store::ContentStore;
use crate::db::SharedDB;
use futures::executor::ThreadPool;


const MAX_PROTOCOL_VERSION: u32 = 70001;

pub struct P2PBitcoin {
    connections: usize,
    peers: Vec<SocketAddr>,
    chaindb: SharedChainDB,
    network: Network,
    db: SharedDB
}

impl P2PBitcoin {
    pub fn new (network: Network, connections: usize, peers: Vec<SocketAddr>, chaindb: SharedChainDB, db: SharedDB) -> P2PBitcoin {
        P2PBitcoin {connections, peers, chaindb, network, db}
    }
    pub fn start(&self, thread_pool: &mut ThreadPool) {
        let (sender, receiver) = mpsc::sync_channel(100);

        let mut dispatcher = Dispatcher::new(receiver);

        self.chaindb.write().unwrap().init(false).expect("can not initialize db");

        let height =
            if let Some(tip) = self.chaindb.read().unwrap().header_tip() {
                AtomicUsize::new(tip.stored.height as usize)
            }
            else {
                AtomicUsize::new(0)
            };

        let p2pconfig = BitcoinP2PConfig {
            nonce: thread_rng().next_u64(),
            network: self.network,
            max_protocol_version: MAX_PROTOCOL_VERSION,
            user_agent: "biadnet 0.1.0".to_string(),
            server: false,
            height
        };

        let (p2p, p2p_control) = P2P::new(
            p2pconfig,
            PeerMessageSender::new(sender),
            10);

        let timeout = Arc::new(Mutex::new(Timeout::new(p2p_control.clone())));

        let downstream = Arc::new(Mutex::new(BitcoinDriver{store:
        ContentStore::new(Arc::new(ChainDBTrunk{chaindb: self.chaindb.clone()}))}));

        let header_downloader = HeaderDownload::new(self.chaindb.clone(), p2p_control.clone(), timeout.clone(), downstream);
        let ping = Ping::new(p2p_control.clone(), timeout);

        dispatcher.add_listener(header_downloader);
        dispatcher.add_listener(ping);

        let p2p2 = p2p.clone();
        let p2p_task = Box::new(future::poll_fn(move |ctx| {
            p2p2.run("bitcoin", 0, ctx).unwrap();
            Ok(Async::Ready(()))
        }));
        // start the task that runs all network communication
        thread_pool.spawn(p2p_task).unwrap();

        info!("Bitcoin p2p engine started");
        thread_pool.spawn(Self::keep_connected(self.network,p2p.clone(), self.peers.clone(), self.connections, self.db.clone())).unwrap();
    }

    fn keep_connected(network: Network, p2p: Arc<P2P<NetworkMessage, RawNetworkMessage, BitcoinP2PConfig>>, peers: Vec<SocketAddr>, min_connections: usize, db: SharedDB) -> Box<dyn Future<Item=(), Error=Never> + Send> {

        // add initial peers if any
        let mut added = Vec::new();
        for addr in &peers {
            added.push(p2p.add_peer("bitcoin", PeerSource::Outgoing(addr.clone())));
        }

        return Box::new( KeepConnected { network, min_connections, connections: added, p2p, dns: Vec::new(), earlier: HashSet::new(), db });

        struct KeepConnected {
            network: Network,
            min_connections: usize,
            connections: Vec<Box<dyn Future<Item=SocketAddr, Error=MurmelError> + Send>>,
            p2p: Arc<P2P<NetworkMessage, RawNetworkMessage, BitcoinP2PConfig>>,
            dns: Vec<SocketAddr>,
            earlier: HashSet<SocketAddr>,
            db: SharedDB
        }

        // this task runs until it runs out of peers
        impl Future for KeepConnected {
            type Item = ();
            type Error = Never;

            fn poll(&mut self, cx: &mut task::Context) -> Poll<Self::Item, Self::Error> {
                // return from this loop with 'pending' if enough peers are connected
                loop {
                    while self.connections.len() < self.min_connections {
                        if let Some(addr) = self.get_an_address() {
                            self.connections.push(self.p2p.add_peer("bitcoin", PeerSource::Outgoing(addr)));
                        }
                        else {
                            error!("no more peers to connect");
                            return Ok(Async::Ready(()));
                        }
                    }
                    // find a finished peer
                    let finished = self.connections.iter_mut().enumerate().filter_map(|(i, f)| {
                        // if any of them finished
                        // note that poll is reusing context of this poll, so wakeups come here
                        match f.poll(cx) {
                            Ok(Async::Pending) => None,
                            Ok(Async::Ready(e)) => {
                                trace!("woke up to lost peer");
                                Some((i, Ok(e)))
                            }
                            Err(e) => {
                                trace!("woke up to peer error");
                                Some((i, Err(e)))
                            }
                        }
                    }).next();
                    match finished {
                        Some((i, _)) => self.connections.remove(i),
                        None => return Ok(Async::Pending)
                    };
                }
            }
        }

        impl KeepConnected {
            fn get_an_address(&mut self) -> Option<SocketAddr> {
                if let Ok(Some(a)) = self.db.lock().unwrap().transaction().get_an_address(&self.earlier) {
                    self.earlier.insert(a);
                    return Some(a);
                }
                if self.dns.len() == 0 {
                    self.dns = dns_seed(self.network);
                    let mut db = self.db.lock().unwrap();
                    let mut tx = db.transaction();
                    for a in &self.dns {
                        tx.store_address("bitcoin", a, 0, 0).expect("can not store addresses in db");
                    }
                    tx.commit();
                }
                if self.dns.len() > 0 {
                    let mut rng = thread_rng();
                    return Some(self.dns[(rng.next_u32() as usize) % self.dns.len()]);
                }
                None
            }

            fn dns_lookup(&mut self) {
                while self.connections.len() < self.min_connections {
                    if self.dns.len() == 0 {
                        self.dns = dns_seed(self.network);
                    }
                    if self.dns.len() > 0 {
                        let mut rng = thread_rng();
                        let addr = self.dns[(rng.next_u64() as usize) % self.dns.len()];
                        self.connections.push(self.p2p.add_peer("bitcoin", PeerSource::Outgoing(addr)));
                    }
                }
            }
        }
    }
}


struct BitcoinDriver {
    store: ContentStore
}

impl Downstream for BitcoinDriver {
    fn block_connected(&mut self, block: &Block, height: u32) {}

    fn header_connected(&mut self, block: &BlockHeader, height: u32) {
        self.store.add_header(block).expect("can not add header");
    }

    fn block_disconnected(&mut self, header: &BlockHeader) {
        self.store.unwind_tip(header).expect("can not unwind tip");
    }
}

pub struct ChainDBTrunk {
    pub chaindb: SharedChainDB
}

impl Trunk for ChainDBTrunk {
    fn is_on_trunk(&self, block_hash: &sha256d::Hash) -> bool {
        self.chaindb.read().unwrap().pos_on_trunk(block_hash).is_some()
    }

    fn get_header(&self, block_hash: &sha256d::Hash) -> Option<BlockHeader> {
        if let Some(cached) = self.chaindb.read().unwrap().get_header(block_hash) {
            return Some(cached.stored.header.clone())
        }
        None
    }

    fn get_height(&self, block_hash: &sha256d::Hash) -> Option<u32> {
        self.chaindb.read().unwrap().pos_on_trunk(block_hash)
    }

    fn get_tip(&self) -> Option<BlockHeader> {
        if let Some(cached) = self.chaindb.read().unwrap().header_tip() {
            return Some(cached.stored.header.clone());
        }
        None
    }

    fn len(&self) -> u32 {
        if let Some(cached) = self.chaindb.read().unwrap().header_tip() {
            return cached.stored.height
        }
        0
    }
}

