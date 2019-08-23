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
    net::SocketAddr,
    time::SystemTime,
    thread,
    sync::{Arc, Mutex, mpsc, atomic::AtomicUsize}
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
use future::Future;
use futures::{future, Never, Async, Poll, task, executor::Executor};

use murmel::{
    dispatcher::Dispatcher,
    p2p::P2P,
    chaindb::SharedChainDB,
    dns::dns_seed,
    downstream::Downstream,
    error::MurmelError,
    ping::Ping,
    p2p::{
        PeerMessageSender, PeerSource, P2PControlSender, PeerMessage, PeerMessageReceiver,
        BitcoinP2PConfig
    },
    timeout::Timeout
};
use rand::{RngCore, thread_rng};

use crate::db::SharedDB;
use futures::executor::ThreadPool;
use crate::store::SharedContentStore;
use murmel::p2p::PeerId;
use std::collections::HashMap;
use std::time::Duration;
use futures::task::Waker;
use crate::trunk::Trunk;
use crate::blockdownload::BlockDownload;
use crate::sendtx::SendTx;


const MAX_PROTOCOL_VERSION: u32 = 70001;

pub struct P2PBitcoin {
    connections: usize,
    peers: Vec<SocketAddr>,
    chaindb: SharedChainDB,
    network: Network,
    db: SharedDB,
    content_store: SharedContentStore,
    discovery: bool,
    birth: u64
}

impl P2PBitcoin {
    pub fn new (network: Network, connections: usize, peers: Vec<SocketAddr>, discovery: bool, chaindb: SharedChainDB, db: SharedDB, content_store: SharedContentStore, birth: u64) -> P2PBitcoin {
        P2PBitcoin {connections, peers, chaindb, network, db, content_store, discovery, birth}
    }
    pub fn start(&self, thread_pool: &mut ThreadPool) {
        let (sender, receiver) = mpsc::sync_channel(100);

        let mut dispatcher = Dispatcher::new(receiver);

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

        let downstream = Arc::new(Mutex::new(BitcoinDriver{store: self.content_store.clone()}));

        let processed_block;
        {
            let mut db = self.db.lock().unwrap();
            let mut tx = db.transaction();
            processed_block = tx.read_processed().expect("can not read processed block");
        }
        if let Some(mut processed_block) = processed_block {
            let mut disconnected = Vec::new();
            {
                // re-org might have happened while this node was down
                let chaindb = self.chaindb.read().unwrap();
                if let Some(mut header) = chaindb.get_header(&processed_block) {
                    while chaindb.pos_on_trunk(&processed_block).is_none() {
                        disconnected.push(header.stored.header.clone());
                        processed_block = header.stored.header.prev_blockhash;
                        header = chaindb.get_header(&processed_block).expect("inconsistent header cache");
                    }
                } else {
                    panic!("can not find header for last processed block");
                }
            }
            if !disconnected.is_empty() {
                let mut downstream = downstream.lock().unwrap();
                for h in &disconnected {
                    downstream.block_disconnected(h);
                }
            }
        }

        let timeout = Arc::new(Mutex::new(Timeout::new(p2p_control.clone())));

        if self.discovery {
            dispatcher.add_listener(AddressPoolMaintainer::new(p2p_control.clone(), self.db.clone(), murmel::p2p::SERVICE_BLOCKS));
        }
        dispatcher.add_listener(BlockDownload::new(self.chaindb.clone(), p2p_control.clone(), timeout.clone(), downstream, processed_block, self.birth));
        dispatcher.add_listener(Ping::new(p2p_control.clone(), timeout.clone()));

        let sendtx = SendTx::new(p2p_control.clone(), self.db.clone());
        self.content_store.write().unwrap().set_tx_sender(sendtx);

        let p2p2 = p2p.clone();
        let p2p_task = Box::new(future::poll_fn(move |ctx| {
            p2p2.run("bitcoin", murmel::p2p::SERVICE_BLOCKS, ctx).unwrap();
            Ok(Async::Ready(()))
        }));
        // start the task that runs all network communication
        thread_pool.spawn(p2p_task).unwrap();

        let keep_connected = Self::keep_connected(self.network, p2p.clone(), self.peers.clone(), self.connections, self.discovery, self.db.clone());
        let waker = keep_connected.waker.clone();
        thread::Builder::new().name("bitkeep".to_string()).spawn(move ||
            {
                thread::sleep(Duration::from_secs(10));
                let mut waker = waker.lock().unwrap();
                if let Some(ref mut w) = *waker {
                    w.wake();
                }
            }).expect("can not start bitcoin connector thread");
        info!("Bitcoin p2p engine started");
        thread_pool.spawn(Box::new(keep_connected)).unwrap();
    }

    fn keep_connected(network: Network, p2p: Arc<P2P<NetworkMessage, RawNetworkMessage, BitcoinP2PConfig>>, peers: Vec<SocketAddr>, min_connections: usize, discovery: bool, db: SharedDB) -> KeepConnected {
        // add initial peers if any
        let mut connections = Vec::new();
        for addr in &peers {
            connections.push((*addr, p2p.add_peer("bitcoin", PeerSource::Outgoing(addr.clone()))));
        }

        return KeepConnected { network, min_connections, connections, p2p,
            dns: Vec::new(), earlier: HashSet::new(), db, waker: Arc::new(Mutex::new(None)), discovery, peers };
    }
}

struct KeepConnected {
    network: Network,
    min_connections: usize,
    connections: Vec<(SocketAddr, Box<dyn Future<Item=SocketAddr, Error=MurmelError> + Send>)>,
    p2p: Arc<P2P<NetworkMessage, RawNetworkMessage, BitcoinP2PConfig>>,
    dns: Vec<SocketAddr>,
    earlier: HashSet<SocketAddr>,
    db: SharedDB,
    waker: Arc<Mutex<Option<Waker>>>,
    discovery: bool,
    peers: Vec<SocketAddr>
}

// this task runs until it runs out of peers
impl Future for KeepConnected {
    type Item = ();
    type Error = Never;

    fn poll(&mut self, cx: &mut task::Context) -> Poll<Self::Item, Self::Error> {
        // find a finished peers
        let finished = self.connections.iter_mut().enumerate().filter_map(|(i, (_, c))| {
            match c.poll(cx) {
                Ok(Async::Pending) => None,
                Ok(Async::Ready(address)) => {
                    debug!("keep connected woke up to lost peer at {}", address);
                    Some(i)
                },
                Err(e) => {
                    debug!("keep connected woke up to error {:?}", e);
                    Some(i)
                }
            }
        }).collect::<Vec<_>>();
        let mut n = 0;
        for i in finished.iter() {
            let (socket, _) = self.connections.remove(*i - n);
            n += 1;
            if !self.discovery && self.peers.contains(&socket) {
                // attempt to re-connect to mandatory peers
                self.connections.push((socket, self.p2p.add_peer("bitcoin", PeerSource::Outgoing(socket))));
            }
        }
        if self.discovery {
            while self.connections.len() < self.min_connections {
                if let Some(addr) = self.get_an_address() {
                    self.connections.push((addr, self.p2p.add_peer("bitcoin", PeerSource::Outgoing(addr))));
                } else {
                    warn!("Want to connect to {} bitcoin peers but have found only {}", self.min_connections, self.connections.len());
                    break;
                }
            }
        }
        let mut waker = self.waker.lock().unwrap();
        *waker = Some(cx.waker().clone());
        return Ok(Async::Pending);
    }
}

impl KeepConnected {
    fn get_an_address(&mut self) -> Option<SocketAddr> {
        if let Ok(Some(a)) = self.db.lock().unwrap().transaction().get_an_address("bitcoin", &self.earlier) {
            self.earlier.insert(a);
            return Some(a);
        }
        if self.dns.len() == 0 {
            self.dns = dns_seed(self.network);
            let mut db = self.db.lock().unwrap();
            let mut tx = db.transaction();
            for a in &self.dns {
                tx.store_address("bitcoin", a, 0, 0, 0).expect("can not store addresses in db");
            }
            tx.commit();
        }
        if self.dns.len() > 0 {
            let eligible = self.dns.iter().filter(|a| !self.earlier.contains(a)).cloned().collect::<Vec<_>>();
            if eligible.len() > 0 {
                let mut rng = thread_rng();
                let choice = eligible[(rng.next_u32() as usize) % eligible.len()];
                self.earlier.insert(choice.clone());
                return Some(choice);
            }
        }
        None
    }
}

struct AddressPoolMaintainer {
    db: SharedDB,
    addresses: HashMap<PeerId, SocketAddr>,
    needed_services: u64
}

impl AddressPoolMaintainer {
    pub fn new(p2p: P2PControlSender<NetworkMessage>, db: SharedDB, needed_services: u64) -> PeerMessageSender<NetworkMessage>  {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);
        let mut m = AddressPoolMaintainer { db, addresses: HashMap::new(), needed_services };

        thread::Builder::new().name("address pool".to_string()).spawn(move || { m.run(receiver) }).unwrap();

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver<NetworkMessage>) {
        while let Ok(msg) = receiver.recv () {
            match msg {
                PeerMessage::Connected(pid, addr) => {
                    if let Some(address) = addr {
                        self.addresses.insert(pid, address);
                        let mut db = self.db.lock().unwrap();
                        let mut tx = db.transaction();
                        debug!("store successful connection to {} peer={}", &address, pid);
                        let now = SystemTime::now().duration_since(
                            SystemTime::UNIX_EPOCH).unwrap().as_secs();
                        tx.store_address("bitcoin", &address, now, now, 0).unwrap();
                        tx.commit();
                    }
                }
                PeerMessage::Disconnected(pid, banned) => {
                    if banned {
                        if let Some(address) = self.addresses.remove(&pid) {
                            let mut db = self.db.lock().unwrap();
                            let mut tx = db.transaction();
                            let now = SystemTime::now().duration_since(
                                SystemTime::UNIX_EPOCH).unwrap().as_secs();
                            debug!("store ban of {} peer={}", &address, pid);
                            tx.store_address("bitcoin", &address, 0, 0, now).unwrap();
                            tx.commit();
                        }
                    }
                }
                PeerMessage::Message(pid, msg) => {
                    match msg {
                        NetworkMessage::Addr(av) => {
                            let mut db = self.db.lock().unwrap();
                            let mut tx = db.transaction();
                            for (last_seen, a) in &av {
                                if (*last_seen as u64) < (SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()) &&
                                    a.services & self.needed_services == self.needed_services {
                                    if let Ok(addr) = a.socket_addr() {
                                        debug!("received and stored address {} peer={}", &addr, pid);
                                        tx.store_address("bitcoin", &addr, 0, *last_seen as u64, 0).unwrap();
                                    }
                                }
                            }
                            tx.commit();
                        }
                        _ => { }
                    }
                }
            }
        }
    }
}

struct BitcoinDriver {
    store: SharedContentStore
}

impl Downstream for BitcoinDriver {
    fn block_connected(&mut self, block: &Block, height: u32) {
        self.store.write().unwrap().block_connected(block, height).expect("can not add block");
    }

    fn header_connected(&mut self, block: &BlockHeader, height: u32) {
        self.store.write().unwrap().add_header(height, block).expect("can not add header");
    }

    fn block_disconnected(&mut self, header: &BlockHeader) {
        self.store.write().unwrap().unwind_tip(header).expect("can not unwind tip");
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

    fn get_header_for_height(&self, height: u32) -> Option<BlockHeader> {
        if let Some(cached) = self.chaindb.read().unwrap().get_header_for_height(height) {
            return Some(cached.stored.header.clone());
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

