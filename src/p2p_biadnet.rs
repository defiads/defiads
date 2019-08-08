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
    io,
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, Mutex, mpsc},
    time::{UNIX_EPOCH, SystemTime},
    thread
};
use bitcoin::{
    BlockHeader
};
use bitcoin_hashes::sha256d;
use bitcoin_wallet::trunk::Trunk;
use future::Future;
use futures::{future, Never, Async, Poll, task,
              executor::{Executor, ThreadPool}
};

use murmel::{
    dispatcher::Dispatcher,
    p2p::P2P,
    chaindb::SharedChainDB,
    error::MurmelError,
    p2p::{
        PeerMessageSender, PeerSource,
        P2PConfig, P2PControl, Buffer
    },
    timeout::Timeout
};
use rand::{RngCore, thread_rng};

use crate::find_peers::seed;
use crate::messages::{Message, Envelope, VersionMessage, NetAddress};
use crate::updater::Updater;

use serde_cbor::Deserializer;
use crate::db::SharedDB;
use crate::store::SharedContentStore;
use murmel::p2p::P2PControlSender;
use murmel::p2p::PeerMessageReceiver;
use murmel::p2p::PeerMessage;
use std::collections::HashMap;
use murmel::p2p::PeerId;
use std::time::Duration;
use futures::task::Waker;

const MAGIC: u32 = 0xB1AD;
const MAX_PROTOCOL_VERSION: u32 = 1;
const MIN_PROTOCOL_VERSION: u32 = 1;
const MAX_MESSAGE_SIZE:usize = 2^26;

#[derive(Clone)]
struct BiadnetP2PConfig {
    // This node's identifier on the network (random)
    pub nonce: u64,
    // This node's human readable type identification
    pub user_agent: String,
    // this node's maximum protocol version
    pub max_protocol_version: u32,
    // serving others
    pub server: bool,
}

impl P2PConfig<Message, Envelope> for BiadnetP2PConfig {
    // compile this node's version message for outgoing connections
    fn version (&self, remote: &SocketAddr, max_protocol_version: u32) -> Message {
        Message::Version(
            VersionMessage {
                version: std::cmp::min(MAX_PROTOCOL_VERSION, max_protocol_version),
                nonce: self.nonce,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                start_height: 0, // TODO
                user_agent: "biadnet 0.1.0".to_string(),
                receiver: NetAddress::new(remote),
                sender: NetAddress::default(), // TODO
            }
        )
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn magic(&self) -> u32 {
        MAGIC
    }

    fn user_agent(&self) -> &str {
        self.user_agent.as_str()
    }

    fn get_height(&self) -> u32 {
        0
    }

    fn set_height(&self, _height: u32) {
    }

    fn max_protocol_version(&self) -> u32 {
        self.max_protocol_version
    }

    fn min_protocol_version(&self) -> u32 {
        MIN_PROTOCOL_VERSION
    }

    fn verack(&self) -> Message {
        Message::Verack
    }

    fn wrap(&self, m: Message) -> Envelope {
        Envelope{magic: MAGIC, payload: m}
    }

    fn unwrap(&self, e: Envelope) -> Result<Message, io::Error> {
        Ok(e.payload)
    }

    // encode a message in Bitcoin's wire format extending the given buffer
    fn encode(&self, item: &Envelope, dst: &mut Buffer) -> Result<(), io::Error> {
        match serde_cbor::to_writer(dst, item) {
            Err(_) => Err(io::Error::from(io::ErrorKind::InvalidInput)),
            Ok(_)=> Ok(())
        }
    }

    // decode a message from the buffer if possible
    fn decode(&self, src: &mut Buffer) -> Result<Option<Envelope>, io::Error> {
        // attempt to decode
        let decode;
        {
            let passthrough = PassThroughBufferReader{buffer: src};
            decode = Deserializer::from_reader(passthrough).into_iter::<Envelope>().next();
        }
        match decode {
            None => {
                if src.len() > MAX_MESSAGE_SIZE {
                    return  Err(io::Error::from(io::ErrorKind::InvalidInput));
                }
                src.rollback();
                return Ok(None);
            }
            Some(Ok(m)) => {
                // success: free the read data in buffer and return the message
                src.commit();
                Ok(Some(m))
            },
            Some(Err(e)) => {
                if e.classify() == serde_cbor::error::Category::Eof {
                    // need more data, rollback and retry after additional read
                    src.rollback();
                    return Ok(None)
                } else {
                    return  Err(io::Error::from(io::ErrorKind::InvalidInput));
                }
            },
        }
    }
}

struct PassThroughBufferReader<'a> {
    buffer: &'a mut Buffer
}

impl<'a> io::Read for PassThroughBufferReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.buffer.read(buf)
    }
}

pub struct P2PBiadNet {
    connections: usize,
    peers: Vec<SocketAddr>,
    listen: Vec<SocketAddr>,
    db: SharedDB,
    content_store: SharedContentStore
}

impl P2PBiadNet {
    pub fn new (connections: usize, peers: Vec<SocketAddr>, listen: Vec<SocketAddr>, db: SharedDB, content_store: SharedContentStore) -> P2PBiadNet {
        P2PBiadNet {connections, peers, listen, db, content_store}
    }
    pub fn start(&self, thread_pool: &mut ThreadPool) {
        let (sender, receiver) = mpsc::sync_channel(100);
        let mut dispatcher = Dispatcher::new(receiver);

        let p2pconfig = BiadnetP2PConfig {
            nonce: thread_rng().next_u64(),
            max_protocol_version: MAX_PROTOCOL_VERSION,
            user_agent: "biadnet 0.1.0".to_string(),
            server: false
        };

        let (p2p, p2p_control) = P2P::new(
            p2pconfig,
            PeerMessageSender::new(sender),
            10);

        let timeout = Arc::new(Mutex::new(Timeout::new(p2p_control.clone())));

        let updater = Updater::new(p2p_control.clone(), timeout.clone(), self.content_store.clone());
        dispatcher.add_listener(updater);
        let address_pool = AddressPoolMaintainer::new(p2p_control.clone(), self.db.clone());
        dispatcher.add_listener(address_pool);

        let p2p2 = p2p.clone();
        let p2p_task = Box::new(future::poll_fn(move |ctx| {
            p2p2.run("biadnet", 0, ctx).unwrap();
            Ok(Async::Ready(()))
        }));

        for addr in &self.listen {
            p2p_control.send(P2PControl::Bind(addr.clone()));
        }

        // start the task that runs all network communication
        thread_pool.spawn(p2p_task).unwrap();

        info!("BiadNet p2p engine started");
        let keep_connected = Self::keep_connected(p2p.clone(), self.peers.clone(), self.connections, self.db.clone());
        let waker = keep_connected.waker.clone();
        thread::Builder::new().name("biadnet keep connected".to_string()).spawn(move ||
            {
                thread::sleep(Duration::from_secs(30));
                let mut waker = waker.lock().unwrap();
                if let Some(ref mut w) = *waker {
                    w.wake();
                }
            }).expect("can not start biadnet connector thread");
        thread_pool.spawn(Box::new(keep_connected)).unwrap();
    }

    fn keep_connected(p2p: Arc<P2P<Message, Envelope, BiadnetP2PConfig>>, peers: Vec<SocketAddr>, min_connections: usize, db: SharedDB) -> KeepConnected {

        // add initial peers if any
        let mut added = Vec::new();
        for addr in &peers {
            added.push(p2p.add_peer("biadnet", PeerSource::Outgoing(addr.clone())));
        }

        return KeepConnected { min_connections, connections: added, p2p,
            dns: Vec::new(), earlier: HashSet::new(), db, waker: Arc::new(Mutex::new(None)) };
    }
}


struct KeepConnected {
    min_connections: usize,
    connections: Vec<Box<dyn Future<Item=SocketAddr, Error=MurmelError> + Send>>,
    p2p: Arc<P2P<Message, Envelope, BiadnetP2PConfig>>,
    dns: Vec<SocketAddr>,
    earlier: HashSet<SocketAddr>,
    db: SharedDB,
    waker: Arc<Mutex<Option<Waker>>>
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
                    self.connections.push(self.p2p.add_peer("biadnet", PeerSource::Outgoing(addr)));
                }
                else {
                    warn!("no more biadnet peers to connect");
                    let mut waker = self.waker.lock().unwrap();
                    *waker = Some(cx.waker().clone());
                    return Ok(Async::Pending);
                }
            }
            // find a finished peer
            let finished = self.connections.iter_mut().enumerate().filter_map(|(i, f)| {
                // if any of them finished
                // note that poll is reusing context of this poll, so wakeups come here
                match f.poll(cx) {
                    Ok(Async::Pending) => None,
                    Ok(Async::Ready(address)) => {
                        trace!("keep connected woke up to lost peer at {}", address);
                        Some((i, Ok(address)))
                    }
                    Err(e) => {
                        trace!("keep connected woke up to error {:?}", e);
                        Some((i, Err(e)))
                    }
                }
            }).next();
            match finished {
                Some((i, _)) => {self.connections.remove(i);},
                None => {}
            };
        }
    }
}

impl KeepConnected {
    fn get_an_address(&mut self) -> Option<SocketAddr> {
        if let Ok(Some(a)) = self.db.lock().unwrap().transaction().get_an_address("biadnet", &self.earlier) {
            self.earlier.insert(a);
            return Some(a);
        }
        if self.dns.len() == 0 {
            self.dns = seed();
            let mut db = self.db.lock().unwrap();
            let mut tx = db.transaction();
            for a in &self.dns {
                tx.store_address("biadnet", a, 0, 0).expect("can not store addresses in db");
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
    addresses: HashMap<PeerId, SocketAddr>
}

impl AddressPoolMaintainer {
    pub fn new(p2p: P2PControlSender<Message>, db: SharedDB) -> PeerMessageSender<Message>  {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);
        let mut m = AddressPoolMaintainer { db, addresses: HashMap::new() };

        thread::Builder::new().name("address pool".to_string()).spawn(move || { m.run(receiver) }).unwrap();

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver<Message>) {
        while let Ok(msg) = receiver.recv () {
            match msg {
                PeerMessage::Connected(pid, addr) => {
                    if let Some(address) = addr {
                        self.addresses.insert(pid, address);
                        let mut db = self.db.lock().unwrap();
                        let mut tx = db.transaction();
                        debug!("store successful connection to {} peer={}", &address, pid);
                        tx.store_address("biadnet", &address,
                                         SystemTime::now().duration_since(
                                             SystemTime::UNIX_EPOCH).unwrap().as_secs(), 0).unwrap();
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
                            tx.store_address("biadnet", &address, 0, now).unwrap();
                            tx.commit();
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

#[derive(Eq, PartialEq, Hash, Debug)]
pub enum ExpectedReply {
    PollContent,
    IBLT,
    Content,
    Get
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

