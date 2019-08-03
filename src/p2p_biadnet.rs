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
    net::{IpAddr, SocketAddr, SocketAddrV4},
    path::Path,
    sync::{Arc, Mutex, RwLock, mpsc, atomic::AtomicUsize},
    time::{UNIX_EPOCH, SystemTime}
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
              executor::{Executor, ThreadPoolBuilder, ThreadPool}
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
    p2p::{
        PeerMessageSender, PeerSource,
        P2PConfig, P2PControl, Buffer
    },
    timeout::Timeout
};
use rand::{RngCore, thread_rng};
use simple_logger::init_with_level;

use crate::error::BiadNetError;
use crate::store::ContentStore;
use crate::messages::{Message, Envelope, VersionMessage, SockAddress};
use crate::updater::Updater;

use murmel::p2p::Version;
use serde_cbor::{Deserializer, StreamDeserializer};

const MAGIC: u32 = 0xB1AD;
const MAX_PROTOCOL_VERSION: u32 = 1;

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
                nonce: thread_rng().next_u64(),
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                start_height: 0, // TODO
                user_agent: "biadnet 0.1.0".to_string(),
                receiver: SockAddress::default(), // TODO
                sender: SockAddress::default(), // TODO
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

    fn set_height(&self, height: u32) {
    }

    fn max_protocol_version(&self) -> u32 {
        self.max_protocol_version
    }

    fn verack(&self) -> Message {
        Message::Verack
    }

    fn wrap(&self, m: Message) -> Envelope {
        Envelope{magic: MAGIC, payload: m}
    }

    fn unwrap(&self, e: Envelope) -> Message {
        e.payload
    }

    // encode a message in Bitcoin's wire format extending the given buffer
    fn encode(&self, item: &Envelope, dst: &mut Buffer) -> Result<(), io::Error> {
        match serde_cbor::to_writer(dst, item) {
            Err(e) => Err(io::Error::from(io::ErrorKind::InvalidInput)),
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

pub struct BiadNetAdaptor{}

impl BiadNetAdaptor {
    pub fn start(thread_pool: &mut ThreadPool) {
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

        let updater = Updater::new(p2p_control, timeout);
        dispatcher.add_listener(updater);

        let p2p2 = p2p.clone();
        let p2p_task = Box::new(future::poll_fn(move |ctx| {
            p2p2.run(0, ctx).unwrap();
            Ok(Async::Ready(()))
        }));
        // start the task that runs all network communication
        thread_pool.spawn(p2p_task).unwrap();

        info!("BiadNet p2p engine started");
        thread_pool.spawn(Self::keep_connected(p2p.clone(), vec!(), 3)).unwrap();
    }

    fn keep_connected(p2p: Arc<P2P<Message, Envelope, BiadnetP2PConfig>>, peers: Vec<SocketAddr>, min_connections: usize) -> Box<dyn Future<Item=(), Error=Never> + Send> {

        // add initial peers if any
        let mut added = Vec::new();
        for addr in &peers {
            added.push(p2p.add_peer(PeerSource::Outgoing(addr.clone())));
        }

        struct KeepConnected {
            min_connections: usize,
            connections: Vec<Box<dyn Future<Item=SocketAddr, Error=MurmelError> + Send>>,
            p2p: Arc<P2P<Message, Envelope, BiadnetP2PConfig>>,
            dns: Vec<SocketAddr>,
            earlier: HashSet<SocketAddr>
        }

        // this task runs until it runs out of peers
        impl Future for KeepConnected {
            type Item = ();
            type Error = Never;

            fn poll(&mut self, cx: &mut task::Context) -> Poll<Self::Item, Self::Error> {
                // return from this loop with 'pending' if enough peers are connected
                loop {
                    // add further peers from db if needed
                    self.peers_from_db();
                    self.dns_lookup();

                    if self.connections.len() == 0 {
                        // run out of peers. this is fatal
                        error!("no more peers to connect");
                        return Ok(Async::Ready(()));
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
            fn peers_from_db(&mut self) {
                // TODO
            }

            fn dns_lookup(&mut self) {
                while self.connections.len() < self.min_connections {
                    if self.dns.len() == 0 {
                        // TODO self.dns = dns_seed(self.network);
                    }
                    if self.dns.len() > 0 {
                        let mut rng = thread_rng();
                        let addr = self.dns[(rng.next_u64() as usize) % self.dns.len()];
                        self.connections.push(self.p2p.add_peer(PeerSource::Outgoing(addr)));
                    }
                    else {
                        break;
                    }
                }
            }
        }

        Box::new(KeepConnected { min_connections, connections: added, p2p, dns: Vec::new(), earlier: HashSet::new() })
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

