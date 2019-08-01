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

use bitcoin::{
    Block, BlockHeader,
    network::constants::Network
};
use murmel::{
    dispatcher::Dispatcher,
    p2p::P2P
};

use log::Level;
use simple_logger::init_with_level;
use std::sync::mpsc;
use murmel::p2p::{PeerSource, PeerMessageSender};
use murmel::p2p::P2PControl;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use future::Future;
use futures::{Never, future};
use futures::Async;
use futures::executor::{Executor, ThreadPoolBuilder};
use murmel::chaindb::ChainDB;
use murmel::headerdownload::HeaderDownload;
use murmel::timeout::Timeout;
use murmel::downstream::Downstream;

use biadne::store::ContentStore;
use std::sync::RwLock;

const MAX_PROTOCOL_VERSION: u32 = 70001;

pub fn main () {
    simple_logger::init_with_level(Level::Debug).unwrap();

    let mynode = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(87,230,22,85), 8333));

    let (sender, receiver) = mpsc::sync_channel(100);

    let mut dispatcher = Dispatcher::new(receiver);

    let chaindb = Arc::new(RwLock::new(
        ChainDB::new(&Path::new("headers"), Network::Bitcoin, 0).expect("can not open db")));
    chaindb.write().unwrap().init(false).expect("can not initialize db");

    let (p2p, p2p_control) = P2P::new(
        "biadnet 0.1.0".to_string(),
        Network::Bitcoin,
        0,
        MAX_PROTOCOL_VERSION,
        false,
        PeerMessageSender::new(sender),
        10);

    let timeout = Arc::new(Mutex::new(Timeout::new(p2p_control.clone())));

    let downstream = Arc::new(Mutex::new(Driver{store: ContentStore::new()}));

    let header_downloader = HeaderDownload::new(chaindb.clone(), p2p_control.clone(), timeout, downstream);

    dispatcher.add_listener(header_downloader);

    p2p.add_peer(PeerSource::Outgoing(mynode));

    let mut thread_pool = ThreadPoolBuilder::new().create().expect("can not start thread pool");
    let p2p2 = p2p.clone();
    let p2p_task = Box::new(future::poll_fn(move |ctx| {
        p2p2.run(0, ctx).unwrap();
        Ok(Async::Ready(()))
    }));
    // start the task that runs all network communication
    thread_pool.spawn(p2p_task).unwrap();

    // note that this call does not return
    thread_pool.run::<Box<dyn Future<Item=(),Error=Never>>>(Box::new(future::poll_fn(|c| Ok(Async::Pending)))).unwrap();
}

pub struct Driver {
    store: ContentStore
}

impl Downstream for Driver {
    fn block_connected(&mut self, block: &Block, height: u32) {}

    fn header_connected(&mut self, block: &BlockHeader, height: u32) {
        self.store.add_header(block).expect("can not add header");
    }

    fn block_disconnected(&mut self, _: &BlockHeader) {
        self.store.unwind_tip().expect("can not unwind tip");
    }
}