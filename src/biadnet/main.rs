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

use bitcoin::network::constants::Network;
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
use future::Future;
use futures::{Never, future};
use futures::Async;
use futures::executor::{Executor, ThreadPoolBuilder};

const MAX_PROTOCOL_VERSION: u32 = 70001;

pub fn main () {
    simple_logger::init_with_level(Level::Trace).unwrap();

    let mynode = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(87,230,22,85), 8333));

    let (sender, receiver) = mpsc::sync_channel(100);

    let dispatcher = Dispatcher::new(receiver);

    let (p2p, p2p_control) = P2P::new(
        "biadnet 0.1.0".to_string(),
        Network::Bitcoin,
        0,
        MAX_PROTOCOL_VERSION,
        false,
        PeerMessageSender::new(sender),
        10);

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