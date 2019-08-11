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
//! BiadNet network discovery

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, SocketAddrV4};
use std::io;
use std::hash::Hasher;
use byteorder::{ByteOrder, LittleEndian};
use std::ops::BitXorAssign;
use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, Duration};

use murmel::p2p::{PeerId, P2PControlSender, PeerMessageSender, PeerMessageReceiver, PeerMessage};
use murmel::timeout::SharedTimeout;

use crate::p2p_biadnet::ExpectedReply;
use crate::messages::{PollAddressMessage, Message};
use crate::error::BiadNetError;
use crate::iblt::{IBLTKey, estimate_diff_size, IBLT, IBLTEntry};
use crate::db::SharedDB;


const MINIMUM_IBLT_SIZE: u32 = 100;
const MAXIMUM_IBLT_SIZE: u32 = MINIMUM_IBLT_SIZE << 2;
const POLL_FREQUENCY: u64 = 60; // every minute

pub struct Discovery {
    p2p: P2PControlSender<Message>,
    timeout: SharedTimeout<Message, ExpectedReply>,
    db: SharedDB,
    poll_asked: HashMap<PeerId, PollAddressMessage>,
    iblt_sent: HashMap<PeerId, IBLT<NetAddress>>
}

impl Discovery {
    pub fn new(p2p: P2PControlSender<Message>, timeout: SharedTimeout<Message, ExpectedReply>, db: SharedDB) -> PeerMessageSender<Message> {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut discovery = Discovery { p2p, timeout, db, poll_asked: HashMap::new(), iblt_sent: HashMap::new() };

        thread::Builder::new().name("discovery".to_string()).spawn(move || { discovery.run(receiver) }).unwrap();

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver<Message>) {
        let mut last_polled = SystemTime::now();
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                match msg {
                    PeerMessage::Connected(pid, _) => {
                        debug!("address poll peer={}", pid);
                        self.poll_address(pid);
                        last_polled = SystemTime::now();
                    },
                    PeerMessage::Disconnected(pid,_) => {
                        self.poll_asked.remove(&pid);
                        self.iblt_sent.remove(&pid);
                    }
                    PeerMessage::Message(pid, msg) => {
                        match msg {
                            Message::PollAddress(poll) => {
                                if let Some(question) = self.poll_asked.remove(&pid) {
                                    debug!("got address poll reply from peer={}", pid);
                                    // this is a reply
                                    self.timeout.lock().unwrap().received(pid, 1, ExpectedReply::PollAddress);
                                    let diff = estimate_diff_size(
                                        question.sketch.as_slice(), question.size,
                                        poll.sketch.as_slice(), poll.size)*3/2;
                                    if diff > 0 {
                                        let mut size = MINIMUM_IBLT_SIZE;
                                        while size < MAXIMUM_IBLT_SIZE && size < diff {
                                            size <<= 2;
                                        }
                                        let mut db = self.db.lock().unwrap();
                                        let mut tx = db.transaction();
                                        let iblt = tx.compute_address_iblt(size).expect("could not compute address IBLT").clone();
                                        self.iblt_sent.insert(pid, iblt.clone());
                                        self.timeout.lock().unwrap().expect(pid, 1, ExpectedReply::AddressIBLT);
                                        debug!("ask IBLT of size {} from peer={}", size, pid);
                                        self.p2p.send_network(pid, Message::AddressIBLT(iblt));
                                    }
                                    else {
                                        debug!("in sync with peer={}", pid);
                                    }
                                }
                                else {
                                    // this is initial request
                                    debug!("reply address poll to peer={}", pid);
                                    self.poll_address(pid)
                                }
                            }
                            Message::AddressIBLT(mut iblt) => {
                                self.timeout.lock().unwrap().received(pid, 1, ExpectedReply::AddressIBLT);
                                debug!("received address IBLT from peer={}", pid);
                                if let Some(sent) = self.iblt_sent.remove(&pid) {
                                    iblt.substract(&sent);
                                }
                                let mut db = self.db.lock().unwrap();
                                let mut tx = db.transaction();
                                for entry in iblt.into_iter() {
                                    if let Ok(entry) = entry {
                                        match entry {
                                            IBLTEntry::Deleted(addr) => {
                                                if let Ok(addr) = addr.socket_address() {
                                                    tx.store_address("biadnet", &addr, 0, 0).expect("can not store addresses");
                                                }
                                            }
                                            _ => {}
                                        };
                                    }
                                    else {
                                        debug!("not successful inverting address IBLT diff with peer={}", pid);
                                        break;
                                    }
                                }
                                tx.commit();
                            }
                            _ => {}
                        }
                    }
                }
            }
            self.timeout.lock().unwrap().check(vec!(ExpectedReply::PollAddress, ExpectedReply::AddressIBLT));
        }
    }

    fn poll_address(&mut self, pid: PeerId) {
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction();
        let (sketch, size) = tx.compute_address_sketch(10).expect("can not compute address sketch");
        let poll = PollAddressMessage {
            sketch,
            size
        };

        self.poll_asked.insert(pid, poll.clone());
        self.p2p.send_network(pid, Message::PollAddress(poll));
        self.timeout.lock().unwrap().expect(pid, 1, ExpectedReply::PollAddress);
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Hash, Default, Eq, PartialEq, Debug)]
pub struct NetAddress {
    /// Network byte-order ipv6 address, or ipv4-mapped ipv6 address
    pub address: [u16; 8],
    /// Network port
    pub port: u16
}

const ONION : [u16; 3] = [0xFD87, 0xD87E, 0xEB43];

impl NetAddress {
    /// Create an address message for a socket
    pub fn new (socket :&SocketAddr) -> NetAddress {
        let (address, port) = match socket {
            &SocketAddr::V4(ref addr) => (addr.ip().to_ipv6_mapped().segments(), addr.port()),
            &SocketAddr::V6(ref addr) => (addr.ip().segments(), addr.port())
        };
        NetAddress { address: address, port: port }
    }


    pub fn socket_address(&self) -> Result<SocketAddr, BiadNetError> {
        let addr = &self.address;
        if addr[0..3] == ONION[0..3] {
            return Err(BiadNetError::IO(io::Error::from(io::ErrorKind::AddrNotAvailable)));
        }
        let ipv6 = Ipv6Addr::new(
            addr[0],addr[1],addr[2],addr[3],
            addr[4],addr[5],addr[6],addr[7]
        );
        if let Some(ipv4) = ipv6.to_ipv4() {
            Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, self.port)))
        }
        else {
            Ok(SocketAddr::V6(SocketAddrV6::new(ipv6, self.port, 0, 0)))
        }
    }

    pub fn to_string(&self) -> Result<String, BiadNetError> {
        Ok(format!("{}", self.socket_address()?))
    }

    pub fn from_str(s: &str) -> Result<NetAddress, BiadNetError> {
        use std::str::FromStr;

        let (address, port) = match SocketAddr::from_str(s)? {
            SocketAddr::V4(ref addr) => (addr.ip().to_ipv6_mapped().segments(), addr.port()),
            SocketAddr::V6(ref addr) => (addr.ip().segments(), addr.port())
        };
        Ok(NetAddress { address, port })
    }
}

impl BitXorAssign for NetAddress {
    fn bitxor_assign(&mut self, rhs: NetAddress) {
        self.address.iter_mut().zip(rhs.address.iter()).for_each(|(a, b)| *a ^= b);
        self.port ^= rhs.port;
    }
}

impl IBLTKey for NetAddress {
    fn hash_to_u64_with_keys(&self, k0: u64, k1: u64) -> u64 {
        let mut hasher = siphasher::sip::SipHasher::new_with_keys(k0, k1);
        let mut buf = [0u8;2];
        for a in &self.address {
            LittleEndian::write_u16(&mut buf, *a);
            hasher.write(&buf);
        }
        LittleEndian::write_u16(&mut buf, self.port);
        hasher.write(&buf);
        hasher.finish()
    }
}
