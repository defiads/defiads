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

//! P2P messages
use crate::bitcoin_hashes::sha256d;
use murmel::p2p::{Command, Version, VersionCarrier};
use std::sync::atomic::AtomicUsize;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io;
use crate::error::BiadNetError;

#[derive(Serialize, Deserialize, Debug)]
pub struct Envelope {
    pub magic: u32,
    pub payload: Message
}

impl Command for Envelope {
    fn command(&self) -> String {
        match self.payload {
            Message::Version(_) => "version",
            Message::Verack => "verack",
            Message::PollContent(_) => "poll content"
        }.to_string()
    }
}

/// All P2P messages supported
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    Version(VersionMessage),
    Verack,
    PollContent(PollContentMessage),
}

impl Version for Message {
    fn is_verack(&self) -> bool {
        match self {
            Message::Verack => true,
            _ => false
        }
    }

    fn is_version(&self) -> Option<VersionCarrier> {
        match self {
            Message::Version(v) => {
                Some(VersionCarrier {
                    version: v.version,
                    receiver: bitcoin::network::address::Address { services: 0, address: v.receiver.address, port: v.receiver.port },
                    sender: bitcoin::network::address::Address { services: 0, address: v.sender.address, port: v.sender.port },
                    user_agent: v.user_agent.clone(),
                    start_height: v.start_height,
                    timestamp: v.timestamp,
                    nonce: v.nonce,
                    relay: false,
                    services: 0
                })
            },
            _ => None
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct NetAddress {
    /// Network byte-order ipv6 address, or ipv4-mapped ipv6 address
    pub address: [u16; 8],
    /// Network port
    pub port: u16
}

const ONION : [u16; 3] = [0xFD87, 0xD87E, 0xEB43];

impl NetAddress {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionMessage {
    pub version: u32,
    pub timestamp: u64,
    pub receiver: NetAddress,
    pub sender: NetAddress,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: u32
}

/// Connect message
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PollContentMessage {
    /// known chain tip of Bitcoin
    tip: sha256d::Hash,
    /// min sketch of own id set
    sketch: Vec<u64>,
    /// own set size
    size: usize
}

