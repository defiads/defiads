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
use crate::bitcoin_hashes::{sha256, sha256d};
use murmel::p2p::{Command, Version, VersionCarrier};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io;
use crate::error::BiadNetError;
use crate::iblt::{IBLT, IBLTKey};
use crate::content::ContentKey;
use crate::content::Content;
use crate::discovery::NetAddress;

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
            Message::PollAddress(_) => "poll address",
            Message::AddressIBLT(_) => "address iblt",
            Message::PollContent(_) => "poll content",
            Message::ContentIBLT(_, _) => "content iblt",
            Message::Get(_) => "get",
            Message::Content(_) => "content"
        }.to_string()
    }
}

/// All P2P messages supported
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    Version(VersionMessage),
    Verack,
    PollAddress(PollAddressMessage),
    AddressIBLT(IBLT<NetAddress>),
    PollContent(PollContentMessage),
    ContentIBLT(sha256d::Hash, IBLT<ContentKey>),
    Get(Vec<sha256::Hash>),
    Content(Content)
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
    pub tip: sha256d::Hash,
    /// min sketch of own id set
    pub sketch: Vec<u64>,
    /// own set size
    pub size: u32
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PollAddressMessage {
    /// min sketch of own id set
    pub sketch: Vec<u64>,
    /// own set size
    pub size: u32
}