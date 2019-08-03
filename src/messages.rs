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
use bitcoin::network::address::Address;
use crate::bitcoin_hashes::sha256d;
use murmel::p2p::{Command, Version, VersionCarrier};
use std::sync::atomic::AtomicUsize;

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
                    receiver: Address { services: 0, address: v.receiver.address, port: v.receiver.port },
                    sender: Address { services: 0, address: v.sender.address, port: v.sender.port },
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
pub struct SockAddress {
    /// Network byte-order ipv6 address, or ipv4-mapped ipv6 address
    pub address: [u16; 8],
    /// Network port
    pub port: u16
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionMessage {
    pub version: u32,
    pub timestamp: u64,
    pub receiver: SockAddress,
    pub sender: SockAddress,
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

