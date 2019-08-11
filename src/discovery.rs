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

use crate::error::BiadNetError;
use crate::iblt::IBLTKey;

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
