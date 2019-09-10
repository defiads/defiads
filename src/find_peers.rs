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
//! Find peers

use std::net::{SocketAddr, ToSocketAddrs};

pub const BIADNET_PORT: u16 = 21766;

const SEEDER: [&str;0] = [];

pub fn seed (test: bool) -> Vec<SocketAddr> {
    let mut seeds = Vec::new ();
    info!("reaching out for defiads seed...");
    for seedhost in SEEDER.iter() {
        if let Ok(lookup) = (*seedhost, BIADNET_PORT + if test {100} else {0}).to_socket_addrs() {
            for host in lookup {
                seeds.push(host);
            }
        } else {
            trace!("{} did not answer", seedhost);
        }
    }
    info!("received {} defiads seeds", seeds.len());
    seeds
}