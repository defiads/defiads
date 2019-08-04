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

//! biadnet

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(unused_must_use)]
#![forbid(unsafe_code)]


extern crate snap;
extern crate byteorder;
extern crate serde;
#[macro_use]extern crate serde_derive;
#[cfg(test)]extern crate hex;
extern crate bitcoin_hashes;
extern crate bitcoin;
extern crate bitcoin_wallet;
extern crate siphasher;
extern crate secp256k1;
extern crate rand;
extern crate murmel;
#[macro_use]extern crate log;
extern crate simple_logger;
extern crate rusqlite;

mod error;
mod text;
mod ad;
mod iblt;
mod messages;
mod content;
mod funding;
mod store;
mod db;
pub mod updater;
pub mod p2p_bitcoin;
pub mod p2p_biadnet;
