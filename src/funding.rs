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

//! Funding related code

use crate::bitcoin::{
    PublicKey, Script,
    blockdata::{
        script::Builder,
        opcodes::all
    },
    util::address::Address,
    network::constants::Network
};

use crate::bitcoin_hashes::sha256;
use bitcoin_wallet::context::SecpContext;
use std::sync::Arc;

pub fn funding_script (funder: &PublicKey, digest: &sha256::Hash, term: u16, ctx: Arc<SecpContext>) -> Script {
    let mut tweaked = funder.clone();
    ctx.tweak_exp_add(&mut tweaked, &digest[..]).unwrap();

    let script = Builder::new()
        .push_int(term as i64)
        .push_opcode(all::OP_CSV)
        .push_opcode(all::OP_DROP)
        .push_slice(tweaked.to_bytes().as_slice())
        .push_opcode(all::OP_CHECKSIGVERIFY)
        .into_script();

    Address::p2wsh(&script, Network::Bitcoin).script_pubkey()
}

