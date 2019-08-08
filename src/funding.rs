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
use crate::secp256k1::{Secp256k1, All};
use crate::byteorder::{LittleEndian, ByteOrder};

pub fn funding_script (funder: &PublicKey, digest: &sha256::Hash, term: u16, ctx: &Secp256k1<All>) -> Script {
    let mut tweaked = funder.clone();
    tweaked.key.add_exp_assign(ctx, &digest[..]).unwrap();
    let mut buf = [0u8; 4];
    LittleEndian::write_u32(&mut buf, term as u32 | (1 << 22));

    let script = Builder::new()
        .push_slice(&buf[0..3])
        .push_opcode(all::OP_NOP3) // OP_CHECKSEQUENCEVERIFY
        .push_opcode(all::OP_DROP)
        .push_slice(tweaked.to_bytes().as_slice())
        .push_opcode(all::OP_CHECKSIGVERIFY)
        .into_script();

    Address::p2wsh(&script, Network::Bitcoin).script_pubkey()
}

