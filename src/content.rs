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

//! distributed content
use crate::bitcoin::PublicKey;
use crate::bitcoin_hashes::hex::ToHex;
use crate::bitcoin_wallet::{
    proved::ProvedTransaction
};

use crate::ad::Ad;
use crate::iblt::IBLTKey;

use std::{
    ops::BitXorAssign,
    hash::Hasher,
    fmt
};

const DIGEST_LEN: usize = secp256k1::constants::MESSAGE_SIZE;

/// Distributed content
#[derive(Clone, Copy, Serialize, Deserialize, Hash, Default, Eq, PartialEq)]
pub struct ContentKey {
    /// content digest
    pub digest: [u8; DIGEST_LEN]
}

impl BitXorAssign for ContentKey {
    fn bitxor_assign(&mut self, rhs: ContentKey) {
        self.digest.iter_mut().zip(rhs.digest.iter()).for_each(|(a, b)| *a ^= b);
    }
}

impl IBLTKey for ContentKey {
    fn hash_to_u64_with_keys(&self, k0: u64, k1: u64) -> u64 {
        let mut hasher = siphasher::sip::SipHasher::new_with_keys(k0, k1);
        hasher.write(&self.digest[..]);
        hasher.finish()
    }
}

impl fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "ContentKey{{digest: {}}} ", self.digest.to_hex())
    }
}

impl ContentKey {
    pub fn new (hash: &[u8]) -> ContentKey {
        assert_eq!(hash.len(), DIGEST_LEN);
        let mut digest = [0u8; DIGEST_LEN];
        digest.copy_from_slice(&hash[..]);
        ContentKey{digest}
    }
}

/// replicated content
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Content {
    /// content ad
    pub ad: Ad,
    /// funding transaction
    pub funding: ProvedTransaction,
    /// funder
    pub funder: PublicKey,
    /// term of funding in blocks (around 455 days max)
    pub term: u16
}

impl Content {
    pub fn length(&self) -> u32 {
        self.ad.serialize().len() as u32
    }
}

