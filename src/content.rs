//! distributed content

use std::{
    ops::BitXorAssign,
    hash::Hasher,
    fmt,
    error
};
use crate::bitcoin::{
    Transaction,
    Script,
    blockdata::{
        opcodes::all,
        script::Builder
    },
    PublicKey,
    BitcoinHash,
    util::address::Address,
    network::constants::Network
};

use crate::bitcoin_hashes::{
    sha256d,
    sha256,
    Hash,
    HashEngine,
    hex::ToHex
};

use secp256k1::{Secp256k1, VerifyOnly};

use crate::iblt::IBLTKey;

use byteorder::{ByteOrder, BigEndian, LittleEndian};

const DIGEST_LEN: usize = secp256k1::constants::MESSAGE_SIZE;

/// Distributed content
#[derive(Clone, Copy, Serialize, Deserialize, Hash, Default, Eq, PartialEq)]
pub struct ContentKey {
    /// content digest
    pub digest: [u8; DIGEST_LEN],
    /// content length
    pub length: u32,
    /// content weight (funding/length)
    pub weight: u32
}

impl BitXorAssign for ContentKey {
    fn bitxor_assign(&mut self, rhs: ContentKey) {
        self.length ^= rhs.length;
        self.weight ^= rhs.weight;
        self.digest.iter_mut().zip(rhs.digest.iter()).for_each(|(a, b)| *a ^= b);
    }
}

impl IBLTKey for ContentKey {
    fn hash_to_u64_with_keys(&self, k0: u64, k1: u64) -> u64 {
        let mut hasher = siphasher::sip::SipHasher::new_with_keys(k0, k1);
        let mut buf = [0u8; 4];
        BigEndian::write_u32(&mut buf, self.length);
        hasher.write(&buf);
        BigEndian::write_u32(&mut buf, self.weight);
        hasher.write(&buf);
        hasher.write(&self.digest[..]);
        hasher.finish()
    }
}

impl fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "ContentKey{{ digest: {} weight: {} }} ", self.digest.to_hex(), self.weight)
    }
}

impl ContentKey {
    pub fn new (hash: &[u8], length: u32, weight: u32) -> ContentKey {
        assert_eq!(hash.len(), DIGEST_LEN);
        let mut digest = [0u8; DIGEST_LEN];
        digest.copy_from_slice(&hash[..]);
        ContentKey{digest, length, weight}
    }
}

/// replicated content
#[derive(Clone, Serialize, Deserialize)]
pub struct Content {
    /// content data
    pub data: Vec<u8>,
    /// funding transaction
    pub funding: Transaction,
    /// block id the transaction was included into
    pub block_id: sha256d::Hash,
    /// SPV proof that the transaction is included into the block
    pub spv_proof: Vec<(bool, sha256d::Hash)>,
    /// funder
    pub funder: PublicKey,
    /// term of funding in blocks
    pub term: u16
}

impl Content {
    /// calculate the digest that identifies this content
    pub fn digest (&self) -> sha256::Hash {
        let mut hasher = sha256::Hash::engine();
        hasher.input(self.data.as_slice());
        hasher.input(&self.funder.to_bytes().as_slice());
        sha256::Hash::from_engine(hasher)
    }

    /// check if the spv proof is correct
    pub fn is_valid_spv_proof(&self, merkle_root: &sha256d::Hash) -> bool {
        self.spv_proof.iter().fold(self.funding.bitcoin_hash(), |a, (left, b)| {
            let mut hasher = sha256::Hash::engine();
            if *left {
                hasher.input(&b[..]);
                hasher.input(&a[..]);
            }
            else {
                hasher.input(&a[..]);
                hasher.input(&b[..]);
            }
            sha256d::Hash::from_engine(hasher)
        }) == *merkle_root
    }

    pub fn length(&self) -> Result<u32, Box<dyn error::Error>> {
        Ok(serde_cbor::to_vec(self)?.len() as u32)
    }

    /// return ratio of funding and size
    pub fn weight (&self, ctx: &Secp256k1<VerifyOnly>) -> Result<u32, Box<dyn error::Error>> {
        let f_script = funding_script(&self.funder, &self.digest(), self.term, ctx);

        Ok((self.funding.output.iter().filter_map(|o| if o.script_pubkey == f_script { Some(o.value)} else {None}).sum::<u64>()
            / self.length()? as u64) as u32)
    }
}

pub fn funding_script (funder: &PublicKey, digest: &sha256::Hash, term: u16, ctx: &Secp256k1<VerifyOnly>) -> Script {
    let mut tweaked = funder.clone();
    tweaked.key.add_exp_assign(ctx, &digest[..]).unwrap();
    let mut buf = [0u8; 4];
    LittleEndian::write_u16(&mut buf, term | (1 << 22));

    let script = Builder::new()
        .push_slice(tweaked.to_bytes().as_slice())
        .push_opcode(all::OP_CHECKSIGVERIFY)
        .push_slice(&buf[0..3])
        .push_opcode(all::OP_NOP3) // OP_CHECKSEQUENCEVERIFY
        .into_script();

    Address::p2wsh(&script, Network::Bitcoin).script_pubkey()
}
