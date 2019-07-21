//! distributed content

use std::{
    ops::BitXorAssign,
    hash::Hasher,
    fmt,
    error
};
use crate::bitcoin::{
    Transaction,
    PublicKey,
    consensus,
    BitcoinHash
};

use crate::bitcoin_hashes::{
    sha256d,
    sha256,
    Hash,
    HashEngine,
    hex::ToHex
};

use secp256k1::{Secp256k1, Signature, VerifyOnly, Message};

use crate::iblt::IBLTKey;
use crate::serde::{Serialize, Deserialize, Serializer, Deserializer};

use byteorder::{ByteOrder, BigEndian};

const DIGEST_LEN: usize = secp256k1::constants::MESSAGE_SIZE;

/// Distributed content
#[derive(Clone, Copy, Serialize, Deserialize, Hash, Default, Eq, PartialEq)]
pub struct ContentKey {
    /// content digest
    pub digest: [u8; DIGEST_LEN],
    /// content weight
    pub weight: u32
}

impl BitXorAssign for ContentKey {
    fn bitxor_assign(&mut self, rhs: ContentKey) {
        self.weight ^= rhs.weight;
        self.digest.iter_mut().zip(rhs.digest.iter()).for_each(|(a, b)| *a ^= b);
    }
}

impl IBLTKey for ContentKey {
    fn hash_to_u64_with_keys(&self, k0: u64, k1: u64) -> u64 {
        let mut hasher = siphasher::sip::SipHasher::new_with_keys(k0, k1);
        let mut buf = [0u8; 4];
        BigEndian::write_u32(&mut buf, self.weight);
        hasher.write(&buf);
        hasher.write(&self.digest[..]);
        hasher.finish()
    }
}

impl fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "ContentKey{{ digest: {} weight: {} }}", self.digest.to_hex(), self.weight)
    }
}

impl ContentKey {
    pub fn new (hash: &[u8], weight: u32) -> ContentKey {
        assert_eq!(hash.len(), DIGEST_LEN);
        let mut digest = [0u8; DIGEST_LEN];
        digest.copy_from_slice(&hash[..]);
        ContentKey{digest, weight}
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
    /// publisher
    pub publisher: PublicKey,
    /// signature of the publisher
    pub signature: Signature
}

impl Content {
    /// calculate the digest that identifies this content
    pub fn digest (&self) -> sha256::Hash {
        let mut hasher = sha256::Hash::engine();
        hasher.input(consensus::serialize(self.data.as_slice()).as_slice());
        hasher.input(consensus::serialize(&self.funding).as_slice());
        hasher.input(consensus::serialize(&self.block_id).as_slice());
        hasher.input(consensus::serialize(&self.spv_proof).as_slice());
        hasher.input(consensus::serialize(&self.publisher.to_bytes()).as_slice());
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

    /// is the signature of the publisher valid
    pub fn is_valid_publisher_signature(&self, ctx: &Secp256k1<VerifyOnly>) -> bool{
        ctx.verify(&Message::from_slice(&self.digest()[..]).unwrap(), &self.signature, &self.publisher.key).is_ok()
    }
}