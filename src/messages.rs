//! P2P messages

use crate::iblt::AdKey;
use crate::ad::Ad;
use crate::bitcoin_hashes::sha256d;
use crate::bitcoin_hashes::sha256;
use crate::bitcoin::blockdata::transaction::Transaction;
use crate::serde::{Serializer, Serialize, Deserialize, Deserializer};

/// All P2P messages supported
#[derive(Serialize, Deserialize, Debug)]
pub enum Messages {
    Connect(ConnectMessage),
    Substantiate(Vec<AdKey>),
    InsertedID(InsertedIDMessage),
    GetAds(GetAdsMessage),
    Ad(Ad)
}

/// Connect message
#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectMessage {
    /// known chain tip of Bitcoin
    tip: sha256d::Hash,
    /// min sketch of own id set
    sketch: Vec<u16>,
    /// own set size
    size: usize
}

/// Message to ask for certain ads
#[derive(Serialize, Deserialize, Debug)]
pub struct GetAdsMessage {
    /// list of ads
    ids: Vec<sha256::Hash>
}

/// Substantiation of an inserted ID
#[derive(Serialize, Deserialize, Debug)]
pub struct InsertedIDMessage {
    ad: Ad,
    spv_proof: SPVProof
}

/// proof that a transaction was included into the Bitcoin block chain
#[derive(Serialize, Deserialize, Debug)]
pub struct SPVProof {
    header: sha256d::Hash,
    transaction: Transaction,
    leafs: Vec<sha256d::Hash>
}



