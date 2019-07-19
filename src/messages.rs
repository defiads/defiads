//! P2P messages

use crate::iblt::IBLTKey;
use crate::ad::Ad;
use crate::bitcoin_hashes::sha256d;
use crate::bitcoin::blockdata::transaction::Transaction;
use crate::serde::{Serializer, Serialize, Deserialize, Deserializer};

/// All P2P messages supported
#[derive(Serialize, Deserialize, Debug)]
pub enum Messages {
    Connect(ConnectMessage),
    Substantiate(Vec<IBLTKey>),
    InsertedID(InsertedIDMessage)
}

/// Connect message
#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectMessage {
    /// known chain tip of Bitcoin
    tip: sha256d::Hash,
    /// min sketch of own id set
    sketch: Vec<u16>
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
    pair: Vec<SPVNode>
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SPVNode {
    Hash(sha256d::Hash),
    Transaction(Transaction)
}


