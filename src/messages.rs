//! P2P messages

use crate::bitcoin_hashes::sha256d;

/// All P2P messages supported
#[derive(Serialize, Deserialize, Debug)]
pub enum Messages {
    PollContent(PollContentMessage),
}

/// Connect message
#[derive(Serialize, Deserialize, Debug)]
pub struct PollContentMessage {
    /// known chain tip of Bitcoin
    tip: sha256d::Hash,
    /// min sketch of own id set
    sketch: Vec<u64>,
    /// own set size
    size: usize
}

