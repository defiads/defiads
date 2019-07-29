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

