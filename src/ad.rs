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
// ! An ad, the payload of distributed content

use std::error::Error;

use crate::text::Text;
use crate::bitcoin_hashes::{sha256, Hash};

/// An ad, the payload of distributed content
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Ad {
    pub cat : String,
    pub abs: String,
    pub content: Text
}

impl Ad {
    pub fn new(cat: String, abs: String, content: &str) -> Ad {
        Ad{
            cat, abs, content: Text::new(content)
        }
    }
    /// serialize an ad to a byte stream
    pub fn serialize(&self) -> Vec<u8> {
        serde_cbor::ser::to_vec_packed(&self).unwrap()
    }

    /// deserialize an ad from a byte stream
    pub fn deserialize(data: &[u8]) -> Result<Ad, Box<dyn Error>> {
        Ok(serde_cbor::from_slice::<Ad>(data)?)
    }

    /// the digest funding transactions commit to
    pub fn digest(&self) -> sha256::Hash {
        sha256::Hash::hash(self.serialize().as_slice())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::text::Text;
    use crate::hex;

    #[test]
    fn test_ad_serialization () {
        let ad = Ad { cat: "whatever".to_string(), abs: "loret ipsum".to_string(),
            content: Text::new("職認子相帯金領観年旅計読。東率歳本読谷車陸保美情僕代捕期負骨義著一")};

        println!("Ad {:?}\nhas commitment {}", ad, hex::encode(&ad.digest()[..]));
        println!("Ad serialized to {}", hex::encode(ad.serialize()));
        assert_eq!(Ad::deserialize(ad.serialize().as_slice()).unwrap(), ad);
        println!("Deserealized to same content.")
    }
}