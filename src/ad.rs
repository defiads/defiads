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
    pub content: Vec<KeyValue>
}

impl Ad {
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

/// Key Value Pair
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct KeyValue {
    /// key
    pub key: String,
    /// value
    pub value: Value
}

/// a number in the ad
#[derive(Serialize, Deserialize, Debug)]
pub struct Number {
    value: f32
}

impl Number {
    /// create a new number
    pub fn new(value: f32) -> Number {
        Number{value}
    }
}

impl Eq for Number {}

impl PartialEq for Number {
    fn eq(&self, other: &Number) -> bool {
        self.value == other.value
    }

    fn ne(&self, other: &Number) -> bool {
        self.value != other.value
    }
}

/// A value
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum Value {
    Text(Text),
    Number(Number),
    Sub(Vec<KeyValue>)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::text::Text;
    use crate::hex;

    #[test]
    fn test_ad_serialization () {
        let ad = Ad { cat: "whatever".to_string(), abs: "this".to_string(),
            content:
                vec![
                    KeyValue{key: "description".to_string(),
                            value : Value::Text(Text::new("職認子相帯金領観年旅計読。東率歳本読谷車陸保美情僕代捕期負骨義著一"))},
                    KeyValue{key: "tldr".to_string(),
                        value : Value::Text(Text::new("Lorem ipsum dolor sit amet, ius te animal perpetua efficiantur"))},
                    KeyValue{key: "price".to_string(),
                        value : Value::Number(Number::new(1.0))},
                    KeyValue {
                        key: "sub".to_string(),
                        value: Value::Sub(
                            vec![
                                KeyValue{
                                    key: "option A".to_string(),
                                    value: Value::Text(Text::new("blue"))},
                                KeyValue{
                                    key: "option B".to_string(),
                                    value: Value::Text(Text::new("green"))},
                            ])
                    }
                ]};

        println!("Ad {:?}\nhas commitment {}", ad, hex::encode(&ad.digest()[..]));
        println!("Ad serialized to {}", hex::encode(ad.serialize()));
        assert_eq!(Ad::deserialize(ad.serialize().as_slice()).unwrap(), ad);
        println!("Deserealized to same content.")
    }
}