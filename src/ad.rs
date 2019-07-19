//! An advertizement

use std::error::Error;

use crate::text::Text;
use crate::serde::{Serialize, Deserialize};
use crate::bitcoin_hashes::{sha256, Hash, HashEngine};

/// An ad
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Ad {
    cat : String,
    content: Vec<KeyValue>
}

impl Ad {
    /// serialize an ad to a byte stream
    pub fn serialize(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }

    /// deserealize an ad from a byte stream
    pub fn deserialize(data: &[u8]) -> Result<Ad, Box<Error>> {
        Ok(serde_cbor::from_slice::<Ad>(data)?)
    }

    pub fn commitment (&self) -> sha256::Hash {
        sha256::Hash::hash(self.serialize().as_slice())
    }
}

/// Key Value Pair
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct KeyValue {
    key: String,
    value: Value
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Number {
    value: f32
}

impl Number {
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
        let ad = Ad { cat: "whatever".to_string(),
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

        println!("Ad {:?}\nhas commitment {}", ad, hex::encode(&ad.commitment()[..]));
        println!("Ad serialized to {}", hex::encode(ad.serialize()));
        assert_eq!(Ad::deserialize(ad.serialize().as_slice()).unwrap(), ad);
        println!("Deserealized to same content.")
    }
}