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
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct Ad {
    /**
     * The category of the advertisement.
     * This might be a machine-understandable string to identify
     * the application that uses this category of advertisements
     * to search for counterparties or services.
     * For example, a decentralized exchange between
     * cryptocurrencies might use a category of "exchange", and
     * automated bots that attempt to do arbitrage could locate
     * all ads that have this category and contact exchange offers
     * to attempt trading with them using e.g. cross-chain
     * atomic swaps.
     *
     * The intent is that applications will define a particular
     * category that service providers of that application will
     * advertise under.
     * For example, Lightning Watchtowers might advertise themselves
     * by specifying a category of "watchtower", then Lightning
     * nodes could filter ads with that category and parse the
     * abstract to get the relevant information (e.g. rates charged
     * for watching, what kinds of channels supported, etc.).
     */
    pub cat : String,
    /**
     * The abstract (i.e. TLDR) of the advertisement.
     * May contain machine-readable data (JSON or XML or ...)
     * describing any application-specific data.
     * For example, an advertising exchange on a decentralized
     * exchange application might indicate here which pairs it
     * supports trading and the exchange rate between pairs,
     * and the mechanical details on how to get in touch with
     * the advertiser.
     * As this uses a String it might not be appropriate for
     * human-readable text in non-Western languages, as
     * serialization of some non-Western scripts will take
     * longer.
     * Thus, this field should be used for machine-readable
     * data instead.
     */
    pub abs: String,
    /**
     * The content of the advertisement.
     * This is a human-readable description of the service
     * or product being advertised.
     * The specialized Text type is designed to have somewhat
     * consistent encoding in bytes across different scripts,
     * so as not to introduce bias against languages which
     * require many bytes per character when encoded in e.g.
     * UTF-8.
     */
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
        serde_cbor::ser::to_vec(&self).unwrap()
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
