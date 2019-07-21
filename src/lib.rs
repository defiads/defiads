//! biadne

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]
#![deny(unused_must_use)]

extern crate snap;
extern crate byteorder;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
extern crate hex;
extern crate bitcoin_hashes;
extern crate bitcoin;
extern crate siphasher;
extern crate secp256k1;

mod text;
mod ad;
mod iblt;
mod messages;
mod content;