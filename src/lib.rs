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

mod text;
mod ad;
mod iblt;