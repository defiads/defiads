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

#[macro_use]extern crate log;

use simple_logger;
use log::Level;

use biadne::p2p_bitcoin::BitcoinAdaptor;
use biadne::p2p_biadnet::BiadNetAdaptor;

pub fn main () {
    simple_logger::init_with_level(Level::Debug).unwrap();
    info!("biadnet starting.");
    BitcoinAdaptor::new().run();
    BiadNetAdaptor::new().run();
}

