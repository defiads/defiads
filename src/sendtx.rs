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
use murmel::p2p::{P2PControlSender};
use bitcoin::network::message::NetworkMessage;
use crate::db::SharedDB;
use std::{
    thread,
    sync::{Arc, mpsc, Mutex}
};
use std::time::Duration;

pub struct TxSender {
    sender: Arc<Mutex<mpsc::Sender<NetworkMessage>>>
}

impl TxSender {
    pub fn send(&self, msg: NetworkMessage) {
        self.sender.lock().unwrap().send(msg).expect("can not send tx to sender queue");
    }
}

pub struct SendTx {
    p2p: P2PControlSender<NetworkMessage>,
    db: SharedDB
}

impl SendTx {
    pub fn new(p2p: P2PControlSender<NetworkMessage>, db: SharedDB) -> TxSender {
        let (sender, receiver) = mpsc::channel();

        let mut txsender = SendTx { p2p, db };

        thread::Builder::new().name("sendtx".to_string()).spawn(move || { txsender.run(receiver) }).unwrap();

        TxSender{ sender: Arc::new(Mutex::new(sender)) }
    }

    fn run(&mut self, receiver: mpsc::Receiver<NetworkMessage>) {
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_secs(60)) {
                match msg {
                    NetworkMessage::Tx(transaction) => {
                        let mut db = self.db.lock().unwrap();
                        let mut tx = db.transaction();
                        tx.store_txout(&transaction).expect("can not store outgoing transaction");
                        tx.commit();
                    },
                    _ => {}
                }
            }
            let mut db = self.db.lock().unwrap();
            let tx = db.transaction();
            for transaction in tx.read_unconfirmed().expect("can not read txout db") {
                self.p2p.send_random_network(NetworkMessage::Tx(transaction));
            }
        }
    }
}