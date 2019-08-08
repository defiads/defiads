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

use bitcoin_hashes::{sha256, Hash};
use murmel::p2p::{PeerMessageSender, P2PControlSender, PeerMessageReceiver, PeerMessage};
use murmel::timeout::SharedTimeout;

use crate::messages::Message;

use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use crate::store::SharedContentStore;
use crate::messages::PollContentMessage;
use crate::p2p_biadnet::ExpectedReply;
use murmel::p2p::PeerId;
use std::collections::HashMap;
use crate::iblt::estimate_diff_size;
use crate::iblt::IBLTEntry;
use std::time::SystemTime;

const MINIMUM_IBLT_SIZE: u32 = 100;
const MAXIMUM_IBLT_SIZE: u32 = MINIMUM_IBLT_SIZE << 16;
const POLL_FREQUENCY: u64 = 60; // every minute

pub struct Updater {
    p2p: P2PControlSender<Message>,
    timeout: SharedTimeout<Message, ExpectedReply>,
    store: SharedContentStore,
    poll_asked: HashMap<PeerId, PollContentMessage>
}

impl Updater {
    pub fn new(p2p: P2PControlSender<Message>, timeout: SharedTimeout<Message, ExpectedReply>, store: SharedContentStore) -> PeerMessageSender<Message> {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut updater = Updater { p2p, timeout, store, poll_asked: HashMap::new() };

        thread::Builder::new().name("biadnet updater".to_string()).spawn(move || { updater.run(receiver) }).unwrap();

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver<Message>) {
        let mut last_polled = SystemTime::now();
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                match msg {
                    PeerMessage::Connected(pid, _) => {
                        debug!("content poll peer={}", pid);
                        self.poll_content(pid);
                        last_polled = SystemTime::now();
                    },
                    PeerMessage::Disconnected(pid,_) => {
                        self.poll_asked.remove(&pid);
                    }
                    PeerMessage::Message(pid, msg) => {
                        match msg {
                            Message::PollContent(poll) => {
                                if let Some(question) = self.poll_asked.remove(&pid) {
                                    debug!("got content poll reply from peer={}", pid);
                                    // this is a reply
                                    self.timeout.lock().unwrap().received(pid, 1, ExpectedReply::PollContent);
                                    let mut store = self.store.write().unwrap();
                                    if let Some(our_tip) = store.get_tip() {
                                        if our_tip == question.tip && question.tip == poll.tip {
                                            // only worth speaking if we are at the same height
                                            // compute and send our iblt
                                            let diff = estimate_diff_size(
                                                question.sketch.as_slice(), question.size,
                                                poll.sketch.as_slice(), poll.size)*3/2;
                                            if diff > 0 {
                                                let mut size = MINIMUM_IBLT_SIZE;
                                                while size < MAXIMUM_IBLT_SIZE && size < diff {
                                                    size <<= 2;
                                                }
                                                let iblt = store.get_iblt(size).expect("could not compute IBLT").clone();
                                                self.timeout.lock().unwrap().expect(pid, 1, ExpectedReply::IBLT);
                                                self.p2p.send_network(pid, Message::IBLT(our_tip, iblt));
                                            }
                                        }
                                        else {
                                            debug!("not at same height with peer={}", pid);
                                        }
                                    }
                                    else {
                                        debug!("not at same height with peer={}", pid);
                                    }
                                }
                                else {
                                    // this is initial request
                                    debug!("reply content poll to peer={}", pid);
                                    self.poll_content(pid)
                                }
                            },
                            Message::IBLT(tip, mut iblt) => {
                                self.timeout.lock().unwrap().received(pid, 1, ExpectedReply::IBLT);
                                debug!("received IBLT from peer={}", pid);
                                let mut store = self.store.write().unwrap();
                                if let Some(our_tip) = store.get_tip() {
                                    if tip == our_tip {
                                        let size = iblt.len();
                                        iblt.substract(
                                            store.get_iblt(size).expect("can not compute IBLT")
                                        );
                                        let mut request = Vec::new();
                                        for entry in iblt.into_iter() {
                                            if let Ok(entry) = entry {
                                                match entry {
                                                    IBLTEntry::Deleted(key) =>
                                                        request.push(sha256::Hash::from_slice(&key.digest[..]).unwrap()),
                                                    _ => {}
                                                };
                                            }
                                            else {
                                                debug!("not ssuccessful inverting IBLT diff with peer={}", pid);
                                                break;
                                            }
                                        }
                                        let len = request.len();
                                        if len > 0 {
                                            debug!("asking for {} contents from peer={}", len, pid);
                                            self.timeout.lock().unwrap().expect(pid, len, ExpectedReply::Content);
                                            self.p2p.send_network(pid, Message::Get(request));
                                        }
                                        else {
                                            debug!("in sync with peer={}", pid);
                                        }
                                    }
                                    else {
                                        debug!("not at same height with peer={}", pid);
                                    }
                                }
                            },
                            Message::Content(content) =>{
                                debug!("received content {} from peer={}", content.ad.digest(), pid);
                                self.timeout.lock().unwrap().received(pid, 1, ExpectedReply::Content);
                                let mut store = self.store.write().unwrap();
                                if store.add_content(&content).is_err() {
                                    debug!("failed to add content {} peer={}", content.ad.digest(), pid);
                                }
                                if !self.timeout.lock().unwrap().is_busy_with(pid, ExpectedReply::Content) {
                                    debug!("truncating db");
                                    store.truncate_to_limit().expect("failed to truncate db to maz size");
                                }
                            },
                            Message::Get(ids) => {
                                debug!("received {} get requests from peer={}", ids.len(), pid);
                                let store = self.store.read().unwrap();
                                for id in &ids {
                                    if let Ok(Some(content)) = store.get_content(id) {
                                        debug!("delivering content {} to peer={}", id, pid);
                                        self.p2p.send_network(pid, Message::Content(content));
                                    }
                                    else {
                                        debug!("can not find requested content {} peer={}", id, pid);
                                    }
                                }
                            }
                            _ => {  }
                        }
                    }
                }
            }
            self.timeout.lock().unwrap().check(vec!(ExpectedReply::PollContent, ExpectedReply::IBLT, ExpectedReply::Content, ExpectedReply::Get));
            if SystemTime::now().duration_since(last_polled).unwrap().as_secs() > POLL_FREQUENCY {
                last_polled = SystemTime::now();
                let store = self.store.read().unwrap();
                if let Some(tip) = store.get_tip() {
                    let sketch = store.get_sketch().clone();
                    let poll = PollContentMessage {
                        tip,
                        sketch,
                        size: store.get_nkeys()
                    };
                    let pid = self.p2p.send_random_network(Message::PollContent(poll.clone()));
                    self.poll_asked.insert(pid, poll);
                    self.timeout.lock().unwrap().expect(pid, 1, ExpectedReply::PollContent);
                }
            }
        }
    }

    fn poll_content(&mut self, pid: PeerId) {
        let store = self.store.read().unwrap();
        if let Some(tip) = store.get_tip() {
            let sketch = store.get_sketch().clone();
            let poll = PollContentMessage {
                tip,
                sketch,
                size: store.get_nkeys()
            };

            self.poll_asked.insert(pid, poll.clone());
            self.p2p.send_network(pid, Message::PollContent(poll));
            self.timeout.lock().unwrap().expect(pid, 1, ExpectedReply::PollContent);
        }
    }
}