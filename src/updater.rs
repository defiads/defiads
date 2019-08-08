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

const MINIMUM_IBLT_SIZE: u32 = 100;
const MAXIMUM_IBLT_SIZE: u32 = MINIMUM_IBLT_SIZE << 16;

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
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                match msg {
                    PeerMessage::Connected(pid) => self.poll_content(pid),
                    PeerMessage::Disconnected(_,_) => {
                    }
                    PeerMessage::Message(pid, msg) => {
                        match msg {
                            Message::PollContent(poll) => {
                                if let Some(question) = self.poll_asked.remove(&pid) {
                                    // this is a reply
                                    self.timeout.lock().unwrap().received(pid, 1, ExpectedReply::PollContent);
                                    if question.tip == poll.tip {
                                        // only worth speaking if we are at the same height
                                        let diff = estimate_diff_size(
                                            question.sketch.as_slice(), question.size,
                                            poll.sketch.as_slice(), poll.size);
                                        let mut size = MINIMUM_IBLT_SIZE;
                                        while size < MAXIMUM_IBLT_SIZE && size < diff {
                                            size <<= 2;
                                        }
                                        let iblt = self.store.write().unwrap().get_iblt(size).expect("could not compute IBLT").clone();
                                        self.p2p.send_network(pid, Message::IBLT(iblt));
                                    }
                                }
                                else {
                                    // this is initial request
                                    self.poll_content(pid)
                                }
                            },
                            _ => {  }
                        }
                    }
                }
            }
            self.timeout.lock().unwrap().check(vec!(ExpectedReply::PollContent));
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