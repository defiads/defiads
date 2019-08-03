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
use murmel::downstream::SharedDownstream;
use murmel::timeout::SharedTimeout;

use crate::messages::Message;

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub struct Updater {
    p2p: P2PControlSender<Message>,
    timeout: SharedTimeout<Message>
}

impl Updater {
    pub fn new(p2p: P2PControlSender<Message>, timeout: SharedTimeout<Message>) -> PeerMessageSender<Message> {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut updater = Updater { p2p, timeout };

        thread::spawn(move || { updater.run(receiver) });

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver<Message>) {
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                match msg {
                    PeerMessage::Connected(pid) => {
                    }
                    PeerMessage::Disconnected(_) => {
                    }
                    PeerMessage::Message(pid, msg) => {
                        match msg {
                            _ => {  }
                        }
                    }
                }
            }
            //self.timeout.lock().unwrap().check(vec!(ExpectedReply::Headers));
        }
    }
}