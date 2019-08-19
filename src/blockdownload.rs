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
use bitcoin::{BitcoinHash, blockdata::{
    block::LoneBlockHeader,
}, network::{
    message::NetworkMessage,
    message_blockdata::{GetHeadersMessage, Inventory, InvType},
}, Block};
use bitcoin_hashes::sha256d;
use murmel::chaindb::SharedChainDB;
use murmel::error::MurmelError;
use murmel::p2p::{P2PControl, P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender, SERVICE_BLOCKS};
use murmel::timeout::{ExpectedReply, SharedTimeout};
use murmel::downstream::SharedDownstream;
use std::{
    collections::VecDeque,
    sync::mpsc,
    thread,
    time::Duration,
};

pub struct BlockDownload {
    p2p: P2PControlSender<NetworkMessage>,
    chaindb: SharedChainDB,
    timeout: SharedTimeout<NetworkMessage, ExpectedReply>,
    downstream: SharedDownstream,
    blocks_wanted: VecDeque<(sha256d::Hash, u32)>,
    blocks_asked: VecDeque<(sha256d::Hash, u32)>,
    block_download_peer: Option<PeerId>,
    birth: u64
}

impl BlockDownload {
    pub fn new(chaindb: SharedChainDB, p2p: P2PControlSender<NetworkMessage>, timeout: SharedTimeout<NetworkMessage, ExpectedReply>, downstream: SharedDownstream, processed_block: Option<sha256d::Hash>, birth: u64) -> PeerMessageSender<NetworkMessage> {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut blocks_wanted = VecDeque::new();
        {
            let chaindb = chaindb.read().unwrap();
            if let Some(mut h) = chaindb.header_tip() {
                if (h.stored.header.time as u64) > birth {
                    let stop_at = processed_block.unwrap_or_default();
                    let mut block_hash = h.bitcoin_hash();
                    while block_hash != stop_at {
                        blocks_wanted.push_front((block_hash, h.stored.height));
                        block_hash = h.stored.header.prev_blockhash.clone();
                        if block_hash != sha256d::Hash::default() {
                            h = chaindb.get_header(&block_hash).expect("inconsistent header cache");
                            if (h.stored.header.time as u64) < birth {
                                break;
                            }
                        }
                    }
                }
            }
        }

        let mut headerdownload = BlockDownload { chaindb, p2p, timeout, downstream: downstream,
            blocks_wanted, blocks_asked: VecDeque::new(), block_download_peer: None, birth };

        thread::Builder::new().name("header download".to_string()).spawn(move || { headerdownload.run(receiver) }).unwrap();

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver<NetworkMessage>) {
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                match msg {
                    PeerMessage::Connected(pid,_) => {
                        if self.is_serving_blocks(pid) {
                            trace!("serving blocks peer={}", pid);
                            self.get_headers(pid);
                            if self.block_download_peer.is_none() {
                                debug!("new block download peer={}", pid);
                                self.block_download_peer = Some(pid);
                            }
                        }
                    }
                    PeerMessage::Disconnected(pid,_) => {
                        if self.block_download_peer.is_some() {
                            if pid == self.block_download_peer.unwrap() {
                                self.block_download_peer = None;
                                debug!("lost block download peer={}", pid);
                                while let Some(asked) = self.blocks_asked.pop_back() {
                                    self.blocks_wanted.push_front(asked);
                                }
                            }
                        }
                    }
                    PeerMessage::Message(pid, msg) => {
                        match msg {
                            NetworkMessage::Headers(ref headers) => if self.is_serving_blocks(pid) { self.headers(headers, pid); },
                            NetworkMessage::Inv(ref inv) => if self.is_serving_blocks(pid) { self.inv(inv, pid); },
                            NetworkMessage::Block(ref block) => self.block(block, pid),
                            _ => {}
                        }
                        if self.block_download_peer.is_none() {
                            self.block_download_peer = Some(pid);
                        }
                        if pid == download_peer {
                            self.ask_blocks(pid)
                        }
                    }
                }
            }
            self.timeout.lock().unwrap().check(vec!(ExpectedReply::Headers, ExpectedReply::Block));
        }
    }

    fn ask_blocks (&mut self, pid: PeerId) {
        let mut timeout = self.timeout.lock().unwrap();
        if !timeout.is_busy_with(pid, ExpectedReply::Block) {
            let mut n_entries = 0;
            while let Some((hash, height)) = self.blocks_wanted.pop_front() {
                self.blocks_asked.push_back((hash, height));
                n_entries += 1;
                if n_entries == 1000 {
                    break;
                }
            }
            if self.blocks_asked.len() > 0 {
                self.p2p.send_network(pid, NetworkMessage::GetData(
                    self.blocks_asked.iter().map(|(hash, _)|
                        Inventory {
                            inv_type: InvType::Block,
                            hash: hash.clone()
                        }
                    ).collect()));
                debug!("asked {} blocks from peer={}", self.blocks_asked.len(), pid);
                timeout.expect(pid, self.blocks_asked.len(), ExpectedReply::Block);
            }
        }
        else {
            debug!("still waiting for blocks from peer={}", pid);
        }
    }

    fn block (&mut self, block: &Block, pid: PeerId) {
        if let Some(download_peer) = self.block_download_peer {
            if download_peer == pid {
                if let Some((expected, height)) = self.blocks_asked.front() {
                    let height = *height;
                    if block.header.bitcoin_hash() == *expected {
                        // will drop for out of sequence answers
                        self.timeout.lock().unwrap().received(pid, 1, ExpectedReply::Block);

                        self.blocks_asked.pop_front();
                        let mut downstream = self.downstream.lock().unwrap();
                        downstream.block_connected(block, height);
                    }
                }
            }
        }
    }

    fn is_serving_blocks(&self, peer: PeerId) -> bool {
        if let Some(peer_version) = self.p2p.peer_version(peer) {
            return peer_version.services & SERVICE_BLOCKS != 0;
        }
        false
    }

    // process an incoming inventory announcement
    fn inv(&mut self, v: &Vec<Inventory>, peer: PeerId) {
        let mut ask_for_headers = false;
        for inventory in v {
            // only care for blocks
            if inventory.inv_type == InvType::Block {
                let chaindb = self.chaindb.read().unwrap();
                if chaindb.get_header(&inventory.hash).is_none() {
                    debug!("received inv for new block {} peer={}", inventory.hash, peer);
                    // ask for header(s) if observing a new block
                    ask_for_headers = true;
                }
            } else {
                // do not spam us with transactions
                debug!("received unsolicited inv {:?} peer={}", inventory.inv_type, peer);
                self.p2p.ban(peer, 10);
                return;
            }
        }
        if ask_for_headers {
            self.get_headers(peer);
        }
    }

    /// get headers this peer is ahead of us
    fn get_headers(&mut self, peer: PeerId) {
        if self.timeout.lock().unwrap().is_busy_with(peer, ExpectedReply::Headers) {
            return;
        }
        let chaindb = self.chaindb.read().unwrap();
        let locator = chaindb.header_locators();
        if locator.len() > 0 {
            let first = if locator.len() > 0 {
                *locator.first().unwrap()
            } else {
                sha256d::Hash::default()
            };
            self.timeout.lock().unwrap().expect(peer, 1, ExpectedReply::Headers);
            self.p2p.send_network(peer, NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, first)));
        }
    }

    fn headers(&mut self, headers: &Vec<LoneBlockHeader>, peer: PeerId) {
        self.timeout.lock().unwrap().received(peer, 1, ExpectedReply::Headers);

        if headers.len() > 0 {
            // current height
            let mut height;
            // some received headers were not yet known
            let mut some_new = false;
            let mut moved_tip = None;
            {
                let chaindb = self.chaindb.read().unwrap();

                if let Some(tip) = chaindb.header_tip() {
                    height = tip.stored.height;
                } else {
                    return;
                }
            }

            let mut headers_queue = VecDeque::new();
            headers_queue.extend(headers.iter());
            while !headers_queue.is_empty() {
                let mut connected_headers = Vec::new();
                let mut disconnected_headers = Vec::new();
                {
                    let mut chaindb = self.chaindb.write().unwrap();
                    while let Some(header) = headers_queue.pop_front() {
                        // add to blockchain - this also checks proof of work
                        match chaindb.add_header(&header.header) {
                            Ok(Some((stored, unwinds, forwards))) => {
                                connected_headers.push((stored.height, stored.header));
                                // POW is ok, stored top chaindb
                                some_new = true;

                                if let Some(forwards) = forwards {
                                    moved_tip = Some(forwards.last().unwrap().clone());
                                }
                                height = stored.height;

                                if let Some(unwinds) = unwinds {
                                    disconnected_headers.extend(unwinds.iter()
                                        .map(|h| chaindb.get_header(h).unwrap().stored.header));
                                    break;
                                }
                            }
                            Ok(None) => {}
                            Err(MurmelError::SpvBadProofOfWork) => {
                                info!("Incorrect POW, banning peer={}", peer);
                                self.p2p.ban(peer, 100);
                            }
                            Err(e) => {
                                debug!("error {} processing header {} ", e, header.header.bitcoin_hash());
                            }
                        }
                    }
                    chaindb.batch().unwrap();
                }

                // call downstream outside of chaindb lock
                let mut downstream = self.downstream.lock().unwrap();
                for header in &disconnected_headers {
                    if (header.time as u64) > self.birth {
                        self.blocks_wanted.pop_back();
                        downstream.block_disconnected(header);
                    }
                }
                for (height, header) in &connected_headers {
                    if (header.time as u64) > self.birth {
                        self.blocks_wanted.push_back((header.bitcoin_hash(), *height));
                        downstream.header_connected(header, *height);
                    }
                }
            }

            if some_new {
                // ask if peer knows even more
                self.get_headers(peer);
            }

            if let Some(new_tip) = moved_tip {
                info!("received {} headers new tip={} from peer={}", headers.len(), new_tip, peer);
                self.p2p.send(P2PControl::Height(height));
            } else {
                debug!("received {} known or orphan headers from peer={}", headers.len(), peer);
            }
        }
    }
}