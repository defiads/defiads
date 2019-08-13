use bitcoin::{
    BitcoinHash,
    blockdata::{
        block::LoneBlockHeader,
    },
    network::{
        message::NetworkMessage,
        message_blockdata::{GetHeadersMessage, Inventory, InvType},
    }
};
use murmel::chaindb::SharedChainDB;
use murmel::p2p::{P2PControl, P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender};
use murmel::downstream::Downstream;
use murmel::timeout::{ExpectedReply, SharedTimeout};
use murmel::downstream::SharedDownstream;
use std::{
    sync::mpsc,
    thread,
    time::Duration,
};


pub struct BlockDownload {
    p2p: P2PControlSender<NetworkMessage>,
    chaindb: SharedChainDB,
    timeout: SharedTimeout<NetworkMessage, ExpectedReply>,
    downstream: SharedDownstream
}

impl BlockDownload {
    pub fn new(chaindb: SharedChainDB, p2p: P2PControlSender<NetworkMessage>, timeout: SharedTimeout<NetworkMessage, ExpectedReply>, downstream: SharedDownstream) -> PeerMessageSender<NetworkMessage> {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut headerdownload = BlockDownload { chaindb, p2p, timeout, downstream: downstream };

        thread::Builder::new().name("block download".to_string()).spawn(move || { headerdownload.run(receiver) }).unwrap();

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver<NetworkMessage>) {
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                match msg {
                    PeerMessage::Connected(pid,_) => {},
                    PeerMessage::Disconnected(_,_) => {},
                    PeerMessage::Message(pid, msg) => {
                        match msg {
                            NetworkMessage::Headers(ref headers) => {  },
                            NetworkMessage::Block(ref block) => {
                                // TODO
                                // self.downstream.get_mut().unwrap().block_connected(block);
                            }
                            _ => {}
                        }
                    }
                }
            }
            //self.timeout.lock().unwrap().check(vec!(ExpectedReply::Headers));
        }
    }
}