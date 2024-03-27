use xelis_common::{
    api::daemon::{Direction, NotifyEvent, PeerPeerListUpdatedEvent},
    crypto::Hash,
    difficulty::CumulativeDifficulty,
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
};
use crate::{
    config::P2P_PING_PEER_LIST_LIMIT,
    core::{
        blockchain::Blockchain,
        storage::Storage
    },
    p2p::{
        error::P2pError,
        peer::Peer,
        is_local_address,
    },
    rpc::rpc::get_peer_entry
};
use std::{
    fmt::Display,
    borrow::Cow,
    net::SocketAddr,
    sync::Arc
};
use log::{error, trace, debug};

#[derive(Clone, Debug)]
pub struct Ping<'a> {
    top_hash: Cow<'a, Hash>,
    topoheight: u64,
    height: u64,
    pruned_topoheight: Option<u64>,
    cumulative_difficulty: CumulativeDifficulty,
    peer_list: Vec<SocketAddr>
}

impl<'a> Ping<'a> {
    pub fn new(top_hash: Cow<'a, Hash>, topoheight: u64, height: u64, pruned_topoheight: Option<u64>, cumulative_difficulty: CumulativeDifficulty, peer_list: Vec<SocketAddr>) -> Self {
        Self {
            top_hash,
            topoheight,
            height,
            pruned_topoheight,
            cumulative_difficulty,
            peer_list
        }
    }

    pub async fn update_peer<S: Storage>(self, peer: &Arc<Peer>, blockchain: &Arc<Blockchain<S>>) -> Result<(), P2pError> {
        trace!("Updating {} with {}", peer, self);
        peer.set_top_block_hash(self.top_hash.into_owned()).await;
        peer.set_topoheight(self.topoheight);
        peer.set_height(self.height);

        if peer.is_pruned() && self.pruned_topoheight.is_none() {
            return Err(P2pError::InvalidPrunedTopoHeightChange)
        }

        if let Some(pruned_topoheight) = self.pruned_topoheight {
            if pruned_topoheight > self.topoheight {
                return Err(P2pError::InvalidPrunedTopoHeight(pruned_topoheight, self.height))
            }

            if let Some(old_pruned_topoheight) = peer.get_pruned_topoheight() {
                if pruned_topoheight < old_pruned_topoheight {
                    error!("Invalid protocol rules: pruned topoheight {} is less than old pruned topoheight {} in ping packet", pruned_topoheight, old_pruned_topoheight);
                    return Err(P2pError::InvalidNewPrunedTopoHeight(pruned_topoheight, old_pruned_topoheight))
                }
            }
        }

        peer.set_pruned_topoheight(self.pruned_topoheight);
        peer.set_cumulative_difficulty(self.cumulative_difficulty).await;

        if peer.sharable() {
            trace!("Locking RPC Server to notify PeerStateUpdated event");
            if let Some(rpc) = blockchain.get_rpc().read().await.as_ref() {
                if rpc.is_event_tracked(&NotifyEvent::PeerStateUpdated).await {
                    rpc.notify_clients_with(&NotifyEvent::PeerStateUpdated, get_peer_entry(peer).await).await;
                }
            }
            trace!("End locking for PeerStateUpdated event");
        }

        if !self.peer_list.is_empty() {
            debug!("Received a peer list ({:?}) for {}", self.peer_list, peer.get_outgoing_address());
            let mut shared_peers = peer.get_peers().lock().await;
            debug!("Our peer list is ({:?}) for {}", shared_peers, peer.get_outgoing_address());
            let peer_addr = peer.get_connection().get_address();
            for addr in &self.peer_list {
                if peer_addr == addr {
                    return Err(P2pError::OwnSocketAddress(*addr))
                }

                // Local addresses are not allowed
                if is_local_address(&addr) {
                    return Err(P2pError::LocalSocketAddress(*addr))
                }

                debug!("Adding {} for {} in ping packet", addr, peer.get_outgoing_address());
                if let Some(direction) = shared_peers.get_mut(addr) {
                    if !direction.update(Direction::In) {
                        let d = *direction;
                        debug!("Received peer list: {:?}, our peerlist is: {:?}", self.peer_list, shared_peers);
                        return Err(P2pError::DuplicatedPeer(*addr, *peer.get_outgoing_address(), d))
                    }
                } else {
                    shared_peers.insert(*addr, Direction::In);
                }
            }

            if peer.sharable() {
                trace!("Locking RPC Server to notify PeerPeerListUpdated event");
                if let Some(rpc) = blockchain.get_rpc().read().await.as_ref() {
                    if rpc.is_event_tracked(&NotifyEvent::PeerPeerListUpdated).await {
                        let value = PeerPeerListUpdatedEvent {
                            peer_id: peer.get_id(),
                            peerlist: self.peer_list
                        };
                        rpc.notify_clients_with(&NotifyEvent::PeerPeerListUpdated, value).await;
                    }
                }
                trace!("End locking for PeerPeerListUpdated event");
            }
        }

        Ok(())
    }

    pub fn get_height(&self) -> u64 {
        self.height
    }

    pub fn get_topoheight(&self) -> u64 {
        self.topoheight
    }

    pub fn get_peers(&self) -> &Vec<SocketAddr> {
        &self.peer_list
    }

    pub fn get_mut_peers(&mut self) -> &mut Vec<SocketAddr> {
        &mut self.peer_list
    }
}

impl Serializer for Ping<'_> {
    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.top_hash);
        writer.write_u64(&self.topoheight);
        writer.write_u64(&self.height);
        self.pruned_topoheight.write(writer);
        self.cumulative_difficulty.write(writer);
        writer.write_u8(self.peer_list.len() as u8);
        for peer in &self.peer_list {
            peer.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let top_hash = Cow::Owned(reader.read_hash()?);
        let topoheight = reader.read_u64()?;
        let height = reader.read_u64()?;
        let pruned_topoheight = Option::read(reader)?;
        if let Some(pruned_topoheight) = &pruned_topoheight {
            if *pruned_topoheight == 0 {
                debug!("Invalid pruned topoheight (0) in ping packet");
                return Err(ReaderError::InvalidValue)
            }
        }
        let cumulative_difficulty = CumulativeDifficulty::read(reader)?;
        let peers_len = reader.read_u8()? as usize;
        if peers_len > P2P_PING_PEER_LIST_LIMIT {
            debug!("Too much peers sent in this ping packet: received {} while max is {}", peers_len, P2P_PING_PEER_LIST_LIMIT);
            return Err(ReaderError::InvalidValue)
        }

        let mut peer_list = Vec::with_capacity(peers_len);
        for _ in 0..peers_len {
            let peer = SocketAddr::read(reader)?;
            peer_list.push(peer);
        }

        Ok(Self { top_hash, topoheight, height, pruned_topoheight, cumulative_difficulty, peer_list })
    }

    fn size(&self) -> usize {
        self.top_hash.size() +
        self.topoheight.size() +
        self.height.size() +
        self.pruned_topoheight.size() +
        self.cumulative_difficulty.size() +
        // u8 for the length of the peer list
        1 +
        self.peer_list.iter().map(|p| p.size()).sum::<usize>()
    }
}

impl Display for Ping<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ping[top_hash: {}, topoheight: {}, height: {}, pruned topoheight: {:?}, peers length: {}]", self.top_hash, self.topoheight, self.height, self.pruned_topoheight, self.peer_list.len())
    }
}