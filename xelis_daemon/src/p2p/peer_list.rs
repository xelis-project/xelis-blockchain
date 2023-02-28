use super::{peer::Peer, packet::Packet};
use std::collections::HashMap;
use tokio::sync::RwLock;
use xelis_common::serializer::Serializer;
use std::sync::Arc;
use bytes::Bytes;
use log::{info, debug, trace, error};

pub type SharedPeerList = Arc<RwLock<PeerList>>;

// this object will be shared in Server, and each Peer
// so when we call Peer#close it will remove it from the list too
// using a RwLock so we can have multiple readers at the same time
pub struct PeerList {
    peers: HashMap<u64, Arc<Peer>>
}

impl PeerList {
    pub fn new(capacity: usize) -> SharedPeerList {
        Arc::new(
            RwLock::new(
                Self {
                    peers: HashMap::with_capacity(capacity)
                }
            )
        )
    }

    pub fn remove_peer(&mut self, peer: &Peer) {
        self.peers.remove(&peer.get_id());
        info!("Peer disconnected: {}", peer);
    }

    pub fn add_peer(&mut self, id: u64, peer: Peer) -> Arc<Peer> {
        let peer = Arc::new(peer);
        self.peers.insert(id, peer.clone());
        info!("New peer connected: {}", peer);
        peer
    }

    pub fn has_peer(&self, peer_id: &u64) -> bool {
        self.peers.contains_key(peer_id)
    }

    pub fn get_peers(&self) -> &HashMap<u64, Arc<Peer>> {
        &self.peers
    }

    pub fn size(&self) -> usize {
        self.peers.len()
    }

    pub async fn close_all(&mut self) {
        for (_, peer) in self.peers.iter() {
            debug!("Closing peer: {}", peer);
            if let Err(e) = peer.get_connection().close().await {
                error!("Error while trying to close peer {}: {}", peer.get_connection().get_address(), e);
            }
        }
        self.peers.clear();
    }

    pub async fn broadcast(&self, packet: Packet<'_>) {
        trace!("broadcast to all peers");
        let bytes = Bytes::from(packet.to_bytes());
        for (_, peer) in self.peers.iter() {
            if let Err(e) = peer.send_bytes(bytes.clone()).await {
                error!("Error while trying to broadcast packet to peer {}: {}", peer.get_connection().get_address(), e);
            };
        }
    }

    pub async fn broadcast_filter<P>(&self, predicate: P, packet: Packet<'_>)
    where P: FnMut(&(&u64, &Arc<Peer>)) -> bool {
        trace!("broadcast with filter");
        let bytes = Bytes::from(packet.to_bytes());
        for (_, peer) in self.peers.iter().filter(predicate) {
            if let Err(e) = peer.send_bytes(bytes.clone()).await {
                error!("Error while trying to broadcast packet to peer {}: {}", peer.get_connection().get_address(), e);
            };
        }
    }

    pub fn get_best_topoheight(&self) -> u64 { // TODO: Calculate median of all peers
        let mut best_height = 0;
        for (_, peer) in self.peers.iter() {
            let height = peer.get_topoheight();
            if height > best_height {
                best_height = height;
            }
        }
        best_height
    }
}