use super::peer::Peer;
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::sync::Arc;
use bytes::Bytes;
use log::{info, error};

pub type SharedPeerList = Arc<Mutex<PeerList>>;

// this object will be shared in Server, and each Peer
// so when we call Peer#close it will remove it from the list too
pub struct PeerList {
    peers: HashMap<u64, Arc<Peer>>
}

impl PeerList {
    pub fn new(capacity: usize) -> SharedPeerList {
        Arc::new(
            Mutex::new(
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
            if let Err(e) = peer.get_connection().close().await {
                error!("Error while trying to close peer {}: {}", peer.get_connection().get_address(), e);
            }
        }
        self.peers.clear();
    }

    pub async fn broadcast(&self, bytes: Bytes) {
        for (_, peer) in self.peers.iter() {
            if let Err(e) = peer.send_bytes(bytes.clone()).await {
                error!("Error while trying to broadcast to peer {}: {}", peer.get_connection().get_address(), e);
            }
        }
    }

    pub async fn broadcast_except(&self, peer_id: u64, bytes: Bytes) {
        for (_, peer) in self.peers.iter() {
            if peer.get_id() != peer_id {
                if let Err(e) = peer.send_bytes(bytes.clone()).await {
                    error!("Error while trying to broadcast to peer {}: {}", peer.get_connection().get_address(), e);
                }
            }
        }
    }
}