use super::peer::Peer;
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::sync::Arc;
use bytes::Bytes;
use log::{info, debug, error};

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
            debug!("Closing peer: {}", peer);
            if let Err(e) = peer.get_connection().close().await {
                error!("Error while trying to close peer {}: {}", peer.get_connection().get_address(), e);
            }
        }
        self.peers.clear();
    }

    pub async fn broadcast(&self, bytes: Bytes) {
        for (_, peer) in self.peers.iter() {
            self.send_bytes_to_peer(peer, bytes.clone()).await;
        }
    }

    pub async fn broadcast_filter<P>(&self, predicate: P, bytes: Bytes)
    where P: FnMut(&(&u64, &Arc<Peer>)) -> bool {
        for (_, peer) in self.peers.iter().filter(predicate) {
            self.send_bytes_to_peer(peer, bytes.clone()).await;
        }
    }

    pub async fn send_bytes_to_peer(&self, peer: &Arc<Peer>, bytes: Bytes) {
        if let Err(e) = peer.send_bytes(bytes).await {
            error!("Error while trying to broadcast to peer {}: {}", peer.get_connection().get_address(), e);
        }
    }

    pub fn get_best_height(&self) -> u64 { // TODO: Calculate median of all peers
        let mut best_height = 0;
        for (_, peer) in self.peers.iter() {
            let height = peer.get_block_height();
            if height > best_height {
                best_height = height;
            }
        }
        best_height
    }
}