use super::error::P2pError;
use super::peer::Peer;
use std::collections::HashMap;
use std::sync::{Mutex, Arc};
use bytes::Bytes;

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
    }

    pub fn add_peer(&mut self, id: u64, peer: Peer) -> Arc<Peer> {
        let peer = Arc::new(peer);
        self.peers.insert(id, peer.clone());
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

    pub fn close_all(&mut self) -> Result<(), P2pError> {
        for (_, peer) in self.peers.into_iter() { // TODO verify if peers is cleaned after that
            peer.get_connection().close()?;
        }
        Ok(())
    }

    pub fn broadcast(&self, peer_id: u64, bytes: Bytes) {
        for (_, peer) in self.peers.iter() {
            if peer.get_id() != peer_id {
                // TODO
            }
        }
    }
}