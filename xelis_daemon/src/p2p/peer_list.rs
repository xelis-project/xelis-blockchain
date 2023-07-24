use crate::p2p::packet::peer_disconnected::PacketPeerDisconnected;

use super::{peer::Peer, packet::Packet, error::P2pError};
use std::{collections::HashMap, net::SocketAddr, fs};
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;
use xelis_common::{serializer::Serializer, globals::get_current_time, config::{P2P_EXTEND_PEERLIST_DELAY, PEER_FAIL_LIMIT}};
use std::sync::Arc;
use bytes::Bytes;
use log::{info, debug, trace, error, warn};

pub type SharedPeerList = Arc<RwLock<PeerList>>;

// this object will be shared in Server, and each Peer
// so when we call Peer#close it will remove it from the list too
// using a RwLock so we can have multiple readers at the same time
pub struct PeerList {
    peers: HashMap<u64, Arc<Peer>>,
    stored_peers: HashMap<SocketAddr, StoredPeer>,
    filename: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum StoredPeerState {
    Whitelist,
    Graylist,
    Blacklist,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct StoredPeer {
    last_seen: u64,
    last_connection_try: u64,
    fail_count: u8,
    state: StoredPeerState
}

impl PeerList {
    // load all the stored peers from the file
    fn load_stored_peers(filename: &String) -> Result<HashMap<SocketAddr, StoredPeer>, P2pError> {
        // check that the file exists
        if fs::metadata(filename).is_err() {
            info!("Peerlist file not found, creating a new one");
            let peers = HashMap::new();
            // write empty set in file
            fs::write(filename, serde_json::to_string_pretty(&peers)?)?;
            return Ok(peers);
        }

        // read the whole file
        let content = match fs::read_to_string(filename) {
            Ok(content) => content,
            Err(e) => {
                error!("Error while reading peerlist file: {}", e);
                warn!("Removing peerlist file and creating a new empty one");
                fs::remove_file(filename)?;
                let peers = HashMap::new();
                // write empty set in file
                fs::write(filename, serde_json::to_string_pretty(&peers)?)?;

                return Ok(peers);
            }
        };

        // deserialize the content
        let peers = match serde_json::from_str(&content) {
            Ok(peers) => peers,
            Err(e) => {
                error!("Error while deserializing peerlist: {}", e);
                warn!("Removing peerlist file and creating a new empty one");
                fs::remove_file(filename)?;
                let peers = HashMap::new();
                // write empty set in file
                fs::write(filename, serde_json::to_string_pretty(&peers)?)?;

                peers
            }
        };

        Ok(peers)
    }

    pub fn new(capacity: usize, filename: String) -> SharedPeerList {
        let stored_peers = match Self::load_stored_peers(&filename) {
            Ok(peers) => peers,
            Err(e) => {
                error!("Error while loading peerlist: {}", e);
                info!("Creating a empty peerlist");
                HashMap::new()
            }
        };

        Arc::new(
            RwLock::new(
                Self {
                    peers: HashMap::with_capacity(capacity),
                    stored_peers,
                    filename
                }
            )
        )
    }

    pub async fn remove_peer(&mut self, peer: &Peer) {
        self.peers.remove(&peer.get_id());

        // now remove this peer from all peers that tracked it
        let mut addr = peer.get_connection().get_address().clone();
        if !peer.is_out() {
            addr.set_port(peer.get_local_port());
        }

        let packet = Bytes::from(Packet::PeerDisconnected(PacketPeerDisconnected::new(addr)).to_bytes());
        for peer in self.peers.values() {
            let peer_peers = peer.get_peers().lock().await;
            // check if it was in common
            if peer_peers.contains(&addr) {
                debug!("Sending PeerDisconnected packet to peer {} for {}", peer, addr);
                // we send the packet to notify the peer that we don't have it in common anymore
                if let Err(e) = peer.send_bytes(packet.clone()).await {
                    error!("Error while trying to send RemovePeer packet to peer {}: {}", peer.get_connection().get_address(), e);
                }
            }
        }

        info!("Peer disconnected: {}", peer);
    }

    pub fn add_peer(&mut self, id: u64, peer: Peer) -> Arc<Peer> {
        let peer = Arc::new(peer);
        self.peers.insert(id, peer.clone());
        info!("New peer connected: {}", peer);

        self.update_peer(&peer);

        peer
    }

    fn update_peer(&mut self, peer: &Peer) {
        let mut addr = peer.get_connection().get_address().clone();
        if !peer.is_out() {
            addr.set_port(peer.get_local_port());
        }

        if let Some(stored_peer) = self.stored_peers.get_mut(&addr) {
            debug!("Updating {} in stored peerlist", peer);
            // reset the fail count and update the last seen time
            stored_peer.set_fail_count(0);
            stored_peer.set_last_seen(get_current_time());
        } else {
            debug!("Saving {} in stored peerlist", peer);
            self.stored_peers.insert(addr, StoredPeer::new(get_current_time(), StoredPeerState::Graylist));
        }
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

        if let Err(e) = self.save_peers_to_file() {
            error!("Error while trying to save peerlist to file: {}", e);
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
        where P: FnMut(&(&u64, &Arc<Peer>)) -> bool
    {
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


    // get a peer by its address
    fn internal_get_peer_by_addr<'a>(peers: &'a HashMap<u64, Arc<Peer>>, addr: &SocketAddr) -> Option<&'a Arc<Peer>> {
        peers.values().find(|peer| {
            // if this peer is incoming, we need to check if the peer_addr is the same as the one we're connected to
            // if its a outgoing one, just check its address
            if peer.is_out() {
                peer.get_connection().get_address() == addr
            } else {
                peer.get_local_port() == addr.port() && peer.get_connection().get_address().ip() == addr.ip()
            }
        })
    }

    pub fn get_peer_by_addr<'a>(&'a self, addr: &SocketAddr) -> Option<&'a Arc<Peer>> {
        Self::internal_get_peer_by_addr(&self.peers, addr)
    }

    pub fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> bool {
        Self::internal_get_peer_by_addr(&self.peers, peer_addr).is_some()
    }

    pub fn is_blacklisted(&self, addr: &SocketAddr) -> bool {
        if let Some(stored_peer) = self.stored_peers.get(addr) {
            return *stored_peer.get_state() == StoredPeerState::Blacklist;
        }

        false
    }

    fn set_state_to_address(&mut self, addr: &SocketAddr, state: StoredPeerState) {
        if let Some(stored_peer) = self.stored_peers.get_mut(addr) {
            stored_peer.set_state(state);
        } else {
            self.stored_peers.insert(addr.clone(), StoredPeer::new(get_current_time(), state));
        }
    }

    // blacklist a peer address
    // if this peer is already known, change its state to blacklist
    // otherwise create a new StoredPeer with state blacklist
    // disconnect the peer if present in peerlist
    pub async fn blacklist_address(&mut self, addr: &SocketAddr) {
        self.set_state_to_address(addr, StoredPeerState::Blacklist);

        if let Some(peer) = self.peers.values().find(|peer| *peer.get_connection().get_address() == *addr) {
            if let Err(e) = peer.get_connection().close().await {
                error!("Error while trying to close peer {} for being blacklisted: {}", peer.get_connection().get_address(), e);
            }
        }
    }

    // whitelist a peer address
    // if this peer is already known, change its state to whitelist
    // otherwise create a new StoredPeer with state whitelist
    pub fn whitelist_address(&mut self, addr: &SocketAddr) {
        self.set_state_to_address(addr, StoredPeerState::Whitelist);
    }

    pub fn find_peer_to_connect(&mut self) -> Option<SocketAddr> {
        // remove all peers that have a high fail count
        self.stored_peers.retain(|_, stored_peer| stored_peer.get_fail_count() < PEER_FAIL_LIMIT);

        let current_time = get_current_time();
        // first lets check in whitelist
        if let Some(addr) = self.find_peer_to_connect_to_with_state(current_time, StoredPeerState::Whitelist) {
            return Some(addr);
        }

        // then in graylist
        if let Some(addr) = self.find_peer_to_connect_to_with_state(current_time, StoredPeerState::Graylist) {
            return Some(addr);
        }

        None
    }

    // find among stored peers a peer to connect to with the requested StoredPeerState
    // we check that we're not already connected to this peer and that we didn't tried to connect to it recently
    fn find_peer_to_connect_to_with_state(&mut self, current_time: u64, state: StoredPeerState) -> Option<SocketAddr> {
        for (addr, stored_peer) in &mut self.stored_peers {
            if *stored_peer.get_state() == state && stored_peer.get_last_connection_try() + P2P_EXTEND_PEERLIST_DELAY <= current_time && Self::internal_get_peer_by_addr(&self.peers, addr).is_none() {
                stored_peer.set_last_connection_try(current_time);
                return Some(addr.clone());
            }
        }

        None
    }

    // increase the fail count of a peer
    pub fn increase_fail_count_for_saved_peer(&mut self, addr: &SocketAddr) {
        if let Some(stored_peer) = self.stored_peers.get_mut(addr) {
            stored_peer.set_fail_count(stored_peer.get_fail_count() + 1);
        }
    }

    // serialize the stored peers to a file
    fn save_peers_to_file(&self) -> Result<(), P2pError> {
        let content = serde_json::to_string_pretty(&self.stored_peers)?;
        fs::write(&self.filename, content)?;

        Ok(())
    }
}

impl StoredPeer {
    fn new(last_seen: u64, state: StoredPeerState) -> Self {
        Self {
            last_seen,
            last_connection_try: 0,
            fail_count: 0,
            state
        }
    }

    // fn get_last_seen(&self) -> u64 {
    //     self.last_seen
    // }

    fn get_last_connection_try(&self) -> u64 {
        self.last_connection_try
    }

    fn get_state(&self) -> &StoredPeerState {
        &self.state
    }

    fn set_last_seen(&mut self, last_seen: u64) {
        self.last_seen = last_seen;
    }

    fn set_last_connection_try(&mut self, last_connection_try: u64) {
        self.last_connection_try = last_connection_try;
    }

    fn set_state(&mut self, state: StoredPeerState) {
        self.state = state;
    }

    fn get_fail_count(&self) -> u8 {
        self.fail_count
    }

    fn set_fail_count(&mut self, fail_count: u8) {
        self.fail_count = fail_count;
    }
}