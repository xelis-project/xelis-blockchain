use crate::{
    p2p::packet::peer_disconnected::PacketPeerDisconnected,
    config::{P2P_EXTEND_PEERLIST_DELAY, PEER_FAIL_LIMIT}
};
use super::{peer::Peer, packet::Packet, error::P2pError};
use std::{collections::HashMap, net::{SocketAddr, IpAddr},
fs, fmt::{Formatter, self, Display},
time::Duration};
use humantime::format_duration;
use serde::{Serialize, Deserialize};
use tokio::sync::{RwLock, mpsc::UnboundedSender};
use xelis_common::{
    serializer::Serializer,
    time::{TimestampSeconds, get_current_time_in_seconds},
    api::daemon::Direction
};
use std::sync::Arc;
use bytes::Bytes;
use log::{info, debug, trace, error, warn};

pub type SharedPeerList = Arc<RwLock<PeerList>>;

// this object will be shared in Server, and each Peer
// so when we call Peer#close it will remove it from the list too
// using a RwLock so we can have multiple readers at the same time
pub struct PeerList {
    peers: HashMap<u64, Arc<Peer>>,
    // We only keep one "peer" per address in case the peer changes multiple
    // times its local port
    stored_peers: HashMap<IpAddr, StoredPeer>,
    filename: String,
    // used to notify the server that a peer disconnected
    // this is done through a channel to not have to handle generic types
    // and to be flexible in the future
    peer_disconnect_channel: Option<UnboundedSender<Arc<Peer>>>
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum StoredPeerState {
    Whitelist,
    Graylist,
    Blacklist,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredPeer {
    first_seen: TimestampSeconds,
    last_seen: TimestampSeconds,
    last_connection_try: TimestampSeconds,
    fail_count: u8,
    local_port: u16,
    // Until when the peer is banned
    temp_ban_until: Option<u64>,
    state: StoredPeerState
}

impl PeerList {
    // load all the stored peers from the file
    fn load_stored_peers(filename: &String) -> Result<HashMap<IpAddr, StoredPeer>, P2pError> {
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
        let mut peers: HashMap<IpAddr, StoredPeer> = match serde_json::from_str(&content) {
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

        // reset the fail count of all whitelisted peers
        for stored_peer in peers.values_mut() {
            if *stored_peer.get_state() == StoredPeerState::Whitelist {
                stored_peer.fail_count = 0;
            }
        }

        Ok(peers)
    }

    pub fn new(capacity: usize, filename: String, peer_disconnect_channel: Option<UnboundedSender<Arc<Peer>>>) -> SharedPeerList {
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
                    filename,
                    peer_disconnect_channel
                }
            )
        )
    }

    // Remove a peer from the list
    // We will notify all peers that have this peer in common
    pub async fn remove_peer(&mut self, peer_id: u64) -> Result<(), P2pError> {
        let peer = self.peers.remove(&peer_id).ok_or(P2pError::PeerNotFoundById(peer_id))?;
    
        // If peer allows us to share it, we have to notify all peers that have this peer in common
        if peer.sharable() {
            // now remove this peer from all peers that tracked it
            let addr = peer.get_outgoing_address();
            let packet = Bytes::from(Packet::PeerDisconnected(PacketPeerDisconnected::new(*addr)).to_bytes());
            for peer in self.peers.values() {
                let mut shared_peers = peer.get_peers().lock().await;
                // check if it was a common peer (we sent it and we received it)
                // Because its a common peer, we can expect that he will send us the same packet
                if let Some(direction) = shared_peers.get(addr) {
                    // If its a outgoing direction, send a packet to notify that the peer disconnected
                    if *direction != Direction::In {
                        trace!("Sending PeerDisconnected packet to peer {} for {}", peer.get_outgoing_address(), addr);
                        // we send the packet to notify the peer that we don't have it in common anymore
                        if let Err(e) = peer.send_bytes(packet.clone()).await {
                            error!("Error while trying to send PeerDisconnected packet to peer {}: {}", peer.get_connection().get_address(), e);
                        }
    
                        // Maybe he only disconnected from us, delete it to stay synced
                        shared_peers.remove(addr);
                    }
                }
            }
        }

        info!("Peer disconnected: {}", peer);
        if let Some(peer_disconnect_channel) = &self.peer_disconnect_channel {
            debug!("Notifying server that {} disconnected", peer);
            if let Err(e) = peer_disconnect_channel.send(peer) {
                error!("Error while sending peer disconnect notification: {}", e);
            }
        }

        Ok(())
    }

    pub fn add_peer(&mut self, id: u64, peer: Peer) -> Arc<Peer> {
        let peer = Arc::new(peer);
        self.peers.insert(id, peer.clone());
        info!("New peer connected: {}", peer);

        self.update_peer(&peer);

        peer
    }

    fn update_peer(&mut self, peer: &Peer) {
        let addr = peer.get_outgoing_address();
        let ip = addr.ip();
        if let Some(stored_peer) = self.stored_peers.get_mut(&ip) {
            debug!("Updating {} in stored peerlist", peer);
            // reset the fail count and update the last seen time
            stored_peer.set_fail_count(0);
            stored_peer.set_last_seen(get_current_time_in_seconds());
            stored_peer.set_local_port(peer.get_local_port());
        } else {
            debug!("Saving {} in stored peerlist", peer);
            self.stored_peers.insert(ip, StoredPeer::new(peer.get_local_port(), StoredPeerState::Graylist));
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

    // Returns the highest topoheight of all peers
    pub fn get_best_topoheight(&self) -> u64 {
        let mut best_height = 0;
        for (_, peer) in self.peers.iter() {
            let height = peer.get_topoheight();
            if height > best_height {
                best_height = height;
            }
        }
        best_height
    }

    // Returns the median topoheight of all peers
    pub fn get_median_topoheight(&self, our_topoheight: Option<u64>) -> u64 {
        let mut values = self.peers.values().map(|peer| peer.get_topoheight()).collect::<Vec<u64>>();
        if let Some(our_topoheight) = our_topoheight {
            values.push(our_topoheight);
        }

        let len = values.len();

        // No peers, so network median is 0
        if len == 0 {
            return 0;
        }

        values.sort();

        if len % 2 == 0 {
            let left = values[len / 2 - 1];
            let right = values[len / 2];
            (left + right) / 2
        } else {
            values[len / 2]
        }
    }

    // get a peer by its address
    fn internal_get_peer_by_addr<'a>(peers: &'a HashMap<u64, Arc<Peer>>, addr: &SocketAddr) -> Option<&'a Arc<Peer>> {
        peers.values().find(|peer| {
            // check both SocketAddr (the outgoing and the incoming)
            peer.get_connection().get_address() == addr || peer.get_outgoing_address() == addr
        })
    }

    pub fn get_peer_by_addr<'a>(&'a self, addr: &SocketAddr) -> Option<&'a Arc<Peer>> {
        Self::internal_get_peer_by_addr(&self.peers, addr)
    }

    pub fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> bool {
        Self::internal_get_peer_by_addr(&self.peers, peer_addr).is_some()
    }

    pub fn is_blacklisted(&self, ip: &IpAddr) -> bool {
        self.addr_has_state(ip, StoredPeerState::Blacklist)
    }

    // Verify that the peer is not blacklisted or temp banned
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        if let Some(stored_peer) = self.stored_peers.get(&ip) {
            // If peer is blacklisted, don't accept it
            return *stored_peer.get_state() != StoredPeerState::Blacklist
            // If it's still temp banned, don't accept it
            && stored_peer.get_temp_ban_until()
                // Temp ban is lower than current time, he is not banned anymore
                .map(|temp_ban_until| temp_ban_until < get_current_time_in_seconds())
                // We don't have a temp ban, so he is not banned
                .unwrap_or(true)
        }

        true
    }

    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.addr_has_state(ip, StoredPeerState::Whitelist)
    }

    fn addr_has_state(&self, ip: &IpAddr, state: StoredPeerState) -> bool {
        if let Some(stored_peer) = self.stored_peers.get(&ip) {
            return *stored_peer.get_state() == state;
        }

        false
    }

    fn set_state_to_address(&mut self, addr: &IpAddr, state: StoredPeerState) {
        if let Some(stored_peer) = self.stored_peers.get_mut(addr) {
            stored_peer.set_state(state);
        } else {
            self.stored_peers.insert(addr.clone(), StoredPeer::new(0, state));
        }
    }

    // Set a peer to graylist, if its local port is 0, delete it from the stored peerlist
    // Because it was added manually and never connected to before
    pub fn set_graylist_for_peer(&mut self, ip: &IpAddr) {
        let delete = if let Some(peer) = self.stored_peers.get_mut(ip) {
            peer.set_state(StoredPeerState::Graylist);
            peer.get_local_port() == 0
        } else {
            false
        };

        if delete {
            info!("Deleting {} from stored peerlist", ip);
            self.stored_peers.remove(ip);
        }
    }

    fn get_list_with_state<'a>(&'a self, state: &StoredPeerState) -> Vec<(&'a IpAddr, &'a StoredPeer)> {
        self.stored_peers.iter().filter(|(_, stored_peer)| *stored_peer.get_state() == *state).collect()
    }

    pub fn get_blacklist<'a>(&'a self) -> Vec<(&'a IpAddr, &'a StoredPeer)> {
        self.get_list_with_state(&StoredPeerState::Blacklist)
    }

    pub fn get_whitelist<'a>(&'a self) -> Vec<(&'a IpAddr, &'a StoredPeer)> {
        self.get_list_with_state(&StoredPeerState::Blacklist)
    }

    // blacklist a peer address
    // if this peer is already known, change its state to blacklist
    // otherwise create a new StoredPeer with state blacklist
    // disconnect the peer if present in peerlist
    pub async fn blacklist_address(&mut self, ip: &IpAddr) {
        self.set_state_to_address(ip, StoredPeerState::Blacklist);

        if let Some(peer) = self.peers.values().find(|peer| peer.get_connection().get_address().ip() == *ip) {
            // We have to clone because we're holding a immutable reference from self
            let peer = Arc::clone(peer);
            if let Err(e) = peer.close_with_peerlist(self).await {
                error!("Error while trying to close peer {} for being blacklisted: {}", peer.get_connection().get_address(), e);
            }
        }
    }

    // temp ban a peer for a duration in seconds
    // this will also close the peer
    pub async fn temp_ban_peer(&mut self, peer: &Peer, seconds: u64) {
        self.temp_ban_address(&peer.get_connection().get_address().ip(), seconds).await;
        if let Err(e) = peer.close_with_peerlist(self).await {
            error!("Error while trying to close peer {} for being blacklisted: {}", peer.get_connection().get_address(), e);
        }
    }

    // temp ban a peer address for a duration in seconds
    pub async fn temp_ban_address(&mut self, ip: &IpAddr, seconds: u64) {
        if let Some(stored_peer) = self.stored_peers.get_mut(ip) {
            stored_peer.set_temp_ban_until(Some(get_current_time_in_seconds() + seconds));
        } else {
            self.stored_peers.insert(ip.clone(), StoredPeer::new(0, StoredPeerState::Graylist));
        }
    }

    // whitelist a peer address
    // if this peer is already known, change its state to whitelist
    // otherwise create a new StoredPeer with state whitelist
    pub fn whitelist_address(&mut self, ip: &IpAddr) {
        self.set_state_to_address(ip, StoredPeerState::Whitelist);
    }

    pub fn find_peer_to_connect(&mut self) -> Option<SocketAddr> {
        // remove all peers that have a high fail count
        self.stored_peers.retain(|_, stored_peer| *stored_peer.get_state() == StoredPeerState::Whitelist || stored_peer.get_fail_count() < PEER_FAIL_LIMIT);

        let current_time = get_current_time_in_seconds();
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
    fn find_peer_to_connect_to_with_state(&mut self, current_time: TimestampSeconds, state: StoredPeerState) -> Option<SocketAddr> {
        for (ip, stored_peer) in &mut self.stored_peers {
            let addr = SocketAddr::new(*ip, stored_peer.get_local_port());
            if *stored_peer.get_state() == state && stored_peer.get_last_connection_try() + (stored_peer.get_fail_count() as u64 * P2P_EXTEND_PEERLIST_DELAY) <= current_time && Self::internal_get_peer_by_addr(&self.peers, &addr).is_none() {
                stored_peer.set_last_connection_try(current_time);
                return Some(addr);
            }
        }

        None
    }

    // increase the fail count of a peer
    pub fn increase_fail_count_for_saved_peer(&mut self, ip: &IpAddr) {
        if let Some(stored_peer) = self.stored_peers.get_mut(ip) {
            let fail_count = stored_peer.get_fail_count();
            if fail_count == u8::MAX {
                // we reached the max value, we can't increase it anymore
                return;
            }
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
    fn new(local_port: u16, state: StoredPeerState) -> Self {
        let current_time = get_current_time_in_seconds();
        Self {
            first_seen: current_time,
            last_seen: current_time,
            last_connection_try: 0,
            fail_count: 0,
            local_port,
            temp_ban_until: None,
            state
        }
    }

    fn get_last_connection_try(&self) -> TimestampSeconds {
        self.last_connection_try
    }

    fn get_state(&self) -> &StoredPeerState {
        &self.state
    }

    fn set_last_seen(&mut self, last_seen: TimestampSeconds) {
        self.last_seen = last_seen;
    }

    fn set_last_connection_try(&mut self, last_connection_try: TimestampSeconds) {
        self.last_connection_try = last_connection_try;
    }

    fn set_state(&mut self, state: StoredPeerState) {
        self.state = state;
    }

    fn get_temp_ban_until(&self) -> Option<u64> {
        self.temp_ban_until
    }

    fn set_temp_ban_until(&mut self, temp_ban_until: Option<u64>) {
        self.temp_ban_until = temp_ban_until;
    }

    fn get_fail_count(&self) -> u8 {
        self.fail_count
    }

    fn set_fail_count(&mut self, fail_count: u8) {
        self.fail_count = fail_count;
    }

    fn set_local_port(&mut self, local_port: u16) {
        self.local_port = local_port;
    }

    fn get_local_port(&self) -> u16 {
        self.local_port
    }
}

impl Display for StoredPeer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let current_time = get_current_time_in_seconds();
        write!(f, "StoredPeer[first seen: {} ago, last seen: {} ago]", format_duration(Duration::from_secs(current_time - self.first_seen)), format_duration(Duration::from_secs(current_time - self.last_seen)))
    }
}