use crate::{
    config::{
        P2P_EXTEND_PEERLIST_DELAY,
        PEER_FAIL_LIMIT,
        PEER_FAIL_TO_CONNECT_LIMIT,
        PEER_TEMP_BAN_TIME_ON_CONNECT,
    },
    p2p::packet::peer_disconnected::PacketPeerDisconnected
};
use super::{peer::Peer, packet::Packet, error::P2pError};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    fmt::{self, Display, Formatter},
    fs, net::{IpAddr, SocketAddr},
    time::Duration
};
use humantime::format_duration;
use serde::{Serialize, Deserialize};
use tokio::sync::{mpsc::Sender, RwLock};
use xelis_common::{
    serializer::Serializer,
    time::{TimestampSeconds, get_current_time_in_seconds},
    api::daemon::Direction
};
use std::sync::Arc;
use bytes::Bytes;
use log::{info, debug, trace, error, warn};

pub type SharedPeerList = Arc<PeerList>;

// this object will be shared in Server, and each Peer
// so when we call Peer#close it will remove it from the list too
// using a RwLock so we can have multiple readers at the same time
pub struct PeerList {
    // Keep track of all connected peers
    peers: RwLock<HashMap<u64, Arc<Peer>>>,
    // We only keep one "peer" per address in case the peer changes multiple
    // times its local port
    stored_peers: RwLock<HashMap<IpAddr, StoredPeer>>,
    filename: String,
    // used to notify the server that a peer disconnected
    // this is done through a channel to not have to handle generic types
    // and to be flexible in the future
    peer_disconnect_channel: Option<Sender<Arc<Peer>>>
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

    pub fn new(capacity: usize, filename: String, peer_disconnect_channel: Option<Sender<Arc<Peer>>>) -> SharedPeerList {
        let stored_peers = match Self::load_stored_peers(&filename) {
            Ok(peers) => peers,
            Err(e) => {
                error!("Error while loading peerlist: {}", e);
                info!("Creating a empty peerlist");
                HashMap::new()
            }
        };

        Arc::new(
            Self {
                peers: RwLock::new(HashMap::with_capacity(capacity)),
                stored_peers: RwLock::new(stored_peers),
                filename,
                peer_disconnect_channel
            }
        )
    }

    // Clear the peerlist, this will overwrite the file on disk also
    pub async fn clear_peerlist(&self) {
        trace!("clear peerlist");
        let mut stored_peers = self.stored_peers.write().await;
        stored_peers.clear();

        if let Err(e) = self.save_peers_to_file(&stored_peers) {
            error!("Error while trying to save peerlist to file: {}", e);
        }
    }

    // Remove a peer from the list
    // We will notify all peers that have this peer in common
    pub async fn remove_peer(&self, peer_id: u64, notify: bool) -> Result<(), P2pError> {
        let (peer, peers) = {
            let mut peers = self.peers.write().await;
            let peer = peers.remove(&peer_id).ok_or(P2pError::PeerNotFoundById(peer_id))?;
            let peers = peers.values().cloned().collect::<Vec<Arc<Peer>>>();
            (peer, peers)
        };
 
        // If peer allows us to share it, we have to notify all peers that have this peer in common
        if notify && peer.sharable() {
            // now remove this peer from all peers that tracked it
            let addr = peer.get_outgoing_address();
            let packet = Bytes::from(Packet::PeerDisconnected(PacketPeerDisconnected::new(*addr)).to_bytes());
            for peer in peers {
                trace!("Locking shared peers for {}", peer.get_connection().get_address());
                let mut shared_peers = peer.get_peers().lock().await;
                trace!("locked shared peers for {}", peer.get_connection().get_address());

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
            if let Err(e) = peer_disconnect_channel.send(peer).await {
                error!("Error while sending peer disconnect notification: {}", e);
            }
        }

        Ok(())
    }

    // Add a new peer to the list
    // This will returns an error if peerlist is full
    pub async fn add_peer(&self, peer: &Arc<Peer>, max_peers: usize) -> Result<(), P2pError> {
        {
            let mut peers = self.peers.write().await;
            if peers.len() >= max_peers {
                return Err(P2pError::PeerListFull);
            }

            if peers.contains_key(&peer.get_id()) {
                return Err(P2pError::PeerIdAlreadyUsed(peer.get_id()));
            }

            peers.insert(peer.get_id(), Arc::clone(&peer));
        }
        info!("New peer connected: {}", peer);

        self.update_peer(&peer).await;

        Ok(())
    }

    async fn update_peer(&self, peer: &Peer) {
        let addr = peer.get_outgoing_address();
        let ip = addr.ip();
        let mut stored_peers = self.stored_peers.write().await;
        if let Some(stored_peer) = stored_peers.get_mut(&ip) {
            debug!("Updating {} in stored peerlist", peer);
            // reset the fail count and update the last seen time
            stored_peer.set_fail_count(0);
            stored_peer.set_last_seen(get_current_time_in_seconds());
            stored_peer.set_local_port(peer.get_local_port());
        } else {
            debug!("Saving {} in stored peerlist", peer);
            stored_peers.insert(ip, StoredPeer::new(peer.get_local_port(), StoredPeerState::Graylist));
        }
    }

    // Verify if the peer is connected (in peerlist)
    pub async fn has_peer(&self, peer_id: &u64) -> bool {
        let peers = self.peers.read().await;
        peers.contains_key(peer_id)
    }

    // Check if the peer is known from our peerlist
    pub async fn has_peer_stored(&self, ip: &IpAddr) -> bool {
        let stored_peers = self.stored_peers.read().await;
        stored_peers.contains_key(ip)
    }

    pub fn get_peers(&self) -> &RwLock<HashMap<u64, Arc<Peer>>> {
        &self.peers
    }

    // Get stored peers locked
    pub fn get_stored_peers(&self) -> &RwLock<HashMap<IpAddr, StoredPeer>> {
        &self.stored_peers
    }

    pub async fn get_cloned_peers(&self) -> HashSet<Arc<Peer>> {
        self.peers.read().await.values().cloned().collect()
    }

    pub async fn size(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    pub async fn close_all(&self) {
        trace!("closing all peers");
        let peers = {
            let mut peers = self.peers.write().await;
            peers.drain().collect::<Vec<(u64, Arc<Peer>)>>()
        };

        info!("Closing {} peers", peers.len());
        for (_, peer) in peers {
            debug!("Closing {}", peer);

            if let Err(e) = peer.signal_exit().await {
                error!("Error while trying to signal exit to {}: {}", peer, e);
            }
        }

        let stored_peers = self.stored_peers.read().await;
        if let Err(e) = self.save_peers_to_file(&stored_peers) {
            error!("Error while trying to save peerlist to file: {}", e);
        }
    }

    // Returns the highest topoheight of all peers
    pub async fn get_best_topoheight(&self) -> u64 {
        let mut best_height = 0;
        let peers = self.peers.read().await;
        for (_, peer) in peers.iter() {
            let height = peer.get_topoheight();
            if height > best_height {
                best_height = height;
            }
        }
        best_height
    }

    // Returns the median topoheight of all peers
    pub async fn get_median_topoheight(&self, our_topoheight: Option<u64>) -> u64 {
        let peers = self.peers.read().await;
        let mut values = peers.values().map(|peer| peer.get_topoheight()).collect::<Vec<u64>>();
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

    pub async fn get_peer_by_addr<'a>(&'a self, addr: &SocketAddr) -> Option<Arc<Peer>> {
        let peers = self.peers.read().await;
        Self::internal_get_peer_by_addr(&peers, addr).cloned()
    }

    pub async fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> bool {
        let peers = self.peers.read().await;
        Self::internal_get_peer_by_addr(&peers, peer_addr).is_some()
    }

    pub async fn is_blacklisted(&self, ip: &IpAddr) -> bool {
        self.addr_has_state(ip, StoredPeerState::Blacklist).await
    }

    // Verify that the peer is not blacklisted or temp banned
    pub async fn is_allowed(&self, ip: &IpAddr) -> bool {
        let stored_peers = self.stored_peers.read().await;
        if let Some(stored_peer) = stored_peers.get(&ip) {
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

    pub async fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.addr_has_state(ip, StoredPeerState::Whitelist).await
    }

    async fn addr_has_state(&self, ip: &IpAddr, state: StoredPeerState) -> bool {
        let stored_peers = self.stored_peers.read().await;
        if let Some(stored_peer) = stored_peers.get(&ip) {
            return *stored_peer.get_state() == state;
        }

        false
    }

    async fn set_state_to_address(&self, addr: &IpAddr, state: StoredPeerState) {
        let mut stored_peers = self.stored_peers.write().await;
        if let Some(stored_peer) = stored_peers.get_mut(addr) {
            stored_peer.set_state(state);
        } else {
            stored_peers.insert(addr.clone(), StoredPeer::new(0, state));
        }
    }

    // Set a peer to graylist, if its local port is 0, delete it from the stored peerlist
    // Because it was added manually and never connected to before
    pub async fn set_graylist_for_peer(&self, ip: &IpAddr) {
        let mut stored_peers = self.stored_peers.write().await;
        let delete = if let Some(peer) = stored_peers.get_mut(ip) {
            peer.set_state(StoredPeerState::Graylist);
            peer.get_local_port() == 0
        } else {
            false
        };

        if delete {
            info!("Deleting {} from stored peerlist", ip);
            stored_peers.remove(ip);
        }
    }

    fn get_list_with_state<'a>(&'a self, stored_peers: &'a HashMap<IpAddr, StoredPeer>, state: &StoredPeerState) -> Vec<(&'a IpAddr, &'a StoredPeer)> {
        stored_peers.iter().filter(|(_, stored_peer)| *stored_peer.get_state() == *state).collect()
    }

    // Get all peers blacklisted from peerlist
    pub fn get_blacklist<'a>(&'a self, stored_peers: &'a HashMap<IpAddr, StoredPeer>) -> Vec<(&'a IpAddr, &'a StoredPeer)> {
        self.get_list_with_state(stored_peers, &StoredPeerState::Blacklist)
    }

    // Retrieve whitelist stored peers
    pub fn get_whitelist<'a>(&'a self, stored_peers: &'a HashMap<IpAddr, StoredPeer>) -> Vec<(&'a IpAddr, &'a StoredPeer)> {
        self.get_list_with_state(stored_peers, &StoredPeerState::Blacklist)
    }

    // blacklist a peer address
    // if this peer is already known, change its state to blacklist
    // otherwise create a new StoredPeer with state blacklist
    // disconnect the peer if present in peerlist
    pub async fn blacklist_address(&self, ip: &IpAddr) {
        self.set_state_to_address(ip, StoredPeerState::Blacklist).await;

        let potential_peer = {
            let peers = self.peers.read().await;
            peers.values().find(|peer| peer.get_connection().get_address().ip() == *ip).cloned()
        };

        if let Some(peer) = potential_peer {
            if let Err(e) = peer.signal_exit().await {
                error!("Error while trying to close peer {} for being blacklisted: {}", peer.get_connection().get_address(), e);
            }
        }
    }

    // temp ban a peer for a duration in seconds
    // this will also close the peer
    pub async fn temp_ban_peer(&self, peer: &Peer, seconds: u64) {
        self.temp_ban_address(&peer.get_connection().get_address().ip(), seconds).await;
        if let Err(e) = peer.get_connection().close().await {
            error!("Error while trying to close {} for being temp banned: {}", peer, e);
        }

        if let Err(e) = self.remove_peer(peer.get_id(), true).await {
            error!("Error while removing peer from peerlist for being temp banned: {}", e);
        }
    }

    // temp ban a peer address for a duration in seconds
    pub async fn temp_ban_address(&self, ip: &IpAddr, seconds: u64) {
        let mut stored_peers = self.stored_peers.write().await;
        if let Some(stored_peer) = stored_peers.get_mut(ip) {
            stored_peer.set_temp_ban_until(Some(get_current_time_in_seconds() + seconds));
        } else {
            stored_peers.insert(ip.clone(), StoredPeer::new(0, StoredPeerState::Graylist));
        }
    }

    // whitelist a peer address
    // if this peer is already known, change its state to whitelist
    // otherwise create a new StoredPeer with state whitelist
    pub async fn whitelist_address(&self, ip: &IpAddr) {
        self.set_state_to_address(ip, StoredPeerState::Whitelist).await;
    }

    pub async fn find_peer_to_connect(&self) -> Option<SocketAddr> {
        // remove all peers that have a high fail count
        let peers = self.peers.read().await;
        let mut stored_peers = self.stored_peers.write().await;
        stored_peers.retain(|_, stored_peer| *stored_peer.get_state() == StoredPeerState::Whitelist || stored_peer.get_fail_count() < PEER_FAIL_LIMIT);

        let current_time = get_current_time_in_seconds();
        // first lets check in whitelist
        if let Some(addr) = self.find_peer_to_connect_to_with_state(&peers, &mut stored_peers, current_time, StoredPeerState::Whitelist) {
            return Some(addr);
        }

        // then in graylist
        if let Some(addr) = self.find_peer_to_connect_to_with_state(&peers, &mut stored_peers, current_time, StoredPeerState::Graylist) {
            return Some(addr);
        }

        None
    }

    // find among stored peers a peer to connect to with the requested StoredPeerState
    // we check that we're not already connected to this peer and that we didn't tried to connect to it recently
    fn find_peer_to_connect_to_with_state(&self, peers: &HashMap<u64, Arc<Peer>>, stored_peers: &mut HashMap<IpAddr, StoredPeer>, current_time: TimestampSeconds, state: StoredPeerState) -> Option<SocketAddr> {
        for (ip, stored_peer) in stored_peers {
            let addr = SocketAddr::new(*ip, stored_peer.get_local_port());
            if *stored_peer.get_state() == state && stored_peer.get_last_connection_try() + (stored_peer.get_fail_count() as u64 * P2P_EXTEND_PEERLIST_DELAY) <= current_time && Self::internal_get_peer_by_addr(peers, &addr).is_none() {
                stored_peer.set_last_connection_try(current_time);
                return Some(addr);
            }
        }

        None
    }

    // increase the fail count of a peer
    pub async fn increase_fail_count_for_stored_peer(&self, ip: &IpAddr, temp_ban: bool) {
        trace!("increasing fail count for {}, allow temp ban: {}", ip, temp_ban);
        let mut stored_peers = self.stored_peers.write().await;
        let stored_peer = match stored_peers.entry(*ip) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(StoredPeer::new(0, StoredPeerState::Graylist))
        };
        let fail_count = stored_peer.get_fail_count();
        if *stored_peer.get_state() != StoredPeerState::Whitelist {
            if temp_ban && fail_count != 0 && fail_count % PEER_FAIL_TO_CONNECT_LIMIT == 0 {
                debug!("Temp banning {} for failing too many times (count = {})", ip, fail_count);
                stored_peer.set_temp_ban_until(Some(get_current_time_in_seconds() + PEER_TEMP_BAN_TIME_ON_CONNECT));
            }

            debug!("Increasing fail count for {}", ip);
            stored_peer.set_fail_count(fail_count.wrapping_add(1));
        } else {
            debug!("{} is whitelisted, not increasing fail count", ip);
        }
    }

    // Store a new peer address into the peerlist file
    pub async fn store_peer_address(&self, addr: SocketAddr) -> bool {
        let mut stored_peers = self.stored_peers.write().await;
        let ip: IpAddr = addr.ip();
        if stored_peers.contains_key(&ip) {
            return false;
        }

        stored_peers.insert(ip, StoredPeer::new(addr.port(), StoredPeerState::Graylist));

        true
    }

    // serialize the stored peers to a file
    fn save_peers_to_file(&self, stored_peers: &HashMap<IpAddr, StoredPeer>) -> Result<(), P2pError> {
        trace!("saving peerlist to file");
        let content = serde_json::to_string_pretty(&stored_peers)?;
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