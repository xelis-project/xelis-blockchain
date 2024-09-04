use crate::{
    config::{
        P2P_EXTEND_PEERLIST_DELAY,
        PEER_FAIL_TO_CONNECT_LIMIT,
        PEER_TEMP_BAN_TIME_ON_CONNECT,
    },
    p2p::packet::peer_disconnected::PacketPeerDisconnected
};
use super::{
    disk_cache::{DiskCache, DiskError},
    error::P2pError,
    packet::Packet,
    peer::Peer
};
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    net::{IpAddr, SocketAddr},
    time::Duration
};
use humantime::format_duration;
use serde::{Serialize, Deserialize};
use tokio::sync::{mpsc::Sender, RwLock};
use xelis_common::{
    api::daemon::Direction,
    serializer::{Reader, ReaderError, Serializer, Writer},
    time::{get_current_time_in_seconds, TimestampSeconds}
};
use std::sync::Arc;
use bytes::Bytes;
use log::{info, debug, trace, error};

pub type SharedPeerList = Arc<PeerList>;

// this object will be shared in Server, and each Peer
// so when we call Peer#close it will remove it from the list too
// using a RwLock so we can have multiple readers at the same time
pub struct PeerList {
    // Keep track of all connected peers
    peers: RwLock<HashMap<u64, Arc<Peer>>>,
    // used to notify the server that a peer disconnected
    // this is done through a channel to not have to handle generic types
    // and to be flexible in the future
    peer_disconnect_channel: Option<Sender<Arc<Peer>>>,
    // We only keep one "peer" per address in case the peer changes multiple
    // times its local port
    cache: DiskCache
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
enum PeerListEntryState {
    Whitelist,
    Graylist,
    Blacklist,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerListEntry {
    first_seen: Option<TimestampSeconds>,
    last_seen: Option<TimestampSeconds>,
    last_connection_try: Option<TimestampSeconds>,
    fail_count: u8,
    local_port: Option<u16>,
    // Until when the peer is banned
    temp_ban_until: Option<u64>,
    state: PeerListEntryState
}

impl PeerList {
    pub fn new(capacity: usize, filename: String, peer_disconnect_channel: Option<Sender<Arc<Peer>>>) -> Result<SharedPeerList, P2pError> {
        Ok(Arc::new(
            Self {
                peers: RwLock::new(HashMap::with_capacity(capacity)),
                peer_disconnect_channel,
                cache: DiskCache::new(filename)?
            }
        ))
    }

    // Clear the peerlist, this will overwrite the file on disk also
    pub async fn clear_peerlist(&self) -> Result<(), P2pError> {
        trace!("clear peerlist");
        self.cache.clear_peerlist().await?;
        Ok(())
    }

    // Get the cache
    pub fn get_cache(&self) -> &DiskCache {
        &self.cache
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

        // Update the peerlist entry
        self.update_peer(&peer).await?;
        
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

        self.update_peer(&peer).await?;

        Ok(())
    }

    // Update a peer in the stored peerlist
    async fn update_peer(&self, peer: &Peer) -> Result<(), P2pError> {
        let addr = peer.get_outgoing_address();
        let ip = addr.ip();
        if self.cache.has_peerlist_entry(&ip)? {
            let mut entry = self.cache.get_peerlist_entry(&ip)?;
            debug!("Updating {} in stored peerlist", peer);
            // reset the fail count and update the last seen time
            entry.set_fail_count(0);
            if entry.get_first_seen().is_none() {
                entry.set_first_seen(peer.get_connection().connected_on());
            }

            entry.set_last_seen(get_current_time_in_seconds());
            entry.set_local_port(peer.get_local_port());

            self.cache.set_peerlist_entry(&ip, entry)?;
        } else {
            debug!("Saving {} in stored peerlist", peer);
            let mut entry = PeerListEntry::new(Some(peer.get_local_port()), PeerListEntryState::Graylist);
            entry.set_first_seen(peer.get_connection().connected_on());
            entry.set_last_seen(get_current_time_in_seconds());

            self.cache.set_peerlist_entry(&ip, entry)?;
        }

        Ok(())
    }

    // Verify if the peer is connected (in peerlist)
    pub async fn has_peer(&self, peer_id: &u64) -> bool {
        let peers = self.peers.read().await;
        peers.contains_key(peer_id)
    }

    // Check if the peer is known from our peerlist
    pub async fn has_peer_stored(&self, ip: &IpAddr) -> Result<bool, P2pError> {
        Ok(self.cache.has_peerlist_entry(ip)?)
    }

    pub fn get_peers(&self) -> &RwLock<HashMap<u64, Arc<Peer>>> {
        &self.peers
    }

    // Get stored peers locked
    pub fn get_peerlist_entries(&self) -> impl Iterator<Item = Result<(IpAddr, PeerListEntry), DiskError>> {
        self.cache.get_peerlist_entries()
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

            if let Err(e) = self.update_peer(&peer).await {
                error!("Error while updating peer {}: {}", peer, e);
            }
        }

        if let Err(e) = self.cache.flush().await {
            error!("Error while flushing cache to disk: {}", e);
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

    // Is the ip blacklisted in the stored peerlist
    pub async fn is_blacklisted(&self, ip: &IpAddr) -> Result<bool, P2pError> {
        self.addr_has_state(ip, PeerListEntryState::Blacklist).await
    }

    // Verify that the peer is not blacklisted or temp banned
    pub async fn is_allowed(&self, ip: &IpAddr) -> Result<bool, P2pError> {
        if !self.cache.has_peerlist_entry(ip)? {
            return Ok(true);
        }

        let entry = self.cache.get_peerlist_entry(&ip)?;
        // If peer is blacklisted, don't accept it
        return Ok(*entry.get_state() != PeerListEntryState::Blacklist
            // If it's still temp banned, don't accept it
            && entry.get_temp_ban_until()
                // Temp ban is lower than current time, he is not banned anymore
                .map(|temp_ban_until| temp_ban_until < get_current_time_in_seconds())
                // We don't have a temp ban, so he is not banned
                .unwrap_or(true)
        )
    }

    // Verify if the peer is whitelisted in the stored peerlist
    pub async fn is_whitelisted(&self, ip: &IpAddr) -> Result<bool, P2pError> {
        self.addr_has_state(ip, PeerListEntryState::Whitelist).await
    }

    async fn addr_has_state(&self, ip: &IpAddr, state: PeerListEntryState) -> Result<bool, P2pError> {
        if self.cache.has_peerlist_entry(ip)? {
            let entry = self.cache.get_peerlist_entry(ip)?;
            return Ok(*entry.get_state() == state);
        }

        Ok(false)
    }

    // Set the state of a peer address
    async fn set_state_to_address(&self, addr: &IpAddr, state: PeerListEntryState) -> Result<(), P2pError> {
        if self.cache.has_peerlist_entry(addr)? {
            let mut entry = self.cache.get_peerlist_entry(addr)?;
            entry.set_state(state);
            self.cache.set_peerlist_entry(addr, entry)?;
        } else {
            self.cache.set_peerlist_entry(addr, PeerListEntry::new(None, state))?;
        }

        Ok(())
    }

    // Set a peer to graylist, if its local port is 0, delete it from the stored peerlist
    // Because it was added manually and never connected to before
    pub async fn set_graylist_for_peer(&self, ip: &IpAddr) -> Result<(), P2pError> {
        if self.cache.has_peerlist_entry(ip)? {
            let mut entry = self.cache.get_peerlist_entry(ip)?;
            if entry.get_local_port().is_none() {
                info!("Deleting {} from stored peerlist", ip);
                self.cache.remove_peerlist_entry(ip)?;
            } else {
                entry.set_state(PeerListEntryState::Graylist);
            }
        }

        Ok(())
    }

    fn get_list_with_state(&self, state: &PeerListEntryState) -> Result<Vec<(IpAddr, PeerListEntry)>, P2pError> {
        let mut values = Vec::new();
        for res in self.cache.get_peerlist_entries() {
            let (ip, entry) = res?;
            if entry.get_state() == state {
                values.push((ip, entry));
            }
        }

        Ok(values)
    }

    // Get all peers blacklisted from peerlist
    pub fn get_blacklist(&self) -> Result<Vec<(IpAddr, PeerListEntry)>, P2pError> {
        self.get_list_with_state(&PeerListEntryState::Blacklist)
    }

    // Retrieve whitelist stored peers
    pub fn get_whitelist(&self) -> Result<Vec<(IpAddr, PeerListEntry)>, P2pError> {
        self.get_list_with_state(&PeerListEntryState::Whitelist)
    }

    // blacklist a peer address
    // if this peer is already known, change its state to blacklist
    // otherwise create a new PeerListEntry with state blacklist
    // disconnect the peer if present in peerlist
    pub async fn blacklist_address(&self, ip: &IpAddr) -> Result<(), P2pError> {
        self.set_state_to_address(ip, PeerListEntryState::Blacklist).await?;

        let potential_peer = {
            let peers = self.peers.read().await;
            peers.values().find(|peer| peer.get_connection().get_address().ip() == *ip).cloned()
        };

        if let Some(peer) = potential_peer {
            peer.signal_exit().await?;
        }

        Ok(())
    }

    // temp ban a peer address for a duration in seconds
    pub async fn temp_ban_address(&self, ip: &IpAddr, seconds: u64) -> Result<(), P2pError> {
        if self.cache.has_peerlist_entry(ip)? {
            let mut entry = self.cache.get_peerlist_entry(ip)?;
            entry.set_temp_ban_until(Some(get_current_time_in_seconds() + seconds));
            self.cache.set_peerlist_entry(ip, entry)?;
        } else {
            self.cache.set_peerlist_entry(ip, PeerListEntry::new(None, PeerListEntryState::Graylist))?;
        }

        Ok(())
    }

    // whitelist a peer address
    // if this peer is already known, change its state to whitelist
    // otherwise create a new PeerListEntry with state whitelist
    pub async fn whitelist_address(&self, ip: &IpAddr) -> Result<(), P2pError> {
        self.set_state_to_address(ip, PeerListEntryState::Whitelist).await
    }

    // Find a peer to connect to from the stored peerlist
    // This will return None if no peer is found
    // We will search for a whitelisted peer first, then a graylisted peer
    // If a peer is found, we update its last connection try time
    pub async fn find_peer_to_connect(&self) -> Result<Option<SocketAddr>, P2pError> {
        let peers = self.peers.read().await;
        let peerlist_entries = self.cache.get_peerlist_entries();

        let current_time = get_current_time_in_seconds();

        // Search the first peer that we can connect to
        let mut potential_gray_peer = None;
        for res in peerlist_entries {
            let (ip, mut entry) = res?;
            if let Some(local_port) = entry.get_local_port() {
                let addr = SocketAddr::new(ip, local_port);
                if *entry.get_state() != PeerListEntryState::Blacklist && entry.get_last_connection_try().unwrap_or(0) + (entry.get_fail_count() as u64 * P2P_EXTEND_PEERLIST_DELAY) <= current_time && Self::internal_get_peer_by_addr(&peers, &addr).is_none() {
                    // Store it if we don't have any whitelisted peer to connect to
                    if potential_gray_peer.is_none() && *entry.get_state() == PeerListEntryState::Graylist {
                        potential_gray_peer = Some((ip, addr));
                    } else if *entry.get_state() == PeerListEntryState::Whitelist {
                        debug!("Found peer to connect: {}, updating last connection try", addr);
                        entry.set_last_connection_try(current_time);
                        self.cache.set_peerlist_entry(&ip, entry)?;
                        return Ok(Some(addr));
                    }
                }
            }
        }

        // If we didn't find a whitelisted peer, try to connect to a graylisted peer
        Ok(match potential_gray_peer {
            Some((ip, addr)) => {
                debug!("Found gray peer to connect: {}, updating last connection try", addr);
                let mut entry = self.cache.get_peerlist_entry(&ip)?;
                entry.set_last_connection_try(current_time);
                self.cache.set_peerlist_entry(&ip, entry)?;
                Some(addr)
            },
            None => None
        })
    }


    // increase the fail count of a peer
    pub async fn increase_fail_count_for_peerlist_entry(&self, ip: &IpAddr, temp_ban: bool) -> Result<(), P2pError> {
        trace!("increasing fail count for {}, allow temp ban: {}", ip, temp_ban);
        let mut entry = if self.cache.has_peerlist_entry(ip)? {
            self.cache.get_peerlist_entry(ip)?
        } else {
            PeerListEntry::new(None, PeerListEntryState::Graylist)
        };

        let fail_count = entry.get_fail_count();
        if *entry.get_state() != PeerListEntryState::Whitelist {
            if temp_ban && fail_count != 0 && fail_count % PEER_FAIL_TO_CONNECT_LIMIT == 0 {
                debug!("Temp banning {} for failing too many times (count = {})", ip, fail_count);
                entry.set_temp_ban_until(Some(get_current_time_in_seconds() + PEER_TEMP_BAN_TIME_ON_CONNECT));
            }

            debug!("Increasing fail count for {}", ip);
            entry.set_fail_count(fail_count.wrapping_add(1));

            self.cache.set_peerlist_entry(ip, entry)?;
        } else {
            debug!("{} is whitelisted, not increasing fail count", ip);
        }

        Ok(())
    }

    // Store a new peer address into the peerlist file
    pub async fn store_peer_address(&self, addr: SocketAddr) -> Result<bool, P2pError> {
        let ip: IpAddr = addr.ip();
        if self.cache.has_peerlist_entry(&ip)? {
            return Ok(false);
        }

        self.cache.set_peerlist_entry(&ip, PeerListEntry::new(Some(addr.port()), PeerListEntryState::Graylist))?;

        Ok(true)
    }
}

impl PeerListEntry {
    fn new(local_port: Option<u16>, state: PeerListEntryState) -> Self {
        Self {
            first_seen: None,
            last_seen: None,
            last_connection_try: None,
            fail_count: 0,
            local_port,
            temp_ban_until: None,
            state
        }
    }

    fn get_last_connection_try(&self) -> Option<TimestampSeconds> {
        self.last_connection_try
    }

    fn get_state(&self) -> &PeerListEntryState {
        &self.state
    }

    pub fn set_first_seen(&mut self, first_seen: TimestampSeconds) {
        self.first_seen = Some(first_seen);
    }

    pub fn get_first_seen(&self) -> Option<TimestampSeconds> {
        self.first_seen
    }

    fn set_last_seen(&mut self, last_seen: TimestampSeconds) {
        self.last_seen = Some(last_seen);
    }

    fn set_last_connection_try(&mut self, last_connection_try: TimestampSeconds) {
        self.last_connection_try = Some(last_connection_try);
    }

    fn set_state(&mut self, state: PeerListEntryState) {
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
        self.local_port = Some(local_port);
    }

    fn get_local_port(&self) -> Option<u16> {
        self.local_port
    }
}

impl Display for PeerListEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let current_time = get_current_time_in_seconds();
        write!(
            f,
            "PeerListEntry[state: {:?}, first seen: {}, last seen: {}, last try: {}]",
            self.state,
            self.first_seen.map(|v| format!("{} ago", format_duration(Duration::from_secs(current_time - v)))).unwrap_or_else(|| "never".to_string()),
            self.last_seen.map(|v| format!("{} ago", format_duration(Duration::from_secs(current_time - v)))).unwrap_or_else(|| "never".to_string()),
            self.last_connection_try.map(|v| format!("{} ago", format_duration(Duration::from_secs(current_time - v)))).unwrap_or_else(|| "never".to_string())
        )
    }
}

impl Serializer for PeerListEntryState {
    fn write(&self, writer: &mut Writer) {
        match self {
            Self::Whitelist => writer.write_u8(0),
            Self::Graylist => writer.write_u8(1),
            Self::Blacklist => writer.write_u8(2)
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => Self::Whitelist,
            1 => Self::Graylist,
            2 => Self::Blacklist,
            _ => return Err(ReaderError::InvalidValue)
        })
    }
}

impl Serializer for PeerListEntry {
    fn write(&self, writer: &mut Writer) {
        writer.write_optional_non_zero_u64(self.first_seen);
        writer.write_optional_non_zero_u64(self.last_seen);
        writer.write_optional_non_zero_u64(self.last_connection_try);
        self.fail_count.write(writer);
        writer.write_optional_non_zero_u16(self.local_port);
        self.temp_ban_until.write(writer);
        self.state.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let first_seen = reader.read_optional_non_zero_u64()?;
        let last_seen = reader.read_optional_non_zero_u64()?;
        let last_connection_try = reader.read_optional_non_zero_u64()?;
        let fail_count = reader.read_u8()?;
        let local_port = reader.read_optional_non_zero_u16()?;
        let temp_ban_until = Option::read(reader)?;
        let state = PeerListEntryState::read(reader)?;

        Ok(Self {
            first_seen,
            last_seen,
            last_connection_try,
            fail_count,
            local_port,
            temp_ban_until,
            state
        })
    }
}