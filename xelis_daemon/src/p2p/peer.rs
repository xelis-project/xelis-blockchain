use lru::LruCache;
use xelis_common::config::{PEER_FAIL_TIME_RESET, STABLE_LIMIT, TIPS_LIMIT, PEER_TIMEOUT_BOOTSTRAP_STEP};
use xelis_common::utils::get_current_time;
use xelis_common::{
    crypto::hash::Hash,
    config::PEER_TIMEOUT_REQUEST_OBJECT,
    serializer::Serializer
};
use super::packet::bootstrap_chain::{StepRequest, BootstrapChainRequest, StepResponse};
use super::packet::object::{ObjectRequest, OwnedObjectResponse};
use super::peer_list::SharedPeerList;
use super::connection::{Connection, ConnectionMessage};
use super::packet::Packet;
use super::error::P2pError;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicBool, Ordering};
use std::fmt::{Display, Error, Formatter};
use std::time::Duration;
use tokio::sync::oneshot::Sender;
use tokio::time::timeout;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use std::borrow::Cow;
use bytes::Bytes;
use log::{warn, trace, debug};

pub type RequestedObjects = HashMap<ObjectRequest, Sender<OwnedObjectResponse>>;

pub struct Peer {
    connection: Connection,
    id: u64,
    node_tag: Option<String>, // Node tag if provided
    local_port: u16,
    version: String, // daemon version
    out: bool, // True mean we are the client
    priority: bool, // if this node can be trusted (seed node or added manually by user)
    top_hash: Mutex<Hash>, // current block top hash for this peer
    topoheight: AtomicU64, // current highest topo height for this peer
    height: AtomicU64, // current highest block height for this peer
    last_chain_sync: AtomicU64,
    last_fail_count: AtomicU64, // last time we got a fail
    fail_count: AtomicU8, // fail count: if greater than 20, we should close this connection
    peer_list: SharedPeerList,
    chain_requested: AtomicBool,
    objects_requested: Mutex<RequestedObjects>,
    peers_received: Mutex<HashSet<SocketAddr>>, // all peers from this peer
    peers_sent: Mutex<HashSet<SocketAddr>>, // all peers sent to this peer
    last_peer_list: AtomicU64, // last time we received a peerlist from this peer
    last_ping: AtomicU64, // last time we got a ping packet from this peer
    cumulative_difficulty: AtomicU64, // cumulative difficulty of peer chain
    txs_cache: Mutex<LruCache<Hash, ()>>, // All transactions propagated to/from this peer
    blocks_propagation: Mutex<LruCache<Hash, ()>>, // last blocks propagated to/from this peer
    last_inventory: AtomicU64, // last time we got an inventory packet from this peer
    requested_inventory: AtomicBool, // if we requested this peer to send us an inventory notification
    pruned_topoheight: AtomicU64, // pruned topoheight if its a pruned node
    is_pruned: AtomicBool, // cannot be set to false if its already to true (protocol rules)
    // used for await on bootstrap chain packets
    bootstrap_chain: Mutex<Option<Sender<StepResponse>>>,
    // IP address with local port
    outgoing_address: SocketAddr
}

impl Peer {
    pub fn new(connection: Connection, id: u64, node_tag: Option<String>, local_port: u16, version: String, top_hash: Hash, topoheight: u64, height: u64, pruned_topoheight: Option<u64>, out: bool, priority: bool, cumulative_difficulty: u64, peer_list: SharedPeerList, peers: HashSet<SocketAddr>) -> Self {
        let mut outgoing_address = *connection.get_address();
        outgoing_address.set_port(local_port);

        Self {
            connection,
            id,
            node_tag,
            local_port,
            version,
            top_hash: Mutex::new(top_hash),
            topoheight: AtomicU64::new(topoheight),
            height: AtomicU64::new(height),
            out,
            priority,
            last_fail_count: AtomicU64::new(0),
            fail_count: AtomicU8::new(0),
            last_chain_sync: AtomicU64::new(0),
            peer_list,
            chain_requested: AtomicBool::new(false),
            objects_requested: Mutex::new(HashMap::new()),
            peers_received: Mutex::new(peers),
            peers_sent: Mutex::new(HashSet::new()),
            last_peer_list: AtomicU64::new(0),
            last_ping: AtomicU64::new(0),
            cumulative_difficulty: AtomicU64::new(cumulative_difficulty),
            txs_cache: Mutex::new(LruCache::new(128)),
            blocks_propagation: Mutex::new(LruCache::new(STABLE_LIMIT as usize * TIPS_LIMIT)),
            last_inventory: AtomicU64::new(0),
            requested_inventory: AtomicBool::new(false),
            pruned_topoheight: AtomicU64::new(pruned_topoheight.unwrap_or(0)),
            is_pruned: AtomicBool::new(pruned_topoheight.is_some()),
            bootstrap_chain: Mutex::new(None),
            outgoing_address
        }
    }

    pub fn get_txs_cache(&self) -> &Mutex<LruCache<Hash, ()>> {
        &self.txs_cache
    }

    pub fn get_blocks_propagation(&self) -> &Mutex<LruCache<Hash, ()>> {
        &self.blocks_propagation
    }

    pub fn get_connection(&self) -> &Connection {
        &self.connection
    }

    pub fn get_id(&self) -> u64 {
        self.id
    }

    pub fn get_node_tag(&self) -> &Option<String> {
        &self.node_tag
    }

    pub fn get_local_port(&self) -> u16 {
        self.local_port
    }

    pub fn get_version(&self) -> &String {
        &self.version
    }

    pub fn get_topoheight(&self) -> u64 {
        self.topoheight.load(Ordering::Acquire)
    }

    pub fn set_topoheight(&self, topoheight: u64) {
        self.topoheight.store(topoheight, Ordering::Release);
    }

    pub fn get_height(&self) -> u64 {
        self.height.load(Ordering::Acquire)
    }

    pub fn set_height(&self, height: u64) {
        self.height.store(height, Ordering::Release);
    }

    pub fn is_pruned(&self) -> bool {
        self.is_pruned.load(Ordering::Acquire)
    }

    pub fn get_pruned_topoheight(&self) -> Option<u64> {
        if self.is_pruned() {
            Some(self.pruned_topoheight.load(Ordering::Acquire))
        } else {
            None
        }
    }

    pub fn set_pruned_topoheight(&self, pruned_topoheight: Option<u64>) {
        if let Some(pruned_topoheight) = pruned_topoheight {
            self.is_pruned.store(true, Ordering::Release);
            self.pruned_topoheight.store(pruned_topoheight, Ordering::Release);
        } else {
            self.is_pruned.store(false, Ordering::Release);
        }
    }

    pub async fn set_block_top_hash(&self, hash: Hash) {
        *self.top_hash.lock().await = hash
    }

    pub fn get_top_block_hash(&self) -> &Mutex<Hash> {
        &self.top_hash
    }

    pub fn get_cumulative_difficulty(&self) -> u64 {
        self.cumulative_difficulty.load(Ordering::Acquire)
    }

    pub fn set_cumulative_difficulty(&self, cumulative_difficulty: u64) {
        self.cumulative_difficulty.store(cumulative_difficulty, Ordering::Release)
    }

    pub fn is_out(&self) -> bool {
        self.out
    }

    pub fn is_priority(&self) -> bool {
        self.priority
    }

    pub fn get_last_fail_count(&self) -> u64 {
        self.last_fail_count.load(Ordering::Acquire)
    }

    pub fn set_last_fail_count(&self, value: u64) {
        self.last_fail_count.store(value, Ordering::Release);
    }

    pub fn get_fail_count(&self) -> u8 {
        self.fail_count.load(Ordering::Acquire)
    }

    fn update_fail_count_default(&self) -> bool {
        self.update_fail_count(get_current_time(), 0)
    }

    fn update_fail_count(&self, current_time: u64, to_store: u8) -> bool {
        let last_fail = self.get_last_fail_count();
        let reset = last_fail + PEER_FAIL_TIME_RESET < current_time;
        if reset {
            // reset counter
            self.fail_count.store(to_store, Ordering::Release);
        }
        reset
    }

    pub fn increment_fail_count(&self) {
        let current_time = get_current_time();
        // if its long time we didn't get a fail, reset the fail count to 1 (because of current fail)
        // otherwise, add 1
        if !self.update_fail_count(current_time, 1) {
            self.fail_count.fetch_add(1, Ordering::Release);
        }
        self.set_last_fail_count(current_time);
    }

    pub fn get_last_chain_sync(&self) -> u64 {
        self.last_chain_sync.load(Ordering::Acquire)
    }

    pub fn set_last_chain_sync(&self, time: u64) {
        self.last_chain_sync.store(time, Ordering::Release);
    }

    pub fn chain_sync_requested(&self) -> bool {
        self.chain_requested.load(Ordering::Acquire)
    }

    pub fn set_chain_sync_requested(&self, value: bool) {
        self.chain_requested.store(value, Ordering::Release);
    }

    pub fn get_objects_requested(&self) -> &Mutex<RequestedObjects> {
        &self.objects_requested
    }

    pub async fn remove_object_request(&self, request: ObjectRequest) -> Result<Sender<OwnedObjectResponse>, P2pError> {
        let mut objects = self.objects_requested.lock().await;
        objects.remove(&request).ok_or(P2pError::ObjectNotFound(request))
    }

    // Request a object from this peer and wait on it until we receive it or until timeout 
    pub async fn request_blocking_object(&self, request: ObjectRequest) -> Result<OwnedObjectResponse, P2pError> {
        trace!("Requesting {} from {}", request, self);
        let receiver = {
            let mut objects = self.objects_requested.lock().await;
            if objects.contains_key(&request) {
                return Err(P2pError::ObjectAlreadyRequested(request));
            }
            self.send_packet(Packet::ObjectRequest(Cow::Borrowed(&request))).await?;
            let (sender, receiver) = tokio::sync::oneshot::channel();
            objects.insert(request.clone(), sender); // clone is necessary in case timeout has occured
            receiver
        };
        let object = match timeout(Duration::from_millis(PEER_TIMEOUT_REQUEST_OBJECT), receiver).await {
            Ok(res) => res?,
            Err(e) => {
                trace!("Requested data has timed out");
                let mut objects = self.objects_requested.lock().await;
                objects.remove(&request); // remove it from request list
                return Err(P2pError::AsyncTimeOut(e));
            }
        };
        let object_hash = object.get_hash();
        if *object_hash != *request.get_hash() {
            return Err(P2pError::InvalidObjectResponse(object_hash.clone()))
        }

        Ok(object)
    }

    pub async fn request_boostrap_chain(&self, step: StepRequest<'_>) -> Result<StepResponse, P2pError> {
        debug!("Requesting bootstrap chain step: {:?}", step);
        let step_kind = step.kind();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        {
            let mut sender_lock = self.bootstrap_chain.lock().await;
            *sender_lock = Some(sender);
        }

        // send the packet
        self.send_packet(Packet::BootstrapChainRequest(BootstrapChainRequest::new(step))).await?;

        // wait on the response
        let response: StepResponse = match timeout(Duration::from_millis(PEER_TIMEOUT_BOOTSTRAP_STEP), receiver).await {
            Ok(res) => res?,
            Err(e) => {
                trace!("Requested bootstrap chain step {:?} has timed out", step_kind);
                return Err(P2pError::AsyncTimeOut(e));
            }
        };

        // check that the response is what we asked for
        let response_kind = response.kind();
        if response_kind != step_kind {
            return Err(P2pError::InvalidBootstrapStep(step_kind, response_kind))
        }

        Ok(response)
    }

    pub fn get_bootstrap_chain_channel(&self) -> &Mutex<Option<Sender<StepResponse>>> {
        &self.bootstrap_chain
    }

    pub fn get_peers(&self, sent: bool) -> &Mutex<HashSet<SocketAddr>> {
        if sent {
            &self.peers_sent
        } else {
            &self.peers_received
        }
    }

    pub fn get_last_peer_list(&self) -> u64 {
        self.last_peer_list.load(Ordering::Acquire)
    }

    pub fn set_last_peer_list(&self, value: u64) {
        self.last_peer_list.store(value, Ordering::Release)
    }

    pub fn get_last_ping(&self) -> u64 {
        self.last_ping.load(Ordering::Acquire)
    }

    pub fn set_last_ping(&self, value: u64) {
        self.last_ping.store(value, Ordering::Release)
    }

    pub fn get_last_inventory(&self) -> u64 {
        self.last_inventory.load(Ordering::Acquire)
    }

    pub fn set_last_inventory(&self, value: u64) {
        self.last_inventory.store(value, Ordering::Release)
    }

    pub fn has_requested_inventory(&self) -> bool {
        self.requested_inventory.load(Ordering::Acquire)
    }

    pub fn set_requested_inventory(&self, value: bool) {
        self.requested_inventory.store(value, Ordering::Release)
    }

    pub fn get_outgoing_address(&self) -> &SocketAddr {
        &self.outgoing_address
    }

    pub async fn close(&self) -> Result<(), P2pError> {
        trace!("Closing connection with {}", self);
        let mut peer_list = self.peer_list.write().await;
        peer_list.remove_peer(&self).await;
        self.get_connection().close().await?;
        trace!("{} has been disconnected", self);
        Ok(())
    }

    pub async fn send_packet(&self, packet: Packet<'_>) -> Result<(), P2pError> {
        self.send_bytes(Bytes::from(packet.to_bytes())).await
    }

    pub async fn send_bytes(&self, bytes: Bytes) -> Result<(), P2pError> {
        let tx = self.connection.get_tx().lock().await;
        tx.send(ConnectionMessage::Packet(bytes))?;
        Ok(())
    }
}

impl Display for Peer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error> {
        // update fail counter to have up-to-date data to display
        self.update_fail_count_default();
        let peers_count = if let Ok(peers) = self.get_peers(false).try_lock() {
            format!("{}", peers.len())
        } else {
            "Couldn't retrieve data".to_string()
        };

        let top_hash = if let Ok(hash) = self.get_top_block_hash().try_lock() {
            hash.to_string()
        } else {
            "Couldn't retrieve data".to_string()
        };

        let pruned_state = if let Some(value) = self.get_pruned_topoheight() {
            format!("Yes ({})", value)
        } else {
            "No".to_string()
        };

        write!(f, "Peer[connection: {}, id: {}, topoheight: {}, top hash: {}, height: {}, pruned: {}, priority: {}, tag: {}, version: {}, fail count: {}, out: {}, peers: {}]",
            self.get_connection(),
            self.get_id(),
            self.get_topoheight(),
            top_hash,
            self.get_height(),
            pruned_state,
            self.is_priority(),
            self.get_node_tag().as_ref().unwrap_or(&"None".to_owned()),
            self.get_version(),
            self.get_fail_count(),
            self.is_out(),
            peers_count
        )
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if !self.get_connection().is_closed() {
            warn!("{} was not closed correctly /!\\", self)
        }
    }
}