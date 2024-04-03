use crate::{
    config::{
        PEER_FAIL_TIME_RESET, PEER_BLOCK_CACHE_SIZE, PEER_TX_CACHE_SIZE,
        PEER_TEMP_BAN_TIME, PEER_TIMEOUT_BOOTSTRAP_STEP,
        PEER_TIMEOUT_REQUEST_OBJECT, CHAIN_SYNC_TIMEOUT_SECS
    },
    p2p::packet::PacketWrapper
};
use xelis_common::{
    api::daemon::Direction,
    crypto::Hash,
    difficulty::CumulativeDifficulty,
    serializer::Serializer,
    time::{
        TimestampSeconds,
        get_current_time_in_seconds
    }
};
use super::{
    packet::{
        bootstrap_chain::{
            StepRequest,
            BootstrapChainRequest,
            StepResponse
        },
        chain::{
            ChainRequest,
            ChainResponse
        },
        object::{
            ObjectRequest,
            OwnedObjectResponse
        },
        Packet
    },
    peer_list::{PeerList, SharedPeerList},
    connection::Connection,
    error::P2pError
};
use std::{
    num::NonZeroUsize,
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt::{Display, Error, Formatter},
    hash::{Hash as StdHash, Hasher},
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
    time::Duration
};
use tokio::{
    sync::{oneshot::Sender, Mutex},
    time::timeout,
};
use lru::LruCache;
use bytes::Bytes;
use log::{
    Level,
    log_enabled,
    trace,
    debug,
    warn,
};

// A RequestedObjects is a map of all objects requested from a peer
// This is done to be awaitable with a timeout
pub type RequestedObjects = HashMap<ObjectRequest, Sender<OwnedObjectResponse>>;

// A Peer represents a connection to another node in the network
// It is used to propagate and receive blocks / transactions and do chain sync
// It contains all the necessary information to manage the connection and the communication
pub struct Peer {
    // Connection of the peer to manage read/write to TCP Stream
    connection: Connection,
    // unique ID of the peer to recognize him
    id: u64,
    // Node tag if provided
    node_tag: Option<String>,
    // port on which the node is listening on its side
    local_port: u16,
    // daemon version
    version: String,
    // if this node can be trusted (seed node or added manually by user)
    priority: bool,
    // current block top hash for this peer
    top_hash: Mutex<Hash>,
    // current highest topo height for this peer
    topoheight: AtomicU64,
    // current highest block height for this peer
    height: AtomicU64,
    // last time we got a chain request
    last_chain_sync: AtomicU64,
    // last time we got a fail
    last_fail_count: AtomicU64,
    // fail count: if greater than 20, we should close this connection
    fail_count: AtomicU8,
    // shared pointer to the peer list in case of disconnection
    peer_list: SharedPeerList,
    // map of requested objects from this peer
    objects_requested: Mutex<RequestedObjects>,
    // all peers sent/received
    peers: Mutex<HashMap<SocketAddr, Direction>>,
    // last time we received a peerlist from this peer
    last_peer_list: AtomicU64,
    // last time we got a ping packet from this peer
    last_ping: AtomicU64,
    // last time we sent a ping packet to this peer
    last_ping_sent: AtomicU64,
    // cumulative difficulty of peer chain
    cumulative_difficulty: Mutex<CumulativeDifficulty>,
    // All transactions propagated from/to this peer
    txs_cache: Mutex<LruCache<Hash, Direction>>,
    // last blocks propagated to/from this peer
    blocks_propagation: Mutex<LruCache<Hash, Direction>>,
    // last time we got an inventory packet from this peer
    last_inventory: AtomicU64,
    // if we requested this peer to send us an inventory notification
    requested_inventory: AtomicBool,
    // pruned topoheight if its a pruned node
    pruned_topoheight: AtomicU64,
    // Store the pruned state of the peer
    // cannot be set to false if its already to true (protocol rules)
    is_pruned: AtomicBool,
    // used for await on bootstrap chain packets
    bootstrap_chain: Mutex<Option<Sender<StepResponse>>>,
    // used to wait on chain response when syncing chain
    sync_chain: Mutex<Option<Sender<ChainResponse>>>,
    // IP address with local port
    outgoing_address: SocketAddr,
    // Determine if this peer allows to be shared to others and/or through API
    sharable: bool
}

impl Peer {
    pub fn new(connection: Connection, id: u64, node_tag: Option<String>, local_port: u16, version: String, top_hash: Hash, topoheight: u64, height: u64, pruned_topoheight: Option<u64>, priority: bool, cumulative_difficulty: CumulativeDifficulty, peer_list: SharedPeerList, peers_received: HashSet<SocketAddr>, sharable: bool) -> Self {
        let mut outgoing_address = *connection.get_address();
        outgoing_address.set_port(local_port);

        let mut peers = HashMap::new();
        for peer in peers_received {
            peers.insert(peer, Direction::In);
        }

        Self {
            connection,
            id,
            node_tag,
            local_port,
            version,
            top_hash: Mutex::new(top_hash),
            topoheight: AtomicU64::new(topoheight),
            height: AtomicU64::new(height),
            priority,
            last_fail_count: AtomicU64::new(0),
            fail_count: AtomicU8::new(0),
            last_chain_sync: AtomicU64::new(0),
            peer_list,
            objects_requested: Mutex::new(HashMap::new()),
            peers: Mutex::new(peers),
            last_peer_list: AtomicU64::new(0),
            last_ping: AtomicU64::new(0),
            last_ping_sent: AtomicU64::new(0),
            cumulative_difficulty: Mutex::new(cumulative_difficulty),
            txs_cache: Mutex::new(LruCache::new(NonZeroUsize::new(PEER_TX_CACHE_SIZE).unwrap())),
            blocks_propagation: Mutex::new(LruCache::new(NonZeroUsize::new(PEER_BLOCK_CACHE_SIZE).unwrap())),
            last_inventory: AtomicU64::new(0),
            requested_inventory: AtomicBool::new(false),
            pruned_topoheight: AtomicU64::new(pruned_topoheight.unwrap_or(0)),
            is_pruned: AtomicBool::new(pruned_topoheight.is_some()),
            bootstrap_chain: Mutex::new(None),
            sync_chain: Mutex::new(None),
            outgoing_address,
            sharable
        }
    }

    // Get the IP address of the peer
    pub fn get_ip(&self) -> IpAddr {
        self.connection.get_address().ip()
    }

    // Get all transactions propagated from/to this peer
    pub fn get_txs_cache(&self) -> &Mutex<LruCache<Hash, Direction>> {
        &self.txs_cache
    }

    // Get all blocks propagated from/to this peer
    pub fn get_blocks_propagation(&self) -> &Mutex<LruCache<Hash, Direction>> {
        &self.blocks_propagation
    }

    // Get its connection object to manage p2p communication
    pub fn get_connection(&self) -> &Connection {
        &self.connection
    }

    // Get the unique ID of the peer
    pub fn get_id(&self) -> u64 {
        self.id
    }

    // Get the node tag of the peer
    pub fn get_node_tag(&self) -> &Option<String> {
        &self.node_tag
    }

    // Get the local port of the peer
    pub fn get_local_port(&self) -> u16 {
        self.local_port
    }

    // Get the running version reported during handshake
    pub fn get_version(&self) -> &String {
        &self.version
    }

    // Get the topoheight of the peer
    pub fn get_topoheight(&self) -> u64 {
        self.topoheight.load(Ordering::Acquire)
    }

    // Set the topoheight of the peer
    pub fn set_topoheight(&self, topoheight: u64) {
        self.topoheight.store(topoheight, Ordering::Release);
    }

    // Get the height of the peer
    pub fn get_height(&self) -> u64 {
        self.height.load(Ordering::Acquire)
    }

    // Set the height of the peer
    pub fn set_height(&self, height: u64) {
        self.height.store(height, Ordering::Release);
    }

    // Is the peer running a pruned chain
    pub fn is_pruned(&self) -> bool {
        self.is_pruned.load(Ordering::Acquire)
    }

    // Get the pruned topoheight
    pub fn get_pruned_topoheight(&self) -> Option<u64> {
        if self.is_pruned() {
            Some(self.pruned_topoheight.load(Ordering::Acquire))
        } else {
            None
        }
    }

    // Update the pruned topoheight state
    pub fn set_pruned_topoheight(&self, pruned_topoheight: Option<u64>) {
        if let Some(pruned_topoheight) = pruned_topoheight {
            self.is_pruned.store(true, Ordering::Release);
            self.pruned_topoheight.store(pruned_topoheight, Ordering::Release);
        } else {
            self.is_pruned.store(false, Ordering::Release);
        }
    }

    // Store the top block hash 
    pub async fn set_top_block_hash(&self, hash: Hash) {
        *self.top_hash.lock().await = hash
    }

    // Get the top block hash of peer chain
    pub fn get_top_block_hash(&self) -> &Mutex<Hash> {
        &self.top_hash
    }

    // Get the cumulative difficulty
    pub fn get_cumulative_difficulty(&self) -> &Mutex<CumulativeDifficulty> {
        &self.cumulative_difficulty
    }

    // Store the cumulative difficulty
    // This is updated by ping packet
    pub async fn set_cumulative_difficulty(&self, cumulative_difficulty: CumulativeDifficulty) {
        *self.cumulative_difficulty.lock().await = cumulative_difficulty;
    }

    // Verify if its a outgoing connection
    pub fn is_out(&self) -> bool {
        self.connection.is_out()
    }

    // Get the priority flag of the peer
    // If the peer is a seed node or added manually by the user, it should be trusted
    pub fn is_priority(&self) -> bool {
        self.priority
    }

    // Get the sharable flag of the peer
    pub fn sharable(&self) -> bool {
        self.sharable
    }

    // Get the last time we got a fail from the peer
    pub fn get_last_fail_count(&self) -> u64 {
        self.last_fail_count.load(Ordering::Acquire)
    }

    // Set the last fail count of the peer
    pub fn set_last_fail_count(&self, value: u64) {
        self.last_fail_count.store(value, Ordering::Release);
    }

    // Get the fail count of the peer
    pub fn get_fail_count(&self) -> u8 {
        self.fail_count.load(Ordering::Acquire)
    }

    // Update the fail count of the peer
    // This is used by display to have up-to-date data
    // We don't add anything, just reset the counter if its long time we didn't get a fail
    fn update_fail_count_default(&self) -> bool {
        self.update_fail_count(get_current_time_in_seconds(), 0)
    }

    // Update the fail count of the peer
    fn update_fail_count(&self, current_time: u64, to_store: u8) -> bool {
        let last_fail = self.get_last_fail_count();
        let reset = last_fail + PEER_FAIL_TIME_RESET < current_time;
        if reset {
            // reset counter
            self.fail_count.store(to_store, Ordering::Release);
        }
        reset
    }

    // Increment the fail count of the peer
    // This is used to track the number of times we failed to communicate with the peer
    // If the fail count is greater than 20, we should close the connection
    pub fn increment_fail_count(&self) {
        let current_time = get_current_time_in_seconds();
        // if its long time we didn't get a fail, reset the fail count to 1 (because of current fail)
        // otherwise, add 1
        if !self.update_fail_count(current_time, 1) {
            self.fail_count.fetch_add(1, Ordering::Release);
        }
        self.set_last_fail_count(current_time);
    }

    // Get the last time we got a chain sync request
    // This is used to prevent spamming the chain sync packet
    pub fn get_last_chain_sync(&self) -> TimestampSeconds {
        self.last_chain_sync.load(Ordering::Acquire)
    }

    // Store the last time we got a chain sync request
    pub fn set_last_chain_sync(&self, time: TimestampSeconds) {
        self.last_chain_sync.store(time, Ordering::Release);
    }

    // Get all objects requested from this peer
    pub fn get_objects_requested(&self) -> &Mutex<RequestedObjects> {
        &self.objects_requested
    }

    // Verify if this peer requested the object
    pub async fn has_requested_object(&self, request: &ObjectRequest) -> bool {
        let objects = self.objects_requested.lock().await;
        objects.contains_key(&request)
    }

    // Remove a requested object from the requested list
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

        // Verify that the object is the one we requested
        let object_hash = object.get_hash();
        if *object_hash != *request.get_hash() {
            return Err(P2pError::InvalidObjectResponse(object_hash.clone()))
        }

        // Returns error if the object is not found
        if let OwnedObjectResponse::NotFound(request) = &object {
            return Err(P2pError::ObjectNotFound(request.clone()));
        }

        Ok(object)
    }

    // Request a bootstrap chain from this peer and wait on it until we receive it or until timeout
    pub async fn request_boostrap_chain(&self, step: StepRequest<'_>) -> Result<StepResponse, P2pError> {
        debug!("Requesting bootstrap chain step: {:?}", step.kind());
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
                debug!("Requested bootstrap chain step {:?} has timed out", step_kind);
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

    // Request a sync chain from this peer and wait on it until we receive it or until timeout
    pub async fn request_sync_chain(&self, request: PacketWrapper<'_, ChainRequest>) -> Result<ChainResponse, P2pError> {
        debug!("Requesting sync chain");
        let (sender, receiver) = tokio::sync::oneshot::channel();
        {
            let mut sender_lock = self.sync_chain.lock().await;
            *sender_lock = Some(sender);
        }

        trace!("sending chain request packet");
        self.send_packet(Packet::ChainRequest(request)).await?;

        trace!("waiting for chain response");
        let response: ChainResponse = match timeout(Duration::from_secs(CHAIN_SYNC_TIMEOUT_SECS), receiver).await {
            Ok(res) => res?,
            Err(e) => {
                debug!("Requested sync chain step timed out");
                return Err(P2pError::AsyncTimeOut(e));
            }
        };

        Ok(response)
    }

    // Get the bootstrap chain channel
    // Like the sync chain channel, but for bootstrap (fast sync) syncing
    pub fn get_bootstrap_chain_channel(&self) -> &Mutex<Option<Sender<StepResponse>>> {
        &self.bootstrap_chain
    }

    // Get the sync chain channel
    // This is used for chain sync requests to be fully awaited
    pub fn get_sync_chain_channel(&self) -> &Mutex<Option<Sender<ChainResponse>>> {
        &self.sync_chain
    }

    // Get all shared peers between this peer and us
    pub fn get_peers(&self) -> &Mutex<HashMap<SocketAddr, Direction>> {
        &self.peers
    }

    // Get the last time we got a peer list
    pub fn get_last_peer_list(&self) -> TimestampSeconds {
        self.last_peer_list.load(Ordering::Acquire)
    }

    // Track the last time we got a peer list
    // This is used to prevent spamming the peer list
    pub fn set_last_peer_list(&self, value: TimestampSeconds) {
        self.last_peer_list.store(value, Ordering::Release)
    }

    // Get the last time we got a ping packet from this peer
    pub fn get_last_ping(&self) -> TimestampSeconds {
        self.last_ping.load(Ordering::Acquire)
    }

    // Track the last time we got a ping packet from this peer
    pub fn set_last_ping(&self, value: TimestampSeconds) {
        self.last_ping.store(value, Ordering::Release)
    }

    // Get the last time we sent a ping packet to this peer
    pub fn get_last_ping_sent(&self) -> TimestampSeconds {
        self.last_ping_sent.load(Ordering::Acquire)
    }

    // Track the last time we sent a ping packet to this peer
    pub fn set_last_ping_sent(&self, value: TimestampSeconds) {
        self.last_ping.store(value, Ordering::Release)
    }

    // Get the last time a inventory has been requested
    pub fn get_last_inventory(&self) -> TimestampSeconds {
        self.last_inventory.load(Ordering::Acquire)
    }

    // Set the last inventory time
    pub fn set_last_inventory(&self, value: TimestampSeconds) {
        self.last_inventory.store(value, Ordering::Release)
    }

    // Get the requested inventory flag
    pub fn has_requested_inventory(&self) -> bool {
        self.requested_inventory.load(Ordering::Acquire)
    }

    // Set the requested inventory flag
    pub fn set_requested_inventory(&self, value: bool) {
        self.requested_inventory.store(value, Ordering::Release)
    }

    // Get the outgoing address of the peer
    // This represents the IP address of the peer and the port on which it is listening
    pub fn get_outgoing_address(&self) -> &SocketAddr {
        &self.outgoing_address
    }

    // Close the peer connection and remove it from the peer list
    pub async fn close_and_temp_ban(&self) -> Result<(), P2pError> {
        trace!("Tempban {}", self);
        let mut peer_list = self.peer_list.write().await;
        if !self.is_priority() {
            peer_list.temp_ban_address(&self.get_connection().get_address().ip(), PEER_TEMP_BAN_TIME).await;
        } else {
            warn!("{} is a priority peer, closing only", self);
        }
        self.close_with_peerlist(&mut peer_list).await
    }

    // Close peer connection and delete it from the peer list
    pub async fn close_with_peerlist(&self, peer_list: &mut PeerList) -> Result<(), P2pError> {
        trace!("Closing connection with {}", self);
        peer_list.remove_peer(self.get_id()).await?;
        self.get_connection().close().await?;
        trace!("{} has been disconnected", self);
        Ok(())
    }

    // Close the peer connection and remove it from the peer list
    pub async fn close(&self) -> Result<(), P2pError> {
        trace!("Closing connection with {}", self);
        let mut peer_list = self.peer_list.write().await;
        self.close_with_peerlist(&mut peer_list).await
    }

    // Send a packet to the peer
    // This will transform the packet into bytes and send it to the peer
    pub async fn send_packet(&self, packet: Packet<'_>) -> Result<(), P2pError> {
        self.send_bytes(Bytes::from(packet.to_bytes())).await
    }

    // Send packet bytes to the peer
    // This will send the bytes to the writer task through its channel
    pub async fn send_bytes(&self, bytes: Bytes) -> Result<(), P2pError> {
        self.get_connection().send_bytes_to_task(bytes).await
    }
}

impl Display for Peer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error> {
        // update fail counter to have up-to-date data to display
        self.update_fail_count_default();
        let peers = if let Ok(peers) = self.get_peers().try_lock() {
            if log_enabled!(Level::Debug) {
                format!("{:?}", peers)
            } else {
                format!("{}", peers.len())
            }
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
            peers
        )
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        // This shouldn't happen, but in case we have a lurking bug somewhere
        if !self.get_connection().is_closed() {
            warn!("{} was not closed correctly /!\\", self)
        }
    }
}

impl PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        self.get_id() == other.get_id()
    }
}

impl Eq for Peer {}

impl StdHash for Peer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_id().hash(state);
    }
}