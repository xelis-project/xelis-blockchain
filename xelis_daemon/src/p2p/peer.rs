use crate::{
    config::{
        PEER_FAIL_TIME_RESET, PEER_BLOCK_CACHE_SIZE,
        PEER_TX_CACHE_SIZE, PEER_TIMEOUT_BOOTSTRAP_STEP,
        PEER_TIMEOUT_REQUEST_OBJECT, CHAIN_SYNC_TIMEOUT_SECS,
        PEER_PACKET_CHANNEL_SIZE, PEER_PEERS_CACHE_SIZE
    },
    p2p::packet::PacketWrapper
};
use anyhow::Context;
use xelis_common::{
    api::daemon::{Direction, TimedDirection},
    block::TopoHeight,
    crypto::Hash,
    difficulty::CumulativeDifficulty,
    serializer::Serializer,
    time::{
        get_current_time_in_seconds,
        TimestampSeconds
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
    peer_list::SharedPeerList,
    connection::Connection,
    error::P2pError
};
use std::{
    num::NonZeroUsize,
    borrow::Cow,
    collections::{HashMap, VecDeque},
    fmt::{Display, Error, Formatter},
    hash::{Hash as StdHash, Hasher},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
        Arc
    },
    time::Duration
};
use tokio::{
    select,
    sync::{broadcast, mpsc, oneshot::Sender, Mutex},
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

pub type Tx = mpsc::Sender<Bytes>;
pub type Rx = mpsc::Receiver<Bytes>;

// Enum used to track the state of a task
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TaskState {
    // not started yet
    Inactive,
    // running
    Active,
    // task has been cancelled
    Exiting,
    // Task has exited
    Finished,
    Unknown,
}

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
    peers: Mutex<LruCache<SocketAddr, TimedDirection>>,
    // last time we received a peerlist from this peer
    last_peer_list: AtomicU64,
    // last time we got a ping packet from this peer
    last_ping: AtomicU64,
    // last time we sent a ping packet to this peer
    last_ping_sent: AtomicU64,
    // cumulative difficulty of peer chain
    cumulative_difficulty: Mutex<CumulativeDifficulty>,
    // All transactions propagated from/to this peer
    txs_cache: Mutex<LruCache<Arc<Hash>, (Direction, bool)>>,
    // last blocks propagated to/from this peer
    blocks_propagation: Mutex<LruCache<Hash, (TimedDirection, bool)>>,
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
    // Because we are in a TCP stream, we know that all our
    // requests will be answered in the order we sent them
    // So we can use a queue to store the senders and pop them
    bootstrap_chain: Mutex<VecDeque<Sender<StepResponse>>>,
    // used to wait on chain response when syncing chain
    sync_chain: Mutex<Option<Sender<ChainResponse>>>,
    // IP address with local port
    outgoing_address: SocketAddr,
    // Determine if this peer allows to be shared to others and/or through API
    sharable: bool,
    // Channel to send bytes to the writer task
    tx: Tx,
    // Channel to notify the tasks to exit
    exit_channel: broadcast::Sender<()>,
    // Tracking dedicated tasks
    read_task: Mutex<TaskState>,
    write_task: Mutex<TaskState>,
}

impl Peer {
    pub fn new(connection: Connection, id: u64, node_tag: Option<String>, local_port: u16, version: String, top_hash: Hash, topoheight: TopoHeight, height: u64, pruned_topoheight: Option<TopoHeight>, priority: bool, cumulative_difficulty: CumulativeDifficulty, peer_list: SharedPeerList, sharable: bool) -> (Self, Rx) {
        let mut outgoing_address = *connection.get_address();
        outgoing_address.set_port(local_port);

        let (exit_channel, _) = broadcast::channel(1);
        let (tx, rx) = mpsc::channel(PEER_PACKET_CHANNEL_SIZE);

        (Self {
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
            peers: Mutex::new(LruCache::new(NonZeroUsize::new(PEER_PEERS_CACHE_SIZE).unwrap())),
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
            bootstrap_chain: Mutex::new(VecDeque::new()),
            sync_chain: Mutex::new(None),
            outgoing_address,
            sharable,
            exit_channel,
            tx,
            read_task: Mutex::new(TaskState::Inactive),
            write_task: Mutex::new(TaskState::Inactive),
        }, rx)
    }

    // Subscribe to the exit channel to be notified when peer disconnects
    pub fn get_exit_receiver(&self) -> broadcast::Receiver<()> {
        self.exit_channel.subscribe()
    }

    // Get the IP address of the peer
    pub fn get_ip(&self) -> IpAddr {
        self.connection.get_address().ip()
    }

    // Get all transactions propagated from/to this peer
    pub fn get_txs_cache(&self) -> &Mutex<LruCache<Arc<Hash>, (Direction, bool)>> {
        &self.txs_cache
    }

    // Get all blocks propagated from/to this peer
    pub fn get_blocks_propagation(&self) -> &Mutex<LruCache<Hash, (TimedDirection, bool)>> {
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
    pub fn get_topoheight(&self) -> TopoHeight {
        self.topoheight.load(Ordering::SeqCst)
    }

    // Set the topoheight of the peer
    pub fn set_topoheight(&self, topoheight: TopoHeight) {
        self.topoheight.store(topoheight, Ordering::SeqCst);
    }

    // Get the height of the peer
    pub fn get_height(&self) -> u64 {
        self.height.load(Ordering::SeqCst)
    }

    // Set the height of the peer
    pub fn set_height(&self, height: u64) {
        self.height.store(height, Ordering::SeqCst);
    }

    // Is the peer running a pruned chain
    pub fn is_pruned(&self) -> bool {
        self.is_pruned.load(Ordering::SeqCst)
    }

    // Get the pruned topoheight
    pub fn get_pruned_topoheight(&self) -> Option<TopoHeight> {
        if self.is_pruned() {
            Some(self.pruned_topoheight.load(Ordering::SeqCst))
        } else {
            None
        }
    }

    // Update the pruned topoheight state
    pub fn set_pruned_topoheight(&self, pruned_topoheight: Option<TopoHeight>) {
        if let Some(pruned_topoheight) = pruned_topoheight {
            self.is_pruned.store(true, Ordering::SeqCst);
            self.pruned_topoheight.store(pruned_topoheight, Ordering::SeqCst);
        } else {
            self.is_pruned.store(false, Ordering::SeqCst);
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
        self.last_fail_count.load(Ordering::SeqCst)
    }

    // Set the last fail count of the peer
    pub fn set_last_fail_count(&self, value: u64) {
        self.last_fail_count.store(value, Ordering::SeqCst);
    }

    // Get the fail count of the peer
    pub fn get_fail_count(&self) -> u8 {
        self.fail_count.load(Ordering::SeqCst)
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
            self.fail_count.store(to_store, Ordering::SeqCst);
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
            self.fail_count.fetch_add(1, Ordering::SeqCst);
        }
        self.set_last_fail_count(current_time);
    }

    // Get the last time we got a chain sync request
    // This is used to prevent spamming the chain sync packet
    pub fn get_last_chain_sync(&self) -> TimestampSeconds {
        self.last_chain_sync.load(Ordering::SeqCst)
    }

    // Store the last time we got a chain sync request
    pub fn set_last_chain_sync(&self, time: TimestampSeconds) {
        self.last_chain_sync.store(time, Ordering::SeqCst);
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

        let mut exit_channel = self.get_exit_receiver();
        let object = select! {
            _ = exit_channel.recv() => return Err(P2pError::Disconnected),
            res = timeout(Duration::from_millis(PEER_TIMEOUT_REQUEST_OBJECT), receiver) => match res {
                Ok(res) => res?,
                Err(e) => {
                    warn!("Requested data {} has timed out", request);
                    let mut objects = self.objects_requested.lock().await;
                    // remove it from request list
                    objects.remove(&request);
                    return Err(P2pError::AsyncTimeOut(e));
                }
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
            let mut senders = self.bootstrap_chain.lock().await;
            senders.push_back(sender);
        }

        // send the packet
        self.send_packet(Packet::BootstrapChainRequest(BootstrapChainRequest::new(step))).await?;

        let mut exit_channel = self.get_exit_receiver();
        let response = select! {
            _ = exit_channel.recv() => return Err(P2pError::Disconnected),
            res = timeout(Duration::from_millis(PEER_TIMEOUT_BOOTSTRAP_STEP), receiver) => match res {
                Ok(res) => res?,
                Err(e) => {
                    // Clear the bootstrap chain channel to preserve the order
                    {
                        let mut senders = self.bootstrap_chain.lock().await;
                        senders.pop_front();
                    }

                    debug!("Requested bootstrap chain step {:?} has timed out", step_kind);
                    return Err(P2pError::AsyncTimeOut(e));
                }
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
        let mut exit_channel = self.get_exit_receiver();
        let response = select! {
            _ = exit_channel.recv() => return Err(P2pError::Disconnected),
            res = timeout(Duration::from_secs(CHAIN_SYNC_TIMEOUT_SECS), receiver) => match res {
                Ok(res) => res?,
                Err(e) => {
                    // Clear the sync chain channel
                    let contains = self.sync_chain.lock().await.take().is_some();
                    debug!("Requested sync chain has timed out, contains: {}", contains);
                    return Err(P2pError::AsyncTimeOut(e));
                }
            }
        };

        Ok(response)
    }

    // Get the bootstrap chain channel
    // Like the sync chain channel, but for bootstrap (fast sync) syncing
    pub fn get_bootstrap_chain_channel(&self) -> &Mutex<VecDeque<Sender<StepResponse>>> {
        &self.bootstrap_chain
    }

    // Get the sync chain channel
    // This is used for chain sync requests to be fully awaited
    pub fn get_sync_chain_channel(&self) -> &Mutex<Option<Sender<ChainResponse>>> {
        &self.sync_chain
    }

    // Get all shared peers between this peer and us
    pub fn get_peers(&self) -> &Mutex<LruCache<SocketAddr, TimedDirection>> {
        &self.peers
    }

    // Get the last time we got a peer list
    pub fn get_last_peer_list(&self) -> TimestampSeconds {
        self.last_peer_list.load(Ordering::SeqCst)
    }

    // Track the last time we got a peer list
    // This is used to prevent spamming the peer list
    pub fn set_last_peer_list(&self, value: TimestampSeconds) {
        self.last_peer_list.store(value, Ordering::SeqCst)
    }

    // Get the last time we got a ping packet from this peer
    pub fn get_last_ping(&self) -> TimestampSeconds {
        self.last_ping.load(Ordering::SeqCst)
    }

    // Track the last time we got a ping packet from this peer
    pub fn set_last_ping(&self, value: TimestampSeconds) {
        self.last_ping.store(value, Ordering::SeqCst)
    }

    // Get the last time we sent a ping packet to this peer
    pub fn get_last_ping_sent(&self) -> TimestampSeconds {
        self.last_ping_sent.load(Ordering::SeqCst)
    }

    // Track the last time we sent a ping packet to this peer
    pub fn set_last_ping_sent(&self, value: TimestampSeconds) {
        self.last_ping.store(value, Ordering::SeqCst)
    }

    // Get the last time a inventory has been requested
    pub fn get_last_inventory(&self) -> TimestampSeconds {
        self.last_inventory.load(Ordering::SeqCst)
    }

    // Set the last inventory time
    pub fn set_last_inventory(&self, value: TimestampSeconds) {
        self.last_inventory.store(value, Ordering::SeqCst)
    }

    // Get the requested inventory flag
    pub fn has_requested_inventory(&self) -> bool {
        self.requested_inventory.load(Ordering::SeqCst)
    }

    // Set the requested inventory flag
    pub fn set_requested_inventory(&self, value: bool) {
        self.requested_inventory.store(value, Ordering::SeqCst)
    }

    // Get the outgoing address of the peer
    // This represents the IP address of the peer and the port on which it is listening
    pub fn get_outgoing_address(&self) -> &SocketAddr {
        &self.outgoing_address
    }

    // Close the peer connection and remove it from the peer list
    pub async fn close_and_temp_ban(&self, seconds: u64) -> Result<(), P2pError> {
        trace!("temp ban {}", self);
        if !self.is_priority() {
            self.peer_list.temp_ban_address(&self.get_connection().get_address().ip(), seconds, false).await?;
        } else {
            debug!("{} is a priority peer, closing only", self);
        }

        self.peer_list.remove_peer(self.get_id(), true).await?;
        
        Ok(())
    }

    // Signal the exit of the peer to the tasks
    // This is listened by write task to close the connection
    pub async fn signal_exit(&self) -> Result<(), P2pError> {
        self.exit_channel.send(())
            .map_err(|e| P2pError::SendError(e.to_string()))?;

        Ok(())
    }

    // Close the peer connection and remove it from the peer list
    pub async fn close(&self) -> Result<(), P2pError> {
        trace!("Deleting peer {} from peerlist", self);
        let res = self.peer_list.remove_peer(self.get_id(), true).await;

        trace!("Closing connection internal with {}", self);
        self.get_connection()
            .close()
            .await
            .context("Error while closing internal connection")?;

        res
    }

    // Send a packet to the peer
    // This will transform the packet into bytes and send it to the peer
    pub async fn send_packet(&self, packet: Packet<'_>) -> Result<(), P2pError> {
        trace!("Sending {:?}", packet);
        self.send_bytes(Bytes::from(packet.to_bytes())).await
    }

    // Send packet bytes to the peer
    // This will send the bytes to the writer task through its channel
    pub async fn send_bytes(&self, bytes: Bytes) -> Result<(), P2pError> {
        self.tx.send(bytes).await
            .map_err(|e| P2pError::SendError(e.to_string()))
    }

    pub async fn set_read_task_state(&self, state: TaskState) {
        *self.read_task.lock().await = state;
    }

    pub async fn set_write_task_state(&self, state: TaskState) {
        *self.write_task.lock().await = state;
    }

    pub async fn get_read_task_state(&self) -> TaskState {
        *self.read_task.lock().await
    }

    pub async fn get_write_task_state(&self) -> TaskState {
        *self.write_task.lock().await
    }
}

impl Display for Peer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error> {
        // update fail counter to have up-to-date data to display
        self.update_fail_count_default();
        let peers = if let Ok(peers) = self.get_peers().try_lock() {
            if log_enabled!(Level::Trace) {
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

        let read_task = self.read_task.try_lock().map(|v| *v).unwrap_or(TaskState::Unknown);
        let write_task = self.write_task.try_lock().map(|v| *v).unwrap_or(TaskState::Unknown);

        write!(f, "Peer[connection: {}, id: {}, topoheight: {}, top hash: {}, height: {}, pruned: {}, priority: {}, tag: {}, version: {}, fail count: {}, out: {}, peers: {}, tasks: {:?}/{:?}]",
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
            peers,
            read_task,
            write_task
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