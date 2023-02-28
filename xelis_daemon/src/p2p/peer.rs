use xelis_common::config::PEER_FAIL_TIME_RESET;
use xelis_common::globals::get_current_time;
use xelis_common::{
    crypto::hash::Hash,
    config::PEER_TIMEOUT_REQUEST_OBJECT,
    serializer::Serializer
};
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
use log::{warn, trace};

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
    peers: Mutex<HashSet<SocketAddr>>, // all peers from this peer
    last_peer_list_update: AtomicU64, // last time we send our peerlist to this peer
    last_peer_list: AtomicU64, // last time we received a peerlist from this peer
    last_ping: AtomicU64, // last time we got a ping packet from this peer
    cumulative_difficulty: AtomicU64 // cumulative difficulty of peer chain
}

impl Peer {
    pub fn new(connection: Connection, id: u64, node_tag: Option<String>, local_port: u16, version: String, top_hash: Hash, topoheight: u64, height: u64, out: bool, priority: bool, cumulative_difficulty: u64, peer_list: SharedPeerList, peers: HashSet<SocketAddr>) -> Self {
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
            peers: Mutex::new(peers),
            last_peer_list_update: AtomicU64::new(0),
            last_peer_list: AtomicU64::new(0),
            last_ping: AtomicU64::new(0),
            cumulative_difficulty: AtomicU64::new(cumulative_difficulty)
        }
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

    pub fn get_peers(&self) -> &Mutex<HashSet<SocketAddr>> {
        &self.peers
    }

    pub fn get_last_peer_list_update(&self) -> u64 {
        self.last_peer_list_update.load(Ordering::Acquire)
    }

    pub fn set_last_peer_list_update(&self, value: u64) {
        self.last_peer_list_update.store(value, Ordering::Release)
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

    pub async fn close(&self) -> Result<(), P2pError> {
        let mut peer_list = self.peer_list.write().await;
        peer_list.remove_peer(&self);
        self.get_connection().close().await?;
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
        let peers_count = if let Ok(peers) = self.get_peers().try_lock() {
            format!("{}", peers.len())
        } else {
            "Couldn't retrieve data".to_string()
        };

        write!(f, "Peer[connection: {}, id: {}, topoheight: {}, height: {}, priority: {}, tag: {}, version: {}, fail count: {}, out: {}, peers: {}]",
            self.get_connection(),
            self.get_id(),
            self.get_topoheight(),
            self.get_height(),
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