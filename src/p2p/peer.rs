use crate::config::PEER_TIMEOUT_REQUEST_OBJECT;
use crate::core::serializer::Serializer;
use crate::crypto::hash::Hash;
use super::packet::object::{ObjectRequest, OwnedObjectResponse};
use super::packet::ping::Ping;
use super::peer_list::SharedPeerList;
use super::connection::{Connection, ConnectionMessage};
use super::packet::{Packet, PacketWrapper};
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

pub type RequestedObjects = HashMap<ObjectRequest, Sender<OwnedObjectResponse>>;

pub struct Peer {
    connection: Connection,
    id: u64,
    node_tag: Option<String>, // Node tag if provided
    local_port: u16,
    version: String, // daemon version
    out: bool, // True mean we are the client
    priority: bool, // if this node can be trusted (seed node or added manually by user)
    block_top_hash: Mutex<Hash>, // current block top hash for this peer
    block_topoheight: AtomicU64, // current block height for this peer
    last_chain_sync: AtomicU64,
    // TODO last_fail_count
    fail_count: AtomicU8, // fail count: if greater than 20, we should close this connection
    peer_list: SharedPeerList,
    chain_requested: AtomicBool,
    objects_requested: Mutex<RequestedObjects>,
    peers: Mutex<HashSet<SocketAddr>>, // all peers from this peer
    last_peer_list_update: AtomicU64, // last time we send our peerlist to this peer
    last_peer_list: AtomicU64, // last time we received a peerlist from this peer
    last_ping: AtomicU64 // last time we got a ping packet from this peer
}

impl Peer {
    pub fn new(connection: Connection, id: u64, node_tag: Option<String>, local_port: u16, version: String, block_top_hash: Hash, block_topoheight: u64, out: bool, priority: bool, peer_list: SharedPeerList, peers: HashSet<SocketAddr>) -> Self {
        Self {
            connection,
            id,
            node_tag,
            local_port,
            version,
            block_top_hash: Mutex::new(block_top_hash),
            block_topoheight: AtomicU64::new(block_topoheight),
            out,
            priority,
            fail_count: AtomicU8::new(0),
            last_chain_sync: AtomicU64::new(0),
            peer_list,
            chain_requested: AtomicBool::new(false),
            objects_requested: Mutex::new(HashMap::new()),
            peers: Mutex::new(peers),
            last_peer_list_update: AtomicU64::new(0),
            last_peer_list: AtomicU64::new(0),
            last_ping: AtomicU64::new(0)
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

    pub fn get_block_topoheight(&self) -> u64 {
        self.block_topoheight.load(Ordering::Relaxed)
    }

    pub fn set_block_topoheight(&self, topoheight: u64) {
        self.block_topoheight.store(topoheight, Ordering::Relaxed);
    }

    pub async fn set_block_top_hash(&self, hash: Hash) {
        *self.block_top_hash.lock().await = hash
    }

    pub fn get_top_block_hash(&self) -> &Mutex<Hash> {
        &self.block_top_hash
    }

    pub fn is_out(&self) -> bool {
        self.out
    }

    pub fn is_priority(&self) -> bool {
        self.priority
    }

    pub fn get_fail_count(&self) -> u8 {
        self.fail_count.load(Ordering::Relaxed)
    }

    // TODO verify last fail count
    pub fn increment_fail_count(&self) {
        self.fail_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_last_chain_sync(&self) -> u64 {
        self.last_chain_sync.load(Ordering::Relaxed)
    }

    pub fn set_last_chain_sync(&self, time: u64) {
        self.last_chain_sync.store(time, Ordering::Relaxed);
    }

    pub fn chain_sync_requested(&self) -> bool {
        self.chain_requested.load(Ordering::Relaxed)
    }

    pub fn set_chain_sync_requested(&self, value: bool) {
        self.chain_requested.store(value, Ordering::Relaxed);
    }

    pub fn get_objects_requested(&self) -> &Mutex<RequestedObjects> {
        &self.objects_requested
    }

    pub async fn remove_object_request(&self, request: ObjectRequest) -> Result<Sender<OwnedObjectResponse>, P2pError> {
        let mut objects = self.objects_requested.lock().await;
        objects.remove(&request).ok_or(P2pError::ObjectNotFound(request))
    }

    // Request a object from this peer and wait on it until we receive it or until timeout 
    pub async fn request_blocking_object(&self, request: ObjectRequest, ping: &Ping<'_>) -> Result<OwnedObjectResponse, P2pError> {
        let receiver = {
            let mut objects = self.objects_requested.lock().await;
            if objects.contains_key(&request) {
                return Err(P2pError::ObjectAlreadyRequested(request));
            }
            self.send_packet(Packet::ObjectRequest(PacketWrapper::new(Cow::Borrowed(&request), Cow::Borrowed(ping)))).await?;
            let (sender, receiver) = tokio::sync::oneshot::channel();
            objects.insert(request.clone(), sender); // clone is necessary in case timeout has occured
            receiver
        };
        let object = match timeout(Duration::from_millis(PEER_TIMEOUT_REQUEST_OBJECT), receiver).await {
            Ok(res) => res?,
            Err(e) => {
                let mut objects = self.objects_requested.lock().await;
                objects.remove(&request); // remove it from request list
                return Err(P2pError::AsyncTimeOut(e));
            }
        };
        let object_hash = object.get_hash();
        if object_hash != *request.get_hash() {
            return Err(P2pError::InvalidObjectResponse(object_hash))
        }

        Ok(object)
    }

    pub fn get_peers(&self) -> &Mutex<HashSet<SocketAddr>> {
        &self.peers
    }

    pub fn get_last_peer_list_update(&self) -> u64 {
        self.last_peer_list_update.load(Ordering::Relaxed)
    }

    pub fn set_last_peer_list_update(&self, value: u64) {
        self.last_peer_list_update.store(value, Ordering::Relaxed)
    }

    pub fn get_last_peer_list(&self) -> u64 {
        self.last_peer_list.load(Ordering::Relaxed)
    }

    pub fn set_last_peer_list(&self, value: u64) {
        self.last_peer_list.store(value, Ordering::Relaxed)
    }

    pub fn get_last_ping(&self) -> u64 {
        self.last_ping.load(Ordering::Relaxed)
    }

    pub fn set_last_ping(&self, value: u64) {
        self.last_ping.store(value, Ordering::Relaxed)
    }

    pub async fn close(&self) -> Result<(), P2pError> {
        self.peer_list.lock().await.remove_peer(&self);
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
        write!(f, "Peer[connection: {}, id: {}, topoheight: {}, priority: {}, tag: {}, version: {}, out: {}]",
            self.get_connection(),
            self.get_id(),
            self.get_block_topoheight(),
            self.is_priority(),
            self.get_node_tag().as_ref().unwrap_or(&"None".to_owned()),
            self.get_version(),
            self.is_out()
        )
    }
}