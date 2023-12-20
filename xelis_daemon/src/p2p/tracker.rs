use std::{borrow::Cow, time::{Duration, Instant}, sync::{Arc, atomic::{AtomicU64, Ordering}}, collections::HashMap};
use bytes::Bytes;
use indexmap::IndexMap;
use tokio::{sync::{mpsc::{Sender, Receiver}, RwLock, oneshot, Mutex, broadcast}, select};
use xelis_common::{crypto::hash::Hash, serializer::Serializer};
use crate::{core::{blockchain::Blockchain, storage::Storage}, config::PEER_TIMEOUT_REQUEST_OBJECT};
use log::{error, debug, trace, warn};
use super::{packet::{object::{ObjectRequest, OwnedObjectResponse}, Packet}, error::P2pError, peer::Peer};

pub type SharedObjectTracker = Arc<ObjectTracker>;
pub type ResponseBlocker = broadcast::Receiver<()>;

// This is used to take out the sender from Request if it exists
struct Listener {
    sender: Option<broadcast::Sender<()>>
}

impl Listener {
    pub fn new(sender: Option<broadcast::Sender<()>>) -> Self {
        Self {
            sender
        }
    }

    pub fn notify(self) {
        if let Some(sender) = self.sender {
            if let Err(e) = sender.send(()) {
                debug!("Error while sending notification: {}", e);
            }
        }
    }
}

// Element of the queue for this Object Tracker
struct Request {
    // The object requested
    request: ObjectRequest,
    // The peer from which it has to be requested
    peer: Arc<Peer>,
    // Channel sender to be notified of success/timeout
    sender: Option<broadcast::Sender<()>>,
    // Response received from the peer
    response: Option<OwnedObjectResponse>,
    // Timestamp when it got requested
    requested_at: Option<Instant>,
    // If it linked to a group
    group_id: Option<u64>,
    // If it has to be broadcast on handling or not
    broadcast: bool
}

impl Request {
    pub fn new(request: ObjectRequest, peer: Arc<Peer>, group_id: Option<u64>, broadcast: bool) -> Self {
        Self {
            request,
            peer,
            sender: None,
            response: None,
            requested_at: None,
            group_id,
            broadcast
        }
    }

    pub fn get_object(&self) -> &ObjectRequest {
        &self.request
    }

    pub fn get_peer(&self) -> &Arc<Peer> {
        &self.peer
    }

    pub fn set_response(&mut self, response: OwnedObjectResponse) {
        self.response = Some(response);
    }

    pub fn take_response(&mut self) -> Option<OwnedObjectResponse> {
        self.response.take()
    }

    pub fn get_group_id(&self) -> Option<u64> {
        self.group_id
    }

    pub fn set_requested(&mut self) {
        self.requested_at = Some(Instant::now());
    }

    pub fn get_requested(&self) -> &Option<Instant> {
        &self.requested_at
    }

    pub fn get_hash(&self) -> &Hash {
        self.request.get_hash()
    }

    pub fn get_response_blocker(&mut self) -> ResponseBlocker {
        if let Some(sender) = &self.sender {
            sender.subscribe()
        } else {
            let (sender, receiver) = broadcast::channel(1);
            self.sender = Some(sender);
            receiver
        }
    }

    pub fn broadcast(&self) -> bool {
        self.broadcast
    }

    fn to_listener(&mut self) -> Listener {
        Listener::new(self.sender.take())
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        self.to_listener().notify();
    }
}

#[derive(Debug)]
pub enum GroupError {
    SendFailure,
    Timeout,
}

// this ObjectTracker is a unique sender allows to create a queue system in one task only
// currently used to fetch in order all txs propagated by the network
pub struct ObjectTracker {
    // This is used to send the request to the requester task loop
    // it is a bounded channel, so if the queue is full, it will block the sender
    request_sender: Sender<Hash>,
    // This is used to send the response to the handler task loop
    handler_sender: Sender<OwnedObjectResponse>,
    // queue of requests with preserved order
    queue: RwLock<IndexMap<Hash, Request>>,
    // This is used to have unique id for each group of requests
    group_id: AtomicU64,
    groups: Mutex<HashMap<u64, oneshot::Sender<GroupError>>>
}

// How many requests can be queued in the channel
const REQUESTER_CHANNEL_BUFFER: usize = 128;
// How many responses can be queued in the channel
// It is set to 1 by default to not be spammed by the peer
const HANDLER_CHANNEL_BUFFER: usize = 1;

impl ObjectTracker {
    pub fn new<S: Storage>(blockchain: Arc<Blockchain<S>>) -> SharedObjectTracker {
        let (request_sender, request_receiver) = tokio::sync::mpsc::channel(REQUESTER_CHANNEL_BUFFER);
        let (handler_sender, handler_receiver) = tokio::sync::mpsc::channel(HANDLER_CHANNEL_BUFFER);

        let zelf: Arc<ObjectTracker> = Arc::new(Self {
            request_sender,
            handler_sender,
            queue: RwLock::new(IndexMap::new()),
            group_id: AtomicU64::new(0),
            groups: Mutex::new(HashMap::new())
        });
        
        // start the requester task loop which send requests to peers
        {
            let zelf = zelf.clone();
            tokio::spawn(async move {
                zelf.requester_loop(request_receiver).await;
            });
        }

        // start the handler task loop which handle the responses based on request queue order
        {
            let zelf = zelf.clone();
            tokio::spawn(async move {
                zelf.handler_loop(blockchain, handler_receiver).await;
            });
        }

        zelf
    }

    // Generate a new group id
    pub async fn next_group_id(&self) -> (u64, oneshot::Receiver<GroupError>) {
        let mut groups = self.groups.lock().await;
        let id = self.group_id.fetch_add(1, Ordering::SeqCst);
        let (sender, receiver) = oneshot::channel();
        groups.insert(id, sender);
        (id, receiver)
    }

    // Unregister an existing group id by removing it
    pub async fn unregister_group(&self, group_id: u64) {
        let mut groups = self.groups.lock().await;
        groups.remove(&group_id);
    }

    // Handle the object response and returns the error if any
    async fn handle_object_response_internal<S: Storage>(&self, blockchain: &Arc<Blockchain<S>>, response: OwnedObjectResponse, broadcast: bool) -> Result<(), P2pError> {
        match response {
            OwnedObjectResponse::Transaction(tx, hash) => {
                blockchain.add_tx_to_mempool_with_hash(tx, hash, broadcast).await?;
            },
            OwnedObjectResponse::Block(block, _) => {
                blockchain.add_new_block(block, false, false).await?;
            }
            _ => {
                warn!("ObjectTracker received an invalid object response");
            }
        }
        Ok(())
    }

    // Task loop to handle all responses in order
    async fn handler_loop<S: Storage>(&self, blockchain: Arc<Blockchain<S>>, mut handler_receiver: Receiver<OwnedObjectResponse>) {
        debug!("Starting handler loop...");
        // Interval timer is necessary in case we don't receive any response from peer but we don't want to block the queue
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            select! {
                biased;
                response = handler_receiver.recv() => {
                    if let Some(response) = response {
                        trace!("Received object response: {}", response.get_hash());
                        let object = response.get_hash();
                        let mut queue = self.queue.write().await;
                        if let Some(request) = queue.get_mut(object) {
                            request.set_response(response);
                        }
                    } else {
                        // channel closed
                        break;
                    }
                },
                _ = interval.tick() => {
                    // Check if we have timed out requests
                    trace!("Checking for timed out requests...");
                }
            }
    
            // Loop through the queue in a ordered way to handle correctly the responses
            // For this, we need to check if the first element has a response and so on
            // If we don't have a response during too much time, we remove the request from the queue as it is probably timed out
            let mut queue = self.queue.write().await;
            let mut failed_group: Option<u64> = None;
            while let Some((_, request)) = queue.get_index_mut(0) {
                // Delete all from the same group if one of them failed
                if let (Some(request_group), Some(group)) = (request.get_group_id(), &failed_group) {
                    if request_group == *group {
                        queue.shift_remove_index(0).unwrap();
                        continue;
                    }
                }

                match request.take_response() {
                    Some(response) => {
                        let (_, request) = queue.shift_remove_index(0).unwrap();
                        if let Err(e) = self.handle_object_response_internal(&blockchain, response, request.broadcast()).await {
                            error!("Error while handling object response for {} in ObjectTracker from {}: {}", request.get_hash(), request.get_peer(), e);
                        }
                    },
                    None => {
                        if let Some(requested_at) = request.get_requested() {
                            // check if the request is timed out
                            if requested_at.elapsed() > Duration::from_millis(PEER_TIMEOUT_REQUEST_OBJECT) || request.get_peer().get_connection().is_closed() {
                                failed_group = request.get_group_id();
                                warn!("Request timed out: {} (group: {:?})", request.get_hash(), failed_group);
                                {
                                    let mut groups = self.groups.lock().await;
                                    if let Some(group) = request.get_group_id() {
                                        if let Some(sender) = groups.remove(&group) {
                                            if sender.send(GroupError::Timeout).is_err() {
                                                warn!("Error while sending group error");
                                            }
                                        }
                                    }
                                }
                                queue.shift_remove_index(0).unwrap();
                            } else {
                                // Give a chance to get the response on above loop
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn requester_loop(&self, mut request_receiver: Receiver<Hash>) {
        debug!("Starting requester loop...");
        while let Some(hash) = request_receiver.recv().await {
            self.request_object_from_peer_internal(hash).await
        }
    }

    // Check if the object is already requested
    pub async fn has_requested_object(&self, object_hash: &Hash) -> bool {
        let queue = self.queue.read().await;
        queue.contains_key(object_hash)
    }

    // Get the response blocker for the requested object
    pub async fn get_response_blocker_for_requested_object(&self, object_hash: &Hash) -> Option<ResponseBlocker> {
        let mut queue = self.queue.write().await;
        let request = queue.get_mut(object_hash)?;
        Some(request.get_response_blocker())
    }

    // This function is called from P2p Server when a peer sends an object response that we requested
    // It will pass the response to the handler task loop
    pub async fn handle_object_response(&self, response: OwnedObjectResponse) -> Result<(), P2pError> {
        {
            let queue = self.queue.read().await;
            if let Some(request) = queue.get(response.get_hash()) {
                if request.get_hash() != response.get_hash() {
                    debug!("Invalid object hash in ObjectTracker: expected {}, got {}", request.get_hash(), response.get_hash());
                    return Err(P2pError::InvalidObjectHash(request.get_hash().clone(), response.get_hash().clone()));
                }
            } else {
                let request = response.get_request();
                debug!("Object not requested in ObjectTracker: {}", request);
                return Err(P2pError::ObjectNotRequested(request));
            }
        }

        if self.handler_sender.send(response).await.is_err() {
            error!("Error while sending object response in ObjectTracker");
        }

        Ok(())
    }

    // Request the object from the peer or return false if it is already requested
    pub async fn request_object_from_peer(&self, peer: Arc<Peer>, request: ObjectRequest, broadcast: bool) -> Result<bool, P2pError> {
        self.request_object_from_peer_with(peer, request, None, false, broadcast).await?;
        Ok(true)
    }

    // Request the object from the peer and returns the response blocker
    pub async fn request_object_from_peer_with(&self, peer: Arc<Peer>, request: ObjectRequest, group_id: Option<u64>, blocker: bool, broadcast: bool) -> Result<Option<ResponseBlocker>, P2pError> {
        trace!("Requesting object {} from {}", request.get_hash(), peer);
        let (listener, hash) = {
            let mut queue = self.queue.write().await;
            let hash = request.get_hash().clone();
            let mut req = Request::new(request, peer, group_id, broadcast);
            
            let listener = if blocker {
                Some(req.get_response_blocker())
            } else {
                None
            };

            if queue.insert(hash.clone(), req).is_some() {
                debug!("Object already requested in ObjectTracker: {}", hash);
                return Ok(None)
            }
            (listener, hash)
        };

        trace!("Transfering object request {} to task", hash);
        self.request_sender.send(hash).await?;
        Ok(listener)
    }

    // Request the object from the peer
    // This is called from the requester task loop
    async fn request_object_from_peer_internal(&self, request_hash: Hash) {
        debug!("Requesting object with hash {}", request_hash);
        let mut failed_peer = None;
        let mut failed_group = None;
        {
            let mut queue = self.queue.write().await;
            if let Some(request) = queue.get_mut(&request_hash) {
                request.set_requested();
                let packet = Bytes::from(Packet::ObjectRequest(Cow::Borrowed(request.get_object())).to_bytes());
                // send the packet to the Peer
                if let Err(e) = request.get_peer().send_bytes(packet).await {
                    debug!("Error while requesting object {} using Object Tracker: {}", request_hash, e);
                    request.get_peer().increment_fail_count();
                    failed_group = request.get_group_id();
                    failed_peer = Some(request.get_peer().clone());
                }
            } else {
                trace!("Object {} not requested anymore", request_hash);
            }

            if let Some(peer) = failed_peer {
                trace!("Deleting requested object with hash {} from {}", request_hash, peer);
                queue.remove(&request_hash);

                // Delete all from the same group if one of them failed
                if let Some(group) = failed_group {
                    debug!("Group {} failed", group);
                    queue.retain(|_, request| {
                        if request.get_peer().get_id() == peer.get_id() || request.get_peer().get_connection().is_closed() {
                            return false;
                        }

                        if let Some(request_group) = request.get_group_id() {
                            if request_group == group {
                                return false;
                            }
                        }
                        true
                    });

                    let mut groups = self.groups.lock().await;
                    if let Some(sender) = groups.remove(&group) {
                        if sender.send(GroupError::SendFailure).is_err() {
                            warn!("Error while sending group result");
                        }
                    }
                }
            }
        }
    }
}