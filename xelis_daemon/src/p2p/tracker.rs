use std::{borrow::Cow, time::{Duration, Instant}, sync::{Arc, atomic::{AtomicU64, Ordering}}};
use bytes::Bytes;
use indexmap::IndexMap;
use tokio::{sync::{mpsc::{Sender, Receiver}, RwLock}, select};
use xelis_common::{crypto::hash::Hash, serializer::Serializer};
use crate::{core::{blockchain::Blockchain, storage::Storage}, config::PEER_TIMEOUT_REQUEST_OBJECT};
use log::{error, debug, trace, warn};
use super::{packet::{object::{ObjectRequest, OwnedObjectResponse}, Packet}, error::P2pError, peer::Peer};

pub type SharedObjectTracker = Arc<ObjectTracker>;
pub type ResponseBlocker = tokio::sync::broadcast::Receiver<()>;

struct Listener {
    sender: Option<tokio::sync::broadcast::Sender<()>>
}

impl Listener {
    pub fn new(sender: Option<tokio::sync::broadcast::Sender<()>>) -> Self {
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

struct Request {
    request: ObjectRequest,
    peer: Arc<Peer>,
    sender: Option<tokio::sync::broadcast::Sender<()>>,
    response: Option<OwnedObjectResponse>,
    requested_at: Option<Instant>,
    group_id: Option<u64>,
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
            let (sender, receiver) = tokio::sync::broadcast::channel(1);
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

// this ObjectTracker is a unique sender allows to create a queue system in one task only
// currently used to fetch in order all txs propagated by the network
pub struct ObjectTracker {
    request_sender: Sender<Message>,
    handler_sender: Sender<OwnedObjectResponse>,
    // queue of requests with preserved order
    queue: RwLock<IndexMap<Hash, Request>>,
    // This is used to have unique id for each group of requests
    group_id: AtomicU64
}

enum Message {
    Request(Hash),
    Exit
}

const CHANNEL_BUFFER: usize = 128;

impl ObjectTracker {
    pub fn new<S: Storage>(blockchain: Arc<Blockchain<S>>) -> SharedObjectTracker {
        let (request_sender, request_receiver) = tokio::sync::mpsc::channel(CHANNEL_BUFFER);
        let (handler_sender, handler_receiver) = tokio::sync::mpsc::channel(CHANNEL_BUFFER);

        let zelf: Arc<ObjectTracker> = Arc::new(Self {
            request_sender,
            handler_sender,
            queue: RwLock::new(IndexMap::new()),
            group_id: AtomicU64::new(0)
        });

        { // start the loop
            let zelf = zelf.clone();
            tokio::spawn(async move {
                zelf.requester_loop(request_receiver).await;
            });
        }

        {
            let zelf = zelf.clone();
            tokio::spawn(async move {
                zelf.handler_loop(blockchain, handler_receiver).await;
            });
        }

        zelf
    }

    pub async fn stop(&self) {
        debug!("Stopping ObjectTracker...");
        if self.request_sender.send(Message::Exit).await.is_err() {
            error!("Error while sending exit message to ObjectTracker");
        }
    }

    pub fn next_group_id(&self) -> u64 {
        self.group_id.fetch_add(1, Ordering::SeqCst)
    }

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
                            if requested_at.elapsed() > Duration::from_secs(PEER_TIMEOUT_REQUEST_OBJECT) {
                                failed_group = request.get_group_id();
                                warn!("Request timed out: {} (group: {:?}", request.get_hash(), failed_group);
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

    async fn requester_loop(&self, mut request_receiver: Receiver<Message>) {
        debug!("Starting requester loop...");
        while let Some(msg) = request_receiver.recv().await {
            match msg {
                Message::Request(object) => {
                    self.request_object_from_peer_internal(&object).await;
                },
                Message::Exit => break
            }
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
        trace!("Requesting object {} from {}", request.get_hash(), peer);
        let hash = {
            let mut queue = self.queue.write().await;
            let hash = request.get_hash().clone();
            let req = Request::new(request, peer, None, broadcast);
            if queue.insert(hash.clone(), req).is_some() {
                debug!("Object already requested in ObjectTracker: {}", hash);
                return Ok(false)
            }
            hash
        };

        trace!("Transfering object request {} to task", hash);
        self.request_sender.send(Message::Request(hash)).await?;
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
        self.request_sender.send(Message::Request(hash)).await?;
        Ok(listener)
    }

    async fn request_object_from_peer_internal(&self, request_hash: &Hash) {
        debug!("Requesting object with hash {}", request_hash);
        let mut delete = false;
        let mut failed_group = None;
        {
            let mut queue = self.queue.write().await;
            if let Some(request) = queue.get_mut(request_hash) {
                request.set_requested();
                let packet = Bytes::from(Packet::ObjectRequest(Cow::Borrowed(request.get_object())).to_bytes());
                // send the packet to the Peer
                if let Err(e) = request.get_peer().send_bytes(packet).await {
                    error!("Error while requesting object {} using Object Tracker: {}", request_hash, e);
                    request.get_peer().increment_fail_count();
                    failed_group = request.get_group_id();
                    delete = true;
                }
            } else {
                // it got aborted
            }
        }

        if delete {
            trace!("Deleting requested object with hash {}", request_hash);
            let mut queue = self.queue.write().await;
            queue.remove(request_hash);

            // Delete all from the same group if one of them failed
            if let Some(group) = failed_group {
                queue.retain(|_, request| {
                    if let Some(request_group) = request.get_group_id() {
                        if request_group == group {
                            return false;
                        }
                    }
                    true
                });
            }
        }
    }
}