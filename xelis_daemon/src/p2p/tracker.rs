use std::{borrow::Cow, time::{Duration, Instant}, sync::Arc};

use bytes::Bytes;
use indexmap::IndexMap;
use tokio::sync::{mpsc::{UnboundedSender, UnboundedReceiver, Sender, Receiver}, RwLock};
use xelis_common::{crypto::hash::Hash, serializer::Serializer};
use crate::{core::{blockchain::Blockchain, storage::Storage}, config::PEER_TIMEOUT_REQUEST_OBJECT};
use log::{error, debug};

use super::{packet::{object::{ObjectRequest, OwnedObjectResponse}, Packet}, error::P2pError, peer::Peer};

pub type SharedObjectTracker = Arc<ObjectTracker>;

pub type ResponseBlocker = tokio::sync::broadcast::Receiver<()>;

pub struct Listener {
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
            if sender.send(()).is_err() {
                error!("Error while sending notification to ObjectTracker");
            }
        }
    }
}

struct Request {
    request: ObjectRequest,
    sender: Option<tokio::sync::broadcast::Sender<()>>,
    response: Option<OwnedObjectResponse>,
    requested_at: Option<Instant>
}


impl Request {
    pub fn new(request: ObjectRequest) -> Self {
        Self {
            request,
            sender: None,
            response: None,
            requested_at: None
        }
    }

    pub fn get_object(&self) -> &ObjectRequest {
        &self.request
    }

    pub fn set_response(&mut self, response: OwnedObjectResponse) {
        self.response = Some(response);
    }

    pub fn has_response(&self) -> bool {
        self.response.is_some()
    }

    pub fn take_response(&mut self) -> Option<OwnedObjectResponse> {
        self.response.take()
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

    pub fn to_listener(self) -> Listener {
        Listener::new(self.sender)
    }
}

// this ObjectTracker is a unique sender allows to create a queue system in one task only
// currently used to fetch in order all txs propagated by the network
pub struct ObjectTracker {
    request_sender: UnboundedSender<Message>,
    handler_sender: Sender<OwnedObjectResponse>,
    queue: RwLock<IndexMap<Hash, Request>>
}

enum Message {
    Request(Arc<Peer>, Hash),
    Exit
}

impl ObjectTracker {
    pub fn new<S: Storage>(blockchain: Arc<Blockchain<S>>) -> SharedObjectTracker {
        let (request_sender, request_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (handler_sender, handler_receiver) = tokio::sync::mpsc::channel(128);

        let zelf: Arc<ObjectTracker> = Arc::new(Self {
            request_sender,
            handler_sender,
            queue: RwLock::new(IndexMap::new())
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

    pub fn stop(&self) {
        debug!("Stopping ObjectTracker...");
        if self.request_sender.send(Message::Exit).is_err() {
            error!("Error while sending exit message to ObjectTracker");
        }
    }


    async fn handle_object_response_internal<S: Storage>(&self, blockchain: &Arc<Blockchain<S>>, response: OwnedObjectResponse) -> Result<(), P2pError> {
        match response {
            OwnedObjectResponse::Transaction(tx, hash) => {
                blockchain.add_tx_with_hash_to_mempool(tx, hash, true).await?;
            },
            _ => {
                debug!("ObjectTracker received an invalid object response");
            }
        }
        Ok(())
    }

    async fn handler_loop<S: Storage>(&self, blockchain: Arc<Blockchain<S>>, mut handler_receiver: Receiver<OwnedObjectResponse>) {
        debug!("Starting handler loop...");
        while let Some(response) = handler_receiver.recv().await {
            let object = response.get_hash();
            let mut queue = self.queue.write().await;
            if let Some(request) = queue.get_mut(object) {
                request.set_response(response);
            }

            'inner: while !queue.is_empty() {
                let handle = if let Some((_, request)) = queue.get_index(0) {
                    request.has_response()
                } else {
                    false
                };

                if handle {
                    let (_, mut request) = queue.shift_remove_index(0).unwrap();
                    let response = request.take_response().unwrap();
                    if let Err(e) = self.handle_object_response_internal(&blockchain, response).await {
                        error!("Error while handling object response in ObjectTracker: {}", e);
                    }
                    request.to_listener().notify();
                } else {
                    // Maybe it timed out
                    if let Some((_, request)) = queue.get_index(0) {
                        if let Some(requested_at) = request.get_requested() {
                            if requested_at.elapsed() > Duration::from_millis(PEER_TIMEOUT_REQUEST_OBJECT) {
                                let (_, request) = queue.shift_remove_index(0).unwrap();
                                request.to_listener().notify();
                            }
                        }
                    }
                    break 'inner;
                }
            }
        }
    }

    async fn requester_loop(&self, mut request_receiver: UnboundedReceiver<Message>) {
        debug!("Starting requester loop...");
        while let Some(msg) = request_receiver.recv().await {
            match msg {
                Message::Request(peer, object) => {
                    if let Err(e) = self.request_object_from_peer_internal(&peer, &object).await {
                        error!("Error while requesting object {} from {}: {}", object, peer, e);
                    };
                },
                Message::Exit => break
            }
        }
    }

    pub async fn has_requested_object(&self, object_hash: &Hash) -> bool {
        let queue = self.queue.read().await;
        queue.contains_key(object_hash)
    }

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

    pub async fn request_object_from_peer(&self, peer: Arc<Peer>, request: ObjectRequest) -> Result<(), P2pError> {
        let hash = {
            let mut queue = self.queue.write().await;
            let hash = request.get_hash().clone();
            if let Some(old) = queue.insert(hash.clone(), Request::new(request)) {
                return Err(P2pError::ObjectAlreadyRequested(old.request))
            }
            hash
        };

        self.request_sender.send(Message::Request(peer, hash))?;
        Ok(())
    }

    async fn request_object_from_peer_internal(&self, peer: &Peer, request_hash: &Hash) -> Result<(), P2pError> {
        debug!("Requesting object with hash {}", request_hash);
        let mut queue = self.queue.write().await;
        let request = queue.get_mut(request_hash).ok_or_else(|| P2pError::ObjectHashNotPresentInQueue(request_hash.clone()))?;
        request.set_requested();
        let packet = Bytes::from(Packet::ObjectRequest(Cow::Borrowed(request.get_object())).to_bytes());

        // send the packet to the Peer
        peer.send_bytes(packet).await.map_err(|e| {
            if let Some(request) = queue.remove(request_hash) {
                request.to_listener().notify();
            }

            e
        })
    }
}