use std::{borrow::Cow, collections::HashMap, time::Duration, sync::Arc};

use bytes::Bytes;
use tokio::{sync::{mpsc::{UnboundedSender, UnboundedReceiver}, RwLock, oneshot}, time::timeout};
use xelis_common::{crypto::hash::Hash, config::PEER_TIMEOUT_REQUEST_OBJECT, serializer::Serializer};
use log::{error, debug};

use super::{packet::{object::{ObjectRequest, OwnedObjectResponse}, Packet}, error::P2pError, peer::Peer};

pub type WaiterResponse = oneshot::Receiver<Result<(OwnedObjectResponse, Listener), P2pError>>;
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
    sender: Option<tokio::sync::broadcast::Sender<()>>
}


impl Request {
    pub fn new(request: ObjectRequest) -> Self {
        Self {
            request,
            sender: None
        }
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
    response_sender: UnboundedSender<Result<(OwnedObjectResponse, Listener), P2pError>>,
    queue: RwLock<HashMap<Hash, Request>>
}

enum Message {
    Request(Arc<Peer>, ObjectRequest, oneshot::Sender<Result<(OwnedObjectResponse, Listener), P2pError>>),
    Exit
}

impl ObjectTracker {
    pub fn new() -> SharedObjectTracker {
        let (request_sender, request_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (response_sender, response_receiver) = tokio::sync::mpsc::unbounded_channel();

        let zelf: Arc<ObjectTracker> = Arc::new(Self {
            request_sender,
            response_sender,
            queue: RwLock::new(HashMap::new())
        });

        { // start the loop
            let zelf = zelf.clone();
            tokio::spawn(async move {
                zelf.requester_loop(request_receiver, response_receiver).await;
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

    async fn requester_loop(&self, mut request_receiver: UnboundedReceiver<Message>, mut response_receiver: UnboundedReceiver<Result<(OwnedObjectResponse, Listener), P2pError>>) {
        debug!("Starting requester loop...");
        while let Some(msg) = request_receiver.recv().await {
            match msg {
                Message::Request(peer, request, sender) => {
                    if let Err(e) = self.request_object_from_peer_internal(&peer, request).await {
                        if sender.send(Err(e)).is_err() {
                            error!("Error while sending error response from ObjectTracker");
                        }
                    } else {
                        let res: Result<(OwnedObjectResponse, Listener), P2pError> = timeout(Duration::from_millis(PEER_TIMEOUT_REQUEST_OBJECT), response_receiver.recv()).await
                            .map_err(|e| P2pError::AsyncTimeOut(e))
                            .and_then(|res| res.ok_or(P2pError::NoResponse))
                            .and_then(|res| res);

                        if sender.send(res).is_err() {
                            error!("Error while sending response from ObjectTracker");
                        }
                    }
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
        let request = {
            let mut queue = self.queue.write().await;
            if let Some(request) = queue.remove(response.get_hash()) {
                request
            } else {
                let request = response.get_request();
                debug!("Object not requested in ObjectTracker: {}", request);
                return Err(P2pError::ObjectNotRequested(request));
            }
        };

        if request.get_hash() != response.get_hash() {
            debug!("Invalid object hash in ObjectTracker: expected {}, got {}", request.get_hash(), response.get_hash());
            return Err(P2pError::InvalidObjectHash(request.get_hash().clone(), response.get_hash().clone()));
        }

        if self.response_sender.send(Ok((response, request.to_listener()))).is_err() {
            error!("Error while sending object response in ObjectTracker");
        }

        Ok(())
    }

    pub fn request_object_from_peer(&self, peer: Arc<Peer>, request: ObjectRequest) -> Result<WaiterResponse, P2pError> {
        let (sender, receiver) = oneshot::channel();
        self.request_sender.send(Message::Request(peer, request, sender))?;
        Ok(receiver)
    }

    pub async fn fetch_object_from_peer(&self, peer: Arc<Peer>, request: ObjectRequest) -> Result<(OwnedObjectResponse, Listener), P2pError> {
        Ok(self.request_object_from_peer(peer, request)?.await??)
    }

    async fn request_object_from_peer_internal(&self, peer: &Peer, request: ObjectRequest) -> Result<(), P2pError> {
        debug!("Requesting {}", request);
        let packet = Bytes::from(Packet::ObjectRequest(Cow::Borrowed(&request)).to_bytes());
        let hash = request.get_hash().clone();
        {
            let mut queue = self.queue.write().await;
            if queue.contains_key(request.get_hash()) {
                return Err(P2pError::ObjectAlreadyRequested(request))
            }

            queue.insert(request.get_hash().clone(), Request::new(request));
        }

        // send the packet to the Peer
        if let Err(e) = peer.send_bytes(packet).await {
            error!("Error while sending object request to peer: {}", e);
            let mut queue = self.queue.write().await;
            queue.remove(&hash);
            return Err(e);
        }

        Ok(())
    }
}