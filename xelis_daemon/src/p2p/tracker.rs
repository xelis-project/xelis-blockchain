use std::{borrow::Cow, collections::HashMap, time::Duration};

use tokio::{sync::{mpsc::{UnboundedSender, UnboundedReceiver}, RwLock, Mutex}, time::timeout};
use xelis_common::{crypto::hash::Hash, config::PEER_TIMEOUT_REQUEST_OBJECT};
use log::{error, debug};

use super::{packet::{object::{ObjectRequest, OwnedObjectResponse}, Packet}, error::P2pError, peer::Peer};

// this sender allows to create a queue system in one task only
// currently used to fetch in order all txs propagated by the network
pub struct ObjectTracker {
    receiver: Mutex<UnboundedReceiver<OwnedObjectResponse>>,
    sender: Mutex<UnboundedSender<OwnedObjectResponse>>,
    queue: RwLock<HashMap<Hash, ObjectRequest>>
}

impl ObjectTracker {
    pub fn new() -> Self {
        let (common_object_sender, common_object_receiver) = tokio::sync::mpsc::unbounded_channel();
        Self {
            receiver: Mutex::new(common_object_receiver),
            sender: Mutex::new(common_object_sender),
            queue: RwLock::new(HashMap::new())
        }
    }

    pub async fn has_requested_object(&self, object_hash: &Hash) -> bool {
        let queue = self.queue.read().await;
        queue.contains_key(object_hash)
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

        let sender = self.sender.lock().await;
        if let Err(e) = sender.send(response) {
            error!("Error while sending object response in ObjectTracker: {}", e);
        }

        Ok(())
    }

    pub async fn request_object_from_peer(&self, peer: &Peer, request: ObjectRequest) -> Result<OwnedObjectResponse, P2pError> {
        debug!("Requesting {} from peer {}", request, peer);
        {
            let mut queue = self.queue.write().await;
            if queue.insert(request.get_hash().clone(), request.clone()).is_some() {
                return Err(P2pError::ObjectAlreadyRequested(request));
            }
        }
        
        // wait for the lock
        let mut receiver = self.receiver.lock().await;
        
        // send the packet to the Peer
        peer.send_packet(Packet::ObjectRequest(Cow::Owned(request))).await?;

        // wait for the response
        timeout(Duration::from_millis(PEER_TIMEOUT_REQUEST_OBJECT), receiver.recv()).await
            .map_err(|e| P2pError::AsyncTimeOut(e))?
            .ok_or(P2pError::NoResponse)
    }
}