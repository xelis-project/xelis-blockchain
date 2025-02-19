use std::{sync::Arc, time::Instant};

use tokio::sync::broadcast;
use xelis_common::crypto::Hash;
use log::debug;
use crate::p2p::{packet::object::{ObjectRequest, OwnedObjectResponse}, peer::Peer};
use super::ResponseBlocker;


// Element of the queue for this Object pub Tracker
pub struct Request {
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

    pub fn is_requested(&self) -> bool {
        self.requested_at.is_some()
    }

    pub fn get_hash(&self) -> &Hash {
        self.request.get_hash()
    }

    pub fn listen(&mut self) -> ResponseBlocker {
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
}

impl Drop for Request {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            if sender.send(()).is_err() {
                debug!("Couldn't send notification for {}", self.get_object());
            }
        }
    }
}
