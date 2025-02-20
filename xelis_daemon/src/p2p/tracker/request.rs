use std::{sync::Arc, time::Instant};

use tokio::sync::broadcast;
use log::error;
use xelis_common::crypto::Hash;
use crate::p2p::{
    packet::object::{ObjectRequest, OwnedObjectResponse},
    peer::Peer
};

pub type RequestCallback = broadcast::Sender<OwnedObjectResponse>;
pub type RequestResponse = broadcast::Receiver<OwnedObjectResponse>;

// Element of the queue for this Object pub Tracker
pub struct Request {
    // The object requested
    request: ObjectRequest,
    // The peer from which it has to be requested
    peer: Arc<Peer>,
    // Timestamp when it got requested
    requested_at: Option<Instant>,
    // If it linked to a group
    group_id: Option<u64>,
    // Channel used as a callback to give the response
    // If None is sent, it means it got timed out / something went wrong
    callback: RequestCallback
}

impl Request {
    pub fn new(request: ObjectRequest, peer: Arc<Peer>, group_id: Option<u64>) -> (Self, RequestResponse) {
        let (callback, receiver) = broadcast::channel(1);
        (Self {
            request,
            peer,
            requested_at: None,
            group_id,
            callback
        }, receiver)
    }

    pub fn get_object(&self) -> &ObjectRequest {
        &self.request
    }

    pub fn get_peer(&self) -> &Arc<Peer> {
        &self.peer
    }

    pub fn listen(&self) -> RequestResponse {
        self.callback.subscribe()
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

    pub fn notify(self, msg: OwnedObjectResponse) {
        if self.callback.send(msg).is_err() {
            error!("Error while notifying about request {}: channel seems closed", self.request.get_hash());
        }
    }
}