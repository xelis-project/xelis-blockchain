mod request;
mod group;

use std::{
    borrow::Cow,
    time::{Duration, Instant},
    sync::Arc,
    collections::HashMap
};
use tokio::{
    sync::{
        mpsc::{Sender, Receiver, self},
        RwLock,
        Mutex,
        broadcast
    },
    select,
    time::interval
};
use log::{
    trace,
    debug,
    warn,
};
use xelis_common::{
    crypto::Hash,
    queue::Queue,
    tokio::spawn_task
};
use super::{
    packet::{
        object::{
            ObjectRequest,
            OwnedObjectResponse
        },
        Packet
    },
    error::P2pError,
    peer::Peer
};
use crate::config::PEER_TIMEOUT_REQUEST_OBJECT;
use request::*;
use group::*;

pub type SharedObjectTracker = Arc<ObjectTracker>;
pub type ResponseBlocker = broadcast::Receiver<()>;

struct ExpirableCache {
    cache: Mutex<HashMap<Hash, Instant>>
}

impl ExpirableCache {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new())
        }
    }

    pub async fn insert(&self, hash: Hash) {
        let mut cache = self.cache.lock().await;
        cache.insert(hash, Instant::now());
    }

    pub async fn remove(&self, hash: &Hash) -> bool {
        let mut cache = self.cache.lock().await;
        cache.remove(hash).is_some()
    }

    pub async fn clean(&self, timeout: Duration) {
        let mut cache = self.cache.lock().await;
        cache.retain(|_, v| {
            v.elapsed() < timeout
        });
    }
}

// this ObjectTracker is a unique sender that allows to create a queue system in one task only
// currently used to fetch in order all txs propagated by the network
pub struct ObjectTracker {
    // This is used to send the request to the requester task loop
    // it is a bounded channel, so if the queue is full, it will block the sender
    request_sender: Sender<Hash>,
    // queue of requests with preserved order
    queue: RwLock<Queue<Hash, Request>>,
    // Group Manager for batched requests
    // If one fail, all the group is removed
    group: GroupManager,
    // Requests that should be ignored
    // They got canceled but already requested
    cache: ExpirableCache
}

// How many requests can be queued in the channel
const REQUESTER_CHANNEL_BUFFER: usize = 8;
// How many responses can be queued in the channel
// It is set to 1 by default to not be spammed by the peer
const HANDLER_CHANNEL_BUFFER: usize = 16;

// Duration constant for timeout instead of building it at each iteration
const TIME_OUT: Duration = Duration::from_millis(PEER_TIMEOUT_REQUEST_OBJECT);

impl ObjectTracker {
    pub fn new(server_exit: broadcast::Receiver<()>) -> SharedObjectTracker {
        let (request_sender, request_receiver) = mpsc::channel(REQUESTER_CHANNEL_BUFFER);

        let zelf: Arc<ObjectTracker> = Arc::new(Self {
            request_sender,
            queue: RwLock::new(Queue::new()),
            group: GroupManager::new(),
            cache: ExpirableCache::new()
        });

        // start the requester task loop which send requests to peers
        {
            let server_exit = server_exit.resubscribe();
            let zelf = zelf.clone();
            spawn_task("p2p-tracker-requester", async move {
                zelf.requester_loop(request_receiver, server_exit).await;
            });
        }

        // start the handler task loop which handle the responses based on request queue order
        {
            let server_exit = server_exit.resubscribe();
            let zelf = zelf.clone();
            spawn_task("p2p-tracker-handler", async move {
                zelf.handler_loop(server_exit).await;
            });
        }

        {
            let zelf = zelf.clone();
            spawn_task("p2p-tracker-clean", async move {
                zelf.task_clean_cache(server_exit).await;
            });
        }

        zelf
    }

    // Task to clean the expired cache
    async fn task_clean_cache(&self, mut on_exit: broadcast::Receiver<()>) {
        let mut interval = interval(Duration::from_secs(5));
        loop {
            select! {
                biased;
                _ = on_exit.recv() => {
                    break;
                },
                _ = interval.tick() => {
                    self.cache.clean(TIME_OUT).await;
                }
            }
        }
    }

    // Returns the group manager used
    pub fn get_group_manager(&self) -> &GroupManager {
        &self.group
    }

    // Task loop to handle all responses in order
    async fn handler_loop(&self, mut server_exit: broadcast::Receiver<()>) {
        debug!("Starting handler loop...");
        // Interval timer is necessary in case we don't receive any response from peer but we don't want to block the queue
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            select! {
                biased;
                _ = server_exit.recv() => {
                    debug!("Exiting handler task due to server exit");
                    break;
                },
                _ = interval.tick() => {
                    // Check if we have timed out requests
                    trace!("Checking for timed out requests...");

                    // Loop through the queue in a ordered way to handle correctly the responses
                    // For this, we need to check if the first element has a response and so on
                    // If we don't have a response during too much time, we remove the request from the queue as it is probably timed out
                    let mut queue = self.queue.write().await;
                    while let Some((_, request)) = queue.peek_mut() {
                        if let Some(requested_at) = request.get_requested() {
                            // check if the request is timed out
                            if requested_at.elapsed() > TIME_OUT {
                                warn!("Request timed out for object {}", request.get_hash());
                                let peer_id = request.get_peer().get_id();
                                let group_id = request.get_group_id()
                                    .map(|v| (v, P2pError::TrackerRequestExpired));

                                self.clean_queue(&mut queue, peer_id, group_id).await;
                            } else {
                                break;
                            }
                        } else {
                            // It wasn't yet requested
                            debug!("Request not yet sent for object {}", request.get_hash());
                            break;
                        }
                    }
                }
            }
        }

        debug!("Clearing tracker queue");
        let mut queue = self.queue.write().await;
        queue.clear();
    }

    // Task loop to request all objects in order
    async fn requester_loop(&self, mut request_receiver: Receiver<Hash>, mut server_exit: broadcast::Receiver<()>) {
        debug!("Starting requester loop...");
        loop {
            select! {
                biased;
                _ = server_exit.recv() => {
                    debug!("Exiting requester task due to server exit");
                    break;
                },
                hash = request_receiver.recv() => {
                    if let Some(hash) = hash {
                        self.request_object_from_peer_internal(hash).await;
                    } else {
                        warn!("Request channel seems to be closed, exiting requester task");
                        // channel closed
                        break;
                    }
                }
            }
        }
    }

    // This function is called from P2p Server when a peer sends an object response that we requested
    // It will pass the response to the handler task loop
    pub async fn handle_object_response(&self, response: OwnedObjectResponse) -> Result<bool, P2pError> {
        trace!("handle object response {}", response.get_hash());
        {
            let mut queue = self.queue.write().await;
            if let Some((_, request)) = queue.remove(response.get_hash()) {
                request.notify(response);
                return Ok(true)
            }
        }

        if self.cache.remove(response.get_hash()).await {
            return Ok(true)
        }

        Ok(false)
    }

    // Request the object from the peer or return false if it is already requested
    pub async fn request_object_from_peer(&self, peer: Arc<Peer>, request: ObjectRequest) -> Result<bool, P2pError> {
        self.request_object_from_peer_with(peer, request, None).await?;
        Ok(true)
    }

    // Request the object from the peer and returns the response blocker
    pub async fn request_object_from_peer_with(&self, peer: Arc<Peer>, request: ObjectRequest, group_id: Option<u64>) -> Result<RequestResponse, P2pError> {
        trace!("Requesting object {} from {}", request.get_hash(), peer);
        let (listener, hash) = {
            let mut queue = self.queue.write().await;
            let hash = request.get_hash().clone();
            let (req, receiver) = Request::new(request, peer, group_id);

            if !queue.push(hash.clone(), req) {
                debug!("Object already requested in ObjectTracker: {}", hash);
                // TODO
            }

            (receiver, hash)
        };

        trace!("Transfering object request {} to task", hash);
        self.request_sender.send(hash).await?;
        Ok(listener)
    }

    // Clean the queue from all requests from the given peer or from the group if it is specified
    async fn clean_queue(&self, queue: &mut Queue<Hash, Request>, peer_id: u64, group: Option<(u64, P2pError)>) {
        let iter = queue.extract_if(|(_, request)| {
            if let (Some((failed_group, _)), Some(request_group)) = (group.as_ref(), request.get_group_id()) {
                if *failed_group == request_group {
                    return true;
                }
            }

            let peer = request.get_peer();
            if peer.get_id() == peer_id || peer.get_connection().is_closed() {
                return true;
            }

            if let Some(requested_at) = request.get_requested() {
                if requested_at.elapsed() > TIME_OUT {
                    return true;
                }
            }

            false
        }).filter_map(|(hash, request)| {
            if request.is_requested() {
                Some(Arc::try_unwrap(hash).unwrap())
            } else {
                None
            }
        });

        for hash in iter {
            debug!("Adding requested object with hash {} in expirable cache", hash);
            self.cache.insert(hash).await;
        }

        // Delete all from the same group if one of them failed
        if let Some((group, err)) = group {
            debug!("Group {} failed", group);
            self.group.notify_group(group, err).await;
        }
    }

    // Request the object from the peer
    // This is called from the requester task loop
    async fn request_object_from_peer_internal(&self, request_hash: Hash) {
        debug!("Requesting object with hash {}", request_hash);
        let mut queue = self.queue.write().await;

        let fail = if let Some(request) = queue.get_mut(&request_hash) {
            request.set_requested();
            // send the packet to the Peer
            let peer = request.get_peer();
            if peer.get_connection().is_closed() {
                warn!("Peer {} is disconnected but still has a pending request object {}", peer, request_hash);
                Some((peer.get_id(), request.get_group_id().map(|v| (v, P2pError::Disconnected))))
            } else if let Err(e) = peer.send_packet(Packet::ObjectRequest(Cow::Borrowed(request.get_object()))).await {
                warn!("Error while requesting object {} using Object Tracker: {}", request_hash, e);
                Some((peer.get_id(), request.get_group_id().map(|v| (v, e))))
            } else {
                None
            }
        } else {
            trace!("Object {} not requested anymore", request_hash);
            None
        };

        if let Some((peer_id, group)) = fail {
            warn!("cleaning queue because of failure");
            self.clean_queue(&mut queue, peer_id, group).await;
        }
    }
}