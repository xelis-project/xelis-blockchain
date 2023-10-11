use std::sync::Arc;
use log::{error, debug};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use crate::core::{blockchain::Blockchain, storage::Storage};
use super::{peer::Peer, packet::object::{ObjectRequest, OwnedObjectResponse}, tracker::SharedObjectTracker};

// TODO optimize to request the data but only handle in good order
// This allow to have a special queue for this and to not block/flood the other queue
pub struct QueuedFetcher {
    sender: UnboundedSender<(Arc<Peer>, ObjectRequest)>
}

impl QueuedFetcher {
    pub fn new<S: Storage>(blockchain: Arc<Blockchain<S>>, tracker: SharedObjectTracker) -> Self {
        let (sender, mut receiver) = unbounded_channel();
        let fetcher = Self {
            sender
        };

        tokio::spawn(async move {
            while let Some((peer, request)) = receiver.recv().await {
                match tracker.fetch_object_from_peer(peer.clone(), request).await {
                    Ok((response, listener)) => {
                        if let OwnedObjectResponse::Transaction(tx, hash) = response {
                            debug!("Adding {} to mempool from {}", hash, peer);
                            if let Err(e) = blockchain.add_tx_to_mempool(tx, true).await {
                                error!("Error while adding tx {} to mempool: {}", hash, e);
                                peer.increment_fail_count();
                            }
                        } else {
                            error!("Received non tx object from peer");
                            peer.increment_fail_count();
                        }
                        listener.notify();
                    },
                    Err(e) => {
                        error!("Error while fetching object from peer: {}", e);
                    }
                };
            }
        });

        fetcher
    }

    pub fn fetch(&self, peer: Arc<Peer>, request: ObjectRequest) {
        if let Err(e) = self.sender.send((peer, request)) {
            error!("Error while sending get_data to fetcher: {}", e);
        }
    }
}