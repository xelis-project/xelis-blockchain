use std::sync::Arc;
use log::{error, debug};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use crate::core::{blockchain::Blockchain, storage::Storage};
use super::{peer::Peer, packet::object::{ObjectRequest, OwnedObjectResponse}, tracker::{SharedObjectTracker, WaiterResponse}, error::P2pError};

// TODO optimize to request the data but only handle in good order
// This allow to not wait for the data to be fetched to request the next one
pub struct QueuedFetcher {
    sender: UnboundedSender<WaiterResponse>,
    tracker: SharedObjectTracker
}

impl QueuedFetcher {
    pub fn new<S: Storage>(blockchain: Arc<Blockchain<S>>, tracker: SharedObjectTracker) -> Self {
        let (sender, mut receiver) = unbounded_channel();
        let fetcher = Self {
            sender,
            tracker
        };

        tokio::spawn(async move {
            while let Some(waiter) = receiver.recv().await {
                match waiter.await {
                    Ok(Ok((response, listener))) => {
                        if let OwnedObjectResponse::Transaction(tx, hash) = response {
                            debug!("Adding {} to mempool from queued fetcher", hash);
                            if let Err(e) = blockchain.add_tx_to_mempool(tx, true).await {
                                error!("Error while adding tx {} to mempool: {}", hash, e);
                            }
                        } else {
                            error!("Received non tx object from peer");
                        }
                        listener.notify();
                    },
                    Err(e) => {
                        error!("Error while fetching object from peer: {}", e);
                    },
                    Ok(Err(e)) => error!("Error while fetching object from peer: {}", e)
                };
            }
        });

        fetcher
    }

    pub async fn fetch(&self, peer: Arc<Peer>, request: ObjectRequest) -> Result<(), P2pError> {
        let receiver = self.tracker.request_object_from_peer(peer, request).await?;
        if let Err(e) = self.sender.send(receiver) {
            error!("Error while sending object fetcher response: {}", e);
        }
        Ok(())
    }
}