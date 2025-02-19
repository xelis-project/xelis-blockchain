use std::{collections::HashMap, sync::atomic::{AtomicU64, Ordering}};

use log::warn;
use tokio::sync::{oneshot, Mutex};

use crate::p2p::error::P2pError;

pub struct GroupManager {
    // This is used to have unique id for each group of requests
    group_id: AtomicU64,
    groups: Mutex<HashMap<u64, oneshot::Sender<P2pError>>>
}

impl GroupManager {
    pub fn new() -> Self {
        Self {
            group_id: AtomicU64::new(0),
            groups: Mutex::new(HashMap::new())
        }
    }

    // Generate a new group id
    pub async fn next_group_id(&self) -> (u64, oneshot::Receiver<P2pError>) {
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

    // Notify the requester about the failure
    pub async fn notify_group(&self, group_id: u64, err: P2pError) {
        let mut groups = self.groups.lock().await;
        if let Some(sender) = groups.remove(&group_id) {
            if sender.send(err).is_err() {
                warn!("Error while sending group error");
            }
        }
    }
}