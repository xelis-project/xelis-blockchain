use std::sync::Arc;
use log::error;
use metrics::counter;
use xelis_common::tokio::sync::mpsc::Receiver;
use crate::{
    core::storage::Storage,
    rpc::{RpcEvent, RpcEventBatch, RpcEventWorker},
};
use super::Blockchain;

impl<S: Storage> Blockchain<S> {
    pub(super) async fn start_rpc_event_worker(self: &Arc<Self>, receiver: Receiver<RpcEvent>) {
        let worker = RpcEventWorker::start(Arc::downgrade(self), receiver);
        *self.rpc_event_worker.lock().await = Some(worker);
    }

    pub(super) fn queue_rpc_events(&self, batch: RpcEventBatch) {
        if !batch.is_empty() {
            // Never wait for subscriber delivery while holding chain state locks.
            if let Err(e) = self.rpc_event_sender.try_send(RpcEvent::Blockchain(batch)) {
                counter!("xelis_blockchain_rpc_event_queue_errors_total").increment(1u64);
                error!("Blockchain RPC event batch skipped because it could not be queued: {}", e);
            }
        }
    }

    pub(super) async fn stop_rpc_event_worker(&self) {
        let worker = { self.rpc_event_worker.lock().await.take() };
        if let Some(worker) = worker {
            worker.stop().await;
        }
    }
}
