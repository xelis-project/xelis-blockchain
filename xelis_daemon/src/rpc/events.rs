use std::{sync::Weak, time::Instant};
use indexmap::IndexMap;
use log::{debug, error};
use metrics::histogram;
use serde_json::Value;
use xelis_common::{
    api::daemon::NotifyEvent,
    tokio::{
        select,
        spawn_task,
        sync::{
            mpsc::Receiver,
            oneshot::{self, Receiver as ExitReceiver, Sender as ExitSender},
        },
        task::JoinHandle,
    },
};
use crate::{
    core::{blockchain::Blockchain, storage::Storage},
    p2p::PeerEvent,
};

pub const RPC_EVENT_CHANNEL_CAPACITY: usize = 64;

pub enum RpcEvent {
    Blockchain(RpcEventBatch),
    Peer(PeerEvent),
}

// Chain values are owned snapshots; peer payloads are built by the worker.
pub struct RpcEventBatch {
    events: IndexMap<NotifyEvent, Vec<Value>>,
    block: bool,
}

impl RpcEventBatch {
    pub fn block(events: IndexMap<NotifyEvent, Vec<Value>>) -> Self {
        Self { events, block: true }
    }

    pub fn single(event: NotifyEvent, value: Value) -> Self {
        let mut events = IndexMap::new();
        events.insert(event, vec![value]);
        Self { events, block: false }
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

pub struct RpcEventWorker {
    exit: ExitSender<()>,
    task: JoinHandle<()>,
}

impl RpcEventWorker {
    pub fn start<S: Storage>(blockchain: Weak<Blockchain<S>>, receiver: Receiver<RpcEvent>) -> Self {
        let (exit, exit_receiver) = oneshot::channel();
        let task = spawn_task("rpc-events", rpc_event_loop(blockchain, receiver, exit_receiver));
        Self { exit, task }
    }

    pub async fn stop(self) {
        let _ = self.exit.send(());
        if let Err(e) = self.task.await {
            error!("Error while stopping RPC event worker: {}", e);
        }
    }
}

async fn rpc_event_loop<S: Storage>(blockchain: Weak<Blockchain<S>>, mut receiver: Receiver<RpcEvent>, mut exit: ExitReceiver<()>) {
    debug!("Starting RPC event worker");
    loop {
        let event = select! {
            biased;
            _ = &mut exit => break,
            event = receiver.recv() => match event {
                Some(event) => event,
                None => break,
            },
        };

        // Keep no strong reference to the blockchain while waiting for events.
        let Some(blockchain) = blockchain.upgrade() else {
            break;
        };

        let notify = async {
            // RPC may be disabled or still starting. Release its guard before delivery.
            let rpc = { blockchain.get_rpc().read().await.clone() };
            let Some(rpc) = rpc else {
                return;
            };
            match event {
                RpcEvent::Blockchain(batch) => {
                    let start = Instant::now();
                    for (event, values) in batch.events {
                        for value in values {
                            if let Err(e) = rpc.notify_clients(&event, value).await {
                                debug!("Error while broadcasting event {:?}: {}", event, e);
                            }
                        }
                    }
                    if batch.block {
                        histogram!("xelis_new_block_notify_events_ms").record(start.elapsed().as_millis() as f64);
                    }
                },
                RpcEvent::Peer(event) => event.notify(&rpc).await,
            }
        };

        // Shutdown also interrupts a notification stalled on a subscriber or RPC lock.
        select! {
            biased;
            _ = &mut exit => break,
            _ = notify => (),
        }
    }

    debug!("RPC event worker stopped");
}
