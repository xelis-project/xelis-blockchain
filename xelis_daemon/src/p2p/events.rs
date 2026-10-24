use std::{net::SocketAddr, sync::Arc};
use indexmap::IndexSet;
use log::{debug, error};
use xelis_common::{
    api::daemon::{NotifyEvent, PeerPeerDisconnectedEvent, PeerPeerListUpdatedEvent},
    tokio::{
        select,
        sync::{broadcast::Receiver as BroadcastReceiver, mpsc::Receiver},
    },
};
use crate::{
    core::storage::Storage,
    rpc::rpc::get_peer_entry,
};
use super::{P2pError, P2pServer, Peer, Ping};

// Payloads are prepared by the worker so packet handlers never wait on RPC.
pub enum PeerEvent {
    Connected(Arc<Peer>),
    Disconnected(Arc<Peer>),
    Updated {
        peer: Arc<Peer>,
        peerlist: IndexSet<SocketAddr>,
    },
    PeerDisconnected {
        peer: Arc<Peer>,
        addr: SocketAddr,
    },
}

impl PeerEvent {
    fn peer(&self) -> &Arc<Peer> {
        match self {
            Self::Connected(peer) | Self::Disconnected(peer)
            | Self::Updated { peer, .. } | Self::PeerDisconnected { peer, .. } => peer,
        }
    }
}

impl<S: Storage> P2pServer<S> {
    pub(super) fn notify_peer_event(&self, event: PeerEvent) {
        if event.peer().shareable() {
            // Notifications are best effort under overload; never stall packets.
            if let Err(e) = self.event_sender.try_send(event) {
                error!("P2P notification skipped because it could not be queued: {}", e);
            }
        }
    }

    pub(super) async fn update_peer(&self, peer: &Arc<Peer>, ping: Ping<'_>) -> Result<(), P2pError> {
        let peerlist = ping.update_peer(peer).await?;
        self.notify_peer_event(PeerEvent::Updated {
            peer: Arc::clone(peer),
            peerlist,
        });
        Ok(())
    }

    pub(super) async fn event_loop(self: Arc<Self>, mut receiver: Receiver<PeerEvent>, mut exit: BroadcastReceiver<()>) {
        debug!("Starting P2P event loop task");
        if !self.is_running() {
            return;
        }
        loop {
            let event = select! {
                biased;
                _ = exit.recv() => break,
                event = receiver.recv() => match event {
                    Some(event) => event,
                    None => break,
                },
            };
            // Shutdown also interrupts a notification stalled on a subscriber.
            select! {
                biased;
                _ = exit.recv() => break,
                _ = self.send_peer_event(event) => (),
            }
        }
        debug!("P2P event loop task is stopped");
    }

    async fn send_peer_event(&self, event: PeerEvent) {
        // Release the blockchain RPC lock before building or delivering events.
        let rpc = { self.blockchain.get_rpc().read().await.clone() };
        let Some(rpc) = rpc else {
            return;
        };

        match event {
            PeerEvent::Connected(peer) => {
                if rpc.is_event_tracked(&NotifyEvent::PeerConnected).await {
                    rpc.notify_clients_with(&NotifyEvent::PeerConnected, get_peer_entry(&peer).await).await;
                }
            },
            PeerEvent::Disconnected(peer) => {
                if rpc.is_event_tracked(&NotifyEvent::PeerDisconnected).await {
                    rpc.notify_clients_with(&NotifyEvent::PeerDisconnected, get_peer_entry(&peer).await).await;
                }
            },
            PeerEvent::Updated { peer, peerlist } => {
                if rpc.is_event_tracked(&NotifyEvent::PeerStateUpdated).await {
                    rpc.notify_clients_with(&NotifyEvent::PeerStateUpdated, get_peer_entry(&peer).await).await;
                }
                if !peerlist.is_empty() && rpc.is_event_tracked(&NotifyEvent::PeerPeerListUpdated).await {
                    rpc.notify_clients_with(&NotifyEvent::PeerPeerListUpdated, PeerPeerListUpdatedEvent {
                        peer_id: peer.get_id(),
                        peerlist,
                    }).await;
                }
            },
            PeerEvent::PeerDisconnected { peer, addr } => {
                if rpc.is_event_tracked(&NotifyEvent::PeerPeerDisconnected).await {
                    rpc.notify_clients_with(&NotifyEvent::PeerPeerDisconnected, PeerPeerDisconnectedEvent {
                        peer_id: peer.get_id(),
                        peer_addr: addr,
                    }).await;
                }
            },
        }
    }
}
