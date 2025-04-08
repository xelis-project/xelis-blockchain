pub mod connection;
pub mod peer;
pub mod error;
pub mod packet;
pub mod peer_list;
pub mod chain_validator;
pub mod diffie_hellman;

mod tracker;
mod encryption;
mod disk_cache;
mod bootstrap;
mod chain_sync;

use anyhow::Context;
pub use encryption::EncryptionKey;

use futures::{
    stream::{self, FuturesOrdered},
    Stream,
    StreamExt
};
use indexmap::IndexSet;
use lru::LruCache;
use xelis_common::{
    api::daemon::{
        Direction,
        NotifyEvent,
        PeerPeerDisconnectedEvent,
        TimedDirection
    },
    block::{
        Block,
        BlockHeader,
        TopoHeight,
    },
    config::{TIPS_LIMIT, VERSION},
    crypto::{Hash, Hashable},
    difficulty::CumulativeDifficulty,
    immutable::Immutable,
    serializer::Serializer,
    time::{
        get_current_time_in_millis,
        get_current_time_in_seconds,
        TimestampMillis
    },
    tokio::{spawn_task, ThreadPool},
};
use crate::{
    config::*,
    core::{
        blockchain::Blockchain,
        error::BlockchainError,
        hard_fork,
        storage::Storage
    },
    p2p::packet::{
        chain::CommonPoint,
        inventory::{
            NotifyInventoryRequest,
            NotifyInventoryResponse,
            NOTIFY_MAX_LEN
        }
    },
    rpc::rpc::get_peer_entry
};
use self::{
    connection::{Connection, State},
    error::P2pError,
    packet::{
        chain::BlockId,
        handshake::Handshake,
        object::{ObjectRequest, ObjectResponse, OwnedObjectResponse},
        ping::Ping,
        Packet,
        PacketWrapper
    },
    peer::{Peer, TaskState, Rx},
    peer_list::{PeerList, SharedPeerList},
    tracker::{ObjectTracker, SharedObjectTracker}
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    select,
    sync::{
        broadcast,
        mpsc::{
            self,
            channel,
            Receiver,
            Sender
        },
        oneshot,
        Mutex
    },
    task::JoinHandle,
    time::{interval, sleep, timeout}
};
use log::{info, warn, error, debug, trace};
use std::{
    borrow::Cow,
    io,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc
    },
    time::Duration
};
use bytes::Bytes;
use rand::{seq::IteratorRandom, Rng};

pub const TRANSACTIONS_CHANNEL_CAPACITY: usize = 128;

// P2pServer is a fully async TCP server
// Each connection will block on a data to send or to receive
// useful for low end hardware
pub struct P2pServer<S: Storage> {
    // unique peer id
    peer_id: u64,
    // node tag sent on handshake
    tag: Option<String>,
    // max peers accepted by this server
    max_peers: usize,
    // ip:port address to receive connections
    bind_address: SocketAddr,
    // all peers accepted
    peer_list: SharedPeerList,
    // reference to the chain to add blocks/txs
    blockchain: Arc<Blockchain<S>>,
    // this sender allows to create a queue system in one task only
    connections_sender: Sender<(SocketAddr, bool)>,
    // used to requests objects to peers and avoid requesting the same object to multiple peers
    object_tracker: SharedObjectTracker,
    // used to check if the server is running or not in tasks
    is_running: AtomicBool,
    // Synced cache to prevent concurrent tasks adding the block
    // Timestamp is None if block is not yet executed
    blocks_propagation_queue: Mutex<LruCache<Hash, Option<TimestampMillis>>>,
    // Sender for the blocks processing task to have an ordered queue
    blocks_processor: Sender<(Arc<Peer>, BlockHeader, Hash)>,
    // Sender for the transactions propagated
    // Synced cache to prevent concurrent tasks adding the block
    txs_propagation_queue: Mutex<LruCache<Arc<Hash>, TimestampMillis>>,
    // Sender for the txs processing task to have an ordered queue
    txs_processor: Sender<(Arc<Peer>, Arc<Hash>)>,
    // allow fast syncing (only balances / assets / Smart Contracts changes)
    // without syncing the history
    allow_fast_sync_mode: bool,
    // This can be used safely from a trusted node
    // to boost the sync speed by allowing to request several blocks at same time
    allow_boost_sync_mode: bool,
    // max size of the chain response
    // this is a configurable parameter for nodes to manage their resources
    // Can be reduced for low devices, and increased for high end devices
    // You may sync faster or slower depending on this value
    max_chain_response_size: usize,
    // Configured exclusive nodes
    // If not empty, no other peer than those listed can connect to this node
    exclusive_nodes: IndexSet<SocketAddr>,
    // Are we allowing others nodes to share us as a potential peer ?
    // Also if we allows to be listed in get_peers RPC API
    sharable: bool,
    // Do we try to connect to others nodes
    // If this is enabled, only way to have peers is to let them connect to us
    outgoing_connections_disabled: AtomicBool,
    // Should we propagate the blocks from priority nodes
    // before checking them
    // This is useful for faster propagation through the network
    // if we trust a peer and want to propagate its blocks asap
    // Example: pools having several nodes want to propagate them faster
    allow_priority_blocks: bool,
    // Are we syncing the chain with another peer
    is_syncing: AtomicBool,
    // Current syncing rate in BPS
    syncing_rate_bps: AtomicU64,
    // Exit channel to notify all tasks to stop
    exit_sender: broadcast::Sender<()>,
    // Diffie-Hellman keypair
    dh_keypair: diffie_hellman::DHKeyPair,
    // Diffie-Hellman key verification action
    dh_action: diffie_hellman::KeyVerificationAction,
    // Current stream concurrency to use
    // This is used to limit the number of concurrency tasks in a stream
    stream_concurrency: usize,
}

impl<S: Storage> P2pServer<S> {
    pub fn new(
        concurrency: usize,
        dir_path: Option<String>,
        tag: Option<String>,
        max_peers: usize,
        bind_address: String,
        blockchain: Arc<Blockchain<S>>,
        use_peerlist: bool,
        exclusive_nodes: Vec<SocketAddr>,
        allow_fast_sync_mode: bool,
        allow_boost_sync_mode: bool,
        allow_priority_blocks: bool,
        max_chain_response_size: usize,
        sharable: bool,
        disable_outgoing_connections: bool,
        dh_keypair: Option<diffie_hellman::DHKeyPair>,
        dh_action: diffie_hellman::KeyVerificationAction,
        stream_concurrency: usize,
    ) -> Result<Arc<Self>, P2pError> {
        if tag.as_ref().is_some_and(|tag| tag.len() == 0 || tag.len() > 16) {
            return Err(P2pError::InvalidTag);
        }

        if max_chain_response_size < CHAIN_SYNC_RESPONSE_MIN_BLOCKS || max_chain_response_size > CHAIN_SYNC_RESPONSE_MAX_BLOCKS {
            return Err(P2pError::InvalidMaxChainResponseSize);
        }

        if max_peers == 0 {
            return Err(P2pError::InvalidMaxPeers);
        }

        // set channel to communicate with listener thread
        let mut rng = rand::thread_rng();
        // generate a random peer id for network
        let peer_id: u64 = rng.gen();
        // parse the bind address
        let addr: SocketAddr = bind_address.parse()?;

        // create mspc channel for connections to peers
        let (connections_sender, connections_receiver) = mpsc::channel(max_peers);
        let (blocks_processor, blocks_processor_receiver) = mpsc::channel(TIPS_LIMIT * STABLE_LIMIT as usize);
        let (txs_processor, txs_processor_receiver) = mpsc::channel(TRANSACTIONS_CHANNEL_CAPACITY);

        // Channel used to broadcast the stop message
        let (exit_sender, exit_receiver) = broadcast::channel(1);
        let object_tracker = ObjectTracker::new(exit_receiver);

        let (sender, event_receiver) = channel::<Arc<Peer>>(max_peers); 
        let peer_list = PeerList::new(max_peers, format!("{}peerlist-{}", dir_path.unwrap_or_default(), blockchain.get_network().to_string().to_lowercase()), Some(sender))?;

        let server = Self {
            peer_id,
            tag,
            max_peers,
            bind_address: addr,
            peer_list,
            blockchain,
            connections_sender,
            object_tracker,
            is_running: AtomicBool::new(true),
            blocks_propagation_queue: Mutex::new(LruCache::new(NonZeroUsize::new(STABLE_LIMIT as usize * TIPS_LIMIT).unwrap())),
            blocks_processor,
            txs_propagation_queue: Mutex::new(LruCache::new(NonZeroUsize::new(TRANSACTIONS_CHANNEL_CAPACITY).unwrap())),
            txs_processor,
            allow_fast_sync_mode,
            allow_boost_sync_mode,
            max_chain_response_size,
            exclusive_nodes: IndexSet::from_iter(exclusive_nodes.into_iter()),
            sharable,
            allow_priority_blocks,
            is_syncing: AtomicBool::new(false),
            syncing_rate_bps: AtomicU64::new(0),
            outgoing_connections_disabled: AtomicBool::new(disable_outgoing_connections),
            exit_sender,
            dh_keypair: dh_keypair.unwrap_or_else(diffie_hellman::DHKeyPair::new),
            dh_action,
            stream_concurrency
        };

        let arc = Arc::new(server);
        {
            let zelf = Arc::clone(&arc);
            spawn_task("p2p-engine", async move {
                if let Err(e) = zelf.start(
                    connections_receiver,
                    blocks_processor_receiver,
                    txs_processor_receiver,
                    event_receiver,
                    use_peerlist,
                    concurrency
                ).await {
                    error!("Unexpected error on P2p module: {}", e);
                }
            });
        }

        Ok(arc)
    }

    // Stop the p2p module by closing all connections
    pub async fn stop(&self) {
        info!("Stopping P2p Server...");
        self.is_running.store(false, Ordering::SeqCst);

        info!("Waiting for all peers to be closed...");
        self.peer_list.close_all().await;

        if let Err(e) = self.exit_sender.send(()) {
            error!("Error while sending Exit message to stop all tasks: {}", e);
        }
        info!("P2p Server is now stopped!");
    }

    // Verify if we are still running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    pub fn is_outgoing_connections_disabled(&self) -> bool {
        self.outgoing_connections_disabled.load(Ordering::SeqCst)
    }

    pub fn set_disable_outgoing_connections(&self, disable: bool) {
        self.outgoing_connections_disabled.store(disable, Ordering::SeqCst);
    }

    // every 10 seconds, verify and connect if necessary to a random node
    async fn maintains_connection_to_nodes(self: &Arc<Self>, nodes: IndexSet<SocketAddr>, sender: Sender<SocketAddr>) -> Result<(), P2pError> {
        debug!("Starting maintains seed nodes task...");
        let mut interval = interval(Duration::from_secs(P2P_AUTO_CONNECT_PRIORITY_NODES_DELAY));
        let mut exit_receiver = self.exit_sender.subscribe();
        loop {
            select! {
                biased;
                _ = exit_receiver.recv() => {
                    debug!("Received exit message, exiting maintains seed nodes task");
                    break;
                },
                _ = interval.tick() => {
                    if !self.is_running() {
                        debug!("Maintains seed nodes task is stopped!");
                        break;
                    }

                    let connect = if self.peer_list.size().await >= self.max_peers {
                        // if we have already reached the limit, we ignore this new connection
                        None
                    } else {
                        let mut potential_nodes = Vec::new();
                        for node in &nodes {
                            if !self.peer_list.is_connected_to_addr(&node).await {
                                potential_nodes.push(node);
                            }
                        }

                        potential_nodes.into_iter().choose(&mut rand::thread_rng()).copied()
                    };
                    if let Some(node) = connect {
                        trace!("Trying to connect to priority node: {}", node);
                        if let Err(e) = sender.send(node).await {
                            error!("Error while sending priority node to connect: {}", e);
                        }
                    }
                },
            }
        }

        Ok(())
    }

    // connect to seed nodes, start p2p server
    // and wait on all new connections
    async fn start(
        self: &Arc<Self>,
        receiver: Receiver<(SocketAddr, bool)>,
        blocks_processor_receiver: Receiver<(Arc<Peer>, BlockHeader, Hash)>,
        txs_processor_receiver: Receiver<(Arc<Peer>, Arc<Hash>)>,
        event_receiver: Receiver<Arc<Peer>>,
        use_peerlist: bool,
        concurrency: usize
    ) -> Result<(), P2pError> {
        let listener = TcpListener::bind(self.get_bind_address()).await?;
        info!("P2p Server will listen on: {}", self.get_bind_address());

        let mut exclusive_nodes = self.exclusive_nodes.clone();
        if exclusive_nodes.is_empty() {
            debug!("No exclusive nodes available, using seed nodes...");
            let network = self.blockchain.get_network();
            let seed_nodes = get_seed_nodes(&network);
            exclusive_nodes = seed_nodes.iter().map(|s| s.parse().unwrap()).collect();
        }

        let (priority_sender, priority_connections) = mpsc::channel(1);
        // create tokio task to maintains connection to exclusive nodes or seed nodes
        let zelf = Arc::clone(self);
        spawn_task("p2p-maintain-nodes", async move {
            info!("Connecting to seed nodes...");
            if let Err(e) = zelf.maintains_connection_to_nodes(exclusive_nodes, priority_sender).await {
                error!("Error while maintening connection with seed nodes: {}", e);
            };
        });

        // start a new task for chain sync
        spawn_task("p2p-chain-sync", Arc::clone(&self).chain_sync_loop());

        // start another task for ping loop
        spawn_task("p2p-ping", Arc::clone(&self).ping_loop());

        // start the blocks processing task to have a queued handler
        spawn_task("p2p-blocks", Arc::clone(&self).blocks_processing_task(blocks_processor_receiver));
        // Start the same task for transactions propagated
        spawn_task("p2p-transactions", Arc::clone(&self).txs_processing_task(txs_processor_receiver));

        // start the event loop task to handle peer disconnect events
        spawn_task("p2p-events", Arc::clone(&self).event_loop(event_receiver));

        // start another task for peerlist loop
        if use_peerlist {
            spawn_task("p2p-peerlist", Arc::clone(&self).peerlist_loop());
        }

        let (tx, mut rx) = channel(1);
        spawn_task("p2p-outgoing-connections", Arc::clone(&self).handle_outgoing_connections(priority_connections, receiver, tx.clone()));
        spawn_task("p2p-incoming-connections", Arc::clone(&self).handle_incoming_connections(listener, tx, concurrency));

        let mut exit_receiver = self.exit_sender.subscribe();
        loop {
            select! {
                biased;
                _ = exit_receiver.recv() => {
                    debug!("Received exit message, exiting handle peer task");
                    break;
                },
                res = rx.recv() => match res {
                    Some((peer, rx)) => {
                        trace!("New peer received: {}", peer);
                        if !self.is_running() {
                            debug!("blocks processing task is stopped!");
                            break;
                        }

                        let peer = Arc::new(peer);
                        match self.handle_new_peer(&peer, rx).await {
                            Ok(_) => {},
                            Err(e) => {
                                error!("Error while handling new connection: {}", e);
                                if let Err(e) = peer.get_connection().close().await {
                                    debug!("Error while closing unhandled connection: {}", e);
                                }
                            }
                        }
                    },
                    None => {
                        debug!("channel is closed, exiting task");
                        break;
                    }
                }
            }
        }

        debug!("P2p Server main task has exited");

        Ok(())
    }

    async fn handle_outgoing_connections(self: Arc<Self>, mut priority_connections: Receiver<SocketAddr>, mut receiver: Receiver<(SocketAddr, bool)>, tx: Sender<(Peer, Rx)>) {
        // only allocate one time the buffer for this packet
        let mut handshake_buffer = [0; 512];
        let mut exit_receiver = self.exit_sender.subscribe();
        loop {
            let (addr, priority) = select! {
                biased;
                _ = exit_receiver.recv() => {
                    debug!("Received exit message, exiting outgoing connections task");
                    break;
                },
                res = priority_connections.recv() => {
                    trace!("New priority connection received");
                    match res {
                        Some(res) => (res, true),
                        None => {
                            error!("Error while receiving priority connection, exiting task");
                            break;
                        }
                    }
                },
                res = receiver.recv() => {
                    match res {
                        Some(msg) => msg,
                        None => {
                            error!("Error while receiving outgoing connection, exiting task");
                            break;
                        }
                    }
                }
            };

            trace!("Trying to connect to {}", addr);
            if !priority {
                trace!("checking if connection can be accepted");
                // check that this incoming peer isn't blacklisted
                if !self.accept_new_connections().await {
                    debug!("{} is not allowed, we don't accept any new connection", addr);
                    continue;
                }

                match self.peer_list.is_allowed(&addr.ip()).await {
                    Ok(allowed) => {
                        if !allowed {
                            debug!("{} is not allowed to connect", addr);
                            continue;
                        }
                    },
                    Err(e) => {
                        error!("Error while checking if {} is allowed: {}", addr, e);
                        continue;
                    }
                };
            }

            if !self.is_running() {
                break;
            }

            let connection = match self.connect_to_peer(addr).await {
                Ok(connection) => connection,
                Err(e) => {
                    debug!("Error while connecting to address {}: {}", addr, e);

                    if !priority {
                        if let Err(e) = self.peer_list.increase_fail_count_for_peerlist_entry(&addr.ip(), false).await {
                            error!("Error while increasing fail count for peer {} while connecting to it: {}", addr, e);
                        }
                    }

                    continue;
                }
            };

            let peer = match self.create_verified_peer(&mut handshake_buffer, connection, priority).await {
                Ok(handshake) => handshake,
                Err(e) => {
                    debug!("Error while verifying connection to address {}: {}", addr, e);
                    if !priority {
                        if let Err(e) = self.peer_list.increase_fail_count_for_peerlist_entry(&addr.ip(), false).await {
                            error!("Error while increasing fail count for peer {} while verifying it: {}", addr, e);
                        }
                    }
                    continue;
                }
            };

            // Peer is valid, send it to connect
            if let Err(e) = tx.send(peer).await {
                error!("Error while sending new connection to listener: {}, exiting task", e);
                break;
            }
        }

        debug!("handle outgoing connections task has exited");
    }

    // This task will handle an incoming connection request
    // It will verify if we can accept this connection
    // If we can, we will create a new peer and send it to the listener
    async fn handle_incoming_connection(self: &Arc<Self>, res: io::Result<(TcpStream, SocketAddr)>, thread_pool: &ThreadPool, tx: &Sender<(Peer, Rx)>) -> Result<(), P2pError> {
        let (mut stream, addr) = res?;

        // Verify if we can accept new connections
        let reject = !self.is_compatible_with_exclusive_nodes(&addr)
            // check that this incoming peer isn't blacklisted
            || !self.accept_new_connections().await
            || !self.peer_list.is_allowed(&addr.ip()).await?
            || self.is_connected_to_addr(&addr).await;

        // Reject connection
        if reject {
            debug!("Rejecting connection from {}", addr);
            stream.shutdown().await?;
            return Ok(())
        }

        let connection = Connection::new(stream, addr, false);
        let zelf = Arc::clone(&self);
        let tx = tx.clone();
        thread_pool.execute(async move {
            let mut buffer = [0; 512];
            match zelf.create_verified_peer(&mut buffer, connection, false).await {
                Ok((peer, rx)) => {
                    if let Err(e) = tx.send((peer, rx)).await {
                        error!("Error while sending new connection to listener: {}", e);
                    }
                },
                Err(e) => {
                    debug!("Error while handling incoming connection {}: {}", addr, e);
                    if let Err(e) = zelf.peer_list.increase_fail_count_for_peerlist_entry(&addr.ip(), true).await {
                        error!("Error while increasing fail count for incoming peer {} while verifying it: {}", addr, e);
                    }
                }
            };
        }).await?;

        Ok(())
    }

    // This task will handle all incoming connections requests
    // Based on the concurrency set, it will create a thread pool to handle requests and wait when
    // a worker is free to accept a new connection
    async fn handle_incoming_connections(self: Arc<Self>, listener: TcpListener, tx: Sender<(Peer, Rx)>, concurrency: usize) {
        let mut thread_pool = ThreadPool::new(concurrency);
        let mut exit_receiver = self.exit_sender.subscribe();
        loop {
            select! {
                _ = exit_receiver.recv() => {
                    debug!("Received exit message, exiting incoming connections task");
                    break;
                }
                res = listener.accept() => {
                    trace!("New listener result received (is err: {})", res.is_err());

                    if !self.is_running() {
                        break;
                    }

                    self.handle_incoming_connection(res, &thread_pool, &tx).await.unwrap_or_else(|e| {
                        debug!("Error while handling incoming connection: {}", e);
                    });
                }
            }
        }

        thread_pool.stop();

        debug!("incoming connections task has exited");
    }

    // Verify handshake send by a new connection
    // based on data size, network ID, peers address validity
    // block height and block top hash of this peer (to know if we are on the same chain)
    async fn verify_handshake(&self, connection: &mut Connection, handshake: &mut Handshake<'_>) -> Result<(), P2pError> {
        if handshake.get_network() != self.blockchain.get_network() {
            trace!("{} has an invalid network: {}", connection, handshake.get_network());
            return Err(P2pError::InvalidNetwork)
        }

        if *handshake.get_network_id() != NETWORK_ID {
            return Err(P2pError::InvalidNetworkID);
        }

        if handshake.get_local_port() == 0 {
            return Err(P2pError::InvalidLocalPort);
        }

        if self.has_peer_id_used(&handshake.get_peer_id()).await {
            return Err(P2pError::PeerIdAlreadyUsed(handshake.get_peer_id()));
        }

        let genesis_hash = match get_genesis_block_hash(self.blockchain.get_network()) {
            Some(hash) => Cow::Borrowed(hash),
            None => {
                trace!("no hardcoded genesis block hash found, using the one from the storage");
                let storage = self.blockchain.get_storage().read().await;
                let hash = storage.get_hash_at_topo_height(0).await?;
                Cow::Owned(hash)
            }
        };

        if *handshake.get_block_genesis_hash() != *genesis_hash {
            debug!("Invalid genesis block hash {}", handshake.get_block_genesis_hash());
            return Err(P2pError::InvalidHandshake)
        }

        if let Some(pruned_topoheight) = handshake.get_pruned_topoheight() {
            let topoheight = handshake.get_topoheight();
            if *pruned_topoheight > topoheight {
                debug!("Peer {} has a pruned topoheight {} higher than its topoheight {}", connection, pruned_topoheight, topoheight);
                return Err(P2pError::InvalidHandshake)
            }
        }

        // check if the version of this peer is allowed
        if !hard_fork::is_version_allowed_at_height(self.blockchain.get_network(), self.blockchain.get_height(), handshake.get_version()).map_err(|e| P2pError::InvalidP2pVersion(e.to_string()))? {
            return Err(P2pError::InvalidP2pVersion(handshake.get_version().clone()));
        }

        Ok(())
    }

    // Build a handshake packet
    // We feed the packet with all chain data
    async fn build_handshake(&self) -> Result<Vec<u8>, P2pError> {
        debug!("locking storage for building handshake");
        let storage = self.blockchain.get_storage().read().await;
        debug!("storage lock acquired for building handshake");
        let (block, top_hash) = storage.get_top_block_header().await?;
        let topoheight = self.blockchain.get_topo_height();
        let pruned_topoheight = storage.get_pruned_topoheight().await?;
        let cumulative_difficulty = storage.get_cumulative_difficulty_for_block_hash(&top_hash).await?;
        let genesis_block = match get_genesis_block_hash(self.blockchain.get_network()) {
            Some(hash) => Cow::Borrowed(hash),
            None => {
                trace!("no hardcoded genesis block hash found, using the one from the storage");
                Cow::Owned(storage.get_hash_at_topo_height(0).await?)
            }
        };
        let handshake = Handshake::new(Cow::Owned(VERSION.to_owned()), *self.blockchain.get_network(), Cow::Borrowed(self.get_tag()), Cow::Borrowed(&NETWORK_ID), self.get_peer_id(), self.bind_address.port(), get_current_time_in_seconds(), topoheight, block.get_height(), pruned_topoheight, Cow::Borrowed(&top_hash), genesis_block, Cow::Borrowed(&cumulative_difficulty), self.sharable);
        Ok(Packet::Handshake(Cow::Owned(handshake)).to_bytes())
    }

    // Create a valid peer using the connection, if an error happen, it will close the stream and return the error
    async fn create_verified_peer(&self, buf: &mut [u8], mut connection: Connection, priority: bool) -> Result<(Peer, Rx), P2pError> {
        let handshake = match self.verify_connection(buf, &mut connection).await {
            Ok(handshake) => handshake,
            Err(e) => {
                debug!("Error while verifying connection with {}: {}", connection, e);
                connection.close().await?;
                return Err(e);
            }
        };

        let (peer, rx) = handshake.create_peer(connection, priority, self.peer_list.clone());
        Ok((peer, rx))
    }

    // this function handle all new connections
    // A new connection have to send an Handshake
    // if the handshake is valid, we accept it & register it on server
    async fn verify_connection(&self, buf: &mut [u8], connection: &mut Connection) -> Result<Handshake, P2pError> {
        trace!("New connection: {}", connection);

        // Exchange encryption keys
        let expected_key = self.peer_list.get_dh_key_for_peer(&connection.get_address().ip()).await?;
        let new_key = connection.exchange_keys(&self.dh_keypair, expected_key.as_ref(), self.dh_action, buf).await?;
        self.peer_list.store_dh_key_for_peer(&connection.get_address().ip(), new_key).await?;

        // Start handshake now
        connection.set_state(State::Handshake);
        if connection.is_out() {
            self.send_handshake(&connection).await?;
        }

        // wait on the handshake packet
        let mut handshake: Handshake<'_> = match timeout(Duration::from_millis(PEER_TIMEOUT_INIT_CONNECTION), connection.read_packet(buf, buf.len() as u32)).await?? {
            // only allow handshake packet
            Packet::Handshake(h) => h.into_owned(),
            _ => return Err(P2pError::ExpectedHandshake)
        };

        trace!("received handshake packet!");
        self.verify_handshake(connection, &mut handshake).await?;

        trace!("Handshake has been verified");
        // if it's a outgoing connection, don't send the handshake back
        // because we have already sent it
        if !connection.is_out() {
            trace!("Sending handshake back to {}", connection);
            self.send_handshake(&connection).await?;
        }

        // if we reach here, handshake is all good, we can start listening this new peer
        connection.set_state(State::Success);

        Ok(handshake)
    }

    async fn handle_new_peer(self: &Arc<Self>, peer: &Arc<Peer>, rx: Rx) -> Result<(), P2pError> {
        // we can save the peer in our peerlist
        let peer_id = peer.get_id(); // keep in memory the peer_id outside connection (because of moved value)
        if self.is_internal_id(peer_id) {
            return Err(P2pError::PeerIdAlreadyUsed(peer_id));
        }

        self.peer_list.add_peer(peer, self.get_max_peers()).await?;

        if peer.sharable() {
            trace!("Locking RPC Server to notify PeerConnected event");
            if let Some(rpc) = self.blockchain.get_rpc().read().await.as_ref() {
                if rpc.is_event_tracked(&NotifyEvent::PeerConnected).await {
                    debug!("Notifying clients with PeerConnected event");
                    rpc.notify_clients_with(&NotifyEvent::PeerConnected, get_peer_entry(&peer).await).await;
                }
            }
            trace!("End locking for PeerConnected event");
        }

        self.handle_connection(peer.clone(), rx).await
    }

    // Verify that we don't have any exclusive nodes configured OR that we are part of this list
    pub fn is_compatible_with_exclusive_nodes(&self, addr: &SocketAddr) -> bool {
        self.exclusive_nodes.is_empty() || self.exclusive_nodes.contains(addr)
    }

    // Connect to a specific peer address
    // Buffer is passed in parameter to prevent the re-allocation each time
    // No check is done, this is done at the moment of the connection
    pub async fn try_to_connect_to_peer(&self, addr: SocketAddr, priority: bool) {
        debug!("try to connect to peer addr {}, priority: {}", addr, priority);
        if self.connections_sender.is_closed() {
            error!("Connection sender is closed, we can't connect to peer {}", addr);
            return;
        }

        if let Err(e) = self.connections_sender.send((addr, priority)).await {
            error!("Error while trying to connect to address {} (priority = {}): {}", addr, priority, e);
        }
    }

    // Connect to a new peer using its socket address
    // Then we send him a handshake
    async fn connect_to_peer(&self, addr: SocketAddr) -> Result<Connection, P2pError> {
        trace!("Trying to connect to {}", addr);

        if !self.is_compatible_with_exclusive_nodes(&addr) {
            debug!("Not in exclusive node list: {}, skipping", addr);
            return Err(P2pError::ExclusiveNode);
        }

        {
            trace!("peer list locked for trying to connect to peer {}", addr);
            if self.is_connected_to_addr(&addr).await {
                debug!("Already connected to peer: {}, skipping", addr);
                return Err(P2pError::PeerAlreadyConnected(addr));
            }

            if !self.peer_list.is_allowed(&addr.ip()).await? {
                debug!("{} is not allowed, we can't connect to it", addr);
                return Err(P2pError::NotAllowed);
            }
        }

        let stream = timeout(Duration::from_millis(PEER_TIMEOUT_INIT_OUTGOING_CONNECTION), TcpStream::connect(&addr)).await??;
        let connection = Connection::new(stream, addr, true);
        Ok(connection)
    }

    // Send a handshake to a connection (this is used to determine if its a potential peer)
    // Handsake is sent only once, when we connect to a new peer, and we get it back from connection to make it a peer
    async fn send_handshake(&self, connection: &Connection) -> Result<(), P2pError> {
        trace!("Sending handshake to {}", connection);
        let handshake = self.build_handshake().await?;
        connection.send_bytes(&handshake).await
    }

    // build a ping packet with the current state of the blockchain
    // if a peer is given, we will check and update the peers list
    async fn build_generic_ping_packet_with_storage(&self, storage: &S) -> Result<Ping<'_>, P2pError> {
        debug!("building generic ping packet");
        let (cumulative_difficulty, block_top_hash, pruned_topoheight) = {
            let pruned_topoheight = storage.get_pruned_topoheight().await?;
            let top_block_hash = storage.get_top_block_hash().await?;
            let cumulative_difficulty = storage.get_cumulative_difficulty_for_block_hash(&top_block_hash).await?;
            (cumulative_difficulty, top_block_hash, pruned_topoheight)
        };
        let highest_topo_height = self.blockchain.get_topo_height();
        let highest_height = self.blockchain.get_height();
        let new_peers = IndexSet::new();
        Ok(Ping::new(Cow::Owned(block_top_hash), highest_topo_height, highest_height, pruned_topoheight, cumulative_difficulty, new_peers))
    }

    // Build a generic ping packet
    // This will lock the storage for us
    async fn build_generic_ping_packet(&self) -> Result<Ping<'_>, P2pError> {
        debug!("locking storage to build generic ping packet");
        let storage = self.blockchain.get_storage().read().await;
        debug!("storage is locked for generic ping packet");
        self.build_generic_ping_packet_with_storage(&*storage).await
    }

    // select a random peer which is greater than us to sync chain
    // candidate peer should have a greater topoheight or a higher block height than us
    // It must also have a greater cumulative difficulty than us
    // Cumulative difficulty is used in case two chains are running at same speed
    // We must determine which one has the most work done
    // if we are not in fast sync mode, we must verify its pruned topoheight to be sure
    // he have the blocks we need
    async fn select_random_best_peer(&self, fast_sync: bool, previous_peer: Option<(u64, bool, bool)>) -> Result<Option<Arc<Peer>>, BlockchainError> {
        trace!("select random best peer");
        
        let our_height = self.blockchain.get_height();
        let our_topoheight = self.blockchain.get_topo_height();

        // Search our cumulative difficulty
        let our_cumulative_difficulty = {
            debug!("locking storage to search our cumulative difficulty");
            let storage = self.blockchain.get_storage().read().await;
            debug!("storage locked for cumulative difficulty");
            let hash = storage.get_hash_at_topo_height(our_topoheight).await?;
            storage.get_cumulative_difficulty_for_block_hash(&hash).await?
        };

        trace!("peer list locked for select random best peer");

        // search for peers which are greater than us
        // and that are pruned but before our height so we can sync correctly
        let available_peers = self.peer_list.get_cloned_peers().await;
        // IndexSet is used to select by random index
        let mut peers: IndexSet<Arc<Peer>> = IndexSet::with_capacity(available_peers.len());

        for p in available_peers {
            // Avoid selecting peers that have a weaker cumulative difficulty than us
            {
                let cumulative_difficulty = p.get_cumulative_difficulty().lock().await;
                if *cumulative_difficulty <= our_cumulative_difficulty {
                    trace!("Peer {} has a lower cumulative difficulty than us, skipping...", p);
                    continue;
                }
            }

            let peer_topoheight = p.get_topoheight();
            if fast_sync {
                // if we want to fast sync, but this peer is not compatible, we skip it
                // for this we check that the peer topoheight is not less than the prune safety limit
                if peer_topoheight < PRUNE_SAFETY_LIMIT || our_topoheight + PRUNE_SAFETY_LIMIT > peer_topoheight {
                    trace!("Peer {} has a topoheight less than the prune safety limit, skipping...", p);
                    continue;
                }
                if let Some(pruned_topoheight) = p.get_pruned_topoheight() {
                    // This shouldn't be possible if following the protocol,
                    // But we may never know if a peer is not following the protocol strictly
                    if peer_topoheight - pruned_topoheight < PRUNE_SAFETY_LIMIT {
                        trace!("Peer {} has a pruned topoheight {} less than the prune safety limit, skipping...", p, pruned_topoheight);
                        continue;
                    }
                }
            } else {
                // check that the pruned topoheight is less than our topoheight to sync
                // so we can sync chain from pruned chains
                if let Some(pruned_topoheight) = p.get_pruned_topoheight() {
                    if pruned_topoheight > our_topoheight {
                        trace!("Peer {} has a pruned topoheight {} higher than our topoheight {}, skipping...", p, pruned_topoheight, our_topoheight);
                        continue;
                    }
                }
            }

            // check if this peer may have a block we don't have
            if p.get_height() > our_height || peer_topoheight > our_topoheight {
                debug!("Peer {} is a candidate for chain sync, our topoheight: {}, our height: {}", p, our_topoheight, our_height);
                peers.insert(p);
            }
        }

        // Try to not reuse the same peer between each sync
        if let Some((previous_peer, priority, err)) = previous_peer {
            if peers.len() > 1 || (err && !priority) {
                debug!("removing previous peer {} from random selection, err: {}, priority: {}", previous_peer, err, priority);
                // We don't need to preserve the order
                if let Some(position) = peers.iter().position(|p| p.get_id() == previous_peer) {
                    peers.swap_remove_index(position);
                }
            }
        }

        let count = peers.len();
        trace!("peers available for random selection: {}", count);
        if count == 0 {
            return Ok(None)
        }

        let selected = rand::thread_rng().gen_range(0..count);
        // clone the Arc to prevent the lock until the end of the sync request
        Ok(peers.swap_remove_index(selected))
    }

    // Check if user has allowed fast sync mode
    // This is useful for light node by syncing only the top chain while staying fully compatible
    pub fn allow_fast_sync(&self) -> bool {
        self.allow_fast_sync_mode
    }

    // Check if user has allowed the boost sync mode
    // This is requesting blocks in parallel during chain sync
    pub fn allow_boost_sync(&self) -> bool {
        self.allow_boost_sync_mode
    }

    // Set the chain syncing state
    fn set_chain_syncing(&self, syncing: bool) {
        self.is_syncing.store(syncing, Ordering::SeqCst);
    }

    // Check if we are syncing the chain
    pub fn is_syncing_chain(&self) -> bool {
        self.is_syncing.load(Ordering::SeqCst)
    }

    // Set the chain syncing rate bps
    fn set_chain_sync_rate_bps(&self, rate: u64) {
        self.syncing_rate_bps.store(rate, Ordering::SeqCst);
    }

    // Get the current syncing rate if its syncing
    pub fn get_syncing_rate_bps(&self) -> Option<u64> {
        if self.is_syncing_chain() && self.allow_boost_sync() {
            Some(self.syncing_rate_bps.load(Ordering::SeqCst))
        } else {
            None
        }
    }

    // This a infinite task that is running every CHAIN_SYNC_DELAY seconds
    // Based on the user configuration, it will try to sync the chain with another node with longest chain if any
    async fn chain_sync_loop(self: Arc<Self>) {
        // used to detect how much time we have to wait before next request
        let mut last_chain_sync = get_current_time_in_millis();
        let interval = Duration::from_secs(CHAIN_SYNC_DELAY);
        // Try to not reuse the same peer between each sync
        // Don't use it at all if its errored
        // the Peer ID, peer priority flag, error state
        let mut previous_peer: Option<(u64, bool, bool)> = None;
        loop {
            // Detect exact time needed before next chain sync
            let current = get_current_time_in_millis();
            let diff = current - last_chain_sync;
            if  diff < CHAIN_SYNC_DELAY * MILLIS_PER_SECOND {
                let wait = CHAIN_SYNC_DELAY * MILLIS_PER_SECOND - diff;
                debug!("Waiting {} ms for chain sync delay...", wait);
                sleep(Duration::from_millis(wait)).await;
            }
            last_chain_sync = current;

            if !self.is_running() {
                debug!("Chain sync loop is stopped!");
                break;
            }

            // first we have to check if we allow fast sync mode
            // and then we check if we have a potential peer above us to fast sync
            // otherwise we sync normally 
            let fast_sync = if self.allow_fast_sync() {
                trace!("locking peer list for fast sync check");
                trace!("peer list locked for fast sync check");
                let our_topoheight = self.blockchain.get_topo_height();
                self.peer_list.get_peers().read().await.values().find(|p| {
                    let peer_topoheight = p.get_topoheight();
                    peer_topoheight > our_topoheight && peer_topoheight - our_topoheight > PRUNE_SAFETY_LIMIT
                }).is_some()
            } else {
                false
            };

            let peer_selected = match self.select_random_best_peer(fast_sync, previous_peer).await {
                Ok(peer) => peer,
                Err(e) => {
                    error!("Error while selecting random best peer for chain sync: {}", e);
                    None
                }
            };

            if let Some(peer) = peer_selected {
                debug!("Selected for chain sync is {}", peer);
                // We are syncing the chain
                self.set_chain_sync_rate_bps(0);
                self.set_chain_syncing(true);

                // check if we can maybe fast sync first
                // otherwise, fallback on the normal chain sync
                let err = if fast_sync {
                    if let Err(e) = self.bootstrap_chain(&peer).await {
                        warn!("Error occured while fast syncing with {}: {}", peer, e);
                        true
                    } else {
                        false
                    }
                } else {
                    let previous_err = previous_peer.map(|(_, _, err)| err).unwrap_or(false);
                    if let Err(e) = self.request_sync_chain_for(&peer, &mut last_chain_sync, previous_err).await {
                        warn!("Error occured on chain sync with {}: {}", peer, e);
                        true
                    } else {
                        false
                    }
                };
                previous_peer = Some((peer.get_id(), peer.is_priority(), err));
                // We are not syncing anymore
                self.set_chain_syncing(false);
            } else {
                trace!("No peer found for chain sync, waiting before next check");
                sleep(interval).await;
            }
        }
    }

    // broadcast generic ping packet every 10s
    // if we have to send our peerlist to all peers, we calculate the ping for each peer
    // instead of being done in each write task of peer, we do it one time so we don't have
    // several lock on the chain and on peerlist
    async fn ping_loop(self: Arc<Self>) {
        debug!("Starting ping loop...");

        let mut last_peerlist_update = get_current_time_in_seconds();
        let duration = Duration::from_secs(P2P_PING_DELAY);
        loop {
            trace!("Waiting for ping delay...");
            sleep(duration).await;

            if !self.is_running() {
                debug!("Ping loop task is stopped!");
                break;
            }

            // If peer list is empty, skip this iteration
            if self.peer_list.is_empty().await {
                debug!("Peer list is empty, skipping ping packet");
                continue;
            }

            debug!("Building ping packet from ping task");
            let ping = match self.build_generic_ping_packet().await {
                Ok(ping) => ping,
                Err(e) => {
                    error!("Error while building generic ping packet: {}", e);
                    // We will retry later
                    continue;
                }
            };
            trace!("generic ping packet finished");

            // Get all connected peers
            let all_peers = self.peer_list.get_cloned_peers().await;

            let current_time = get_current_time_in_seconds();
            // check if its time to send our peerlist
            if current_time > last_peerlist_update + P2P_PING_PEER_LIST_DELAY {
                trace!("Sending ping packet with peerlist...");

                stream::iter(all_peers.iter())
                    .for_each_concurrent(self.stream_concurrency, |peer| {
                        // Clone the ping packet for each peer
                        // We need to update the shared peers in it
                        let mut ping = ping.clone();
                        let all_peers = &all_peers;
                        async move {
                            if peer.get_connection().is_closed() {
                                debug!("{} is closed, skipping ping packet", peer);
                                return;
                            }

                            // Is it a peer from our local network
                            let is_local_peer = is_local_address(peer.get_connection().get_address());
        
                            // all the peers we already shared with this peer
                            let mut shared_peers = peer.get_peers().lock().await;
        
                            // iterate through our peerlist to determinate which peers we have to send
                            for p in all_peers.iter() {
                                // don't send him itself
                                // and don't share a peer that don't want to be shared
                                if p.get_id() == peer.get_id() || !p.sharable() {
                                    continue;
                                }
        
                                // if we haven't send him this peer addr and that he don't have him already, insert it
                                let addr = p.get_outgoing_address();
        
                                // Don't share local network addresses if it's external peer
                                if (is_local_address(addr) && !is_local_peer) || !is_valid_address(addr) {
                                    debug!("{} is a local address but peer is external, skipping", addr);
                                    continue;
                                }
        
                                let direction = TimedDirection::Out {
                                    sent_at: get_current_time_in_millis()
                                };
        
                                let send = match shared_peers.get_mut(addr) {
                                    Some(e) => e.update(direction),
                                    None => {
                                        shared_peers.put(*addr, direction);
                                        true
                                    }
                                };
        
                                if send {
                                    // add it in our side to not re send it again
                                    trace!("{} didn't received {} yet, adding it to peerlist in ping packet", peer.get_outgoing_address(), addr);
        
                                    // add it to new list to send it
                                    ping.add_peer(*addr);
                                    if ping.get_peers().len() >= P2P_PING_PEER_LIST_LIMIT {
                                        break;
                                    }
                                }
                            }
        
                            // update the ping packet with the new peers
                            debug!("Set peers: {:?}, going to {}", ping.get_peers(), peer.get_outgoing_address());
                            // send the ping packet to the peer
                            if let Err(e) = peer.send_packet(Packet::Ping(Cow::Borrowed(&ping))).await {
                                debug!("Error sending specific ping packet to {}: {}", peer, e);
                            } else {
                                peer.set_last_ping_sent(current_time);
                            }
                        }
                    }).await;

                // update the last time we sent our peerlist
                // We don't use previous current_time variable because it may have been
                // delayed due to the packet sending
                last_peerlist_update = get_current_time_in_seconds();
            } else {
                trace!("Sending generic ping packet...");
                let packet = Packet::Ping(Cow::Owned(ping));
                let bytes = Bytes::from(packet.to_bytes());

                // broadcast directly the ping packet asap to all peers
                stream::iter(all_peers)
                    .for_each_concurrent(self.stream_concurrency, |peer| {
                        // Move the reference only
                        let bytes = &bytes;
                        async move {
                            if current_time - peer.get_last_ping_sent() > P2P_PING_DELAY && !peer.get_connection().is_closed() {
                                trace!("broadcast generic ping packet to {}", peer);
                                if let Err(e) = peer.send_bytes(bytes.clone()).await {
                                    error!("Error while trying to send ping packet to {}: {}", peer, e);
                                } else {
                                    peer.set_last_ping_sent(current_time);
                                }
                            } else {
                                trace!("we already sent a ping packet to {}, skipping", peer);
                            }
                        }
                    }).await;

                trace!("generic ping packet sent to all peers");
            }
        }
    }

    // try to extend our peerlist each time its possible by searching in known peerlist from disk
    async fn peerlist_loop(self: Arc<Self>) {
        debug!("Starting peerlist task...");
        loop {
            sleep(Duration::from_secs(P2P_EXTEND_PEERLIST_DELAY)).await;
            if !self.is_running() {
                debug!("Peerlist loop task is stopped!");
                break;
            }

            if self.accept_new_connections().await {
                let peer = {
                    trace!("Locking peer list write mode (peerlist loop)");
                    match self.peer_list.find_peer_to_connect().await {
                        Ok(peer) => peer,
                        Err(e) => {
                            error!("Error while finding peer to connect: {}", e);
                            None
                        }
                    }
                };
                trace!("End locking peer list write mode (peerlist loop)");

                if let Some(addr) = peer {
                    debug!("Found peer {}", addr);
                    self.try_to_connect_to_peer(addr, false).await;
                } else {
                    trace!("No peer found to connect to");
                }
            }
        }
    }

    // This function is used to broadcast PeerDisconnected event to listeners
    // We use a channel to avoid having to pass the Blockchain<S> to the Peerlist & Peers
    async fn event_loop(self: Arc<Self>, mut receiver: Receiver<Arc<Peer>>) {
        debug!("Starting event loop task...");
        let mut server_exit = self.exit_sender.subscribe();

        loop {
            select! {
                _ = server_exit.recv() => {
                    debug!("Exit message received, stopping event loop task");
                    break;
                },
                peer = receiver.recv() => {
                    if let Some(peer) = peer {
                        if peer.sharable() {
                            if let Some(rpc) = self.blockchain.get_rpc().read().await.as_ref() {
                                if rpc.is_event_tracked(&NotifyEvent::PeerDisconnected).await {
                                    debug!("Notifying clients with PeerDisconnected event");
                                    rpc.notify_clients_with(&NotifyEvent::PeerDisconnected, get_peer_entry(&peer).await).await;
                                }
                            }
                        }
                    } else {
                        debug!("No more events to notify, stopping event loop task");
                        break;
                    }
                }

            }
        }
        debug!("Event loop task is stopped!");
    }

    // Task for all blocks propagation
    async fn blocks_processing_task(self: Arc<Self>, mut receiver: Receiver<(Arc<Peer>, BlockHeader, Hash)>) {
        debug!("Starting blocks processing task");
        let mut server_exit = self.exit_sender.subscribe();

        'main: loop {
            select! {
                biased;
                _ = server_exit.recv() => {
                    debug!("Exit message received, stopping blocks processing task");
                    break 'main;
                }
                msg = receiver.recv() => {
                    let Some((peer, header, block_hash)) = msg else {
                        debug!("No more blocks to process, stopping blocks processing task");
                        break 'main;
                    };

                    let mut transactions = Vec::with_capacity(header.get_txs_count());
                    let mut futures = FuturesOrdered::new();
                    for hash in header.get_txs_hashes() {
                        if let Ok(tx) = self.blockchain.get_tx(hash).await {
                            transactions.push(Some(tx));
                        } else {
                            // request it from peer
                            let hash = hash.clone();
                            let fut = async {
                                let mut listener = self.object_tracker.request_object_from_peer_with_or_get_notified(Arc::clone(&peer), ObjectRequest::Transaction(hash), None).await?;
                                let response = listener.recv().await.context("Error while reading transaction for block")?;
                                match response {
                                    OwnedObjectResponse::Transaction(tx, _) => Ok(tx),
                                    _ => Err(P2pError::ExpectedTransaction(response))
                                }
                            };
                            futures.push_back(fut);
                            transactions.push(None);
                        }
                    }

                    let mut txs = Vec::with_capacity(header.get_txs_count());
                    for (tx, tx_hash) in transactions.into_iter().zip(header.get_txs_hashes()) {
                        match tx {
                            Some(tx) => {
                                txs.push(Immutable::Arc(tx));
                            },
                            None => {
                                if let Some(response) = futures.next().await {
                                    match response {
                                        Ok(tx) => {
                                            txs.push(Immutable::Owned(tx));
                                        },
                                        Err(e) => {
                                            error!("Error on block tx {}: {}", tx_hash, e);
                                            continue 'main;
                                        }
                                    };
                                }
                            }
                        }
                    }

                    // Mark the timestamp of when its being added
                    {
                        debug!("Locking blocks propagation queue to mark the execution timestamp for {}", block_hash);
                        let mut blocks_propagation_queue = self.blocks_propagation_queue.lock().await;
                        match blocks_propagation_queue.peek_mut(&block_hash) {
                            Some(v) => {
                                *v = Some(get_current_time_in_millis());
                            },
                            None => {
                                warn!("Block propagation {} not found in queue, are we overloaded?", block_hash);
                            }
                        }
                    }

                    // add immediately the block to chain as we are synced with
                    let block = Block::new(Immutable::Owned(header), txs);
                    debug!("Adding received block {} from {} to chain", block_hash, peer);
                    if let Err(e) = self.blockchain.add_new_block(block, true, false).await {
                        error!("Error while adding new block from {}: {}", peer, e);
                        peer.increment_fail_count();
                    }
                }
            }
        }

        debug!("Blocks processing task ended");
    }

    // Task for all transactions propagation
    async fn txs_processing_task(self: Arc<Self>, mut receiver: Receiver<(Arc<Peer>, Arc<Hash>)>) {
        debug!("Starting txs processing task");
        let mut server_exit = self.exit_sender.subscribe();
        let mut futures = FuturesOrdered::new();

        'main: loop {
            select! {
                biased;
                _ = server_exit.recv() => {
                    debug!("Exit message received, stopping txs processing task");
                    break 'main;
                }
                Some((peer, hash)) = receiver.recv() => {
                    // We may have lagged by waiting on previous request, lets double check that its not in chain already
                    let has_tx = match self.blockchain.has_tx(&hash).await {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Error while double checking if TX {} was already included: {}", hash, e);
                            continue;
                        }
                    };

                    if has_tx {
                        debug!("TX {} is already in chain, mostly due to lag on previous request, skipping it", hash);
                        continue;
                    }

                    debug!("Adding TX {} from {} to futures queue", hash, peer);

                    let future = async move {
                        debug!("Requesting from txs processing task tx {}", hash);
                        // TODO
                        let (transaction, hash2) = match peer.request_blocking_object(ObjectRequest::Transaction(hash.as_ref().clone())).await {
                            Ok(OwnedObjectResponse::Transaction(tx, hash)) => (tx, hash),
                            Ok(response) => {
                                warn!("Received invalid object type response from {}", peer);
                                peer.increment_fail_count();
                                return Err(P2pError::ExpectedTransaction(response))
                            },
                            Err(e) => {
                                peer.increment_fail_count();
                                return Err(e)
                            }
                        };

                        debug_assert!(hash.as_ref() == &hash2, "Hash mismatch between request and response");

                        Ok((transaction, hash))
                    };

                    futures.push_back(future);
                },
                Some(res) = futures.next() => {
                    match res {
                        Ok((transaction, hash)) => {
                            debug!("Adding TX to mempool from processing TX task: {}", hash);
                            if let Err(e) = self.blockchain.add_tx_to_mempool_with_hash(transaction, Immutable::Arc(hash.clone()), true).await {
                                warn!("Couldn't add processed TX {}: {}", hash, e);
                            }
                        },
                        Err(e) => {
                            error!("Error while handling TX: {}", e);
                        }
                    }
                }
            }
        }

        debug!("Blocks processing task ended");
    }

    // this function handle the logic to send all packets to the peer
    async fn handle_connection_write_side(&self, peer: &Arc<Peer>, rx: &mut Rx, mut task_rx: oneshot::Receiver<()>) -> Result<(), P2pError> {
        let mut server_exit = self.exit_sender.subscribe();
        let mut peer_exit = peer.get_exit_receiver();
        let mut interval = interval(Duration::from_secs(P2P_HEARTBEAT_INTERVAL));
        loop {
            select! {
                biased;
                // exit message from the read task
                _ = &mut task_rx => {
                    trace!("Exit message received from read task for peer {}", peer);
                    break;
                },
                _ = server_exit.recv() => {
                    trace!("Exit message from server received for peer {}", peer);
                    break;
                },
                _ = peer_exit.recv() => {
                    debug!("Peer {} has exited, stopping...", peer);
                    break;
                },
                _ = interval.tick() => {
                    trace!("Checking heartbeat of {}", peer);
                    // Last time we got a ping packet from him
                    let last_ping = peer.get_last_ping();
                    if last_ping != 0 && get_current_time_in_seconds() - last_ping > P2P_PING_TIMEOUT {
                        debug!("{} has not sent a ping packet for {} seconds, closing connection...", peer, P2P_PING_TIMEOUT);
                        break;
                    }
                },
                // all packets to be sent to the peer are received here
                Some(bytes) = rx.recv() => {
                    // there is a overhead of 4 for each packet (packet size u32 4 bytes, packet id u8 is counted in the packet size)
                    trace!("Sending packet with real length: {}", bytes.len());
                    trace!("Packet id #{} : {:?}", bytes[0], bytes);
                    peer.get_connection().send_bytes(&bytes).await?;
                    trace!("data sucessfully sent!");
                }
            }
        }
        Ok(())
    }

    // This function is a separated task with its own buffer (1kB) to read and handle every packets from the peer sequentially
    async fn handle_connection_read_side(self: &Arc<Self>, peer: &Arc<Peer>, mut write_task: JoinHandle<()>) -> Result<(), P2pError> {
        // allocate the unique buffer for this connection
        let mut buf = [0u8; 1024];
        let mut server_exit = self.exit_sender.subscribe();
        let mut peer_exit = peer.get_exit_receiver();
        loop {
            select! {
                biased;
                _ = server_exit.recv() => {
                    trace!("Exit message received for peer {}", peer);
                    break;
                },
                _ = peer_exit.recv() => {
                    debug!("Peer {} has exited, stopping...", peer);
                    break;
                },
                _ = &mut write_task => {
                    debug!("write task for {} has finished, stopping...", peer);
                    break;
                },
                res = self.listen_connection(&mut buf, &peer) => {
                    res?;

                    // check that we don't have too many fails
                    // otherwise disconnect peer
                    // Priority nodes are not disconnected
                    if peer.get_fail_count() >= PEER_FAIL_LIMIT && !peer.is_priority() {
                        warn!("High fail count detected for {}! Closing connection...", peer);
                        if let Err(e) = peer.close_and_temp_ban().await {
                            error!("Error while trying to close connection with {} due to high fail count: {}", peer, e);
                        }
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    // this function handle the whole connection with a peer
    // create a task for each part (reading and writing)
    // so we can do both at the same time without blocking / waiting on other part when important traffic
    async fn handle_connection(self: &Arc<Self>, peer: Arc<Peer>, mut rx: Rx) -> Result<(), P2pError> {
        trace!("handle connection of {}", peer);
        // task for writing to peer

        let (write_tx, write_rx) = oneshot::channel();
        let write_task = {
            let zelf = Arc::clone(self);
            let peer = Arc::clone(&peer);
            spawn_task(format!("p2p-handle-write-{}", peer.get_connection().get_address()), async move {
                peer.set_write_task_state(TaskState::Active).await;

                let addr = *peer.get_connection().get_address();
                trace!("Handle connection write side task for {} has been started", addr);
                if let Err(e) = zelf.handle_connection_write_side(&peer, &mut rx, write_rx).await {
                    debug!("Error while writing to {}: {}", peer, e);
                }

                peer.set_write_task_state(TaskState::Exiting).await;

                // clean shutdown
                rx.close();

                debug!("Closing {} from write task", peer);
                if let Err(e) = peer.close().await {
                    debug!("Error while closing connection for {} from write task: {}", peer, e);
                }

                peer.set_write_task_state(TaskState::Finished).await;
                debug!("Handle connection write side task for {} has been finished", addr);
            })
        };

        // task for reading from peer
        {
            let zelf = Arc::clone(&self);
            let peer = Arc::clone(&peer);
            spawn_task(format!("p2p-handle-read-{}", peer.get_connection().get_address()), async move {
                peer.set_read_task_state(TaskState::Active).await;
                let addr = *peer.get_connection().get_address();
                trace!("Handle connection read side task for {} has been started", addr);
                if let Err(e) = zelf.handle_connection_read_side(&peer, write_task).await {
                    debug!("Error while running read part from {}: {}", peer, e);

                    peer.set_read_task_state(TaskState::Exiting).await;

                    // Verify that the connection is closed
                    // Write task should be responsible for closing the connection
                    if write_tx.send(()).is_err() {
                        debug!("Write task has already exited, closing connection for {}", peer);
                    }
                }

                peer.set_read_task_state(TaskState::Finished).await;

                debug!("Handle connection read side task for {} has been finished", addr);
            });
        }

        // verify that we are synced with him to receive all TXs correctly
        let our_topoheight = self.blockchain.get_topo_height();
        let peer_topoheight = peer.get_topoheight();
        if peer_topoheight == our_topoheight {
            if let Err(e) = self.request_inventory_of(&peer).await {
                warn!("Error while requesting inventory of {}: {}", peer, e);
            }
        }

        Ok(())
    }

    // Returns the list of all common peers we have between Peer and us
    // TODO fix common peers detection
    // Problem is:
    // We are connected to node A and node B, we know that they are connected each other
    // But they may not already shared their peerlist about us so they don't know we are
    // a common peer between them two, which result in false positive in our case and they send
    // us both the same object
    async fn get_common_peers_for<'a>(&'a self, peer: &'a Arc<Peer>) -> impl Stream<Item = Arc<Peer>> + 'a {
        debug!("get common peers for {}", peer);
        trace!("locked peer_list, locking peers received (common peers)");
        let peer_peers = {
            let lock = peer.get_peers().lock().await;
            lock.clone()
        };
        trace!("locked peers received (common peers)");

        let peer_id = peer.get_id();
        stream::iter(peer_peers)
            .filter_map(move |(addr, _)| {
                let peer_list = Arc::clone(&self.peer_list);
                async move {
                    peer_list.get_peer_by_addr(&addr).await
                        .filter(|peer| peer.get_id() != peer_id)
                }
            })
    }

    // Main function used by every nodes connections
    // This is handling each packet available in our p2p protocol
    // Each packet is a enum variant
    async fn handle_incoming_packet(self: &Arc<Self>, peer: &Arc<Peer>, packet: Packet<'_>) -> Result<(), P2pError> {
        match packet {
            Packet::Handshake(_) => {
                error!("{} sent us handshake packet (not valid!)", peer);
                peer.close().await?;
                return Err(P2pError::InvalidPacket)
            },
            Packet::KeyExchange(key) => {
                trace!("{}: Rotate key packet", peer);
                let key = key.into_owned();
                peer.get_connection().rotate_peer_key(key).await?;
            },
            Packet::TransactionPropagation(packet_wrapper) => {
                trace!("{}: Transaction Propagation packet", peer);
                let (hash, ping) = packet_wrapper.consume();
                let hash = Arc::new(hash.into_owned());

                ping.into_owned().update_peer(peer, &self.blockchain).await?;

                // peer should not send us twice the same transaction
                debug!("Received tx hash {} from {}", hash, peer.get_outgoing_address());
                {
                    let mut txs_cache = peer.get_txs_cache().lock().await;

                    if let Some((direction, is_common)) = txs_cache.get_mut(&hash) {
                        if !direction.update(Direction::In) && !*is_common {
                            warn!("{} send us a transaction ({}) already tracked by him ({:?})", peer, hash, direction);
                            return Err(P2pError::AlreadyTrackedTx(hash.as_ref().clone(), *direction))
                        }
                    } else {
                        txs_cache.put(hash.clone(), (Direction::In, false));
                    }
                }

                // Avoid sending the TX propagated to a common peer
                // because we track peerlist of each peers, we can try to determinate it
                // iterate over all common peers of this peer broadcaster
                self.get_common_peers_for(&peer).await
                    .for_each_concurrent(self.stream_concurrency, |common_peer| {
                        let hash = &hash;
                        async move {
                            debug!("{} is a common peer with {}, adding TX {} to its cache", common_peer, peer, hash);
                            let mut txs_cache = common_peer.get_txs_cache().lock().await;
                            if !txs_cache.contains(hash) {
                                debug!("Adding TX {} to common peer {} cache", hash, common_peer);
                                // Set it as Out so we don't send it anymore but we can get it one time in case of bad common peer prediction
                                txs_cache.put(hash.clone(), (Direction::In, true));
                            }
                        }
                    }).await;

                // Check that the tx is not in mempool or on disk already
                if self.blockchain.has_tx(&hash).await? {
                   debug!("TX {} propagated is already in chain", hash);
                   return Ok(())
                }

                // Check that we are not already waiting on it
                {
                    let mut txs_propagation_queue = self.txs_propagation_queue.lock().await;
                    if txs_propagation_queue.contains(&hash) {
                        debug!("TX {} propagated is already in processing from another peer", hash);
                        return Ok(())
                    }
                    txs_propagation_queue.put(hash.clone(), get_current_time_in_millis());
                }

                let peer = Arc::clone(peer);
                // This will block the task if the bounded channel is full
                debug!("Pushing TX {} in txs processor channel", hash);
                if let Err(e) = self.txs_processor.send((peer, hash)).await {
                    error!("Error while sending block propagated to blocks processor task: {}", e);
                }
            },
            Packet::BlockPropagation(packet_wrapper) => {
                trace!("Received a block propagation packet from {}", peer);
                let (header, ping) = packet_wrapper.consume();
                ping.into_owned().update_peer(peer, &self.blockchain).await?;

                // check that the block height is valid
                let header = header.into_owned();
                let block_hash = header.hash();

                trace!("Received block {}", block_hash);

                // verify that this block wasn't already sent by him
                let direction = TimedDirection::In {
                    received_at: get_current_time_in_millis()
                };

                {
                    let mut blocks_propagation = peer.get_blocks_propagation().lock().await;
                    if let Some((origin, is_common)) = blocks_propagation.get_mut(&block_hash) {
                        if !origin.update(direction) && !*is_common {
                            warn!("{} send us a block ({}) already tracked by him ({:?} {})", peer, block_hash, origin, is_common);
                            return Err(P2pError::AlreadyTrackedBlock(block_hash, *origin))
                        }
                    } else {
                        debug!("Saving {} in blocks propagation cache for {}", block_hash, peer);
                        blocks_propagation.put(block_hash.clone(),  (direction, false));
                    }
                }

                // Avoid sending the same block to a common peer that may have already got it
                // because we track peerlist of each peers, we can try to determinate it
                self.get_common_peers_for(&peer).await
                    .for_each_concurrent(self.stream_concurrency, |common_peer| {
                        let block_hash = &block_hash;
                        async move {
                            debug!("{} is a common peer with {}, adding block {} to its cache", common_peer, peer, block_hash);
                            let mut blocks_propagation = common_peer.get_blocks_propagation().lock().await;
                            if !blocks_propagation.contains(block_hash) {
                                debug!("Adding block {} to common peer {} cache", block_hash, common_peer);
                                // Out allow to get "In" again, because it's a prediction, don't block it completely
                                blocks_propagation.put(block_hash.clone(), (direction, true));
                            }
                        }
                    }).await;

                // check that we don't have this block in our chain
                {
                    let storage = self.blockchain.get_storage().read().await;
                    if storage.has_block_with_hash(&block_hash).await? {
                        debug!("{}: {} with hash {} is already in our chain. Skipping", peer, header, block_hash);
                        return Ok(())
                    }
                }

                // Check that we are not already waiting on it
                {
                    let mut blocks_propagation_queue = self.blocks_propagation_queue.lock().await;
                    if blocks_propagation_queue.contains(&block_hash) {
                        debug!("Block {} propagated is already in processing from another peer", block_hash);
                        return Ok(())
                    }
                    blocks_propagation_queue.put(block_hash.clone(), None);
                }

                debug!("Received block at height {} from {}", header.get_height(), peer);
                if self.allow_priority_blocks && peer.is_priority() {
                    debug!("fast propagating block {} from {}", block_hash, peer);

                    let zelf = Arc::clone(self);
                    let block_hash = block_hash.clone();
                    let header = header.clone();

                    spawn_task("p2p-broadcast-priority-block", async move {
                        debug!("building generic ping packet for priority block");
                        match zelf.build_generic_ping_packet().await {
                            Ok(mut ping) => {
                                // We provide the highest height available
                                ping.set_height(header.get_height().max(ping.get_height()));

                                debug!("broadcasting priority block {} with ping packet to all peers", block_hash);
                                zelf.broadcast_block_with_ping(
                                    &header,
                                    ping,
                                    &block_hash,
                                    false,
                                    false,
                                ).await;
                            },
                            Err(e) => {
                                error!("Error while trying to broadcast priority block {}: {}", block_hash, e);
                            }
                        }
                    });
                }

                let peer = Arc::clone(peer);

                // This will block the task if the bounded channel is full
                if let Err(e) = self.blocks_processor.send((peer, header, block_hash)).await {
                    error!("Error while sending block propagated to blocks processor task: {}", e);
                }
            },
            Packet::ChainRequest(packet_wrapper) => {
                trace!("Received a chain request from {}", peer);
                let (request, ping) = packet_wrapper.consume();
                ping.into_owned().update_peer(peer, &self.blockchain).await?;
                let request = request.into_owned();
                let last_request = peer.get_last_chain_sync();
                let time = get_current_time_in_seconds();
                // Node is trying to ask too fast our chain
                // Don't allow faster than 1/3 of the delay
                if  last_request + (CHAIN_SYNC_DELAY * 2 / 3) > time {
                    debug!("{} requested sync chain too fast!", peer);
                    return Err(P2pError::RequestSyncChainTooFast)
                }
                peer.set_last_chain_sync(time);

                // at least one block necessary (genesis block)
                let request_size = request.size();
                if request_size == 0 || request_size > CHAIN_SYNC_REQUEST_MAX_BLOCKS { // allows maximum 64 blocks id (2560 bytes max)
                    warn!("{} sent us a malformed chain request ({} blocks)!", peer, request_size);
                    return Err(P2pError::MalformedChainRequest(request_size))
                }

                let mut accepted_response_size = request.get_accepted_response_size() as usize;

                // This can be configured by node operators
                // Verify that the requested size is not bigger than our limit
                if accepted_response_size > self.max_chain_response_size {
                    accepted_response_size = self.max_chain_response_size;
                }

                let blocks = request.get_blocks();
                self.handle_chain_request(&peer, blocks, accepted_response_size).await?;
            },
            Packet::ChainResponse(response) => {
                trace!("Received a chain response from {}", peer);
                let sender = peer.get_sync_chain_channel()
                    .lock().await
                    .take()
                    .ok_or(P2pError::UnrequestedChainResponse)?;

                if sender.send(response).is_err() {
                    error!("Error while sending chain response to channel of {}", peer);
                }
            },
            Packet::Ping(ping) => {
                trace!("Received a ping packet from {}", peer);
                let current_time = get_current_time_in_seconds();
                let empty_peer_list = ping.get_peers().is_empty();

                // update the last ping only if he respect the protocol rules
                peer.set_last_ping(current_time);

                // we verify the respect of the countdown of peer list updates to prevent any spam
                if !empty_peer_list {
                    trace!("received peer list from {}: {}", peer, ping.get_peers().len());
                    let last_peer_list = peer.get_last_peer_list();
                    let diff = current_time - last_peer_list;
                    // Don't allow faster than 1/3 of the delay (because of connection latency / packets being queued)
                    if last_peer_list != 0 && diff < (P2P_PING_PEER_LIST_DELAY * 2 / 3) {
                        return Err(P2pError::PeerInvalidPeerListCountdown(P2P_PING_PEER_LIST_DELAY - diff))
                    }
                    peer.set_last_peer_list(current_time);
                }

                {
                    let is_local_peer = is_local_address(peer.get_connection().get_address());
                    for addr in ping.get_peers() {
                        if (is_local_address(addr) && !is_local_peer) || !is_valid_address(addr) {
                            error!("{} is a local address from {} but peer is external", addr, peer);
                            return Err(P2pError::InvalidPeerlist)
                        }

                        if !self.is_connected_to_addr(addr).await && !self.peer_list.has_peer_stored(&addr.ip()).await? {
                            if !self.peer_list.store_peer_address(*addr).await? {
                                debug!("{} already stored in peer list", addr);
                            }
                        }
                    }
                }

                ping.into_owned().update_peer(peer, &self.blockchain).await?;
            },
            Packet::ObjectRequest(request) => {
                trace!("Received a object request from {}", peer);
                let request = request.into_owned();
                match &request {
                    ObjectRequest::Block(hash) => {
                        debug!("{} asked full block {}", peer, hash);
                        let block = {
                            let storage = self.blockchain.get_storage().read().await;
                            storage.get_block_by_hash(hash).await
                        };

                        match block {
                            Ok(block) => {
                                debug!("block {} found, sending it", hash);
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::Block(Cow::Borrowed(&block)))).await?;
                            },
                            Err(e) => {
                                debug!("{} asked block '{}' but not present in our chain: {}", peer, hash, e);
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::NotFound(request))).await?;
                            }
                        };
                    },
                    ObjectRequest::BlockHeader(hash) => {
                        debug!("{} asked block header {}", peer, hash);
                        let block = {
                            let storage = self.blockchain.get_storage().read().await;
                            storage.get_block_header_by_hash(hash).await
                        };

                        match block {
                            Ok(block) => {
                                debug!("block header {} found, sending it", hash);
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::BlockHeader(Cow::Borrowed(&block)))).await?;
                            },
                            Err(e) => {
                                debug!("{} asked block header '{}' but not present in our chain: {}", peer, hash, e);
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::NotFound(request))).await?;
                            }
                        };
                    },
                    ObjectRequest::Transaction(hash) => {
                        debug!("{} asked tx {}", peer, hash);
                        match self.blockchain.get_tx(hash).await {
                            Ok(tx) => {
                                debug!("tx {} found, sending it", hash);
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::Transaction(Cow::Borrowed(&tx)))).await?;
                            },
                            Err(e) => {
                                debug!("{} asked tx '{}' but not present in our chain: {}", peer, hash, e);
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::NotFound(request))).await?;
                            }
                        }
                    }
                }
            },
            Packet::ObjectResponse(response) => {
                trace!("Received a object response from {}", peer);
                let response = response.to_owned();
                trace!("Object response received is {}", response.get_hash());

                // check if we requested it from this peer directly
                // or that we requested it through the object tracker
                let request = response.get_request();
                if peer.has_requested_object(&request).await {
                    let sender = peer.remove_object_request(request).await?;
                    // handle the response
                    if sender.send(response).is_err() {
                        error!("Error while sending object response to sender!");
                    }
                } else if !self.object_tracker.handle_object_response(response).await? {
                    return Err(P2pError::ObjectNotRequested(request))
                }
            },
            Packet::NotifyInventoryRequest(packet_wrapper) => {
                trace!("Received a inventory request from {}", peer);
                let (request, ping) = packet_wrapper.consume();
                ping.into_owned().update_peer(peer, &self.blockchain).await?;

                let request = request.into_owned();

                let page_id = request.page().unwrap_or(0);
                let skip = page_id as usize * NOTIFY_MAX_LEN;

                let packet = {
                    let mempool = self.blockchain.get_mempool().read().await;
                    let nonces_cache = mempool.get_caches();
                    let txs = nonces_cache.values()
                        .flat_map(|v| v.get_txs())
                        .skip(skip).take(NOTIFY_MAX_LEN)
                        .map(|tx| Cow::Borrowed(tx.as_ref()))
                        .collect::<IndexSet<_>>();
                    let mempool_size = mempool.size();
                    let next_page = {
                        if txs.len() == NOTIFY_MAX_LEN && mempool_size > skip && mempool_size - skip > NOTIFY_MAX_LEN {
                            Some(page_id + 1)
                        } else {
                            None
                        }
                    };
                    Packet::NotifyInventoryResponse(NotifyInventoryResponse::new(next_page, Cow::Owned(txs))).to_bytes()
                };

                trace!("Sending inventory response to {}", peer);
                peer.send_bytes(Bytes::from(packet)).await?;
            },
            Packet::NotifyInventoryResponse(inventory) => {
                debug!("Received a notify inventory from {}: {} txs", peer, inventory.len());
                if !peer.has_requested_inventory() {
                    warn!("Received a notify inventory from {} but we didn't request it", peer);
                    return Err(P2pError::InvalidPacket)
                }

                // we received the inventory
                peer.set_requested_inventory(false);
                peer.set_last_inventory(get_current_time_in_seconds());

                let next_page = inventory.next();
                let txs = inventory.get_txs();
                let total_count = txs.len();

                // check that the response was really full if he send us another "page"
                if next_page.is_some() {
                    if total_count != NOTIFY_MAX_LEN {
                        error!("Received only {} while maximum is {} elements, and tell us that there is another page", total_count, NOTIFY_MAX_LEN);
                        return Err(P2pError::InvalidInventoryPagination)
                    }
                }

                // Process the response
                for tx in txs.into_owned() {
                    let tx = Arc::new(tx.into_owned());

                    // Check that the tx is not in mempool or on disk already
                    if self.blockchain.has_tx(&tx).await? {
                        debug!("TX {} from inventory response is already in chain", tx);
                        continue;
                    }

                    // Check current cache
                    // We lock each time in case we're blocked by the channel below
                    {
                        let mut cache = self.txs_propagation_queue.lock().await;
                        if cache.contains(&tx) {
                            debug!("Skipping TX {} from being requested as its in propagation queue already", tx);
                            continue;
                        }

                        cache.put(tx.clone(), get_current_time_in_millis());
                    }

                    if let Err(e) = self.txs_processor.send((Arc::clone(peer), tx)).await {
                        error!("Error while sending to TXs processor task from inventory response of {}: {}", peer, e);
                        peer.increment_fail_count();
                        return Ok(())
                    }
                }

                // request the next page
                if next_page.is_some() {
                    trace!("Requesting next page of inventory from {}", peer);
                    let packet = Cow::Owned(NotifyInventoryRequest::new(next_page));
                    let ping = Cow::Owned(self.build_generic_ping_packet().await?);
                    peer.set_requested_inventory(true);
                    peer.send_packet(Packet::NotifyInventoryRequest(PacketWrapper::new(packet, ping))).await?;
                }
            },
            Packet::BootstrapChainRequest(request) => {
                self.handle_bootstrap_chain_request(peer, request.step()).await?;
            },
            Packet::BootstrapChainResponse(response) => {
                debug!("Received a bootstrap chain response ({:?}) from {}", response.kind(), peer);
                if let Some(sender) = peer.get_bootstrap_chain_channel().lock().await.take() {
                    trace!("Sending bootstrap chain response ({:?})", response.kind());
                    let response = response.response();
                    if let Err(e) = sender.send(response) {
                        error!("Error while sending bootstrap response to channel: {:?}", e.kind());
                    }
                } else {
                    debug!("{} send us a bootstrap chain response of step {:?} but we didn't asked it", peer, response.kind());
                    return Err(P2pError::UnrequestedBootstrapChainResponse)
                }
            },
            Packet::PeerDisconnected(packet) => {
                // This packet is used to keep sync between peers being shared
                let addr = packet.to_addr();
                debug!("{} disconnected from {}", addr, peer);
                {
                    let mut shared_peers = peer.get_peers().lock().await;
                    if shared_peers.pop(&addr).is_none() {
                        debug!("{} disconnected from {} but its not in our shared peer, maybe it disconnected from us too", addr, peer.get_outgoing_address());
                        return Ok(())
                    }
                }

                if peer.sharable() {
                    trace!("Locking RPC Server to notify PeerDisconnected event");
                    if let Some(rpc) = self.blockchain.get_rpc().read().await.as_ref() {
                        if rpc.is_event_tracked(&NotifyEvent::PeerPeerDisconnected).await {
                            let value = PeerPeerDisconnectedEvent {
                                peer_id: peer.get_id(),
                                peer_addr: addr
                            };
                            rpc.notify_clients_with(&NotifyEvent::PeerPeerDisconnected, value).await;
                        }
                    }
                    trace!("End locking for PeerDisconnected event");
                }
            }
        };
        Ok(())
    }

    // Listen to incoming packets from a connection
    // Packet is read from the same task always, while its handling is delegated to a unique task
    async fn listen_connection(self: &Arc<Self>, buf: &mut [u8], peer: &Arc<Peer>) -> Result<(), P2pError> {
        // Read & parse the packet
        // 16 additional bytes are for AEAD
        let packet = peer.get_connection().read_packet(buf, PEER_MAX_PACKET_SIZE).await?;
        let packet_id = packet.get_id();
        // Handle the packet
        if let Err(e) = self.handle_incoming_packet(&peer, packet).await {
            match e {
                P2pError::Disconnected => {
                    debug!("Peer {} has disconnected, stopping...", peer);
                    return Err(e)
                },
                P2pError::SendError(_) => {
                    debug!("Error while sending packet to peer: {}", e);
                    return Err(e)
                },
                e => {
                    error!("Error occured while handling incoming packet #{} from {}: {}", packet_id, peer, e);
                    peer.increment_fail_count();
                }
            }
        }

        Ok(())
    }

    // Search a common point between us and the peer chain
    // For this we have a list of block id which is basically block hash + its topoheight
    // BlockId list should be in descending order (higher topoheight first)
    async fn find_common_point(&self, storage: &S, blocks: IndexSet<BlockId>) -> Result<Option<CommonPoint>, P2pError> {
        let start_topoheight = if let Some(first) = blocks.first() {
            first.get_topoheight() + 1
        } else {
            warn!("Block id list is empty!");
            return Err(P2pError::InvalidBlockIdList)
        };

        // Verify we have the same genesis block hash
        if let Some(genesis_id) = blocks.last() {
            let our_genesis_hash = storage.get_hash_at_topo_height(0).await?;
            if *genesis_id.get_hash() != our_genesis_hash || genesis_id.get_topoheight() > start_topoheight {
                warn!("Block id list has incorrect block genesis hash! Got {} at {}", genesis_id.get_hash(), genesis_id.get_topoheight());
                return Err(P2pError::InvalidBlockIdList)
            }
        }

        let mut expected_topoheight = start_topoheight;
        // search a common point
        for (i, block_id) in blocks.into_iter().enumerate() {
            // Verify good order of blocks
            // If we already processed genesis block (topo 0) and still have some blocks, it's invalid list
            // If we are in the first CHAIN_SYNC_REQUEST_EXPONENTIAL_INDEX_START blocks, verify the exact good order
            // If we are above it, i = i * 2, start topo - i = expected topoheight
            if expected_topoheight == 0 || (i < CHAIN_SYNC_REQUEST_EXPONENTIAL_INDEX_START && expected_topoheight - 1 != block_id.get_topoheight()) {
                warn!("Block id list has not a good order at index {}, current topo {}, next: {}", i, expected_topoheight, block_id.get_topoheight());
                return Err(P2pError::InvalidBlockIdList) 
            }
            expected_topoheight -= 1;

            debug!("Searching common point for block {} at topoheight {}", block_id.get_hash(), block_id.get_topoheight());
            if storage.has_block_with_hash(block_id.get_hash()).await? {
                let (hash, topoheight) = block_id.consume();
                debug!("Block {} is common, expected topoheight: {}", hash, topoheight);
                // check that the block is ordered like us
                if storage.is_block_topological_ordered(&hash).await && storage.get_topo_height_for_hash(&hash).await? == topoheight { // common point
                    debug!("common point found at block {} with same topoheight at {}", hash, topoheight);
                    return Ok(Some(CommonPoint::new(hash, topoheight)))
                }
            }
        }
        Ok(None)
    }

    // determine if we are connected to a priority node and that this node is equal / greater to our chain
    async fn is_connected_to_a_synced_priority_node(&self) -> bool {
        let topoheight = self.blockchain.get_topo_height();
        trace!("locking peer list for checking if connected to a synced priority node");

        for peer in self.peer_list.get_peers().read().await.values() {
            if peer.is_priority() {
                let peer_topoheight = peer.get_topoheight();
                if peer_topoheight >= topoheight || topoheight - peer_topoheight < STABLE_LIMIT {
                    return true
                }
            }
        }
        false
    }

    // Get the optional tag set 
    pub fn get_tag(&self) -> &Option<String> {
        &self.tag
    }

    // Get the maximum peers count allowed to be connected
    pub fn get_max_peers(&self) -> usize {
        self.max_peers
    }

    // Get our unique peer ID
    pub fn get_peer_id(&self) -> u64 {
        self.peer_id
    }

    // Check if we are accepting new connections by verifying if we have free slots available
    pub async fn accept_new_connections(&self) -> bool {
        self.get_peer_count().await < self.get_max_peers()
    }

    // Returns the count of peers connected
    pub async fn get_peer_count(&self) -> usize {
        self.peer_list.size().await
    }

    // Returns the median topoheight based on all peers
    pub async fn get_median_topoheight_of_peers(&self) -> TopoHeight {
        let topoheight = self.blockchain.get_topo_height();
        self.peer_list.get_median_topoheight(Some(topoheight)).await
    }

    // Returns the best topoheight based on all peers
    pub async fn get_best_topoheight(&self) -> TopoHeight {
        self.peer_list.get_best_topoheight().await
    }

    pub fn is_internal_id(&self, id: u64) -> bool {
        id == self.peer_id
    }

    // Verify if this peer id is already used by a peer
    pub async fn has_peer_id_used(&self, peer_id: &u64) -> bool {
        self.is_internal_id(*peer_id) || self.peer_list.has_peer(peer_id).await
    }

    // Check if we are already connected to a socket address (IPv4 or IPv6) including its port
    pub async fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> bool {
        if *peer_addr == *self.get_bind_address() { // don't try to connect to ourself
            debug!("Trying to connect to ourself, ignoring.");
            return true
        }

        self.peer_list.is_connected_to_addr(peer_addr).await
    }

    // get the socket address on which we are listening
    pub fn get_bind_address(&self) -> &SocketAddr {
        &self.bind_address
    }

    // Get our peerlist
    pub fn get_peer_list(&self) -> &SharedPeerList {
        &self.peer_list
    }

    // Retrieve at which timestamp the block got finally started to be finally executed
    pub async fn get_block_propagation_timestamp(&self, hash: &Hash) -> Option<TimestampMillis> {
        let blocks_propagation_queue = self.blocks_propagation_queue.lock().await;
        blocks_propagation_queue.peek(hash)
            .copied()
            .flatten()
    }

    // Broadcast a new transaction hash using propagation packet
    // This is used so we don't overload the network during spam or high transactions count
    // We simply share its hash to nodes and others nodes can check if they have it already or not
    pub async fn broadcast_tx_hash(&self, tx: Arc<Hash>) {
        debug!("Broadcasting tx hash {}", tx);
        let ping = match self.build_generic_ping_packet().await {
            Ok(ping) => ping,
            Err(e) => {
                error!("Error while building generic ping packet for tx broadcast: {}", e);
                return
            }
        };
        debug!("Ping packet has been generated for tx broadcast");
        let current_topoheight = ping.get_topoheight();
        let packet = Packet::TransactionPropagation(PacketWrapper::new(Cow::Borrowed(&tx), Cow::Owned(ping)));
        // transform packet to bytes (so we don't need to transform it for each peer)
        let bytes = Bytes::from(packet.to_bytes());
        trace!("Locking peer list for tx broadcast");
        let peers = self.peer_list.get_cloned_peers().await;
        trace!("Lock acquired for tx broadcast");

        stream::iter(peers).for_each_concurrent(self.stream_concurrency, |peer| {
            // Move the references only
            let bytes = &bytes;
            let tx = &tx;

            async move {
                // check that the peer is not too far from us
                // otherwise we may spam him for nothing
                let peer_topoheight = peer.get_topoheight();
                if (peer_topoheight >= current_topoheight && peer_topoheight - current_topoheight < STABLE_LIMIT) || (current_topoheight >= peer_topoheight && current_topoheight - peer_topoheight < STABLE_LIMIT) {
                    trace!("Peer {} is not too far from us, checking cache for tx hash {}", peer, tx);

                    // Do not keep the txs cache lock while sending the packet
                    let send = {
                        let mut txs_cache = peer.get_txs_cache().lock().await;
                        trace!("Cache locked for tx hash {}", tx);
                        let send = !txs_cache.contains(tx);
                        // check that we didn't already send this tx to this peer or that he don't already have it
                        if send {
                            trace!("Adding tx hash {} to cache for {}", tx, peer);
                            // Set it as outgoing
                            txs_cache.put(tx.clone(), (Direction::Out, false));
                        } else {
                            trace!("Peer {} already has tx hash {}, don't send it", peer, tx);
                        }

                        send
                    };

                    if send {
                        trace!("Broadcasting tx hash {} to {}", tx, peer);
                        if let Err(e) = peer.send_bytes(bytes.clone()).await {
                            error!("Error while broadcasting tx hash {} to {}: {}", tx, peer, e);
                        }
                    }
                }
            }
        }).await;
    }

    // broadcast block to all peers that can accept directly this new block
    pub async fn broadcast_block(&self, block: &BlockHeader, cumulative_difficulty: CumulativeDifficulty, our_topoheight: u64, our_height: u64, pruned_topoheight: Option<u64>, hash: &Hash, lock: bool) {
        debug!("Building the ping packet for broadcast block {}", hash);
        // we build the ping packet ourself this time (we have enough data for it)
        // because this function can be call from Blockchain, which would lead to a deadlock
        let ping = Ping::new(Cow::Borrowed(hash), our_topoheight, our_height, pruned_topoheight, cumulative_difficulty, IndexSet::new());
        self.broadcast_block_with_ping(block, ping, hash, lock, true).await;
    }

    // Broadcast a block with a pre-built ping packet
    pub async fn broadcast_block_with_ping(&self, block: &BlockHeader, ping: Ping<'_>, hash: &Hash, lock: bool, send_ping: bool) {
        debug!("Broadcasting block {} at height {}", hash, block.get_height());

        // Build the block propagation packet
        let block_packet = Packet::BlockPropagation(PacketWrapper::new(Cow::Borrowed(block), Cow::Borrowed(&ping)));
        let packet_block_bytes = Bytes::from(block_packet.to_bytes());
        let packet_ping_bytes = Bytes::from(Packet::Ping(Cow::Owned(ping)).to_bytes());

        // Lock the block from being handled again as we are broadcasting it
        if lock {
            debug!("Locking block propagation {}", hash);
            let mut blocks_propagation_queue = self.blocks_propagation_queue.lock().await;
            blocks_propagation_queue.put(hash.clone(), Some(get_current_time_in_millis()));
        }

        trace!("start broadcasting block {} to all peers", hash);
        // Prepare all the futures to execute them in parallel
        stream::iter(self.peer_list.get_cloned_peers().await)
            .for_each_concurrent(self.stream_concurrency, |peer| {
                // We can't move them, but we can copy them as Bytes is cheap
                let packet_block_bytes = &packet_block_bytes;
                let packet_ping_bytes = &packet_ping_bytes;

                async move {
                    // if the peer can directly accept this new block, send it
                    let peer_height = peer.get_height();

                    // if the peer is not too far from us, send the block
                    // check that peer height is greater or equal to block height but still under or equal to STABLE_LIMIT
                    // or, check that peer height as difference of maximum 1 block
                    // (block height is always + 1 above the highest tip height, so we can just check that peer height is not above block height + 1, it's enough in 90% of time)
                    // chain can accept old blocks (up to STABLE_LIMIT) but new blocks only N+1
                    if (peer_height >= block.get_height() && peer_height - block.get_height() <= STABLE_LIMIT) || (peer_height <= block.get_height() && block.get_height() - peer_height <= 1) {
                        // Don't lock the blocks propagation while sending the packet
                        let send_block = {
                            trace!("locking blocks propagation for peer {}", peer);
                            let mut blocks_propagation = peer.get_blocks_propagation().lock().await;
                            trace!("end locking blocks propagation for peer {}", peer);
                            let send = !blocks_propagation.contains(hash);
                            // check that this block was never shared with this peer
                            if send {
                                // we broadcasted to him, add it to the cache
                                // he should not send it back to us if it's a block found by us
                                // Because only us is aware of this block
                                let direction = if lock {
                                    TimedDirection::Both {
                                        sent_at: get_current_time_in_millis(),
                                        // Never received, but locked
                                        received_at: 0
                                    }
                                } else {
                                    TimedDirection::Out {
                                        sent_at: get_current_time_in_millis()
                                    }
                                };
                                blocks_propagation.put(hash.clone(), (direction, false));
                            }

                            send
                        };

                        if send_block {
                            debug!("Broadcast {} to {}", hash, peer);
                            if let Err(e) = peer.send_bytes(packet_block_bytes.clone()).await {
                                debug!("Error on broadcast block {} to {}: {}", hash, peer, e);
                            }
                            trace!("{} has been broadcasted to {}", hash, peer);
                        } else if send_ping {
                            debug!("{} contains {}, don't broadcast block to him", peer, hash);
                            // But we can notify him with a ping packet that we got the block
                            if let Err(e) = peer.send_bytes(packet_ping_bytes.clone()).await {
                                debug!("Error on sending ping for notifying that we accepted the block {} to {}: {}", hash, peer, e);
                            } else {
                                trace!("{} has been notified that we have the block {}", peer, hash);
                                peer.set_last_ping_sent(get_current_time_in_seconds());
                            }
                        }
                    } else if send_ping && peer_height >= block.get_height() {
                        // Peer is above us, send him a ping packet to inform him we got a block propagated
                        if let Err(e) = peer.send_bytes(packet_ping_bytes.clone()).await {
                            debug!("Error on sending ping to peer for notifying that we got the block {} to {}: {}", hash, peer, e);
                        } else {
                            trace!("{} has been notified that we received the block {}", peer, hash);
                            peer.set_last_ping_sent(get_current_time_in_seconds());
                        }
                    } else {
                        // Peer is too far, don't send the block and neither the ping packet
                        debug!("Cannot broadcast {} at height {} to {}, too far", hash, block.get_height(), peer);
                    }
                }
        }).await;

        debug!("broadcasting block {} is done", hash);
    }

    // Build a block id list to share our DAG order and chain state
    // Block id list must be in descending order and unique hash / topoheight
    // This is used to search the common point between two peers
    async fn build_list_of_blocks_id(&self, storage: &S) -> Result<IndexSet<BlockId>, BlockchainError> {
        let mut blocks = IndexSet::new();
        let topoheight = self.blockchain.get_topo_height();
        let pruned_topoheight = storage.get_pruned_topoheight().await?.unwrap_or(0);
        let mut i = 0;

        // we add 1 for the genesis block added below
        trace!("Building list of blocks id for {} blocks, pruned topo: {}", topoheight, pruned_topoheight);
        while i < topoheight && topoheight - i > pruned_topoheight && blocks.len() + 1 < CHAIN_SYNC_REQUEST_MAX_BLOCKS {
            let current_topo = topoheight - i;
            trace!("Requesting hash at topo {} for building list of blocks id", current_topo);
            let hash = storage.get_hash_at_topo_height(current_topo).await?;
            blocks.insert(BlockId::new(hash, current_topo));
            // This parameter can be tuned based on the chain size
            if blocks.len() < CHAIN_SYNC_REQUEST_EXPONENTIAL_INDEX_START {
                i += 1;
            } else {
                i = i * 2;
            }
        }

        // add genesis block
        let genesis_block = storage.get_hash_at_topo_height(0).await?;
        blocks.insert(BlockId::new(genesis_block, 0));
        Ok(blocks)
    }

    // Request the inventory of a peer
    // This will sends him a request packet so we get notified of all its TXs hashes in its mempool
    async fn request_inventory_of(&self, peer: &Arc<Peer>) -> Result<(), BlockchainError> {
        debug!("Requesting inventory of {}", peer);
        let packet = Cow::Owned(NotifyInventoryRequest::new(None));
        let ping = Cow::Owned(self.build_generic_ping_packet().await?);
        peer.set_requested_inventory(true);
        peer.send_packet(Packet::NotifyInventoryRequest(PacketWrapper::new(packet, ping))).await?;
        Ok(())
    }

    // Clear all p2p connections by kicking peers
    pub async fn clear_connections(&self) {
        self.peer_list.close_all().await;
    }
}

// Check if a socket address is a local address
pub fn is_local_address(socket_addr: &SocketAddr) -> bool {
    match socket_addr.ip() {
        IpAddr::V4(ipv4) => {
            // Check if it's a local IPv4 address (e.g., 127.0.0.1)
            ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            // Check if it's a local IPv6 address (e.g., ::1)
            // https://github.com/rust-lang/rust/issues/27709
            ipv6.is_loopback() // || ipv6.is_unique_local()
        }
    }
}

// Check if a socket address is a valid address
// Only public and private addresses that can be used in a network are considered valid
pub fn is_valid_address(socket_addr: &SocketAddr) -> bool {
    match socket_addr.ip() {
        IpAddr::V4(ipv4) => {
            // Check if it's a valid IPv4 address
            !ipv4.is_unspecified() && !ipv4.is_loopback() && !ipv4.is_multicast() && !ipv4.is_documentation() && !ipv4.is_link_local() && !ipv4.is_broadcast()
        }
        IpAddr::V6(ipv6) => {
            // Check if it's a valid IPv6 address
            !ipv6.is_unspecified() && !ipv6.is_loopback() && !ipv6.is_multicast() // && !ipv6.is_documentation() && !ipv6.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::*;

    #[test]
    fn test_is_local_address() {
        assert!(is_local_address(&SocketAddr::from_str("172.20.0.1:2125").unwrap()));
        assert!(!is_local_address(&SocketAddr::from_str("1.1.1.1:2125").unwrap()));
    }
}