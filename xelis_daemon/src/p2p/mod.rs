pub mod connection;
pub mod peer;
pub mod error;
pub mod packet;
pub mod peer_list;
pub mod chain_validator;
mod tracker;
mod encryption;

pub use encryption::EncryptionKey;

use indexmap::IndexSet;
use lru::LruCache;
use xelis_common::{
    account::VersionedNonce,
    api::daemon::{
        Direction,
        NotifyEvent,
        PeerPeerDisconnectedEvent
    },
    block::{Block, BlockHeader, BlockVersion},
    config::{TIPS_LIMIT, VERSION},
    crypto::{Hash, Hashable, PublicKey},
    difficulty::CumulativeDifficulty,
    immutable::Immutable,
    serializer::Serializer,
    tokio::{ThreadPool, spawn_task},
    time::{
        get_current_time_in_millis,
        get_current_time_in_seconds,
        TimestampMillis
    }
};
use crate::{
    config::{
        get_genesis_block_hash,
        get_seed_nodes,
        CHAIN_SYNC_DEFAULT_RESPONSE_BLOCKS, CHAIN_SYNC_DELAY, CHAIN_SYNC_REQUEST_EXPONENTIAL_INDEX_START,
        CHAIN_SYNC_REQUEST_MAX_BLOCKS, CHAIN_SYNC_RESPONSE_MAX_BLOCKS, CHAIN_SYNC_RESPONSE_MIN_BLOCKS,
        CHAIN_SYNC_TOP_BLOCKS, MILLIS_PER_SECOND, NETWORK_ID, P2P_AUTO_CONNECT_PRIORITY_NODES_DELAY,
        P2P_EXTEND_PEERLIST_DELAY, P2P_PING_DELAY, P2P_PING_PEER_LIST_DELAY, P2P_PING_PEER_LIST_LIMIT,
        PEER_FAIL_LIMIT, PEER_MAX_PACKET_SIZE, PEER_TIMEOUT_INIT_CONNECTION, PEER_TIMEOUT_INIT_OUTGOING_CONNECTION,
        PRUNE_SAFETY_LIMIT, STABLE_LIMIT, P2P_PING_TIMEOUT, P2P_HEARTBEAT_INTERVAL
    },
    core::{
        blockchain::Blockchain,
        error::BlockchainError,
        storage::Storage,
        hard_fork::{get_version_at_height, is_version_allowed_at_height}
    },
    p2p::{
        chain_validator::ChainValidator,
        packet::{
            bootstrap_chain::{
                BlockMetadata,
                BootstrapChainResponse,
                StepRequest,
                StepResponse,
                MAX_ITEMS_PER_PAGE
            },
            chain::CommonPoint,
            inventory::{
                NotifyInventoryRequest,
                NotifyInventoryResponse,
                NOTIFY_MAX_LEN
            }
        },
        tracker::ResponseBlocker
    },
    rpc::rpc::get_peer_entry
};
use self::{
    connection::{Connection, State},
    error::P2pError,
    packet::{
        chain::{BlockId, ChainRequest, ChainResponse},
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
    collections::{hash_map::Entry, HashSet},
    io,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc
    },
    time::Duration
};
use bytes::Bytes;
use rand::{seq::IteratorRandom, Rng};

// P2pServer is a fully async TCP server.
// Each connection will block on a data to send or to receive
// making it suitable for low-end hardware.
pub struct P2pServer<S: Storage> {
    // Unique peer id
    peer_id: u64,
    // Node tag sent on handshake
    tag: Option<String>,
    // Max peers accepted by this server
    max_peers: usize,
    // ip:port address to receive connections
    bind_address: SocketAddr,
    // All peers accepted
    peer_list: SharedPeerList,
    // Reference to the chain to add blocks/txs
    blockchain: Arc<Blockchain<S>>,
    // This sender allows to create a queue system in one task only
    connections_sender: Sender<(SocketAddr, bool)>,
    // Used to requests objects to peers and avoid requesting the same object to multiple peers
    object_tracker: SharedObjectTracker,
    // Used to check if the server is running or not in tasks
    is_running: AtomicBool,
    // Synced cache to prevent concurrent tasks adding the block
    blocks_propagation_queue: Mutex<LruCache<Hash, ()>>,
    // Sender for the blocks processing task to have a ordered queue
    blocks_processor: Sender<(Arc<Peer>, BlockHeader, Hash)>,
    // Allow fast syncing (only balances / assets / Smart Contracts changes)
    // without syncing the history.
    allow_fast_sync_mode: bool,
    // This can be used safely from a trusted node
    // to boost the sync speed by allowing the request of several blocks at same time.
    allow_boost_sync_mode: bool,
    // Max size of the chain response.
    // This is a configurable parameter for nodes to manage their resources.
    // Can be reduced for low devices, and increased for high end devices.
    // You may sync faster or slower depending on this value.
    max_chain_response_size: usize,
    // Configured exclusive nodes. 
    // If not empty, only the listed peers can connect
    // to this node; no other peer will be allowed.
    exclusive_nodes: IndexSet<SocketAddr>,
    // Are we allowing other nodes to share us as a potential peer? 
    // This also controls if we can be listed in the get_peers RPC API.
    sharable: bool,
    // Do we try to connect to others nodes?
    // If this is enabled, only way to have peers is to let them connect to us.
    outgoing_connections_disabled: AtomicBool,
    // Are we syncing the chain with another peer?
    is_syncing: AtomicBool,
    // Exit channel to notify all tasks to stop
    exit_sender: broadcast::Sender<()>
}

impl<S: Storage> P2pServer<S> {
    pub fn new(concurrency: usize, dir_path: Option<String>, tag: Option<String>, max_peers: usize, bind_address: String, blockchain: Arc<Blockchain<S>>, use_peerlist: bool, exclusive_nodes: Vec<SocketAddr>, allow_fast_sync_mode: bool, allow_boost_sync_mode: bool, max_chain_response_size: Option<usize>, sharable: bool, disable_outgoing_connections: bool) -> Result<Arc<Self>, P2pError> {
        if tag.as_ref().is_some_and(|tag| tag.len() == 0 || tag.len() > 16) {
            return Err(P2pError::InvalidTag);
        }

        if max_chain_response_size.is_some_and(|size| size < CHAIN_SYNC_RESPONSE_MIN_BLOCKS || size > CHAIN_SYNC_RESPONSE_MAX_BLOCKS) {
            return Err(P2pError::InvalidMaxChainResponseSize);
        }

        if max_peers == 0 {
            return Err(P2pError::InvalidMaxPeers);
        }

        // Set channel to communicate with listener thread
        let mut rng = rand::thread_rng();
        let peer_id: u64 = rng.gen(); // generate a random peer id for network
        let addr: SocketAddr = bind_address.parse()?; // parse the bind address
        // Create mspc channel for connections to peers
        let (connections_sender, connections_receiver) = mpsc::channel(max_peers);
        let (blocks_processor, blocks_processor_receiver) = mpsc::channel(TIPS_LIMIT * STABLE_LIMIT as usize);

        // Channel used to broadcast the stop message
        let (exit_sender, exit_receiver) = broadcast::channel(1);
        let object_tracker = ObjectTracker::new(blockchain.clone(), exit_receiver);

        let (sender, event_receiver) = channel::<Arc<Peer>>(max_peers); 
        let peer_list = PeerList::new(max_peers, format!("{}peerlist-{}.json", dir_path.unwrap_or_default(), blockchain.get_network().to_string().to_lowercase()), Some(sender));


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
            allow_fast_sync_mode,
            allow_boost_sync_mode,
            max_chain_response_size: max_chain_response_size.unwrap_or(CHAIN_SYNC_DEFAULT_RESPONSE_BLOCKS),
            exclusive_nodes: IndexSet::from_iter(exclusive_nodes.into_iter()),
            sharable,
            is_syncing: AtomicBool::new(false),
            outgoing_connections_disabled: AtomicBool::new(disable_outgoing_connections),
            exit_sender,
        };

        let arc = Arc::new(server);
        {
            let zelf = Arc::clone(&arc);
            spawn_task("p2p-engine", async move {
                if let Err(e) = zelf.start(connections_receiver, blocks_processor_receiver, event_receiver, use_peerlist, concurrency).await {
                    error!("Unexpected error on P2p module: {}", e);
                }
            });
        }

        Ok(arc)
    }

    // Stop the p2p module by closing all connections
    pub async fn stop(&self) {
        info!("Stopping P2p Server...");
        self.is_running.store(false, Ordering::Release);

        info!("Waiting for all peers to be closed...");
        self.peer_list.close_all().await;

        if let Err(e) = self.exit_sender.send(()) {
            error!("Error while sending Exit message to stop all tasks: {}", e);
        }
        info!("P2p Server is now stopped!");
    }

    // Verify if we are still running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Acquire)
    }

    pub fn is_outgoing_connections_disabled(&self) -> bool {
        self.outgoing_connections_disabled.load(Ordering::Acquire)
    }

    pub fn set_disable_outgoing_connections(&self, disable: bool) {
        self.outgoing_connections_disabled.store(disable, Ordering::Release);
    }

    // Every 10 seconds, verify and connect if necessary to a random node
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
                        // If we have already reached the limit, we ignore this new connection
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

    // Connect to seed nodes, start p2p server,
    // and wait on all new connections.
    async fn start(self: &Arc<Self>, receiver: Receiver<(SocketAddr, bool)>, blocks_processor_receiver: Receiver<(Arc<Peer>, BlockHeader, Hash)>, event_receiver: Receiver<Arc<Peer>>, use_peerlist: bool, concurrency: usize) -> Result<(), P2pError> {
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
        // Create tokio task to maintains connection to exclusive nodes or seed nodes
        let zelf = Arc::clone(self);
        spawn_task("p2p-maintain-nodes", async move {
            info!("Connecting to seed nodes...");
            if let Err(e) = zelf.maintains_connection_to_nodes(exclusive_nodes, priority_sender).await {
                error!("Error while maintaining connection with seed nodes: {}", e);
            };
        });

        // Start a new task for chain sync
        spawn_task("p2p-chain-sync", Arc::clone(&self).chain_sync_loop());

        // Start another task for ping loop
        spawn_task("p2p-ping", Arc::clone(&self).ping_loop());

        // Start the blocks processing task to have a queued handler
        spawn_task("p2p-blocks", Arc::clone(&self).blocks_processing_task(blocks_processor_receiver));

        // Start the event loop task to handle peer disconnect events
        spawn_task("p2p-events", Arc::clone(&self).event_loop(event_receiver));


        // Start another task for peerlist loop
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
                            Err(e) => match e {
                                P2pError::PeerListFull => {
                                    debug!("Peer list is full, we can't accept new connections");
                                    if let Err(e) = peer.get_connection().close().await {
                                        debug!("Error while closing unhandled connection: {}", e);
                                    }
                                },
                                _ => {
                                    error!("Error while handling new connection: {}", e);
                                    if let Err(e) = peer.get_connection().close().await {
                                        debug!("Error while closing unhandled connection: {}", e);
                                    }
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
        // Only allocate one time the buffer for this packet
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
                // Check that this incoming peer isn't blacklisted
                if !self.accept_new_connections().await || !self.peer_list.is_allowed(&addr.ip()).await {
                    debug!("{} is not allowed, we can't connect to it", addr);
                    continue;
                }
            }

            if !self.is_running() {
                break;
            }

            let connection = match self.connect_to_peer(addr).await {
                Ok(connection) => connection,
                Err(e) => {
                    debug!("Error while connecting to address {}: {}", addr, e);

                    if !priority {
                        self.peer_list.increase_fail_count_for_stored_peer(&addr.ip(), false).await;
                    }

                    continue;
                }
            };

            let peer = match self.create_verified_peer(&mut handshake_buffer, connection, priority).await {
                Ok(handshake) => handshake,
                Err(e) => {
                    debug!("Error while verifying connection to address {}: {}", addr, e);
                    if !priority {
                        self.peer_list.increase_fail_count_for_stored_peer(&addr.ip(), false).await;
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

    // This task will handle an incoming connection request.
    // It will verify if we can accept this connection.
    // If we can, we will create a new peer and send it to the listener.
    async fn handle_incoming_connection(self: &Arc<Self>, res: io::Result<(TcpStream, SocketAddr)>, thread_pool: &ThreadPool, tx: &Sender<(Peer, Rx)>) -> Result<(), P2pError> {
        let (mut stream, addr) = res?;

        // Verify if we can accept new connections
        let reject = !self.is_compatible_with_exclusive_nodes(&addr)
            // Check that this incoming peer isn't blacklisted
            || !self.accept_new_connections().await
            || !self.peer_list.is_allowed(&addr.ip()).await
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
                    zelf.peer_list.increase_fail_count_for_stored_peer(&addr.ip(), true).await;
                }
            };
        }).await?;

        Ok(())
    }

    // This task will handle all incoming connections requests.
    // Based on the concurrency set, it will create a thread pool to handle requests and wait until
    // a worker is free to accept a new connection.
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

    // Verify the handshake sent by a new connection.
    // This verification checks the data size, network ID, validity of the peer's address,
    // block height, and the top block hash of the peer (to ensure we are on the same chain).
    async fn verify_handshake(&self, connection: &mut Connection, handshake: &mut Handshake<'_>) -> Result<(), P2pError> {
        if handshake.get_network() != self.blockchain.get_network() {
            trace!("{} has an invalid network: {}", connection, handshake.get_network());
            return Err(P2pError::InvalidNetwork)
        }

        if *handshake.get_network_id() != NETWORK_ID {
            return Err(P2pError::InvalidNetworkID);
        }

        if self.has_peer_id_used(&handshake.get_peer_id()).await {
            return Err(P2pError::PeerIdAlreadyUsed(handshake.get_peer_id()));
        }

        if *handshake.get_block_genesis_hash() != *get_genesis_block_hash(self.blockchain.get_network()) {
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

        // Check if the version of this peer is allowed
        if !is_version_allowed_at_height(self.blockchain.get_network(), self.blockchain.get_height(), handshake.get_version()).map_err(|e| P2pError::InvalidP2pVersion(e.to_string()))? {
            return Err(P2pError::InvalidP2pVersion(handshake.get_version().clone()));
        }

        Ok(())
    }

    // Build a handshake packet.
    // We feed the packet with all chain data.
    async fn build_handshake(&self) -> Result<Vec<u8>, P2pError> {
        let storage = self.blockchain.get_storage().read().await;
        let (block, top_hash) = storage.get_top_block_header().await?;
        let topoheight = self.blockchain.get_topo_height();
        let pruned_topoheight = storage.get_pruned_topoheight().await?;
        let cumulative_difficulty = storage.get_cumulative_difficulty_for_block_hash(&top_hash).await.unwrap_or_else(|_| CumulativeDifficulty::zero());
        let genesis_block = get_genesis_block_hash(self.blockchain.get_network());
        let handshake = Handshake::new(Cow::Owned(VERSION.to_owned()), *self.blockchain.get_network(), Cow::Borrowed(self.get_tag()), Cow::Borrowed(&NETWORK_ID), self.get_peer_id(), self.bind_address.port(), get_current_time_in_seconds(), topoheight, block.get_height(), pruned_topoheight, Cow::Borrowed(&top_hash), Cow::Borrowed(genesis_block), Cow::Borrowed(&cumulative_difficulty), self.sharable);
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

    // This function handles all new connections.
    // A new connection must send a handshake.
    // If the handshake is valid, we accept it and register it on the server
    async fn verify_connection(&self, buf: &mut [u8], connection: &mut Connection) -> Result<Handshake, P2pError> {
        trace!("New connection: {}", connection);

        // Exchange encryption keys
        connection.exchange_keys(buf).await?;

        // Start handshake now
        connection.set_state(State::Handshake);
        if connection.is_out() {
            self.send_handshake(&connection).await?;
        }

        // Wait on the handshake packet
        let mut handshake: Handshake<'_> = match timeout(Duration::from_millis(PEER_TIMEOUT_INIT_CONNECTION), connection.read_packet(buf, buf.len() as u32)).await?? {
            // Only allow handshake packet
            Packet::Handshake(h) => h.into_owned(),
            _ => return Err(P2pError::ExpectedHandshake)
        };

        trace!("received handshake packet!");
        self.verify_handshake(connection, &mut handshake).await?;

        trace!("Handshake has been verified");
        // If it's a outgoing connection, don't send the handshake back
        // because we have already sent it.
        if !connection.is_out() {
            trace!("Sending handshake back to {}", connection);
            self.send_handshake(&connection).await?;
        }

        // If we reach here, handshake is valid, we can start listening to this new peer
        connection.set_state(State::Success);

        Ok(handshake)
    }

    async fn handle_new_peer(self: &Arc<Self>, peer: &Arc<Peer>, rx: Rx) -> Result<(), P2pError> {
        // We can save the peer in our peerlist
        let peer_id = peer.get_id(); 
        // Keep in memory the peer_id outside connection (because of moved value)
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

    // Connect to a specific peer address.
    // Buffer is passed in parameter to prevent the re-allocation each time.
    // No check is done, this is done at the moment of the connection.
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

    // Connect to a new peer using its socket address.
    // Then we send the peer a handshake.
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

            if !self.peer_list.is_allowed(&addr.ip()).await {
                debug!("{} is not allowed, we can't connect to it", addr);
                return Err(P2pError::NotAllowed);
            }
        }

        let stream = timeout(Duration::from_millis(PEER_TIMEOUT_INIT_OUTGOING_CONNECTION), TcpStream::connect(&addr)).await??;
        let connection = Connection::new(stream, addr, true);
        Ok(connection)
    }

    // Send a handshake to a connection (this is used to determine if its a potential peer).
    // Handshake is sent only once, when we connect to a new peer, and we get it back from connection to make it a peer.
    async fn send_handshake(&self, connection: &Connection) -> Result<(), P2pError> {
        trace!("Sending handshake to {}", connection);
        let handshake = self.build_handshake().await?;
        connection.send_bytes(&handshake).await
    }

    // Build a ping packet with the current state of the blockchain,
    // if a peer is given, we will check and update the peers list.
    async fn build_generic_ping_packet_with_storage(&self, storage: &S) -> Ping<'_> {
        let (cumulative_difficulty, block_top_hash, pruned_topoheight) = {
            let pruned_topoheight = match storage.get_pruned_topoheight().await {
                Ok(pruned_topoheight) => pruned_topoheight,
                Err(e) => {
                    error!("Couldn't get the pruned topoheight from storage for generic ping packet: {}", e);
                    None
                }
            };

            match storage.get_top_block_hash().await {
                Err(e) => {
                    error!("Couldn't get the top block hash from storage for generic ping packet: {}", e);
                    (CumulativeDifficulty::zero(), get_genesis_block_hash(self.blockchain.get_network()).clone(), pruned_topoheight)
                },
                Ok(hash) => (storage.get_cumulative_difficulty_for_block_hash(&hash).await.unwrap_or_else(|_| CumulativeDifficulty::zero()), hash, pruned_topoheight)
            }
        };
        let highest_topo_height = self.blockchain.get_topo_height();
        let highest_height = self.blockchain.get_height();
        let new_peers = IndexSet::new();
        Ping::new(Cow::Owned(block_top_hash), highest_topo_height, highest_height, pruned_topoheight, cumulative_difficulty, new_peers)
    }

    // Build a generic ping packet.
    // This will lock the storage for us.
    async fn build_generic_ping_packet(&self) -> Ping<'_> {
        let storage = self.blockchain.get_storage().read().await;
        debug!("locking storage to build generic ping packet");
        self.build_generic_ping_packet_with_storage(&*storage).await
    }

    // Select a random peer with a higher chain state to sync the chain from.
    // The candidate peer should have a higher topoheight or block height than us.
    // It must also have a greater cumulative difficulty than us.
    // Cumulative difficulty helps determine which chain has more work done if two chains are running at the same speed.
    // If we are not in fast sync mode, we must verify its pruned topoheight to be sure
    // that is has the blocks we need.
    async fn select_random_best_peer(&self, fast_sync: bool, previous_peer: Option<&(Arc<Peer>, bool)>) -> Result<Option<Arc<Peer>>, BlockchainError> {
        trace!("select random best peer");
        
        let our_height = self.blockchain.get_height();
        let our_topoheight = self.blockchain.get_topo_height();

        // Search our cumulative difficulty
        let our_cumulative_difficulty = {
            trace!("locking storage to search our cumulative difficulty");
            let storage = self.blockchain.get_storage().read().await;
            let hash = storage.get_hash_at_topo_height(our_topoheight).await?;
            storage.get_cumulative_difficulty_for_block_hash(&hash).await?
        };

        trace!("peer list locked for select random best peer");

        // Search for peers which are higher than us
        // and that are pruned but before our height so we can sync correctly.
        let available_peers = self.peer_list.get_cloned_peers().await;
        // IndexSet is used to select by random index
        let mut peers: IndexSet<Arc<Peer>> = IndexSet::with_capacity(available_peers.len());

        for p in available_peers {
            // Avoid selecting peers that have a weaker cumulative difficulty than us
            {
                let cumulative_difficulty = p.get_cumulative_difficulty().lock().await;
                if *cumulative_difficulty <= our_cumulative_difficulty {
                    continue;
                }
            }

            let peer_topoheight = p.get_topoheight();
            if fast_sync {
                // If we want to fast sync but this peer is not compatible, we skip it.
                // For this we check that the peer topoheight is not less than the prune safety limit.
                if peer_topoheight < PRUNE_SAFETY_LIMIT || our_topoheight + PRUNE_SAFETY_LIMIT > peer_topoheight {
                    continue;
                }
                if let Some(pruned_topoheight) = p.get_pruned_topoheight() {
                    // This shouldn't be possible if following the protocol,
                    // but we may never know if a peer is not following the protocol strictly.
                    if peer_topoheight - pruned_topoheight < PRUNE_SAFETY_LIMIT {
                        continue;
                    }
                }
            } else {
                // Check that the pruned topoheight is less than our topoheight to sync
                // so we can sync chain from pruned chains.
                if let Some(pruned_topoheight) = p.get_pruned_topoheight() {
                    if pruned_topoheight > our_topoheight {
                        continue;
                    }
                }
            }

            if !(p.get_height() > our_height || peer_topoheight > our_topoheight) {
                continue;
            }

            peers.insert(p);
        }

        // Try to not reuse the same peer between each sync
        if let Some((previous_peer, err)) = previous_peer {
            if peers.len() > 1 || (*err && !previous_peer.is_priority()) {
                debug!("removing previous peer {} from random selection, err: {}, priority: {}", previous_peer, err, previous_peer.is_priority());
                // We don't need to preserve the order
                peers.swap_remove(previous_peer);
            }
        }

        let count = peers.len();
        trace!("peers available for random selection: {}", count);
        if count == 0 {
            return Ok(None)
        }

        let selected = rand::thread_rng().gen_range(0..count);
        // Clone the Arc to prevent the lock until the end of the sync request
        Ok(peers.swap_remove_index(selected))
    }

    // Check if user has allowed fast sync mode.
    // This is useful for lite node by syncing only the top chain while staying fully compatible.
    pub fn allow_fast_sync(&self) -> bool {
        self.allow_fast_sync_mode
    }

    // Check if user has allowed the boost sync mode.
    // This is requesting blocks in parallel during chain sync.
    pub fn allow_boost_sync(&self) -> bool {
        self.allow_boost_sync_mode
    }

    // Set the chain syncing state
    fn set_chain_syncing(&self, syncing: bool) {
        self.is_syncing.store(syncing, Ordering::Release);
    }

    // Check if we are syncing the chain
    pub fn is_syncing_chain(&self) -> bool {
        self.is_syncing.load(Ordering::Acquire)
    }

    // This is an infinite task that is running every CHAIN_SYNC_DELAY seconds.
    // Based on the user configuration, it will attempt to sync the chain with another node that has the longest chain, if available.
    async fn chain_sync_loop(self: Arc<Self>) {
        // Used to detect how much time we have to wait before next request
        let mut last_chain_sync = get_current_time_in_millis();
        let interval = Duration::from_secs(CHAIN_SYNC_DELAY);
        // Try to not reuse the same peer between each sync.
        // Don't use it at all if its errored.
        let mut previous_peer: Option<(Arc<Peer>, bool)> = None;
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

            // First, we check if fast sync mode is allowed.
            // Then, we check if there is a potential peer with a higher chain state for fast syncing.
            // If not, we proceed with normal synchronization.
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

            let peer_selected = match self.select_random_best_peer(fast_sync, previous_peer.as_ref()).await {
                Ok(peer) => peer,
                Err(e) => {
                    error!("Error while selecting random best peer for chain sync: {}", e);
                    None
                }
            };

            if let Some(peer) = peer_selected {
                debug!("Selected for chain sync is {}", peer);
                // We are syncing the chain
                self.set_chain_syncing(true);

                // First, check if fast sync is possible.
                // If not, fall back to the normal chain synchronization.
                let err = if fast_sync {
                    if let Err(e) = self.bootstrap_chain(&peer).await {
                        warn!("Error occurred while fast syncing with {}: {}", peer, e);
                        true
                    } else {
                        false
                    }
                } else {
                    let previous_err = previous_peer.map(|(_, err)| err).unwrap_or(false);
                    if let Err(e) = self.request_sync_chain_for(&peer, &mut last_chain_sync, previous_err).await {
                        warn!("Error occurred on chain sync with {}: {}", peer, e);
                        true
                    } else {
                        false
                    }
                };
                previous_peer = Some((peer, err));
                // We are not syncing anymore
                self.set_chain_syncing(false);
            } else {
                trace!("No peer found for chain sync, waiting before next check");
                sleep(interval).await;
            }
        }
    }


    // Broadcast a generic ping packet every 10 seconds.
    // If we need to send our peer list to all peers, we calculate the ping for each peer.
    // Instead of performing this calculation in each peer's write task, we do it once to avoid
    // multiple locks on the chain and the peer list.
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

            let mut ping = self.build_generic_ping_packet().await;
            trace!("generic ping packet finished");

            // Get all connected peers
            let all_peers = self.peer_list.get_cloned_peers().await;

            let current_time = get_current_time_in_seconds();
            // Check if its time to send our peerlist
            if current_time > last_peerlist_update + P2P_PING_PEER_LIST_DELAY {
                trace!("Sending ping packet with peerlist...");
                for peer in all_peers.iter() {
                    let new_peers = ping.get_mut_peers();
                    new_peers.clear();

                    if peer.get_connection().is_closed() {
                        debug!("{} is closed, skipping ping packet", peer);
                        continue;
                    }

                    // Is it a peer from our local network
                    let is_local_peer = is_local_address(peer.get_connection().get_address());

                    // All the peers we already shared with this peer
                    let mut shared_peers = peer.get_peers().lock().await;

                    // Iterate through our peerlist to determinate which peers we have to send
                    for p in all_peers.iter() {
                        // Don't send to itself
                        // and don't share a peer that doesn't want to be shared
                        if p.get_id() == peer.get_id() || !p.sharable() {
                            continue;
                        }

                        // If we haven't sent him this peer address and he doesn't already have it, insert it
                        let addr = p.get_outgoing_address();

                        // Don't share local network addresses with an external peer
                        if (is_local_address(addr) && !is_local_peer) || !is_valid_address(addr) {
                            debug!("{} is a local address but peer is external, skipping", addr);
                            continue;
                        }

                        let send = match shared_peers.entry(*addr) {
                            Entry::Occupied(mut e) => e.get_mut().update(Direction::Out),
                            Entry::Vacant(e) => {
                                e.insert(Direction::Out);
                                true
                            }
                        };

                        if send {
                            // Add it in our side to not send it again
                            trace!("{} didn't received {} yet, adding it to peerlist in ping packet", peer.get_outgoing_address(), addr);

                            // Add it to new list to send it
                            new_peers.insert(*addr);
                            if new_peers.len() >= P2P_PING_PEER_LIST_LIMIT {
                                break;
                            }
                        }
                    }

                    // Update the ping packet with the new peers
                    debug!("Set peers: {:?}, going to {}", new_peers, peer.get_outgoing_address());
                    // Send the ping packet to the peer
                    if let Err(e) = peer.send_packet(Packet::Ping(Cow::Borrowed(&ping))).await {
                        debug!("Error sending specific ping packet to {}: {}", peer, e);
                    } else {
                        peer.set_last_ping_sent(current_time);
                    }
                }

                // Update the last time we sent our peerlist.
                // We don't use the previous current_time variable because it may have been
                // delayed due to the packet sending.
                last_peerlist_update = get_current_time_in_seconds();
            } else {
                trace!("Sending generic ping packet...");
                let packet = Packet::Ping(Cow::Owned(ping));
                let bytes = Bytes::from(packet.to_bytes());
                // Broadcast directly the ping packet asap to all peers
                for peer in all_peers {
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
            }
        }
    }

    // Try to extend our peerlist whenever possible by searching in the known peerlist from disk
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
                    self.peer_list.find_peer_to_connect().await
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

    // This function broadcast PeerDisconnected events to listeners.
    // A channel is used to avoid passing Blockchain<S> to Peerlist & Peers.
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

                    let mut response_blockers: Vec<ResponseBlocker> = Vec::new();
                    for hash in header.get_txs_hashes() {
                        let contains = { 
                            // Don't lock for extended periods to avoid waiting on p2p response
                            // Check in ObjectTracker
                            if let Some(response_blocker) = self.object_tracker.get_response_blocker_for_requested_object(hash).await {
                                trace!("{} is already requested, waiting on response blocker for block {}", hash, block_hash);
                                response_blockers.push(response_blocker);
                                true
                            } else {
                                self.blockchain.has_tx(hash).await.unwrap_or(false)
                            }
                        };

                        if !contains { 
                            // Retrieve one by one to prevent acquiring the lock for nothing
                            debug!("Requesting TX {} to {} for block {}", hash, peer, block_hash);
                            if let Err(e) = self.object_tracker.request_object_from_peer(Arc::clone(&peer), ObjectRequest::Transaction(hash.clone()), false).await {
                                    error!("Error while requesting TX {} to {} for block {}: {}", hash, peer, block_hash, e);
                                    peer.increment_fail_count();
                                    continue 'main;
                            }

                            if let Some(response_blocker) = self.object_tracker.get_response_blocker_for_requested_object(hash).await {
                                response_blockers.push(response_blocker);
                            }
                        }
                    }

                    // Wait for all previously requested txs
                    for mut blocker in response_blockers {
                        if let Err(e) = blocker.recv().await {
                            // It's mostly a closed channel error, so we can ignore it
                            warn!("Error while waiting on response blocker: {}", e);
                            peer.increment_fail_count();
                            continue 'main;
                        }
                    }

                    // Add the block to the chain immediately, as we are synced
                    let block = match self.blockchain.build_block_from_header(Immutable::Owned(header)).await {
                        Ok(block) => block,
                        Err(e) => {
                            error!("Error while building block {} from peer {}: {}", block_hash, peer, e);
                            peer.increment_fail_count();
                            continue 'main;
                        }
                    };
        
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

    // This function handles the logic for sending all packets to the peer
    async fn handle_connection_write_side(&self, peer: &Arc<Peer>, rx: &mut Rx, mut task_rx: oneshot::Receiver<()>) -> Result<(), P2pError> {
        let mut server_exit = self.exit_sender.subscribe();
        let mut peer_exit = peer.get_exit_receiver();
        let mut interval = interval(Duration::from_secs(P2P_HEARTBEAT_INTERVAL));
        loop {
            select! {
                biased;
                // Exit message from the read task
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
                    // Last time we got a ping packet from peer
                    let last_ping = peer.get_last_ping();
                    if last_ping != 0 && get_current_time_in_seconds() - last_ping > P2P_PING_TIMEOUT {
                        debug!("{} has not sent a ping packet for {} seconds, closing connection...", peer, P2P_PING_TIMEOUT);
                        break;
                    }
                },
                // All packets to be sent to the peer are received here
                Some(bytes) = rx.recv() => {
                    // There is an overhead of 4 bytes per packet (packet size u32 4 bytes, packet id u8 is counted in the packet size)
                    trace!("Sending packet with ID {}, size sent: {}, real size: {}", bytes[4], u32::from_be_bytes(bytes[0..4].try_into()?), bytes.len());
                    peer.get_connection().send_bytes(&bytes).await?;
                    trace!("data successfully sent!");
                }
            }
        }
        Ok(())
    }

    // This function runs as a separate task with its own 1kB buffer to read and handle packets from the peer sequentially
    async fn handle_connection_read_side(self: &Arc<Self>, peer: &Arc<Peer>, mut write_task: JoinHandle<()>) -> Result<(), P2pError> {
        // Allocate the unique buffer for this connection
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

                    // Check if there are too many failures.
                    // If so, disconnect the peer.
                    // Priority nodes are not disconnected.
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

    // This function manages the entire connection with a peer.
    // It creates separate tasks for reading and writing,
    // allowing both operations to proceed simultaneously
    // without blocking or waiting on the other part during important traffic.
    async fn handle_connection(self: &Arc<Self>, peer: Arc<Peer>, mut rx: Rx) -> Result<(), P2pError> {
        // Task for writing to peer

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

                // Clean shutdown
                rx.close();

                if let Err(e) = peer.close().await {
                    debug!("Error while closing connection for {} from write task: {}", peer, e);
                }

                peer.set_write_task_state(TaskState::Finished).await;
                debug!("Handle connection read side task for {} has been finished", addr);
            })
        };

        // Task for reading from peer
        {
            let zelf = Arc::clone(&self);
            let peer = Arc::clone(&peer);
            spawn_task(format!("p2p-handle-read-{}", peer.get_connection().get_address()), async move {
                peer.set_read_task_state(TaskState::Active).await;
                let addr = *peer.get_connection().get_address();
                trace!("Handle connection read side task for {} has been started", addr);
                if let Err(e) = zelf.handle_connection_read_side(&peer, write_task).await {
                    debug!("Error while running read part from peer {}: {}", peer, e);

                    peer.set_read_task_state(TaskState::Exiting).await;

                    // Verify that the connection is closed.
                    // Write task should be responsible for closing the connection.
                    if write_tx.send(()).is_err() {
                        debug!("Write task has already exited, closing connection for {}", peer);
                    }
                }

                peer.set_read_task_state(TaskState::Finished).await;

                debug!("Handle connection read side task for {} has been finished", addr);
            });
        }

        // Verify that we are synced with the peer to receive all TXs correctly
        let our_topoheight = self.blockchain.get_topo_height();
        let peer_topoheight = peer.get_topoheight();
        if peer_topoheight == our_topoheight {
            if let Err(e) = self.request_inventory_of(&peer).await {
                warn!("Error while requesting inventory of {}: {}", peer, e);
            }
        }

        Ok(())
    }

    // Returns the list of all common peers we have between a peer and us.
    // TODO fix common peers detection
    // Problem: We are connected to nodes A and B, which are connected to each
    // other. However, they may not have shared their peer lists with each other,
    // so they don't know we are a common peer. This can cause false positives
    // where they send us the same object.
    async fn get_common_peers_for(&self, peer: &Arc<Peer>) -> Vec<Arc<Peer>> {
        debug!("get common peers for {}", peer);
        trace!("locked peer_list, locking peers received (common peers)");
        let peer_peers = peer.get_peers().lock().await;
        trace!("locked peers received (common peers)");

        let mut common_peers = Vec::new();
        for (common_peer_addr, _) in peer_peers.iter().filter(|(_, direction)| **direction == Direction::Both) {
            // If we have a common peer with them
            if let Some(common_peer) = self.peer_list.get_peer_by_addr(common_peer_addr).await {
                if peer.get_id() != common_peer.get_id() {
                    common_peers.push(common_peer);
                }
            }
        }

        common_peers
    }

    // Main function for handling connections with nodes.
    // Processes each packet in our p2p protocol; each packet is an enum variant.
    async fn handle_incoming_packet(self: &Arc<Self>, peer: &Arc<Peer>, packet: Packet<'_>) -> Result<(), P2pError> {
        match packet {
            Packet::Handshake(_) => {
                error!("{} sent us handshake packet (not valid!)", peer);
                peer.get_connection().close().await?;
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
                let hash = hash.into_owned();

                ping.into_owned().update_peer(peer, &self.blockchain).await?;

                // Peer should not send us the same TX twice
                debug!("Received tx hash {} from {}", hash, peer.get_outgoing_address());
                {
                    let mut txs_cache = peer.get_txs_cache().lock().await;

                    if let Some(direction) = txs_cache.get_mut(&hash) {
                        if !direction.update(Direction::In) {
                            debug!("{} send us a transaction ({}) already tracked by him ({:?})", peer, hash, direction);
                            // return Err(P2pError::AlreadyTrackedTx(hash))
                        }
                    } else {
                        txs_cache.put(hash.clone(), Direction::In);
                    }
                }

                // Check that the TX is not in mempool or on disk already
                if !self.blockchain.has_tx(&hash).await? {
                    trace!("Requesting tx {} propagated because we don't have it", hash);
                    if !self.object_tracker.request_object_from_peer(Arc::clone(peer), ObjectRequest::Transaction(hash.clone()), true).await? {
                        debug!("TX propagated {} was already requested, ignoring", hash);
                    }
                }

                // Avoid sending the TX propagated to a common peer.
                // We track the peer list of each peer and determine common peers.
                // Iterate over all common peers of this peer broadcaster.
                for common_peer in self.get_common_peers_for(&peer).await {
                    debug!("{} is a common peer with {}, adding TX {} to its cache", common_peer, peer, hash);
                    let mut txs_cache = common_peer.get_txs_cache().lock().await;
                    // Mark the TX as Out so we don't send it again. This allows us to retrieve
                    // it once in case of incorrect common peer prediction.
                    txs_cache.put(hash.clone(), Direction::Out);
                }
            },
            Packet::BlockPropagation(packet_wrapper) => {
                trace!("Received a block propagation packet from {}", peer);
                let (header, ping) = packet_wrapper.consume();
                ping.into_owned().update_peer(peer, &self.blockchain).await?;

                // Check that the block height is valid
                let header = header.into_owned();
                let block_hash = header.hash();

                // Verify that this block wasn't already sent by him
                {
                    let mut blocks_propagation = peer.get_blocks_propagation().lock().await;
                    if let Some(direction) = blocks_propagation.get_mut(&block_hash) {
                        if !direction.update(Direction::In) {
                            debug!("{} send us a block ({}) already tracked by him ({:?})", peer, block_hash, direction);
                            // return Err(P2pError::AlreadyTrackedBlock(block_hash, *direction))
                        }
                    } else {
                        debug!("Saving {} in blocks propagation cache for {}", block_hash, peer);
                        blocks_propagation.put(block_hash.clone(),  Direction::In);
                    }
                }

                // Avoid sending the same block to a common peer that may have already received it.
                // We track the peer list of each peer and use this information to determine this.
                for common_peer in self.get_common_peers_for(&peer).await {
                    debug!("{} is a common peer with {}, adding block {} to its propagation cache", common_peer, peer, block_hash);
                    let mut blocks_propagation = common_peer.get_blocks_propagation().lock().await;
                    // Mark the block as Out to avoid sending it again.
                    // This allows us to get it back in case our prediction was incorrect.
                    if !blocks_propagation.contains(&block_hash) {
                        blocks_propagation.put(block_hash.clone(), Direction::Out);
                    }
                }

                // Check that this block is not already in our chain.
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
                    blocks_propagation_queue.put(block_hash.clone(), ());
                }

                let block_height = header.get_height();
                debug!("Received block at height {} from {}", block_height, peer);
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
                // Node is requesting the chain too quickly
                // Don't allow faster than 1/3 of the delay
                if  last_request + (CHAIN_SYNC_DELAY * 2 / 3) > time {
                    debug!("{} requested sync chain too fast!", peer);
                    return Err(P2pError::RequestSyncChainTooFast)
                }
                peer.set_last_chain_sync(time);

                // At least one block necessary (genesis block)
                let request_size = request.size();
                if request_size == 0 || request_size > CHAIN_SYNC_REQUEST_MAX_BLOCKS { 
                    // Allows maximum 64 blocks id (2560 bytes max)
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

                // Update the last ping time only if the peer respects the protocol rules.
                peer.set_last_ping(current_time);

                // Verify compliance with the countdown for peer list updates to prevent spam.
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

                        if !self.is_connected_to_addr(addr).await && !self.peer_list.has_peer_stored(&addr.ip()).await {
                            if !self.peer_list.store_peer_address(*addr).await {
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

                // Check if we requested it from this peer already
                let request = response.get_request();
                if peer.has_requested_object(&request).await {
                    let sender = peer.remove_object_request(request).await?;
                    // Handle the response
                    if sender.send(response).is_err() {
                        error!("Error while sending object response to sender!");
                    }
                // Check if the Object Tracker has requested this object
                } else if self.object_tracker.has_requested_object(request.get_hash()).await {
                    trace!("Object Tracker requested it, handling it");
                    self.object_tracker.handle_object_response(response).await?;
                } else if self.object_tracker.is_ignored_request_hash(request.get_hash()).await {
                    debug!("Object {} was ignored by Object Tracker, ignoring response", request.get_hash());
                } else {
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

                peer.send_bytes(Bytes::from(packet)).await?
            },
            Packet::NotifyInventoryResponse(inventory) => {
                debug!("Received a notify inventory from {}: {} txs", peer, inventory.len());
                if !peer.has_requested_inventory() {
                    warn!("Received a notify inventory from {} but we didn't request it", peer);
                    return Err(P2pError::InvalidPacket)
                }

                // We received the inventory
                peer.set_requested_inventory(false);
                peer.set_last_inventory(get_current_time_in_seconds());

                let next_page = inventory.next();
                {
                    let txs = inventory.get_txs();
                    let total_count = txs.len();

                    // Check that the response was really full if he send us another "page"
                    if next_page.is_some() {
                        if total_count != NOTIFY_MAX_LEN {
                            error!("Received only {} while maximum is {} elements, and tell us that there is another page", total_count, NOTIFY_MAX_LEN);
                            return Err(P2pError::InvalidInventoryPagination)
                        }
                    }

                    for hash in txs.into_owned() {
                        // Verify that we don't already have it
                        if !self.blockchain.has_tx(&hash).await? {
                            trace!("Requesting TX {} from inventory response", hash);
                            if !self.object_tracker.request_object_from_peer(Arc::clone(peer), ObjectRequest::Transaction(hash.into_owned()), false).await? {
                                debug!("TX was already requested, ignoring");
                            }
                        }
                    }
                }

                // Request the next page
                if next_page.is_some() {
                    trace!("Requesting next page of inventory from {}", peer);
                    let packet = Cow::Owned(NotifyInventoryRequest::new(next_page));
                    let ping = Cow::Owned(self.build_generic_ping_packet().await);
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
                    if shared_peers.contains_key(&addr) {
                        // Delete the peer received
                        shared_peers.remove(&addr);
                    } else {
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

    // Listen for incoming packets from a connection.
    // Packets are read by a single task, but handling is delegated to a separate task.
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
                    error!("Error occurred while handling incoming packet #{} from {}: {}", packet_id, peer, e);
                    peer.increment_fail_count();
                }
            }
        }

        Ok(())
    }

    // Find a common point between our chain and the peer's chain.
    // For this we have a list of block ids which is basically block hash + its topoheight.
    // The BlockId list should be in descending order (higher topoheight first).
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
        // Search a common point
        for (i, block_id) in blocks.into_iter().enumerate() {
            // Verify good order of blocks.
            // If we have already processed the genesis block (topo 0) but still have blocks, the list is invalid.
            // For the first CHAIN_SYNC_REQUEST_EXPONENTIAL_INDEX_START blocks, verify the exact order.
            // If we are above it, i = i * 2, start topo - i = expected topoheight.
            if expected_topoheight == 0 || (i < CHAIN_SYNC_REQUEST_EXPONENTIAL_INDEX_START && expected_topoheight - 1 != block_id.get_topoheight()) {
                warn!("Block id list has not a good order at index {}, current topo {}, next: {}", i, expected_topoheight, block_id.get_topoheight());
                return Err(P2pError::InvalidBlockIdList) 
            }
            expected_topoheight -= 1;

            debug!("Searching common point for block {} at topoheight {}", block_id.get_hash(), block_id.get_topoheight());
            if storage.has_block_with_hash(block_id.get_hash()).await? {
                let (hash, topoheight) = block_id.consume();
                debug!("Block {} is common, expected topoheight: {}", hash, topoheight);
                // Check that the block order matches our chain.
                if storage.is_block_topological_ordered(&hash).await && storage.get_topo_height_for_hash(&hash).await? == topoheight { 
                    // Common point
                    debug!("common point found at block {} with same topoheight at {}", hash, topoheight);
                    return Ok(Some(CommonPoint::new(hash, topoheight)))
                }
            }
        }
        Ok(None)
    }

    // Search for a common point between our blockchain and the peer's.
    // Once the common point is found, start sending blocks from this point.
    async fn handle_chain_request(self: &Arc<Self>, peer: &Arc<Peer>, blocks: IndexSet<BlockId>, accepted_response_size: usize) -> Result<(), BlockchainError> {
        debug!("handle chain request for {} with {} blocks", peer, blocks.len());
        let storage = self.blockchain.get_storage().read().await;
        // Blocks hashes sent for syncing (topoheight ordered)
        let mut response_blocks = IndexSet::new();
        let mut top_blocks = IndexSet::new();
        // Common point used to notify peer if he should rewind or not
        let common_point = self.find_common_point(&*storage, blocks).await?;
        // Lowest height of the blocks sent
        let mut lowest_common_height = None;

        if let Some(common_point) = &common_point {
            let mut topoheight = common_point.get_topoheight();
            // Lets add all blocks ordered hash
            let top_topoheight = self.blockchain.get_topo_height();
            // Used to detect if we find unstable height for alt tips
            let mut unstable_height = None;
            let top_height = self.blockchain.get_height();
            // Check to see if we should search for alt tips (and above unstable height)
            let should_search_alt_tips = top_topoheight - topoheight < accepted_response_size as u64;
            if should_search_alt_tips {
                debug!("Peer is near to be synced, will send him alt tips blocks");
                unstable_height = Some(self.blockchain.get_stable_height() + 1);
            }

            // Search the lowest height
            let mut lowest_height = top_height;

            // Complete ChainResponse blocks until we are full or that we reach the top topoheight
            while response_blocks.len() < accepted_response_size && topoheight <= top_topoheight {
                trace!("looking for hash at topoheight {}", topoheight);
                let hash = storage.get_hash_at_topo_height(topoheight).await?;

                // Find the lowest height
                let height = storage.get_height_for_block_hash(&hash).await?;
                if height < lowest_height {
                    lowest_height = height;
                }

                let mut swap = false;
                if let Some(previous_hash) = response_blocks.last() {
                    let version = get_version_at_height(self.blockchain.get_network(), height);
                    // Due to the TX being orphaned, some TXs may be in the wrong order in V1.
                    // It has been sorted in V2 and should not happen anymore.
                    if version == BlockVersion::V0 && storage.has_block_position_in_order(&hash).await? && storage.has_block_position_in_order(&previous_hash).await? {
                        if self.blockchain.is_side_block_internal(&*storage, &hash, top_topoheight).await? {
                            let position = storage.get_block_position_in_order(&hash).await?;
                            let previous_position = storage.get_block_position_in_order(&previous_hash).await?;
                            // If the block is a side block, we need to check if it's in the right order
                            if position < previous_position {
                                swap = true;
                            }
                        }
                    }
                }

                if swap {
                    trace!("for chain request, swapping hash {} at topoheight {}", hash, topoheight);
                    let previous = response_blocks.pop();
                    response_blocks.insert(hash);
                    if let Some(previous) = previous {
                        response_blocks.insert(previous);
                    }
                } else {
                    trace!("for chain request, adding hash {} at topoheight {}", hash, topoheight);
                    response_blocks.insert(hash);
                }
                topoheight += 1;
            }
            lowest_common_height = Some(lowest_height);

            // now, lets check if peer is near to be synced, and send him alt tips blocks
            if let Some(mut height) = unstable_height {
                let top_height = self.blockchain.get_height();
                trace!("unstable height: {}, top height: {}", height, top_height);
                while height <= top_height && top_blocks.len() < CHAIN_SYNC_TOP_BLOCKS {
                    trace!("get blocks at height {} for top blocks", height);
                    for hash in storage.get_blocks_at_height(height).await? {
                        if !response_blocks.contains(&hash) {
                            trace!("Adding top block at height {}: {}", height, hash);
                            top_blocks.insert(hash);
                        } else {
                            trace!("Top block at height {}: {} was skipped because its already present in response blocks", height, hash);
                        }
                    }
                    height += 1;
                }
            }
        }

        debug!("Sending {} blocks & {} top blocks as response to {}", response_blocks.len(), top_blocks.len(), peer);
        peer.send_packet(Packet::ChainResponse(ChainResponse::new(common_point, lowest_common_height, response_blocks, top_blocks))).await?;
        Ok(())
    }

    // Handle a chain response from another peer.
    // We receive a list of block hashes ordered by their topoheight.
    // It includes a CommonPoint, which is a block hash where our topoheight matches the peer's.
    // Based on the lowest height in the chain sent, we may need to rewind some blocks.
    // NOTE: Only a priority node can rewind below the stable height.
    async fn handle_chain_response(&self, peer: &Arc<Peer>, mut response: ChainResponse, requested_max_size: usize, skip_stable_height_check: bool) -> Result<(), BlockchainError> {
        trace!("handle chain response from {}", peer);
        let response_size = response.blocks_size();

        let (Some(common_point), Some(lowest_height)) = (response.get_common_point(), response.get_lowest_height()) else {
            warn!("No common block was found with {}", peer);
            if response.blocks_size() > 0 {
                warn!("Peer have no common block but send us {} blocks!", response.blocks_size());
                return Err(P2pError::InvalidPacket.into())
            }
            return Ok(())
        };

        let common_topoheight = common_point.get_topoheight();
        debug!("{} found a common point with block {} at topo {} for sync, received {} blocks", peer.get_outgoing_address(), common_point.get_hash(), common_topoheight, response_size);
        let pop_count = {
            let storage = self.blockchain.get_storage().read().await;
            let topoheight = storage.get_topo_height_for_hash(common_point.get_hash()).await?;
            if topoheight != common_topoheight {
                error!("{} sent us a valid block hash, but at invalid topoheight (expected: {}, got: {})!", peer, topoheight, common_topoheight);
                return Err(P2pError::InvalidCommonPoint(common_topoheight).into())
            }

            let block_height = storage.get_height_for_block_hash(common_point.get_hash()).await?;
            trace!("block height: {}, stable height: {}, topoheight: {}, hash: {}", block_height, self.blockchain.get_stable_height(), topoheight, common_point.get_hash());
            // We are under the stable height, rewind is necessary
            let mut count = if skip_stable_height_check || peer.is_priority() || lowest_height <= self.blockchain.get_stable_height() {
                let our_topoheight = self.blockchain.get_topo_height();
                if our_topoheight > topoheight {
                    our_topoheight - topoheight
                } else {
                    topoheight - our_topoheight
                }
            } else {
                0
            };

            if let Some(pruned_topo) = storage.get_pruned_topoheight().await? {
                let available_diff = self.blockchain.get_topo_height() - pruned_topo;
                if count > available_diff && !(available_diff == 0 && peer.is_priority()) {
                    warn!("Peer sent us a pop count of {} but we only have {} blocks available", count, available_diff);
                    count = available_diff;
                }
            }

            count
        };

        // Packet verification ended, handle the chain response now

        let (mut blocks, top_blocks) = response.consume();
        debug!("handling chain response from {}, {} blocks, {} top blocks, pop count {}", peer, blocks.len(), top_blocks.len(), pop_count);

        let our_previous_topoheight = self.blockchain.get_topo_height();
        let our_previous_height = self.blockchain.get_height();
        let top_len = top_blocks.len();
        let blocks_len = blocks.len();

        // Merge both list together
        blocks.extend(top_blocks);

        if pop_count > 0 {
            warn!("{} sent us a pop count request of {} with {} blocks", peer, pop_count, blocks_len);
        }

        // If node asks us to pop blocks, check that the peer's height/topoheight is in advance on us
        let peer_topoheight = peer.get_topoheight();
        if pop_count > 0
            && peer_topoheight > our_previous_topoheight
            && peer.get_height() >= our_previous_height
            // Then, verify if it's a priority node, otherwise, check if we are connected to a priority node so only this peer can rewind us
            && (peer.is_priority() || !self.is_connected_to_a_synced_priority_node().await)
        {
            // Check if we can trust this peer
            if peer.is_priority() {
                warn!("Rewinding chain without checking because {} is a priority node (pop count: {})", peer, pop_count);
                // User trusts this peer as a priority node. Rewind the chain without checking.
                // Allow going below the stable height as well.
                self.blockchain.rewind_chain(pop_count, false).await?;
            } else {
                // Verify that someone isn't trying to trick us
                if pop_count > blocks_len as u64 {
                    // TODO: maybe we could request its whole chain for comparison until chain validator has_higher_cumulative_difficulty ?
                    // If after going through all its chain and we still have a higher cumulative difficulty, we should not rewind.
                    warn!("{} sent us a pop count of {} but only sent us {} blocks, ignoring", peer, pop_count, blocks_len);
                    return Err(P2pError::InvalidPopCount(pop_count, blocks_len as u64).into())
                }

                // Request all block headers and verify the basic chain structure.
                // The starting topoheight must be the next one after the common block.
                // Blocks in the chain response must be ordered by topoheight; otherwise, it will give incorrect results.
                let mut chain_validator = ChainValidator::new(&self.blockchain, common_topoheight + 1);
                for hash in blocks {
                    trace!("Request block header for chain validator: {}", hash);

                    // Check if we already have the block to not request it
                    if self.blockchain.has_block(&hash).await? {
                        trace!("We already have block {}, skipping", hash);
                        continue;
                    }

                    let response = peer.request_blocking_object(ObjectRequest::BlockHeader(hash)).await?;
                    if let OwnedObjectResponse::BlockHeader(header, hash) = response {
                        trace!("Received {} with hash {}", header, hash);
                        chain_validator.insert_block(hash, header).await?;
                    } else {
                        error!("{} sent us an invalid object response", peer);
                        return Err(P2pError::ExpectedBlock.into())
                    }
                }

                // Verify that it has a higher cumulative difficulty than us
                // Otherwise we don't switch to his chain
                if !chain_validator.has_higher_cumulative_difficulty().await? {
                    error!("{} sent us a chain response with lower cumulative difficulty than ours", peer);
                    return Err(BlockchainError::LowerCumulativeDifficulty)
                }

                // Peer chain looks correct, lets rewind our chain
                warn!("Rewinding chain because of {} (pop count: {})", peer, pop_count);
                self.blockchain.rewind_chain(pop_count, false).await?;

                // Now retrieve all TXs from all blocks header and add block in chain
                for (hash, header) in chain_validator.get_blocks() {
                    trace!("Processing block {} from chain validator", hash);
                    // We don't already have this block, lets retrieve its TXs and add in our chain
                    if !self.blockchain.has_block(&hash).await? {
                        let mut transactions = Vec::new(); // don't pre allocate
                        for tx_hash in header.get_txs_hashes() {
                            // First, check on disk in case it was already fetched by a previous block.
                            // This can happen as TXs can be integrated into multiple blocks but executed only once.
                            // Check if we find it.
                            if let Some(tx) = self.blockchain.get_tx(tx_hash).await.ok() {
                                trace!("Found the transaction {} on disk", tx_hash);
                                transactions.push(Immutable::Arc(tx));
                            } else {
                                // Otherwise, ask it from peer
                                let response = peer.request_blocking_object(ObjectRequest::Transaction(tx_hash.clone())).await?;
                                if let OwnedObjectResponse::Transaction(tx, _) = response {
                                    trace!("Received transaction {} at block {} from {}", tx_hash, hash, peer);
                                    transactions.push(Immutable::Owned(tx));
                                } else {
                                    error!("{} sent us an invalid block response", peer);
                                    return Err(P2pError::ExpectedTransaction.into())
                                }
                            }
                        }

                        // Assemble back the block and add it to the chain
                        let block = Block::new(Immutable::Arc(header), transactions);
                        self.blockchain.add_new_block(block, false, false).await?; // Don't broadcast block because it's syncing
                    }
                }
            }
        } else {
            // Rewind is not needed, process normally.
            // It will first add blocks to sync, and then all alt-tips blocks if any (top blocks).
            let mut total_requested: usize = 0;
            let mut final_blocker = None;
            // If boost sync is allowed, we can request all blocks in parallel,
            // create a new group in Object Tracker to be notified of a failure.
            let (group_id, mut notifier) = if self.allow_boost_sync() {
                let (group_id, notifier) = self.object_tracker.get_group_manager().next_group_id().await;
                (Some(group_id), Some(notifier))
            } else {
                (None, None)
            };

            // Peekable is here to help know if we are at the last element,
            // so we create only one channel for the last blocker.
            let mut blocks_iter = blocks.into_iter().peekable();
            while let Some(hash) = blocks_iter.next() {
                if !self.blockchain.has_block(&hash).await? {
                    trace!("Block {} is not found, asking it to {} (index = {})", hash, peer.get_outgoing_address(), total_requested);
                    // If it's allowed by the user, request all blocks in parallel
                    if self.allow_boost_sync() {
                        if let Some(notifier) = &mut notifier {
                            // Check if we don't have any message pending in the channel
                            if let Ok(err) = notifier.try_recv() {
                                debug!("An error has occurred in batch while requesting chain in boost mode");
                                return Err(P2pError::BoostSyncModeFailed(Box::new(err)).into());
                            }
                        }

                        let is_last = blocks_iter.peek().is_none();
                        if let Some(blocker) = self.object_tracker.request_object_from_peer_with(Arc::clone(peer), ObjectRequest::Block(hash.clone()), group_id, is_last, is_last).await? {
                            final_blocker = Some(blocker);
                        }
                    } else {
                        // Otherwise, request them one by one and wait for the response
                        let response = peer.request_blocking_object(ObjectRequest::Block(hash)).await?;
                        if let OwnedObjectResponse::Block(block, hash) = response {
                            trace!("Received block {} at height {} from {}", hash, block.get_height(), peer);
                            self.blockchain.add_new_block(block, false, false).await?;
                        } else {
                            error!("{} sent us an invalid block response", peer);
                            return Err(P2pError::ExpectedBlock.into())
                        }
                    }
                    total_requested += 1;
                } else {
                    trace!("Block {} is already in chain, verify if its in DAG", hash);

                    let block = {
                        let mut storage = self.blockchain.get_storage().write().await;
                        if !storage.is_block_topological_ordered(&hash).await {
                            match storage.delete_block_with_hash(&hash).await {
                                Ok(block) => Some(block),
                                Err(e) => {
                                    // This shouldn't happen, but in case
                                    error!("Error while deleting block {} from storage to re-execute it for chain sync: {}", hash, e);
                                    continue;
                                }
                            }
                        } else {
                            None
                        }
                    };

                    if let Some(block) = block {
                        warn!("Block {} is already in chain but not in DAG, re-executing it", hash);
                        self.blockchain.add_new_block(block, false, false).await?;
                    } else {
                        trace!("Block {} is already in DAG, skipping it", hash);
                    }
                }
            }

            if let (Some(mut notifier), Some(mut blocker)) = (notifier, final_blocker) {
                debug!("Waiting for final blocker to finish...");
                select! {
                    res = &mut notifier => {
                        let err = res.map_err(|e| P2pError::BoostSyncModeBlockerResponseError(e))?;
                        debug!("An error has occurred while requesting chain in boost mode: {}", err);
                        return Err(err.into());
                    },
                    res = blocker.recv() => match res {
                        Ok(()) => {
                            debug!("Final blocker finished");
                            if let Some(group_id) = group_id {
                                self.object_tracker.get_group_manager().unregister_group(group_id).await;
                            } else {
                                warn!("Group ID is None while it should not be");
                            }
                        },
                        Err(e) => {
                            error!("Error while waiting for final blocker: {}", e);
                            return Err(P2pError::BoostSyncModeBlockerError.into());
                        }
                    }
                }
            }
            info!("we've synced {} on {} blocks and {} top blocks from {}", total_requested, blocks_len, top_len, peer);
        }

        let peer_topoheight = peer.get_topoheight();
        // Ask for the inventory from this peer if we are synced from too far behind.
        // If we are not further than one sync, request the inventory.
        if peer_topoheight > our_previous_topoheight && blocks_len < requested_max_size {
            let our_topoheight = self.blockchain.get_topo_height();
            // Verify that we synced it partially well
            if peer_topoheight >= our_topoheight && peer_topoheight - our_topoheight < STABLE_LIMIT {
                if let Err(e) = self.request_inventory_of(&peer).await {
                    error!("Error while asking inventory to {}: {}", peer, e);
                }
            }
        }

        Ok(())
    }

    // Determine if we are connected to a priority node and that this node is equal / greater to our chain
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
    pub async fn get_median_topoheight_of_peers(&self) -> u64 {
        let topoheight = self.blockchain.get_topo_height();
        self.peer_list.get_median_topoheight(Some(topoheight)).await
    }

    // Returns the best topoheight based on all peers
    pub async fn get_best_topoheight(&self) -> u64 {
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
        if *peer_addr == *self.get_bind_address() { 
            // Don't try to connect to ourself
            debug!("Trying to connect to ourself, ignoring.");
            return true
        }

        self.peer_list.is_connected_to_addr(peer_addr).await
    }

    // Get the socket address on which we are listening
    pub fn get_bind_address(&self) -> &SocketAddr {
        &self.bind_address
    }

    // Get our peerlist
    pub fn get_peer_list(&self) -> &SharedPeerList {
        &self.peer_list
    }

    // Broadcast a new transaction hash using propagation packet.
    // This is used so we don't overload the network during spam or high transactions count.
    // We simply share its hash to nodes and others nodes can check if they have it already or not.
    pub async fn broadcast_tx_hash(&self, tx: Hash) {
        debug!("Broadcasting tx hash {}", tx);
        let ping = self.build_generic_ping_packet().await;
        debug!("Ping packet has been generated for tx broadcast");
        let current_topoheight = ping.get_topoheight();
        let packet = Packet::TransactionPropagation(PacketWrapper::new(Cow::Borrowed(&tx), Cow::Owned(ping)));
        // Transform packet to bytes (so we don't need to transform it for each peer)
        let bytes = Bytes::from(packet.to_bytes());
        trace!("Locking peer list for tx broadcast");
        let peers = self.peer_list.get_cloned_peers().await;
        trace!("Lock acquired for tx broadcast");

        for peer in peers {
            // Check that the peer is not too far from us,
            // otherwise we may spam him for nothing.
            let peer_topoheight = peer.get_topoheight();
            if (peer_topoheight >= current_topoheight && peer_topoheight - current_topoheight < STABLE_LIMIT) || (current_topoheight >= peer_topoheight && current_topoheight - peer_topoheight < STABLE_LIMIT) {
                trace!("Peer {} is not too far from us, checking cache for tx hash {}", peer, tx);
                let mut txs_cache = peer.get_txs_cache().lock().await;
                trace!("Cache locked for tx hash {}", tx);
                // Check that we haven't already sent this TX to the peer and that he doesn't already have it
                if !txs_cache.contains(&tx) {
                    trace!("Broadcasting tx hash {} to {}", tx, peer);
                    if let Err(e) = peer.send_bytes(bytes.clone()).await {
                        error!("Error while broadcasting tx hash {} to {}: {}", tx, peer, e);
                    }
                    trace!("Adding tx hash {} to cache for {}", tx, peer);
                    // Set it as "In" so we can't get it back as we are the sender of it
                    txs_cache.put(tx.clone(), Direction::In);
                } else {
                    trace!("{} have tx hash {} in cache, skipping", peer, tx);
                }
            }
        }
    }

    // Broadcast the block to all peers that can directly accept this new block
    pub async fn broadcast_block(&self, block: &BlockHeader, cumulative_difficulty: CumulativeDifficulty, our_topoheight: u64, our_height: u64, pruned_topoheight: Option<u64>, hash: &Hash, lock: bool) {
        debug!("Broadcasting block {} at height {}", hash, block.get_height());
        // We build the ping packet ourself this time (we have enough data for it)
        // because this function can be call from Blockchain, which would lead to a deadlock.
        let ping = Ping::new(Cow::Borrowed(hash), our_topoheight, our_height, pruned_topoheight, cumulative_difficulty, IndexSet::new());
        let block_packet = Packet::BlockPropagation(PacketWrapper::new(Cow::Borrowed(block), Cow::Borrowed(&ping)));
        let packet_block_bytes = Bytes::from(block_packet.to_bytes());
        let packet_ping_bytes = Bytes::from(Packet::Ping(Cow::Owned(ping)).to_bytes());

        trace!("Locking peer list for broadcasting block {}", hash);
        trace!("start broadcasting block {} to all peers", hash);
        for peer in self.peer_list.get_cloned_peers().await {
            // If the peer can directly accept this new block, send it
            let peer_height = peer.get_height();

            // If the peer is not too far from us, send the block.
            // Ensure the peer height is greater than or equal to the block height 
            // but still within STABLE_LIMIT, or check that the peer height is at most 
            // one block behind (block height is always +1 above the highest tip height, 
            // so checking if peer height is not above block height + 1 suffices in most cases).
            // The chain can accept old blocks (up to STABLE_LIMIT), but new blocks only N+1.
            if (peer_height >= block.get_height() && peer_height - block.get_height() <= STABLE_LIMIT) || (peer_height <= block.get_height() && block.get_height() - peer_height <= 1) {
                trace!("locking blocks propagation for peer {}", peer);
                let mut blocks_propagation = peer.get_blocks_propagation().lock().await;
                trace!("end locking blocks propagation for peer {}", peer);
                // Check that this block was never shared with this peer
                if !blocks_propagation.contains(hash) {
                    // We broadcasted to him, add it to the cache.
                    // He should not send it back to us if it's a block found by us.
                    blocks_propagation.put(hash.clone(), if lock { Direction::Both } else { Direction::Out });

                    debug!("Broadcast {} to {} (lock: {})", hash, peer, lock);
                    if let Err(e) = peer.send_bytes(packet_block_bytes.clone()).await {
                        debug!("Error on broadcast block {} to {}: {}", hash, peer, e);
                    }
                    trace!("{} has been broadcasted to {}", hash, peer);
                } else {
                    debug!("{} contains {}, don't broadcast block to him", peer, hash);
                    // But we can notify him with a ping packet that we got the block
                    if let Err(e) = peer.send_bytes(packet_ping_bytes.clone()).await {
                        debug!("Error on sending ping for notifying that we accepted the block {} to {}: {}", hash, peer, e);
                    } else {
                        trace!("{} has been notified that we have the block {}", peer, hash);
                        peer.set_last_ping_sent(get_current_time_in_seconds());
                    }
                }
            } else {
                trace!("Cannot broadcast {} at height {} to {}, too far", hash, block.get_height(), peer);
            }
        }
        trace!("broadcasting block {} is done", hash);
    }

    // Handle a bootstrap chain request
    // We have different steps available for a bootstrap sync
    // We verify that they are sent in the correct order.
    async fn handle_bootstrap_chain_request(self: &Arc<Self>, peer: &Arc<Peer>, request: StepRequest<'_>) -> Result<(), BlockchainError> {
        let request_kind = request.kind();
        debug!("Handle bootstrap chain request {:?} from {}", request_kind, peer);

        let storage = self.blockchain.get_storage().read().await;
        let pruned_topoheight = storage.get_pruned_topoheight().await?.unwrap_or(0);
        if let Some(topoheight) = request.get_requested_topoheight() {
            let our_topoheight = self.blockchain.get_topo_height();
            if
                pruned_topoheight >= topoheight
                || topoheight > our_topoheight
                || topoheight < PRUNE_SAFETY_LIMIT
            {
                warn!("Invalid begin topoheight (received {}, our is {}, pruned: {}) received from {} on step {:?}", topoheight, our_topoheight, pruned_topoheight, peer, request_kind);
                return Err(P2pError::InvalidRequestedTopoheight.into())
            }

            // Check that the block is stable
            let hash = storage.get_hash_at_topo_height(topoheight).await?;
            if !self.blockchain.is_sync_block(&storage, &hash).await? {
                warn!("Requested topoheight {} is not stable, ignoring", topoheight);
                return Err(P2pError::InvalidRequestedTopoheight.into())
            }
        }

        let response = match request {
            StepRequest::ChainInfo(blocks) => {
                let common_point = self.find_common_point(&*storage, blocks).await?;
                let tips = storage.get_tips().await?;
                let (hash, height) = self.blockchain.find_common_base::<S, _>(&storage, &tips).await?;
                let stable_topo = storage.get_topo_height_for_hash(&hash).await?;
                StepResponse::ChainInfo(common_point, stable_topo, height, hash)
            },
            StepRequest::Assets(min, max, page) => {
                if min > max {
                    warn!("Invalid range for assets");
                    return Err(P2pError::InvalidPacket.into())
                }

                let page = page.unwrap_or(0);
                let assets = storage.get_partial_assets(MAX_ITEMS_PER_PAGE, page as usize * MAX_ITEMS_PER_PAGE, min, max).await?;
                let page = if assets.len() == MAX_ITEMS_PER_PAGE {
                    Some(page + 1)
                } else {
                    None
                };
                StepResponse::Assets(assets, page)
            },
            StepRequest::Balances(key, asset, min, max) => {
                if min > max {
                    warn!("Invalid range for account balance");
                    return Err(P2pError::InvalidPacket.into())
                }

                let mut balances = Vec::with_capacity(MAX_ITEMS_PER_PAGE);
                for key in key.iter() {
                    trace!("Requesting balance for {} requested by {} for bootstrap chain", key.as_address(true), peer);
                    let balance = storage.get_account_summary_for(&key, &asset, min, max).await?;
                    balances.push(balance);
                }

                trace!("Sending {} balances to {}", balances.len(), peer);
                StepResponse::Balances(balances)
            },
            StepRequest::Nonces(topoheight, keys) => {
                let mut nonces = Vec::with_capacity(keys.len());
                for key in keys.iter() {
                    let nonce = storage.get_nonce_at_maximum_topoheight(key, topoheight).await?.map(|(_, v)| v.get_nonce()).unwrap_or(0);
                    nonces.push(nonce);
                }
                StepResponse::Nonces(nonces)
            },
            StepRequest::Keys(min, max, page) => {
                if min > max {
                    warn!("Invalid range for keys");
                    return Err(P2pError::InvalidPacket.into())
                }

                let page = page.unwrap_or(0);
                let keys = storage.get_registered_keys(MAX_ITEMS_PER_PAGE, page as usize * MAX_ITEMS_PER_PAGE, min, max).await?;
                let page = if keys.len() == MAX_ITEMS_PER_PAGE {
                    Some(page + 1)
                } else {
                    None
                };
                StepResponse::Keys(keys, page)
            },
            StepRequest::BlocksMetadata(topoheight) => {
                let mut blocks = IndexSet::with_capacity(PRUNE_SAFETY_LIMIT as usize);
                // Go from the lowest available point until the requested stable topoheight
                let lower = if topoheight - PRUNE_SAFETY_LIMIT <= pruned_topoheight {
                    pruned_topoheight + 1
                } else {
                    topoheight - PRUNE_SAFETY_LIMIT
                };

                for topoheight in (lower..=topoheight).rev() {
                    let hash = storage.get_hash_at_topo_height(topoheight).await?;
                    let supply = storage.get_supply_at_topo_height(topoheight).await?;
                    let reward = storage.get_block_reward_at_topo_height(topoheight)?;
                    let difficulty = storage.get_difficulty_for_block_hash(&hash).await?;
                    let cumulative_difficulty = storage.get_cumulative_difficulty_for_block_hash(&hash).await?;
                    let p = storage.get_estimated_covariance_for_block_hash(&hash).await?;

                    blocks.insert(BlockMetadata { hash, supply, reward, difficulty, cumulative_difficulty, p });
                }
                StepResponse::BlocksMetadata(blocks)
            },
        };
        peer.send_packet(Packet::BootstrapChainResponse(BootstrapChainResponse::new(response))).await?;
        Ok(())
    }

    // Build a block id list to share our DAG order and chain state.
    // Block id list must be in descending order and unique hash / topoheight.
    // This is used to search the common point between two peers.
    async fn build_list_of_blocks_id(&self, storage: &S) -> Result<IndexSet<BlockId>, BlockchainError> {
        let mut blocks = IndexSet::new();
        let topoheight = self.blockchain.get_topo_height();
        let pruned_topoheight = storage.get_pruned_topoheight().await?.unwrap_or(0);
        let mut i = 0;

        // We add 1 for the genesis block added below
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

        // Add genesis block
        let genesis_block = storage.get_hash_at_topo_height(0).await?;
        blocks.insert(BlockId::new(genesis_block, 0));
        Ok(blocks)
    }


    // Update all keys using bootstrap request.
    // This will fetch the nonce and associated balance for each asset.
    async fn update_bootstrap_keys(&self, peer: &Arc<Peer>, keys: &IndexSet<PublicKey>, our_topoheight: u64, stable_topoheight: u64) -> Result<(), P2pError> {
        if keys.is_empty() {
            warn!("No keys to update");
            return Ok(())
        }

        let StepResponse::Nonces(nonces) = peer.request_boostrap_chain(StepRequest::Nonces(stable_topoheight, Cow::Borrowed(&keys))).await? else {
            // Shouldn't happen
            error!("Received an invalid StepResponse (how ?) while fetching nonces");
            return Err(P2pError::InvalidPacket.into())
        };

        {
            let mut storage = self.blockchain.get_storage().write().await;
            // Save all nonces
            for (key, nonce) in keys.iter().zip(nonces) {
                debug!("Saving nonce {} for {}", nonce, key.as_address(self.blockchain.get_network().is_mainnet()));
                storage.set_last_nonce_to(key, stable_topoheight, &VersionedNonce::new(nonce, None)).await?;
                storage.set_account_registration_topoheight(key, stable_topoheight).await?;
            }
        }

        let mut page = 0;
        loop {
            // Retrieve chunked assets
            let assets = {
                let storage = self.blockchain.get_storage().read().await;
                let assets = storage.get_chunked_assets(MAX_ITEMS_PER_PAGE, page * MAX_ITEMS_PER_PAGE).await?;
                if assets.is_empty() {
                    break;
                }
                page += 1;
                assets
            };

            // Request every asset balance
            for asset in assets {
                debug!("Requesting balances for asset {} at topo {}", asset, stable_topoheight);
                let StepResponse::Balances(balances) = peer.request_boostrap_chain(StepRequest::Balances(Cow::Borrowed(&keys), Cow::Borrowed(&asset), our_topoheight, stable_topoheight)).await? else {
                    // Shouldn't happen
                    error!("Received an invalid StepResponse (how ?) while fetching balances");
                    return Err(P2pError::InvalidPacket.into())
                };

                // Save all balances for this asset
                for (key, balance) in keys.iter().zip(balances) {
                    // Check that the account has a balance for this asset
                    if let Some(account) = balance {
                        debug!("Saving balance {} summary for {}", asset, key.as_address(self.blockchain.get_network().is_mainnet()));
                        let ((stable_topo, stable), output) = account.as_versions();
                        let mut storage = self.blockchain.get_storage().write().await;
                        storage.set_last_balance_to(key, &asset, stable_topo, &stable).await?;

                        // Save the output balance if it's different from the stable one
                        if let Some((topo, output)) = output{
                            storage.set_balance_at_topoheight(&asset, topo, key, &output).await?;
                        }

                        // TODO clean up old balances
                    } else {
                        debug!("No balance for key {} at topoheight {}", key.as_address(self.blockchain.get_network().is_mainnet()), stable_topoheight);
                    }
                }
            }
        }

        Ok(())
    }
    // First, retrieve chain info from the selected peer.
    // Retrieve all assets through pagination.
    // Fetch all keys with their nonces and balances, also through pagination.
    // Finally, retrieve the last STABLE TOPOHEIGHT - PRUNE_SAFETY_LIMIT blocks.
    // Reload blockchain cache from disk, and we're ready to sync the rest of the chain.
    // NOTE: It could be faster without retrieving each TX, but we do it if pruning is not enabled.
    async fn bootstrap_chain(&self, peer: &Arc<Peer>) -> Result<(), BlockchainError> {
        info!("Starting fast sync with {}", peer);

        let mut our_topoheight = self.blockchain.get_topo_height();

        let mut stable_topoheight = 0;
        let mut step: Option<StepRequest> = {
            let storage = self.blockchain.get_storage().read().await;
            Some(StepRequest::ChainInfo(self.build_list_of_blocks_id(&*storage).await?))
        };

        // Keep them in memory and add them during syncing to prevent sync failure.
        let mut top_topoheight: u64 = 0;
        let mut top_height: u64 = 0;
        let mut top_block_hash: Option<Hash> = None;

        loop {
            let response = if let Some(step) = step.take() {
                info!("Requesting step {:?}", step.kind());
                // This will also verify that the received step is the requested one
                peer.request_boostrap_chain(step).await?
            } else {
                break;
            };

            step = match response {
                StepResponse::ChainInfo(common_point, topoheight, height, hash) => {
                    // First, check the common point in case we deviated from the chain
                    if let Some(common_point) = common_point {
                        let mut storage = self.blockchain.get_storage().write().await;
                        debug!("Unverified common point found at {} with hash {}", common_point.get_topoheight(), common_point.get_hash());
                        let hash_at_topo = storage.get_hash_at_topo_height(common_point.get_topoheight()).await?;
                        if hash_at_topo != *common_point.get_hash() {
                            warn!("Common point is {} while our hash at topoheight {} is {}. Aborting", common_point.get_hash(), common_point.get_topoheight(), storage.get_hash_at_topo_height(common_point.get_topoheight()).await?);
                            return Err(BlockchainError::Unknown)
                        }

                        let top_block_hash = storage.get_top_block_hash().await?;
                        if *common_point.get_hash() != top_block_hash {
                            let pruned_topoheight = storage.get_pruned_topoheight().await?.unwrap_or(0);
                            
                            warn!("Common point is {} while our top block hash is {} !", common_point.get_hash(), top_block_hash);
                            // Count how much blocks we need to pop
                            let pop_count = if pruned_topoheight >= common_point.get_topoheight() {
                                our_topoheight - pruned_topoheight
                            } else {
                                our_topoheight - common_point.get_topoheight()
                            };
                            warn!("We need to pop {} blocks for fast sync", pop_count);
                            our_topoheight = self.blockchain.rewind_chain_for_storage(&mut *storage, pop_count, !peer.is_priority()).await?;
                            debug!("New topoheight after rewind is now {}", our_topoheight);
                        }
                    } else {
                        warn!("No common point with {} ! Not same chain ?", peer);
                        return Err(BlockchainError::Unknown)
                    }

                    top_topoheight = topoheight;
                    top_height = height;
                    top_block_hash = Some(hash);
                    stable_topoheight = topoheight;

                    Some(StepRequest::Assets(our_topoheight, topoheight, None))
                },
                // Fetch all assets from peer
                StepResponse::Assets(assets, next_page) => {
                    {
                        let mut storage = self.blockchain.get_storage().write().await;
                        for asset in assets {
                            let (asset, data) = asset.consume();
                            debug!("Saving asset {} at topoheight {}", asset, stable_topoheight);
                            storage.add_asset(&asset, data).await?;
                        }
                    }

                    if next_page.is_some() {
                        Some(StepRequest::Assets(our_topoheight, stable_topoheight, next_page))
                    } else {
                        // We must handle all stored keys before extending our ledger
                        let mut minimum_topoheight = 0;
                        loop {

                            let keys = {
                                let storage = self.blockchain.get_storage().read().await;
                                let keys = storage.get_registered_keys(MAX_ITEMS_PER_PAGE, 0, minimum_topoheight, our_topoheight).await?;

                                // Keys are sorted by topoheight, so we get the minimum topoheight
                                // of the last key to avoid fetching the same keys again.
                                // Using skip might miss some keys because update_bootstrap_keys can reorganize the keys.
                                // This solution might duplicate some keys. We could fetch all in one
                                // request and store them in memory, but consider future scalability
                                // with potentially millions of accounts in memory :)
                                if let Some(key) = keys.last() {
                                    minimum_topoheight = storage.get_account_registration_topoheight(key).await?;
                                } else {
                                    break;
                                }

                                keys
                            };

                            self.update_bootstrap_keys(peer, &keys, our_topoheight, stable_topoheight).await?;
                            if keys.len() < MAX_ITEMS_PER_PAGE {
                                break;
                            }
                        }

                        // Go to next step
                        Some(StepRequest::Keys(our_topoheight, stable_topoheight, None))
                    }
                },
                // Fetch all new accounts
                StepResponse::Keys(keys, next_page) => {
                    debug!("Requesting nonces for keys");
                    self.update_bootstrap_keys(peer, &keys, our_topoheight, stable_topoheight).await?;                    

                    if next_page.is_some() {
                        Some(StepRequest::Keys(our_topoheight, stable_topoheight, next_page))
                    } else {
                        // Go to next step
                        Some(StepRequest::BlocksMetadata(stable_topoheight))
                    }
                },
                StepResponse::BlocksMetadata(blocks) => {
                    // Last N blocks + stable block
                    if blocks.len() != PRUNE_SAFETY_LIMIT as usize + 1 {
                        error!("Received {} blocks metadata while expecting {}", blocks.len(), PRUNE_SAFETY_LIMIT + 1);
                        return Err(P2pError::InvalidPacket.into())
                    }

                    let mut lowest_topoheight = stable_topoheight;
                    for (i, metadata) in blocks.into_iter().enumerate() {
                        let topoheight = stable_topoheight - i as u64;
                        trace!("Processing block metadata {} at topoheight {}", metadata.hash, topoheight);
                        // Check that we don't already have this block in storage
                        if self.blockchain.has_block(&metadata.hash).await? {
                            warn!("Block {} at topo {} already in storage, skipping", metadata.hash, topoheight);
                            continue;
                        }

                        lowest_topoheight = topoheight;
                        debug!("Saving block metadata {}", metadata.hash);
                        let OwnedObjectResponse::BlockHeader(header, hash) = peer.request_blocking_object(ObjectRequest::BlockHeader(metadata.hash)).await? else {
                            error!("Received an invalid requested object while fetching blocks metadata");
                            return Err(P2pError::InvalidPacket.into())
                        };

                        let mut txs = Vec::with_capacity(header.get_txs_hashes().len());
                        debug!("Retrieving {} txs for block {}", header.get_txs_count(), hash);
                        for tx_hash in header.get_txs_hashes() {
                            trace!("Retrieving TX {} for block {}", tx_hash, hash);
                            let tx = if self.blockchain.has_tx(tx_hash).await? {
                                Immutable::Arc(self.blockchain.get_tx(tx_hash).await?)
                            } else {
                                let OwnedObjectResponse::Transaction(tx, _) = peer.request_blocking_object(ObjectRequest::Transaction(tx_hash.clone())).await? else {
                                    error!("Received an invalid requested object while fetching block transaction {}", tx_hash);
                                    return Err(P2pError::InvalidObjectResponseType.into())
                                };
                                Immutable::Owned(tx)
                            };
                            trace!("TX {} ok", tx_hash);
                            txs.push(tx);
                        }

                        // Link its TX to the block
                        let mut storage = self.blockchain.get_storage().write().await;
                        for tx_hash in header.get_txs_hashes() {
                            storage.add_block_for_tx(tx_hash, &hash)?;
                        }

                        // Save metadata of this block
                        storage.set_supply_at_topo_height(lowest_topoheight, metadata.supply)?;
                        storage.set_block_reward_at_topo_height(lowest_topoheight, metadata.reward)?;
                        storage.set_topo_height_for_block(&hash, lowest_topoheight).await?;

                        storage.set_cumulative_difficulty_for_block_hash(&hash, metadata.cumulative_difficulty).await?;

                        // Save the block with its transactions, difficulty
                        storage.save_block(Arc::new(header), &txs, metadata.difficulty, metadata.p, hash).await?;
                    }

                    let mut storage = self.blockchain.get_storage().write().await;

                    // Create a snapshots for all others keys that didn't got updated
                    // storage.create_snapshot_balances_at_topoheight(lowest_topoheight).await?;
                    storage.create_snapshot_nonces_at_topoheight(lowest_topoheight).await?;
                    storage.create_snapshot_registrations_at_topoheight(lowest_topoheight).await?;

                    // Delete all old data
                    // storage.delete_versioned_balances_below_topoheight(lowest_topoheight).await?;
                    storage.delete_versioned_nonces_below_topoheight(lowest_topoheight).await?;
                    storage.delete_registrations_below_topoheight(lowest_topoheight).await?;

                    storage.set_pruned_topoheight(lowest_topoheight).await?;
                    storage.set_top_topoheight(top_topoheight)?;
                    storage.set_top_height(top_height)?;
                    storage.store_tips(&HashSet::from([top_block_hash.take().expect("Expected top block hash for fast sync")]))?;

                    None
                },
                response => {
                    // Shouldn't happens
                    error!("Received bootstrap chain response {:?} but didn't asked for it", response);
                    return Err(P2pError::InvalidPacket.into());
                }
            };
        }
        self.blockchain.reload_from_disk().await?;
        info!("Fast sync done with {}", peer);

        Ok(())
    }

    // Request the inventory of a peer.
    // This will send him a request packet so we get notified of all its TXs hashes in its mempool.
    async fn request_inventory_of(&self, peer: &Arc<Peer>) -> Result<(), BlockchainError> {
        debug!("Requesting inventory of {}", peer);
        let packet = Cow::Owned(NotifyInventoryRequest::new(None));
        let ping = Cow::Owned(self.build_generic_ping_packet().await);
        peer.set_requested_inventory(true);
        peer.send_packet(Packet::NotifyInventoryRequest(PacketWrapper::new(packet, ping))).await?;
        Ok(())
    }

    // This function sends all our blocks in topological order (topoheight).
    // We send up to CHAIN_SYNC_REQUEST_MAX_BLOCKS block IDs (combination of block hash and topoheight).
    // The genesis block is included to ensure we align with other peers.
    // It is used to find a common point with the peer when requesting the chain.
    pub async fn request_sync_chain_for(&self, peer: &Arc<Peer>, last_chain_sync: &mut TimestampMillis, skip_stable_height_check: bool) -> Result<(), BlockchainError> {
        trace!("Requesting chain from {}", peer);

        // This can be configured by the node operator and adjusted within protocol bounds
        // and based on peer configuration. It allows for faster syncing for those who want it
        // and can be used to conserve resources for lower-end devices.
        let requested_max_size = self.max_chain_response_size;

        let packet = {
            let storage = self.blockchain.get_storage().read().await;
            let request = ChainRequest::new(self.build_list_of_blocks_id(&*storage).await?, requested_max_size as u16);
            trace!("Built a chain request with {} blocks", request.size());
            let ping = self.build_generic_ping_packet_with_storage(&*storage).await;
            PacketWrapper::new(Cow::Owned(request), Cow::Owned(ping))
        };

        let response = peer.request_sync_chain(packet).await?;

        // Check that the peer followed our requirements
        if response.blocks_size() > requested_max_size {
            return Err(P2pError::InvalidChainResponseSize(response.blocks_size(), requested_max_size).into())
        }

        // Update last chain sync time
        *last_chain_sync = get_current_time_in_millis();

        self.handle_chain_response(peer, response, requested_max_size, skip_stable_height_check).await
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

// Check if a socket address is a valid address.
// Only public and private addresses that can be used in a network are considered valid.
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