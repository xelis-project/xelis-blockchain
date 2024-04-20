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
    block::{Block, BlockHeader},
    config::{TIPS_LIMIT, VERSION},
    crypto::{Hash, Hashable},
    difficulty::CumulativeDifficulty,
    immutable::Immutable,
    serializer::Serializer,
    time::{
        get_current_time_in_millis,
        get_current_time_in_seconds,
        TimestampMillis
    }
};
use crate::{
    config::{
        get_genesis_block_hash, get_seed_nodes,
        CHAIN_SYNC_DEFAULT_RESPONSE_BLOCKS, CHAIN_SYNC_DELAY, CHAIN_SYNC_REQUEST_EXPONENTIAL_INDEX_START,
        CHAIN_SYNC_REQUEST_MAX_BLOCKS, CHAIN_SYNC_RESPONSE_MIN_BLOCKS, CHAIN_SYNC_TOP_BLOCKS, PEER_MAX_PACKET_SIZE,
        MILLIS_PER_SECOND, NETWORK_ID, P2P_EXTEND_PEERLIST_DELAY, P2P_PING_DELAY, P2P_PING_PEER_LIST_DELAY, P2P_PING_PEER_LIST_LIMIT,
        PEER_FAIL_LIMIT, PEER_TIMEOUT_INIT_CONNECTION, PRUNE_SAFETY_LIMIT, STABLE_LIMIT
    },
    core::{
        blockchain::Blockchain,
        error::BlockchainError,
        storage::Storage
    },
    p2p::{
        chain_validator::ChainValidator,
        connection::ConnectionMessage,
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
    packet::{
        chain::{BlockId, ChainRequest, ChainResponse},
        object::{ObjectRequest, ObjectResponse, OwnedObjectResponse},
        handshake::Handshake,
        ping::Ping,
        {Packet, PacketWrapper}
    },
    peer::Peer,
    tracker::{ObjectTracker, SharedObjectTracker},
    peer_list::{SharedPeerList, PeerList},
    connection::{State, Connection},
    error::P2pError
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{
            self, UnboundedSender, UnboundedReceiver,
            Sender, Receiver, unbounded_channel
        },
        Mutex
    },
    select,
    task::JoinHandle,
    io::AsyncWriteExt,
    time::{interval, timeout, sleep}
};
use log::{info, warn, error, debug, trace};
use std::{
    num::NonZeroUsize,
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering}
    },
    collections::{hash_map::Entry, HashSet},
    convert::TryInto,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use bytes::Bytes;
use rand::Rng;

enum MessageChannel {
    Exit,
    Connect((SocketAddr, bool))
}

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
    connections_sender: UnboundedSender<MessageChannel>,
    // used to requests objects to peers and avoid requesting the same object to multiple peers
    object_tracker: SharedObjectTracker,
    // used to check if the server is running or not in tasks
    is_running: AtomicBool,
    // Synced cache to prevent concurrent tasks adding the block
    blocks_propagation_queue: Mutex<LruCache<Hash, ()>>,
    // Sender for the blocks processing task to have a ordered queue
    blocks_processor: Sender<(Arc<Peer>, BlockHeader, Hash)>,
    // allow fast syncing (only balances / assets / Smart Contracts changes)
    // without syncing the history
    allow_fast_sync_mode: bool,
    // This can be used safely from a trusted node
    // to boost the sync speed by allowing to request several blocks at same time
    allow_boost_sync_mode: bool,
    // max size of the chain response
    // this is a configurable paramater for nodes to manage their resources
    // Can be reduced for low devices, and increased for high end devices
    // You may sync faster or slower depending on this value
    max_chain_response_size: usize,
    // Configured exclusive nodes
    // If not empty, no other peer than those listed can connect to this node
    exclusive_nodes: HashSet<SocketAddr>,
    // Are we allowing others nodes to share us as a potential peer ?
    // Also if we allows to be listed in get_peers RPC API
    sharable: bool,
    // Are we syncing the chain with another peer
    is_syncing: AtomicBool,
}

impl<S: Storage> P2pServer<S> {
    pub fn new(dir_path: Option<String>, tag: Option<String>, max_peers: usize, bind_address: String, blockchain: Arc<Blockchain<S>>, use_peerlist: bool, exclusive_nodes: Vec<SocketAddr>, allow_fast_sync_mode: bool, allow_boost_sync_mode: bool, max_chain_response_size: Option<usize>, sharable: bool) -> Result<Arc<Self>, P2pError> {
        if let Some(tag) = &tag {
            debug_assert!(tag.len() > 0 && tag.len() <= 16);
        }

        if let Some(max_chain_response_size) = max_chain_response_size {
            debug_assert!(max_chain_response_size >= CHAIN_SYNC_RESPONSE_MIN_BLOCKS && max_chain_response_size <= CHAIN_SYNC_REQUEST_MAX_BLOCKS);
        }

        // set channel to communicate with listener thread
        let mut rng = rand::thread_rng();
        let peer_id: u64 = rng.gen(); // generate a random peer id for network
        let addr: SocketAddr = bind_address.parse()?; // parse the bind address
        // create mspc channel for connections to peers
        let (connections_sender, connections_receiver) = mpsc::unbounded_channel();
        let (blocks_processor, blocks_processor_receiver) = mpsc::channel(TIPS_LIMIT * STABLE_LIMIT as usize);
        let object_tracker = ObjectTracker::new(blockchain.clone());

        let (sender, event_receiver) = unbounded_channel::<Arc<Peer>>(); 
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
            exclusive_nodes: HashSet::from_iter(exclusive_nodes.into_iter()),
            sharable,
            is_syncing: AtomicBool::new(false),
        };

        let arc = Arc::new(server);
        {
            let zelf = Arc::clone(&arc);
            tokio::spawn(async move {
                if let Err(e) = zelf.start(connections_receiver, blocks_processor_receiver, event_receiver, use_peerlist).await {
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

        if let Err(e) = self.connections_sender.send(MessageChannel::Exit) {
            error!("Error while sending Exit message to stop accepting new connections: {}", e);
        }

        info!("Waiting for all peers to be closed...");
        let mut peers = self.peer_list.write().await;
        peers.close_all().await;
        info!("P2p Server is now stopped!");
    }

    // Verify if we are still running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Acquire)
    }

    // Connect to nodes which aren't already connected in parameters
    async fn connect_to_nodes(self: &Arc<Self>, nodes: impl Iterator<Item = SocketAddr>) -> Result<(), P2pError> {
        for addr in nodes {
            if self.accept_new_connections().await {
                if !self.is_connected_to_addr(&addr).await? {
                    self.try_to_connect_to_peer(addr, true).await;
                }
            }
        }
        Ok(())
    }

    // every 10 seconds, verify and connect if necessary
    async fn maintains_connection_to_nodes(self: &Arc<Self>, nodes: HashSet<SocketAddr>) -> Result<(), P2pError> {
        debug!("Starting maintains seed nodes task...");
        let mut interval = interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            if !self.is_running() {
                debug!("Maintains seed nodes task is stopped!");
                break;
            }

            if self.accept_new_connections().await {
                if let Err(e) = self.connect_to_nodes(nodes.iter().cloned()).await {
                    debug!("Error while connecting to seed nodes: {}", e);
                };
            }
        }

        Ok(())
    }

    // connect to seed nodes, start p2p server
    // and wait on all new connections
    async fn start(self: &Arc<Self>, mut receiver: UnboundedReceiver<MessageChannel>, blocks_processor_receiver: Receiver<(Arc<Peer>, BlockHeader, Hash)>, event_receiver: UnboundedReceiver<Arc<Peer>>, use_peerlist: bool) -> Result<(), P2pError> {
        let listener = TcpListener::bind(self.get_bind_address()).await?;
        info!("P2p Server will listen on: {}", self.get_bind_address());

        let mut exclusive_nodes = self.exclusive_nodes.clone();
        if exclusive_nodes.is_empty() {
            debug!("No exclusive nodes available, using seed nodes...");
            let network = self.blockchain.get_network();
            let seed_nodes = get_seed_nodes(&network);
            exclusive_nodes = seed_nodes.iter().map(|s| s.parse().unwrap()).collect();
        }

        // create tokio task to maintains connection to exclusive nodes or seed nodes
        let zelf = Arc::clone(self);
        tokio::spawn(async move {
            info!("Connecting to seed nodes...");
            if let Err(e) = zelf.maintains_connection_to_nodes(exclusive_nodes).await {
                error!("Error while maintening connection with seed nodes: {}", e);
            };
        });

        // start a new task for chain sync
        tokio::spawn(Arc::clone(&self).chain_sync_loop());

        // start another task for ping loop
        tokio::spawn(Arc::clone(&self).ping_loop());

        // start the blocks processing task to have a queued handler
        tokio::spawn(Arc::clone(&self).blocks_processing_task(blocks_processor_receiver));

        // start the event loop task to handle peer disconnect events
        tokio::spawn(Arc::clone(&self).event_loop(event_receiver));


        // start another task for peerlist loop
        if use_peerlist {
            tokio::spawn(Arc::clone(&self).peerlist_loop());
        }

        // only allocate one time the buffer for this packet
        let mut handshake_buffer = [0; 512];
        loop {
            let (connection, priority) = select! {
                res = listener.accept() => {
                    trace!("New listener result received (is err: {})", res.is_err());
                    let (mut stream, addr) = match res {
                        Ok((stream, addr)) => (stream, addr),
                        Err(e) => {
                            error!("Error while accepting new connection: {}", e);
                            continue;
                        }
                    };

                    // Verify if we can accept new connections
                    let reject = if !self.accept_new_connections().await { // if we have already reached the limit, we ignore this new connection
                        debug!("Max peers reached, rejecting connection");
                        true
                    } else if !self.is_compatible_with_exclusive_nodes(&addr) {
                        debug!("{} is not an exclusive node, reject connection", addr);
                        true
                    } else {
                        // check that this incoming peer isn't blacklisted
                        let peer_list = self.peer_list.read().await;
                        if !peer_list.is_allowed(&addr.ip()) {
                            debug!("{} is blacklisted, rejecting connection", addr);
                            true
                        } else {
                            false
                        }
                    };

                    // Reject connection
                    if reject {
                        if let Err(e) = stream.shutdown().await {
                            debug!("Error while closing & ignoring incoming connection {}: {}", addr, e);
                        }
                        continue;
                    }

                    let connection = Connection::new(stream, addr, false);
                    (connection, false)
                },
                Some(msg) = receiver.recv() => match msg {
                    MessageChannel::Exit => break,
                    MessageChannel::Connect((addr, priority)) => {
                        if !self.accept_new_connections().await {
                            trace!("Coudln't connect to {}, limit has been reached!", addr);
                            continue;
                        }

                        match self.connect_to_peer(addr).await {
                            Ok(connection) => (connection, priority),
                            Err(e) => {
                                trace!("Error while trying to connect to new outgoing peer: {}", e);
                                // if its a outgoing connection, increase its fail count
                                let mut peer_list = self.peer_list.write().await;
                                peer_list.increase_fail_count_for_saved_peer(&addr.ip());
                                continue;
                            }
                        }
                    }
                }
            };
            trace!("Handling new connection: {} (out = {}, priority = {})", connection, connection.is_out(), priority);
            if let Err(e) = self.handle_new_connection(&mut handshake_buffer, connection, priority).await {
                debug!("Error occured on handled connection: {}", e);
                // no need to close it here, as it will be automatically closed in drop
            }
        }

        Ok(())
    }

    // Verify handshake send by a new connection
    // based on data size, network ID, peers address validity
    // block height and block top hash of this peer (to know if we are on the same chain)
    async fn verify_handshake(&self, mut connection: Connection, handshake: Handshake<'_>, priority: bool) -> Result<Peer, P2pError> {
        if handshake.get_network() != self.blockchain.get_network() {
            trace!("{} has an invalid network: {}", connection, handshake.get_network());
            return Err(P2pError::InvalidNetwork)
        }

        if *handshake.get_network_id() != NETWORK_ID {
            trace!("{} has an invalid network id: {:#?}", connection, handshake.get_network_id());
            connection.close().await?;
            return Err(P2pError::InvalidNetworkID);
        }

        if self.is_connected_to(&handshake.get_peer_id()).await? {
            trace!("{} has an already used peer id {}", connection, handshake.get_peer_id());
            connection.close().await?;
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

        connection.set_state(State::Success);
        let peer = handshake.create_peer(connection, priority, Arc::clone(&self.peer_list));
        Ok(peer)
    }

    // Build a handshake packet
    // We feed the packet with all chain data
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

    // this function handle all new connections
    // A new connection have to send an Handshake
    // if the handshake is valid, we accept it & register it on server
    async fn handle_new_connection(self: &Arc<Self>, buf: &mut [u8], mut connection: Connection, priority: bool) -> Result<(), P2pError> {
        trace!("New connection: {}", connection);
        connection.exchange_keys(buf).await?;
        if connection.is_out() {
            self.send_handshake(&connection).await?;
        }

        let handshake: Handshake<'_> = match timeout(Duration::from_millis(PEER_TIMEOUT_INIT_CONNECTION), connection.read_packet(buf, buf.len() as u32)).await?? {
            Packet::Handshake(h) => h.into_owned(), // only allow handshake packet
            _ => return Err(P2pError::ExpectedHandshake)
        };
        trace!("received handshake packet!");
        connection.set_state(State::Handshake);
        let peer = self.verify_handshake(connection, handshake, priority).await?;
        trace!("Handshake has been verified");
        // if it's a outgoing connection, don't send the handshake back
        // because we have already sent it
        if !peer.is_out() {
            trace!("Sending handshake back to {}", peer);
            self.send_handshake(peer.get_connection()).await?;
        }

        // if we reach here, handshake is all good, we can start listening this new peer
        // we can save the peer in our peerlist
        let peer_id = peer.get_id(); // keep in memory the peer_id outside connection (because of moved value)
        let peer = {
            trace!("Locking peer list write mode (add peer)");
            let mut peer_list = self.peer_list.write().await;
            trace!("End locking peer list write mode (add peer)");
            peer_list.add_peer(peer_id, peer)
        };

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

        self.handle_connection(peer).await
    }

    // Verify that we don't have any exclusive nodes configured OR that we are part of this list
    pub fn is_compatible_with_exclusive_nodes(&self, addr: &SocketAddr) -> bool {
        self.exclusive_nodes.is_empty() || self.exclusive_nodes.contains(addr)
    }

    // Connect to a specific peer address
    // Buffer is passed in parameter to prevent the re-allocation each time
    pub async fn try_to_connect_to_peer(&self, addr: SocketAddr, priority: bool) {
        trace!("try to connect to peer addr {}, priority: {}", addr, priority);
        if !self.is_compatible_with_exclusive_nodes(&addr) {
            debug!("Not in exclusive node list: {}, skipping", addr);
            return;
        }

        {
            let peer_list = self.peer_list.read().await;
            trace!("peer list locked for trying to connect to peer {}", addr);
            if !peer_list.is_allowed(&addr.ip()) {
                debug!("{} is not allowed, we can't connect to it", addr);
                return;
            }
        }

        if let Err(e) = self.connections_sender.send(MessageChannel::Connect((addr, priority))) {
            error!("Error while trying to connect to address {} (priority = {}): {}", addr, priority, e);
        }
    }

    // Connect to a new peer using its socket address
    // We give up to 800 millis to connect to this address
    // Then we send him a handshake
    async fn connect_to_peer(&self, addr: SocketAddr) -> Result<Connection, P2pError> {
        trace!("Trying to connect to {}", addr);
        if self.is_connected_to_addr(&addr).await? {
            return Err(P2pError::PeerAlreadyConnected(format!("{}", addr)));
        }
        let stream = timeout(Duration::from_millis(800), TcpStream::connect(&addr)).await??; // allow maximum 800ms of latency
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
        let new_peers = Vec::new();
        Ping::new(Cow::Owned(block_top_hash), highest_topo_height, highest_height, pruned_topoheight, cumulative_difficulty, new_peers)
    }

    // Build a generic ping packet
    // This will lock the storage for us
    async fn build_generic_ping_packet(&self) -> Ping<'_> {
        let storage = self.blockchain.get_storage().read().await;
        self.build_generic_ping_packet_with_storage(&*storage).await
    }

    // select a random peer which is greater than us to sync chain
    // candidate peer should have a greater topoheight or a higher block height than us
    // It must also have a greater cumulative difficulty than us
    // Cumulative difficulty is used in case two chains are running at same speed
    // We must determine which one has the most work done
    // if we are not in fast sync mode, we must verify its pruned topoheight to be sure
    // he have the blocks we need
    async fn select_random_best_peer(&self, fast_sync: bool, previous_peer: Option<&(Arc<Peer>, bool)>) -> Result<Option<Arc<Peer>>, BlockchainError> {
        trace!("select random best peer");
        let peer_list = self.peer_list.read().await;
        trace!("peer list locked for select random best peer");
        let our_height = self.blockchain.get_height();
        let our_topoheight = self.blockchain.get_topo_height();

        // Search our cumulative difficulty
        let our_cumulative_difficulty = {
            debug!("locking storage to search our cumulative difficulty");
            let storage = self.blockchain.get_storage().read().await;
            let hash = storage.get_hash_at_topo_height(our_topoheight).await?;
            storage.get_cumulative_difficulty_for_block_hash(&hash).await?
        };

        // search for peers which are greater than us
        // and that are pruned but before our height so we can sync correctly
        let available_peers = peer_list.get_peers().values();
        // IndexSet is used to select by random index
        let mut peers: IndexSet<&Arc<Peer>> = IndexSet::with_capacity(available_peers.len());

        for p in available_peers {
            // Avoid selecting peers that have a weaker cumulative difficulty than us
            let cumulative_difficulty = p.get_cumulative_difficulty().lock().await;
            if *cumulative_difficulty <= our_cumulative_difficulty {
                continue;
            }

            let peer_topoheight = p.get_topoheight();
            if fast_sync {
                // if we want to fast sync, but this peer is not compatible, we skip it
                // for this we check that the peer topoheight is not less than the prune safety limit
                if peer_topoheight < PRUNE_SAFETY_LIMIT || our_topoheight + PRUNE_SAFETY_LIMIT > peer_topoheight {
                    continue;
                }
                if let Some(pruned_topoheight) = p.get_pruned_topoheight() {
                    // This shouldn't be possible if following the protocol,
                    // But we may never know if a peer is not following the protocol strictly
                    if peer_topoheight - pruned_topoheight < PRUNE_SAFETY_LIMIT {
                        continue;
                    }
                }
            } else {
                // check that the pruned topoheight is less than our topoheight to sync
                // so we can sync chain from pruned chains
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
            if peers.len() > 1 || *err {
                debug!("removing previous peer {} from random selection, err: {}", previous_peer, err);
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
        // clone the Arc to prevent the lock until the end of the sync request
        Ok(peers.swap_remove_index(selected).map(|p| Arc::clone(p)))
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
        self.is_syncing.store(syncing, Ordering::Release);
    }

    // Check if we are syncing the chain
    pub fn is_syncing_chain(&self) -> bool {
        self.is_syncing.load(Ordering::Acquire)
    }

    // This a infinite task that is running every CHAIN_SYNC_DELAY seconds
    // Based on the user configuration, it will try to sync the chain with another node with longest chain if any
    async fn chain_sync_loop(self: Arc<Self>) {
        // used to detect how much time we have to wait before next request
        let mut last_chain_sync = get_current_time_in_millis();
        let interval = Duration::from_secs(CHAIN_SYNC_DELAY);
        // Try to not reuse the same peer between each sync
        // Don't use it at all if its errored
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

            // first we have to check if we allow fast sync mode
            // and then we check if we have a potential peer above us to fast sync
            // otherwise we sync normally 
            let fast_sync = if self.allow_fast_sync() {
                trace!("locking peer list for fast sync check");
                let peerlist = self.peer_list.read().await;
                trace!("peer list locked for fast sync check");
                let our_topoheight = self.blockchain.get_topo_height();
                peerlist.get_peers().values().find(|p| {
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
                    if let Err(e) = self.request_sync_chain_for(&peer, &mut last_chain_sync).await {
                        warn!("Error occured on chain sync with {}: {}", peer, e);
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

    // broadcast generic ping packet every 10s
    // if we have to send our peerlist to all peers, we calculate the ping for each peer
    async fn ping_loop(self: Arc<Self>) {
        debug!("Starting ping loop...");

        let mut last_peerlist_update = get_current_time_in_seconds();
        let duration = Duration::from_secs(P2P_PING_DELAY);
        loop {
            trace!("Waiting for ping delay...");
            sleep(duration).await;

            let mut ping = self.build_generic_ping_packet().await;
            trace!("generic ping packet finished");

            let current_time = get_current_time_in_seconds();
            // check if its time to send our peerlist
            if current_time > last_peerlist_update + P2P_PING_PEER_LIST_DELAY {
                trace!("Sending ping packet with peerlist...");
                last_peerlist_update = current_time;
                trace!("locking peer list for ping loop extended");
                let peer_list = self.peer_list.read().await;
                trace!("peer list locked for ping loop extended");
                for peer in peer_list.get_peers().values() {
                    let new_peers = ping.get_mut_peers();
                    new_peers.clear();

                    // Is it a peer from our local network
                    let is_local_peer = is_local_address(peer.get_connection().get_address());

                    // all the peers we already shared with this peer
                    let mut shared_peers = peer.get_peers().lock().await;

                    // iterate through our peerlist to determinate which peers we have to send
                    for p in peer_list.get_peers().values() {
                        // don't send him itself
                        // and don't share a peer that don't want to be shared
                        if p.get_id() == peer.get_id() || !p.sharable() {
                            continue;
                        }

                        // if we haven't send him this peer addr and that he don't have him already, insert it
                        let addr = p.get_outgoing_address();

                        // Don't share local network addresses if it's external peer
                        if is_local_address(addr) && !is_local_peer {
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
                            // add it in our side to not re send it again
                            trace!("{} didn't received {} yet, adding it to peerlist in ping packet", peer.get_outgoing_address(), addr);

                            // add it to new list to send it
                            new_peers.push(*addr);
                            if new_peers.len() >= P2P_PING_PEER_LIST_LIMIT {
                                break;
                            }
                        }
                    }

                    // update the ping packet with the new peers
                    debug!("Set peers: {:?}, going to {}", new_peers, peer.get_outgoing_address());
                    // send the ping packet to the peer
                    if let Err(e) = peer.send_packet(Packet::Ping(Cow::Borrowed(&ping))).await {
                        debug!("Error sending specific ping packet to {}: {}", peer, e);
                    } else {
                        peer.set_last_ping_sent(current_time);
                    }
                }
            } else {
                trace!("Sending generic ping packet...");
                let packet = Packet::Ping(Cow::Owned(ping));
                let bytes = Bytes::from(packet.to_bytes());
                trace!("Locking peerlist... (generic ping)");
                let peerlist = self.peer_list.read().await;
                trace!("End locking peerlist... (generic ping)");
                // broadcast directly the ping packet asap to all peers
                for peer in peerlist.get_peers().values() {
                    trace!("broadcast generic ping packet to {}", peer);
                    if current_time - peer.get_last_ping_sent() > P2P_PING_DELAY {
                        if let Err(e) = peer.send_bytes(bytes.clone()).await {
                            error!("Error while trying to broadcast directly ping packet to {}: {}", peer, e);
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
                    let mut  peer_list = self.peer_list.write().await;
                    peer_list.find_peer_to_connect()
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
    async fn event_loop(self: Arc<Self>, mut receiver: UnboundedReceiver<Arc<Peer>>) {
        debug!("Starting event loop task...");
        while let Some(peer) = receiver.recv().await {
            if !self.is_running() {
                break;
            }

            if peer.sharable() {
                if let Some(rpc) = self.blockchain.get_rpc().read().await.as_ref() {
                    if rpc.is_event_tracked(&NotifyEvent::PeerDisconnected).await {
                        debug!("Notifying clients with PeerDisconnected event");
                        rpc.notify_clients_with(&NotifyEvent::PeerDisconnected, get_peer_entry(&peer).await).await;
                    }
                }
            }
        }
        debug!("Event loop task is stopped!");
    }

    // Task for all blocks propagation
    async fn blocks_processing_task(self: Arc<Self>, mut receiver: Receiver<(Arc<Peer>, BlockHeader, Hash)>) {
        debug!("Starting blocks processing task");
        while let Some((peer, header, block_hash)) = receiver.recv().await {
            let mut response_blockers: Vec<ResponseBlocker> = Vec::new();
            for hash in header.get_txs_hashes() {
                let contains = { // we don't lock one time because we may wait on p2p response
                    // Check in ObjectTracker
                    if let Some(response_blocker) = self.object_tracker.get_response_blocker_for_requested_object(hash).await {
                        trace!("{} is already requested, waiting on response blocker for block {}", hash, block_hash);
                        response_blockers.push(response_blocker);
                        true
                    } else {
                        self.blockchain.has_tx(hash).await.unwrap_or(false)
                    }
                };

                if !contains { // retrieve one by one to prevent acquiring the lock for nothing
                    debug!("Requesting TX {} to {} for block {}", hash, peer, block_hash);
                    if let Err(e) = self.object_tracker.request_object_from_peer(Arc::clone(&peer), ObjectRequest::Transaction(hash.clone()), false).await {
                            error!("Error while requesting TX {} to {} for block {}: {}", hash, peer, block_hash, e);
                            peer.increment_fail_count();
                            continue;
                    }

                    if let Some(response_blocker) = self.object_tracker.get_response_blocker_for_requested_object(hash).await {
                        response_blockers.push(response_blocker);
                    }
                }
            }

            // Wait on all already requested txs
            for mut blocker in response_blockers {
                if let Err(e) = blocker.recv().await {
                    // It's mostly a closed channel error, so we can ignore it
                    debug!("Error while waiting on response blocker: {}", e);
                }
            }

            // add immediately the block to chain as we are synced with
            let block = match self.blockchain.build_block_from_header(Immutable::Owned(header)).await {
                Ok(block) => block,
                Err(e) => {
                    error!("Error while building block {} from peer {}: {}", block_hash, peer, e);
                    peer.increment_fail_count();
                    continue;
                }
            };

            debug!("Adding received block {} from {} to chain", block_hash, peer);
            if let Err(e) = self.blockchain.add_new_block(block, true, false).await {
                error!("Error while adding new block from {}: {}", peer, e);
                peer.increment_fail_count();
            }
        }

        debug!("Blocks processing task ended");
    }

    // this function handle the logic to send all packets to the peer
    async fn handle_connection_write_side(&self, peer: &Arc<Peer>, rx: &mut UnboundedReceiver<ConnectionMessage>) -> Result<(), P2pError> {
        loop {
            // all packets to be sent
            if let Some(data) = rx.recv().await {
                if peer.get_connection().is_closed() {
                    break;
                }

                match data {
                    ConnectionMessage::Packet(bytes) => {
                        // there is a overhead of 4 for each packet (packet size u32 4 bytes, packet id u8 is counted in the packet size)
                        trace!("Sending packet with ID {}, size sent: {}, real size: {}", bytes[4], u32::from_be_bytes(bytes[0..4].try_into()?), bytes.len());
                        peer.get_connection().send_bytes(&bytes).await?;
                        trace!("data sucessfully sent!");
                    }
                    ConnectionMessage::Exit => {
                        trace!("Exit message received for peer {}", peer);
                        break;
                    }
                };
            } else {
                debug!("Closing write side because all senders are dropped");
                break;
            }
        }
        Ok(())
    }

    // This function is a separated task with its own buffer (1kB) to read and handle every packets from the peer sequentially
    async fn handle_connection_read_side(self: Arc<Self>, peer: &Arc<Peer>, mut write_task: JoinHandle<()>) -> Result<(), P2pError> {
        // allocate the unique buffer for this connection
        let mut buf = [0u8; 1024];
        loop {
            select! {
                biased;
                _ = &mut write_task => {
                    debug!("write task for {} has finished, stopping...", peer);
                    break;
                },
                res = self.listen_connection(&mut buf, &peer) => {
                    res?;

                    // check that we don't have too many fails
                    // otherwise disconnect peer
                    if peer.get_fail_count() >= PEER_FAIL_LIMIT {
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
    async fn handle_connection(self: &Arc<Self>, peer: Arc<Peer>) -> Result<(), P2pError> {
        // task for writing to peer
        let write_task = {
            let zelf = Arc::clone(self);
            let peer = Arc::clone(&peer);
            tokio::spawn(async move {
                let mut rx = peer.get_connection().get_rx().lock().await;
                if let Err(e) = zelf.handle_connection_write_side(&peer, &mut rx).await {
                    debug!("Error while writing to {}: {}", peer, e);
                    if !peer.get_connection().is_closed() {
                        if let Err(e) = peer.close().await {
                            debug!("Error while closing {} from write side: {}", peer, e);
                        }
                    }
                }
                rx.close(); // clean shutdown
            })
        };

        // task for reading from peer
        {
            let zelf = Arc::clone(&self);
            let peer = Arc::clone(&peer);
            tokio::spawn(async move {
                if let Err(e) = zelf.handle_connection_read_side(&peer, write_task).await {
                    debug!("Error while running read part from peer {}: {}", peer, e);
                    if !peer.get_connection().is_closed() {
                        if let Err(e) = peer.close().await {
                            debug!("Error while closing {} from read side: {}", peer, e);
                        }
                    }
                }
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
    async fn get_common_peers_for(&self, peer: &Arc<Peer>) -> Vec<Arc<Peer>> {
        debug!("get common peers for {}", peer);
        let peer_list = self.peer_list.read().await;
        trace!("locked peer_list, locking peers received (common peers)");
        let peer_peers = peer.get_peers().lock().await;
        trace!("locked peers received (common peers)");

        let mut common_peers = Vec::new();
        for (common_peer_addr, _) in peer_peers.iter().filter(|(_, direction)| **direction == Direction::Both) {
            // if we have a common peer with him
            if let Some(common_peer) = peer_list.get_peer_by_addr(common_peer_addr) {
                if peer.get_id() != common_peer.get_id() {
                    common_peers.push(common_peer.clone());
                }
            }
        }

        common_peers
    }

    // Main function used by every nodes connections
    // This is handling each packet available in our p2p protocol
    // Each packet is a enum variant
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

                // peer should not send us twice the same transaction
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

                // Check that the tx is not in mempool or on disk already
                if !self.blockchain.has_tx(&hash).await? {
                    trace!("Requesting tx {} propagated because we don't have it", hash);
                    if !self.object_tracker.request_object_from_peer(Arc::clone(peer), ObjectRequest::Transaction(hash.clone()), true).await? {
                        debug!("TX propagated {} was already requested, ignoring", hash);
                    }
                }

                // Avoid sending the TX propagated to a common peer
                // because we track peerlist of each peers, we can try to determinate it
                // iterate over all common peers of this peer broadcaster
                for common_peer in self.get_common_peers_for(&peer).await {
                    debug!("{} is a common peer with {}, adding TX {} to its cache", common_peer, peer, hash);
                    let mut txs_cache = common_peer.get_txs_cache().lock().await;
                    // Set it as Out so we don't send it anymore but we can get it one time in case of bad common peer prediction
                    txs_cache.put(hash.clone(), Direction::Out);
                }
            },
            Packet::BlockPropagation(packet_wrapper) => {
                trace!("Received a block propagation packet from {}", peer);
                let (header, ping) = packet_wrapper.consume();
                ping.into_owned().update_peer(peer, &self.blockchain).await?;

                // check that the block height is valid
                let header = header.into_owned();
                let block_hash = header.hash();

                // verify that this block wasn't already sent by him
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

                // Avoid sending the same block to a common peer that may have already got it
                // because we track peerlist of each peers, we can try to determinate it
                for common_peer in self.get_common_peers_for(&peer).await {
                    debug!("{} is a common peer with {}, adding block {} to its propagation cache", common_peer, peer, block_hash);
                    let mut blocks_propagation = common_peer.get_blocks_propagation().lock().await;
                    // Out allow to get "In" again, because it's a prediction, don't block it completely
                    if !blocks_propagation.contains(&block_hash) {
                        blocks_propagation.put(block_hash.clone(), Direction::Out);
                    }
                }

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
                // Node is trying to ask too fast our chain
                if  last_request + CHAIN_SYNC_DELAY > time {
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
                // verify the respect of the coutdown to prevent massive packet incoming
                // if he send 4x faster than rules, throw error (because of connection latency / packets being queued)
                // let last_ping = peer.get_last_ping();
                // Disabled for testing block notification
                // if current_time - last_ping < P2P_PING_DELAY / 4 && empty_peer_list {
                //     return Err(P2pError::PeerInvalidPingCoutdown)
                // }

                // update the last ping only if he respect the protocol rules
                peer.set_last_ping(current_time);

                // we verify the respect of the countdown of peer list updates to prevent any spam
                if !empty_peer_list {
                    trace!("received peer list from {}: {}", peer, ping.get_peers().len());
                    let last_peer_list = peer.get_last_peer_list();
                    let diff = current_time - last_peer_list;
                    if last_peer_list != 0 && diff < P2P_PING_PEER_LIST_DELAY {
                        return Err(P2pError::PeerInvalidPeerListCountdown(P2P_PING_PEER_LIST_DELAY - diff))
                    }
                    peer.set_last_peer_list(current_time);
                }

                let is_local_peer = is_local_address(peer.get_connection().get_address());
                for peer in ping.get_peers() {
                    if is_local_address(peer) && !is_local_peer {
                        error!("{} is a local address but peer is external", peer);
                        return Err(P2pError::InvalidPeerlist)
                    }

                    if !self.is_connected_to_addr(&peer).await? {
                        let peer = peer.clone();
                        self.try_to_connect_to_peer(peer, false).await;
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

                // check if we requested it from this peer
                let request = response.get_request();
                if peer.has_requested_object(&request).await {
                    let sender = peer.remove_object_request(request).await?;
                    // handle the response
                    if sender.send(response).is_err() {
                        error!("Error while sending object response to sender!");
                    }
                // check if the Object Tracker has requested this object
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

                let mempool = self.blockchain.get_mempool().read().await;
                let nonces_cache = mempool.get_caches();
                let all_txs = nonces_cache.values()
                    .flat_map(|v| v.get_txs())
                    .skip(skip).take(NOTIFY_MAX_LEN)
                    .map(|tx| Cow::Borrowed(tx.as_ref()))
                    .collect::<IndexSet<_>>();

                let next_page = {
                    let mempool_size = mempool.size();
                    if all_txs.len() == NOTIFY_MAX_LEN && mempool_size > skip && mempool_size - skip > NOTIFY_MAX_LEN {
                        Some(page_id + 1)
                    } else {
                        None
                    }
                };

                let packet = NotifyInventoryResponse::new(next_page, Cow::Owned(all_txs));
                peer.send_packet(Packet::NotifyInventoryResponse(packet)).await?
            },
            Packet::NotifyInventoryResponse(inventory) => {
                trace!("Received a notify inventory from {}", peer);
                if !peer.has_requested_inventory() {
                    warn!("Received a notify inventory from {} but we didn't request it", peer);
                    return Err(P2pError::InvalidPacket)
                }

                // we received the inventory
                peer.set_requested_inventory(false);
                peer.set_last_inventory(get_current_time_in_seconds());

                let next_page = inventory.next();
                {
                    let txs = inventory.get_txs();
                    let total_count = txs.len();

                    // check that the response was really full if he send us another "page"
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

                // request the next page
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

    // Listen to incoming packets from a connection
    // Packet is read from the same task always, while its handling is delegated to a unique task
    async fn listen_connection(self: &Arc<Self>, buf: &mut [u8], peer: &Arc<Peer>) -> Result<(), P2pError> {
        // Read & parse the packet
        // 16 additional bytes are for AEAD
        let packet = peer.get_connection().read_packet(buf, PEER_MAX_PACKET_SIZE).await?;
        let packet_id = packet.get_id();
        // Handle the packet
        if let Err(e) = self.handle_incoming_packet(&peer, packet).await {
            error!("Error occured while handling incoming packet #{} from {}: {}", packet_id, peer, e);
            peer.increment_fail_count();
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

    // search a common point between our blockchain and the peer's one
    // when the common point is found, start sending blocks from this point
    async fn handle_chain_request(self: &Arc<Self>, peer: &Arc<Peer>, blocks: IndexSet<BlockId>, accepted_response_size: usize) -> Result<(), BlockchainError> {
        debug!("handle chain request for {} with {} blocks", peer, blocks.len());
        let storage = self.blockchain.get_storage().read().await;
        // blocks hashes sent for syncing (topoheight ordered)
        let mut response_blocks = IndexSet::new();
        let mut top_blocks = IndexSet::new();
        // common point used to notify peer if he should rewind or not
        let common_point = self.find_common_point(&*storage, blocks).await?;
        // Lowest height of the blocks sent
        let mut lowest_common_height = None;

        if let Some(common_point) = &common_point {
            let mut topoheight = common_point.get_topoheight();
            // lets add all blocks ordered hash
            let top_topoheight = self.blockchain.get_topo_height();
            let stable_height = self.blockchain.get_stable_height();
            // used to detect if we find unstable height for alt tips
            let mut potential_unstable_height = None;
            // Search the lowest height
            let mut lowest_height = self.blockchain.get_height();
            // check to see if we should search for alt tips (and above unstable height)
            let should_search_alt_tips = top_topoheight - topoheight < accepted_response_size as u64;

            // complete ChainResponse blocks until we are full or that we reach the top topheight
            while response_blocks.len() < accepted_response_size && topoheight <= top_topoheight {
                trace!("looking for hash at topoheight {}", topoheight);
                let hash = storage.get_hash_at_topo_height(topoheight).await?;
                if should_search_alt_tips && potential_unstable_height.is_none() {
                    let height = storage.get_height_for_block_hash(&hash).await?;
                    if height >= stable_height {
                        debug!("Found unstable height at {}", height);
                        potential_unstable_height = Some(height);
                    }
                }

                // Find the lowest height
                let height = storage.get_height_for_block_hash(&hash).await?;
                if height < lowest_height {
                    lowest_height = height;
                }

                trace!("for chain request, adding hash {} at topoheight {}", hash, topoheight);
                response_blocks.insert(hash);
                topoheight += 1;
            }
            lowest_common_height = Some(lowest_height);

            // now, lets check if peer is near to be synced, and send him alt tips blocks
            if let Some(mut height) = potential_unstable_height {
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

    // Handle a chain response from another peer
    // We receive a list of blocks hashes ordered by their topoheight
    // It also contains a CommonPoint which is a block hash point where we have the same topoheight as our peer
    // Based on the lowest height of the chain sent, we may need to rewind some blocks
    // NOTE: Only a priority node can rewind below the stable height 
    async fn handle_chain_response(&self, peer: &Arc<Peer>, mut response: ChainResponse, requested_max_size: usize) -> Result<(), BlockchainError> {
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
            let mut count = if lowest_height <= self.blockchain.get_stable_height() {
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

        // merge both list together
        blocks.extend(top_blocks);

        // if node asks us to pop blocks, check that the peer's height/topoheight is in advance on us
        let peer_topoheight = peer.get_topoheight();
        if pop_count > 0
            && peer_topoheight > our_previous_topoheight
            && peer.get_height() >= our_previous_height
            // then, verify if it's a priority node, otherwise, check if we are connected to a priority node so only him can rewind us
            && (peer.is_priority() || !self.is_connected_to_a_synced_priority_node().await)
        {
            // check that if we can trust him
            if peer.is_priority() {
                warn!("Rewinding chain without checking because {} is a priority node (pop count: {})", peer, pop_count);
                // User trust him as a priority node, rewind chain without checking, allow to go below stable height also
                self.blockchain.rewind_chain(pop_count, false).await?;
            } else {
                // Verify that someone isn't trying to trick us
                if pop_count > blocks_len as u64 {
                    // TODO: maybe we could request its whole chain for comparison until chain validator has_higher_cumulative_difficulty ?
                    // If after going through all its chain and we still have a higher cumulative difficulty, we should not rewind 
                    warn!("{} sent us a pop count of {} but only sent us {} blocks, ignoring", peer, pop_count, blocks_len);
                    return Err(P2pError::InvalidPopCount(pop_count, blocks_len as u64).into())
                }

                // request all blocks header and verify basic chain structure
                // Starting topoheight must be the next topoheight after common block
                // Blocks in chain response must be ordered by topoheight otherwise it will give incorrect results 
                let mut chain_validator = ChainValidator::new(&self.blockchain, common_topoheight + 1);
                for hash in blocks {
                    trace!("Request block header for chain validator: {}", hash);

                    // check if we already have the block to not request it
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

                // peer chain looks correct, lets rewind our chain
                warn!("Rewinding chain because of {} (pop count: {})", peer, pop_count);
                self.blockchain.rewind_chain(pop_count, false).await?;

                // now retrieve all txs from all blocks header and add block in chain
                for (hash, header) in chain_validator.get_blocks() {
                    trace!("Processing block {} from chain validator", hash);
                    // we don't already have this block, lets retrieve its txs and add in our chain
                    if !self.blockchain.has_block(&hash).await? {
                        let mut transactions = Vec::new(); // don't pre allocate
                        for tx_hash in header.get_txs_hashes() {
                            // check first on disk in case it was already fetch by a previous block
                            // it can happens as TXs can be integrated in multiple blocks and executed only one time
                            // check if we find it
                            if let Some(tx) = self.blockchain.get_tx(tx_hash).await.ok() {
                                trace!("Found the transaction {} on disk", tx_hash);
                                transactions.push(Immutable::Arc(tx));
                            } else { // otherwise, ask it from peer
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
                        self.blockchain.add_new_block(block, false, false).await?; // don't broadcast block because it's syncing
                    }
                }
            }
        } else {
            // no rewind are needed, process normally
            // it will first add blocks to sync, and then all alt-tips blocks if any (top blocks)
            let mut total_requested: usize = 0;
            let mut final_blocker = None;
            // If boost sync is allowed, we can request all blocks in parallel,
            // Create a new group in Object Tracker to be notified of a failure
            let (group_id, mut notifier) = if self.allow_boost_sync() {
                let (group_id, notifier) = self.object_tracker.get_group_manager().next_group_id().await;
                (Some(group_id), Some(notifier))
            } else {
                (None, None)
            };

            // Peekable is here to help to know if we are at the last element
            // so we create only one channel for the last blocker
            let mut blocks_iter = blocks.into_iter().peekable();
            while let Some(hash) = blocks_iter.next() {
                if !self.blockchain.has_block(&hash).await? {
                    trace!("Block {} is not found, asking it to {} (index = {})", hash, peer.get_outgoing_address(), total_requested);
                    // if it's allowed by the user, request all blocks in parallel
                    if self.allow_boost_sync() {
                        if let Some(notifier) = &mut notifier {
                            // Check if we don't have any message pending in the channel
                            if notifier.try_recv().is_ok() {
                                debug!("An error has occured in batch while requesting chain in boost mode");
                                return Err(P2pError::BoostSyncModeFailed.into());
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
                    trace!("Block {} is already in chain, skipping it", hash);
                }
            }

            if let (Some(mut notifier), Some(mut blocker)) = (notifier, final_blocker) {
                debug!("Waiting for final blocker to finish...");
                select! {
                    res = &mut notifier => {
                        let err = res.map_err(|e| P2pError::BoostSyncModeBlockerResponseError(e))?;
                        debug!("An error has occured while requesting chain in boost mode: {}", err);
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
        // ask inventory of this peer if we sync from too far
        // if we are not further than one sync, request the inventory
        if peer_topoheight > our_previous_topoheight && blocks_len < requested_max_size {
            let our_topoheight = self.blockchain.get_topo_height();
            // verify that we synced it partially well
            if peer_topoheight >= our_topoheight && peer_topoheight - our_topoheight < STABLE_LIMIT {
                if let Err(e) = self.request_inventory_of(&peer).await {
                    error!("Error while asking inventory to {}: {}", peer, e);
                }
            }
        }

        Ok(())
    }

    // determine if we are connected to a priority node and that this node is equal / greater to our chain
    async fn is_connected_to_a_synced_priority_node(&self) -> bool {
        let topoheight = self.blockchain.get_topo_height();
        trace!("locking peer list for checking if connected to a synced priority node");
        let peer_list = self.peer_list.read().await;
        trace!("locked peer list for checking if connected to a synced priority node");

        for peer in peer_list.get_peers().values() {
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
        let peer_list = self.peer_list.read().await;
        peer_list.size()
    }

    // Returns the median topoheight based on all peers
    pub async fn get_median_topoheight_of_peers(&self) -> u64 {
        let peer_list = self.peer_list.read().await;
        let topoheight = self.blockchain.get_topo_height();
        peer_list.get_median_topoheight(Some(topoheight))
    }

    // Returns the best topoheight based on all peers
    pub async fn get_best_topoheight(&self) -> u64 {
        let peer_list = self.peer_list.read().await;
        peer_list.get_best_topoheight()
    }

    // Verify if this peer id is already used by a peer
    pub async fn is_connected_to(&self, peer_id: &u64) -> Result<bool, P2pError> {
        let peer_list = self.peer_list.read().await;
        Ok(self.peer_id == *peer_id || peer_list.has_peer(peer_id))
    }

    // Check if we are already connected to a socket address (IPv4 or IPv6) including its port
    pub async fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> Result<bool, P2pError> {
        if *peer_addr == *self.get_bind_address() { // don't try to connect to ourself
            debug!("Trying to connect to ourself, ignoring.");
            return Ok(true)
        }

        let peer_list = self.peer_list.read().await;
        Ok(peer_list.is_connected_to_addr(peer_addr))
    }

    // get the socket address on which we are listening
    pub fn get_bind_address(&self) -> &SocketAddr {
        &self.bind_address
    }

    // Get our peerlist
    pub fn get_peer_list(&self) -> &SharedPeerList {
        &self.peer_list
    }

    // Broadcast a new transaction hash using propagation packet
    // This is used so we don't overload the network during spam or high transactions count
    // We simply share its hash to nodes and others nodes can check if they have it already or not
    pub async fn broadcast_tx_hash(&self, tx: Hash) {
        debug!("Broadcasting tx hash {}", tx);
        let ping = self.build_generic_ping_packet().await;
        trace!("Ping packet has been generated for tx broadcast");
        let current_topoheight = ping.get_topoheight();
        let packet = Packet::TransactionPropagation(PacketWrapper::new(Cow::Borrowed(&tx), Cow::Owned(ping)));
        // transform packet to bytes (so we don't need to transform it for each peer)
        let bytes = Bytes::from(packet.to_bytes());
        trace!("Locking peer list for tx broadcast");
        let peer_list = self.peer_list.read().await;
        trace!("Lock acquired for tx broadcast");

        for peer in peer_list.get_peers().values() {
            // check that the peer is not too far from us
            // otherwise we may spam him for nothing
            let peer_topoheight = peer.get_topoheight();
            if (peer_topoheight >= current_topoheight && peer_topoheight - current_topoheight < STABLE_LIMIT) || (current_topoheight >= peer_topoheight && current_topoheight - peer_topoheight < STABLE_LIMIT) {
                trace!("Peer {} is not too far from us, checking cache for tx hash {}", peer, tx);
                let mut txs_cache = peer.get_txs_cache().lock().await;
                // check that we didn't already send this tx to this peer or that he don't already have it
                if !txs_cache.contains(&tx) {
                    trace!("Broadcasting tx hash {} to {}", tx, peer);
                    if let Err(e) = peer.send_bytes(bytes.clone()).await {
                        error!("Error while broadcasting tx hash {} to {}: {}", tx, peer, e);
                    }
                    // Set it as "In" so we can't get it back as we are the sender of it
                    txs_cache.put(tx.clone(), Direction::In);
                } else {
                    trace!("{} have tx hash {} in cache, skipping", peer, tx);
                }
            }
        }
    }

    // broadcast block to all peers that can accept directly this new block
    pub async fn broadcast_block(&self, block: &BlockHeader, cumulative_difficulty: CumulativeDifficulty, our_topoheight: u64, our_height: u64, pruned_topoheight: Option<u64>, hash: &Hash, lock: bool) {
        debug!("Broadcasting block {} at height {}", hash, block.get_height());
        // we build the ping packet ourself this time (we have enough data for it)
        // because this function can be call from Blockchain, which would lead to a deadlock
        let ping = Ping::new(Cow::Borrowed(hash), our_topoheight, our_height, pruned_topoheight, cumulative_difficulty, Vec::new());
        let block_packet = Packet::BlockPropagation(PacketWrapper::new(Cow::Borrowed(block), Cow::Borrowed(&ping)));
        let packet_block_bytes = Bytes::from(block_packet.to_bytes());
        let packet_ping_bytes = Bytes::from(Packet::Ping(Cow::Owned(ping)).to_bytes());

        trace!("Locking peer list for broadcasting block {}", hash);
        let peer_list = self.peer_list.read().await;
        trace!("start broadcasting block {} to all peers", hash);
        for (_, peer) in peer_list.get_peers() {
            // if the peer can directly accept this new block, send it
            let peer_height = peer.get_height();

            // if the peer is not too far from us, send the block
            // check that peer height is greater or equal to block height but still under or equal to STABLE_LIMIT
            // or, check that peer height as difference of maximum 1 block
            // (block height is always + 1 above the highest tip height, so we can just check that peer height is not above block height + 1, it's enough in 90% of time)
            // chain can accept old blocks (up to STABLE_LIMIT) but new blocks only N+1
            if (peer_height >= block.get_height() && peer_height - block.get_height() < STABLE_LIMIT) || (peer_height <= block.get_height() && block.get_height() - peer_height <= 1) {
                let mut blocks_propagation = peer.get_blocks_propagation().lock().await;
                // check that this block was never shared with this peer
                if !blocks_propagation.contains(hash) {
                    // we broadcasted to him, add it to the cache
                    // he should not send it back to us if it's a block found by us
                    blocks_propagation.put(hash.clone(), if lock { Direction::Both } else { Direction::Out });

                    debug!("Broadcast {} to {} (lock: {})", hash, peer, lock);
                    if let Err(e) = peer.send_bytes(packet_block_bytes.clone()).await {
                        debug!("Error on broadcast block {} to {}: {}", hash, peer, e);
                    }
                } else {
                    debug!("{} contains {}, don't broadcast block to him", peer, hash);
                    // But we can notify him with a ping packet that we got the block
                    if let Err(e) = peer.send_bytes(packet_ping_bytes.clone()).await {
                        debug!("Error on sending ping for notifying that we accepted the block {} to {}: {}", hash, peer, e);
                    } else {
                        peer.set_last_ping_sent(get_current_time_in_seconds());
                    }
                }
            } else {
                trace!("Cannot broadcast {} at height {} to {}, too far", hash, block.get_height(), peer);
            }
        }
        trace!("broadcasting block {} is done", hash);
    }

    // Broadcast a packet to across all nodes connected
    pub async fn broadcast_packet(&self, packet: Packet<'_>) {
        trace!("Locking peer list for broadcasting packet");
        let peer_list = self.peer_list.read().await;
        trace!("Lock acquired, broadcast packet");
        peer_list.broadcast(packet).await;
    }

    // Handle a bootstrap chain request
    // We have differents steps available for a bootstrap sync
    // We verify that they are send in good order
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
                warn!("Invalid begin topoheight (received {}, our is {}, pruned: {}) received from {}", topoheight, our_topoheight, pruned_topoheight, peer);
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
            StepRequest::Balances(topoheight, asset, keys) => {
                let balances = storage.get_versioned_balances(&asset, keys.iter(), topoheight).await?;
                StepResponse::Balances(balances.into_iter().map(|v| {
                    v.map(|v| {
                        let (balance, output_balance, balance_type, _) = v.consume();
                        (balance, output_balance, balance_type)
                    })
                }).collect())
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
                    warn!("Invalid range for assets");
                    return Err(P2pError::InvalidPacket.into())
                }

                let page = page.unwrap_or(0);
                let keys = storage.get_partial_keys(MAX_ITEMS_PER_PAGE, page as usize * MAX_ITEMS_PER_PAGE, min, max).await?;
                let page = if keys.len() == MAX_ITEMS_PER_PAGE {
                    Some(page + 1)
                } else {
                    None
                };
                StepResponse::Keys(keys, page)
            },
            StepRequest::BlocksMetadata(topoheight) => {
                let mut blocks = IndexSet::with_capacity(PRUNE_SAFETY_LIMIT as usize);
                // go from the lowest available point until the requested stable topoheight
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

    // first, retrieve chain info of selected peer
    // We retrieve all assets through pagination,
    // then we fetch all keys with its nonces and its balances (also through pagination)
    // and for the last step, retrieve last STABLE TOPOHEIGHT - PRUNE_SAFETY_LIMIT blocks
    // reload blockchain cache from disk, and we're ready to sync the rest of the chain
    // NOTE: it could be even faster without retrieving each TXs, but we do it in case user don't enable pruning
    async fn bootstrap_chain(&self, peer: &Arc<Peer>) -> Result<(), BlockchainError> {
        info!("Starting fast sync with {}", peer);

        let mut our_topoheight = self.blockchain.get_topo_height();

        let mut stable_topoheight = 0;
        let mut step: Option<StepRequest> = {
            let storage = self.blockchain.get_storage().read().await;
            Some(StepRequest::ChainInfo(self.build_list_of_blocks_id(&*storage).await?))
        };

        // keep them in memory, we add them when we're syncing
        // it's done to prevent any sync failure
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
                    // first, check the common point in case we deviated from the chain
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
                // fetch all assets from peer
                StepResponse::Assets(assets, next_page) => {
                    let mut storage = self.blockchain.get_storage().write().await;
                    for asset in assets {
                        let (asset, data) = asset.consume();
                        debug!("Saving asset {} at topoheight {}", asset, stable_topoheight);
                        storage.add_asset(&asset, data).await?;
                    }

                    if next_page.is_some() {
                        Some(StepRequest::Assets(our_topoheight, stable_topoheight, next_page))
                    } else {
                        // Go to next step
                        Some(StepRequest::Keys(our_topoheight, stable_topoheight, None))
                    }
                },
                // fetch all new accounts
                StepResponse::Keys(keys, next_page) => {
                    debug!("Requesting nonces for keys");
                    let StepResponse::Nonces(nonces) = peer.request_boostrap_chain(StepRequest::Nonces(stable_topoheight, Cow::Borrowed(&keys))).await? else {
                        // shouldn't happen
                        error!("Received an invalid StepResponse (how ?) while fetching nonces");
                        return Err(P2pError::InvalidPacket.into())
                    };

                    {
                        let mut storage = self.blockchain.get_storage().write().await;
                        // save all nonces
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
                                break
                            }
                            page += 1;
                            assets
                        };

                        // Request every asset balances
                        for asset in assets {
                            debug!("Request balances for asset {}", asset);
                            let StepResponse::Balances(balances) = peer.request_boostrap_chain(StepRequest::Balances(stable_topoheight, Cow::Borrowed(&asset), Cow::Borrowed(&keys))).await? else {
                                // shouldn't happen
                                error!("Received an invalid StepResponse (how ?) while fetching balances");
                                return Err(P2pError::InvalidPacket.into())
                            };
    
                            // save all balances for this asset
                            let mut storage = self.blockchain.get_storage().write().await;
                            for (key, balance) in keys.iter().zip(balances) {
                                // check that the account have balance for this asset
                                if let Some((balance, output_balance, balance_type)) = balance {
                                    debug!("Saving balance {:?} for key {} at topoheight {}", balance, key.as_address(self.blockchain.get_network().is_mainnet()), stable_topoheight);
                                    let mut versioned_balance = storage.get_new_versioned_balance(key, &asset, stable_topoheight).await?;
                                    versioned_balance.set_balance(balance);
                                    versioned_balance.set_output_balance(output_balance);
                                    versioned_balance.set_balance_type(balance_type);
                                    versioned_balance.set_previous_topoheight(None);
                                    storage.set_last_balance_to(key, &asset, stable_topoheight, &versioned_balance).await?;
                                }
                            }
                        }
                    }

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
                        // check that we don't already have this block in storage
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

                        // link its TX to the block
                        let mut storage = self.blockchain.get_storage().write().await;
                        for tx_hash in header.get_txs_hashes() {
                            storage.add_block_for_tx(tx_hash, &hash)?;
                        }

                        // save metadata of this block
                        storage.set_supply_at_topo_height(lowest_topoheight, metadata.supply)?;
                        storage.set_block_reward_at_topo_height(lowest_topoheight, metadata.reward)?;
                        storage.set_topo_height_for_block(&hash, lowest_topoheight).await?;

                        storage.set_cumulative_difficulty_for_block_hash(&hash, metadata.cumulative_difficulty).await?;

                        // save the block with its transactions, difficulty
                        storage.save_block(Arc::new(header), &txs, metadata.difficulty, metadata.p, hash).await?;
                    }

                    let mut storage = self.blockchain.get_storage().write().await;

                    // Create a snapshots for all others keys that didn't got updated
                    storage.create_snapshot_balances_at_topoheight(lowest_topoheight).await?;
                    storage.create_snapshot_nonces_at_topoheight(lowest_topoheight).await?;
                    storage.create_snapshot_registrations_at_topoheight(lowest_topoheight).await?;

                    // Delete all old data
                    storage.delete_versioned_balances_below_topoheight(lowest_topoheight).await?;
                    storage.delete_versioned_nonces_below_topoheight(lowest_topoheight).await?;
                    storage.delete_registrations_below_topoheight(lowest_topoheight).await?;

                    storage.set_pruned_topoheight(lowest_topoheight).await?;
                    storage.set_top_topoheight(top_topoheight)?;
                    storage.set_top_height(top_height)?;
                    storage.store_tips(&HashSet::from([top_block_hash.take().expect("Expected top block hash for fast sync")]))?;

                    None
                },
                response => { // shouldn't happens
                    error!("Received bootstrap chain response {:?} but didn't asked for it", response);
                    return Err(P2pError::InvalidPacket.into());
                }
            };
        }
        self.blockchain.reload_from_disk().await?;
        info!("Fast sync done with {}", peer);

        Ok(())
    }

    // Request the inventory of a peer
    // This will sends him a request packet so we get notified of all its TXs hashes in its mempool
    async fn request_inventory_of(&self, peer: &Arc<Peer>) -> Result<(), BlockchainError> {
        debug!("Requesting inventory of {}", peer);
        let packet = Cow::Owned(NotifyInventoryRequest::new(None));
        let ping = Cow::Owned(self.build_generic_ping_packet().await);
        peer.set_requested_inventory(true);
        peer.send_packet(Packet::NotifyInventoryRequest(PacketWrapper::new(packet, ping))).await?;
        Ok(())
    }

    // this function basically send all our blocks based on topological order (topoheight)
    // we send up to CHAIN_SYNC_REQUEST_MAX_BLOCKS blocks id (combinaison of block hash and topoheight)
    // we add at the end the genesis block to be sure to be on the same chain as others peers
    // its used to find a common point with the peer to which we ask the chain
    pub async fn request_sync_chain_for(&self, peer: &Arc<Peer>, last_chain_sync: &mut TimestampMillis) -> Result<(), BlockchainError> {
        trace!("Requesting chain from {}", peer);

        // This can be configured by the node operator, it will be adjusted between protocol bounds
        // and based on peer configuration
        // This will allow to boost-up syncing for those who want and can be used to use low resources for low devices
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
            return Err(P2pError::InvaliChainResponseSize(response.blocks_size(), requested_max_size).into())
        }

        // Update last chain sync time
        *last_chain_sync = get_current_time_in_millis();

        self.handle_chain_response(peer, response, requested_max_size).await
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