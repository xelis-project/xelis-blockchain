pub mod connection;
pub mod peer;
pub mod error;
pub mod packet;
pub mod peer_list;
pub mod chain_validator;
mod tracker;

use indexmap::IndexSet;
use lru::LruCache;
use xelis_common::{
    config::VERSION,
    serializer::Serializer,
    crypto::hash::{Hashable, Hash},
    block::{BlockHeader, Block},
    utils::get_current_time,
    immutable::Immutable,
    api::daemon::{NotifyEvent, PeerPeerDisconnectedEvent}
};
use crate::{
    core::{
        blockchain::Blockchain,
        storage::Storage,
        error::BlockchainError
    },
    p2p::{
        chain_validator::ChainValidator,
        packet::{
            bootstrap_chain::{
                StepRequest, StepResponse, BootstrapChainResponse, MAX_ITEMS_PER_PAGE, BlockMetadata
            },
            inventory::{
                NOTIFY_MAX_LEN, NotifyInventoryRequest, NotifyInventoryResponse
            },
            chain::CommonPoint
        },
        tracker::ResponseBlocker,
        connection::ConnectionMessage,
    },
    config::{
        NETWORK_ID, SEED_NODES, MAX_BLOCK_SIZE, CHAIN_SYNC_DELAY, P2P_PING_DELAY, CHAIN_SYNC_REQUEST_MAX_BLOCKS,
        P2P_PING_PEER_LIST_DELAY, P2P_PING_PEER_LIST_LIMIT, STABLE_LIMIT, PEER_FAIL_LIMIT,
        CHAIN_SYNC_RESPONSE_MAX_BLOCKS, CHAIN_SYNC_TOP_BLOCKS, GENESIS_BLOCK_HASH, PRUNE_SAFETY_LIMIT,
        P2P_EXTEND_PEERLIST_DELAY, TIPS_LIMIT, PEER_TIMEOUT_INIT_CONNECTION
    }, rpc::rpc::get_peer_entry
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
    sync::{mpsc::{self, UnboundedSender, UnboundedReceiver}, Mutex},
    select,
    task::JoinHandle,
    io::AsyncWriteExt,
    time::{interval, timeout, sleep}
};
use log::{info, warn, error, debug, trace};
use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering}
    },
    collections::HashSet,
    convert::TryInto,
    net::SocketAddr,
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
    peer_id: u64, // unique peer id
    tag: Option<String>, // node tag sent on handshake
    max_peers: usize, // max peers accepted by this server
    bind_address: SocketAddr, // ip:port address to receive connections
    peer_list: SharedPeerList, // all peers accepted
    blockchain: Arc<Blockchain<S>>, // reference to the chain to add blocks/txs
    connections_sender: UnboundedSender<MessageChannel>, // this sender allows to create a queue system in one task only
    syncing_peer: Mutex<Option<Arc<Peer>>>, // used to check if we are already syncing with one peer or not
    object_tracker: SharedObjectTracker, // used to requests objects to peers and avoid requesting the same object to multiple peers
    is_running: AtomicBool, // used to check if the server is running or not in tasks
    blocks_propagation_queue: Mutex<LruCache<Hash, ()>>, // Synced cache to prevent concurrent tasks adding the block
    blocks_processor: UnboundedSender<(Arc<Peer>, BlockHeader, Hash)> // Sender for the blocks processing task to have a ordered queue
}

impl<S: Storage> P2pServer<S> {
    pub fn new(tag: Option<String>, max_peers: usize, bind_address: String, blockchain: Arc<Blockchain<S>>, use_peerlist: bool, exclusive_nodes: Vec<SocketAddr>) -> Result<Arc<Self>, P2pError> {
        if let Some(tag) = &tag {
            debug_assert!(tag.len() > 0 && tag.len() <= 16);
        }

        // set channel to communicate with listener thread
        let mut rng = rand::thread_rng();
        let peer_id: u64 = rng.gen(); // generate a random peer id for network
        let addr: SocketAddr = bind_address.parse()?; // parse the bind address
        // create mspc channel for connections to peers
        let (connections_sender, connections_receiver) = mpsc::unbounded_channel();

        let (blocks_processer, blocks_processor_receiver) = mpsc::unbounded_channel();

        let object_tracker = ObjectTracker::new(blockchain.clone());

        let server = Self {
            peer_id,
            tag,
            max_peers,
            bind_address: addr,
            peer_list: PeerList::new(max_peers, format!("peerlist-{}.json", blockchain.get_network().to_string().to_lowercase())),
            blockchain,
            connections_sender,
            syncing_peer: Mutex::new(None),
            object_tracker,
            is_running: AtomicBool::new(true),
            blocks_propagation_queue: Mutex::new(LruCache::new(STABLE_LIMIT as usize * TIPS_LIMIT)),
            blocks_processor: blocks_processer
        };

        let arc = Arc::new(server);
        {
            let zelf = Arc::clone(&arc);
            tokio::spawn(async move {
                if let Err(e) = zelf.start(connections_receiver, use_peerlist, exclusive_nodes).await {
                    error!("Unexpected error on P2p module: {}", e);
                }
            });
        }

        // Start the blocks processing task to have a queued handler
        {
            let zelf = Arc::clone(&arc);
            tokio::spawn(zelf.blocks_processing_task(blocks_processor_receiver));
        }

        Ok(arc)
    }

    pub async fn stop(&self) {
        info!("Stopping P2p Server...");
        self.is_running.store(false, Ordering::Release);

        self.object_tracker.stop();
        if let Err(e) = self.connections_sender.send(MessageChannel::Exit) {
            error!("Error while sending Exit message to stop accepting new connections: {}", e);
        }

        let mut peers = self.peer_list.write().await;
        peers.close_all().await;
        info!("P2p Server is now stopped!");
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Acquire)
    }

    // Connect to nodes which aren't already connected in parameters
    async fn connect_to_nodes(self: &Arc<Self>, nodes: &Vec<SocketAddr>) -> Result<(), P2pError> {
        for addr in nodes {
            if self.accept_new_connections().await {
                if !self.is_connected_to_addr(addr).await? {
                    self.try_to_connect_to_peer(addr.clone(), true).await;
                }
            }
        }
        Ok(())
    }

    // every 10 seconds, verify and connect if necessary
    async fn maintains_connection_to_nodes(self: &Arc<Self>, nodes: Vec<SocketAddr>) -> Result<(), P2pError> {
        debug!("Starting maintains seed nodes task...");
        let mut interval = interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            if !self.is_running() {
                debug!("Maintains seed nodes task is stopped!");
                break;
            }

            if self.accept_new_connections().await {
                if let Err(e) = self.connect_to_nodes(&nodes).await {
                    debug!("Error while connecting to seed nodes: {}", e);
                };
            }
        }

        Ok(())
    }

    // connect to seed nodes, start p2p server
    // and wait on all new connections
    async fn start(self: &Arc<Self>, mut receiver: UnboundedReceiver<MessageChannel>, use_peerlist: bool, mut exclusive_nodes: Vec<SocketAddr>) -> Result<(), P2pError> {
        if exclusive_nodes.is_empty() {
            debug!("No exclusive nodes available, using seed nodes...");
            exclusive_nodes = SEED_NODES.iter().map(|s| s.parse().unwrap()).collect();
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

        // start another task for peerlist loop
        if use_peerlist {
            tokio::spawn(Arc::clone(&self).peerlist_loop());
        }

        let listener = TcpListener::bind(self.get_bind_address()).await?;
        info!("P2p Server will listen on: {}", self.get_bind_address());
        // only allocate one time the buffer for this packet
        let mut handshake_buffer = [0; 512];
        loop {
            let (connection, out, priority) = select! {
                res = listener.accept() => {
                    trace!("New listener result received (is err: {})", res.is_err());
                    let (mut stream, addr) = res?;
                    if !self.accept_new_connections().await { // if we have already reached the limit, we ignore this new connection
                        debug!("Max peers reached, rejecting connection");
                        if let Err(e) = stream.shutdown().await {
                            debug!("Error while closing & ignoring incoming connection {}: {}", addr, e);
                        }
                        continue;
                    } else {
                        // check that this incoming peer isn't blacklisted
                        let peer_list = self.peer_list.read().await;
                        if peer_list.is_blacklisted(&addr) {
                            debug!("{} is blacklisted, rejecting connection", addr);
                            if let Err(e) = stream.shutdown().await {
                                debug!("Error while closing & ignoring incoming connection {}: {}", addr, e);
                            }
                            continue;
                        }
                    }
                    (Connection::new(stream, addr), false, false)
                },
                Some(msg) = receiver.recv() => match msg {
                    MessageChannel::Exit => break,
                    MessageChannel::Connect((addr, priority)) => {
                        if !self.accept_new_connections().await {
                            trace!("Coudln't connect to {}, limit has been reached!", addr);
                            continue;
                        }

                        match self.connect_to_peer(addr).await {
                            Ok(connection) => (connection, true, priority),
                            Err(e) => {
                                trace!("Error while trying to connect to new outgoing peer: {}", e);
                                // if its a outgoing connection, increase its fail count
                                let mut peer_list = self.peer_list.write().await;
                                peer_list.increase_fail_count_for_saved_peer(&addr);
                                continue;
                            }
                        }
                    }
                }
            };
            trace!("Handling new connection: {} (out = {}, priority = {})", connection, out, priority);
            if let Err(e) = self.handle_new_connection(&mut handshake_buffer, connection, out, priority).await {
                trace!("Error occured on handled connection: {}", e);
                // no need to close it here, as it will be automatically closed in drop
            }
        }

        Ok(())
    }

    // Verify handshake send by a new connection
    // based on data size, network ID, peers address validity
    // block height and block top hash of this peer (to know if we are on the same chain)
    async fn verify_handshake(&self, mut connection: Connection, handshake: Handshake, out: bool, priority: bool) -> Result<Peer, P2pError> {
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

        if *handshake.get_block_genesis_hash() != *GENESIS_BLOCK_HASH {
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
        let peer = handshake.create_peer(connection, out, priority, Arc::clone(&self.peer_list));
        Ok(peer)
    }

    async fn build_handshake(&self) -> Result<Handshake, P2pError> {
        let storage = self.blockchain.get_storage().read().await;
        let (block, top_hash) = storage.get_top_block_header().await?;
        let topoheight = self.blockchain.get_topo_height();
        let pruned_topoheight = storage.get_pruned_topoheight()?;
        let cumulative_difficulty = storage.get_cumulative_difficulty_for_block_hash(&top_hash).await.unwrap_or(0);
        Ok(Handshake::new(VERSION.to_owned(), *self.blockchain.get_network(), self.get_tag().clone(), NETWORK_ID, self.get_peer_id(), self.bind_address.port(), get_current_time(), topoheight, block.get_height(), pruned_topoheight, top_hash, GENESIS_BLOCK_HASH.clone(), cumulative_difficulty))
    }

    // this function handle all new connections
    // A new connection have to send an Handshake
    // if the handshake is valid, we accept it & register it on server
    async fn handle_new_connection(self: &Arc<Self>, buf: &mut [u8], mut connection: Connection, out: bool, priority: bool) -> Result<(), P2pError> {
        trace!("New connection: {}", connection);
        let handshake: Handshake = match timeout(Duration::from_millis(PEER_TIMEOUT_INIT_CONNECTION), connection.read_packet(buf, buf.len() as u32)).await?? {
            Packet::Handshake(h) => h.into_owned(), // only allow handshake packet
            _ => return Err(P2pError::ExpectedHandshake)
        };
        trace!("received handshake packet!");
        connection.set_state(State::Handshake);
        let peer = self.verify_handshake(connection, handshake, out, priority).await?;
        trace!("Handshake has been verified");
        // if it's a outgoing connection, don't send the handshake back
        // because we have already sent it
        if !out {
            trace!("Sending handshake back to {}", peer);
            self.send_handshake(peer.get_connection()).await?;
        }

        // if we reach here, handshake is all good, we can start listening this new peer
        // we can save the peer in our peerlist
        let peer_id = peer.get_id(); // keep in memory the peer_id outside connection (because of moved value)
        let peer = {
            let mut peer_list = self.peer_list.write().await;
            peer_list.add_peer(peer_id, peer)
        };

        {
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

    // Connect to a specific peer address
    // Buffer is passed in parameter to prevent the re-allocation each time
    pub async fn try_to_connect_to_peer(&self, addr: SocketAddr, priority: bool) {
        trace!("try to connect to peer addr {}, priority: {}", addr, priority);
        {
            let peer_list = self.peer_list.read().await;
            trace!("peer list locked for trying to connect to peer {}", addr);
            if peer_list.is_blacklisted(&addr) {
                debug!("{} is banned, we can't connect to it", addr);
                return;
            }
        }

        if let Err(e) = self.connections_sender.send(MessageChannel::Connect((addr, priority))) {
            error!("Error while trying to connect to address {} (priority = {}): {}", addr, priority, e);
        }
    }

    async fn connect_to_peer(&self, addr: SocketAddr) -> Result<Connection, P2pError> {
        trace!("Trying to connect to {}", addr);
        if self.is_connected_to_addr(&addr).await? {
            return Err(P2pError::PeerAlreadyConnected(format!("{}", addr)));
        }
        let stream = timeout(Duration::from_millis(800), TcpStream::connect(&addr)).await??; // allow maximum 800ms of latency
        let connection = Connection::new(stream, addr);
        self.send_handshake(&connection).await?;
        Ok(connection)
    }

    async fn send_handshake(&self, connection: &Connection) -> Result<(), P2pError> {
        let handshake: Handshake = self.build_handshake().await?;
        connection.send_bytes(&Packet::Handshake(Cow::Owned(handshake)).to_bytes()).await
    }

    // build a ping packet with the current state of the blockchain
    // if a peer is given, we will check and update the peers list
    async fn build_generic_ping_packet_with_storage(&self, storage: &S) -> Ping<'_> {
        let (cumulative_difficulty, block_top_hash, pruned_topoheight) = {
            let pruned_topoheight = match storage.get_pruned_topoheight() {
                Ok(pruned_topoheight) => pruned_topoheight,
                Err(e) => {
                    error!("Couldn't get the pruned topoheight from storage for generic ping packet: {}", e);
                    None
                }
            };

            match storage.get_top_block_hash().await {
                Err(e) => {
                    error!("Couldn't get the top block hash from storage for generic ping packet: {}", e);
                    (0, GENESIS_BLOCK_HASH.clone(), pruned_topoheight)
                },
                Ok(hash) => (storage.get_cumulative_difficulty_for_block_hash(&hash).await.unwrap_or(0), hash, pruned_topoheight)
            }
        };
        let highest_topo_height = self.blockchain.get_topo_height();
        let highest_height = self.blockchain.get_height();
        let new_peers = Vec::new();
        Ping::new(Cow::Owned(block_top_hash), highest_topo_height, highest_height, pruned_topoheight, cumulative_difficulty, new_peers)
    }

    async fn build_generic_ping_packet(&self) -> Ping<'_> {
        let storage = self.blockchain.get_storage().read().await;
        self.build_generic_ping_packet_with_storage(&*storage).await
    }

    // select a random peer which is greater than us to sync chain
    // candidate peer should have a greater topoheight or a higher block height than us
    // if we are not in fast sync mode, we must verify its pruned topoheight to be sure
    // he have the blocks we need
    async fn select_random_best_peer(&self, fast_sync: bool) -> Option<Arc<Peer>> {
        trace!("select random best peer");
        let peer_list = self.peer_list.read().await;
        trace!("peer list locked for select random best peer");
        let our_height = self.blockchain.get_height();
        let our_topoheight = self.blockchain.get_topo_height();
        // search for peers which are greater than us
        // and that are pruned but before our height so we can sync correctly
        let peers: Vec<&Arc<Peer>> = peer_list.get_peers().values().filter(|p| {
            let peer_topoheight = p.get_topoheight();
            if fast_sync {
                // if we want to fast sync, but this peer is not compatible, we skip it
                // for this we check that the peer topoheight is not less than the prune safety limit
                if peer_topoheight < PRUNE_SAFETY_LIMIT || our_topoheight + PRUNE_SAFETY_LIMIT > peer_topoheight {
                    return false
                }
            } else {
                // check that the pruned topoheight is less than our topoheight to sync
                // so we can sync chain from pruned chains
                if let Some(pruned_topoheight) = p.get_pruned_topoheight() {
                    if pruned_topoheight > our_topoheight {
                        return false
                    }
                }
            }

            p.get_height() > our_height || peer_topoheight > our_topoheight
        }).collect();

        let count = peers.len();
        trace!("peers available for random selection: {}", count);
        if count == 0 {
            return None
        }

        let selected = rand::thread_rng().gen_range(0..count);
        let peer = peers.get(selected)?;
        trace!("selected peer for sync chain: ({}) {}", selected, peer);
        // clone the Arc to prevent the lock until the end of the sync request
        Some(Arc::clone(peer))
    }

    async fn chain_sync_loop(self: Arc<Self>) {
        let duration = Duration::from_secs(CHAIN_SYNC_DELAY);
        loop {
            sleep(duration).await;
            if !self.is_syncing().await {
                // first we have to check if we allow fast sync mode
                // and then we check if we have a potential peer above us to fast sync
                // otherwise we sync normally 
                let fast_sync = if self.blockchain.is_fast_sync_mode_allowed() {
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

                if let Some(peer) = self.select_random_best_peer(fast_sync).await {
                    self.start_syncing(peer.clone()).await;
                    debug!("Selected for chain sync is {}", peer);
                    // check if we can maybe fast sync first
                    // otherwise, fallback on the normal chain sync
                    if fast_sync {
                        if let Err(e) = self.bootstrap_chain(&peer).await {
                            warn!("Error occured while fast syncing with {}: {}", peer, e);
                        }
                    } else {
                        if let Err(e) = self.request_sync_chain_for(&peer).await {
                            debug!("Error occured on chain sync with {}: {}", peer, e);
                        }
                    }
                    self.stop_syncing().await;
                } else {
                    trace!("No peer found for chain sync");
                }
            }
        }
    }

    // broadcast generic ping packet every 10s
    // if we have to send our peerlist to all peers, we calculate the ping for each peer
    async fn ping_loop(self: Arc<Self>) {
        debug!("Starting ping loop...");

        let mut last_peerlist_update = get_current_time();
        let duration = Duration::from_secs(P2P_PING_DELAY);
        loop {
            trace!("Waiting for ping delay...");
           sleep(duration).await;

            let mut ping = self.build_generic_ping_packet().await;
            trace!("generic ping packet finished");

            let current_time = get_current_time();
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

                    // all the peers we already sent to this current peer
                    let mut peers_sent = peer.get_peers(true).lock().await;

                    // iterate through our peerlist to determinate which peers we have to send
                    for p in peer_list.get_peers().values() {
                        // don't send him itself
                        if p.get_id() == peer.get_id() {
                            continue;
                        }

                        // if we haven't send him this peer addr and that he don't have him already, insert it
                        let addr = p.get_outgoing_address();
                        if !peers_sent.contains(addr) {
                            // add it in our side to not re send it again
                            trace!("{} didn't received {} yet, adding it to peerlist in ping packet", peer.get_outgoing_address(), addr);
                            peers_sent.insert(*addr);
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
                        peer.set_last_ping_sent(get_current_time());
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
                let current_time = get_current_time();
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
                    let mut  peer_list = self.peer_list.write().await;
                    peer_list.find_peer_to_connect()
                };

                if let Some(addr) = peer {
                    debug!("Found peer {}", addr);
                    self.try_to_connect_to_peer(addr, false).await;
                } else {
                    trace!("No peer found to connect to");
                }
            }
        }
    }

    // Task for all blocks propagation
    async fn blocks_processing_task(self: Arc<Self>, mut receiver: UnboundedReceiver<(Arc<Peer>, BlockHeader, Hash)>) {
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
                        trace!("Sending packet with ID {}, size sent: {}, real size: {}", bytes[5], u32::from_be_bytes(bytes[0..4].try_into()?), bytes.len() - 4);
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
                        if let Err(e) = peer.close().await {
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
        let peer_peers = peer.get_peers(false).lock().await;
        trace!("locked peers received (common peers)");

        let mut common_peers = Vec::new();
        for common_peer_addr in peer_peers.iter() {
            // if we have a common peer with him
            if let Some(common_peer) = peer_list.get_peer_by_addr(common_peer_addr) {
                if peer.get_id() != common_peer.get_id() {
                    trace!("locking common peers received");
                    let peers_received = common_peer.get_peers(false).lock().await;
                    trace!("locking common peers sent");
                    let peers_sent = common_peer.get_peers(true).lock().await;
                    trace!("lock acquired (common peer)");

                    // verify that we already know that he his connected to it and that we informed him we are connected too to prevent any desync
                    if peers_received.iter().find(
                        |addr: &&SocketAddr| *addr == peer.get_outgoing_address()
                    ).is_some() && peers_sent.iter().find(
                        |addr: &&SocketAddr| *addr == common_peer.get_outgoing_address()
                    ).is_some() {
                        common_peers.push(common_peer.clone());
                    }
                }
            }
        }

        common_peers
    }

    async fn handle_incoming_packet(self: &Arc<Self>, peer: &Arc<Peer>, packet: Packet<'_>) -> Result<(), P2pError> {
        match packet {
            Packet::Handshake(_) => {
                error!("{} sent us handshake packet (not valid!)", peer);
                peer.get_connection().close().await?;
                return Err(P2pError::InvalidPacket)
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
                    if txs_cache.contains(&hash) {
                        debug!("{} send us a transaction ({}) already tracked by him", peer, hash);
                        // TODO Fix common peer detection
                        return Ok(()) // Err(P2pError::AlreadyTrackedTx(hash))
                    }
                    txs_cache.put(hash.clone(), ());
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
                    txs_cache.put(hash.clone(), ());
                }
            },
            Packet::BlockPropagation(packet_wrapper) => {
                trace!("Received a block propagation packet from {}", peer);
                let (header, ping) = packet_wrapper.consume();
                ping.into_owned().update_peer(peer, &self.blockchain).await?;
                let block_height = header.get_height();

                // check that the block height is valid
                let header = header.into_owned();
                let block_hash = header.hash();
                if block_height < self.blockchain.get_stable_height() {
                    error!("{} send us a block propagation packet which is under stable height (height = {})!", peer, block_height);
                    return Err(P2pError::BlockPropagatedUnderStableHeight(block_hash, block_height))
                }

                // verify that this block wasn't already sent by him
                {
                    let mut blocks_propagation = peer.get_blocks_propagation().lock().await;
                    if blocks_propagation.contains(&block_hash) {
                        debug!("{} send us a block ({}) already tracked by him", peer, block_hash);
                        return Err(P2pError::AlreadyTrackedBlock(block_hash))
                    }
                    debug!("Saving {} in blocks propagation cache for {}", block_hash, peer);
                    blocks_propagation.put(block_hash.clone(), ());
                }

                // Avoid sending the same block to a common peer that may have already got it
                // because we track peerlist of each peers, we can try to determinate it
                for common_peer in self.get_common_peers_for(&peer).await {
                    debug!("{} is a common peer with {}, adding block {} to its propagation cache", common_peer, peer, block_hash);
                    let mut blocks_propagation = common_peer.get_blocks_propagation().lock().await;
                    blocks_propagation.put(block_hash.clone(), ());
                }

                // check that we don't have this block in our chain
                {
                    let storage = self.blockchain.get_storage().read().await;
                    if storage.has_block(&block_hash).await? {
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
                if let Err(e) = self.blocks_processor.send((peer, header, block_hash)) {
                    error!("Error while sending block propagated to blocks processor task: {}", e);
                }
            },
            Packet::ChainRequest(packet_wrapper) => {
                trace!("Received a chain request from {}", peer);
                let (request, ping) = packet_wrapper.consume();
                ping.into_owned().update_peer(peer, &self.blockchain).await?;
                let request = request.into_owned();
                let last_request = peer.get_last_chain_sync();
                let time = get_current_time();
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

                let zelf = Arc::clone(self);
                let peer = Arc::clone(peer);
                let blocks = request.get_blocks();
                tokio::spawn(async move {
                    if let Err(e) = zelf.handle_chain_request(&peer, blocks).await {
                        error!("Error while handling chain request from {}: {}", peer, e);
                        peer.increment_fail_count();
                    }
                });
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
                let current_time = get_current_time();
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
                    peer.set_last_peer_list(current_time);
                    if last_peer_list != 0 && current_time - last_peer_list < P2P_PING_PEER_LIST_DELAY {
                        return Err(P2pError::PeerInvalidPeerListCountdown)
                    }
                }

                for peer in ping.get_peers() {
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
                            storage.get_block(hash).await
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
                let nonces_cache = mempool.get_nonces_cache();
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
                peer.set_last_inventory(get_current_time());

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
                let addr = packet.to_addr();
                debug!("{} disconnected from {}", addr, peer);
                {
                    let mut peers_received = peer.get_peers(false).lock().await;
                    let peers_sent = peer.get_peers(true).lock().await;
    
                    let received_contains = peers_received.contains(&addr);
                    let sent_contains = peers_sent.contains(&addr);
                    // Because it was a common peer and that the peer disconnected from us and him
                    // it would works but if it get only disconnected from one side, that mean
                    // It would only be deleted from one of the two side and create a desync
                    // As we can't delete after sending the packet directly
                    // Current solution is to check only if it was a received one
                    if !received_contains {
                        debug!("{} disconnected from {} but its not a common peer ? {} {}", addr, peer.get_outgoing_address(), received_contains, sent_contains);
                        return Err(P2pError::UnknownPeerReceived(addr))                    
                    }
    
                    // Delete the peer received
                    peers_received.remove(&addr);
                }

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
        };
        Ok(())
    }

    // Listen to incoming packets from a connection
    // Packet is read from the same task always, while its handling is delegated to a unique task
    async fn listen_connection(self: &Arc<Self>, buf: &mut [u8], peer: &Arc<Peer>) -> Result<(), P2pError> {
        // Read & parse the packet
        let packet = peer.get_connection().read_packet(buf, MAX_BLOCK_SIZE as u32).await?;
        // Handle the packet
        if let Err(e) = self.handle_incoming_packet(&peer, packet).await {
            error!("Error occured while handling incoming packet from {}: {}", peer, e);
            peer.increment_fail_count();
        }

        Ok(())
    }

    async fn find_common_point(&self, storage: &S, blocks: Vec<BlockId>) -> Result<Option<CommonPoint>, BlockchainError> {
        for block_id in blocks { // search a common point
            trace!("Searching common point for block {} at topoheight {}", block_id.get_hash(), block_id.get_topoheight());
            if storage.has_block(block_id.get_hash()).await? {
                let (hash, topoheight) = block_id.consume();
                trace!("Block {} is common, expected topoheight: {}", hash, topoheight);
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
    async fn handle_chain_request(self: &Arc<Self>, peer: &Arc<Peer>, blocks: Vec<BlockId>) -> Result<(), BlockchainError> {
        debug!("handle chain request for {} with {} blocks", peer, blocks.len());
        let storage = self.blockchain.get_storage().read().await;
        // blocks hashes sent for syncing (topoheight ordered)
        let mut response_blocks = IndexSet::new();
        let mut top_blocks = IndexSet::new();
        // common point used to notify peer if he should rewind or not
        let common_point = self.find_common_point(&*storage, blocks).await?;
        if let Some(common_point) = &common_point {
            let mut topoheight = common_point.get_topoheight();
            // lets add all blocks ordered hash
            let top_topoheight = self.blockchain.get_topo_height();
            let stable_height = self.blockchain.get_stable_height();
            // used to detect if we find unstable height for alt tips
            let mut potential_unstable_height = None;
            // check to see if we should search for alt tips (and above unstable height)
            let should_search_alt_tips = top_topoheight - topoheight < CHAIN_SYNC_RESPONSE_MAX_BLOCKS as u64;

            // complete ChainResponse blocks until we are full or that we reach the top topheight
            while response_blocks.len() < CHAIN_SYNC_RESPONSE_MAX_BLOCKS && topoheight <= top_topoheight {
                trace!("looking for hash at topoheight {}", topoheight);
                let hash = storage.get_hash_at_topo_height(topoheight).await?;
                if should_search_alt_tips && potential_unstable_height.is_none() {
                    let height = storage.get_height_for_block_hash(&hash).await?;
                    if height >= stable_height {
                        debug!("Found unstable height at {}", height);
                        potential_unstable_height = Some(height);
                    }
                }
                trace!("for chain request, adding hash {} at topoheight {}", hash, topoheight);
                response_blocks.insert(hash);
                topoheight += 1;
            }

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
        peer.send_packet(Packet::ChainResponse(ChainResponse::new(common_point, response_blocks, top_blocks))).await?;
        Ok(())
    }

    async fn handle_chain_response(&self, peer: &Arc<Peer>, mut response: ChainResponse) -> Result<(), BlockchainError> {
        trace!("handle chain response from {}", peer);
        let response_size = response.size();
        if response.size() > CHAIN_SYNC_RESPONSE_MAX_BLOCKS { // peer is trying to spam us
            warn!("{} is maybe trying to spam us", peer);
            return Err(P2pError::MalformedChainResponse(response_size).into())
        }

        let Some(common_point) = response.get_common_point() else {
            warn!("No common block was found with {}", peer);
            if response.size() > 0 {
                warn!("Peer have no common block but send us {} blocks!", response.size());
                return Err(P2pError::InvalidPacket.into())
            }
            return Ok(())
        };

        debug!("{} found a common point with block {} at {} for sync, received {} blocks", peer, common_point.get_hash(), common_point.get_topoheight(), response_size);
        let pop_count = {
            let storage = self.blockchain.get_storage().read().await;
            let topoheight = storage.get_topo_height_for_hash(common_point.get_hash()).await?;
            if topoheight != common_point.get_topoheight() {
                error!("{} sent us a valid block hash, but at invalid topoheight (expected: {}, got: {})!", peer, topoheight, common_point.get_topoheight());
                return Err(P2pError::InvalidCommonPoint(common_point.get_topoheight()).into())
            }

            let block_height = storage.get_height_for_block_hash(common_point.get_hash()).await?;
            // We are under the stable height, rewind is necessary
            if block_height <= self.blockchain.get_stable_height() {
                self.blockchain.get_topo_height() - topoheight
            } else {
                0
            }
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
        if pop_count > 0
            && peer.get_topoheight() > our_previous_topoheight
            && peer.get_height() >= our_previous_height
            // if the difference is above the STABLE LIMIT, we have to rewind as the common point is in stable height and no block can be added
            && common_point.get_topoheight() <= our_previous_topoheight && our_previous_topoheight - common_point.get_topoheight() > STABLE_LIMIT
            // then, verify if it's a priority node, otherwise, check if we are connected to a priority node so only him can rewind us
            && (peer.is_priority() || !self.is_connected_to_a_synced_priority_node().await)
        {
            // check that if we can trust him
            if peer.is_priority() {
                warn!("Rewinding chain without checking because {} is a priority node (pop count: {})", peer, pop_count);
                self.blockchain.rewind_chain(pop_count).await?;
            } else {
                // request all blocks header and verify basic chain structure
                let mut chain_validator = ChainValidator::new(self.blockchain.clone());
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
                // peer chain looks correct, lets rewind our chain
                warn!("Rewinding chain because of {} (pop count: {})", peer, pop_count);
                self.blockchain.rewind_chain(pop_count).await?;

                // now retrieve all txs from all blocks header and add block in chain
                for hash in chain_validator.get_order() {
                    let header = chain_validator.consume_block_header(&hash)?;
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
    
                        let block = Block::new(Immutable::Arc(header), transactions);
                        self.blockchain.add_new_block(block, false, false).await?; // don't broadcast block because it's syncing
                    }
                }
            }
        } else {
            // no rewind are needed, process normally
            // it will first add blocks to sync, and then all alt-tips blocks if any (top blocks)
            let mut total_requested: usize = 0;
            for hash in blocks { // Request all blocks now
                if !self.blockchain.has_block(&hash).await? {
                    trace!("Block {} is not found, asking it to {} (index = {})", hash, peer.get_outgoing_address(), total_requested);
                    let response = peer.request_blocking_object(ObjectRequest::Block(hash)).await?;
                    if let OwnedObjectResponse::Block(block, hash) = response {
                        trace!("Received block {} at height {} from {}", hash, block.get_height(), peer);
                        self.blockchain.add_new_block(block, false, false).await?;
                    } else {
                        error!("{} sent us an invalid block response", peer);
                        return Err(P2pError::ExpectedBlock.into())
                    }
                    total_requested += 1;
                } else {
                    trace!("Block {} is already in chain, skipping it", hash);
                }
            }
            debug!("we've synced {} on {} blocks and {} top blocks from {}", total_requested, blocks_len, top_len, peer);
        }

        let peer_topoheight = peer.get_topoheight();
        // ask inventory of this peer if we sync from too far
        // if we are not further than one sync, request the inventory
        if peer_topoheight > our_previous_topoheight && blocks_len < CHAIN_SYNC_RESPONSE_MAX_BLOCKS {
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

    pub fn get_tag(&self) -> &Option<String> {
        &self.tag
    }

    pub fn get_max_peers(&self) -> usize {
        self.max_peers
    }

    pub fn get_peer_id(&self) -> u64 {
        self.peer_id
    }

    pub async fn accept_new_connections(&self) -> bool {
        self.get_peer_count().await < self.get_max_peers()
    }

    pub async fn get_peer_count(&self) -> usize {
        let peer_list = self.peer_list.read().await;
        peer_list.size()
    }

    pub async fn get_best_topoheight(&self) -> u64 {
        let our = self.blockchain.get_topo_height();
        let peer_list = self.peer_list.read().await;
        let best = peer_list.get_best_topoheight();
        if best > our {
            best
        } else {
            our
        }
    }

    async fn start_syncing(&self, peer: Arc<Peer>) {
        let mut syncing = self.syncing_peer.lock().await;
        *syncing = Some(peer);
    }

    async fn stop_syncing(&self) -> bool {
        let mut syncing = self.syncing_peer.lock().await;
        syncing.take().is_some()
    }

    pub async fn is_syncing(&self) -> bool {
        self.syncing_peer.lock().await.is_some()
    }

    pub async fn is_connected_to(&self, peer_id: &u64) -> Result<bool, P2pError> {
        let peer_list = self.peer_list.read().await;
        Ok(self.peer_id == *peer_id || peer_list.has_peer(peer_id))
    }

    pub async fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> Result<bool, P2pError> {
        if *peer_addr == *self.get_bind_address() { // don't try to connect to ourself
            debug!("Trying to connect to ourself, ignoring.");
            return Ok(true)
        }

        let peer_list = self.peer_list.read().await;
        Ok(peer_list.is_connected_to_addr(peer_addr))
    }

    pub fn get_bind_address(&self) -> &SocketAddr {
        &self.bind_address
    }

    pub fn get_peer_list(&self) -> &SharedPeerList {
        &self.peer_list
    }

    pub async fn broadcast_tx_hash(&self, tx: Hash) {
        info!("Broadcasting tx hash {}", tx);
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
                    txs_cache.put(tx.clone(), ());
                } else {
                    trace!("{} have tx hash {} in cache, skipping", peer, tx);
                }
            }
        }
    }

    // broadcast block to all peers that can accept directly this new block
    pub async fn broadcast_block(&self, block: &BlockHeader, cumulative_difficulty: u64, our_topoheight: u64, our_height: u64, pruned_topoheight: Option<u64>, hash: &Hash, lock: bool) {
        info!("Broadcasting block {} at height {}", hash, block.get_height());
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
            // or, check that peer height is less or equal to block height but still under or equal to STABLE_LIMIT
            // chain can accept old blocks (up to STABLE_LIMIT) but new blocks only N+1
            if (peer_height >= block.get_height() && peer_height - block.get_height() <= STABLE_LIMIT) || (peer_height <= block.get_height() && block.get_height() - peer_height <= STABLE_LIMIT) {
                let mut blocks_propagation = peer.get_blocks_propagation().lock().await;
                // check that we don't send the block to the peer that sent it to us
                if !blocks_propagation.contains(hash) {
                    // we broadcasted to him, add it to the cache
                    // he should not send it back to us
                    if lock {
                        blocks_propagation.put(hash.clone(), ());
                    }

                    debug!("Broadcast {} to {}", hash, peer);
                    if let Err(e) = peer.send_bytes(packet_block_bytes.clone()).await {
                        debug!("Error on broadcast block {} to {}: {}", hash, peer, e);
                    }
                } else {
                    debug!("{} contains {}, don't broadcast block to him", peer, hash);
                    // But we can notify him with a ping packet that we got the block
                    if let Err(e) = peer.send_bytes(packet_ping_bytes.clone()).await {
                        debug!("Error on sending ping for notifying that we accepted the block {} to {}: {}", hash, peer, e);
                    } else {
                        peer.set_last_ping_sent(get_current_time());
                    }
                }
            } else {
                trace!("Cannot broadcast {} at height {} to {}, too far", hash, block.get_height(), peer);
            }
        }
        trace!("broadcasting block {} is done", hash);
    }

    pub async fn broadcast_packet(&self, packet: Packet<'_>) {
        trace!("Locking peer list for broadcasting packet");
        let peer_list = self.peer_list.read().await;
        trace!("Lock acquired, broadcast packet");
        peer_list.broadcast(packet).await;
    }

    async fn handle_bootstrap_chain_request(self: &Arc<Self>, peer: &Arc<Peer>, request: StepRequest<'_>) -> Result<(), BlockchainError> {
        let request_kind = request.kind();
        debug!("Handle bootstrap chain request {:?} from {}", request_kind, peer);

        let storage = self.blockchain.get_storage().read().await;
        let pruned_topoheight = storage.get_pruned_topoheight()?.unwrap_or(0);
        if let Some(topoheight) = request.get_requested_topoheight() {
            let our_topoheight = self.blockchain.get_topo_height();
            // verify that the topoheight asked is above the PRUNE_SAFETY_LIMIT
            // TODO check that the block is stable
            if
                pruned_topoheight >= topoheight
                || topoheight > our_topoheight
                || topoheight < PRUNE_SAFETY_LIMIT
            {
                warn!("Invalid begin topoheight (received {}, our is {}, pruned: {}) received from {}", topoheight, our_topoheight, pruned_topoheight, peer);
                return Err(P2pError::InvalidRequestedTopoheight.into())
            }
        }

        let response = match request {
            StepRequest::ChainInfo(blocks) => {
                let common_point = self.find_common_point(&*storage, blocks).await?;
                let tips = storage.get_tips().await?;
                let (hash, height) = self.blockchain.find_common_base(&storage, &tips).await?;
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
                let balances = storage.get_balances(&asset, keys.iter(), topoheight).await?;
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
                let mut blocks = Vec::with_capacity(PRUNE_SAFETY_LIMIT as usize);
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

                    blocks.push(BlockMetadata { hash, supply, reward, difficulty, cumulative_difficulty });
                }
                StepResponse::BlocksMetadata(blocks)
            },
        };
        peer.send_packet(Packet::BootstrapChainResponse(BootstrapChainResponse::new(response))).await?;
        Ok(())
    }

    async fn build_list_of_blocks_id(&self, storage: &S) -> Result<Vec<BlockId>, BlockchainError> {
        let mut blocks = Vec::new();
        let topoheight = self.blockchain.get_topo_height();
        let pruned_topoheight = storage.get_pruned_topoheight()?.unwrap_or(0);
        let mut i = 0;

        // we add 1 for the genesis block added below
        while i < topoheight && topoheight - i >= pruned_topoheight && blocks.len() + 1 < CHAIN_SYNC_REQUEST_MAX_BLOCKS {
            trace!("Requesting hash at topo {} for building list of blocks id", topoheight - i);
            let hash = storage.get_hash_at_topo_height(topoheight - i).await?;
            blocks.push(BlockId::new(hash, topoheight - i));
            match blocks.len() {
                0..=19 => {
                    i += 1;
                },
                20..=39 => {
                    i += 5;
                }
                40..=59 => {
                    i += 50;
                },
                60..=79 => {
                    i += 500;
                }
                _ => {
                    i = i * 2;
                }
            };
        }

        // add genesis block
        let genesis_block = storage.get_hash_at_topo_height(0).await?;
        blocks.push(BlockId::new(genesis_block, 0));
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

        let mut all_assets = HashSet::new();
        loop {
            let response = if let Some(step) = step.take() {
                info!("Requesting step {:?}", step.kind());
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
                            let pruned_topoheight = storage.get_pruned_topoheight()?.unwrap_or(0);
                            
                            warn!("Common point is {} while our top block hash is {} !", common_point.get_hash(), top_block_hash);
                            let pop_count = if pruned_topoheight >= common_point.get_topoheight() {
                                our_topoheight - pruned_topoheight
                            } else {
                                our_topoheight - common_point.get_topoheight()
                            };
                            our_topoheight = self.blockchain.rewind_chain_for_storage(&mut *storage, pop_count).await?;
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
                        all_assets.insert(asset);
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
                            debug!("Saving nonce {} for {}", nonce, key);
                            storage.set_nonce_at_topoheight(key, nonce, stable_topoheight).await?;
                        }
                    }

                    // TODO don't retrieve ALL each time but one by one
                    // otherwise in really long time, it may consume lot of memory
                    for asset in &all_assets {
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
                            if let Some(balance) = balance {
                                debug!("Saving balance {} for key {} at topoheight {}", balance, key, stable_topoheight);
                                let mut versioned_balance = storage.get_new_versioned_balance(key, &asset, stable_topoheight).await?;
                                versioned_balance.set_balance(balance);
                                storage.set_balance_to(key, &asset, stable_topoheight, &versioned_balance).await?;
                                storage.set_last_topoheight_for_balance(key, &asset, stable_topoheight)?;
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
                    let mut lowest_topoheight = stable_topoheight;
                    for (i, metadata) in blocks.into_iter().enumerate() {
                        // check that we don't already have this block in storage
                        if self.blockchain.has_block(&metadata.hash).await? {
                            continue;
                        }

                        lowest_topoheight = stable_topoheight - i as u64;
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
                        storage.add_new_block(Arc::new(header), &txs, metadata.difficulty, hash).await?;
                    }

                    let mut storage = self.blockchain.get_storage().write().await;
                    storage.set_pruned_topoheight(lowest_topoheight)?;
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
    pub async fn request_sync_chain_for(&self, peer: &Arc<Peer>) -> Result<(), BlockchainError> {
        trace!("Requesting chain from {}", peer);
        let packet = {
            let storage = self.blockchain.get_storage().read().await;
            let request = ChainRequest::new(self.build_list_of_blocks_id(&*storage).await?);
            trace!("Built a chain request with {} blocks", request.size());
            let ping = self.build_generic_ping_packet_with_storage(&*storage).await;
            PacketWrapper::new(Cow::Owned(request), Cow::Owned(ping))
        };

        let response = peer.request_sync_chain(packet).await?;
        self.handle_chain_response(peer, response).await
    }
}