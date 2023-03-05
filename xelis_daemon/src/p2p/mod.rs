pub mod connection;
pub mod peer;
pub mod error;
pub mod packet;
pub mod peer_list;

use serde_json::Value;
use xelis_common::{
    config::{VERSION, NETWORK_ID, SEED_NODES, MAX_BLOCK_SIZE, CHAIN_SYNC_DELAY, P2P_PING_DELAY, CHAIN_SYNC_REQUEST_MAX_BLOCKS, MAX_BLOCK_REWIND, P2P_PING_PEER_LIST_DELAY, P2P_PING_PEER_LIST_LIMIT, STABLE_HEIGHT_LIMIT, PEER_FAIL_LIMIT, CHAIN_SYNC_RESPONSE_MAX_BLOCKS},
    serializer::Serializer,
    crypto::hash::{Hashable, Hash},
    block::Block,
    globals::get_current_time
};
use crate::core::blockchain::Blockchain;
use crate::core::error::BlockchainError;
use crate::p2p::connection::ConnectionMessage;
use crate::p2p::packet::chain::CommonPoint;
use self::packet::chain::{BlockId, ChainRequest, ChainResponse};
use self::packet::object::{ObjectRequest, ObjectResponse, OwnedObjectResponse};
use self::peer_list::{SharedPeerList, PeerList};
use self::connection::{State, Connection};
use self::packet::handshake::Handshake;
use self::packet::ping::Ping;
use self::error::P2pError;
use self::packet::{Packet, PacketWrapper};
use self::peer::Peer;
use tokio::{net::{TcpListener, TcpStream}, sync::mpsc::{self, UnboundedSender, UnboundedReceiver}, select, task::JoinHandle, time::MissedTickBehavior};
use log::{info, warn, error, debug, trace};
use tokio::io::AsyncWriteExt;
use tokio::time::interval;
use tokio::time::timeout;
use std::{borrow::Cow, fs, path::Path, sync::atomic::{AtomicBool, Ordering}};
use std::convert::TryInto;
use std::net::SocketAddr;
use std::time::Duration;
use std::sync::Arc;
use bytes::Bytes;
use rand::Rng;

enum MessageChannel {
    Exit,
    Connect((SocketAddr, bool))
}

// P2pServer is a fully async TCP server
// Each connection will block on a data to send or to receive
// useful for low end hardware
pub struct P2pServer {
    peer_id: u64, // unique peer id
    tag: Option<String>, // node tag sent on handshake
    max_peers: usize, // max peers accepted by this server
    bind_address: SocketAddr, // ip:port address to receive connections
    peer_list: SharedPeerList, // all peers accepted
    blockchain: Arc<Blockchain>, // reference to the chain to add blocks/txs
    connections_sender: UnboundedSender<MessageChannel>, // this sender allows to create a queue system in one task only
    syncing: AtomicBool // used to check if we are already syncing with one peer or not
}

impl P2pServer {
    pub fn new(tag: Option<String>, max_peers: usize, bind_address: String, blockchain: Arc<Blockchain>) -> Result<Arc<Self>, P2pError> {
        if let Some(tag) = &tag {
            assert!(tag.len() > 0 && tag.len() <= 16);
        }

        // set channel to communicate with listener thread
        let mut rng = rand::thread_rng();
        let peer_id: u64 = rng.gen(); // generate a random peer id for network
        let addr: SocketAddr = bind_address.parse()?; // parse the bind address
        // create mspc channel
        let (connections_sender, receiver) = mpsc::unbounded_channel();
        let server = Self {
            peer_id,
            tag,
            max_peers,
            bind_address: addr,
            peer_list: PeerList::new(max_peers),
            blockchain,
            connections_sender,
            syncing: AtomicBool::new(false)
        };

        let arc = Arc::new(server);
        let zelf = Arc::clone(&arc);
        tokio::spawn(async move {
            if let Err(e) = zelf.start(receiver).await {
                error!("Unexpected error on P2p module: {}", e);
            }
        });
        Ok(arc)
    }

    pub async fn stop(&self) {
        info!("Stopping P2p Server...");
        if let Err(e) = self.connections_sender.send(MessageChannel::Exit) {
            error!("Error while sending Exit message to stop accepting new connections: {}", e);
        }

        let mut peers = self.peer_list.write().await;
        match self.get_peers_from_file().await {
            Ok(mut peers_from_file) => {
                for (_, peer) in peers.get_peers() {
                    let addr = peer.get_connection().get_address();
                    if !peers_from_file.contains(&addr) {
                        peers_from_file.push(addr.clone());
                    }
                }
                if let Err(e) = self.save_peers_to_file(&peers_from_file).await {
                    error!("Couldn't save peers to file: {}", e);
                };
            },
            Err(e) => {
                error!("Couldn't retrieve peers from file: {}", e);
            }
        }
        peers.close_all().await;
        info!("P2p Server is now stopped!");
    }

    // Connect to all seed nodes from constant
    // buffer parameter is to prevent the re-allocation
    async fn connect_to_seed_nodes(self: &Arc<Self>) -> Result<(), P2pError> {
        for peer in SEED_NODES {
            let addr: SocketAddr = match peer.parse() {
                Ok(addr) => addr,
                Err(e) => return Err(P2pError::InvalidPeerAddress(format!("seed node {}: {}", peer, e)))
            };
            if !self.is_connected_to_addr(&addr).await? {
                self.try_to_connect_to_peer(addr, true);
            }
        }
        Ok(())
    }

    // every 10 seconds, verify
    async fn maintains_seed_nodes(self: &Arc<Self>) -> Result<(), P2pError> {
        let mut interval = interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            if let Err(e) = self.connect_to_seed_nodes().await {
                debug!("Error while connecting to seed nodes: {}", e);
            };
        }
    }

    fn get_peerlist_file(&self) -> String {
        format!("peerlist-{}.json", self.blockchain.get_network().to_string().to_lowercase())
    }

    // we save it in peerlist-{network}.json file in case we want to do custom peerlist files
    async fn get_peers_from_file(&self) -> Result<Vec<SocketAddr>, P2pError> {
        let mut peers = Vec::new();
        let str_path = self.get_peerlist_file();
        let path = Path::new(&str_path);
        if !path.exists() {
            info!("Peerlist at {} not found, creating file...", str_path);
            self.save_peers_to_file(&peers).await?;
            return Ok(peers);
        }

        let string = fs::read_to_string(path)?;
        let json: Value = serde_json::from_str(&string).map_err(|_| P2pError::InvalidPeerlist)?;

        if let Some(values) = json.as_array() {
            for value in values {
                if let Some(addr) = value.as_str() {
                    let addr: SocketAddr = match addr.parse() {
                        Ok(addr) => addr,
                        Err(e) => return Err(P2pError::InvalidPeerAddress(format!("peerlist {}: {}", addr, e)))
                    };
                    peers.push(addr);
                } else {
                    debug!("Content in peerlist is not a string");
                    return Err(P2pError::InvalidPeerlist);
                }
            }
        } else {
            debug!("Content in peerlist is not an array");
            return Err(P2pError::InvalidPeerlist);
        }

        Ok(peers)
    }

    // save a new peer to peerlist.json file
    // for this we have to fetch all, add it to Vec and save it
    async fn save_peer_to_file(&self, addr: SocketAddr) -> Result<(), P2pError> {
        debug!("Saving peer {} to peerlist file...", addr);
        let mut peers = self.get_peers_from_file().await?;
        if peers.contains(&addr) {
            debug!("Peerlist file already contains {}", addr);
            return Ok(())
        }

        peers.push(addr);
        self.save_peers_to_file(&peers).await
    }

    async fn save_peers_to_file(&self, peers: &Vec<SocketAddr>) -> Result<(), P2pError> {
        let content = match serde_json::to_string_pretty(peers) {
            Ok(content) => content,
            Err(e) => {
                error!("Error while serializing peerlist: {}", e);
                return Err(P2pError::InvalidPeerlist)
            }
        };

        let str_path = self.get_peerlist_file();
        fs::write(str_path, content)?;

        Ok(())
    }

    // connect to seed nodes, start p2p server
    // and wait on all new connections
    async fn start(self: &Arc<Self>, mut receiver: UnboundedReceiver<MessageChannel>) -> Result<(), P2pError> {
        // create tokio task to maintains connection to seed nodes
        {
            let zelf = Arc::clone(self);
            tokio::spawn(async move {
                info!("Connecting to seed nodes...");
                if let Err(e) = zelf.maintains_seed_nodes().await {
                    error!("Error while maintening connection with seed nodes: {}", e);
                };
            });
        }

        // retrieve all peers from peerlist.json
        let peers = self.get_peers_from_file().await?;
        for peer in peers {
            if !self.accept_new_connections().await {
                debug!("Daemon has reached limit of connections");
                break;
            }

            info!("Adding peer address {} from peerlist to queue", peer);
            self.try_to_connect_to_peer(peer, false);
        }

        // start a new task for chain sync
        tokio::spawn(Arc::clone(&self).chain_sync_loop());

        // start another task for ping loop
        tokio::spawn(Arc::clone(&self).ping_loop());

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
    async fn verify_handshake(&self, mut connection: Connection, handshake: Handshake, out: bool, priority: bool) -> Result<(Peer, Vec<SocketAddr>), P2pError> {
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

        // check if peer is not greater than us and that we can rewind his top chain in case he is not on not the same chain
        if handshake.get_block_height() <= self.blockchain.get_height() && self.blockchain.get_height() - handshake.get_block_height() > MAX_BLOCK_REWIND {
            let storage = self.blockchain.get_storage().read().await;
            match storage.get_block_by_hash(handshake.get_block_top_hash()).await {
                Ok(block) => {
                    if block.get_height() != handshake.get_block_height() {
                        debug!("{} (block {}) is not on the same chain! Block height: {}, handshake height: {}", connection, handshake.get_block_top_hash(), block.get_height(), handshake.get_block_height());
                        connection.close().await?;
                        return Err(P2pError::InvalidHandshake)
                    }
                },
                Err(_) => {
                    debug!("{} has a block '{}' which is not found at height '{}'.", connection, handshake.get_block_top_hash(), handshake.get_block_height());
                    connection.close().await?;
                    return Err(P2pError::InvalidHandshake)
                }
            };
        }

        connection.set_state(State::Success);
        let (peer, peers) = handshake.create_peer(connection, out, priority, Arc::clone(&self.peer_list));
        Ok((peer, peers))
    }

    async fn build_handshake(&self) -> Result<Handshake, P2pError> {
        let mut peers: Vec<SocketAddr> = Vec::new();
        {
            let peer_list = self.peer_list.read().await;
            let mut iter = peer_list.get_peers().iter();
            while peers.len() < Handshake::MAX_LEN {
                match iter.next() {
                    Some((_, v)) => {
                        let mut addr: SocketAddr = v.get_connection().get_address().clone();
                        if !v.is_out() {
                            addr.set_port(v.get_local_port());
                        }
                        peers.push(addr);
                    },
                    None => break
                };
            }
        }

        let storage = self.blockchain.get_storage().read().await;
        let (block, top_hash) = storage.get_top_block().await?;
        let topoheight = self.blockchain.get_topo_height();
        let cumulative_difficulty = storage.get_cumulative_difficulty_for_block(&top_hash).await.unwrap_or(0);
        Ok(Handshake::new(VERSION.to_owned(), *self.blockchain.get_network(), self.get_tag().clone(), NETWORK_ID, self.get_peer_id(), self.bind_address.port(), get_current_time(), topoheight, block.get_height(), top_hash, cumulative_difficulty, peers))
    }

    // this function handle all new connections
    // A new connection have to send an Handshake
    // if the handshake is valid, we accept it & register it on server
    async fn handle_new_connection(self: &Arc<Self>, buf: &mut [u8], mut connection: Connection, out: bool, priority: bool) -> Result<(), P2pError> {
        trace!("New connection: {}", connection);
        let handshake: Handshake = match timeout(Duration::from_millis(800), connection.read_packet(buf, buf.len() as u32)).await?? {
            Packet::Handshake(h) => h.into_owned(), // only allow handshake packet
            _ => return Err(P2pError::ExpectedHandshake)
        };
        trace!("received handshake packet!");
        connection.set_state(State::Handshake);
        let (peer, peers) = self.verify_handshake(connection, handshake, out, priority).await?;
        // if it's a outgoing connection, don't send the handshake back
        // because we have already sent it
        if !out {
            self.send_handshake(peer.get_connection()).await?;
        }

        // if we reach here, handshake is all good, we can start listening this new peer
        // we can save the peer in our peerlist
        {
            let mut addr = peer.get_connection().get_address().clone();
            if !peer.is_out() {
                addr.set_port(peer.get_local_port());
            }
            if let Err(e) = self.save_peer_to_file(addr).await {
                error!("Error while saving peer on disk: {}", e);
            };
        }

        let peer_id = peer.get_id(); // keep in memory the peer_id outside connection (because of moved value)
        let peer = {
            let mut peer_list = self.peer_list.write().await;
            peer_list.add_peer(peer_id, peer)
        };

        // try to extend our peer list
        for peer_addr in peers { // should we limit to X peers only ?
            if !self.accept_new_connections().await {
                break
            }

            if !self.is_connected_to_addr(&peer_addr).await? {
                debug!("Trying to extend peer list with {} from {}", peer_addr, peer);
                self.try_to_connect_to_peer(peer_addr, false);
            }
        }

        self.handle_connection(peer.clone()).await
    }

    // Connect to a specific peer address
    // Buffer is passed in parameter to prevent the re-allocation each time
    pub fn try_to_connect_to_peer(&self, addr: SocketAddr, priority: bool) {
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
    async fn build_generic_ping_packet(&self) -> Ping<'_> {
        let (cumulative_difficulty, block_top_hash) = {
            let storage = self.blockchain.get_storage().read().await;
            match storage.get_top_block_hash().await {
                Err(e) => {
                    error!("Couldn't get the top block hash from storage for generic ping packet: {}", e);
                    (0, Hash::zero())
                },
                Ok(hash) => (storage.get_cumulative_difficulty_for_block(&hash).await.unwrap_or(0), hash)
            }
        };
        let highest_topo_height = self.blockchain.get_topo_height();
        let highest_height = self.blockchain.get_height();
        let new_peers = Vec::new();
        Ping::new(Cow::Owned(block_top_hash), highest_topo_height, highest_height, cumulative_difficulty, new_peers)
    }

    // select a random peer which is greater than us to sync chain
    // candidate peer should have a greater topoheight or a higher block height than us
    async fn select_random_best_peer(&self) -> Option<Arc<Peer>> {
        trace!("select random best peer");
        let peer_list = self.peer_list.read().await;
        let our_height = self.blockchain.get_height();
        let our_topoheight = self.blockchain.get_topo_height();
        let peers: Vec<&Arc<Peer>> = peer_list.get_peers().values().filter(|p| p.get_height() > our_height || p.get_topoheight() > our_topoheight).collect();
        let count = peers.len();
        trace!("peers available for random selection: {}", count);
        if count == 0 {
            return None
        }
        let selected = rand::thread_rng().gen_range(0..count);
        let peer = peers.get(selected)?;
        trace!("selected peer: ({}) {}", selected, peer);
        // clone the Arc to prevent the lock until the end of the sync request
        Some(Arc::clone(peer))
    }

    async fn chain_sync_loop(self: Arc<Self>) {
        let mut interval = interval(Duration::from_secs(CHAIN_SYNC_DELAY));
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            interval.tick().await;
            if self.is_syncing() {
                trace!("We are already syncing, skipping...");
                continue;
            }
            if let Some(peer) = self.select_random_best_peer().await {
                trace!("Selected for chain sync is {}", peer);
                if let Err(e) = self.request_sync_chain_for(&peer).await {
                    debug!("Error occured on chain sync: {}", e);
                }
            }
        }
    }

    // broadcast generic ping packet every 10s
    // if we have to send our peerlist to all peers, we calculate the ping for each peer
    async fn ping_loop(self: Arc<Self>) {
        let mut ping_interval = interval(Duration::from_secs(P2P_PING_DELAY));
        ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // first tick is immediately elapsed
        let mut last_peerlist_update = get_current_time();
        loop {
            ping_interval.tick().await;
            trace!("build generic ping packet");
            let mut ping = self.build_generic_ping_packet().await;
            trace!("generic ping packet finished");

            let current_time = get_current_time();
            // check if its time to send our peerlist
            if current_time > last_peerlist_update + P2P_PING_PEER_LIST_DELAY {
                trace!("Sending ping packet with peerlist...");
                last_peerlist_update = current_time;
                let peer_list = self.peer_list.read().await;
                for (_, peer) in peer_list.get_peers() {
                    let mut new_peers = Vec::new();

                    // all the peers of current peer
                    let mut peer_peers = peer.get_peers().lock().await;

                    // iterate through our peerlist to determinate which peers we have to send
                    for p in peer_list.get_peers().values() {
                        // don't send him itself
                        if *p.get_connection().get_address() == *peer.get_connection().get_address() {
                            continue;
                        }

                        let mut addr = p.get_connection().get_address().clone();
                        if !p.is_out() { // if we are connected to it (outgoing connection), set the local port instead
                            addr.set_port(p.get_local_port());
                        }

                        // if we haven't send him this peer addr, insert it
                        if !peer_peers.contains(&addr) {
                            peer_peers.insert(addr.clone());
                            new_peers.push(addr.clone());
                            if new_peers.len() >= P2P_PING_PEER_LIST_LIMIT {
                                break;
                            }
                        }
                    }

                    // update the ping packet with the new peers
                    ping.set_peers(new_peers);
                    // send the ping packet to the peer
                    if let Err(e) = peer.send_packet(Packet::Ping(Cow::Borrowed(&ping))).await {
                        debug!("Error sending specific ping packet to {}: {}", peer, e);
                    }
                }
            } else {
                trace!("Sending generic ping packet...");
                let packet = Packet::Ping(Cow::Owned(ping));
                let peerlist = self.peer_list.read().await;
                peerlist.broadcast(packet).await;
            }
        }
    }

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
                    debug!("write task has finished, stopping...");
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

        Ok(())
    }

    async fn handle_incoming_packet(self: &Arc<Self>, peer: &Arc<Peer>, packet: Packet<'_>) -> Result<(), P2pError> {
        match packet {
            Packet::Handshake(_) => {
                error!("{} sent us handshake packet (not valid!)", peer);
                peer.get_connection().close().await?;
                return Err(P2pError::InvalidPacket)
            },
            Packet::TransactionPropagation(packet_wrapper) => { // TODO prevent spam
                trace!("{}: Transaction Propagation packet", peer);
                let (hash, ping) = packet_wrapper.consume();
                let hash = hash.into_owned();

                // peer should not send us twice the same transaction
                let mut txs_cache = peer.get_txs_cache().lock().await;
                if txs_cache.contains(&hash) {
                    warn!("{} send us a transaction ({}) already tracked by him", peer, hash);
                    return Err(P2pError::InvalidProtocolRules)
                }
                txs_cache.put(hash.clone(), ());

                ping.into_owned().update_peer(peer).await;
                let mempool = self.blockchain.get_mempool().read().await;
                if !mempool.contains_tx(&hash) {
                    let zelf = Arc::clone(self);
                    let peer = Arc::clone(peer);
                    tokio::spawn(async move {
                        let response = match peer.request_blocking_object(ObjectRequest::Transaction(hash)).await {
                            Ok(response) => response,
                            Err(err) => {
                                error!("Error while requesting transaction: {}", err);
                                peer.increment_fail_count();
                                return;
                            }
                        };
                        if let OwnedObjectResponse::Transaction(tx, hash) = response {
                            if let Err(e) = zelf.blockchain.add_tx_with_hash_to_mempool(tx, hash, true).await {
                                match e {
                                    // another peer was faster than us
                                    BlockchainError::TxAlreadyInMempool(_) => {}, // TODO: synced request list
                                    e => {
                                        error!("Error while adding TX to mempool: {}", e);
                                        peer.increment_fail_count();
                                    }
                                };
                            }
                        } else {
                            peer.increment_fail_count();
                            error!("Expected to receive a Transaction object from peer: {}", peer);
                        }
                    });
                }
            },
            Packet::BlockPropagation(packet_wrapper) => {
                trace!("Received a block propagation packet from {}", peer);
                let (block, ping) = packet_wrapper.consume();
                ping.into_owned().update_peer(peer).await;
                let block_height = block.get_height();

                // check that the block height is valid
                if block_height < self.blockchain.get_stable_height() {
                    error!("{} send us a block propagation packet which is under stable height (height = {})!", peer, block_height);
                    return Err(P2pError::InvalidProtocolRules)
                }

                let block = block.into_owned();
                let block_hash = block.hash();
                {
                    let storage = self.blockchain.get_storage().read().await;
                    if storage.has_block(&block_hash).await? {
                        debug!("{}: {} with hash {} is already in our chain. Skipping", peer, block, block_hash);
                        return Ok(())
                    }
                }
                let block_height = block.get_height();
                debug!("Received block at height {} from {}", block_height, peer);
                let zelf = Arc::clone(self);
                let peer = Arc::clone(peer);
                // verify that we have all txs in local or ask peer to get missing txs
                tokio::spawn(async move {
                    for hash in block.get_txs_hashes() {
                        let contains = { // we don't lock one time because we may wait on p2p response
                            let mempool = zelf.blockchain.get_mempool().read().await;
                            mempool.contains_tx(hash)
                        };

                        if !contains { // retrieve one by one to prevent the acquiring the lock for nothing
                            debug!("Requesting TX {} to {} for block {}", hash, peer, block_hash);
                            let response = match peer.request_blocking_object(ObjectRequest::Transaction(hash.clone())).await {
                                Ok(response) => response,
                                Err(e) => {
                                    error!("Error while requesting TX {} to peer {}: {}", hash, peer, e);
                                    peer.increment_fail_count();
                                    return;
                                }
                            };
                            if let OwnedObjectResponse::Transaction(tx, _) = response {
                                if let Err(e) = zelf.blockchain.add_tx_to_mempool(tx, false).await {
                                    if let BlockchainError::TxAlreadyInMempool(_) = e {
                                        debug!("TX {} is already in mempool finally, another peer was faster", hash);
                                    } else {
                                        error!("Error while adding new requested tx to mempool: {}", e);
                                        peer.increment_fail_count();
                                    }
                                }
                            } else {
                                error!("Invalid object response received from {}, expected {} got {}", peer, hash, response.get_hash());
                                peer.increment_fail_count();
                                return;
                            }
                        }
                    }

                    // add immediately the block to chain as we are synced with
                    let complete_block = match zelf.blockchain.build_complete_block_from_block(block).await {
                        Ok(block) => block,
                        Err(e) => {
                            error!("Error while building complete block {} from peer {}: {}", block_hash, peer, e);
                            peer.increment_fail_count();
                            return;
                        }
                    };

                    debug!("Adding received block {} to chain", block_hash);
                    if let Err(e) = zelf.blockchain.add_new_block(complete_block, true).await {
                        error!("Error while adding new block: {}", e);
                        peer.increment_fail_count();
                    }
                });
            },
            Packet::ChainRequest(packet_wrapper) => {
                trace!("Received a chain request from {}", peer);
                let (request, ping) = packet_wrapper.consume();
                ping.into_owned().update_peer(peer).await;
                let request = request.into_owned();
                let last_request = peer.get_last_chain_sync();
                let time = get_current_time();
                peer.set_last_chain_sync(time);
                // Node is trying to ask too fast our chain
                if  last_request + CHAIN_SYNC_DELAY > time {
                    debug!("Peer requested sync chain too fast!");
                    return Err(P2pError::RequestSyncChainTooFast)
                }

                // at least one block necessary (genesis block)
                if request.size() == 0 || request.size() > CHAIN_SYNC_REQUEST_MAX_BLOCKS { // allows maximum 64 blocks id (2560 bytes max)
                    warn!("{} sent us a malformed chain request ({} blocks)!", peer, request.size());
                    return Err(P2pError::InvalidProtocolRules)
                }

                let zelf = Arc::clone(self);
                let peer = Arc::clone(peer);
                let blocks = request.get_blocks();
                tokio::spawn(async move {
                    zelf.set_syncing(true);
                    if let Err(e) = zelf.handle_chain_request(&peer, blocks).await {
                        error!("Error while handling chain request from {}: {}", peer, e);
                        peer.increment_fail_count();
                    }
                    zelf.set_syncing(false);
                });
            },
            Packet::ChainResponse(response) => {
                trace!("Received a chain response from {}", peer);
                if !peer.chain_sync_requested() {
                    warn!("{} sent us a chain response but we haven't requested any.", peer);
                    return Err(P2pError::InvalidProtocolRules)
                }
                peer.set_chain_sync_requested(false);

                if response.size() > CHAIN_SYNC_RESPONSE_MAX_BLOCKS { // peer is trying to spam us
                    warn!("{} is maybe trying to spam us", peer);
                    return Err(P2pError::InvalidProtocolRules)
                }

                if let Some(common_point) = response.get_common_point() {
                    debug!("Peer found a common point with block {} at {} for sync, received {} blocks", common_point.get_hash(), common_point.get_topoheight(), response.size());
                    let pop_count = {
                        let storage = self.blockchain.get_storage().read().await;
                        let block_height = match storage.get_height_for_block(common_point.get_hash()).await {
                            Ok(height) => height,
                            Err(e) => {
                                warn!("{} sent us an invalid common point: {}", peer, e);
                                return Err(P2pError::InvalidPacket)
                            }
                        };
                        let topoheight = storage.get_topo_height_for_hash(common_point.get_hash()).await?;
                        if topoheight != common_point.get_topoheight() {
                            error!("{} sent us a valid block hash, but at invalid topoheight (expected: {}, got: {})!", peer, block_height, common_point.get_topoheight());
                            return Err(P2pError::InvalidPacket)
                        }
                        self.blockchain.get_height() - block_height
                    };

                    if pop_count > MAX_BLOCK_REWIND {
                        warn!("We may have deviated too much! Pop count: {}", pop_count);
                    }

                    let peer = Arc::clone(peer);
                    let zelf = Arc::clone(self);
                    let blocks: Vec<Hash> = response.get_blocks().into_iter().map(|b| b.into_owned()).collect();

                    // start a new task to wait on all requested blocks
                    tokio::spawn(async move {
                        zelf.set_syncing(true);
                        if let Err(e) = zelf.handle_chain_response(&peer, blocks, pop_count).await {
                            error!("Error while handling chain response from {}: {}", peer, e);
                            peer.increment_fail_count();
                        }
                        zelf.set_syncing(false);
                    });
                } else {
                    warn!("No common block was found with {}", peer);
                    if response.size() > 0 {
                        debug!("Peer have no common block but send us {} blocks!", response.size());
                        return Err(P2pError::InvalidPacket)
                    }
                }
            },
            Packet::Ping(ping) => {
                trace!("Received a ping packet from {}", peer);
                let last_ping = peer.get_last_ping();
                let current_time = get_current_time();
                peer.set_last_ping(current_time);
                // verify the respect of the coutdown to prevent massive packet incoming
                if last_ping != 0 && current_time - last_ping < P2P_PING_DELAY {
                    return Err(P2pError::PeerInvalidPingCoutdown)
                }

                // we verify the respect of the countdown of peer list updates to prevent any spam
                if ping.get_peers().len() > 0 {
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
                        self.try_to_connect_to_peer(peer, false);
                    }
                }
                ping.into_owned().update_peer(peer).await;
            },
            Packet::ObjectRequest(request) => {
                trace!("Received a object request from {}", peer);
                let request = request.into_owned();
                match &request {
                    ObjectRequest::Block(hash) => {
                        let storage = self.blockchain.get_storage().read().await;
                        if storage.has_block(hash).await? {
                            let block = storage.get_complete_block(hash).await?;
                            peer.send_packet(Packet::ObjectResponse(ObjectResponse::Block(Cow::Owned(block)))).await?;
                        } else {
                            debug!("{} asked block '{}' but not present in our chain", peer, hash);
                            peer.send_packet(Packet::ObjectResponse(ObjectResponse::NotFound(request))).await?;
                        }
                    },
                    ObjectRequest::Transaction(hash) => {
                        let mempool = self.blockchain.get_mempool().read().await;
                        match mempool.view_tx(hash) {
                            Ok(tx) => {
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::Transaction(Cow::Borrowed(tx)))).await?;
                            },
                            Err(e) => {
                                debug!("{} asked tx '{}' but got on error while retrieving it: {}", peer, hash, e);
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::NotFound(request))).await?;
                            }
                        }
                    }
                }
            },
            Packet::ObjectResponse(response) => {
                trace!("Received a object response from {}", peer);
                let request = response.get_request();

                // check if we have requested this object & get the sender from it
                let sender = peer.remove_object_request(request.into_owned()).await?;
                // handle the response
                if sender.send(response.to_owned()?).is_err() {
                    error!("Error while sending object response to sender!");
                }
            }
        };
        Ok(())
    }

    // Listen to incoming packets from a connection
    async fn listen_connection(self: &Arc<Self>, buf: &mut [u8], peer: &Arc<Peer>) -> Result<(), P2pError> {
        let packet = peer.get_connection().read_packet(buf, MAX_BLOCK_SIZE as u32).await?;
        if let Err(e) = self.handle_incoming_packet(peer, packet).await {
            error!("Error occured while handling incoming packet from {}: {}", peer, e);
            peer.increment_fail_count();
        }
        Ok(())
    }

    // search a common point between our blockchain and the peer's one
    // when the common point is found, start sending blocks from this point
    async fn handle_chain_request(self: &Arc<Self>, peer: &Arc<Peer>, blocks: Vec<BlockId>) -> Result<(), BlockchainError> {
        debug!("handle chain request for peer {} with {} blocks", peer, blocks.len());
        let storage = self.blockchain.get_storage().read().await;
        let mut response_blocks = Vec::new();
        let mut common_point = None;
        for block_id in blocks { // search a common point
            trace!("Searching common point for block {} at topoheight {}", block_id.get_hash(), block_id.get_topoheight());
            if storage.has_block(block_id.get_hash()).await? {
                let common_block = storage.get_block_by_hash(block_id.get_hash()).await?;
                let (hash, topoheight) = block_id.consume();
                trace!("Block {} is common, expected topoheight from {}: {}", hash, peer, topoheight);
                // check that the block is ordered like us
                if storage.is_block_topological_ordered(&hash).await && storage.get_topo_height_for_hash(&hash).await? == topoheight { // common point
                    debug!("common point with {} found at block {} with same topoheight at {}", peer, hash, topoheight);
                    common_point = Some(CommonPoint::new(Cow::Owned(hash), topoheight));
                    let top_height = self.blockchain.get_height();
                    let mut height = common_block.get_height();
                    while response_blocks.len() < CHAIN_SYNC_RESPONSE_MAX_BLOCKS && height <= top_height {
                        for hash in storage.get_blocks_at_height(height).await? {
                            trace!("for chain request, adding hash {} at height {}", hash, height);
                            response_blocks.push(Cow::Owned(hash));
                        }
                        height += 1;
                    }
                    break;
                }
            }
        }

        debug!("Sending {} blocks as response to {}", response_blocks.len(), peer);
        peer.send_packet(Packet::ChainResponse(ChainResponse::new(common_point, response_blocks))).await?;
        Ok(())
    }

    async fn handle_chain_response(self: &Arc<Self>, peer: &Arc<Peer>, blocks_request: Vec<Hash>, pop_count: u64) -> Result<(), BlockchainError> {
        debug!("handling chain response from peer {}, {} blocks, pop count {}", peer, blocks_request.len(), pop_count);

        // if node asks us to pop blocks, verify if it's a priority one
        // if it's not a priority node, check if we are connected to one
        // if yes, don't accept the pop count from this peer
        // if no, check that the pop count request is less or equal than the configured limit
        let mut storage = self.blockchain.get_storage().write().await; // lock until we get all blocks
        if pop_count > 0 && (peer.is_priority() || ((pop_count <= MAX_BLOCK_REWIND) && !self.is_connected_to_a_synced_priority_node().await)) {
            warn!("Rewinding chain because of {} (priority: {}, pop count: {})", peer, peer.is_priority(), pop_count);
            match self.blockchain.rewind_chain_for_storage(&mut storage, pop_count as usize).await {
                Ok(topoheight) => debug!("Chain has been rewinded to topoheight {}", topoheight),
                Err(e) => error!("Error on rewind chain with pop count at {}, error: {}", pop_count, e)
            };
        }

        let blocks_count = blocks_request.len();
        for hash in blocks_request { // Request all complete blocks now
            if !storage.has_block(&hash).await? {
                trace!("Block {} is not found, asking it to peer", hash);
                let object_request = ObjectRequest::Block(hash.clone());
                let response = peer.request_blocking_object(object_request).await?;
                if let OwnedObjectResponse::Block(block, hash) = response {
                    trace!("Received block {} at height {} from {}", hash, block.get_height(), peer);
                    self.blockchain.add_new_block_for_storage(&mut storage, block, false).await?;
                } else {
                    error!("{} sent us an invalid block response", peer);
                    return Err(P2pError::ExpectedBlock.into())
                }
            } else {
                trace!("Block {} is already in chain, skipping it", hash);
            }
        }

        debug!("we've synced {} blocks from {}", blocks_count, peer);
        Ok(())
    }

    // determine if we are connected to a priority node and that this node is equal / greater to our chain
    async fn is_connected_to_a_synced_priority_node(&self) -> bool {
        let topoheight = self.blockchain.get_topo_height();
        let peer_list = self.peer_list.read().await;
        for peer in peer_list.get_peers().values() {
            if peer.is_priority() {
                let peer_topoheight = peer.get_topoheight();
                if peer_topoheight >= topoheight || topoheight - peer_topoheight <= MAX_BLOCK_REWIND {
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
        let our_height = self.blockchain.get_topo_height();
        let peer_list = self.peer_list.read().await;
        let best_height = peer_list.get_best_topoheight();
        if best_height > our_height {
            best_height
        } else {
            our_height
        }
    }

    fn set_syncing(&self, value: bool) {
        self.syncing.store(value, Ordering::SeqCst);
    }
    pub fn is_syncing(&self) -> bool {
        self.syncing.load(Ordering::SeqCst)
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
        for peer in peer_list.get_peers().values() {
            if *peer.get_connection().get_address() == *peer_addr {
                return Ok(true)
            }
        }
        Ok(false)
    }

    pub fn get_bind_address(&self) -> &SocketAddr {
        &self.bind_address
    }

    pub fn get_peer_list(&self) -> &SharedPeerList {
        &self.peer_list
    }

    pub async fn broadcast_tx_hash(&self, tx: &Hash) {
        let ping = self.build_generic_ping_packet().await;
        let current_height = ping.get_height();
        let packet = Packet::TransactionPropagation(PacketWrapper::new(Cow::Borrowed(tx), Cow::Owned(ping)));
        // transform packet to bytes (so we don't need to transform it for each peer)
        let bytes = Bytes::from(packet.to_bytes());
        let peer_list = self.peer_list.read().await;
        for peer in peer_list.get_peers().values() {
            // check that the peer is not too far from us
            // otherwise we may spam him for nothing
            if peer.get_height() + CHAIN_SYNC_RESPONSE_MAX_BLOCKS as u64 > current_height {
                trace!("Peer {} is not too far from us, checking cache for tx hash {}", peer, tx);
                let mut txs_cache = peer.get_txs_cache().lock().await;
                // check that we didn't already send this tx to this peer or that he don't already have it
                if !txs_cache.contains(tx) {
                    trace!("Broadcasting tx hash {} to {}", tx, peer);
                    if let Err(e) = peer.send_bytes(bytes.clone()).await {
                        error!("Error while broadcasting tx hash {} to {}: {}", tx, peer, e);
                    };
                    txs_cache.put(tx.clone(), ());
                } else {
                    trace!("{} have tx hash {} in cache, skipping", peer, tx);
                }
            }
        }
    }

    // broadcast block to all peers that can accept directly this new block
    pub async fn broadcast_block(&self, block: &Block, cumulative_difficulty: u64, highest_topoheight: u64, highest_height: u64, hash: &Hash) {
        trace!("Broadcast block: {}", hash);
        // we build the ping packet ourself this time (we have enough data for it)
        // because this function can be call from Blockchain, which would lead to a deadlock
        let ping = Ping::new(Cow::Borrowed(hash), highest_topoheight, highest_height, cumulative_difficulty, Vec::new());
        let packet = Packet::BlockPropagation(PacketWrapper::new(Cow::Borrowed(block), Cow::Owned(ping)));
        let bytes = Bytes::from(packet.to_bytes());
        // TODO should we move it in another async task ?
        let peer_list = self.peer_list.read().await;
        for (_, peer) in peer_list.get_peers() {
            // if the peer can directly accept this new block, send it
            if block.get_height() - 1 == peer.get_height() || peer.get_height() - block.get_height() < STABLE_HEIGHT_LIMIT {
                // check that we don't send the block to the peer that sent it to us
                if *hash != *peer.get_top_block_hash().lock().await {
                    trace!("Broadcast to {}", peer);
                    if let Err(e) = peer.send_bytes(bytes.clone()).await {
                        debug!("Error on broadcast block {} to {}: {}", hash, peer, e);
                    };
                }
            }
        }
    }

    pub async fn broadcast_packet(&self, packet: Packet<'_>) {
        let peer_list = self.peer_list.read().await;
        peer_list.broadcast(packet).await;
    }

    // this function basically send all our blocks based on topological order (topoheight)
    // we send up to CHAIN_SYNC_REQUEST_MAX_BLOCKS blocks id (combinaison of block hash and topoheight)
    // we add at the end the genesis block to be sure to be on the same chain as others peers
    // its used to find a common point with the peer to which we ask the chain
    pub async fn request_sync_chain_for(&self, peer: &Arc<Peer>) -> Result<(), BlockchainError> {
        debug!("Requesting chain from {}", peer);
        let mut request = ChainRequest::new();
        {
            let storage = self.blockchain.get_storage().read().await;
            let topoheight = self.blockchain.get_topo_height();
            let mut i = 0;

            // we add 1 for the genesis block added below
            while i < topoheight && request.size() + 1 < CHAIN_SYNC_REQUEST_MAX_BLOCKS {
                trace!("Requesting hash at topo {}", topoheight - i);
                let hash = storage.get_hash_at_topo_height(topoheight - i).await?;
                request.add_block_id(hash, topoheight - i);
                match request.size() {
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
            request.add_block_id(genesis_block, 0);
            trace!("Sending a chain request with {} blocks", request.size());
            peer.set_chain_sync_requested(true);
        }
        let ping = self.build_generic_ping_packet().await;
        peer.send_packet(Packet::ChainRequest(PacketWrapper::new(Cow::Owned(request), Cow::Owned(ping)))).await?;
        Ok(())
    }
}