use crate::config::{VERSION, NETWORK_ID, SEED_NODES, MAX_BLOCK_SIZE, CHAIN_SYNC_DELAY, P2P_PING_DELAY, CHAIN_SYNC_REQUEST_MAX_BLOCKS, MAX_BLOCK_REWIND, P2P_PING_PEER_LIST_DELAY, P2P_PING_PEER_LIST_LIMIT};
use crate::core::blockchain::Blockchain;
use crate::core::error::BlockchainError;
use crate::core::serializer::Serializer;
use crate::core::block::CompleteBlock;
use crate::globals::get_current_time;
use crate::crypto::hash::{Hashable, Hash};
use crate::core::writer::Writer;
use crate::p2p::connection::ConnectionMessage;
use crate::p2p::packet::chain::CommonPoint;
use super::packet::chain::{BlockId, ChainRequest, ChainResponse};
use super::packet::object::{ObjectRequest, ObjectResponse, OwnedObjectResponse};
use super::peer_list::{SharedPeerList, PeerList};
use super::connection::{State, Connection};
use super::packet::handshake::Handshake;
use super::packet::ping::Ping;
use super::error::P2pError;
use super::packet::{Packet, PacketWrapper};
use super::peer::Peer;
use tokio::net::{TcpListener, TcpStream};
use log::{info, warn, error, debug, trace};
use tokio::io::AsyncWriteExt;
use tokio::time::interval;
use tokio::time::timeout;
use std::borrow::Cow;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::time::Duration;
use std::sync::Arc;
use bytes::Bytes;
use rand::Rng;

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
        let server = Self {
            peer_id,
            tag,
            max_peers,
            bind_address: addr,
            peer_list: PeerList::new(max_peers),
            blockchain
        };

        let arc = Arc::new(server);
        let zelf = Arc::clone(&arc);
        tokio::spawn(async move {
            if let Err(e) = zelf.start().await {
                error!("Unexpected error on P2p module: {}", e);
            }
        });
        Ok(arc)
    }

    pub async fn stop(&self) {
        info!("Stopping P2p Server...");
        let mut peers = self.peer_list.lock().await;
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
            self.try_to_connect_to_peer(addr, true);
        }
        Ok(())
    }

    // connect to seed nodes, start p2p server
    // and wait on all new connections
    async fn start(self: &Arc<Self>) -> Result<(), P2pError> {
        info!("Connecting to seed nodes...");
        // allocate this buffer only one time, because we are using the same thread
        if let Err(e) = self.connect_to_seed_nodes().await {
            error!("Error while connecting to seed nodes: {}", e);
        }

        // start a new task for chain sync
        tokio::spawn(Arc::clone(&self).chain_sync_loop());

        let listener = TcpListener::bind(self.get_bind_address()).await?;
        info!("P2p Server will listen on: {}", self.get_bind_address());
        loop {
            let (mut stream, addr) = listener.accept().await?;
            if !self.accept_new_connections().await { // if we have already reached the limit, we ignore this new connection
                debug!("Max peers reached, rejecting connection");
                if let Err(e) = stream.shutdown().await {
                    debug!("Error while closing & ignoring incoming connection {}: {}", addr, e);
                }
                continue;
            }

            let connection = Connection::new(stream, addr.clone());
            let zelf = Arc::clone(self);
            tokio::spawn(async move {
                if let Err(e) = zelf.handle_new_connection(connection, false, false).await {
                    debug!("Error on {}: {}", addr, e);
                }
            });
        }
    }

    // Verify handshake send by a new connection
    // based on data size, network ID, peers address validity
    // block height and block top hash of this peer (to know if we are on the same chain)
    async fn verify_handshake(&self, mut connection: Connection, handshake: Handshake, out: bool, priority: bool) -> Result<(Peer, Vec<SocketAddr>), P2pError> {
        if *handshake.get_network_id() != NETWORK_ID {
            return Err(P2pError::InvalidNetworkID);
        }

        if self.is_connected_to(&handshake.get_peer_id()).await? {
            connection.close().await?;
            return Err(P2pError::PeerIdAlreadyUsed(handshake.get_peer_id()));
        }

        if handshake.get_block_height() <= self.blockchain.get_height() { // peer is not greater than us
            let storage = self.blockchain.get_storage().read().await;
            let block = match storage.get_block_by_hash(handshake.get_block_top_hash()).await {
                Ok(block) => block,
                Err(_) => {
                    warn!("Block '{}' not found at height '{}'.", handshake.get_block_top_hash(), handshake.get_block_height());
                    return Err(P2pError::InvalidHandshake)
                }
            };
            if block.get_height() != handshake.get_block_height() {
                error!("Peer is not on the same chain!");
                return Err(P2pError::InvalidHandshake)
            }
        }

        connection.set_state(State::Success);
        let (peer, peers) = handshake.create_peer(connection, out, priority, Arc::clone(&self.peer_list));
        Ok((peer, peers))
    }

    async fn build_handshake(&self) -> Result<Handshake, P2pError> {
        let mut peers: Vec<SocketAddr> = Vec::new();
        let peer_list = self.peer_list.lock().await;
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

        let block_height = self.blockchain.get_height();
        let top_hash = self.blockchain.get_storage().read().await.get_top_block_hash().unwrap_or_else(|_| Hash::zero());
        Ok(Handshake::new(VERSION.to_owned(), self.get_tag().clone(), NETWORK_ID, self.get_peer_id(), self.bind_address.port(), get_current_time(), block_height, top_hash, peers))
    }

    // this function handle all new connections
    // A new connection have to send an Handshake
    // if the handshake is valid, we accept it & register it on server
    async fn handle_new_connection(self: Arc<Self>,mut connection: Connection, out: bool, priority: bool) -> Result<(), P2pError> {
        trace!("New connection: {}", connection);
        let mut buf = [0u8; 1024];
        let handshake: Handshake = match timeout(Duration::from_millis(800), connection.read_packet(&mut buf, 1024)).await?? {
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
        let peer_id = peer.get_id(); // keep in memory the peer_id outside connection (because of moved value)
        let peer = {
            let mut peer_list = self.peer_list.lock().await;
            peer_list.add_peer(peer_id, peer)
        };

        // try to extend our peer list
        for peer_addr in peers { // should we limit to X peers only ?
            if !self.accept_new_connections().await {
                break
            }

            if !self.is_connected_to_addr(&peer_addr).await? {
                debug!("Trying to extend peer list with {}", peer_addr);
                self.try_to_connect_to_peer(peer_addr, false);
            }
        }

        self.handle_connection(&mut buf, peer).await
    }

    // Connect to a specific peer address
    // Buffer is passed in parameter to prevent the re-allocation each time
    pub fn try_to_connect_to_peer(self: &Arc<Self>, addr: SocketAddr, priority: bool) {
        let zelf = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = zelf.connect_to_peer(addr, priority).await {
                debug!("Error occured on outgoing peer {}: {}", addr, e);
            }
        });
    }

    async fn connect_to_peer(self: Arc<Self>, addr: SocketAddr, priority: bool) -> Result<(), P2pError> {
        debug!("Trying to connect to {}", addr);
        if self.is_connected_to_addr(&addr).await? {
            return Err(P2pError::PeerAlreadyConnected(format!("{}", addr)));
        }
        let stream = timeout(Duration::from_millis(800), TcpStream::connect(&addr)).await??; // allow maximum 800ms of latency
        let connection = Connection::new(stream, addr);
        self.send_handshake(&connection).await?;
        self.handle_new_connection(connection, true, priority).await
    }

    async fn send_handshake(&self, connection: &Connection) -> Result<(), P2pError> {
        let handshake: Handshake = self.build_handshake().await?;
        let mut writer = Writer::new();
        Packet::Handshake(Cow::Owned(handshake)).write(&mut writer);
        connection.send_bytes(&writer.bytes()).await
    }

    async fn build_ping_packet(&self, peer: Option<&Arc<Peer>>) -> Ping<'_> {
        let block_top_hash = self.blockchain.get_top_block_hash().await;
        let block_height = self.blockchain.get_height();
        let mut new_peers = Vec::new();
        if let Some(peer) = peer {
            let current_time = get_current_time();
            if current_time > peer.get_last_peer_list_update() + P2P_PING_PEER_LIST_DELAY {
                peer.set_last_peer_list_update(current_time);
                // all the peers of current peer
                let mut peer_peers = peer.get_peers().lock().await;
                // our peerlist
                let peer_list = self.peer_list.lock().await;
                for p in peer_list.get_peers().values() {
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
            }
        }
        Ping::new(Cow::Owned(block_top_hash.unwrap()), block_height, new_peers)
    }

    // build a ping packet with a specific peerlist for the peer
    async fn build_ping_packet_for_peer(&self, peer: &Arc<Peer>) -> Ping<'_> {
        self.build_ping_packet(Some(peer)).await
    }
    // send a ping packet to specific peer every 10s
    async fn loop_ping(self: Arc<Self>, peer: Arc<Peer>) {
        let mut ping_interval = interval(Duration::from_secs(P2P_PING_DELAY));
        loop {
            ping_interval.tick().await;
            if peer.get_connection().is_closed() {
                break;
            }

            let packet = Packet::Ping(Cow::Owned(self.build_ping_packet_for_peer(&peer).await));
            trace!("Sending ping packet to peer: {}", peer.get_connection().get_address());
            if let Err(e) = peer.send_packet(packet).await {
                debug!("Error occured on ping: {}", e);
                break;
            }
        }
    }

    async fn select_random_best_peer(&self) -> Option<Arc<Peer>> {
        let peer_list = self.peer_list.lock().await;
        let our_height = self.blockchain.get_height();
        let peers: Vec<&Arc<Peer>> = peer_list.get_peers().values().filter(|p| p.get_block_height() > our_height).collect();
        let count = peers.len();
        trace!("peers available for random selection: {}", count);
        if count == 0 {
            return None
        }
        let selected = rand::thread_rng().gen_range(0..count);
        // clone the Arc to prevent the lock until the end of the sync request
        Some(Arc::clone(peers.get(selected)?))
    }

    async fn chain_sync_loop(self: Arc<Self>) {
        let mut interval = interval(Duration::from_secs(CHAIN_SYNC_DELAY));
        loop {
            interval.tick().await;
            if let Some(peer) = self.select_random_best_peer().await {
                trace!("Peer selected for chain sync: {}", peer.get_connection().get_address());
                if let Err(e) = self.request_sync_chain_for(&peer).await {
                    debug!("Error occured on chain sync: {}", e);
                }
            }
        }
    }

    async fn handle_connection(self: Arc<Self>, buf: &mut [u8], peer: Arc<Peer>) -> Result<(), P2pError> {
        tokio::spawn(Arc::clone(&self).loop_ping(Arc::clone(&peer)));
        let mut rx = peer.get_connection().get_rx().lock().await;
        loop {
            tokio::select! {
                res = self.listen_connection(buf, &peer) => {
                    if let Err(e) = res { // close on any error
                        debug!("Error while reading packet from peer {}: {}", peer.get_connection().get_address(), e);
                        peer.close().await?;
                        break;
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        ConnectionMessage::Packet(bytes) => {
                            trace!("Data to send to {} received!", peer.get_connection().get_address());
                            debug!("Sending packet with ID {}, size sent: {}, real size: {}", bytes[5], u32::from_be_bytes(bytes[0..4].try_into()?), bytes.len() - 4);
                            peer.get_connection().send_bytes(&bytes).await?;
                            trace!("data sucessfully sent!");
                        }
                        ConnectionMessage::Exit => {
                            trace!("Exit message received for peer {}", peer);
                            break;
                        }
                    };
                }
            }

            if peer.get_fail_count() >= 20 {
                error!("High fail count detected for {}!", peer);
                if let Err(e) = peer.close().await {
                    error!("Error while trying to close connection {} due to high fail count: {}", peer.get_connection().get_address(), e);
                }
                break;
            }
        }
        rx.close(); // clean shutdown
        Ok(())
    }

    async fn handle_incoming_packet(self: &Arc<Self>, peer: &Arc<Peer>, packet: Packet<'_>) -> Result<(), P2pError> {
        match packet {
            Packet::Handshake(_) => {
                return Err(P2pError::InvalidPacket)
            },
            Packet::TransactionPropagation(packet_wrapper) => {
                let (hash, ping) = packet_wrapper.consume();
                let hash = hash.into_owned();
                ping.into_owned().update_peer(peer).await;
                let mempool = self.blockchain.get_mempool().lock().await;
                if !mempool.contains_tx(&hash) {
                    let zelf = Arc::clone(self);
                    let peer = Arc::clone(peer);
                    tokio::spawn(async move {
                        let ping = zelf.build_ping_packet(None).await;
                        let response = match peer.request_blocking_object(ObjectRequest::Transaction(hash), &ping).await {
                            Ok(response) => response,
                            Err(err) => {
                                error!("Error while requesting transaction: {}", err);
                                peer.increment_fail_count();
                                return;
                            }
                        };
                        if let OwnedObjectResponse::Transaction(tx) = response {
                            if let Err(e) = zelf.blockchain.add_tx_to_mempool(tx, true).await {
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
                trace!("Received a block propagation packet from {}", peer.get_connection().get_address());
                let (block, ping) = packet_wrapper.consume();
                ping.into_owned().update_peer(peer).await;
                let block = block.into_owned();
                let block_height = block.get_height();
                debug!("Received block at height {} from {}", block_height, peer.get_connection().get_address());
                { // add immediately the block to chain as we are synced with
                    if let Err(e) = self.blockchain.add_new_block(block, true).await {
                        error!("Error while adding new block: {}", e);
                        peer.increment_fail_count();
                    }
                }
            },
            Packet::ChainRequest(packet_wrapper) => {
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
                    warn!("Peer {} sent us a malformed chain request ({} blocks)!", peer.get_connection().get_address(), request.size());
                    return Err(P2pError::InvalidPacket)
                }

                let zelf = Arc::clone(&self);
                let peer = Arc::clone(peer);
                let blocks = request.get_blocks();
                tokio::spawn(async move {
                    if let Err(e) = zelf.handle_chain_request(&peer, blocks).await {
                        error!("Error while handling chain request from {}: {}", peer.get_connection().get_address(), e);
                        peer.increment_fail_count();
                    }
                });
            },
            Packet::ChainResponse(response) => {
                trace!("Received a chain response from {}", peer.get_connection().get_address());
                if !peer.chain_sync_requested() {
                    warn!("Peer {} sent us a chain response but we haven't requested any.", peer.get_connection().get_address());
                    return Err(P2pError::InvalidPacket)
                }
                peer.set_chain_sync_requested(false);

                if response.size() > CHAIN_SYNC_REQUEST_MAX_BLOCKS { // peer is trying to spam us
                    warn!("Peer {} is maybe trying to spam us", peer.get_connection().get_address());
                    return Err(P2pError::InvalidPacket)
                }

                if let Some(common_point) = response.get_common_point() {
                    debug!("Peer found a common point for sync, received {} blocks", response.size());
                    let pop_count = {
                        let storage = self.blockchain.get_storage().read().await;
                        let common_block = match storage.get_block_by_hash(common_point.get_hash()).await {
                            Ok(block) => block,
                            Err(e) => {
                                warn!("Peer {} sent us an invalid common point: {}", peer.get_connection().get_address(), e);
                                return Err(P2pError::InvalidPacket)
                            }
                        };
                        if common_block.get_height() != common_point.get_height() {
                            error!("Peer {} sent us a valid block hash, but at invalid height (expected: {}, got: {})!", peer.get_connection().get_address(), common_block.get_height(), common_point.get_height());
                            return Err(P2pError::InvalidPacket)
                        }
                        self.blockchain.get_height() - common_block.get_height()
                    };

                    if pop_count > MAX_BLOCK_REWIND {
                        warn!("We may have deviated too much! Pop count: {}", pop_count);
                    }

                    let peer = Arc::clone(peer);
                    let zelf = Arc::clone(self);
                    let blocks: Vec<Hash> = response.get_blocks().into_iter().map(|b| b.into_owned()).collect();

                    // start a new task to wait on all requested blocks
                    tokio::spawn(async move {
                        if let Err(e) = zelf.handle_chain_response(&peer, blocks, pop_count).await {
                            error!("Error while handling chain response from {}: {}", peer.get_connection().get_address(), e);
                            peer.increment_fail_count();
                        }
                    });
                } else {
                    warn!("No common block was found with peer {}", peer.get_connection().get_address());
                    if response.size() > 0 {
                        debug!("Peer have no common block but send us {} blocks!", response.size());
                        return Err(P2pError::InvalidPacket)
                    }
                }
            },
            Packet::Ping(ping) => {
                trace!("Received a ping packet from {}", peer.get_connection().get_address());
                let current_time = get_current_time();
                // verify the respect of the coutdown to prevent massive packet incoming
                if current_time - peer.get_last_ping() < P2P_PING_DELAY {
                    return Err(P2pError::PeerInvalidPingCoutdown)
                }
                peer.set_last_ping(current_time);

                // we verify the respect of the countdown of peer list updates to prevent any spam
                if ping.get_peers().len() > 0 {
                    if current_time - peer.get_last_peer_list() < P2P_PING_PEER_LIST_DELAY {
                        return Err(P2pError::PeerInvalidPeerListCountdown)
                    }
                    peer.set_last_peer_list(current_time);
                }

                for peer in ping.get_peers() {
                    if !self.is_connected_to_addr(&peer).await? {
                        let peer = peer.clone();
                        self.try_to_connect_to_peer(peer, false);
                    }
                }
                ping.into_owned().update_peer(peer).await;
            },
            Packet::ObjectRequest(packet_wrapper) => {
                trace!("Received a object request from {}", peer.get_connection().get_address());
                let (request, ping) = packet_wrapper.consume();
                ping.into_owned().update_peer(peer).await;
                let request = request.into_owned();
                match &request {
                    ObjectRequest::Block(hash) => {
                        let storage = self.blockchain.get_storage().read().await;
                        match storage.get_complete_block(hash).await {
                            Ok(block) => {
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::Block(Cow::Owned(block)))).await?;
                            },
                            Err(e) => {
                                debug!("Peer {} asked block '{}' but got on error while retrieving it: {}", peer.get_connection().get_address(), hash, e);
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::NotFound(request))).await?;
                            }
                        }
                    },
                    ObjectRequest::Transaction(hash) => {
                        let mempool = self.blockchain.get_mempool().lock().await;
                        match mempool.view_tx(hash) {
                            Ok(tx) => {
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::Transaction(Cow::Borrowed(tx)))).await?;
                            },
                            Err(e) => {
                                debug!("Peer {} asked tx '{}' but got on error while retrieving it: {}", peer.get_connection().get_address(), hash, e);
                                peer.send_packet(Packet::ObjectResponse(ObjectResponse::NotFound(request))).await?;
                            }
                        }
                    }
                }
            },
            Packet::ObjectResponse(response) => {
                trace!("Received a object response from {}", peer.get_connection().get_address());
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
            error!("Error occured while handling incoming packet from {}: {}", peer.get_connection().get_address(), e);
            peer.increment_fail_count();
        }
        Ok(())
    }

    async fn handle_chain_request(self: Arc<Self>, peer: &Arc<Peer>, blocks: Vec<BlockId>) -> Result<(), BlockchainError> {
        let storage = self.blockchain.get_storage().read().await;
        let mut response_blocks = Vec::new();
        let mut common_point = None;
        for block_id in blocks { // search a common point
            if let Ok(block) = storage.get_block_by_hash(block_id.get_hash()).await {
                let (hash, height) = block_id.consume();
                debug!("Block {} found for height: {}", hash, height);
                if block.get_height() == height { // common point
                    debug!("common point with peer found at block {} hash: {}", height, hash);
                    common_point = Some(CommonPoint::new(Cow::Owned(hash), height));
                    let top_height = self.blockchain.get_height();
                    let mut height = block.get_height() + 1;
                    while response_blocks.len() < CHAIN_SYNC_REQUEST_MAX_BLOCKS && height <= top_height {
                        let metadata = storage.get_block_metadata(height).await?;
                        debug!("for request, adding hash {} for height {}", metadata.get_hash(), height);
                        response_blocks.push(Cow::Owned(metadata.get_hash().clone()));
                        height += 1;
                    }
                    break;
                }
            }
        }
        peer.send_packet(Packet::ChainResponse(ChainResponse::new(common_point, response_blocks))).await?;
        Ok(())
    }

    async fn handle_chain_response(self: Arc<Self>, peer: &Arc<Peer>, blocks_request: Vec<Hash>, pop_count: u64) -> Result<(), BlockchainError> {
        let ping = self.build_ping_packet_for_peer(peer).await;
        let mut storage = self.blockchain.get_storage().write().await; // lock until we get all blocks
        let mut blocks: Vec<CompleteBlock> = Vec::with_capacity(blocks_request.len());
        for hash in blocks_request { // Request all complete blocks now
            let object_request = ObjectRequest::Block(hash);
            let response = peer.request_blocking_object(object_request, &ping).await?;
            if let OwnedObjectResponse::Block(block) = response {
                let hash = block.hash();
                debug!("Received block {} at height {} from peer {}", hash, block.get_height(), peer.get_connection().get_address());
                blocks.push(block);
            } else {
                error!("Peer {} sent us an invalid block response", peer.get_connection().get_address());
                return Err(P2pError::ExpectedBlock.into())
            }
        }

        if pop_count > 0 && (pop_count <= MAX_BLOCK_REWIND && peer.is_priority()) {
            warn!("Rewinding chain because of peer {} (priority: {}, pop count: {})", peer.get_connection().get_address(), peer.is_priority(), pop_count);
            if let Err(e) = self.blockchain.rewind_chain_for_storage(&mut storage, pop_count as usize).await {
                error!("Error on rewind chain: pop count: {}, error: {}", pop_count, e);
            }
        }

        for block in blocks {
            self.blockchain.add_new_block_for_storage(&mut storage, block, false).await?;
        }
        Ok(())
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
        let peer_list = self.peer_list.lock().await;
        peer_list.size()
    }

    pub async fn get_best_height(&self) -> u64 {
        let our_height = self.blockchain.get_height();
        let peer_list = self.peer_list.lock().await;
        let best_height = peer_list.get_best_height();
        if best_height > our_height {
            best_height
        } else {
            our_height
        }
    }

    pub async fn is_connected_to(&self, peer_id: &u64) -> Result<bool, P2pError> {
        let peer_list = self.peer_list.lock().await;
        Ok(self.peer_id == *peer_id || peer_list.has_peer(peer_id))
    }

    pub async fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> Result<bool, P2pError> {
        if *peer_addr == *self.get_bind_address() { // don't try to connect to ourself
            debug!("Trying to connect to ourself, ignoring.");
            return Ok(true)
        }
        let peer_list = self.peer_list.lock().await;
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

    pub async fn broadcast_tx_hash(&self, tx: &Hash) {
        let ping = self.build_ping_packet(None).await;
        self.broadcast_packet(Packet::TransactionPropagation(PacketWrapper::new(Cow::Borrowed(tx), Cow::Owned(ping)))).await;
    }

    // broadcast block to all peers that can accept directly this new block
    pub async fn broadcast_block(&self, block: &CompleteBlock, hash: &Hash) {
        let block_height = block.get_height();
        trace!("Broadcast block: {} at height {}", hash, block_height);
        // we build the ping packet ourself this time (we have enough data for it)
        // because this function can be call from Blockchain, which would lead to deadlock
        let ping = Ping::new(Cow::Borrowed(hash), block_height, Vec::new());
        let packet = Packet::BlockPropagation(PacketWrapper::new(Cow::Borrowed(block), Cow::Owned(ping)));
        let bytes = Bytes::from(packet.to_bytes());
        // TODO should we move it in another async task ?
        let peer_list = self.peer_list.lock().await;
        for (_, peer) in peer_list.get_peers() {
            // if the peer can directly accept this new block, send it
            if peer.get_block_height() == block_height - 1 {
                trace!("Broadcast block to {}", peer);
                peer_list.send_bytes_to_peer(peer, bytes.clone()).await;
                peer.set_block_height(block_height); // we suppose peer will accept the block like us
            }
        }
    }

    pub async fn broadcast_packet(&self, packet: Packet<'_>) {
        let peer_list = self.peer_list.lock().await;
        peer_list.broadcast(Bytes::from(packet.to_bytes())).await;
    }

    pub async fn request_sync_chain_for(&self, peer: &Arc<Peer>) -> Result<(), BlockchainError> {
        let mut request = ChainRequest::new();
        {
            let storage = self.blockchain.get_storage().read().await;
            let height = self.blockchain.get_height();
            let mut i = 0;
            while i < height && request.size() + 1 < CHAIN_SYNC_REQUEST_MAX_BLOCKS {
                let metadata = storage.get_block_metadata(height - i).await?;
                request.add_block_id(metadata.get_hash().clone(), height - i);
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
            let genesis_block = storage.get_block_metadata(1).await?;
            request.add_block_id(genesis_block.get_hash().clone(), 1);
            trace!("Sending a chain request with {} blocks", request.size());
            peer.set_chain_sync_requested(true);
        }
        let ping = self.build_ping_packet(None).await;
        peer.send_packet(Packet::ChainRequest(PacketWrapper::new(Cow::Owned(request), Cow::Owned(ping)))).await?;
        Ok(())
    }
}