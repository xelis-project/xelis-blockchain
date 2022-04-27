use crate::config::{VERSION, NETWORK_ID, SEED_NODES, MAX_BLOCK_SIZE, CHAIN_SYNC_TIMEOUT_SECS, CHAIN_SYNC_MAX_BLOCK, CHAIN_SYNC_DELAY, P2P_PING_DELAY};
use crate::core::transaction::Transaction;
use crate::core::blockchain::Blockchain;
use crate::core::error::BlockchainError;
use crate::core::serializer::Serializer;
use crate::core::block::CompleteBlock;
use crate::globals::get_current_time;
use crate::crypto::hash::Hashable;
use crate::core::writer::Writer;
use super::peer_list::{SharedPeerList, PeerList};
use super::packet::request_chain::RequestChain;
use super::connection::{State, Connection};
use super::packet::handshake::Handshake;
use super::chain_sync::ChainSync;
use super::packet::ping::Ping;
use super::error::P2pError;
use super::packet::Packet;
use super::peer::Peer;
use tokio::net::{TcpListener, TcpStream};
use log::{info, warn, error, debug};
use tokio::io::AsyncWriteExt;
use tokio::time::interval;
use tokio::time::timeout;
use std::borrow::Cow;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::Mutex;
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
    sync: Mutex<ChainSync>
}

impl P2pServer {
    pub fn new(tag: Option<String>, max_peers: usize, bind_address: String, blockchain: Arc<Blockchain>) -> Arc<Self> {
        if let Some(tag) = &tag {
            assert!(tag.len() > 0 && tag.len() <= 16);
        }

        // set channel to communicate with listener thread
        let mut rng = rand::thread_rng();
        let peer_id: u64 = rng.gen(); // generate a random peer id for network
        let addr: SocketAddr = bind_address.parse().unwrap();
        let server = Self {
            peer_id,
            tag,
            max_peers,
            bind_address: addr,
            peer_list: PeerList::new(max_peers),
            blockchain,
            sync: Mutex::new(ChainSync::new())
        };

        let arc = Arc::new(server);
        let instance = arc.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::start(&instance).await {
                error!("Unexpected error on P2p module: {}", e);
            }
        });

        arc
    }

    pub async fn stop(&self) -> Result<(), P2pError> {
        info!("Stopping P2p Server...");
        let mut peers = self.peer_list.lock().await;
        peers.close_all().await;
        Ok(())
    }

    // Connect to all seed nodes from constant
    // buffer parameter is to prevent the re-allocation
    async fn connect_to_seed_nodes(self: &Arc<Self>) -> Result<(), P2pError> {
        for peer in SEED_NODES {
            let addr: SocketAddr = match peer.parse() {
                Ok(addr) => addr,
                Err(e) => return Err(P2pError::InvalidPeerAddress(format!("seed node {}: {}", peer, e)))
            };
            Arc::clone(self).try_to_connect_to_peer(addr, true);
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
            let storage = self.blockchain.get_storage().lock().await;
            let block = match storage.get_block_by_hash(handshake.get_block_top_hash()) {
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
        let (peer, peers) = handshake.create_peer(connection, out, priority, self.peer_list.clone());
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
        let top_hash = self.blockchain.get_storage().lock().await.get_top_block_hash().clone();
        Ok(Handshake::new(VERSION.to_owned(), self.get_tag().clone(), NETWORK_ID, self.get_peer_id(), self.bind_address.port(), get_current_time(), block_height, top_hash, peers))
    }

    // this function handle all new connections
    // A new connection have to send an Handshake
    // if the handshake is valid, we accept it & register it on server
    async fn handle_new_connection(self: Arc<Self>,mut connection: Connection, out: bool, priority: bool) -> Result<(), P2pError> {
        debug!("New connection: {}", connection);
        let mut buf = [0u8; 1024];
        let handshake: Handshake = match timeout(Duration::from_millis(300), connection.read_packet(&mut buf, 1024)).await?? {
            Packet::Handshake(h) => h.into_owned(), // only allow handshake packet
            _ => return Err(P2pError::ExpectedHandshake)
        };
        debug!("received handshake packet!");
        connection.set_state(State::Handshake);
        let (peer, peers) = self.verify_handshake(connection, handshake, out, priority).await?;
        // if it's a outgoing connection, don't send the handshake back
        // because we have already sent it
        if !out {
            self.send_handshake(peer.get_connection()).await?;
        }

        // if we reach here, handshake is all good, we can start listening this new peer
        let peer_id = peer.get_id(); // keep in memory the peer_id outside connection (because of moved value)
        let peer = self.peer_list.lock().await.add_peer(peer_id, peer);

        // try to extend our peer list
        for peer_addr in peers { // should we limit to X peers only ?
            if !self.accept_new_connections().await {
                break
            }

            if !self.is_connected_to_addr(&peer_addr).await? {
                debug!("Trying to extend peer list with {}", peer_addr);
                Arc::clone(&self).try_to_connect_to_peer(peer_addr, false);
            }
        }

        self.handle_connection(&mut buf, peer).await
    }

    // Connect to a specific peer address
    // Buffer is passed in parameter to prevent the re-allocation each time
    fn try_to_connect_to_peer(self: Arc<Self>, addr: SocketAddr, priority: bool) {
        tokio::spawn(async move {
            if let Err(e) = self.connect_to_peer(addr, priority).await {
                debug!("Error occured on outgoing peer: {}", e);
            }
        });
    }

    pub async fn connect_to_peer(self: Arc<Self>, addr: SocketAddr, priority: bool) -> Result<(), P2pError> {
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

    // send a ping packet to specific peer every 10s
    fn loop_ping(self: Arc<Self>, peer: Arc<Peer>) {
        let mut ping_interval = interval(Duration::from_secs(P2P_PING_DELAY));
        tokio::spawn(async move {
            loop {
                ping_interval.tick().await;
                let block_top_hash = self.blockchain.get_top_block_hash().await;
                let block_height = self.blockchain.get_height();
                let ping = Ping::new(block_top_hash, block_height);
                let packet = Packet::Ping(Cow::Owned(ping));
                debug!("Sending ping packet to peer: {}", peer.get_connection().get_address());
                if let Err(e) = peer.send_packet(packet).await {
                    debug!("Error occured on ping: {}", e);
                    break
                }
            }
        });
    }

    async fn handle_connection(self: Arc<Self>, buf: &mut [u8], peer: Arc<Peer>) -> Result<(), P2pError> {
        let mut rx = peer.get_connection().get_rx().lock().await;
        Arc::clone(&self).loop_ping(peer.clone());
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
                    debug!("Data to send to {} received!", peer.get_connection().get_address());
                    peer.get_connection().send_bytes(&data).await?;
                    debug!("data sucessfully sent!");
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

    async fn handle_incoming_packet(&self, peer: &Arc<Peer>, packet: Packet<'_>) -> Result<(), P2pError> {
        match packet {
            Packet::Handshake(_) => {
                return Err(P2pError::InvalidPacket)
            },
            Packet::Transaction(tx) => {
                let tx = tx.into_owned();
                let packet = Bytes::from(Packet::Transaction(Cow::Borrowed(&tx)).to_bytes());
                if let Err(e) = self.blockchain.add_tx_to_mempool(tx, false).await {
                    match e {
                        BlockchainError::TxAlreadyInMempool(_) => {},
                        e => {
                            error!("Error while adding TX to mempool: {}", e);
                            peer.increment_fail_count();
                        }
                    };
                } else {
                    let peer_list = self.peer_list.lock().await;
                    peer_list.broadcast_except(peer.get_id(), packet).await; // broadcast tx to our peers
                }
            },
            Packet::Block(block) => {
                let block = block.into_owned();
                debug!("Received block at height {} from {}", block.get_height(), peer.get_connection().get_address());
                let block_height = block.get_height();
                if peer.get_block_height() < block_height {
                    peer.set_block_height(block_height);
                }

                { // add immediately the block to chain as we are synced with
                    let packet = Bytes::from(Packet::Block(Cow::Borrowed(&block)).to_bytes());
                    if let Err(e) = self.blockchain.add_new_block(block, false).await {
                        error!("Error while adding new block: {}", e);
                        peer.increment_fail_count();
                    } else { // broadcast new block to peers
                        debug!("broadcast received block to peers!");
                        let peer_list = self.peer_list.lock().await;
                        peer_list.broadcast_except(peer.get_id(), packet).await;
                    }
                }
            },
            Packet::RequestChain(request) => {
                let last_request = peer.get_last_chain_sync();
                let time = get_current_time();
                peer.set_last_chain_sync(time);
                if  last_request + CHAIN_SYNC_DELAY > time {
                    return Err(P2pError::RequestSyncChainTooFast)
                }

                let our_height = self.blockchain.get_height();
                let start = 0; // TODO request.get_start_height();
                let end = 0; // request.get_end_height();
                if start > our_height || end > our_height || start > end || end - start > CHAIN_SYNC_MAX_BLOCK { // only 20 blocks max per request
                    return Err(P2pError::InvalidHeightRange)
                }

                debug!("Peer {} request block from {} to {}", peer.get_connection().get_address(), start, end);
                let storage = self.blockchain.get_storage().lock().await;
                for i in start..=end {
                    match storage.get_block_at_height(i) {
                        Ok(block) => {
                            peer.send_packet(Packet::Block(Cow::Borrowed(&block))).await?;
                        },
                        Err(_) => { // shouldn't happens as we verify range before
                            debug!("Peer {} requested an invalid block height.", peer);
                            peer.increment_fail_count();
                        }
                    };
                }
            }
            Packet::Ping(ping) => {
                ping.into_owned().update_peer(peer);
            },
        };
        Ok(())
    }

    // Listen to incoming packets from a connection
    async fn listen_connection(&self, buf: &mut [u8], peer: &Arc<Peer>) -> Result<(), P2pError> {
        let packet = peer.get_connection().read_packet(buf, MAX_BLOCK_SIZE as u32).await?;
        if let Err(e) = self.handle_incoming_packet(peer, packet).await {
            debug!("Error occured while handling incoming packet from {}: {}", peer.get_connection().get_address(), e);
            peer.increment_fail_count();
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

    pub fn get_peer_list(&self) -> &SharedPeerList {
        &self.peer_list
    }

    pub async fn broadcast_tx(&self, tx: &Transaction) {
        self.broadcast_packet(Packet::Transaction(Cow::Borrowed(tx))).await;
    }

    pub async fn broadcast_block(&self, block: &CompleteBlock) {
        self.broadcast_packet(Packet::Block(Cow::Borrowed(block))).await;
    }

    pub async fn broadcast_packet(&self, packet: Packet<'_>) {
        let peer_list = self.peer_list.lock().await;
        peer_list.broadcast(Bytes::from(packet.to_bytes())).await;
    }

    pub async fn request_sync_chain_for(&self, peer: &Arc<Peer>) -> Result<(), BlockchainError> {
        let storage = self.blockchain.get_storage().lock().await;
        let height = self.blockchain.get_height();
        let mut i = 0;
        let mut request = RequestChain::new();
        while i < height {
            let block = storage.get_block_at_height(height - i)?;
            request.add_block_id(block.hash(), height); // TODO get hash from DB
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
        // TODO Add Genesis block
        peer.send_packet(Packet::RequestChain(Cow::Owned(request))).await?;
        Ok(())
    }
}