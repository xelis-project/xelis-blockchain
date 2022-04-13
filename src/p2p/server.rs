use crate::config::{VERSION, NETWORK_ID, SEED_NODES, MAX_BLOCK_SIZE, CHAIN_SYNC_TIMEOUT_SECS, CHAIN_SYNC_MAX_BLOCK, CHAIN_SYNC_DELAY, P2P_PING_DELAY};
use crate::core::difficulty::check_difficulty;
use crate::crypto::hash::{Hash, Hashable};
use crate::core::transaction::Transaction;
use crate::core::difficulty::hash_to_big;
use crate::core::blockchain::Blockchain;
use crate::core::error::BlockchainError;
use crate::core::serializer::Serializer;
use crate::core::block::CompleteBlock;
use crate::globals::get_current_time;
use crate::core::writer::Writer;
use super::peer_list::{SharedPeerList, PeerList};
use super::packet::request_chain::RequestChain;
use super::connection::{Rx, Tx, State, Connection};
use super::packet::{PacketIn, PacketOut};
use super::packet::handshake::Handshake;
use super::packet::ping::Ping;
use super::error::P2pError;
use super::peer::Peer;
use tokio::net::{TcpListener, TcpStream};
use std::collections::{HashMap, HashSet};
use async_recursion::async_recursion;
use log::{info, warn, error, debug};
use tokio::sync::{mpsc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use std::net::SocketAddr;
use num_bigint::BigUint;
use std::time::Duration;
use std::io::ErrorKind;
use num_traits::Zero;
use std::sync::Arc;
use rand::Rng;

struct ChainSync { // TODO, receive Block Header only
    current_top_hash: Hash, // top hash of our current blockchain
    blocks: HashMap<Hash, CompleteBlock>,
    asked_peers: HashMap<u64, u64>, // Peer id, Blocks asked
    syncing: bool,
    start_at: u64 // timestamp in seconds
}

impl ChainSync {
    pub fn new() -> Self {
        Self {
            current_top_hash: Hash::zero(),
            blocks: HashMap::new(),
            asked_peers: HashMap::new(),
            syncing: false,
            start_at: 0
        }
    }

    pub fn contains_peer(&self, peer: &u64) -> bool {
        self.asked_peers.contains_key(peer)
    }

    pub fn add_peer(&mut self, peer: u64, asked: u64) {
        self.asked_peers.insert(peer, asked);
    }

    pub fn remove_peer(&mut self, peer: &u64) -> bool {
        self.asked_peers.remove(peer).is_some()
    }

    pub fn is_ready(&self) -> bool {
        (self.asked_peers.len() == 0 && self.blocks.len() > 0) || self.has_timed_out()
    }

    pub fn is_syncing(&self) -> bool {
        self.syncing
    }

    // prevent malicious peers that don't send response to request chain
    pub fn has_timed_out(&self) -> bool {
        self.start_at + CHAIN_SYNC_TIMEOUT_SECS <= get_current_time()
    }

    // allow only one request every 1s
    pub fn can_sync(&self) -> bool {
        self.start_at + CHAIN_SYNC_DELAY < get_current_time()
    }

    pub fn start_sync(&mut self, hash: Hash) {
        self.current_top_hash = hash;
        self.syncing = true;
        self.start_at = get_current_time();
    }

    pub fn to_chain(&mut self, blockchain: &Arc<Blockchain>) -> Result<(), BlockchainError> {
        self.asked_peers.clear();
        let mut branch: HashSet<Hash> = HashSet::new();
        {
            let max_hash = hash_to_big(&Hash::max());
            let mut total_diff: BigUint = BigUint::zero();
            let top_blocks = self.get_top_blocks()?;
            debug!("Total branches: {}", top_blocks.len());
            for block_hash in top_blocks {
                let mut current_total_diff = BigUint::zero();
                let mut current_block = self.get_block(&block_hash)?;
                let mut hash = &block_hash;
                let mut branch_hashes = HashSet::new(); // all hashes for this top block
                loop { // add all blocks until our local top block hash
                    branch_hashes.insert(hash.clone());
                    current_total_diff += max_hash.clone() - hash_to_big(&hash);
                    hash = current_block.get_previous_hash(); // get previous hash of previous block
                    if *hash == self.current_top_hash {
                        break;
                    }
                    current_block = self.get_block(hash)?; // get previous block
                }

                if current_total_diff >= total_diff { // get heaviest chain
                    total_diff = current_total_diff;
                    branch = branch_hashes;
                }
            }
        }

        debug!("Branches: {}, blocks: {}", branch.len(), self.blocks.len());
        let mut blocks: Vec<CompleteBlock> = Vec::with_capacity(branch.len());
        for (k, v) in self.blocks.drain() {
            if branch.contains(&k) {
                branch.remove(&k);
                blocks.push(v);
            }
        }

        blocks.sort_by(|a,b| a.get_height().cmp(&b.get_height()));

        for block in blocks {
            debug!("Trying to add block from chain sync to blockchain: {}", block.get_height());
            blockchain.add_new_block(block, false)?;
        }
        self.syncing = false;
        Ok(())
    }

    pub fn get_top_blocks(&self) -> Result<Vec<Hash>, BlockchainError> {
        let blocks: Vec<&CompleteBlock> = self.blocks.values().collect();
        let mut top_blocks = Vec::new();
        for block in blocks { // check all next blocks for each block
            let block_hash = block.hash();
            let next_blocks = self.get_next_blocks(&block_hash)?;
            if next_blocks.len() > 1 { // we have more than one branch at this block
                for block in next_blocks { // search top blocks from all these branches
                    let hash = block.hash();
                    let top_block_hash = self.get_top_block_hash(&hash)?;
                    top_blocks.push(top_block_hash);
                }
            } else if next_blocks.len() == 0 {
                top_blocks.push(block_hash);
            }
        }
        Ok(top_blocks)
    }

    pub fn get_top_block_hash(&self, hash: &Hash) -> Result<Hash, BlockchainError> {
        for (h, block) in &self.blocks {
            if *block.get_previous_hash() == *hash {
                return self.get_top_block_hash(h);
            }
        }
        Ok(hash.clone())
    }

    pub fn get_next_blocks(&self, hash: &Hash) -> Result<Vec<&CompleteBlock>, BlockchainError> {
        let mut blocks = Vec::new();
        for (_, block) in &self.blocks {
            if *block.get_previous_hash() == *hash {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    pub fn block_exist(&self, hash: &Hash) -> bool {
        *hash == self.current_top_hash || self.get_block(hash).is_ok()
    }

    pub fn get_block(&self, hash: &Hash) -> Result<&CompleteBlock, BlockchainError> {
        match self.blocks.get(hash) {
            Some(v) => Ok(v),
            None => return Err(BlockchainError::BlockNotFound(hash.clone()))
        }
    }

    pub fn insert_block(&mut self, block: CompleteBlock, peer: &u64) -> Result<(), BlockchainError> {
        let block_hash = block.hash();
        if !self.block_exist(&block_hash) { // no need to re verify/insert block
            if !self.block_exist(block.get_previous_hash()) {
                return Err(BlockchainError::BlockNotFound(block.get_previous_hash().clone()))
            }

            if !check_difficulty(&block_hash, block.get_difficulty())? {
                return Err(BlockchainError::InvalidDifficulty)
            }
        }

        if let Some(left) = self.asked_peers.get_mut(peer) {
            if *left <= 1 {
                self.asked_peers.remove(peer);
            } else {
                *left -= 1;
            }
        }

        self.blocks.insert(block_hash, block);
        Ok(())
    }
}

// P2pServer only use 2 threads: one for incoming new connections
// and one for listening/sending data to all connections already accepted
// useful for low end hardware
pub struct P2pServer {
    peer_id: u64, // unique peer id
    tag: Option<String>, // node tag sent on handshake
    max_peers: usize, // max peers accepted by this server
    bind_address: SocketAddr, // ip:port address to receive connections
    peer_list: SharedPeerList, // all peers accepted
    blockchain: Arc<Blockchain>,
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
            Arc::clone(self).try_to_connect_to_peer(addr, true).await;
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

            let (connection, rx) = self.create_connection(addr.clone(), stream);
            let zelf = Arc::clone(self);
            tokio::spawn(async move {
                if let Err(e) = zelf.handle_new_connection(connection, rx, false, false).await {
                    debug!("Error on {}: {}", addr, e);
                }
            });
        }
    }

    fn create_connection(&self, addr: SocketAddr, stream: TcpStream) -> (Connection, Rx) {
        let (tx, rx) = mpsc::unbounded_channel();
        let connection = Connection::new(stream, addr, tx);
        (connection, rx)
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
            let storage = self.blockchain.get_storage().lock()?;
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
        let top_hash = self.blockchain.get_storage().lock()?.get_top_block_hash().clone();
        Ok(Handshake::new(VERSION.to_owned(), self.get_tag().clone(), NETWORK_ID, self.get_peer_id(), self.bind_address.port(), get_current_time(), block_height, top_hash, peers))
    }

    // this function handle all new connections
    // A new connection have to send an Handshake
    // if the handshake is valid, we accept it & register it on server
    async fn handle_new_connection(self: Arc<Self>,mut connection: Connection, rx: Rx, out: bool, priority: bool) -> Result<(), P2pError> {
        debug!("New connection: {}", connection);
        let mut buf = [0u8; 1024];
        let handshake: Handshake = match timeout(Duration::from_millis(300), connection.read_packet(&mut buf, 1024)).await?? {
            PacketIn::Handshake(h) => h, // only allow handshake packet
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
                Arc::clone(&self).try_to_connect_to_peer(peer_addr, false).await;
            }
        }

        self.handle_connection(&mut buf, peer, rx).await
    }

    // Connect to a specific peer address
    // Buffer is passed in parameter to prevent the re-allocation each time
    #[async_recursion]
    async fn try_to_connect_to_peer(self: Arc<Self>, addr: SocketAddr, priority: bool) {
        tokio::spawn(async move {
            if let Err(e) = self.connect_to_peer(addr, priority).await {
                debug!("Error while trying to connect: {}", e);
            }
        });
    }

    pub async fn connect_to_peer(self: Arc<Self>, addr: SocketAddr, priority: bool) -> Result<(), P2pError> {
        debug!("Trying to connect to {}", addr);
        if self.is_connected_to_addr(&addr).await? {
            return Err(P2pError::PeerAlreadyConnected(format!("{}", addr)));
        }
        let stream = timeout(Duration::from_millis(800), TcpStream::connect(&addr)).await??; // allow maximum 800ms of latency
        let (connection, rx) = self.create_connection(addr, stream);
        self.send_handshake(&connection).await?;
        self.handle_new_connection(connection, rx, true, priority).await
    }

    async fn send_handshake(&self, connection: &Connection) -> Result<(), P2pError> {
        let handshake: Handshake = self.build_handshake().await?;
        let mut writer = Writer::new();
        PacketOut::Handshake(&handshake).write(&mut writer);
        connection.send_bytes(&writer.bytes()).await
    }

    async fn handle_connection(&self, buf: &mut [u8], peer: Arc<Peer>, mut rx: Rx) -> Result<(), P2pError> {
        loop {
            tokio::select! {
                Err(e) = self.listen_connection(buf, &peer) => {
                    peer.increment_fail_count();
                    debug!("Error occured while listening {}: {}", peer, e);
                }
                Some(data) = rx.recv() => {
                    debug!("Data to send to {} received!", peer.get_connection().get_address());
                    peer.get_connection().send_bytes(&data).await?;
                }
            }

            if peer.get_fail_count() >= 20 {
                error!("High fail count detected for {}!", peer);
                if let Err(e) = peer.close().await {
                    error!("Error while trying to close connection {} due to high fail count: {}", peer.get_connection().get_address(), e);
                }
            }

            if peer.get_connection().is_closed() {
                break;
            }
        }
        Ok(())
    }

    async fn handle_incoming_packet(&self, peer: &Arc<Peer>, packet: PacketIn) -> Result<(), P2pError> {
        match packet {
            PacketIn::Handshake(_) => {
                return Err(P2pError::InvalidPacket)
            },
            PacketIn::Transaction(tx) => {
                if let Err(e) = self.blockchain.add_tx_to_mempool(tx, false) {
                    match e {
                        BlockchainError::TxAlreadyInMempool(_) => {},
                        e => {
                            error!("Error while adding TX to mempool: {}", e);
                            peer.increment_fail_count();
                        }
                    };
                }
            },
            PacketIn::Block(block) => {
                debug!("Received block at height {} from {}", block.get_height(), peer.get_connection().get_address());
                let block_height = block.get_height();
                if peer.get_block_height() < block_height {
                    peer.set_block_height(block_height);
                }

                let peer_id = peer.get_id();
                let mut sync = self.sync.lock().await;
                // check if it's a new propagated block, or if it's from a RequestSync
                if sync.contains_peer(&peer_id) {
                    if let Err(e) = sync.insert_block(block, &peer_id) {
                        error!("Error while adding block to chain sync: {}", e);
                        peer.increment_fail_count();
                    }
                    self.try_sync_chain(&mut sync);
                } else { // add immediately the block to chain as we are synced with
                    if let Err(e) = self.blockchain.add_new_block(block, false) {
                        error!("Error while adding new block: {}", e);
                        peer.increment_fail_count();
                    }
                }
            },
            PacketIn::RequestChain(request) => {
                let last_request = peer.get_last_chain_sync();
                let time = get_current_time();
                peer.set_last_chain_sync(time);
                if  last_request + CHAIN_SYNC_DELAY > time {
                    return Err(P2pError::RequestSyncChainTooFast)
                }

                let our_height = self.blockchain.get_height();
                let start = request.get_start_height();
                let end = request.get_end_height();
                if start > our_height || end > our_height || start > end || end - start > CHAIN_SYNC_MAX_BLOCK { // only 20 blocks max per request
                    return Err(P2pError::InvalidHeightRange)
                }

                debug!("Peer {} request block from {} to {}", peer.get_connection().get_address(), start, end);
                let storage = self.blockchain.get_storage().lock()?;
                for i in start..=end {
                    match storage.get_block_at_height(i) {
                        Ok(block) => {
                            // TODO peer.send_packet(&PacketOut::Block(block)).await?;
                        },
                        Err(_) => { // shouldn't happens as we verify range before
                            debug!("Peer {} requested an invalid block height.", peer);
                            peer.increment_fail_count();
                        }
                    };
                }
            }
            PacketIn::Ping(ping) => {
                ping.update_peer(peer);
            },
        };
        Ok(())
    }

    // Listen to incoming packets from a connection
    async fn listen_connection(&self, buf: &mut [u8], peer: &Arc<Peer>) -> Result<(), P2pError> {
        match peer.get_connection().read_packet(buf, MAX_BLOCK_SIZE as u32).await {
            Ok(packet) => self.handle_incoming_packet(peer, packet).await?,
            Err(e) => match e {
                P2pError::Disconnected => {
                    // connection already catched the disconnection, just remove it from peer_list
                    self.peer_list.lock().await.remove_peer(&peer);
                },
                P2pError::ErrorStd(e) if e.kind() == ErrorKind::WouldBlock => {},
                e => {
                    error!("An error has occured while reading bytes from {}: {}", peer, e);
                    if let Err(e) = peer.close().await {
                        error!("Error while removing {}: {}", peer.get_connection().get_address(), e);
                    }
                }
            }
        };
        Ok(())
    }

    // Called when a node is disconnected or when a new block is submitted
    fn try_sync_chain(&self, sync: &mut ChainSync) {
        if sync.is_ready() {
            if let Err(e) = sync.to_chain(&self.blockchain) {
                warn!("Error while adding sync chain to blockchain: {}", e);
            }
        }
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
        self.peer_list.lock().await.size()
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
}

/*
impl Drop for P2pServer {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            error!("Error on drop: {}", e);
        }
    }
}*/