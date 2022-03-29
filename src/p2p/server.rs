use crate::config::{VERSION, NETWORK_ID, SEED_NODES, MAX_BLOCK_SIZE, CHAIN_SYNC_TIMEOUT_SECS, CHAIN_SYNC_MAX_BLOCK, CHAIN_SYNC_DELAY, P2P_PING_DELAY};
use crate::core::reader::Reader;
use crate::core::difficulty::check_difficulty;
use crate::crypto::hash::{Hash, Hashable};
use crate::core::transaction::Transaction;
use crate::core::blockchain::Blockchain;
use crate::core::error::BlockchainError;
use crate::core::serializer::Serializer;
use crate::core::block::CompleteBlock;
use crate::globals::get_current_time;
use super::packet::{PacketIn, PacketOut};
use super::packet::handshake::Handshake;
use super::packet::request_chain::RequestChain;
use super::connection::Connection;
use super::packet::ping::Ping;
use super::error::P2pError;
use std::net::{TcpListener, TcpStream, SocketAddr, Shutdown};
use std::sync::mpsc::{Sender, Receiver, TryRecvError, channel};
use num_bigint::BigUint;
use std::io::prelude::{Write, Read};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::io::ErrorKind;
use num_traits::Zero;
use std::thread;
use rand::Rng;

enum Message {
    SendBytes(u64, Vec<u8>), // peer id, Packet
    MultipleSend(Vec<u64>, Vec<u8>),
    Broadcast(Vec<u8>),
    AddConnection(Arc<Connection>),
    RemoveConnection(u64),
    Exit,
}

struct ChainSync { // TODO, receive Block Header only
    current_top_hash: Hash,
    blocks: HashMap<Hash, CompleteBlock>,
    asked_peers: HashMap<u64, u64>, // Peer id, Blocks asked
    syncing: bool,
    start_at: u64
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
            let mut total_diff: BigUint = BigUint::zero();
            let top_blocks = self.get_top_blocks()?;
            println!("Total branches: {}", top_blocks.len());
            for block_hash in top_blocks {
                let mut current_total_diff = BigUint::zero();
                let mut current_block = self.get_block(&block_hash)?;
                let mut hash = &block_hash;
                let mut branch_hashes = HashSet::new(); // all hashes for this top block
                loop { // add all blocks until our local top block hash
                    branch_hashes.insert(hash.clone());
                    current_total_diff += current_block.get_difficulty();
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

        println!("Branches: {}, blocks: {}", branch.len(), self.blocks.len());
        let mut blocks: Vec<CompleteBlock> = Vec::with_capacity(branch.len());
        for (k, v) in self.blocks.drain() {
            if branch.contains(&k) {
                branch.remove(&k);
                blocks.push(v);
            }
        }

        blocks.sort_by(|a,b| a.get_height().cmp(&b.get_height()));

        for block in blocks {
            println!("Trying to add block from chain sync to blockchain: {}", block.get_height());
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
                return Err(BlockchainError::InvalidDifficulty(block.get_difficulty(), 0))
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
    bind_address: String, // ip:port address to receive connections
    connections: Mutex<HashMap<u64, Arc<Connection>>>, // all connections accepted
    sender: Mutex<Sender<Message>>, // sender to send messages to the thread #2
    receiver: Mutex<Receiver<Message>>, // only used by the thread #2
    blockchain: Arc<Blockchain>,
    sync: Mutex<ChainSync>
}

impl P2pServer {
    pub fn new(tag: Option<String>, max_peers: usize, bind_address: String, blockchain: Arc<Blockchain>) -> Arc<Self> {
        if let Some(tag) = &tag {
            assert!(tag.len() > 0 && tag.len() <= 16);
        }

        // set channel to communicate with listener thread
        let (sender, receiver) = channel();
        let mut rng = rand::thread_rng();
        let peer_id: u64 = rng.gen();

        let server = Self {
            peer_id,
            tag,
            max_peers,
            bind_address,
            connections: Mutex::new(HashMap::new()),
            sender: Mutex::new(sender),
            receiver: Mutex::new(receiver),
            blockchain,
            sync: Mutex::new(ChainSync::new())
        };

        let arc = Arc::new(server);
        Self::start(arc.clone());
        arc
    }

    fn start(self: Arc<Self>) {
        // spawn threads
        let clone = self.clone();
        thread::spawn(move || {
            clone.listen_new_connections();
        });

        thread::spawn(move || {
            self.listen_existing_connections();
        });
    }

    pub fn stop(&self) -> Result<(), P2pError> {
        println!("Stopping P2p Server...");
        let sender = self.sender.lock()?;
        if let Err(e) = sender.send(Message::Exit) {
            println!("Error while sending message to exit: {}", e);
        }

        let connections = self.connections.lock()?;
        for (_, conn) in connections.iter() {
            if !conn.is_closed() {
                conn.close()?;
            }
        }
        Ok(())
    }

    // Connect to all seed nodes from constant
    // buffer parameter is to prevent the re-allocation
    fn connect_to_seed_nodes(&self, buffer: &mut [u8]) -> Result<(), P2pError> {
        for peer in SEED_NODES {
            let addr: SocketAddr = match peer.parse() {
                Ok(addr) => addr,
                Err(e) => return Err(P2pError::InvalidPeerAddress(format!("seed node {}: {}", peer, e)))
            };
            if let Err(e) = self.connect_to_peer(buffer, addr, true) {
                println!("Error while trying to connect to seed node '{}': {}", peer, e);
            }
        }

        Ok(())
    }

    // connect to seed nodes, start p2p server
    // and wait on all new connections
    fn listen_new_connections(&self) {
        println!("Connecting to seed nodes..."); // TODO only if peerlist is empty
        // allocate this buffer only one time, because we are using the same thread
        let mut buffer: [u8; 512] = [0; 512]; // maximum 512 bytes for handshake
        if let Err(e) = self.connect_to_seed_nodes(&mut buffer) {
            println!("Error while connecting to seed nodes: {}", e);
        }

        println!("Starting p2p server...");
        let listener = TcpListener::bind(self.get_bind_address()).unwrap();

        println!("Waiting for connections...");
        for stream in listener.incoming() { // main thread verify all new connections
            println!("New incoming connection");
            match stream {
                Ok(stream) => {
                    if !self.accept_new_connections() { // if we have already reached the limit, we ignore this new connection
                        println!("Max peers reached, rejecting connection");
                        if let Err(e) = stream.shutdown(Shutdown::Both) {
                            println!("Error while closing & ignoring incoming connection: {}", e);
                        }
                        continue;
                    }

                    if let Err(e) = self.handle_new_connection(&mut buffer, stream, false, false) {
                        println!("Error on new connection: {}", e);
                    }
                }
                Err(e) => {
                    println!("Error while accepting new connection: {}", e);
                }
            }
        }
    }

    // listening connections thread
    fn listen_existing_connections(&self) {
        println!("Starting single thread connection listener...");
        let mut connections: HashMap<u64, Arc<Connection>> = HashMap::new();
        let mut buf: [u8; 1024] = [0; 1024]; // allocate this buffer only one time
        let mut last_ping = get_current_time();
        match self.receiver.lock() {
            Ok(receiver) => {
                loop {
                    if connections.len() == 0 { // maintains connection to seed nodes
                        if let Err(e) = self.connect_to_seed_nodes(&mut buf) {
                            println!("Error while connecting to seed nodes: {}", e);
                        }
                    }

                    while let Ok(msg) = if connections.len() == 0 {
                        receiver.recv().or(Err(TryRecvError::Empty))
                    } else {
                        receiver.try_recv()
                    } { // read all messages from channel
                        match msg {
                            Message::Exit => {
                                return;
                            },
                            Message::AddConnection(connection) => {
                                connections.insert(connection.get_peer_id(), connection);
                            }
                            Message::RemoveConnection(peer_id) => {
                                connections.remove(&peer_id);
                            }
                            Message::MultipleSend(peers, bytes) => {
                                for peer in peers {
                                    if let Some(connection) = connections.get(&peer) {
                                        if let Err(e) = connection.send_bytes(&bytes) {
                                            println!("Error on sending bytes: {}", e);
                                            if let Err(e) = self.remove_connection(&peer) {
                                                println!("Error while trying to remove {}: {}", connection, e);
                                            }
                                        }
                                    } else {
                                        println!("Unknown peer '{}' to send bytes!", peer);
                                    }
                                }
                            },
                            Message::SendBytes(peer_id, packet) => {
                                if let Some(connection) = connections.get(&peer_id) {
                                    if let Err(e) = connection.send_bytes(&packet) {
                                        println!("Error on sending bytes: {}", e);
                                        if let Err(e) = self.remove_connection(&peer_id) {
                                            println!("Error while trying to remove {}: {}", connection, e);
                                        }
                                    }
                                } else {
                                    println!("Unknown peer {} to send bytes!", peer_id);
                                }
                            }
                            Message::Broadcast(packet) => {
                                for connection in connections.values() {
                                    if let Err(e) = connection.send_bytes(&packet) {
                                        println!("Error on sending bytes to '{}': {}", connection, e);
                                    }
                                }
                            }
                        }
                    }

                    match self.sync.try_lock() {  
                        Ok(mut sync) => {
                            if !sync.is_syncing() && sync.can_sync() {
                                if let Ok(top_hash) = self.blockchain.get_top_block_hash() {
                                    let our_height = self.blockchain.get_height();
                                    for connection in connections.values() {
                                        let peer_height = connection.get_block_height();
                                        if peer_height > our_height {
                                            if !sync.is_syncing() { // init one time only
                                                sync.start_sync(top_hash.clone());
                                            }
                                            let peer_id = connection.get_peer_id();
                                            let diff = peer_height - our_height;
                                            let max_diff = if diff > CHAIN_SYNC_MAX_BLOCK { CHAIN_SYNC_MAX_BLOCK } else { diff };
                                            println!("Requesting {} blocks ({} to {}) to peer {}", max_diff, our_height, our_height + max_diff, peer_id);
                                            sync.add_peer(peer_id, max_diff);
                                            let request = RequestChain::new(our_height + 1, our_height + max_diff, top_hash.clone());
                                            if let Err(e) = connection.send_bytes(&PacketOut::RequestChain(&request).to_bytes()) {
                                                println!("Error while requesting chain to peer '{}': {}", peer_id, e);
                                            }
                                        }
                                    }
                                }
                            } else {
                                self.try_sync_chain(&mut sync);
                            }
                        }
                        Err(e) => {
                            println!("Error while trying to lock ChainSync: {}", e);
                        }
                    };

                    let current_time = get_current_time();
                    let ping: Option<Ping> = if current_time - last_ping > P2P_PING_DELAY {
                        match self.blockchain.get_top_block_hash() {
                            Ok(v) => {
                                last_ping = current_time;
                                Some(Ping::new(v, self.blockchain.get_height()))
                            },
                            Err(e) => {
                                println!("Error while getting block top hash: {}", e);
                                None
                            }
                        }
                    } else {
                        None
                    };

                    for connection in connections.values() {
                        if let Some(ping) = &ping {
                            if let Err(e) = connection.send_bytes(&PacketOut::Ping(ping).to_bytes()) {
                                println!("Error while sending ping to peer '{}': {}", connection, e);
                            }
                        }
                        self.handle_connection(&mut buf, &connection);
                    }

                    // wait 25ms between each iteration
                    thread::sleep(Duration::from_millis(25));
                }
            },
            Err(e) => panic!("Couldn't lock receiver! {}", e)
        }
    }

    // Verify handshake send by a new connection
    // based on data size, network ID, peers address validity
    // block height and block top hash of this peer (to know if we are on the same chain)
    fn verify_handshake(&self, addr: SocketAddr, stream: TcpStream, handshake: Handshake, out: bool, priority: bool) -> Result<(Connection, Vec<SocketAddr>), P2pError> {
        if *handshake.get_network_id() != NETWORK_ID {
            return Err(P2pError::InvalidNetworkID);
        }

        if self.is_connected_to(&handshake.get_peer_id())? {
            stream.shutdown(Shutdown::Both)?;
            return Err(P2pError::PeerIdAlreadyUsed(handshake.get_peer_id()));
        }

        // TODO check block height, check if top hash is equal to block height
        let (connection, str_peers) = handshake.create_connection(stream, addr, out, priority);
        let mut peers: Vec<SocketAddr> = vec![];
        for peer in str_peers {
            let addr = match peer.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(e) => {
                    let _ = connection.close(); // peer send us an invalid socket address, invalid handshake
                    return Err(P2pError::InvalidPeerAddress(format!("{}", e)));
                }
            };
            peers.push(addr);
        }
        peers = peers.into_iter().take(self.get_slots_available()).collect(); // limit to X slots available
        Ok((connection, peers))
    }

    fn build_handshake(&self) -> Result<Handshake, P2pError> {
        let mut peers = vec![];
        let connections = self.connections.lock()?;
        let mut iter = connections.iter();
        while peers.len() < Handshake::MAX_LEN {
            match iter.next() {
                Some((_, v)) => {
                    if !v.is_out() { // don't send our clients
                        // TODO send IP in bytes format
                        peers.push(format!("{}", v.get_peer_address()));
                    }
                },
                None => break
            };
        }

        let block_height = self.blockchain.get_height();
        let top_hash = self.blockchain.get_storage().lock()?.get_top_block_hash().clone();
        Ok(Handshake::new(VERSION.to_owned(), self.get_tag().clone(), NETWORK_ID, self.get_peer_id(), get_current_time(), block_height, top_hash, peers))
    }

    // this function handle all new connection on main thread
    // A new connection have to send an Handshake
    // if the handshake is valid, we accept it & register it on server
    fn handle_new_connection(&self, buffer: &mut [u8], mut stream: TcpStream, out: bool, priority: bool) -> Result<(), P2pError> {
        stream.set_read_timeout(Some(Duration::from_millis(300)))?;
        let addr = stream.peer_addr()?;
        println!("New connection: {}", addr);
        let n = stream.read(buffer)?;
        let mut reader = Reader::new(&buffer[0..n]);
        let handshake = match Handshake::read(&mut reader) {
            Ok(v) => v,
            Err(_) => return Err(P2pError::InvalidHandshake)
        };
        let (connection, peers) = self.verify_handshake(addr, stream, handshake, out, priority)?;
        // if it's a outgoing connection, don't send the handshake back
        // because we have already sent it
        if !out {
            let handshake = self.build_handshake()?; // TODO don't send same peers list
            connection.send_bytes(&handshake.to_bytes())?; // send handshake back
        }

        // handle connection
        // set stream no-blocking
        connection.set_blocking(false)?;

        // if we reach here, handshake is all good, we can start listening this new peer
        let peer_id = connection.get_peer_id(); // keep in memory the peer_id outside connection (because of moved value)
        self.add_connection(connection)?;
        // try to extend our peer list
        for peer in peers {
            if let Err(e) = self.connect_to_peer(buffer, peer, false) {
                println!("Error while trying to connect to a peer from {}: {}", peer_id, e);
            }
        }

        Ok(())
    }

    // Connect to a specific peer address
    // Buffer is passed in parameter to prevent the re-allocation each time
    pub fn connect_to_peer(&self, buffer: &mut [u8], peer_addr: SocketAddr, priority: bool) -> Result<(), P2pError> {
        if self.is_connected_to_addr(&peer_addr)? {
            return Err(P2pError::PeerAlreadyConnected(format!("{}", peer_addr)));
        }

        println!("Trying to connect to {}", peer_addr);
        let mut stream = TcpStream::connect(&peer_addr)?;
        let handshake: Handshake = self.build_handshake()?;
        println!("Sending handshake from server");
        stream.write(&handshake.to_bytes())?;

        // wait on Handshake reply & manage this new connection
        self.handle_new_connection(buffer, stream, true, priority)
    }

    fn handle_connection(&self, buf: &mut [u8], connection: &Arc<Connection>) {
        if let Err(e) = self.listen_connection(buf, connection) {
            connection.increment_fail_count();
            println!("Error occured while listening {}: {}", connection, e);
        }

        if connection.fail_count() >= 20 {
            println!("High fail count detected, remove connection!");
            if let Err(e) = self.remove_connection(&connection.get_peer_id()) {
                println!("Error while trying to remove {} due to high fail count: {}", connection, e);
            }
        }
    }

    // Listen to incoming packets from a connection
    fn listen_connection(&self, buf: &mut [u8], connection: &Arc<Connection>) -> Result<(), P2pError> {
        loop {
            match connection.read_packet_size(buf) {
                Ok((0, _)) => { // peer disconnected
                    let _ = self.remove_connection(&connection.get_peer_id());
                    break;
                },
                Ok((_, size)) => {
                    if size == 0 || size > MAX_BLOCK_SIZE as u32 { // If packet size is bigger than a full block, then reject it
                        return Err(P2pError::InvalidPacketSize)
                    }
    
                    let bytes = connection.read_all_bytes(buf, size)?;
                    let mut reader = Reader::new(&bytes);
                    match PacketIn::read(&mut reader)? {
                        PacketIn::Handshake(_) => {
                            return Err(P2pError::InvalidPacket)
                        },
                        PacketIn::Transaction(tx) => {
                            if let Err(e) = self.blockchain.add_tx_to_mempool(tx, false) {
                                println!("Error while adding TX to mempool: {}", e);
                                match e {
                                    BlockchainError::TxAlreadyInMempool(_) => {},
                                    _ => {
                                        connection.increment_fail_count();
                                    }
                                };
                            }
                        },
                        PacketIn::Block(block) => {
                            let block_height = block.get_height();
                            if connection.get_block_height() < block_height {
                                connection.set_block_height(block_height);
                            }

                            let peer_id = connection.get_peer_id();
                            let mut sync = self.sync.lock()?;
                            // check if it's a new propagated block, or if it's from a RequestSync
                            if sync.contains_peer(&peer_id) {
                                if let Err(e) = sync.insert_block(block, &peer_id) {
                                    println!("Error while adding block to chain sync: {}", e);
                                    connection.increment_fail_count();
                                }
                                self.try_sync_chain(&mut sync);
                            } else { // add immediately the block to chain as we are synced with
                                if let Err(e) = self.blockchain.add_new_block(block, false) {
                                    println!("Error while adding new block: {}", e);
                                    connection.increment_fail_count();
                                }
                            }
                        },
                        PacketIn::RequestChain(request) => {
                            let last_request = connection.get_last_chain_sync();
                            let time = get_current_time();
                            connection.set_last_chain_sync(time);
                            if  last_request + CHAIN_SYNC_DELAY > time {
                                return Err(P2pError::RequestSyncChainTooFast)
                            }

                            let our_height = self.blockchain.get_height();
                            let start = request.get_start_height();
                            let end = request.get_end_height();
                            if start > our_height || end > our_height || start > end || end - start > CHAIN_SYNC_MAX_BLOCK { // only 20 blocks max per request
                                return Err(P2pError::InvalidHeightRange)
                            }

                            println!("Peer {} request block from {} to {}", connection, start, end);
                            let storage = self.blockchain.get_storage().lock()?;
                            for i in start..=end {
                                match storage.get_block_at_height(i) {
                                    Ok(block) => {
                                        self.send_to_peer(connection.get_peer_id(), PacketOut::Block(block))?;
                                    },
                                    Err(_) => { // shouldn't happens as we verify range before
                                        connection.increment_fail_count();
                                        println!("Peer requested an invalid block height.");
                                    }
                                };
                            }
                        }
                        PacketIn::Ping(ping) => {
                            ping.update_connection(connection);
                        },
                    };
                },
                Err(e) => {
                    if let P2pError::ErrorStd(e) = &e {
                        if e.kind() == ErrorKind::WouldBlock {
                            return Ok(())
                        } 
                    }
                    if let Err(e) = self.remove_connection(&connection.get_peer_id()) {
                        println!("Error while removing connection: {}", e);
                    }
                    println!("An error has occured while reading bytes from {}: {}", connection, e);
                    break;
                }
            };
        }

        Ok(())
    }

    // Called when a node is disconnected or when a new block is submitted
    fn try_sync_chain(&self, sync: &mut ChainSync) {
        if sync.is_ready() {
            if let Err(e) = sync.to_chain(&self.blockchain) {
                println!("Error while adding sync chain to blockchain: {}", e);
            }
        }
    }

    pub fn get_highest_height(&self) -> u64 {
        match self.connections.lock() {
            Ok(connections) => {
                let mut max = 0;
                for connection in connections.values() {
                    if connection.get_block_height() > max {
                        max = connection.get_block_height();
                    }
                }
                max
            },
            Err(_) => 0
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

    pub fn accept_new_connections(&self) -> bool {
        self.get_peer_count() < self.get_max_peers()
    }

    pub fn get_peer_count(&self) -> usize {
        match self.connections.lock() {
            Ok(connections) => connections.len(),
            Err(_) => 0
        }
    }

    pub fn get_slots_available(&self) -> usize {
        self.max_peers - self.get_peer_count()
    }

    pub fn is_connected_to(&self, peer_id: &u64) -> Result<bool, P2pError> {
        let connections = self.connections.lock()?;
        Ok(self.peer_id == *peer_id || connections.contains_key(peer_id))
    }

    pub fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> Result<bool, P2pError> {
        let connections = self.connections.lock()?;
        for connection in connections.values() {
            if *connection.get_peer_address() == *peer_addr {
                return Ok(true)
            }
        }
        Ok(false)
    }

    pub fn get_bind_address(&self) -> &String {
        &self.bind_address
    }

    fn add_connection(&self, connection: Connection) -> Result<(), P2pError> {
        let mut connections = self.connections.lock()?;
        let peer_id = connection.get_peer_id();
        let arc_connection = Arc::new(connection);
        match connections.insert(peer_id, arc_connection.clone()) {
            Some(c) => {  // should not happen (check is done in verify_handshake)
                connections.insert(peer_id, c);
                return Err(P2pError::PeerIdAlreadyUsed(peer_id))
            },
            None => {
                let sender = self.sender.lock()?;
                sender.send(Message::AddConnection(arc_connection))?;
                println!("add new connection (total {}): {}", connections.len(), self.bind_address);
                Ok(())
            }
        }
    }

    fn remove_connection(&self, peer_id: &u64) -> Result<(), P2pError> {
        let mut connections = self.connections.lock()?;
        match connections.remove(peer_id) {
            Some(connection) => {
                let sender = self.sender.lock()?;
                sender.send(Message::RemoveConnection(*peer_id))?;
                if !connection.is_closed() {
                    connection.close()?;
                }
                println!("{} disconnected", connection);
                let mut sync = self.sync.lock()?;
                if sync.remove_peer(peer_id) {
                    self.try_sync_chain(&mut sync);
                }
                Ok(())
            },
            None => Err(P2pError::PeerNotFound(*peer_id)),
        }
    }

    pub fn get_connections(&self) -> &Mutex<HashMap<u64, Arc<Connection>>> {
        &self.connections
    }

    // notify the thread that own the target peer through channel
    pub fn send_to_peer(&self, peer_id: u64, packet: PacketOut) -> Result<(), P2pError> {
        let sender = self.sender.lock()?;
        sender.send(Message::SendBytes(peer_id, packet.to_bytes()))?;
        Ok(())
    }

    pub fn broadcast_tx(&self, tx: &Transaction) -> Result<(), P2pError> {
        self.broadcast_packet(PacketOut::Transaction(tx))
    }

    pub fn broadcast_block(&self, block: &CompleteBlock) -> Result<(), P2pError> {
        let packet_bytes = PacketOut::Block(block).to_bytes();
        let connections = self.connections.lock()?;
        let mut peers: Vec<u64> = Vec::new();
        for connection in connections.values() {
            if block.get_height() == connection.get_block_height() + 1 {
                println!("Will broadcast block to: {}", connection);
                peers.push(connection.get_peer_id());
                connection.set_block_height(block.get_height());
            }
        }

        let sender = self.sender.lock()?;
        sender.send(Message::MultipleSend(peers, packet_bytes))?;
        Ok(())
    }

    // send bytes in param to all connected peers
    fn broadcast_packet(&self, packet: PacketOut) -> Result<(), P2pError> {
        println!("Broadcast Packet");
        let sender = self.sender.lock()?;
        sender.send(Message::Broadcast(packet.to_bytes()))?;
        Ok(())
    }
}

impl Drop for P2pServer {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            println!("Error on drop: {}", e);
        }
    }
}