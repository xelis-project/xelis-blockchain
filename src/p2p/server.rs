use crate::config::{VERSION, NETWORK_ID, SEED_NODES};
use crate::globals::get_current_time;
use crate::core::serializer::Serializer;
use crate::core::reader::{Reader, ReaderError};
use crate::core::transaction::Transaction;
use crate::core::block::CompleteBlock;
use crate::crypto::hash::Hash;
use super::connection::Connection;
use super::handshake::Handshake;
use super::error::P2pError;
use std::net::{TcpListener, TcpStream, SocketAddr, Shutdown};
use std::sync::mpsc::{Sender, Receiver, channel};
use std::io::prelude::{Write, Read};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::io::ErrorKind;
use std::thread;

enum Message {
    SendBytes(u64, Vec<u8>), // peer id, bytes
    AddConnection(Arc<Connection>),
    RemoveConnection(u64),
    Exit,
}

// SingleThreadServer only use 2 threads: one for incoming new connections
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
}

impl P2pServer {
    pub fn new(peer_id: u64, tag: Option<String>, max_peers: usize, bind_address: String) -> Arc<Self> {
        if let Some(tag) = &tag {
            assert!(tag.len() > 0 && tag.len() <= 16);
        }

        // set channel to communicate with listener thread
        let (sender, receiver) = channel();

        let server = Self {
            peer_id,
            tag,
            max_peers,
            bind_address,
            connections: Mutex::new(HashMap::new()),
            sender: Mutex::new(sender),
            receiver: Mutex::new(receiver)
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

        match self.sender.lock() {
            Ok(sender) => {
                if let Err(e) = sender.send(Message::Exit) {
                    println!("Error while sending message to exit: {}", e);
                }
            },
            Err(e) => return Err(P2pError::OnLock(format!("{}", e)))
        };

        match self.connections.lock() {
            Ok(connections) => {
                for (_, conn) in connections.iter() {
                    if !conn.is_closed() {
                        if let Err(e) = conn.close() {
                            return Err(P2pError::OnConnectionClose(format!("{}", e)));
                        }
                    }
                }
            },
            Err(e) => return Err(P2pError::OnLock(format!("{}", e)))
        };
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
            if let Err(e) = self.connect_to_peer(buffer, addr) {
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

                    if let Err(e) = self.handle_new_connection(&mut buffer, stream, false) {
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
        // TODO extend buffer as we have verified this peer
        let mut connections: HashMap<u64, Arc<Connection>> = HashMap::new();
        let mut buf: [u8; 512] = [0; 512]; // allocate this buffer only one time
        loop {
            match self.receiver.lock() {
                Ok(receiver) => {
                    while let Ok(msg) = receiver.try_recv() { // read all messages from channel
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
                            Message::SendBytes(peer_id, bytes) => {
                                if let Some(connection) = connections.get(&peer_id) {
                                    if let Err(e) = connection.send_bytes(&bytes) {
                                        println!("Error on sending bytes: {}", e);
                                        if let Err(e) = self.remove_connection(&peer_id) {
                                            println!("Error while trying to remove {}: {}", connection, e);
                                        }
                                    }
                                } else {
                                    println!("Unknown peer {} to send bytes!", peer_id);
                                }
                            }
                        }
                    }
                },
                Err(e) => panic!("Couldn't lock receiver! {}", e)
            }

            for connection in connections.values() {
                self.handle_connection(&mut buf, &connection);
            }
        }
    }

    pub fn broadcast_tx(&self, tx: &Transaction) -> Result<(), P2pError> {
        let mut bytes: Vec<u8> = tx.to_bytes();
        bytes.insert(0, 0); // id 0 for tx
        self.broadcast_bytes(&bytes)
    }

    pub fn broadcast_block(&self, block: &CompleteBlock) -> Result<(), P2pError> {
        let mut bytes = block.to_bytes();
        bytes.insert(0, 1); // id 1 for block
        self.broadcast_bytes(&bytes)
    }

    // Verify handshake send by a new connection
    // based on data size, network ID, peers address validity
    // block height and block top hash of this peer (to know if we are on the same chain)
    fn verify_handshake(&self, addr: SocketAddr, stream: TcpStream, handshake: Handshake, out: bool) -> Result<(Connection, Vec<SocketAddr>), P2pError> {
        println!("Handshake: {}", handshake);
        if *handshake.get_network_id() != NETWORK_ID {
            return Err(P2pError::InvalidNetworkID);
        }

        if self.is_connected_to(&handshake.get_peer_id())? {
            if let Err(e) = stream.shutdown(Shutdown::Both) {
                println!("Error while rejecting peer: {}", e);
            }
            return Err(P2pError::PeerIdAlreadyUsed(handshake.get_peer_id()));
        }

        // TODO check block height, check if top hash is equal to block height
        let (connection, str_peers) = handshake.create_connection(stream, addr, out);
        let mut peers: Vec<SocketAddr> = vec![];
        for peer in str_peers {
            let peer_addr: SocketAddr = match peer.parse() {
                Ok(addr) => addr,
                Err(e) => {
                    let _ = connection.close(); // peer send us an invalid socket address, invalid handshake
                    return Err(P2pError::InvalidPeerAddress(format!("{}", e)));
                }
            };

            if !self.is_connected_to_addr(&peer_addr)? { // prevent reconnecting to a known p2p server
                peers.push(peer_addr);
            }
        }
        peers = peers.into_iter().take(self.get_slots_available()).collect(); // limit to X slots available
        Ok((connection, peers))
    }

    fn build_handshake(&self) -> Result<Handshake, P2pError> {
        let mut peers = vec![];
        match self.connections.lock() {
            Ok(connections) => {
                let mut iter = connections.iter();
                while peers.len() < Handshake::MAX_LEN {
                    match iter.next() {
                        Some((_, v)) => {
                            if !v.is_out() { // don't send our clients
                                peers.push(format!("{}", v.get_peer_address()));
                            }
                        },
                        None => break
                    };
                }
            },
            Err(e) => return Err(P2pError::OnLock(format!("{}", e)))
        };

        // TODO Handshake hash
        Ok(Handshake::new(VERSION.to_owned(), self.get_tag().clone(), NETWORK_ID, self.get_peer_id(), get_current_time(), 0, Hash::new([0u8; 32]), peers))
    }

    // this function handle all new connection on main thread
    // A new connection have to send an Handshake
    // if the handshake is valid, we accept it & register it on server
    fn handle_new_connection(&self, buffer: &mut [u8], mut stream: TcpStream, out: bool) -> Result<(), P2pError> {
        match stream.peer_addr() {
            Ok(addr) => {
                println!("New connection: {}", addr);
                match stream.read(buffer) {
                    Ok(n) => {
                        let handshake = Handshake::from_bytes(&buffer[0..n])?;
                        let (connection, peers) = self.verify_handshake(addr, stream, handshake, out)?;

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
                            if let Err(e) = self.connect_to_peer(buffer, peer) {
                                println!("Error while trying to connect to a peer from {}: {}", peer_id, e);
                            }
                        }
                    },
                    Err(e) => println!("Error while reading handshake: {}", e)
                }
            }
            Err(e) => println!("Error while retrieving peer address: {}", e)
        };

        Ok(())
    }

    // Connect to a specific peer address
    // Buffer is passed in parameter to prevent the re-allocation each time
    pub fn connect_to_peer(&self, buffer: &mut [u8], peer_addr: SocketAddr) -> Result<(), P2pError> {
        println!("Trying to connect to {}", peer_addr);
        match TcpStream::connect(&peer_addr) {
            Ok(mut stream) => {
                let handshake: Handshake = self.build_handshake()?;
                println!("Sending handshake from server");
                if let Err(e) = stream.write(&handshake.to_bytes()) {
                    return Err(P2pError::OnWrite(format!("connect to peer {}: {}", peer_addr, e)));
                }

                // wait on Handshake reply & manage this new connection
                self.handle_new_connection(buffer, stream, true)
            },
            Err(e) => Err(P2pError::InvalidPeerAddress(format!("Can't connect to a new peer: {}", e)))
        }
    }

    fn handle_connection(&self, buf: &mut [u8], connection: &Arc<Connection>) {
        if let Err(e) = self.listen_connection(buf, connection) {
            println!("Error occured while listening {}: {}", connection, e);
            connection.increment_fail_count();
        }

        if connection.fail_count() >= 20 {
            println!("High fail count detected, remove connection!");
            if let Err(e) = self.remove_connection(&connection.get_peer_id()) {
                println!("Error while trying to remove {} due to high fail count: {}", connection, e);
            }
        }
    }

    // Listen to incoming packets from a connection
    fn listen_connection(&self, buf: &mut [u8], connection: &Arc<Connection>) -> Result<(), ReaderError> {
        match connection.read_bytes(buf) {
            Ok(0) => { // peer disconnected
                let _ = self.remove_connection(&connection.get_peer_id());
            },
            Ok(n) => {
                let mut reader = Reader::new(buf[0..n].to_vec());
                let id = reader.read_u8()?;
                match id {
                    0 => {
                        let tx = Transaction::from_bytes(&mut reader)?;                        
                        // TODO add TX to mempool
                    },
                    1 => {
                        let block = CompleteBlock::from_bytes(&mut reader)?;
                    },
                    _ => return Err(ReaderError::InvalidValue)
                };

                if n != reader.total_read() { // request was valid, but peer send more than expected
                    connection.increment_fail_count();
                    println!("{} sent {} bytes but read only {} bytes", connection, n, reader.total_read());
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // Don't do anything
            },
            Err(e) => {
                let _ = self.remove_connection(&connection.get_peer_id());
                println!("An error has occured while reading bytes from {}: {}", connection, e);
            }
        };

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
        match self.connections.lock() {
            Ok(connections) => {
                Ok(self.peer_id == *peer_id || connections.contains_key(peer_id))
            },
            Err(e) => Err(P2pError::OnLock(format!("is connected to {}: {}", peer_id, e)))
        }
    }

    pub fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> Result<bool, P2pError> {
        match self.connections.lock() {
            Ok(connections) => {
                for connection in connections.values() {
                    if *connection.get_peer_address() == *peer_addr {
                        return Ok(true)
                    }
                }
                Ok(false)
            },
            Err(e) => Err(P2pError::OnLock(format!("is connected to {}: {}", peer_addr, e)))
        }
    }

    pub fn get_bind_address(&self) -> &String {
        &self.bind_address
    }

    fn add_connection(&self, connection: Connection) -> Result<(), P2pError> {
        match self.connections.lock() {
            Ok(mut connections) => {
                let peer_id = connection.get_peer_id();
                let arc_connection = Arc::new(connection);
                match connections.insert(peer_id, arc_connection.clone()) {
                    Some(c) => {  // should not happen (check is done in verify_handshake)
                        connections.insert(peer_id, c);
                        return Err(P2pError::PeerIdAlreadyUsed(peer_id))
                    },
                    None => match self.sender.lock() {
                        Ok(ref channel) => {
                            match channel.send(Message::AddConnection(arc_connection)) {
                                Ok(_) => {
                                    println!("add new connection (total {}): {}", connections.len(), self.bind_address);
                                    Ok(())
                                }
                                Err(e) => Err(P2pError::OnChannelMessage(peer_id, format!("{}", e)))
                            }
                        },
                        Err(e) => Err(P2pError::OnLock(format!("trying to add {} to thread: {}", arc_connection, e)))
                    }
                }
            }
            Err(e) => {
                Err(P2pError::OnLock(format!("trying to add {}: {}", connection, e)))
            }
        }
    }

    fn remove_connection(&self, peer_id: &u64) -> Result<(), P2pError> {
        match self.connections.lock() {
            Ok(mut connections) => match connections.remove(peer_id) {
                Some(connection) => {
                    if !connection.is_closed() {
                        if let Err(e) = connection.close() {
                            return Err(P2pError::OnConnectionClose(format!("trying to remove {}: {}", peer_id, e)));
                        }
                    }
                    println!("{} disconnected", connection);
    
                    match self.sender.lock() {
                        Ok(channel) => {
                            if let Err(e) = channel.send(Message::RemoveConnection(*peer_id)) {
                                Err(P2pError::OnChannelMessage(*peer_id, format!("{}", e)))
                            } else {
                                Ok(())
                            }
                        }
                        Err(e) => {
                            Err(P2pError::OnLock(format!("trying to remove {}: {}", peer_id, e)))
                        }
                    }
                },
                None => Err(P2pError::PeerNotFound(*peer_id)),
            },
            Err(e) => Err(P2pError::OnLock(format!("trying to remove {}: {}", peer_id, e)))
        }
    }

    pub fn get_connections(&self) -> &Mutex<HashMap<u64, Arc<Connection>>> {
        &self.connections
    }

    // notify the thread that own the target peer through channel
    pub fn send_to_peer(&self, peer_id: u64, bytes: Vec<u8>) -> Result<(), P2pError> {
        match self.sender.lock() {
            Ok(chan) => {
                if let Err(e) = chan.send(Message::SendBytes(peer_id, bytes)) {
                    Err(P2pError::OnChannelMessage(peer_id, format!("'SendBytes': {}", e)))
                } else {
                    Ok(())
                }
            }
            Err(e) => {
                Err(P2pError::OnLock(format!("send_to_peer: {}", e))) 
            }
        }
    }

    // send bytes in param to all connected peers
    fn broadcast_bytes(&self, buf: &[u8]) -> Result<(), P2pError> {
        match self.connections.lock() {
            Ok(connections) => {
                for connection in connections.keys() {
                    self.send_to_peer(*connection, buf.to_vec())?;
                }
                Ok(())
            },
            Err(e) => Err(P2pError::OnLock(format!("broadcast: {}", e)))
        }
    }
}

impl Drop for P2pServer {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            println!("Error on drop: {}", e);
        }
    }
}