use crate::core::block::CompleteBlock;
use crate::config::{VERSION, NETWORK_ID, SEED_NODES};
use crate::crypto::hash::Hash;
use crate::globals::get_current_time;
use super::connection::Connection;
use super::handshake::Handshake;
use super::error::P2pError;
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::io::prelude::{Write, Read};
use std::net::{TcpListener, TcpStream, SocketAddr, Shutdown};
use std::thread;

pub struct P2pServer {
    peer_id: u64, // unique peer id
    tag: Option<String>, // node tag sent on handshake
    max_peers: usize,
    bind_address: String,
    connections: HashMap<u64, Arc<Connection>>
}

impl P2pServer {
    pub fn new(peer_id: u64, tag: Option<String>, max_peers: usize, bind_address: String) -> Self {
        if let Some(tag) = &tag {
            assert!(tag.len() > 0 && tag.len() <= 16);
        }

        P2pServer {
            peer_id,
            tag,
            max_peers,
            bind_address,
            connections: HashMap::new(),
        }
    }

    pub fn start(self) {
        println!("Starting p2p server...");
        let listener = TcpListener::bind(&self.bind_address).unwrap();
        let arc = Arc::new(RwLock::new(self));

        println!("Connecting to seed nodes..."); // TODO only if peerlist is empty
        for peer in SEED_NODES {
            let addr: SocketAddr = peer.parse().unwrap();
            let zelf = arc.clone();
            if peer != zelf.read().unwrap().bind_address {
                P2pServer::connect_to_peer(zelf, addr);
            }
        }

        println!("Waiting for connections...");
        for stream in listener.incoming() { // main thread verify all new connections
            println!("New incoming connection");
            match stream {
                Ok(stream) => {
                    let zelf = arc.clone();
                    if !zelf.read().unwrap().accept_new_connections() { // if we have already reached the limit, we ignore this new connection
                        println!("Max peers reached, rejecting connection");
                        if let Err(e) = stream.shutdown(Shutdown::Both) {
                            println!("Error while closing & ignoring incoming connection: {}", e);
                        }
                        continue;
                    }

                    P2pServer::handle_new_connection(zelf, stream, false);
                }
                Err(e) => {
                    println!("Error while accepting new connection: {}", e);
                }
            }
        }
    }

    pub fn accept_new_connections(&self) -> bool {
        self.get_peer_count() < self.max_peers
    }

    pub fn get_peer_count(&self) -> usize {
        self.connections.len()
    }

    pub fn get_slots_available(&self) -> usize {
        self.max_peers - self.connections.len()
    }

    pub fn is_connected_to(&self, peer_id: &u64) -> bool {
        self.peer_id != *peer_id && self.connections.contains_key(peer_id)
    }

    pub fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> bool {
        for connection in self.connections.values() {
            if *connection.get_peer_address() == *peer_addr {
                return true
            }
        }
        false
    }

    // Send a block too all connected peers (block propagation)
    pub fn broadcast_block(&self, block: &CompleteBlock) {
        use crate::crypto::hash::Hashable;
        for connection in self.connections.values() {
            connection.send_bytes(&block.to_bytes());
        }
    }

    pub fn broadcast_block_except(&self, block: &CompleteBlock, peer_id: u64) {
        use crate::crypto::hash::Hashable;
        for connection in self.connections.values() {
            if connection.get_peer_id() != peer_id {
                connection.send_bytes(&block.to_bytes());
            }
        }
    }

    fn add_connection(&mut self, peer_id: u64, connection: Arc<Connection>) {
        match self.connections.insert(peer_id, connection) {
            Some(_) => {
                panic!("Peer ID '{}' is already used!", peer_id); // should not happen
            },
            None => {}
        }
        println!("add new connection (total {}): {}", self.connections.len(), self.bind_address);
    }

    fn remove_connection(&mut self, peer_id: &u64) -> bool {
        match self.connections.remove(peer_id) {
            Some(connection) => {
                if !connection.is_closed() {
                    if let Err(e) = connection.close() {
                        println!("Error while closing connection: {}", e);
                    }
                }
                true
            },
            None => false,
        }
    }

    fn build_handshake(&self) -> Handshake {
        let mut peers = vec![];
        let mut iter = self.connections.values();
        while peers.len() < Handshake::MAX_LEN {
            match iter.next() {
                Some(v) => {
                    peers.push(format!("{}", v.get_peer_address()));
                },
                None => break
            };
        }

        // TODO set correct params
        Handshake::new(VERSION.to_owned(), self.tag.clone(), NETWORK_ID, self.peer_id, get_current_time(), 0, Hash::zero(), peers)
    }

    fn verify_handshake(&self, addr: SocketAddr, stream: TcpStream, handshake: Handshake, out: bool) -> Result<(Connection, Vec<SocketAddr>), P2pError> {
        println!("Handshake: {}", handshake);
        if *handshake.get_network_id() != NETWORK_ID {
            return Err(P2pError::InvalidNetworkID);
        }

        if self.is_connected_to(&handshake.get_peer_id()) {
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

            if !self.is_connected_to_addr(&peer_addr) { // prevent reconnecting to a known p2p server
                peers.push(peer_addr);
            }
        }
        peers = peers.into_iter().take(self.get_slots_available()).collect(); // limit to X slots available
        Ok((connection, peers))
    }

    fn connect_to_peer(zelf: Arc<RwLock<P2pServer>>, peer_addr: SocketAddr) {
        println!("Trying to connect to {}", peer_addr);
        match TcpStream::connect(&peer_addr) {
            Ok(mut stream) => {
                let handshake: Handshake = zelf.read().unwrap().build_handshake();
                println!("Sending handshake from server");
                if let Err(e) = stream.write(&handshake.to_bytes()) {
                    println!("Error while sending handshake to connection: {}", e);
                    return;
                }

                // wait on Handshake reply & manage this new connection
                P2pServer::handle_new_connection(zelf, stream, true);
            },
            Err(e) => {
                println!("Error while connecting to a new peer: {}", e);
            }
        };
    }

    // this function
    fn handle_new_connection(zelf: Arc<RwLock<P2pServer>>, mut stream: TcpStream, out: bool) {
        match stream.peer_addr() {
            Ok(addr) => {
                println!("New connection: {}", addr);
                let mut buffer = [0; 512]; // maximum 512 bytes for handshake
                match stream.read(&mut buffer) {
                    Ok(n) => {
                        match Handshake::from_bytes(&buffer[0..n]) {
                            Ok(handshake) => {
                                let (connection, peers) = match zelf.read().unwrap().verify_handshake(addr, stream, handshake, out) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        println!("Error while verifying handshake from {}", addr);
                                        return;
                                    }
                                };

                                // if it's a outgoing connection, don't send the handshake back
                                // because we have already sent it
                                if !out {
                                    let handshake = zelf.read().unwrap().build_handshake(); // TODO don't send same peers list
                                    connection.send_bytes(&handshake.to_bytes()); // send handshake back
                                }

                                // if we reach here, handshake is all good, we can start listening this new peer
                                let zelf_clone = zelf.clone();
                                thread::spawn(move || {
                                    P2pServer::listen_connection(zelf_clone, connection);
                                });

                                // try to extend our peer list
                                for peer in peers {
                                    P2pServer::connect_to_peer(zelf.clone(), peer);
                                }
                            },
                            Err(e) => println!("Invalid handshake request: {}", e)
                        }
                    },
                    Err(e) => println!("Error while reading handshake: {}", e)
                }
            }
            Err(e) => println!("Error while retrieving peer address: {}", e)
        };
    }

    fn listen_connection(zelf: Arc<RwLock<P2pServer>>, connection: Connection) {
        let peer_id = connection.get_peer_id();
        let connection = Arc::new(connection);
        zelf.write().unwrap().add_connection(peer_id, connection.clone()); // register this connection to the server

        // TODO extend buffer as we have verified this peer
        let mut buf: [u8; 512] = [0; 512]; // allocate this buffer only one time
        loop {
            match connection.read_bytes(&mut buf) {
                Ok(0) => {
                    zelf.write().unwrap().remove_connection(&peer_id);
                    println!("{} disconnected", connection);
                    break;
                },
                Ok(n) => {
                    println!("Received from {}: {}", connection, String::from_utf8_lossy(&buf[0..n]));

                    // TODO manage all packets here
                }
                Err(e) => {
                    zelf.write().unwrap().remove_connection(&peer_id);
                    println!("An error has occured while reading bytes from {}: {}", connection, e);
                }
            }
        }
    }
}