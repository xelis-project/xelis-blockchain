use std::io::prelude::{Write, Read};
use std::net::{TcpListener, TcpStream, SocketAddr, Shutdown};
use std::thread;
use super::connection::Connection;
use std::sync::{Arc, RwLock};
use crate::core::block::CompleteBlock;
use super::handshake::Handshake;
use crate::config::{VERSION, NETWORK_ID, SEED_NODES};
use crate::crypto::hash::Hash;
use crate::globals::get_current_time;
use std::collections::HashMap;

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
         // TODO configurable: max clients
        let arc = Arc::new(RwLock::new(self));

        /*println!("Connecting to seed nodes..."); // TODO only if peerlist is empty
        for peer in SEED_NODES {
            let addr: SocketAddr = peer.parse().unwrap();
            let zelf = arc.clone();
            P2pServer::connect_to_peer(zelf, addr);
        }*/

        println!("Waiting for connections...");
        for stream in listener.incoming() { // main thread verify all new connections
            println!("NEW STREAM!!");
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

                    P2pServer::handle_new_connection(zelf, stream);
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

    pub fn broadcast_block(&mut self, block: &CompleteBlock) {
        use crate::crypto::hash::Hashable;
        for connection in &mut self.connections.values() {
            connection.send_bytes(&block.to_bytes());
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
                if let Err(e) = connection.close() {
                    println!("Error while closing connection: {}", e);
                }
                true
            },
            None => false,
        }
    }

    fn build_handshake(&self) -> Handshake {
        // TODO build peers list
        Handshake::new(VERSION.to_owned(), self.tag.clone(), NETWORK_ID, self.peer_id, get_current_time(), 0, Hash::zero(), vec![])
    }

    fn connect_to_peer(zelf: Arc<RwLock<P2pServer>>, peer_addr: SocketAddr) {
        println!("Trying to connect to {}", peer_addr);
        match TcpStream::connect(&peer_addr) {
            Ok(mut stream) => {
                let handshake: Handshake = zelf.read().unwrap().build_handshake();
                println!("Sending handshake from server");
                match stream.write(&handshake.to_bytes()) {
                    Ok(_) => {
                        match stream.flush() {
                            Ok(_) => {
                                let connection = handshake.create_connection(stream, peer_addr, true);
                                P2pServer::listen_connection(zelf, connection);
                            },
                            Err(e) => {
                                println!("Error while flushing to a new peer {}: {}", peer_addr, e);
                            }
                        };
                    },
                    Err(e) => {
                        println!("Error while sending handshake request to a new peer {}: {}", peer_addr, e);
                    }
                };
            },
            Err(e) => {
                println!("Error while connecting to a new peer: {}", e);
            }
        };
    }

    fn handle_new_connection(zelf: Arc<RwLock<P2pServer>>, mut stream: TcpStream) {
        match stream.peer_addr() {
            Ok(addr) => {
                println!("New connection: {}", addr);
                let mut buffer = [0; 512]; // maximum 512 bytes for handshake
                match stream.read(&mut buffer) {
                    Ok(n) => {
                        match Handshake::from_bytes(&buffer[0..n]) {
                            Ok(handshake) => {
                                println!("Handshake: {}", handshake);
                                if *handshake.get_network_id() != NETWORK_ID {
                                    println!("Invalid Network ID");
                                    return;
                                }

                                if zelf.read().unwrap().is_connected_to(&handshake.get_peer_id()) {
                                    println!("Peer ID '{}' is already used.", handshake.get_peer_id());
                                    if let Err(e) = stream.shutdown(Shutdown::Both) {
                                        println!("Error while rejecting peer: {}", e);
                                    }

                                    return;
                                }

                                // TODO check block height, check if top hash is equal to block height
                                let peers = handshake.get_peers();
                                let mut index = 0;
                                while index < peers.len() && zelf.read().unwrap().accept_new_connections() {
                                    let peer_addr: SocketAddr = match peers[index].parse() {
                                        Ok(addr) => addr,
                                        Err(e) => {
                                            println!("Invalid Peer address received: {}, error: {}", peers[index], e);
                                            return;
                                        }
                                    };

                                    if addr != peer_addr /*&& !zelf.read().unwrap().is_connected_to(&peer_addr)*/ { // TODO
                                        // We try to connect to it
                                        P2pServer::connect_to_peer(zelf.clone(), peer_addr);
                                    }
                                    index += 1;
                                }

                                // TODO send handshake response
                                let connection = handshake.create_connection(stream, addr, false);
                                P2pServer::listen_connection(zelf, connection);
                            },
                            Err(_) => println!("Invalid handshake request")
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
        zelf.write().unwrap().add_connection(peer_id, connection.clone());

        let mut buf: [u8; 512] = [0; 512];
        thread::spawn(move || {
            loop {
                match connection.read_bytes(&mut buf) {
                    Ok(0) => {
                        zelf.write().unwrap().remove_connection(&peer_id);
                        println!("closed connection safely");
                        break;
                    },
                    Ok(n) => {
                        println!("Received from {}: {}", connection, String::from_utf8_lossy(&buf[0..n]));
                    }
                    Err(e) => {
                        zelf.write().unwrap().remove_connection(&peer_id);
                        println!("read error!!! {}", e);
                    }
                }
            }
        });
    }
}