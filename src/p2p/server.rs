use std::io::prelude::*;
use std::net::{TcpListener, TcpStream, SocketAddr};
use crate::core::thread_pool::ThreadPool;
use super::connection::Connection;
use std::sync::{Arc, Mutex, RwLock};
use crate::core::block::CompleteBlock;
use super::handshake::Handshake;
use crate::config::{VERSION, NETWORK_ID, SEED_NODES};
use crate::crypto::hash::Hash;
use crate::globals::get_current_time;

const MAX_PEERS: usize = 8;

pub struct P2pServer {
    //thread_pool: ThreadPool,
    bind_address: String,
    connections: Vec<Arc<Mutex<Connection>>>
}

impl P2pServer {
    pub fn new(thread_pool_size: usize, bind_address: String) -> Self {
        P2pServer {
            //thread_pool: ThreadPool::new(thread_pool_size),
            bind_address,
            connections: vec![],
        }
    }

    pub fn start(mut self) {
        println!("Connecting to seed nodes...");
        for peer in SEED_NODES {
            let addr: SocketAddr = peer.parse().unwrap();
            //self.connect_to_peer(addr);
        }

        println!("Starting p2p server...");
        let listener = TcpListener::bind(&self.bind_address).unwrap();
        println!("Waiting for connections...");
        let arc = Arc::new(RwLock::new(self));
        let test = arc.clone();
        let mut thread_pool = ThreadPool::new(MAX_PEERS);
        for stream in listener.incoming() { // main thread verify all new connections
            if test.read().unwrap().get_peer_count() >= MAX_PEERS { // if we have already reached the limit, we ignore this new connection
                println!("SKIPPED!!");
                continue;
            }

            println!("NEW STREAM!!");
            match stream {
                Ok(stream) => {
                    let zelf = arc.clone();
                    P2pServer::handle_new_connection(zelf, stream, &mut thread_pool);
                }
                Err(e) => {
                    println!("Error while accepting new connection: {}", e);
                }
            }
        }
    }

    pub fn get_peer_count(&self) -> usize {
        self.connections.len()
    }

    pub fn is_connected_to(&self, peer_addr: &SocketAddr) -> bool {
        for connection in &self.connections {
            if *connection.lock().unwrap().get_peer_address() == *peer_addr {
                return true
            }
        }

        false
    }

    pub fn broadcast_block(&mut self, block: &CompleteBlock) {
        use crate::crypto::hash::Hashable;
        for connection in &mut self.connections {
            connection.lock().unwrap().send_bytes(&block.to_bytes());
        }
    }

    fn add_connection(&mut self, connection: Arc<Mutex<Connection>>) {
        self.connections.push(connection);
        println!("add new connection (total {}): {}", self.connections.len(), self.bind_address);
    }

    fn remove_connection(&mut self, peer_id: u64) -> bool {
        match self.connections.iter().position(|c| c.lock().unwrap().get_peer_id() == peer_id) {
            Some(index) => self.connections.remove(index),
            None => return false,
        };

        true
    }

    fn connect_to_peer(zelf: Arc<RwLock<P2pServer>>, peer_addr: SocketAddr, thread_pool: &mut ThreadPool) {
        println!("Trying to connect to {}", peer_addr);
        match TcpStream::connect(&peer_addr) {
            Ok(mut stream) => {
                let handshake = Handshake::new(VERSION.to_owned(), None, NETWORK_ID, 0, get_current_time(), 0, Hash::zero(), vec![]);
                println!("Sending handshake from server");
                match stream.write(&handshake.to_bytes()) {
                    Ok(_) => {
                        match stream.flush() {
                            Ok(_) => {
                                let connection = handshake.create_connection(stream, peer_addr, true);
                                P2pServer::listen_connection(zelf, connection, thread_pool);
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

    fn handle_new_connection(zelf: Arc<RwLock<P2pServer>>, mut stream: TcpStream, thread_pool: &mut ThreadPool) {
        match stream.peer_addr() {
            Ok(addr) => {
                println!("New connection: {}", addr);
                let mut buffer = [0; 512]; // maximum 512 bytes for handshake
                match stream.read(&mut buffer) {
                    Ok(n) => {
                        match Handshake::from_bytes(&buffer[0..n]) {
                            Ok(handshake) => {
                                if *handshake.get_network_id() != NETWORK_ID {
                                    println!("Invalid Network ID");
                                    return;
                                }
                                // TODO check block height, check if top hash is equal to block height

                                println!("Handshake OK: {}", handshake);
                                let peers = handshake.get_peers();
                                let mut index = 0;
                                while index < peers.len() && zelf.read().unwrap().get_peer_count() + 1 < MAX_PEERS {
                                    let peer_addr: SocketAddr = match peers[index].parse() {
                                        Ok(addr) => addr,
                                        Err(e) => {
                                            println!("Invalid Peer address received: {}, error: {}", peers[index], e);
                                            return;
                                        }
                                    };

                                    if addr != peer_addr /*&& !zelf.read().unwrap().is_connected_to(&peer_addr)*/ { // TODO
                                        // We try to connect to it
                                        P2pServer::connect_to_peer(zelf.clone(), peer_addr, thread_pool);
                                    }
                                    index += 1;
                                }

                                // TODO send handshake response
                                let connection = handshake.create_connection(stream, addr, false);
                                P2pServer::listen_connection(zelf, connection, thread_pool);
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

    fn listen_connection(zelf: Arc<RwLock<P2pServer>>, connection: Connection, thread_pool: &mut ThreadPool) {
        let peer_id = connection.get_peer_id();
        let connection = Arc::new(Mutex::new(connection));
        zelf.write().unwrap().add_connection(connection.clone());

        let mut buf: [u8; 512] = [0; 512];
        thread_pool.execute(move || {
            loop {
                println!("Read from: {}", connection.lock().unwrap());
                match connection.lock().unwrap().read_bytes(&mut buf) {
                    Ok(0) => {
                        zelf.write().unwrap().remove_connection(peer_id);
                        println!("closed connection safely");
                    },
                    Ok(n) => {
                        println!("Received from client: {}", String::from_utf8_lossy(&buf[0..n]));
                    }
                    Err(e) => {
                        zelf.write().unwrap().remove_connection(peer_id);
                        println!("read error!!! {}", e);
                    }
                }
            }
        });
    }
}