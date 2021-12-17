use crate::core::block::CompleteBlock;
use crate::crypto::hash::Hashable;
use crate::config::{VERSION, NETWORK_ID, SEED_NODES};
use crate::crypto::hash::Hash;
use crate::globals::get_current_time;
use crate::core::thread_pool::ThreadPool;
use super::connection::Connection;
use super::handshake::Handshake;
use super::error::P2pError;
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::io::prelude::{Write, Read};
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream, SocketAddr, Shutdown};

pub struct P2pServer {
    peer_id: u64, // unique peer id
    tag: Option<String>, // node tag sent on handshake
    max_peers: usize,
    multi_threaded: bool,
    bind_address: String,
    thread_pool: Mutex<ThreadPool>,
    connections: HashMap<u64, Arc<Connection>>
}

impl P2pServer {
    pub fn new(peer_id: u64, tag: Option<String>, max_peers: usize, multi_threaded: bool, bind_address: String) -> Self {
        if let Some(tag) = &tag {
            assert!(tag.len() > 0 && tag.len() <= 16);
        }

        let threads = if multi_threaded {
            max_peers + 1 // 1 thread for new incoming connections
        } else {
            2 // 1 thread for new incoming connections + 1 thread for listening connections
        };

        P2pServer {
            peer_id,
            tag,
            max_peers,
            multi_threaded,
            bind_address,
            thread_pool: Mutex::new(ThreadPool::new(threads)),
            connections: HashMap::new(),
        }
    }

    pub fn start(self) {
        let arc = Arc::new(RwLock::new(self));

        // main thread
        let arc_clone = arc.clone();
        arc.read().unwrap().thread_pool.lock().unwrap().execute(move || {
            let arc = arc_clone;
            println!("Connecting to seed nodes..."); // TODO only if peerlist is empty
            // allocate this buffer only one time, because we are using the same thread
            let mut buffer: [u8; 512] = [0; 512]; // maximum 512 bytes for handshake
            for peer in SEED_NODES {
                let addr: SocketAddr = peer.parse().unwrap();
                let zelf = arc.clone();
                if let Err(e) = P2pServer::connect_to_peer(zelf, &mut buffer, addr) {
                    println!("Error while trying to connect to seed node '{}': {}", peer, e);
                }
            }

            println!("Starting p2p server...");
            let listener = TcpListener::bind(arc.read().unwrap().get_bind_address()).unwrap();

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

                        if let Err(e) = P2pServer::handle_new_connection(zelf, &mut buffer, stream, false) {
                            println!("Error on new connection: {}", e);
                        }
                    }
                    Err(e) => {
                        println!("Error while accepting new connection: {}", e);
                    }
                }
            }
        });

        // listening connections thread
        {
            let lock = arc.read().unwrap();
            if !lock.is_multi_threaded() {
                let arc_clone = arc.clone();
                println!("Starting single thread connection listener...");
                lock.thread_pool.lock().unwrap().execute(move || {
                    // TODO extend buffer as we have verified this peer
                    let mut buf: [u8; 512] = [0; 512]; // allocate this buffer only one time
                    loop {
                        for connection in arc_clone.read().unwrap().get_connections() { // TODO Lock occure here! 
                            P2pServer::listen_connection(&arc_clone, &mut buf, &connection)
                        }
                    }
                });
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

    pub fn is_multi_threaded(&self) -> bool {
        self.multi_threaded
    }

    pub fn get_bind_address(&self) -> &String {
        &self.bind_address
    }

    // Send a block too all connected peers (block propagation)
    pub fn broadcast_block(&self, block: &CompleteBlock) -> Result<(), P2pError> {
        for connection in self.get_connections() {
            connection.send_bytes(&block.to_bytes())?;
        }

        Ok(())
    }

    pub fn broadcast_block_except(&self, block: &CompleteBlock, peer_id: u64) -> Result<(), P2pError> {
        for connection in self.get_connections() {
            if connection.get_peer_id() != peer_id {
                connection.send_bytes(&block.to_bytes())?;
            }
        }

        Ok(())
    }

    fn add_connection(&mut self, connection: Arc<Connection>) {
        let peer_id = connection.get_peer_id();
        match self.connections.insert(peer_id, connection) {
            Some(_) => {
                panic!("Peer ID '{}' is already used!", peer_id); // should not happen
            },
            None => {}
        }
        println!("add new connection (total {}): {}", self.connections.len(), self.bind_address);
    }

    fn remove_connection(&mut self, peer_id: &u64) -> bool {
        println!("removing peer {}", peer_id);
        match self.connections.remove(peer_id) {
            Some(connection) => {
                if !connection.is_closed() {
                    if let Err(e) = connection.close() {
                        println!("Error while closing connection: {}", e);
                    }
                }
                println!("{} disconnected", connection);

                true
            },
            None => false,
        }
    }

    fn get_connections(&self) -> Vec<&Arc<Connection>> {
        self.connections.values().collect()
    }

    fn build_handshake(&self) -> Handshake {
        let mut peers = vec![];
        let mut iter = self.connections.values();
        while peers.len() < Handshake::MAX_LEN {
            match iter.next() {
                Some(v) => {
                    if !v.is_out() { // don't send our clients
                        peers.push(format!("{}", v.get_peer_address()));
                    }
                },
                None => break
            };
        }

        // TODO set correct params: block height, top block hash
        Handshake::new(VERSION.to_owned(), self.tag.clone(), NETWORK_ID, self.peer_id, get_current_time(), 0, Hash::zero(), peers)
    }

    // Verify handshake send by a new connection
    // based on data size, network ID, peers address validity
    // block height and block top hash of this peer (to know if we are on the same chain)
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

    fn connect_to_peer(zelf: Arc<RwLock<P2pServer>>, buffer: &mut [u8], peer_addr: SocketAddr) -> Result<(), P2pError> {
        println!("Trying to connect to {}", peer_addr);
        match TcpStream::connect(&peer_addr) {
            Ok(mut stream) => {
                let handshake: Handshake = zelf.read().unwrap().build_handshake();
                println!("Sending handshake from server");
                if let Err(e) = stream.write(&handshake.to_bytes()) {
                    return Err(P2pError::OnWrite(format!("{}", e)));
                }

                // wait on Handshake reply & manage this new connection
                P2pServer::handle_new_connection(zelf, buffer, stream, true)?;
            },
            Err(e) => {
                println!("Error while connecting to a new peer: {}", e);
            }
        };

        Ok(())
    }

    // this function handle all new connection on main thread
    // A new connection have to send an Handshake
    // if the handshake is valid, we accept it & register it on server
    fn handle_new_connection(zelf: Arc<RwLock<P2pServer>>, buffer: &mut [u8], mut stream: TcpStream, out: bool) -> Result<(), P2pError> {
        match stream.peer_addr() {
            Ok(addr) => {
                println!("New connection: {}", addr);
                match stream.read(buffer) {
                    Ok(n) => {
                        let handshake = Handshake::from_bytes(&buffer[0..n])?;
                        let (connection, peers) = zelf.read().unwrap().verify_handshake(addr, stream, handshake, out)?;

                        // if it's a outgoing connection, don't send the handshake back
                        // because we have already sent it
                        if !out {
                            let handshake = zelf.read().unwrap().build_handshake(); // TODO don't send same peers list
                            connection.send_bytes(&handshake.to_bytes())?; // send handshake back
                        }

                        // if we reach here, handshake is all good, we can start listening this new peer
                        let peer_id = connection.get_peer_id(); // keep in memory the peer_id outside connection (because of moved value)
                        let arc_connection = Arc::new(connection);

                        // handle connection
                        {
                            let lock = zelf.read().unwrap(); 
                            if lock.is_multi_threaded() {
                                let zelf_clone = zelf.clone();
                                // 1 thread = 1 client
                                lock.thread_pool.lock().unwrap().execute(move || {
                                    println!("Adding connection to multithread mode!");
                                    // TODO extend buffer as we have verified this peer
                                    let mut connection_buf: [u8; 512] = [0; 512]; // allocate this buffer only one time
                                    while !arc_connection.is_closed() {
                                        // if this is considered as disconnected, stop looping on it
                                        P2pServer::listen_connection(&zelf_clone, &mut connection_buf, &arc_connection);
                                    }
                                });
                            } else {
                                drop(lock);
                                // set stream no-blocking for single thread
                                match arc_connection.set_blocking(false) {
                                    Ok(_) => {
                                        // register this connection to the server
                                        zelf.write().unwrap().add_connection(arc_connection.clone());
                                        println!("Connection added in singlethread mode!");
                                    },
                                    Err(e) => {
                                        println!("Error while trying to set Connection to no-blocking: {}", e);
                                        let _ = arc_connection.close(); // can't support non blocking ? remove connection
                                    }
                                }
                            }
                        }

                        // try to extend our peer list
                        for peer in peers {
                            if let Err(e) = P2pServer::connect_to_peer(zelf.clone(), buffer, peer) {
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

    // Listen to incoming packets from a connection
    // return true if it should be considered as disconnected
    fn listen_connection(zelf: &Arc<RwLock<P2pServer>>, buf: &mut [u8], connection: &Arc<Connection>) {
        match connection.read_bytes(buf) {
            Ok(0) => {
                zelf.write().unwrap().remove_connection(&connection.get_peer_id());
                println!("{} disconnected", connection);
            },
            Ok(n) => {
                //println!("{}: {}", connection, String::from_utf8_lossy(&buf[0..n]));
                for connection in zelf.read().unwrap().get_connections() {
                    if let Err(e) = connection.send_bytes(&buf[0..n]) {
                        println!("Error while trying to send bytes: {}", e);
                         // Peer have maybe disconnected
                        zelf.write().unwrap().remove_connection(&connection.get_peer_id());
                    }
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => { // shouldn't happens if server is multithreaded
                // Don't do anything
            },
            Err(e) => {
                zelf.write().unwrap().remove_connection(&connection.get_peer_id());
                println!("An error has occured while reading bytes from {}: {}", connection, e);
            }
        };
    }
}