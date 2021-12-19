use crate::config::{VERSION, NETWORK_ID, SEED_NODES};
use crate::crypto::hash::Hash;
use crate::globals::get_current_time;
use crate::core::serializer::Serializer;
use crate::core::transaction::Transaction;
use crate::core::block::CompleteBlock;
use super::connection::Connection;
use super::handshake::Handshake;
use super::error::P2pError;
use std::sync::{Arc};
use std::io::prelude::{Write, Read};
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream, SocketAddr, Shutdown};

pub trait P2pServer {
    fn new(peer_id: u64, tag: Option<String>, max_peers: usize, bind_address: String) -> Self;
    fn start(&self);
    fn stop(&self);
    fn get_peer_id(&self) -> u64;
    fn get_tag(&self) -> &Option<String>;
    fn get_max_peers(&self) -> usize;
    fn get_peer_count(&self) -> usize;
    fn get_slots_available(&self) -> usize;
    fn accept_new_connections(&self) -> bool;
    fn is_multi_threaded(&self) -> bool;
    fn get_bind_address(&self) -> &String;
    fn get_connection(&self, peer_id: &u64) -> Result<Arc<Connection>, P2pError>;
    fn add_connection(&self, connection: Connection) -> Result<(), P2pError>;
    fn remove_connection(&self, peer_id: &u64) -> Result<(), P2pError>;
    fn get_connections(&self) -> Result<Vec<Arc<Connection>>, P2pError>;
    fn get_connections_id(&self) -> Result<Vec<u64>, P2pError>;
    fn is_connected_to(&self, peer_id: &u64) -> Result<bool, P2pError>;
    fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> Result<bool, P2pError>;
    fn send_to_peer(&self, peer_id: u64, bytes: Vec<u8>) -> Result<(), P2pError>;

    // defaults functions

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

    // send bytes in param to all connected peers
    fn broadcast_bytes(&self, buf: &[u8]) -> Result<(), P2pError> {
        for connection in self.get_connections_id()? {
            self.send_to_peer(connection, buf.to_vec())?;
        }
        Ok(())
    }

    fn broadcast_tx(&self, tx: &Transaction) -> Result<(), P2pError> {
        let mut bytes: Vec<u8> = tx.to_bytes();
        bytes.insert(0, 0); // id 0 for tx
        self.broadcast_bytes(&bytes)
    }

    fn broadcast_block(&self, block: &CompleteBlock) -> Result<(), P2pError> {
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
        let connections = self.get_connections()?;
        let mut iter = connections.iter();
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
        Ok(Handshake::new(VERSION.to_owned(), self.get_tag().clone(), NETWORK_ID, self.get_peer_id(), get_current_time(), 0, Hash::zero(), peers))
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

                        // if we reach here, handshake is all good, we can start listening this new peer
                        let peer_id = connection.get_peer_id(); // keep in memory the peer_id outside connection (because of moved value)

                        // handle connection
                        // set stream no-blocking
                        connection.set_blocking(false)?;
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
    fn connect_to_peer(&self, buffer: &mut [u8], peer_addr: SocketAddr) -> Result<(), P2pError> {
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

    // Listen to incoming packets from a connection
    fn listen_connection(&self, buf: &mut [u8], connection: &Arc<Connection>) {
        match connection.read_bytes(buf) {
            Ok(0) => {
                let _ = self.remove_connection(&connection.get_peer_id());
            },
            Ok(n) => {
                let id = buf[0];
                match id {
                    0 => { // TODO tx from bytes

                    },
                    1 => { // TODO block from bytes

                    },
                    _ => println!("Not implemented!")
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => { // shouldn't happens if server is multithreaded
                // Don't do anything
            },
            Err(e) => {
                let _ = self.remove_connection(&connection.get_peer_id());
                println!("An error has occured while reading bytes from {}: {}", connection, e);
            }
        };
    }
}