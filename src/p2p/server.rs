use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
use crate::core::thread_pool::ThreadPool;
use super::connection::Connection;
use std::sync::Arc;
use std::sync::Mutex;
use crate::core::block::CompleteBlock;
use super::handshake::Handshake;
use crate::config::NETWORK_ID;

pub struct P2pServer {
    connections: Vec<Connection>
}

impl P2pServer {
    pub fn new() -> Self { // TODO config (thread pool size, p2p bind...)
        P2pServer {
            connections: vec![],
        }
    }

    pub fn start(self) {
        println!("Starting p2p server...");
        let thread_pool = ThreadPool::new(4); // use 4 threads to accept new connections
        let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
        let arc_self = Arc::new(Mutex::new(self));

        println!("Waiting for connections...");
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let zelf = Arc::clone(&arc_self);
                    thread_pool.execute(move || {
                        P2pServer::handle_new_connection(&zelf, stream);
                    });
                }
                Err(e) => {
                    println!("Error while accepting new connection: {}", e);
                }
            }
        }
    }

    pub fn broadcast_block(&mut self, block: &CompleteBlock) {
        use crate::crypto::hash::Hashable;
        for connection in &mut self.connections {
            connection.send_bytes(&block.to_bytes());
        }
    }

    fn handle_new_connection(server_arc: &Arc<std::sync::Mutex<P2pServer>>, mut stream: TcpStream) {
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
                                }
                                // TODO check block height, check if top hash is equal to block height

                                println!("Handshake OK!");
                                match server_arc.lock() {
                                    Ok(mut server) => {
                                        let connection = handshake.create_connection(stream, addr);
                                        server.connections.push(connection);
                                    }
                                    Err(e) => println!("Error while trying to lock server arc: {}", e)
                                }
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
}