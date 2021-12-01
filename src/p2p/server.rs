use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
//use crate::core::thread_pool::ThreadPool;
use super::connection::Connection;

pub struct P2pServer {
    connections: Vec<Connection>
}

impl P2pServer {

    pub fn new() -> Self { // TODO config
        P2pServer {
            connections: vec![],
        }
    }

    pub fn start(mut self) {
        //let thread_pool = ThreadPool::new(4);
        let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
        for stream in listener.incoming() {
            let stream = stream.unwrap();

            self.handle_new_connection(stream);
        }
    }

    fn handle_new_connection(&mut self, mut stream: TcpStream) {
        println!("New connection: {}", stream.peer_addr().unwrap());
        let mut buffer = [0; 32];
        stream.read(&mut buffer).unwrap();
        println!("Request: {}", String::from_utf8_lossy(&buffer[..]));

        let connection = Connection::new(self.connections.len(), stream);
        self.connections.push(connection);
    }
}