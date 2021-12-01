use std::net::{TcpStream, SocketAddr};
use std::io::{Write, Read, Result};

pub struct Connection {
    id: u64, // TODO use a UUID
    node_tag: Option<String>,
    version: String,
    block_height: u64, // current block height for this peer
    stream: TcpStream,
    addr: SocketAddr,
}

impl Connection {
    pub fn new(id: u64, node_tag: Option<String>, version: String, block_height: u64, stream: TcpStream, addr: SocketAddr) -> Self {
        Connection {
            id,
            node_tag,
            version,
            block_height,
            stream,
            addr
        }
    }

    pub fn send_bytes(&mut self, buf: &[u8]) {
        if let Err(e) = self.stream.write(buf) {
            panic!("Error while sending bytes to connection {}: {}", self.id, e);
        }
    }

    pub fn read_bytes(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream.read(buf)
    }

    pub fn get_peer_id(&self) -> u64 {
        self.id
    }

    pub fn get_node_tag(&self) -> &Option<String> {
        &self.node_tag
    }

    pub fn get_version(&self) -> &String {
        &self.version
    }

    pub fn get_block_height(&self) -> u64 {
        self.block_height
    }

    pub fn get_peer_address(&self) -> &SocketAddr {
        &self.addr
    }
}

