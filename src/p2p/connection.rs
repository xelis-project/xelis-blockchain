use std::net::{TcpStream, SocketAddr, Shutdown};
use std::io::{Write, Read, Result};

pub struct Connection {
    id: u64, // TODO use a UUID
    node_tag: Option<String>, // Node tag if provided
    version: String, // daemon version
    block_height: u64, // current block height for this peer
    stream: TcpStream, // Stream for read & write
    addr: SocketAddr, // TCP Address
    out: bool, // True mean we are the client
    bytes_in: usize, // total bytes read
    bytes_out: usize // total bytes sent
}

impl Connection {
    pub fn new(id: u64, node_tag: Option<String>, version: String, block_height: u64, stream: TcpStream, addr: SocketAddr, out: bool) -> Self {
        Connection {
            id,
            node_tag,
            version,
            block_height,
            stream,
            addr,
            out,
            bytes_in: 0,
            bytes_out: 0
        }
    }

    pub fn send_bytes(&mut self, buf: &[u8]) {
        if let Err(e) = self.stream.write(buf) {
            panic!("Error while sending bytes to connection {}: {}", self.id, e);
        }
        self.bytes_out += buf.len();
    }

    pub fn read_bytes(&mut self, buf: &mut [u8]) -> Result<usize> {
        let result = self.stream.read(buf);
        match &result {
            Ok(n) => {
                self.bytes_in += n;
            }
            _ => {}
        };
        result
    }

    pub fn clone_stream(&mut self) -> TcpStream {
        self.stream.try_clone().expect("Error while cloning stream")
    }

    pub fn close(&mut self) -> Result<()> {
        self.stream.shutdown(Shutdown::Both)
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

    pub fn is_out(&self) -> bool {
        self.out
    }

    pub fn bytes_out(&self) -> usize {
        self.bytes_out
    }

    pub fn bytes_in(&self) -> usize {
        self.bytes_in
    }
}

use std::fmt::{Display, Error, Formatter};

impl Display for Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error> {
        let node_tag: String = if let Some(value) = self.get_node_tag() {
            value.clone()
        } else {
            String::from("None")
        };

        write!(f, "Connection[version: {}, node tag: {}, peer_id: {}, block_height: {}, out: {}, read: {} kB, sent: {} kB]", self.get_version(), node_tag, self.get_peer_id(), self.get_block_height(), self.is_out(), self.bytes_in / 1024, self.bytes_out / 1024)
    }
}