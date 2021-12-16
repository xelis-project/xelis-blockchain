use std::net::{TcpStream, SocketAddr, Shutdown};
use std::io::{Write, Read, Result};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub struct Connection {
    id: u64, // TODO use a UUID
    node_tag: Option<String>, // Node tag if provided
    version: String, // daemon version
    block_height: u64, // current block height for this peer
    stream: Mutex<TcpStream>, // Stream for read & write
    addr: SocketAddr, // TCP Address
    out: bool, // True mean we are the client
    bytes_in: AtomicUsize, // total bytes read
    bytes_out: AtomicUsize, // total bytes sent
    closed: AtomicBool // if Connection#close() is called, close is set to true
}

impl Connection {
    pub fn new(id: u64, node_tag: Option<String>, version: String, block_height: u64, stream: TcpStream, addr: SocketAddr, out: bool) -> Self {
        Connection {
            id,
            node_tag,
            version,
            block_height,
            stream: Mutex::new(stream),
            addr,
            out,
            bytes_in: AtomicUsize::new(0),
            bytes_out: AtomicUsize::new(0),
            closed: AtomicBool::new(false)
        }
    }

    pub fn send_bytes(&self, buf: &[u8]) {
        if let Err(e) = self.stream.lock().unwrap().write(buf) {
            panic!("Error while sending bytes to connection {}: {}", self.id, e);
        }
        self.bytes_out.fetch_add(buf.len(), Ordering::Relaxed);
    }

    pub fn read_bytes(&self, buf: &mut [u8]) -> Result<usize> {
        let result = self.stream.lock().unwrap().read(buf);
        match &result {
            Ok(n) => {
                self.bytes_in.fetch_add(*n, Ordering::Relaxed);
            }
            _ => {}
        };
        result
    }

    pub fn close(&self) -> Result<()> {
        self.closed.store(false, Ordering::Relaxed);
        self.stream.lock().unwrap().shutdown(Shutdown::Both)
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
        self.bytes_out.load(Ordering::Relaxed)
    }

    pub fn bytes_in(&self) -> usize {
        self.bytes_in.load(Ordering::Relaxed)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
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

        write!(f, "Connection[peer: {}, version: {}, node tag: {}, peer_id: {}, block_height: {}, out: {}, read: {} kB, sent: {} kB, closed: {}]", self.get_peer_address(), self.get_version(), node_tag, self.get_peer_id(), self.get_block_height(), self.is_out(), self.bytes_in() / 1024, self.bytes_out() / 1024, self.is_closed())
    }
}