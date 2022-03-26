use crate::globals::get_current_time;
use super::error::P2pError;
use std::net::{TcpStream, SocketAddr, Shutdown};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, AtomicU8, AtomicU64, Ordering};
use std::io::{Write, Read, Result};
use std::convert::TryInto;

type P2pResult<T> = std::result::Result<T, P2pError>;

pub struct Connection {
    id: u64, // TODO use a UUID
    node_tag: Option<String>, // Node tag if provided
    version: String, // daemon version
    block_height: AtomicU64, // current block height for this peer
    stream: Mutex<TcpStream>, // Stream for read & write
    addr: SocketAddr, // TCP Address
    out: bool, // True mean we are the client
    bytes_in: AtomicUsize, // total bytes read
    bytes_out: AtomicUsize, // total bytes sent
    connected_on: u64,
    // TODO last_fail_count
    fail_count: AtomicU8, // fail count: if greater than 20, we should close this connection
    closed: AtomicBool, // if Connection#close() is called, close is set to true
    blocking: AtomicBool // blocking until something is sent or not
}

impl Connection {
    pub fn new(id: u64, node_tag: Option<String>, version: String, block_height: u64, stream: TcpStream, addr: SocketAddr, out: bool) -> Self {
        Connection {
            id,
            node_tag,
            version,
            block_height: AtomicU64::new(block_height),
            stream: Mutex::new(stream),
            addr,
            out,
            connected_on: get_current_time(),
            bytes_in: AtomicUsize::new(0),
            bytes_out: AtomicUsize::new(0),
            fail_count: AtomicU8::new(0),
            closed: AtomicBool::new(false),
            blocking: AtomicBool::new(true)
        }
    }

    // Set the connection thread blocking or not
    pub fn set_blocking(&self, blocking: bool) -> P2pResult<()> {
        match self.stream.lock() {
            Ok(stream) => {
                match stream.set_nonblocking(!blocking) {
                    Ok(_) => {
                        self.blocking.store(blocking, Ordering::Relaxed);
                        Ok(())
                    }
                    Err(e) => Err(P2pError::OnStreamBlocking(blocking, format!("{}", e)))
                }
            },
            Err(_) => Err(P2pError::OnLock)
        }
    }

    pub fn send_bytes(&self, buf: &[u8]) -> P2pResult<()> {
        match self.stream.lock() {
            Ok(mut lock) => match lock.write(buf) {
                Ok(_) => {
                    self.bytes_out.fetch_add(buf.len(), Ordering::Relaxed);
                    match lock.flush() {
                        Ok(_) => Ok(()),
                        Err(e) => Err(P2pError::OnWrite(format!("{}", e)))
                    }
                },
                Err(e) => Err(P2pError::OnWrite(format!("{}", e)))
            },
            Err(_) => Err(P2pError::OnLock)
        }
    }

    pub fn read_packet_size(&self, buf: &mut [u8]) -> Result<(usize, u32)> {
        let read = self.read_bytes(&mut buf[0..4])?;
        let array: [u8; 4] = match buf[0..4].try_into() {
            Ok(v) => v,
            Err(_) => panic!("TODO") // TODO
        };
        let size = u32::from_be_bytes(array);
        Ok((read, size))
    }

    pub fn read_all_bytes(&self, buf: &mut [u8], mut left: u32) -> Result<Vec<u8>> {
        let buf_size = buf.len();
        let mut bytes = Vec::new();
        while left > 0 {
            let max = if buf_size as u32 > left {
                left as usize
            } else {
                buf_size
            };

            let read = self.read_bytes(&mut buf[0..max])?;
            if read == 0 {
                break; // TODO error
            }
            left -= read as u32;
            bytes.extend(&buf[0..read]);
        }
        Ok(bytes)
    }

    // this function will wait until something is sent to the socket
    // this return the size of data read & set in the buffer.
    pub fn read_bytes(&self, buf: &mut [u8]) -> Result<usize> {
        let result = self.stream.lock().unwrap().read(buf);
        match &result {
            Ok(0) => {
                self.close()?;
            }
            Ok(n) => {
                self.bytes_in.fetch_add(*n, Ordering::Relaxed);
            },
            _ => {}
        };
        result
    }

    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Relaxed);
        self.stream.lock().unwrap().shutdown(Shutdown::Both)
    }

    // TODO verify last fail count
    pub fn increment_fail_count(&self) {
        self.fail_count.fetch_add(1, Ordering::Relaxed);
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
        self.block_height.load(Ordering::Relaxed)
    }

    pub fn set_block_height(&self, height: u64) {
        self.block_height.store(height, Ordering::Relaxed);
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

    pub fn connected_on(&self) -> u64 {
        self.connected_on
    }

    pub fn fail_count(&self) -> u8 {
        self.fail_count.load(Ordering::Relaxed)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub fn is_blocking(&self) -> bool {
        self.blocking.load(Ordering::Relaxed)
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

        write!(f, "Connection[peer: {}, version: {}, node tag: {}, peer_id: {}, block_height: {}, out: {}, read: {} kB, sent: {} kB, connected on: {}, fail count: {}, closed: {},  blocking: {}]", self.get_peer_address(), self.get_version(), node_tag, self.get_peer_id(), self.get_block_height(), self.is_out(), self.bytes_in() / 1024, self.bytes_out() / 1024, self.connected_on(), self.fail_count(), self.is_closed(), self.is_blocking())
    }
}