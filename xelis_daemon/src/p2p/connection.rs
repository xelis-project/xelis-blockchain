use super::error::P2pError;
use super::packet::Packet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::net::SocketAddr;
use std::time::Duration;
use human_bytes::human_bytes;
use humantime::format_duration;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedWriteHalf, OwnedReadHalf};
use xelis_common::{
    utils::get_current_time_in_seconds,
    serializer::{Reader, Serializer},
};
use std::fmt::{Display, Error, Formatter};
use tokio::sync::{mpsc, Mutex};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::convert::TryInto;
use bytes::Bytes;
use log::{trace, warn};

pub enum ConnectionMessage {
    Packet(Bytes),
    Exit
}

pub type Tx = mpsc::UnboundedSender<ConnectionMessage>;
pub type Rx = mpsc::UnboundedReceiver<ConnectionMessage>;

type P2pResult<T> = std::result::Result<T, P2pError>;

pub enum State {
    Pending, // connection is new, no handshake received
    Handshake, // handshake received, not checked
    Success // handshake is valid
}

pub struct Connection {
    state: State,
    write: Mutex<OwnedWriteHalf>, // write to stream
    read: Mutex<OwnedReadHalf>, // read from stream
    addr: SocketAddr, // TCP Address
    tx: Mutex<Tx>, // Tx to send bytes
    rx: Mutex<Rx>, // Rx to read bytes to send
    bytes_in: AtomicUsize, // total bytes read
    bytes_out: AtomicUsize, // total bytes sent
    connected_on: u64,
    closed: AtomicBool, // if Connection#close() is called, close is set to true
}

impl Connection {
    pub fn new(stream: TcpStream, addr: SocketAddr) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Err(e) = stream.set_nodelay(true) {
            warn!("Failed to set nodelay on connection {}: {}", addr, e);
        }

        let (read, write) = stream.into_split();
        Self {
            state: State::Pending,
            write: Mutex::new(write),
            read: Mutex::new(read),
            addr,
            tx: Mutex::new(tx),
            rx: Mutex::new(rx),
            connected_on: get_current_time_in_seconds(),
            bytes_in: AtomicUsize::new(0),
            bytes_out: AtomicUsize::new(0),
            closed: AtomicBool::new(false)
        }
    }

    pub fn get_tx(&self) -> &Mutex<Tx> {
        &self.tx
    }

    pub fn get_rx(&self) -> &Mutex<Rx> {
        &self.rx
    }

    pub async fn send_bytes(&self, buf: &[u8]) -> P2pResult<()> {
        let mut stream = self.write.lock().await;
        stream.write_all(buf).await?;
        self.bytes_out.fetch_add(buf.len(), Ordering::Relaxed);
        stream.flush().await?;
        Ok(())
    }

    pub async fn read_packet_bytes(&self, buf: &mut [u8], max_size: u32) -> P2pResult<Vec<u8>> {
        let mut stream = self.read.lock().await;
        let size = self.read_packet_size(&mut stream, buf).await?;
        if size == 0 || size > max_size {
            warn!("Received invalid packet size: {} bytes (max: {} bytes) from peer {}", size, max_size, self.get_address());
            return Err(P2pError::InvalidPacketSize)
        }
        trace!("Size received: {}", size);

        let bytes = self.read_all_bytes(&mut stream, buf, size).await?;
        Ok(bytes)
    }

    pub async fn read_packet_from_bytes(&self, bytes: &[u8]) -> P2pResult<Packet<'_>> {
        let mut reader = Reader::new(&bytes);
        let packet = Packet::read(&mut reader)?;
        if reader.total_read() != bytes.len() {
            warn!("read {:?} only {}/{} on bytes available from {}", packet, reader.total_read(), bytes.len(), self);
            return Err(P2pError::InvalidPacketNotFullRead)
        }
        Ok(packet)
    }

    pub async fn read_packet(&self, buf: &mut [u8], max_size: u32) -> P2pResult<Packet<'_>> {
        let bytes = self.read_packet_bytes(buf, max_size).await?;
        self.read_packet_from_bytes(&bytes).await
    }

    async fn read_packet_size(&self, stream: &mut OwnedReadHalf, buf: &mut [u8]) -> P2pResult<u32> {
        let read = self.read_bytes_from_stream(stream, &mut buf[0..4]).await?;
        if read != 4 {
            warn!("Received invalid packet size: expected to read 4 bytes but read only {} bytes from peer {}", read, self.get_address());
            warn!("Read: {:?}", &buf[0..read]);
            return Err(P2pError::InvalidPacketSize)
        }
        let array: [u8; 4] = buf[0..4].try_into()?;
        let size = u32::from_be_bytes(array);
        Ok(size)
    }

    async fn read_all_bytes(&self, stream: &mut OwnedReadHalf, buf: &mut [u8], mut left: u32) -> P2pResult<Vec<u8>> {
        let buf_size = buf.len() as u32;
        let mut bytes = Vec::new();
        while left > 0 {
            let max = if buf_size > left {
                left as usize
            } else {
                buf_size as usize
            };
            let read = self.read_bytes_from_stream(stream, &mut buf[0..max]).await?;
            left -= read as u32;
            bytes.extend(&buf[0..read]);
        }
        Ok(bytes)
    }

    // this function will wait until something is sent to the socket if it's in blocking mode
    // this return the size of data read & set in the buffer.
    // used to only lock one time the stream and read on it
    async fn read_bytes_from_stream(&self, stream: &mut OwnedReadHalf, buf: &mut [u8]) -> P2pResult<usize> {
        let result = stream.read(buf).await?;
        match result {
            0 => {
                Err(P2pError::Disconnected)
            }
            n => {
                self.bytes_in.fetch_add(n, Ordering::Relaxed);
                Ok(n)
            }
        }
    }

    pub async fn close(&self) -> P2pResult<()> {
        self.closed.store(true, Ordering::Relaxed);
        let tx = self.get_tx().lock().await;
        tx.send(ConnectionMessage::Exit)?; // send a exit message to stop the current lock of stream
        let mut stream = self.write.lock().await;
        stream.shutdown().await?; // sometimes the peer is not removed on other peer side
        Ok(())
    }

    pub fn set_state(&mut self, state: State) {
        self.state = state;
    }

    pub fn get_address(&self) -> &SocketAddr {
        &self.addr
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

    pub fn get_human_uptime(&self) -> String {
        let elapsed_seconds = get_current_time_in_seconds() - self.connected_on();
        format_duration(Duration::from_secs(elapsed_seconds)).to_string()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

impl Display for Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error> {
        write!(f, "Connection[peer: {}, read: {}, sent: {}, connected since: {}, closed: {}]", self.get_address(), human_bytes(self.bytes_in() as f64), human_bytes(self.bytes_out() as f64), self.get_human_uptime(), self.is_closed())
    }
}