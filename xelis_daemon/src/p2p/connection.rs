use super::{
    encryption::Encryption,
    error::P2pError,
    packet::Packet
};
use std::{
    convert::TryInto,
    fmt::{Display, Error, Formatter},
    net::SocketAddr,
    sync::atomic::{
        AtomicBool,
        AtomicUsize,
        Ordering
    },
    time::Duration
};
use human_bytes::human_bytes;
use humantime::format_duration;
use tokio::{
    net::{
        TcpStream,
        tcp::{OwnedWriteHalf, OwnedReadHalf}
    },
    sync::{mpsc, Mutex},
    io::{AsyncWriteExt, AsyncReadExt},
};
use xelis_common::{
    time::{TimestampSeconds, get_current_time_in_seconds},
    serializer::{Reader, Serializer},
};
use bytes::Bytes;
use log::{trace, warn};

pub enum ConnectionMessage {
    Packet(Bytes),
    Exit
}

pub type Tx = mpsc::UnboundedSender<ConnectionMessage>;
pub type Rx = mpsc::UnboundedReceiver<ConnectionMessage>;

type P2pResult<T> = Result<T, P2pError>;

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    Pending, // connection is new, no handshake received
    Handshake, // handshake received, not checked
    Success // handshake is valid
}

pub struct Connection {
    state: State,
    // write to stream
    write: Mutex<OwnedWriteHalf>,
    // read from stream
    read: Mutex<OwnedReadHalf>,
    // TCP Address
    addr: SocketAddr,
    // Tx to send bytes
    tx: Mutex<Tx>,
    // Rx to read bytes to send
    rx: Mutex<Rx>,
    // total bytes read
    bytes_in: AtomicUsize,
    // total bytes sent
    bytes_out: AtomicUsize,
    // when the connection was established
    connected_on: TimestampSeconds,
    // if Connection#close() is called, close is set to true
    closed: AtomicBool,
    // Encryption state used for packets
    encryption: Mutex<Encryption>
}

impl Connection {
    pub fn new(stream: TcpStream, addr: SocketAddr) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
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
            closed: AtomicBool::new(false),
            encryption: Mutex::new(Encryption::new())
        }
    }

    pub fn get_tx(&self) -> &Mutex<Tx> {
        &self.tx
    }

    pub fn get_rx(&self) -> &Mutex<Rx> {
        &self.rx
    }

    // Send bytes to the peer
    // Encrypt must be used all time except for the handshake
    pub async fn send_bytes(&self, packet: &[u8], encrypt_buffer: Option<&mut [u8]>) -> P2pResult<()> {
        let mut stream = self.write.lock().await;
        if let Some(buffer) = encrypt_buffer {
            let mut encryption = self.encryption.lock().await;
            encryption.encrypt_packet(packet, buffer)?;
            stream.write_all(buffer).await?;
        } else {
            stream.write_all(packet).await?;
        }

        self.bytes_out.fetch_add(packet.len(), Ordering::Relaxed);
        stream.flush().await?;
        Ok(())
    }

    // Read packet bytes from the stream
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

    pub async fn read_packet_from_bytes(&self, bytes: &[u8]) -> P2pResult<Packet<'static>> {
        let mut reader = Reader::new(&bytes);
        let packet = Packet::read(&mut reader)?;
        if reader.total_read() != bytes.len() {
            warn!("read {:?} only {}/{} on bytes available from {}", packet, reader.total_read(), bytes.len(), self);
            return Err(P2pError::InvalidPacketNotFullRead)
        }
        Ok(packet)
    }

    pub async fn read_packet(&self, buf: &mut [u8], max_size: u32) -> P2pResult<Packet<'static>> {
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
        let mut read = 0;
        let buf_len = buf.len();
        // Packet may have been fragmented, try to read it completely
        while read < buf_len {
            let result = stream.read(&mut buf[read..]).await?;
            match result {
                0 => {
                    return Err(P2pError::Disconnected);
                }
                n => {
                    read += n;
                }
            }
        }
        self.bytes_in.fetch_add(read, Ordering::Relaxed);

        // If it's a peer, and that the handshake was done, we decrypt the packet
        if self.state == State::Success {
            let encryption = self.encryption.lock().await;
            encryption.decrypt_packet(&mut buf[0..read])?;
        }

        Ok(read)
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

    pub fn connected_on(&self) -> TimestampSeconds {
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