use crate::config::{PEER_TIMEOUT_DISCONNECT, PEER_TIMEOUT_INIT_CONNECTION, PEER_SEND_BYTES_TIMEOUT};
use super::{
    encryption::Encryption,
    error::P2pError,
    packet::Packet,
    EncryptionKey
};
use std::{
    borrow::Cow,
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
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream
    },
    sync::Mutex,
    time::timeout
};
use xelis_common::{
    time::{TimestampSeconds, get_current_time_in_seconds},
    serializer::{Reader, Serializer},
};
use bytes::Bytes;
use log::{debug, error, trace, warn};

type P2pResult<T> = Result<T, P2pError>;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    Pending, // Connection is new, no handshake received
    KeyExchange, // Start exchanging keys
    Handshake, // Handshake received, not checked
    Success // Connection is ready
}

pub struct Connection {
    // True mean we are the client
    out: bool,
    // State of the connection
    state: State,
    // Write to stream
    write: Mutex<OwnedWriteHalf>,
    // Read from stream
    read: Mutex<OwnedReadHalf>,
    // TCP Address
    addr: SocketAddr,
    // Total bytes read
    bytes_in: AtomicUsize,
    // Total bytes sent
    bytes_out: AtomicUsize,
    // Total bytes sent using current key
    bytes_out_key: AtomicUsize,
    // When the connection was established
    connected_on: TimestampSeconds,
    // If Connection#close() is called, close is set to true
    closed: AtomicBool,
    // How many key rotation we got
    rotate_key_in: AtomicUsize,
    // How many key rotation we sent
    rotate_key_out: AtomicUsize,
    // Encryption state used for packets
    encryption: Encryption
}

// We are rotating every 1GB sent
const ROTATE_EVERY_N_BYTES: usize = 1024 * 1024 * 1024;

impl Connection {
    pub fn new(stream: TcpStream, addr: SocketAddr, out: bool) -> Self {
        let (read, write) = stream.into_split();
        Self {
            out,
            state: State::Pending,
            write: Mutex::new(write),
            read: Mutex::new(read),
            addr,
            connected_on: get_current_time_in_seconds(),
            bytes_in: AtomicUsize::new(0),
            bytes_out: AtomicUsize::new(0),
            bytes_out_key: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            rotate_key_in: AtomicUsize::new(0),
            rotate_key_out: AtomicUsize::new(0),
            encryption: Encryption::new(),
        }
    }

    // Perform a key exchange with the peer.
    // If we're the client, we send our key in plaintext first.
    // We then wait for the peer to send its key.
    // If we're the server, we respond with our key.
    // NOTE: This does not prevent MITM attacks.
    // A MITM could intercept the key and send its own key to the peer, acting as a proxy.
    // Currently, there is no decentralized method to prevent MITM without a third party.
    // TLS/SSL uses CA certificates for this purpose, but it's not decentralized or trustless.
    // One idea is to hardcode seed node keys and have nodes share keys with each other along with their socket addresses.
    pub async fn exchange_keys(&mut self, buffer: &mut [u8]) -> P2pResult<()> {
        trace!("Exchanging keys with {}", self.addr);

        // Update our state
        self.set_state(State::KeyExchange);

        // Send our key if we initiated the connection
        if self.is_out() {
            trace!("Sending our key to {}", self.addr);
            let packet = self.rotate_key_packet().await?;
            self.send_bytes(&packet).await?;
            self.encryption.mark_as_ready();
        }

        trace!("Waiting for key from {}", self.addr);
        // Wait for the peer to receive its key
        let Packet::KeyExchange(peer_key) = timeout(
            Duration::from_millis(PEER_TIMEOUT_INIT_CONNECTION),
            self.read_packet(buffer, 256)
        ).await?? else {
            error!("Expected KeyExchange packet");
            return Err(P2pError::InvalidPacket);
        };

        // Now that we got the peer key, update our encryption state
        self.rotate_peer_key(peer_key.into_owned()).await?;

        // Send back our key if we are the server
        if !self.is_out() {
            trace!("Replying with our key to {}", self.addr);
            let packet = self.rotate_key_packet().await?;
            self.send_bytes(&packet).await?;
            self.encryption.mark_as_ready();
        }

        trace!("Key exchange with {} successful", self.addr);

        Ok(())
    }

    // Verify if its a outgoing connection
    pub fn is_out(&self) -> bool {
        self.out
    }

    // This will send to the peer a packet to rotate the key
    async fn rotate_key_packet(&self) -> P2pResult<Bytes> {
        trace!("rotating our encryption key for peer {}", self.get_address());
        // Generate a new key to use
        let new_key = self.encryption.generate_key();
        // Verify if we already have one set
        
        // Build the packet
        let mut packet = Bytes::from(Packet::KeyExchange(Cow::Borrowed(&new_key)).to_bytes());

        // This is used to determine if we need to encrypt the packet or not
        // Check if we already had a key set, if so, encrypt it
        if self.encryption.is_write_ready().await {
            // Encrypt with the our previous key our new key
            packet = self.encryption.encrypt_packet(&packet).await?.into();
        }

        // Rotate the key in our encryption state
        self.encryption.rotate_key(new_key, true).await?;

        // Increment the key rotation counter
        self.rotate_key_out.fetch_add(1, Ordering::Relaxed);

        // Reset the counter
        self.bytes_out_key.store(0, Ordering::Relaxed);

        Ok(packet)
    }

    // Rotate the peer's symmetric key.
    // Update our state accordingly.
    // Since we're using TCP and packets are processed in sequential order,
    // there's no need to send an ACK to the peer for the key rotation.
    // All subsequent packets will be encrypted with the new key, which we've updated beforehand.
    pub async fn rotate_peer_key(&self, key: EncryptionKey) -> P2pResult<()> {
        trace!("Rotating encryption key of peer {}", self.get_address());
        self.encryption.rotate_key(key, false).await?;
        // Increment the key rotation counter
        self.rotate_key_in.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    // This function will send the packet to the peer without flushing the stream.
    // Packet length is ALWAYS sent in raw (not encrypted).
    // Otherwise, we can't know how much bytes to read for each ciphertext/packet.
    async fn send_packet_bytes_internal(&self, stream: &mut OwnedWriteHalf, packet: &[u8]) -> P2pResult<()> {
        let packet_len = packet.len() as u32;
        stream.write_all(&packet_len.to_be_bytes()).await?;
        stream.write_all(packet).await?;

        Ok(())
    }

    // Send bytes to the tcp stream with a timeout
    // if an error occurs, the connection is closed
    pub async fn send_bytes(&self, packet: &[u8]) -> P2pResult<()> {
        match timeout(Duration::from_millis(PEER_SEND_BYTES_TIMEOUT), self.send_bytes_internal(packet)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                debug!("Failed to send bytes to {}: {}", self.get_address(), e);
                self.closed.store(true, Ordering::SeqCst);
                Err(e.into())
            }
            Err(e) => {
                debug!("Failed to send bytes in requested time to {}: {}", self.get_address(), e);
                self.closed.store(true, Ordering::SeqCst);
                Err(e.into())
            }
        }
    }

    // Send bytes to the peer.
    // Encryption must be used at all times starting from the handshake.
    async fn send_bytes_internal(&self, packet: &[u8]) -> P2pResult<()> {
        trace!("Sending {} bytes to {}", packet.len(), self.get_address());
        let mut stream = self.write.lock().await;

        // Count the bytes sent
        self.bytes_out.fetch_add(packet.len(), Ordering::Relaxed);

        if self.encryption.is_write_ready().await {
            let buffer = self.encryption.encrypt_packet(packet).await?;
            // Send the bytes in encrypted format
            self.send_packet_bytes_internal(&mut stream, &buffer).await?;

            // Count the bytes sent with the current key
            let bytes_out_key = self.bytes_out_key.fetch_add(packet.len(), Ordering::Relaxed);

            // Rotate the key if necessary
            if bytes_out_key > 0 && bytes_out_key >= ROTATE_EVERY_N_BYTES {
                debug!("Rotating our key with peer {}", self.get_address());
                let packet = self.rotate_key_packet().await?;
                // Send the new key to the peer
                self.send_packet_bytes_internal(&mut stream, &packet).await?;
            }
        } else {
            // Send the bytes in raw format
            self.send_packet_bytes_internal(&mut stream, &packet).await?;
        }

        // Flush the stream
        stream.flush().await?;

        Ok(())
    }

    // Read packet bytes from the stream
    pub async fn read_packet_bytes(&self, buf: &mut [u8], max_size: u32) -> P2pResult<Vec<u8>> {
        let mut stream = self.read.lock().await;
        let size = self.read_packet_size(&mut stream, buf, max_size).await?;
        if size == 0 || size > max_size {
            if self.get_state() == State::Success {
                warn!("Received invalid packet size: {} bytes (max: {} bytes) from peer {}", size, max_size, self.get_address());
            }
            return Err(P2pError::InvalidPacketSize)
        }
        trace!("Size received: {}", size);

        let bytes = self.read_all_bytes(&mut stream, buf, size).await?;
        Ok(bytes)
    }

    // Deserialize a packet from bytes and verify its integrity
    pub async fn read_packet_from_bytes(&self, bytes: &[u8]) -> P2pResult<Packet<'static>> {
        let mut reader = Reader::new(&bytes);
        let packet = Packet::read(&mut reader)?;
        if reader.total_read() != bytes.len() {
            debug!("read {:?} only {}/{} on bytes available from {}", packet, reader.total_read(), bytes.len(), self);
            return Err(P2pError::InvalidPacketNotFullRead)
        }
        Ok(packet)
    }

    // Read a packet and deserialize it.
    // This will read the packet size and then read the packet bytes.
    pub async fn read_packet(&self, buf: &mut [u8], max_size: u32) -> P2pResult<Packet<'static>> {
        let bytes = self.read_packet_bytes(buf, max_size).await?;
        self.read_packet_from_bytes(&bytes).await
    }

    // Read the packet size, this is always sent in raw (not encrypted).
    // Packet size must be a u32 in big endian.
    async fn read_packet_size(&self, stream: &mut OwnedReadHalf, buf: &mut [u8], max_usize: u32) -> P2pResult<u32> {
        let read = self.read_bytes_from_stream(stream, &mut buf[0..4]).await?;
        if read != 4 {
            if self.get_state() == State::Success {
                warn!("Received invalid packet size: expected to read 4 bytes but read only {} bytes from {}", read, self);
                warn!("Read: {:?}", &buf[0..read]);
            }
            return Err(P2pError::InvalidPacketSize)
        }
        let array: [u8; 4] = buf[0..4].try_into()?;
        let size = u32::from_be_bytes(array);

        // Verify if the size is valid
        if size > max_usize {
            if self.get_state() == State::Success {
                warn!("Received invalid packet size: {} bytes from {}", size, self);
            }
            return Err(P2pError::InvalidPacketSize)
        }
        Ok(size)
    }

    // Read all bytes until the the buffer is full with the requested size.
    // This support fragmented packets and encryption.
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

        // If encryption is supported, use it
        if self.encryption.is_read_ready().await {
            let content = self.encryption.decrypt_packet(&bytes).await?;
            Ok(content)
        } else {
            Ok(bytes)
        }
    }

    // This function waits until data is sent to the socket if it's in blocking mode.
    // It returns the size of the data read and set in the buffer.
    // This ensures the stream is locked only once and data is read efficiently.
    async fn read_bytes_from_stream_internal(&self, stream: &mut OwnedReadHalf, buf: &mut [u8]) -> P2pResult<usize> {
        let mut read = 0;
        let buf_len = buf.len();
        // Packet may have been fragmented, try to read it completely
        while read < buf_len {
            let result = stream.read(&mut buf[read..]).await?;
            match result {
                0 => return Err(P2pError::Disconnected),
                n => {
                    read += n;
                }
            }
        }
        self.bytes_in.fetch_add(read, Ordering::Relaxed);

        Ok(read)
    }

    // This function waits until something is sent to the socket if it's in blocking mode.
    // It returns the size of the data read and set in the buffer.
    // This ensures the stream is locked only once and data is read efficiently.
    // Any error encountered will be treated as a disconnection.
    async fn read_bytes_from_stream(&self, stream: &mut OwnedReadHalf, buf: &mut [u8]) -> P2pResult<usize> {
        match self.read_bytes_from_stream_internal(stream, buf).await {
            Ok(read) => Ok(read),
            Err(e) => {
                debug!("Failed to read bytes from {}: {}", self.get_address(), e);
                self.closed.store(true, Ordering::SeqCst);
                Err(e)
            }
        }
    }

    // Close internal close directly the stream.
    // This must be called only from the write connection task.
    pub async fn close(&self) -> P2pResult<()> {
        trace!("Closing internal connection with {}", self.addr);
        if self.closed.swap(true, Ordering::SeqCst) {
            debug!("Connection with {} already closed", self.addr);
            return Ok(());
        }

        // Occasionally, the peer may not be removed on the other peer's side.
        let mut stream = self.write.lock().await;
        timeout(Duration::from_secs(PEER_TIMEOUT_DISCONNECT), stream.shutdown()).await??;

        Ok(())
    }

    // Get the state of the connection
    pub fn get_state(&self) -> State {
        self.state
    }

    // Set the state of the connection
    pub fn set_state(&mut self, state: State) {
        self.state = state;
    }

    // Get the socket address used for this connection
    pub fn get_address(&self) -> &SocketAddr {
        &self.addr
    }

    // Get the total bytes sent
    pub fn bytes_out(&self) -> usize {
        self.bytes_out.load(Ordering::Relaxed)
    }

    // Get the total bytes read
    pub fn bytes_in(&self) -> usize {
        self.bytes_in.load(Ordering::Relaxed)
    }

    // Get the key rotation in
    pub fn key_rotation_in(&self) -> usize {
        self.rotate_key_in.load(Ordering::Relaxed)
    }

    // Get the key rotation out
    pub fn key_rotation_out(&self) -> usize {
        self.rotate_key_out.load(Ordering::Relaxed)
    }

    // Get the time when the connection was established
    pub fn connected_on(&self) -> TimestampSeconds {
        self.connected_on
    }

    // Get the human readable uptime of the connection
    pub fn get_human_uptime(&self) -> String {
        let elapsed_seconds = get_current_time_in_seconds() - self.connected_on();
        format_duration(Duration::from_secs(elapsed_seconds)).to_string()
    }

    // Verify if the connection is closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

impl Display for Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error> {
        write!(f, "Connection[state: {:?}, peer: {}, read: {}, sent: {}, key rotation (in/out): ({}/{}), connected since: {}, closed: {}]", self.state, self.get_address(), human_bytes(self.bytes_in() as f64), human_bytes(self.bytes_out() as f64), self.key_rotation_in(), self.key_rotation_out(), self.get_human_uptime(), self.is_closed())
    }
}