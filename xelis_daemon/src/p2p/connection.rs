use crate::config::{PEER_TIMEOUT_DISCONNECT, PEER_TIMEOUT_INIT_CONNECTION, PEER_SEND_BYTES_TIMEOUT};
use super::{
    diffie_hellman,
    encryption::{Encryption, CipherSide},
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
use log::{debug, error, trace, warn};

type P2pResult<T> = Result<T, P2pError>;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    // connection is new, no handshake received
    Pending,
    // start exchanging keys
    KeyExchange,
    // handshake received, not checked
    Handshake,
    // connection is ready
    Success
}

pub struct Connection {
    // True mean we are the client
    out: bool,
    // State of the connection
    state: State,
    // write to stream
    write: Mutex<OwnedWriteHalf>,
    // read from stream
    read: Mutex<OwnedReadHalf>,
    // TCP Address
    addr: SocketAddr,
    // total bytes read
    bytes_in: AtomicUsize,
    // total bytes sent
    bytes_out: AtomicUsize,
    // total bytes encrypted and sent using same encryption key
    bytes_encrypted: AtomicUsize,
    // when the connection was established
    connected_on: TimestampSeconds,
    // if Connection#close() is called, close is set to true
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
            bytes_encrypted: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            rotate_key_in: AtomicUsize::new(0),
            rotate_key_out: AtomicUsize::new(0),
            encryption: Encryption::new(),
        }
    }

    // Exchange keys in the old way for compatibility reasons
    pub async fn exchange_keys_old(&mut self, buffer: &mut [u8]) -> P2pResult<()> {
        trace!("Exchanging keys with {}", self.addr);

        // Update our state
        self.set_state(State::KeyExchange);

        // Send our key if we initiated the connection
        if self.is_out() {
            trace!("Sending our key to {}", self.addr);
            let packet = self.rotate_key_packet().await?;
            self.send_bytes(&packet).await?;
            self.encryption.mark_ready();
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
            self.encryption.mark_ready();
        }

        trace!("Key exchange with {} successful", self.addr);

        Ok(())
    }

    // Do a key exchange with the peer
    // We use the Diffie-Hellman key exchange to generate a shared secret
    // The shared secret is used to encrypt the generated (symetric) encryption key
    // The encryption key is then used to encrypt the packets
    // Each party will have its own key
    // NOTE: This doesn't prevent any MITM if there is not a strict verification of the DH key of the peer.
    // Because a MITM could intercept the key and send its own key to the peer
    // and play the role as a proxy.
    // Afaik, there is no way to have a decentralized way to prevent MITM without trusting a third party
    // (That's what TLS/SSL does with the CA, but it's not decentralized and it's not trustless)
    // A potential idea would be to hardcode seed nodes keys,
    // and each nodes share the key of other along the socket address
    pub async fn exchange_keys(&mut self, keypair: &diffie_hellman::DHKeyPair, expected_key: Option<&diffie_hellman::PublicKey>, action: diffie_hellman::KeyVerificationAction, buffer: &mut [u8]) -> P2pResult<diffie_hellman::PublicKey> {
        trace!("Exchanging keys with {}", self.addr);

        // Update our state
        self.set_state(State::KeyExchange);

        // Send our DH key
        {
            trace!("Sending our DH key to {}", self.addr);
            let pk_bytes = keypair.get_public_key().as_bytes();
            let packet = Packet::KeyExchange(Cow::Borrowed(pk_bytes));
            self.send_bytes(&packet.to_bytes()).await?;
        }

        // Wait for the peer to receive its key
        let Packet::KeyExchange(peer_dh_key) = timeout(
            Duration::from_millis(PEER_TIMEOUT_INIT_CONNECTION),
            self.read_packet(buffer, 256)
        ).await?? else {
            error!("Expected KeyExchange packet");
            return Err(P2pError::InvalidPacket);
        };

        trace!("Received DH key from {}", self.addr);

        let peer_dh_key = diffie_hellman::PublicKey::from(peer_dh_key.into_owned());

        // Verify the key of the peer
        if let Some(expected_key) = expected_key {
            if expected_key != &peer_dh_key {
                match action {
                    diffie_hellman::KeyVerificationAction::Warn => {
                        warn!("Expected Diffie-Hellman key from {} is different from the received key, ignoring", self.addr);
                    },
                    diffie_hellman::KeyVerificationAction::Reject => {
                        error!("Expected Diffie-Hellman key from {} is different from the received key", self.addr);
                        return Err(P2pError::InvalidDHKey);
                    },
                    diffie_hellman::KeyVerificationAction::Ignore => {
                        debug!("Expected Diffie-Hellman key from {} is different from the received key, ignoring", self.addr);
                    }
                }
            }
        }

        // the secret generated is used to encrypt our newly generated encryption key
        let secret = keypair.get_shared_secret(&peer_dh_key);

        // Send our newly generated key if we initiated the connection
        {
            trace!("Sending our encryption key to {}", self.addr);
            self.encryption.rotate_key(secret, CipherSide::Both).await?;
            let packet = self.rotate_key_packet().await?;
            self.send_bytes(&packet).await?;
        }

        // Mark the encryption as ready because we have shared our key
        self.encryption.mark_ready();

        trace!("Waiting for key from {}", self.addr);
        // Wait for the shared key of the peer to receive
        let Packet::KeyExchange(peer_key) = timeout(
            Duration::from_millis(PEER_TIMEOUT_INIT_CONNECTION),
            self.read_packet(buffer, 256)
        ).await?? else {
            error!("Expected KeyExchange packet");
            return Err(P2pError::InvalidPacket);
        };

        trace!("Received encryption key from {}", self.addr);

        // Now that we got the shared peer key, update our encryption state
        self.encryption.rotate_key(peer_key.into_owned(), CipherSide::Peer).await?;

        trace!("Key exchange with {} successful", self.addr);

        Ok(peer_dh_key)
    }

    // Verify if its a outgoing connection
    pub fn is_out(&self) -> bool {
        self.out
    }

    // Generate a new key and rotate the current key
    async fn rotate_key_packet(&self) -> P2pResult<Vec<u8>> {
        trace!("rotating our encryption key for peer {}", self.get_address());
        // Generate a new key to use
        let new_key = self.encryption.generate_key();
        self.generate_rotate_key_packet(new_key).await
    }

    // Rotate the current key with a new key and generate the packet
    async fn generate_rotate_key_packet(&self, new_key: EncryptionKey) -> P2pResult<Vec<u8>> {
        // Build the packet
        let mut packet = Packet::KeyExchange(Cow::Borrowed(&new_key)).to_bytes();

        if self.encryption.is_write_ready().await {
            // Encrypt with the our previous key our new key
            packet = self.encryption.encrypt_packet(&packet).await?;
        }

        // Rotate the key in our encryption state
        self.encryption.rotate_key(new_key, CipherSide::Our).await?;

        // Increment the key rotation counter
        self.rotate_key_out.fetch_add(1, Ordering::Relaxed);

        // Reset the counter
        self.bytes_encrypted.store(0, Ordering::Relaxed);

        Ok(packet)
    }

    // Rotate the peer symetric key
    // We update our state
    // Because we use TCP and packets are read/executed in sequential order,
    // We don't need to send a ACK to the peer to confirm the key rotation
    // as all next packets will be encrypted with the new key and we have updated it before
    pub async fn rotate_peer_key(&self, key: EncryptionKey) -> P2pResult<()> {
        trace!("Rotating encryption key of peer {}", self.get_address());
        self.encryption.rotate_key(key, CipherSide::Peer).await?;
        // Increment the key rotation counter
        self.rotate_key_in.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    // This function will send the packet to the peer without flushing the stream
    // Packet length is ALWAYS sent in raw (not encrypted)
    // Otherwise, we can't know how much bytes to read for each ciphertext/packet
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

    // Send bytes to the peer
    // Encrypt must be used all time starting handshake
    async fn send_bytes_internal(&self, packet: &[u8]) -> P2pResult<()> {
        trace!("Sending {} bytes to {}", packet.len(), self.get_address());
        let mut stream = self.write.lock().await;

        // Count the bytes sent
        self.bytes_out.fetch_add(packet.len(), Ordering::Relaxed);

        // We check if the encryption is enabled to manage it ourself here
        if self.encryption.is_ready() {
            let buffer = self.encryption.encrypt_packet(packet).await?;
            // Send the bytes in encrypted format
            self.send_packet_bytes_internal(&mut stream, &buffer).await?;

            // Count the bytes sent with the current key
            let sum = self.bytes_encrypted.fetch_add(packet.len(), Ordering::Relaxed) + packet.len();
            self.bytes_encrypted.store(sum, Ordering::Relaxed);

            // Rotate the key if necessary
            if sum >= ROTATE_EVERY_N_BYTES {
                debug!("Rotating our encryption key with peer {}", self.get_address());
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

    // Read a packet and deserialize it
    // This will read the packet size and then read the packet bytes
    pub async fn read_packet(&self, buf: &mut [u8], max_size: u32) -> P2pResult<Packet<'static>> {
        let bytes = self.read_packet_bytes(buf, max_size).await?;
        self.read_packet_from_bytes(&bytes).await
    }

    // Read the packet size, this is always sent in raw (not encrypted)
    // And packet size must be a u32 in big endian
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

    // Read all bytes until the the buffer is full with the requested size
    // This support fragmented packets and encryption
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

    // this function will wait until something is sent to the socket if it's in blocking mode
    // this return the size of data read & set in the buffer.
    // used to only lock one time the stream and read on it
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

    // this function will wait until something is sent to the socket if it's in blocking mode
    // this return the size of data read & set in the buffer.
    // used to only lock one time the stream and read on it
    // on any error, it will considered as disconnected
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

    // Close internal close directly the stream
    // This must be called only from the write connection task
    pub async fn close(&self) -> P2pResult<()> {
        trace!("Closing internal connection with {}", self.addr);
        if self.closed.swap(true, Ordering::SeqCst) {
            debug!("Connection with {} already closed", self.addr);
            return Ok(());
        }

        // sometimes the peer is not removed on other peer side
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