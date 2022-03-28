use crate::p2p::connection::Connection;
use crate::core::serializer::Serializer;
use crate::core::reader::{Reader, ReaderError};
use crate::core::writer::Writer;
use crate::crypto::hash::Hash;
use std::fmt::{Display, Error, Formatter};
use std::net::{TcpStream, SocketAddr};


// this Handshake is the first data sent when connecting to the server
// If handshake is valid, server reply with his own handshake
// We just have to repeat this request to all peers until we reach max connection
// Network ID, Block Height & block top hash is to verify that we are on the same network & chain.
pub struct Handshake {
    version: String, // daemon version
    node_tag: Option<String>, // node tag
    network_id: [u8; 16],
    peer_id: u64, // unique peer id randomly generated 
    utc_time: u64, // current time in seconds
    block_height: u64, // current block height
    block_top_hash: Hash, // current block top hash
    peers: Vec<String> // all peers that we are already connected to
} // Server reply with his own list of peers, but we remove all already known by requester for the response.

impl Handshake {
    pub const MAX_LEN: usize = 16;

    pub fn new(version: String, node_tag: Option<String>, network_id: [u8; 16], peer_id: u64, utc_time: u64, block_height: u64, block_top_hash: Hash, peers: Vec<String>) -> Self {
        assert!(version.len() > 0 && version.len() <= Handshake::MAX_LEN); // version cannot be greater than 16 chars
        if let Some(node_tag) = &node_tag {
            assert!(node_tag.len() > 0 && node_tag.len() <= Handshake::MAX_LEN); // node tag cannot be greater than 16 chars
        }

        assert!(peers.len() <= Handshake::MAX_LEN); // maximum 16 peers allowed

        Handshake {
            version,
            node_tag,
            network_id,
            peer_id,
            utc_time,
            block_height,
            block_top_hash,
            peers
        }
    }

    pub fn create_connection(self, stream: TcpStream, addr: SocketAddr, out: bool, priority: bool) -> (Connection, Vec<String>) {
        let block_height = self.get_block_height();
        (Connection::new(self.get_peer_id(), self.node_tag, self.version, self.block_top_hash, block_height, stream, addr, out, priority), self.peers)
    }

    pub fn get_version(&self) -> &String {
        &self.version
    }

    pub fn get_network_id(&self) -> &[u8; 16] {
        &self.network_id
    }

    pub fn get_node_tag(&self) -> &Option<String> {
        &self.node_tag
    }

    pub fn get_peer_id(&self) -> u64 {
        self.peer_id
    }

    pub fn get_utc_time(&self) -> u64 {
        self.utc_time
    }

    pub fn get_block_height(&self) -> u64 {
        self.block_height
    }

    pub fn get_block_top_hash(&self) -> &Hash {
        &self.block_top_hash
    }

    pub fn get_peers(&self) -> &Vec<String> {
        &self.peers
    }
}

impl Serializer for Handshake {
    // 1 + MAX(16) + 1 + MAX(16) + 16 + 8 + 8 + 8 + 32 + 1 + 24 * 16
    fn write(&self, writer: &mut Writer) {
        // daemon version
        writer.write_string(&self.version);

        // node tag
        writer.write_optional_string(&self.node_tag);

        writer.write_bytes(&self.network_id); // network ID
        writer.write_u64(&self.peer_id); // transform peer ID to bytes
        writer.write_u64(&self.utc_time); // UTC Time
        writer.write_u64(&self.block_height); // Block Height
        writer.write_hash(&self.block_top_hash); // Block Top Hash (32 bytes)

        writer.write_u8(self.peers.len() as u8);
        for peer in &self.peers {
            writer.write_u8(peer.len() as u8);
            writer.write_bytes(peer.as_bytes());
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        // Handshake have a static size + some part of dynamic size (node tag, version, peers list)
        // we must verify the correct size each time we want to read from the data sent by the client
        // if we don't verify each time, it can create a panic error and crash the node

        // Daemon version
        let version = reader.read_string()?;
        if version.len() == 0 || version.len() > Handshake::MAX_LEN {
            return Err(ReaderError::InvalidSize)
        }

        // Node Tag
        let node_tag = reader.read_optional_string()?;
        if let Some(tag) = &node_tag {
            if tag.len() > Handshake::MAX_LEN {
                return Err(ReaderError::InvalidSize)
            }
        }

        let network_id: [u8; 16] = reader.read_bytes(16)?;
        let peer_id = reader.read_u64()?;
        let utc_time = reader.read_u64()?;
        let block_height = reader.read_u64()?;
        let block_top_hash = Hash::new(reader.read_bytes_32()?);
        let peers_len = reader.read_u8()? as usize;
        if peers_len > Handshake::MAX_LEN {
            return Err(ReaderError::InvalidSize)
        }

        let mut peers = vec![];
        for _ in 0..peers_len {
            let peer = reader.read_string()?;
            if peer.len() > Handshake::MAX_LEN {
                return Err(ReaderError::InvalidSize)
            }
            peers.push(peer);
        }
        Ok(Handshake::new(version, node_tag, network_id, peer_id, utc_time, block_height, block_top_hash, peers))
    }
}

impl Display for Handshake {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let node_tag: String;
        if let Some(value) = self.get_node_tag() {
            node_tag = value.clone();
        } else {
            node_tag = String::from("None");
        }

        write!(f, "Handshake[version: {}, node tag: {}, network_id: {}, peer_id: {}, utc_time: {}, block_height: {}, block_top_hash: {}, peers: ({})]", self.get_version(), node_tag, hex::encode(self.get_network_id()), self.get_peer_id(), self.get_utc_time(), self.get_block_height(), self.get_block_top_hash(), self.get_peers().join(","))
    }
}