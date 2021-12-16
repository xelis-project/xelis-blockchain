use crate::crypto::hash::Hash;
use core::convert::TryInto;
use super::connection::Connection;
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
    pub fn new(version: String, node_tag: Option<String>, network_id: [u8; 16], peer_id: u64, utc_time: u64, block_height: u64, block_top_hash: Hash, peers: Vec<String>) -> Self {
        assert!(version.len() > 0 && version.len() <= 16); // version cannot be greater than 16 chars
        if let Some(node_tag) = &node_tag {
            assert!(node_tag.len() > 0 && node_tag.len() <= 16); // node tag cannot be greater than 16 chars
        }

        assert!(peers.len() <= 16); // maximum 16 peers allowed

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

    pub fn create_connection(self, stream: TcpStream, addr: SocketAddr, out: bool) -> Connection {
        let block_height = self.get_block_height();
        Connection::new(self.get_peer_id(), self.node_tag, self.version, block_height, stream, addr, out)
    }

    // 1 + MAX(16) + 1 + MAX(16) + 16 + 8 + 8 + 8 + 32 + 1 + 24 * 16
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        
        // daemon version
        bytes.push(self.version.len() as u8); // send string size
        bytes.extend(self.version.as_bytes()); // send string as bytes

        // node tag
        match &self.node_tag {
            Some(tag) => {
                bytes.push(tag.len() as u8);
                if tag.len() > 0 {
                    bytes.extend(tag.as_bytes());
                }
            }
            None => {
                bytes.push(0);
            }
        }

        bytes.extend(self.network_id); // network ID
        bytes.extend(self.peer_id.to_be_bytes()); // transform peer ID to bytes
        bytes.extend(self.utc_time.to_be_bytes()); // UTC Time
        bytes.extend(self.block_height.to_be_bytes()); // Block Height
        bytes.extend(self.block_top_hash.as_bytes()); // Block Top Hash (32 bytes)

        bytes.push(self.peers.len() as u8);
        for peer in &self.peers {
            bytes.push(peer.len() as u8);
            bytes.extend(peer.as_bytes());
        }

        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ()> {
        let mut n = 0;
        
        // Daemon version
        let version_len = data[n] as usize;
        n += 1;
        if version_len == 0 || version_len > 16 {
            return Err(())
        }
        let version = String::from_utf8(data[n..n+version_len].try_into().unwrap()).unwrap();
        n += version_len;

        // Node Tag
        let node_tag_len = data[n] as usize;
        n += 1;
        if version_len > 16 {
            return Err(())
        }
        let node_tag = if node_tag_len == 0 {
            None
        } else {
            Some(String::from_utf8(data[n..n+node_tag_len].try_into().unwrap()).unwrap())
        };
        n += node_tag_len;

        let network_id: [u8; 16] = data[n..n+16].try_into().unwrap();
        n += 16;

        let peer_id = u64::from_be_bytes(data[n..n+8].try_into().unwrap());
        n += 8;

        let utc_time = u64::from_be_bytes(data[n..n+8].try_into().unwrap());
        n += 8;

        let block_height = u64::from_be_bytes(data[n..n+8].try_into().unwrap());
        n += 8;

        let block_top_hash = Hash::new(data[n..n+32].try_into().unwrap());
        n += 32;

        let peers_len = data[n] as usize;
        if peers_len > 16 {
            return Err(())
        }

        n += 1;

        let mut peers = vec![];
        for _ in 0..peers_len {
            let size = data[n] as usize;
            if size == 0 || size > 16 {
                return Err(())
            }

            n += 1;
            let peer = String::from_utf8(data[n..n+size].try_into().unwrap()).unwrap();
            // TODO verify peer validity
            n += size;

            peers.push(peer);
        }

        Ok(Handshake::new(version, node_tag, network_id, peer_id, utc_time, block_height, block_top_hash, peers))
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

use std::fmt::{Display, Error, Formatter};

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