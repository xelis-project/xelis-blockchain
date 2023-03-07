use xelis_common::{
    serializer::{Serializer, Writer, ReaderError, Reader},
    globals::{ip_from_bytes, ip_to_bytes},
    crypto::hash::Hash, network::Network
};

use crate::p2p::peer_list::SharedPeerList;
use crate::p2p::connection::Connection;
use crate::p2p::peer::Peer;
use std::collections::HashSet;
use std::fmt::{Display, Error, Formatter};
use std::net::SocketAddr;

// this Handshake is the first data sent when connecting to the server
// If handshake is valid, server reply with his own handshake
// We just have to repeat this request to all peers until we reach max connection
// Network ID, Block Height & block top hash is to verify that we are on the same network & chain.
#[derive(Clone, Debug)]
pub struct Handshake {
    version: String, // daemon version
    network: Network,
    node_tag: Option<String>, // node tag
    network_id: [u8; 16],
    peer_id: u64, // unique peer id randomly generated
    local_port: u16, // local P2p Server port
    utc_time: u64, // current time in seconds
    topoheight: u64, // current topo height
    height: u64, // current block height
    top_hash: Hash, // current block top hash
    genesis_hash: Hash, // genesis hash
    cumulative_difficulty: u64,
    peers: Vec<SocketAddr> // all peers that we are already connected to
} // Server reply with his own list of peers, but we remove all already known by requester for the response.

impl Handshake {
    pub const MAX_LEN: usize = 16;

    pub fn new(version: String, network: Network, node_tag: Option<String>, network_id: [u8; 16], peer_id: u64, local_port: u16, utc_time: u64, topoheight: u64, height: u64, top_hash: Hash, genesis_hash: Hash, cumulative_difficulty: u64, peers: Vec<SocketAddr>) -> Self {
        assert!(version.len() > 0 && version.len() <= Handshake::MAX_LEN); // version cannot be greater than 16 chars
        if let Some(node_tag) = &node_tag {
            assert!(node_tag.len() > 0 && node_tag.len() <= Handshake::MAX_LEN); // node tag cannot be greater than 16 chars
        }

        assert!(peers.len() <= Handshake::MAX_LEN); // maximum 16 peers allowed

        Self {
            version,
            network,
            node_tag,
            network_id,
            peer_id,
            local_port,
            utc_time,
            topoheight,
            height,
            top_hash,
            genesis_hash,
            cumulative_difficulty,
            peers
        }
    }

    pub fn create_peer(self, connection: Connection, out: bool, priority: bool, peer_list: SharedPeerList) -> (Peer, Vec<SocketAddr>) {
        let mut peers = HashSet::new();
        for peer in &self.peers {
            peers.insert(peer.clone());
        }
        (Peer::new(connection, self.get_peer_id(), self.node_tag, self.local_port, self.version, self.top_hash, self.topoheight, self.height, out, priority, self.cumulative_difficulty, peer_list, peers), self.peers)
    }

    pub fn get_version(&self) -> &String {
        &self.version
    }

    pub fn get_network(&self) -> &Network {
        &self.network
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
        self.height
    }

    pub fn get_block_top_hash(&self) -> &Hash {
        &self.top_hash
    }

    pub fn get_block_genesis_hash(&self) -> &Hash {
        &self.genesis_hash
    }

    pub fn get_peers(&self) -> &Vec<SocketAddr> {
        &self.peers
    }
}

impl Serializer for Handshake {
    // 1 + MAX(16) + 1 + MAX(16) + 16 + 8 + 8 + 8 + 32 + 1 + 24 * 16
    fn write(&self, writer: &mut Writer) {
        // daemon version
        writer.write_string(&self.version);

        // network
        self.network.write(writer);

        // node tag
        writer.write_optional_string(&self.node_tag);

        writer.write_bytes(&self.network_id); // network ID
        writer.write_u64(&self.peer_id); // transform peer ID to bytes
        writer.write_u16(self.local_port); // local port
        writer.write_u64(&self.utc_time); // UTC Time
        writer.write_u64(&self.topoheight); // Topo height
        writer.write_u64(&self.height); // Block Height
        writer.write_hash(&self.top_hash); // Block Top Hash (32 bytes)
        writer.write_hash(&self.genesis_hash); // Genesis Hash
        writer.write_u64(&self.cumulative_difficulty);

        writer.write_u8(self.peers.len() as u8);
        for peer in &self.peers {
            writer.write_bytes(&ip_to_bytes(peer));
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

        // Network
        let network = Network::read(reader)?;

        // Node Tag
        let node_tag = reader.read_optional_string()?;
        if let Some(tag) = &node_tag {
            if tag.len() > Handshake::MAX_LEN {
                return Err(ReaderError::InvalidSize)
            }
        }

        let network_id: [u8; 16] = reader.read_bytes(16)?;
        let peer_id = reader.read_u64()?;
        let local_port = reader.read_u16()?;
        let utc_time = reader.read_u64()?;
        let topoheight = reader.read_u64()?;
        let height = reader.read_u64()?;
        let top_hash = reader.read_hash()?;
        let genesis_hash = reader.read_hash()?;
        let cumulative_difficulty = reader.read_u64()?;
        let peers_len = reader.read_u8()? as usize;
        if peers_len > Handshake::MAX_LEN {
            return Err(ReaderError::InvalidSize)
        }

        let mut peers = Vec::with_capacity(peers_len);
        for _ in 0..peers_len {
            let peer = ip_from_bytes(reader)?;
            peers.push(peer);
        }
        Ok(Handshake::new(version, network, node_tag, network_id, peer_id, local_port, utc_time, topoheight, height, top_hash, genesis_hash, cumulative_difficulty, peers))
    }
}

const NO_NODE_TAG: &str = "None";

impl Display for Handshake {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let node_tag: &dyn Display = if let Some(tag) = self.get_node_tag() {
            tag
        } else {
            &NO_NODE_TAG
        };
        write!(f, "Handshake[version: {}, node tag: {}, network_id: {}, peer_id: {}, utc_time: {}, block_height: {}, block_top_hash: {}, peers: ({})]", self.get_version(), node_tag, hex::encode(self.get_network_id()), self.get_peer_id(), self.get_utc_time(), self.get_block_height(), self.get_block_top_hash(), self.get_peers().len())
    }
}