use log::debug;
use xelis_common::{
    crypto::Hash,
    difficulty::CumulativeDifficulty,
    network::Network,
    serializer::{Reader, ReaderError, Serializer, Writer},
    time::TimestampSeconds
};
use crate::p2p::{
    peer_list::SharedPeerList,
    peer::Peer,
    connection::Connection
};
use std::{
    borrow::Cow,
    collections::HashSet,
    fmt::{Display, Error, Formatter}
};

// this Handshake is the first data sent when connecting to the server
// If handshake is valid, server reply with his own handshake
// We just have to repeat this request to all peers until we reach max connection
// Network ID, Block Height & block top hash is to verify that we are on the same network & chain.
#[derive(Clone, Debug)]
pub struct Handshake<'a> {
    // daemon version
    version: Cow<'a, String>,
    // Network type on which it relies
    // Mainnet, testnet...
    network: Network,
    // node tag set
    node_tag: Cow<'a, Option<String>>,
    // Which network id it relies on
    network_id: Cow<'a, [u8; 16]>,
    // unique peer id randomly generated
    peer_id: u64,
    // local P2p Server port
    local_port: u16,
    // current time in seconds
    utc_time: TimestampSeconds,
    // current topo height
    topoheight: u64,
    // current block height
    height: u64,
    // until which topoheight the node is pruned
    pruned_topoheight: Option<u64>,
    // current top block hash
    top_hash: Cow<'a, Hash>,
    // genesis hash
    genesis_hash: Cow<'a, Hash>,
    // cumulative difficulty of its chain at top
    cumulative_difficulty: Cow<'a, CumulativeDifficulty>,
    // By default it's true, and peer allow to be shared to others and/or through API
    // If false, we must not share it
    can_be_shared: bool
} // Server reply with his own list of peers, but we remove all already known by requester for the response.

impl<'a> Handshake<'a> {
    pub const MAX_LEN: usize = 16;

    pub fn new(version: Cow<'a, String>, network: Network, node_tag: Cow<'a, Option<String>>, network_id: Cow<'a, [u8; 16]>, peer_id: u64, local_port: u16, utc_time: TimestampSeconds, topoheight: u64, height: u64, pruned_topoheight: Option<u64>, top_hash: Cow<'a, Hash>, genesis_hash: Cow<'a, Hash>, cumulative_difficulty: Cow<'a, CumulativeDifficulty>, can_be_shared: bool) -> Self {
        debug_assert!(version.len() > 0 && version.len() <= Handshake::MAX_LEN);
        // version cannot be greater than 16 chars
        if let Some(node_tag) = node_tag.as_ref() {
            // node tag cannot be greater than 16 chars
            debug_assert!(node_tag.len() > 0 && node_tag.len() <= Handshake::MAX_LEN);
        }

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
            pruned_topoheight,
            top_hash,
            genesis_hash,
            cumulative_difficulty,
            can_be_shared
        }
    }

    // Create a new peer using its connection and this handshake packet
    pub fn create_peer(self, connection: Connection, priority: bool, peer_list: SharedPeerList) -> Peer {
        let peers = HashSet::new();
        Peer::new(connection, self.get_peer_id(), self.node_tag.into_owned(), self.local_port, self.version.into_owned(), self.top_hash.into_owned(), self.topoheight, self.height, self.pruned_topoheight, priority, self.cumulative_difficulty.into_owned(), peer_list, peers, self.can_be_shared)
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

    pub fn get_utc_time(&self) -> TimestampSeconds {
        self.utc_time
    }

    pub fn get_block_height(&self) -> u64 {
        self.height
    }

    pub fn get_topoheight(&self) -> u64 {
        self.topoheight
    }

    pub fn get_block_top_hash(&self) -> &Hash {
        &self.top_hash
    }

    pub fn get_block_genesis_hash(&self) -> &Hash {
        &self.genesis_hash
    }

    pub fn get_pruned_topoheight(&self) -> &Option<u64> {
        &self.pruned_topoheight
    }
}

impl Serializer for Handshake<'_> {
    // 1 + MAX(16) + 1 + MAX(16) + 16 + 8 + 8 + 8 + 32 + 1 + 24 * 16 + 1
    fn write(&self, writer: &mut Writer) {
        // daemon version
        writer.write_string(&self.version);

        // network
        self.network.write(writer);

        // node tag
        writer.write_optional_string(&self.node_tag);

        writer.write_bytes(self.network_id.as_ref()); // network ID
        writer.write_u64(&self.peer_id); // transform peer ID to bytes
        writer.write_u16(self.local_port); // local port
        writer.write_u64(&self.utc_time); // UTC Time
        writer.write_u64(&self.topoheight); // Topo height
        writer.write_u64(&self.height); // Block Height
        self.pruned_topoheight.write(writer); // Pruned Topo Height
        writer.write_hash(&self.top_hash); // Block Top Hash (32 bytes)
        writer.write_hash(&self.genesis_hash); // Genesis Hash
        self.cumulative_difficulty.write(writer); // Cumulative Difficulty
        writer.write_bool(self.can_be_shared); // Can be shared
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
        let pruned_topoheight = Option::read(reader)?;
        if let Some(pruned_topoheight) = &pruned_topoheight {
            if *pruned_topoheight == 0 {
                debug!("Invalid pruned topoheight (0) in handshake packet");
                return Err(ReaderError::InvalidValue)
            }
        }
        let top_hash = reader.read_hash()?;
        let genesis_hash = reader.read_hash()?;
        let cumulative_difficulty = CumulativeDifficulty::read(reader)?;
        let can_be_shared = reader.read_bool()?;

        Ok(Handshake::new(Cow::Owned(version), network, Cow::Owned(node_tag), Cow::Owned(network_id), peer_id, local_port, utc_time, topoheight, height, pruned_topoheight, Cow::Owned(top_hash), Cow::Owned(genesis_hash), Cow::Owned(cumulative_difficulty), can_be_shared))
    }

    fn size(&self) -> usize {
        // daemon version
        self.version.size() +
        // network
        self.network.size() +
        // node tag
        self.node_tag.size() +
        // network ID
        self.network_id.size() +
        // peer ID
        self.peer_id.size() +
        // local port
        self.local_port.size() +
        // UTC Time
        self.utc_time.size() +
        // Topo height
        self.topoheight.size() +
        // Block Height
        self.height.size() +
        // Pruned Topo Height
        self.pruned_topoheight.size() +
        // Block Top Hash
        self.top_hash.size() +
        // Genesis Hash
        self.genesis_hash.size() +
        // Cumulative Difficulty
        self.cumulative_difficulty.size() +
        // Can be shared
        self.can_be_shared.size()
    }
}

const NO_NODE_TAG: &str = "None";

impl Display for Handshake<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let node_tag: &dyn Display = if let Some(tag) = self.get_node_tag() {
            tag
        } else {
            &NO_NODE_TAG
        };
        write!(f, "Handshake[version: {}, node tag: {}, network_id: {}, peer_id: {}, utc_time: {}, block_height: {}, block_top_hash: {}]", self.get_version(), node_tag, hex::encode(self.get_network_id()), self.get_peer_id(), self.get_utc_time(), self.get_block_height(), self.get_block_top_hash())
    }
}