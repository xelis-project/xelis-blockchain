use lazy_static::lazy_static;
use xelis_common::{
    api::daemon::DevFeeThreshold,
    crypto::{
        Address,
        Hash,
        PublicKey
    },
    difficulty::Difficulty,
    network::Network,
    time::TimestampSeconds,
};

// In case of potential forks, have a unique network id to not connect to others compatible chains
pub const NETWORK_ID_SIZE: usize = 16;
pub const NETWORK_ID: [u8; NETWORK_ID_SIZE] = [0x73, 0x6c, 0x69, 0x78, 0x65, 0x5f, 0x78, 0x65, 0x6c, 0x69, 0x73, 0x5f, 0x62, 0x6c, 0x6f, 0x63];
pub const SEED_NODES: [&str; 2] = ["74.208.251.149:2125", "162.19.249.100:2125"];

// bind addresses
pub const DEFAULT_P2P_BIND_ADDRESS: &str = "0.0.0.0:2125";
pub const DEFAULT_RPC_BIND_ADDRESS: &str = "0.0.0.0:8080";

// Default cache size for storage DB
pub const DEFAULT_CACHE_SIZE: usize = 1024;

// Block rules
// Millis per second, it is used to prevent having random 1000 values anywhere
pub const MILLIS_PER_SECOND: u64 = 1000;
// Block Time in milliseconds
pub const BLOCK_TIME_MILLIS: u64 = 15 * MILLIS_PER_SECOND; // 15s block time
// Minimum difficulty (each difficulty point is in H/s)
// Current: BLOCK TIME in millis * 1000 = 1 MH/s minimum
pub const MINIMUM_DIFFICULTY: Difficulty = Difficulty::from_u64(BLOCK_TIME_MILLIS * 1000);
pub const GENESIS_BLOCK_DIFFICULTY: Difficulty = Difficulty::from_u64(1);
// 1024 * 1024 + (256 * 1024) bytes = 1.25 MB maximum size per block with txs
pub const MAX_BLOCK_SIZE: usize = (1024 * 1024) + (256 * 1024);
// 2 seconds maximum in future (prevent any attack on reducing difficulty but keep margin for unsynced devices)
pub const TIMESTAMP_IN_FUTURE_LIMIT: TimestampSeconds = 2 * 1000;

// keep at least last N blocks until top topoheight when pruning the chain
// WARNING: This must be at least 50 blocks for difficulty adjustement
pub const PRUNE_SAFETY_LIMIT: u64 = STABLE_LIMIT * 10;

// BlockDAG rules
pub const STABLE_LIMIT: u64 = 8; // in how many height we consider the block stable

// Emission rules
// 15%, 10%, 5% per block going to dev address
pub const DEV_FEES: [DevFeeThreshold; 3] = [
    DevFeeThreshold {
        height: 0,
        fee_percentage: 15
    },
    DevFeeThreshold {
        height: 1_250_000, // after ~6 months it's reduced to 10%
        fee_percentage: 10
    },
    DevFeeThreshold {
        height: 3_000_000, // after ~1 year it's reduced to 5%
        fee_percentage: 5
    }
];
// only 30% of reward for side block
pub const SIDE_BLOCK_REWARD_PERCENT: u64 = 30;
pub const EMISSION_SPEED_FACTOR: u64 = 20;

// Developer address for paying dev fees until Smart Contracts integration
// (testnet/mainnet format is converted lazily later)
pub const DEV_ADDRESS: &str = "xel:3tr88r8vvx3qxvgr7gdja5kae784v8htc7ayaj4nxlzgflhchlmqq4gwg7h";

// Chain sync config
// minimum X seconds between each chain sync request per peer
pub const CHAIN_SYNC_DELAY: u64 = 5;
// wait maximum between each chain sync request to peers
pub const CHAIN_SYNC_TIMEOUT_SECS: u64 = CHAIN_SYNC_DELAY * 3;
// first 30 blocks are sent in linear way, then it's exponential
pub const CHAIN_SYNC_REQUEST_EXPONENTIAL_INDEX_START: usize = 30;
// allows up to X blocks id (hash + height) sent for request
pub const CHAIN_SYNC_REQUEST_MAX_BLOCKS: usize = 64;
// minimum X blocks hashes sent for response
pub const CHAIN_SYNC_RESPONSE_MIN_BLOCKS: usize = 512;
// Default response blocks sent/accepted
pub const CHAIN_SYNC_DEFAULT_RESPONSE_BLOCKS: usize = 4096;
// allows up to X blocks hashes sent for response
pub const CHAIN_SYNC_RESPONSE_MAX_BLOCKS: usize = 16384;
// send last 10 heights
pub const CHAIN_SYNC_TOP_BLOCKS: usize = 10;

// P2p rules
// time between each ping
pub const P2P_PING_DELAY: u64 = 10;
// time in seconds between each update of peerlist
pub const P2P_PING_PEER_LIST_DELAY: u64 = 60 * 5;
// maximum number of addresses to be send
pub const P2P_PING_PEER_LIST_LIMIT: usize = 16;
// default number of maximum peers
pub const P2P_DEFAULT_MAX_PEERS: usize = 32;
// time in seconds between each time we try to connect to a new peer
pub const P2P_EXTEND_PEERLIST_DELAY: u64 = 60;

// Peer rules
// number of seconds to reset the counter
// Set to 30 minutes
pub const PEER_FAIL_TIME_RESET: u64 = 30 * 60;
// number of fail to disconnect the peer
pub const PEER_FAIL_LIMIT: u8 = 50;
// number of seconds to temp ban the peer in case of fail reached
// Set to 1 hour
pub const PEER_TEMP_BAN_TIME: u64 = 60 * 60;
// millis until we timeout
pub const PEER_TIMEOUT_REQUEST_OBJECT: u64 = 15000;
// millis until we timeout during a bootstrap request
pub const PEER_TIMEOUT_BOOTSTRAP_STEP: u64 = 60000;
// millis until we timeout during a handshake
pub const PEER_TIMEOUT_INIT_CONNECTION: u64 = 3000;
// 16 additional bytes are for AEAD from ChaCha20Poly1305
pub const PEER_MAX_PACKET_SIZE: u32 = MAX_BLOCK_SIZE as u32 + 16;

// Genesis block to have the same starting point for every nodes
// Genesis block in hexadecimal format
const TESTNET_GENESIS_BLOCK: &str = "0000000000000000000000018dc0f93552000000000000000000000000000000000000000000000000000000000000000000000000000000000000008ac6738cec61a2033103f21b2ed2ddcf8f561eebc7ba4ecab337c484fef8bff6";

// Genesis block getter
// This is necessary to prevent having the same Genesis Block for differents network
// Dev returns none to generate a new genesis block each time it starts a chain
pub fn get_hex_genesis_block(network: &Network) -> Option<&str> {
    match network {
        Network::Mainnet => todo!("Mainnet is not ready yet, please use testnet network"),
        Network::Testnet => Some(TESTNET_GENESIS_BLOCK),
        Network::Dev => None
    }
}

lazy_static! {
    // Developer public key is lazily converted from address to support any network
    pub static ref DEV_PUBLIC_KEY: PublicKey = Address::from_string(&DEV_ADDRESS.to_owned()).unwrap().to_public_key();
}

// Testnet genesis block hash
// It must be the same as the hash of the genesis block
const TESTNET_GENESIS_BLOCK_HASH: Hash = Hash::new([183, 21, 203, 2, 41, 209, 63, 95, 84, 10, 228, 138, 223, 3, 188, 49, 176, 148, 176, 64, 176, 117, 106, 36, 84, 99, 27, 45, 221, 137, 156, 58]);

// Genesis block hash based on network selected
pub fn get_genesis_block_hash(network: &Network) -> &'static Hash {
    match network {
        Network::Mainnet => todo!("Mainnet is not ready yet, please use testnet network"),
        _ => &TESTNET_GENESIS_BLOCK_HASH
    }
}

// Mainnet seed nodes
const MAINNET_SEED_NODES: [&str; 0] = [];
// Testnet seed nodes
const TESTNET_SEED_NODES: [&str; 2] = ["74.208.251.149:2125", "162.19.249.100:2125"];

// Get seed nodes based on the network used
pub const fn get_seed_nodes(network: &Network) -> &[&str] {
    match network {
        Network::Mainnet => &MAINNET_SEED_NODES,
        Network::Testnet => &TESTNET_SEED_NODES,
        Network::Dev => &[],
    }
}