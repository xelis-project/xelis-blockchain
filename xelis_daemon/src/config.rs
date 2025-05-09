use lazy_static::lazy_static;
use xelis_common::{
    api::daemon::{DevFeeThreshold, HardFork},
    block::BlockVersion,
    config::MAX_BLOCK_SIZE,
    crypto::{
        Address,
        Hash,
        PublicKey
    },
    difficulty::Difficulty,
    network::Network,
    time::TimestampSeconds
};

// In case of potential forks, have a unique network id to not connect to others compatible chains
pub const NETWORK_ID_SIZE: usize = 16;
pub const NETWORK_ID: [u8; NETWORK_ID_SIZE] = [0x73, 0x6c, 0x69, 0x78, 0x65, 0x5f, 0x78, 0x65, 0x6c, 0x69, 0x73, 0x5f, 0x62, 0x6c, 0x6f, 0x63];

// bind addresses
pub const DEFAULT_P2P_BIND_ADDRESS: &str = "0.0.0.0:2125";
pub const DEFAULT_RPC_BIND_ADDRESS: &str = "0.0.0.0:8080";

// Default cache size for storage DB
pub const DEFAULT_CACHE_SIZE: usize = 1024;

// Block rules
// Millis per second, it is used to prevent having random 1000 values anywhere
pub const MILLIS_PER_SECOND: u64 = 1000;
// Block Time in milliseconds
// 15s block time
pub const BLOCK_TIME_MILLIS: u64 = 15 * MILLIS_PER_SECOND;

// Constants for hashrate
// Used for difficulty calculation
// and to be easier to read
pub const HASH: u64 = 1;
pub const KILO_HASH: u64 = HASH * 1000;
pub const MEGA_HASH: u64 = KILO_HASH * 1000;
pub const GIGA_HASH: u64 = MEGA_HASH * 1000;
pub const TERA_HASH: u64 = GIGA_HASH * 1000;

// Minimum difficulty is calculated the following (each difficulty point is in H/s)
// BLOCK TIME in millis * N = minimum hashrate
// This is to prevent spamming the network with low difficulty blocks
// and is only active on mainnet
// Currently set to 20 KH/s
pub const MAINNET_MINIMUM_HASHRATE: u64 = 20 * KILO_HASH;
// Testnet & Devnet minimum hashrate
// Currently set to 2 KH/s
pub const DEFAULT_MINIMUM_HASHRATE: u64 = 2 * KILO_HASH;

// This is also used as testnet and devnet minimum difficulty
pub const GENESIS_BLOCK_DIFFICULTY: Difficulty = Difficulty::from_u64(1 * HASH);

// 2 seconds maximum in future (prevent any attack on reducing difficulty but keep margin for unsynced devices)
pub const TIMESTAMP_IN_FUTURE_LIMIT: TimestampSeconds = 2 * MILLIS_PER_SECOND;

// keep at least last N blocks until top topoheight when pruning the chain
// WARNING: This must be at least 50 blocks for difficulty adjustement
pub const PRUNE_SAFETY_LIMIT: u64 = STABLE_LIMIT * 10;

// BlockDAG rules
// in how many height we consider the block stable
pub const STABLE_LIMIT: u64 = 8;

// Emission rules
// 15% (6 months), 10% (6 months), 5% per block going to dev address
// NOTE: The explained emission above was the expected one
// But due to a bug in the function to calculate the dev fee reward,
// the actual emission was directly set to 10% per block
// New emission rules are: 10% during 1.5 years, then 5% for the rest
// This is the same for the project but reduce a bit the mining cost as they earn 5% more
pub const DEV_FEES: [DevFeeThreshold; 2] = [
    // Activated for 3M blocks
    DevFeeThreshold {
        height: 0,
        fee_percentage: 10
    },
    // Activated for the rest
    DevFeeThreshold {
        // after ~1.5 year it's reduced to 5%
        // 3 250 000 blocks * 15s of block time / 60s / 60m / 24h / 365d = 1.5 years
        height: 3_250_000, 
        fee_percentage: 5
    }
];
// only 30% of reward for side block
// This is to prevent spamming side blocks
// and also give rewards for miners with valid work on main chain
pub const SIDE_BLOCK_REWARD_PERCENT: u64 = 30;
// maximum 3 blocks for side block reward
// Each side block reward will be divided by the number of side blocks * 2
// With a configuration of 3 blocks, we have the following percents:
// 1 block: 30%
// 2 blocks: 15%
// 3 blocks: 7%
// 4 blocks: minimum percentage set below
pub const SIDE_BLOCK_REWARD_MAX_BLOCKS: u64 = 3;
// minimum 5% of block reward for side block
// This is the minimum given for all others valid side blocks
pub const SIDE_BLOCK_REWARD_MIN_PERCENT: u64 = 5;
// Emission speed factor for the emission curve
// It is used to calculate based on the supply the block reward
pub const EMISSION_SPEED_FACTOR: u64 = 20;

// Developer address for paying dev fees until Smart Contracts integration
// (testnet/mainnet format is converted lazily later)
pub const DEV_ADDRESS: &str = "xel:vs3mfyywt0fjys0rgslue7mm4wr23xdgejsjk0ld7f2kxng4d4nqqnkdufz";

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
// time in seconds between each time we try to connect to a outgoing peer
// At least 5 minutes of countdown to retry to connect to the same peer
// This will be multiplied by the number of fails
pub const P2P_PEERLIST_RETRY_AFTER: u64 = 60 * 15;
// Peer wait on error accept new p2p connections in seconds
pub const P2P_PEER_WAIT_ON_ERROR: u64 = 15;
// Delay in second to connect to priority nodes
pub const P2P_AUTO_CONNECT_PRIORITY_NODES_DELAY: u64 = 5;
// Default number of concurrent tasks for incoming p2p connections
pub const P2P_DEFAULT_CONCURRENCY_TASK_COUNT_LIMIT: usize = 4;
// Heartbeat interval in seconds to check if peer is still alive
pub const P2P_HEARTBEAT_INTERVAL: u64 = P2P_PING_DELAY / 2;
// Timeout in seconds
// If we didn't receive any packet from a peer during this time, we disconnect it
pub const P2P_PING_TIMEOUT: u64 = P2P_PING_DELAY * 6;

// Peer rules
// number of seconds to reset the counter
// Set to 30 minutes
pub const PEER_FAIL_TIME_RESET: u64 = 30 * 60;
// number of fail to disconnect the peer
pub const PEER_FAIL_LIMIT: u8 = 50;
// number of fail during handshake before temp ban
pub const PEER_FAIL_TO_CONNECT_LIMIT: u8 = 3;
// number of seconds to temp ban the peer in case of fail reached during handshake
// It is only used for incoming connections
// Set to 1 minute
pub const PEER_TEMP_BAN_TIME_ON_CONNECT: u64 = 60;
// number of seconds to temp ban the peer in case of fail count limit (`PEER_FAIL_LIMIT`) reached
// Set to 15 minutes
pub const PEER_TEMP_BAN_TIME: u64 = 15 * 60;
// millis until we timeout
pub const PEER_TIMEOUT_REQUEST_OBJECT: u64 = 15_000;
// millis until we timeout during a bootstrap request
pub const PEER_TIMEOUT_BOOTSTRAP_STEP: u64 = 60_000;
// millis until we timeout during a handshake
pub const PEER_TIMEOUT_INIT_CONNECTION: u64 = 5_000;
// millis until we timeout during outgoing connection try
pub const PEER_TIMEOUT_INIT_OUTGOING_CONNECTION: u64 = 30_000;
// millis until we timeout during a handshake
pub const PEER_TIMEOUT_DISCONNECT: u64 = 1_500;
// 16 additional bytes are for AEAD from ChaCha20Poly1305
pub const PEER_MAX_PACKET_SIZE: u32 = MAX_BLOCK_SIZE as u32 + 16;
// Peer TX cache size
// This is how many elements are stored in the LRU cache at maximum
pub const PEER_TX_CACHE_SIZE: usize = 10240;
// How many peers propagated are stored per peer in the LRU cache at maximum
pub const PEER_PEERS_CACHE_SIZE: usize = 1024;
// Peer Block cache size
pub const PEER_BLOCK_CACHE_SIZE: usize = 1024;
// Peer packet channel size
pub const PEER_PACKET_CHANNEL_SIZE: usize = 1024;
// Peer timeout for packet channel
// Millis
pub const PEER_SEND_BYTES_TIMEOUT: u64 = 3_000;

// Hard Forks configured
const HARD_FORKS: [HardFork; 3] = [
    HardFork {
        height: 0,
        version: BlockVersion::V0,
        changelog: "Initial version",
        version_requirement: None
    },
    HardFork {
        // Expected date: 10/07/2024 12am UTC
        height: 434_100,
        version: BlockVersion::V1,
        changelog: "xelis-hash v2",
        version_requirement: Some(">=1.13.0")
    },
    HardFork {
        // Expected date: 30/12/2024 9pm UTC
        height: 1_376_000,
        version: BlockVersion::V2,
        changelog: "MultiSig, P2P",
        version_requirement: Some(">=1.16.0")
    }
];

// Testnet / Devnet hard forks
const TESTNET_HARD_FORKS: [HardFork; 4] = [
    HardFork {
        height: 0,
        version: BlockVersion::V0,
        changelog: "Initial version",
        version_requirement: None
    },
    HardFork {
        height: 5,
        version: BlockVersion::V1,
        changelog: "xelis-hash v2",
        version_requirement: Some(">=1.13.0")
    },
    HardFork {
        height: 10,
        version: BlockVersion::V2,
        changelog: "MultiSig, P2P",
        version_requirement: Some(">=1.16.0")
    },
    HardFork {
        height: 15,
        version: BlockVersion::V3,
        changelog: "Smart Contracts",
        version_requirement: Some(">=1.16.0")
    }
];

// Mainnet seed nodes
const MAINNET_SEED_NODES: [&str; 7] = [
    // France
    "51.210.117.23:2125",
    // US
    "198.71.55.87:2125",
    // Germany
    "162.19.249.100:2125",
    // Singapore
    "139.99.89.27:2125",
    // Poland
    "51.68.142.141:2125",
    // Great Britain
    "51.195.220.137:2125",
    // "Canada"
    "66.70.179.137:2125"
];

// Testnet seed nodes
const TESTNET_SEED_NODES: [&str; 1] = [
    // US
    "74.208.251.149:2125",
];

// Genesis block to have the same starting point for every nodes
// Genesis block in hexadecimal format
const MAINNET_GENESIS_BLOCK: &str = "0000000000000000000000018efc057580000000000000000000000000000000000000000000000000000000000000000000000000000000000000006423b4908e5bd32241e3443fccfb7bab86a899a8cca12b3fedf255634d156d66";
const TESTNET_GENESIS_BLOCK: &str = "0000000000000000000000018f116b47cf000000000000000000000000000000000000000000000000000000000000000000000000000000000000006423b4908e5bd32241e3443fccfb7bab86a899a8cca12b3fedf255634d156d66";

// Genesis block hash for both networks
// It must be the same as the hash of the genesis block
const MAINNET_GENESIS_BLOCK_HASH: Hash = Hash::new([175, 118, 37, 203, 175, 200, 25, 148, 9, 202, 29, 120, 93, 128, 36, 209, 146, 193, 217, 36, 61, 51, 24, 194, 114, 113, 121, 208, 237, 163, 27, 55]);
const TESTNET_GENESIS_BLOCK_HASH: Hash = Hash::new([171, 50, 219, 186, 28, 164, 189, 225, 197, 167, 187, 143, 213, 59, 217, 238, 51, 242, 133, 181, 188, 235, 151, 50, 110, 33, 185, 188, 100, 146, 23, 132]);

// Genesis block getter
// This is necessary to prevent having the same Genesis Block for differents network
// Dev returns none to generate a new genesis block each time it starts a chain
pub fn get_hex_genesis_block(network: &Network) -> Option<&str> {
    match network {
        Network::Mainnet => Some(MAINNET_GENESIS_BLOCK),
        Network::Testnet => Some(TESTNET_GENESIS_BLOCK),
        Network::Dev => None
    }
}

lazy_static! {
    // Developer public key is lazily converted from address to support any network
    pub static ref DEV_PUBLIC_KEY: PublicKey = Address::from_string(&DEV_ADDRESS)
        .expect("valid dev address")
        .to_public_key();
}

// Genesis block hash based on network selected
pub fn get_genesis_block_hash(network: &Network) -> Option<&'static Hash> {
    match network {
        Network::Mainnet => Some(&MAINNET_GENESIS_BLOCK_HASH),
        Network::Testnet => Some(&TESTNET_GENESIS_BLOCK_HASH),
        Network::Dev => None
    }
}

// Get seed nodes based on the network used
pub const fn get_seed_nodes(network: &Network) -> &[&str] {
    match network {
        Network::Mainnet => &MAINNET_SEED_NODES,
        Network::Testnet => &TESTNET_SEED_NODES,
        Network::Dev => &[],
    }
}

// Get hard forks based on the network
pub const fn get_hard_forks(network: &Network) -> &[HardFork] {
    match network {
        Network::Mainnet => &HARD_FORKS,
        _ => &TESTNET_HARD_FORKS,
    }
}