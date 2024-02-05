use lazy_static::lazy_static;
use xelis_common::{
    block::BlockHeader,
    difficulty::Difficulty,
    config::COIN_VALUE,
    crypto::{
        key::PublicKey, address::Address, hash::{Hash, Hashable}
    },
    serializer::Serializer,
    api::daemon::DevFeeThreshold
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
pub const MINIMUM_DIFFICULTY: Difficulty = BLOCK_TIME_MILLIS as Difficulty * 1000;
pub const GENESIS_BLOCK_DIFFICULTY: Difficulty = 1;
// 1024 * 1024 + (256 * 1024) bytes = 1.25 MB maximum size per block with txs
pub const MAX_BLOCK_SIZE: usize = (1024 * 1024) + (256 * 1024);
// 2 seconds maximum in future (prevent any attack on reducing difficulty but keep margin for unsynced devices)
pub const TIMESTAMP_IN_FUTURE_LIMIT: u128 = 2 * 1000;

// keep at least last N blocks until top topoheight when pruning the chain
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
// 18.4M full coin
pub const MAXIMUM_SUPPLY: u64 = 18_400_000 * COIN_VALUE;

// Genesis block to have the same starting point for every nodes
pub const GENESIS_BLOCK: &str = "0000000000000000000000000000000000000001872f3e0c02000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c24cdc1c8ee8f028b8cafe7b79a66a0902f26d89dd54eeff80abcf251a9a3bd"; // Genesis block in hexadecimal format
// Developer address for paying dev fees until Smart Contracts integration
// (testnet/mainnet format is converted lazily later)
pub const DEV_ADDRESS: &str = "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5";

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
pub const PEER_FAIL_TIME_RESET: u64 = 60 * 5;
// number of fail to disconnect the peer
pub const PEER_FAIL_LIMIT: u8 = 20;
// millis until we timeout
pub const PEER_TIMEOUT_REQUEST_OBJECT: u64 = 15000;
// millis until we timeout
pub const PEER_TIMEOUT_BOOTSTRAP_STEP: u64 = 60000;
// millis until we timeout
pub const PEER_TIMEOUT_INIT_CONNECTION: u64 = 3000;

lazy_static! {
    // Developer public key is lazily converted from address to support any network
    pub static ref DEV_PUBLIC_KEY: PublicKey = Address::from_string(&DEV_ADDRESS.to_owned()).unwrap().to_public_key();
    // Genesis block hash generated from the hex string directly
    pub static ref GENESIS_BLOCK_HASH: Hash = BlockHeader::from_hex(GENESIS_BLOCK.to_owned()).unwrap().hash();
}