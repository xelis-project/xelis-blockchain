use lazy_static::lazy_static;

use crate::{crypto::{hash::Hash, key::PublicKey, address::Address}, serializer::Serializer};
pub const NETWORK_ID_SIZE: usize = 16;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NETWORK_ID: [u8; NETWORK_ID_SIZE] = [0x73, 0x6c, 0x69, 0x78, 0x65, 0x5f, 0x78, 0x65, 0x6c, 0x69, 0x73, 0x5f, 0x62, 0x6c, 0x6f, 0x63];
pub const SEED_NODES: [&str; 2] = ["74.208.251.149:2125", "217.160.96.80:2125"];
pub const DEFAULT_P2P_BIND_ADDRESS: &str = "0.0.0.0:2125";
pub const DEFAULT_RPC_BIND_ADDRESS: &str = "0.0.0.0:8080";
pub const DEFAULT_CACHE_SIZE: usize = 1024;
pub const XELIS_ASSET: Hash = Hash::zero();
pub const SIDE_BLOCK_REWARD_PERCENT: u64 = 30; // only 30% of reward for side block
pub const BLOCK_TIME: u64 = 15; // Block Time in seconds
pub const BLOCK_TIME_MILLIS: u64 = BLOCK_TIME * 1000; // Block Time in milliseconds
pub const MINIMUM_DIFFICULTY: u64 = BLOCK_TIME_MILLIS * 10;
pub const GENESIS_BLOCK_DIFFICULTY: u64 = 1;
pub const MAX_BLOCK_SIZE: usize = (1024 * 1024) + (256 * 1024); // 1.25 MB
pub const FEE_PER_KB: u64 = 1000; // 0.01000 XLS per KB
pub const DEV_FEE_PERCENT: u64 = 5; // 5% per block going to dev address
pub const TIPS_LIMIT: usize = 3; // maximum 3 previous blocks
pub const STABLE_HEIGHT_LIMIT: u64 = 8;
pub const TIMESTAMP_IN_FUTURE_LIMIT: u128 = 2 * 1000; // 2 seconds maximum in future

pub const PREFIX_ADDRESS: &str = "xel"; // mainnet prefix address
pub const TESTNET_PREFIX_ADDRESS: &str = "xet"; // testnet prefix address
pub const COIN_VALUE: u64 = 100_000; // 5 decimals for a full coin
pub const MAX_SUPPLY: u64 = 18_400_000 * COIN_VALUE; // 18.4M full coin
pub const EMISSION_SPEED_FACTOR: u64 = 21;

pub const GENESIS_BLOCK: &str = "000000000000000000000000000000000000018656cff68a000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c24cdc1c8ee8f028b8cafe7b79a66a0902f26d89dd54eeff80abcf251a9a3bd"; // Genesis block in hexadecimal format
pub const GENESIS_BLOCK_HASH_STR: &str = "007957a0f04d08ff6f75a99ae37a25e43c640be68bd223c6af86c7f572352d73";
pub const DEV_ADDRESS: &str = "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5"; // Dev address

pub const MAX_BLOCK_REWIND: u64 = STABLE_HEIGHT_LIMIT - 1; // maximum X blocks can be rewinded
pub const CHAIN_SYNC_TIMEOUT_SECS: u64 = 3; // wait maximum between each chain sync request to peers
pub const CHAIN_SYNC_DELAY: u64 = 5; // minimum X seconds between each chain sync request per peer
pub const CHAIN_SYNC_REQUEST_MAX_BLOCKS: usize = 64; // allows up to X blocks id (hash + height) sent for request
pub const CHAIN_SYNC_RESPONSE_MAX_BLOCKS: usize = 512; // allows up to X blocks hashes sent for response
pub const CHAIN_SYNC_TOP_BLOCKS: usize = 10; // send last 10 heights
pub const P2P_PING_DELAY: u64 = 10; // time between each ping
pub const P2P_PING_PEER_LIST_DELAY: u64 = 60 * 5; // time in seconds between each update of peerlist
pub const P2P_PING_PEER_LIST_LIMIT: usize = 16; // maximum number of addresses to be send
pub const P2P_DEFAULT_MAX_PEERS: usize = 32; // default number of maximum peers
pub const PEER_FAIL_TIME_RESET: u64 = 60 * 5; // number of seconds to reset the counter
pub const PEER_FAIL_LIMIT: u8 = 20; // number of fail to disconnect the peer
pub const PEER_TIMEOUT_REQUEST_OBJECT: u64 = 3000; // millis until we timeout

// Wallet config
pub const DEFAULT_DAEMON_ADDRESS: &str = "http://127.0.0.1:8080";

lazy_static! {
    pub static ref DEV_PUBLIC_KEY: PublicKey = Address::from_string(&DEV_ADDRESS.to_owned()).unwrap().to_public_key();
    pub static ref GENESIS_BLOCK_HASH: Hash = Hash::from_hex(GENESIS_BLOCK_HASH_STR.to_string()).unwrap();
}