pub const VERSION: &str = "alpha-0.0.1";
pub const NETWORK_ID: [u8; 16] = [0xA, 0xB, 0xC, 0xD, 0xE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xF];
pub const SEED_NODES: [&str; 1] = ["127.0.0.1:2125"]; // ["127.0.0.1:2125", "127.0.0.1:2126", "127.0.0.1:2127", "127.0.0.1:2128"];
pub const DEFAULT_P2P_BIND_ADDRESS: &str = "0.0.0.0:2125";
pub const DEFAULT_RPC_BIND_ADDRESS: &str = "0.0.0.0:8080";
pub const DEFAULT_DIR_PATH: &str = "mainnet";

pub const BLOCK_TIME: u64 = 15 * 1000; // Block Time in milliseconds
pub const MINIMUM_DIFFICULTY: u64 = BLOCK_TIME * 10;
pub const REGISTRATION_DIFFICULTY: u64 = 1/*0_000_000*/;
pub const MAX_BLOCK_SIZE: usize = (1024 * 1024) + (256 * 1024); // 1.25 MB
pub const FEE_PER_KB: u64 = 1000; // 0.01000 XLS per KB
pub const DEV_FEE_PERCENT: u64 = 5; // 5% per block going to dev address

pub const PREFIX_ADDRESS: &str = "xel"; // mainnet prefix address
pub const TESTNET_PREFIX_ADDRESS: &str = "xet"; // testnet prefix address
pub const COIN_VALUE: u64 = 100_000; // 5 decimals for a full coin
pub const MAX_SUPPLY: u64 = 18_400_000 * COIN_VALUE; // 18.4M full coin
pub const EMISSION_SPEED_FACTOR: u64 = 21;

pub const GENESIS_BLOCK: &str = "0000000000000001000000000000000000000181a6c150b90000000000000000000000000000000000000000000000000000000000000000000000000000a8ac000000000000000000000000000000000000000000000000000000000000000000006c24cdc1c8ee8f028b8cafe7b79a66a0902f26d89dd54eeff80abcf251a9a3bd0200000000000249f0"; // Genesis block in hexadecimal format
pub const DEV_ADDRESS: &str = "xel1qyqxcfxdc8ywarcz3wx2leahnfn2pyp0ymvfm42waluq408j2x5680g05xfx5"; // Dev address

pub const MAX_BLOCK_REWIND: u64 = 5; // maximum X blocks can be rewinded
pub const CHAIN_SYNC_TIMEOUT_SECS: u64 = 3; // wait maximum between each chain sync request to peers
pub const CHAIN_SYNC_DELAY: u64 = 3; // minimum X seconds between each chain sync request per peer
pub const CHAIN_SYNC_REQUEST_MAX_BLOCKS: usize = 64; // allows up to X blocks id (hash + height) 
pub const P2P_PING_DELAY: u64 = 10; // time between each ping
pub const P2P_PING_PEER_LIST_DELAY: u64 = 15; // time in seconds between each update of peerlist
pub const P2P_PING_PEER_LIST_LIMIT: usize = 16; // maximum number of addresses to be send
pub const P2P_DEFAULT_MAX_PEERS: usize = 32; // default number of maximum peers
pub const PEER_TIMEOUT_REQUEST_OBJECT: u64 = 1500; // millis until we timeout