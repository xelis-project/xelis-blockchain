pub const VERSION: &str = "alpha-0.0.1";
pub const NETWORK_ID: [u8; 16] = [0xA, 0xB, 0xC, 0xD, 0xE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xF];
pub const SEED_NODES: [&str; 1] = ["127.0.0.1:2125"]; // ["127.0.0.1:2125", "127.0.0.1:2126", "127.0.0.1:2127", "127.0.0.1:2128"];
pub const DEFAULT_P2P_BIND_ADDRESS: &str = "0.0.0.0:2125";
pub const DEFAULT_RPC_BIND_ADDRESS: &str = "0.0.0.0:8080";

pub const BLOCK_TIME: u64 = 15 * 1000; // Block Time in milliseconds
pub const MINIMUM_DIFFICULTY: u64 = BLOCK_TIME * 1000;
pub const REGISTRATION_DIFFICULTY: u64 = 1/*0_000_000*/;
pub const MAX_BLOCK_SIZE: usize = (1024 * 1024) + (256 * 1024); // 1.25 MB
pub const FEE_PER_KB: u64 = 1000; // 0.01000 XLS per KB
pub const DEV_FEE_PERCENT: u64 = 5; // 5% per block going to dev address

pub const PREFIX_ADDRESS: &str = "xel";
pub const COIN_VALUE: u64 = 100_000; // 5 decimals for a full coin
pub const MAX_SUPPLY: u64 = 18_400_000 * COIN_VALUE; // 18.4M full coin
pub const EMISSION_SPEED_FACTOR: u64 = 21;

pub const GENESIS_BLOCK: &str = "0000000000000001000000000000000000000181399f826500000000000000000000000000000000000000000000000000000000000000000000000000d56ac90000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000d63440000000000000000d78d440345f60976f713f55fb0f2c33c17deef132121eac24109f4712c74d32700000000000000000000000000e4e1c0"; // Genesis block in hexadecimal format
pub const DEV_ADDRESS: &str = "xel167x5gq697cyhdacn740mpukr8staamcnyys74sjpp868ztr56vns8fs7d6"; // Dev address

pub const MAX_BLOCK_REWIND: u64 = 5; // maximum X blocks can be rewinded
pub const CHAIN_SYNC_TIMEOUT_SECS: u64 = 3; // wait maximum between each chain sync request to peers
pub const CHAIN_SYNC_DELAY: u64 = 3; // minimum X seconds between each chain sync request per peer
pub const CHAIN_SYNC_REQUEST_MAX_BLOCKS: usize = 64; // allows up to X blocks id (hash + height) 
pub const P2P_PING_DELAY: u64 = 10; // time between each ping
pub const P2P_PING_PEER_LIST_DELAY: u64 = 15; // time in seconds between each update of peerlist
pub const P2P_PING_PEER_LIST_LIMIT: usize = 16; // maximum number of addresses to be send
pub const P2P_DEFAULT_MAX_PEERS: usize = 32; // default number of maximum peers
pub const PEER_TIMEOUT_REQUEST_OBJECT: u64 = 1500; // millis until we timeout