pub const VERSION: &str = "alpha-0.0.1";
pub const NETWORK_ID: [u8; 16] = [0xA, 0xB, 0xC, 0xD, 0xE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xF];
pub const SEED_NODES: [&str; 1] = ["127.0.0.1:2129"]; // ["127.0.0.1:2125", "127.0.0.1:2126", "127.0.0.1:2127", "127.0.0.1:2128"];
pub const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:2125";

pub const BLOCK_TIME: u64 = 15; // Block Time in seconds
pub const MINIMUM_DIFFICULTY: u64 = BLOCK_TIME * 100_000;
pub const REGISTRATION_DIFFICULTY: u64 = 1/*0_000_000*/;
pub const MAX_BLOCK_SIZE: usize = (1024 * 1024) + (256 * 1024); // 1.25 MB
pub const FEE_PER_KB: u64 = 1000;
pub const DEV_FEE_PERCENT: u64 = 5; // 5% per block going to dev address

pub const PREFIX_ADDRESS: &str = "xel";
pub const COIN_VALUE: u64 = 100_000; // 5 decimals for a full coin
pub const MAX_SUPPLY: u64 = 18_400_000 * COIN_VALUE; // 18.4M full coin
pub const EMISSION_SPEED_FACTOR: u64 = 21;

pub const GENESIS_BLOCK: &str = "00000000000000000000000062543006000000000000000000000000000000000000000000000000000000000000000000000000003eb9d50000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000d63440000000000000000d78d440345f60976f713f55fb0f2c33c17deef132121eac24109f4712c74d3270000000000000000000000000016e360"; // Genesis block in hexadecimal format
pub const DEV_ADDRESS: &str = "xel167x5gq697cyhdacn740mpukr8staamcnyys74sjpp868ztr56vns8fs7d6"; // Dev address

pub const MAX_BLOCK_REWIND: u64 = 5; // maximum 5 blocks can be rewinded
pub const CHAIN_SYNC_TIMEOUT_SECS: u64 = 3; // wait maximum between each chain sync request to peers
pub const CHAIN_SYNC_DELAY: u64 = 3; // minimum 3s between each chain sync request per peer
pub const CHAIN_SYNC_REQUEST_MAX_BLOCKS: usize = 64; // allows up to 64 blocks id (hash + height) 
pub const P2P_PING_DELAY: u64 = 10; // 10s between each handshake update
pub const PEER_TIMEOUT_REQUEST_OBJECT: u64 = 1500; // 1500ms until we timeout
