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