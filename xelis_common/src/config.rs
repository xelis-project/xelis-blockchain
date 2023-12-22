use crate::crypto::hash::Hash;

pub const VERSION: &str = env!("BUILD_VERSION");
pub const XELIS_ASSET: Hash = Hash::zero();
// 0.01000 XEL per KB
pub const FEE_PER_KB: u64 = 1000;
// 5 decimals numbers
pub const COIN_DECIMALS: u8 = 5;
// 100 000 to represent 1 XEL
pub const COIN_VALUE: u64 = 10u64.pow(COIN_DECIMALS as u32);

// Addresses format
// mainnet prefix address
pub const PREFIX_ADDRESS: &str = "xel";
// testnet prefix address
pub const TESTNET_PREFIX_ADDRESS: &str = "xet";

// Max transaction size in bytes
pub const MAX_TRANSACTION_SIZE: usize = 1024 * 1024; // 1 MB