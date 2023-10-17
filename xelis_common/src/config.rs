use crate::crypto::hash::Hash;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const XELIS_ASSET: Hash = Hash::zero();
// 0.01000 XLS per KB
pub const FEE_PER_KB: u64 = 1000;
pub const COIN_DECIMALS: u8 = 5; // 5 decimals numbers
pub const COIN_VALUE: u64 = 10u64.pow(COIN_DECIMALS as u32); // 100 000

// Addresses format
pub const PREFIX_ADDRESS: &str = "xel"; // mainnet prefix address
pub const TESTNET_PREFIX_ADDRESS: &str = "xet"; // testnet prefix address