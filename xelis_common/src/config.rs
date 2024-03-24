use crate::crypto::Hash;

pub const VERSION: &str = env!("BUILD_VERSION");
pub const XELIS_ASSET: Hash = Hash::zero();

// 0.00010000 XEL per KB
pub const FEE_PER_KB: u64 = 10000;
// 0.0100000 XEL per account creation
// User can create an account with 0.01 XEL
// Or can mine a block to be registered for free
pub const FEE_PER_ACCOUNT_CREATION: u64 = 100000;
// 0.00005000 XEL per KB
// Each transfer has a overhead of 5000 atomic units
pub const FEE_PER_TRANSFER: u64 = 5000;

// 8 decimals numbers
pub const COIN_DECIMALS: u8 = 8;
// 100 000 000 to represent 1 XEL
pub const COIN_VALUE: u64 = 10u64.pow(COIN_DECIMALS as u32);
// 18.4M full coin
pub const MAXIMUM_SUPPLY: u64 = 18_400_000 * COIN_VALUE;

// Addresses format
// mainnet prefix address
pub const PREFIX_ADDRESS: &str = "xel";
// testnet prefix address
pub const TESTNET_PREFIX_ADDRESS: &str = "xet";

// Max transaction size in bytes
pub const MAX_TRANSACTION_SIZE: usize = 1024 * 1024; // 1 MB

// BlockDAG rules
pub const TIPS_LIMIT: usize = 3; // maximum 3 TIPS per block