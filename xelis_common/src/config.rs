use crate::{
    contract::register_opaque_types,
    crypto::Hash,
    static_assert
};

pub const VERSION: &str = env!("BUILD_VERSION");
pub const XELIS_ASSET: Hash = Hash::zero();

// Lowest fee per KB possible on the network
// 0.00010000 XEL per KB
pub const FEE_PER_KB: u64 = 10_000;
// 0.00100000 XEL per account creation
// User can create an account with 0.001 XEL
// Or can mine a block to be registered for free
pub const FEE_PER_ACCOUNT_CREATION: u64 = 100_000;
// 0.00005000 XEL per KB
// Each transfer has a overhead of 5000 atomic units
pub const FEE_PER_TRANSFER: u64 = 5_000;
// 0.00005000 XEL per KB
// Each signature from multisig has a overhead of 5000 atomic units
pub const FEE_PER_EXTRA_SIGNATURE: u64 = 5_000;
// 30% of the extra TX base fee is burned.
// extra TX base fee is calculated such as:
// extra = required base fee - FEE_PER_KB
// on the extra base fee, we take configured percentage
// that is burned by the protocol.
// This way, we ensures no dishonest miner can cheat by spamming
// free heavy TXs to increase the base fee.
pub const EXTRA_BASE_FEE_BURN_PERCENT: u64 = 30;

// Contracts rules
// 1 XEL per contract deployed
// Each contract deployed has a overhead of 1 XEL
// This amount is burned and is needed for safety of the chain
// Otherwise people could bloat the chain by deploying contracts
// And could make the chain unusable or slow
// Note that if we depends on fees only, miners could do such attacks for free
// by mining their own transactions and getting the fees back
pub const BURN_PER_CONTRACT: u64 = COIN_VALUE;
// 1 XEL per asset created
// This is to prevent spamming the network with tokens
pub const COST_PER_ASSET: u64 = COIN_VALUE;
// Cost in XEL to burn to schedule an execution
// at a specific topoheight
// This is set to 0.0005
pub const COST_PER_SCHEDULED_EXECUTION: u64 = 50_000;
// Cost in XEL to burn to schedule an execution
// at the end of the same block
// This is set to 0.00005
pub const COST_PER_SCHEDULED_EXECUTION_AT_BLOCK_END: u64 = 5_000;

// 30% of the transaction fee is burned
// This is to reduce the supply over time
// and also to prevent spamming the network with low fee transactions
// or free tx from miners
// This should be enabled once Smart Contracts are released
pub const TX_GAS_BURN_PERCENT: u64 = 30;
// Fee per store operation in a contract
// Each store operation has a fixed cost of 0.00000100 XEL
pub const FEE_PER_STORE_CONTRACT: u64 = 100;
// Fee per read operation in a contract
// Each read operation has a fixed cost of 0.00000025 XEL
pub const FEE_PER_READ_CONTRACT: u64 = 25;
// Fee per byte of data stored in a contract
// Each byte of data stored (key + value) in a contract has a fixed cost
// 0.00000005 XEL per byte
pub const FEE_PER_BYTE_STORED_CONTRACT: u64 = 5;
// Fee per byte of data stored in a contract memory
// Each byte of data stored in the contract memory has a fixed cost
pub const FEE_PER_BYTE_IN_CONTRACT_MEMORY: u64 = 1;
// Fee per byte of data used to emit an event
// Data is not stored, but only exposed to websocket listeners
pub const FEE_PER_BYTE_OF_EVENT_DATA: u64 = 2;
// Max gas usage available per block
// Currently, set to 0.5 XEL per transaction
pub const MAX_GAS_USAGE_PER_TX: u64 = COIN_VALUE / 2;

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

// Proof prefix
pub const PREFIX_PROOF: &str = "proof";

// 1 KB = 1024 bytes
pub const BYTES_PER_KB: usize = 1024;

// Max transaction size in bytes
pub const MAX_TRANSACTION_SIZE: usize = BYTES_PER_KB * BYTES_PER_KB; // 1 MB

// Max block size in bytes
// 1024 * 1024 + (256 * 1024) bytes = 1.25 MB maximum size per block with txs
pub const MAX_BLOCK_SIZE: usize = (BYTES_PER_KB * BYTES_PER_KB) + (256 * BYTES_PER_KB);

// BlockDAG rules
pub const TIPS_LIMIT: usize = 3; // maximum 3 TIPS per block

// Initialize the configuration
pub fn init() {
    // register the opaque types
    register_opaque_types();
}


// Static checks
static_assert!(MAX_TRANSACTION_SIZE <= MAX_BLOCK_SIZE, "Max transaction size must be less than or equal to max block size");
static_assert!(MAXIMUM_SUPPLY >= COIN_VALUE, "Maximum supply must be greater than or equal to coin value");