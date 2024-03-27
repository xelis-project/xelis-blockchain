mod header;
mod block;
mod miner;

pub use header::BlockHeader;
pub use block::Block;
pub use miner::BlockMiner;

pub const EXTRA_NONCE_SIZE: usize = 32;
pub const HEADER_WORK_SIZE: usize = 73;
pub const BLOCK_WORK_SIZE: usize = 112; // 32 + 8 + 8 + 32 + 32 = 112