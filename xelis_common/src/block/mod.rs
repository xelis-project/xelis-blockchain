mod header;
mod block;
mod miner;

pub use header::BlockHeader;
pub use block::Block;
pub use miner::BlockMiner;

use crate::crypto::{Hash, HASH_SIZE};

pub const EXTRA_NONCE_SIZE: usize = 32;
pub const HEADER_WORK_SIZE: usize = 137;
pub const BLOCK_WORK_SIZE: usize = 112; // 32 + 8 + 8 + 32 + 32 = 112

// Get combined hash for tips
// This is used to get a hash that is unique for a set of tips
pub fn get_combined_hash_for_tips<'a, I: Iterator<Item = &'a Hash>>(tips: I) -> Hash {
    let mut bytes = [0u8; HASH_SIZE];
    for tip in tips {
        for i in 0..HASH_SIZE {
            bytes[i] ^= tip.as_bytes()[i];
        }
    }
    Hash::new(bytes)
}