use crate::crypto::hash::Hash;
use num_bigint::{BigUint, ToBigUint};
use num_traits::{One};
use super::error::BlockchainError;
use crate::config::{MINIMUM_DIFFICULTY, BLOCK_TIME};
use super::block::CompleteBlock;

pub fn check_difficulty(hash: &Hash, difficulty: u64) -> Result<bool, BlockchainError> {
    let big_diff = difficulty_to_big(difficulty)?;
    let big_hash = hash_to_big(hash);

    Ok(big_hash <= big_diff)
}

pub fn difficulty_to_big(difficulty: u64) -> Result<BigUint, BlockchainError> {
    if difficulty == 0 {
        return Err(BlockchainError::DifficultyCannotBeZero)
    }

    let big_diff = match ToBigUint::to_biguint(&difficulty) {
        Some(v) => v,
        None => return Err(BlockchainError::DifficultyErrorOnConversion)
    };
    let one_lsh_256 = BigUint::one() << 256;
    Ok(one_lsh_256 / big_diff)
}

pub fn hash_to_big(hash: &Hash) -> BigUint {
    BigUint::from_bytes_be(hash.as_bytes())
}

pub fn calculate_difficulty(parent_block: &CompleteBlock, new_block: &CompleteBlock) -> u64 {
    let timestamp_diff: u64 = new_block.get_timestamp() - parent_block.get_timestamp();
    let parent_diff = parent_block.get_difficulty();
    // (parent_diff + (parent_diff / 100 * max(1 - (block_timestamp - parent_timestamp) / (expected_block_time * 2 / 3), -99))
    let ratio: i64 = max(1 - timestamp_diff as i64 / (BLOCK_TIME as i64 * 2 / 3), -99);
    let diff = ((parent_diff / 100) as i64) * ratio;
    let block_diff: u64 = (parent_diff as i64 + diff) as u64;

    if block_diff < MINIMUM_DIFFICULTY {
       return MINIMUM_DIFFICULTY
    }

    block_diff
}

fn max(left: i64, right: i64) -> i64 {
    if left > right {
        return left
    }

    return right
}