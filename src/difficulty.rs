use crate::globals::Hash;
use num_bigint::{BigUint, ToBigUint};
use num_traits::{One};
use crate::blockchain::BlockchainError;
use crate::config::{MINIMUM_DIFFICULTY, BLOCK_TIME, WINDOW_DIFFICULTY_BLOCK};
use crate::block::Block;

pub fn check_difficulty(hash: &Hash, difficulty: u64) -> Result<bool, BlockchainError> {
    let big_diff = difficulty_to_big(difficulty)?;
    let big_hash = hash_to_big(hash);

    Ok(big_hash <= big_diff)
}

fn difficulty_to_big(difficulty: u64) -> Result<BigUint, BlockchainError> {
    if difficulty == 0 {
        return Err(BlockchainError::DifficultyCannotBeZero)
    }

    let big_diff = match ToBigUint::to_biguint(&difficulty) {
        Some(v) => v,
        None => return Err(BlockchainError::DifficultyErrorOnConversion)
    };
    let one_lsh_256 = BigUint::one() << 256;
    //println!("difficulty: {} | 1 << 256: {} | diff: {} | result: {}", difficulty, one_lsh_256, big_diff, (&one_lsh_256 / &big_diff));
    Ok(one_lsh_256 / big_diff)
}

fn hash_to_big(hash: &Hash) -> BigUint {
    BigUint::from_bytes_be(hash)
}

pub fn calculate_difficulty(blocks: &Vec<Block>) -> u64 {
    let difficulty = MINIMUM_DIFFICULTY;

    if blocks.len() < 4 {
        return difficulty;
    }

    let mut cumulative_block_time: u64 = 0;
    let max_range = if blocks.len() > WINDOW_DIFFICULTY_BLOCK { WINDOW_DIFFICULTY_BLOCK } else { blocks.len() };
    for i in 1..max_range {
        cumulative_block_time += blocks[i - 1].timestamp - blocks[i].timestamp;
    }

    let average_block_time = cumulative_block_time / max_range as u64; 

    difficulty
}