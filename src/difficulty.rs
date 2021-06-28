use crate::globals::Hash;
use num_bigint::{BigUint, ToBigUint};
use num_traits::{One};
use crate::blockchain::BlockchainError;

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