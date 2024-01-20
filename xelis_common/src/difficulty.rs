use crate::crypto::hash::Hash;
use num_bigint::{BigUint, ToBigUint};
use thiserror::Error;
use num_traits::One;

// This type is used to easily switch between u64 and u128 as example
// And its easier to see where we use the block difficulty
pub type Difficulty = u64;

#[derive(Error, Debug)]
pub enum DifficultyError {
    #[error("Difficulty cannot be a value zero")]
    DifficultyCannotBeZero,
    #[error("Error while converting value to BigUint")]
    ErrorOnConversionBigUint
}

pub fn check_difficulty(hash: &Hash, difficulty: Difficulty) -> Result<bool, DifficultyError> {
    let big_diff = difficulty_to_big(difficulty)?;
    let big_hash = hash_to_big(hash);

    Ok(big_hash <= big_diff)
}

pub fn difficulty_to_big(difficulty: Difficulty) -> Result<BigUint, DifficultyError> {
    if difficulty == 0 {
        return Err(DifficultyError::DifficultyCannotBeZero)
    }

    let big_diff = match ToBigUint::to_biguint(&difficulty) {
        Some(v) => v,
        None => return Err(DifficultyError::ErrorOnConversionBigUint)
    };
    let one_lsh_256 = BigUint::one() << 256;
    Ok(one_lsh_256 / big_diff)
}

pub fn hash_to_big(hash: &Hash) -> BigUint {
    BigUint::from_bytes_be(hash.as_bytes())
}