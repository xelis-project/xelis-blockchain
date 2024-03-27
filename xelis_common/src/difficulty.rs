use crate::{varuint::VarUint, crypto::Hash};
use primitive_types::U256;
use thiserror::Error;

// This type is used to easily switch between u64 and u128 as example
// And its easier to see where we use the block difficulty
// Difficulty is a value that represents the amount of work required to mine a block
// On XELIS, each difficulty point is a hash per second
pub type Difficulty = VarUint;
// Cumulative difficulty is the sum of all difficulties of all blocks in the chain
// It is used to determine which branch is the main chain in BlockDAG merging.
pub type CumulativeDifficulty = VarUint;

#[derive(Error, Debug)]
pub enum DifficultyError {
    #[error("Difficulty cannot be a value zero")]
    DifficultyCannotBeZero,
    #[error("Error while converting value to BigUint")]
    ErrorOnConversionBigUint
}

// Verify the validity of a block difficulty against the current network difficulty
// All operations are done on U256 to avoid overflow
pub fn check_difficulty(hash: &Hash, difficulty: &Difficulty) -> Result<bool, DifficultyError> {
    let target = compute_difficulty_target(difficulty)?;
    Ok(check_difficulty_against_target(hash, &target))
}

// Compute the difficulty target from the difficulty value
// This can be used to keep the target in cache instead of recomputing it each time
pub fn compute_difficulty_target(difficulty: &Difficulty) -> Result<U256, DifficultyError> {
    let diff = difficulty.as_ref();
    if diff.is_zero() {
        return Err(DifficultyError::DifficultyCannotBeZero)
    }

    Ok(U256::max_value() / diff)
}

// Check if the hash is below the target difficulty
pub fn check_difficulty_against_target(hash: &Hash, target: &U256) -> bool {
    let hash_work = U256::from_big_endian(hash.as_bytes());
    hash_work <= *target
}

// Convert a hash to a difficulty value
// This is only used by miner
#[inline(always)]
pub fn difficulty_from_hash(hash: &Hash) -> Difficulty {
    (U256::max_value() / U256::from_big_endian(hash.as_bytes())).into()
}