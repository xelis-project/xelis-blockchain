use crate::{varuint::VarUint, crypto::hash::Hash};
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
pub fn check_difficulty(hash: &Hash, difficulty: &Difficulty) -> Result<bool, DifficultyError> {
    let diff = difficulty.as_ref();
    let hash_work = U256::from_big_endian(hash.as_bytes());

    Ok(hash_work <= *diff)
}