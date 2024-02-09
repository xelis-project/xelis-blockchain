use std::f64::consts::E;

use log::trace;
use xelis_common::difficulty::Difficulty;
use crate::config::{STABLE_LIMIT, BLOCK_TIME_MILLIS, MINIMUM_DIFFICULTY};

const M: f64 = STABLE_LIMIT as f64;
const BLOCK_TIME: f64 = BLOCK_TIME_MILLIS as f64;
const FACTOR: i64 = 10000;

// Calculate the difficulty for the next block
// Difficulty jump can happen easily but drop is limited to 2x the block time
// This is to prevent any attack on the difficulty where a miner would try to manipulate the network
pub fn calculate_difficulty_v1(parent_timestamp: u128, new_timestamp: u128, previous_difficulty: Difficulty) -> Difficulty {
    let mut solve_time = (new_timestamp - parent_timestamp) as f64;

    // Limit to 2x the block time to prevent any too-big difficulty drop
    if solve_time > BLOCK_TIME * 2f64 {
        solve_time = BLOCK_TIME * 2f64;
    }

    let previous_difficulty: u64 = previous_difficulty.into();
    let adjustment_factor = (E.powf((1f64 - solve_time as f64 / BLOCK_TIME) / M) * FACTOR as f64) as i64;
    let diff = (((previous_difficulty as i64 * adjustment_factor) / FACTOR) as u64).into();
    trace!("adjustment factor: {}, previous difficulty: {}, new difficulty: {}", adjustment_factor, previous_difficulty, diff);

    if diff < MINIMUM_DIFFICULTY {
       return MINIMUM_DIFFICULTY
    }

    diff
}

const DIFFICULTY_BOUND_DIVISOR: Difficulty = Difficulty::from_u64(2048);
const CHAIN_TIME_RANGE: u64 = BLOCK_TIME_MILLIS * 2 / 3;

// Difficulty algorithm from Ethereum: Homestead but tweaked for our needs
pub fn calculate_difficulty(tips_count: u64, parent_timestamp: u128, new_timestamp: u128, previous_difficulty: Difficulty) -> Difficulty {
    // For current testnet, keep using same algorithm
    if true {
        return calculate_difficulty_v1(parent_timestamp, new_timestamp, previous_difficulty);
    }

    let mut adjust = previous_difficulty / DIFFICULTY_BOUND_DIVISOR;
    let mut x = (new_timestamp - parent_timestamp) as u64 / CHAIN_TIME_RANGE;
    trace!("x: {x}, tips count: {tips_count}, adjust: {adjust}");
    let neg = x >= tips_count;
    if x == 0 {
        x = x - tips_count;
    } else {
        x = tips_count - x;
    }

    // max(x, 99)
    if x > 99 {
        x = 99;
    }

    let x: Difficulty = x.into();
    // Compute the new diff based on the adjustement
    adjust = adjust * x;
    let new_diff = if neg {
        previous_difficulty - adjust
    } else {
        previous_difficulty + adjust
    };

    trace!("previous diff: {} new diff: {}", previous_difficulty, new_diff);

    if new_diff < MINIMUM_DIFFICULTY {
        return MINIMUM_DIFFICULTY
    }

    new_diff
}