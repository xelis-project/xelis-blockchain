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
pub fn calculate_difficulty(parent_timestamp: u128, new_timestamp: u128, previous_difficulty: Difficulty) -> Difficulty {
    let mut solve_time = (new_timestamp - parent_timestamp) as f64;

    // Limit to 2x the block time to prevent any too-big difficulty drop
    if solve_time > BLOCK_TIME * 2f64 {
        solve_time = BLOCK_TIME * 2f64;
    }

    let adjustment_factor = (E.powf((1f64 - solve_time as f64 / BLOCK_TIME) / M) * FACTOR as f64) as i64;
    let diff = ((previous_difficulty as i64 * adjustment_factor) / FACTOR) as Difficulty;
    trace!("adjustment factor: {}, previous difficulty: {}, new difficulty: {}", adjustment_factor, previous_difficulty, diff);

    if diff < MINIMUM_DIFFICULTY {
       return MINIMUM_DIFFICULTY
    }

    diff
}