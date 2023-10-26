use std::f64::consts::E;

use log::trace;
use xelis_common::block::Difficulty;
use crate::config::{STABLE_LIMIT, BLOCK_TIME_MILLIS, MINIMUM_DIFFICULTY};

const M: f64 = STABLE_LIMIT as f64;
const BLOCK_TIME: f64 = BLOCK_TIME_MILLIS as f64;

pub fn calculate_difficulty(parent_timestamp: u128, new_timestamp: u128, previous_difficulty: Difficulty) -> Difficulty {
    let mut solve_time = (new_timestamp - parent_timestamp) as f64;
    if solve_time > BLOCK_TIME * 2f64 {
        solve_time = BLOCK_TIME * 2f64;
    }

    let easypart = (E.powf((1f64 - solve_time as f64 / BLOCK_TIME) / M) * 10000f64) as i64;
    let diff = ((previous_difficulty as i64 * easypart) / 10000) as Difficulty;
    trace!("Difficulty calculated, easypart: {}, previous diff: {}, diff: {}", easypart, previous_difficulty, diff);

    if diff < MINIMUM_DIFFICULTY {
       return MINIMUM_DIFFICULTY
    }

    diff
}