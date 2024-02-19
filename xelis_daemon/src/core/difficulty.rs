use log::trace;
use xelis_common::{
    difficulty::Difficulty,
    time::TimestampMillis,
    utils::format_difficulty
};
use crate::config::{BLOCK_TIME_MILLIS, MINIMUM_DIFFICULTY};

const DIFFICULTY_BOUND_DIVISOR: Difficulty = Difficulty::from_u64(100);

// Custom difficulty in test
pub fn calculate_difficulty(tips_count: u64, average_solve_time: TimestampMillis, previous_difficulty: Difficulty) -> Difficulty {
    let mut adjust = previous_difficulty / DIFFICULTY_BOUND_DIVISOR;
    // By how much we need to adjust the difficulty
    // If we have a solve time of 30s and the range is 15s, we need to adjust by 2
    // With a bound divisor of 1000, we will adjust by 0.1% for each points in x
    let (mut x, neg) = if average_solve_time > BLOCK_TIME_MILLIS {
        (average_solve_time / BLOCK_TIME_MILLIS, true)
    } else {
        (BLOCK_TIME_MILLIS / average_solve_time, false)
    };
    trace!("x: {x}, neg: {neg}, tips count: {tips_count}, adjust: {adjust}, difficulty: {}, adjust: {}", format_difficulty(previous_difficulty), format_difficulty(adjust));

    // Maximum 10% adjustment
    if x >= 10 {
        x = 10;
    }

    trace!("final x: {}", x);
    // Returns the previous difficulty if no adjustment is needed
    if x == 0 {
        return previous_difficulty
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