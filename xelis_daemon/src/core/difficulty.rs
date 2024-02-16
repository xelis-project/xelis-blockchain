use log::trace;
use xelis_common::{
    difficulty::Difficulty,
    time::TimestampMillis,
    utils::format_difficulty
};
use crate::config::{BLOCK_TIME_MILLIS, MINIMUM_DIFFICULTY};

const DIFFICULTY_BOUND_DIVISOR: Difficulty = Difficulty::from_u64(100);
const CHAIN_TIME_RANGE: TimestampMillis = BLOCK_TIME_MILLIS / 2;

// Difficulty algorithm from Ethereum: Homestead but tweaked for our needs
pub fn calculate_difficulty(tips_count: u64, parent_timestamp: TimestampMillis, new_timestamp: TimestampMillis, previous_difficulty: Difficulty) -> Difficulty {
    let mut adjust = previous_difficulty / DIFFICULTY_BOUND_DIVISOR;
    let solve_time = new_timestamp - parent_timestamp;
    // By how much we need to adjust the difficulty
    // If we have a solve time of 30s and the range is 15s, we need to adjust by 2
    // With a bound divisor of 100, we will adjust by 2% of the previous difficulty
    let mut x = solve_time / CHAIN_TIME_RANGE;
    trace!("x: {x}, tips count: {tips_count}, adjust: {adjust}, difficulty: {}, adjust: {}", format_difficulty(previous_difficulty), format_difficulty(adjust));

    let neg = x >= tips_count;
    if neg {
        x = x - tips_count;
    } else {
        x = tips_count - x;
    }

    // max(x, 99)
    if x > 99 {
        x = 99;
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