use log::{debug, trace};
use xelis_common::{
    difficulty::Difficulty,
    time::TimestampMillis,
    utils::format_difficulty
};
use crate::config::{BLOCK_TIME_MILLIS, MINIMUM_DIFFICULTY};

// Difficulty adjustment of at least 0.1% per block
const DIFFICULTY_BOUND_DIVISOR: Difficulty = Difficulty::from_u64(1000);

// Difficulty algorithm from Ethereum, tweaked to fit our needs
pub fn calculate_difficulty(tips_count: u64, average_solve_time: TimestampMillis, solve_time: TimestampMillis, previous_difficulty: Difficulty) -> Difficulty {
    trace!("calculate difficulty from parent: {}", format_difficulty(previous_difficulty));
    let mut adjust = previous_difficulty / DIFFICULTY_BOUND_DIVISOR;
    // By how much we need to adjust the difficulty
    // If we have a solve time of 30s and the block time is 15s, we need to adjust by 2
    // With a bound divisor of 1000, we will adjust by 0.1% for each points in x

    // Average solve time over 50 blocks take 3/4 of the weight
    // But average solve time already take in count the new solve time
    let avg_solve_time = (average_solve_time * 3 + solve_time) / 4;
    let mut x = avg_solve_time / BLOCK_TIME_MILLIS;
    let c = if tips_count > 1 {
        2
    } else {
        1
    };

    let neg = x >= c;
    debug!("x: {x}, neg: {neg}, avg: {avg_solve_time} ms, solve time: {solve_time} ms, average solve time: {average_solve_time} ms, adjust: {}", format_difficulty(adjust));
    if neg {
        x = x - c;
    } else {
        x = c - x;
    }

    if x > 99 {
        x = 99;
    }

    debug!("final x: {}", x);
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