use std::time::Duration;
use humantime::format_duration;
use log::trace;
use xelis_common::{
    difficulty::Difficulty,
    time::TimestampMillis,
    utils::format_difficulty,
    varuint::VarUint
};
use crate::config::BLOCK_TIME_MILLIS;

const SHIFT: u64 = 32;
// This is equal to 2 ** 32
const LEFT_SHIFT: VarUint = VarUint::from_u64(1 << SHIFT);
// Process noise covariance: 5% of shift
const PROCESS_NOISE_COVAR: VarUint = VarUint::from_u64((1 << SHIFT) / 100 * 5);

// Initial estimate covariance
// It is used by first blocks
pub const P: VarUint = LEFT_SHIFT;

// Kalman filter with unsigned integers only
// z: The observed value (latest hashrate calculated on current block time).
// x_est_prev: The previous hashrate estime.
// p_prev: The previous estimate covariance.
// Returns the new state estimate and covariance
pub fn kalman_filter(z: VarUint, x_est_prev: VarUint, p_prev: VarUint) -> (VarUint, VarUint) {
    trace!("z: {}, x_est_prev: {}, p_prev: {}", z, x_est_prev, p_prev);
    // Scale up
    let z = z * LEFT_SHIFT;
    let r = z * 2;
    let x_est_prev = x_est_prev * LEFT_SHIFT;

    // Prediction step
    let p_pred = ((x_est_prev * PROCESS_NOISE_COVAR) >> SHIFT) + p_prev;

    // Update step
    let k = (p_pred << SHIFT) / (p_pred + r + VarUint::one());

    // Ensure positive numbers only
    let mut x_est_new = if z >= x_est_prev {
        x_est_prev + ((k * (z - x_est_prev)) >> SHIFT)
    } else {
        x_est_prev - ((k * (x_est_prev - z)) >> SHIFT)
    };

    trace!("p pred: {}, noise covar: {}, p_prev: {}, k: {}", p_pred, PROCESS_NOISE_COVAR, p_prev, k);
    let p_new = ((LEFT_SHIFT - k) * p_pred) >> SHIFT;

    // Scale down
    x_est_new >>= SHIFT;

    (x_est_new, p_new)
}

// Calculate the required difficulty for the next block based on the solve time of the previous block
// We are using a Kalman filter to estimate the hashrate and adjust the difficulty
pub fn calculate_difficulty(parent_timestamp: TimestampMillis, timestamp: TimestampMillis, previous_difficulty: Difficulty, p: VarUint, minimum_difficulty: Difficulty) -> (Difficulty, VarUint) {
    let mut solve_time = timestamp - parent_timestamp;

    // Someone trying to do something shady or really lucky
    // 1ms is the minimum solve time
    if solve_time == 0 {
        solve_time = 1;
    }

    let z = previous_difficulty / solve_time;
    trace!("Calculating difficulty, solve time: {}, previous_difficulty: {}, z: {}, p: {}", format_duration(Duration::from_millis(solve_time)), format_difficulty(previous_difficulty), z, p);
    let (x_est_new, p_new) = kalman_filter(z, previous_difficulty / BLOCK_TIME_MILLIS, p);
    trace!("x_est_new: {}, p_new: {}", x_est_new, p_new);

    let difficulty = x_est_new * BLOCK_TIME_MILLIS;
    if difficulty < minimum_difficulty {
        return (minimum_difficulty, P);
    }

    (difficulty, p_new)
}

#[cfg(test)]
mod tests {
    use crate::config::MINIMUM_DIFFICULTY;
    use super::*;

    #[test]
    fn test_kalman_filter() {
        let z = MINIMUM_DIFFICULTY / VarUint::from_u64(1000);
        let (x_est_new, p_new) = kalman_filter(z, VarUint::one(), P);
        assert_eq!(x_est_new, VarUint::one());
        assert_eq!(p_new, VarUint::from_u64(4501837440));

        let (x_est_new, p_new) = kalman_filter(MINIMUM_DIFFICULTY / VarUint::from_u64(2000), x_est_new, p_new);
        assert_eq!(x_est_new, VarUint::one());
        assert_eq!(p_new, VarUint::from_u64(4699383461));
    }
}