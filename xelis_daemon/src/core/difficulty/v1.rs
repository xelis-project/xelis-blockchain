use std::time::Duration;
use humantime::format_duration;
use log::trace;
use xelis_common::{
    difficulty::Difficulty,
    time::TimestampMillis,
    utils::format_difficulty,
    varuint::VarUint
};
use crate::{config::BLOCK_TIME_MILLIS, core::difficulty::kalman_filter};

const SHIFT: u64 = 32;
// This is equal to 2 ** 32
const LEFT_SHIFT: VarUint = VarUint::from_u64(1 << SHIFT);
// Process noise covariance: 5% of shift
const PROCESS_NOISE_COVAR: VarUint = VarUint::from_u64((1 << SHIFT) / 100 * 5);

// Initial estimate covariance
// It is used by first blocks
pub const P: VarUint = LEFT_SHIFT;

// Calculate the required difficulty for the next block based on the solve time of the previous block
// We are using a Kalman filter to estimate the hashrate and adjust the difficulty
pub fn calculate_difficulty(solve_time: TimestampMillis, previous_difficulty: Difficulty, p: VarUint, minimum_difficulty: Difficulty) -> (Difficulty, VarUint) {
    let z = previous_difficulty / solve_time;
    trace!("Calculating difficulty v1, solve time: {}, previous_difficulty: {}, z: {}, p: {}", format_duration(Duration::from_millis(solve_time)), format_difficulty(previous_difficulty), z, p);
    let (x_est_new, p_new) = kalman_filter(z, previous_difficulty / BLOCK_TIME_MILLIS, p, SHIFT, LEFT_SHIFT, PROCESS_NOISE_COVAR);
    trace!("x_est_new: {}, p_new: {}", x_est_new, p_new);

    let difficulty = x_est_new * BLOCK_TIME_MILLIS;
    if difficulty < minimum_difficulty {
        return (minimum_difficulty, P);
    }

    (difficulty, p_new)
}

#[cfg(test)]
mod tests {
    use crate::config::MAINNET_MINIMUM_DIFFICULTY;
    use super::*;

    #[test]
    fn test_kalman_filter_v1() {
        let z = MAINNET_MINIMUM_DIFFICULTY / VarUint::from_u64(1000);
        let (x_est_new, p_new) = kalman_filter(z, VarUint::one(), P, SHIFT, LEFT_SHIFT, PROCESS_NOISE_COVAR);
        assert_eq!(x_est_new, VarUint::one());
        assert_eq!(p_new, VarUint::from_u64(4501837440));

        let (x_est_new, p_new) = kalman_filter(MAINNET_MINIMUM_DIFFICULTY / VarUint::from_u64(2000), x_est_new, p_new, SHIFT, LEFT_SHIFT, PROCESS_NOISE_COVAR);
        assert_eq!(x_est_new, VarUint::one());
        assert_eq!(p_new, VarUint::from_u64(4699383461));
    }
}