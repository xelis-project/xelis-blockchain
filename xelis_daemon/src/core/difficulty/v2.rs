use std::time::Duration;
use humantime::format_duration;
use log::trace;
use xelis_common::{
    difficulty::Difficulty,
    time::TimestampMillis,
    utils::format_difficulty,
    varuint::VarUint
};
use crate::{
    config::MILLIS_PER_SECOND,
    core::difficulty::kalman_filter
};

pub const SHIFT: u64 = 20;
// This is equal to 2 ** 20
pub const LEFT_SHIFT: VarUint = VarUint::from_u64(1 << SHIFT);
// Process noise covariance: 2% of shift
pub const PROCESS_NOISE_COVAR: VarUint = VarUint::from_u64((1 << SHIFT) * SHIFT / MILLIS_PER_SECOND);

// Initial estimate covariance
// It is used by first blocks
pub const P: VarUint = LEFT_SHIFT;

pub fn calculate_difficulty(solve_time: TimestampMillis, previous_difficulty: Difficulty, p: VarUint, minimum_difficulty: Difficulty, block_time_target: TimestampMillis) -> (Difficulty, VarUint) {
    let z = previous_difficulty * MILLIS_PER_SECOND / solve_time;
    let x_est_prev = previous_difficulty * MILLIS_PER_SECOND / block_time_target;

    trace!("Calculating difficulty v2, solve time: {}, previous_difficulty: {}, z: {}, p: {}", format_duration(Duration::from_millis(solve_time)), format_difficulty(previous_difficulty), z, p);
    let (x_est_new, p_new) = kalman_filter(z, x_est_prev, p, SHIFT, LEFT_SHIFT, PROCESS_NOISE_COVAR);
    trace!("x_est_new: {}, p_new: {}", x_est_new, p_new);

    let difficulty = x_est_new * block_time_target / MILLIS_PER_SECOND;
    if difficulty < minimum_difficulty {
        return (minimum_difficulty, P);
    }

    (difficulty, p_new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kalman_filter_v2() {
        const DEFAULT_DIFFICULTY: Difficulty = Difficulty::from_u64(20 * 15 * 1000);

        let z = DEFAULT_DIFFICULTY / VarUint::from_u64(1000);
        let (x_est_new, p_new) = kalman_filter(z, VarUint::one(), P, SHIFT, LEFT_SHIFT, PROCESS_NOISE_COVAR);
        assert_eq!(x_est_new, VarUint::one());
        assert_eq!(p_new, VarUint::from_u64(1067732));

        let (x_est_new, p_new) = kalman_filter(DEFAULT_DIFFICULTY / VarUint::from_u64(2000), x_est_new, p_new, SHIFT, LEFT_SHIFT, PROCESS_NOISE_COVAR);
        assert_eq!(x_est_new, VarUint::one());
        assert_eq!(p_new, VarUint::from_u64(1084948));
    }
}