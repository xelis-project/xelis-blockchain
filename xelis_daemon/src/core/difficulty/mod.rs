use log::trace;
use xelis_common::{
    difficulty::Difficulty,
    time::TimestampMillis,
    varuint::VarUint,
    block::BlockVersion
};

mod v1;
mod v2;

// Kalman filter with unsigned integers only
// z: The observed value (latest hashrate calculated on current block time).
// x_est_prev: The previous hashrate estime.
// p_prev: The previous estimate covariance.
// Returns the new state estimate and covariance
fn kalman_filter(z: VarUint, x_est_prev: VarUint, p_prev: VarUint, shift: u64, left_shift: VarUint, process_noise_covar: VarUint) -> (VarUint, VarUint) {
    trace!("z: {}, x_est_prev: {}, p_prev: {}", z, x_est_prev, p_prev);
    // Scale up
    let z = z * left_shift;
    let r = z * 2;
    let x_est_prev = x_est_prev * left_shift;

    // Prediction step
    let p_pred = ((x_est_prev * process_noise_covar) >> shift) + p_prev;

    // Update step
    let k = (p_pred << shift) / (p_pred + r + VarUint::one());

    // Ensure positive numbers only
    let mut x_est_new = if z >= x_est_prev {
        x_est_prev + ((k * (z - x_est_prev)) >> shift)
    } else {
        x_est_prev - ((k * (x_est_prev - z)) >> shift)
    };

    trace!("x_est_new: {}, p pred: {}, noise covar: {}, p_prev: {}, k: {}", x_est_new, p_pred, process_noise_covar, p_prev, k);
    let p_new = ((left_shift - k) * p_pred) >> shift;

    // Scale down
    x_est_new >>= shift;

    (x_est_new, p_new)
}

// Calculate the required difficulty for the next block based on the solve time of the previous block
// We are using a Kalman filter to estimate the hashrate and adjust the difficulty
// This function will determine which algorithm to use based on the version
pub fn calculate_difficulty(parent_timestamp: TimestampMillis, timestamp: TimestampMillis, previous_difficulty: Difficulty, p: VarUint, minimum_difficulty: Difficulty, version: BlockVersion) -> (Difficulty, VarUint) {
    let solve_time = (timestamp - parent_timestamp).max(1);

    match version {
        BlockVersion::V0 => v1::calculate_difficulty(solve_time, previous_difficulty, p, minimum_difficulty),
        BlockVersion::V1 => v2::calculate_difficulty(solve_time, previous_difficulty, p, minimum_difficulty),
    }
}

// Get the process noise covariance based on the version
// It is used by first blocks on a new version
pub fn get_covariance_p(version: BlockVersion) -> VarUint {
    match version {
        BlockVersion::V0 => v1::P,
        BlockVersion::V1 => v2::P
    }
}