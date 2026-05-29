
use crate::config::MILLIS_PER_SECOND;
use log::trace;
use xelis_common::{difficulty::Difficulty, time::TimestampMillis, varuint::VarUint};

const EFFECTIVE_COUNT: u64 = 80;
const FAST_EFFECTIVE_COUNT: u64 = 52;
const FAST_THRESHOLD_PERCENT: u64 = 144;
const PRIOR_COUNT: u64 = 12;
const MIN_MEASUREMENT_COUNT: u64 = 2;
const MAX_REPLAY_EVENTS: u64 = 256;
const MAX_RATE_INCREASE_PERCENT: u64 = 103;
const STATE_SHIFT: u64 = 64;
const ALPHA_SCALE: VarUint = VarUint::from_u64(1 << 32);
const BETA_SCALE: VarUint = VarUint::from_u128(1u128 << 96);
const PACK_BASE: VarUint = VarUint::from_u128(1u128 << STATE_SHIFT);

// Initial packed Gamma filter state. Stored in the historical `p` metadata slot.
pub const P: VarUint = VarUint::zero();

fn decode_state(p: VarUint, x_est_prev: &VarUint) -> (VarUint, VarUint) {
    let alpha = p % PACK_BASE;
    let beta = p >> STATE_SHIFT;

    if alpha >= ALPHA_SCALE && beta > VarUint::zero() {
        return (alpha, beta);
    }

    let alpha = ALPHA_SCALE * PRIOR_COUNT;
    let beta = VarUint::from_u64(PRIOR_COUNT) * BETA_SCALE / x_est_prev.clone().max(VarUint::one());
    (alpha, beta.max(VarUint::one()))
}

// Rate filter for Poisson block arrivals. The caller passes a DAG-aware
// work/time hashrate measurement and the stored state from the first measured
// block, then this replays the measurement span once.
fn filter_hashrate(z: VarUint, x_est_prev: VarUint, p_prev: VarUint, measurement_count: u64) -> (VarUint, VarUint) {
    let (mut alpha, mut beta) = decode_state(p_prev, &x_est_prev);
    let baseline = x_est_prev.clone().max(VarUint::one());
    let effective_count = if z.clone() * 100 > baseline.clone() * FAST_THRESHOLD_PERCENT || z.clone() * FAST_THRESHOLD_PERCENT < baseline * 100 {
        FAST_EFFECTIVE_COUNT
    } else {
        EFFECTIVE_COUNT
    };
    let replay_events = measurement_count.max(1).min(MAX_REPLAY_EVENTS);
    let observed_exposure = (VarUint::from_u64(measurement_count) * BETA_SCALE / z.max(VarUint::one())).max(VarUint::one());
    let event_exposure = (observed_exposure / replay_events).max(VarUint::one());

    for _ in 0..replay_events {
        alpha = (alpha * (effective_count - 1)) / effective_count + ALPHA_SCALE;
        beta = (beta * (effective_count - 1)) / effective_count + event_exposure;
    }

    let mut x_est_new = (alpha * BETA_SCALE / (beta * ALPHA_SCALE)).max(VarUint::one());
    let mut max_rate = x_est_prev.max(VarUint::one());
    for _ in 0..replay_events {
        max_rate = (max_rate * MAX_RATE_INCREASE_PERCENT / 100).max(VarUint::one());
    }
    if x_est_new > max_rate {
        x_est_new = max_rate;
        beta = (alpha * BETA_SCALE / (x_est_new * ALPHA_SCALE)).max(VarUint::one());
    }

    (x_est_new, (beta << STATE_SHIFT) + alpha)
}

pub fn calculate_difficulty(observed_hashrate: VarUint, previous_difficulty: Difficulty, p: VarUint, minimum_difficulty: Difficulty, block_time_target: TimestampMillis, measurement_count: u64) -> (Difficulty, VarUint) {
    if measurement_count < MIN_MEASUREMENT_COUNT {
        trace!("Skipping V6 difficulty update, measurement count {} is below {}", measurement_count, MIN_MEASUREMENT_COUNT);
        return (previous_difficulty.max(minimum_difficulty), p);
    }

    let x_est_prev = previous_difficulty * MILLIS_PER_SECOND / block_time_target;
    trace!("Filtering difficulty v3, z: {}, x_est_prev: {}, p: {}", observed_hashrate, x_est_prev, p);
    let (x_est_new, p_new) = filter_hashrate(observed_hashrate, x_est_prev, p, measurement_count);
    trace!("x_est_new: {}, p_new: {}", x_est_new, p_new);

    ((x_est_new * block_time_target / MILLIS_PER_SECOND).max(minimum_difficulty), p_new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_state_and_response() {
        let x_est_prev = VarUint::from_u64(1_000_000);
        let (_, p) = filter_hashrate(x_est_prev, x_est_prev, P, MIN_MEASUREMENT_COUNT);
        let (alpha, beta) = decode_state(p, &x_est_prev);

        let (x_down, _) = filter_hashrate(VarUint::from_u64(500_000), x_est_prev, p, 24);
        let (x_up, _) = filter_hashrate(VarUint::from_u64(2_000_000), x_est_prev, p, 24);

        assert!(alpha >= ALPHA_SCALE);
        assert!(beta > VarUint::zero());
        assert!(x_down < x_est_prev);
        assert!(x_up > x_est_prev);

        let (difficulty, p) = calculate_difficulty(VarUint::from_u64(100_000_000), Difficulty::from_u64(1_000_000), P, Difficulty::one(), MILLIS_PER_SECOND, MIN_MEASUREMENT_COUNT - 1);
        assert_eq!(difficulty, Difficulty::from_u64(1_000_000));
        assert_eq!(p, P);
    }
}