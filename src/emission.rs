use crate::config::{MAX_SUPPLY, EMISSION_SPEED_FACTOR};

pub fn get_block_reward(supply: u64, fee: u64) -> u64 {
    let base_reward = (MAX_SUPPLY - supply) >> EMISSION_SPEED_FACTOR;
    println!("base_reward: {}, supply: {}", base_reward, supply);
    base_reward + fee
}