use std::time::{SystemTime, UNIX_EPOCH};
use crate::config::{COIN_VALUE};

pub fn get_current_time() -> u64 {
    let start = SystemTime::now();
    let time = start.duration_since(UNIX_EPOCH).expect("Incorrect time returned from get_current_time");
    time.as_secs()
}

pub fn format_coin(value: u64) -> String {
    format!("{}", value as f64 / COIN_VALUE as f64)
}