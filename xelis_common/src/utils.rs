use crate::block::Difficulty;
use crate::network::Network;
use crate::config::{FEE_PER_KB, COIN_DECIMALS};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH, Duration};

#[macro_export]
macro_rules! async_handler {
    ($func: expr) => {
        move |a, b| {
          Box::pin($func(a, b))
        }
    };
}

#[inline]
pub fn get_current_time() -> Duration {
    let start = SystemTime::now();
    let time = start.duration_since(UNIX_EPOCH).expect("Incorrect time returned from get_current_time");
    time
}

// return timestamp in seconds
pub fn get_current_time_in_seconds() -> u64 {
    get_current_time().as_secs()
}

// return timestamp in milliseconds
pub fn get_current_time_in_millis() -> u128 {
    get_current_time().as_millis()
}

// Format any coin value using the requested decimals count
pub fn format_coin(value: u64, decimals: u8) -> String {
    format!("{:.1$}", value as f64 / 10usize.pow(decimals as u32) as f64, decimals as usize)
}

// Format value using XELIS decimals
pub fn format_xelis(value: u64) -> String {
    format_coin(value, COIN_DECIMALS)
}

// Convert a XELIS amount from string to a u64
pub fn from_xelis(value: impl Into<String>) -> Option<u64> {
    let value = value.into();
    let mut split = value.split('.');
    let xelis: u64 = split.next()?.parse::<u64>().ok()?;
    let decimals = split.next().unwrap_or("0");
    if decimals.len() > COIN_DECIMALS as usize {
        return None;
    }

    let mut decimals = decimals.parse::<u64>().ok()?;
    while decimals > 0 && decimals % 10 == 0 {
        decimals /= 10;
    }

    Some(xelis * 10u64.pow(COIN_DECIMALS as u32) + decimals)
}

// return the fee for a transaction based on its size in bytes
// the fee is calculated in atomic units for XEL
// This is a really simple function, plan to improve it later based on caracteristics of the transaction
pub fn calculate_tx_fee(tx_size: usize) -> u64 {
    let mut size_in_kb = tx_size as u64 / 1024;

    if tx_size % 1024 != 0 { // we consume a full kb for fee
        size_in_kb += 1;
    }
    
    size_in_kb * FEE_PER_KB
}

const HASHRATE_FORMATS: [&str; 5] = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s"];

// Format a hashrate in human-readable format
pub fn format_hashrate(mut hashrate: f64) -> String {
    let max = HASHRATE_FORMATS.len() - 1;
    let mut count = 0;
    while hashrate >= 1000f64 && count < max {
        count += 1;
        hashrate = hashrate / 1000f64;
    }

    return format!("{:.2} {}", hashrate, HASHRATE_FORMATS[count]);
}

const DIFFICULTY_FORMATS: [&str; 6] = ["", "K", "M", "G", "T", "P"];

// Format a difficulty in a human-readable format
pub fn format_difficulty(mut difficulty: Difficulty) -> String {
    let max = HASHRATE_FORMATS.len() - 1;
    let mut count = 0;
    while difficulty > 1000 && count < max {
        count += 1;
        difficulty = difficulty / 1000;
    }

    return format!("{}{}", difficulty, DIFFICULTY_FORMATS[count]);
}

// by default it start in mainnet mode
// it is mainly used by fmt::Display to display & Serde for the correct format of addresses / keys
static NETWORK: Mutex<Network> = Mutex::new(Network::Mainnet);
pub fn get_network() -> Network {
    let network = NETWORK.lock().unwrap();
    *network
}

// it should never be called later, only at launch!!
// TODO Deprecated
pub fn set_network_to(network: Network) {
    // its already mainnet by default
    if network != Network::Mainnet {
        *NETWORK.lock().unwrap() = network;
    }
}