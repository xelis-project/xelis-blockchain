use crate::{
    config::{
        COIN_DECIMALS,
        FEE_PER_ACCOUNT_CREATION,
        FEE_PER_KB,
        FEE_PER_TRANSFER
    },
    difficulty::Difficulty,
    varuint::VarUint
};

#[macro_export]
macro_rules! async_handler {
    ($func: expr) => {
        move |a, b| {
          Box::pin($func(a, b))
        }
    };
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
// Sending to a newly created address will increase the fee
// Each transfers output will also increase the fee
pub fn calculate_tx_fee(tx_size: usize, output_count: usize, new_addresses: usize) -> u64 {
    let mut size_in_kb = tx_size as u64 / 1024;

    if tx_size % 1024 != 0 { // we consume a full kb for fee
        size_in_kb += 1;
    }

    size_in_kb * FEE_PER_KB
    + output_count as u64 * FEE_PER_TRANSFER
    + new_addresses as u64 * FEE_PER_ACCOUNT_CREATION
}

const HASHRATE_FORMATS: [&str; 7] = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"];

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

const DIFFICULTY_FORMATS: [&str; 7] = ["", "K", "M", "G", "T", "P", "E"];

// Format a difficulty in a human-readable format
pub fn format_difficulty(mut difficulty: Difficulty) -> String {
    let max = HASHRATE_FORMATS.len() - 1;
    let mut count = 0;
    let thousand = VarUint::from_u64(1000);
    while difficulty > thousand && count < max {
        count += 1;
        difficulty = difficulty / thousand;
    }

    return format!("{}{}", difficulty, DIFFICULTY_FORMATS[count]);
}