use std::net::SocketAddr;

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
    from_coin(value, COIN_DECIMALS)
}

// Convert a coin amount from string to a u64 based on the provided decimals
pub fn from_coin(value: impl Into<String>, coin_decimals: u8) -> Option<u64> {
    let value = value.into();
    let mut split = value.split('.');
    let value: u64 = split.next()?.parse::<u64>().ok()?;
    let right_part = split.next().unwrap_or("0");
    let decimals: String = right_part.chars().chain(std::iter::repeat('0')).take(coin_decimals as usize).collect();
    let decimals_value = decimals.parse::<u64>().ok()?;
    Some(value * 10u64.pow(coin_decimals as u32) + decimals_value)
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
    let mut left = VarUint::zero();
    while difficulty >= thousand && count < max {
        count += 1;
        left = difficulty % thousand;
        difficulty = difficulty / thousand;
    }

    let left_str = if left == VarUint::zero() {
        "".to_string()
    } else {
        format!(".{}", left / 10)
    };

    return format!("{}{}{}", difficulty, left_str, DIFFICULTY_FORMATS[count]);
}

// Sanitize a daemon address to make sure it's a valid websocket address
// By default, will use ws:// if no protocol is specified
pub fn sanitize_daemon_address(target: &str) -> String {
    let mut target = target.to_lowercase();
    if target.starts_with("https://") {
        target.replace_range(..8, "wss://");
    }
    else if target.starts_with("http://") {
        target.replace_range(..7, "ws://");
    }
    else if !target.starts_with("ws://") && !target.starts_with("wss://") {
        // use ws:// if it's a IP address, otherwise it may be a domain, use wss://
        let prefix = if target.parse::<SocketAddr>().is_ok() {
            "ws://"
        } else {
            "wss://"
        };

        target.insert_str(0, prefix);
    }

    if target.ends_with("/") {
        target.pop();
    }

    target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_format_zero() {
        let value = Difficulty::zero();
        assert_eq!(format_difficulty(value), "0");
    }

    #[test]
    fn test_difficulty_format_thousand_k() {
        let value: Difficulty = 1000u64.into();
        assert_eq!(format_difficulty(value), "1K");
    }

    #[test]
    fn test_difficulty_format_thousand_k_left() {
        let value: Difficulty = 1150u64.into();
        assert_eq!(format_difficulty(value), "1.15K");
    }

    #[test]
    fn test_high_difficulty() {
        let value: Difficulty = 1150_000_000u64.into();
        assert_eq!(format_difficulty(value), "1.15G");
    }

    #[test]
    fn test_from_xelis() {
        let value = from_xelis("100.123");
        assert_eq!(value, Some(100_123_00000));
    }
}