use crate::block::Difficulty;
use crate::network::Network;
use crate::serializer::{Reader, ReaderError};
use crate::config::{FEE_PER_KB, COIN_DECIMALS};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

#[macro_export]
macro_rules! async_handler {
    ($func: expr) => {
        move |a, b| {
          Box::pin($func(a, b))
        }
    };
}

// return timestamp in seconds
pub fn get_current_time() -> u64 {
    let start = SystemTime::now();
    let time = start.duration_since(UNIX_EPOCH).expect("Incorrect time returned from get_current_time");
    time.as_secs()
}

// return timestamp in milliseconds
pub fn get_current_timestamp() -> u128 {
    let start = SystemTime::now();
    let time = start.duration_since(UNIX_EPOCH).expect("Incorrect time returned from get_current_timestamp");
    time.as_millis()
}

pub fn format_coin(value: u64, decimals: u8) -> String {
    format!("{:.1$}", value as f64 / 10usize.pow(decimals as u32) as f64, decimals as usize)
}

pub fn format_xelis(value: u64) -> String {
    format_coin(value, COIN_DECIMALS)
}

// format a IP:port to byte format
pub fn ip_to_bytes(ip: &SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::new();
    match ip.ip() {
        IpAddr::V4(addr) => {
            bytes.push(0);
            bytes.extend(addr.octets());
        },
        IpAddr::V6(addr) => {
            bytes.push(1);
            bytes.extend(addr.octets());
        }
    };
    bytes.extend(ip.port().to_be_bytes());
    bytes
}

// bytes to ip
pub fn ip_from_bytes(reader: &mut Reader) -> Result<SocketAddr, ReaderError> {
    let is_v6 = reader.read_bool()?;
    let ip: IpAddr = if !is_v6 {
        let a = reader.read_u8()?;
        let b = reader.read_u8()?;
        let c = reader.read_u8()?;
        let d = reader.read_u8()?;
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    } else {
        let a = reader.read_u16()?;
        let b = reader.read_u16()?;
        let c = reader.read_u16()?;
        let d = reader.read_u16()?;
        let e = reader.read_u16()?;
        let f = reader.read_u16()?;
        let g = reader.read_u16()?;
        let h = reader.read_u16()?;
        IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
    };
    let port = reader.read_u16()?;
    Ok(SocketAddr::new(ip, port))
}

pub fn calculate_tx_fee(tx_size: usize) -> u64 {
    let mut size_in_kb = tx_size as u64 / 1024;

    if tx_size % 1024 != 0 { // we consume a full kb for fee
        size_in_kb += 1;
    }
    
    size_in_kb * FEE_PER_KB
}

const HASHRATE_FORMATS: [&str; 5] = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s"];

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
pub fn set_network_to(network: Network) {
    // its already mainnet by default
    if network != Network::Mainnet {
        *NETWORK.lock().unwrap() = network;
    }
}