use argon2::{Params, Argon2, Algorithm, Version};
use lazy_static::lazy_static;

pub const DIR_PATH: &str = "wallets/";
pub const XSWD_BIND_ADDRESS: &str = "0.0.0.0:44325";
pub const PASSWORD_HASH_SIZE: usize = 32;
pub const SALT_SIZE: usize = 32;
pub const KEY_SIZE: usize = 32;

// daemon address by default when no specified
pub const DEFAULT_DAEMON_ADDRESS: &str = "http://127.0.0.1:6666";
// Auto reconnect interval in seconds for Network Handler
pub const AUTO_RECONNECT_INTERVAL: u64 = 5;

lazy_static! {
    pub static ref PASSWORD_ALGORITHM: Argon2<'static> = {
        // 15 MB, 16 iterations
        let params = Params::new(15 * 1000, 16, 1,  Some(PASSWORD_HASH_SIZE)).unwrap();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    };
}
