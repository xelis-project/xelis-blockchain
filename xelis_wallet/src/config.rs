use argon2::{Params, Argon2, Algorithm, Version};
use lazy_static::lazy_static;

pub const PASSWORD_HASH_SIZE: usize = 32;
pub const SALT_SIZE: usize = 32;
pub const KEY_SIZE: usize = 32;

lazy_static! {
    pub static ref PASSWORD_ALGORITHM: Argon2<'static> = {
        let params = Params::new(32 * 1024, 16, 1,  Some(PASSWORD_HASH_SIZE)).unwrap();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    };
}