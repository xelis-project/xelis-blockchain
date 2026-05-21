use serde::{Deserialize, Serialize};
use crate::config::DEFAULT_CACHE_SIZE;

use super::StorageMode;

const fn default_sled_cache_size() -> usize {
    DEFAULT_CACHE_SIZE
}

const fn default_db_cache_size() -> u64 {
    64 * 1024 * 1024 // 64 MB
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct SledConfig {
    /// Set LRUCache size (0 = disabled).
    #[clap(name = "sled-cache-size", long, default_value_t = default_sled_cache_size())]
    #[serde(default = "default_sled_cache_size")]
    pub cache_size: usize,
    /// DB cache size in bytes
    #[clap(name = "sled-internal-cache-size", long, default_value_t = default_db_cache_size())]
    #[serde(default = "default_db_cache_size")]
    pub internal_cache_size: u64,
    /// Internal DB mode to use
    #[clap(name = "sled-internal-db-mode", long, value_enum, default_value_t)]
    #[serde(default)]
    pub internal_db_mode: StorageMode,
}

impl Default for SledConfig {
    fn default() -> Self {
        Self {
            cache_size: default_sled_cache_size(),
            internal_cache_size: default_db_cache_size(),
            internal_db_mode: StorageMode::default(),
        }
    }
}