use serde::{Deserialize, Serialize};
use xelis_common::utils::detect_available_parallelism;

use crate::core::storage::rocksdb::{CacheMode, CompressionMode};


const fn default_max_open_files() -> i32 {
    256
}

const fn default_db_cache_size() -> u64 {
    64 * 1024 * 1024 // 64 MB
}

const fn default_keep_max_log_files() -> usize {
    4
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct RocksDBConfig {
    /// How many background threads RocksDB should use for parallelism.
    /// Default set to the available parallelism detected.
    #[clap(name = "rocksdb-background-threads", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub parallelism: usize,
    /// Sets maximum number of concurrent background jobs (compactions and flushes).
    /// Default set to the available parallelism detected.
    #[clap(name = "rocksdb-max-background-jobs", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub max_background_jobs: usize,
    /// Sets maximum number of threads that will concurrently perform a compaction job by breaking it into multiple,
    /// smaller ones that are run simultaneously.
    /// Default set to the available parallelism detected.
    #[clap(name = "rocksdb-max-subcompaction-jobs", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub max_subcompaction_jobs: usize,
    /// Sets the size of the low priority thread pool that can be used to prevent compactions from stalling memtable flushes.
    /// Default set to the available parallelism detected.
    #[clap(name = "rocksdb-low-priority-background-threads", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub low_priority_background_threads: usize,
    /// Sets the number of open files that can be used by the DB.
    /// You may need to increase this if your database has a large working set.
    /// Value -1 means files opened are always kept open.
    #[clap(name = "rocksdb-max-open-files", long, default_value_t = default_max_open_files())]
    #[serde(default = "default_max_open_files")]
    pub max_open_files: i32,
    /// Specify the maximal number of info log files to be kept.
    #[clap(name = "rocksdb-keep-max-log-files", long, default_value_t = default_keep_max_log_files())]
    #[serde(default = "default_keep_max_log_files")]
    pub keep_max_log_files: usize,
    /// Compression mode to use for RocksDB.
    #[clap(name = "rocksdb-compression-mode", value_enum, long, default_value_t)]
    #[serde(default)]
    pub compression_mode: CompressionMode,
    /// RocksDB block based cache mode to use.
    #[clap(name = "rocksdb-cache-mode", value_enum, long, default_value_t)]
    #[serde(default)]
    pub cache_mode: CacheMode,
    /// Size in bytes for the RocksDB block based to cache use if mode is not None.
    #[clap(name = "rocksdb-cache-size", long, default_value_t = default_db_cache_size())]
    #[serde(default = "default_db_cache_size")]
    pub cache_size: u64,
    /// Write buffer to use for the amount of data to build up in memtables.
    #[clap(name = "rocksdb-write-buffer-size", long, default_value_t = default_db_cache_size())]
    #[serde(default = "default_db_cache_size")]
    pub write_buffer_size: u64,
    /// Enforces a limit for a single memtable using the above write buffer size.
    /// Disabled by default, each column will have its own buffer.
    #[clap(name = "rocksdb-write-buffer-shared", long)]
    #[serde(default)]
    pub write_buffer_shared: bool,
    /// Bloom filter bits per key for column families that use a prefix extractor.
    /// Higher values reduce false positives but increase memory usage.
    #[clap(name = "rocksdb-bloom-filter-bits-per-key", long)]
    #[serde(default)]
    pub bloom_filter_bits_per_key: Option<f64>,
    /// Override for target SST file size in bytes.
    /// None (default) uses the RocksDB default of 64 MiB.
    #[clap(name = "rocksdb-target-file-size-base", long)]
    #[serde(default)]
    pub target_file_size_base: Option<u64>,
}

impl Default for RocksDBConfig {
    fn default() -> Self {
        Self {
            parallelism: detect_available_parallelism(),
            max_background_jobs: detect_available_parallelism(),
            max_subcompaction_jobs: detect_available_parallelism(),
            low_priority_background_threads: detect_available_parallelism(),
            max_open_files: default_max_open_files(),
            keep_max_log_files: default_keep_max_log_files(),
            compression_mode: CompressionMode::default(),
            cache_mode: CacheMode::default(),
            cache_size: default_db_cache_size(),
            write_buffer_size: default_db_cache_size(),
            write_buffer_shared: false,
            bloom_filter_bits_per_key: None,
            target_file_size_base: None,
        }
    }
}
