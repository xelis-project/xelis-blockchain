use std::time::Duration;
use humantime::Duration as HumanDuration;
use serde::{Deserialize, Serialize};
use xelis_common::{
    crypto::Hash,
    prompt::LogLevel,
    utils::detect_available_parallelism
};
use crate::{
    config::*,
    core::storage::sled::StorageMode,
    p2p::{KeyVerificationAction, WrappedSecret}
};

use super::simulator::Simulator;

#[cfg(feature = "rocksdb")]
use super::storage::rocksdb::{CacheMode, CompressionMode};

// Functions helpers for serde default values
fn default_p2p_bind_address() -> String {
    DEFAULT_P2P_BIND_ADDRESS.to_owned()
}

const fn default_max_peers() -> usize {
    P2P_DEFAULT_MAX_PEERS
}

const fn default_max_outgoing_peers() -> usize {
    P2P_DEFAULT_MAX_OUTGOING_PEERS
}

fn default_rpc_bind_address() -> String {
    DEFAULT_RPC_BIND_ADDRESS.to_owned()
}

fn default_prometheus_route() -> String {
    "/metrics".to_owned()
}

const fn default_cache_size() -> usize {
    DEFAULT_CACHE_SIZE
}

const fn default_p2p_concurrency_task_count_limit() -> usize {
    P2P_DEFAULT_CONCURRENCY_TASK_COUNT_LIMIT
}

const fn default_chain_sync_response_blocks() -> usize {
    CHAIN_SYNC_DEFAULT_RESPONSE_BLOCKS
}

const fn default_getwork_rate_limit_ms() -> u64 {
    500
}

fn default_p2p_temp_ban_duration() -> HumanDuration {
    HumanDuration::from(Duration::from_secs(PEER_TEMP_BAN_TIME))
}

const fn default_p2p_fail_count_limit() -> u8 {
    PEER_FAIL_LIMIT
}

const fn debug_log_level() -> LogLevel {
    LogLevel::Debug
}

const fn default_db_cache_size() -> u64 {
    64 * 1024 * 1024 // 64 MB
}

const fn default_max_open_files() -> i32 {
    1024
}

const fn default_keep_max_log_files() -> usize {
    4
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct GetWorkConfig {
    /// Disable GetWork Server (WebSocket for miners).
    #[clap(name = "disable-getwork-server", long)]
    #[serde(default)]
    pub disable: bool,
    /// Set the rate limit for GetWork server in milliseconds.
    /// In case of high transactions added in mempool, new jobs are rate limited.
    /// If is set to 0 (no limit), any new job will be sent to miners directly.
    #[clap(name = "getwork-rate-limit-ms", long, default_value_t = default_getwork_rate_limit_ms())]
    #[serde(default = "default_getwork_rate_limit_ms")]
    pub rate_limit_ms: u64,
    /// Set the concurrency for GetWork server during a new job notification.
    /// Notify concurrently to N miners at a time.
    /// Set to 0 means no limit and will process as one task per miner.
    /// Default is detected based on available parallelism.
    #[clap(name = "getwork-notify-job-concurrency", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub notify_job_concurrency: usize,
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct PrometheusConfig {
    /// Enable Prometheus metrics server
    /// This only works if the RPC server is enabled.
    #[clap(long = "prometheus-enable")]
    #[serde(default)]
    pub enable: bool,
    /// Route for the Prometheus metrics export
    #[clap(name = "prometheus-route", long, default_value_t = default_prometheus_route())]
    #[serde(default = "default_prometheus_route")]
    pub route: String,
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct RPCConfig {
    /// GetWork configuration
    /// This is used to configure the GetWork server.
    /// Only available if the RPC is enabled
    #[clap(flatten)]
    pub getwork: GetWorkConfig,
    /// Prometheus configuration
    /// This is used to configure the Prometheus metrics server.
    #[clap(flatten)]
    pub prometheus: PrometheusConfig,
    /// Disable RPC Server
    /// This will also disable the GetWork Server as it is loaded on RPC server.
    #[clap(name = "disable-rpc-server", long)]
    #[serde(default)]
    pub disable: bool,
    /// RPC bind address to listen for HTTP requests
    #[clap(name = "rpc-bind-address", long, default_value_t = default_rpc_bind_address())]
    #[serde(default = "default_rpc_bind_address")]
    pub bind_address: String,
    /// Number of workers to spawn for the HTTP server.
    /// If not provided, it will use the available paralellism.
    #[clap(name = "rpc-threads", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub threads: usize,
    /// RPC Server notification events concurrency
    /// This is used to configure the number of concurrent tasks
    /// that will be used to notify the events to the clients.
    /// By default, it will use the available parallelism.
    /// If set to 0, it will be unlimited.
    #[clap(name = "rpc-notify-events-concurrency", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub notify_events_concurrency: usize,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Serialize, Deserialize, strum::Display)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    #[clap(name = "socks5")]
    Socks5,
    #[clap(name = "socks4")]
    Socks4,
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Configure a proxy address to be used
    /// Make sure to set the `proxy` type along it
    /// when connecting to a peer
    #[clap(name = "p2p-proxy-address", long)]
    #[serde(default)]
    pub address: Option<String>,
    /// Proxy protocol to use when connecting to a peer
    #[clap(name = "p2p-proxy", long)]
    pub kind: Option<ProxyKind>,
    /// Proxy username for authentication
    #[clap(name = "p2p-proxy-username", long)]
    pub username: Option<String>,
    /// Proxy password for authentication
    #[clap(name = "p2p-proxy-password", long)]
    pub password: Option<String>
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct P2pConfig {
    /// Proxy configuration
    #[clap(flatten)]
    pub proxy: ProxyConfig,
    /// Optional node tag
    /// This is used to identify the node in the network.
    #[clap(long)]
    pub tag: Option<String>,
    /// P2p bind address to listen for incoming connections
    #[clap(name = "p2p-bind-address", long, default_value_t = default_p2p_bind_address())]
    #[serde(default = "default_p2p_bind_address")]
    pub bind_address: String,
    /// Number of maximums peers allowed
    #[clap(long, default_value_t = default_max_peers())]
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
    /// Set a maximum of P2P outgoing peers.
    /// 
    /// This is useful to limit to how many nodes you want to connect to.
    #[clap(name = "p2p-max-outgoing-peers", long, default_value_t = default_max_outgoing_peers())]
    #[serde(default = "default_max_outgoing_peers")]
    pub max_outgoing_peers: usize,
    /// Add a priority node to connect when P2p is started.
    /// A priority node is connected only one time.
    #[clap(long)]
    #[serde(default)]
    pub priority_nodes: Vec<String>,
    /// An exclusive node is connected and its connection is maintained in case of disconnect
    /// it also replaces seed nodes.
    /// NOTE: no others nodes will be accepted if an exclusive node is set.
    #[clap(long)]
    #[serde(default)]
    pub exclusive_nodes: Vec<String>,
    /// Disable the P2P Server.
    /// No connections will be accepted.
    /// Node will not be able to communicate the network.
    #[clap(name = "disable-p2p-server", long)]
    #[serde(default)]
    pub disable: bool,
    /// Allow fast sync mode.
    /// 
    /// Sync a bootstrapped chain if your local copy is outdated.
    /// 
    /// It will not store any blocks / TXs and will not verify the history locally.
    /// 
    /// Use it with extreme cautions and trusted nodes to have a valid bootstrapped chain.
    #[clap(long)]
    #[serde(default)]
    pub allow_fast_sync: bool,
    /// Allow boost chain sync mode.
    /// 
    /// This will request in parallel all blocks instead of sequentially.
    /// 
    /// It is not enabled by default because it will requests several blocks before validating each previous.
    #[clap(long)]
    #[serde(default)]
    pub allow_boost_sync: bool,
    /// Allow blocks coming from priority nodes to be fast forwarded to our peers.
    /// 
    /// Propagate a new block to our peers as soon as we receive it from a priority node before verifying it ourself.
    /// This reduces the time to propagate a new block to our peers.
    /// Useful for pools operating having several nodes across the world to propagate their blocks faster.
    /// 
    /// By default, this is disabled.
    #[clap(long)]
    #[serde(default)]
    pub allow_priority_blocks: bool,
    /// Configure the maximum chain response size.
    /// 
    /// This is useful for low devices who want to reduce resources usage
    /// and for high-end devices who want to (or help others to) sync faster.
    #[clap(long, default_value_t = default_chain_sync_response_blocks())]
    #[serde(default = "default_chain_sync_response_blocks")]
    pub max_chain_response_size: usize,
    /// Ask peers to not share our IP to others and/or through API.
    /// 
    /// This is useful for people that don't want that their IP is revealed in RPC API
    /// and/or shared to others nodes as a potential new peer to connect to.
    /// 
    /// Note that it may prevent to have new incoming peers.
    #[clap(long)]
    #[serde(default)]
    pub disable_ip_sharing: bool,
    /// Limit of concurrent tasks accepting new incoming connections.
    #[clap(name = "p2p-concurrency-task-count-limit", long, default_value_t = default_p2p_concurrency_task_count_limit())]
    #[serde(default = "default_p2p_concurrency_task_count_limit")]
    pub concurrency_task_count_limit: usize,
    /// Execute a specific action when the P2p Diffie-Hellman Key of a peer is different from our stored one.
    /// By default, it will ignore the key change and update it.
    #[clap(name = "p2p-on-dh-key-change", long, value_enum, default_value_t = KeyVerificationAction::Ignore)]
    #[serde(default)]
    pub on_dh_key_change: KeyVerificationAction,
    /// P2p DH private key to use.
    /// By default, a newly generated key will be used.
    /// Reusing the same private key will allow to keep the same public key
    /// and avoid the need to re-verify the key with our peers.
    /// This is useful for nodes that want to keep the same public key
    /// across several restarts.
    /// Note that reusing the same key may allow to track your node
    /// across your IP changes.
    #[clap(name = "p2p-dh-private-key", long)]
    pub dh_private_key: Option<WrappedSecret>,
    /// P2P Concurrency to use during streams.
    /// This is used to configure the number of concurrent tasks
    /// that will be used to process the streams.
    /// By default, it will use the available parallelism.
    /// If set to 0, it will be unlimited.
    #[clap(name = "p2p-stream-concurrency", long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub stream_concurrency: usize,
    /// P2P Time to set when banning a peer temporarily due to the fail count limit reached.
    /// This is used to configure the time to wait before unbanning the peer.
    /// By default, it will be set to 15 minutes.
    #[clap(name = "p2p-temp-ban-duration", long, default_value_t = default_p2p_temp_ban_duration())]
    #[serde(
        with = "humantime_serde",
        default = "default_p2p_temp_ban_duration"
    )]
    pub temp_ban_duration: HumanDuration,
    /// P2P Fail count limit to ban a peer temporarily.
    /// This is used to configure the number of failed requests
    /// before banning the peer temporarily.
    #[clap(name = "p2p-fail-count-limit", long, default_value_t = default_p2p_fail_count_limit())]
    #[serde(default = "default_p2p_fail_count_limit")]
    pub fail_count_limit: u8,
    /// Disable the P2P to re-execute an orphaned block during chain sync.
    /// If set to true, the P2P server will stop removing the block from storage
    /// and prevent to re-execute it by re-adding it to the chain.
    #[clap(name = "p2p-disable-reexecute-blocks-on-sync", long)]
    #[serde(default)]
    pub disable_reexecute_blocks_on_sync: bool,
    /// P2P log level for the block propagation
    /// This is used to configure the log level used during the block propagation to peers.
    /// By default, it will be set to "debug".
    #[clap(name = "p2p-block-propagation-log-level", long, value_enum, default_value_t = LogLevel::Debug)]
    #[serde(default = "debug_log_level")]
    pub block_propagation_log_level: LogLevel,
    /// Disable requesting P2P transactions propagated
    #[clap(name = "p2p-disable-fetching-txs-propagated", long)]
    #[serde(default)]
    pub disable_fetching_txs_propagated: bool,
    #[clap(name = "p2p-handle-peer-packets-in-dedicated-task", long)]
    #[serde(default)]
    pub handle_peer_packets_in_dedicated_task: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Serialize, Deserialize)]
pub enum StorageBackend {
    #[serde(rename = "sled")]
    Sled,
    #[cfg(feature = "rocksdb")]
    #[serde(rename = "rocksdb")]
    #[clap(name = "rocksdb")]
    RocksDB
}

impl Default for StorageBackend {
    fn default() -> Self {
        Self::Sled
    }
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct SledConfig {
    /// Set LRUCache size (0 = disabled).
    #[clap(name = "sled-cache-size", long, default_value_t = default_cache_size())]
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
    /// DB cache size in bytes
    #[clap(name = "sled-internal-cache-size", long, default_value_t = default_db_cache_size())]
    #[serde(default = "default_db_cache_size")]
    pub internal_cache_size: u64,
    /// Internal DB mode to use
    #[clap(name = "sled-internal-db-mode", long, value_enum, default_value_t = StorageMode::LowSpace)]
    #[serde(default)]
    pub internal_db_mode: StorageMode,
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
    #[cfg(feature = "rocksdb")]
    #[clap(name = "rocksdb-compression-mode", value_enum, long, default_value_t)]
    #[serde(default)]
    pub compression_mode: CompressionMode,
    /// RocksDB block based cache mode to use.
    #[cfg(feature = "rocksdb")]
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
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct Config {
    /// RPC configuration
    #[clap(flatten)]
    pub rpc: RPCConfig,
    /// P2P configuration
    #[clap(flatten)]
    pub p2p: P2pConfig,
    /// Sled DB Backend if enabled
    #[clap(flatten)]
    pub sled: SledConfig,
    /// RocksDB Backend if enabled
    #[clap(flatten)]
    pub rocksdb: RocksDBConfig,
    /// Set dir path for blockchain storage.
    /// This will be appended by the network name for the database directory.
    /// It must ends with a slash.
    #[clap(long)]
    pub dir_path: Option<String>,
    /// Enable the simulator (skip PoW verification, generate a new block for every BLOCK_TIME).
    #[clap(long)]
    pub simulator: Option<Simulator>,
    /// Skip PoW verification.
    /// Warning: This is dangerous and should not be used in production.
    #[clap(long)]
    #[serde(default)]
    pub skip_pow_verification: bool,
    /// Enable the auto prune mode and prune the chain
    /// at each new block by keeping at least N blocks
    /// before the top.
    #[clap(long)]
    pub auto_prune_keep_n_blocks: Option<u64>,
    /// Skip the TXs verification when building a block template.
    #[clap(long)]
    #[serde(default)]
    pub skip_block_template_txs_verification: bool,
    /// Use the hexadecimal representation of the genesis block for the dev mode.
    /// This is useful for testing and development.
    #[clap(long)]
    pub genesis_block_hex: Option<String>,
    /// Blocks hashes checkpoints
    /// No rewind can go below any of those checkpoints
    #[serde(default)]
    pub checkpoints: Vec<Hash>,
    /// Set the threads count to use during TXs verifications.
    /// By default, will detect the best value.
    /// If set to 1, it will use the main thread.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub txs_verification_threads_count: usize,
    /// Se the threads count to use during block pre verification.
    /// By default, will detect the best value.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub pre_verify_block_threads_count: usize,
    /// Enable the DB integrity check that happen on chain initialization.
    /// This may take some times on huge DB as it's iterating through all versioned data
    /// to verify that no pointer or version is above our current topoheight.
    /// Please note that if the recovery mode is enabled, this will be skipped.
    /// By default, it is disabled.
    #[clap(long)]
    #[serde(default)]
    pub check_db_integrity: bool,
    /// Enable the recovery mode of the daemon.
    /// No DB integrity check or pre-computations will occurs
    /// such as difficulty for tips, stable height, etc.
    #[clap(long)]
    #[serde(default)]
    pub recovery_mode: bool,
    /// Flush the storage onto the disk every N blocks (topoheight based).
    /// In case of RocksDB, this will also compact the changes. 
    #[clap(long)]
    #[serde(default)]
    pub flush_db_every_n_blocks: Option<u64>,
    /// Use a different DB backend from the default.
    /// Note that the data will not be migrated from one to another
    /// and you may lose your data.
    #[clap(long, value_enum, default_value_t)]
    #[serde(default)]
    pub use_db_backend: StorageBackend,
    // Disable the TX Cache (ZKP Cache)
    // ZKP Cache is enabled by default and
    // prevent to re-verify the same ZK Proofs more than once.
    #[clap(long)]
    #[serde(default)]
    pub disable_zkp_cache: bool
}

mod humantime_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &HumanDuration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HumanDuration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<HumanDuration>().map_err(serde::de::Error::custom)
    }
}