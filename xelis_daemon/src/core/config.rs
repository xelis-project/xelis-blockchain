use std::time::Duration;
use human_bytes::human_bytes;
use humantime::Duration as HumanDuration;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use xelis_common::{
    config::FEE_PER_KB,
    crypto::Hash,
    prompt::LogLevel,
    utils::detect_available_parallelism,
    rpc::server::websocket::{
        DEFAULT_MAX_SESSION_CHANNEL_SIZE,
        DEFAULT_MAX_SESSION_WORK_QUEUE,
        DEFAULT_MAX_WEBSOCKET_SESSIONS
    }
};
use crate::{
    config::*,
    p2p::{KeyVerificationAction, WrappedSecret}
};

use super::simulator::Simulator;

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

const fn default_rpc_batch_limit() -> usize {
    20
}

const fn default_rpc_max_websocket_sessions() -> usize {
    DEFAULT_MAX_WEBSOCKET_SESSIONS
}

const fn default_rpc_websocket_session_channel_size() -> usize {
    DEFAULT_MAX_SESSION_CHANNEL_SIZE
}

const fn default_rpc_websocket_session_work_queue_size() -> usize {
    DEFAULT_MAX_SESSION_WORK_QUEUE
}

const fn default_min_fee_per_kb() -> u64 {
    FEE_PER_KB
}

// Default transaction expiration time in the mempool (24 hours).
fn default_mempool_tx_expiration_time() -> HumanDuration {
    HumanDuration::from(Duration::from_secs(24 * 3600))
}

// Default maximum mempool memory usage (800 MB).
const fn default_mempool_max_memory_usage() -> u64 {
    800 * 1000 * 1000
}

fn parse_human_bytes(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("byte value cannot be empty".to_owned());
    }

    let unit_start = value
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(value.len());
    let (amount, unit) = value.split_at(unit_start);

    if amount.is_empty() {
        return Err(format!("missing byte amount in '{value}'"));
    }

    let amount = amount
        .parse::<f64>()
        .map_err(|e| format!("invalid byte amount '{amount}': {e}"))?;

    if !amount.is_finite() || amount < 0.0 {
        return Err("byte amount must be a finite positive number".to_owned());
    }

    let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" | "byte" | "bytes" => 1_f64,
        "k" | "kb" => 1000_f64,
        "m" | "mb" => 1000_f64.powi(2),
        "g" | "gb" => 1000_f64.powi(3),
        "t" | "tb" => 1000_f64.powi(4),
        "p" | "pb" => 1000_f64.powi(5),
        "e" | "eb" => 1000_f64.powi(6),
        "ki" | "kib" => 1024_f64,
        "mi" | "mib" => 1024_f64.powi(2),
        "gi" | "gib" => 1024_f64.powi(3),
        "ti" | "tib" => 1024_f64.powi(4),
        "pi" | "pib" => 1024_f64.powi(5),
        "ei" | "eib" => 1024_f64.powi(6),
        unit => return Err(format!("unsupported byte unit '{unit}'")),
    };

    let bytes = amount * multiplier;
    if bytes > u64::MAX as f64 {
        return Err(format!("byte value '{value}' exceeds u64::MAX"));
    }

    Ok(bytes.round() as u64)
}

mod human_bytes_serde {
    use super::*;

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&human_bytes(*value as f64))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(HumanBytesVisitor)
    }

    struct HumanBytesVisitor;

    impl<'de> de::Visitor<'de> for HumanBytesVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a byte count or a human-readable byte string")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            u64::try_from(value).map_err(E::custom)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_human_bytes(value).map_err(E::custom)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&value)
        }
    }
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

impl Default for GetWorkConfig {
    fn default() -> Self {
        Self {
            disable: false,
            rate_limit_ms: default_getwork_rate_limit_ms(),
            notify_job_concurrency: detect_available_parallelism(),
        }
    }
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct PrometheusConfig {
    /// Enable Prometheus metrics server
    /// This only works if the RPC server is enabled.
    #[clap(long = "enable-prometheus")]
    #[serde(default)]
    pub enable: bool,
    /// Route for the Prometheus metrics export
    #[clap(name = "prometheus-route", long, default_value_t = default_prometheus_route())]
    #[serde(default = "default_prometheus_route")]
    pub route: String,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            enable: false,
            route: default_prometheus_route(),
        }
    }
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
    /// Configure the maximum batch size for JSON-RPC requests.
    /// This is used to prevent DoS attacks by limiting the number of requests
    /// that can be sent in a single batch.
    /// Default is 20 requests per batch.
    #[clap(name = "rpc-json-rpc-batch-limit", long, default_value_t = default_rpc_batch_limit())]
    #[serde(default = "default_rpc_batch_limit")]
    pub batch_limit: usize,
    /// Maximum websocket sessions accepted by each RPC websocket server.
    #[clap(name = "rpc-max-websocket-sessions", long, default_value_t = default_rpc_max_websocket_sessions())]
    #[serde(default = "default_rpc_max_websocket_sessions")]
    pub max_websocket_sessions: usize,
    /// Maximum outbound messages queued per websocket session.
    #[clap(name = "rpc-websocket-session-channel-size", long, default_value_t = default_rpc_websocket_session_channel_size())]
    #[serde(default = "default_rpc_websocket_session_channel_size")]
    pub websocket_session_channel_size: usize,
    /// Maximum inbound RPC work queued per websocket session.
    #[clap(name = "rpc-websocket-session-work-queue-size", long, default_value_t = default_rpc_websocket_session_work_queue_size())]
    #[serde(default = "default_rpc_websocket_session_work_queue_size")]
    pub websocket_session_work_queue_size: usize,
    /// Configure CORS allowed origins for RPC server.
    /// This will allow any whitelisted origin to access the RPC server.
    #[clap(name = "rpc-cors-allowed-origins", long)]
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    /// Allow RPC methods that are private and should not be exposed publicly.
    /// This is useful for nodes that are running in a trusted environment
    /// and want to expose admin commands.
    #[clap(name = "rpc-allow-private-methods", long)]
    #[serde(default)]
    pub allow_private_methods: bool,
    /// Allow the contract VM executions in the RPC methods.
    /// This is useful for nodes that want to enable the contract VM executions in the RPC methods.
    /// Currently used for the `simulate_contract_invoke` method to execute the contract using current chain state.
    #[clap(name = "rpc-allow-contract-vm-executions", long)]
    #[serde(default)]
    pub allow_contract_vm_executions: bool,
}

impl Default for RPCConfig {
    fn default() -> Self {
        Self {
            getwork: GetWorkConfig::default(),
            prometheus: PrometheusConfig::default(),
            disable: false,
            bind_address: default_rpc_bind_address(),
            threads: detect_available_parallelism(),
            notify_events_concurrency: detect_available_parallelism(),
            batch_limit: default_rpc_batch_limit(),
            max_websocket_sessions: default_rpc_max_websocket_sessions(),
            websocket_session_channel_size: default_rpc_websocket_session_channel_size(),
            websocket_session_work_queue_size: default_rpc_websocket_session_work_queue_size(),
            cors_allowed_origins: Vec::new(),
            allow_private_methods: false,
            allow_contract_vm_executions: false,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Serialize, Deserialize, strum::Display)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    #[clap(name = "socks5")]
    Socks5,
    #[clap(name = "socks4")]
    Socks4,
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize, Default)]
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
    #[clap(name = "disable-p2p-reexecute-blocks-on-sync", long)]
    #[serde(default)]
    pub disable_reexecute_blocks_on_sync: bool,
    /// P2P log level for the block propagation
    /// This is used to configure the log level used during the block propagation to peers.
    /// By default, it will be set to "debug".
    #[clap(name = "p2p-block-propagation-log-level", long, value_enum, default_value_t = LogLevel::Debug)]
    #[serde(default = "debug_log_level")]
    pub block_propagation_log_level: LogLevel,
    /// Disable requesting P2P transactions propagated.
    /// No transaction being broadcasted across the p2p network will be requested.
    /// This may leads to mempool being not synchronized at all.
    /// It is discouraged to enable this config in a small p2p network.
    #[clap(name = "disable-p2p-fetching-txs-propagated", long)]
    #[serde(default)]
    pub disable_fetching_txs_propagated: bool,
    /// Handle peer packets in parallel by creating a new dedicated task.
    /// Each packet has its own dedicated task expect those which are
    /// order dependent. They are set in an sequential executor to ensure
    /// that the order stay the same despite this config enabled.
    /// Creating a dedicated task per packet handling is useful for
    /// reducing latency during heavy network usage but may increase
    /// heavily the network usage under high load.
    /// By default, all p2p packets are handled sequentially
    /// in a single task per peer.
    #[clap(name = "p2p-handle-peer-packets-in-dedicated-task", long)]
    #[serde(default)]
    pub handle_peer_packets_in_dedicated_task: bool,
    /// Experimental: Enable the compression for packets being sent to peers.
    /// Compression is done using the Snappy algorithm.
    /// It is only used for packets greater than 1 KiB.
    /// This is useful to reduce the bandwidth usage when having several peers.
    /// Note that it may increase the CPU usage due to the compression/decompression.
    /// By default, it is disabled.
    #[clap(name = "enable-p2p-compression", long)]
    #[serde(default)]
    pub enable_compression: bool,
    /// Disable the fast sync support.
    /// If set to true, others nodes will not be able to use the fast sync mode with us.
    #[clap(name = "disable-fast-sync-support", long)]
    #[serde(default)]
    pub disable_fast_sync_support: bool,
    /// During the sync from peers, only sync from priority nodes.
    /// This is useful to ensure that we only sync from trusted nodes.
    #[clap(name = "p2p-sync-from-priority-only", long)]
    #[serde(default)]
    pub sync_from_priority_only: bool,
    /// During a reorg, only accept blocks from priority nodes.
    /// This is useful to ensure that we only accept blocks from trusted nodes.
    #[clap(name = "p2p-reorg-from-priority-only", long)]
    #[serde(default)]
    pub reorg_from_priority_only: bool,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            tag: None,
            bind_address: default_p2p_bind_address(),
            max_peers: default_max_peers(),
            max_outgoing_peers: default_max_outgoing_peers(),
            priority_nodes: Vec::new(),
            exclusive_nodes: Vec::new(),
            disable: false,
            allow_fast_sync: false,
            allow_boost_sync: false,
            allow_priority_blocks: false,
            max_chain_response_size: default_chain_sync_response_blocks(),
            disable_ip_sharing: false,
            concurrency_task_count_limit: default_p2p_concurrency_task_count_limit(),
            on_dh_key_change: KeyVerificationAction::Ignore,
            dh_private_key: None,
            stream_concurrency: detect_available_parallelism(),
            temp_ban_duration: default_p2p_temp_ban_duration(),
            fail_count_limit: default_p2p_fail_count_limit(),
            disable_reexecute_blocks_on_sync: false,
            block_propagation_log_level: debug_log_level(),
            disable_fetching_txs_propagated: false,
            handle_peer_packets_in_dedicated_task: false,
            enable_compression: false,
            disable_fast_sync_support: false,
            sync_from_priority_only: false,
            reorg_from_priority_only: false,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    #[cfg(feature = "sled")]
    Sled,
    #[cfg(feature = "rocksdb")]
    #[clap(name = "rocksdb")]
    RocksDB,
    Memory,
}

impl Default for StorageBackend {
    fn default() -> Self {
        // RocksDB is preferred if both are enabled
        #[cfg(feature = "rocksdb")]
        {
            return Self::RocksDB;
        }

        #[cfg(all(not(feature = "rocksdb"), feature = "sled"))]
        {
            return Self::Sled;
        }

        #[cfg(all(not(feature = "rocksdb"), not(feature = "sled")))]
        {
            return Self::Memory;
        }
    }
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct MempoolConfig {
    /// Minimum fee per kB to consider a transaction as valid for the mempool.
    /// This is in atomic units (1e-8 of the currency unit).
    #[clap(long = "mempool-min-fee-per-kb", default_value_t = default_min_fee_per_kb())]
    #[serde(default = "default_min_fee_per_kb")]
    pub min_fee_per_kb: u64,
    /// Maximum time a transaction can stay in the mempool before being considered as expired and removed.
    #[clap(long = "mempool-tx-expiration-time", default_value_t = default_mempool_tx_expiration_time())]
    #[serde(
        with = "humantime_serde",
        default = "default_mempool_tx_expiration_time"
    )]
    pub tx_expiration_time: HumanDuration,
    /// Maximum mempool memory usage before starting to evict transactions.
    #[clap(long = "mempool-max-memory-usage", value_parser = parse_human_bytes, default_value_t = default_mempool_max_memory_usage())]
    #[serde(
        default = "default_mempool_max_memory_usage",
        serialize_with = "human_bytes_serde::serialize",
        deserialize_with = "human_bytes_serde::deserialize"
    )]
    pub max_memory_usage: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            min_fee_per_kb: default_min_fee_per_kb(),
            tx_expiration_time: default_mempool_tx_expiration_time(),
            max_memory_usage: default_mempool_max_memory_usage(),
        }
    }
}

#[derive(Debug, Clone, clap::Args, Serialize, Deserialize)]
pub struct BlockchainConfig {
    /// RPC configuration
    #[clap(flatten)]
    #[serde(default)]
    pub rpc: RPCConfig,
    /// P2P configuration
    #[clap(flatten)]
    #[serde(default)]
    pub p2p: P2pConfig,
    /// Mempool configuration
    #[clap(flatten)]
    #[serde(default)]
    pub mempool: MempoolConfig,
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
    /// Enable the contracts logging during their execution.
    /// This will print the logs of the contracts being executed in the block.
    #[clap(long)]
    #[serde(default)]
    pub enable_contracts_logging: bool,
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
    /// Disable the TX Cache (ZKP Cache)
    /// ZKP Cache is enabled by default and
    /// prevent to re-verify the same ZK Proofs more than once.
    #[clap(long)]
    #[serde(default)]
    pub disable_zkp_cache: bool,
    /// Max concurrency allowed for general tasks
    /// By default, it will use the available parallelism.
    #[clap(long, default_value_t = detect_available_parallelism())]
    #[serde(default = "detect_available_parallelism")]
    pub concurrency: usize,
    /// Enable snapshot mode during DAG reorganizations.
    /// This will create a snapshot of the current state before applying the reorg and will use
    /// as a memory buffer to apply the reorg and then flush it to the storage at the end of the reorg.
    #[clap(long)]
    #[serde(default)]
    pub enable_snapshot_on_reorg: bool,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            rpc: RPCConfig::default(),
            p2p: P2pConfig::default(),
            mempool: MempoolConfig::default(),
            dir_path: None,
            simulator: None,
            skip_pow_verification: false,
            enable_contracts_logging: false,
            auto_prune_keep_n_blocks: None,
            skip_block_template_txs_verification: false,
            genesis_block_hex: None,
            checkpoints: Vec::new(),
            txs_verification_threads_count: detect_available_parallelism(),
            pre_verify_block_threads_count: detect_available_parallelism(),
            check_db_integrity: false,
            recovery_mode: false,
            flush_db_every_n_blocks: None,
            disable_zkp_cache: false,
            concurrency: detect_available_parallelism(),
            enable_snapshot_on_reorg: false,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct MempoolConfigCli {
        #[clap(flatten)]
        mempool: MempoolConfig,
    }

    #[test]
    fn parse_mempool_max_memory_usage_human_bytes() {
        assert_eq!(parse_human_bytes("1024").unwrap(), 1024);
        assert_eq!(parse_human_bytes("1 KiB").unwrap(), 1024);
        assert_eq!(parse_human_bytes("1.5 MiB").unwrap(), 1_572_864);
        assert_eq!(parse_human_bytes("2GB").unwrap(), 2_000_000_000);
        assert!(parse_human_bytes("12 XB").is_err());
    }

    #[test]
    fn clap_mempool_max_memory_usage_human_bytes() {
        let cli = MempoolConfigCli::parse_from(["test"]);
        assert_eq!(cli.mempool.max_memory_usage, default_mempool_max_memory_usage());

        let cli = MempoolConfigCli::parse_from([
            "test",
            "--mempool-max-memory-usage",
            "1MiB"
        ]);

        assert_eq!(cli.mempool.max_memory_usage, 1_048_576);
    }

    #[test]
    fn serde_mempool_max_memory_usage_human_bytes() {
        let config: MempoolConfig = serde_json::from_str(r#"{"max_memory_usage":"1.5 MiB"}"#).unwrap();
        assert_eq!(config.max_memory_usage, 1_572_864);

        let config: MempoolConfig = serde_json::from_str(r#"{"max_memory_usage":1024}"#).unwrap();
        assert_eq!(config.max_memory_usage, 1024);

        let config: MempoolConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.max_memory_usage, default_mempool_max_memory_usage());

        let json = serde_json::to_string(&MempoolConfig {
            max_memory_usage: 10 * 1024 * 1024,
            ..MempoolConfig::default()
        })
        .unwrap();
        assert!(json.contains(r#""max_memory_usage":"10 MiB""#));
    }
}
